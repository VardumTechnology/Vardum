/**
 * @veil/device — one-tap contact sessions ("pin = identity").
 *
 * Exact web contract (extracted from the fixed reference bundle):
 *   1. identityLookup — fetch the peer's published prekeys (public only)
 *   2. verifyPeerPrekeys — SPK_sig AND pq_sig checked against the PINNED IK;
 *      on mismatch or absence the session is refused (MITM / downgrade guard)
 *   3. createContactSession — ephemeral X25519 vs peer SPK and peer IK + ML-KEM encap
 *      (b76: + X25519 and ML-KEM against one of the peer's one-time prekey pairs, when served)
 *   4. sign {v:4,t,ek,to,pq,spk,d} with the identity key (Ed25519); d = canonical dials
 *      (b76: {v:5,…,opk,opq} when a one-time pair was used — requestSigPayloadOf)
 *   5. VeilSession.create server-side (public material + write-secret hashes)
 *   6. ratchet state sealed in the device session store
 */

import { pinDeps } from './wipe-generation';
import {
  createContactSession, acceptContactSession, ikSign, verifyWithIk, veilIdFromIkPub,
  serializeRatchetState, canonicalDials, clampDials, verifyOneTimePrekeySig, OPK_ID_RE,
  utf8, toB64, randomBytes, deliveryForRole,
} from '../../crypto-core/src/index';
import { scheduleInboundOpen, prepareOpenBlind, adoptJoinOpenSig, reblindForJoin, isOpenKeyRefusal, noteOpenKeyRefused } from './sealed';
import { loadOneTimePrekey, oneTimePrekeyUsed, consumeOneTimePrekey, withOneTimePrekeyLock, OPK_ALREADY_USED_MESSAGE } from './opk';
import type { RatchetStateSerialized, VeilStorage } from '../../crypto-core/src/index';
import type { VeilRelay, PinStore, SessionStore, KeyvaultIdentity } from './index.js';
import { saveOrThrow } from './save-strict';
import { serializeRatchetSend } from './send-queue';

export interface OneTapDeps {
  relay: VeilRelay;
  pins: PinStore;
  sessions: SessionStore;
  /** b70 (audit L-2): where the answered-request ledger and the previous prekeys live */
  storage?: VeilStorage;
}

/* b71: v3 contact requests (token-only root; a relay could re-sign one person's
 * request as another's) are refused, and the code that read them is gone. */

/** b70 (audit L-2): requests this phone already answered (hashes, bounded) */
export const CONTACT_SEEN_KEY = 'veil_contact_seen_v1';
/** b70 (audit L-2): the prekeys replaced by the last rotation, kept for requests already on their way */
export { PREV_PREKEYS_KEY, PREV_PREKEYS_KEEP_MS, readPrevPrekeys } from './prekeys-prev';
import { readPrevPrekeys } from './prekeys-prev';
import { isChatToken } from './session-store'; // b77m (audit VAR-26)
// b70 (re-review P6): 8-byte hashes, 1500 of them (~28 KB), under the secure-store item limit
const CONTACT_SEEN_MAX = 1500;

/** b70 (L-2): short public id of a signed prekey (which one a request used) */
export async function spkIdOf(spkPubB64: string): Promise<string> {
  const h = new Uint8Array(await crypto.subtle.digest('SHA-256', utf8('vardum-spk-id:' + spkPubB64) as unknown as BufferSource));
  return [...h.slice(0, 8)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

async function writeHashHex(secret: string): Promise<string> {
  const h = new Uint8Array(await crypto.subtle.digest('SHA-256', utf8(secret) as unknown as BufferSource));
  return [...h].map((b) => b.toString(16).padStart(2, '0')).join('');
}

async function requestHash(token: string, ek: string): Promise<string> {
  const h = new Uint8Array(await crypto.subtle.digest('SHA-256', utf8('vardum-contact-seen:' + token + ':' + ek) as unknown as BufferSource));
  return [...h.slice(0, 8)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

/** b70 (re-review P6): merge answered-request hashes (a device transfer carries them) */
export async function mergeContactSeen(storage: VeilStorage, hashes: unknown): Promise<void> {
  if (!Array.isArray(hashes)) return;
  const add = hashes.filter((x): x is string => typeof x === 'string' && /^[0-9a-f]{16}$/.test(x));
  if (!add.length) return;
  const merged = [...new Set([...(await seenList(storage)), ...add])].slice(-CONTACT_SEEN_MAX);
  await storage.set(CONTACT_SEEN_KEY, JSON.stringify(merged));
}

export async function readContactSeen(storage: VeilStorage): Promise<string[]> {
  return seenList(storage);
}

/** b75 (audit RT-6): add a request to the answered-request ledger; false when the write was refused */
async function recordAnswered(storage: VeilStorage, hash: string): Promise<boolean> {
  const cur = await seenList(storage);
  if (cur.includes(hash)) return true;
  const list = [...cur, hash].slice(-CONTACT_SEEN_MAX);
  return (await storage.set(CONTACT_SEEN_KEY, JSON.stringify(list))) !== false;
}

async function seenList(storage: VeilStorage): Promise<string[]> {
  try { const raw = await storage.get(CONTACT_SEEN_KEY); const v = raw ? JSON.parse(raw) : []; return Array.isArray(v) ? v.filter((x) => typeof x === 'string') : []; } catch { return []; }
}

export interface OneTapResult {
  token: string;
  state: RatchetStateSerialized;
  /** b76 (one-time prekeys): initiator — the request used one of the peer's one-time pairs
   *  (false: the relay served none, so only the signed prekeys) */
  oneTimePrekey?: boolean;
}

/** Start a one-tap session with a pinned contact. Refuses on any trust failure. */
export interface SessionDials {
  default_ttl_seconds?: number;
  expire_after_seconds?: number;
  /** b71 (audit): despite the name, this is "End quiet chats after" (hours), not a key
   *  lifetime; skipped 1:1 message keys always expire after 7 days (SKIPPED_KEY_MAX_AGE_MS) */
  key_retention_hours?: number;
  burn_after_open?: boolean;
}

export async function createOneTapSession(
  deps: OneTapDeps,
  identity: KeyvaultIdentity,
  peerVeilId: string,
  clientId: string,
  dials?: SessionDials,
  /** b68: my self-chosen nickname — the peer sees it in this thread's title */
  displayName?: string,
): Promise<OneTapResult> {
  deps = pinDeps(deps); // b70 (re-review 9): a wipe while this waits on the relay stops its writes
  const pin = await deps.pins.getPin(peerVeilId);
  if (!pin) throw new Error('Pin this contact first — the pinned key is the trust anchor.');

  // b76 (one-time prekeys): this lookup also claims one of the peer's one-time prekey pairs (the
  // relay hands each out once and deletes it); with none left it serves the signed prekeys alone
  const r = await deps.relay.identityLookup(peerVeilId, { claimOpk: true, requesterVeilId: identity.veilId });
  const rec = (r.data as { data?: Record<string, string> })?.data ?? (r.data as Record<string, string>);
  const IK_pub = rec?.IK_pub, SPK_pub = rec?.SPK_pub, SPK_sig = rec?.SPK_sig;
  if (!IK_pub || !SPK_pub || !SPK_sig) throw new Error('No published prekeys for that Vardum ID.');

  // b54: SPK_sig AND pq_sig must verify against the PINNED IK (no classical fallback)
  const trust = await deps.pins.verifyPeerPrekeys(peerVeilId, { IK_pub, SPK_pub, SPK_sig, pq_pub: rec?.pq_pub, pq_sig: rec?.pq_sig });
  if (!trust.trusted) {
    if (trust.reason === 'pq-prekey-unsigned') throw new Error('Your contact needs to update Vardum before you can chat securely.');
    // b75 (audit 2 V9)
    if (trust.reason === 'prekeys-expired') throw new Error('Your contact\'s keys on the server are out of date. Ask them to open Vardum, then try again.');
    throw new Error(`Refusing to start: ${trust.reason}`);
  }
  // b76 (one-time prekeys): a served one-time pair must be signed by the PINNED identity key over
  // its id and both keys, and fresh; a bad one is refused (only a relay tampering with it, or
  // serving a stale copy, makes one). None served: the signed prekeys alone (the fallback).
  const opk = await checkServedOpk(pin.ikPubB64, (rec as unknown as { opk?: unknown })?.opk);
  if (opk === 'invalid') throw new Error('Refusing to start: one-time-prekey-invalid');

  // b197-r6: handshake stage profiler — the owner reported 5-10s handshake
  // lag; these marks identify which stage eats the time (prime suspects:
  // pure-JS ML-KEM encap on Hermes, relay RTTs, keychain save+verify).
  const HS_T0 = Date.now();
  const hsMark = (label: string) => console.log(`[veil-hs] +${String(Date.now() - HS_T0).padStart(5)}ms ${label}`);
  hsMark('pin + prekey lookup + trust verify done');

  // xu(24) in the web bundle: 24 random bytes, hex — same token format
  const token = [...randomBytes(24)].map((b) => b.toString(16).padStart(2, '0')).join('');
  // Batch C (V-12): the initiator's own dials, clamped — signed into the request and kept locally
  const myDials = clampDials({
    defaultTtlSeconds: dials?.default_ttl_seconds ?? 7200,
    expireAfterSeconds: dials?.expire_after_seconds ?? 86400,
    keyRetentionHours: dials?.key_retention_hours ?? 168,
    burnAfterOpen: dials?.burn_after_open ?? true,
  });
  // Batch C (B9): the PINNED IK feeds the extra DH(EK, IK_peer) term
  const created = await createContactSession(
    token, { spkPubB64: trust.spkPubB64, pqPubB64: trust.pqPubB64, ikPubB64: pin.ikPubB64, opk: opk ?? null }, identity.ikPubB64, myDials,
  );
  hsMark('crypto core done (X25519 + ML-KEM encap) — prime suspect if large');

  // b54: the IK signature also covers the initiator session pub (spk).
  // Batch C (V-12): and the session dials (d), so the relay can't rewrite them.
  // b70 (re-review 4): v4 = the session root also covers both identity keys
  // b76 (one-time prekeys): v5 = v4 plus the one-time pair's id and its ML-KEM ct (requestSigPayload)
  const sigMsg = opk
    ? requestSigPayloadOf({ token, ek: created.ekPubB64, to: peerVeilId, pq: created.pqCt, spk: created.sessionPub, d: canonicalDials(myDials), opkId: opk.id, opkPq: created.opkPqCt })
    : JSON.stringify({ v: 4, t: token, ek: created.ekPubB64, to: peerVeilId, pq: created.pqCt, spk: created.sessionPub, d: canonicalDials(myDials) });
  const sig = await ikSign(identity.ikSeedB64, toB64(utf8(sigMsg)));
  hsMark('ikSign done');

  const writeHash = async (secret: string) => {
    const h = await crypto.subtle.digest('SHA-256', utf8(secret) as unknown as BufferSource);
    return [...new Uint8Array(h)].map((b) => b.toString(16).padStart(2, '0')).join('');
  };

  void clientId; // b77 (sealed sender): no account id on the row (the relay never stored the body's copy)
  await deps.relay.entityCreate('VeilSession', {
    token,
    state: 'pending',
    responder_client_id: '',
    // b71 (review): no nickname goes to the relay (it never used it, and stored it in clear)
    passphrase_required: false,
    session_fingerprint: '',
    initiator_pub_jwk: created.sessionPub,
    initiator_pq_pub: '',
    initiator_pq_ct: created.pqCt,
    initiator_ek_pub: created.ekPubB64,
    initiator_sig: sig,
    initiator_veil_id: identity.veilId,
    responder_veil_id: peerVeilId,
    responder_spk_id: await spkIdOf(trust.spkPubB64), // b70 (L-2)
    // b76 (one-time prekeys): which one-time pair the request used and the ct to its PQ key
    // (both covered by initiator_sig); empty = the signed prekeys only
    responder_opk_id: opk?.id ?? '',
    initiator_opk_pq_ct: created.opkPqCt,
    contact_session: true,
    initiator_write_hash: await writeHash(created.writeSecrets.initiator),
    responder_write_hash: await writeHash(created.writeSecrets.responder),
    initiator_verified: false,
    responder_verified: false,
    // SPEC §2.11: pending contact request expires after 24h (web: 864e5 ms).
    // Dials = the web's default settings values (wh.burnTtlSeconds/expireAfterSeconds/retentionHours).
    default_ttl_seconds: myDials.defaultTtlSeconds,
    // b197-r8l (TWO-DIAL SYNCHRONIZED MODEL, owner spec): BOTH dials are
    // founder-programmable and relay-enforced —
    //   default_ttl_seconds = burn-after-open window (relay copy dies open+N)
    //   expire_after_seconds = unopened-message relay deletion horizon
    //                         (12/24/36/48 h chips)
    expire_after_seconds: myDials.expireAfterSeconds,
    key_retention_hours: myDials.keyRetentionHours,
    burn_after_open: myDials.burnAfterOpen,
    last_activity: new Date().toISOString(),
    expires_at: new Date(Date.now() + 24 * 3600 * 1000).toISOString(),
  });
  hsMark('entityCreate (relay RTT, big payload) done');

  const state = await serializeRatchetState(created.state);
  await saveOrThrow(deps.sessions, token, { // Batch H (R6-1-06): a refused save is an error
    ...state,
    // Batch F (round-4 review R4-1-04): who this chat is with, from the PIN — the
    // only local record of it (the handshake's contactPending is cleared later)
    peerVeilId,
    peerIkPub: pin.ikPubB64,
    burnAfterOpen: myDials.burnAfterOpen,
    defaultTtlSeconds: myDials.defaultTtlSeconds,
    expireAfterSeconds: myDials.expireAfterSeconds,
  } as never);
  hsMark('ratchet serialize + keychain save(+verify) done — HANDSHAKE COMPLETE');
  return { token, state, oneTimePrekey: !!opk };
}

/**
 * b76 (one-time prekeys): the one-time pair the relay served with the lookup, checked against
 * the PINNED identity key: null when none was served (the relay's pool ran out, or it withheld
 * one: the fallback), 'invalid' when one was served but its id, keys or signature don't check.
 */
export async function checkServedOpk(pinnedIkPubB64: string, served: unknown): Promise<{ id: string; xPubB64: string; pqPubB64: string } | null | 'invalid'> {
  if (served === null || served === undefined || served === '') return null;
  const o = served as { id?: unknown; x_pub?: unknown; pq_pub?: unknown; sig?: unknown };
  if (typeof o !== 'object' || typeof o.id !== 'string' || typeof o.x_pub !== 'string' || typeof o.pq_pub !== 'string' || typeof o.sig !== 'string') return 'invalid';
  if (!(await verifyOneTimePrekeySig(pinnedIkPubB64, o.id, o.x_pub, o.pq_pub, o.sig))) return 'invalid';
  return { id: o.id, xPubB64: o.x_pub, pqPubB64: o.pq_pub };
}

// ---------------------------------------------------------------------------
// Responder side (SPEC §3): verify the initiator's request, re-derive the
// shared root from OUR prekeys, join via the session gate, seal the ratchet.
// ---------------------------------------------------------------------------

/**
 * Batch F (round-4 review R4-1-04): who a 1:1 chat is with, from this phone's own
 * sealed state. Only contact (pinned-key) chats record it; invite chats and chats
 * sealed before b60 return null. Never derived from the relay row.
 */
export function sealedPeer(sealed: unknown): { veilId: string; ikPub: string } | null {
  const s = (sealed ?? {}) as { peerVeilId?: unknown; peerIkPub?: unknown };
  return typeof s.peerVeilId === 'string' && s.peerVeilId && typeof s.peerIkPub === 'string' && s.peerIkPub
    ? { veilId: s.peerVeilId, ikPub: s.peerIkPub } : null;
}

/** Batch F (R4-1-04): true when the sealed chat is a contact chat with exactly this peer and key. */
export function sealedPeerMatches(sealed: unknown, veilId: string, ikPub: string): boolean {
  const p = sealedPeer(sealed);
  return !!p && (sealed as { contact?: unknown }).contact === true && p.veilId === veilId && p.ikPub === ikPub;
}

/**
 * Batch F (R4-1-04): of the candidate chats (in the caller's order), the first
 * whose SEALED state is a contact chat with this contact under its pinned key.
 * The relay list only supplies candidates; it can't relabel a chat into this set.
 */
export async function pickContactSession(
  sessions: { load(token: string): Promise<unknown> },
  candidates: string[],
  veilId: string,
  pinnedIkPub: string,
): Promise<string | null> {
  for (const t of candidates) {
    const sealed = await sessions.load(t).catch(() => null);
    if (sealedPeerMatches(sealed, veilId, pinnedIkPub)) return t;
  }
  return null;
}

/** A pending contact-session record as served by veilSessionGate list/peek. */
export interface IncomingContactRequest {
  token: string;
  state: string;
  initiator_veil_id: string;
  initiator_ek_pub: string;
  initiator_pq_ct?: string | null;
  initiator_pub_jwk: string;
  initiator_sig: string;
  default_ttl_seconds?: unknown;
  expire_after_seconds?: unknown;
  key_retention_hours?: unknown;
  burn_after_open?: unknown;
  /** b79: stamped by THIS function's own relay.sessionJoin call — empty
   *  until the responder-side crypto join has actually happened. This is
   *  the correct "already joined" signal, NOT req.state (see guard below). */
  responder_pub_jwk?: string;
  /** b76 (one-time prekeys): the one-time pair the request used ('' / absent: none) and the ct
   *  to its PQ key — both covered by initiator_sig (v5) */
  responder_opk_id?: string;
  initiator_opk_pq_ct?: string;
}

/**
 * b71 (audit): a contact request from a Vardum ID this phone hasn't pinned is
 * never accepted without the user's explicit Accept. Pinned contacts
 * re-messaging keep the one-tap flow.
 */
export async function needsExplicitAccept(pins: Pick<PinStore, 'getPin'>, initiatorVeilId: string, userAccepted: boolean): Promise<boolean> {
  if (userAccepted) return false;
  if (!initiatorVeilId) return true;
  const pin = await pins.getPin(initiatorVeilId).catch(() => null);
  if (!pin) return true;
  // a pin whose key doesn't hash to the ID is not a trust anchor (Batch D, D-12)
  return (await veilIdFromIkPub(pin.ikPubB64).catch(() => '')) !== initiatorVeilId;
}

/** Batch C (V-12): a request's dials as the initiator signed them (clamped first) */
function requestDials(req: Pick<IncomingContactRequest, 'default_ttl_seconds' | 'expire_after_seconds' | 'key_retention_hours' | 'burn_after_open'>) {
  return clampDials({
    defaultTtlSeconds: req.default_ttl_seconds as number,
    expireAfterSeconds: req.expire_after_seconds as number,
    keyRetentionHours: req.key_retention_hours as number,
    burnAfterOpen: req.burn_after_open === true,
  });
}

/**
 * the BYTE-EXACT payload the initiator signs. v4 = {v:4,t,ek,to,pq,spk,d} (no one-time pair: the
 * fallback). b76 (one-time prekeys): v5 = {v:5,t,ek,to,pq,spk,d,opk,opq} — the one-time pair's id
 * and the ML-KEM ct to its PQ key. The version follows from the row's responder_opk_id, so a relay
 * that blanks or swaps the id (or the ct) makes the signature fail, and one that adds an id to a
 * fallback request does too.
 */
export function requestSigPayloadOf(p: { token: string; ek: string; to: string; pq: string; spk: string; d: string; opkId?: string; opkPq?: string }): string {
  if (p.opkId) return JSON.stringify({ v: 5, t: p.token, ek: p.ek, to: p.to, pq: p.pq, spk: p.spk, d: p.d, opk: p.opkId, opq: p.opkPq ?? '' });
  return JSON.stringify({ v: 4, t: p.token, ek: p.ek, to: p.to, pq: p.pq, spk: p.spk, d: p.d });
}
function requestSigPayload(req: IncomingContactRequest, toVeilId: string): string {
  return requestSigPayloadOf({
    token: req.token, ek: req.initiator_ek_pub, to: toVeilId, pq: req.initiator_pq_ct || '', spk: req.initiator_pub_jwk,
    d: canonicalDials(requestDials(req)), opkId: typeof req.responder_opk_id === 'string' ? req.responder_opk_id : '',
    opkPq: typeof req.initiator_opk_pq_ct === 'string' ? req.initiator_opk_pq_ct : '',
  });
}

/**
 * b75r2 (audit P-2): is this contact request really signed by the pinned key? The session
 * list titled a request naming a pinned contact with that contact's nickname and "request
 * from a contact" on the row's word alone, so the relay could make one up (and accepting it
 * then failed with nothing shown). This is the accept's own signature check, offline and
 * cheap: the pin's key must hash to the ID (Batch D, D-12) and initiator_sig must verify
 * under it over the v4 payload addressed to me (v5 when the row names a one-time pair; b76r2,
 * audit SP-01: the spec said v4 only). Results are kept per row, so the list's
 * repeated refreshes don't re-verify.
 */
const signedByPinMemo = new Map<string, boolean>();
export async function contactRequestSignedBy(req: IncomingContactRequest, pinnedIkPubB64: string, myVeilId: string): Promise<boolean> {
  if (!req?.token || !isChatToken(req.token) || !req.initiator_veil_id || typeof req.initiator_sig !== 'string' || !req.initiator_sig || !pinnedIkPubB64 || !myVeilId) return false; // b77m (audit VAR-26): a well-formed token only
  let key = '';
  try { key = JSON.stringify([requestSigPayload(req, myVeilId), req.initiator_veil_id, req.initiator_sig, pinnedIkPubB64]); } catch { return false; }
  const memo = signedByPinMemo.get(key);
  if (memo !== undefined) return memo;
  let ok = false;
  try {
    ok = (await veilIdFromIkPub(pinnedIkPubB64)) === req.initiator_veil_id
      && await verifyWithIk(pinnedIkPubB64, toB64(utf8(requestSigPayload(req, myVeilId))), req.initiator_sig);
  } catch { ok = false; }
  if (signedByPinMemo.size > 500) signedByPinMemo.clear();
  signedByPinMemo.set(key, ok);
  return ok;
}

/** b75r3 (audit PR3-01): a Vardum ID's shape — base58(SHA-256(IK))[0:16], as the relay checks it.
 *  A request row naming anything else (free text such as "Vardum Team") is never shown as an ID. */
export function isVardumIdShape(v: unknown): v is string {
  return typeof v === 'string' && /^[1-9A-HJ-NP-Za-km-z]{16}$/.test(v);
}

/**
 * b75r3 (audit PR3-01): is this contact request signed by the Vardum ID it names, pinned or not?
 * P-2 checked only requests naming a PINNED ID, so a request row the relay made up naming an ID
 * the user had nicknamed but never pinned (a chat accepted from a request and then renamed) wore
 * that nickname. Now: the pinned key, else the published key from a lookup (what accept itself
 * uses); either must hash to the ID (contactRequestSignedBy). 'unknown' = the lookup failed;
 * callers show no nickname then either. Lookups are kept 10 minutes (a failure 1 minute), so
 * the list's 10-second refresh doesn't ask the relay again each time.
 */
const requestKeyMemo = new Map<string, { ik: string | null; until: number }>();
export async function contactRequestCheck(
  deps: { relay: Pick<VeilRelay, 'identityLookup'>; pins: Pick<PinStore, 'getPin'> },
  req: IncomingContactRequest, myVeilId: string,
): Promise<'signed' | 'unsigned' | 'unknown'> {
  const vid = req?.initiator_veil_id;
  if (!isVardumIdShape(vid) || !myVeilId) return 'unsigned';
  const pin = await deps.pins.getPin(vid).catch(() => null);
  let ik = pin?.ikPubB64 ?? '';
  if (!ik) {
    const memo = requestKeyMemo.get(vid);
    if (memo && memo.until > Date.now()) ik = memo.ik ?? '';
    else {
      let got: string | null = null;
      try {
        const r = await deps.relay.identityLookup(vid);
        const rec = (r.data as { data?: Record<string, string> })?.data ?? (r.data as Record<string, string>);
        got = typeof rec?.IK_pub === 'string' && rec.IK_pub ? rec.IK_pub : null;
      } catch { got = null; }
      if (requestKeyMemo.size > 500) requestKeyMemo.clear();
      requestKeyMemo.set(vid, { ik: got, until: Date.now() + (got ? 600_000 : 60_000) });
      ik = got ?? '';
    }
    if (!ik) return 'unknown';
  }
  return (await contactRequestSignedBy(req, ik, myVeilId)) ? 'signed' : 'unsigned';
}

/** b75r3 (audit PR3-01): what a request row showed — who it names and what they signed. The
 *  Accept is bound to it: if the row has changed by the time the accept runs, it is refused. */
export function requestDisplayBinding(req: Record<string, unknown>): string {
  return JSON.stringify([req.token, req.initiator_veil_id, req.initiator_sig, req.initiator_ek_pub, req.initiator_pq_ct || '', req.initiator_pub_jwk,
    req.default_ttl_seconds, req.expire_after_seconds, req.key_retention_hours, req.burn_after_open,
    req.responder_opk_id || '', req.initiator_opk_pq_ct || '' /* b76 (one-time prekeys) */].map((x) => (x === undefined ? null : x)));
}

/**
 * b75r2 (audit P-2): what the user is told when their Accept fails. The accept's own
 * refusals are written for people and pass through; a signature failure is said plainly;
 * anything else (network, relay) gets a short retry line, never a raw error.
 */
export function acceptFailureMessage(reason: string): string {
  const m = String(reason ?? '');
  if (/signature failed verification|does not match their Vardum ID/i.test(m)) return 'This request isn’t signed by the Vardum ID it names, so it was not accepted.';
  if (/changed after it was shown/i.test(m)) return m; // b75r3 (PR3-01): the Accept is bound to the row shown
  if (/already answered|already exists on this phone|no longer has|could not save|has ended|already joined|already accepted/i.test(m)) return m;
  if (/one-time key/i.test(m)) return m; // b76 (one-time prekeys): the accept's own refusals
  return 'The request could not be accepted right now. Try again in a moment.';
}

/**
 * b75r2 (audit P-3): one accept per token at a time. The Accept tap and a live poll could run
 * two accepts of the same request side by side: both read "no chat here", the first joined and
 * saved a ready chat, and the second then saved its own pending state over it — with keys the
 * relay never stored — so the next handshake pass deleted the chat. Accepts now share the
 * token's ratchet lock (the one syncs and sends use), so the second one starts only after the
 * first has finished and finds the chat already there.
 */
// b76r1 (one-time prekeys, audit P-1 / D1): and one accept per one-time PAIR at a time. Two
// requests (two tokens, so two token locks) naming the same pair used to overlap: both found it
// unused, both derived from it, both consumed it — one one-time key, two chats. The pair's lock
// spans the used check, the load, the derive and the consume, so the second waits, then finds
// the pair used and is refused (consumeOneTimePrekey also refuses an id already used).
export function acceptOneTapSession(...args: Parameters<typeof acceptOneTapSessionUnlocked>): ReturnType<typeof acceptOneTapSessionUnlocked> {
  return serializeRatchetSend(String(args[2]?.token ?? ''), () => {
    const opkId = typeof args[2]?.responder_opk_id === 'string' ? args[2].responder_opk_id : '';
    return opkId ? withOneTimePrekeyLock(opkId, () => acceptOneTapSessionUnlocked(...args)) : acceptOneTapSessionUnlocked(...args);
  });
}

async function acceptOneTapSessionUnlocked(
  deps: OneTapDeps,
  identity: KeyvaultIdentity,
  req: IncomingContactRequest,
  clientId: string,
  /** b68: my self-chosen nickname — the initiator sees it in this thread's title */
  displayName?: string,
): Promise<OneTapResult> {
  deps = pinDeps(deps); // b70 (re-review 9): a wipe while this waits on the relay stops its writes
  const { relay, pins, sessions } = deps;
  // b77m (audit VAR-26): the token becomes this chat's storage keys and mailbox ids — 48 lowercase hex only
  if (!isChatToken(req?.token)) throw new Error('This request is malformed, so it was not accepted.');
  // Batch G (round-5 review R5-1-06): never overwrite a chat this phone already holds
  // (a relay could relabel my own pending invite as a contact request to me)
  {
    const existing = await sessions.load(req.token) as (Record<string, unknown> & { joinPendingResponderPub?: string; joinPendingSeenHash?: string; peerVeilId?: string; peerIkPub?: string }) | null;
    // b70 (re-review 10): an accept whose join reply was lost — the relay has it if the
    // row now carries OUR responder key; then the chat is finished, not refused.
    // b75 (audit RT-6): reachable now — the pending state is saved NOT ready, so the app's
    // handshake driver comes back here instead of treating the chat as done; and the join
    // is re-sent with the same keys when the row shows none, instead of starting over (the
    // request is already in the answered-request ledger, so starting over would refuse it).
    if (existing?.joinPendingResponderPub) {
      const { joinPendingResponderPub: pendingPub, joinPendingSeenHash: seen, joinPendingRatchetPub: pendingRatchetPub, joinPendingTicketHashes: _oldTickets, joinPendingOpenBlind: pendingBlind, ...rest } = existing as typeof existing & { joinPendingRatchetPub?: string; joinPendingTicketHashes?: [string, string]; joinPendingOpenBlind?: { kid: string; x: string; r: string } };
      void _oldTickets; // b77p: ticket hashes are retired (a pending state from b77 drops them)
      // b75 (RT-6): the ledger entry, if an older build skipped it
      if (deps.storage && seen) await recordAnswered(deps.storage, seen);
      if (req.responder_pub_jwk && req.responder_pub_jwk !== pendingPub) {
        // someone else's join landed: this phone's half can never work
        await sessions.remove(req.token);
        throw new Error('Session already joined.');
      }
      let rejoin: unknown = null;
      let joinBlind = pendingBlind;
      if (!req.responder_pub_jwk) {
        if (req.state === 'ended') throw new Error('Session has ended.');
        const st = rest as { writeSecret?: string | null; fingerprint?: string | null; bound?: { responderRatchetPub?: string } | null; ratchetPub?: string };
        // b77 (sealed sender): no login, no client id; b77p: the same blinded open token rides the re-sent join
        let again = await reblindForJoin(relay, pendingBlind, sessions); // b77q (audit 3 CR-1): the pinned issuer key
        if (!again) {
          // b77p round 2 (review L2): the issuer key moved on since the first join (or a b77 pending state kept no
          // blind): a FRESH blinded token, kept in the pending state before it is sent (a lost answer re-sends the
          // same one). A join with no blind got 410 "older protocol" and the chat never finished.
          const fresh = await prepareOpenBlind(relay, sessions);
          if (fresh) {
            await saveOrThrow(sessions, req.token, { ...existing, joinPendingOpenBlind: fresh.blind } as never);
            joinBlind = fresh.blind;
            again = { open_blind: fresh.open_blind, open_kid: fresh.open_kid };
          }
        }
        rejoin = await relay.sessionJoin({
          token: req.token,
          write_secret: st.writeSecret ?? '',
          client_id: '',
          responder_pub_jwk: pendingPub as string,
          responder_ratchet_pub_jwk: pendingRatchetPub ?? st.bound?.responderRatchetPub ?? st.ratchetPub ?? '',
          responder_pq_ct: '',
          fingerprint: st.fingerprint ?? '',
          ...(again ? { open_blind: again.open_blind, open_kid: again.open_kid } : {}),
        }, { anon: true }).catch(async (e) => {
          // b77q (audit 3 CR-1): the relay refused the issuer key: noted on the pin (the next attempt may fetch again)
          if (again && isOpenKeyRefusal(e)) await noteOpenKeyRefused(sessions, again.open_kid).catch(() => undefined);
          throw e;
        });
      }
      // b71 (audit): accepting never pins; pinning is the user's own step.
      const ready = { ...rest, ready: true };
      await saveOrThrow(sessions, req.token, ready as never);
      if ((rest as { delivery?: unknown }).delivery) {
        await scheduleInboundOpen(sessions, req.token); // b77
        // b77p: the open token from the re-sent join, else the kept blind (gate `issue` recovers it)
        if (joinBlind) await adoptJoinOpenSig(relay, sessions, req.token, joinBlind, rejoin);
      }
      return { token: req.token, state: ready as never };
    } else if (existing) throw new Error('This chat already exists on this phone, so the request was not accepted.');
  }
  // b79 CRITICAL FIX (owner report: "no accept window comes up on native,
  // it just appears in the conversations box" — a PINNED-CONTACT one-tap
  // re-message session needed no accept step (trust already exists via the
  // pin). b71: the row is created 'pending' like any other (the relay's create
  // whitelist has no state field); a request from an unpinned ID now waits for
  // the user's explicit Accept (needsExplicitAccept). The OLD guard here refused to run unless state==='pending', which
  // meant the crypto join (the part that actually derives this device's
  // ratchet keys and stamps responder_pub_jwk) never ran AT ALL for that
  // flow — advanceHandshake called this every poll, it threw every time, the
  // bare catch swallowed it silently, and the message could never decrypt
  // (peer stuck on "waiting for their device to open it" forever). The
  // correct guard is "has THIS session already been joined", which
  // responder_pub_jwk answers directly — it's empty until the one
  // relay.sessionJoin call below stamps it, whatever the row's state says.
  // (b75r1, spec §10: since b75 (audit 2 V3) the relay stores every new row
  // 'pending'; a client-sent 'active' at create is ignored.)
  if (req.responder_pub_jwk) throw new Error('Session already joined.');
  if (req.state === 'ended') throw new Error('Session has ended.');

  // 1. resolve the trust anchor for the initiator's IK: pinned if available,
  //    otherwise lookup (SPEC §3.1 allows either). b71 (audit): an accept never
  //    pins. The app asks for an explicit Accept on a request from a Vardum ID
  //    that isn't pinned (needsExplicitAccept); pinning is a separate step.
  let ikPubB64: string;
  const pin = await pins.getPin(req.initiator_veil_id);
  if (pin) {
    // Batch D (D-12, RV-22): a pin made before the B1 rule may hold a key that
    // doesn't hash to the ID — re-check on every accept, pinned or not
    if ((await veilIdFromIkPub(pin.ikPubB64)) !== req.initiator_veil_id) throw new Error('Initiator identity does not match their Vardum ID.');
    ikPubB64 = pin.ikPubB64;
  } else {
    const r = await relay.identityLookup(req.initiator_veil_id);
    const rec = (r.data as { data?: Record<string, string> })?.data ?? (r.data as Record<string, string>);
    if (!rec?.IK_pub) throw new Error('Initiator has no published identity.');
    // Batch C (B1): the Vardum ID IS the hash of the identity key — refuse a registry record that doesn't match
    if ((await veilIdFromIkPub(rec.IK_pub)) !== req.initiator_veil_id) throw new Error('Initiator identity does not match their Vardum ID.');
    ikPubB64 = rec.IK_pub;
  }

  // 2. verify initiator_sig over the BYTE-EXACT payload {v:4,t,ek,to,pq,spk,d}.
  //    Batch C (V-12): the dials come from the row but must match what the
  //    initiator signed — a relay rewrite fails the signature. Clamped first.
  const reqDials = requestDials(req);
  // v4 requests bind both identity keys into the session root (b71: only v4)
  if (!(await verifyWithIk(ikPubB64, toB64(utf8(requestSigPayload(req, identity.veilId))), req.initiator_sig))) {
    throw new Error('Request signature failed verification against the initiator identity key.');
  }

  // b70 (audit L-2): a request this phone already answered is never answered
  // again — even after its chat was deleted here. (A relay replaying an old
  // signed request used to create a "ghost" chat sealed as that contact.)
  const seenHash = await requestHash(req.token, req.initiator_ek_pub);
  if (deps.storage && (await seenList(deps.storage)).includes(seenHash)) {
    throw new Error('This request was already answered on this phone, so it was not accepted again.');
  }
  // b76 (one-time prekeys): a request that names one of this phone's one-time pairs (signed, v5)
  // needs that pair's private keys, found by id. A pair already used is refused (a replay, even
  // under a fresh token or ephemeral key); one this phone doesn't have (expired, wiped, made on
  // another phone) can't be answered. Requests naming none (the fallback) go on as before.
  const opkId = typeof req.responder_opk_id === 'string' ? req.responder_opk_id : '';
  let opkKeys: { id: string; xPrivB64: string; xPubB64: string; pqPrivB64: string; pqPubB64: string; pqCt: string } | null = null;
  if (opkId) {
    if (!OPK_ID_RE.test(opkId)) throw new Error('This request names a one-time key in a form Vardum doesn’t use, so it was not accepted.');
    if (!deps.storage || await oneTimePrekeyUsed(deps.storage, opkId)) {
      throw new Error(OPK_ALREADY_USED_MESSAGE);
    }
    const held = await loadOneTimePrekey(deps.storage, opkId);
    if (!held) throw new Error('This request was made to keys this phone no longer has, so it could not be accepted. Ask your contact to send a new one.');
    opkKeys = { id: opkId, xPrivB64: held.xPrivB64, xPubB64: held.xPubB64, pqPrivB64: held.pqPrivB64, pqPubB64: held.pqPubB64, pqCt: req.initiator_opk_pq_ct || '' };
  }
  // b70 (audit L-2): prekeys rotate; a request made just before a rotation names
  // the previous set (responder_spk_id), which is kept for exactly that
  let keys = { spkPrivB64: identity.spkPrivB64, spkPubB64: identity.spkPubB64, pqPrivB64: identity.pqPrivB64, pqPubB64: identity.pqPubB64 };
  const hint = String((req as { responder_spk_id?: unknown }).responder_spk_id ?? '');
  if (hint && deps.storage && hint !== await spkIdOf(identity.spkPubB64)) {
    try {
      const prev = (await readPrevPrekeys(deps.storage)) as typeof keys | null; // b70 (re-review 7): within its window only
      if (prev?.spkPubB64 && hint === await spkIdOf(prev.spkPubB64)) keys = prev;
    } catch { /* no previous set: the current one is tried */ }
  }

  // 3. reproduce the shared root from OUR prekeys (SPEC §3.2).
  // b70 (re-review P2): the row's responder_write_hash is a key confirmation
  // (only the right shared root yields that write secret). Try the hinted set
  // first, then the other one; refuse when neither matches, instead of
  // silently making a chat that can never decrypt.
  let prevSet: typeof keys | null = null;
  try { prevSet = deps.storage ? ((await readPrevPrekeys(deps.storage)) as typeof keys | null) : null; } catch { prevSet = null; }
  const currentSet = { spkPrivB64: identity.spkPrivB64, spkPubB64: identity.spkPubB64, pqPrivB64: identity.pqPrivB64, pqPubB64: identity.pqPubB64 };
  // the hinted set first, then the current, then the previous (each once)
  const candidates: (typeof keys)[] = [];
  for (const set of [keys, currentSet, prevSet]) if (set?.spkPubB64 && !candidates.some((c) => c.spkPubB64 === set.spkPubB64)) candidates.push(set);
  const wantHash = String((req as { responder_write_hash?: unknown }).responder_write_hash ?? '');
  let accepted: Awaited<ReturnType<typeof acceptContactSession>> | null = null;
  for (const set of candidates) {
    let a: Awaited<ReturnType<typeof acceptContactSession>>;
    try {
      a = await acceptContactSession(req.token, {
        ekPubB64: req.initiator_ek_pub,
        pqCt: req.initiator_pq_ct || '',
        spkPrivB64: set.spkPrivB64,
        spkPubB64: set.spkPubB64,
        pqPrivB64: set.pqPrivB64,
        pqPubB64: set.pqPubB64,
        initiatorSessionPub: req.initiator_pub_jwk,
        ikSeedB64: identity.ikSeedB64,
        ikPubB64: identity.ikPubB64,
        initiatorIkPubB64: ikPubB64,
        dials: reqDials,
        opk: opkKeys, // b76 (one-time prekeys)
      });
    } catch (e) { if (set === candidates[candidates.length - 1]) throw e; continue; }
    // b70 (re-review 8): no confirmation hash, no accept (the relay used to switch the check off by blanking it)
    if (wantHash && await writeHashHex(a.writeSecret) === wantHash) { accepted = a; break; }
  }
  if (!accepted) throw new Error('This request was made to keys this phone no longer has, so it could not be accepted. Ask your contact to send a new one.');

  // b76 (one-time prekeys): the one-time pair is spent — recorded as used and its private keys
  // deleted (and the delete checked) BEFORE anything of this chat is saved. If that fails, the
  // accept fails; a chat never exists here while the key that opened it still does.
  if (opkKeys && deps.storage) await consumeOneTimePrekey(deps.storage, opkKeys.id);

  // b70 (re-review 10): sealed BEFORE the join, marked pending — a join the relay stored
  // but whose reply was lost used to leave nothing here, and the chat dead for good.
  // b75 (audit RT-6): saved NOT ready (nothing decrypts or sends on it, and the app's
  // handshake driver keeps coming back to finish the join), and the answered-request
  // ledger entry is written with it, before the join: a relay that fails the join and
  // later re-serves the same signed request can no longer get it accepted again.
  // b77 (sealed sender): this phone's delivery capabilities (responder side) and the two ticket
  // hashes the join hands the relay — kept with the pending state so a re-sent join carries them
  const delivery = await deliveryForRole(accepted.delivery, 'responder');
  // b77p (audit 2 VAR-01): my blinded mailbox-open token (it replaced the two ticket hashes the relay could match
  // to the later opens); kept with the pending state so a re-sent join carries the same value
  const openPrep = await prepareOpenBlind(relay, sessions); // b77q (audit 3 CR-1): the pinned issuer key
  const pendingState = { ...(await serializeRatchetState(accepted.state)), ready: false, peerVeilId: req.initiator_veil_id, peerIkPub: ikPubB64,
    burnAfterOpen: reqDials.burnAfterOpen, defaultTtlSeconds: reqDials.defaultTtlSeconds, expireAfterSeconds: reqDials.expireAfterSeconds,
    delivery,
    joinPendingResponderPub: accepted.responderPub, joinPendingRatchetPub: accepted.responderRatchetPub, joinPendingSeenHash: seenHash, ...(openPrep ? { joinPendingOpenBlind: openPrep.blind } : {}) };
  if (deps.storage && !(await recordAnswered(deps.storage, seenHash))) {
    throw new Error('This phone could not save the request as answered, so it was not accepted. Try again.');
  }
  // b75r2 (audit P-3): never write the pending state over a chat that appeared meanwhile
  // (another code path, or a caller outside the lock above)
  if (await sessions.load(req.token)) throw new Error('This chat already exists on this phone, so the request was not accepted.');
  await saveOrThrow(sessions, req.token, pendingState as never);

  // 4. join (SPEC §3.3) — write_secret is the lowercase-hex responder credential
  // b77 (sealed sender): a 1:1 join needs no login and no client id (sent anonymously; the write
  // secret is the capability), and hands the relay my blinded open token (b77p)
  void clientId;
  const joinAnswer = await relay.sessionJoin({
    token: req.token,
    write_secret: accepted.writeSecret,
    client_id: '', // b71 (review): no display_name — the relay has no use for a nickname
    responder_pub_jwk: accepted.responderPub,
    responder_ratchet_pub_jwk: accepted.responderRatchetPub,
    responder_pq_ct: '',
    fingerprint: accepted.fingerprint,
    ...(openPrep ? { open_blind: openPrep.open_blind, open_kid: openPrep.open_kid } : {}),
  }, { anon: true }).catch(async (e) => {
    // b77q (audit 3 CR-1): the relay refused the issuer key: noted on the pin (the re-sent join may fetch again)
    if (openPrep && isOpenKeyRefusal(e)) await noteOpenKeyRefused(sessions, openPrep.open_kid).catch(() => undefined);
    throw e;
  });

  // 5. b71 (audit): no auto-pin. The chat is sealed with the initiator's checked
  //    key below; pinning them as a contact is the user's decision.

  const state = await serializeRatchetState(accepted.state);
  await saveOrThrow(sessions, req.token, { // Batch H (R6-1-06): a refused save is an error
    ...state,
    // Batch F (R4-1-04): the initiator, as verified above (pin, or ID = f(IK) + signature)
    peerVeilId: req.initiator_veil_id,
    peerIkPub: ikPubB64,
    burnAfterOpen: reqDials.burnAfterOpen,
    defaultTtlSeconds: reqDials.defaultTtlSeconds,
    expireAfterSeconds: reqDials.expireAfterSeconds,
    delivery, // b77 (sealed sender)
  } as never);
  // b77: open my own inbound after the random 5–120 s delay (never at once: the relay must not
  // be able to pair the open with this join by time)
  await scheduleInboundOpen(sessions, req.token);
  if (openPrep) await adoptJoinOpenSig(relay, sessions, req.token, openPrep.blind, joinAnswer); // b77p
  // (b75, RT-6: the answered-request ledger entry was written with the pending state)
  return { token: req.token, state };
}
