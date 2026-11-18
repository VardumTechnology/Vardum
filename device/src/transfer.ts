/**
 * @veil/device — moving chats to a new phone (b75: receiver-bound move, spec §7).
 *
 * b75 (audit XF-1 / XF-2, owner decision): the move runs the other way round
 * from b39–b74. The old flow put a whole-key link on the OLD phone, so whoever
 * captured the QR or clipboard took the identity seed and every chat, and the old
 * phone then erased its own copy on the taker's ack. Now:
 *
 * NEW PHONE (receiver) — it already holds the same Vardum ID (restored with the
 * 24 words; that is the only way onto a phone):
 *   1. `startReceive`: a fresh X25519 key pair and a fresh ML-KEM-768 key pair, in
 *      memory only, for this one screen. It signs its half of the transcript (token,
 *      both public keys, Vardum ID) with the identity key it restored from the 24
 *      words: `deviceLink open {token, kem_pub, rsig}`.
 *   2. Shows the MOVE CODE (QR, or text to copy):
 *        vardum-move:1:<b64url(token16 ‖ X25519 pub32 ‖ SHA-256(ML-KEM pub)32)>:<Vardum ID>
 *      Public values only: a photo of it can't take anything.
 *   3. `waitForOffer`: the old phone's offer must be signed by THIS phone's own
 *      identity key over the full transcript, else it is refused. Shows the
 *      6-digit check code derived from that transcript.
 *   4. `receiveMove`: fetches the bundle, checks it against the offer's commitment,
 *      decrypts it with the in-memory keys, imports, and sends the ack (an HMAC
 *      only the holder of the receiver's private keys can compute).
 *
 * OLD PHONE (sender):
 *   1. `prepareMove(code)`: refuses a code for another Vardum ID; fetches the
 *      ML-KEM public key and checks it against the hash in the code; refuses unless
 *      the receiver's signature verifies under THIS phone's own identity key (b75r1,
 *      audit PX-01: a code is public values only, so without it anyone could make a
 *      valid code for a Vardum ID from its public key and collect its chats); builds the
 *      bundle (one-to-one chats only, NO identity keys) and encrypts it to both
 *      receiver keys (X25519 + ML-KEM-768 → HKDF → AES-256-GCM); posts only the
 *      OFFER (its ephemeral public key, the ML-KEM ciphertext, the bundle's
 *      commitment and an identity-key signature). Nothing secret has left yet.
 *   2. Both phones show the same check code. The user confirms on the old phone.
 *   3. `confirmMove`: records the move on this phone, then uploads the bundle.
 *   4. `finishTransferMove`: the moved chats are retired here only on the
 *      receiver's ack proof. Without it, after the link's life plus a margin
 *      (MOVE_PAUSE_CAP_MS), the user decides (keep here / remove here); the
 *      relay's word alone never retires or resumes anything.
 *
 * Why the identity keys stay out of the bundle (b75, XF-1 "consider leaving the
 * seed out"): the new phone can only reach Settings after the 24 words restored
 * the identity there, so the seed in the bundle was never needed — it only made
 * a stolen bundle a stolen identity. A move now carries chats, not the Vardum ID.
 * Group sessions stay on the old phone (b71 P-07, spec §11.13): group records
 * never travel, so a moved seat was useless on the new phone.
 */
import { x25519 } from '@noble/curves/ed25519';
import { pinDeps } from './wipe-generation';
import { serializeRatchetSend } from './send-queue';
import { mergeContactSeen, readContactSeen } from './contact';
import {
  randomBytes, toB64, fromB64, utf8, concat, sha256, hkdf, hmacSha256,
  mlkemKeypair, mlkemEncap, mlkemDecap, ikSign, verifyWithIk, x25519Dh, padBlob, unpadBlob,
} from '../../crypto-core/src/index';
import type { RatchetStateSerialized } from '../../crypto-core/src/ratchet';
import { isStoreToken, type SessionStore, type OutboxItem } from './session-store'; // b77m (audit VAR-26): isStoreToken
import type { ChatMessage } from './chat';
import type { IdentityVault } from './keyvault';
import type { VeilRelay } from './relay';
import type { VeilStorage } from '../../crypto-core/src/storage-adapter';
import { loadGroupRecords, listGroupTokens, groupRecord } from './groups';

/** a move code lives as long as the relay keeps its row (10 minutes, relay `open`) */
export const MOVE_LINK_MS = 10 * 60_000;
/** b75 (audit XF-3): the longest the old phone keeps moved chats paused on its own.
 *  After this, with no ack proof, the USER decides; nothing the relay says extends it. */
export const MOVE_PAUSE_CAP_MS = MOVE_LINK_MS + 20 * 60_000;
export const MOVE_CODE_PREFIX = 'vardum-move:1:';
const LABEL = 'vardum-move-v1';
/** b75r3 (audit I-1): the label of the offer signature the RELAY checks (spec §2.8) */
export const MOVE_OFFER_RELAY_LABEL = 'vardum-move-offer-relay-v1:';

export interface TransferBundleV3 {
  v: 3;
  /** the Vardum ID the chats belong to (must equal the receiver's own) */
  veilId: string;
  sessions: Record<string, RatchetStateSerialized>;
  /** b70 (re-review P6): the answered-contact-request ledger moves too */
  contactSeen?: string[];
  /** 32 random bytes (hex): the ack needs the decrypted bundle, not just the keys */
  ackNonce: string;
  /** b75r3 (audit I-3): per chat, what isn't in the ratchet state but must not be lost by the
   *  move — messages this phone opened in the background but nobody has displayed yet, the
   *  unread count, and the relay burns still owed (awaiting display, or waiting to retry) */
  carry?: Record<string, MoveCarry>;
}

/** b75r3 (audit I-3) */
export interface MoveCarry {
  unshown?: ChatMessage[];
  unread?: number;
  burns?: Awaited<ReturnType<SessionStore['pendingBurns']>>;
  /** b77 (sealed sender): the chat's own-inbound state — the fetch cursor, whether (and when) it
   *  is opened. The capabilities themselves travel in the sealed record (`delivery`). The wake
   *  reference does not: the new phone binds its own. */
  mbox?: { seq: number; opened: boolean; openAt: number; verified?: boolean; rvEnded?: boolean; everOpened?: boolean };
  /** b77: envelopes encrypted here that still wait for the peer's inbound to open */
  outbox?: OutboxItem[];
}

export interface DeviceTransferResult {
  sessionCount: number;
  importedCount: number;
  skippedExisting: number;
  /** imported, but no ack was sent, so the old phone keeps its chats */
  ackHeld?: 'already-here';
  /** Batch G (R5-3-03): a save was refused; the old phone keeps its chats */
  incomplete?: boolean;
  /** b70 (VAR-05): chats not imported because they named a pinned contact under another key */
  conflicts?: number;
  /** the ack reached the relay (the old phone can now retire its copy) */
  acked?: boolean;
}

export interface TransferDeps {
  sessions: SessionStore;
  vault: IdentityVault;
  relay: VeilRelay;
  /** Batch E (F-3): where the pending move is recorded until it is finished */
  storage?: VeilStorage;
}

// ---------- small helpers ----------

function hex(b: Uint8Array): string { return Array.from(b).map((x) => x.toString(16).padStart(2, '0')).join(''); }
function unhex(s: string): Uint8Array {
  if (!/^(?:[0-9a-f]{2})*$/.test(s)) throw new Error('bad hex');
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(2 * i, 2 * i + 2), 16);
  return out;
}
function b64url(b: Uint8Array): string { return toB64(b).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); }
function unb64url(s: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]*$/.test(s)) throw new Error('bad b64url');
  const p = s.replace(/-/g, '+').replace(/_/g, '/');
  return fromB64(p + '='.repeat((4 - (p.length % 4)) % 4));
}
/** b70 (re-review 14): constant-time compare of two hex strings */
function ctEqHex(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}
/** lp(x) = 4-byte big-endian length ‖ x, for every field (spec §1.2 style) */
function lp(parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + 4 + p.length, 0);
  const buf = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    new DataView(buf.buffer).setUint32(off, p.length);
    buf.set(p, off + 4);
    off += 4 + p.length;
  }
  return buf;
}
function wipe(...arrs: (Uint8Array | undefined)[]): void { for (const a of arrs) if (a) a.fill(0); }
function relayData(r: unknown): Record<string, unknown> {
  // the relay answers bare ({state}) or data-wrapped ({data: {blob}})
  const d = ((r as { data?: unknown })?.data ?? {}) as Record<string, unknown>;
  const inner = d.data as Record<string, unknown> | undefined;
  return inner && typeof inner === 'object' ? inner : d;
}
async function aesGcm(mode: 'encrypt' | 'decrypt', key: Uint8Array, iv: Uint8Array, aad: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
  const k = await crypto.subtle.importKey('raw', key as unknown as BufferSource, { name: 'AES-GCM' }, false, [mode]);
  const alg = { name: 'AES-GCM', iv: iv as unknown as BufferSource, additionalData: aad as unknown as BufferSource };
  return new Uint8Array(mode === 'encrypt' ? await crypto.subtle.encrypt(alg, k, data as unknown as BufferSource) : await crypto.subtle.decrypt(alg, k, data as unknown as BufferSource));
}
const sleep = (ms: number) => new Promise((res) => setTimeout(res, ms));

// ---------- the move code ----------

export interface MoveCode { token: string; xPub: Uint8Array; kemHash: Uint8Array; veilId: string }

export function formatMoveCode(c: MoveCode): string {
  return `${MOVE_CODE_PREFIX}${b64url(concat(unb64url(c.token), c.xPub, c.kemHash))}:${c.veilId}`;
}

/** Parse a move code (scanned or pasted). Throws a plain message for anything else. */
export function parseMoveCode(raw: string): MoveCode {
  const s = String(raw ?? '').trim();
  const bad = () => new Error('That isn’t a Vardum move code. On your new phone open Settings → Receive from old phone, then scan the code it shows.');
  if (!s.startsWith(MOVE_CODE_PREFIX)) throw bad();
  const m = s.slice(MOVE_CODE_PREFIX.length).match(/^([A-Za-z0-9_-]{107}):([1-9A-HJ-NP-Za-km-z]{8,64})$/);
  if (!m) throw bad();
  let b: Uint8Array;
  try { b = unb64url(m[1]); } catch { throw bad(); }
  if (b.length !== 80) throw bad();
  return { token: b64url(b.slice(0, 16)), xPub: b.slice(16, 48), kemHash: b.slice(48, 80), veilId: m[2] };
}

// ---------- the transcript ----------

async function transcriptHash(c: MoveCode, ePub: Uint8Array, kemCt: Uint8Array): Promise<Uint8Array> {
  return sha256(lp([utf8(LABEL), utf8(c.token), c.xPub, c.kemHash, utf8(c.veilId), ePub, kemCt]));
}
async function finalHash(th: Uint8Array, commitment: Uint8Array): Promise<Uint8Array> {
  return sha256(lp([utf8(LABEL + '/final'), th, commitment]));
}
/** the 6-digit check code both phones show ("123 456") */
export async function moveCheckCode(final: Uint8Array): Promise<string> {
  const h = await sha256(lp([utf8(LABEL + '/sas'), final]));
  const n = (((h[0] << 24) | (h[1] << 16) | (h[2] << 8) | h[3]) >>> 0) % 1_000_000;
  const d = String(n).padStart(6, '0');
  return `${d.slice(0, 3)} ${d.slice(3)}`;
}
function offerSigMessage(final: Uint8Array): Uint8Array { return concat(utf8('vardum-move-offer-v1:'), final); }
/**
 * b75r1 (audit PX-01): what the NEW phone signs with its identity key — its half of the
 * transcript: the token, its X25519 key, the hash of its ML-KEM key and the Vardum ID.
 * Every value the old phone encrypts to is covered, so only a phone holding the seed
 * can make a code the old phone will answer. Signing at `open` (not after the offer)
 * costs no extra round trip and lets the old phone refuse before it builds or posts
 * anything. A replayed signature is useless: it names keys whose private halves only
 * that new phone ever held (and wipes when its screen closes).
 */
export async function receiverSigMessage(c: MoveCode): Promise<Uint8Array> {
  return concat(utf8('vardum-move-receiver-v1:'), await sha256(lp([utf8(LABEL + '/receiver'), utf8(c.token), c.xPub, c.kemHash, utf8(c.veilId)])));
}
async function deriveKeys(dh: Uint8Array, ss: Uint8Array, th: Uint8Array): Promise<{ kEnc: Uint8Array; kAck: Uint8Array }> {
  const okm = await hkdf(concat(dh, ss), th, LABEL + ' keys', 64);
  return { kEnc: okm.slice(0, 32), kAck: okm.slice(32, 64) };
}
async function ackFor(kAck: Uint8Array, final: Uint8Array, ackNonceHex: string): Promise<string> {
  return hex(await hmacSha256(kAck, concat(utf8('vardum-move-ack-v1:'), final, unhex(ackNonceHex))));
}

interface Offer { e: string; kc: string; c: string; sig: string }
function parseOffer(raw: unknown): Offer | null {
  let o: unknown = raw;
  if (typeof raw === 'string') { try { o = JSON.parse(raw); } catch { return null; } }
  const q = o as Partial<Offer> | null;
  if (!q || typeof q.e !== 'string' || typeof q.kc !== 'string' || typeof q.c !== 'string' || typeof q.sig !== 'string') return null;
  if (!/^[0-9a-f]{64}$/.test(q.c)) return null;
  return { e: q.e, kc: q.kc, c: q.c, sig: q.sig };
}

// ====================================================================
// NEW PHONE (receiver)
// ====================================================================

/** In memory only. The private keys never touch storage; closing the screen ends the move. */
export interface ReceiveSession {
  code: string;
  token: string;
  veilId: string;
  ikPubB64: string;
  xPriv: Uint8Array;
  xPub: Uint8Array;
  kemPub: string;
  kemPriv: string;
  kemHash: Uint8Array;
  /** set by waitForOffer */
  accepted?: { th: Uint8Array; final: Uint8Array; commitment: string; kEnc: Uint8Array; kAck: Uint8Array; sas: string };
  closed?: boolean;
}

export async function startReceive(deps: Pick<TransferDeps, 'relay' | 'vault'>): Promise<ReceiveSession> {
  const me = (await deps.vault.load()) as { veilId?: string; ikPubB64?: string; ikSeedB64?: string } | null;
  // b75r1 (audit PX-01): the identity PRIVATE key is needed — the old phone answers only
  // a code signed with it. A vault holding only the public key (all an outsider can get)
  // can't receive.
  if (!me?.veilId || !me.ikPubB64 || !me.ikSeedB64) {
    throw new Error('Restore your Vardum ID on this phone with your 24 words first, then receive your chats. (ref TF-10)');
  }
  const xPriv = x25519.utils.randomPrivateKey();
  const xPub = x25519.getPublicKey(xPriv);
  const kem = await mlkemKeypair();
  const kemHash = await sha256(fromB64(kem.pub));
  const token = b64url(randomBytes(16));
  const rsig = await ikSign(me.ikSeedB64, toB64(await receiverSigMessage({ token, xPub, kemHash, veilId: me.veilId })));
  // b75r3 (audit I-1): veil_id — the relay then takes only an offer this ID's identity key signed
  await deps.relay.invoke('deviceLink', { action: 'open', token, kem_pub: kem.pub, rsig, veil_id: me.veilId });
  return {
    code: formatMoveCode({ token, xPub, kemHash, veilId: me.veilId }),
    token, veilId: me.veilId, ikPubB64: me.ikPubB64, xPriv, xPub, kemPub: kem.pub, kemPriv: kem.priv, kemHash,
  };
}

/** Wait for the old phone's offer; return the check code to show. Refuses an offer
 *  not signed by this phone's own identity key over this session's transcript. */
export async function waitForOffer(
  deps: Pick<TransferDeps, 'relay'>,
  s: ReceiveSession,
  opts: { intervalMs?: number; timeoutMs?: number; isCancelled?: () => boolean } = {},
): Promise<{ sas: string }> {
  const interval = opts.intervalMs ?? 4000;
  const deadline = Date.now() + (opts.timeoutMs ?? MOVE_LINK_MS + 30_000);
  while (Date.now() < deadline && !s.closed && !opts.isCancelled?.()) {
    let d: Record<string, unknown> = {};
    try { d = relayData(await deps.relay.invoke('deviceLink', { action: 'poll', token: s.token })); } catch { /* transient */ }
    if (d.state === 'expired') break;
    if ((d.state === 'offered' || d.state === 'ready') && d.offer) {
      const offer = parseOffer(d.offer);
      if (!offer) throw new Error('The answer from your old phone was damaged. Start again on both phones. (ref TF-11)');
      const code: MoveCode = { token: s.token, xPub: s.xPub, kemHash: s.kemHash, veilId: s.veilId };
      let ePub: Uint8Array; let kemCt: Uint8Array;
      try { ePub = fromB64(offer.e); kemCt = fromB64(offer.kc); } catch { throw new Error('The answer from your old phone was damaged. Start again on both phones. (ref TF-11)'); }
      const th = await transcriptHash(code, ePub, kemCt);
      const final = await finalHash(th, unhex(offer.c));
      // b75 (audit XF-2): only a phone holding THIS Vardum ID's identity key can answer.
      // Someone who photographed the code can post an offer, but not this signature.
      if (!(await verifyWithIk(s.ikPubB64, toB64(offerSigMessage(final)), offer.sig).catch(() => false))) {
        throw new Error('A phone that doesn’t hold your Vardum ID answered this code, so nothing will be accepted. Start again on both phones. (ref TF-12)');
      }
      const dh = x25519Dh(s.xPriv, offer.e);
      const ss = await mlkemDecap(s.kemPriv, offer.kc);
      const { kEnc, kAck } = await deriveKeys(dh, ss, th);
      wipe(dh, ss);
      const sas = await moveCheckCode(final);
      s.accepted = { th, final, commitment: offer.c, kEnc, kAck, sas };
      return { sas };
    }
    await sleep(interval);
  }
  throw new Error(s.closed || opts.isCancelled?.() ? 'Cancelled.' : 'Your old phone didn’t answer in time. Start again on both phones. (ref TF-13)');
}

/** After waitForOffer: wait for the bundle, check it, import it, send the ack. */
export async function receiveMove(
  deps: TransferDeps,
  s: ReceiveSession,
  opts: {
    /** b70 (audit VAR-05): the identity key this phone has pinned for a Vardum ID (null = not pinned) */
    pinnedIk?: (veilId: string) => Promise<string | null>;
    intervalMs?: number; timeoutMs?: number; isCancelled?: () => boolean;
  } = {},
): Promise<DeviceTransferResult> {
  deps = pinDeps(deps); // b70 (re-review 11): a wipe while this waits on the relay stops its writes
  const acc = s.accepted;
  if (!acc) throw new Error('No answer from your old phone yet.');
  const interval = opts.intervalMs ?? 4000;
  const deadline = Date.now() + (opts.timeoutMs ?? MOVE_LINK_MS + 30_000);
  let blob = '';
  while (!blob && Date.now() < deadline && !s.closed && !opts.isCancelled?.()) {
    let d: Record<string, unknown> = {};
    try { d = relayData(await deps.relay.invoke('deviceLink', { action: 'poll', token: s.token })); } catch { /* transient */ }
    if (d.state === 'expired') break;
    if (d.state === 'ready') {
      const r = relayData(await deps.relay.invoke('deviceLink', { action: 'fetch', token: s.token }));
      // b74 (VAR-20) / b75: the relay hands the bundle back inline; a relay-chosen file
      // link is never followed (b75 rows always hold a relay blob)
      if (typeof r.blob !== 'string' || !r.blob) throw new Error('The transfer could not be collected. Start again on both phones. (ref DL-05)');
      blob = r.blob;
      break;
    }
    await sleep(interval);
  }
  if (!blob) throw new Error(s.closed || opts.isCancelled?.() ? 'Cancelled.' : 'Your old phone didn’t send the chats in time. Nothing was imported. Start again on both phones. (ref TF-14)');

  let bundle: TransferBundleV3;
  try {
    // the bundle must be exactly the one the old phone committed to in its signed offer
    if (!ctEqHex(hex(await sha256(utf8(blob))), acc.commitment)) throw new Error('commitment');
    const env = JSON.parse(blob) as { iv: string; ct: string };
    const pt = await aesGcm('decrypt', acc.kEnc, fromB64(env.iv), acc.th, fromB64(env.ct));
    // b76 (padding): stripped strictly — a frame whose length doesn't match exactly is refused (DL-05)
    const inner = unpadBlob(pt);
    const parsed = JSON.parse(new TextDecoder().decode(inner)) as Partial<TransferBundleV3>;
    wipe(pt);
    if (parsed.v !== 3 || !parsed.sessions || typeof parsed.sessions !== 'object' || typeof parsed.ackNonce !== 'string' || !/^[0-9a-f]{64}$/.test(parsed.ackNonce)) throw new Error('shape');
    bundle = parsed as TransferBundleV3;
  } catch {
    throw new Error('The transfer could not be opened on this phone, so nothing was imported. Start again on both phones. (ref DL-05)');
  }
  // b70 (audit VAR-05): the chats are imported only under the Vardum ID they were made
  // with. The offer is signed by this ID's identity key, and the bundle names it too.
  if (bundle.veilId !== s.veilId) {
    throw new Error('This transfer belongs to a different Vardum ID from the one on this phone. Nothing was imported, and your old phone keeps its chats. (ref DL-08)');
  }

  let importedCount = 0;
  let skippedExisting = 0;
  let allSaved = true; // Batch G (R5-3-03): the ack goes out only when every save landed
  let conflicts = 0;
  for (const [sessToken, state] of Object.entries(bundle.sessions)) {
    // b77z2 (Z-7): each chat is imported on its per-token chain. The state save let a sync pass
    // (or a send) start for the chat at once, beside the carry writes below, and a pass writes the
    // whole pending-burn queue back at its end: a pass that read the queue before the carried
    // burns landed dropped them. The chain makes a pass wait for the whole import of the chat.
    // b77m (audit VAR-26): a token that can't be a storage key (it could name another chat's keys) is not imported
    if (!isStoreToken(sessToken)) { skippedExisting += 1; continue; }
    await serializeRatchetSend(sessToken, async () => {
      if (await deps.sessions.load(sessToken)) { skippedExisting += 1; return; }
      // b70 (VAR-05): a chat sealed as being with a pinned contact must carry that contact's pinned key
      const peer = state as { peerVeilId?: unknown; peerIkPub?: unknown };
      if (opts.pinnedIk && typeof peer.peerVeilId === 'string' && peer.peerVeilId) {
        const pinned = await opts.pinnedIk(peer.peerVeilId).catch(() => null);
        if (pinned && pinned !== peer.peerIkPub) { conflicts += 1; skippedExisting += 1; return; }
      }
      // b75r3 (audit I-3): what the old phone carried for this chat (history off here keeps the
      // unshown messages in memory until the chat is opened, as for any other)
      const c = bundle.carry && Object.prototype.hasOwnProperty.call(bundle.carry, sessToken) ? bundle.carry[sessToken] : null;
      // b77z2 (Z-7): the burns still owed are written BEFORE the state (a death between the two used
      // to leave the chat here with its owed burns gone); a refused save takes them back out
      const burns = c && typeof c === 'object' && Array.isArray(c.burns) ? c.burns.filter((b) => b && typeof b.id === 'string') : [];
      if (burns.length) {
        const r = await deps.sessions.setPendingBurns(sessToken, burns).catch(() => ({ saved: false, full: false }));
        if (!r.saved) allSaved = false;
      }
      let landed = false;
      if (!(await deps.sessions.save(sessToken, state))) allSaved = false;
      else landed = true;
      if (!landed) {
        if (burns.length) await deps.sessions.setPendingBurns(sessToken, []).catch(() => undefined);
      } else {
        importedCount += 1;
        if (c && typeof c === 'object') {
          const unshown = Array.isArray(c.unshown) ? c.unshown.filter((m) => m && typeof m.id === 'string' && !m.mine).map((m) => ({ ...m, openedAt: undefined })) : [];
          if (unshown.length && (await deps.sessions.cacheMessages(sessToken, unshown).catch(() => false)) === false) allSaved = false;
          if (Number.isSafeInteger(c.unread) && (c.unread as number) > 0) await deps.sessions.bumpUnread(sessToken, Math.min(c.unread as number, 10_000)).catch(() => undefined);
          // b77 (sealed sender): the inbound's cursor and open state (this phone binds its own wake reference)
          const ms = deps.sessions as Partial<Pick<SessionStore, 'setMboxState' | 'setOutbox'>>;
          if (c.mbox && typeof c.mbox === 'object' && ms.setMboxState) {
            const ok = await ms.setMboxState(sessToken, {
              seq: Math.max(0, Math.floor(Number(c.mbox.seq) || 0)), opened: c.mbox.opened === true, openAt: Number(c.mbox.openAt) || 0,
              // b77r2 (audit R2-A-2 / R2-A-3): a carried `retired` (an older phone's bundle) is
              // ignored; `everOpened` is carried (and an opened inbound counts as ever opened)
              verified: c.mbox.verified === true, rvEnded: c.mbox.rvEnded === true, pushBound: false,
              ...(c.mbox.everOpened === true || c.mbox.opened === true ? { everOpened: true } : {}),
            }).catch(() => false);
            if (!ok) allSaved = false;
          }
          if (Array.isArray(c.outbox) && c.outbox.length && ms.setOutbox) {
            const items = c.outbox.filter((o) => o && typeof o.ciphertext === 'string' && typeof o.header === 'string' && typeof o.iv === 'string');
            if (items.length && !(await ms.setOutbox(sessToken, items).catch(() => false))) allSaved = false;
          }
        }
      }
    });
  }
  if (deps.storage) await mergeContactSeen(deps.storage, bundle.contactSeen).catch(() => undefined);

  // Batch H (R6-1-04): skipped chats (a copy was already here, or a key conflict)
  // mean the old phone must keep its copy — no ack
  const ackHeld = skippedExisting > 0 ? 'already-here' as const : null;
  let acked = false;
  if (allSaved && !ackHeld) {
    // b75 (audit XF-1): the proof needs the receiver's private keys AND the decrypted bundle
    const ack = await ackFor(acc.kAck, acc.final, bundle.ackNonce);
    for (let i = 0; i < 3 && !acked; i++) {
      try { await deps.relay.invoke('deviceLink', { action: 'ack', token: s.token, ack }); acked = true; } catch { /* retry */ }
    }
    if (!acked) console.log('[veil-transfer] import done, but the relay did not take the acknowledgement — the old phone keeps its copy');
  }
  closeReceive(s);
  return {
    sessionCount: Object.keys(bundle.sessions).length,
    importedCount,
    skippedExisting,
    incomplete: !allSaved,
    acked,
    ...(conflicts ? { conflicts } : {}),
    ...(ackHeld ? { ackHeld } : {}),
  };
}

/** forget the in-memory keys (the code is useless from here on) */
export function closeReceive(s: ReceiveSession): void {
  s.closed = true;
  wipe(s.xPriv, s.accepted?.kEnc, s.accepted?.kAck);
  s.kemPriv = '';
}

/** the user closed the receive screen: drop the keys and the relay row */
export async function cancelReceive(deps: Pick<TransferDeps, 'relay'>, s: ReceiveSession): Promise<void> {
  closeReceive(s);
  try { await deps.relay.invoke('deviceLink', { action: 'cancel', token: s.token }); } catch { /* it expires on its own */ }
}

// ====================================================================
// OLD PHONE (sender)
// ====================================================================

export interface PreparedMove {
  token: string;
  /** the check code the user compares with the new phone */
  sas: string;
  sessionTokens: string[];
  sessionCount: number;
  /** b71 (review P-07): group sessions left on this phone */
  groupsKept: number;
  /** encrypted bundle, held in memory until the user confirms */
  envelope: string;
  /** what the receiver's ack must equal */
  expectedAck: string;
}

/** Old phone, step 1: read the new phone's code, build and encrypt the bundle, post the offer.
 *  Nothing secret leaves this phone here. */
export async function prepareMove(deps: TransferDeps, rawCode: string): Promise<PreparedMove> {
  deps = pinDeps(deps); // b70 (re-review 11)
  const code = parseMoveCode(rawCode);
  const me = (await deps.vault.load()) as { veilId?: string; ikSeedB64?: string; ikPubB64?: string } | null;
  if (!me?.veilId || !me.ikSeedB64 || !me.ikPubB64) throw new Error('This phone has no Vardum ID to move from. (ref TF-01)');
  if (code.veilId !== me.veilId) {
    throw new Error(`That phone uses a different Vardum ID (${code.veilId}). On the new phone, restore your own 24 words first, then show its code again. (ref TF-02)`);
  }
  // the ML-KEM key is too big for a QR: the relay holds it, the code holds its hash
  const gone = 'That code has expired, or another phone already answered it. Show a fresh code on the new phone. (ref TF-03)';
  let peek: Record<string, unknown>;
  try { peek = relayData(await deps.relay.invoke('deviceLink', { action: 'peek', token: code.token })); } catch { throw new Error(gone); }
  const kemPub = typeof peek.kem_pub === 'string' ? peek.kem_pub : '';
  let kemOk = false;
  try { kemOk = !!kemPub && ctEqHex(hex(await sha256(fromB64(kemPub))), hex(code.kemHash)); } catch { kemOk = false; }
  if (!kemOk) throw new Error('That code doesn’t match what Vardum’s server holds for it, so nothing was sent. Show a fresh code on the new phone. (ref TF-04)');
  // b75r1 (audit PX-01): the new phone must prove it holds THIS Vardum ID's identity
  // private key. The code alone is public values (anyone can build one for an ID from
  // its public key), and the check code can't catch that — an outsider who made the
  // code really is an endpoint of the key agreement and shows the same digits. Checked
  // against this phone's own IK, before any chat is read, encrypted or posted.
  const rsig = typeof peek.rsig === 'string' ? peek.rsig : '';
  let receiverOk = false;
  try { receiverOk = !!rsig && await verifyWithIk(me.ikPubB64, toB64(await receiverSigMessage(code)), rsig); } catch { receiverOk = false; }
  if (!receiverOk) {
    throw new Error('That code didn’t come from a phone holding your Vardum ID, so nothing was sent. Only scan the code your own new phone shows after you restored your 24 words on it. (ref TF-07)');
  }

  // b71 (review P-07): a move never takes a group's sessions (spec §11.13)
  const groupSessionTokens = new Set<string>();
  if (deps.storage) {
    await loadGroupRecords(deps.storage);
    for (const gt of listGroupTokens(deps.storage)) {
      const r = groupRecord(deps.storage, gt);
      if (r?.sessionToken) groupSessionTokens.add(r.sessionToken);
      if (r?.seatToken) groupSessionTokens.add(r.seatToken);
    }
  }
  const tokens = (await deps.sessions.listTokens()).filter((t) => !groupSessionTokens.has(t));
  const sessions: Record<string, RatchetStateSerialized> = {};
  for (const token of tokens) {
    const state = await deps.sessions.load(token);
    if (state) sessions[token] = state;
  }
  if (!Object.keys(sessions).length) {
    throw new Error('There are no one-to-one chats on this phone to move. (ref TF-01)');
  }
  // b75r3 (audit I-3): a move used to drop messages opened here in the background but not yet
  // displayed (the ratchet keys for them are spent, so the new phone can never open them
  // again), the unread badge, and the relay burns this phone still owed. They travel now.
  const carry: Record<string, MoveCarry> = {};
  for (const token of Object.keys(sessions)) {
    const st = deps.sessions as Partial<Pick<SessionStore, 'cachedMessages' | 'getUnread' | 'pendingBurns' | 'mboxState' | 'outbox' | 'displayedMarks'>>;
    const unshown = ((await st.cachedMessages?.(token).catch(() => [])) ?? [])
      .filter((m) => !m.mine && !m.openedAt && !(m as { systemNote?: unknown }).systemNote);
    const unread = (await st.getUnread?.(token).catch(() => 0)) ?? 0;
    const burns = (await st.pendingBurns?.(token).catch(() => [])) ?? [];
    // b77z2 (Z-1): display marks no sync pass has merged yet travel inside the burns they flip
    const marks = (await st.displayedMarks?.(token).catch(() => null)) ?? null;
    if (marks?.size) for (const b of burns) if (b.displayed === false && marks.has(b.id)) b.displayed = true;
    // b77 (sealed sender): the mailbox cursor and open state, and any queued envelopes
    const m = await st.mboxState?.(token).catch(() => null);
    const mbox = m ? { seq: Math.max(0, Math.floor(Number(m.seq) || 0)), opened: !!m.opened, openAt: Number(m.openAt) || 0, ...(m.verified ? { verified: true } : {}), ...(m.rvEnded ? { rvEnded: true } : {}), ...(m.everOpened ? { everOpened: true } : {}) } : null;
    const outbox = (await st.outbox?.(token).catch(() => [])) ?? [];
    if (unshown.length || unread > 0 || burns.length || mbox || outbox.length) {
      carry[token] = { ...(unshown.length ? { unshown } : {}), ...(unread > 0 ? { unread } : {}), ...(burns.length ? { burns } : {}), ...(mbox ? { mbox } : {}), ...(outbox.length ? { outbox } : {}) };
    }
  }
  const bundle: TransferBundleV3 = {
    v: 3,
    veilId: me.veilId,
    sessions,
    ackNonce: hex(randomBytes(32)),
    ...(deps.storage ? { contactSeen: await readContactSeen(deps.storage) } : {}),
    ...(Object.keys(carry).length ? { carry } : {}),
  };

  // hybrid: X25519 (ephemeral, this move only) + ML-KEM-768, both to the receiver's keys
  const ePriv = x25519.utils.randomPrivateKey();
  const ePub = x25519.getPublicKey(ePriv);
  const dh = x25519Dh(ePriv, toB64(code.xPub));
  const enc = await mlkemEncap(kemPub);
  const kemCt = fromB64(enc.ct);
  const th = await transcriptHash(code, ePub, kemCt);
  const { kEnc, kAck } = await deriveKeys(dh, enc.secret, th);
  wipe(ePriv, dh, enc.secret);
  const iv = randomBytes(12);
  // b76 (padding, spec §8.3): the bundle is framed and padded inside the encryption (padBlob), so
  // the stored blob and its byte_length show only a size class (PADME above 32 KiB), not how
  // many chats or how much history moved
  const plain = padBlob(utf8(JSON.stringify(bundle)));
  const ct = await aesGcm('encrypt', kEnc, iv, th, plain);
  wipe(plain);
  const envelope = JSON.stringify({ iv: toB64(iv), ct: toB64(ct) });
  const commitment = await sha256(utf8(envelope));
  const final = await finalHash(th, commitment);
  const expectedAck = await ackFor(kAck, final, bundle.ackNonce);
  wipe(kEnc, kAck);
  const sig = await ikSign(me.ikSeedB64, toB64(offerSigMessage(final)));
  const offer: Offer = { e: toB64(ePub), kc: enc.ct, c: hex(commitment), sig };
  // b75r3 (audit I-1): a second, relay-checkable signature over the token alone. The relay can't
  // check `sig` (it never sees the code's X25519 key), so anyone who saw the code could answer
  // first and kill the move; with this it refuses an offer this Vardum ID didn't sign.
  const osig = await ikSign(me.ikSeedB64, toB64(utf8(MOVE_OFFER_RELAY_LABEL + code.token)));
  try {
    await deps.relay.invoke('deviceLink', { action: 'offer', token: code.token, offer: JSON.stringify(offer), osig });
  } catch {
    throw new Error('Another phone answered that code first, or it expired, so nothing was sent. Start again on both phones. (ref TF-06)');
  }
  return {
    token: code.token,
    sas: await moveCheckCode(final),
    sessionTokens: Object.keys(sessions),
    sessionCount: Object.keys(sessions).length,
    groupsKept: groupSessionTokens.size,
    envelope,
    expectedAck,
  };
}

/**
 * Old phone, step 2 (the user said the codes match): record the move, then send.
 * b75 (audit XF-4): from the moment the record is written the moved chats stay paused
 * here until the receiver's proof arrives or the user explicitly keeps them here —
 * even if this call fails part-way (the relay may have the bundle anyway).
 */
export async function confirmMove(deps: TransferDeps, p: PreparedMove): Promise<void> {
  deps = pinDeps(deps);
  if (!deps.storage) throw new Error('Could not prepare the transfer on this phone. (ref TF-05)');
  // Batch E (F-3): recorded BEFORE anything is sent, so an app kill can't leave the chats on both phones
  await savePendingTransfer(deps.storage, { token: p.token, sessionTokens: p.sessionTokens, createdAt: Date.now(), ack: p.expectedAck, sas: p.sas });
  const uri = await deps.relay.uploadPrivateFile({ bytes: utf8(p.envelope), name: 'veil-transfer' });
  try {
    await deps.relay.invoke('deviceLink', { action: 'store', token: p.token, container_uri: uri, byte_length: p.envelope.length });
  } catch (e) {
    // b75 (audit RL-04): a bundle the relay refused to link is deleted, not left for the 49 h backstop
    await (deps.relay as { deleteBlob?: (u: string) => Promise<unknown> }).deleteBlob?.(uri).catch(() => undefined);
    throw e;
  }
  p.envelope = '';
}

/** Old phone: the user backed out before confirming (or the codes differed). Nothing was sent. */
export async function cancelMove(deps: Pick<TransferDeps, 'relay'>, p: PreparedMove): Promise<void> {
  p.envelope = '';
  try { await deps.relay.invoke('deviceLink', { action: 'cancel', token: p.token }); } catch { /* it expires on its own */ }
}

// ---------- the pending-move record (old phone) ----------

export const PENDING_TRANSFER_KEY = 'veil_pending_transfer_v1';
export interface PendingTransfer {
  token: string; sessionTokens: string[];
  /** when the user confirmed and the bundle was sent */
  createdAt: number;
  /** the receiver's expected ack (hex); only an answer carrying it retires the chats */
  ack: string;
  /** the check code the user confirmed — shown again as "who collected it" */
  sas?: string;
  /** when the user last answered "Not now" to the keep-or-remove question */
  askedAt?: number;
}

// Batch F (round-4 review R4-4-13): one record PER MOVE.
function cleanPending(p: unknown): PendingTransfer | null {
  const q = p as PendingTransfer | null;
  if (!q || typeof q.token !== 'string' || !q.token || !Array.isArray(q.sessionTokens)) return null;
  // b75: every record carries the receiver's expected ack (b74's ack-less rule is gone)
  if (typeof q.ack !== 'string' || !/^[0-9a-f]{64}$/.test(q.ack)) return null;
  return {
    token: q.token, sessionTokens: q.sessionTokens.filter((t) => typeof t === 'string'), createdAt: Number(q.createdAt) || 0, ack: q.ack,
    ...(typeof q.sas === 'string' && /^\d{3} \d{3}$/.test(q.sas) ? { sas: q.sas } : {}),
    ...(Number(q.askedAt) > 0 ? { askedAt: Number(q.askedAt) } : {}),
  };
}

/** every pending move on this phone (a damaged record reads as none) */
export async function loadPendingTransfers(storage: VeilStorage): Promise<PendingTransfer[]> {
  try {
    const raw = await storage.get(PENDING_TRANSFER_KEY);
    if (!raw) return [];
    const v = JSON.parse(raw) as unknown;
    if (Array.isArray(v)) return v.map(cleanPending).filter((x): x is PendingTransfer => !!x);
    const one = cleanPending(v);
    return one ? [one] : [];
  } catch {
    return [];
  }
}

/** Batch E (F-3): throws when the record can't be written, so nothing is sent that this phone could not finish. */
export async function savePendingTransfer(storage: VeilStorage, p: PendingTransfer): Promise<void> {
  const all = (await loadPendingTransfers(storage)).filter((x) => x.token !== p.token);
  all.push(p);
  if (!(await storage.set(PENDING_TRANSFER_KEY, JSON.stringify(all)))) {
    throw new Error('Could not prepare the transfer on this phone (storage is full or locked). Try again. (ref TF-05)');
  }
}

export async function clearPendingTransfer(storage: VeilStorage, token: string): Promise<void> {
  const rest = (await loadPendingTransfers(storage)).filter((x) => x.token !== token);
  if (rest.length) await storage.set(PENDING_TRANSFER_KEY, JSON.stringify(rest));
  else await storage.remove(PENDING_TRANSFER_KEY);
}

/** Batch H (R6-1-11): remember "Not now", so the question waits for the next unlock */
export async function markTransferAsked(storage: VeilStorage, token: string): Promise<void> {
  const all = await loadPendingTransfers(storage);
  const p = all.find((x) => x.token === token);
  if (!p) return;
  p.askedAt = Date.now();
  await storage.set(PENDING_TRANSFER_KEY, JSON.stringify(all));
}

/** the first pending move (kept for older callers) */
export async function loadPendingTransfer(storage: VeilStorage): Promise<PendingTransfer | null> {
  return (await loadPendingTransfers(storage))[0] ?? null;
}

/** b75 (audit XF-1): who collected the last move, and when (this phone's clock, at the proof) */
export const LAST_MOVE_KEY = 'veil_last_move_v1';
export interface LastMove { at: number; count: number; sas?: string }
export async function loadLastMove(storage: VeilStorage): Promise<LastMove | null> {
  try {
    const v = JSON.parse((await storage.get(LAST_MOVE_KEY)) || 'null') as LastMove | null;
    return v && Number(v.at) > 0 ? { at: Number(v.at), count: Number(v.count) || 0, ...(typeof v.sas === 'string' ? { sas: v.sas } : {}) } : null;
  } catch { return null; }
}

/**
 * Old phone: finish a recorded move.
 * - `used` — the relay returned an ack equal to the expected one (only the receiver
 *   could compute it): the moved chats are retired here and the record cleared.
 * - `unconfirmed` — no proof, and the pause has reached MOVE_PAUSE_CAP_MS: the
 *   caller asks the user (keep here / remove here). `hint` is what the relay
 *   claims, which this phone can't verify.
 * - `waiting` — no proof yet, still inside the pause.
 * b75 (audit XF-3 / XF-4): the relay's "expired" or "fetched" never resumes or
 * retires anything; only the proof or the user does.
 */
export async function finishTransferMove(
  deps: { relay: Pick<VeilRelay, 'invoke'>; sessions: Pick<SessionStore, 'remove'>; storage: VeilStorage },
  pending: PendingTransfer,
  opts: { intervalMs?: number; timeoutMs?: number; now?: () => number } = {},
): Promise<{ state: 'used' | 'waiting' | 'unconfirmed'; retired: number; at?: number; hint?: 'not-collected' | 'collected' }> {
  const interval = opts.intervalMs ?? 5000;
  const now = opts.now ?? Date.now;
  const deadline = now() + (opts.timeoutMs ?? MOVE_PAUSE_CAP_MS);
  let hint: 'not-collected' | 'collected' | undefined;
  for (;;) {
    try {
      const d = relayData(await deps.relay.invoke('deviceLink', { action: 'status', token: pending.token }));
      if (d.state === 'used' && typeof d.ack === 'string' && ctEqHex(d.ack, pending.ack)) {
        const retired = await retireTransferredSessions({ sessions: deps.sessions as SessionStore }, pending.sessionTokens);
        await clearPendingTransfer(deps.storage, pending.token);
        const at = now();
        await deps.storage.set(LAST_MOVE_KEY, JSON.stringify({ at, count: retired, ...(pending.sas ? { sas: pending.sas } : {}) } satisfies LastMove)).catch(() => false);
        return { state: 'used', retired, at };
      }
      if (d.state === 'used') console.log('[veil-transfer] the relay says "used" without the new phone’s proof — chats kept');
      hint = d.state === 'expired' ? 'not-collected' : d.state === 'fetched' || d.state === 'used' ? 'collected' : hint;
    } catch { /* transient — keep waiting */ }
    if (now() >= pending.createdAt + MOVE_PAUSE_CAP_MS) return { state: 'unconfirmed', retired: 0, ...(hint ? { hint } : {}) };
    if (now() >= deadline) return { state: 'waiting', retired: 0 };
    await sleep(interval);
  }
}

/** The user chose "Keep using them here" (no proof arrived): end the move; the caller unpauses. */
export async function keepMovedChatsHere(deps: { relay: Pick<VeilRelay, 'invoke'>; storage: VeilStorage }, pending: PendingTransfer): Promise<void> {
  try { await deps.relay.invoke('deviceLink', { action: 'cancel', token: pending.token }); } catch { /* best effort: the bundle can't be opened without the new phone's keys */ }
  await clearPendingTransfer(deps.storage, pending.token);
}

/** The user chose "Remove from this phone" (no proof arrived, they checked the new phone). */
export async function removeMovedChatsHere(deps: { sessions: Pick<SessionStore, 'remove'>; storage: VeilStorage }, pending: PendingTransfer): Promise<number> {
  const n = await retireTransferredSessions({ sessions: deps.sessions as SessionStore }, pending.sessionTokens);
  await clearPendingTransfer(deps.storage, pending.token);
  return n;
}

/**
 * Batch C (B5): the old phone retires the moved chats — their ratchet states, caches and
 * per-chat keys are overwritten and removed, so two phones never hold (and fork) the
 * same session. The identity stays.
 */
export async function retireTransferredSessions(deps: Pick<TransferDeps, 'sessions'>, sessionTokens: string[]): Promise<number> {
  let n = 0;
  for (const t of sessionTokens) {
    try { await deps.sessions.remove(t); n += 1; } catch { /* keep going — best effort per chat */ }
  }
  return n;
}
