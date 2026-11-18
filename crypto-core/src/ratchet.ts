/**
 * @veil/crypto-core — veil-ratchet-8 session engine (b54 Batch A; Batch C, b74 and b77 protocol bumps).
 *
 * b77 (veil-ratchet-8): the header travels ENCRYPTED. The signed JSON header of ratchet-7 is
 * framed to a fixed size and sealed with AES-GCM under the sending chain's header key (from
 * the same root as its epoch key), plus a small tag under the per-direction session header
 * key that carries only the epoch number. Every 1:1 header string has the same length; the
 * relay sees no ratchet pub, counter, epoch or PQ step (spec §4.2).
 *
 * Session setup (PQXDH-style, two entry families):
 *   strict invite  createSession / joinSession / completeHandshake
 *                  X25519 session DH + ML-KEM-768 encapsulation + the invite
 *                  link secret `k` (fragment-only, never sent to the relay)
 *   one-tap contact createContactSession / acceptContactSession / completeHandshake
 *                  ephemeral X25519 vs the peer's IK-signed SPK + ML-KEM-768
 *                  encapsulation to the peer's IK-signed PQ prekey
 * Post-quantum is MANDATORY: a missing or malformed PQ key, ciphertext or
 * keygen failure aborts the handshake (no classical fallback).
 *
 * After setup: the Signal Double Ratchet (rev. 4) over X25519 — KDF_RK =
 * HKDF-SHA256(salt = RK, ikm = DH_out || PQ_secret), KDF_CK = HMAC(ck, 0x01/0x02),
 * skipped-key store, MAX_SKIP guards — with an ML-KEM-768 secret mixed into
 * every ratchet step (per-step PQ re-key). Every header is signed over ALL its
 * fields (version, ratchet pub, both counters, epoch, PQ step pub and ciphertext;
 * b74, VAR-09) twice: `sig` under the sender's EPOCH key, re-derived from the root
 * at every DH step so it heals (b75, RT-5), and `ssig` under the per-direction
 * SESSION key derived once from rk0, which only tells "out of sync" from junk.
 * (b75r3 comment fix: this said only the ratchet pub and PQ step pub were signed,
 * under one session key — the veil-ratchet-6 / b74 picture.)
 *
 * Fingerprint: transcriptFingerprint over every public handshake value plus
 * SHA-256(shared) (kdf.ts), so substitution or downgrade is user-visible.
 *
 * X25519 runs on @noble/curves directly (raw 32-byte keys, b64 on the wire).
 */

import { toB64, fromB64, utf8, fromUtf8Strict } from './bytes';
import { hkdf, hmacSha256, sha256, combine, transcriptFingerprint } from './kdf';
import { mlkemKeypair, mlkemEncap, mlkemDecap } from './mlkem';
import { padPlaintext, unpadPlaintext } from './padding';
import { deriveDelivery, type DeliveryCaps } from './delivery'; // b77 sealed sender (the only hook here: the shared root)
import { ed25519, x25519, edwardsToMontgomeryPub, edwardsToMontgomeryPriv } from '@noble/curves/ed25519';
import {
  RATCHET_PROTOCOL_LATEST, RATCHET_PROTOCOL_SUPPORTED, ROOT_KEY_INFO, RK0_SALT_PREFIX, RK0_INFO,
  PP_SALT_PREFIX, PP_INFO, RATCHET_SIG_INFO, RATCHET_HEADER_SIG_LABEL, CONTACT_WRITE_INFO, FINGERPRINT_LABEL,
  RATCHET_EPOCH_SIG_INFO, RATCHET_HEADER_SESSION_SIG_LABEL,
  MLKEM768_PUB_BYTES, MLKEM768_CT_BYTES, OPK_ID_RE,
  RATCHET_HEADER_KEY_LABEL, RATCHET_HEADER_SESSION_KEY_LABEL, HEADER_FRAME_BYTES, HEADER_PREFIX,
  HEADER_SEALED_BYTES, HEADER_STRING_LENGTH, isSealedHeaderString,
} from './constants';

const MAX_COUNTER_GAP = 500;   // max skip ahead before "desynchronised"
// b70 (audit L-1): as many as a chain may skip, so a relay that delivers the
// newest message first can no longer make older ones undecryptable
const MAX_SKIPPED_PER_CHAIN = MAX_COUNTER_GAP;
// b71: across chains, room for four full chains (a DH step after a withheld run used to
// evict the whole older chain at 500 total)
const MAX_SKIPPED_TOTAL = 4 * MAX_COUNTER_GAP;
const MAX_PROCESSED_IDS = 500;
/** b74 (VAR-15): fingerprints of processed envelopes remembered for replay recognition */
const MAX_SEEN_DIGESTS = 512;
// b70 (audit L-3): 64 replaced epochs let an old signed header be replayed as a
// rotation candidate (CPU only); 512 keeps them refused for far longer
const MAX_SEEN_PUBS = 512; // replaced key epochs remembered for stale-header rejection
const MAX_MY_PUBS = 64; // own ratchet pubs remembered for own-echo rejection (bounded state)
/** b75 (audit RT-5): header verification keys of replaced peer epochs kept (for skipped
 *  keys and for recognising old copies); an epoch past this is classed as stale */
const MAX_PEER_SIG_PUBS = 64;
/** b77: header keys of my own last sending chains kept, only to recognise my echoed envelopes */
const MAX_MY_HKS = 8;

export type SessionRole = 'initiator' | 'responder';

/** b74 (VAR-15): thrown for an authenticated copy of a message this session already
 *  processed — a duplicate to drop silently, never a desync. */
export class ReplayedMessageError extends Error {
  constructor() {
    super('This message was already received.');
    this.name = 'ReplayedMessageError';
  }
}

/** b75 (audit RT-2): an envelope that does not authenticate against this session (bad or
 *  missing signatures, unreadable header, unknown protocol). Anyone on the path, the relay
 *  included, can make these, so the caller ledgers them as junk and never counts them
 *  towards "out of sync". */
export class JunkEnvelopeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'JunkEnvelopeError';
  }
}

/** b75 (audit RT-2, audit 2 V5): an authentic header whose message key is already used or
 *  gone (a copy of an old message, beyond the replay window or not; or a late message whose
 *  skipped key expired). No state change; ledgered, never a desync. */
export class StaleMessageError extends Error {
  constructor() {
    super('An old copy of a message (its key was already used or has expired).');
    this.name = 'StaleMessageError';
  }
}

/** b75 (audit RT-5): the header carries the peer's valid session signature but its epoch
 *  signature does not match the key this device derives: the peer's ratchet and this one
 *  have diverged (a restored or copied state on one side). Thrown before any DH or ML-KEM
 *  work. The session key never heals, so whoever stole a past copy of the state can make
 *  these too (spec §8.2); the relay alone cannot. */
export class OutOfSyncError extends Error {
  /** b77r1 (audit C-2): the epoch the header's session tag names, when the header was classed
   *  by that tag alone (no header key opened it, so there is no rp / n to key the failure on) */
  readonly epoch?: number;
  constructor(epoch?: number) {
    super('This message came from your contact, but this device\'s keys for the chat no longer match theirs — the session is out of sync.');
    this.name = 'OutOfSyncError';
    if (epoch !== undefined) this.epoch = epoch;
  }
}

/** b77p (audit VAR-04): the header authenticated but the BODY failed AES-GCM. The header signature
 *  covers the header only, so the relay can make this from any genuine envelope by flipping a bit of
 *  its ciphertext or IV: it is junk (a JunkEnvelopeError — ledgered, never counted towards "out of
 *  sync"), not proof that the two ratchets diverged. (A divergence of the roots surfaces as an
 *  OutOfSyncError: the epoch signatures stop matching.) No state change. */
export class TamperedBodyError extends JunkEnvelopeError {
  constructor() {
    super('The message body did not authenticate (changed in transit) — dropped as junk.');
    this.name = 'TamperedBodyError';
  }
}

/** b77p (audit VAR-04): message keys of headers whose body failed AES-GCM, kept in memory (bounded, a few
 *  minutes) so a relay that re-serves a tampered copy — the same one, or with other bits flipped, under
 *  any envelope id — costs one AES-GCM attempt, not a new candidate ratchet step (2 X25519, an ML-KEM
 *  keygen + encap + decap, up to MAX_COUNTER_GAP HMACs). Keyed by the session's verification key and the
 *  exact sealed header string. A copy that opens under the cached key goes the full normal path (the
 *  genuine body, late). Overwritten on eviction. */
const FAILED_BODY_MAX = 64;
const FAILED_BODY_TTL_MS = 15 * 60 * 1000;
/** b77s (audit 4 CR-1): exp = when the entry goes (at most FAILED_BODY_TTL_MS after it was cached, and never
 *  later than the skipped key it came from would have expired). Expired entries are swept on every decrypt and
 *  every save (they used to go only when the same header came back, so a key outlived the 7-day skipped-key
 *  limit and the chat itself). */
const failedBodyKeys = new Map<string, { mk: Uint8Array; exp: number }>();
/** b77s (audit 4 CR-1): bumped by clearFailedBodyCache — a decrypt that started before a clear never caches */
let failedBodyGen = 0;
function failedBodyKeyOf(state: RatchetState, headerStr: string): string {
  return `${state.sessionSigPubB64 ?? ''}|${headerStr}`;
}
function dropFailedBodyKey(k: string): void {
  const v = failedBodyKeys.get(k);
  if (v) { v.mk.fill(0); failedBodyKeys.delete(k); }
}
/** b77s (audit 4 CR-1): drop (and overwrite) every entry past its time */
function sweepFailedBodyCache(now = Date.now()): void {
  for (const [k, v] of [...failedBodyKeys]) if (!(v.exp > now)) dropFailedBodyKey(k);
}
function rememberFailedBody(k: string, mk: Uint8Array, gen: number, notAfter?: number): void {
  if (gen !== failedBodyGen) return; // b77s (audit 4 CR-1): the cache was cleared (a wipe) while this decrypt ran
  const now = Date.now();
  const exp = Math.min(now + FAILED_BODY_TTL_MS, notAfter ?? Number.POSITIVE_INFINITY);
  dropFailedBodyKey(k);
  if (!(exp > now)) return;
  failedBodyKeys.set(k, { mk: mk.slice(), exp });
  while (failedBodyKeys.size > FAILED_BODY_MAX) dropFailedBodyKey(failedBodyKeys.keys().next().value as string);
}
/** b77p (VAR-04): forget every cached key (tests; a wipe). b77s (audit 4 CR-1): every key is overwritten, and a
 *  decrypt still running when this is called can't put its key back afterwards (wipe generation). The app
 *  calls it on a wipe, a Nothing-at-Rest close and when a chat ends. */
export function clearFailedBodyCache(): void {
  failedBodyGen += 1;
  for (const k of [...failedBodyKeys.keys()]) dropFailedBodyKey(k);
}
/** b77p (VAR-04): how many tampered-header keys are cached (tests). b77s (audit 4 CR-1): expired ones swept first */
export function failedBodyCacheSize(): number { sweepFailedBodyCache(); return failedBodyKeys.size; }

/** Thrown when a stored session predates the current protocol (hard cut). */
export class LegacySessionError extends Error {
  constructor() {
    super('This chat used an older security protocol and has ended. Start a new chat.');
    this.name = 'LegacySessionError';
  }
}

export interface RatchetState {
  role: SessionRole;
  /** protocol tag written into headers — always RATCHET_PROTOCOL_LATEST */
  proto: string;
  /** replaced remote ratchet pubs — a header from an already-replaced epoch is rejected */
  seenRemotePubs: Set<string>;
  /** one-tap contact session (bootstraps from pinned IK + signed SPK / PQ prekey) */
  contact: boolean;
  ready: boolean;
  fingerprint: string | null;
  /** always 'hybrid' since veil-ratchet-6 (kept as a field so state is self-describing) */
  pq: 'hybrid';
  /** session handshake X25519 key (per session, not the Vardum identity) */
  hsPriv: Uint8Array;
  hsPub: string;
  bound: { initiatorPub: string; responderPub: string; responderRatchetPub?: string } | null;
  /** strict initiator: own handshake ML-KEM pair (pub kept for the transcript) */
  pqPub: string | null;
  pqPriv: string | null;
  /** per-step PQ re-key pair */
  pqStepPriv: string | null;
  pqStepPub: string | null;
  /** ct encapsulated to the peer's current step pub — travels in our next header */
  pendingPqCt: string | null;
  /** strict initiator: HKDF of the invite link secret `k`, mixed into the root */
  ppSecret: Uint8Array | null;
  /** relay write credential (strict: random, link fragment; contact: HKDF of the root) */
  writeSecret: string | null;
  /** Ed25519 header signing (null only on an initiator before completion).
   *  Batch C (B9): sigPrivB64 = MY direction's key; sigPubB64 = the PEER's direction's public key.
   *  b75 (audit RT-5): these are EPOCH keys. sigPrivB64 signs the headers of my current
   *  sending chain and sigPubB64 verifies the peer's current chain (remoteRatchetPub); both
   *  are re-derived from the root key at every DH ratchet step (epochSigSeed). */
  sigPrivB64: string | null;
  sigPubB64: string | null;
  /** b75 (audit RT-5): the per-direction SESSION keys derived once from the handshake root
   *  (what sigPrivB64/sigPubB64 were up to b74). They make the second header signature
   *  (ssig), which only classifies a failure as "out of sync" rather than junk. */
  sessionSigPrivB64: string | null;
  sessionSigPubB64: string | null;
  /** b75 (audit RT-5): epoch verification keys of replaced peer ratchet pubs (rp -> pub) */
  peerSigPubs: Map<string, string>;
  /** b75 (audit RT-5): my epoch number (how many sending ratchet pubs I have made); signed
   *  into every header as `e` */
  sendEpoch: number;
  /** b75: the peer's epoch number for remoteRatchetPub (0 = no chain from the peer yet) */
  remoteEpoch: number;
  /** Batch C (V-12): canonical dials bound into the fingerprint (initiator keeps its own until completion) */
  dials: string | null;
  /** Batch C (B9): contact initiator — values needed to finish the transcript at completion */
  contactPending: { initiatorIkPub: string; responderIkPub: string; ekPub: string; spkPub: string; pqPub: string; pqCt: string; sharedHash: string;
    /** b76 (one-time prekeys): the one-time pair the request used (absent: the signed prekeys only) */
    opk?: ContactOpkTranscript } | null;
  ratchetPriv: Uint8Array | null;
  ratchetPub: string;
  remoteRatchetPub: string | null;
  myPubs: Set<string>;
  rootKey: Uint8Array;
  sendChain: Uint8Array | null;
  recvChain: Uint8Array | null;
  sendCount: number;
  prevSendCount: number;
  recvCount: number;
  processedIds: Set<string>;
  skipped: Map<string, Map<number, Uint8Array>>;
  /** b70 (audit L-1): my real messages sent (the sender trailer's sequence) */
  sendSeq: number;
  /** b70 (audit info): when each skipped key was stored ("rp:n" -> ms); keys
   *  older than SKIPPED_KEY_MAX_AGE_MS are dropped, so a message that never
   *  arrives doesn't keep its key on the phone forever */
  skippedAt: Map<string, number>;
  /** b70 (audit L-1): the highest sequence number received from the peer */
  recvSeqMax: number;
  /** b74 (review VAR-15): digests of the headers of envelopes this session opened. A
   *  refused header that matches one is a copy (a relay replay): dropped quietly.
   *  b75 (audit RT-2): the digest is over the SIGNED fields (headerSigMessage), not the
   *  header string, so a re-spaced copy of a genuine header matches too. One that doesn't
   *  match but whose key is used or gone is a StaleMessageError (also never a desync). */
  seenDigests: Set<string>;
  /** b77 (veil-ratchet-8, spec §4.2): header key of my current sending chain (B64, 32 bytes) */
  hkSend: string | null;
  /** b77: header key of the peer's current chain (null until the peer has one) */
  hkRecv: string | null;
  /** b77: header keys of the peer's replaced chains (rp -> key), kept and evicted with peerSigPubs */
  peerHks: Map<string, string>;
  /** b77: header keys of my last MAX_MY_HKS sending chains (own-echo recognition only) */
  myHks: Set<string>;
  /** b77 (deviation from the design, spec §4.2): per-direction SESSION header-tag keys from rk0
   *  (mine / the peer's). They seal only the epoch number, so a header no header key opens
   *  is still classed as out of sync / an old copy / my own echo rather than junk. */
  shkSend: string | null;
  shkRecv: string | null;
}

// ---------- X25519 (@noble/curves) ----------

interface X25519Pair { priv: Uint8Array; pub: string }

function x25519Pair(): X25519Pair {
  const priv = x25519.utils.randomPrivateKey();
  return { priv, pub: toB64(x25519.getPublicKey(priv)) };
}

function x25519PubBytes(pubB64: string): Uint8Array {
  let b: Uint8Array;
  try { b = fromB64(pubB64); } catch { throw new Error('Malformed X25519 public key.'); }
  if (b.length !== 32) throw new Error('Malformed X25519 public key.');
  return b;
}

/** X25519 DH. noble rejects low-order points (all-zero output) — re-checked here.
 *  b71: exported (as x25519Dh) so the Wycheproof suite tests this exact function. */
export { dh as x25519Dh };
function dh(priv: Uint8Array, pubB64: string): Uint8Array {
  const out = x25519.getSharedSecret(priv, x25519PubBytes(pubB64));
  if (out.every((x) => x === 0)) throw new Error('Invalid X25519 shared secret.');
  return out;
}

// ---------- ML-KEM input checks (fail closed) ----------

function requirePqPub(pubB64: string | null | undefined, what: string): string {
  let ok = false;
  try { ok = !!pubB64 && fromB64(pubB64).length === MLKEM768_PUB_BYTES; } catch { ok = false; }
  if (!ok) throw new Error(`Post-quantum key missing or malformed (${what}) — refusing a downgraded session.`);
  return pubB64 as string;
}

function requirePqCt(ctB64: string | null | undefined, what: string): string {
  let ok = false;
  try { ok = !!ctB64 && fromB64(ctB64).length === MLKEM768_CT_BYTES; } catch { ok = false; }
  if (!ok) throw new Error(`Post-quantum ciphertext missing or malformed (${what}) — refusing a downgraded session.`);
  return ctB64 as string;
}

/**
 * PQ key generation, fail-closed: if ML-KEM key generation fails, the
 * operation aborts loudly and the caller retries. Nothing is ever sent
 * without its post-quantum binding.
 */
async function pqStepPair(): Promise<{ pub: string; priv: string }> {
  try {
    return await mlkemKeypair();
  } catch {
    throw new Error('Post-quantum key generation failed — aborted to avoid a security downgrade. Please retry.');
  }
}

// ---------- roots / chains ----------

/** KDF_RK: HKDF-64 -> {rk, ck}; salt = current root, ikm = DH_out (|| PQ secret). */
async function deriveRoot(salt: Uint8Array, ikm: Uint8Array, extra: Uint8Array | null): Promise<{ rk: Uint8Array; ck: Uint8Array }> {
  const material = extra ? combine(ikm, extra) : ikm;
  const out = await hkdf(material, salt, ROOT_KEY_INFO, 64);
  return { rk: out.slice(0, 32), ck: out.slice(32, 64) };
}

/** Handshake root rk0 = HKDF(shared, salt = `vardum-ratchet-6:<token>`, info = rk0). */
async function deriveRk0(shared: Uint8Array, token: string): Promise<Uint8Array> {
  return hkdf(shared, utf8(`${RK0_SALT_PREFIX}${token}`), RK0_INFO, 32);
}

/** b70 (re-review 4): a contact session's root also covers BOTH identity keys,
 *  so a request re-signed under another identity derives a different root (its
 *  key confirmation fails) — no unknown key-share. b71: the only form (v3 requests,
 *  which used a token-only root, are refused). */
function contactRk0Token(token: string, initiatorIkPub: string, responderIkPub: string, opkId?: string): string {
  // b71: always bound to both identity keys (no v3 form). b76 (one-time prekeys): and to the
  // one-time pair's id when the request used one (the fallback string is unchanged)
  return `${token}|ik2:${initiatorIkPub}:${responderIkPub}${opkId ? `|opk:${opkId}` : ''}`;
}

/** b76 (one-time prekeys): the public half of a one-time pair as it enters the transcript */
export interface ContactOpkTranscript { id: string; xPub: string; pqPub: string; pqCt: string }

function requireOpkId(id: unknown): string {
  if (typeof id !== 'string' || !OPK_ID_RE.test(id)) throw new Error('Malformed one-time prekey id.');
  return id;
}

/** Invite link secret term. `k` travels only in the link fragment, never to the relay. */
export async function derivePpSecret(inviteSecret: string, token: string): Promise<Uint8Array> {
  if (!inviteSecret) throw new Error('This invite link is missing its secret — ask for a fresh link.');
  return hkdf(utf8(inviteSecret), utf8(`${PP_SALT_PREFIX}${token}`), PP_INFO, 32);
}

/** One-tap contact relay write credentials (lowercase hex, 64 chars). */
async function contactWriteSecrets(root: Uint8Array): Promise<{ initiator: string; responder: string }> {
  const hex = (b: Uint8Array) => [...b].map((x) => x.toString(16).padStart(2, '0')).join('');
  const initiator = await hkdf(root, utf8(CONTACT_WRITE_INFO), 'initiator', 32);
  const responder = await hkdf(root, utf8(CONTACT_WRITE_INFO), 'responder', 32);
  return { initiator: hex(initiator), responder: hex(responder) };
}

interface ChainKeys { ck: Uint8Array; mk: Uint8Array }

/** KDF_CK: mk = HMAC(ck, 0x01), ck' = HMAC(ck, 0x02). */
async function advanceChain(chain: Uint8Array): Promise<ChainKeys> {
  const mk = await hmacSha256(chain, new Uint8Array([1]));
  const ck = await hmacSha256(chain, new Uint8Array([2]));
  return { ck, mk };
}

// ---------- fingerprints ----------

/**
 * Batch C (V-12): session dials, canonical form. Both peers bind the SAME
 * string into the fingerprint (and, for contact sessions, the IK-signed
 * request), so a relay that rewrites the burn / expiry dials on the session
 * row produces a visible fingerprint mismatch instead of a silent change.
 */
export interface DialsInput { defaultTtlSeconds: number; expireAfterSeconds: number; keyRetentionHours: number; burnAfterOpen: boolean }

export const DIAL_LIMITS = {
  ttlMax: 30 * 24 * 3600, // 30 days
  expireMax: 30 * 24 * 3600,
  retentionMax: 24 * 30,
} as const;

/** Clamp to whole numbers inside the supported ranges; non-numbers fall back to the app defaults. */
export function clampDials(d: Partial<DialsInput> | null | undefined): DialsInput {
  const int = (x: unknown, lo: number, hi: number, dflt: number) => {
    const n = Number(x);
    if (!Number.isFinite(n) || !Number.isInteger(n)) return dflt;
    return Math.min(hi, Math.max(lo, n));
  };
  return {
    defaultTtlSeconds: int(d?.defaultTtlSeconds, 0, DIAL_LIMITS.ttlMax, 7200),
    expireAfterSeconds: int(d?.expireAfterSeconds, 0, DIAL_LIMITS.expireMax, 86400),
    keyRetentionHours: int(d?.keyRetentionHours, 0, DIAL_LIMITS.retentionMax, 168), // 0 = Off (settings QUIET_OPTIONS)
    burnAfterOpen: d?.burnAfterOpen === true,
  };
}

export function canonicalDials(d: Partial<DialsInput> | null | undefined): string {
  const c = clampDials(d);
  return `t=${c.defaultTtlSeconds};e=${c.expireAfterSeconds};r=${c.keyRetentionHours};b=${c.burnAfterOpen ? 1 : 0}`;
}

/** Batch C (NF-7, V-12): the responder's first ratchet pub and the dials join the transcript. */
async function inviteFingerprint(
  token: string, initiatorPub: string, responderPub: string, responderRatchetPub: string,
  initiatorPqPub: string, responderPqCt: string, dials: string, shared: Uint8Array,
): Promise<string> {
  return transcriptFingerprint(FINGERPRINT_LABEL, [
    utf8(RATCHET_PROTOCOL_LATEST), utf8('invite'), utf8(token),
    fromB64(initiatorPub), fromB64(responderPub), fromB64(responderRatchetPub),
    fromB64(initiatorPqPub), fromB64(responderPqCt), utf8(dials),
    await sha256(shared),
  ]);
}

/** Batch C (B9, NF-7, V-12): both identity keys, the responder ratchet pub and the dials join the transcript.
 *  b77p (audit VAR-05): the responder's handshake pub (`responder_pub_jwk`) is NOT in it any more. In the
 *  contact flow that key takes part in no key agreement and is signed by nobody, so the initiator read it
 *  from the relay's row unauthenticated: a relay that replaced it made the two phones show different safety
 *  codes while messages flowed (verification, and the calls that need it, blocked). Every value left is
 *  authenticated: the identity keys are pinned, the prekeys signed, the request signed (ek, pq ct, the
 *  initiator's session pub, the dials), and the responder ratchet pub and the shared-secret hash are bound
 *  by the key agreement (a replaced ratchet pub gives a different root: nothing opens). The new code is
 *  labelled 'contact2', so a phone on an older build shows a different code instead of a coincidence. */
async function contactFingerprint(
  token: string, initiatorIkPub: string, responderIkPub: string, ekPub: string, spkPub: string, pqPub: string, pqCt: string,
  initiatorSessionPub: string, responderRatchetPub: string, dials: string, sharedHash: Uint8Array,
  opk?: ContactOpkTranscript,
): Promise<string> {
  // b76 (one-time prekeys): a request that used a one-time pair adds its id, both public keys
  // and the ML-KEM ciphertext, so the safety code still covers every public handshake value.
  // A fallback request (no one-time pair) has exactly the b75 field list (less responder_pub, b77p).
  return transcriptFingerprint(FINGERPRINT_LABEL, [
    utf8(RATCHET_PROTOCOL_LATEST), utf8('contact2'), utf8(token),
    fromB64(initiatorIkPub), fromB64(responderIkPub),
    fromB64(ekPub), fromB64(spkPub), fromB64(pqPub), fromB64(pqCt), fromB64(initiatorSessionPub),
    fromB64(responderRatchetPub), utf8(dials),
    sharedHash,
    ...(opk ? [utf8('opk'), utf8(opk.id), fromB64(opk.xPub), fromB64(opk.pqPub), fromB64(opk.pqCt)] : []),
  ]);
}

/** Batch C (B9): X25519 term against the responder's long-term identity key
 *  (Ed25519 IK converted to Montgomery form), as in X3DH's DH(EK, IK_B). */
function ikPubToX25519(ikPubB64: string): string {
  let b: Uint8Array;
  try { b = fromB64(ikPubB64); } catch { throw new Error('Malformed identity key.'); }
  if (b.length !== 32) throw new Error('Malformed identity key.');
  return toB64(edwardsToMontgomeryPub(b));
}

// ---------- skipped keys ----------

/** b70 (audit info): a skipped key is kept at most this long */
export const SKIPPED_KEY_MAX_AGE_MS = 7 * 24 * 3600 * 1000;

/** b70: drop skipped keys past their age (keys from before b70 get their age now) */
/** zeroFill=false on a decrypt's candidate: its key buffers are shared with the live
 *  state until commit, so overwriting there would change the live state of an envelope
 *  that is then refused (b71; the commit zero-fills whatever the new state dropped) */
function pruneSkipped(state: RatchetState, now = Date.now(), dropEmpty = true, zeroFill = true): void {
  for (const [rp, per] of state.skipped) {
    for (const n of [...per.keys()]) {
      const k = rp + ':' + n;
      const at = state.skippedAt.get(k);
      if (at === undefined) state.skippedAt.set(k, now);
      else if (now - at > SKIPPED_KEY_MAX_AGE_MS) { if (zeroFill) per.get(n)?.fill(0); per.delete(n); state.skippedAt.delete(k); }
    }
    if (dropEmpty && !per.size) state.skipped.delete(rp);
  }
  for (const k of [...state.skippedAt.keys()]) {
    const cut = k.lastIndexOf(':');
    if (!state.skipped.get(k.slice(0, cut))?.has(Number(k.slice(cut + 1)))) state.skippedAt.delete(k);
  }
}

/** b77r1 (audit C-1): forget every skipped key of one peer chain (and their timestamps). No
 *  overwrite here: on a decrypt candidate the buffers still back the live state until the
 *  commit, which zero-fills every key the new state no longer holds (§4.4 step 13). */
function dropSkippedChain(state: RatchetState, rp: string): void {
  if (!state.skipped.has(rp)) return;
  state.skipped.delete(rp);
  for (const k of [...state.skippedAt.keys()]) if (k.slice(0, k.lastIndexOf(':')) === rp) state.skippedAt.delete(k);
}

function storeSkipped(state: RatchetState, rp: string, n: number, mk: Uint8Array): void {
  let per = state.skipped.get(rp);
  if (!per) { per = new Map(); state.skipped.set(rp, per); }
  per.set(n, mk);
  state.skippedAt.set(rp + ':' + n, Date.now());
  while (per.size > MAX_SKIPPED_PER_CHAIN) { const n0 = per.keys().next().value as number; per.delete(n0); state.skippedAt.delete(rp + ':' + n0); }
  let total = 0;
  for (const m of state.skipped.values()) total += m.size;
  if (total <= MAX_SKIPPED_TOTAL) return;
  // b77u (audit 6 R4 #7): over the total cap, the OLDEST individual keys go, across every chain (by the time each
  // was stored, then insertion order). It used to drop whole chains, oldest first: one burst on a new chain silently
  // threw away every key still waiting on an older one. No overwrite here (a decrypt candidate's buffers still back
  // the live state until the commit, which zero-fills what the new state no longer holds).
  const all: { rp: string; n: number; at: number; i: number }[] = [];
  let i = 0;
  for (const [r, m] of state.skipped) for (const k of m.keys()) all.push({ rp: r, n: k, at: state.skippedAt.get(r + ':' + k) ?? 0, i: i++ });
  all.sort((a, b) => a.at - b.at || a.i - b.i);
  for (const e of all.slice(0, total - MAX_SKIPPED_TOTAL)) {
    const m = state.skipped.get(e.rp);
    if (!m) continue;
    m.delete(e.n);
    state.skippedAt.delete(e.rp + ':' + e.n);
    if (!m.size && e.rp !== rp) state.skipped.delete(e.rp);
  }
}

/** b77u (audit 6 R4 #7): tests only — the skipped-key store's insert and cap */
export const __skippedKeysForTest = { storeSkipped, MAX_SKIPPED_TOTAL, MAX_SKIPPED_PER_CHAIN };

function takeSkipped(state: RatchetState, header: EnvelopeHeader): Uint8Array | null {
  const per = state.skipped.get(header.rp);
  if (!per) return null;
  const mk = per.get(header.n);
  if (mk) per.delete(header.n);
  // b71: a key that was overwritten (wiped, or expired and zero-filled) never decrypts
  if (mk && mk.every((b) => b === 0)) return null;
  return mk ?? null;
}

/**
 * Signal DR spec (DHRatchet / header.pn): before accepting the peer's NEW
 * ratchet pub and rotating, skip-and-store message keys on the CURRENT
 * receive chain up to header.pn, so old-chain stragglers stay decryptable.
 */
async function skipOldChainBeforeRotation(state: RatchetState, pn: number): Promise<void> {
  if (!state.recvChain || state.remoteRatchetPub === null) return; // no old chain to protect
  requireLiveChain(state.recvChain, 'receiving'); // b71: never derive skipped keys from a wiped chain
  if (pn < state.recvCount || pn - state.recvCount > MAX_COUNTER_GAP) {
    throw new Error('Message counter out of range — the session is desynchronised.');
  }
  while (state.recvCount < pn) {
    const step = await advanceChain(state.recvChain);
    state.recvChain = step.ck;
    storeSkipped(state, state.remoteRatchetPub, state.recvCount, step.mk);
    state.recvCount += 1;
  }
}

// ---------- message header ----------

export interface EnvelopeHeader {
  v: string;
  /** sender's current X25519 ratchet pub (raw, b64) */
  rp: string;
  /** sender's previous chain length at last ratchet step */
  pn: number;
  /** message counter in the current chain */
  n: number;
  /** b75 (audit RT-5): the sender's epoch number (1 for its first ratchet pub, +1 per new pub) */
  e?: number;
  /** per-step PQ: sender's current ML-KEM step pub (mandatory) */
  pq?: string;
  /** ct encapsulated to the peer's step pub */
  pqct?: string;
  /** Ed25519 signature over the whole header (headerSigMessage) with the sender's EPOCH key
   *  (mandatory; b75: the epoch key follows the root key) */
  sig?: string;
  /** b75 (audit RT-5): the same fields signed with the sender's per-direction SESSION key
   *  (mandatory); classifies a failure as out of sync rather than junk */
  ssig?: string;
}

export interface Envelope {
  ciphertext: string;
  iv: string;
  /** b77: the sealed header string ('h8.' || base64, HEADER_STRING_LENGTH) — AES-GCM AAD (the exact sender bytes) */
  header: string;
  byteLength?: number;
}

async function importAesKey(mk: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', mk as BufferSource, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

// ---------- signed ratchet keys ----------

/**
 * Session-scoped Ed25519 signing pairs derived from the handshake root (rk0).
 * Batch C (B9): one pair PER DIRECTION. Each side keeps only its own private
 * key and the peer's public key, so a header signed by one side can never be
 * reflected back and accepted as the other's.
 * b75 (audit RT-5): these SESSION pairs make only the second header signature (ssig),
 * which tells an authentic-but-undecryptable header (out of sync) from junk. They no
 * longer gate any key work: the epoch keys below do, and those heal.
 */
async function deriveSigPairs(rk0: Uint8Array, token: string, role: SessionRole): Promise<{ privB64: string; pubB64: string }> {
  const pair = async (dir: SessionRole) => {
    const seed = await hkdf(rk0, utf8(`${RATCHET_SIG_INFO}:${token}`), `${RATCHET_SIG_INFO}/${dir}`, 32);
    return { priv: seed, pub: ed25519.getPublicKey(seed) };
  };
  const mine = await pair(role);
  const theirs = await pair(otherRole(role));
  const out = { privB64: toB64(mine.priv), pubB64: toB64(theirs.pub) };
  mine.priv.fill(0); theirs.priv.fill(0); // b75 (audit 2 V10)
  return out;
}

function otherRole(role: SessionRole): SessionRole {
  return role === 'initiator' ? 'responder' : 'initiator';
}

/**
 * b75 (audit RT-5): EPOCH header-signing keys. The headers of a sending chain are signed
 * with a key derived from the root key that was the salt of that chain's own KDF_RK
 * (rk0 for the responder's first chain, root1 for the initiator's first chain, and the
 * receiving-side root rootA at every DH step). That root is exactly the receiver's current
 * root key when the first header of the new chain arrives, so the receiver can still check
 * the signature BEFORE any DH or ML-KEM work — and once the root heals after a state
 * compromise, so do these keys (up to b74 they came from rk0 and never changed).
 */
async function epochSigSeed(root: Uint8Array, dir: SessionRole): Promise<Uint8Array> {
  return hkdf(root, utf8(RATCHET_EPOCH_SIG_INFO), `${RATCHET_EPOCH_SIG_INFO}/${dir}`, 32);
}

async function epochSigPrivB64(root: Uint8Array, dir: SessionRole): Promise<string> {
  const seed = await epochSigSeed(root, dir);
  const out = toB64(seed);
  seed.fill(0); // b75 (audit 2 V10)
  return out;
}

async function epochSigPubB64(root: Uint8Array, dir: SessionRole): Promise<string> {
  const seed = await epochSigSeed(root, dir);
  const out = toB64(ed25519.getPublicKey(seed));
  seed.fill(0); // b75 (audit 2 V10)
  return out;
}

// ---------- b77: encrypted header (veil-ratchet-8, spec §4.2) ----------

/** b77: HK(R, dir) — the header key of the chain whose KDF_RK was salted with root R. Exported
 *  for the test suites (it needs a root key, which never leaves the state). */
export async function headerKeyB64(root: Uint8Array, dir: SessionRole): Promise<string> {
  const k = await hkdf(root, utf8(RATCHET_HEADER_KEY_LABEL), `${RATCHET_HEADER_KEY_LABEL}/${dir}`, 32);
  const out = toB64(k);
  k.fill(0);
  return out;
}

/** b77 (deviation, spec §4.2): the per-direction session header-tag keys, from rk0 */
async function sessionHeaderKeys(rk0: Uint8Array, token: string, role: SessionRole): Promise<{ sendB64: string; recvB64: string }> {
  const key = async (dir: SessionRole) => {
    const k = await hkdf(rk0, utf8(`${RATCHET_HEADER_SESSION_KEY_LABEL}:${token}`), `${RATCHET_HEADER_SESSION_KEY_LABEL}/${dir}`, 32);
    const out = toB64(k);
    k.fill(0);
    return out;
  };
  return { sendB64: await key(role), recvB64: await key(otherRole(role)) };
}

const HDR_AAD = utf8(RATCHET_HEADER_KEY_LABEL);
const HDR_SESSION_AAD = utf8(RATCHET_HEADER_SESSION_KEY_LABEL);
const HDR_HCT_END = 12 + HEADER_FRAME_BYTES + 16; // hnonce || hct

async function aesGcm(op: 'encrypt' | 'decrypt', keyB64: string, iv: Uint8Array, aad: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
  const raw = fromB64(keyB64);
  let key: CryptoKey;
  try { key = await crypto.subtle.importKey('raw', raw as BufferSource, { name: 'AES-GCM' }, false, [op]); } finally { raw.fill(0); } // (audit 2 V10 style)
  const out = await crypto.subtle[op]({ name: 'AES-GCM', iv: iv as BufferSource, additionalData: aad as BufferSource }, key, data as BufferSource);
  return new Uint8Array(out);
}

/** b77: the strict header frame — u16be(len) || utf8(inner) || zeros, exactly HEADER_FRAME_BYTES */
export function frameHeader(inner: string): Uint8Array {
  const body = utf8(inner);
  if (body.length + 2 > HEADER_FRAME_BYTES) throw new Error('Message header too large.');
  const frame = new Uint8Array(HEADER_FRAME_BYTES);
  frame[0] = body.length >> 8;
  frame[1] = body.length & 0xff;
  frame.set(body, 2);
  return frame;
}

/** b77: strict unframing (like §4.8): the length must fit, every padding byte must be zero,
 *  and the text must be well-formed UTF-8. Anything else is junk (null). */
export function unframeHeader(frame: Uint8Array): string | null {
  if (frame.length !== HEADER_FRAME_BYTES) return null;
  const len = (frame[0] << 8) | frame[1];
  if (len < 2 || len + 2 > HEADER_FRAME_BYTES) return null;
  for (let i = 2 + len; i < frame.length; i++) if (frame[i] !== 0) return null;
  try { return fromUtf8Strict(frame.subarray(2, 2 + len)); } catch { return null; }
}

/** b77: seals an inner (JSON) header into the envelope's header string:
 *  'h8.' || B64(hnonce || AES-GCM(hk, hnonce, aad = label, frame) || snonce || AES-GCM(shk, snonce,
 *  aad = session label || hnonce || hct, u32be(e))). Exported for the test suites. */
export async function sealHeader(inner: string, hkB64: string, shkB64: string, epoch: number): Promise<string> {
  const frame = frameHeader(inner);
  try { return await sealHeaderFrame(frame, hkB64, shkB64, epoch); } finally { frame.fill(0); }
}

/** b77: sealHeader on a ready-made frame (exported for the test suites' malformed frames) */
export async function sealHeaderFrame(frame: Uint8Array, hkB64: string, shkB64: string, epoch: number): Promise<string> {
  const hnonce = crypto.getRandomValues(new Uint8Array(12));
  const hct = await aesGcm('encrypt', hkB64, hnonce, HDR_AAD, frame);
  const outer = new Uint8Array(HEADER_SEALED_BYTES);
  outer.set(hnonce, 0);
  outer.set(hct, 12);
  const e = new Uint8Array(4);
  new DataView(e.buffer).setUint32(0, epoch >>> 0);
  const snonce = crypto.getRandomValues(new Uint8Array(12));
  const sct = await aesGcm('encrypt', shkB64, snonce, concatBytes(HDR_SESSION_AAD, outer.subarray(0, HDR_HCT_END)), e);
  outer.set(snonce, HDR_HCT_END);
  outer.set(sct, HDR_HCT_END + 12);
  const s = HEADER_PREFIX + toB64(outer);
  if (s.length !== HEADER_STRING_LENGTH) throw new Error('Message header has the wrong length.');
  return s;
}

function concatBytes(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

/** b77: which key opened a header — the peer's current chain, its next chain (salted with
 *  this state's root), one of its replaced chains, or my own (an echo of what I sent). */
export type OpenedHeaderKind = 'current' | 'next' | 'old' | 'own';

export interface OpenedHeader {
  kind: OpenedHeaderKind;
  /** the inner header (absent only for an own echo recognised by the session tag alone) */
  header: EnvelopeHeader | null;
}

/** b77: the inner header, parsed strictly (a JSON object carrying the current protocol tag) */
function parseInnerHeader(inner: string): EnvelopeHeader {
  let h: unknown;
  try { h = JSON.parse(inner); } catch { throw new JunkEnvelopeError('Malformed message header rejected.'); }
  if (!h || typeof h !== 'object' || Array.isArray(h)) throw new JunkEnvelopeError('Malformed message header rejected.');
  if ((h as EnvelopeHeader).v !== RATCHET_PROTOCOL_LATEST) throw new JunkEnvelopeError('Unsupported protocol version in message header.');
  return h as EnvelopeHeader;
}

/**
 * b77 (spec §4.2): opens an encrypted header by trial AES-GCM decrypts, in order:
 *   1. hkRecv (the peer's current chain), 2. HK(rootKey, peer) (its next chain),
 *   3. each peerHks key (its replaced chains: late messages), 4. hkSend and myHks (my echo).
 * Consistency: `current` must carry exactly remoteRatchetPub, `next` must not, and `old` must
 * carry the rp it is filed under — a mismatch is junk.
 * When no header key opens it (deviation, see shkRecv): the peer's session tag that opens
 * names an epoch — above the peer's current one: OutOfSyncError (the peer's root and this
 * state's diverged); otherwise StaleMessageError (an old copy whose key is gone). My own session
 * tag: an own echo. Nothing opens: JunkEnvelopeError. Never changes the state.
 * b77q (audit 3 CR-2): the two session tags are checked FIRST. Every genuine header carries one (the peer's under
 * shkRecv, which peerHeader required anyway; my own under shkSend), so a header neither opens is junk after two
 * 4-byte decrypts — it used to reach the end of up to 76 trial decrypts of the 3.8 KB frame (hkRecv, the next
 * chain, 64 peerHks, hkSend + myHks) before it was refused, which a relay could repeat for every row it served.
 * A peer-tagged header is tried only with the peer's header keys, an own-tagged one only with mine.
 */
export async function openHeader(state: RatchetState, headerStr: string): Promise<OpenedHeader> {
  if (typeof headerStr !== 'string' || !headerStr.startsWith(HEADER_PREFIX)) {
    // a ratchet-7 (cleartext JSON) header, or anything else
    throw new JunkEnvelopeError('Unsupported protocol version in message header.');
  }
  if (!isSealedHeaderString(headerStr)) throw new JunkEnvelopeError('Malformed message header rejected.');
  let outer: Uint8Array;
  try { outer = fromB64(headerStr.slice(HEADER_PREFIX.length)); } catch { throw new JunkEnvelopeError('Malformed message header rejected.'); }
  if (outer.length !== HEADER_SEALED_BYTES) throw new JunkEnvelopeError('Malformed message header rejected.');
  const hnonce = outer.subarray(0, 12);
  const hct = outer.subarray(12, HDR_HCT_END);
  const tryKey = async (k: string | null | undefined): Promise<EnvelopeHeader | null> => {
    if (!k) return null;
    let frame: Uint8Array;
    try { frame = await aesGcm('decrypt', k, hnonce, HDR_AAD, hct); } catch { return null; }
    const inner = unframeHeader(frame);
    frame.fill(0);
    if (inner === null) throw new JunkEnvelopeError('Malformed message header frame rejected.');
    return parseInnerHeader(inner);
  };
  const rpOf = (h: EnvelopeHeader) => (typeof h.rp === 'string' ? h.rp : '');
  // the session tag: sealed under the per-direction session key, bound to hnonce || hct
  const snonce = outer.subarray(HDR_HCT_END, HDR_HCT_END + 12);
  const sct = outer.subarray(HDR_HCT_END + 12);
  const aad = concatBytes(HDR_SESSION_AAD, outer.subarray(0, HDR_HCT_END));
  const tag = async (k: string | null): Promise<number | null> => {
    if (!k) return null;
    try {
      const e = await aesGcm('decrypt', k, snonce, aad, sct);
      return e.length === 4 ? new DataView(e.buffer, e.byteOffset, 4).getUint32(0) : null;
    } catch { return null; }
  };
  // b77q (audit 3 CR-2): the session tags first — neither opens: junk, before any frame decrypt
  const peerEpoch = await tag(state.shkRecv);
  const ownEpoch = peerEpoch === null ? await tag(state.shkSend) : null;
  if (peerEpoch === null && ownEpoch === null) throw new JunkEnvelopeError('Message header did not open with this chat\'s keys.');
  // a header from the peer also carries the peer's session tag naming the epoch it signed, so
  // every byte of the header string is authenticated before any key work
  const peerHeader = async (kind: OpenedHeaderKind, hh: EnvelopeHeader): Promise<OpenedHeader> => {
    if (peerEpoch !== hh.e) throw new JunkEnvelopeError('Message header tag does not match.');
    return { kind, header: hh };
  };
  if (peerEpoch === null) {
    // my own session tag: an echo of what I sent (b77r1, audit C-4: hkSend is always in myHks too — each key once)
    for (const k of new Set([state.hkSend, ...[...state.myHks].reverse()])) {
      const own = await tryKey(k);
      if (own) return { kind: 'own', header: own };
    }
    return { kind: 'own', header: null };
  }
  let h = await tryKey(state.hkRecv);
  if (h) {
    if (rpOf(h) !== state.remoteRatchetPub) throw new JunkEnvelopeError('Message header does not match its chain.');
    return peerHeader('current', h);
  }
  if (state.ready && state.rootKey.some((b) => b !== 0)) {
    h = await tryKey(await headerKeyB64(state.rootKey, otherRole(state.role)));
    if (h) {
      if (!rpOf(h) || rpOf(h) === state.remoteRatchetPub) throw new JunkEnvelopeError('Message header does not match its chain.');
      return peerHeader('next', h);
    }
  }
  for (const [rp, k] of state.peerHks) {
    h = await tryKey(k);
    if (h) {
      if (rpOf(h) !== rp) throw new JunkEnvelopeError('Message header does not match its chain.');
      return peerHeader('old', h);
    }
  }
  // b77 (deviation): no header key opens it — the peer's session tag classifies it
  if (peerEpoch > state.remoteEpoch) throw new OutOfSyncError(peerEpoch); // b77r1 (C-2): keyed by the tag's epoch
  throw new StaleMessageError();
}

/** b77: what the receive loop may know about an envelope before decrypting it — whether it is
 *  my own echo, and the ratchet pub / counter for logs and the PR3-03 failure key. null: no
 *  key opens it (or it is refused; decryptMessage then says why). Never changes the state. */
export async function peekHeader(state: RatchetState, headerStr: string): Promise<{ own: boolean; rp: string; n: number } | null> {
  try {
    const o = await openHeader(state, headerStr);
    const rp = o.header && typeof o.header.rp === 'string' ? o.header.rp : '';
    const n = o.header && Number.isSafeInteger(o.header.n) && (o.header.n as number) >= 0 ? o.header.n : -1;
    return { own: o.kind === 'own', rp, n };
  } catch {
    return null;
  }
}

/** b74 (veil-ratchet-7, review VAR-09): the signature covers the WHOLE header —
 *  version, ratchet pub, both counters, the PQ step pub and the PQ ciphertext — so a
 *  relay can't reuse a genuine signature on a header with other counters to make the
 *  receiver derive chain keys (ratchet-6 signed only rp and pq). JSON of a fixed-order
 *  array: no field can bleed into another. */
function headerSigMessage(h: Pick<EnvelopeHeader, 'v' | 'rp' | 'pn' | 'n' | 'e' | 'pq' | 'pqct'>, label: string = RATCHET_HEADER_SIG_LABEL): Uint8Array {
  // b75 (audit RT-5): e (the sender's epoch number) is signed too
  return utf8(JSON.stringify([label, h.v, h.rp, h.pn, h.n, h.e ?? 0, h.pq ?? '', h.pqct ?? '']));
}

function signHeader(state: RatchetState, header: EnvelopeHeader): { sig: string; ssig: string } {
  if (!state.sigPrivB64 || !state.sessionSigPrivB64) throw new Error('Session signing key missing — the handshake is incomplete.');
  return {
    sig: toB64(ed25519.sign(headerSigMessage(header), fromB64(state.sigPrivB64))),
    ssig: toB64(ed25519.sign(headerSigMessage(header, RATCHET_HEADER_SESSION_SIG_LABEL), fromB64(state.sessionSigPrivB64))),
  };
}

/** T-2: strict RFC 8032 (noble's default ZIP-215 accepts forgeries under small-order keys). Never throws. */
function edVerify(sigB64: unknown, msg: Uint8Array, pubB64: string | null | undefined): boolean {
  if (typeof sigB64 !== 'string' || !sigB64 || !pubB64) return false;
  try { return ed25519.verify(fromB64(sigB64), msg, fromB64(pubB64), { zip215: false }); } catch { return false; }
}

/** b75 (audit RT-5): the epoch verification key for a header, from THIS state.
 *  'gone' = an old epoch whose key this device no longer keeps. */
async function epochVerifyKeyFor(state: RatchetState, header: EnvelopeHeader): Promise<string | 'gone'> {
  const rp = header.rp;
  if (rp === state.remoteRatchetPub) return state.sigPubB64 ?? 'gone';
  const kept = state.peerSigPubs.get(rp);
  if (kept) return kept;
  if (state.seenRemotePubs.has(rp) || state.skipped.has(rp)) return 'gone';
  // The peer makes a new ratchet pub only after it has read this device's newest one, so
  // its epoch numbers rise by one per new pub. A pub this device no longer remembers, from
  // an epoch at or below the current one, is an old copy (past the seenRemotePubs window),
  // never a desync (audit 2 V5).
  if ((header.e ?? 0) <= state.remoteEpoch) return 'gone';
  // a new epoch: the peer signed it with a key from the root this device holds now
  return epochSigPubB64(state.rootKey, otherRole(state.role));
}

/**
 * Fail-closed authentication of every header, before any chain or DH work.
 * b75 (audit RT-2 / RT-5): typed outcomes, so the caller never counts relay-made junk as
 * a desync:
 *   - both signatures verify ................ 'ok'
 *   - epoch key gone (old epoch), ssig ok ... 'gone' (only a stored skipped key may open it)
 *   - epoch fails, session ssig verifies .... OutOfSyncError (the peer's ratchet and ours diverged)
 *   - otherwise ............................. JunkEnvelopeError
 */
async function authenticateHeader(state: RatchetState, header: EnvelopeHeader): Promise<'ok' | 'gone'> {
  if (!state.sessionSigPubB64) throw new Error('Session signing key missing — the handshake is incomplete.');
  if (!header.sig) throw new JunkEnvelopeError('Unsigned message header rejected.');
  if (typeof header.rp !== 'string' || !header.rp || !Number.isSafeInteger(header.pn) || header.pn < 0 || !Number.isSafeInteger(header.n) || header.n < 0
    || !Number.isSafeInteger(header.e) || (header.e as number) < 1) {
    throw new JunkEnvelopeError('Malformed message header rejected.');
  }
  const sessionOk = edVerify(header.ssig, headerSigMessage(header, RATCHET_HEADER_SESSION_SIG_LABEL), state.sessionSigPubB64);
  if (!sessionOk) throw new JunkEnvelopeError('Invalid message header signature — header did not authenticate against the session.');
  const key = await epochVerifyKeyFor(state, header);
  if (key === 'gone') return 'gone';
  if (!edVerify(header.sig, headerSigMessage(header), key)) throw new OutOfSyncError();
  return 'ok';
}

/** b75 (audit RT-2): a header's replay digest — 8 bytes of SHA-256 over the SIGNED fields
 *  (b74 hashed the header string, so a re-spaced copy of a genuine header was "new"). */
async function headerDigest(header: EnvelopeHeader): Promise<string> {
  const h = await sha256(headerSigMessage(header));
  return [...h.slice(0, 8)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

function emptyState(role: SessionRole, contact: boolean, hs: X25519Pair): RatchetState {
  return {
    role,
    proto: RATCHET_PROTOCOL_LATEST,
    seenRemotePubs: new Set(),
    contact,
    ready: false,
    fingerprint: null,
    pq: 'hybrid',
    hsPriv: hs.priv,
    hsPub: hs.pub,
    bound: null,
    pqPub: null,
    pqPriv: null,
    pqStepPriv: null,
    pqStepPub: null,
    pendingPqCt: null,
    ppSecret: null,
    writeSecret: null,
    sigPrivB64: null,
    sigPubB64: null,
    sessionSigPrivB64: null,
    sessionSigPubB64: null,
    peerSigPubs: new Map(),
    sendEpoch: 0,
    remoteEpoch: 0,
    dials: null,
    contactPending: null,
    ratchetPriv: null,
    ratchetPub: '',
    remoteRatchetPub: null,
    myPubs: new Set<string>(),
    rootKey: new Uint8Array(32),
    sendChain: null,
    recvChain: null,
    sendCount: 0,
    prevSendCount: 0,
    recvCount: 0,
    processedIds: new Set<string>(),
    skipped: new Map(),
    sendSeq: 0,
    recvSeqMax: 0,
    skippedAt: new Map(),
    seenDigests: new Set(),
    hkSend: null,
    hkRecv: null,
    peerHks: new Map(),
    myHks: new Set(),
    shkSend: null,
    shkRecv: null,
  };
}

// ---------- strict invite: initiator create ----------

export interface CreatedSession {
  state: RatchetState;
  /** initiator session X25519 pub (b64) — the `initiator_pub_jwk` relay field */
  initiatorPub: string;
  /** ML-KEM-768 pub (b64) — the `initiator_pq_pub` relay field */
  initiatorPqPub: string;
}

/** Initiator creates a strict session. inviteSecret = the link's `k=` fragment.
 *  dials = the initiator's OWN dials; kept in state and bound into the fingerprint at completion. */
export async function createSession(token: string, inviteSecret: string, dials: Partial<DialsInput>): Promise<CreatedSession> {
  const hs = x25519Pair();
  const ppSecret = await derivePpSecret(inviteSecret, token);
  const pq = await pqStepPair();
  const state = emptyState('initiator', false, hs);
  state.pqPub = pq.pub;
  state.pqPriv = pq.priv;
  state.ppSecret = ppSecret;
  state.dials = canonicalDials(dials);
  return { state, initiatorPub: hs.pub, initiatorPqPub: pq.pub };
}

// ---------- strict invite: responder join ----------

export interface JoinedSession {
  state: RatchetState;
  responderPub: string;
  responderRatchetPub: string;
  /** ct encapsulated to the initiator's ML-KEM pub — the `responder_pq_ct` field */
  responderPqCt: string;
  fingerprint: string;
  /** b77 (sealed sender): both directions' delivery capabilities, from rk0 */
  delivery: DeliveryCaps;
}

/** Responder joins. Session is READY on return (root1 = send chain). */
export async function joinSession(
  token: string,
  inviteSecret: string,
  initiatorPub: string,
  initiatorPqPub: string | null,
  /** the dials as read from the session row — bound into the fingerprint (V-12) */
  dials: Partial<DialsInput>,
): Promise<JoinedSession> {
  requirePqPub(initiatorPqPub, 'invite');
  const pp = await derivePpSecret(inviteSecret, token);
  const hs = x25519Pair();
  const dhOut = dh(hs.priv, initiatorPub);
  const { ct, secret } = await mlkemEncap(initiatorPqPub as string);
  const stepPq = await pqStepPair();
  const combined = combine(dhOut, secret);
  const shared = combine(combined, pp);
  const rk0 = await deriveRk0(shared, token);
  const sig = await deriveSigPairs(rk0, token, 'responder');
  const ratchet = x25519Pair();
  const dhR = dh(ratchet.priv, initiatorPub);
  const root1 = await deriveRoot(rk0, dhR, null);
  const dialsStr = canonicalDials(dials);
  const fingerprint = await inviteFingerprint(token, initiatorPub, hs.pub, ratchet.pub, initiatorPqPub as string, ct, dialsStr, shared);
  // b75 (audit RT-5): my first chain's salt is rk0, so its epoch key comes from rk0
  const epochPriv = await epochSigPrivB64(rk0, 'responder');
  const delivery = await deriveDelivery(rk0); // b77 (sealed sender): invite chats' delivery root is rk0
  // b77: and so does its header key; the session header-tag keys come from rk0 once
  const hkSend = await headerKeyB64(rk0, 'responder');
  const shk = await sessionHeaderKeys(rk0, token, 'responder');
  // b75 (audit 2 V10): handshake secrets overwritten once used
  for (const b of [dhOut, secret, combined, shared, pp, rk0, dhR, hs.priv]) b.fill(0);
  const state = emptyState('responder', false, hs);
  Object.assign(state, {
    ready: true,
    fingerprint,
    dials: dialsStr,
    bound: { initiatorPub, responderPub: hs.pub, responderRatchetPub: ratchet.pub },
    hsPriv: new Uint8Array(32), // Batch H (R6-1-07): used above, never again
    pqStepPriv: stepPq.priv,
    pqStepPub: stepPq.pub,
    sigPrivB64: epochPriv,
    sigPubB64: null, // no chain from the initiator yet: its first one is verified from the root then
    sessionSigPrivB64: sig.privB64,
    sessionSigPubB64: sig.pubB64,
    sendEpoch: 1,
    remoteEpoch: 0,
    ratchetPriv: ratchet.priv,
    ratchetPub: ratchet.pub,
    remoteRatchetPub: initiatorPub,
    rootKey: root1.rk,
    sendChain: root1.ck,
    hkSend,
    hkRecv: null, // no chain from the initiator yet: its first one opens with HK(root1, initiator)
    myHks: new Set([hkSend]),
    shkSend: shk.sendB64,
    shkRecv: shk.recvB64,
  });
  state.myPubs.add(ratchet.pub);
  return { state, responderPub: hs.pub, responderRatchetPub: ratchet.pub, responderPqCt: ct, fingerprint, delivery };
}

// ---------- one-tap contact family ----------

export interface ContactPeerPrekeys {
  /** peer's X25519 SPK — SPK_sig verified against the PINNED IK by the caller */
  spkPubB64: string;
  /** peer's ML-KEM-768 prekey — pq_sig verified against the PINNED IK by the caller */
  pqPubB64: string;
  /** Batch C (B9): the peer's PINNED Ed25519 identity key — adds DH(EK, IK_peer) */
  ikPubB64: string;
  /** b76 (one-time prekeys): the one-time pair the relay handed out — its signature verified
   *  against the PINNED IK by the caller. Absent: the signed prekeys only (fallback). */
  opk?: { id: string; xPubB64: string; pqPubB64: string } | null;
}

export interface CreatedContactSession {
  state: RatchetState;
  /** ephemeral X25519 pub — travels to the peer in the session request */
  ekPubB64: string;
  /** ML-KEM ct encapsulated to the peer's pq_pub */
  pqCt: string;
  /** initiator session X25519 pub — the `initiator_pub_jwk` relay field */
  sessionPub: string;
  writeSecrets: { initiator: string; responder: string };
  fingerprint: string;
  /** b76 (one-time prekeys): the ML-KEM ct encapsulated to the one-time pair's PQ key ('' = none used) */
  opkPqCt: string;
}

/**
 * Initiator bootstraps a one-tap session from the pinned peer's signed prekeys.
 * shared = DH(EK, SPK) ‖ DH(EK, IK_peer) ‖ ML-KEM ss  (Batch C, B9: the IK term
 * means only the holder of the peer's long-term identity key can derive the root).
 * b76 (one-time prekeys): with a one-time pair, shared also gets ‖ DH(EK, OPK) ‖ ML-KEM ss_opk
 * (160 bytes), and the rk0 salt names the pair's id — as X3DH's DH4 and PQXDH's one-time PQ
 * prekey. The responder deletes the pair's private keys once used, so a later theft of the
 * phone (signed prekeys and identity key included) can't re-derive this root.
 * The fingerprint is finished at completion, once the responder's keys are known.
 */
export async function createContactSession(
  token: string, peer: ContactPeerPrekeys, myIkPubB64: string, dials: Partial<DialsInput>,
): Promise<CreatedContactSession> {
  requirePqPub(peer.pqPubB64, 'contact prekey');
  const opk = peer.opk ?? null;
  if (opk) { requireOpkId(opk.id); requirePqPub(opk.pqPubB64, 'one-time prekey'); x25519PubBytes(opk.xPubB64); }
  const ek = x25519Pair();
  const dhSpk = dh(ek.priv, peer.spkPubB64);
  const dhIk = dh(ek.priv, ikPubToX25519(peer.ikPubB64));
  const enc = await mlkemEncap(peer.pqPubB64);
  const dhOpk = opk ? dh(ek.priv, opk.xPubB64) : null;
  const encOpk = opk ? await mlkemEncap(opk.pqPubB64) : null;
  const combined = combine(dhSpk, dhIk);
  const base = combine(combined, enc.secret);
  const shared = dhOpk && encOpk ? combine(base, combine(dhOpk, encOpk.secret)) : base;
  const rootKey = await deriveRk0(shared, contactRk0Token(token, myIkPubB64, peer.ikPubB64, opk?.id));
  const sig = await deriveSigPairs(rootKey, token, 'initiator');
  const shk = await sessionHeaderKeys(rootKey, token, 'initiator'); // b77
  const writeSecrets = await contactWriteSecrets(rootKey);
  const hs = x25519Pair();
  const sharedHash = toB64(await sha256(shared));
  // b75 (audit 2 V10): the ephemeral key and DH outputs are single-use
  for (const b of [ek.priv, dhSpk, dhIk, enc.secret, combined, base, shared, dhOpk, encOpk?.secret]) b?.fill(0);
  const state = emptyState('initiator', true, hs);
  Object.assign(state, {
    writeSecret: writeSecrets.initiator,
    // b75 (audit RT-5): the epoch keys are set at completion (from rk0 / root1)
    sessionSigPrivB64: sig.privB64,
    sessionSigPubB64: sig.pubB64,
    shkSend: shk.sendB64, // b77: the header keys themselves are set at completion
    shkRecv: shk.recvB64,
    rootKey,
    dials: canonicalDials(dials),
    contactPending: {
      initiatorIkPub: myIkPubB64, responderIkPub: peer.ikPubB64, ekPub: ek.pub,
      spkPub: peer.spkPubB64, pqPub: peer.pqPubB64, pqCt: enc.ct, sharedHash,
      ...(opk && encOpk ? { opk: { id: opk.id, xPub: opk.xPubB64, pqPub: opk.pqPubB64, pqCt: encOpk.ct } } : {}),
    },
  });
  return { state, ekPubB64: ek.pub, pqCt: enc.ct, sessionPub: hs.pub, writeSecrets, fingerprint: '', opkPqCt: encOpk?.ct ?? '' };
}

export interface ContactRequest {
  /** initiator's ephemeral X25519 pub */
  ekPubB64: string;
  /** ct encapsulated to OUR pq_pub */
  pqCt: string;
  /** OUR SPK (device keyvault) */
  spkPrivB64: string;
  spkPubB64: string;
  /** OUR ML-KEM prekey (device keyvault) */
  pqPrivB64: string;
  pqPubB64: string;
  /** initiator's session X25519 pub (from the request; covered by initiator_sig) */
  initiatorSessionPub: string;
  /** Batch C (B9): OUR identity seed (adds DH(IK, EK)) and public key */
  ikSeedB64: string;
  ikPubB64: string;
  /** the initiator's identity key (the one that verified initiator_sig) */
  initiatorIkPubB64: string;
  /** Batch C (V-12): the dials carried in the SIGNED request */
  dials: Partial<DialsInput>;
  /** b76 (one-time prekeys): OUR one-time pair the (signed) request names, found by id, and the
   *  ct encapsulated to its PQ key. Absent: the request used the signed prekeys only. */
  opk?: { id: string; xPrivB64: string; xPubB64: string; pqPrivB64: string; pqPubB64: string; pqCt: string } | null;
}

export interface AcceptedContactSession {
  state: RatchetState;
  fingerprint: string;
  responderPub: string;
  responderRatchetPub: string;
  writeSecret: string;
  /** b77 (sealed sender): both directions' delivery capabilities, from the root contactWriteSecrets uses */
  delivery: DeliveryCaps;
}

/** Responder accepts the one-tap request; session is READY on return. */
export async function acceptContactSession(token: string, req: ContactRequest): Promise<AcceptedContactSession> {
  requirePqCt(req.pqCt, 'contact request');
  if (!req.pqPrivB64) throw new Error('Post-quantum prekey missing on this device — re-open Vardum to republish it.');
  if (!req.ikSeedB64) throw new Error('Identity key missing on this device.');
  const ikSeed = fromB64(req.ikSeedB64);
  if (ikSeed.length !== 32 || toB64(ed25519.getPublicKey(ikSeed)) !== req.ikPubB64) throw new Error('Identity key mismatch on this device.');
  const opk = req.opk ?? null;
  if (opk) {
    requireOpkId(opk.id);
    requirePqCt(opk.pqCt, 'one-time prekey');
    if (!opk.xPrivB64 || !opk.pqPrivB64) throw new Error('One-time prekey missing on this device.');
  }
  const spkPriv = fromB64(req.spkPrivB64);
  const ikX = edwardsToMontgomeryPriv(ikSeed);
  const dhSpk = dh(spkPriv, req.ekPubB64);
  const dhIk = dh(ikX, req.ekPubB64);
  const pqSecret = await mlkemDecap(req.pqPrivB64, req.pqCt);
  // b76 (one-time prekeys): DH(OPK, EK) and the one-time ML-KEM secret join the root
  const opkPriv = opk ? fromB64(opk.xPrivB64) : null;
  const dhOpk = opk && opkPriv ? dh(opkPriv, req.ekPubB64) : null;
  const opkSecret = opk ? await mlkemDecap(opk.pqPrivB64, opk.pqCt) : null;
  const combined = combine(dhSpk, dhIk);
  const base = combine(combined, pqSecret);
  const shared = dhOpk && opkSecret ? combine(base, combine(dhOpk, opkSecret)) : base;
  const rootKey = await deriveRk0(shared, contactRk0Token(token, req.initiatorIkPubB64, req.ikPubB64, opk?.id));
  const sig = await deriveSigPairs(rootKey, token, 'responder');
  const writeSecrets = await contactWriteSecrets(rootKey);
  const ratchet = x25519Pair();
  const dhR = dh(ratchet.priv, req.initiatorSessionPub);
  const root1 = await deriveRoot(rootKey, dhR, null);
  const hs = x25519Pair();
  const step = await pqStepPair();
  const dialsStr = canonicalDials(req.dials);
  const fingerprint = await contactFingerprint(
    token, req.initiatorIkPubB64, req.ikPubB64, req.ekPubB64, req.spkPubB64, req.pqPubB64, req.pqCt,
    req.initiatorSessionPub, ratchet.pub, dialsStr, await sha256(shared), // b77p (VAR-05): hs.pub left out
    opk ? { id: opk.id, xPub: opk.xPubB64, pqPub: opk.pqPubB64, pqCt: opk.pqCt } : undefined,
  );
  // b75 (audit RT-5): my first chain's salt is rk0, so its epoch key comes from rk0
  const epochPriv = await epochSigPrivB64(rootKey, 'responder');
  const delivery = await deriveDelivery(rootKey); // b77 (sealed sender): the root contactWriteSecrets uses
  // b77: and so does its header key; the session header-tag keys come from rk0 once
  const hkSend = await headerKeyB64(rootKey, 'responder');
  const shk = await sessionHeaderKeys(rootKey, token, 'responder');
  // b75 (audit 2 V10): copies of long-term keys and the handshake secrets, overwritten
  for (const b of [ikSeed, spkPriv, ikX, dhSpk, dhIk, pqSecret, combined, base, shared, rootKey, dhR, hs.priv, opkPriv, dhOpk, opkSecret]) b?.fill(0);
  const state = emptyState('responder', true, hs);
  Object.assign(state, {
    ready: true,
    fingerprint,
    dials: dialsStr,
    bound: { initiatorPub: req.initiatorSessionPub, responderPub: hs.pub, responderRatchetPub: ratchet.pub },
    hsPriv: new Uint8Array(32), // Batch H (R6-1-07): used above, never again
    pqStepPriv: step.priv,
    pqStepPub: step.pub,
    writeSecret: writeSecrets.responder,
    sigPrivB64: epochPriv,
    sigPubB64: null, // no chain from the initiator yet: its first one is verified from the root then
    sessionSigPrivB64: sig.privB64,
    sessionSigPubB64: sig.pubB64,
    sendEpoch: 1,
    remoteEpoch: 0,
    ratchetPriv: ratchet.priv,
    ratchetPub: ratchet.pub,
    remoteRatchetPub: req.initiatorSessionPub,
    rootKey: root1.rk,
    sendChain: root1.ck,
    hkSend,
    hkRecv: null, // no chain from the initiator yet: its first one opens with HK(root1, initiator)
    myHks: new Set([hkSend]),
    shkSend: shk.sendB64,
    shkRecv: shk.recvB64,
  });
  state.myPubs.add(ratchet.pub);
  return { state, fingerprint, responderPub: hs.pub, responderRatchetPub: ratchet.pub, writeSecret: writeSecrets.responder, delivery };
}

// ---------- initiator completes the handshake ----------

/** Completes the handshake from the responder's join material; returns the converged fingerprint. */
export async function completeHandshake(
  state: RatchetState,
  token: string,
  responderPub: string,
  responderRatchetPub: string,
  responderPqCt: string | null,
  /** b77 (sealed sender): receives both directions' delivery capabilities (contact: the root
   *  contactWriteSecrets uses; invite: rk0). Filled only by the call that completes. */
  out?: { delivery?: DeliveryCaps },
): Promise<string> {
  if (state.role !== 'initiator') throw new Error('Only the initiator completes the handshake');
  if (state.ready) return state.fingerprint!;

  // Batch C (V-12): the initiator binds its OWN dials, never the relay row's
  if (!state.dials) throw new Error('Handshake state incomplete — start a new chat.');
  let rootKey: Uint8Array;
  if (state.contact) {
    // contact: root (and the signing pairs) were derived at create from the
    // peer's signed prekeys; the transcript is finished here (NF-7).
    const cp = state.contactPending;
    if (!cp) throw new Error('Handshake state incomplete — start a new chat.');
    rootKey = state.rootKey;
    state.fingerprint = await contactFingerprint(
      token, cp.initiatorIkPub, cp.responderIkPub, cp.ekPub, cp.spkPub, cp.pqPub, cp.pqCt,
      // b77p (audit VAR-05): responderPub (the relay row's responder_pub_jwk, unauthenticated) is not in it
      state.hsPub, responderRatchetPub, state.dials, fromB64(cp.sharedHash), cp.opk ?? undefined,
    );
    state.contactPending = null;
  } else {
    requirePqCt(responderPqCt, 'invite join');
    if (!state.pqPriv || !state.pqPub || !state.ppSecret) throw new Error('Handshake state incomplete — ask for a fresh invite.');
    const dhOut = dh(state.hsPriv, responderPub);
    const pqSecret = await mlkemDecap(state.pqPriv, responderPqCt as string);
    const combined = combine(dhOut, pqSecret);
    const shared = combine(combined, state.ppSecret);
    rootKey = await deriveRk0(shared, token);
    const sig = await deriveSigPairs(rootKey, token, 'initiator');
    state.sessionSigPrivB64 = sig.privB64;
    state.sessionSigPubB64 = sig.pubB64;
    const shk = await sessionHeaderKeys(rootKey, token, 'initiator'); // b77
    state.shkSend = shk.sendB64;
    state.shkRecv = shk.recvB64;
    state.fingerprint = await inviteFingerprint(token, state.hsPub, responderPub, responderRatchetPub, state.pqPub, responderPqCt as string, state.dials, shared);
    for (const b of [dhOut, pqSecret, combined, shared]) b.fill(0); // b75 (audit 2 V10)
  }
  const step = await pqStepPair();
  const dh1 = dh(state.hsPriv, responderRatchetPub);
  const root1 = await deriveRoot(rootKey, dh1, null);
  const ratchet = x25519Pair();
  const dh2 = dh(ratchet.priv, responderRatchetPub);
  const root2 = await deriveRoot(root1.rk, dh2, null);
  // b75 (audit RT-5): the responder's first chain was derived with salt rk0, mine with
  // salt root1 — each chain's epoch key comes from its own salt
  state.sigPubB64 = await epochSigPubB64(rootKey, 'responder');
  if (out) out.delivery = await deriveDelivery(rootKey); // b77 (sealed sender)
  state.sigPrivB64 = await epochSigPrivB64(root1.rk, 'initiator');
  // b77: the header keys follow the same roots
  state.hkRecv = await headerKeyB64(rootKey, 'responder');
  state.hkSend = await headerKeyB64(root1.rk, 'initiator');
  state.peerHks = new Map();
  state.myHks = new Set([state.hkSend]);
  if (!state.shkSend || !state.shkRecv) throw new Error('Handshake state incomplete — start a new chat.');
  state.sendEpoch = 1;
  state.remoteEpoch = 1;
  state.peerSigPubs = new Map();
  for (const b of [dh1, dh2, rootKey, root1.rk]) b.fill(0); // b75 (audit 2 V10)

  state.rootKey = root2.rk;
  state.ratchetPriv = ratchet.priv;
  state.ratchetPub = ratchet.pub;
  state.remoteRatchetPub = responderRatchetPub;
  state.bound = { initiatorPub: state.hsPub, responderPub, responderRatchetPub };
  state.sendChain = root2.ck;
  state.recvChain = root1.ck;
  state.sendCount = 0;
  state.prevSendCount = 0;
  state.recvCount = 0;
  state.skipped = new Map();
  state.processedIds = new Set<string>();
  state.myPubs = new Set([ratchet.pub]);
  state.pqStepPriv = step.priv;
  state.pqStepPub = step.pub;
  state.pendingPqCt = null;
  // the handshake ML-KEM key and link secret are single-use: drop them
  state.pqPriv = null;
  state.ppSecret?.fill(0); // b70 (audit PRIM-7): overwritten, not just dropped
  state.ppSecret = null;
  // Batch H (round-6 review R6-1-07): the handshake DH key is single-use too — it was
  // kept (and saved, and moved in transfers) for the life of the chat
  state.hsPriv.fill(0); // b70 (audit PRIM-7)
  state.hsPriv = new Uint8Array(32);
  state.ready = true;
  return state.fingerprint!;
}

// ---------- ratchet step ----------

async function stepRatchet(state: RatchetState, header: EnvelopeHeader): Promise<void> {
  if (header.rp === state.ratchetPub) return; // own pub echoed (multi-tab guard) — no step
  if (state.seenRemotePubs.has(header.rp)) {
    throw new StaleMessageError(); // b75 (audit RT-2): an already-replaced key epoch is an old copy
  }
  // verify BEFORE any DH work or state mutation (runs on the candidate state).
  // b75 (audit RT-5): against the epoch key derived from the root this state holds now
  if ((await authenticateHeader(state, header)) !== 'ok') throw new StaleMessageError();
  const newPeerSigPub = await epochSigPubB64(state.rootKey, otherRole(state.role));
  const newPeerHk = await headerKeyB64(state.rootKey, otherRole(state.role)); // b77: the `next` key that opened it
  requirePqPub(header.pq, 'ratchet step');
  // b77m (audit VAR-37): the per-step ML-KEM ciphertext is REQUIRED on every step but one. A peer's new
  // ratchet key is made in its own step, when it answers my last header's PQ key (pendingPqCt), so its
  // headers carry pqct from then on. The one step that can't: the responder's first step, onto the
  // initiator's first ratchet key (made at completeHandshake, before the initiator saw any PQ step key of
  // mine) — that is the responder's only step while it has replaced no remote key yet. Everywhere else a
  // missing pqct (only the authenticated peer can omit it) would quietly drop the PQ term from the root.
  const firstResponderStep = state.role === 'responder' && state.seenRemotePubs.size === 0;
  if (!header.pqct && !firstResponderStep) throw new Error('Post-quantum ciphertext missing on a ratchet step — refusing a downgraded session.');
  let pqRekeySecret: Uint8Array | null = null;
  if (header.pqct) {
    if (!state.pqStepPriv) throw new Error('Post-quantum step key missing — the session is desynchronised.');
    pqRekeySecret = await mlkemDecap(state.pqStepPriv, requirePqCt(header.pqct, 'ratchet step'));
  }
  const { ct, secret: pqAnswerSecret } = await mlkemEncap(header.pq as string);
  state.pendingPqCt = ct;
  if (!state.ratchetPriv) throw new Error('No ratchet key for this session.');
  const dhA = dh(state.ratchetPriv, header.rp);
  const rootA = await deriveRoot(state.rootKey, dhA, pqRekeySecret);
  const fresh = x25519Pair();
  const dhB = dh(fresh.priv, header.rp);
  const rootB = await deriveRoot(rootA.rk, dhB, pqAnswerSecret);
  const step = await pqStepPair();
  // b75 (audit RT-5): my next chain's salt is rootA, so its epoch key comes from rootA; the
  // peer's new chain is verified with the key from the root it was salted with (the one
  // this state held until now). The replaced peer key is kept for its skipped keys.
  if (state.remoteRatchetPub && state.sigPubB64) {
    state.peerSigPubs = new Map(state.peerSigPubs).set(state.remoteRatchetPub, state.sigPubB64);
    while (state.peerSigPubs.size > MAX_PEER_SIG_PUBS) state.peerSigPubs.delete(state.peerSigPubs.keys().next().value as string);
  }
  state.sigPubB64 = newPeerSigPub;
  state.sigPrivB64 = await epochSigPrivB64(rootA.rk, state.role);
  // b77: the header keys move the same way — the replaced peer key is kept (with its epoch
  // key) for late messages, my new chain's key comes from rootA, and my last few are kept
  // to recognise my own echoes
  if (state.remoteRatchetPub && state.hkRecv) {
    state.peerHks = new Map(state.peerHks).set(state.remoteRatchetPub, state.hkRecv);
    while (state.peerHks.size > MAX_PEER_SIG_PUBS) {
      const evicted = state.peerHks.keys().next().value as string;
      state.peerHks.delete(evicted);
      // b77r1 (audit C-1): a chain whose header key is gone can't open a late message any more
      // (it is classed Stale by the session tag), so its skipped keys go with it. This runs on
      // the decrypt candidate: the buffers are only dropped here; the commit zero-fills them.
      dropSkippedChain(state, evicted);
    }
  }
  state.hkRecv = newPeerHk;
  state.hkSend = await headerKeyB64(rootA.rk, state.role);
  state.myHks = new Set(state.myHks).add(state.hkSend);
  while (state.myHks.size > MAX_MY_HKS) state.myHks.delete(state.myHks.keys().next().value as string);
  state.remoteEpoch = header.e as number;
  state.sendEpoch = (state.sendEpoch || 0) + 1;
  // b75 (audit 2 V10): DH outputs and PQ secrets are single-use
  for (const b of [dhA, dhB, pqRekeySecret, pqAnswerSecret, rootA.rk]) b?.fill(0);
  state.prevSendCount = state.sendCount;
  state.sendCount = 0;
  state.recvCount = 0;
  state.rootKey = rootB.rk;
  state.ratchetPriv = fresh.priv;
  state.ratchetPub = fresh.pub;
  if (state.remoteRatchetPub) {
    state.seenRemotePubs.add(state.remoteRatchetPub);
    while (state.seenRemotePubs.size > MAX_SEEN_PUBS) state.seenRemotePubs.delete(state.seenRemotePubs.keys().next().value as string);
  }
  state.remoteRatchetPub = header.rp;
  state.sendChain = rootB.ck;
  state.recvChain = rootA.ck;
  state.myPubs.add(state.ratchetPub);
  while (state.myPubs.size > MAX_MY_PUBS) state.myPubs.delete(state.myPubs.keys().next().value as string);
  state.pqStepPriv = step.priv;
  state.pqStepPub = step.pub;
}

// ---------- chain catch-up ----------

async function messageKeyFor(state: RatchetState, n: number): Promise<Uint8Array> {
  if (!state.recvChain) throw new Error('No receive chain for this message');
  requireLiveChain(state.recvChain, 'receiving'); // b71: never derive from a wiped chain
  if (n < state.recvCount || n - state.recvCount > MAX_COUNTER_GAP) {
    throw new Error('Message counter out of range — the session is desynchronised.');
  }
  while (state.recvCount < n) {
    const step = await advanceChain(state.recvChain);
    state.recvChain = step.ck;
    storeSkipped(state, state.remoteRatchetPub!, state.recvCount, step.mk);
    state.recvCount += 1;
  }
  const step = await advanceChain(state.recvChain);
  state.recvChain = step.ck;
  state.recvCount += 1;
  return step.mk;
}

// b77: senderPseudonym (sender_client_id = 'a' || hex(SHA-256(rp))[0:6], b71) is gone — a 1:1
// envelope carries no sender tag at all, and the relay refuses one (spec §4.10).

// ---------- send ----------

/**
 * b71: one operation at a time per session state, inside the engine. A decrypt works on a
 * candidate copy and commits it at the end; an encrypt that ran in between used to have its
 * chain advance overwritten by that commit (and its zeroed old chain key restored), so the
 * next message key would come from an all-zero chain. Callers serialise today; this makes
 * the engine safe on its own.
 */
const stateLocks = new WeakMap<RatchetState, Promise<unknown>>();
function withStateLock<T>(state: RatchetState, fn: () => Promise<T>): Promise<T> {
  const prev = stateLocks.get(state) ?? Promise.resolve();
  const run = prev.catch(() => undefined).then(fn);
  stateLocks.set(state, run.catch(() => undefined));
  return run;
}

/** b71: a chain key that is all zeros (wiped, or restored from a wiped copy) is never used */
function requireLiveChain(chain: Uint8Array | null | undefined, what: string): Uint8Array {
  if (!chain || chain.length !== 32 || chain.every((b) => b === 0)) throw new Error(`The ${what} chain key is missing or wiped — the session must be re-established.`);
  return chain;
}

/** Returns the envelope to submit to the relay. */
export function encryptMessage(state: RatchetState, text: string, opts: { cover?: boolean; envelopeId?: string; /** b70 (re-review P7): a message a person sees — only these are numbered */ counted?: boolean } = {}): Promise<Envelope> {
  return withStateLock(state, () => encryptMessageLocked(state, text, opts));
}

async function encryptMessageLocked(state: RatchetState, text: string, opts: { cover?: boolean; envelopeId?: string; counted?: boolean }): Promise<Envelope> {
  if (!state.ready) throw new Error('Session keys not established. The session may have ended or locked.');
  // b77: checked before any chain or counter change
  if (!state.hkSend || !state.shkSend) throw new Error('Session header key missing — the handshake is incomplete.');
  if (!state.pqStepPub) {
    const step = await pqStepPair();
    state.pqStepPriv = step.priv;
    state.pqStepPub = step.pub;
  }
  // b70 (audit L-1): the sender's time and sequence travel inside the encryption
  // b70 (re-review P7): only human-visible messages are numbered (seq 0 = not
  // counted): receipts, call signals and cover traffic can expire or be retired
  // without being "missing"
  // b71: framed before any chain or counter change, so a refused message (too long)
  // uses up no chain step and no sequence number (only a stored state with no PQ step
  // key gets one generated first, above)
  const counted = !!opts.counted && !opts.cover;
  const seq = counted ? (state.sendSeq || 0) + 1 : 0;
  const padded = padPlaintext(text, !!opts.cover, { sentAt: Date.now(), seq });
  // b77r1 (audit C-3): the step is derived, the header signed and sealed and the message key
  // imported BEFORE anything is committed — a failure there (a corrupt stored header key) used
  // to leave the chain advanced, its old key zeroed and a counter spent, with nothing sent
  const step = await advanceChain(requireLiveChain(state.sendChain, 'sending'));
  // (the IV is drawn here, where it always was relative to the header seal's nonces)
  const iv = crypto.getRandomValues(new Uint8Array(12));
  let headerStr: string;
  let key: CryptoKey;
  try {
    const header: EnvelopeHeader = {
      v: state.proto,
      rp: state.ratchetPub,
      pn: state.prevSendCount,
      n: state.sendCount,
      e: state.sendEpoch || 1, // b75 (audit RT-5)
      pq: state.pqStepPub!,
    };
    // The ct is re-sent until the sender's NEXT rotation replaces it: the
    // re-send IS the delivery mechanism for the PQ re-key (a lost first copy
    // must not desync the chains). The peer decapsulates it only at its DH step
    // (the first message with this rp it opens); copies on later messages are
    // ignored. b71: at that step the ct always answers the peer's current step key
    // (it changes only at the peer's own next step); a mismatched ct would decap to
    // a different secret (implicit rejection), the root would differ, and the
    // message would fail AEAD with no state change.
    if (state.pendingPqCt) header.pqct = state.pendingPqCt;
    const sigs = signHeader(state, header);
    header.sig = sigs.sig;
    header.ssig = sigs.ssig; // b75 (audit RT-5)
    // b77 (veil-ratchet-8): the signed JSON header travels sealed under my chain's header key;
    // the message AEAD's AAD is the sealed header string
    headerStr = await sealHeader(JSON.stringify(header), state.hkSend as string, state.shkSend as string, header.e as number);
    key = await importAesKey(step.mk);
  } catch (e) {
    step.ck.fill(0); step.mk.fill(0); // nothing committed: the step is discarded
    padded.fill(0);
    throw e;
  }
  step.mk.fill(0); // b75 (audit 2 V10): the AES key object holds its own copy
  // commit the step
  state.sendChain?.fill(0); // b70 (audit PRIM-7): the old chain key can't be recovered from memory
  state.sendChain = step.ck;
  state.sendCount += 1;
  if (counted) state.sendSeq = seq;
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv as BufferSource, additionalData: utf8(headerStr) as BufferSource }, key, padded as BufferSource);
  padded.fill(0); // b75 (audit 2 V10): the padded plaintext
  return { ciphertext: toB64(new Uint8Array(ct)), iv: toB64(iv), header: headerStr, byteLength: padded.length };
}

// ---------- receive ----------

export interface DecryptedMessage {
  text: string;
  cover: boolean;
  /** b70 (audit L-1): the sender's own time and sequence (absent from older builds) */
  meta?: { sentAt: number; seq: number };
  /** b70 (L-1): the peer's highest sequence number before this message */
  prevSeqMax?: number;
}

/** Decrypts an envelope. `envelope.header` is the serialized header (AAD).
 *  b75 (audit RT-2): failures are typed — JunkEnvelopeError (does not authenticate),
 *  StaleMessageError / ReplayedMessageError (an authentic old copy) and OutOfSyncError (an
 *  authentic header this device's keys no longer match). b77p (audit VAR-04): an AES-GCM failure of
 *  the BODY under an authenticated header is TamperedBodyError (a JunkEnvelopeError): the header
 *  signature doesn't cover the body, so the relay can make it. Anything else (a counter gap past
 *  MAX_COUNTER_GAP, a frame that authenticated but doesn't parse) is a real decryption failure. */
export function decryptMessage(state: RatchetState, envelope: Envelope, envelopeId?: string): Promise<DecryptedMessage | null> {
  return withStateLock(state, () => decryptMessageLocked(state, envelope, envelopeId));
}

function rememberProcessedId(state: RatchetState, envelopeId: string): void {
  state.processedIds.add(envelopeId);
  if (state.processedIds.size > MAX_PROCESSED_IDS) state.processedIds.delete(state.processedIds.keys().next().value as string);
}
/** b77u (audit 6 R4 #10): the own-echo path's commit — the id goes into a NEW set swapped in as one step, never a
 *  mutation of the live set (a copy taken before this call, such as a candidate or a serialisation in flight, keeps
 *  what it saw), like the decrypt path's Object.assign commit */
function commitProcessedId(state: RatchetState, envelopeId: string): void {
  const next = new Set(state.processedIds);
  next.add(envelopeId);
  if (next.size > MAX_PROCESSED_IDS) next.delete(next.keys().next().value as string);
  state.processedIds = next;
}

async function decryptMessageLocked(state: RatchetState, envelope: Envelope, envelopeId?: string): Promise<DecryptedMessage | null> {
  if (!state.ready) throw new Error('Session keys not established. The session may have ended or locked.');
  if (envelopeId && state.processedIds.has(envelopeId)) return null; // idempotent replay guard
  // b77p (audit VAR-04): a header whose body already failed AES-GCM here — one AES-GCM attempt under the
  // key derived then; a body that fails again is refused before any header, DH or ML-KEM work
  const fbGen = failedBodyGen; // b77s (audit 4 CR-1)
  sweepFailedBodyCache(); // b77s (audit 4 CR-1): every expired entry, not only this header's
  const fbKey = failedBodyKeyOf(state, envelope.header);
  const fb = failedBodyKeys.get(fbKey);
  if (fb) {
    try {
      const k0 = await importAesKey(fb.mk);
      const pt0 = new Uint8Array(await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: fromB64(envelope.iv) as BufferSource, additionalData: utf8(envelope.header) as BufferSource },
        k0, fromB64(envelope.ciphertext) as BufferSource));
      pt0.fill(0);
    } catch { throw new TamperedBodyError(); }
    // b77u (audit 6 R4 #10): the cached key is dropped at the commit below, not here (a genuine body whose frame or
    // step then fails keeps the cache entry, so a re-served copy still costs one AES-GCM attempt)
  }
  // b77 (veil-ratchet-8): the header is opened first (trial decrypts under the header keys,
  // spec §4.2). Unopenable is junk (or, by the session tag, an old copy / out of sync).
  const oh = await openHeader(state, envelope.header);
  // an envelope my own header keys open is my own echo (b77: was "rp is one of OUR pubs").
  // b75 (audit 2 V11): its id is remembered like any processed envelope, so a relay that
  // keeps re-serving it is answered from the id check above without re-opening it
  if (oh.kind === 'own' || !oh.header) {
    if (envelopeId) commitProcessedId(state, envelopeId); // b77u (R4 #10)
    return null;
  }
  const header = oh.header;
  if (!(RATCHET_PROTOCOL_SUPPORTED as readonly string[]).includes(header.v)) throw new JunkEnvelopeError('Unsupported protocol version in message header.');
  if (typeof header.rp === 'string' && state.myPubs.has(header.rp)) {
    if (envelopeId) commitProcessedId(state, envelopeId); // b77u (R4 #10)
    return null;
  }
  // Work on an isolated candidate state: a malformed envelope must not consume
  // skipped keys, advance receive counters, or rotate root keys before AEAD
  // authentication succeeds.
  const candidate: RatchetState = {
    ...state,
    seenRemotePubs: new Set(state.seenRemotePubs),
    myPubs: new Set(state.myPubs),
    processedIds: new Set(state.processedIds),
    skipped: new Map([...state.skipped].map(([rp, keys]) => [rp, new Map(keys)])),
    skippedAt: new Map(state.skippedAt),
    peerSigPubs: new Map(state.peerSigPubs),
    peerHks: new Map(state.peerHks),
    myHks: new Set(state.myHks),
  };
  pruneSkipped(candidate, Date.now(), true, false); // b70 (audit info); b71: no overwrite before commit
  // b74 (VAR-09): every header is authenticated before any chain or DH work. The
  // signature covers both counters, so a forged header can no longer make this device
  // derive up to MAX_COUNTER_GAP keys; a replayed genuine header costs no more than the
  // genuine message did. b75 (audit RT-5): against the epoch key, which heals.
  const auth = await authenticateHeader(candidate, header);
  const skippedAt = candidate.skippedAt.get(header.rp + ':' + header.n); // b77s (audit 4 CR-1)
  let mk = takeSkipped(candidate, header);
  const mkFromSkipped = !!mk;
  try {
    if (!mk) {
      // b75 (audit RT-2 / audit 2 V5): an authentic header whose key is already used (current
      // chain), whose epoch was replaced, or whose epoch key this device no longer keeps, is
      // an old copy — a relay replay (whatever IV it now carries, however its JSON is spaced),
      // a copy older than the replay window, or a late message whose skipped key expired.
      // Typed, so the caller ledgers it instead of counting a desync. One whose signed fields
      // match a header this session opened is a plain duplicate. (A sender restored from an old
      // state re-signs the same header, so what it re-sends under a used counter is dropped
      // too — known limit, spec §8.2.)
      if (auth === 'gone' || candidate.seenRemotePubs.has(header.rp) || (header.rp === state.remoteRatchetPub && header.n < candidate.recvCount)) {
        if (candidate.seenDigests.has(await headerDigest(header))) throw new ReplayedMessageError();
        throw new StaleMessageError();
      }
      if (header.rp !== state.remoteRatchetPub) {
        await skipOldChainBeforeRotation(candidate, header.pn);
        await stepRatchet(candidate, header);
      }
      mk = await messageKeyFor(candidate, header.n);
    }
    const key = await importAesKey(mk);
    let pt: ArrayBuffer;
    try {
      pt = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: fromB64(envelope.iv) as BufferSource, additionalData: utf8(envelope.header) as BufferSource },
        key,
        fromB64(envelope.ciphertext) as BufferSource,
      );
    } catch {
      // b77p (audit VAR-04): the header authenticated, the body (or its IV) did not — relay-forgeable
      // junk, never a desync. The key is cached so a re-served copy can't cost another ratchet step.
      // b77s (audit 4 CR-1): a key taken from the skipped store is cached no longer than it would have been kept there
      rememberFailedBody(fbKey, mk, fbGen, mkFromSkipped && skippedAt !== undefined ? skippedAt + SKIPPED_KEY_MAX_AGE_MS : undefined);
      throw new TamperedBodyError();
    }
    const ptBytes = new Uint8Array(pt);
    // b76 (padding): the frame is stripped strictly (exact class, zero padding, its own
    // length) — a frame that fails throws here and the candidate is discarded (§4.4 step 11)
    let opened: ReturnType<typeof unpadPlaintext>;
    try { opened = unpadPlaintext(ptBytes); } finally { ptBytes.fill(0); } // b75 (audit 2 V10)
    const { text, cover, meta } = opened;
    const prevSeqMax = candidate.recvSeqMax || 0;
    if (meta && !cover && meta.seq > 0 && meta.seq > prevSeqMax) candidate.recvSeqMax = meta.seq;
    candidate.seenDigests = new Set(candidate.seenDigests).add(await headerDigest(header));
    while (candidate.seenDigests.size > MAX_SEEN_DIGESTS) candidate.seenDigests.delete(candidate.seenDigests.keys().next().value as string);
    if (envelopeId) rememberProcessedId(candidate, envelopeId);
    // b70 (audit PRIM-7): once committed, key buffers the new state no longer
    // uses are overwritten (before the commit they still back the rollback copy)
    const replaced = [state.ratchetPriv, state.rootKey, state.recvChain, state.sendChain].filter((b): b is Uint8Array => !!b);
    // b71: and the skipped keys the new state no longer holds (expired, evicted)
    for (const per of state.skipped.values()) for (const k of per.values()) replaced.push(k);
    Object.assign(state, candidate); // commit only after authenticated decrypt + frame parse
    if (fb) dropFailedBodyKey(fbKey); // b77u (audit 6 R4 #10): the failed-body cache changes with the commit only
    const live = new Set<Uint8Array | null>([state.ratchetPriv, state.rootKey, state.recvChain, state.sendChain]);
    for (const per of state.skipped.values()) for (const k of per.values()) live.add(k);
    for (const b of replaced) if (!live.has(b) && b !== mk) b.fill(0);
    mk.fill(0);
    return { text, cover, ...(meta ? { meta, prevSeqMax } : {}) };
  } catch (e) {
    // b75 (audit 2 V10): a refused envelope leaves no key material behind — buffers this
    // candidate derived itself (a stepped root, chain or ratchet key, a fresh message key)
    // are overwritten; anything still shared with the live state is left alone
    const liveBufs = new Set<Uint8Array | null>([state.ratchetPriv, state.rootKey, state.recvChain, state.sendChain]);
    for (const per of state.skipped.values()) for (const k of per.values()) liveBufs.add(k);
    for (const b of [candidate.ratchetPriv, candidate.rootKey, candidate.recvChain, candidate.sendChain]) if (b && !liveBufs.has(b)) b.fill(0);
    for (const per of candidate.skipped.values()) for (const k of per.values()) if (!liveBufs.has(k)) k.fill(0);
    if (mk && !mkFromSkipped && !liveBufs.has(mk)) mk.fill(0);
    throw e;
  }
}

// ---------- persistence ----------

export interface RatchetStateSerialized {
  proto: string;
  role: SessionRole;
  seenRemotePubs: string[];
  contact: boolean;
  ready: boolean;
  fingerprint: string | null;
  pq: 'hybrid';
  writeSecret: string | null;
  hsPub: string;
  hsPrivB64: string;
  bound: RatchetState['bound'];
  pqPub: string | null;
  pqPriv: string | null;
  pqStepPriv: string | null;
  pqStepPub: string | null;
  pendingPqCt: string | null;
  sigPrivB64: string | null;
  sigPubB64: string | null;
  /** b75 (audit RT-5) */
  sessionSigPrivB64?: string | null;
  sessionSigPubB64?: string | null;
  peerSigPubs?: Array<[string, string]>;
  sendEpoch?: number;
  remoteEpoch?: number;
  dials: string | null;
  contactPending: RatchetState['contactPending'];
  ppSecretB64: string | null;
  ratchetPub: string;
  ratchetPrivB64: string | null;
  remoteRatchetPub: string | null;
  myPubs: string[];
  rootKeyB64: string;
  sendChainB64: string | null;
  recvChainB64: string | null;
  sendCount: number;
  prevSendCount: number;
  recvCount: number;
  processedIds: string[];
  skipped: Array<[string, Array<[number, string]>]>;
  /** b70 (L-1); absent in older saves (0) */
  sendSeq?: number;
  skippedAt?: Array<[string, number]>;
  recvSeqMax?: number;
  /** b74 (VAR-15) */
  seenDigests?: string[];
  /** b77 (veil-ratchet-8): header keys (required: a ready state without them is refused) */
  hkSend?: string | null;
  hkRecv?: string | null;
  peerHks?: Array<[string, string]>;
  myHks?: string[];
  shkSend?: string | null;
  shkRecv?: string | null;
}

/** True when a stored session predates the current protocol (b54 hard cut; Batch C: veil-ratchet-6).
 *  b75 (audit RT-5): also a b74-format veil-ratchet-7 state — a completed (or one-tap) chat
 *  with no session signing key, whose header keys never ratchet. b74 never reached testers;
 *  such a chat could not talk to a b75 peer, so it ends cleanly instead of failing later. */
export function isLegacySessionState(data: unknown): boolean {
  if (!data || typeof data !== 'object') return false;
  // b77p (audit VAR-06): a chat the peer ended keeps its record with every key dropped (SessionStore.dropRatchetKeys):
  // read-only history, not an older protocol
  if (Number((data as { keysDropped?: unknown }).keysDropped) > 0) return false;
  const d = data as { proto?: unknown; ready?: unknown; contact?: unknown; sessionSigPubB64?: unknown };
  if (d.proto !== RATCHET_PROTOCOL_LATEST) return true;
  // b77: a completed veil-ratchet-8 chat always has its header keys (a one-tap initiator
  // gets the session header-tag keys at create, the header keys at completion)
  const k = data as { hkSend?: unknown; shkSend?: unknown; shkRecv?: unknown };
  if (d.ready === true && (!k.hkSend || !k.shkSend || !k.shkRecv)) return true;
  if (d.contact === true && (!k.shkSend || !k.shkRecv)) return true;
  return (d.ready === true || d.contact === true) && !d.sessionSigPubB64;
}

/** b71: under the engine lock — a save prunes and zero-fills expired keys, which must
 *  not interleave with a decrypt that is still using them */
export function serializeRatchetState(state: RatchetState): Promise<RatchetStateSerialized> {
  return withStateLock(state, () => serializeRatchetStateLocked(state));
}

async function serializeRatchetStateLocked(state: RatchetState): Promise<RatchetStateSerialized> {
  // b71: expired skipped keys go at every save too (they used to wait for the next
  // successful decrypt, so an idle chat kept them past their age)
  pruneSkipped(state, Date.now(), false); // (empty chain entries kept: saved bytes stay as before)
  sweepFailedBodyCache(); // b77s (audit 4 CR-1)
  return {
    proto: state.proto,
    role: state.role,
    seenRemotePubs: [...state.seenRemotePubs],
    contact: state.contact,
    ready: state.ready,
    fingerprint: state.fingerprint,
    pq: state.pq,
    writeSecret: state.writeSecret,
    hsPub: state.hsPub,
    hsPrivB64: toB64(state.hsPriv),
    bound: state.bound,
    pqPub: state.pqPub,
    pqPriv: state.pqPriv,
    pqStepPriv: state.pqStepPriv,
    pqStepPub: state.pqStepPub,
    pendingPqCt: state.pendingPqCt,
    sigPrivB64: state.sigPrivB64,
    sigPubB64: state.sigPubB64,
    sessionSigPrivB64: state.sessionSigPrivB64,
    sessionSigPubB64: state.sessionSigPubB64,
    peerSigPubs: [...state.peerSigPubs.entries()],
    sendEpoch: state.sendEpoch,
    remoteEpoch: state.remoteEpoch,
    dials: state.dials,
    contactPending: state.contactPending,
    ppSecretB64: state.ppSecret ? toB64(state.ppSecret) : null,
    ratchetPub: state.ratchetPub,
    ratchetPrivB64: state.ratchetPriv ? toB64(state.ratchetPriv) : null,
    remoteRatchetPub: state.remoteRatchetPub,
    myPubs: [...state.myPubs],
    rootKeyB64: toB64(state.rootKey),
    sendChainB64: state.sendChain ? toB64(state.sendChain) : null,
    recvChainB64: state.recvChain ? toB64(state.recvChain) : null,
    sendCount: state.sendCount,
    prevSendCount: state.prevSendCount,
    recvCount: state.recvCount,
    processedIds: [...state.processedIds],
    sendSeq: state.sendSeq,
    recvSeqMax: state.recvSeqMax,
    skippedAt: [...state.skippedAt.entries()],
    seenDigests: [...state.seenDigests],
    hkSend: state.hkSend,
    hkRecv: state.hkRecv,
    peerHks: [...state.peerHks.entries()],
    myHks: [...state.myHks],
    shkSend: state.shkSend,
    shkRecv: state.shkRecv,
    skipped: [...state.skipped.entries()].map(([rp, m]) => [rp, [...m.entries()].map(([n, mk]) => [n, toB64(mk)])] as [string, Array<[number, string]>]),
  };
}

/** b77r1 (audit C-3): a stored header key or session header-tag key must decode to exactly 32
 *  bytes; a corrupt one is refused at load, not discovered at the next send or receive */
function storedKey32(v: unknown, what: string): string | null {
  if (v === undefined || v === null) return null;
  let b: Uint8Array | null = null;
  try { b = typeof v === 'string' ? fromB64(v) : null; } catch { b = null; }
  const ok = !!b && b.length === 32;
  b?.fill(0);
  if (!ok) throw new Error(`Stored chat state is damaged (${what}) — this chat can't continue on this phone.`);
  return v as string;
}

export async function deserializeRatchetState(data: RatchetStateSerialized): Promise<RatchetState> {
  if (isLegacySessionState(data) || data.pq !== 'hybrid') throw new LegacySessionError();
  // b77r1 (audit C-3)
  const hkSend = storedKey32(data.hkSend, 'hkSend');
  const hkRecv = storedKey32(data.hkRecv, 'hkRecv');
  const shkSend = storedKey32(data.shkSend, 'shkSend');
  const shkRecv = storedKey32(data.shkRecv, 'shkRecv');
  const peerHks = new Map(Array.isArray(data.peerHks) ? data.peerHks.filter((e): e is [string, string] => Array.isArray(e) && typeof e[0] === 'string' && typeof e[1] === 'string') : []);
  for (const k of peerHks.values()) storedKey32(k, 'peerHks');
  const myHks = new Set(Array.isArray(data.myHks) ? data.myHks.filter((x): x is string => typeof x === 'string') : []);
  for (const k of myHks) storedKey32(k, 'myHks');
  return {
    role: data.role,
    proto: data.proto,
    seenRemotePubs: new Set(data.seenRemotePubs ?? []),
    contact: data.contact,
    ready: data.ready,
    fingerprint: data.fingerprint,
    pq: 'hybrid',
    writeSecret: data.writeSecret ?? null,
    // Batch H (R6-1-07): a completed chat needs no handshake key; older saves drop it here
    hsPriv: data.ready ? new Uint8Array(32) : fromB64(data.hsPrivB64),
    hsPub: data.hsPub,
    bound: data.bound,
    pqPub: data.pqPub ?? null,
    pqPriv: data.pqPriv,
    pqStepPriv: data.pqStepPriv,
    pqStepPub: data.pqStepPub,
    pendingPqCt: data.pendingPqCt,
    sigPrivB64: data.sigPrivB64 ?? null,
    sigPubB64: data.sigPubB64 ?? null,
    sessionSigPrivB64: data.sessionSigPrivB64 ?? null,
    sessionSigPubB64: data.sessionSigPubB64 ?? null,
    peerSigPubs: new Map(Array.isArray(data.peerSigPubs) ? data.peerSigPubs.filter((e): e is [string, string] => Array.isArray(e) && typeof e[0] === 'string' && typeof e[1] === 'string') : []),
    sendEpoch: Number(data.sendEpoch) || 0,
    remoteEpoch: Number(data.remoteEpoch) || 0,
    dials: data.dials ?? null,
    contactPending: data.contactPending ?? null,
    ppSecret: data.ppSecretB64 ? fromB64(data.ppSecretB64) : null,
    ratchetPriv: data.ratchetPrivB64 ? fromB64(data.ratchetPrivB64) : null,
    ratchetPub: data.ratchetPub,
    remoteRatchetPub: data.remoteRatchetPub,
    myPubs: new Set(data.myPubs),
    rootKey: fromB64(data.rootKeyB64),
    sendChain: data.sendChainB64 ? fromB64(data.sendChainB64) : null,
    recvChain: data.recvChainB64 ? fromB64(data.recvChainB64) : null,
    sendCount: data.sendCount,
    prevSendCount: data.prevSendCount,
    recvCount: data.recvCount,
    processedIds: new Set(data.processedIds),
    sendSeq: Number(data.sendSeq) || 0,
    recvSeqMax: Number(data.recvSeqMax) || 0,
    skippedAt: new Map(Array.isArray(data.skippedAt) ? data.skippedAt : []),
    seenDigests: new Set(Array.isArray(data.seenDigests) ? data.seenDigests.filter((x): x is string => typeof x === 'string') : []),
    skipped: new Map(data.skipped.map(([rp, m]) => [rp, new Map(m.map(([n, mkB64]) => [n, fromB64(mkB64)]))])),
    hkSend,
    hkRecv,
    peerHks,
    myHks,
    shkSend,
    shkRecv,
  };
}
