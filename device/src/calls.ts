/**
 * @veil/device — CALLS core: signalling, guard rails and the local-only
 * integrity monitor. What the code actually does:
 *
 *  - Signalling (offer / answer / ICE / ringing / end) is a control payload
 *    tagged __veil_call, sent inside the existing end-to-end encrypted chat
 *    session (the same hybrid post-quantum ratchet and submitEnvelope channel
 *    as a chat message). The relay sees only cipher-text. The SDP inside it
 *    carries each side's DTLS certificate fingerprint, so those fingerprints
 *    are authenticated by the chat session.
 *  - Media is standard WebRTC DTLS-SRTP. Its keys come from the DTLS
 *    handshake, i.e. classical (EC)DHE: call AUDIO is NOT post-quantum. What
 *    the chat session adds is that the DTLS certificate each side accepts is
 *    the one the peer sent inside the encrypted signalling
 *    (verifyAppliedRemoteSdp below, run by CallManager on the description it
 *    actually applied).
 *  - There is no extra per-frame encryption layer. An earlier design had one
 *    (a per-call AES-GCM frame key in the offer); it was never wired into the
 *    media path and has been removed. The offer still carries a dummy `k`
 *    field only because older builds refuse an offer without one.
 *  - Calls run over TURN relays only (CallManager): no call starts without
 *    relay servers, so the peer never learns this phone's IP address.
 *
 * The call integrity monitor: LOCAL-ONLY, append-only, per-call event log
 * (fingerprint hard-fails, degradation). Never uploaded; destroyed with the
 * call.
 */

import { randomBytes } from '../../crypto-core/src/index';
import { serializeRatchetSend } from './send-queue';
import { saveOrThrow } from './save-strict';
import { requireDelivery, sealedSend, syncInboundVerified } from './sealed';
import type { SealedSubmission } from './relay';

export const CALL_CONTROL_TAG = '__veil_call';

/** Sent as `k` in every offer. Builds before the frame layer was removed
 *  refuse an offer without a `k`; nothing reads its value, so it is not a key
 *  and is the same for every call. */
export const LEGACY_OFFER_K = 'unused';

// ---------------------------------------------------------------------------
// Signalling payloads (ride the existing end-to-end encrypted chat session)
// ---------------------------------------------------------------------------

export type CallSignalOp = 'invite' | 'offer' | 'answer' | 'ice' | 'end' | 'ringing'; // 'ringing' (21 Oct 2026): the callee confirms the call reached its screen
// b77n (audit VAR-04): 'invite' rings the callee and carries the call's TURN grant id; the callee's
// phone approves the grant as it rings, and only then can the caller get relay credentials, build
// its connection and send the 'offer' (SDP). See CallManager and spec §12.12.

export interface CallSignal {
  __veil_call: 1;
  op: CallSignalOp;
  /** 16-hex-char random id, fresh per call attempt */
  call_id: string;
  /** op=invite (b77n): the call's TURN grant id (64 hex) — the callee approves it on its own inbound */
  grant?: string;
  /** op=offer / answer: the SDP, including this side's DTLS fingerprint. */
  sdp?: string;
  /** op=offer only: LEGACY_OFFER_K. Not a key; older builds require the field. */
  k?: string;
  /** op=ice: one ICE candidate, as serialized by WebRTC */
  cand?: string;
  /** op=ice (20 Oct 2026): a batch of candidates; `cand` still holds the first,
   *  so a build that predates batching reads at least that one */
  cands?: string[];
  /** op=end: as sent, the sender's reason ('hangup' | 'busy' | 'missed' | 'refused' | a CallManager teardown
   *  reason); b77m (audit VAR-25): as received (parseCallSignal), always this phone's own text for it
   *  (PEER_CALL_END_TEXT), never the peer's words */
  reason?: string;
  /** monotonic attempt number — replays of an OLD offer for the same
   *  call_id are refused by the answerer (tested). */
  seq?: number;
  /** Sender's clock when the signal was sent (epoch ms). Inside the encrypted
   *  payload, so the relay can't change it; an offer far from now never rings. */
  ts?: number;
  /** Set on RECEIVE only, by the sync layer: the ratchet frame's own
   *  authenticated send time (decrypted meta.sentAt). Never read from the
   *  payload itself (parseCallSignal drops it). */
  sentAt?: number;
}

export function newCallId(): string {
  return [...randomBytes(8)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

/**
 * b77m (audit VAR-25): the call-end reasons a peer can give, and the text THIS phone shows for each.
 * The peer's `reason` used to be shown verbatim on the call card ("Call ended · <anything>", in the
 * slot used for this phone's own verdicts such as "security check failed"), any type, any length,
 * bidi characters included. Now a received reason is looked up here (exact, case-insensitive, after
 * trimming) and replaced by the app-written text; anything else becomes 'ended'. The values on the
 * left are what builds send (CallManager teardown reasons, and the older 'hangup' | 'busy' | 'missed'
 * | 'refused'), so the wire format is unchanged. The texts say what the OTHER phone reported.
 */
export const PEER_CALL_END_TEXT: Readonly<Record<string, string>> = {
  'hangup': 'hung up',
  'ended': 'ended',
  'busy': 'the other phone is busy',
  'missed': 'missed',
  'no answer': 'no answer',
  'declined': 'declined',
  'refused': 'declined',
  'call refused': 'declined',
  'not reachable': 'the other phone could not be reached',
  'call failed to connect': 'call failed to connect',
  'could not start the call': 'the other phone could not start the call',
  'replaced by a newer call': 'replaced by a newer call',
  'ended on the lock screen': 'ended',
  'security check failed': 'the other phone reported a failed security check',
  "couldn't reach the call relay — try again": 'the other phone could not reach the call relay',
};
/** b77m (audit VAR-25): the most characters of a reason looked up (anything longer is 'ended') */
const CALL_REASON_MAX = 64;

/** b77m (audit VAR-25): the app-written text for a peer's call-end reason ('ended' for anything unknown) */
export function peerCallEndText(reason: unknown): string {
  if (typeof reason !== 'string' || reason.length > CALL_REASON_MAX) return 'ended';
  const k = reason.trim().toLowerCase();
  return Object.prototype.hasOwnProperty.call(PEER_CALL_END_TEXT, k) ? PEER_CALL_END_TEXT[k] : 'ended';
}

/** b77m (audit VAR-25): bounds on the other signal fields (schema check on receive) */
const CALL_ID_RE = /^[A-Za-z0-9_-]{1,64}$/; // newCallId: 16 hex
const CALL_SDP_MAX = 262144;
const CALL_CAND_MAX = 4096;
const CALL_CANDS_MAX = 64;

export function parseCallSignal(text: string): CallSignal | null {
  if (typeof text !== 'string' || !text.startsWith('{"__veil_call":')) return null;
  try {
    const t = JSON.parse(text) as CallSignal;
    if (!t || typeof t !== 'object' || t.__veil_call !== 1 || typeof t.call_id !== 'string') return null;
    if (!['invite', 'offer', 'answer', 'ice', 'end', 'ringing'].includes(t.op)) return null;
    // b77m (audit VAR-25): every field is schema-checked; a malformed one fails the whole signal
    if (!CALL_ID_RE.test(t.call_id)) return null;
    if (t.sdp !== undefined && (typeof t.sdp !== 'string' || t.sdp.length > CALL_SDP_MAX)) return null;
    if (t.k !== undefined && (typeof t.k !== 'string' || t.k.length > 256)) return null;
    if (t.cand !== undefined && (typeof t.cand !== 'string' || t.cand.length > CALL_CAND_MAX)) return null;
    if (t.cands !== undefined && (!Array.isArray(t.cands) || t.cands.length > CALL_CANDS_MAX || t.cands.some((c) => typeof c !== 'string' || c.length > CALL_CAND_MAX))) return null;
    if (t.seq !== undefined && !(Number.isSafeInteger(t.seq) && t.seq >= 0)) return null;
    // b77n (audit VAR-04): an invite carries exactly one well-formed grant id; nothing else carries one
    if (t.op === 'invite' ? !(typeof t.grant === 'string' && /^[0-9a-f]{64}$/.test(t.grant)) : t.grant !== undefined) return null;
    delete (t as { sentAt?: unknown }).sentAt; // only the sync layer sets it, from the frame
    if (t.ts !== undefined && (typeof t.ts !== 'number' || !Number.isFinite(t.ts))) delete t.ts;
    // b77m (audit VAR-25): the reason becomes this phone's own text (the call card shows it as-is)
    if (t.op === 'end') t.reason = peerCallEndText(t.reason);
    else delete t.reason;
    return t;
  } catch { return null; }
}

/** True when a decrypted chat payload is a call control signal — the sync
 *  loop filters these out of the message list exactly like receipts/cover. */
export function isCallSignal(text: string): boolean {
  return parseCallSignal(text) !== null;
}

// ---------------------------------------------------------------------------
// Fingerprint binding — the DTLS certificate is the one the encrypted
// signalling carried
// ---------------------------------------------------------------------------

/** Extract the DTLS certificate fingerprint from an SDP body. WebRTC SDP
 *  carries exactly one a=fingerprint line per m= section in practice; we
 *  require ALL of them to be identical and return it, or null on none/
 *  mismatch — a mismatched set is itself a hard fail (tampered SDP). */
export function extractDtlsFingerprint(sdp: string): string | null {
  if (typeof sdp !== 'string' || sdp.length > 262144) return null; // fuzz guard: SDP beyond 256KB is hostile
  const fps = [...sdp.matchAll(/^a=fingerprint:(\S+)\s+([0-9A-Fa-f:]{16,200})\s*$/gm)];
  if (fps.length === 0) return null;
  const norm = (m: RegExpMatchArray) => `${(m[1] || '').toLowerCase()} ${(m[2] || '').toUpperCase()}`;
  const first = norm(fps[0]);
  return fps.every((m) => norm(m) === first) ? first : null;
}

export class CallRefusedError extends Error {
  constructor(public readonly code: 'fingerprint-mismatch' | 'malformed-sdp' | 'replayed-offer' | 'unknown-call') {
    super(code);
    Object.setPrototypeOf(this, CallRefusedError.prototype);
  }
}

// ---------------------------------------------------------------------------
// Integrity monitor (S3b) — LOCAL-ONLY, append-only, per call
// ---------------------------------------------------------------------------

export type CallEventClass = 'fingerprint' | 'tamper' | 'replay' | 'degraded' | 'churn'; // tamper/replay: kept for the monitor's banner rule; no media path records them

export interface CallEvent {
  cls: CallEventClass;
  detail: string;
  ts: number;
  call_id: string;
}

/** Tamper/replay escalate to a banner after >2 events inside 10s (S3b.2). */
const TAMPER_WINDOW_MS = 10_000;
const TAMPER_BANNER_THRESHOLD = 2;

export class CallIntegrityMonitor {
  private events: CallEvent[] = [];
  constructor(private readonly callId: string) {}

  record(cls: CallEventClass, detail: string): void {
    this.events.push({ cls, detail, ts: Date.now(), call_id: this.callId });
  }

  /** >2 tamper/replay events inside the 10s window -> surface the banner. */
  bannerDue(now = Date.now()): boolean {
    const recent = this.events.filter((e) => (e.cls === 'tamper' || e.cls === 'replay') && now - e.ts <= TAMPER_WINDOW_MS);
    return recent.length > TAMPER_BANNER_THRESHOLD;
  }

  /** Amber in-call dot: any degradation events, and no hard-fail so far. */
  status(now = Date.now()): 'ok' | 'amber' | 'red' {
    if (this.events.some((e) => e.cls === 'fingerprint' || e.cls === 'churn')) return 'red';
    if (this.events.some((e) => e.cls === 'degraded') || this.bannerDue(now)) return 'amber';
    return 'ok';
  }

  /** Post-call report — device-local only, exportable by the user, wiped by
   *  NaR/duress/sign-out alongside all other local data. */
  report(): CallEvent[] { return [...this.events]; }
  /** Hard reset on call teardown — keys and counters never outlive the call. */
  destroy(): void { this.events = []; }
}

// ---------------------------------------------------------------------------
// Call state machine — the answerer-side guard rails
// ---------------------------------------------------------------------------

export type CallPhase = 'idle' | 'ringing' | 'active' | 'ended';

export interface CallState {
  callId: string;
  phase: CallPhase;
  /** the PEER's DTLS fingerprint as carried in its encrypted offer (callee)
   *  or answer (caller): what the applied remote description must match */
  offerFingerprint: string | null;
  seqSeen: number;
}

/**
 * Process an inbound offer as the CALLEE. Hard-fails (CallRefusedError):
 *  - malformed-sdp: no single consistent a=fingerprint in the offer
 *  - replayed-offer: same call_id re-offered with a stale seq (a replayed
 *    envelope must never ring twice)
 *  - fingerprint-mismatch: an SDP whose fingerprint differs from the one
 *    already authenticated for this call_id (mid-call churn / MITM)
 * On success: phase -> ringing, fingerprint bound. (`k` is not checked:
 * it is a legacy filler, see LEGACY_OFFER_K.)
 */
export function processOffer(state: CallState, sig: CallSignal): CallState {
  if (sig.op !== 'offer') throw new CallRefusedError('unknown-call');
  const fp = extractDtlsFingerprint(sig.sdp ?? '');
  if (!fp) throw new CallRefusedError('malformed-sdp');
  const seq = typeof sig.seq === 'number' ? sig.seq : 0;
  if (state.callId === sig.call_id && seq <= state.seqSeen) throw new CallRefusedError('replayed-offer');
  if (state.callId === sig.call_id && state.offerFingerprint && state.offerFingerprint !== fp) {
    throw new CallRefusedError('fingerprint-mismatch');
  }
  return { callId: sig.call_id, phase: 'ringing', offerFingerprint: fp, seqSeen: seq };
}

/**
 * The DTLS fingerprint observed for the peer (from the remote description
 * WebRTC applied, or from its certificate stats) must equal the one the peer
 * sent inside the encrypted signalling. Mismatch = "someone may be in the
 * middle" (monitor: cls='fingerprint', status red).
 */
export function verifyMediaFingerprint(state: CallState, observedFp: string, monitor: CallIntegrityMonitor): boolean {
  if (!state.offerFingerprint) {
    monitor.record('fingerprint', 'no bound offer fingerprint — refusing media');
    return false;
  }
  if (normalizeFp(state.offerFingerprint) === normalizeFp(observedFp)) return true;
  monitor.record('fingerprint', 'media fingerprint differs from the one in the encrypted signalling — MITM suspected');
  return false;
}

/** Run on the remote description the peer connection actually holds after
 *  setRemoteDescription: its single DTLS fingerprint must be the one bound
 *  from the encrypted offer/answer. WebRTC then refuses any DTLS handshake
 *  whose certificate doesn't match it. */
export function verifyAppliedRemoteSdp(state: CallState, appliedSdp: string | null | undefined, monitor: CallIntegrityMonitor): boolean {
  const fp = extractDtlsFingerprint(appliedSdp ?? '');
  if (!fp) {
    monitor.record('fingerprint', 'applied remote description has no single DTLS fingerprint');
    return false;
  }
  return verifyMediaFingerprint(state, fp, monitor);
}

function normalizeFp(fp: string): string {
  return fp.trim().replace(/\s+/g, ' ').toUpperCase();
}

/** Answerer accepts the ring: phase -> active; the answer SDP (with the
 *  callee's own DTLS fingerprint) goes back via sendCallSignal. */
export function answerCall(state: CallState): CallState {
  if (state.phase !== 'ringing') throw new Error('No call is ringing.');
  return { ...state, phase: 'active' };
}

/** Any side ends the call — its state and monitor die with it. */
export function endCall(state: CallState, _reason: string): CallState {
  if (state.phase === 'ended') return state;
  return { ...state, phase: 'ended' };
}

// ---------------------------------------------------------------------------
// Transport — signalling rides the chat ratchet exactly like a read receipt
// ---------------------------------------------------------------------------

/** b77 (sealed sender): call signals ride sealedSubmit to the peer's inbound like any other 1:1
 *  envelope (no session token, write secret, sender tag or bearer token). The ring is the
 *  submit's notify 'call' — the relay rings only when the callee's inbound is verified. */
export interface CallRelay {
  sealedSubmit(sub: SealedSubmission): Promise<{ data: unknown; status: number }>;
  /** my own inbound's verified flag, re-sent before a ring (optional for test doubles) */
  mailboxVerify?: (mbox: string, readCap: string, verified: boolean) => Promise<unknown>;
}

export interface CallSessionStore {
  load(token: string): Promise<unknown>;
  save(token: string, s: unknown): Promise<void>;
}

export function sendCallSignal(...args: Parameters<typeof sendCallSignalUnlocked>): ReturnType<typeof sendCallSignalUnlocked> {
  // b147: ratchet writes serialize per token — a concurrent burst must not
  // encrypt the same step twice (see send-queue.ts).
  return serializeRatchetSend(args[2] as string, () => sendCallSignalUnlocked(...args));
}

async function sendCallSignalUnlocked(
  relay: CallRelay,
  sessions: CallSessionStore,
  token: string,
  clientId: string,
  sig: CallSignal,
  encrypt: (state: unknown, body: string) => Promise<{ ciphertext: string; iv: string; header: unknown; byteLength?: number }>,
  serializeState: (s: unknown) => Promise<unknown>,
  deserializeState: (s: unknown) => Promise<unknown>,
): Promise<void> {
  const sealed = await sessions.load(token) as { writeSecret?: string | null; proto?: string } | null;
  if (!sealed) throw new Error('No ratchet state for this session on this device.');
  const dlv = requireDelivery(sealed); // b77: a chat sealed before b77 has ended
  void clientId;
  const state = await deserializeState(sealed);
  const { sentAt: _drop, ...out } = sig; // receive-side field, never sent
  const body = JSON.stringify({ ...out, __veil_call: 1 as const, ts: Date.now() });
  const env = await encrypt(state, body);
  // Batch H (round-6 review R6-1-06): persist BEFORE send (a refused save stops the
  // signal; a step is never sent twice). b143: keep the loaded record's extras.
  await saveOrThrow(sessions, token, { ...(sealed as Record<string, unknown>), ...(await serializeState(state) as Record<string, unknown>) });
  // b198 (live-caught: calling a QUIT app rang into the void — the callee's
  // offer sat unfetched until the 21s ringout): fire the contentless callee
  // wake on the INVITE only (b77n; it was the offer). Offer/ICE/answer/end are machine-consumed — no push.
  // b77 (sealed sender): the wake is the submit's notify flag ('call' on the invite, false else).
  // b77n (audit VAR-04): the INVITE rings now (it used to be the offer, which follows the callee's
  // approval of the TURN grant). b71 (audit F-08): this phone's own verified flag (calls start only
  // on a chat it confirmed) is re-sent first, on its own inbound, in case an earlier one was lost.
  if (sig.op === 'invite' && relay.mailboxVerify) {
    await syncInboundVerified(relay as { mailboxVerify: NonNullable<CallRelay['mailboxVerify']> } as never, sessions as never, token).catch(() => false);
  }
  const header = typeof env.header === 'string' ? env.header : JSON.stringify(env.header);
  // call setup is latency-bound; stale offers must die fast (300 s). Never queued: a call
  // signal the callee's inbound can't take yet fails the call step at once.
  await sealedSend(relay, sessions as never, token, dlv, { ciphertext: env.ciphertext, iv: env.iv, header, byteLength: env.byteLength }, 300, sig.op === 'invite' ? 'call' : false, false);
  // b143 FIX (the save above): the resealed state keeps the loaded record's EXTRAS
  // (writeSecret, expire dials, burn flags, proto), as sendChatMessage's withExtras.
}
