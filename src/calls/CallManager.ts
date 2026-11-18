/**
 * VEIL CallManager (b144, W3): the device-side glue that turns the tested
 * calls.ts core (signalling + state machine + integrity monitor) into a live
 * audio call on react-native-webrtc. What it does:
 *
 *  SIGNALLING  offer / answer / ICE / ringing / end ride the chat session's
 *      end-to-end encrypted ratchet (sendCallSignal) — the relay sees only
 *      cipher-text. Each SDP carries its side's DTLS fingerprint, so the
 *      fingerprint is authenticated by the chat session.
 *  MEDIA  standard WebRTC DTLS-SRTP, keyed by the DTLS handshake (classical
 *      ECDHE — the audio itself is NOT post-quantum). After applying the
 *      peer's description, the fingerprint WebRTC holds is checked against
 *      the one from the encrypted signalling (verifyAppliedRemoteSdp); when
 *      connected, the certificate WebRTC reports is checked again if the
 *      stats carry it. b71 (audit F-28): the first check compares two copies
 *      of the same description, so the call card says "keys checked" only
 *      once the live certificate itself matched (dtlsCertChecked).
 *  There is no extra per-frame encryption layer.
 *
 * PRIVACY: calls go through VEIL's OWN TURN server (coturn on the VEIL VPS,
 * no third-party STUN/TURN). Short-lived credentials come from the relay
 * (sealedTurn through the chat's own inbound, see turnIce below) and the PC always runs
 * iceTransportPolicy 'relay', so the two peers never learn each other's IP
 * addresses (each only sees the TURN server). Media stays DTLS-SRTP end to
 * end between the devices: TURN forwards encrypted packets it cannot decrypt
 * — it sees only that two devices exchanged media, when, and roughly how much.
 * FAIL CLOSED: if TURN credentials can't be had (relay not configured,
 * offline, 429, 4s timeout, malformed) NO peer connection is built and the
 * call ends with "Couldn't reach the call relay — try again". As a second
 * guard, every outgoing SDP and trickled candidate is scrubbed to relay
 * candidates only, with this phone's own addresses removed (callGuards.ts).
 *
 * UI CONTRACT: CallManager is a module singleton. App configures it once
 * (relay/sessions/clientId/storage closures), syncToken feeds it inbound
 * signals, CallOverlay subscribes to snapshots. No prop drilling, no navigation.
 */
import { Platform, Vibration } from 'react-native';
import { requireOptionalNativeModule } from 'expo-modules-core';
import { createIceBatcher, iceSignalBody, candsOf, type IceBatcher, candidateInSdp } from './iceBatch';
import {
  CALL_RELAY_UNREACHABLE, CALL_PEER_UNREACHABLE, relayOnlyPcConfig, scrubCandidateJson, scrubOutgoingSdp,
  offerFreshness, SeenCallIds, remoteCertFingerprint, type CallKV, type TurnIce,
  setTurnHostAllowList, PRODUCT_TURN_HOST_SUFFIXES, captureBeside /* b77u (U-M4) */
} from './callGuards';
// b75 round 2 (audit D2): TURN hosts must be under the product's own domains (a public name
// can resolve to a LAN or loopback address); a TURN server on this machine only in development
setTurnHostAllowList(PRODUCT_TURN_HOST_SUFFIXES, { devLoopback: typeof __DEV__ !== 'undefined' && __DEV__ === true });
// b149: incoming-call ringtone. expo-av is already in the dev client (media
// playback uses it), so Metro hot-reload can reach the native module.
// Respects the hardware mute switch — silent mode stays silent (vibration
// still runs); we deliberately do NOT set playsInSilentMode.
import { Audio } from 'expo-av';
import {
  newTurnGrant, openTurnGrant, approveTurnGrant, awaitTurnGrant, turnGrantRefusal, type TurnGrantRelay,
} from '../../vendor/device/src/sealed'; // b77n (audit VAR-04): TURN only for a call the other phone approved
import ringAsset from '../../assets/veil-ring.wav';
import ringbackAsset from '../../assets/veil-ringback.wav';
import { RTCPeerConnection, RTCSessionDescription, RTCIceCandidate, mediaDevices, type MediaStream, type MediaStreamTrack } from 'react-native-webrtc';
import {
  type CallSignal, type CallState, CallIntegrityMonitor, CallRefusedError,
  newCallId, LEGACY_OFFER_K, processOffer, answerCall, endCall,
  extractDtlsFingerprint, sendCallSignal, verifyAppliedRemoteSdp, verifyMediaFingerprint,
} from '../../vendor/device/src/calls';
import {
  encryptMessage, serializeRatchetState, deserializeRatchetState,
} from '../../vendor/crypto-core/src/index';

export type CallUiPhase = 'calling' | 'ringing' | 'connecting' | 'active' | 'ended';

export interface CallSnapshot {
  phase: CallUiPhase;
  role: 'caller' | 'callee';
  peerLabel: string;
  callId: string;
  token: string;              // b199: the call's session, for App's call poll
  startedAt: number | null;   // epoch ms, active only
  endedReason: string | null;
  muted: boolean;
  /** audit fix (b71): 'ok' / 'amber' only once THIS call's peer fingerprint
   *  was checked against the encrypted signalling ('amber' = checked, but the
   *  connection degraded); 'unchecked' = no check passed yet; 'red' = a check
   *  failed. */
  integrity: 'ok' | 'amber' | 'red' | 'unchecked';
  /** b71 (audit F-28): the live DTLS certificate matched the signed fingerprint */
  certChecked?: boolean;
  reach: 'pending' | 'ringing' | 'unreachable' | null; // 21 Oct 2026: caller side, has the other phone confirmed it rings?
}

interface CallSession {
  callId: string;
  token: string;
  peerLabel: string;
  role: 'caller' | 'callee';
  phase: CallUiPhase;
  core: CallState;                 // calls.ts state machine (guard rails)
  monitor: CallIntegrityMonitor;   // local-only interference log
  pc: RTCPeerConnection | null;
  local: MediaStream | null;
  pendingIce: CallSignal[];        // ICE that arrived before remote description
  pendingOfferSdp: string | null;  // callee: the offer SDP stashed until Answer
  startedAt: number | null;
  endedReason: string | null;
  muted: boolean;
  seq: number;
  ringVib: number | null;
  timeoutHandle: ReturnType<typeof setTimeout> | null;
  mediaUp: boolean;                // b199: 'connected' already fired (may beat armConnecting)
  /** 20 Oct 2026: candidate batching and the callee prewarm */
  iceBatcher?: IceBatcher | null;
  iceRelease?: boolean;            // false while a prewarmed callee is still ringing
  heldIce: string[];               // candidates gathered before Accept
  prewarming?: Promise<void> | null;
  answering?: boolean;             // b64 test (C-5): Accept tapped, answer in progress
  gathered?: boolean;              // 21 Oct 2026: this side's candidates are all in
  firstCandAt?: number | null;     // when the first candidate arrived
  reach?: 'pending' | 'ringing' | 'unreachable'; // caller: the callee's ringing confirmation
  ackHandle?: ReturnType<typeof setTimeout> | null;
  keysChecked?: boolean;           // audit fix (b71): applied remote fingerprint matched the signed one
  dtlsCertChecked?: boolean;       // b71 (audit F-28): the live DTLS certificate matched it too
  ringoutAt?: number;              // b71 (device test): when the ring window ends
  ringAcked?: boolean;             // audit fix (b71): 'ringing' sent (only once the ring is on screen)
  /** b77n (audit VAR-04): this call's TURN grant id — the caller opened it on its inbound and sent it
   *  in the invite; the callee approves it on its own inbound as the call rings */
  grant?: string;
  invited?: boolean;               // caller: the invite went out (a failure after it sends 'end')
  approval?: Promise<boolean> | null; // callee: the grant approval (prewarm starts it, answer reuses it)
  /** audit VAR-09 (1f51): THIS call's grant is known approved — the callee's own approval went
   *  through, or the caller redeemed it. Only then may a cached credential be reused. */
  grantOk?: boolean;
  noApproval?: boolean;            // b77n2 (review INFO): caller — the ring window ended without the other phone's approval
  offerApplied?: Promise<void> | null; // callee: the offer being applied to the prewarmed connection
}

interface CallTransport {
  relay: () => unknown;
  sessions: () => unknown;
  clientId: () => Promise<string | null>;
  /** audit fix (b71): where the seen-call-id list persists. Optional: without
   *  it the list lives in memory only (the 60 s time check still holds). */
  storage?: () => CallKV | null | undefined;
}

let transport: CallTransport | null = null;
let session: CallSession | null = null;
const listeners = new Set<(s: CallSnapshot | null) => void>();

const IDLE_CORE: CallState = { callId: '', phase: 'idle', offerFingerprint: null, seqSeen: -1 };

// audit fix (b71): every call id this phone rang or refused, so a replayed
// offer never rings (persisted through transport.storage when App gives it).
const seenCalls = new SeenCallIds(() => transport?.storage?.() ?? null);

const RING_PATTERN = [0, 600, 800] as number[];

// b157 missed-call tracking: a call this device never answered leaves a
// durable trace, so an offer held out by the lock (hold-until-unlock keeps
// a locked phone holding no message data — call offers are ratcheted exactly
// like chat, so they cannot bypass the hold) still surfaces as a notice.
const locallyEndedCalls = new Set<string>();
const recordedMisses = new Set<string>();

function recordMissed(callId: string, token: string, peerLabel: string): void {
  if (recordedMisses.has(callId)) return;
  recordedMisses.add(callId);
  if (recordedMisses.size > 500) recordedMisses.clear();
  try { CallManager.onMissedCall?.(token, peerLabel); } catch { /* notice must never break calls */ }
}

// b149: looping ringtone for the ringing phase. Lazy-loaded on first use;
// any audio failure degrades to vibration-only (never blocks the call).
let ringSound: Awaited<ReturnType<typeof Audio.Sound.createAsync>>['sound'] | null = null;
let ringLoading: Promise<void> | null = null;
let ringBroken = false;

// b199 (Android handover TODO): iOS's player already obeys the mute switch;
// Android's plays on the media stream, which ignores silent/vibrate. Ask the
// native module for the ringer mode (Android-only function; absent on iOS
// and on older builds → 'normal', i.e. today's behaviour).
function androidRingerMode(): 'normal' | 'vibrate' | 'silent' {
  if (Platform.OS !== 'android') return 'normal';
  try {
    const mod = requireOptionalNativeModule<{ ringerMode?: () => string }>('VeilCrypto');
    const m = mod?.ringerMode?.();
    return m === 'silent' || m === 'vibrate' ? m : 'normal';
  } catch { return 'normal'; }
}

// Call quality (owner test 20 Oct 2026: echo on the Android side): Android only
// applies its call echo cancellation and earpiece routing in call mode. iOS
// needs nothing here (WebRTC's audio session is already a voice-chat session);
// older Android builds without the function keep today's behaviour.
function callAudioMode(active: boolean): void {
  if (Platform.OS !== 'android') return;
  try {
    const mod = requireOptionalNativeModule<{ setCallAudioMode?: (on: boolean) => boolean }>('VeilCrypto');
    if (active) mod?.setCallAudioMode?.(true);
    else mod?.setCallAudioMode?.(false);
  } catch { /* audio routing is best-effort */ }
}

async function startRingtone(): Promise<void> {
  if (ringBroken) return;
  if (androidRingerMode() !== 'normal') return; // silent/vibrate: no ring sound
  try {
    if (!ringSound && !ringLoading) {
      ringLoading = Audio.Sound.createAsync(ringAsset, { isLooping: true, volume: 1.0 }).then(({ sound }) => { // b198 (owner): full volume
        ringSound = sound;
      });
    }
    await ringLoading;
    await ringSound?.setIsLoopingAsync(true);
    await ringSound?.playAsync();
  } catch (e) {
    // Native module missing from this binary, or the asset failed to load:
    // disable for this run, keep calls working, vibration still alerts.
    ringBroken = true;
    console.warn('[veil-call] ringtone unavailable (vibration-only):', (e as Error)?.message ?? e);
  }
}

async function stopRingtone(): Promise<void> {
  try { await ringSound?.stopAsync(); } catch { /* already stopped */ }
}

// Caller ringback (owner request 20 Oct 2026): the caller hears a ring
// (400+450 Hz, 0.4/0.2/0.4 s on, 2 s off) while the other phone rings. Quieter
// than the incoming ring; any audio failure just means a silent wait.
let ringbackSound: Awaited<ReturnType<typeof Audio.Sound.createAsync>>['sound'] | null = null;
let ringbackLoading: Promise<void> | null = null;
let ringbackBroken = false;

async function startRingback(s: CallSession): Promise<void> {
  if (ringbackBroken) return;
  try {
    if (Platform.OS === 'ios') {
      // b63 review (C-2): the mic is already live, so keep the shared audio
      // session record-capable (PlayAndRecord). expo-av's default is a
      // play-only category, which would cut the caller's mic.
      await Audio.setAudioModeAsync({ allowsRecordingIOS: true, playsInSilentModeIOS: true });
    }
    if (!ringbackSound && !ringbackLoading) {
      ringbackLoading = Audio.Sound.createAsync(ringbackAsset, { isLooping: true, volume: 0.45 }).then(({ sound }) => {
        ringbackSound = sound;
      });
    }
    await ringbackLoading;
    if (session !== s || s.phase !== 'calling') return; // answered or ended while loading
    await ringbackSound?.setIsLoopingAsync(true);
    if (session !== s || s.phase !== 'calling') return; // b63 review (C-3)
    await ringbackSound?.playAsync();
    // b63 review (C-3): an answer or hang-up landed during play; stop again
    if (session !== s || s.phase !== 'calling') await ringbackSound?.stopAsync();
  } catch (e) {
    ringbackBroken = true;
    console.warn('[veil-call] ringback unavailable (silent wait):', (e as Error)?.message ?? e);
  }
}

async function stopRingback(): Promise<void> {
  try { await ringbackSound?.stopAsync(); } catch { /* already stopped */ }
}
const RINGOUT_MS = 60_000; // unanswered ring dies (both directions); b71: 60 s — a locked phone takes up to ~20 s to see the offer, then needs time to unlock
// b151 FIX (live-found, owner repro Oct 1): phase was flipping to 'active'
// the moment the answer SDP was sent/received — pure signaling, no proof
// the actual P2P media path ever connected. The owner saw native show
// "Integrity verified" + a running timer while the caller's side was still
// stuck "trying to connect": two peers disagreeing about whether a call
// was live. Phase now only becomes 'active' on pc.connectionState ===
// 'connected' (see wireConnectState below); if that never happens within
// this window, the call ends honestly instead of hanging in fake-active.
const CONNECT_TIMEOUT_MS = 25_000;

function snapshot(): CallSnapshot | null {
  if (!session) return null;
  return {
    phase: session.phase,
    role: session.role,
    peerLabel: session.peerLabel,
    callId: session.callId,
    token: session.token,
    startedAt: session.startedAt,
    endedReason: session.endedReason,
    muted: session.muted,
    integrity: integrityOf(session),
    certChecked: !!session.dtlsCertChecked, // b71 (audit F-28)
    reach: session.reach ?? null,
  };
}

function integrityOf(s: CallSession): CallSnapshot['integrity'] {
  const st = s.monitor.status();
  if (st === 'red') return 'red';
  if (!s.keysChecked) return 'unchecked';
  return st;
}

function notify(): void {
  const snap = snapshot();
  for (const l of listeners) l(snap);
}

// b146: pre-offer ICE buffer — 10s TTL, swept on each offer handling pass.
const preOfferIce = new Map<string, CallSignal[]>();
/** audit fix (b71): early candidates are held per chat AND call id. */
const iceKey = (token: string, callId: string) => `${token}|${callId}`;
setInterval(() => {
  // candidates older than 10s without an offer are dead; the window is
  // bounded by the relay's fetch cadence anyway.
  preOfferIce.clear();
}, 10000).unref?.();

function clearRing(s: CallSession): void {
  void stopRingtone();
  void stopRingback();
  // b199 (owner report: "it won't stop vibrating" after the caller hung up):
  // ringVib was never set anywhere, so this cancel never ran and the
  // repeating ring vibration outlived the call. Cancel unconditionally — it
  // is a no-op when nothing is vibrating.
  Vibration.cancel();
  s.ringVib = null;
  if (s.timeoutHandle !== null) { clearTimeout(s.timeoutHandle); s.timeoutHandle = null; }
  if (s.ackHandle) { clearTimeout(s.ackHandle); s.ackHandle = null; }
}

/** Full teardown: keys, counters and monitor die with the call (design S3b.4). */
function teardown(s: CallSession, reason: string, sendEnd: boolean): void {
  locallyEndedCalls.add(s.callId); // b157: our own decline/clear must not later count as a missed call
  if (locallyEndedCalls.size > 500) locallyEndedCalls.clear();
  clearRing(s);
  callAudioMode(false); // back to normal audio routing, always
  try { s.monitor.destroy(); } catch { /* already destroyed */ }
  try { s.pc?.close(); } catch { /* already closed */ }
  s.local?.getTracks().forEach((t) => t.stop());
  s.pc = null;
  s.local = null;
  console.log(`[veil-call] teardown: ${reason} (role ${s.role}, phase ${s.phase}, sendEnd ${sendEnd})`);
  if (sendEnd && s.phase !== 'ended') {
    // b199: the end signal used to be fire-and-forget — one 429 or network
    // blip and the peer never learned the call was over. Same one-retry rule
    // as ICE (b196).
    const send = () => signal(s.token, { __veil_call: 1, op: 'end', call_id: s.callId, reason });
    send().then(() => console.log('[veil-call] end sent')).catch((err: Error) => {
      console.log(`[veil-call] end send failed (${err.message}) — one retry in 2.5s`);
      setTimeout(() => {
        send().then(() => console.log('[veil-call] end sent on retry'))
          .catch((err2: Error) => console.log(`[veil-call] end send dropped after retry: ${err2.message}`));
      }, 2500);
    });
  }
  s.phase = 'ended';
  s.endedReason = reason;
  s.core = endCall(s.core, reason);
  notify();
  // keep the ended snapshot on screen briefly, then fully clear
  setTimeout(() => { if (session && session.callId === s.callId && session.phase === 'ended') { session = null; notify(); } }, 2200);
}

/** b63 review (C-1): the call ended, or a newer one replaced it, while
 *  start() or answer() was waiting. */
function callGone(s: CallSession): boolean {
  return session !== s || s.phase === 'ended';
}

/** b63 review (C-1): release what an abandoned start()/answer() built after
 *  teardown already ran. Audio routing is reset only when no newer call owns it. */
function abandon(s: CallSession, local: CallSession['local'], pc: CallSession['pc'], audioOn: boolean): void {
  local?.getTracks().forEach((t) => t.stop());
  try { pc?.close(); } catch { /* already closed */ }
  if (audioOn && (!session || session === s || session.phase === 'ended')) callAudioMode(false);
  console.log(`[veil-call] abandoned a ${s.role} setup: the call ended while it was starting`);
}

// 21 Oct 2026 (owner tests: 5–8 s from Answer to hearing each other): each
// side waits briefly for its own connection details and sends them INSIDE the
// offer/answer SDP, instead of as separate messages after it. Standard WebRTC,
// so older builds read them natively. Anything gathered later still trickles.
const GATHER_WAIT_CALLER_MS = 1500;
const GATHER_WAIT_CALLEE_MS = 1000;
const GATHER_SETTLE_MS = 300; // once one candidate is in, a short grace for the rest

async function waitGathered(s: CallSession, ms: number): Promise<void> {
  const until = Date.now() + ms;
  while (!s.gathered && Date.now() < until && !callGone(s)) {
    if (s.firstCandAt && Date.now() - s.firstCandAt >= GATHER_SETTLE_MS) break;
    await new Promise((r) => setTimeout(r, 50));
  }
}

/** The local SDP as it is now (with the gathered candidates), or the
 *  fallback — scrubbed to relay candidates with no address of this phone
 *  (audit fix b71; the connection itself is relay-only too). */
function localSdp(pc: RTCPeerConnection, fallback: string): string {
  return scrubOutgoingSdp((pc as unknown as { localDescription?: { sdp?: string } | null }).localDescription?.sdp || fallback);
}

/** audit fix (b71): the remote description the connection now HOLDS must
 *  carry the fingerprint the peer sent inside the encrypted offer/answer.
 *  Pass = keys checked for this call; fail = red, and the call ends. */
function checkAppliedRemote(s: CallSession, pc: RTCPeerConnection): boolean {
  const applied = (pc as unknown as { remoteDescription?: { sdp?: string } | null }).remoteDescription?.sdp;
  if (verifyAppliedRemoteSdp(s.core, applied, s.monitor)) {
    s.keysChecked = true;
    return true;
  }
  s.keysChecked = false;
  console.log('[veil-call] applied remote fingerprint differs from the signed one — ending the call');
  teardown(s, 'security check failed', true);
  return false;
}

/** audit fix (b71): once connected, the DTLS certificate WebRTC reports for
 *  the peer (when the stats carry it) must match too. Silent when the stats
 *  have no certificate entry; a mismatch ends the call. */
async function checkDtlsCert(s: CallSession, pc: RTCPeerConnection): Promise<void> {
  try {
    const report = (await pc.getStats()) as unknown as Map<string, Record<string, unknown>>;
    const fp = remoteCertFingerprint(report.values());
    if (!fp || callGone(s)) return;
    if (verifyMediaFingerprint(s.core, fp, s.monitor)) { s.dtlsCertChecked = true; notify(); console.log('[veil-call] DTLS certificate matches the signed fingerprint'); return; }
    s.keysChecked = false;
    teardown(s, 'security check failed', true);
  } catch { /* stats shapes vary; the applied-description check already ran */ }
}

/** Start trickling: send held candidates the SDP didn't already carry. */
function releaseHeldIce(s: CallSession, sdp: string): void {
  s.iceRelease = true;
  const late = s.heldIce.filter((c) => !candidateInSdp(sdp, c));
  console.log(`[veil-call] candidates: ${s.heldIce.length - late.length} in the ${s.role === 'caller' ? 'offer' : 'answer'}, ${late.length} sent after`);
  s.heldIce = [];
  for (const c of late) s.iceBatcher?.push(c);
  if (s.gathered) s.iceBatcher?.flush();
}

// 21 Oct 2026 (owner: "it sounds like it's ringing but nothing comes through"):
// the callee confirms with a 'ringing' signal. Until then the caller shows
// "Calling…" with no tone; with no confirmation in 20 s, "Not reachable yet".
// Older builds never confirm, so the call keeps going to the ringout until
// they're gone; then REQUIRE_RING_ACK ends it at 20 s.
const RING_ACK_MS = 35_000; // b71: a locked phone polls every ~10-20 s
const REQUIRE_RING_ACK = false;

function armRingAck(s: CallSession): void {
  if (s.ackHandle) clearTimeout(s.ackHandle);
  s.ackHandle = setTimeout(() => {
    s.ackHandle = null;
    if (session !== s || s.phase !== 'calling' || s.reach === 'ringing') return;
    s.reach = 'unreachable';
    console.log('[veil-call] no ringing confirmation in 20 s (phone offline, or an older build)');
    notify();
    if (REQUIRE_RING_ACK) teardown(s, 'not reachable', true);
  }, RING_ACK_MS);
}

async function signal(token: string, sig: CallSignal): Promise<void> {
  if (!transport) throw new Error('Call transport not configured yet.');
  const relay = transport.relay();
  const sessions = transport.sessions();
  const who = await transport.clientId();
  if (!relay || !sessions || !who) throw new Error('Session not ready.');
  await sendCallSignal(
    relay as never, sessions as never, token, who, sig,
    encryptMessage as never, serializeRatchetState as never, deserializeRatchetState as never,
  );
}

/** b71 (device test): once the other phone says it is ringing, it gets at least this
 *  long to answer — a locked phone can start ringing well into the ring window (it
 *  polls every ~20 s) and then still has to be unlocked */
const RING_AFTER_ACK_MS = 45_000;

function armRingout(s: CallSession, ms: number = RINGOUT_MS): void {
  if (s.timeoutHandle !== null) clearTimeout(s.timeoutHandle);
  s.ringoutAt = Date.now() + ms;
  s.timeoutHandle = setTimeout(() => {
    const wasRingingCallee = s.role === 'callee';
    // b77n2 (review INFO): a caller whose call the other phone neither confirmed ringing nor approved never
    // reached it — "no answer" claimed it rang
    const reached = s.reach === 'ringing' || !!s.pc;
    teardown(s, s.role === 'caller' ? (reached ? 'no answer' : CALL_PEER_UNREACHABLE) : 'missed', true);
    if (wasRingingCallee) recordMissed(s.callId, s.token, s.peerLabel); // b157
  }, ms);
}

/** b151: signaling is done (answer sent/received) but the real media path
 *  hasn't connected yet — show it honestly and give it a bounded window. */
function armConnecting(s: CallSession): void {
  s.phase = 'connecting';
  if (s.timeoutHandle !== null) clearTimeout(s.timeoutHandle);
  s.timeoutHandle = setTimeout(() => {
    if (session === s && s.phase === 'connecting') {
      teardown(s, 'call failed to connect', true);
    }
  }, CONNECT_TIMEOUT_MS);
  notify();
  // b199 (owner report Oct 16: A stuck on "Connecting" while both could talk;
  // Metro showed the caller's 'connected' event firing DURING the answer
  // handling, while the phase was still 'calling'): markConnected ignored it
  // and no second event ever came. The event is remembered, so a path that
  // came up before this point still flips the call to active.
  if (s.mediaUp) markConnected(s);
}

/** b151: the ONLY place a call becomes 'active' — real transport proof,
 *  not just a signaling exchange. */
function markConnected(s: CallSession): void {
  if (s.phase !== 'connecting') return;
  if (s.timeoutHandle !== null) { clearTimeout(s.timeoutHandle); s.timeoutHandle = null; }
  s.phase = 'active';
  s.startedAt = Date.now();
  notify();
}

// TURN credentials (relay-only internet calling). The VEIL relay mints
// short-lived coturn credentials (TURN REST scheme: username =
// "<expiry-epoch-seconds>:<id>") via the chat's sealedTurn (b77; b77r1: only that); cached until 5
// minutes before expiry. ANY failure — 503 (not configured), 401, 429,
// network, 4s timeout, malformed body — resolves to null, and a null means
// NO call (fail closed: a connection without relay servers would hand the
// peer this phone's LAN / IPv6 addresses). Never log username/credential.
// b77n (audit VAR-04): sealedTurn answers only for the call's TURN GRANT, which the caller opened
// on its own inbound (turnGrant) and the callee's phone approved on ITS own inbound as the call rang
// (turnApprove). So the caller gets credentials only after the callee's phone rings: start() sends
// the invite first, waits for the approval (asking about once a second), and only then builds its
// connection and sends the offer. Spec §12.12.
type TurnInvoker = TurnGrantRelay & {
  invoke(fn: string, payload: Record<string, unknown>): Promise<{ data: unknown; status: number }>;
};
const TURN_FETCH_TIMEOUT_MS = 4_000;
/** b77n: the callee asks for its credentials right after approving; a few seconds of "pending"
 *  (the approval still landing) are waited out */
const CALLEE_TURN_WAIT_MS = 8_000;
/** b77n: Accept tapped before the caller's offer arrived (the caller sends it once the approval is
 *  in): how long answer() waits for it */
const OFFER_WAIT_MS = 20_000;

function withTurnTimeout<T>(p: Promise<T>): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | null = null;
  const timeout = new Promise<never>((_, rej) => { timer = setTimeout(() => rej(new Error('timeout')), TURN_FETCH_TIMEOUT_MS); });
  return Promise.race([p, timeout]).finally(() => { if (timer !== null) clearTimeout(timer); });
}
/** the relay's grant routes, each call bounded by TURN_FETCH_TIMEOUT_MS */
function grantRelay(): TurnGrantRelay | null {
  const relay = transport?.relay() as TurnInvoker | null | undefined;
  if (!relay || typeof relay.sealedTurn !== 'function' || typeof relay.turnGrant !== 'function' || typeof relay.turnApprove !== 'function') return null;
  return {
    turnGrant: (m, r, g) => withTurnTimeout(relay.turnGrant!(m, r, g)),
    turnApprove: (m, r, g) => withTurnTimeout(relay.turnApprove!(m, r, g)),
    sealedTurn: (m, r, g) => withTurnTimeout(relay.sealedTurn!(m, r, g)),
  };
}
const grantSessions = () => transport?.sessions() as { load: (t: string) => Promise<unknown> } | null | undefined;

/** b77n2 (review L1): the wait before re-trying a grant open that failed transiently (doubled the second time) */
const OPEN_GRANT_RETRY_MS = 700;
/** b77n: the caller opens this call's grant on its own inbound (before the invite goes out).
 *  Throws NoRelayError when it can't (nothing has been sent yet). */
async function openGrant(s: CallSession): Promise<void> {
  try {
    const relay = grantRelay(), sess = grantSessions();
    if (!relay || !sess?.load) throw new Error('relay not ready');
    // b77n2 (review L1): a transient failure (a timeout — the answer may have been lost after the relay
    // stored the grant —, a 5xx, a 429) is tried again twice; the relay answers OK to the same opener
    // re-opening its own grant. A refusal (400 / 403 / 410) is final.
    for (let attempt = 0; ; attempt++) {
      try { await openTurnGrant(relay, sess as never, s.token, s.grant as string); break; }
      catch (e) {
        if (attempt >= 2 || turnGrantRefusal(e) || callGone(s)) throw e;
        console.log(`[veil-call] call grant open failed (${(e as Error)?.message ?? e}) — trying again`);
        await new Promise((r) => setTimeout(r, OPEN_GRANT_RETRY_MS * (attempt + 1)));
      }
    }
  } catch (e) {
    console.log(`[veil-call] call grant not opened (${(e as Error)?.message ?? e}) — no call without the relay`);
    throw new NoRelayError();
  }
}

/** b77n: the callee approves the caller's grant on its own inbound — once per call (memoized; one
 *  retry). Without it neither phone gets relay credentials. */
function approveCall(s: CallSession): Promise<boolean> {
  if (s.approval) return s.approval;
  const once = async (): Promise<boolean> => {
    const relay = grantRelay(), sess = grantSessions();
    if (!relay || !sess?.load || !s.grant) throw new Error('relay not ready');
    await approveTurnGrant(relay, sess as never, s.token, s.grant);
    s.grantOk = true; // audit VAR-09: approved for this call
    return true;
  };
  s.approval = (async () => {
    try { return await once(); } catch (e) {
      console.log(`[veil-call] call approval failed (${(e as Error)?.message ?? e}) — one retry`);
      await new Promise((r) => setTimeout(r, 1500));
      if (callGone(s)) return false;
      try { return await once(); } catch (e2) {
        console.log(`[veil-call] call approval failed again (${(e2 as Error)?.message ?? e2})`);
        s.approval = null; // answer() may try once more
        return false;
      }
    }
  })();
  return s.approval;
}
const TURN_REFRESH_MARGIN_MS = 5 * 60_000;
/** b77r1 (audit A-6): keyed by the chat the credentials were fetched for (through that chat's
 *  verified inbound) — they are never handed to a call in another chat.
 *  audit VAR-09 (1f51): and only to a call whose OWN grant is approved (canReuseTurn) — a re-dial
 *  never skips the per-call approval. */
let turnCache: { ice: TurnIce; expiresAt: number; token: string } | null = null;
/** b75 round 3 (audit DV-10): bumped by every wipe (forgetAfterWipe). A credential fetch that
 *  was in flight when a wipe began neither fills the cache nor returns credentials after it. */
let turnEra = 0;

function parseTurn(data: unknown): { ice: TurnIce; expiresAt: number } | null {
  const raw = (data as { iceServers?: unknown } | null)?.iceServers;
  if (!Array.isArray(raw) || raw.length === 0) return null;
  const servers: TurnIce['iceServers'] = [];
  let expiresAt = Infinity;
  for (const e of raw as { urls?: unknown; username?: unknown; credential?: unknown }[]) {
    const urls = typeof e?.urls === 'string' ? [e.urls] : e?.urls;
    if (!Array.isArray(urls) || urls.length === 0 || !urls.every((u) => typeof u === 'string')) return null;
    if (!urls.every((u) => /^turns?:/i.test(u as string))) return null; // relay servers only, never STUN
    if (typeof e.username !== 'string' || typeof e.credential !== 'string') return null;
    const exp = Number(e.username.split(':')[0]);
    if (!Number.isFinite(exp) || exp <= 0) return null;
    expiresAt = Math.min(expiresAt, exp * 1000);
    servers.push({ urls: urls as string[], username: e.username, credential: e.credential });
  }
  return { ice: { iceServers: servers }, expiresAt };
}

/** audit VAR-09 (1f51): a cached credential is handed out only for the same chat, while fresh,
 *  and only once THIS call's grant is approved (the callee approved it itself; a caller learns
 *  it only by redeeming the grant, so a caller never skips the wait). */
export function canReuseTurn(
  cache: { expiresAt: number; token: string } | null,
  call: { token: string; grantOk?: boolean },
  now: number,
): boolean {
  return !!cache && !!call.token && cache.token === call.token && call.grantOk === true
    && cache.expiresAt - TURN_REFRESH_MARGIN_MS > now;
}

/** TURN credentials for this call, or null (the call must not go ahead).
 *  b77n (audit VAR-04): redeemed through this call's grant (s.grant). The caller (waitForApproval)
 *  asks again about once a second until the callee's phone has approved it, up to the ring window;
 *  the callee asks right after its own approval. A credential cached for this chat (fetched for an
 *  earlier call, until 5 minutes before it expires) is used without asking only once this call's
 *  grant is approved (audit VAR-09: canReuseTurn). */
async function turnIce(s: CallSession, waitForApproval = false): Promise<TurnIce | null> {
  const tok = s.token;
  if (turnCache && tok && turnCache.token === tok && canReuseTurn(turnCache, s, Date.now())) {
    console.log(`[veil-call] turn: cache hit, ${turnCache.ice.iceServers.length} server(s), relay-only`);
    return turnCache.ice;
  }
  const era = turnEra; // b75 round 3 (audit DV-10)
  try {
    const relay = grantRelay();
    if (!relay) throw new Error('relay not ready');
    // b77 (sealed sender): the call's chat asks through its own inbound (sealedTurn, read cap) — no
    // login, no account. b77r1 (audit A-6): no fallback to the logged-in account route any more. A
    // chat without delivery capabilities (none can call: they predate b77) gets no credentials: no call.
    if (!tok) throw new Error('no chat for this call');
    if (!s.grant) throw new Error('no call grant');
    const sess = grantSessions();
    if (!sess?.load) throw new Error('relay not ready');
    const calleeUntil = Date.now() + CALLEE_TURN_WAIT_MS;
    // the caller waits as long as the call rings (a 'ringing' confirmation can extend the window)
    const deadline = waitForApproval ? () => s.ringoutAt ?? 0 : calleeUntil;
    const data = await awaitTurnGrant(relay, sess as never, tok, s.grant, { alive: () => !callGone(s), deadline });
    if (data === null && !callGone(s)) s.noApproval = true; // b77n2 (review INFO): not the relay's fault
    if (data === null) throw new Error(callGone(s) ? 'the call ended meanwhile' : 'the other phone has not approved the call');
    s.grantOk = true; // audit VAR-09: the relay issued credentials for this grant, so it was approved
    const parsed = parseTurn(data);
    if (!parsed) throw new Error('malformed credentials');
    const got = { ...parsed, token: tok };
    if (got.expiresAt - TURN_REFRESH_MARGIN_MS <= Date.now()) throw new Error('credentials already near expiry');
    if (era !== turnEra) throw new Error('a wipe happened meanwhile'); // b75 round 3 (audit DV-10)
    turnCache = got;
    console.log(`[veil-call] turn: ${got.ice.iceServers.length} server(s), relay-only`);
    return got.ice;
  } catch (e) {
    console.log(`[veil-call] turn unavailable (${(e as Error)?.message ?? e}) — no call without the relay`);
    return null;
  }
}

/** Thrown when no TURN relay is available: the call ends with this text. */
class NoRelayError extends Error {
  constructor() { super(CALL_RELAY_UNREACHABLE); }
}

async function makePc(s: CallSession, ice: TurnIce | null): Promise<RTCPeerConnection> {
  // audit fix (b71): relay-only through VEIL's own TURN, ALWAYS. No relay
  // servers = no connection (the old host-only fallback leaked LAN IPv4 and
  // global IPv6 host candidates to the peer). iceCandidatePoolSize (20 Oct
  // 2026): relay allocations start as soon as the connection exists.
  const config = relayOnlyPcConfig(ice);
  if (!config) throw new NoRelayError();
  const pc = new RTCPeerConnection(config as never);
  // rn-webrtc extends event-target-shim whose generics don't resolve under
  // bundler moduleResolution — the listeners are structurally sound at
  // runtime, so a narrow structural cast keeps tsc green without weakening
  // any other call on the PC surface.
  const pcEv = pc as unknown as {
    addEventListener(type: 'icecandidate', l: (e: { candidate: RTCIceCandidate | null }) => void): void;
    addEventListener(type: 'connectionstatechange', l: () => void): void;
  };
  // Call quality (20 Oct 2026): candidates go in batches (src/calls/iceBatch.ts)
  // — one ratchet message per short window instead of one per candidate.
  const batcher = createIceBatcher(async (cands) => {
    const send = () => signal(s.token, iceSignalBody(s.callId, cands));
    // b196 (owner Metro log Oct 12: 429s dropped 4 of 9 ICE sends mid-call —
    // the LAN path survived on the ones that got through): one delayed retry
    // before dropping. A batch 2.5s late is still comfortably inside the
    // gathering + connect window, and skips are silent call-quality losses.
    await send().catch((err: Error) => {
      console.log(`[veil-call] ice send failed (${err.message}) — one retry in 2.5s`);
      setTimeout(() => {
        send().catch((err2: Error) => console.log(`[veil-call] ice send dropped after retry: ${err2.message}`));
      }, 2500);
    });
  });
  s.iceBatcher = batcher;
  pcEv.addEventListener('icecandidate', (e) => {
    if (!e.candidate) { s.gathered = true; if (s.iceRelease) batcher.flush(); return; } // null candidate = end-of-gathering
    // audit fix (b71): only relay candidates leave the phone, related address zeroed
    const cand = scrubCandidateJson(JSON.stringify({ candidate: e.candidate.candidate, sdpMid: e.candidate.sdpMid ?? null, sdpMLineIndex: e.candidate.sdpMLineIndex ?? null }));
    if (!cand) return;
    s.firstCandAt = s.firstCandAt ?? Date.now();
    // a prewarmed callee holds its candidates until the call is accepted
    if (s.iceRelease) batcher.push(cand); else s.heldIce.push(cand);
  });
  pcEv.addEventListener('connectionstatechange', () => {
    const st = pc.connectionState;
    console.log(`[veil-call] connection: ${st} (role ${s.role}, phase ${s.phase})`);
    // b151: this is the real signal — the only trustworthy "it's actually
    // live" event for either side.
    if (st === 'connected') { s.mediaUp = true; markConnected(s); void logPath(pc); void checkDtlsCert(s, pc); return; }
    if (st === 'disconnected' || st === 'failed' || st === 'closed') s.mediaUp = false;
    if (st === 'failed') {
      s.monitor.record('degraded', 'media path failed to establish');
      if (s.phase === 'connecting') { teardown(s, 'call failed to connect', true); return; }
      notify();
    }
    if (st === 'disconnected' && s.phase === 'active') { s.monitor.record('degraded', 'media path dropped mid-call'); notify(); }
  });
  return pc;
}

/** Call quality (20 Oct 2026): while a call rings, the callee fetches relay
 *  credentials, builds its connection and applies the offer, so the relay
 *  allocations are underway before Accept. Nothing is sent: candidates are
 *  held until the call is accepted (iceRelease), and a declined or missed
 *  call just closes the connection in teardown. Any failure leaves answer()
 *  to build it the old way. */
async function prewarm(s: CallSession): Promise<void> {
  try {
    // b77n (audit VAR-04): approve the caller's grant first — the caller gets its relay credentials
    // (and sends the offer) only after this; then this phone's own credentials through the same grant
    if (!(await approveCall(s))) return;
    if (session !== s || s.phase !== 'ringing' || s.pc) return;
    const ice = await turnIce(s);
    if (session !== s || s.phase !== 'ringing' || s.pc) return;
    const pc = await makePc(s, ice);
    if (session !== s || s.phase !== 'ringing') { try { pc.close(); } catch { /* closed */ } return; }
    s.pc = pc;
    await applyPrewarmOffer(s); // b77n: the offer may not be here yet; it is applied when it comes
  } catch (e) {
    console.log(`[veil-call] prewarm skipped: ${(e as Error).message}`);
    try { s.pc?.close(); } catch { /* closed */ }
    s.pc = null;
  }
}

/** b77n: the caller's offer applied to the prewarmed connection (once; when the offer and the
 *  connection both exist — whichever came second calls this) */
function applyPrewarmOffer(s: CallSession): Promise<void> {
  if (s.offerApplied) return s.offerApplied;
  const pc = s.pc, offer = s.pendingOfferSdp;
  if (!pc || !offer || s.answering) return Promise.resolve();
  s.offerApplied = (async () => {
    try {
      if (!(pc as unknown as { remoteDescription?: unknown }).remoteDescription) {
        await pc.setRemoteDescription(new RTCSessionDescription({ type: 'offer', sdp: offer }) as never);
      }
      for (const c of s.pendingIce) await addIce(pc, c).catch(() => undefined);
      s.pendingIce = [];
    } catch (e) { console.log(`[veil-call] prewarm offer not applied: ${(e as Error).message}`); }
  })();
  return s.offerApplied;
}

/** b77n: Accept came before the caller's offer — wait for it (or the call ending, or OFFER_WAIT_MS) */
async function waitOffer(s: CallSession, ms: number): Promise<void> {
  const until = Date.now() + ms;
  while (!s.pendingOfferSdp && Date.now() < until && !callGone(s)) await new Promise((r) => setTimeout(r, 50));
}

/** Which path the call took (relay vs host) — candidate types only, never
 *  addresses. Best-effort: stats shapes vary, any failure is silent. */
async function logPath(pc: RTCPeerConnection): Promise<void> {
  try {
    const report = (await pc.getStats()) as unknown as Map<string, Record<string, unknown>>;
    const all = Array.from(report.values());
    const byId = new Map(all.map((r) => [r.id as string, r]));
    const tr = all.find((r) => r.type === 'transport' && r.selectedCandidatePairId);
    const pair = (tr && byId.get(tr.selectedCandidatePairId as string))
      ?? all.find((r) => r.type === 'candidate-pair' && r.state === 'succeeded' && (r.selected || r.nominated));
    if (!pair) return;
    const local = byId.get(pair.localCandidateId as string)?.candidateType ?? '?';
    const remote = byId.get(pair.remoteCandidateId as string)?.candidateType ?? '?';
    console.log(`[veil-call] path: local ${String(local)} / remote ${String(remote)}`);
  } catch { /* diagnostics only */ }
}

/** Attach the mic to the PC — addTrack (rn-webrtc has no addStream). */
function attachMic(pc: RTCPeerConnection, local: MediaStream): void {
  const track: MediaStreamTrack | undefined = local.getAudioTracks()[0];
  if (!track) throw new Error('No audio track from the microphone.');
  pc.addTrack(track, local);
}

async function captureMic(): Promise<MediaStream> {
  // Call quality (20 Oct 2026): ask for WebRTC's echo cancellation, noise
  // suppression and gain control explicitly (the bare default left them to
  // the device, and the ZTE test phone echoed).
  const stream = (await mediaDevices.getUserMedia({
    audio: { echoCancellation: true, noiseSuppression: true, autoGainControl: true },
    video: false,
  } as never)) as unknown as MediaStream;
  return stream;
}

export const CallManager = {
  /** App wires this once the session context exists (App.tsx). */
  configure(t: CallTransport): void { transport = t; },

  /** b75 (audit DEV-L4): every wipe forgets what this module holds in memory: the
   *  cached TURN credentials, the seen-call ids and the calls ended here (a wipe used
   *  to leave them for the rest of the run) */
  forgetAfterWipe(): void {
    turnEra++; // b75 round 3 (audit DV-10): a fetch in flight can't fill the cache after this
    turnCache = null;
    seenCalls.forget();
    locallyEndedCalls.clear();
    recordedMisses.clear();
  },

  subscribe(l: (s: CallSnapshot | null) => void): () => void {
    listeners.add(l);
    l(snapshot());
    return () => { listeners.delete(l); };
  },

  snapshot,

  /** Caller path: start ringing out. */
  async start(token: string, peerLabel: string): Promise<void> {
    if (session && (session.phase === 'calling' || session.phase === 'ringing' || session.phase === 'connecting' || session.phase === 'active')) {
      throw new Error('A call is already in progress.');
    }
    const callId = newCallId();
    const s: CallSession = {
      callId, token, peerLabel, role: 'caller', phase: 'calling',
      core: { ...IDLE_CORE, callId }, monitor: new CallIntegrityMonitor(callId),
      pc: null, local: null, pendingIce: [], pendingOfferSdp: null, startedAt: null, endedReason: null,
      muted: false, seq: 1, ringVib: null, timeoutHandle: null, mediaUp: false,
      iceBatcher: null, iceRelease: false, heldIce: [], prewarming: null, reach: 'pending',
      grant: newTurnGrant(), // b77n (audit VAR-04): fresh per call attempt
    };
    session = s;
    notify();
    armRingout(s);
    let local: CallSession['local'] = null, pc: CallSession['pc'] = null, audioOn = false;
    try {
      // b77n (audit VAR-04): the grant is opened on this phone's inbound before anything is sent
      // b77u (audit 6 U-M4 / R1 F-04): the stream is ours (and stopped by any later abandon) the moment it arrives;
      // a failed grant stops it
      const mic = await captureBeside(captureMic(), openGrant(s), (m) => { local = m; });
      local = mic;
      if (callGone(s)) { abandon(s, local, pc, audioOn); return; } // hung up during the mic prompt
      s.local = local;
      // b77n: the INVITE rings the other phone (and wakes it: notify 'call') and carries the grant;
      // the other phone approves the grant as it rings. The ring window counts from here.
      await signal(token, { __veil_call: 1, op: 'invite', call_id: callId, seq: s.seq, grant: s.grant });
      s.invited = true;
      if (callGone(s)) { abandon(s, local, pc, audioOn); return; }
      armRingout(s);
      armRingAck(s); // the ringing tone waits for the callee's confirmation
      notify();
      // relay credentials only once the other phone approved this call (or one cached for this chat)
      const ice = await turnIce(s, true);
      if (callGone(s)) { abandon(s, local, pc, audioOn); return; } // hung up / rang out while waiting
      if (!relayOnlyPcConfig(ice)) throw new NoRelayError(); // audit fix (b71): fail closed, no offer sent
      callAudioMode(true); // Android call mode: echo cancellation + earpiece/headset
      audioOn = true;
      pc = await makePc(s, ice);
      if (callGone(s)) { abandon(s, local, pc, audioOn); return; }
      s.pc = pc;
      attachMic(pc, s.local);
      const offer = await pc.createOffer({ offerToReceiveAudio: true, offerToReceiveVideo: false });
      await pc.setLocalDescription(offer as never);
      await waitGathered(s, GATHER_WAIT_CALLER_MS); // 21 Oct 2026: details ride in the offer
      if (callGone(s)) { abandon(s, local, pc, audioOn); return; }
      const offerSdp = localSdp(pc, (offer as unknown as { sdp: string }).sdp);
      await signal(token, {
        __veil_call: 1, op: 'offer', call_id: callId, seq: s.seq,
        sdp: offerSdp,
        k: LEGACY_OFFER_K, // not a key: older builds refuse an offer without the field
      });
      if (callGone(s)) return; // teardown already closed what s holds
      releaseHeldIce(s, offerSdp);
      // b71 (device test): the ring window counts from the call reaching the other phone — b77n:
      // the invite (armed above, after it went out), not the tap: the mic prompt and a slow phone's
      // set-up ate half of it, and the other phone rang for only ~30 s
      notify();
    } catch (e) {
      if (callGone(s)) { abandon(s, local, pc, audioOn); return; }
      // b77n: once the invite went out the other phone rings — it is told the call ended
      // b77n2 (review INFO): the ring window ended with no approval from the other phone — say so, not "the relay"
      if (e instanceof NoRelayError) { teardown(s, s.noApproval ? CALL_PEER_UNREACHABLE : CALL_RELAY_UNREACHABLE, s.invited === true); return; } // shown on the call card
      teardown(s, 'could not start the call', s.invited === true);
      throw e;
    }
  },

  /** Callee accepted the ring. */
  // callId (audit fix b71): the call the tapped screen showed — a tap never
  // answers a different call that replaced it.
  async answer(callId?: string): Promise<void> {
    const s = session;
    if (callId !== undefined && s?.callId !== callId) return;
    // b64 test (C-5, live-found 21 Oct): on a slow network the first Accept
    // takes seconds; a second tap re-ran the answer on the same connection,
    // which failed and ended the call. Only the first tap counts.
    if (!s || s.phase !== 'ringing' || s.role !== 'callee' || s.answering) return;
    s.answering = true;
    void stopRingtone(); // feedback that the tap registered
    let local: CallSession['local'] = null, pc: CallSession['pc'] = null, audioOn = false;
    try {
      // 20 Oct 2026: let a prewarm that's still running finish, then reuse it
      const mic = await captureBeside(captureMic(), s.prewarming ?? Promise.resolve(), (m) => { local = m; }); // b77u (audit 6 U-M4)
      local = mic;
      if (callGone(s)) { abandon(s, local, pc, audioOn); return; } // the caller hung up meanwhile
      s.local = local;
      // b77n (audit VAR-04): the caller sends its offer once this phone approved the grant (prewarm
      // did that as the call rang); an Accept that beat the offer waits for it
      if (!s.pc && !(await approveCall(s))) throw new NoRelayError();
      if (!s.pendingOfferSdp) await waitOffer(s, OFFER_WAIT_MS);
      if (callGone(s)) { abandon(s, local, pc, audioOn); return; }
      callAudioMode(true); // Android call mode: echo cancellation + earpiece/headset
      audioOn = true;
      await (s.offerApplied ?? Promise.resolve()); // b77n: a prewarm offer apply still running
      pc = s.pc ?? await makePc(s, await turnIce(s));
      if (callGone(s)) { abandon(s, local, pc, audioOn); return; }
      s.pc = pc;
      attachMic(pc, s.local);
      const offer = s.pendingOfferSdp;
      if (!offer) throw new Error('No offer SDP for this call.');
      if (!(pc as unknown as { remoteDescription?: unknown }).remoteDescription) {
        await pc.setRemoteDescription(new RTCSessionDescription({ type: 'offer', sdp: offer }) as never);
      }
      if (!checkAppliedRemote(s, pc)) return; // audit fix (b71): ended, nothing answered
      // flush ICE that arrived before the remote description existed
      for (const ice of s.pendingIce) await addIce(pc, ice);
      s.pendingIce = [];
      const answer = await pc.createAnswer();
      await pc.setLocalDescription(answer as never);
      await waitGathered(s, GATHER_WAIT_CALLEE_MS); // 21 Oct 2026: details ride in the answer
      if (callGone(s)) { abandon(s, local, pc, audioOn); return; } // never answer a dead call
      s.core = answerCall(s.core);
      const answerSdp = localSdp(pc, (answer as unknown as { sdp: string }).sdp);
      await signal(s.token, {
        __veil_call: 1, op: 'answer', call_id: s.callId, sdp: answerSdp,
      });
      if (callGone(s)) return; // teardown already closed what s holds
      // accepted: anything the answer didn't carry trickles now
      releaseHeldIce(s, answerSdp);
      clearRing(s);
      armConnecting(s);
    } catch (e) {
      console.log(`[veil-call] answer failed: ${(e as Error).message}`);
      if (callGone(s)) { abandon(s, local, pc, audioOn); return; }
      teardown(s, e instanceof NoRelayError ? CALL_RELAY_UNREACHABLE : 'call failed to connect', true);
    }
  },

  /** Callee declined. */
  decline(callId?: string): void { // callId: as for answer
    const s = session;
    if (callId !== undefined && s?.callId !== callId) return;
    if (!s || s.phase !== 'ringing' || s.role !== 'callee') return;
    teardown(s, 'declined', true);
  },

  /** Either side hangs up. No callId = whatever call is live (wipes, decoy). */
  hangup(callId?: string): void {
    const s = session;
    if (callId !== undefined && s?.callId !== callId) return;
    if (!s || s.phase === 'ended') return;
    teardown(s, 'hangup', true);
  },

  /** audit fix (b71): the ring is on screen (CallOverlay calls this while the
   *  app is in front). Only now does the caller hear "Ringing…" — an offer
   *  that rang nowhere visible never confirms. Once per call. */
  ringShown(callId: string): void {
    const s = session;
    if (!s || s.callId !== callId || s.role !== 'callee' || s.phase !== 'ringing' || s.ringAcked) return;
    s.ringAcked = true;
    // audit VAR-09 (1f51): the grant approval and the relay allocations start only now that the
    // ring is on screen (20 Oct 2026 prewarm, moved from the invite's receipt)
    if (!s.prewarming && !s.pc && !s.answering) s.prewarming = prewarm(s);
    void signal(s.token, { __veil_call: 1, op: 'ringing', call_id: s.callId })
      .catch((e: Error) => console.log(`[veil-call] ringing confirmation not sent: ${e.message}`));
  },

  /** audit fix (b71), lock screen: is a call ringing or holding the mic? No
   *  name or token, so it is safe to show under the lock. */
  lockScreenCall(): { phase: CallUiPhase; callId: string; incoming: boolean } | null {
    const s = session;
    if (!s || s.phase === 'ended') return null;
    // b71 (device test): enough for the lock screen to show "incoming — unlock to answer"
    // (still no name or chat)
    return { phase: s.phase, callId: s.callId, incoming: s.role === 'callee' && s.phase === 'ringing' };
  },

  /** audit fix (b71), lock screen: end whatever call is live — the lock
   *  screen's "End call" control, or App ending calls as it locks. */
  endFromLock(): void {
    const s = session;
    if (!s || s.phase === 'ended') return;
    teardown(s, s.role === 'callee' && s.phase === 'ringing' ? 'declined' : 'ended on the lock screen', true);
  },

  /** b157: set by App — receives (threadToken, peerLabel) exactly once per
   *  missed call, and persists it into the thread's pending notices. */
  onMissedCall: null as ((threadToken: string, peerLabel: string) => void) | null,

  toggleMute(): void {
    const s = session;
    if (!s || s.phase !== 'active') return;
    s.muted = !s.muted;
    s.local?.getAudioTracks().forEach((t) => { t.enabled = !s.muted; });
    notify();
  },

  /** Entry point from syncToken: every call signal the sync decrypted.
   *  peerLabel (b152): the background sync path has no open thread UI to
   *  source a name from, so App passes the session row's title alongside. */
  async handleSignals(token: string, sigs: CallSignal[], peerLabel?: string): Promise<void> {
    // b157: a batch holding BOTH the offer and the caller's end for the same
    // call_id is a call that died before this device could ring (typically
    // the offer was held while the app was locked) — record the miss and
    // never ring a dead call.
    const ended = new Set(sigs.filter((x) => x.op === 'end').map((x) => x.call_id));
    for (const sig of sigs) {
      // b77n (audit VAR-04): the invite is what rings (it was the offer)
      if (sig.op === 'invite' && ended.has(sig.call_id)) {
        await seenCalls.add(sig.call_id); // audit fix (b71): a later replay of it never rings
        recordMissed(sig.call_id, token, peerLabel ?? 'Vardum contact');
        continue;
      }
      await this.handleSignal(token, sig, peerLabel);
    }
  },

  async handleSignal(token: string, sig: CallSignal, peerLabel?: string): Promise<void> {
    const s = session;
    console.log(`[veil-call] signal in: ${sig.op} (this call ${s?.callId === sig.call_id ? 'yes' : 'no'}, phase ${s?.phase ?? 'none'})`);
    switch (sig.op) {
      case 'offer': {
        // b77n (audit VAR-04): the offer follows the INVITE (which rang this phone and whose grant it
        // approved): it belongs to the call ringing here, from the same chat, and comes once.
        if (!s || s.role !== 'callee' || s.token !== token || s.callId !== sig.call_id || s.phase !== 'ringing' || s.pendingOfferSdp) {
          console.log('[veil-call] offer ignored: no call from this chat is ringing for it (or it already came)');
          return;
        }
        try {
          s.core = processOffer(s.core, sig);
          s.pendingOfferSdp = sig.sdp ?? null;
          if (s.pc) void applyPrewarmOffer(s);
        } catch (e) {
          if (e instanceof CallRefusedError) console.log(`[veil-call] offer refused (${e.code}): replay/MITM guard did its job`);
          else console.log(`[veil-call] offer error: ${(e as Error).message}`);
        }
        return;
      }
      case 'invite': {
        // audit fix (b71): a withheld or replayed offer never rings. The
        // authenticated send time must be within OFFER_MAX_AGE_MS back /
        // OFFER_MAX_FUTURE_MS ahead, and a call id rings at most once.
        await seenCalls.load();
        if (seenCalls.has(sig.call_id) || s?.callId === sig.call_id) {
          console.log('[veil-call] offer refused: this call id was already handled (replay)');
          return;
        }
        const freshness = offerFreshness(sig);
        if (freshness !== 'fresh') {
          await seenCalls.add(sig.call_id);
          console.log(`[veil-call] offer not rung: ${freshness} (authenticated send time outside the ring window)`);
          // someone did try to call: leave the missed-call notice, never ring
          if (!locallyEndedCalls.has(sig.call_id)) recordMissed(sig.call_id, token, peerLabel ?? 'Vardum contact');
          return;
        }
        await seenCalls.add(sig.call_id);
        if (s && s.phase === 'ringing' && s.callId !== sig.call_id && s.token === token) {
          // b63 review (C-4): a newer call from the SAME chat replaces one
          // still ringing; end the old one properly (its connection, timers,
          // and its caller's ring)
          teardown(s, 'replaced by a newer call', true);
        } else if (s && s.phase === 'ringing') {
          // audit fix (b71): a call from ANOTHER chat never ends this one.
          // b71 (audit F-27): and it gets no automatic "busy" (that told the caller
          // this phone was on a call); it rings out there and shows as missed here
          recordMissed(sig.call_id, token, peerLabel ?? 'Vardum contact');
          return;
        }
        if (s && (s.phase === 'calling' || s.phase === 'connecting' || s.phase === 'active')) {
          recordMissed(sig.call_id, token, peerLabel ?? 'Vardum contact'); // b71 (audit F-27): no automatic "busy"
          return;
        }
        // b77n (audit VAR-04): the invite rings; the SDP (and its DTLS fingerprint, bound by
        // processOffer) comes in the offer the caller sends once this phone approved the grant
        const core: CallState = { ...IDLE_CORE, callId: sig.call_id, phase: 'ringing' };
        try {
          if (typeof sig.grant !== 'string') throw new Error('invite without a call grant');
          const fresh: CallSession = {
            callId: sig.call_id, token, peerLabel: peerLabel ?? 'Vardum contact',
            role: 'callee', phase: 'ringing', core,
            monitor: new CallIntegrityMonitor(sig.call_id),
            pc: null, local: null, pendingIce: [], pendingOfferSdp: null,
            startedAt: null, endedReason: null, muted: false,
            seq: 0, ringVib: null, timeoutHandle: null, mediaUp: false,
            iceBatcher: null, iceRelease: false, heldIce: [], prewarming: null,
            grant: sig.grant,
          };
          session = fresh;
          // b146: drain any candidates that arrived before this offer
          const early = preOfferIce.get(iceKey(token, sig.call_id));
          if (early) { fresh.pendingIce.push(...early); preOfferIce.delete(iceKey(token, sig.call_id)); }
          if (androidRingerMode() !== 'silent') Vibration.vibrate(RING_PATTERN, true); // b199: Android silent = no buzz
          void startRingtone();
          armRingout(fresh);
          notify();
          // audit VAR-09 (1f51): NOT here. Approving the grant (and allocating) on receipt told the
          // caller "the phone got the call" even when it never rang (background sync). The grant is
          // approved and the connection prewarmed from ringShown() — the call screen is up with the
          // app in front — or from answer(). Like 'ringing', which also goes from ringShown().
        } catch (e) {
          console.log(`[veil-call] invite error: ${(e as Error).message}`);
        }
        return;
      }
      case 'ringing': {
        if (!s || s.token !== token || s.callId !== sig.call_id || s.role !== 'caller' || s.phase !== 'calling') return;
        if (s.reach === 'ringing') return;
        s.reach = 'ringing';
        if (s.ackHandle) { clearTimeout(s.ackHandle); s.ackHandle = null; }
        if ((s.ringoutAt ?? 0) - Date.now() < RING_AFTER_ACK_MS) armRingout(s, RING_AFTER_ACK_MS); // b71 (device test)
        void startRingback(s); // now the tone is honest
        notify();
        return;
      }
      case 'answer': {
        if (!s || s.token !== token || s.callId !== sig.call_id || s.role !== 'caller' || s.phase !== 'calling') return; // audit fix (b71): bound to this call's own chat
        const fp = extractDtlsFingerprint(sig.sdp ?? '');
        if (!fp) { s.monitor.record('fingerprint', 'answer SDP carried no DTLS fingerprint — refusing'); teardown(s, 'call refused', true); return; }
        s.core = { ...s.core, offerFingerprint: fp };
        try {
          if (!s.pc) throw new Error('No peer connection.');
          // b63 review (C-2): ringback off before media can start, so stopping
          // it can't touch the audio session under a live call
          await stopRingback();
          if (callGone(s) || !s.pc) return;
          await s.pc.setRemoteDescription(new RTCSessionDescription({ type: 'answer', sdp: sig.sdp as string }) as never);
          if (!checkAppliedRemote(s, s.pc)) return; // audit fix (b71): ended, red
          for (const ice of s.pendingIce) await addIce(s.pc, ice);
          s.pendingIce = [];
          clearRing(s);
          armConnecting(s);
        } catch (e) {
          console.log(`[veil-call] answer error: ${(e as Error).message}`);
          teardown(s, 'call failed to connect', true);
        }
        return;
      }
      case 'ice': {
        if (s && (s.callId !== sig.call_id || s.token !== token)) return; // belongs to another call (or another chat)
        if (!s) {
          // b146: candidates can beat the offer across poll batches (the same
          // race the web client fixed). Buffer them per call and drain into
          // pendingIce the moment the offer creates the session — otherwise
          // the media path silently never connects.
          if (!sig.call_id) return;
          const key = iceKey(token, sig.call_id);
          if (!preOfferIce.has(key)) preOfferIce.set(key, []);
          preOfferIce.get(key)!.push(sig);
          if (preOfferIce.get(key)!.length > 64) preOfferIce.get(key)!.shift();
          return;
        }
        if (s.phase === 'ended') return;
        if (!s.pc || !(s.pc as unknown as { remoteDescription?: unknown }).remoteDescription) { s.pendingIce.push(sig); return; }
        try { await addIce(s.pc, sig); } catch (e) { console.log(`[veil-call] ice error: ${(e as Error).message}`); }
        return;
      }
      case 'end': {
        // audit fix (b71): an end from another chat never touches this call
        if (s && s.callId === sig.call_id && s.token !== token) return;
        if (s && s.callId === sig.call_id) {
          // caller gave up while we were still ringing — a missed call
          const missedCandidate = s.role === 'callee' && s.phase === 'ringing' && !recordedMisses.has(sig.call_id);
          teardown(s, sig.reason ?? 'ended', false); // peer already sent their end
          if (missedCandidate) recordMissed(sig.call_id, token, s.peerLabel); // b157
          return;
        }
        // b157: end for a call this device never saw ring (offer held while
        // the app was locked). Our own decline/hangup already marked the
        // call locally-ended, so that echo never counts as a miss.
        // b71 (audit F-29): only for a call id whose offer this phone received —
        // a bare "end" can no longer plant a missed-call notice
        await seenCalls.load();
        if (seenCalls.has(sig.call_id) && !locallyEndedCalls.has(sig.call_id)) recordMissed(sig.call_id, token, peerLabel ?? 'Vardum contact');
        return;
      }
    }
  },
};

/** Adds every candidate a signal carries: a single `cand` (older builds) or a
 *  batch in `cands` (20 Oct 2026). One bad candidate doesn't stop the rest. */
async function addIce(pc: RTCPeerConnection, sig: CallSignal): Promise<void> {
  const all = candsOf(sig);
  let firstErr: unknown = null;
  for (const raw of all) {
    try {
      const c = JSON.parse(raw) as { candidate: string; sdpMid?: string | null; sdpMLineIndex?: number | null };
      await pc.addIceCandidate(new RTCIceCandidate({
        candidate: c.candidate, sdpMid: c.sdpMid ?? undefined, sdpMLineIndex: c.sdpMLineIndex ?? undefined,
      }) as never);
    } catch (e) { firstErr = firstErr ?? e; }
  }
  if (firstErr && all.length === 1) throw firstErr;
}

