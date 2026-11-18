/**
 * @veil/device — chat sync + send: the exact web envelope loop.
 *   list the session's envelopes (newest first, paged) -> decrypt new envelopes
 *   in order -> advance + reseal the ratchet. Send: encrypt -> submitEnvelope
 *   with the web's TTL/expiry contract.
 */

import { parseCallSignal, type CallSignal } from './calls';
import {
  encryptMessage, decryptMessage, completeHandshake,
  deserializeRatchetState, serializeRatchetState, peekHeader,
  toB64, fromB64, splitForBuckets, BUCKET_TEXT_MAX, clampDials, type DialsInput, padBlob, unpadBlob, coverFillerText, BLOB_OVERHEAD_BYTES,
  ReplayedMessageError, StaleMessageError, JunkEnvelopeError, type DecryptedMessage,
  deliveryForRole, type DeliveryCaps, type ChatDelivery,
} from '../../crypto-core/src/index';
import type { VeilRelay, SessionStore } from './index.js';
import type { PendingBurn } from './session-store';
import { saveOrThrow } from './save-strict';
import { pinToWipe } from './wipe-generation';
import { relayTimestampToIso } from './time';
import { serializeRatchetSend, ratchetChainIdle } from './send-queue';
import { chatGoneAnswers, noteGoneAnswer, clearGoneAnswers, outGoneKey } from './session-liveness';
import { relayStatusOf, RelayTimeoutError } from './relay';
import {
  requireDelivery, chatDelivery, ensureInboundOpen, flushOutbox, sealedSend, scheduleInboundOpen, readHandshakeStatus,
  MailboxNotOpenError, MailboxRetiredError, tagQueued, ensureOutboxRoom, PEER_OPEN_GIVE_UP_MS, type FlushResult,
  noteSendGone, outboundGoneConfirmed, endSealedChat, // b77n (INFO-5): endSealedOutbound no longer used here
} from './sealed';
import { PEEK_DIALS_BURN_FLOOR_SECONDS } from './invite';
import { cleanName } from './names'; // b77k (IP77-3)
import { relayDetailOf } from './relay-errors'; // b77m (audit VAR-20)
import { parseCapturePayload } from './capture-notice'; // b77m review (L1)
import { secureRandomUnit } from './secure-random'; // b77t (audit 5 L-28)

/** Media message descriptor — the web bundle's __veil_media payload (parser
 *  Hp). Media messages carry text:'' and render from these fields instead. */
export interface ChatMedia {
  /** encrypted blob URI in private storage */
  uri?: string;
  /** AES-256-GCM key (b64) — generated fresh per file, only ever E2E */
  k?: string;
  /** AES-GCM IV (b64) */
  iv?: string;
  mime?: string;
  name?: string;
  size?: number;
  /** sender allowed saving this file to the device (web dl:1) */
  dl?: boolean;
  /** device-local render source for the DECRYPTED bytes (sender: picker uri;
   *  receiver: in-memory data: URI — plaintext never touches disk) */
  localUri?: string;
}

export interface ChatMessage {
  id: string;
  text: string;
  mine: boolean;
  ts: string | null;
  media?: ChatMedia;
  /** b199: a group invitation card (text is '' for these) */
  groupInvite?: ChatGroupInvite;
  /** set on MY messages when a peer receipt confirms read:true (web read-receipt parity) */
  read?: boolean;
  /** b199: one reaction per side (pairwise threads) */
  reactions?: { mine?: string; peer?: string };
  /** relay record id captured from the submitEnvelope response (web envelopeId
   *  parity) — MY messages match incoming receipt ids on this, not the local id */
  envId?: string;
  /** b74 (veil-ratchet-7, review VAR-07): the message's own id — derived from its
   *  signed, AEAD-bound header (messageIdOf), the same bytes on both phones. Receipts
   *  and reactions name this, never a relay record id, so a relay can't attach a
   *  peer's read tick or reaction to a different message. */
  mid?: string;
  /** b72: when this message was FIRST OPENED on this device (epoch ms) — the
   *  anchor for the web-parity "burn N hours after open" countdown.
   *  b75r3 (audit PR3-02): stamped at DISPLAY only — never at decrypt or send. The
   *  App stamps rows it shows (markEnvelopesDisplayed -> SessionStore.markShown);
   *  opening a chat stamps the rest (SessionStore.ensureOpenedAt); a sent row
   *  gets it from the peer's read receipt. */
  openedAt?: number;
  /** Play UGC: the sender's Vardum ID on received group rows (block list match) */
  senderVid?: string;
  /** b77r1 (audit A-5): MY message is encrypted but still waiting in the outbox (the peer's
   *  inbound is not open yet) — the bubble says "Waiting to deliver" until it goes */
  queued?: boolean;
  /** b77m (audit VAR-54): a received row — when THIS phone received (decrypted) it, epoch ms. The
   *  unopened-horizon purge runs from this, never from the peer-chosen `ts`. */
  rcvAt?: number;
}

/** b82 EMERGENCY KILL-SWITCH for burn-after-open calls.
 *  HISTORY (Sept 20 incident): the relay gate's 'burn' action was
 *  deleting the ENTIRE VeilSession row, not just the target envelope —
 *  every burn_after_open session self-destructed on its first decrypted
 *  envelope (f240, ed5c1c8a, the b80-era "dead session" flood). b82
 *  disabled ALL native burn calls until the gate was fixed.
 *  b86 (Sept 21): FIX CONFIRMED. The builder delivered the verbatim
 *  burn branch — its ONLY write is VeilEnvelope.update(env.id, ...)
 *  shortening expires_at to the session's burn window (never-extend,
 *  idempotent, no session delete/cascade anywhere in the branch), and a
 *  live end-to-end test on the deployed gate showed the session row
 *  surviving with repeat burn calls returning ok. Kill-switch flipped
 *  OFF; burn-after-open is live again. Keep the flag as an emergency
 *  switch: set callsDisabled back to true ONLY if the invariant breaks
 *  again (symptom: "Session not found" right after a successful burn). */
export const burnFlags = { callsDisabled: false };

/**
 * b70 (audit L-1): a received message shows the SENDER's time (carried inside
 * the encryption) when it is plausible — not in the future, not more than 30
 * days old — so the relay can't backdate or reorder messages unseen. Older
 * builds send no time; their messages keep the relay's.
 */
/** b77m (audit VAR-55): how far a sender's clock may run ahead of this phone's */
export const SHOWN_TIME_SKEW_MS = 10 * 60_000;
export function shownTime(
  dec: { meta?: { sentAt: number } },
  relayCreated: unknown,
  /** b77m (audit VAR-55): rcvAt = when this phone received it (default now); maxAgeMs = the oldest a sender
   *  time may be, counted back from rcvAt (default 30 days; a 1:1 chat passes its envelope lifetime plus the
   *  outbox wait — an older message can't arrive at all) */
  opts: { rcvAt?: number; maxAgeMs?: number } = {},
): string | null {
  // (a mailbox envelope carries no relay time: then this phone's receive time stands in for it)
  const relay = relayCreated ? relayTimestampToIso(relayCreated as string) : null;
  const t = dec.meta?.sentAt;
  const rcv = Number.isFinite(opts.rcvAt) && (opts.rcvAt as number) > 0 ? (opts.rcvAt as number) : Date.now();
  const maxAge = Number.isFinite(opts.maxAgeMs) && (opts.maxAgeMs as number) > 0 ? Math.min(opts.maxAgeMs as number, 30 * 86400_000) : 30 * 86400_000;
  // b77m (audit VAR-55): outside the window the peer's time is not shown — the relay's, or (a mailbox
  // envelope has none) this phone's receive time
  if (!t || !Number.isFinite(t) || t > rcv + SHOWN_TIME_SKEW_MS || t < rcv - maxAge) return relay ?? new Date(rcv).toISOString();
  // a message can't have been sent after it arrived: a sender clock a little ahead shows the receive time
  return new Date(Math.min(t, rcv)).toISOString();
}

export interface SyncResult {
  /** b77u (audit 6 RH-L2): the caller's shouldAbort said stop after the fetch; nothing was processed */
  aborted?: boolean;
  /** b80: set when this sync discovered the session no longer exists
   *  server-side (a real 404 from the relay, not a guess) — caller should
   *  drop this token from sessionRows / mark the thread ended locally. */
  ended?: boolean;
  /** b77m (audit VAR-07): set with `ended` — who ended it. 'peer' = the peer's END control message, decrypted
   *  and authenticated in this chat (the only way `ended` is set now); the local state is removed. */
  endedBy?: 'peer';
  /** b77u (audit 6 U-M8): set with endedBy 'peer' — the peer's authenticated END deleted this phone's copy of the
   *  chat (SessionStore.purgeChatHistory): the app clears the open thread, its decrypted media files and shows that
   *  the other person ended the chat and its messages were removed. The chat stays listed as ended. */
  purged?: boolean;
  /** b77m (audit VAR-07): the RELAY says this chat no longer exists (its mailboxes answered 410 under the P-4
   *  rule) but nothing from the peer said so. The chat is NOT removed and NOT "ended by the other side": its
   *  history stays (read-only; the user can delete it), its mailboxes are retired, and later passes send
   *  nothing (isChatUnavailable). The app says "the server reports this chat no longer exists". */
  unavailable?: boolean;
  /** b77 (sealed sender): the relay said my inbound is retired (410) — the peer ended the chat —
   *  but not yet often enough, over long enough, to remove it (the P-4 rule). Caller backs off. */
  gonePending?: boolean;
  /** b77: my inbound is not open yet (its random delay is running, or the relay said 425) —
   *  nothing to fetch this pass; never "ended" */
  inboundWaiting?: boolean;
  /** b77r1 (audit A-5): this chat can't finish setting up — my inbound's ticket kept being
   *  refused (it never opened), or my envelopes have waited past the time the peer could still
   *  open its inbound. The app says so and offers End ("start a new chat"). */
  setupFailed?: boolean;
  /** b77r1 (audit A-5): my queued messages that went out this pass (local id, relay id) — the
   *  app drops their "Waiting to deliver" state */
  delivered?: { id: string; envId?: string }[];
  /** b77r1 (audit A-5): envelopes still waiting in this chat's outbox */
  outboxWaiting?: number;
  /** b77r1 (audit A-5): local ids of my messages that still have an envelope waiting — any
   *  other bubble the app shows as waiting has gone out */
  queuedIds?: string[];
  /** b87: the skip cursor the caller should persist via
   *  SessionStore.saveSyncSkip() before the next poll — see chat.ts's
   *  syncChat for the advance rule. Always present (0 is a valid value). */
  nextSkip: number;
  /** b143: call signaling payloads decrypted this pass (offers, answers,
   *  ICE candidates, hangups) — filtered from messages, consumed by the
   *  call UI. Empty on every ordinary poll. */
  callSignals?: CallSignal[];
  /** b91 (web stray-classifier parity): envelope ids that failed to decrypt
   *  BUT a newer envelope in the same pass decrypted fine — a stale stray
   *  the ratchet has moved past. Caller surfaces a soft notice. */
  strayIds?: string[];
  /** b70 (audit L-1): messages the peer numbered but that never arrived (a
   *  sequence gap this pass) — the relay may be holding them back */
  missingFromPeer?: number;
  /** b91: true when failures look like a GENUINE desync — header-key
   *  mismatch (epoch divergence), timestamp-less failures, or failures with
   *  no successful newer decrypt after them. Caller keeps the destructive
   *  end-session recommendation. */
  desync?: boolean;
  /** b75 (audit RT-2): the envelope ids behind `desync` (failures on AUTHENTICATED headers
   *  only). They are not ledgered (a later pass may open them), so the caller counts an id
   *  once: re-serving the same failing envelope never builds an "out of sync" streak. */
  desyncIds?: string[];
  /** b75r3 (audit PR3-03): the same failures keyed by the peer's SIGNED header (ratchet key +
   *  counter), so a relay can't make one withheld envelope count again under new ids */
  desyncKeys?: string[];
  /** b75r3 (audit PR3-03): envelopes that opened (authenticated decrypts of any kind — chat,
   *  cover, receipt, call) this pass; any of them resets the "out of sync" streak */
  authOpened?: number;
  /** b175: the relay rejected a burn/fetch this pass with its anti-abuse
   *  rate limiter. Caller should back off its poll interval instead of
   *  retrying at full speed — see App.tsx syncToken. */
  rateLimited?: boolean;
  /** Batch E (Superagent round 3, F-1): burns the relay keeps refusing after
   *  the fast retries — still queued (with backoff), shown in the thread. */
  burnStuck?: number;
  /** Batch H (R6-1-06): this phone's storage refused the chat state this pass */
  stateNotSaved?: boolean;
  /** Batch H (R5-1-09): the burn queue could not be saved, or is full */
  burnQueueTrouble?: boolean;
  messages: ChatMessage[];
  /** every envelope id decrypted this pass — including filtered control/cover
   *  ones — so the caller's knownIds set stays complete (a consumed ratchet
   *  message key can't be re-derived; re-decrypt on the next poll fails). */
  processedIds: string[];
  /** ids of MY messages the peer confirmed READ (receipt payloads with
   *  read:true) — caller marks those bubbles read (web parity). */
  readIds: string[];
  /** b77k (IP77-3): the peer's own nickname changed this pass (saved in the record; '' = cleared) */
  peerNick?: string;
  /** b199 reactions: the peer's reaction changes this pass, in order —
   *  target = the reacted message's envelope id, emoji null = removed. */
  reactions?: { target: string; emoji: string | null }[];
  state: import('../../crypto-core/src/index').RatchetStateSerialized;
}

/** b199 (owner request, Oct 17): hold a message to react. The only emoji a
 *  reaction may carry — anything else received is ignored. */
export const REACTION_EMOJI = ['👍', '👎', '❤️', '🙏', '😂', '😮'] as const;

interface EnvelopeRecord {
  id?: string;
  ciphertext?: string;
  iv?: string;
  header?: string;
  created_date?: string;
  expires_at?: string;
  /** b77: the inbound mailbox's sequence number (sealedFetch) */
  seq?: number;
}

/* b127 (HTTP-200-wrapped rejects throw) and the submit-id unwrapping now live in sealed.ts
 * (sealedSend), the one 1:1 submit path since b77. */

/** b71: a page of envelopes ordered newest-first (what pageBacklog expects) */
export function newestFirst<T extends { created_date?: unknown }>(recs: T[]): T[] {
  return recs.slice().sort((a, b) => String(b.created_date ?? '').localeCompare(String(a.created_date ?? '')));
}

/**
 * AAD is the envelope record's header field STRING, byte-for-byte exactly as
 * received from the relay — NEVER parsed and re-stringified (even a key-order
 * change fails the AES-GCM tag on every message, silently). Object form is a
 * legacy fallback only; the string form round-trips untouched.
 */
/** non-ratchet fields that must survive every reseal (serialize drops them).
 *  Batch D (D-09, RV-07): ALL the dials, not only burnAfterOpen — before this the
 *  expiry and burn dials were dropped by the first reseal, so every envelope
 *  after the first fell back to a 24 h expiry. */
// Batch F (R4-1-04): plus who the chat is with (sealed at the contact handshake)
// Batch F (R4-1-03): plus this phone's own safety-code confirmation; (R4-1-01) where the dials came from
// b77 (sealed sender): plus the chat's delivery capabilities (sealed record `delivery`)
// b77k (IP77-3): plus the peer's own nickname (`peerNick`) and the one this phone last sent (`nickSent`)
const SEALED_DIAL_FIELDS = ['burnAfterOpen', 'defaultTtlSeconds', 'expireAfterSeconds', 'keyRetentionHours', 'peerVeilId', 'peerIkPub', 'myVerifiedFp', 'dialsSource', 'delivery', 'peerNick', 'nickSent'] as const;
function withExtras(serialized: unknown, sealed: unknown): never {
  const extras: Record<string, unknown> = {};
  for (const f of SEALED_DIAL_FIELDS) {
    const v = (sealed as Record<string, unknown>)[f];
    if (v !== undefined) extras[f] = v;
  }
  return { ...(serialized as Record<string, unknown>), ...extras } as never;
}

/**
 * Batch D (D-09): the session's dials. The signed transcript copy (state.dials,
 * bound into the fingerprint since V-12) comes first; sessions from before it
 * use the copy sealed at completion. Never the relay row.
 */
export function sessionDials(sealed: unknown): DialsInput | null {
  const s = (sealed ?? {}) as { dials?: unknown; burnAfterOpen?: unknown; defaultTtlSeconds?: unknown; expireAfterSeconds?: unknown; keyRetentionHours?: unknown };
  if (typeof s.dials === 'string') {
    const m = /^t=(\d+);e=(\d+);r=(\d+);b=([01])$/.exec(s.dials);
    if (m) return clampDials({ defaultTtlSeconds: Number(m[1]), expireAfterSeconds: Number(m[2]), keyRetentionHours: Number(m[3]), burnAfterOpen: m[4] === '1' });
  }
  if (s.defaultTtlSeconds !== undefined || s.expireAfterSeconds !== undefined || s.keyRetentionHours !== undefined) {
    return clampDials({
      defaultTtlSeconds: s.defaultTtlSeconds as number, expireAfterSeconds: s.expireAfterSeconds as number,
      keyRetentionHours: s.keyRetentionHours as number, burnAfterOpen: s.burnAfterOpen === true,
    });
  }
  return null;
}

/**
 * Batch F (round-4 review R4-1-03): did the user on THIS phone confirm the
 * safety code for the session's current fingerprint? The relay's per-side
 * "verified" flags are only hints for the badge; a relay could set them. The
 * send gate needs this local confirmation. Bound to the fingerprint, so a key
 * change (a new fingerprint) needs a new confirmation.
 */
export function locallyVerified(sealed: unknown): boolean {
  const s = (sealed ?? null) as { fingerprint?: string | null; myVerifiedFp?: unknown } | null;
  if (!s || typeof s.myVerifiedFp !== 'string' || !s.myVerifiedFp) return false;
  // Batch G (round-5 NF-1 / R5-1-07): no fingerprint on this phone = nothing was compared
  if (typeof s.fingerprint !== 'string' || !s.fingerprint) return false;
  return s.myVerifiedFp === s.fingerprint;
}

/** Batch H (round-6 review R6-1-05): a key-change revocation clears the sealed
 *  confirmation, so it survives a restart and a fresh comparison is needed. */
export async function clearLocalVerification(sessions: SessionStore, token: string): Promise<void> {
  await serializeRatchetSend(token, async () => {
    const sealed = await sessions.load(token);
    if (!sealed || !(sealed as { myVerifiedFp?: string }).myVerifiedFp) return;
    const { myVerifiedFp: _gone, ...rest } = sealed as unknown as Record<string, unknown>;
    void _gone;
    // Batch I (local review V-03): a refused save used to resolve quietly and
    // the confirmation came back after a restart. It's reported now; the app
    // keeps the gate closed and retries.
    if ((await sessions.save(token, rest as never)) === false) {
      throw new Error('The key-change revocation could not be saved on this phone.');
    }
  });
}

/** Batch F (R4-1-03): seal "I compared the codes and they match" for the session's
 *  current fingerprint. Runs under the session's ratchet lock so a sync or send
 *  in flight can't write over it. */
export async function markLocallyVerified(sessions: SessionStore, token: string): Promise<void> {
  await serializeRatchetSend(token, async () => {
    const sealed = await sessions.load(token);
    if (!sealed) throw new Error('No ratchet state for this session on this device.');
    const fp = (sealed as { fingerprint?: string | null }).fingerprint;
    // Batch G (NF-1): never seal a confirmation without a safety code to compare
    if (typeof fp !== 'string' || !fp) throw new Error('This chat has no safety code on this phone, so it can’t be verified.');
    // b71 (audit): this seal is now the only thing behind the tick and the send gate,
    // so a refused save is an error (the UI must not show a confirmation that isn't kept)
    if ((await sessions.save(token, { ...(sealed as unknown as Record<string, unknown>), myVerifiedFp: fp } as never)) === false) {
      throw new Error('The confirmation could not be saved on this phone. Try again.');
    }
  });
}

/**
 * Batch E (round-3 review F-14): text the user typed is never a control post.
 * Text that happens to start like one ({"__veil_...) gets an invisible word
 * joiner in front, so receivers show it as text and the send-side control
 * exemptions (eviction pending, stale member key) don't apply to it.
 */
export function userText(text: string): string {
  // Batch F (R4-4-15): any text that starts like JSON (the 1:1 classifier parses
  // JSON and matches keys anywhere), not only a literal {"__veil_ prefix
  return text.trimStart().startsWith('{') ? '\u2060' + text : text;
}

/** b77p (audit VAR-28): a message that can't be sent as padded envelopes. Thrown before any ratchet step,
 *  so nothing was sent. Its message is written for people (no "size" / "too large": the app's error
 *  mapper read those as the 25 MB file limit). */
export class MessageTooLongError extends Error {
  constructor(message = 'This message is too long to send \u2014 shorten it or split it into several messages.') {
    super(message);
    this.name = 'MessageTooLongError';
  }
}

const utf8Len = (s: string): number => new TextEncoder().encode(s).length;

/** b77p (audit VAR-28): a person's text, split into chunks that each fit the largest bucket AFTER the
 *  escape (userText) is added to it. Split as before when every escaped chunk fits; otherwise split
 *  again with room for the 3-byte word joiner in every chunk. */
export function chunkUserText(text: string): string[] {
  const plain = splitForBuckets(text).map(userText);
  if (plain.every((c) => utf8Len(c) <= BUCKET_TEXT_MAX)) return plain;
  return splitForBuckets(text, utf8Len('\u2060')).map(userText);
}

/**
 * Batch E (round-3 review R1-01): the burn window used to purge local
 * plaintext. The session's own dials (signed transcript copy, else the copy
 * sealed at completion) always win; the relay row's dials are used only for a
 * legacy thread that has no local dials at all (disclosed residual). Before
 * this, closed threads purged on the row alone, so the relay could set a 1 s
 * burn and wipe history early.
 */
export function burnWindow(sealed: unknown, row?: { burn: boolean; burnSecs: number }): { burn: boolean; secs: number } {
  const d = sessionDials(sealed);
  // Batch F (R4-1-01): dials a joiner took from the relay (an older link) only
  // ever lengthen the local window, never shorten it
  if (d && (sealed as { dialsSource?: unknown } | null)?.dialsSource === 'peek') {
    return { burn: !!d.burnAfterOpen, secs: Math.max(Number(d.defaultTtlSeconds) || 0, PEEK_DIALS_BURN_FLOOR_SECONDS) };
  }
  if (d) {
    // a b74-era web-joined thread sealed its TTL but not the burn flag: the row may
    // still switch burn ON, but only at the session's own window
    const s = (sealed ?? {}) as { dials?: unknown; burnAfterOpen?: unknown };
    const flagKnown = typeof s.dials === 'string' || s.burnAfterOpen !== undefined;
    return { burn: flagKnown ? !!d.burnAfterOpen : !!row?.burn, secs: Number(d.defaultTtlSeconds) || 0 };
  }
  if (row) return { burn: !!row.burn, secs: Number(row.burnSecs) || 0 };
  return { burn: false, secs: 0 };
}

/**
 * Web sends protocol-control envelopes (session intro metadata, delivery
 * receipts) and continuous cover-traffic padding through the SAME encrypted
 * channel as real chat text — decrypt succeeds for all of them, so the app
 * layer (not the crypto layer) must keep non-chat payloads out of the UI.
 * Cover envelopes decrypt to filler content (random bytes, no real meaning);
 * control envelopes decrypt to a JSON object tagged with a __veil_* key.
 */
/** Web parity (Hp): a valid __veil_media body needs uri + k + iv; defaults
 *  match the bundle (mime application/octet-stream, name 'media', size 0,
 *  dl only when ===1). */
export function parseMediaPayload(text: string): ChatMedia | null {
  if (typeof text !== 'string' || !text.startsWith('{"__veil_media":')) return null;
  try {
    const t = JSON.parse(text) as Record<string, unknown>;
    if (t.__veil_media !== 1 || !t.uri || !t.k || !t.iv) return null;
    return {
      uri: String(t.uri),
      k: String(t.k),
      iv: String(t.iv),
      mime: t.mime ? String(t.mime) : 'application/octet-stream',
      name: t.name ? String(t.name) : 'media',
      size: Number(t.size) || 0,
      dl: t.dl === 1,
    };
  } catch { /* not valid media JSON */ }
  return null;
}

/** b199 group invite delivered inside an encrypted 1:1 chat (owner request,
 *  Oct 16 2026: add pinned contacts to groups instead of sharing links). The
 *  link inside carries the group key, so it only ever travels E2E-encrypted;
 *  the seat it points at is locked to the recipient's Veil ID on the relay. */
export interface ChatGroupInvite {
  name: string;
  link: string;
  /** the inviter's Veil ID (display only — the join itself is the proof) */
  from?: string;
}

export function buildGroupInvitePayload(inv: ChatGroupInvite): string {
  return JSON.stringify({ __veil_group_invite: 1, name: String(inv.name).slice(0, 40), link: inv.link, ...(inv.from ? { from: inv.from } : {}) });
}

export function parseGroupInvitePayload(text: string): ChatGroupInvite | null {
  if (typeof text !== 'string' || !text.startsWith('{"__veil_group_invite":')) return null;
  try {
    const t = JSON.parse(text) as Record<string, unknown>;
    const link = String(t.link ?? '');
    if (t.__veil_group_invite !== 1 || !/[?&]join=[0-9a-f]+/.test(link) || !/[?&#]w=/.test(link) || !/[?&]g=/.test(link)) return null;
    return { name: String(t.name ?? 'Group').slice(0, 40) || 'Group', link, ...(t.from ? { from: String(t.from) } : {}) };
  } catch { return null; }
}

/** b198 (cutover battery, owner decision): the media cap is 25 MB on BOTH sides —
 * the relay's disk-fill guard and this client cap are ALIGNED (the old mismatch:
 * client allowed 100 MB while the relay 413'd at 12 MB — a confusing failure the
 * battery would have caught). No soft-warn tier: the cap IS the disclosure. */
/** b76 (padding): the relay's file cap (relay/main.ts UploadPrivateFile: 25 MiB). */
export const MEDIA_RELAY_FILE_CAP = 26214400;
/** b76 (padding): a file is sent padded (cc/padding.ts padBlob, spec §8.3), and the padded
 *  ciphertext must fit the relay's cap — so the largest file is the cap less the frame header and
 *  the GCM tag (22 bytes; PADME maps 25 MiB to itself). b198–b75 allowed exactly 25 MiB of
 *  plaintext, whose ciphertext (+16) the relay then refused. */
export const MEDIA_LIMIT_BYTES = MEDIA_RELAY_FILE_CAP - BLOB_OVERHEAD_BYTES;
export const MEDIA_SOFT_WARN_BYTES = 26214400; // b198: no separate warn tier

/** Web parity (Td): fresh 32-byte AES-GCM key + 12-byte IV per file.
 *  b76 (padding): the file is framed and padded INSIDE the encryption (padBlob: magic, version,
 *  its exact length, zero padding), so the stored ciphertext (tag included) is a blob length of
 *  spec §8.3: at least BLOB_FLOOR (1 KiB), and above that the file's PADME length (at most 12 %
 *  over). The relay learns that padded length, not the exact one.
 *  b76r1 (audit I4): this used to say "1, 4, 16 or 32 KiB, PADME above" — those are the MESSAGE
 *  classes; files never used them. */
export async function encryptMedia(bytes: Uint8Array): Promise<{ ciphertext: Uint8Array; keyB64: string; ivB64: string }> {
  const key = crypto.getRandomValues(new Uint8Array(32));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const k = await crypto.subtle.importKey('raw', key as unknown as BufferSource, { name: 'AES-GCM' }, false, ['encrypt']);
  const frame = padBlob(bytes);
  try {
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv as unknown as BufferSource }, k, frame as unknown as BufferSource));
    return { ciphertext: ct, keyB64: toB64(key), ivB64: toB64(iv) };
  } finally {
    frame.fill(0); // the padded copy of the file is not left in memory
  }
}

/** Web parity (Ed): decrypt with the b64 key/iv carried in the payload.
 *  b76 (padding): then strip the padding strictly (unpadBlob) — the length inside the
 *  authenticated frame must match the frame exactly; anything else (an unpadded blob from an
 *  older build, a truncated or extended frame) is refused. */
export async function decryptMedia(bytes: Uint8Array, keyB64: string, ivB64: string): Promise<Uint8Array> {
  const k = await crypto.subtle.importKey('raw', fromB64(keyB64) as unknown as BufferSource, { name: 'AES-GCM' }, false, ['decrypt']);
  const frame = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: fromB64(ivB64) as unknown as BufferSource }, k, bytes as unknown as BufferSource));
  return unpadBlob(frame);
}

// ---------- b77m (audit VAR-07): "End this chat", said inside the chat's end-to-end encryption ----------
// A relay could end any 1:1 chat as "ended by the other side" and delete its history: the end rested on
// 410 answers alone (the P-4 rule: three over two minutes). Now the phone that ends a chat first sends an
// END control envelope through the ratchet — {"__veil_end":1}, padded like any short message, no wake —
// and only that envelope, decrypted and authenticated, makes the other phone say "ended by the other side"
// and remove the chat. 410 answers alone (the relay's word) leave the chat in place, marked unavailable,
// with its history (SyncResult.unavailable). Builds before b77m classify the envelope as chat text and
// show '{"__veil_end":1}'; b77 has not shipped, so there are none on the network (clean break).

/** the END control message's plaintext */
export const CHAT_END_PAYLOAD = '{"__veil_end":1}';
export function isChatEndPayload(text: string): boolean {
  if (typeof text !== 'string' || !text.startsWith('{"__veil_end":')) return false;
  try { const t = JSON.parse(text) as { __veil_end?: unknown } | null; return !!t && t.__veil_end === 1 && Object.keys(t).length === 1; } catch { return false; }
}

/**
 * b77u2 (UC-L3): the tail of the peer's authenticated END: outbox and burns emptied, ratchet keys dropped, the history
 * purged, then the purgePending flag cleared — only once the purge completed. Idempotent: a pass cut short (the flag
 * still set, or history left on an ended chat) runs it again. Throws when the purge fails (the flag stays).
 */
export async function finishPeerEnd(sessions: SessionStore, token: string): Promise<void> {
  const ss = sessions as Partial<Pick<SessionStore, 'setOutbox' | 'setPendingBurns' | 'dropRatchetKeys' | 'purgeChatHistory' | 'setMboxState'>>;
  await ss.setOutbox?.(token, []).catch(() => false);
  await ss.setPendingBurns?.(token, []).catch(() => undefined);
  await ss.dropRatchetKeys?.(token).catch(() => false);
  await ss.purgeChatHistory?.(token);
  if ((await ss.setMboxState?.(token, { purgePending: 0 })) === false) throw new Error('the purge mark could not be cleared');
}

/** is this chat marked unavailable (the relay reported it gone, P-4; nothing from the peer said so)? */
export async function isChatUnavailable(sessions: Pick<SessionStore, 'mboxState'>, token: string): Promise<boolean> {
  try { return !!(await sessions.mboxState(token))?.unavailable; } catch { return false; }
}

/**
 * b77n (pre-audit INFO-5): "Check again" on a chat marked unavailable on the relay's word alone (P-4, no END).
 * Clears the unavailable mark and the gone-answer counters (both directions), so the caller's next sync pass
 * (it runs one at once) asks the relay afresh; a relay that still answers 410 has to meet the P-4 rule again
 * before the chat is marked unavailable again. A chat the peer's authenticated END ended (`peerEnded`) is
 * never reopened. true = cleared; false = not unavailable, ended by the peer, or the store refused the write.
 */
export async function checkChatAgain(sessions: Pick<SessionStore, 'mboxState' | 'setMboxState'>, token: string): Promise<boolean> {
  let st: Awaited<ReturnType<SessionStore['mboxState']>>;
  try { st = await sessions.mboxState(token); } catch { return false; }
  if (!st?.unavailable || st.peerEnded) return false;
  clearGoneAnswers(chatGoneAnswers, token);
  clearGoneAnswers(chatGoneAnswers, outGoneKey(token));
  return (await sessions.setMboxState(token, { unavailable: undefined }).catch(() => false)) !== false;
}

/**
 * b77m (audit VAR-07): send the END control envelope into this chat (serialized on the chat's ratchet chain
 * like every send; the step is saved before the send). Never queued: true only when the relay took it (it is
 * in the peer's inbound), false when the peer's inbound isn't open yet, the chat has no delivery capabilities
 * or the send failed. Never throws.
 */
export function sendChatEnd(relay: VeilRelay, sessions: SessionStore, token: string): Promise<boolean> {
  sessions = pinToWipe(sessions);
  return serializeRatchetSend(token, async () => {
    try {
      const sealed = await sessions.load(token);
      if (!sealed) return false;
      const dlv = chatDelivery(sealed);
      if (!dlv) return false;
      const state = await deserializeRatchetState(sealed);
      const env = await encryptMessage(state, CHAT_END_PAYLOAD);
      await saveOrThrow(sessions, token, withExtras(await serializeRatchetState(state), sealed));
      const r = await sealedSend(relay, sessions, token, dlv, env, envelopeTtlSeconds(sealed), false, false);
      return !r.queued;
    } catch (e) {
      console.log(`[veil-end] #${token.slice(0, 4)}: the end message was not sent (${relayDetailOf(e).slice(0, 80)})`);
      return false;
    }
  }).catch(() => false);
}

function boundedWait<T>(p: Promise<T>, ms: number, fallback: T): Promise<T> {
  return new Promise((resolve) => {
    const t = setTimeout(() => resolve(fallback), ms);
    p.then((v) => { clearTimeout(t); resolve(v); }, () => { clearTimeout(t); resolve(fallback); });
  });
}

/**
 * b77m (audit VAR-07): "End this chat" for a chat with delivery capabilities — the app's replacement for
 * calling endSealedChat directly. 1) the END control envelope goes to the peer's inbound (bounded by
 * `noticeMs`); 2) my inbound is retired (read cap); 3) the peer's inbound is retired (send cap) ONLY when the
 * END envelope did not get there — a retired mailbox can't be read, so retiring it would destroy the very
 * message that proves the end; the peer's phone retires it itself once it has read the END (syncChat).
 * Without the END the peer's phone sees only 410s and marks the chat unavailable (history kept). Best effort,
 * never throws; the caller removes the local state afterwards, as before.
 */
export async function endChat(
  relay: VeilRelay, sessions: SessionStore, token: string, opts: { noticeMs?: number; timeoutMs?: number } = {},
): Promise<{ notice: boolean; inbound: boolean; outbound: boolean }> {
  const sealed = await sessions.load(token).catch(() => null);
  const d = chatDelivery(sealed);
  if (!d) return { notice: false, inbound: false, outbound: false };
  const notice = await boundedWait(sendChatEnd(relay, sessions, token), opts.noticeMs ?? 6_000, false);
  const t = opts.timeoutMs ?? 4_000;
  const inbound = await boundedWait(relay.sealedEnd(d.inbound.mbox, d.inbound.read).then(() => true), t, false);
  const outbound = notice ? false : await boundedWait(relay.sealedEnd(d.outbound.mbox, d.outbound.send).then(() => true), t, false);
  console.log(`[veil-end] #${token.slice(0, 4)}: chat ended (end message ${notice ? 'delivered' : 'not delivered — the peer\'s inbound retired instead'})`);
  return { notice, inbound, outbound };
}

function classifyDecrypted(dec: { text: string; cover: boolean }): 'chat' | 'cover' | 'intro' | 'receipt' | 'media' | 'call' | 'invite' | 'end' {
  if (dec.cover) return 'cover';
  try {
    const parsed = JSON.parse(dec.text) as Record<string, unknown>;
    if (parsed && typeof parsed === 'object') {
      if (isChatEndPayload(dec.text)) return 'end'; // b77m (audit VAR-07)
      if (parsed.__veil_intro) return 'intro';
      if (parsed.__veil_receipt) return 'receipt';
      if (parseMediaPayload(dec.text)) return 'media';
      if (parseGroupInvitePayload(dec.text)) return 'invite';
      if (parsed.__veil_call === 1) return 'call';
    }
  } catch { /* not JSON — a normal chat message */ }
  return 'chat';
}

// ---------- b77k (IP77-3, owner decision): my nickname, shown in 1:1 chats too ----------
// Sent INSIDE the chat's end-to-end encryption, as an ordinary control envelope (padded like any
// short message, no wake, burned at decrypt like a receipt): {"__veil_intro":1,"nick":"<name>"}.
// Nothing the relay can read is new — no relay field, no rendezvous / request row carries it.
// Builds before b77k classify it as an intro and drop it. Sent once per chat when the chat is
// ready, and again whenever the nickname changes ("" once, to clear a name sent earlier; a
// nickname never set sends nothing). The receiver keeps the latest in the sealed record
// (`peerNick`, saved with the state that opened it); the app shows it as the title only for a
// pinned contact (names.ts peerNickTitle; b77k2: the nickname alone), else quoted (peerNickNote).

/** the most characters of a nickname sent in a 1:1 chat (the group intro's limit) */
export const PEER_NICK_MAX = 40;

/** a nickname as sent and kept: invisible characters gone, single spaces, at most PEER_NICK_MAX */
export function cleanPeerNick(n: unknown): string {
  return typeof n === 'string' ? [...cleanName(n)].slice(0, PEER_NICK_MAX).join('').trim() : '';
}

/** the 1:1 nickname intro's plaintext */
export function buildNickIntro(nick: string): string {
  return JSON.stringify({ __veil_intro: 1, nick: cleanPeerNick(nick) });
}

/** the name a 1:1 nickname intro carries ('' = the sender cleared it), or null when it is not one */
export function parseNickIntro(text: string): string | null {
  if (typeof text !== 'string' || !text.startsWith('{"__veil_intro":')) return null;
  try {
    const t = JSON.parse(text) as { __veil_intro?: unknown; nick?: unknown } | null;
    if (!t || t.__veil_intro !== 1 || typeof t.nick !== 'string') return null;
    return cleanPeerNick(t.nick);
  } catch { return null; }
}

/** does this ready 1:1 chat need my nickname (again)? Never for a chat without delivery
 *  capabilities (pending, or sealed before b77); an empty nickname only clears one sent before */
export function nickIntroDue(sealed: unknown, nick: string | null | undefined): boolean {
  const s = sealed as { ready?: unknown; delivery?: unknown; nickSent?: unknown } | null;
  if (!s || s.ready !== true || !s.delivery) return false;
  const sent = typeof s.nickSent === 'string' ? s.nickSent : '';
  return cleanPeerNick(nick ?? '') !== sent;
}

/** the peer's own nickname this phone keeps for a 1:1 chat ('' = none) */
export function peerNickOf(sealed: unknown): string {
  return cleanPeerNick((sealed as { peerNick?: unknown } | null)?.peerNick);
}

/** b74 (VAR-07): a pairwise message's id = hex(SHA-256(utf8(header)))[0:32]. The header
 *  is signed by the sender and is the AES-GCM AAD, so it can't be swapped onto another
 *  message, and the sender computes the same value from the header it sent. */
export async function messageIdOf(header: string): Promise<string> {
  const h = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(header) as unknown as BufferSource));
  return 'm' + [...h.slice(0, 16)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

function headerString(h: unknown): string {
  if (typeof h === 'string') return h;
  if (h && typeof h === 'object') { try { return JSON.stringify(h); } catch { return ''; } }
  return '';
}

/**
 * b85 → b77 (sealed sender): the lock-screen wake is no longer a separate logged-in gate call
 * after a send (that call named the session token and the account). It is the `notify` flag on
 * the sealedSubmit itself: 'msg' for a message a person reads (text, media, a new reaction),
 * false for cover traffic, receipts and other control envelopes, 'call' for a call ring. The
 * relay coalesces wakes per mailbox, so the b183 client-side throttle is gone with the call.
 */
export type NotifyKind = false | 'msg' | 'call';

/** Pull new envelopes for a session and decrypt them. Ratchet resealed after. */
/**
 * b102 shared burn-result classifier — used by both the fresh-decrypt burn
 * call and the pending-burn retry pass so the two sites can never drift.
 * "gone-session": the VeilSession row is dead server-side — stop entirely,
 * the caller sets sessionGoneRef. "gone-envelope": only this one envelope
 * vanished (concurrent teardown) — burn's goal is already met, drop it.
 * "retry": an ordinary transient failure (network, 5xx) — queue for the
 * next sync pass.
 */
function classifyBurnError(msg: string, status = 0): 'gone-session' | 'gone-envelope' | 'rate-limited' | 'retry' {
  // b77 (sealed sender): my inbound mailbox is retired (the chat was ended)
  if (status === 410) return 'gone-session';
  if (status === 429) return 'rate-limited';
  // Batch F (round-4 review R4-4-07): the exact relay answer only, not a substring
  if (/^\s*session not found\s*$/i.test(msg)) return 'gone-session';
  if (/entity veilenvelope with id .* not found/i.test(msg)) return 'gone-envelope';
  // b175 (owner Metro repro, Oct 2: rapid-fire burst tripped the relay's
  // own anti-abuse limiter — burn/heartbeat/list all 500'd "Rate limit
  // exceeded"). Pre-fix this fell into the generic 'retry' bucket, so a
  // rate-limited pass just kept firing burn attempts for every remaining
  // queued envelope AT FULL SPEED — the opposite of backing off, and the
  // same abuse signature that caused the historical K-4 10-minute lockout.
  if (/rate limit exceeded/i.test(msg)) return 'rate-limited';
  return 'retry';
}

/** b197-r8m: mark an envelope DISPLAYED — the human actually saw it. Flips its
 *  awaiting-display burn entry so the next sync pass delivers the burn.
 *  Called from App.tsx at the live-render site (where openedAt is stamped).
 *  Undisplayed envelopes are never burned — they live to the unopened
 *  horizon (the expire dial), per the owner's two-dial lifetime spec. */
export async function markEnvelopeDisplayed(relay: VeilRelay, sessions: SessionStore, token: string, envId: string): Promise<void> {
  return markEnvelopesDisplayed(relay, sessions, token, [envId]);
}

/**
 * b198 CACHE-RENDER LOOPHOLE (live-caught, media test Oct 15): a message
 * decrypted by BACKGROUND sync while the thread was closed is cached with
 * openedAt = machine-DECRYPT time and a pendingBurn entry stuck displayed:false.
 * The old marker fired ONLY on the live-arrival render path, so cache-rendered
 * messages NEVER unlocked their relay burn: the local view countdown ran off
 * the stale decrypt-stamped clock and the bubble vanished at the dial while the
 * relay envelope (and the media blob file) lived on — the two-dial semantics
 * broke exactly for the most common case (peer sends while you're not in the
 * thread). This batch marker is called at THREAD OPEN for every cached peer
 * row: it flips the pending entries (the relay burn fires next pass, media
 * blobs ride along) and RE-ANCHORS the cached rows' openedAt to the human-open
 * moment. Idempotent: already-displayed entries are skipped and their clock is
 * never re-anchored (thread reopens don't reset a running burn).
 */
export async function markEnvelopesDisplayed(_relay: VeilRelay, sessions: SessionStore, token: string, envIds: string[]): Promise<void> {
  // b77z (BURN-1, ZTE live test): the pending-burn queue is read at the top of every sync pass
  // and written back whole at its end, so a flip this marker wrote into the queue beside a pass
  // was overwritten with displayed:false and the opened message's relay copy lived to its expiry.
  // b77z2 (Z-1 / Z-5): the marker no longer waits on the per-token chain (b77z put it there, so
  // opening a chat stalled behind any pass or send in flight, and behind a relay call that hung).
  // It appends the envelope ids to the chat's display marks (SessionStore.addDisplayedMarks:
  // local storage only, at once); a pass merges them into the queue (applyDisplayedMarks,
  // persistBurnQueue). Only when the chain is idle does it also flip the queue itself, on the
  // chain. A mark is on storage before this returns, so a pass killed mid-run can't take it with
  // it (history off included).
  const ids = envIds.filter(Boolean);
  if (!ids.length) return;
  const st = sessions as Partial<Pick<SessionStore, 'displayedMarks' | 'addDisplayedMarks'>>;
  // a store without display marks (a test double) keeps the b77z write: on the chain, awaited
  if (!st.addDisplayedMarks) {
    await serializeRatchetSend(token, async () => {
      const cover = (await sessions.pendingBurns(token)).filter((p) => p.cover && p.displayed === false).map((p) => p.id); // b77t (M-G)
      await flipQueueEntries(sessions, token, [...ids, ...cover]);
    });
    await (sessions as Partial<Pick<SessionStore, 'markShown'>>).markShown?.(token, ids);
    return;
  }
  const list = await sessions.pendingBurns(token); // read only here (the queue is the chain's to write)
  const marked = st.displayedMarks ? await st.displayedMarks(token).catch(() => new Set<string>()) : new Set<string>();
  const waiting = new Set(list.filter((p) => p.displayed === false).map((p) => p.id));
  // idempotent: an entry already displayed, or already marked, is skipped and its clock is never
  // re-anchored (thread reopens don't reset a running burn)
  // b77t (audit 5 M-G): the chat's waiting cover entries go with its displayed messages (cover is never
  // rendered, so nothing else would name them)
  const cover = list.filter((p) => p.cover && p.displayed === false).map((p) => p.id);
  const flipped = [...new Set([...ids, ...cover])].filter((id) => waiting.has(id) && !marked.has(id));
  if (flipped.length) {
    if (!(await st.addDisplayedMarks(token, flipped).catch(() => false))) {
      console.log(`[veil] burn unlock for ${flipped.length} message(s) on #${token.slice(0, 4)} not saved (storage refused) — marked again at the next open`);
    } else {
      await sessions.stampOpenedAt(token, flipped);
      console.log(`[veil] burn UNLOCKED for ${flipped.length} message(s) on #${token.slice(0, 4)} (human open) — fires next pass`);
      // when nothing is on the chain the queue is updated now too (local storage only: the job
      // runs first and never waits on the relay); with a pass or a send in flight it is not
      // waited for — that pass, or the next, takes the marks in
      if (ratchetChainIdle(token)) {
        await serializeRatchetSend(token, () => flipQueueEntries(sessions, token, flipped)).catch(() => undefined);
      }
    }
  }
  // b75r3 (audit PR3-02 / PR3-04): every row named here is on screen now — rows without a
  // burn clock get one, and messages waiting in memory (history off) are handed over
  await (sessions as Partial<Pick<SessionStore, 'markShown'>>).markShown?.(token, ids);
}

type BurnEntry = PendingBurn;
/** flip these entries' awaiting display (and take in the stored display marks). Runs on the chain. */
async function flipQueueEntries(sessions: SessionStore, token: string, ids: string[]): Promise<void> {
  const list = await sessions.pendingBurns(token);
  const want = new Set(ids);
  let changed = false;
  for (const p of list) if (p.displayed === false && want.has(p.id)) { p.displayed = true; changed = true; }
  const marks = await readDisplayedMarks(sessions, token);
  if (changed || marks.size) await persistBurnQueue(sessions, token, list);
}
type MarkStore = Partial<Pick<SessionStore, 'displayedMarks' | 'dropDisplayedMarks'>>;
async function readDisplayedMarks(sessions: SessionStore, token: string): Promise<Set<string>> {
  const st = sessions as MarkStore;
  return st.displayedMarks ? await st.displayedMarks(token).catch(() => new Set<string>()) : new Set<string>();
}
/** b77z2 (Z-1): flip the awaiting-display entries the human has seen (display marks) */
function applyDisplayedMarks(q: BurnEntry[], marks: ReadonlySet<string>): void {
  if (!marks.size) return;
  for (const p of q) if (p.displayed === false && marks.has(p.id)) p.displayed = true;
}
/** b77z (BURN-1, defence in depth): a sync pass writes its whole copy of the queue back, but that
 *  copy never takes back a display flip already in storage.
 *  b77z2 (Z-1): it also takes in every display mark on storage at the moment of the write
 *  (a mark that landed mid-pass included), and once the queue is saved it drops those marks
 *  (marks added after this read stay for the next pass). `keepMarks`: ids whose marks stay even
 *  so (a refused state save takes this pass's new entries back out; their marks wait for the
 *  pass that queues them again). */
async function persistBurnQueue(sessions: SessionStore, token: string, q: BurnEntry[], keepMarks?: ReadonlySet<string>): Promise<{ saved: boolean; full: boolean } | undefined> {
  const cur = await sessions.pendingBurns(token).catch(() => [] as BurnEntry[]);
  const shown = new Set(cur.filter((p) => p.displayed === true).map((p) => p.id));
  for (const p of q) if (p.displayed === false && shown.has(p.id)) p.displayed = true;
  const marks = await readDisplayedMarks(sessions, token);
  applyDisplayedMarks(q, marks);
  const r = await sessions.setPendingBurns(token, q);
  const st = sessions as MarkStore;
  if (r?.saved && marks.size && st.dropDisplayedMarks) {
    const applied = [...marks].filter((id) => !keepMarks?.has(id));
    await st.dropDisplayedMarks(token, applied).catch(() => undefined);
  }
  return r;
}

/** b77z2: a new queue entry for an envelope this pass opened. b198: media payloads ride their
 *  blob: uri, carried on the entry so the executed burn also deletes the ciphertext FILE from the
 *  relay's disk (the relay cannot map blobs to sessions; the uri only exists inside this E2E
 *  payload). Z-4: dated (`at`) and, when the relay said, its envelope's expiry (`exp`). */
function newBurnEntry(rec: EnvelopeRecord & { id: string }, dec: DecryptedMessage, kind: ReturnType<typeof classifyDecrypted>, pre: boolean): BurnEntry {
  const exp = rec.expires_at ? Date.parse(rec.expires_at) : NaN;
  const base: BurnEntry = { id: rec.id, attempts: 0, ...(pre ? { pre: true } : {}), at: Date.now(), ...(Number.isFinite(exp) ? { exp } : {}) };
  if (kind === 'chat' || kind === 'media' || kind === 'invite') {
    const blob = kind === 'media' ? (parseMediaPayload(dec.text)?.uri ?? undefined) : undefined;
    return { ...base, displayed: false, ...(blob ? { blob } : {}) };
  }
  // b77t (audit 5 M-G, IH C-02): cover waits for display like a chat message (it burned on fetch, which
  // told the relay which envelopes were cover)
  if (kind === 'cover') return { ...base, displayed: false, cover: true };
  return base;
}

/** b77z (BURN-1 recovery): an awaiting-display entry whose message the human has in fact seen.
 *  Installs that hit the lost update hold entries stuck at displayed:false for rows that were
 *  opened (the marker stamped openedAt, the flip was lost). openedAt is only stamped at display
 *  since b75r3 (markShown, stampOpenedAt, ensureOpenedAt), so a cached peer row with openedAt
 *  was displayed.
 *  b77z2 (Z-2): positive evidence only. The absent-row rule (a row gone from a history-keeping
 *  cache below its cap was taken as purged after display) is gone: a row is also absent when
 *  its cache write was refused or the 500-row cap evicted it, and nobody saw those. A displayed
 *  row the purge deletes now records a display mark (SessionStore.purgeBurnedMessages) instead.
 *  A row carrying `read` had openedAt stamped by a peer's receipt (Z-3) and proves nothing.
 *  Entries stuck before this build whose rows were already purged have no evidence left: they
 *  wait to their envelope's expiry. */
async function displayedEvidence(sessions: SessionStore, token: string): Promise<(id: string) => boolean> {
  try {
    const st = sessions as Partial<Pick<SessionStore, 'cachedMessages'>>;
    if (!st.cachedMessages) return () => false;
    const rows = await st.cachedMessages(token);
    const byEnv = new Map<string, ChatMessage>();
    for (const m of rows) { byEnv.set(m.id, m); if (m.envId) byEnv.set(m.envId, m); }
    return (id) => {
      const m = byEnv.get(id);
      return !!m && !m.mine && !(m as { systemNote?: boolean }).systemNote && !!m.openedAt && !m.read;
    };
  } catch { return () => false; }
}

/** b102: cap on pending-burn retry attempts per envelope before giving up
 *  and logging a visible error — protects against retrying forever against
 *  a permanently-broken relay while still surviving many transient blips
 *  (each sync pass is 1.5-3s while a thread is open, so 20 attempts is
 *  30-60s of retrying, plus it resumes across app restarts). */
const MAX_BURN_RETRY_ATTEMPTS = 20;
/** Batch E (F-1): after the fast retries a refused burn is NOT dropped — it is
 *  retried with backoff (1 min doubling to 1 h) until the relay's own sweep
 *  backstop (49 h) has certainly removed the envelope. */
// Batch F (R4-4-12): an envelope can live up to 30 days (the longest dial), not just
// the 49 h file backstop, so refused burns keep trying for that long
const BURN_BACKSTOP_MS = 30 * 24 * 3600_000;
const BURN_BACKOFF_MAX_MS = 3600_000;

export function syncChat(...args: Parameters<typeof syncChatUnlocked>): ReturnType<typeof syncChatUnlocked> {
  // b173: syncs mutate ratchet state (load -> decrypt -> save) exactly like
  // sends do — but the two ran UNSERIALIZED against each other. b147 chained
  // every ratchet-encrypting send per token, while syncChat read the sealed
  // state, spent hundreds of ms paging the relay, and saved on its own
  // schedule. A send landing mid-poll wrote its advance from the pre-sync
  // state; the poll's save then clobbered it (or vice versa). The ratchet
  // forked, the peer's next decrypt hit "counter out of range", and threads
  // "dropped in and out" as the forks alternated. Both sides of the race now
  // share the same per-token chain.
  return serializeRatchetSend(args[2] as string, () => syncChatUnlocked(...args));
}

export async function syncChatUnlocked(
  relay: VeilRelay,
  sessions: SessionStore,
  token: string,
  clientId: string,
  knownIds: ReadonlySet<string>,
  burnAfterOpen = false,
  startSkip = 0,
  /** Batch D (D-09): ignored — the burn window comes from the session's own dials, never the relay row */
  _burnSecondsHint = 0,
  /** b77t (audit 5 M-G): `onScreen` — is this chat on screen now (open, app in front, phone unlocked)? Cover
   *  entries queued by an earlier pass are then flipped like a displayed message's, and burn this pass */
  opts: { onScreen?: () => boolean; /** b77u (audit 6 RH-L2): checked after the fetch, before any decrypt: true leaves every envelope unprocessed for a later pass (the phone locked under "Hold until unlock", the account switched, a wipe) */ shouldAbort?: () => boolean } = {},
): Promise<SyncResult> {
  const passStart = Date.now(); // b77t (M-G)
  // b70 (re-review 2, D2-2): a wipe during this sync stops all its later reads and writes
  sessions = pinToWipe(sessions);
  const sealed = await sessions.load(token);
  if (!sealed) throw new Error('No ratchet state for this session on this device.');
  // b77m (audit VAR-07): a chat the relay reported gone (and this phone marked unavailable) is read-only:
  // no fetch, no send, no relay call at all — its history stays until the user deletes the chat
  // b77p (audit VAR-06): checked BEFORE the capabilities — a chat the peer ended has none left (keys dropped)
  if (await isChatUnavailable(sessions, token)) {
    const mb = await sessions.mboxState(token).catch(() => null);
    const ended = mb?.peerEnded;
    // b77u2 (UC-L3): an END pass cut short after peerEnded was written (the app killed) left its purge unfinished, and
    // every later pass returned here: it is finished now, while the flag or any history remains
    let purgedNow = false;
    if (ended && (mb?.purgePending || ((await sessions.cachedMessages(token).catch(() => [])).length > 0))) {
      try { await finishPeerEnd(sessions, token); purgedNow = true; }
      catch (e) { console.log(`[veil] sync #${token.slice(0, 4)}: the ended chat's purge failed — tried again next pass:`, String((e as Error)?.message ?? e)); }
    }
    return { messages: [], processedIds: [], readIds: [], reactions: [], state: sealed as never, nextSkip: startSkip, strayIds: [], desync: false, desyncIds: [], callSignals: [], unavailable: true, ...(ended ? { endedBy: 'peer' as const } : {}), ...(purgedNow ? { purged: true } : {}) };
  }
  // b77 (sealed sender): a 1:1 chat without delivery capabilities predates b77 — the clean break
  const dlv = requireDelivery(sealed);
  const state = await deserializeRatchetState(sealed);
  // b78: durable dedupe — the relay re-serves every envelope on every poll,
  // and a re-decrypt of a consumed envelope re-runs the PQ rekey and
  // PERMANENTLY desyncs the session ("Message counter out of range"). The
  // caller's knownIds set is a per-thread accelerator; this ledger is the
  // authoritative record (it also covers filtered control payloads the
  // message cache never sees).
  const ledger = await sessions.processedIds(token);
  // b91: strays classified on a previous pass are never re-attempted (a
  // consumed ratchet key can't be re-derived; re-attempts only re-log)
  const strayLedger = await sessions.strayIds(token);

  // WEB-PARITY RECEIVE: the web client polls the VeilEnvelope ENTITY
  // (filter({session_token}, 'created_date', 200)) — it never calls a gate
  // 'fetch' action.
  // b83 (owner repro, direct server confirmation): the legacy gate 'fetch'
  // fallback that used to live here is DEAD — veilSessionGate now rejects
  // it with HTTP 400 "Unknown action". It was only ever reached on a
  // transient entity-poll network failure (exactly the case that's common
  // around a lock/unlock or network handoff), so every one of those
  // recoverable hiccups was being turned into a SECOND, confusing, terminal
  // error ("Unknown action") that killed the whole sync pass. Removed —
  // a network failure here now just propagates once, cleanly, and the next
  // poll (1.5-3s later) retries on its own.
  // b196: newest-first pager (backfill.ts). The old
  // ascending skip cursor froze an offset that SHIFTED every time the
  // sweeper purged expired rows — the same deletion-shift class the group
  // path just fixed: a frozen offset could stride past unprocessed backlog,
  // and a partial page re-downloaded the entire remaining window on EVERY
  // pass (owner Metro log Oct 12: a 77-row thread re-fetched all 77 rows
  // every 1.5-10s, dominating per-account rate pressure). Pages anchor at
  // the NEWEST row — stable against expired-row deletion, which only ever
  // happens at the old/deep end of the sort — and depth is re-derived each
  // pass from the processed-id ledger (b78), never persisted as an offset.
  // The ledger check still runs on every fetched row before decrypt, so
  // ratchet-safety is unchanged; ordering is reversed back to oldest-first
  // so all downstream processing is untouched.
  // R1 (audit doc 13): the old fixed 3-page cap never reached a backlog
  // deeper than one pass, and the newest rows must not be decrypted ahead of
  // older ones (the ratchet keeps up to 500 skipped keys per chain, 2000 in all). The pager
  // (backfill.ts) now walks to the processed boundary or the thread's end,
  // resuming at a persisted row anchor when that takes more than one pass,
  // and the loop below stops after SYNC_BUDGET definitive outcomes so each
  // pass still does a bounded amount of decrypt work, oldest-first.
  // b77 (sealed sender): the receive channel is MY inbound mailbox only, read anonymously with
  // its read capability (sealedFetch), paged by the relay's sequence numbers from a cursor kept
  // per chat (SessionStore.mboxState.seq). No session token, no listing of the peer's
  // envelopes, no own-echo traffic (my sends go to the peer's mailbox). The b196/R1 newest-first
  // pager is gone with the entity list: a sequence cursor can't shift under expired-row deletion.
  const SYNC_PAGE = 100; // the relay's sealedFetch maximum
  const SYNC_FETCH_PAGES = 10;
  const SYNC_BUDGET = 150;
  // vestigial cursor: kept for call-site type compat, never advances now
  const nextSkip = startSkip;
  const mstore = sessions as Partial<Pick<SessionStore, 'mboxState' | 'setMboxState'>>;
  const emptyPass = (extra: Partial<SyncResult>): SyncResult => ({ messages: [], processedIds: [], readIds: [], reactions: [], state: sealed as never, nextSkip, strayIds: [], desync: false, desyncIds: [], callSignals: [], ...extra });
  // b77: a retired inbound (410) is the peer's "End this chat". One answer from the relay never
  // removes a chat (b75r2 audit P-4): it must repeat GROUP_GONE_ANSWERS times over at least
  // GROUP_GONE_SPAN_MS before the keys and history go (then: the existing "ended" path).
  // b77m (audit VAR-07): a confirmed 410 (P-4) is the RELAY's word only — the chat is marked unavailable and
  // kept (history included), never removed and never "ended by the other side" (only the peer's END does that)
  const retiredAnswer = async (): Promise<SyncResult> => {
    if (!outGone && !noteGoneAnswer(chatGoneAnswers, token)) {
      console.log(`[veil] sync #${token.slice(0, 4)}: the relay says this chat was ended (410) — kept until that repeats`);
      return emptyPass({ gonePending: true });
    }
    console.log(`[veil] sync #${token.slice(0, 4)}: the relay reports this chat no longer exists (inbound retired, confirmed) — marked unavailable, history kept`);
    await markUnavailable(outGone ? 'outbound' : 'inbound');
    return emptyPass({ unavailable: true });
  };
  /** b77m (audit VAR-07): the P-4 rule met on relay answers alone — mark the chat unavailable. The ratchet
   *  state and the history stay.
   *  b77n (pre-audit INFO-5): NOTHING is retired any more. This used to end the side the relay still held
   *  (R2-A-1: my outbound = the peer's inbound with my send cap, or both with endSealedChat), so a relay that
   *  lied (410s alone, P-4 met) made this phone end the PEER's mailbox too, permanently. Now no sealedEnd is
   *  sent: the peer's inbound and my own stay as they are, and the outbox and pending burns are kept, so
   *  "Check again" (checkChatAgain) can pick the chat up where it was. Only the peer's authenticated END
   *  (endConfirmed / peerEndedNow) or the user's own End retires mailboxes. */
  async function markUnavailable(_which: 'inbound' | 'outbound'): Promise<void> {
    clearGoneAnswers(chatGoneAnswers, token);
    clearGoneAnswers(chatGoneAnswers, outGoneKey(token));
    await mstore.setMboxState?.(token, { unavailable: Date.now() });
  }
  /** b77r2 (audit R2-A-1): a confirmed end (P-4) of either direction ends the chat here, and ends
   *  the side the relay still holds, so the peer's chat ends too instead of becoming a zombie:
   *  my inbound retired -> end my outbound (the peer's inbound) with my send cap; the peer's
   *  inbound retired (my sends got 410) -> end my inbound with my read cap (and the outbound,
   *  harmlessly). Best effort, bounded; any answer (200 / 410 / 425) is fine. */
  // b77m (audit VAR-07): only the peer's authenticated END comes here now (see the decrypt loop)
  // b77p (audit VAR-06): the END no longer removes the chat. It is ended (mailboxes retired, nothing more
  // is sent or received) and kept READ-ONLY with its whole history (peerEnded + unavailable), whatever
  // arrived with the END — a bare END used to remove every cached message, the recipient's own included,
  // on the peer's timing. The ratchet keys and capabilities are dropped (dropRatchetKeys); the user deletes
  // the chat (sessions.remove) when they choose to.
  async function endConfirmed(): Promise<void> {
    clearGoneAnswers(chatGoneAnswers, token);
    clearGoneAnswers(chatGoneAnswers, outGoneKey(token));
    // b77u2 (UC-L3): the purge is marked pending BEFORE the chat is marked ended (see finishPeerEnd)
    await mstore.setMboxState?.(token, { purgePending: Date.now() });
    try { await endSealedChat(relay, sealed, 2_000); } catch { /* best effort: never blocks the end */ }
    const at = Date.now();
    await mstore.setMboxState?.(token, { unavailable: at, peerEnded: at });
    // b77u (audit 6 U-M8, owner decision): the peer's authenticated END also deletes this phone's copy of the chat
    // (history, cached plaintext, burn queue). Only reached from a decrypted END (the ratchet authenticates it, and
    // its replay / processed-id checks stop a replayed one); never from the relay's 410s (markUnavailable).
    // b77u2 (UC-L3): a failed purge is no longer swallowed: the flag stays and the next pass finishes it
    try { await finishPeerEnd(sessions, token); }
    catch (e) { console.log(`[veil] sync #${token.slice(0, 4)}: the END's purge failed — tried again next pass:`, String((e as Error)?.message ?? e)); }
  }
  // envelopes that waited for the peer's inbound to open go out first (their steps are saved)
  // b77r1 (audit A-4): a 410 on them is the peer's end — one answer for the P-4 counter (the
  // queue is kept until the end is confirmed); a network failure waits for the next pass
  // b77r2 (audit R2-A-1): the answer is counted under the OUTBOUND key, exactly like a 410 to a
  // plain send (no outbox), and the pass goes on to fetch my own inbound — the peer's last
  // messages still arrive while the end is being confirmed. Once the outbound answers meet the
  // P-4 rule (from either path) the chat ends here.
  let flush: FlushResult = { sent: 0, delivered: [], waiting: 0, queuedIds: [] };
  try { flush = await flushOutbox(relay, sessions, token, dlv); } catch (e) {
    if (e instanceof MailboxRetiredError) noteSendGone(token);
    flush = { ...flush, waiting: ((await sessions.outbox?.(token).catch(() => [])) ?? []).length };
  }
  // b77m (audit VAR-07): my sends keep getting 410 (confirmed, P-4) — the relay's word. The pass still reads
  // my inbound first (the peer's END, if it sent one, is there and is the only proof of who ended the chat);
  // without it the chat is marked unavailable at the end of the pass, history kept
  const outGone = outboundGoneConfirmed(token);
  // b77r1 (audit A-5): what the outbox did, for every result of this pass; envelopes waiting
  // past the peer's last chance to open its inbound mean the chat can't finish setting up
  const outboxNow = (await sessions.outbox?.(token).catch(() => [])) ?? [];
  const oldestWaiting = outboxNow.length ? Number(outboxNow[0].at) || 0 : 0;
  const peerNeverOpens = oldestWaiting > 0 && Date.now() - oldestWaiting > PEER_OPEN_GIVE_UP_MS;
  const outboxInfo: Partial<SyncResult> = {
    ...(flush.delivered.length ? { delivered: flush.delivered } : {}),
    outboxWaiting: outboxNow.length,
    queuedIds: [...new Set(outboxNow.map((it) => it.localId).filter((x): x is string => !!x))],
    ...(peerNeverOpens ? { setupFailed: true } : {}),
  };
  const inbound = await ensureInboundOpen(relay, sessions, token, sealed, { ttlCapSeconds: envelopeTtlSeconds(sealed) });
  if (inbound === 'retired') return retiredAnswer();
  if (outGone && inbound !== 'open') { await markUnavailable('outbound'); return emptyPass({ unavailable: true }); } // b77m (VAR-07)
  if (inbound === 'setupFailed') return emptyPass({ ...outboxInfo, setupFailed: true });
  if (inbound === 'waiting') return emptyPass({ ...outboxInfo, inboundWaiting: true });
  const mstate = (await mstore.mboxState?.(token)) ?? { openAt: 0, opened: true, seq: 0 };
  const priorSeq = Math.max(0, Math.floor(Number(mstate.seq) || 0));
  const fetched: EnvelopeRecord[] = [];
  let after = priorSeq;
  let fetchComplete = false; // b77z2 (Z-4): the fetch reached the end of my inbound (not the page cap)
  try {
    for (let page = 0; page < SYNC_FETCH_PAGES; page++) {
      const r = await relay.sealedFetch(dlv.inbound.mbox, dlv.inbound.read, after, SYNC_PAGE);
      const items = r.items.filter((it) => it && typeof it.id === 'string' && Number.isSafeInteger(Number(it.seq)))
        .sort((a, b) => Number(a.seq) - Number(b.seq));
      for (const it of items) fetched.push({ id: it.id, ciphertext: it.ciphertext, iv: it.iv, header: it.header, expires_at: it.expires_at, seq: Number(it.seq) });
      const top = items.length ? Number(items[items.length - 1].seq) : after;
      // the cursor is the highest seq actually seen (= next_seq when the relay's next_seq names the
      // last item); never past it, so a relay counter that runs ahead can't make us skip an envelope
      if (items.length < SYNC_PAGE || top <= after) { fetchComplete = true; break; }
      after = top;
    }
  } catch (e) {
    const s = relayStatusOf(e);
    if (s === 410) return retiredAnswer();
    if (s === 425) {
      // "never opened": the open this phone thought landed did not — open again shortly
      await mstore.setMboxState?.(token, { opened: false, openAt: Date.now() + 30_000 });
      return emptyPass({ ...outboxInfo, inboundWaiting: true });
    }
    throw e;
  }
  // b77u (audit 6 RH-L2): a relay that held the fetch past a lock gets nothing decrypted, cached or notified;
  // the cursor is not moved, so the same envelopes come again on the next pass
  if (opts.shouldAbort?.()) return emptyPass({ ...outboxInfo, aborted: true });
  clearGoneAnswers(chatGoneAnswers, token); // a good fetch clears any earlier "ended" answers
  if (!mstate.everOpened) await mstore.setMboxState?.(token, { everOpened: true }); // b77r1 (A-5)
  const recs = fetched.filter((r) => !!r.id && !ledger.has(r.id!) && !strayLedger.has(r.id!) && !knownIds.has(r.id!)); // oldest-first, unprocessed only
  const maxSeq = fetched.reduce((m, r) => Math.max(m, Number(r.seq) || 0), priorSeq);
  // burn dial lives WITH the sealed ratchet (stored at completion/accept from
  // the session record); the param stays as a legacy fallback
  const burn = (sealed as { burnAfterOpen?: boolean }).burnAfterOpen ?? burnAfterOpen;
  console.log(`[veil] sync #${token.slice(0, 4)}: fetched ${recs.length} envelope(s)${burn ? ' (burn-after-open on)' : ''} (inbound mailbox, after seq ${priorSeq})`);

  const messages: ChatMessage[] = [];
  const callSignals: CallSignal[] = [];
  const processedIds: string[] = [];
  const readIds: string[] = [];
  const reactions: { target: string; emoji: string | null }[] = [];
  let ownSkipped = 0;
  let filtered = 0;
  const sessionGoneRef = { gone: false };
  // b91 (web stray-classifier parity): every decrypt failure is recorded
  // with its header diagnostics + timestamp; after the pass, a failure that
  // a SUCCESSFUL decrypt of a NEWER envelope in the SAME session follows is
  // a stray (stale envelope the ratchet moved past) → soft notice. Key-
  // mismatch failures (header rp is not the expected remote ratchet key =
  // epoch divergence), timestamp-less failures, and failures with no later
  // success (stacking) never downgrade → genuine desync, end-session prompt.
  const failRecs: { id: string; key: string; ts: string | null; rpMismatch: boolean; order: number }[] = [];
  let orderCounter = 0;
  let lastSuccessOrder = -1;
  let missingFromPeer = 0; // b70 (L-1)

  // b102 PENDING-BURN RETRY (owner Metro repro Sept 21: "burn failed for
  // <id>: Network request failed" — that envelope was already added to the
  // processed-ledger by the time burn ran, so it was NEVER retried and sat
  // at its full original expiry instead of burning on open). Runs BEFORE the
  // main loop, every pass, so a queued retry doesn't wait on new traffic —
  // an idle thread with only pending burns still drains them every poll.
  // b175: once the relay rate-limits ANY burn this pass, every further
  // burn attempt (retry queue AND the main loop below) stops immediately —
  // queued instead of fired. Hammering 20 more 500s in the same pass is
  // the exact anti-abuse signature that risked the K-4-era 10-minute lock.
  const rateLimitedRef = { hit: false };
  // b77z3 (Y-1): the relay timeout bounds one call, not the pass. Once a burn or blob delete
  // times out, the relay is not called again this pass (as rateLimitedRef): the rest stay queued
  // (phase 3: owe()). Without it a relay that stopped answering cost every queued burn its own
  // 30 s, holding the chat's chain (and the sends waiting on it) for N x 30 s.
  const relayTimedOutRef = { hit: false };
  const isRelayTimeout = (e: unknown) => e instanceof RelayTimeoutError || (e as Error | null)?.name === 'RelayTimeoutError';
  let burnStuck = 0;
  let pendingBurn = burn ? await sessions.pendingBurns(token) : [];
  // b77z2 (Z-1): the display marks on storage (the marker writes them at once, outside the chain)
  if (pendingBurn.length) applyDisplayedMarks(pendingBurn, await readDisplayedMarks(sessions, token));
  if (pendingBurn.length && burn && !burnFlags.callsDisabled) {
    // b197-r8i (K-22 fix): burns pending → AMBIENT TRAFFIC YIELDS. Heartbeats
    // (7s) and cover sends were eating the per-account limiter budget while
    // the privacy-critical deletes starved, exhausted their 20-attempt
    // budget, and stayed on the relay. Hold ambient for this pass + a
    // grace window so the burn queue gets the budget first.
    // b77z2 (Z-4): only when an entry is actually burnable now (held at the first burn or blob
    // delete this loop fires). An entry waiting for display, for its ledger write (pre), for its
    // backoff or for its media window used to hold ambient on every pass — a wedged one held
    // cover and heartbeat traffic off for good.
    let ambientHeld = false;
    const holdAmbient = () => { if (!ambientHeld) { ambientHeld = true; relay.holdAmbientFor(10000); } };
    const fetchedById = new Map<string, EnvelopeRecord>();
    for (const r of fetched) if (r.id) fetchedById.set(r.id, r);
    const survivors: BurnEntry[] = [];
    // b77z (BURN-1 recovery): read the cache only when some entry still waits for display
    const seen = pendingBurn.some((p) => p.displayed === false) ? await displayedEvidence(sessions, token) : () => false;
    for (const p of pendingBurn) {
      // Batch E (F-1): a late retry waits for its backoff
      const late = p as { retryAt?: number };
      if (late.retryAt && Date.now() < late.retryAt) { burnStuck++; survivors.push(p); continue; }
      // b77z (BURN-2): queued by a pass ahead of its state save + ledger write. Not ledgered yet:
      // that pass died (or its save was refused) before the envelope was settled, so the next
      // pass decrypts it again (and settles the entry). Burning it now could lose the message.
      const nowMs = Date.now();
      if (!p.at) p.at = nowMs; // b77z2 (Z-4): an entry queued before b77z2 is dated from now
      if (p.pre) {
        if (!ledger.has(p.id) && !strayLedger.has(p.id)) {
          // b77z2 (Z-4): ...unless no pass will ever settle it. The relay serves the envelope
          // past its expiry (the client skips it), or no longer has it at all: drop the entry
          // (the relay's copy expires on its own; nothing here can open it again)
          const rec = fetchedById.get(p.id);
          const relayExp = rec?.expires_at ? Date.parse(rec.expires_at) : NaN;
          const horizon = Number.isFinite(relayExp) ? relayExp : (p.exp ?? p.at + BURN_BACKSTOP_MS);
          if (nowMs > horizon || (!rec && fetchComplete)) {
            console.log(`[veil] burn entry ${p.id.slice(0, 8)}… on #${token.slice(0, 4)} dropped: never settled, and its envelope ${rec ? 'has expired' : 'is no longer on the relay'}`);
            continue;
          }
          survivors.push(p); continue;
        }
        delete p.pre; // settled (the pass died between its ledger write and its queue write)
      }
      // b197-r8m: AWAITING-DISPLAY entries are NOT burned — the human hasn't
      // seen them yet. They wait (the unopened horizon bounds the relay copy);
      // App.tsx flips displayed=true at live render, and the NEXT pass burns.
      // b77t (audit 5 M-G): a cover entry from an earlier pass, its chat on screen: displayed, as a real
      // message on screen would have been after that pass rendered it
      if (p.displayed === false && p.cover && (p.at ?? nowMs) < passStart) {
        let on = false;
        try { on = !!opts.onScreen?.(); } catch { on = false; }
        if (on) p.displayed = true;
      }
      if (p.displayed === false) {
        if (!seen(p.id)) {
          // b77z2 (Z-4): past its envelope's expiry the relay copy is gone: nothing left to burn
          if (nowMs > (p.exp ?? p.at + BURN_BACKSTOP_MS)) {
            console.log(`[veil] burn entry ${p.id.slice(0, 8)}… on #${token.slice(0, 4)} dropped: never displayed, its envelope has expired`);
            continue;
          }
          survivors.push(p); continue;
        }
        // b77z (BURN-1 recovery): the message was displayed, its flip was lost (see displayedEvidence)
        console.log(`[veil] burn recovered for ${p.id.slice(0, 8)}… on #${token.slice(0, 4)}: displayed (its unlock was lost) — burning now`);
        p.displayed = true;
      }
      // b198 (live-caught): MEDIA BLOB DELETION IS SCHEDULED AT WINDOW END —
      // deleting at burn-unlock made the media unplayable the moment it was
      // opened (a replay inside the burn window hit a deleted file → 404 →
      // "couldn't load media"). The blob must live exactly as long as the
      // dial says the message does.
      const blobUri = (p as { blob?: string }).blob;
      const blobDeleteAt = (p as { blobDeleteAt?: number }).blobDeleteAt ?? 0;
      if (blobUri && blobDeleteAt) {
        if (Date.now() < blobDeleteAt || relayTimedOutRef.hit) { survivors.push(p); continue; } // b77z3 (Y-1)
        try {
          holdAmbient();
          await relay.sealedFile(dlv.inbound.mbox, dlv.inbound.read, blobUri, 'delete'); // b77: my inbound's file, by its read cap
          console.log('[veil] media blob deleted from relay storage (burn window elapsed)');
          continue; // blob handled — entry complete
        } catch (e) {
          if (isRelayTimeout(e)) relayTimedOutRef.hit = true; // b77z3 (Y-1)
          console.log(`[veil] media blob delete deferred: ${(e as Error).message ?? e}`);
          survivors.push(p); continue;
        }
      }
      // session died, relay said slow down, or (b77z3, Y-1) a relay call timed out this pass — keep queued
      if (sessionGoneRef.gone || rateLimitedRef.hit || relayTimedOutRef.hit) { survivors.push(p); continue; }
      try {
        holdAmbient();
        await relay.sealedBurn(dlv.inbound.mbox, dlv.inbound.read, [p.id]); // b77 (sealed sender)
        console.log(`[veil] burn retry OK for ${p.id} (after ${p.attempts + 1} attempt(s))`);
        // b198 MEDIA DELETION: media payloads carry the blob: uri INSIDE the
        // E2E body — this device decrypted it, so it holds the deletion
        // capability. SCHEDULE the file deletion at window end (open + the
        // burn dial) so the media stays playable for the whole window; the
        // 49h relay sweep is only the never-opened backstop.
        if (p.blob) {
          // b199 (ZTE device run, A3): the file lives exactly as long as the
          // bubble. The bubble reads the chat's dial (sealed, else the relay
          // row the caller passes); this used to fall back to a hard 300 s, so
          // a 60-min chat lost its photo after 5 min while the bubble stayed.
          // Batch D (D-09): the session's own dial (signed transcript, else sealed) — no relay-row fallback
          const burnSeconds = sessionDials(sealed)?.defaultTtlSeconds || 7200;
          survivors.push({ id: p.id, attempts: p.attempts, blob: p.blob, blobDeleteAt: Date.now() + burnSeconds * 1000 });
          console.log(`[veil] media blob deletion scheduled at window end (+${burnSeconds}s)`);
        }
      } catch (e) {
        const msg = relayDetailOf(e); // b77m (audit VAR-20): the relay's words, for classification only
        const outcome = classifyBurnError(msg, relayStatusOf(e));
        if (isRelayTimeout(e)) {
          // b77z3 (Y-1): counted as an ordinary retry below; no further relay call this pass
          console.log(`[veil] burn retry timed out for ${p.id} — pausing the rest of this pass's burns`);
          relayTimedOutRef.hit = true;
        }
        if (outcome === 'gone-session') {
          console.log(`[veil] burn retry: session gone server-side while retrying ${p.id} — cleaning up`);
          sessionGoneRef.gone = true;
          survivors.push(p); // session teardown elsewhere handles this thread's full cleanup
        } else if (outcome === 'gone-envelope') {
          console.log(`[veil] burn retry: ${p.id} already gone — goal met, dropping from queue`);
        } else if (outcome === 'rate-limited') {
          console.log(`[veil] burn retry rate-limited for ${p.id} — pausing ALL burns this pass, caller should back off polling`);
          rateLimitedRef.hit = true;
          survivors.push(p); // don't burn the retry-attempt budget on a server-side throttle
        } else {
          const attempts = p.attempts + 1;
          const now = Date.now();
          const failingSince = (p as { failingSince?: number }).failingSince ?? now;
          if (now - failingSince > BURN_BACKSTOP_MS) {
            // the relay's sweep has removed the envelope by now (or the relay keeps copies, which no client can stop)
            console.log(`[veil] burn retry ended for ${p.id}: past the relay's expiry backstop`);
          } else if (attempts >= MAX_BURN_RETRY_ATTEMPTS) {
            // Batch E (Superagent round 3, F-1): never give up silently — back off and keep trying
            const retryAt = now + Math.min(60_000 * 2 ** Math.min(attempts - MAX_BURN_RETRY_ATTEMPTS, 6), BURN_BACKOFF_MAX_MS);
            console.log(`[veil] burn still refused for ${p.id} (attempt ${attempts}): ${msg} — retrying later`);
            burnStuck++;
            survivors.push({ id: p.id, attempts, blob: (p as { blob?: string }).blob, failingSince, retryAt });
          } else {
            console.log(`[veil] burn retry still failing for ${p.id} (attempt ${attempts}/${MAX_BURN_RETRY_ATTEMPTS}): ${msg}`);
            survivors.push({ id: p.id, attempts, blob: (p as { blob?: string }).blob, failingSince });
          }
        }
      }
    }
    pendingBurn = survivors;
  }

  // b75 (audit RT-3): PHASE 1 only decrypts. Nothing is acted on here — no call signal,
  // receipt, reaction or message is handed out, nothing is burned on the relay and nothing
  // is cached — until the advanced ratchet is saved and the ids are ledgered (phase 2).
  // (b74 acted inside this loop and saved afterwards: a refused save re-delivered the same
  // call offer on the next pass, cached plaintext whose keys stayed derivable from storage,
  // and burned relay copies of messages the stored state could still re-open.)
  const opened: { rec: EnvelopeRecord & { id: string }; header: string; rp: string; n: number; dec: DecryptedMessage; kind: ReturnType<typeof classifyDecrypted> }[] = [];
  for (const rec of recs) {
    if (sessionGoneRef.gone) break;
    // R1: per-pass budget counts definitive outcomes only, so rows that stay
    // retryable can't starve the newer ones behind them
    if (processedIds.length >= SYNC_BUDGET) break;
    if (!rec.id) continue;
    if (knownIds.has(rec.id) || ledger.has(rec.id) || strayLedger.has(rec.id)) continue;
    // web parity (Zu caller): expired envelopes are skipped client-side
    if (rec.expires_at && new Date(rec.expires_at).getTime() < Date.now()) continue;
    const header = headerString(rec.header);
    // Own-envelope filter (web rule Qu). b77 (veil-ratchet-8): the header is encrypted, so
    // it is OPENED (crypto-core peekHeader): an envelope one of my own header keys opens is my
    // echo. rp / n (logs, the PR3-03 failure key) come from the opened header too; an
    // unopenable header gives none (decryptMessage then types it, usually as junk).
    const peek = header ? await peekHeader(state, header) : null;
    const rp = peek?.rp ?? '';
    if (peek?.own) {
      ownSkipped++;
      // b174 (owner Metro repro, Oct 2: growing fetch counts every poll, then UI freeze):
      // own echoed envelopes are ledgered at once, so they are never re-fetched and
      // re-checked on every poll for the life of their TTL.
      // b198 (OWNER SPEC OVERRULES r8m): own echoes must NOT burn the shared relay copy.
      // That single envelope row IS the recipient's delivery; the copy dies only by the
      // two-dial contract (unopened -> expire horizon; opened -> the recipient's burn).
      processedIds.push(rec.id);
      if (burn && !burnFlags.callsDisabled && !sessionGoneRef.gone) {
        console.log(`[veil] own echo ${rec.id.slice(0, 8)}… ledgered, NOT burned — b198 two-dial: the RECIPIENT's open owns the burn clock`);
      }
      continue;
    }
    try {
      const dec = await decryptMessage(state, {
        ciphertext: String(rec.ciphertext ?? ''),
        iv: String(rec.iv ?? ''),
        header, // byte-for-byte AAD — untouched
      }, rec.id);
      // null: an id the stored state already processed (its ledger write was lost) — ledger it
      processedIds.push(rec.id);
      if (dec) {
        lastSuccessOrder = ++orderCounter; // b91: successful decrypt — earlier failures may be strays
        // b70 (audit L-1): a jump in the peer's sequence = messages not delivered;
        // a late one (at or below the mark) fills a gap counted earlier this pass
        if (dec.meta && !dec.cover && dec.meta.seq > 0 && dec.prevSeqMax !== undefined) {
          if (dec.meta.seq > dec.prevSeqMax + 1) missingFromPeer += dec.meta.seq - dec.prevSeqMax - 1;
          else if (dec.meta.seq <= dec.prevSeqMax && missingFromPeer > 0) missingFromPeer -= 1;
        }
        const n = peek?.n ?? -1;
        opened.push({ rec: rec as EnvelopeRecord & { id: string }, header, rp, n, dec, kind: classifyDecrypted(dec) });
      }
    } catch (e) {
      const name = (e as Error)?.name;
      // b74 (VAR-15): an authenticated copy of a message already processed (a relay
      // replay) is dropped and ledgered — never counted towards "session out of sync".
      // b75 (audit RT-2, audit 2 V5): so is an authentic old copy whose key is used or gone
      // (however its header JSON was re-spaced, and however far past the replay window),
      // and so is junk that does not authenticate against this session at all (anyone on
      // the path, the relay included, can make that). Ledgered so it is not re-tried.
      if (e instanceof ReplayedMessageError || name === 'ReplayedMessageError') {
        console.log(`[veil] envelope ${rec.id}: a copy of a message already received — dropped`);
        processedIds.push(rec.id);
        continue;
      }
      if (e instanceof StaleMessageError || name === 'StaleMessageError') {
        console.log(`[veil] envelope ${rec.id}: an old copy (its key was already used or has expired) — dropped`);
        processedIds.push(rec.id);
        continue;
      }
      // b77p (audit VAR-04): and so is a genuine header with a tampered body (TamperedBodyError, a kind of
      // junk) — the header signature doesn't cover the body, so the relay can make it; never "out of sync"
      if (e instanceof JunkEnvelopeError || name === 'JunkEnvelopeError' || name === 'TamperedBodyError') {
        console.log(`[veil] envelope ${rec.id}: does not authenticate against this chat (${(e as Error).message}) — dropped as junk`);
        processedIds.push(rec.id);
        continue;
      }
      // NO silent catches — log the failure WITH reason
      console.error(`[veil] envelope ${rec.id}: decrypt FAILED — ${(e as Error).message ?? e}; header rp=${rp || '(unparsed)'} expected remote=${(state.remoteRatchetPub ?? '?').slice(0, 16)}...; state n=${state.recvCount} (skipped-key cache holds out-of-order counters, nothing is dropped)`);
      // b91: diagnostics for the stray-vs-desync classification below
      const rpMismatch = !!rp && !!state.remoteRatchetPub && rp !== state.remoteRatchetPub;
      // b75r3 (audit PR3-03): the failure is keyed on what the PEER signed — the ratchet key and
      // counter in the header (one message key each) — not on the relay's envelope id, so one
      // withheld envelope re-served under new ids counts once however often it comes back
      const hn = peek?.n ?? -1; // b77: from the opened header; unopenable -> keyed by id
      // b77r1 (audit C-2): an out-of-sync header classed by its session tag alone has no rp / n;
      // it is keyed by the epoch the tag names, never by the relay's id (re-serving one envelope
      // under new ids would otherwise build the "out of sync" streak)
      // b77r2 (audit R2-C-1): `oos#<e>` alone hid every GENUINE desync — a peer this phone can't
      // follow keeps sending under the same epoch, so every new message had the same key and the
      // streak never passed 1. The key now also names the header string (a short SHA-256 of it):
      // the tag is AES-GCM over the header with hnonce||hct as AAD, so the relay can replay a
      // header but not change it — a replay under new ids is still one key, a new message a new one
      const oosEpoch = (e as { epoch?: unknown } | null)?.epoch;
      const key = rp && Number.isSafeInteger(hn) && hn >= 0 ? `${rp}#${hn}`
        : name === 'OutOfSyncError' && Number.isSafeInteger(oosEpoch) ? `oos#${oosEpoch as number}#${(await messageIdOf(headerString(rec.header))).slice(1, 17)}`
        : `id:${rec.id}`;
      // b77: a mailbox envelope has no relay timestamp; its sequence number orders it instead
      failRecs.push({ id: rec.id, key, ts: rec.created_date ?? (rec.seq !== undefined ? `seq:${rec.seq}` : null), rpMismatch, order: ++orderCounter });
    }
  }
  // b91: classify the pass's failures. Stray = timestamped, key-matching, and
  // superseded by a later successful decrypt in this same pass. Everything
  // else is a decrypt failure on an AUTHENTICATED header (b75, audit RT-2: junk, old copies
  // and replays never get here) — counted towards "out of sync".
  // b77m (audit VAR-07): the peer's END control message, decrypted under this chat's ratchet — the only thing
  // that ends a chat here as "ended by the other side".
  // b77m review (L9): messages the peer sent BEFORE its END that arrive in the same pass are no longer dropped
  // unseen with it: the pass goes on for them (cached, state saved, handed out), whatever came after the END
  // is ledgered and ignored, and the chat is then ended but KEPT read-only (peerEnded + unavailable), so they
  // can be read. b77p (audit VAR-06): an END with nothing readable before it is kept read-only the same way
  // (history kept, keys dropped) — it no longer removes the chat.
  const endAt = opened.findIndex((o) => o.kind === 'end');
  if (endAt >= 0) {
    // b77u (audit 6 U-M8, owner decision): the END purges this phone's copy — messages that came with it in this
    // pass are not delivered either (the sender ended the chat to have them gone); nothing is cached or shown
    console.log(`[veil] sync #${token.slice(0, 4)}: chat ended by the other side (end message received) — its messages were removed from this phone, keys dropped`);
    await endConfirmed();
    return emptyPass({ unavailable: true, endedBy: 'peer', purged: true });
  }
  const strayIds = failRecs
    .filter((f) => !f.rpMismatch && f.ts !== null && f.order < lastSuccessOrder)
    .map((f) => f.id);
  const desyncIds = failRecs.filter((f) => !strayIds.includes(f.id)).map((f) => f.id);
  // b75r3 (audit PR3-03): distinct signed headers, for the App's "out of sync" streak
  const desyncKeys = [...new Set(failRecs.filter((f) => !strayIds.includes(f.id)).map((f) => f.key))];
  const desync = desyncIds.length > 0;
  if (ownSkipped) console.log(`[veil] sync #${token.slice(0, 4)}: skipped ${ownSkipped} own envelope(s) (opened with my own header keys)`);

  // b75 (audit RT-3): PHASE 2 — the ratchet is saved and the ids ledgered BEFORE anything
  // is acted on. Batch H (round-6 review R6-1-06): the ids are marked only once the state
  // landed. A refused save now hands out nothing: no messages, call signals, receipts or
  // reactions, no cache, no burns. The stored state still holds the keys, so the next pass
  // decrypts the same envelopes again and delivers them then (exactly once).
  // b75r2 (audit P-6): what a person will read is built and CACHED before that state is
  // saved. The order was save -> ledger -> hand out -> cache, so a crash after the save lost
  // the messages for good: their keys were spent and the next pass ledgered the envelopes as
  // already processed. Now: cache -> save -> ledger -> hand out. A crash after the cache write
  // leaves the state unadvanced (the next pass opens the same envelopes again; the cache keeps
  // one copy per id); a crash after the save leaves the messages in the cache, shown when the
  // chat opens. A refused save takes the early copies back out (RT-3: no plaintext is left
  // cached beside a stored state that can still open it). With history off or Nothing-at-Rest
  // the cache writes nothing by design, so there a crash in this window still loses the pass.
  const readable = new Map<string, ChatMessage>();
  const shownMaxAgeMs = envelopeTtlSeconds(sealed) * 1000 + PEER_OPEN_GIVE_UP_MS + SHOWN_TIME_SKEW_MS; // b77m (audit VAR-55)
  for (const { rec, header, dec, kind } of opened) {
    if (kind !== 'chat' && kind !== 'media' && kind !== 'invite') continue;
    // b75r3 (audit PR3-02): no openedAt here. Decrypting is not displaying: a background pass
    // opens messages while their chat is closed, and stamping the burn clock at decrypt let the
    // closed-thread purge delete them (and burn the relay copy) before anyone saw them. The
    // clock starts when the App displays the row (markEnvelopesDisplayed -> markShown) or when
    // the chat is opened (ensureOpenedAt).
    // b77m (audit VAR-54/55): rcvAt = this phone's receive time; the shown time is the sender's only inside
    // [rcvAt - (envelope lifetime + outbox wait), rcvAt]
    const rcvAt = Date.now();
    const base = { id: rec.id, mid: await messageIdOf(header), mine: false, rcvAt, ts: shownTime(dec, rec.created_date, { rcvAt, maxAgeMs: shownMaxAgeMs }) };
    readable.set(rec.id, kind === 'chat' ? { ...base, text: dec.text }
      : kind === 'media' ? { ...base, text: '', media: parseMediaPayload(dec.text) ?? undefined }
      : { ...base, text: '', groupInvite: parseGroupInvitePayload(dec.text) ?? undefined });
  }
  // b77z (BURN-2, ZTE live test): every burn this pass owes is queued and persisted BEFORE the
  // state save and the ledger write. Phase 3 used to queue or fire them only after both, so a
  // process death in between left a consumed envelope with no burn and no queue entry (the next
  // pass filters it as processed) and its relay copy lived to expiry. New entries carry `pre`
  // until the ledger write lands (the retry loop leaves them alone until then); phase 3 removes
  // the ones it burns, a refused save takes them back out.
  // b77z2: the queue write now comes BEFORE the early cache write, so no row of this pass can be on
  // screen (openChat reads the cache) before its awaiting-display entry is on storage: the
  // display marker only marks entries it finds there. A death between the two leaves a `pre`
  // entry for an envelope the next pass opens again (and re-uses the entry).
  const preQueued = new Set<string>();
  if (burn && !burnFlags.callsDisabled && opened.length) {
    const have = new Set(pendingBurn.map((p) => p.id));
    for (const { rec, dec, kind } of opened) {
      if (have.has(rec.id)) continue; // already owed (a pass that died after queueing it)
      have.add(rec.id);
      preQueued.add(rec.id);
      pendingBurn.push(newBurnEntry(rec, dec, kind, true));
    }
    if (preQueued.size) await persistBurnQueue(sessions, token, pendingBurn);
  }
  const early = [...readable.values()];
  const cachedEarly = early.length ? (await sessions.cacheMessages(token, early).catch(() => false)) !== false : false;
  // b77q owner (1 Nov), as the group path (J2-1): the store REFUSED the early copies (cacheMessages answers true for a
  // history-off / Nothing-at-Rest policy, false only for a real refusal). The state used to be saved anyway, so the
  // messages' keys were spent with no copy kept: lost. Now the pass is held like a refused state save — the state is
  // not saved, nothing is ledgered, acked or burned, and the next pass opens the same envelopes again; the App shows
  // the storage note (stateNotSaved).
  const cacheRefused = early.length > 0 && !cachedEarly;
  // b77k (IP77-3): the peer's nickname (its last intro this pass), saved with the state that opened it
  let peerNick: string | undefined;
  for (const { dec, kind } of opened) {
    if (kind !== 'intro') continue;
    const n = parseNickIntro(dec.text);
    if (n !== null) peerNick = n;
  }
  if (peerNick !== undefined && peerNick === peerNickOf(sealed)) peerNick = undefined; // unchanged
  const next0 = withExtras(await serializeRatchetState(state), sealed) as Record<string, unknown>;
  const next = (peerNick !== undefined ? { ...next0, peerNick } : next0) as never;
  let stateSaved = !cacheRefused; // b77q owner (1 Nov): a refused cache write holds the pass (never saved)
  if (processedIds.length && !cacheRefused) {
    stateSaved = (await sessions.save(token, next).catch(() => false)) !== false;
  }
  if (!stateSaved) {
    console.log(`[veil] sync #${token.slice(0, 4)}: ${cacheRefused ? 'the messages could not be kept' : 'the chat state was not saved'} (storage refused) — nothing from this pass is shown or acted on; it is retried next pass`);
    if (cachedEarly) await (sessions as Partial<Pick<SessionStore, 'uncacheMessages'>>).uncacheMessages?.(token, early.map((m) => m.id)).catch(() => undefined);
    let burnQueueTroubleNs = false;
    if (burn) {
      // only the retry queue from the top of this pass (b77z: the entries queued ahead of the
      // save are taken back out — the next pass opens the same envelopes again)
      const bq = await persistBurnQueue(sessions, token, pendingBurn.filter((p) => !preQueued.has(p.id)), preQueued);
      burnQueueTroubleNs = !!bq && (!bq.saved || bq.full);
    }
    return { messages: [], processedIds: [], readIds: [], reactions: [], state: next, nextSkip, strayIds: [], desync: false, desyncIds: [], callSignals: [], rateLimited: rateLimitedRef.hit, stateNotSaved: true, ...(burnStuck ? { burnStuck } : {}), ...(burnQueueTroubleNs ? { burnQueueTrouble: true } : {}) };
  }
  if (processedIds.length && stateSaved) await sessions.markProcessedIds(token, processedIds);
  // b77z (BURN-2): ledgered — this pass's entries are settled (persisted with the queue below)
  // (and so is an entry a pass that died before its ledger write left behind for this one)
  if (processedIds.length && pendingBurn.some((p) => p.pre)) {
    const ledgeredNow = new Set(processedIds);
    for (const p of pendingBurn) if (p.pre && ledgeredNow.has(p.id)) delete p.pre;
  }
  if (strayIds.length) await sessions.markStrayIds(token, strayIds);
  // b77: advance the mailbox cursor past everything this pass settled — but never past an
  // envelope still open to a later pass (an authenticated failure not ledgered, or one the
  // per-pass budget did not reach), so the relay serves it again
  {
    const done = new Set([...processedIds, ...strayIds]);
    const nowMs = Date.now();
    const open = recs.filter((r) => r.id && !done.has(r.id) && !(r.expires_at && new Date(r.expires_at).getTime() < nowMs));
    const firstOpen = open.reduce((m, r) => Math.min(m, Number(r.seq) || Infinity), Infinity);
    const cursor = Number.isFinite(firstOpen) ? Math.max(priorSeq, Math.min(maxSeq, firstOpen - 1)) : maxSeq;
    if (cursor !== priorSeq) await mstore.setMboxState?.(token, { seq: cursor });
  }
  // b70 (re-review P1): record the gap whether or not the chat is open
  if (missingFromPeer > 0) await sessions.bumpPendingMissing(token, missingFromPeer).catch(() => undefined);

  // PHASE 3 — act on what was opened (the state above is already on disk)
  // b77z2 (Z-6): a burn this pass owes that the early queue write did not cover (the kill switch
  // was on then and is off now) is queued here, settled (the state is saved and the id ledgered)
  const owe = (rec: EnvelopeRecord & { id: string }, dec: DecryptedMessage, kind: ReturnType<typeof classifyDecrypted>) => {
    if (!pendingBurn.some((p) => p.id === rec.id)) pendingBurn.push(newBurnEntry(rec, dec, kind, false));
  };
  for (const { rec, header, rp, n, dec, kind } of opened) {
    if (kind === 'chat') {
      console.log(`[veil] envelope ${rec.id}: decrypt OK (n=${n}, rp=${rp.slice(0, 16)}...)`);
      messages.push(readable.get(rec.id)!); // b75r2 (P-6): built and cached before the save
    } else if (kind === 'media') {
      // web parity: media messages render text:'' + the parsed descriptor
      console.log(`[veil] envelope ${rec.id}: decrypt OK (n=${n}) — media message (${parseMediaPayload(dec.text)?.mime ?? '?'})`);
      messages.push(readable.get(rec.id)!); // b75r2 (P-6)
    } else if (kind === 'invite') {
      // b199: group invitation — rendered as a Join / Decline card
      console.log(`[veil] envelope ${rec.id}: decrypt OK (n=${n}) — group invite`);
      messages.push(readable.get(rec.id)!); // b75r2 (P-6)
    } else if (kind === 'receipt') {
      // web Wp parser: {"__veil_receipt":1,ids:[...],read:true|false}
      try {
        const r = JSON.parse(dec.text) as { __veil_receipt?: number; ids?: unknown; read?: boolean; react?: { t?: unknown; e?: unknown } };
        if (r.__veil_receipt === 1 && Array.isArray(r.ids) && r.read === true) {
          for (const id of r.ids) if (typeof id === 'string') readIds.push(id);
        }
        // b199 reactions ride a receipt envelope with no ids, so builds
        // that predate them treat it as an empty receipt (never as text)
        if (r.__veil_receipt === 1 && r.react && typeof r.react.t === 'string' && r.react.t) {
          const e = r.react.e;
          if (e === null || (typeof e === 'string' && (REACTION_EMOJI as readonly string[]).includes(e))) {
            reactions.push({ target: r.react.t, emoji: e as string | null });
          }
        }
      } catch { /* malformed receipt: not fatal, already processed */ }
      filtered++;
      console.log(`[veil] envelope ${rec.id}: decrypt OK (n=${n}) — receipt payload (${readIds.length} read id(s) so far this pass)`);
    } else if (kind === 'call') {
      // b143: call signaling (offer/answer/ice/end) rides this channel
      // (design S3, L1). Filtered from the chat list like receipts, but
      // surfaced to the caller so the call UI can ring/connect.
      const sig = parseCallSignal(dec.text);
      // b71: the call layer gets the ratchet frame's authenticated send time
      if (sig) callSignals.push(dec.meta?.sentAt ? { ...sig, sentAt: dec.meta.sentAt } : sig);
      filtered++;
      console.log(`[veil] envelope ${rec.id}: decrypt OK (n=${n}) — call signal (op=${sig?.op ?? '?'}), not shown in chat`);
    } else {
      filtered++;
      console.log(`[veil] envelope ${rec.id}: decrypt OK (n=${n}) — ${kind} payload, not shown in chat`);
    }
    if (!burn || sessionGoneRef.gone) continue;
    // b197-r8m (BURN-ON-HUMAN-OPEN, the owner's two-dial spec): PEER
    // envelopes NO LONGER burn at machine-decrypt — background sync
    // decrypts within minutes of sending, which made the fuse start
    // before any human saw anything (K-22/K-24 finding). Instead the envelope is
    // queued as AWAITING-DISPLAY: it burns only when the human actually
    // sees it (App.tsx stamps openedAt at live display and calls
    // markEnvelopeDisplayed). Undisplayed envelopes live to the
    // unopened horizon (the expire dial) — per the owner's two-dial spec.
    if (!burnFlags.callsDisabled && (kind === 'chat' || kind === 'media' || kind === 'invite' || kind === 'cover' /* b77t (M-G) */)) {
      // (b77z, BURN-2: queued with its media blob uri ahead of the state save, above)
      // b77z2 (Z-6): unless the kill switch was on then and is off now — queued here instead
      owe(rec, dec, kind);
      if (rec === opened[opened.length - 1].rec) console.log(`[veil] burn queued AWAITING-DISPLAY for #${token.slice(0, 4)} (${rec.id.slice(0, 8)}…)`);
      continue;
    }
    // CONTROL payloads (receipt/call/cover/intro): machine-consumed, never rendered to a
    // human — burned at decrypt (b75: once the state that consumed them is saved).
    // b82 emergency gate (kill switch) and b175: once the relay rate-limits any burn this
    // pass, the rest are queued, not fired.
    // b77z3 (Y-1): and once a relay call timed out this pass
    if (burn && (burnFlags.callsDisabled || rateLimitedRef.hit || relayTimedOutRef.hit)) {
      // (b77z: queued ahead of the save, above — and left queued; with the kill switch on nothing was)
      if (!burnFlags.callsDisabled) owe(rec, dec, kind); // b77z2 (Z-6)
      if (rec === opened[opened.length - 1].rec) console.log(`[veil] burn-after-open SKIPPED for #${token.slice(0, 4)} (b82/rate-limit/timeout: queued state visible in Metro)`);
      continue;
    }
    // b77z (BURN-2): the entry queued ahead of the save goes once the burn landed
    try { await relay.sealedBurn(dlv.inbound.mbox, dlv.inbound.read, [rec.id]); pendingBurn = pendingBurn.filter((p) => p.id !== rec.id); } // b77 (sealed sender)
    catch (e) {
      const msg = relayDetailOf(e); // b77m (audit VAR-20)
      const outcome = classifyBurnError(msg, relayStatusOf(e));
      // b82: a gone-session refusal is an expected, handled condition (logged, not an error)
      if (outcome === 'gone-session') { console.log(`[veil] burn refused for ${rec.id} — session gone server-side, cleaning up`); sessionGoneRef.gone = true; owe(rec, dec, kind); }
      else if (outcome === 'rate-limited') { console.log(`[veil] burn rate-limited for ${rec.id} — pausing ALL burns this pass, caller should back off polling`); rateLimitedRef.hit = true; owe(rec, dec, kind); }
      // b88: the envelope being gone already satisfies the burn's goal
      // b77z3 (Y-1): a timeout stops the rest of this pass's burns (they are owed, above)
      else if (isRelayTimeout(e)) { relayTimedOutRef.hit = true; owe(rec, dec, kind); console.log(`[veil] burn timed out for ${rec.id}, queued — pausing the rest of this pass's burns`); }
      else if (outcome === 'gone-envelope') { pendingBurn = pendingBurn.filter((p) => p.id !== rec.id); console.log(`[veil] burn skipped for ${rec.id} — envelope already gone (${msg})`); }
      // b102: rec.id is already ledgered, so a dropped connection here stays queued (b77z: since
      // phase 2) for the retry pass at the top of the next call instead of leaving the copy at
      // full expiry (a gone-session refusal, above, stays queued the same way)
      else { owe(rec, dec, kind); console.log(`[veil] burn failed for ${rec.id}, queued for retry: ${msg}`); }
    }
  }
  if (filtered) console.log(`[veil] sync #${token.slice(0, 4)}: filtered ${filtered} non-chat envelope(s) (cover/intro/receipt)`);
  // Batch F (round-4 review R4-1-02): a burn or fetch answer alone doesn't wipe a
  // chat. Ask the relay about THIS session (the same check as the open-chat
  // path); only a definite "Session not found" removes keys and history.
  // b75r2 (audit P-4): and not on one answer either — the session check must say "gone" on
  // repeated passes spread over minutes (the group rule, G-10) before anything is removed.
  // b77 (sealed sender): the "session check" is the inbound's own 410 (a burn refused with 410
  // here); there is no session row to ask any more. The same repeat rule applies.
  // b77r3 (audit R3-6): a burn 410 is counted as ONE answer and never ends the chat here. Every
  // burn runs after this pass's good fetch, which cleared the count (clearGoneAnswers above), so
  // the count can be at most 1 at this point and the P-4 rule (3 answers over 2 min) can't be
  // met — the old "confirmed" branch (b80 cleanup + endConfirmed) was dead code. The end is
  // confirmed on the fetch path (retiredAnswer), where a retired inbound answers 410 on every
  // later pass; the answer counted here just joins those (until a good fetch clears it).
  // The pass goes on and saves its state as usual.
  if (sessionGoneRef.gone) {
    noteGoneAnswer(chatGoneAnswers, token);
    console.log(`[veil] sync #${token.slice(0, 4)}: a relay answer said the chat ended — not removed until that repeats`);
    sessionGoneRef.gone = false;
  }
  // b102: persist the pending-burn queue every pass — new failures queued
  // this pass, retries resolved this pass (removed), and attempt counts for
  // ones still failing. Runs even when unchanged (cheap) so a queue that
  // drains to empty is reliably cleared from storage.
  // Batch H (R5-1-09): a refused write or a full queue is reported
  let burnQueueTrouble = false;
  if (burn) {
    const bq = await persistBurnQueue(sessions, token, pendingBurn); // b77z: never re-locks a display flip
    burnQueueTrouble = !!bq && (!bq.saved || bq.full);
  }
  // (b75r2, P-6: the readable messages were cached before the state save, above)
  if (strayIds.length) {
    console.log(`[veil] sync #${token.slice(0, 4)}: ${strayIds.length} stray envelope(s) failed to decrypt but newer messages arrived fine — classified as strays, not a desync`);
  }
  if (desync) {
    console.error(`[veil] sync #${token.slice(0, 4)}: ${desyncIds.length} authenticated envelope(s) failed to decrypt with no newer message opening — counted towards "out of sync"`);
  }
  // b77m (audit VAR-07): my sends were confirmed refused (P-4) and no END arrived — the relay's word only
  if (outGone) {
    console.log(`[veil] sync #${token.slice(0, 4)}: the relay reports this chat no longer exists (my sends keep getting 410, confirmed) — marked unavailable, history kept`);
    await markUnavailable('outbound');
  }
  return { ...outboxInfo, ...(outGone ? { unavailable: true } : {}), messages, processedIds, readIds, reactions, state: next, nextSkip, strayIds, desync, desyncIds, desyncKeys, authOpened: opened.length, callSignals, rateLimited: rateLimitedRef.hit, ...(missingFromPeer > 0 ? { missingFromPeer } : {}), ...(burnStuck ? { burnStuck } : {}), ...(burnQueueTrouble ? { burnQueueTrouble: true } : {}), ...(peerNick !== undefined ? { peerNick } : {}) /* b77k (IP77-3) */ };
}

/**
 * b91 (builder receipt-expiry parity): ONE per-session TTL for EVERY envelope
 * submission — messages, media, cover, receipts — derived from the session's
 * expire dial (expire_after_seconds, default 24h), exactly like the web's
 * send path. The old hardcoded ttl 3600 let a relay observer single out
 * receipts (and native-origin messages) by expiry alone, contradicting the
 * uniform-envelope claim and the UI's "expire N hours after sending" text.
 */
export function envelopeTtlSeconds(sealed: object): number {
  // Batch D (D-09): the signed transcript dials first (see sessionDials)
  const d = sessionDials(sealed);
  const raw = (d ?? sealed ?? {}) as { expireAfterSeconds?: number };
  // b92 F-S7 (settings sweep): EXPLICIT Off (0) is a chosen dial, not a
  // missing one — web Kh semantics give it the relay's 36 h hard cap, not a
  // silent 24 h expiry that contradicts the "Off" choice. A MISSING/invalid
  // value keeps the defensive 24 h default.
  if (raw.expireAfterSeconds === 0) return 129600; // Off → 36 h relay hard cap (web parity)
  const dial = Number(raw.expireAfterSeconds);
  return Number.isFinite(dial) && dial > 0 ? Math.floor(dial) : 86400;
}

/** Encrypt + submit. Returns the locally-echoed message + advanced ratchet.
 *  b77m review (L1): `text` is what a PERSON wrote. It is never sent as a control message: every chunk that
 *  would parse as one (anything starting with "{", the classifier parses JSON) goes out behind userText()'s
 *  word joiner, here at the source — a caller that forgot userText(), or a long message whose later chunk
 *  happened to start with {"__veil_end":1}, used to end the peer's chat (and wipe its history) or pass as an
 *  intro / receipt / media / invite / call / capture notice. App-made control payloads go through
 *  sendChatControl. */
export function sendChatMessage(relay: VeilRelay, sessions: SessionStore, token: string, clientId: string, text: string, ttlSeconds?: number): Promise<ChatMessage> {
  // b147: ratchet writes serialize per token — a concurrent burst must not
  // encrypt the same step twice (see send-queue.ts).
  return serializeRatchetSend(token, () => sendChatMessageUnlocked(relay, sessions, token, clientId, text, ttlSeconds, false));
}

/** b77m review (L1): the app-level control payloads a chat message may carry on purpose — a group invite card
 *  and a screenshot / recording notice (both shown by the receiving app). Anything else is refused: the
 *  protocol's own controls (END, intro, receipts, media, calls, cover) have their own senders. */
export function isAppControlPayload(text: string): boolean {
  return !!parseGroupInvitePayload(text) || parseCapturePayload(text) !== null;
}
/** b77m review (L1): send an app-made control payload (isAppControlPayload) as it is */
export function sendChatControl(relay: VeilRelay, sessions: SessionStore, token: string, clientId: string, payload: string, ttlSeconds?: number): Promise<ChatMessage> {
  if (!isAppControlPayload(payload)) return Promise.reject(new Error('Not a control message this app sends.'));
  return serializeRatchetSend(token, () => sendChatMessageUnlocked(relay, sessions, token, clientId, payload, ttlSeconds, true));
}

async function sendChatMessageUnlocked(
  relay: VeilRelay,
  sessions: SessionStore,
  token: string,
  clientId: string,
  text: string,
  ttlSeconds: number | undefined,
  control: boolean,
): Promise<ChatMessage> {
  sessions = pinToWipe(sessions); // b70 (re-review 6): a wipe while this waits on the relay stops its later writes
  const sealed = await sessions.load(token);
  if (!sealed) throw new Error('No ratchet state for this session on this device.');
  const dlv = requireDelivery(sealed); // b77: a chat sealed before b77 has ended (clean break)
  const state = await deserializeRatchetState(sealed);
  // b91: per-session expire dial (web parity — the live bundle sends with the
  // session's expire_after_seconds, NOT a hardcoded 1h; see envelopeTtlSeconds)
  const ttl = ttlSeconds ?? envelopeTtlSeconds(sealed);

  // b197 (audit M-4): messages larger than the largest padded bucket used to
  // hard-fail with "Message too long for the padded bucket sizes". Split at
  // UTF-8-safe code-point boundaries and send as sequential envelopes — each
  // chunk is its own ratchet step; the relay's per-session FIFO + receiver
  // counters preserve order. The LOCAL echo stays one bubble with the full
  // text; the peer renders each chunk as its own message (documented).
  // b77m review (L1): a person's text is escaped chunk by chunk (each chunk is its own message on the peer)
  // b77p (audit VAR-28): the escape (3 bytes) used to be added AFTER a chunk was sized to the maximum, so
  // a later chunk starting with `{` outgrew the largest bucket and threw mid-send, after earlier chunks
  // had gone out (and the error read like the 25 MB file limit). Now: when any escaped chunk would not fit,
  // the text is split again with room for the escape; and every chunk is checked BEFORE the first ratchet
  // step, so a message is sent whole or not at all (MessageTooLongError, no step taken).
  const chunks = control ? splitForBuckets(text) : chunkUserText(text);
  if (control && chunks.length !== 1) throw new MessageTooLongError('Control message too long.');
  if (chunks.some((c) => utf8Len(c) > BUCKET_TEXT_MAX)) throw new MessageTooLongError();
  // b77r1 (audit A-5): a full outbox refuses the send before any ratchet step (nothing dropped)
  await ensureOutboxRoom(relay, sessions, token, dlv, chunks.length);
  const id = `local_${Date.now()}_${Math.floor(secureRandomUnit() * 1e6)}`; // b77t (L-28): local only, CSPRNG anyway
  let lastEnvId = '';
  let lastMid = '';
  let queued = false;
  for (let i = 0; i < chunks.length; i++) {
    const env = await encryptMessage(state, chunks[i], { counted: !parseCallSignal(chunks[i]) }); // b70 (re-review P7)
    // Batch H (round-6 review R6-1-06): persist BEFORE send. A refused save stops
    // here, so a step can never be sent twice; a send that then fails leaves a
    // one-step gap, which the peer's skipped-key window absorbs.
    await saveOrThrow(sessions, token, withExtras(await serializeRatchetState(state), sealed));
    // b77 (sealed sender): to the peer's inbound with the send cap — nothing else. The wake is
    // the notify flag ('msg': a person reads this); a 425 queues the (already saved) envelope.
    const r = await sealedSend(relay, sessions, token, dlv, env, ttl, 'msg', true);
    if (r.queued) { queued = true; await tagQueued(sessions, token, id); } // b77r1 (A-5)
    // (saved per chunk, before each chunk went out — Batch H)
    lastEnvId = r.id ?? '';
    lastMid = await messageIdOf(env.header); // b74 (VAR-07): the peer's receipt names this
  }
  // b77p (audit VAR-03): an own bubble's burn clock runs from its send time (ts), receipts or not —
  // see SessionStore.purgeCacheUnlocked (b198 waited for the peer's read receipt, which never comes
  // with receipts off, so the sent plaintext stayed). openedAt is still stamped by a receipt or display.
  // b199: a sent group invite renders as the same card on my side (never raw JSON)
  // b77m review (L1): only a control send renders as a card; a person's text is echoed as sent (escaped)
  const sentInvite = control ? parseGroupInvitePayload(text) : null;
  const msg: ChatMessage = sentInvite
    ? { id, text: '', mine: true, ts: new Date().toISOString(), envId: lastEnvId, mid: lastMid, groupInvite: sentInvite, ...(queued ? { queued: true } : {}) }
    : { id, text: control ? text : userText(text), mine: true, ts: new Date().toISOString(), envId: lastEnvId, mid: lastMid, ...(queued ? { queued: true } : {}) };
  await sessions.cacheMessages(token, [msg]);
  // (b85 → b77: the lock-screen wake rode the submit itself — notify 'msg')
  return msg;
}

/**
 * Send a COVER-TRAFFIC envelope — web parity (live bundle: 15% of poll cycles
 * while a session is open submit a ratchet-encrypted filler message, to blur
 * active chatting with idle polling). This is blurring, not hiding: b71 (audit)
 * the filler's size now follows real messages (usually the 1024-byte bucket,
 * sometimes the 4096 one), but only real messages ask the relay to send a
 * push (notifySent), so a relay that watches those calls can still tell. The
 * filler is random hex of a random length, marked cover:true inside the encrypted
 * plaintext; receivers decrypt it normally and their app layer filters it
 * out (classifyDecrypted -> 'cover'). It advances the ratchet exactly like
 * the web's cover sends do, so both sides stay in lockstep.
 */
export function sendCoverEnvelope(...args: Parameters<typeof sendCoverEnvelopeUnlocked>): ReturnType<typeof sendCoverEnvelopeUnlocked> {
  // b147: ratchet writes serialize per token — a concurrent burst must not
  // encrypt the same step twice (see send-queue.ts).
  return serializeRatchetSend(args[2] as string, () => sendCoverEnvelopeUnlocked(...args));
}

/** b77t (audit 5 M-G, IH C-02): the open chat's poll tick with CSPRNG jitter, uniform in [base/2, 3·base/2)
 *  (it was a fixed 1500 / 3000 ms, and cover went out right after a poll: a relay-visible cadence) */
export function jitteredPollMs(baseMs: number): number {
  return Math.round(baseMs * (0.5 + secureRandomUnit()));
}
/** b77t (M-G): a cover envelope the poll rolled waits a CSPRNG-random 0..COVER_DELAY_MAX_MS before it is sent,
 *  so it never follows a fetch at a fixed offset */
export const COVER_DELAY_MAX_MS = 3000;
export function coverSendDelayMs(): number {
  return Math.floor(secureRandomUnit() * COVER_DELAY_MAX_MS);
}

async function sendCoverEnvelopeUnlocked(
  relay: VeilRelay,
  sessions: SessionStore,
  token: string,
  clientId: string,
  ttlSeconds?: number,
): Promise<boolean> {
  sessions = pinToWipe(sessions); // b70 (re-review 6): a wipe while this waits on the relay stops its later writes
  const sealed = await sessions.load(token);
  if (!sealed) return false;
  const dlv = chatDelivery(sealed);
  if (!dlv) return false; // b77: a chat sealed before b77 sends nothing (it has ended)
  const state = await deserializeRatchetState(sealed);
  const ttl = ttlSeconds ?? envelopeTtlSeconds(sealed); // b91: same dial as messages — cover must be indistinguishable by expiry
  // b71 (audit): random length, so the padded size looks like a real message's —
  // ~85% fit the 1024-byte bucket (as short texts do), the rest the 4096 one.
  // b76 (padding): the same filler as group cover (cc/padding.ts coverFillerText)
  const filler = coverFillerText();
  const env = await encryptMessage(state, filler, { cover: true });
  // Batch H (round-6 review R6-1-06): persist BEFORE send. A refused save stops
  // here, so a step can never be sent twice; a send that then fails leaves a
  // one-step gap, which the peer's skipped-key window absorbs.
  await saveOrThrow(sessions, token, withExtras(await serializeRatchetState(state), sealed));
  // b77 (sealed sender): never a wake (notify false), never queued — a cover envelope the peer's
  // inbound can't take yet is simply dropped (its step is a gap the peer's skip window absorbs)
  try {
    await sealedSend(relay, sessions, token, dlv, env, ttl, false, false);
  } catch (e) {
    if (e instanceof MailboxNotOpenError) return false;
    throw e;
  }
  return true;
}

/**
 * Send a READ RECEIPT — the web bundle's Wp/Up contract byte-exact:
 *   body = {"__veil_receipt":1,ids:[...max 20],read:true|false}
 * ratchet-encrypted like any other message (covers + forward secrecy apply).
 * Web batches up to 20 ids per receipt; ids are the peer's message envelope
 * ids the user has now seen. read reflects the LOCAL read-receipts dial —
 * receipts flow for delivery state even with receipts off (web parity:
 * c ? {__veil_receipt:1,ids:r,read:true} : {__veil_receipt:1,ids:r}).
 */
/**
 * b199 REACTION (owner request, Oct 17): set or clear MY reaction on one
 * message, ratchet-encrypted like everything else. Shape:
 *   {"__veil_receipt":1,"ids":[],"react":{"t":<envelope id>,"e":<emoji|null>}}
 * Riding the receipt shape is deliberate: older builds parse it as an empty
 * receipt and drop it, instead of showing the JSON as a chat message. The
 * relay sees one more ordinary encrypted envelope, as with any receipt.
 */
export function sendReaction(
  relay: VeilRelay, sessions: SessionStore, token: string, clientId: string, target: string, emoji: string | null,
): Promise<void> {
  if (emoji !== null && !(REACTION_EMOJI as readonly string[]).includes(emoji)) return Promise.reject(new Error('Unsupported reaction'));
  sessions = pinToWipe(sessions); // b70 (re-review 6)
  return serializeRatchetSend(token, async () => {
    const sealed = await sessions.load(token);
    if (!sealed) throw new Error('No ratchet state for this session on this device.');
    const dlv = requireDelivery(sealed); // b77
    await ensureOutboxRoom(relay, sessions, token, dlv); // b77r1 (A-5)
    const state = await deserializeRatchetState(sealed);
    const env = await encryptMessage(state, JSON.stringify({ __veil_receipt: 1, ids: [], react: { t: target, e: emoji } }));
    // Batch H (round-6 review R6-1-06): persist BEFORE send. A refused save stops
    // here, so a step can never be sent twice; a send that then fails leaves a
    // one-step gap, which the peer's skipped-key window absorbs.
    await saveOrThrow(sessions, token, withExtras(await serializeRatchetState(state), sealed));
    // b199 (owner, Oct 17 device run): a new reaction alerts the peer like a
    // message does (same content-free push); clearing one stays silent.
    // b77: that is the submit's notify flag now
    await sealedSend(relay, sessions, token, dlv, env, envelopeTtlSeconds(sealed), emoji !== null ? 'msg' : false, true);
  });
}

/**
 * b77k (IP77-3): send my nickname into a ready 1:1 chat when it is due (nickIntroDue: never sent,
 * or changed since). A control envelope like a receipt: no wake, queued on 425. `nickSent` is
 * saved with the ratchet step BEFORE the send (Batch H); a send that then fails puts the old
 * value back, so the next pass tries again. Resolves true when an intro went out.
 */
export function sendNicknameIntro(relay: VeilRelay, sessions: SessionStore, token: string, nick: string): Promise<boolean> {
  sessions = pinToWipe(sessions); // a wipe while this waits on the relay stops its later writes
  return serializeRatchetSend(token, async () => {
    const sealed = await sessions.load(token);
    if (!sealed || !nickIntroDue(sealed, nick)) return false;
    const want = cleanPeerNick(nick);
    const dlv = requireDelivery(sealed);
    await ensureOutboxRoom(relay, sessions, token, dlv);
    const state = await deserializeRatchetState(sealed);
    const env = await encryptMessage(state, buildNickIntro(want));
    const rec = sealed as unknown as Record<string, unknown>;
    const before = rec.nickSent;
    rec.nickSent = want; // kept by withExtras: saved with the step
    await saveOrThrow(sessions, token, withExtras(await serializeRatchetState(state), sealed));
    try {
      await sealedSend(relay, sessions, token, dlv, env, envelopeTtlSeconds(sealed), false, true);
    } catch (e) {
      // the step stays spent (the peer's skipped-key window absorbs it); the intro is due again
      if (before === undefined) delete rec.nickSent; else rec.nickSent = before;
      await sessions.save(token, withExtras(await serializeRatchetState(state), sealed)).catch(() => false);
      throw e;
    }
    return true;
  });
}

export function sendReadReceipt(...args: Parameters<typeof sendReadReceiptUnlocked>): ReturnType<typeof sendReadReceiptUnlocked> {
  // b147: ratchet writes serialize per token — a concurrent burst must not
  // encrypt the same step twice (see send-queue.ts).
  return serializeRatchetSend(args[2] as string, () => sendReadReceiptUnlocked(...args));
}

async function sendReadReceiptUnlocked(
  relay: VeilRelay,
  sessions: SessionStore,
  token: string,
  clientId: string,
  ids: string[],
  read: boolean,
  ttlSeconds?: number,
): Promise<void> {
  sessions = pinToWipe(sessions); // b70 (re-review 6): a wipe while this waits on the relay stops its later writes
  if (!ids.length) return;
  const sealed = await sessions.load(token);
  if (!sealed) throw new Error('No ratchet state for this session on this device.');
  const dlv = requireDelivery(sealed); // b77
  await ensureOutboxRoom(relay, sessions, token, dlv, Math.ceil(ids.length / 20)); // b77r1 (A-5)
  const state = await deserializeRatchetState(sealed);

  const ttl = ttlSeconds ?? envelopeTtlSeconds(sealed); // b91: receipts ride the SAME per-session expiry as messages/cover — no 1h receipt fingerprint
  // b177 (owner report, Oct 2 live Metro: 2 messages sent ~9 min earlier
  // never ticked read, no sign of catching up): this function used to
  // bare `ids.slice(0, 20)` into ONE envelope and silently drop anything
  // past index 20 — but the caller (App.tsx's read-receipt sweep, both
  // native and web) marks the ENTIRE requested `ids` batch as sent in its
  // own bookkeeping the moment this call resolves, regardless of how many
  // ids were actually transmitted. Once a sweep pass accumulates a backlog
  // over 20 un-receipted peer messages (easy right after a rate-limited
  // burst, since receipt-sending itself gets backed off along with
  // everything else), the overflow ids were marked "done" locally and
  // NEVER retried — no error, no log, permanently stuck. Fix: this call
  // now delivers every id in `ids`, looping in chunks of 20 (one envelope,
  // one ratchet step, per chunk) so the caller's "I called this, therefore
  // it's receipted" assumption is actually true.
  for (let i = 0; i < ids.length; i += 20) {
    const chunk = ids.slice(i, i + 20);
    const body = JSON.stringify({ __veil_receipt: 1, ids: chunk, ...(read ? { read: true } : {}) });
    const env = await encryptMessage(state, body);
    // Batch H (round-6 review R6-1-06): persist BEFORE send. A refused save stops
    // here, so a step can never be sent twice; a send that then fails leaves a
    // one-step gap, which the peer's skipped-key window absorbs.
    await saveOrThrow(sessions, token, withExtras(await serializeRatchetState(state), sealed));
    // b77 (sealed sender): no wake for a receipt (notify false); queued on 425 like a message
    await sealedSend(relay, sessions, token, dlv, env, ttl, false, true);

    // b177: the ratchet advance is persisted per chunk (since Batch H, before
    // each chunk goes out), so a LATER failing chunk never leaves the ones that
    // landed out of step with local state.
  }
}

/**
 * Send an encrypted media message — the web bundle's image flow, byte-exact:
 *   1. fresh AES-256-GCM key + 12-byte IV encrypt the file bytes (Td)
 *   2. ciphertext uploads as 'veil-media' via the private-blob endpoint
 *   3. body = {"__veil_media":1,uri,k,iv,name,mime,size,dl?} — ratchet-
 *      encrypted exactly like text (cd), so forward secrecy + covers apply
 *   4. b76r1 (audit AUD-I3): the envelope no longer carries media_uri in clear. The web bundle added it
 *      for media bodies; the relay never stored or used it (blob ownership and cleanup go by the upload's
 *      chat binding and the 49 h sweep), but it told the relay which file each envelope pointed at
 *      (spec §12.9 says the relay can't map envelopes to files). The file id travels only inside the body.
 * The blob key rides INSIDE the end-to-end body — the relay never sees it.
 * localUri is the sender-side preview source; never transmitted.
 */
export function sendMediaMessage(...args: Parameters<typeof sendMediaMessageUnlocked>): ReturnType<typeof sendMediaMessageUnlocked> {
  // b147: ratchet writes serialize per token — a concurrent burst must not
  // encrypt the same step twice (see send-queue.ts).
  return serializeRatchetSend(args[2] as string, () => sendMediaMessageUnlocked(...args));
}

async function sendMediaMessageUnlocked(
  relay: VeilRelay,
  sessions: SessionStore,
  token: string,
  clientId: string,
  media: { bytes: Uint8Array; name?: string; mime?: string; size?: number; dl?: boolean },
  localUri?: string,
  ttlSeconds: number | undefined = undefined,
  /**
   * Optional ciphertext upload adapter (React Native shell): the app writes
   * the ciphertext to a temp file and uploads it as a file:// FormData part —
   * the guaranteed RN networking path. Default: in-memory Blob upload.
   */
  uploadCiphertext?: (ciphertext: Uint8Array, target: { mbox: string; sendCap: string }) => Promise<string>,
): Promise<ChatMessage> {
  sessions = pinToWipe(sessions); // b70 (re-review 6): a wipe while this waits on the relay stops its later writes
  const size = media.size ?? media.bytes.byteLength;
  if (size > MEDIA_LIMIT_BYTES) throw new Error('Media is limited to 25 MB per message.');
  const sealed = await sessions.load(token);
  if (!sealed) throw new Error('No ratchet state for this session on this device.');
  const dlv = requireDelivery(sealed); // b77
  await ensureOutboxRoom(relay, sessions, token, dlv); // b77r1 (A-5)
  const state = await deserializeRatchetState(sealed);
  // b91: per-session expire dial — media rides the same expiry as every
  // other envelope (see envelopeTtlSeconds)
  const ttl = ttlSeconds ?? envelopeTtlSeconds(sealed);

  const { ciphertext, keyB64, ivB64 } = await encryptMedia(media.bytes);
  // b77 (sealed sender): the blob goes to the peer's inbound with the send cap (sealedUpload) —
  // no owner, no account, no session token on the blob row
  const target = { mbox: dlv.outbound.mbox, sendCap: dlv.outbound.send };
  let fileUri: string;
  try {
    fileUri = uploadCiphertext
      ? await uploadCiphertext(ciphertext, target)
      : await relay.sealedUpload({ bytes: ciphertext, name: 'veil-media', ...target });
  } catch (e) {
    if (relayStatusOf(e) === 425) throw new MailboxNotOpenError();
    throw e;
  }

  const f: Record<string, unknown> = {
    name: media.name || 'media',
    mime: media.mime || 'application/octet-stream',
    size,
  };
  if (media.dl) f.dl = 1;
  const body = JSON.stringify({ __veil_media: 1, uri: fileUri, k: keyB64, iv: ivB64, ...f });

  const env = await encryptMessage(state, body, { counted: true }); // b70 (re-review P7)
  // Batch H (round-6 review R6-1-06): persist BEFORE send. A refused save stops
  // here, so a step can never be sent twice; a send that then fails leaves a
  // one-step gap, which the peer's skipped-key window absorbs.
  await saveOrThrow(sessions, token, withExtras(await serializeRatchetState(state), sealed));
  const id = `local_${Date.now()}_${Math.floor(secureRandomUnit() * 1e6)}`; // b77t (L-28): local only, CSPRNG anyway
  // Batch H (round-5 review R4-4-32, dropped in Batch G): a rejected media send is not "sent"
  // b77 (sealed sender): notify 'msg'; a 425 queues the envelope (the blob is already up)
  const r = await sealedSend(relay, sessions, token, dlv, env, ttl, 'msg', true);
  if (r.queued) await tagQueued(sessions, token, id); // b77r1 (A-5)
  // b198 two-dial: own media bubbles have no burn clock until the peer's receipt
  const msg: ChatMessage = {
    id, text: '', mine: true, ts: new Date().toISOString(), envId: r.id, mid: await messageIdOf(env.header),
    media: { uri: fileUri, k: keyB64, iv: ivB64, mime: String(f.mime), name: String(f.name), size, dl: !!media.dl, localUri },
    ...(r.queued ? { queued: true } : {}),
  };
  await sessions.cacheMessages(token, [msg]);
  // (b85 → b77: the wake rode the submit — notify 'msg')
  return msg;
}

/**
 * Receive side: fetch + decrypt a media blob — the web loader contract
 * (vaultFileSignedUrl → fetch → Ed decrypt), with the web's 5-attempt
 * retry (signed URLs can lag the upload by a moment). Returns the
 * DECRYPTED bytes — callers keep them in memory (web parity: blob URLs,
 * never plaintext on disk).
 */
/** b77t (audit 5 L-18, IH V-11): what identifies one media blob (the same uri with another key is another load) */
export function mediaBlobKey(media: Pick<ChatMedia, 'uri' | 'k' | 'iv'>): string {
  return `${media.uri}|${media.k}|${media.iv}`;
}
/** b77t (L-18): at most this many media downloads + decrypts run at once (the rest wait their turn) */
export const MEDIA_LOAD_CONCURRENCY = 2;
let mediaLoadsRunning = 0;
const mediaLoadQueue: (() => void)[] = [];
async function withMediaSlot<T>(fn: () => Promise<T>): Promise<T> {
  if (mediaLoadsRunning >= MEDIA_LOAD_CONCURRENCY) await new Promise<void>((r) => mediaLoadQueue.push(r));
  else mediaLoadsRunning++;
  try { return await fn(); } finally {
    const next = mediaLoadQueue.shift();
    if (next) next(); else mediaLoadsRunning--;
  }
}
/** b77t (L-18): loads in flight by chat, blob and direction. A contact that points many messages at ONE blob
 *  gets one download and one decrypt, shared by every message (the IH PoC: N downloads, N plaintext copies). */
const mediaLoadsInFlight = new Map<string, Promise<Uint8Array>>();

export async function loadMediaFile(
  relay: VeilRelay,
  sessions: SessionStore,
  token: string,
  media: ChatMedia,
  /** b77: true for a file this phone sent, false for one it received (unknown: both are tried) */
  mine?: boolean,
  /** b77u (audit 6 U-M9 / IH W7): `token` is a GROUP seat. Its file is signed by the relay for a seat credential of
   *  the group (vaultFileSignedUrl with the seat token + write secret); a group seat has no 1:1 mailboxes, so the 1:1
   *  path threw LegacySessionError and received group media never loaded. */
  opts: { group?: boolean } = {},
): Promise<Uint8Array> {
  if (!media.uri || !media.k || !media.iv) throw new Error('Media message has no retrievable blob (key missing).');
  const key = `${token}|${opts.group ? 'g' : mine === true ? 'o' : mine === false ? 'i' : 'u'}|${mediaBlobKey(media)}`;
  const running = mediaLoadsInFlight.get(key);
  if (running) return running;
  const p = withMediaSlot(() => loadMediaFileOnce(relay, sessions, token, media, mine, opts.group === true));
  mediaLoadsInFlight.set(key, p);
  const drop = () => { if (mediaLoadsInFlight.get(key) === p) mediaLoadsInFlight.delete(key); };
  p.then(drop, drop);
  return p;
}

async function loadMediaFileOnce(
  relay: VeilRelay,
  sessions: SessionStore,
  token: string,
  media: ChatMedia,
  mine?: boolean,
  group = false,
): Promise<Uint8Array> {
  if (!media.uri || !media.k || !media.iv) throw new Error('Media message has no retrievable blob (key missing).');
  const sealed = await sessions.load(token);
  if (!sealed) throw new Error('No ratchet state for this session on this device.');
  // b77u (audit 6 U-M9): a group seat's file: the seat's own credential (no 1:1 delivery capabilities)
  const seatWs = group ? ((sealed as { writeSecret?: string | null }).writeSecret ?? null) : null;
  const dlv = group ? null : requireDelivery(sealed); // b77
  // b77 (sealed sender): a received file sits on MY inbound (read cap); one I sent sits on the
  // peer's inbound (send cap). `mine` picks; unknown tries mine-received first.
  const routes: [string, string][] = !dlv ? []
    : mine === true ? [[dlv.outbound.mbox, dlv.outbound.send]]
    : mine === false ? [[dlv.inbound.mbox, dlv.inbound.read]]
    : [[dlv.inbound.mbox, dlv.inbound.read], [dlv.outbound.mbox, dlv.outbound.send]];
  let lastErr: unknown = null;
  for (let attempt = 0; attempt < 5; attempt++) {
    try {
      let url: string | null = null;
      let routeErr: unknown = null;
      if (group) url = await relay.vaultFileSignedUrl(media.uri, token, seatWs);
      for (const [mbox, cap] of routes) {
        try { url = await relay.sealedFile(mbox, cap, media.uri, 'url'); break; } catch (e) { routeErr = e; }
      }
      if (!url) throw routeErr ?? new Error('Signed URL unavailable');
      const bytes = await relay.fetchBytes(url);
      try { return await decryptMedia(bytes, media.k, media.iv); } catch (e) {
        // b77t (audit 5 L-18): a blob that doesn't open under its key never will — not re-downloaded
        bytes.fill(0);
        throw Object.assign(e instanceof Error ? e : new Error(String(e)), { mediaFinal: true });
      }
    } catch (e) {
      lastErr = e;
      console.error(`[veil] media load failed (attempt ${attempt + 1}/5): ${(e as Error).message ?? e}`);
      if ((e as { mediaFinal?: boolean })?.mediaFinal) break;
      if ((e as Error)?.name === 'MediaTooLargeError') break; // b77p (audit VAR-11): over the cap is final — never re-downloaded
      if (attempt < 4) await new Promise((r) => setTimeout(r, 3500));
    }
  }
  throw lastErr instanceof Error ? lastErr : new Error(String(lastErr));
}

/**
 * Initiator-side completion: once the responder has joined (session record now
 * carries responder_* keys), derive the sending chains and reseal. No-op when
 * already ready. Throws when the peer has not joined yet (composer gate).
 */
/** Batch H (round-5 review R5-1-07, second half): completion runs under the
 *  session's send lock, so a send or sync in flight can't write over it. */
export function completeContactHandshake(
  relay: VeilRelay,
  sessions: SessionStore,
  token: string,
  prefetched?: Record<string, unknown>,
): Promise<void> {
  return serializeRatchetSend(token, () => completeContactHandshakeUnlocked(relay, sessions, token, prefetched));
}

async function completeContactHandshakeUnlocked(
  relay: VeilRelay,
  sessions: SessionStore,
  token: string,
  prefetched?: Record<string, unknown>,
): Promise<void> {
  sessions = pinToWipe(sessions); // b70 (re-review 6): a wipe while this waits on the relay stops its later writes
  const sealed = await sessions.load(token);
  if (!sealed) throw new Error('No ratchet state for this session on this device.');
  const state = await deserializeRatchetState(sealed);
  if (state.ready) return;

  let rec = prefetched as Record<string, string> | null | undefined;
  if (!rec) {
    // b77 (sealed sender): the no-login gate `status` for this one token (was peek / list)
    rec = (await readHandshakeStatus(relay, token, sealed.writeSecret ?? null)) as Record<string, string> | null;
  }
  if (!rec?.responder_ratchet_pub_jwk) throw new Error('Waiting for your contact to accept.');

  const out: { delivery?: DeliveryCaps } = {};
  await completeHandshake(
    state, token,
    rec.responder_pub_jwk, rec.responder_ratchet_pub_jwk, rec.responder_pq_ct || null,
    out, // b77: the delivery capabilities, from the same root (contact) / rk0 (invite)
  );
  const delivery: ChatDelivery | undefined = out.delivery ? await deliveryForRole(out.delivery, 'initiator') : undefined;
  // keep the session's dials with the ratchet so sync can burn and sends
  // derive the same per-message TTL (web Kh semantics).
  // Batch C (V-12): the initiator keeps its OWN dials (sealed at create and
  // bound into the fingerprint) — never the relay row's copy.
  const own = sealed as { burnAfterOpen?: boolean; defaultTtlSeconds?: number; expireAfterSeconds?: number; peerVeilId?: string; peerIkPub?: string; myVerifiedFp?: string };
  await saveOrThrow(sessions, token, { // Batch H (R6-1-06)
    ...(await serializeRatchetState(state)),
    ...(own.peerVeilId && own.peerIkPub ? { peerVeilId: own.peerVeilId, peerIkPub: own.peerIkPub } : {}), // Batch F (R4-1-04)
    ...(own.myVerifiedFp ? { myVerifiedFp: own.myVerifiedFp } : {}), // Batch F (R4-1-03)
    burnAfterOpen: own.burnAfterOpen === true,
    defaultTtlSeconds: Number.isFinite(Number(own.defaultTtlSeconds)) ? Number(own.defaultTtlSeconds) : 7200,
    expireAfterSeconds: Number.isFinite(Number(own.expireAfterSeconds)) ? Number(own.expireAfterSeconds) : 86400,
    ...(delivery ? { delivery } : {}), // b77 (sealed sender)
  } as never);
  // b77: open my inbound after the random delay; the first sync pass past it opens it, then
  // gate-ends the rendezvous row (ensureInboundOpen)
  if (delivery) await scheduleInboundOpen(sessions, token);
}

/**
 * SPEC §3 (initiator pending loop): while a sent request (contact or invite) is pending, ask
 * the relay about this one rendezvous token — b77: the no-login gate `status {token,
 * write_secret}` (it used to be the logged-in, account-wide list). The request is accepted
 * exactly when the record shows state === 'active' AND both responder_pub_jwk and
 * responder_ratchet_pub_jwk are non-empty; then complete the handshake EXACTLY ONCE from the
 * stored request-time state. (`clientId` / `veilId` are no longer sent.)
 */
export async function pollContactAcceptance(
  relay: VeilRelay,
  sessions: SessionStore,
  token: string,
  _clientId?: string,
  _veilId?: string | null,
): Promise<'pending' | 'accepted' | 'ready'> {
  const sealed = await sessions.load(token);
  if (sealed?.ready) return 'ready';
  if (!sealed) return 'pending';

  const rec = await readHandshakeStatus(relay, token, (sealed as { writeSecret?: string | null }).writeSecret ?? null);
  if (!rec) return 'pending';
  if (rec.state !== 'active' || !rec.responder_pub_jwk || !rec.responder_ratchet_pub_jwk) return 'pending';

  await completeContactHandshake(relay, sessions, token, rec);
  return 'accepted';
}
