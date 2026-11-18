/**
 * @veil/device — session state persistence (veil_rk_<token>).
 *
 * The web app kept serialized ratchet state in localStorage (the veil_rk_*
 * family). Natively the serialized state lives in the secure store; the
 * end-session path must remove BOTH the state and its wrapper record, so the
 * P1-1 ghost class cannot exist structurally: removeRatchet is the ONLY
 * delete path and it always clears every residue key for the token.
 */

import type { RatchetStateSerialized } from '../../crypto-core/src/index';
import { parseChatDelivery, type ChatDelivery } from '../../crypto-core/src/index';
import type { VeilStorage } from '../../crypto-core/src/index';
import { secureRemove, secureRemovePrefix } from './secure-wipe';
import type { ChatMessage } from './chat';
import { parseAnchor, type BackfillAnchor } from './backfill';
import { currentWipeGeneration } from './wipe-generation';
import { serializeRatchetSend } from './send-queue';

/** b77z2 (Z-1 / Z-8): a per-key chain for LOCAL read-modify-writes only (the message cache, the
 *  display marks). It never holds network work, so taking it never waits on the relay, unlike
 *  the per-token ratchet chain (serializeRatchetSend), which a sync pass holds for its whole run.
 *  Lock order (b77z3, Y-4): chain -> cache -> marks, and chain -> marks. The ratchet chain may
 *  take the cache lock or the marks lock; the cache-lock holder may take the marks lock (the
 *  purge records a display mark for a displayed row it deletes); the marks-lock holder takes
 *  nothing else. No local-lock holder waits on the ratchet chain. Module scope, so every SessionStore over
 *  the same storage in this process shares it. */
const localChains = new Map<string, Promise<unknown>>();
function withLocalLock<T>(key: string, run: () => Promise<T>): Promise<T> {
  const prev = localChains.get(key);
  const next = (prev ?? Promise.resolve()).then(() => undefined, () => undefined).then(run);
  localChains.set(key, next);
  const trim = () => { if (localChains.get(key) === next) localChains.delete(key); };
  next.then(trim, trim);
  return next;
}
/** b77m (audit VAR-26): a chat token as this phone creates and accepts them — 24 random bytes, 48 lowercase hex */
export const CHAT_TOKEN_RE = /^[0-9a-f]{48}$/;
export const isChatToken = (t: unknown): t is string => typeof t === 'string' && CHAT_TOKEN_RE.test(t);
/** b77m (audit VAR-26): the characters a token may have to become part of a storage key. Every per-chat key
 *  is `veil_<kind>_<token>` (and `veil_msgcache_<token>_p<i>`), so a token with "_" in it could name another
 *  chat's keys: `<T0>_p0` read (and then retired) chat T0's first history page, and a token starting
 *  `wrap_` was dropped by listTokens (hidden from the duress wipe's mailbox ends, device moves and the list
 *  rebuild). No underscore, no other separator: letters, digits and '-' only, at most 128. Real tokens are
 *  stricter still (isChatToken; checked where a token enters from a link, a request or a transfer). */
export const STORE_TOKEN_RE = /^[A-Za-z0-9-]{1,128}$/;
export const isStoreToken = (t: unknown): t is string => typeof t === 'string' && STORE_TOKEN_RE.test(t);
/** b77m (audit VAR-26): thrown when a malformed token would become a storage key */
export class InvalidTokenError extends Error {
  constructor() { super('This chat link or record is malformed, so it was not used.'); this.name = 'InvalidTokenError'; Object.setPrototypeOf(this, InvalidTokenError.prototype); }
}
/** b77m (audit VAR-26): the token, checked, for a storage key — throws InvalidTokenError otherwise */
function tk(token: string): string {
  if (!isStoreToken(token)) throw new InvalidTokenError();
  return token;
}
const cacheLock = (token: string) => `cache:${token}`;
const marksLock = (token: string) => `marks:${token}`;

/** Batch F (R4-4-12): real (non-cover) entries kept per chat */
export const PENDING_BURN_MAX = 2000;
/** b77t2 (CL-4): cover entries kept per chat, apart from the real ones. A peer (or a chat left open) can queue
 *  cover without limit; past this the oldest cover is dropped (that envelope then just expires on the relay) */
export const PENDING_BURN_COVER_MAX = 50;
/** b77t2 (CL-4): the queue as saved — the newest PENDING_BURN_COVER_MAX cover entries and the newest
 *  PENDING_BURN_MAX others, in their order. A cover entry never pushes out a real one. `full`: real ones dropped */
export function capPendingBurns<T extends { cover?: boolean }>(list: T[]): { kept: T[]; full: boolean } {
  let covers = 0;
  let reals = 0;
  for (const e of list) { if (e.cover) covers++; else reals++; }
  let dropCover = Math.max(0, covers - PENDING_BURN_COVER_MAX);
  let dropReal = Math.max(0, reals - PENDING_BURN_MAX);
  if (!dropCover && !dropReal) return { kept: list, full: false };
  const full = dropReal > 0;
  const kept = list.filter((e) => {
    if (e.cover) { if (dropCover > 0) { dropCover--; return false; } return true; }
    if (dropReal > 0) { dropReal--; return false; }
    return true;
  });
  return { kept, full };
}

/** b102: a relay burn this phone still owes (veil_pendburn_<token>). b77z2: written only on the
 *  per-token ratchet chain (syncChat, the purge's queue edit, a transfer import); a display is
 *  reported through the append-only marks instead (SessionStore.addDisplayedMarks). */
export interface PendingBurn {
  id: string;
  attempts: number;
  /** b197-r8m: false = awaiting display (never burned while false) */
  displayed?: boolean;
  /** b77t (audit 5 M-G): a cover envelope. It waits like a chat message (displayed false) and is flipped
   *  when its chat is on screen (the pass after it was queued) or when the chat's messages are marked
   *  displayed, so its burn comes at the same time a real message's would */
  cover?: boolean;
  /** b77z (BURN-2): queued by a sync pass ahead of its state save + ledger write (not settled yet) */
  pre?: boolean;
  /** b77z2 (Z-4): when the entry was queued (epoch ms) */
  at?: number;
  /** b77z2 (Z-4): the envelope's relay expiry (epoch ms), when the relay gave one */
  exp?: number;
  blob?: string;
  blobDeleteAt?: number;
  retryAt?: number;
  failingSince?: number;
}

/** b77g (hardening): a queued purge, shared by the callers that arrive before it starts */
type PurgeJob = Promise<{ purged: string[]; edit: Promise<unknown> | null }>;
/** b77h (audit77g H-3): a queued purge and whether one of its callers asked for the unread decay */
type PurgeEntry = { job: PurgeJob; decayUnread: boolean };

/** b77z2 (Z-1): at most this many display marks wait per chat (the oldest go first) */
export const DISPLAYED_MARKS_MAX = 2000;

/** b77 (sealed sender): a chat's own-inbound state (see SessionStore.mboxState) */
export interface MboxState {
  /** epoch ms: open the inbound no earlier than this (the random 5–120 s delay) */
  openAt: number;
  opened: boolean;
  /** sealedFetch cursor: the highest seq already handed to the decrypt loop */
  seq: number;
  /** b77: the random wake reference bound to this inbound (b77p: retired — kept so older states parse) */
  pushRef?: string;
  pushBound?: boolean;
  /** b77p (audit 2 VAR-01): the first 16 hex of SHA-256 of the push target last sealed into this inbound's wake
   *  box ('off' = cleared) */
  wakeFp?: string;
  /** b77p (audit 2 VAR-01): my blind open token while it is being issued ({kid, x, r}: r unblinds), then the
   *  token itself until the open ({kid, x, s}) */
  openBlind?: { kid: string; x: string; r: string };
  openToken?: { kid: string; x: string; s: string };
  /** what mailboxVerify last told the relay */
  verified?: boolean;
  /** initiator: gate end on the rendezvous token is done */
  rvEnded?: boolean;
  /** the relay answered 410 (retired) for this inbound.
   *  b77r1 (audit A-2): no longer written — one answer is never stored as a fact; every pass asks
   *  the relay again and the P-4 rule (session-liveness) decides. Kept so older states parse. */
  retired?: boolean;
  /** b77r1 (audit A-5): my inbound was opened for real (200 / 409, or a fetch went through) at least once */
  everOpened?: boolean;
  /** b77r1 (audit A-5): "bad or used ticket" (403) answers to my open, counted while my inbound
   *  has never opened: how many, and when the first came */
  openRefused?: { n: number; first: number };
  /** b77r1 (audit A-5): the open kept being refused long enough — this chat can't finish setting
   *  up (the app says so and offers End; no more opens are sent) */
  setupFailed?: boolean;
  /** b77m (audit VAR-07): epoch ms — the relay reported this chat gone (410s meeting the P-4 rule) with no
   *  END from the peer. The chat is kept read-only with its history; syncChat makes no relay call for it. */
  unavailable?: number;
  /** b77m review (L9): epoch ms — the peer's END arrived in the same pass as messages sent before it. The chat
   *  ended (mailboxes retired, nothing more is sent or received) but is kept read-only, like `unavailable`
   *  (set with it), so those last messages can still be read; the app says the other person ended it. */
  peerEnded?: number;
  /** b77u2 (UC-L3): epoch ms — the peer's END is being finished (keys dropped, history purged). Written BEFORE peerEnded and
   *  cleared only once the purge completed, so a pass cut short (the app killed) is finished by a later pass */
  purgePending?: number;
  /** b77u (audit 6 U-M7): epoch ms — when gate `issue` (my open token, names the rendezvous) runs, on its own timer */
  issueAt?: number;
  /** b77u (U-M7): epoch ms — the open waits until then (a fresh delay after the token came) */
  openStepAt?: number;
  /** b77u (U-M7): epoch ms — the initiator's gate `end` of the rendezvous runs then, on its own timer */
  rvEndAt?: number;
}

/**
 * b77r2: a stored mailbox state as this build reads it (every read; the next write stores it so).
 * - audit R2-A-2: a `retired` flag a b77 build stored from ONE 410 is dropped — it listed the chat
 *   as "Session ended" and kept the background sync off it; the P-4 rule decides an end now.
 * - audit R2-A-3: a stored `opened: true` (a b77 build, or a device move, that never wrote
 *   `everOpened`) means the inbound did open — so a hostile relay's 425 + 403s can't make
 *   `setupFailed` permanent on a chat that really opened.
 */
export function migrateMboxState(v: MboxState): MboxState {
  const { retired: _retired, ...rest } = v;
  return rest.opened === true && rest.everOpened !== true ? { ...rest, everOpened: true } : rest;
}

/** b77: an encrypted envelope waiting for the peer's inbound to open (425) */
export interface OutboxItem { ciphertext: string; iv: string; header: string; byte_length: number; ttl_seconds: number; notify: false | 'msg' | 'call'; at: number; localId?: string }
/** b77r1 (audit A-5): at most this many envelopes wait in one chat's outbox. A send that would
 *  pass it is refused (OutboxFullError) — the outbox never drops an item. */
export const OUTBOX_MAX = 200;

export class SessionStore {
  /** b77g (NaR-1): `deliveryCache: false` (the decoy app's stores) never keeps capabilities in memory */
  constructor(private storage: VeilStorage, opts: { deliveryCache?: boolean } = {}) {
    this.deliveriesOff = opts.deliveryCache === false;
  }

  // ---------- b77g (NaR-1): each chat's delivery capabilities, in memory ----------
  // A wipe must end both mailboxes of every 1:1 chat, and reading the sealed records at wipe time
  // means one keystore read per chat (a slow Android keystore took past the old 1 s bound, so the
  // Nothing-at-Rest wipe ended NO mailbox). Every load and save of a chat's sealed record notes
  // its capabilities here, so a wipe gets them at once with no keystore read (cachedDeliveries).
  // Valid for one wipe generation only (a wipe empties it: forgetDeliveries, and any read after a
  // bump finds it empty); a load that began before a wipe never fills it after; never filled
  // while turned off (decoy mode, the decoy app's stores).
  // b77h (audit77g H-1): a wipe's own reads (the duress capture's writeSecretOf / deliveryOf, the
  // Nothing-at-Rest fallback read, a refreshSessions load) ran between beginWipe's bump and the
  // shred and filled the cache again with every wiped chat, for the rest of the process. Now
  // forgetDeliveries (beginWipe) also sets a latch: while it is set nothing is noted and the cache
  // reads empty. Only a deliberate fresh start (resumeDeliveries: create / restore an identity,
  // sign in — the same calls that lift the storage barrier) clears it. A load or save that began
  // under another latch epoch (before a wipe, or during one that a fresh start has since ended)
  // never notes either.
  private deliveries = new Map<string, ChatDelivery>();
  private deliveriesGen = currentWipeGeneration();
  private deliveriesOff = false;
  private deliveriesWiping = false;
  private deliveriesEpoch = 0;
  private heldDeliveries = new Map<string, ChatDelivery>(); // b77k (IP77-5): see holdDeliveries
  private deliveryCacheLive(): boolean {
    const g = currentWipeGeneration();
    if (this.deliveriesGen !== g) { this.deliveries.clear(); this.deliveriesGen = g; }
    return !this.deliveriesOff && !this.deliveriesWiping;
  }
  /** b77h (H-1): what a load / save captures when it begins (see noteDelivery) */
  private deliveryMark(): { gen: number; epoch: number } {
    return { gen: currentWipeGeneration(), epoch: this.deliveriesEpoch };
  }
  /** `at`: the wipe generation and latch epoch when the load / save began */
  private noteDelivery(token: string, state: unknown, at: { gen: number; epoch: number }): void {
    if (!this.deliveryCacheLive() || at.gen !== currentWipeGeneration() || at.epoch !== this.deliveriesEpoch) return;
    const d = parseChatDelivery((state as { delivery?: unknown } | null)?.delivery);
    if (d) this.deliveries.set(token, d); else this.deliveries.delete(token);
  }
  /** b77g (NaR-1): a copy of every cached chat's capabilities (token -> delivery); synchronous.
   *  b77h (H-1): empty while a wipe's latch is set */
  cachedDeliveries(): Map<string, ChatDelivery> {
    // b77k (IP77-5): + the capabilities a dial-flip wipe carried over (held until the next real wipe)
    const out = this.deliveriesOff ? new Map<string, ChatDelivery>() : new Map(this.heldDeliveries);
    if (this.deliveryCacheLive()) for (const [t, d] of this.deliveries) out.set(t, d);
    return out;
  }
  /**
   * b77k (IP77-5): the Nothing-at-Rest dial flip shreds what is stored but ends no mailbox (the
   * user is still in the app; the departure wipe ends them). Its beginWipe empties and latches the
   * cache like every wipe, so the chats' capabilities taken just before are held here, outside the
   * latch and the wipe generation: cachedDeliveries() still returns them, so the departure wipe
   * (and a duress wipe) ends them exactly as before. A wipe drops a held one only when it ended it
   * (forgetDeliveries(undefined, ended): b77k2, L1 — a wipe that took no snapshot, such as the
   * departure wipe in decoy mode, used to drop them unended); a wipe's end pass
   * (forgetDeliveries(epoch)), a fresh start and decoy mode keep them (those mailboxes still exist
   * until something ends them). b77k2 (IP77-5): the flip now also carries the chats themselves
   * into memory (KeychainStorage memory session), so they keep working until the departure.
   */
  holdDeliveries(caps: Map<string, ChatDelivery>): void {
    for (const [t, d] of caps) this.heldDeliveries.set(t, d);
  }
  /** b77k2 (IP77-5): these chats are stored again (Nothing-at-Rest turned down): no longer held for an end */
  releaseHeldDeliveries(tokens: Iterable<string>): void {
    for (const t of tokens) this.heldDeliveries.delete(t);
  }
  /**
   * b77g (NaR-1): drop every cached capability (every wipe path calls this, in beginWipe).
   * b77h (H-1): and set the wipe latch (nothing is noted until resumeDeliveries). Returns the
   * latch epoch; the wipe's end calls `forgetDeliveries(epoch)` again after its verify pass, which
   * empties the cache only if no fresh start came in between (a new identity's chats stay).
   * b77k2 (L1): `ended` = the capabilities this wipe took to end (its snapshot); only those leave
   * the held set. Without it (a wipe that ends nothing) every held capability stays, to be ended
   * by a later wipe that does. b77k2 (re-review L4): 'all' = a full wipe (nothing kept: duress,
   * sign-out, wipe device, self-destruct) drops every held one, ended or not — kept, they would be
   * ended later under another identity, in the same burst as its own chats (linking the two).
   */
  forgetDeliveries(sinceEpoch?: number, ended?: Map<string, ChatDelivery> | 'all'): number {
    if (sinceEpoch !== undefined && sinceEpoch !== this.deliveriesEpoch) return this.deliveriesEpoch;
    this.deliveries.clear();
    if (sinceEpoch === undefined && ended === 'all') this.heldDeliveries.clear(); // b77k2 (re-review L4)
    else if (sinceEpoch === undefined && ended instanceof Map) for (const t of ended.keys()) this.heldDeliveries.delete(t); // b77k2 (L1)
    this.deliveriesGen = currentWipeGeneration();
    if (sinceEpoch === undefined) { this.deliveriesWiping = true; this.deliveriesEpoch++; }
    return this.deliveriesEpoch;
  }
  /** b77h (H-1): a deliberate fresh start (create / restore an identity, sign in) ends the wipe
   *  latch: the new identity's chats fill the cache again from here on */
  resumeDeliveries(): void {
    this.deliveries.clear();
    this.deliveriesGen = currentWipeGeneration();
    this.deliveriesWiping = false;
    this.deliveriesEpoch++;
  }
  /** b77h (H-1): true from a wipe's forgetDeliveries until the next fresh start */
  deliveriesLatched(): boolean { return this.deliveriesWiping; }
  /** b77g (NaR-1): off = empty now and never filled until turned on again (decoy mode) */
  setDeliveryCacheEnabled(on: boolean): void {
    // b77k2 (L1): the real chats' capabilities cached when decoy mode starts are held, not dropped:
    // a departure wipe in decoy mode ends nothing, and they must still be ended by a later wipe.
    // (Not for a store that never caches: the decoy app's own stores hold none.)
    if (!on && !this.deliveriesOff && this.deliveryCacheLive()) for (const [t, d] of this.deliveries) this.heldDeliveries.set(t, d);
    this.deliveriesOff = !on;
    if (!on) this.deliveries.clear();
  }

  static keyFor(token: string): string {
    return `veil_rk_${tk(token)}`;
  }

  /** b70 (re-review P3): chats being moved to another phone. From the moment
   *  the transfer link exists until the move ends, this phone saves no new
   *  state for them, so it can't advance chains the new phone imports. */
  private moving = new Set<string>();
  freezeMoving(tokens: string[]): void { for (const t of tokens) this.moving.add(t); }
  unfreezeMoving(tokens: string[]): void { for (const t of tokens) this.moving.delete(t); }
  isMoving(token: string): boolean { return this.moving.has(token); }

  async save(token: string, state: RatchetStateSerialized): Promise<boolean> {
    if (this.moving.has(token)) return false; // b70 (re-review P3)
    const at = this.deliveryMark(); // b77h (H-1): the generation and latch epoch at the start
    const ok = await this.storage.set(SessionStore.keyFor(token), JSON.stringify(state));
    if (ok !== false) this.noteDelivery(token, state, at); // b77g (NaR-1)
    return ok;
  }

  async load(token: string): Promise<RatchetStateSerialized | null> {
    const at = this.deliveryMark(); // b77h (H-1)
    const raw = await this.storage.get(SessionStore.keyFor(token));
    let v: RatchetStateSerialized | null = null;
    if (raw) { try { v = JSON.parse(raw); } catch { v = null; } }
    // b77g (NaR-1): a record that reads (or is gone) updates the cache; an unreadable one keeps it
    if (v || raw == null) this.noteDelivery(token, v, at);
    return v;
  }

  /** b77r1 (audit A-9): told when a removed chat had a bound wake reference, so the app can
   *  update its push row's push_refs (to [] when it was the last one) */
  private pushRefRemovedHook: (() => void) | null = null;
  setPushRefRemovedHook(fn: (() => void) | null): void { this.pushRefRemovedHook = fn; }

  /** End-session: removes ALL residue for the token — state, wrapper, msgcache,
   * processed-id ledger. */
  async remove(token: string): Promise<void> {
    this.deliveries.delete(token); // b77g (NaR-1): the chat's capabilities leave memory with it
    this.heldDeliveries.delete(token); // b77k (IP77-5): held ones too
    const hadPushRef = !!(await this.mboxState(token).catch(() => null))?.pushBound;
    this.setUnshown(token, []); // b75r3 (PR3-04): messages waiting in memory go with the chat
    // b93 P2: overwrite before delete — ratchet states, wrapped keys and the
    // PLAINTEXT message cache are exactly the bytes a forensic extraction
    // of the store file wants; a bare remove() left them on disk.
    await secureRemove(this.storage, SessionStore.keyFor(token));
    await secureRemove(this.storage, `veil_rk_wrap_${tk(token)}`);
    await secureRemove(this.storage, `veil_msgcache_${tk(token)}`);
    // b172: chunked cache parts (see cacheWrite) die with the session too
    for (let pi = 0; pi < 256; pi++) {
      const pk = `veil_msgcache_${tk(token)}_p${pi}`;
      if (await this.storage.get(pk) == null) break;
      await secureRemove(this.storage, pk);
    }
    await secureRemove(this.storage, this.procKey(token));
    await secureRemove(this.storage, this.skipKey(token));
    await secureRemove(this.storage, this.backfillKey(token));
    await secureRemove(this.storage, this.unreadKey(token));
    await secureRemove(this.storage, this.strayKey(token));
    await secureRemove(this.storage, this.strayPendingKey(token));
    await secureRemove(this.storage, `veil_missing_${tk(token)}`); // b70 (re-review P1)
    // b70 (re-review 9): the peer label + last call time, and the read-receipt ledger, go too
    await secureRemove(this.storage, this.missedCallKey(token));
    await secureRemove(this.storage, this.receiptedKey(token));
    await secureRemove(this.storage, this.desyncPendingKey(token));
    // b102: pending-burn retry queue dies with the session too — a stale
    // queue would keep firing burn calls for envelopes of a session this
    // device no longer has state for.
    await secureRemove(this.storage, this.pendingBurnKey(token));
    // b77z2 (Z-1): and the display marks waiting for the next sync pass.
    // b77z3 (Y-3): under the marks lock, after the state above is gone: a mark in flight either
    // wrote before this (and is removed here) or finds the chat gone and writes nothing
    await withLocalLock(marksLock(token), () => secureRemove(this.storage, this.displayedKey(token)));
    // b77 (sealed sender): the mailbox cursor / open state and envelopes waiting for the peer's inbound
    await secureRemove(this.storage, this.mboxKey(token));
    await secureRemove(this.storage, this.outboxKey(token));
    this.deliveries.delete(token); // b77g (NaR-1): and again, after any load that raced the removal
    if (hadPushRef && this.pushRefRemovedHook) { try { this.pushRefRemovedHook(); } catch { /* the app's hook is best-effort */ } }
  }

  /** b77p (audit VAR-06): the peer's authenticated END ended this chat. The chat stays, read-only, with
   *  its history (the user deletes it with `remove`), but every secret that could open or send in it goes:
   *  the ratchet's root, chain, header, signing and handshake keys, the skipped-key cache, the write secret
   *  and the delivery capabilities (the mailboxes are retired). What the list and the thread still show
   *  (peer id, nickname, safety code, dials, role) stays. The record is overwritten (secure remove, then
   *  written again) so the old key bytes are not left behind. `keysDropped` marks it; nothing deserializes
   *  such a record (syncChat returns at the `unavailable` mark before it would). false = not saved. */
  async dropRatchetKeys(token: string): Promise<boolean> {
    if (this.moving.has(token)) return false; // b70 (re-review P3)
    const cur = (await this.load(token).catch(() => null)) as Record<string, unknown> | null;
    this.deliveries.delete(token);
    this.heldDeliveries.delete(token);
    if (!cur) return false;
    const scrubbed: Record<string, unknown> = { ...cur, keysDropped: Date.now(), writeSecret: null, hsPrivB64: '', pqPriv: null,
      pqStepPriv: null, pendingPqCt: null, sigPrivB64: null, sessionSigPrivB64: null, ppSecretB64: null, ratchetPrivB64: null,
      rootKeyB64: '', sendChainB64: null, recvChainB64: null, skipped: [], skippedAt: [], hkSend: null, hkRecv: null,
      peerHks: [], myHks: [], shkSend: null, shkRecv: null, contactPending: null };
    delete scrubbed.delivery;
    await secureRemove(this.storage, SessionStore.keyFor(token));
    await secureRemove(this.storage, `veil_rk_wrap_${tk(token)}`);
    await secureRemove(this.storage, this.outboxKey(token));
    return (await this.save(token, scrubbed as unknown as RatchetStateSerialized)) !== false;
  }

  /** b77u (audit 6 U-M8, owner decision: END purges the peer): the peer's AUTHENTICATED END (decrypted under this
   *  chat's ratchet) deletes this phone's copy of the chat — the message history (every cache page), the messages
   *  waiting in memory, the pending burns and display marks, the outbox, the unread / stray / missed-call / receipt /
   *  backfill / gap ledgers. Kept: the ended state (the mailbox record with peerEnded, the scrubbed ratchet record
   *  that lists the chat as ended) and the processed-id ledger and cursor (so nothing is fetched or opened again).
   *  Secure removes (overwrite, then delete). Never called on the relay's word alone (a 410). */
  async purgeChatHistory(token: string): Promise<void> {
    this.setUnshown(token, []);
    await withLocalLock(cacheLock(token), async () => {
      await secureRemove(this.storage, `veil_msgcache_${tk(token)}`);
      for (let pi = 0; pi < 256; pi++) {
        const pk = `veil_msgcache_${tk(token)}_p${pi}`;
        if (await this.storage.get(pk) == null) break;
        await secureRemove(this.storage, pk);
      }
    });
    this.setUnshown(token, []);
    for (const k of [this.backfillKey(token), this.unreadKey(token), this.strayKey(token), this.strayPendingKey(token),
      `veil_missing_${tk(token)}`, this.missedCallKey(token), this.receiptedKey(token), this.desyncPendingKey(token),
      this.pendingBurnKey(token), this.outboxKey(token)]) {
      await secureRemove(this.storage, k);
    }
    await withLocalLock(marksLock(token), () => secureRemove(this.storage, this.displayedKey(token)));
  }

  /** b77p (audit VAR-06): a record whose keys `dropRatchetKeys` removed (the peer ended the chat) */
  static keysDropped(state: unknown): boolean {
    return !!state && typeof state === 'object' && Number((state as { keysDropped?: unknown }).keysDropped) > 0;
  }

  // ---------- b77 sealed-sender mailbox state ----------
  // Per chat: when this phone opens its own inbound (a random 5–120 s after the handshake),
  // whether it did, the sealedFetch cursor (next_seq), and the wake reference bound to it.
  // The capabilities themselves live in the sealed record (`delivery`), so they move with it.
  private mboxKey(token: string): string { return `veil_mbox_${tk(token)}`; }
  private outboxKey(token: string): string { return `veil_outbox_${tk(token)}`; }

  async mboxState(token: string): Promise<MboxState | null> {
    const raw = await this.storage.get(this.mboxKey(token));
    try { const v = raw ? JSON.parse(raw) : null; return v && typeof v === 'object' ? migrateMboxState(v as MboxState) : null; } catch { return null; }
  }

  /** merge `patch` into the chat's mailbox state; false when storage refused it */
  async setMboxState(token: string, patch: Partial<MboxState>): Promise<boolean> {
    // b77u (audit 6 U-M7): one merge at a time per chat (the setup steps' timers write it beside the sync pass)
    return withLocalLock(`mbox:${tk(token)}`, async () => {
      const cur = (await this.mboxState(token)) ?? { openAt: 0, opened: false, seq: 0 };
      return (await this.storage.set(this.mboxKey(token), JSON.stringify({ ...cur, ...patch }))) !== false;
    });
  }

  /** b77q (audit 3 CR-1): the relay's open-token issuer key this phone is pinned to (sealed.ts currentOpenKey), as
   *  JSON, so a restart can't make it take a new one. A `veil_` record: every wipe removes it, Nothing-at-Rest
   *  carries it in memory like the chats. null = none. */
  async openKeyPin(): Promise<string | null> {
    return (await this.storage.get(SessionStore.OPEN_KEY_PIN_KEY)) ?? null;
  }

  /** b77q (audit 3 CR-1): write (or, with null, remove) the pinned issuer key; false when storage refused it */
  async setOpenKeyPin(json: string | null): Promise<boolean> {
    if (json === null) { await secureRemove(this.storage, SessionStore.OPEN_KEY_PIN_KEY); return true; }
    return (await this.storage.set(SessionStore.OPEN_KEY_PIN_KEY, json)) !== false;
  }
  static readonly OPEN_KEY_PIN_KEY = 'veil_open_key_pin';

  /** envelopes already encrypted (their ratchet step saved) that met a 425: the peer's inbound
   *  was not open yet. Re-submitted unchanged, oldest first, by the next sync pass. */
  async outbox(token: string): Promise<OutboxItem[]> {
    const raw = await this.storage.get(this.outboxKey(token));
    try { const v = raw ? JSON.parse(raw) : []; return Array.isArray(v) ? v as OutboxItem[] : []; } catch { return []; }
  }

  async setOutbox(token: string, items: OutboxItem[]): Promise<boolean> {
    if (!items.length) { await this.storage.remove(this.outboxKey(token)); return true; }
    // b77r1 (audit A-5): never drop the oldest silently — a list over the cap is refused whole
    if (items.length > OUTBOX_MAX) return false;
    return (await this.storage.set(this.outboxKey(token), JSON.stringify(items))) !== false;
  }

  // ---------- unread counters (b90) ----------
  // Per-session count of decrypted-but-unseen messages. Persisted so the
  // badge survives app restarts; cleared the moment the thread is opened.
  // Never counts messages decrypted while the thread was open (the user is
  // looking at them) and never counts system notes or receipts.
  private unreadKey(token: string): string {
    return `veil_unread_${tk(token)}`;
  }

  async getUnread(token: string): Promise<number> {
    const raw = await this.storage.get(this.unreadKey(token));
    const n = Number(raw);
    return Number.isFinite(n) && n > 0 ? Math.floor(n) : 0;
  }

  /** Add n (or pass a negative to decay); returns the new count. Clamped >= 0. */
  async bumpUnread(token: string, n: number): Promise<number> {
    const next = Math.max(0, Math.floor((await this.getUnread(token)) + n));
    if (next > 0) {
      await this.storage.set(this.unreadKey(token), String(next));
    } else {
      await this.storage.remove(this.unreadKey(token)); // 0 = no key, keeps storage lean
    }
    return next;
  }

  async clearUnread(token: string): Promise<void> {
    await this.storage.remove(this.unreadKey(token));
  }

  // ---------- stray-envelope ledger (b91) ----------
  // Envelopes classified as strays (failed to decrypt, but newer messages
  // in the same session decrypt fine). A consumed ratchet message key can
  // never be re-derived, so re-attempting a classified stray every poll
  // only re-logs the failure — and once the newer envelopes are all in the
  // processed ledger, the stray fails ALONE and would flip to "desync".
  // Ledgered strays are skipped on future passes, permanently.
  private strayKey(token: string): string {
    return `veil_stray_${tk(token)}`;
  }

  async strayIds(token: string): Promise<Set<string>> {
    const raw = await this.storage.get(this.strayKey(token));
    try {
      const arr = JSON.parse(raw ?? '[]') as string[];
      return new Set(Array.isArray(arr) ? arr : []);
    } catch { return new Set(); }
  }

  async markStrayIds(token: string, ids: string[]): Promise<void> {
    if (!ids.length) return;
    const cur = await this.strayIds(token);
    for (const id of ids) cur.add(id);
    await this.storage.set(this.strayKey(token), JSON.stringify(Array.from(cur).slice(-500)));
  }

  // ---------- pending stray/desync notices (b92 F1, b91 audit) ----------
  // Strays classified while a thread was CLOSED are ledgered silently — the
  // foreground soft-notice renders in React state that no longer exists when
  // the thread later opens, so the failed message would leave ZERO trace.
  // These counters keep the fact that something failed while closed, so
  // openChat can render the same soft notice the user would have seen live.
  // Cleared on drain (opening = seeing).
  private strayPendingKey(token: string): string {
    return `veil_straypending_${tk(token)}`;
  }

  async pendingStrayCount(token: string): Promise<number> {
    const raw = await this.storage.get(this.strayPendingKey(token));
    const n = Number(raw);
    return Number.isFinite(n) && n > 0 ? Math.floor(n) : 0;
  }

  async bumpPendingStrays(token: string, n: number): Promise<void> {
    if (n > 0) await this.storage.set(this.strayPendingKey(token), String((await this.pendingStrayCount(token)) + n));
  }

  /** Drains the pending count (returns it, then clears). */
  async takePendingStrays(token: string): Promise<number> {
    const n = await this.pendingStrayCount(token);
    if (n > 0) await this.storage.remove(this.strayPendingKey(token));
    return n;
  }

  /** b70 (re-review P1): messages the peer numbered that never arrived — kept
   *  per chat so a gap noticed by a background pass still shows on open */
  private missingKey(token: string): string {
    return `veil_missing_${tk(token)}`;
  }

  async bumpPendingMissing(token: string, n: number): Promise<void> {
    if (!(n > 0)) return;
    const cur = Number(await this.storage.get(this.missingKey(token))) || 0;
    await this.storage.set(this.missingKey(token), String(cur + Math.floor(n)));
  }

  /** Drains the pending count (returns it, then clears). */
  async takePendingMissing(token: string): Promise<number> {
    const n = Number(await this.storage.get(this.missingKey(token))) || 0;
    if (n > 0) await this.storage.remove(this.missingKey(token));
    return n > 0 ? n : 0;
  }

  /** b157: calls this device never answered — typically an offer held out by
   *  hold-until-unlock (a locked phone holds no message data, and call
   *  offers are ratcheted exactly like messages, so they cannot bypass the
   *  hold). openChat drains these into a "Missed call" system notice. */
  private missedCallKey(token: string): string {
    return `veil_missedcall_${tk(token)}`;
  }

  async missedCallInfo(token: string): Promise<{ n: number; peer: string; at: number } | null> {
    const raw = await this.storage.get(this.missedCallKey(token));
    if (!raw) return null;
    try { return JSON.parse(raw) as { n: number; peer: string; at: number }; } catch { return null; }
  }

  async bumpMissedCalls(token: string, peer: string): Promise<void> {
    const cur = (await this.missedCallInfo(token)) ?? { n: 0, peer, at: Date.now() };
    cur.n += 1; cur.peer = peer; cur.at = Date.now();
    await this.storage.set(this.missedCallKey(token), JSON.stringify(cur));
  }

  /** Drains the record (returns it, then clears). */
  async takeMissedCalls(token: string): Promise<{ n: number; peer: string; at: number } | null> {
    const info = await this.missedCallInfo(token);
    if (info) await this.storage.remove(this.missedCallKey(token));
    return info;
  }

  /** A genuine desync signature fired while the thread was closed — openChat
   *  surfaces the one-time end-session recommendation when it next opens. */
  private desyncPendingKey(token: string): string {
    return `veil_desyncpending_${tk(token)}`;
  }

  async setPendingDesync(token: string): Promise<void> {
    await this.storage.set(this.desyncPendingKey(token), '1');
  }

  async takePendingDesync(token: string): Promise<boolean> {
    const raw = await this.storage.get(this.desyncPendingKey(token));
    if (raw) await this.storage.remove(this.desyncPendingKey(token));
    return !!raw;
  }

  // ---------- processed-envelope ledger (b78) ----------
  // The relay RE-SERVES every envelope on every poll (the entity list never
  // consumes; 'delivered' marks are metadata only), so the only thing that
  // stands between a poll and a RE-DECRYPT of an already-consumed envelope —
  // which re-runs the PQ rekey, rotates both chains and permanently desyncs
  // the session (the "Message counter out of range" class) — is a durable
  // per-token record of every envelope id this device has decrypted. App-level
  // known-id sets are per-thread and seed from the message cache only, which
  // MISSES filtered control payloads (cover/intro/receipt) — re-decrypting one
  // of those poisons the ratchet exactly the same. This ledger records ALL
  // of them, per token, capped so it can't grow unbounded.
  private procKey(token: string): string {
    return `veil_procids_${tk(token)}`;
  }

  // ---------- pending-burn retry ledger (b102) ----------
  // Owner Metro repro Sept 21: "burn failed for <id>: Network request
  // failed". Root cause traced in chat.ts — the envelope is marked
  // PROCESSED (procKey, above) the instant decrypt succeeds, before the burn
  // call even runs; that ledger is what makes the NEXT sync pass skip an
  // envelope entirely. So once decrypt succeeds, a burn call that fails on a
  // plain network error was NEVER retried — the envelope sat on the relay at
  // its ORIGINAL expiry (hours/a day) instead of the shortened burn-after-
  // open one, silently defeating the feature's whole privacy promise on
  // nothing more than a dropped connection. This ledger tracks {id,attempts}
  // pairs per token so syncChat can retry them on every subsequent pass
  // (attempts cap at MAX_BURN_RETRY_ATTEMPTS so a permanently-failing id,
  // e.g. a dead session, doesn't retry forever — see chat.ts retryPendingBurns).
  private pendingBurnKey(token: string): string {
    return `veil_pendburn_${tk(token)}`;
  }

  async pendingBurns(token: string): Promise<PendingBurn[]> {
    const raw = await this.storage.get(this.pendingBurnKey(token));
    try { return raw ? (JSON.parse(raw) as PendingBurn[]) : []; } catch { return []; }
  }

  async setPendingBurns(token: string, list: PendingBurn[]): Promise<{ saved: boolean; full: boolean }> {
    if (!list.length) { await secureRemove(this.storage, this.pendingBurnKey(token)); return { saved: true, full: false }; }
    // Batch F (R4-4-12): keep up to 2000 (was 200, which silently dropped burns)
    // b77t2 (CL-4): cover entries are capped on their own (capPendingBurns), so cover never evicts a real burn
    const { kept, full } = capPendingBurns(list);
    if (full) console.log(`[veil] pending burn queue for #${token.slice(0, 4)} over ${PENDING_BURN_MAX} — oldest dropped`);
    // Batch H (round-6 review R6-1-10 / R5-1-09): the write result is checked and,
    // with a full queue, reported to the caller (the thread says so)
    const saved = (await this.storage.set(this.pendingBurnKey(token), JSON.stringify(kept)).catch(() => false)) !== false;
    if (!saved) console.log(`[veil] pending burn queue for #${token.slice(0, 4)} not saved (storage refused)`);
    return { saved, full };
  }

  // ---------- b77z2 (Z-1 / Z-2 / Z-5): display marks ----------
  // Envelope ids the human has seen (the display marker), or whose displayed row the purge
  // deleted when its burn window ran out (positive evidence, purgeBurnedMessages). An
  // append-only set, written at once under a local lock and never on the per-token ratchet
  // chain: marking never waits for a sync pass (or a hung relay call), and a mark is on storage
  // even if the app is killed mid-pass. The next sync pass merges the marks into the pending-burn
  // queue (displayed:false -> true) and drops the marks it wrote back.
  private displayedKey(token: string): string {
    return `veil_displayed_${tk(token)}`;
  }

  async displayedMarks(token: string): Promise<Set<string>> {
    const raw = await this.storage.get(this.displayedKey(token));
    try {
      const v = raw ? JSON.parse(raw) : [];
      return new Set(Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : []);
    } catch { return new Set(); }
  }

  /** append ids (deduplicated, capped at DISPLAYED_MARKS_MAX); false when storage refused it.
   *  b77g (hardening): calls made while one is queued (waiting for the marks lock, not started)
   *  join it — their ids are added to it and they share its answer — so a slow keystore can't
   *  build an unbounded backlog of lock jobs. b77h (audit77g H-3 check): the shared answer is
   *  right for every joiner (their ids were in the one write); it is a flag, never a count */
  async addDisplayedMarks(token: string, ids: string[]): Promise<boolean> {
    const add = ids.filter((x) => typeof x === 'string' && !!x);
    if (!add.length) return true;
    return this.coalesced(this.queuedMarks, token, add, marksLock(token), async (all) => {
      // b77z3 (Y-3): a mark in flight when the chat was removed (sessions.remove) writes nothing:
      // it would leave an orphan veil_displayed_<token> behind the removed chat
      if (await this.storage.get(SessionStore.keyFor(token)) == null) return false;
      const cur = await this.displayedMarks(token);
      for (const id of all) { cur.delete(id); cur.add(id); }
      const list = [...cur].slice(-DISPLAYED_MARKS_MAX);
      return (await this.storage.set(this.displayedKey(token), JSON.stringify(list)).catch(() => false)) !== false;
    });
  }

  // ---------- b77g (hardening): coalesced local-lock jobs ----------
  // The purge, the display marks and markShown are started unawaited, often (the purge every
  // second while a burn chat is open). On a slow keystore each queued its own lock job, so the
  // backlog grew without bound. A job queued and not yet started is shared: later callers add
  // their ids to it (the marks, markShown) or simply share it (the purge, keyed by burnSeconds).
  // Once a job starts it leaves the queue map, so a call arriving while it runs queues a new one
  // (it may need to see what the running job is writing).
  private queuedMarks = new Map<string, { ids: Set<string>; job: Promise<boolean> }>();
  private queuedShown = new Map<string, { ids: Set<string>; job: Promise<number> }>();
  private queuedPurges = new Map<string, PurgeEntry>();
  private coalesced<T>(map: Map<string, { ids: Set<string>; job: Promise<T> }>, token: string, ids: string[], lockKey: string, run: (ids: string[]) => Promise<T>): Promise<T> {
    const q = map.get(token);
    if (q) { for (const id of ids) q.ids.add(id); return q.job; }
    const entry = { ids: new Set(ids), job: undefined as unknown as Promise<T> };
    entry.job = withLocalLock(lockKey, () => {
      if (map.get(token) === entry) map.delete(token); // started: later calls queue a new job
      return run([...entry.ids]);
    });
    map.set(token, entry);
    const clear = () => { if (map.get(token) === entry) map.delete(token); };
    entry.job.then(clear, clear);
    return entry.job;
  }

  /** remove the marks a sync pass applied (marks added after it read them stay) */
  async dropDisplayedMarks(token: string, ids: string[]): Promise<void> {
    if (!ids.length) return;
    return withLocalLock(marksLock(token), async () => {
      const cur = await this.displayedMarks(token);
      const before = cur.size;
      for (const id of ids) cur.delete(id);
      if (cur.size === before) return;
      if (!cur.size) await secureRemove(this.storage, this.displayedKey(token));
      else await this.storage.set(this.displayedKey(token), JSON.stringify([...cur]));
    });
  }

  // ---------- envelope-list pagination cursor (b87) ----------
  // b87 (owner repro Sept 21 — "still nothing new" on a day-old heavily-used
  // thread): envelopeList always fetches the OLDEST 200 envelopes for a
  // session (web-parity query, no server-side "already delivered" filter).
  // Once a session accumulates more than 200 total rows — trivial after a
  // day of cover traffic — every poll re-fetches the SAME stale head
  // forever and can never reach anything sent after it: a silent,
  // permanent sync stall with zero error, zero log signal beyond an
  // unchanging "fetched 200 envelope(s)" line. This cursor lets syncChat
  // skip past a head it has fully accounted for. Advances ONLY on a full
  // (200-row) page, by (pageSize - SAFETY_MARGIN) — never on a partial
  // page, since a partial page IS the live tail and must be re-scanned
  // every poll for freshness. The margin absorbs index drift from the
  // relay's burn sweeper deleting expired rows elsewhere in the list
  // (safe either way: a row that vanished because it expired was going to
  // be skipped by the per-record expiry check regardless).
  private skipKey(token: string): string {
    return `veil_syncskip_${tk(token)}`;
  }

  // ---------- deep-backlog anchor (audit doc 13, R1) ----------
  // Set only while a sync pass is still descending a backlog deeper than its
  // fetch cap (see backfill.ts); absent otherwise. Losing it is harmless:
  // the next pass just starts the descent from the top again.
  private backfillKey(token: string): string {
    return `veil_backfill_${tk(token)}`;
  }

  async backfillAnchor(token: string): Promise<BackfillAnchor | null> {
    const raw = await this.storage.get(this.backfillKey(token));
    try { return raw ? parseAnchor(JSON.parse(raw)) : null; } catch { return null; }
  }

  async setBackfillAnchor(token: string, anchor: BackfillAnchor | null): Promise<void> {
    if (anchor) await this.storage.set(this.backfillKey(token), JSON.stringify(anchor));
    else await this.storage.remove(this.backfillKey(token));
  }

  async syncSkip(token: string): Promise<number> {
    const raw = await this.storage.get(this.skipKey(token));
    const n = raw ? Number(raw) : 0;
    return Number.isFinite(n) && n > 0 ? n : 0;
  }

  async saveSyncSkip(token: string, skip: number): Promise<void> {
    await this.storage.set(this.skipKey(token), String(Math.max(0, Math.floor(skip))));
  }

  async processedIds(token: string): Promise<Set<string>> {
    const raw = await this.storage.get(this.procKey(token));
    try { return new Set(raw ? (JSON.parse(raw) as string[]) : []); } catch { return new Set(); }
  }

  async markProcessedIds(token: string, ids: string[]): Promise<void> {
    if (!ids.length) return;
    const cur = await this.processedIds(token);
    for (const id of ids) cur.add(id);
    const arr = [...cur];
    await this.storage.set(this.procKey(token), JSON.stringify(arr.slice(-1000)));
  }

  // ---------- message cache (own sends + decrypted peers survive reload) ----------

  private cacheKey(token: string): string {
    return `veil_msgcache_${tk(token)}`;
  }

  /** b92 F-S1/F-S2: true when local history must not persist (memory mode
   *  or the localHistory dial off). Reads the same keys the vault/settings
   *  stores own, so the decision always matches the live configuration. */
  async historyPersistBlocked(): Promise<boolean> {
    try {
      if (((await this.storage.get('veil_storage_mode')) ?? '') === 'memory') return true;
      const raw = await this.storage.get('veil_settings_v1');
      if (raw) {
        const s = JSON.parse(raw) as { localHistory?: boolean };
        if (s.localHistory === false) return true;
      }
      return false;
    } catch {
      // b71 (review): fail closed. Unreadable settings could be hiding "Keep history: off";
      // a message not cached only means it isn't shown again after a restart
      return true;
    }
  }

  /** audit VAR-01: "Keep history" turned off (or Nothing-at-Rest) erases the stored history, so
   *  earlier messages don't stay on disk. Zero-fills and deletes every veil_msgcache_* record and
   *  returns how many remain (0 = gone; -1 = the store couldn't be listed). The read gate in
   *  cacheRead keeps them off screen meanwhile. */
  async dropStoredHistory(): Promise<number> {
    // b77m review (INFO): each chat's cache record is erased under that chat's cache lock (as every other
    // cache read-modify-write), so a write already running (a sync pass caching, a receipt tick) can't put
    // the old rows back after the erase; a record whose token isn't well-formed goes in the sweep below
    // (a cache is stored in parts, veil_msgcache_<token>_p<i>; a token never holds "_")
    let cacheKeys: string[] = [];
    try { cacheKeys = await this.storage.keys('veil_msgcache_'); } catch { cacheKeys = []; }
    const tokens = new Set(cacheKeys.map((k) => k.slice('veil_msgcache_'.length).split('_')[0]).filter(isStoreToken));
    for (const token of tokens) {
      await withLocalLock(cacheLock(token), async () => {
        const base = `veil_msgcache_${token}`;
        let mine: string[] = [];
        try { mine = (await this.storage.keys(base)).filter((k) => k === base || k.startsWith(base + '_')); } catch { mine = []; }
        for (const k of mine) await secureRemove(this.storage, k);
      });
    }
    await secureRemovePrefix(this.storage, 'veil_msgcache_');
    try { return (await this.storage.keys('veil_msgcache_')).length; } catch { return -1; }
  }

  // ---------- b75r3 (audit PR3-04): messages not shown yet, history off ----------
  // With "Keep history" off (and always in Nothing-at-Rest) the cache writes nothing. A
  // message a BACKGROUND pass opened while its chat was closed then had nowhere to go: its
  // key was spent, its envelope id ledgered, and the App kept only an unread count, so the
  // chat showed a badge and then nothing. Such messages now wait HERE, in memory only, until
  // the chat is opened (ensureOpenedAt hands them out once and forgets them) or a display
  // marker reports them shown (markShown). Never written to storage; gone with the app
  // process, with the chat (remove), and with any wipe (the wipe generation, checked on
  // every access). Capped like the cache.
  private unshown = new Map<string, ChatMessage[]>();
  private unshownGen = currentWipeGeneration();
  private unshownFor(token: string): ChatMessage[] {
    if (this.unshownGen !== currentWipeGeneration()) { this.unshown.clear(); this.unshownGen = currentWipeGeneration(); }
    return this.unshown.get(token) ?? [];
  }
  private setUnshown(token: string, rows: ChatMessage[]): void {
    if (this.unshownGen !== currentWipeGeneration()) { this.unshown.clear(); this.unshownGen = currentWipeGeneration(); }
    if (rows.length) this.unshown.set(token, rows.slice(-SessionStore.CACHE_MAX_MSGS));
    else this.unshown.delete(token);
  }
  /** b75r3 (PR3-04): how many messages are waiting in memory for this chat to open */
  unshownCount(token: string): number { return this.unshownFor(token).length; }

  // b77z2 (Z-8): every cache read-modify-write runs under the chat's local cache lock (never the
  // ratchet chain), so a write from the App side (ensureOpenedAt, markShown, a receipt tick) can't
  // drop a row a sync pass has just cached: that row's key is spent, so a lost row is a message lost
  async cacheMessages(token: string, messages: ChatMessage[]): Promise<boolean> {
    return withLocalLock(cacheLock(token), () => this.cacheMessagesUnlocked(token, messages));
  }

  private async cacheMessagesUnlocked(token: string, messages: ChatMessage[]): Promise<boolean> {
    // b92 F-S1/F-S2 (settings sweep): honor the history dials at the WRITE
    // site. Nothing-at-Rest ('memory' mode) and "Keep conversation history
    // on this device" = Off must mean plaintext never lands on disk.
    // b172: returns false when the store REFUSES the write — the caller can
    // surface it; silence here is what made this bug look like deletion.
    if (await this.historyPersistBlocked()) {
      // b75r3 (audit PR3-04): the peer's messages not shown yet wait in memory (above)
      const cur = this.unshownFor(token);
      const have = new Set(cur.map((m) => m.id));
      const add = messages.filter((m) => !m.mine && !m.openedAt && !have.has(m.id));
      if (add.length) this.setUnshown(token, [...cur, ...add]);
      return true; // policy, not a failure
    }
    const list = await this.cacheRead(token);
    const ids = new Set(list.map((m) => m.id));
    const merged = [...list, ...messages.filter((m) => !ids.has(m.id))];
    return await this.cacheWrite(token, merged);
  }

  /** b75r2 (audit P-6): take rows cached early by syncChat back out when the ratchet save that
   *  should have followed them was refused (no plaintext beside a state that can still open it). */
  async uncacheMessages(token: string, ids: string[]): Promise<boolean> {
    if (!ids.length) return true;
    return withLocalLock(cacheLock(token), () => this.uncacheMessagesUnlocked(token, ids));
  }

  private async uncacheMessagesUnlocked(token: string, ids: string[]): Promise<boolean> {
    const drop = new Set(ids);
    if (await this.historyPersistBlocked()) {
      this.setUnshown(token, this.unshownFor(token).filter((m) => !drop.has(m.id))); // b75r3 (PR3-04)
      return true;
    }
    const list = await this.cacheRead(token);
    const keep = list.filter((m) => !drop.has(m.id));
    return keep.length === list.length ? true : await this.cacheWrite(token, keep);
  }

  /** b127: read the cached thread rows back (receipt sweep + cache
   * renders). b75r3 (PR3-04): plus the messages waiting in memory to be shown. */
  async cachedMessages(token: string): Promise<ChatMessage[]> {
    const rows = await this.cacheRead(token);
    const have = new Set(rows.map((m) => m.id));
    return [...rows, ...this.unshownFor(token).filter((m) => !have.has(m.id))];
  }

  /** b75r3 (audit PR3-02 / PR3-04): these rows are on screen now. Rows without a burn clock get
   *  it (it starts at display, never at decrypt), and messages waiting in memory are handed
   *  over to the screen and forgotten here. Returns the number of cached rows stamped. */
  async markShown(token: string, ids: string[]): Promise<number> {
    if (!ids.length) return 0;
    // b77g (hardening): joins a markShown already queued for this chat (ids merged, one lock job).
    // b77h (audit77g H-3 check): a joined call gets the merged job's count — no caller does
    // arithmetic with it (markEnvelopesDisplayed ignores it), so nothing is counted twice
    return this.coalesced(this.queuedShown, token, ids, cacheLock(token), (all) => this.markShownUnlocked(token, all));
  }

  private async markShownUnlocked(token: string, ids: string[]): Promise<number> {
    const set = new Set(ids);
    const waiting = this.unshownFor(token);
    if (waiting.some((m) => set.has(m.id))) this.setUnshown(token, waiting.filter((m) => !set.has(m.id)));
    const rows = await this.cacheRead(token);
    const now = Date.now();
    let stamped = 0;
    const next = rows.map((m) => {
      if (!set.has(m.id) || m.mine || m.openedAt) return m;
      stamped++;
      return { ...m, openedAt: now };
    });
    if (stamped) await this.cacheWrite(token, next);
    return stamped;
  }

  /** b198 CACHE-RENDER LOOPHOLE: anchor the VIEW burn clock at the HUMAN open
   *  for cache-rendered peer rows whose pendingBurn just flipped. Background
   *  decrypt stamps openedAt at MACHINE time — the countdown then ran while
   *  nobody was looking and the bubble could vanish without a human ever
   *  seeing it, while the relay copy survived. Called only for rows whose burn
   *  entry flipped this instant, so thread reopens never reset a running clock.
   *  Respects the cache-write policy (blocked stores skip silently). Returns
   *  the number of rows stamped. */
  async stampOpenedAt(token: string, ids: string[]): Promise<number> {
    if (!ids.length) return 0;
    return withLocalLock(cacheLock(token), () => this.stampOpenedAtUnlocked(token, ids));
  }

  private async stampOpenedAtUnlocked(token: string, ids: string[]): Promise<number> {
    const set = new Set(ids);
    const rows = await this.cacheRead(token);
    let stamped = 0;
    const next = rows.map((m) => {
      if (!set.has(m.id) || m.mine) return m;
      stamped++;
      return { ...m, openedAt: Date.now() };
    });
    if (stamped) await this.cacheWrite(token, next);
    return stamped;
  }

  // ---------- b172: chunked cache core ----------
  // Owner hardware finding (Oct 2, first real native-to-native test):
  // threads lost ALL history the instant they closed - "messages delete" -
  // while the same thread on web kept everything. Root cause: this cache
  // used to be ONE keychain item per token, and the iOS Keychain silently
  // refuses large values; KeychainStorage.set returns false on refusal and
  // every cache write site ignored the result. A thread with media
  // (screenshots carry uri + wrapped keys + iv) crossed the practical size
  // cliff and every write from then on failed invisibly: history lived in
  // RAM only. Fix: split the cache into bounded parts so no single item can
  // exceed a safe size, and surface write refusals through
  // onCacheWriteFailure so the UI can tell the user, not fake amnesia.

  /** Per-part ceiling: 60 KB of JSON and at most 100 rows. iOS Keychain's
   * practical per-item limit is far below web localStorage's ~5 MB; 60 KB
   * stays comfortably inside it with room for a large media row. */
  private static readonly CACHE_PART_BYTES = 61440;
  private static readonly CACHE_PART_ROWS = 100;
  private static readonly CACHE_MAX_MSGS = 500;

  /** b172: UI hook - fires once per failed cache write. Silent failure is
   *  how this bug masqueraded as "deleting messages" for a whole session. */
  onCacheWriteFailure?: (token: string) => void;

  private partKey(token: string, i: number): string {
    return `veil_msgcache_${tk(token)}_p${i}`;
  }

  /** b172: merge parts + the legacy monolithic key (one-time migration). */
  private async cacheRead(token: string): Promise<ChatMessage[]> {
    // audit VAR-01: one gate for reads as well as writes. With history off nothing stored is shown
    // (or written back by ensureOpenedAt / markShown); only the in-memory rows are
    if (await this.historyPersistBlocked()) return [];
    const out: ChatMessage[] = [];
    const ids = new Set<string>();
    for (let i = 0; i < 4096; i++) {
      const raw = await this.storage.get(this.partKey(token, i));
      if (raw == null) break;
      try {
        for (const m of JSON.parse(raw) as ChatMessage[]) {
          if (ids.has(m.id)) continue;
          ids.add(m.id); out.push(m);
        }
      } catch { break; } // corrupt part: keep what we have
    }
    const legacy = await this.storage.get(this.cacheKey(token));
    if (legacy != null) {
      try {
        for (const m of JSON.parse(legacy) as ChatMessage[]) {
          if (ids.has(m.id)) continue;
          ids.add(m.id); out.push(m);
        }
      } catch { /* corrupt legacy blob ignored */ }
    }
    return out;
  }

  /** b172: bounded parts. Returns false when the store refuses a write
   *  (KeychainStorage.set returns false on failure; void-style stores are
   *  treated as success). Retires the legacy key + stale parts ONLY after
   *  every part wrote clean, so a failed write never destroys old data. */
  private async cacheWrite(token: string, list: ChatMessage[]): Promise<boolean> {
    if (await this.historyPersistBlocked()) return true; // audit VAR-01: re-checked at the write itself
    const capped = list.slice(-SessionStore.CACHE_MAX_MSGS);
    const parts: string[] = [];
    let cur: ChatMessage[] = [];
    let bytes = 2;
    for (const m of capped) {
      const sz = JSON.stringify(m).length + 1;
      if (cur.length && (bytes + sz > SessionStore.CACHE_PART_BYTES || cur.length >= SessionStore.CACHE_PART_ROWS)) {
        parts.push(JSON.stringify(cur)); cur = []; bytes = 2;
      }
      cur.push(m); bytes += sz;
    }
    parts.push(JSON.stringify(cur));
    let ok = true;
    for (let i = 0; i < parts.length; i++) {
      const r = await this.storage.set(this.partKey(token, i), parts[i]);
      if (r === false) ok = false;
    }
    if (ok) {
      // retire the legacy monolithic key + parts left over from a bigger past
      const stale: string[] = [];
      if (await this.storage.get(this.cacheKey(token)) != null) stale.push(this.cacheKey(token));
      for (let i = parts.length; i < 4096; i++) {
        const k = this.partKey(token, i);
        if (await this.storage.get(k) == null) break;
        stale.push(k);
      }
      for (const k of stale) await secureRemove(this.storage, k);
    } else {
      console.log(`[veil-cache] write FAILED for session ${token.slice(0, 8)} - history is NOT being saved on this device`);
      try { this.onCacheWriteFailure?.(token); } catch { /* hook must never throw */ }
    }
    return ok;
  }

  // ---------- b127: per-token receipted-ids ledger ----------
  // Which PEER message ids this device has already acknowledged with a
  // read receipt. Without it, the b127 receipt sweep would re-receipt the
  // whole cached thread after every app restart (harmless for the peer,
  // but wasteful and it re-advances the send chain every launch).

  private receiptedKey(token: string): string {
    return `veil_receipted_${tk(token)}`;
  }

  async receiptedIds(token: string): Promise<Set<string>> {
    const raw = await this.storage.get(this.receiptedKey(token));
    try { return new Set(raw ? (JSON.parse(raw) as string[]) : []); } catch { return new Set(); }
  }

  async markReceiptedIds(token: string, ids: string[]): Promise<void> {
    if (!ids.length) return;
    const cur = await this.receiptedIds(token);
    for (const id of ids) cur.add(id);
    const arr = [...cur];
    await this.storage.set(this.receiptedKey(token), JSON.stringify(arr.slice(-1000)));
  }

  /** b160 K-4 fix: drop this token's receipted-ids ledger. Delivery-only
   * receipts (sent while the read-receipts dial was OFF, or by the pre-b129
   * sweep) can never upgrade to read:true — the peer's messages stay
   * 'delivered' forever. Clearing the ledger lets the open-thread sweep
   * re-acknowledge the cached backlog with the CURRENT dial state (one
   * bounded burst per thread per launch / toggle flip). */
  async clearReceiptedIds(token: string): Promise<void> {
    await this.storage.set(this.receiptedKey(token), JSON.stringify([]));
  }

  /** b69: persist read receipts into the cache — the 'read' tick otherwise
   *  vanished every time the thread was closed and reopened. */
  /** b74 (VAR-07): `by: 'mid'` for pairwise receipts — they name the header-derived
   *  message id only, never a relay-assigned id (a relay could set my message's envId
   *  to another message's mid). Group receipts still name relay envelope ids. */
  async markCachedRead(token: string, envIds: string[], by: 'mid' | 'env' = 'env'): Promise<void> {
    if (!envIds.length) return;
    return withLocalLock(cacheLock(token), () => this.markCachedReadUnlocked(token, envIds, by));
  }

  private async markCachedReadUnlocked(token: string, envIds: string[], by: 'mid' | 'env'): Promise<void> {
    const list = await this.cacheRead(token);
    const set = new Set(envIds);
    let changed = false;
    const out = list.map((m) => {
      if (m.read) return m;
      // b77z2 (Z-3): a pairwise read receipt is about MY messages only. A peer's receipt naming the
      // mid of its own message used to stamp openedAt on my received copy, which took that row for
      // a displayed one (a burn of a message nobody had seen here). The App's in-memory tick
      // already matched `m.mine` only; the cached tick now does too.
      if (by === 'mid' && m.mine !== true) return m;
      // b77m (audit VAR-53): and so is a GROUP read receipt ('env'): a member's receipt naming other
      // members' envelope ids used to mark those cached rows read and re-anchor their burn clock
      if (m.mine !== true) return m;
      if (by === 'mid' ? (!!m.mid && set.has(m.mid)) : ((m.envId && set.has(m.envId)) || set.has(m.id))) {
        changed = true;
        // b198 two-dial: the PEER's read receipt is the true human-open moment —
        // the sender's burn clock (UI countdown + local purge) anchors HERE,
        // matching the relay copy's burn-at-recipient-open
        return { ...m, read: true, openedAt: Date.now() };
      }
      return m;
    });
    if (changed) await this.cacheWrite(token, out);
  }

  /** b199: persist a reaction on the cached message whose id or envId is
   *  `target` (side 'mine' = this device's, 'peer' = the other person's). */
  async setCachedReaction(token: string, target: string, side: 'mine' | 'peer', emoji: string | null, by: 'mid' | 'local' = 'local'): Promise<void> {
    return withLocalLock(cacheLock(token), () => this.setCachedReactionUnlocked(token, target, side, emoji, by));
  }

  private async setCachedReactionUnlocked(token: string, target: string, side: 'mine' | 'peer', emoji: string | null, by: 'mid' | 'local'): Promise<void> {
    const list = await this.cacheRead(token);
    let changed = false;
    const out = list.map((m) => {
      // b74 (VAR-07): a peer's reaction names the header-derived mid only
      if (by === 'mid' ? m.mid !== target : (m.id !== target && m.envId !== target)) return m;
      changed = true;
      const reactions = { ...(m.reactions ?? {}) };
      if (emoji) reactions[side] = emoji; else delete reactions[side];
      return { ...m, reactions };
    });
    if (changed) await this.cacheWrite(token, out);
  }

  /** b123: bind a relay envelope id onto a locally-sent group bubble
   *  (own-echo path). Group sends don't learn their envelope id at submit
   *  time — the inbox poll echoes it back — and without the binding the
   *  b69 read-tick persistence (markCachedRead matches envId) can never
   *  reach these rows. */
  /** b77r1 (audit A-5): queued messages whose envelopes have now all gone out — drop their
   *  "Waiting to deliver" state and record the relay id */
  async markCachedDelivered(token: string, delivered: { id: string; envId?: string }[]): Promise<void> {
    if (!delivered.length) return;
    return withLocalLock(cacheLock(token), () => this.markCachedDeliveredUnlocked(token, delivered));
  }

  private async markCachedDeliveredUnlocked(token: string, delivered: { id: string; envId?: string }[]): Promise<void> {
    const by = new Map(delivered.map((d) => [d.id, d.envId]));
    const list = await this.cacheRead(token);
    let changed = false;
    const out = list.map((m) => {
      if (!by.has(m.id) || !m.queued) return m;
      changed = true;
      const { queued: _q, ...rest } = m;
      const envId = by.get(m.id);
      return envId ? { ...rest, envId } : rest;
    });
    if (changed) await this.cacheWrite(token, out);
  }

  async setCachedEnvId(token: string, localId: string, envId: string): Promise<void> {
    return withLocalLock(cacheLock(token), () => this.setCachedEnvIdUnlocked(token, localId, envId));
  }

  private async setCachedEnvIdUnlocked(token: string, localId: string, envId: string): Promise<void> {
    const list = await this.cacheRead(token);
    let changed = false;
    const out = list.map((m) => {
      if (m.id === localId && m.envId !== envId) { changed = true; return { ...m, envId }; }
      return m;
    });
    if (changed) await this.cacheWrite(token, out);
  }

  /** b72: stamp openedAt on cached rows that pre-date the field (or were
   *  cached before the thread was ever displayed) — "opened" means first
   *  rendered on this device, so the burn countdown starts from NOW for
   *  them. Returns the updated list. */
  async ensureOpenedAt(token: string): Promise<ChatMessage[]> {
    return withLocalLock(cacheLock(token), () => this.ensureOpenedAtUnlocked(token)); // b77z2 (Z-8)
  }

  private async ensureOpenedAtUnlocked(token: string): Promise<ChatMessage[]> {
    const list = await this.listMessages(token);
    const now = Date.now();
    let changed = false;
    const out = list.map((m) => {
      if (m.openedAt) return m;
      changed = true;
      return { ...m, openedAt: now };
    });
    if (changed) await this.cacheWrite(token, out);
    // b75r3 (audit PR3-04): messages that waited in memory (history off) are shown now, once.
    // They join the list with their clock started; they are never written to storage.
    const waiting = this.unshownFor(token);
    if (!waiting.length) return out;
    this.setUnshown(token, []);
    const have = new Set(out.map((m) => m.id));
    return [...out, ...waiting.filter((m) => !have.has(m.id)).map((m) => ({ ...m, openedAt: now }))];
  }

  /** b89 (owner burn test Sept 21 ~03:32 Bris: 5-minute window hit 0 and
   *  the messages stayed on screen AND in this cache): burn-after-open must
   *  actually DELETE expired rows from the local plaintext msgcache, not
   *  just render a "0m 00s" countdown next to them. A row is burned when
   *  openedAt + burnSeconds*1000 <= now. Rows without openedAt were never
   *  displayed on this device, so their clock hasn't started (ensureOpenedAt
   *  stamps them on the next open); they are kept until the unopened horizon
   *  (b75r3). Returns the purged ids so callers can prune in-memory state cheaply.
   *  b75r3 (audit PR3-02): the two dials, exactly. A message nobody has displayed lives
   *  until the unopened horizon (expireAfterSeconds after it was sent, when the relay drops
   *  its copy too); its burn clock starts only at display. syncChat no longer stamps
   *  openedAt at decrypt, and this purge never unlocks a relay burn: only a display marker
   *  (markEnvelopesDisplayed) does that. b77z2 (Z-2): the purge does record a display mark
   *  for a peer row it deletes because that row's burn window ran out (the window starts at
   *  display, so that is positive evidence the human saw it); the next pass burns its copy. */
  async purgeBurnedMessages(token: string, burnSeconds: number, opts: { queue?: 'await' | 'background'; decayUnread?: boolean } = {}): Promise<string[]> {
    if (!(burnSeconds > 0)) return [];
    // b77z (ZTE live test, the purge half of BURN-1): the App runs this every second while a burn
    // chat is open and on every list refresh, beside the sync passes. Its queue edit (read, filter,
    // write back) could land across a pass's queue write and drop the burns that pass had just
    // queued. The queue edit runs on the per-token chain that serializes syncChat and sends.
    // b77z2 (Z-1 / Z-8): only the queue edit. The cache part runs at once under the chat's local
    // cache lock (it never waits for a pass, or for a relay call a pass is stuck in), and the
    // queue edit is needed only when an unopened row passed its horizon. openChat passes
    // queue: 'background' and never waits on the chain; the default waits for the edit. (Never
    // call this from inside a chained job with the default.)
    // b77g (hardening): a purge already queued for this chat with the same burnSeconds (waiting for
    // the cache lock, not started) is shared — its queue edit too — so unawaited purges on a slow
    // keystore can't pile up lock jobs (or ratchet-chain edits)
    // b77h (audit77g H-3): every caller of a shared job is told the same `purged` list (they all
    // prune their own view by it), so the unread badge's decay is done INSIDE the job, once per job,
    // when any of its callers asked for it (`decayUnread`, the list refresh). Two refreshes joining
    // one purge used to lower the badge twice for the same rows.
    const qKey = `${token}:${burnSeconds}`;
    let entry = this.queuedPurges.get(qKey);
    if (!entry) {
      const mine: PurgeEntry = { job: undefined as unknown as PurgeJob, decayUnread: false };
      mine.job = withLocalLock(cacheLock(token), () => {
        if (this.queuedPurges.get(qKey) === mine) this.queuedPurges.delete(qKey); // started: no more joiners
        return this.purgeCacheUnlocked(token, burnSeconds);
      }).then(async ({ purged, unopenedGone }) => {
        // b90: burned rows can no longer be "waiting to read" — decay the badge by the same count
        if (mine.decayUnread && purged.length > 0) {
          try {
            const cur = await this.getUnread(token);
            if (cur > 0) await this.bumpUnread(token, -Math.min(cur, purged.length));
          } catch { /* the badge is best-effort */ }
        }
        return {
          purged,
          edit: unopenedGone.length ? serializeRatchetSend(token, () => this.dropUnopenedBurns(token, unopenedGone)) as Promise<unknown> : null,
        };
      });
      this.queuedPurges.set(qKey, mine);
      const clear = () => { if (this.queuedPurges.get(qKey) === mine) this.queuedPurges.delete(qKey); };
      mine.job.then(clear, clear);
      entry = mine;
    }
    if (opts.decayUnread) entry.decayUnread = true; // read once the cache step is done (joiners join before it starts)
    const { purged, edit } = await entry.job;
    if (edit) {
      if (opts.queue === 'background') void edit.catch(() => undefined);
      else await edit;
    }
    return purged;
  }

  private async purgeCacheUnlocked(token: string, burnSeconds: number): Promise<{ purged: string[]; unopenedGone: string[] }> {
    const list = await this.listMessages(token);
    const now = Date.now();
    // b198 (founder report, receipts battery): OWN copies whose burn clock was
    // anchored to the peer's READ RECEIPT never purged when the recipient has
    // read receipts OFF — no receipt ever lands, so the clock never starts and
    // the sent bubble sat in the thread forever. The anchor now ALSO honors the
    // relay envelope's real lifetime: an own copy purges at send + the
    // unopened horizon (the same moment the relay's sweeper deletes the
    // envelope) — receipts on or off, the sender's copy never outlives the
    // relay's copy.
    let horizonMs = 0;
    try {
      const sealed = (await this.load(token)) as { expireAfterSeconds?: number } | null;
      horizonMs = (Number(sealed?.expireAfterSeconds) || 86400) * 1000;
    } catch { horizonMs = 86400 * 1000; }
    const keep: ChatMessage[] = [];
    const purged: string[] = [];
    const unopenedGone: string[] = [];
    // b77z2 (Z-2): peer rows purged because their burn window (which starts at display) ran out
    const shownGone: string[] = [];
    // b77m (audit VAR-54): a received row's horizon runs from when THIS phone received it (rcvAt), not from
    // the time the peer wrote into the message (ts): a peer could back-date its own message so it was purged
    // unseen and its relay burn dropped. Rows cached by older builds (no rcvAt) keep the old rule.
    const anchorOf = (m: ChatMessage): number => (!m.mine && Number.isFinite(m.rcvAt) && (m.rcvAt as number) > 0 ? (m.rcvAt as number) : (m.ts ? Date.parse(m.ts) : NaN));
    const pastHorizon = (m: ChatMessage) => { const a = anchorOf(m); return Number.isFinite(a) && a + horizonMs < now; };
    // b77p (audit VAR-03): the SENDER's copy follows the burn timer on its own, receipts or not. Its
    // burn clock starts at send (ts, stamped by this phone's own clock when it sent the row; an
    // earlier openedAt would win, but display and receipts come after send), so with read receipts
    // off (the recommended setup), a receipt the relay withholds, or a peer who never opens the
    // message, the sent plaintext still goes burnSeconds after it was sent — and at send + the
    // horizon in any case (b198). A receipt no longer restarts or extends the sender's clock.
    const ownGone = (m: ChatMessage): boolean | null => {
      const sent = m.ts ? Date.parse(m.ts) : NaN;
      const starts = [sent, m.openedAt ?? NaN].filter((v) => Number.isFinite(v) && v > 0);
      if (!starts.length) return null; // no anchor at all (a legacy row): the rules below
      return Math.min(...starts) + burnSeconds * 1000 <= now || (Number.isFinite(sent) && sent + horizonMs < now);
    };
    for (const m of list) {
      const own = m.mine && !(m as { systemNote?: boolean }).systemNote ? ownGone(m) : null;
      // systemNote rows are UI artifacts, not burnable chat content
      if ((m as { systemNote?: boolean }).systemNote) keep.push(m);
      else if (own !== null) { if (own) purged.push(m.id); else keep.push(m); }
      // b75r3 (PR3-02): never displayed here — kept until the unopened horizon, then dropped
      // (the relay's copy expires at the same moment; nothing is burned for it)
      else if (!m.openedAt) { if (!m.mine && pastHorizon(m)) { purged.push(m.id); unopenedGone.push(m.id); } else keep.push(m); }
      else if (m.openedAt + burnSeconds * 1000 > now) keep.push(m);
      else if (m.mine && m.ts && Date.parse(m.ts) + horizonMs < now) purged.push(m.id); // b198: own copy = the envelope's lifetime
      else {
        purged.push(m.id);
        // b77z2 (Z-2): positive evidence of display. Since b75r3 a peer row gets openedAt only when
        // it is displayed (markShown, stampOpenedAt, ensureOpenedAt at chat open). A row that also
        // carries `read` had openedAt stamped by a peer's receipt (Z-3, fixed in markCachedRead) —
        // that proves nothing, so it is left out (its relay copy lives to its expiry).
        if (!m.mine && !m.read) shownGone.push(m.envId ?? m.id);
      }
    }
    // b75r3 (PR3-04): messages waiting in memory (history off) follow the same unopened horizon
    const waiting = this.unshownFor(token);
    const waitingGone = waiting.filter(pastHorizon).map((m) => m.id);
    if (waitingGone.length) {
      this.setUnshown(token, waiting.filter((m) => !waitingGone.includes(m.id)));
      purged.push(...waitingGone); unopenedGone.push(...waitingGone);
    }
    // b77z2 (Z-2): the evidence is on storage before the row goes (the next sync pass burns the
    // relay copy of a displayed message whose display flip was lost; the absent-row inference that
    // used to do this is gone — an absent row also covers rows nobody saw)
    if (shownGone.length) await this.addDisplayedMarks(token, shownGone).catch(() => false);
    if (purged.length > waitingGone.length) await this.cacheWrite(token, keep);
    return { purged, unopenedGone };
  }

  /** b75r3 (audit PR3-02): the purge never unlocks a relay burn. b198 flipped every purged
   *  row's awaiting-display entry to displayed:true on the theory that a completed countdown
   *  proves display, but background decrypt stamped openedAt at MACHINE time, so a message
   *  opened in the background was purged here and its relay copy burned before anyone saw it.
   *  Display markers (markEnvelopesDisplayed) unlock a burn, and (b77z2, Z-2) the display marks
   *  the purge records for rows displayed before it. An entry for a never-displayed message past
   *  the horizon is dropped: the relay copy is gone. Runs on the per-token ratchet chain. */
  private async dropUnopenedBurns(token: string, unopenedGone: string[]): Promise<void> {
    const q = await this.pendingBurns(token);
    const gone = new Set(unopenedGone);
    const rest = q.filter((p) => !(p.displayed === false && gone.has(p.id)));
    if (rest.length !== q.length) await this.setPendingBurns(token, rest);
  }

  async listMessages(token: string): Promise<ChatMessage[]> {
    return await this.cacheRead(token);
  }

  async listTokens(): Promise<string[]> {
    const keys = await this.storage.keys('veil_rk_');
    // b77m (audit VAR-26): only keys a well-formed token makes (a "veil_rk_wrap_<t>" key has an "_")
    return keys.filter((k) => !k.startsWith('veil_rk_wrap_')).map((k) => k.slice('veil_rk_'.length)).filter(isStoreToken);
  }
}
