/**
 * @veil/device — b77 sealed sender (1:1): mailboxes instead of the session row.
 *
 * Once a 1:1 chat is set up, every send goes to the PEER's inbound mailbox with the send
 * capability, and every receive reads MY inbound with the read capability — anonymously
 * (VeilRelay.invokeAnon: no Authorization, no cookies, no session token, no write secret, no
 * sender tag). The relay learns "anonymous mailbox X received an envelope", never who sent it.
 *
 * Capabilities come from the handshake root (crypto-core/delivery.ts) and live in the chat's
 * sealed record (`delivery`), so they move with the §7 move. Per-chat runtime state (when to
 * open my inbound, whether it is open, the fetch cursor, the wake reference) lives in
 * SessionStore.mboxState.
 *
 * Opening: each side opens only its OWN inbound, after a random 1–10 s delay (setMailboxOpenDelay
 * makes it injectable for tests). b77p (audit 2 VAR-01): with a BLIND-SIGNED open token (crypto-core
 * open-token.ts) — the responder's blinded value rides its join, the initiator's the gate `issue`
 * before its open — instead of a ticket whose hash the join named, so the relay can't tie the open to
 * the join by any value. Until the peer's inbound is open a send gets 425; the already-encrypted
 * envelope waits in the chat's outbox and the next pass resends it.
 *
 * Wakes (b77p): this phone seals its own push target into its own inbound (crypto-core wake.ts,
 * mailboxPush {wake}) under the chat's wake capability; the peer presents that capability with each
 * submit. No account row lists anything about a mailbox (b77's push_refs are gone).
 */
import {
  capHash, parseChatDelivery, LegacySessionError, type ChatDelivery,
} from '../../crypto-core/src/index';
import { parseOpenKey, blindOpenToken, reblind, finishOpenToken, isOpenToken, isOpenBlind, type OpenKey, type OpenBlind, type OpenToken } from '../../crypto-core/src/open-token';
import { sealWakeBox, wakeFingerprint, isWakeTarget, type WakeTarget } from '../../crypto-core/src/wake';
import { relayStatusOf, type SealedSubmission, type VeilRelay } from './relay';
import { cleanRelayText, relayErrorText, relayDetailOf } from './relay-errors'; // b77m (audit VAR-20)
import { OUTBOX_MAX, type SessionStore, type MboxState, type OutboxItem } from './session-store';
import { chatGoneAnswers, noteGoneAnswer, clearGoneAnswers, goneAnswersConfirmed, outGoneKey } from './session-liveness';
import { currentWipeGeneration, unwrapPinned } from './wipe-generation'; // b77q (audit 3 CR-1)
import { secureRandomUnit } from './secure-random';

/** the relay's clamp for a mailbox's TTL cap: [60 s, 7 days] */
export const MAILBOX_TTL_CAP_MIN_S = 60;
export const MAILBOX_TTL_CAP_MAX_S = 7 * 24 * 3600;
/** the open delay window (ms). b77k (IP77-7, owner decision): 1–10 s (was 5–120 s, which held a new chat's
 *  first message up to two minutes); still spreads the opens apart from the handshake */
export const MAILBOX_OPEN_DELAY_MIN_MS = 1_000;
export const MAILBOX_OPEN_DELAY_MAX_MS = 10_000;
/** after a fetch says "never opened" (425) on a mailbox this phone thought open, retry the open after this */
const REOPEN_AFTER_MS = 30_000;
/** b77r1 (audit A-5): "bad or used ticket" (403) answers to my open are retried with a doubling
 *  delay (30 s, 1 min, 2 min, … at most 5 min). While my inbound has never opened, this many
 *  answers spread over at least this long mean the chat can't finish setting up. */
export const OPEN_REFUSED_ANSWERS = 5;
export const OPEN_REFUSED_SPAN_MS = 10 * 60_000;
const OPEN_REFUSED_RETRY_MAX_MS = 5 * 60_000;
/** b77r1 (audit A-5): the relay keeps an open ticket 7 days (+ under an hour). An envelope still
 *  waiting for the peer's inbound well after that will never go: the peer can't open it any more. */
export const PEER_OPEN_GIVE_UP_MS = 7 * 24 * 3600_000 + 2 * 3600_000;

/** b77p (audit 2 VAR-01): where this phone's wakes go, as the app knows it now: a target, 'off' (push switched
 *  off: clear the boxes), or null (unknown — decoy mode, no token yet: change nothing) */
export type WakeTargetAnswer = WakeTarget | 'off' | null;
let wakeTargetProvider: ((store: object) => Promise<WakeTargetAnswer>) | null = null;
/** the app's hook (src/notifications.ts currentWakeTarget); null removes it. b77t2 (CL-8): it is asked FOR A STORE
 *  (the pass's own SessionStore, unwrapPinned), so the answer is decided by whose chat the pass is binding, not by
 *  which account is on screen when it asks: a decoy pass still in flight when the real code is entered must never
 *  get the real push target. The app answers 'off' for any store but the real account's (clears a stray binding). */
export function setWakeTargetProvider(fn: ((store: object) => Promise<WakeTargetAnswer>) | null): void { wakeTargetProvider = fn; }
/** b77u (audit 6 W6): this phone's wake key (64 hex), kept in its own storage; a wipe deletes it with every veil_ record */
export const WAKE_KEY_STORAGE = 'veil_wake_key_v1';
/** b77u (audit 6 W6): `target` with this phone's wake key added (made on first use). The relay keys the per-address wake
 *  ceiling on (address, key), so whoever knows only the push token can't use up this phone's wakes. A storage failure
 *  gives the target without a key (the old shared ceiling), never no wakes. */
export async function withWakeKey<T extends { t: string } | null>(target: T, storage: { get(k: string): Promise<string | null>; set(k: string, v: string): Promise<unknown> }): Promise<T> {
  if (!target) return target;
  try {
    let k = await storage.get(WAKE_KEY_STORAGE);
    if (!k || !/^[0-9a-f]{64}$/.test(k)) {
      k = [...crypto.getRandomValues(new Uint8Array(32))].map((b) => b.toString(16).padStart(2, '0')).join('');
      const ok = await storage.set(WAKE_KEY_STORAGE, k);
      if (ok === false) return target;
    }
    return { ...target, k };
  } catch { return target; }
}

/**
 * b77q (audit 3 CR-1): the relay's open-token issuer key is PINNED. b77p kept it in memory until an hour before the
 * relay's own `until`, which the relay chose freely (0 was accepted), every restart forgot it, and a 409 naming the
 * open key dropped it — so a tagging relay could hand every join its own key and tie each mailbox open to its join.
 * Now:
 *  - a key this phone takes must issue for at least OPEN_KEY_MIN_REMAINING_MS more (the relay's `until`); the relay
 *    serves its current key, which issues for 7 days from its rotation, so only a phone with no pin (a new install,
 *    after a wipe) or whose pin ran out can meet a key in its last hour: it waits for the rotation;
 *  - once taken, the key is kept until max(`until`, taken + OPEN_KEY_MIN_PIN_MS) (at most OPEN_KEY_MAX_PIN_MS):
 *    nothing is fetched before then, whatever the relay says, so a short `until` can't rotate this phone's key;
 *  - the pin (kid, n, e, until, when taken) is kept in the phone's store (SessionStore.openKeyPin: a `veil_` record,
 *    so every wipe removes it), so a restart doesn't forget it;
 *  - only a REFUSAL of the pinned key by the relay (409 "open key expired", noteOpenKeyRefused — an honest relay
 *    answers that after its rotation when the pin outlived `until`, or after a test relay's restart lost its
 *    ephemeral key) lets the phone fetch again before the pin's end, and then only if the pinned key was taken at
 *    least OPEN_KEY_REFETCH_MIN_MS ago (a switch is said loudly in the log). So a relay can move a phone to another
 *    key at most once a day, never per join. The L1 re-issue (a 403 to an open drops the token, the next pass asks
 *    gate `issue` again) asks under the pinned key: it can't make the phone take another one.
 *  - b77q review (CR-1 residual): one exception to the day's wait. A phone with no pin can take the relay's key in
 *    its last day (1-24 h of issuing left) and pin it for 6 days; the honest relay's rotation then refused it and new
 *    chats failed for up to ~23 h. So a pin that was short-lived (its `until` less than OPEN_KEY_REFETCH_MIN_MS after
 *    it was taken), refused at or after that `until` (OPEN_KEY_SKEW_MS of clock slack), may switch at once — but only
 *    to a key that issues for at least OPEN_KEY_MIN_PIN_MS more (an honest relay's key is under a day old then, so
 *    it has 6-7 days left). The key it switches to is long-lived, so it never qualifies again: a relay gets at most
 *    ONE such switch per pin taken afresh, never per join.
 * Not closed (spec §12.19.2): a relay can still give each PHONE its own key; publishing keys (roadmap b78) does that.
 */
export const OPEN_KEY_MIN_REMAINING_MS = 3600_000;
export const OPEN_KEY_MIN_PIN_MS = 6 * 86400_000;
export const OPEN_KEY_MAX_PIN_MS = 8 * 86400_000;
export const OPEN_KEY_REFETCH_MIN_MS = 24 * 3600_000;
/** b77q review (CR-1 residual): how far the phone's clock may trail the relay's when judging "refused after `until`" */
export const OPEN_KEY_SKEW_MS = 10 * 60_000;
let openKeyRefetchMinMs = OPEN_KEY_REFETCH_MIN_MS;
/** tests (or a build pointed at a test relay that restarts often): how long a pinned key is kept before a refusal
 *  may replace it (null restores OPEN_KEY_REFETCH_MIN_MS) */
export function setOpenKeyRefetchMinMs(ms: number | null): void { openKeyRefetchMinMs = ms ?? OPEN_KEY_REFETCH_MIN_MS; }

/** b77q (audit 3 CR-1): the relay refused the pinned key less than OPEN_KEY_REFETCH_MIN_MS after it was taken —
 *  nothing is fetched until then (the caller tries again on a later pass) */
export class OpenKeyPinnedError extends Error {
  constructor() { super('The relay refused this phone\'s open-token key too soon after the last change — trying again later.'); this.name = 'OpenKeyPinnedError'; }
}
/** what SessionStore keeps for the pin */
type OpenKeyPinRecord = { v: 1; kid: string; n: string; e: string; until: number; at: number; pinUntil: number; refused?: number };
type OpenKeyPinStore = Partial<Pick<SessionStore, 'openKeyPin' | 'setOpenKeyPin'>>;
type OpenKeySlot = { gen: number; pin: OpenKeyPinRecord | null; key: OpenKey | null; written: boolean };
/** the pin in memory, valid for the wipe generation it was read or taken in (after a wipe the next use reads the
 *  (wiped) store again). b77t2 (CL-7): ONE PER STORE (each account's own SessionStore, unwrapPinned), not one per
 *  process — a decoy session's joins must neither use nor write the real account's pin, nor the other way round.
 *  A call with no store (tests) uses its own slot. */
let openKeyMems = new WeakMap<object, OpenKeySlot>();
let openKeyNoStore: OpenKeySlot | null = null;
/** every store used, and those whose pin forgetOpenKey dropped (removed from the store at its next use) */
const openKeySeen = new Set<object>();
const openKeyPurge = new Set<object>();

function isPinRecord(v: unknown): v is OpenKeyPinRecord {
  const p = v as OpenKeyPinRecord | null;
  return !!p && typeof p === 'object' && p.v === 1 && typeof p.kid === 'string' && typeof p.n === 'string' && typeof p.e === 'string'
    && [p.until, p.at, p.pinUntil].every((x) => Number.isSafeInteger(x) && x > 0) && (p.refused === undefined || Number.isSafeInteger(p.refused));
}
async function openKeySlot(store: OpenKeyPinStore | null | undefined): Promise<OpenKeySlot> {
  const gen = currentWipeGeneration();
  if (!store?.openKeyPin) {
    if (!openKeyNoStore || openKeyNoStore.gen !== gen) openKeyNoStore = { gen, pin: null, key: null, written: false };
    return openKeyNoStore;
  }
  const id = unwrapPinned(store as object);
  let slot = openKeyMems.get(id);
  if (!slot || slot.gen !== gen) { slot = { gen, pin: null, key: null, written: false }; openKeyMems.set(id, slot); }
  openKeySeen.add(id);
  if (openKeyPurge.has(id)) {
    openKeyPurge.delete(id);
    await store.setOpenKeyPin?.(null).catch(() => undefined);
  } else if (!slot.pin) {
    let rec: unknown = null;
    try { rec = JSON.parse((await store.openKeyPin()) ?? 'null'); } catch { rec = null; }
    if (isPinRecord(rec)) {
      const key = await parseOpenKey({ kid: rec.kid, n: rec.n, e: rec.e, until: rec.until }).catch(() => null);
      if (key) { slot.pin = rec; slot.key = key; slot.written = true; }
    }
  }
  if (slot.pin && !slot.written) await savePin(store, slot);
  return slot;
}
async function savePin(store: OpenKeyPinStore | null | undefined, slot: OpenKeySlot): Promise<void> {
  slot.written = false;
  if (!store?.setOpenKeyPin) return;
  try { if (await store.setOpenKeyPin(slot.pin ? JSON.stringify(slot.pin) : null)) slot.written = true; } catch { /* kept in memory; written at the next use */ }
}
/** tests: forget the pin — in memory, and (at its next use) in every store this process used */
export function forgetOpenKey(): void {
  for (const id of openKeySeen) openKeyPurge.add(id);
  openKeySeen.clear();
  openKeyMems = new WeakMap();
  openKeyNoStore = null;
}
/** tests: forget the in-memory pin only, as a restart does (the stores keep theirs) */
export function dropOpenKeyMemory(): void { openKeyMems = new WeakMap(); openKeyNoStore = null; openKeyPurge.clear(); }

/** b77q (audit 3 CR-1): did the relay refuse a request because of its issuer key ("Open key expired — fetch it
 *  again", 409 {open_key_stale})? Only a hint: the pin decides what it may lead to (noteOpenKeyRefused) */
export function isOpenKeyRefusal(e: unknown): boolean {
  if (relayStatusOf(e) !== 409) return false;
  const data = (e as { data?: unknown } | null)?.data as { open_key_stale?: unknown; data?: { open_key_stale?: unknown } } | null | undefined;
  return data?.open_key_stale === true || data?.data?.open_key_stale === true || /open key/i.test(relayDetailOf(e));
}
/** b77q (audit 3 CR-1): the relay refused a request made under issuer key `kid`. If that is the pinned key, the next
 *  currentOpenKey may fetch again (and switch, if the pin is at least OPEN_KEY_REFETCH_MIN_MS old). The pin stays. */
export async function noteOpenKeyRefused(store: OpenKeyPinStore | null | undefined, kid: string, now = Date.now()): Promise<void> {
  const slot = await openKeySlot(store);
  if (!slot.pin || slot.pin.kid !== kid || slot.pin.refused !== undefined) return;
  slot.pin = { ...slot.pin, refused: now };
  console.warn(`[veil-open-key] the relay refused this phone's open-token key ${kid} before its end`);
  await savePin(store, slot);
}

type OpenKeyRelay = Partial<Pick<VeilRelay, 'openKey'>>;
/** b77q (audit 3 CR-1): the pinned issuer key, or (no pin, the pin ran out, or the relay refused it) the relay's
 *  key, checked and pinned. Throws when the relay's key can't be taken (too close to its end, malformed) or the
 *  relay refused the pin too soon after it was taken (OpenKeyPinnedError). */
export function currentOpenKey(relay: OpenKeyRelay, store?: OpenKeyPinStore | null, now = Date.now()): Promise<OpenKey> {
  // one at a time: two joins at once must not each fetch (and pin) a key of the relay's choosing
  const run = openKeyLock.then(() => currentOpenKeyLocked(relay, store, now));
  openKeyLock = run.catch(() => undefined);
  return run;
}
let openKeyLock: Promise<unknown> = Promise.resolve();
async function currentOpenKeyLocked(relay: OpenKeyRelay, store: OpenKeyPinStore | null | undefined, now: number): Promise<OpenKey> {
  const slot = await openKeySlot(store);
  const pin = slot.pin && slot.key ? slot.pin : null;
  // b77q review (CR-1 residual): a short-lived pin the relay refused after its own `until` (an honest rotation)
  let rotatedSwitch = false;
  if (pin && now < pin.pinUntil) {
    if (pin.refused === undefined) return slot.key as OpenKey;
    if (now - pin.at < openKeyRefetchMinMs) {
      rotatedSwitch = pin.until - pin.at < openKeyRefetchMinMs && pin.refused + OPEN_KEY_SKEW_MS >= pin.until && now + OPEN_KEY_SKEW_MS >= pin.until;
      if (!rotatedSwitch) throw new OpenKeyPinnedError();
    }
  }
  if (!relay.openKey) throw new Error('This relay has no open key');
  const r = await relay.openKey();
  const d = (r.data as { data?: unknown } | null)?.data ?? r.data;
  const key = await parseOpenKey(d);
  if (pin && key.kid === pin.kid) {
    // the same key again: kept (a later `until` may lengthen the pin, nothing shortens it); the refusal is forgotten
    slot.pin = { ...pin, until: key.until, pinUntil: Math.max(pin.pinUntil, Math.min(key.until, now + OPEN_KEY_MAX_PIN_MS)), refused: undefined };
    slot.key = key;
    await savePin(store, slot);
    return key;
  }
  if (key.until < now + OPEN_KEY_MIN_REMAINING_MS) throw new Error('The relay\'s open-token key is about to expire, so it was not used — trying again later.');
  // b77q review (CR-1 residual): the early switch only to a key that issues for 6 days or more (the old pin stays)
  if (rotatedSwitch && key.until < now + OPEN_KEY_MIN_PIN_MS) throw new OpenKeyPinnedError();
  if (pin && now < pin.pinUntil) {
    console.warn(`[veil-open-key] SWITCHING open-token key ${pin.kid} -> ${key.kid} before its end: the relay refused it (at most once every ${Math.round(openKeyRefetchMinMs / 3600_000)} h)`);
  }
  slot.pin = { v: 1, kid: key.kid, n: (d as { n: string }).n, e: (d as { e: string }).e, until: key.until, at: now,
    pinUntil: Math.min(Math.max(key.until, now + OPEN_KEY_MIN_PIN_MS), now + OPEN_KEY_MAX_PIN_MS) };
  slot.key = key;
  await savePin(store, slot);
  return key;
}
/** b77p: a fresh blinded open token for a join (responder) — what to keep and what to send. null only for a relay
 *  client without openKey (a test double); a real relay's failure throws (the accept is retried).
 *  b77q (audit 3 CR-1): `store` (the chat's SessionStore) holds the pinned issuer key */
export async function prepareOpenBlind(relay: OpenKeyRelay, store?: OpenKeyPinStore | null): Promise<{ blind: OpenBlind; open_blind: string; open_kid: string } | null> {
  if (!relay.openKey) return null;
  return blindOpenToken(await currentOpenKey(relay, store));
}
/** b77p: the same blinded value again (a re-sent join), or null when the key moved on */
export async function reblindForJoin(relay: OpenKeyRelay, blind: unknown, store?: OpenKeyPinStore | null): Promise<{ open_blind: string; open_kid: string } | null> {
  if (!isOpenBlind(blind)) return null;
  const key = await currentOpenKey(relay, store).catch(() => null);
  if (!key || key.kid !== blind.kid) return null;
  return reblind(key, blind);
}
/** b77p: the open_sig in a gate answer (join: inside `session`; issue: top level) */
export function openSigOf(resp: unknown): string | null {
  const r = resp as { data?: unknown } | null;
  const d = (r?.data as { data?: unknown } | null)?.data ?? r?.data;
  const o = d as { open_sig?: unknown; session?: { open_sig?: unknown } } | null;
  const sig = o?.open_sig ?? o?.session?.open_sig;
  return typeof sig === 'string' && sig ? sig : null;
}
/** b77p: after the join — keep the unblinded token for the open (or the blind, for gate `issue` to recover a
 *  lost answer). Never throws. */
export async function adoptJoinOpenSig(relay: OpenKeyRelay, sessions: MboxStore, token: string, blind: OpenBlind, resp: unknown): Promise<void> {
  try {
    const sig = openSigOf(resp);
    if (sig) {
      const key = await currentOpenKey(relay, sessions);
      const tok = await finishOpenToken(key, blind, sig);
      await sessions.setMboxState?.(token, { openToken: tok, openBlind: undefined });
      return;
    }
  } catch (e) { console.log(`[veil-mbox] #${token.slice(0, 4)}: open signature not usable (${(e as Error).message ?? e})`); }
  try { await sessions.setMboxState?.(token, { openBlind: blind }); } catch { /* the next pass makes a fresh one */ }
}

function secureUniform(maxExclusive: number): number {
  const buf = new Uint32Array(1);
  crypto.getRandomValues(buf);
  return buf[0] % maxExclusive;
}

/** b77m (audit VAR-40): a uniform [0, 1) from the platform CSPRNG (53 random bits) — the privacy delays
 *  (mailbox ends, opens) use this, never Math.random */
export { secureRandomUnit } from './secure-random'; // b77t (audit 5 L-28): moved so relay.ts can use it

const defaultOpenDelay = (): number => MAILBOX_OPEN_DELAY_MIN_MS + secureUniform(MAILBOX_OPEN_DELAY_MAX_MS - MAILBOX_OPEN_DELAY_MIN_MS + 1);
let openDelay: () => number = defaultOpenDelay;

/**
 * b77u (audit 6 U-M7, IH M3 / crypto F-1): the setup calls that name the RENDEZVOUS token (gate `issue` for my open
 * token, gate `end`) used to go out in one pass with the open that names my inbound mailbox (issue -> open -> end,
 * milliseconds apart), so a relay logging requests tied the "anonymous" inbound to the rendezvous row and through it
 * to both Vardum IDs. Now each step has its OWN independent CSPRNG delay of SETUP_STEP_DELAY_MIN_MS..MAX_MS:
 *   issue  at issueAt   (a timer task of its own; no other request of this chat goes with it)
 *   open   at openStepAt = issue's answer + delay  (the next sync pass after it, with this chat's mailbox requests)
 *   end    at rvEndAt  = the open + delay           (a timer task of its own again)
 * The pending times live in the chat's sealed mailbox record (MboxState), so a restart resumes them; a step found
 * overdue when a new process first arms it gets a fresh delay (a restart never fires the backlog back to back). The
 * starter can send at once (its envelopes go to the peer's inbound); the peer's replies arrive once mine opens.
 */
// b77u2 phone test (owner, 5 Nov): 15 s-2 min made a reply to the chat's starter wait about 2.5 min on real phones
// ("already too long"); owner's choice (5 Nov): each step 5-30 s, so a first reply waits about 10 s to 1 minute, and the waiting bubble says why.
export const SETUP_STEP_DELAY_MIN_MS = 5_000;
export const SETUP_STEP_DELAY_MAX_MS = 30_000;
const defaultStepDelay = (): number => SETUP_STEP_DELAY_MIN_MS + secureUniform(SETUP_STEP_DELAY_MAX_MS - SETUP_STEP_DELAY_MIN_MS + 1);
let stepDelayOverride: (() => number) | null = null;
/** b77u (U-M7): tests that call setMailboxOpenDelay(fn) keep the old one-pass flow (the steps run inside the pass,
 *  each after `fn()`); the app never calls it (repro/b77u_device.test.ts checks), so it always uses the timers */
let inlineSteps = false;
/** tests: replace the random 1–10 s open delay (null restores it). b77u (U-M7): a test delay also runs the
 *  rendezvous steps inside the sync pass, delayed by the same function (the old flow, for the protocol harnesses) */
export function setMailboxOpenDelay(fn: (() => number) | null): void { openDelay = fn ?? defaultOpenDelay; inlineSteps = !!fn; }
/** tests: replace the setup steps' random delay (null restores SETUP_STEP_DELAY_MIN_MS..MAX_MS) */
export function setSetupStepDelay(fn: (() => number) | null): void { stepDelayOverride = fn; }
function stepDelay(): number { return Math.max(0, (stepDelayOverride ?? (inlineSteps ? openDelay : defaultStepDelay))()); }
type SetupTimer = (run: () => void, ms: number) => unknown;
const defaultSetupTimer: SetupTimer = (run, ms) => {
  const t = setTimeout(run, Math.max(0, ms));
  (t as { unref?: () => void }).unref?.(); // never keeps a test process alive
  return t;
};
let setupTimer: SetupTimer = defaultSetupTimer;
/** tests: replace the timer that runs a setup step (null restores setTimeout) */
export function setSetupTimer(fn: SetupTimer | null): void { setupTimer = fn ?? defaultSetupTimer; }
/** a chat whose sync pass is running: its timer step waits a little (it never rides along with the pass) */
const passesInFlight = new Map<string, number>();
const storeIds = new WeakMap<object, number>();
let nextStoreId = 1;
function jobKeyOf(sessions: object, token: string): string {
  const id = unwrapPinned(sessions);
  let n = storeIds.get(id);
  if (n === undefined) { n = nextStoreId++; storeIds.set(id, n); }
  return `${n}|${token}`;
}
/** the armed timer per chat and step (its due time), and every chat+step armed in this process */
const setupJobs = new Map<string, number>();
const setupArmedOnce = new Set<string>();
/** b77u (U-M7): the armed timer steps, "<store>|<token>|<step>" (tests) */
export function pendingSetupSteps(): string[] { return [...setupJobs.keys()]; }
/** tests: forget the armed timers, as a restart does (the stored due times stay) */
export function forgetSetupTimers(): void { setupJobs.clear(); setupArmedOnce.clear(); }
export type SetupStep = 'issue' | 'end';
/** how long a timer step waits when it meets this chat's sync pass (CSPRNG, 5–30 s) */
const passBusyDelay = (): number => 5_000 + secureUniform(25_001);

/** The relay calls a sealed relay client must have (a test double implements just these). */
export type SealedRelay = Pick<VeilRelay, 'mailboxOpen' | 'sealedSubmit' | 'sealedFetch' | 'sealedBurn' | 'sealedEnd' | 'mailboxPush' | 'mailboxVerify'>
  & Partial<Pick<VeilRelay, 'sessionEnd' | 'sessionEndAnon' | 'sealedTurn' | 'turnGrant' | 'turnApprove' | 'sealedFile' | 'sealedUpload' | 'openKey' | 'sessionIssue'>>;
type MboxStore = Pick<SessionStore, 'load'> & Partial<Pick<SessionStore, 'mboxState' | 'setMboxState' | 'outbox' | 'setOutbox' | 'listTokens' | 'markCachedDelivered' | 'cachedDeliveries' | 'openKeyPin' | 'setOpenKeyPin'>>;

/** this chat's delivery capabilities, or null (a chat sealed before b77) */
export function chatDelivery(sealed: unknown): ChatDelivery | null {
  return parseChatDelivery((sealed as { delivery?: unknown } | null)?.delivery);
}

/** this chat's delivery capabilities; a 1:1 chat without them predates b77 and has ended
 *  (the clean break: "This chat used an older security protocol and has ended. Start a new chat.") */
export function requireDelivery(sealed: unknown): ChatDelivery {
  const d = chatDelivery(sealed);
  if (!d) throw new LegacySessionError();
  return d;
}

/** A finished 1:1 chat sealed before b77 (no delivery capabilities): it can't send or receive
 *  any more; the app shows the clean-break "start a new chat" notice. Pending handshakes (not
 *  ready) are not pre-sealed: their capabilities come when they complete. b77p round 2 (review L3): neither is a chat
 *  the peer ended (SessionStore.dropRatchetKeys removed its delivery and set keysDropped; it stays ready) — the app
 *  labelled it an old-protocol chat. */
export function isPreSealedChat(sealed: unknown): boolean {
  const s = sealed as { ready?: unknown; keysDropped?: unknown } | null;
  return !!s && s.ready === true && !(Number(s.keysDropped) > 0) && !chatDelivery(s);
}

/** the chat's own TTL dial as the inbound's cap, clamped to what the relay accepts */
export function mailboxTtlCap(ttlSeconds: number): number {
  const t = Math.floor(Number(ttlSeconds) || 0);
  return Math.min(MAILBOX_TTL_CAP_MAX_S, Math.max(MAILBOX_TTL_CAP_MIN_S, t || MAILBOX_TTL_CAP_MAX_S));
}

/** A just-finished handshake: open my inbound after the random delay (not now). */
export async function scheduleInboundOpen(sessions: MboxStore, token: string, now = Date.now()): Promise<void> {
  await sessions.setMboxState?.(token, { openAt: now + Math.max(0, openDelay()), opened: false, seq: 0 });
}

async function mboxOf(sessions: MboxStore, token: string): Promise<MboxState> {
  const st = await sessions.mboxState?.(token);
  if (st) return st;
  // a chat with capabilities but no mailbox state (moved here without it, or an old test double):
  // open after the usual random delay
  const fresh: MboxState = { openAt: Date.now() + Math.max(0, openDelay()), opened: false, seq: 0 };
  await sessions.setMboxState?.(token, fresh);
  return fresh;
}

function isLocallyVerified(sealed: unknown): boolean {
  const s = (sealed ?? null) as { fingerprint?: unknown; myVerifiedFp?: unknown } | null;
  return !!s && typeof s.myVerifiedFp === 'string' && !!s.myVerifiedFp && typeof s.fingerprint === 'string' && s.myVerifiedFp === s.fingerprint;
}

/**
 * b77p (audit 2 VAR-01): my open token — kept, or obtained now: the blind kept from the join (responder, a lost
 * answer) or a fresh one (initiator), signed by gate `issue` on the rendezvous token with my write secret.
 * Returns the token, 'refused' (the relay won't sign for this side: the row is gone or signed another value), or
 * 'later' (anything else: the next pass tries again).
 */
async function obtainOpenToken(relay: SealedRelay, sessions: MboxStore, token: string, sealed: unknown, st: MboxState): Promise<OpenToken | 'refused' | 'later'> {
  if (isOpenToken(st.openToken)) return st.openToken;
  if (!relay.openKey || !relay.sessionIssue) return 'later';
  let key: OpenKey;
  try { key = await currentOpenKey(relay, sessions); } catch { return 'later'; } // b77q (audit 3 CR-1): the pinned key
  let blind = isOpenBlind(st.openBlind) && st.openBlind.kid === key.kid ? st.openBlind : null;
  if (!blind) {
    blind = (await blindOpenToken(key)).blind;
    await sessions.setMboxState?.(token, { openBlind: blind }); // before asking: a lost answer is re-asked with the same value
  }
  const ws = (sealed as { writeSecret?: string | null } | null)?.writeSecret ?? null;
  try {
    const { open_blind, open_kid } = await reblind(key, blind);
    const r = await relay.sessionIssue(token, ws, open_blind, open_kid);
    const sig = openSigOf(r);
    if (!sig) return 'later';
    const tok = await finishOpenToken(key, blind, sig);
    await sessions.setMboxState?.(token, { openToken: tok, openBlind: undefined });
    return tok;
  } catch (e) {
    const s = relayStatusOf(e);
    // b77q (audit 3 CR-1): a refusal of the issuer key no longer drops it (that let the relay choose a key per open):
    // it is noted on the pin, which may then be replaced at most once per OPEN_KEY_REFETCH_MIN_MS (currentOpenKey)
    if (isOpenKeyRefusal(e)) { await noteOpenKeyRefused(sessions, key.kid); await sessions.setMboxState?.(token, { openBlind: undefined }); return 'later'; }
    if (s === 404 || s === 409 || s === 403) return 'refused';
    return 'later';
  }
}

/** b77p (audit 2 VAR-01): seal (or clear) my push target into my own inbound when it changed since the last
 *  bind (MboxState.wakeFp). Best effort: a failure is retried on the next pass. */
async function bindWake(relay: SealedRelay, sessions: MboxStore, token: string, d: ChatDelivery, st: MboxState): Promise<void> {
  // b77p round 2 (owner decisions 1 and 4): a chat set up before b77p has no wake capability, so it gets no wakes —
  // it is received by polling. If an earlier (b77) build of this phone bound a push_ref to its inbound, that binding
  // is cleared once (during the relay's transition window it still woke this phone through the account push row the
  // relay could join it to; this build keeps no account push row). A wake box and a push_ref never coexist: clearing
  // writes {wake: null}, which drops both.
  if (!d.inbound.wake) {
    if (st.pushBound || st.pushRef) {
      try {
        await relay.mailboxPush(d.inbound.mbox, d.inbound.read, null, d.inbound.own);
        await sessions.setMboxState?.(token, { pushBound: false, pushRef: undefined });
      } catch (e) {
        if (relayStatusOf(e) === 410) await sessions.setMboxState?.(token, { pushBound: false, pushRef: undefined }).catch(() => undefined);
        else console.log(`[veil-mbox] #${token.slice(0, 4)}: old wake reference not cleared yet (${(e as Error).message ?? e})`);
      }
    }
    return;
  }
  if (!wakeTargetProvider) return;
  let target: WakeTargetAnswer = null;
  try { target = await wakeTargetProvider(unwrapPinned(sessions as object)); } catch { return; } // b77t2 (CL-8)
  try {
    if (target === 'off') {
      if (!st.wakeFp || st.wakeFp === 'off') return;
      await relay.mailboxPush(d.inbound.mbox, d.inbound.read, null, d.inbound.own);
      await sessions.setMboxState?.(token, { wakeFp: 'off' });
      return;
    }
    if (!target || !isWakeTarget(target)) return;
    const fp = await wakeFingerprint(target);
    if (st.wakeFp === fp) return;
    await relay.mailboxPush(d.inbound.mbox, d.inbound.read, await sealWakeBox(d.inbound.wake, d.inbound.mbox, target), d.inbound.own);
    await sessions.setMboxState?.(token, { wakeFp: fp });
  } catch (e) {
    console.log(`[veil-mbox] #${token.slice(0, 4)}: wake binding deferred (${(e as Error).message ?? e})`);
  }
}

/** 'retired': the relay answered 410 THIS time (never stored — the caller counts it, P-4);
 *  'setupFailed' (b77r1, audit A-5): my inbound never opened and the relay kept refusing the ticket */
export type InboundState = 'open' | 'waiting' | 'retired' | 'setupFailed';

/**
 * Open my inbound once its delay has passed (spec §3.4), then bind its wake reference, tell
 * the relay whether this phone verified the chat, and (initiator) end the rendezvous row.
 * 200 or 409 (it exists: an earlier open landed) = open; 410 = retired, for this pass only.
 * b77r1 (audit A-2): a 410 is no longer stored — every pass asks the relay again, and the chat
 * ends only when syncChat's P-4 counter has seen the answer repeat (session-liveness).
 * b77r1 (audit A-5): 403 ("bad or used ticket") is no longer taken as "already open" (the relay
 * answers 409 for a mailbox that exists, before it looks at the ticket, so a 403 means it does
 * not). It is retried with a doubling delay; if my inbound never opened and the refusals go on
 * for OPEN_REFUSED_ANSWERS answers over OPEN_REFUSED_SPAN_MS, the chat is 'setupFailed' (the app
 * says it couldn't finish setting up and offers End) and no more opens are sent.
 * Any other failure is retried on the next pass.
 */
export async function ensureInboundOpen(relay: SealedRelay, sessions: MboxStore, token: string, sealed: unknown, opts: { ttlCapSeconds: number; now?: number }): Promise<InboundState> {
  // b77u (audit 6 U-M7): a timer step of this chat waits while its pass runs (it never rides along with it)
  const pk = jobKeyOf(sessions as object, token);
  passesInFlight.set(pk, (passesInFlight.get(pk) ?? 0) + 1);
  try { return await ensureInboundOpenPass(relay, sessions, token, sealed, opts); } finally {
    const n = (passesInFlight.get(pk) ?? 1) - 1;
    if (n > 0) passesInFlight.set(pk, n); else passesInFlight.delete(pk);
  }
}

/** b77r1 (audit A-5): a 403 to my open (or a refused gate `issue`): counted, retried with a doubling delay, or
 *  'setupFailed'. b77u (U-M7): the retry is a fresh `issue` (a timer step) at the retry time. */
async function noteOpenRefused(sessions: MboxStore, token: string, st: MboxState, now: number): Promise<'waiting' | 'setupFailed'> {
  // b77p round 2 (review L1): the kept open token (and blind) go — a token the relay refuses (its issuer key
  // gone: a test relay's restart, two rotations, a key file not written) was offered again on every pass until
  // setupFailed; the next pass asks gate `issue` for a fresh one (the relay allows a few per side)
  const n = (st.openRefused?.n ?? 0) + 1;
  const first = st.openRefused?.first ?? now;
  if (!st.everOpened && n >= OPEN_REFUSED_ANSWERS && now - first >= OPEN_REFUSED_SPAN_MS) {
    await sessions.setMboxState?.(token, { openRefused: { n, first }, setupFailed: true, openToken: undefined, openBlind: undefined, issueAt: undefined, openStepAt: undefined });
    console.log(`[veil-mbox] #${token.slice(0, 4)}: the relay keeps refusing this inbound's ticket — the chat couldn't finish setting up`);
    return 'setupFailed';
  }
  const retryIn = Math.min(REOPEN_AFTER_MS * 2 ** Math.min(n - 1, 10), OPEN_REFUSED_RETRY_MAX_MS);
  await sessions.setMboxState?.(token, { openRefused: { n, first }, openAt: now + retryIn, issueAt: now + retryIn, openStepAt: undefined, openToken: undefined, openBlind: undefined });
  console.log(`[veil-mbox] #${token.slice(0, 4)}: open refused (403, ${n}x) — retry in ${Math.round(retryIn / 1000)} s`);
  return 'waiting';
}

/** b77u (U-M7): arm the timer that runs one rendezvous step of this chat on its own. Idempotent per due time. A step
 *  overdue when this process first arms it (a restart) is given a fresh delay, stored, so a restart never sends the
 *  backlog back to back. */
async function armSetupStep(relay: SealedRelay, sessions: MboxStore, token: string, step: SetupStep, at: number, now: number): Promise<void> {
  const key = `${jobKeyOf(sessions as object, token)}|${step}`;
  if (!setupArmedOnce.has(key)) {
    setupArmedOnce.add(key);
    if (at < now) {
      at = now + stepDelay();
      await sessions.setMboxState?.(token, step === 'issue' ? { issueAt: at } : { rvEndAt: at });
    }
  }
  if (setupJobs.get(key) === at) return;
  setupJobs.set(key, at);
  const gen = currentWipeGeneration();
  setupTimer(() => {
    if (setupJobs.get(key) !== at) return; // re-armed for another time meanwhile
    setupJobs.delete(key);
    if (currentWipeGeneration() !== gen) return; // a wipe since: nothing of this chat is left to set up
    void runSetupStep(relay, sessions, token, step).catch((e) => console.log(`[veil-mbox] #${token.slice(0, 4)}: setup step ${step} deferred (${(e as Error)?.message ?? e})`));
  }, at - Date.now());
}

/**
 * b77u (audit 6 U-M7): one rendezvous-naming setup step of a chat, run on its own timer (never inside a sync pass):
 * 'issue' = gate `issue` for my open token (then the open is due a fresh delay later); 'end' = the initiator's gate
 * `end` of the rendezvous row. Re-armed for later while this chat's pass is running. Exported for tests.
 */
export async function runSetupStep(relay: SealedRelay, sessions: MboxStore, token: string, step: SetupStep, now = Date.now()): Promise<'done' | 'later' | 'none'> {
  const pk = jobKeyOf(sessions as object, token);
  if (passesInFlight.has(pk)) {
    const at = now + passBusyDelay();
    await sessions.setMboxState?.(token, step === 'issue' ? { issueAt: at } : { rvEndAt: at });
    await armSetupStep(relay, sessions, token, step, at, now);
    return 'later';
  }
  const sealed = await sessions.load(token).catch(() => null);
  const st = await sessions.mboxState?.(token).catch(() => null);
  if (!sealed || !st || !chatDelivery(sealed) || st.setupFailed || st.unavailable) return 'none';
  if (step === 'issue') {
    if (st.opened || isOpenToken(st.openToken)) return 'none';
    const tok = await obtainOpenToken(relay, sessions, token, sealed, st);
    if (tok === 'refused') { await noteOpenRefused(sessions, token, st, now); return 'later'; }
    if (tok === 'later') {
      const at = Date.now() + stepDelay();
      await sessions.setMboxState?.(token, { issueAt: at });
      await armSetupStep(relay, sessions, token, 'issue', at, Date.now());
      return 'later';
    }
    await sessions.setMboxState?.(token, { issueAt: undefined, openStepAt: Date.now() + stepDelay() });
    return 'done';
  }
  const s = sealed as { role?: unknown; writeSecret?: string | null };
  if (s.role !== 'initiator' || st.rvEnded || !st.opened || !(relay.sessionEndAnon || relay.sessionEnd)) return 'none';
  return (await endRendezvous(relay, sessions, token, s.writeSecret ?? null)) ? 'done' : 'later';
}

/** the initiator's gate `end` of the rendezvous row (no login: the write secret is the proof). true = done */
async function endRendezvous(relay: SealedRelay, sessions: MboxStore, token: string, writeSecret: string | null): Promise<boolean> {
  try {
    if (relay.sessionEndAnon) await relay.sessionEndAnon(token, writeSecret);
    else await relay.sessionEnd!(token, writeSecret);
    await sessions.setMboxState?.(token, { rvEnded: true, rvEndAt: undefined });
    return true;
  } catch (e) {
    const m = relayDetailOf(e); // b77m (audit VAR-20)
    if (/not found|has ended|already ended|retired/i.test(m) || relayStatusOf(e) === 404 || relayStatusOf(e) === 410) {
      await sessions.setMboxState?.(token, { rvEnded: true, rvEndAt: undefined });
      return true;
    }
    // b77u (U-M7): tried again after a fresh delay (inline mode: the next pass)
    if (!inlineSteps) {
      const at = Date.now() + stepDelay();
      await sessions.setMboxState?.(token, { rvEndAt: at });
      await armSetupStep(relay, sessions, token, 'end', at, Date.now());
    }
    return false;
  }
}

async function ensureInboundOpenPass(relay: SealedRelay, sessions: MboxStore, token: string, sealed: unknown, opts: { ttlCapSeconds: number; now?: number }): Promise<InboundState> {
  const d = requireDelivery(sealed);
  let st = await mboxOf(sessions, token);
  // b77r1 (audit A-2): a `retired` flag an earlier build stored from ONE answer is not trusted:
  // drop it and ask the relay again
  if (st.retired) { await sessions.setMboxState?.(token, { retired: undefined }); st = { ...st, retired: undefined }; }
  if (st.setupFailed) return 'setupFailed';
  const now = opts.now ?? Date.now();
  const s = sealed as { role?: unknown; writeSecret?: string | null };
  if (!st.opened) {
    if (now < st.openAt) return 'waiting';
    // b77u (audit 6 U-M7): my open token first. gate `issue` names the rendezvous token, so it is never sent from
    // this pass: it runs on its own timer at `issueAt` (a fresh CSPRNG delay), and the open waits its own delay
    // after the answer (`openStepAt`). The responder's token came with its join: it opens at `openAt` as before.
    if (!isOpenToken(st.openToken)) {
      if (!inlineSteps) {
        let at = st.issueAt;
        if (!Number.isSafeInteger(at)) { at = now + stepDelay(); await sessions.setMboxState?.(token, { issueAt: at }); }
        await armSetupStep(relay, sessions, token, 'issue', at as number, now);
        return 'waiting';
      }
      // tests (setMailboxOpenDelay): the old one-pass flow, each step after the test's delay
      const tok = await obtainOpenToken(relay, sessions, token, sealed, st);
      if (tok === 'later') { console.log(`[veil-mbox] #${token.slice(0, 4)}: open token not ready — next pass`); return 'waiting'; }
      if (tok === 'refused') return noteOpenRefused(sessions, token, st, now);
      const at = now + stepDelay();
      await sessions.setMboxState?.(token, { issueAt: undefined, openStepAt: at });
      st = { ...st, openToken: tok, openBlind: undefined, openStepAt: at };
    }
    if (Number.isSafeInteger(st.openStepAt) && now < (st.openStepAt as number)) return 'waiting';
    try {
      const tok = st.openToken as OpenToken;
      await relay.mailboxOpen({ mbox: d.inbound.mbox, send_hash: d.inbound.sendHash, read_hash: await capHash(d.inbound.read), open_token: tok, ttl_cap_s: mailboxTtlCap(opts.ttlCapSeconds), ...(d.inbound.own ? { own_hash: await capHash(d.inbound.own) } : {}) }); // b77u (audit 6 W4): H(owner cap) when this chat has one
      console.log(`[veil-mbox] #${token.slice(0, 4)}: inbound opened`);
    } catch (e) {
      const status = relayStatusOf(e);
      if (status === 410) return 'retired'; // b77r1 (A-2): this answer only; the caller counts it
      // b77r1 (A-5): the ticket is refused and no mailbox exists — never "already open"
      if (status === 403) return noteOpenRefused(sessions, token, st, now);
      if (status !== 409) { console.log(`[veil-mbox] #${token.slice(0, 4)}: open deferred (${(e as Error).message ?? e})`); return 'waiting'; }
      // b77u (audit 6 W4): "already open" by SOMEONE ELSE (its owner cap is not ours: e.g. the peer, who can derive the
      // mailbox id, opened it first) — this inbound can't be trusted; the chat couldn't finish setting up
      if (d.inbound.own && (e as { data?: { owned?: unknown } } | null)?.data?.owned === false) {
        await sessions.setMboxState?.(token, { setupFailed: true, openToken: undefined, openBlind: undefined });
        console.log(`[veil-mbox] #${token.slice(0, 4)}: inbound was opened by another party — the chat couldn't finish setting up`);
        return 'setupFailed';
      }
      console.log(`[veil-mbox] #${token.slice(0, 4)}: inbound already open (409)`);
    }
    // b77u (U-M7): the initiator's rendezvous end is due its own delay after the open
    const endAt = s.role === 'initiator' && !st.rvEnded ? now + stepDelay() : undefined;
    await sessions.setMboxState?.(token, { opened: true, everOpened: true, openRefused: undefined, openToken: undefined, openBlind: undefined, openStepAt: undefined, ...(endAt !== undefined ? { rvEndAt: endAt } : {}) });
    st = { ...st, opened: true, everOpened: true, ...(endAt !== undefined ? { rvEndAt: endAt } : {}) };
  }
  // b77p (audit 2 VAR-01): my sealed wake box (it replaced b77's push_ref, which my account's push row listed)
  await bindWake(relay, sessions, token, d, st);
  // this phone's own safety-code confirmation, mirrored on its own inbound (rings and TURN need it)
  const want = isLocallyVerified(sealed);
  if ((st.verified ?? false) !== want) {
    try { await relay.mailboxVerify(d.inbound.mbox, d.inbound.read, want, d.inbound.own); await sessions.setMboxState?.(token, { verified: want }); } catch { /* next pass */ }
  }
  // initiator: the rendezvous row has done its job — gate end deletes it and retires the token.
  // b77u (U-M7): on its own timer at `rvEndAt`, never from this pass (it named the token next to my mailbox's requests)
  if (s.role === 'initiator' && !st.rvEnded && (relay.sessionEndAnon || relay.sessionEnd)) {
    let at = st.rvEndAt;
    if (!Number.isSafeInteger(at)) { at = now + stepDelay(); await sessions.setMboxState?.(token, { rvEndAt: at }); }
    if (inlineSteps) { if (now >= (at as number)) await endRendezvous(relay, sessions, token, s.writeSecret ?? null); }
    else await armSetupStep(relay, sessions, token, 'end', at as number, now);
  }
  return 'open';
}

/** Mirror this phone's own verification of the chat on its inbound (verify / unverify). Best
 *  effort: an inbound not open yet gets it when it opens (ensureInboundOpen). */
export async function syncInboundVerified(relay: Pick<SealedRelay, 'mailboxVerify'>, sessions: MboxStore, token: string): Promise<boolean> {
  try {
    const sealed = await sessions.load(token);
    const d = chatDelivery(sealed);
    if (!d) return false;
    const st = await sessions.mboxState?.(token);
    const want = isLocallyVerified(sealed);
    if (!st?.opened) return false;
    await relay.mailboxVerify(d.inbound.mbox, d.inbound.read, want, d.inbound.own);
    await sessions.setMboxState?.(token, { verified: want });
    return true;
  } catch { return false; }
}

/** thrown when the peer's inbound is not open yet and the envelope can't wait (calls) */
export class MailboxNotOpenError extends Error {
  constructor() { super('Your contact’s phone is still setting up this chat. Try again in a minute.'); this.name = 'MailboxNotOpenError'; }
}
/** thrown when the peer's inbound is retired: the chat was ended */
export class MailboxRetiredError extends Error {
  constructor() { super('This chat has ended.'); this.name = 'MailboxRetiredError'; }
}
/** b77r1 (audit A-5): thrown instead of dropping anything when a chat's outbox is full */
export class OutboxFullError extends Error {
  constructor() { super('Too many messages are still waiting to be delivered in this chat. Your contact’s phone hasn’t finished setting it up — try again later, or end this chat and start a new one.'); this.name = 'OutboxFullError'; }
}

/** b77r1 (audit A-4): a 410 from a send counts as one "chat ended" answer for the P-4 rule
 *  (syncChat removes the chat once the answers repeat — never on one).
 *  b77r2 (audit R2-A-1): counted under the chat's OUTBOUND key (`out:<token>`), which only a
 *  submit that lands clears — not under the inbound key a good fetch of my own inbound clears
 *  (that made a half-ended chat a zombie: every send refused, the chat never removed). */
export function noteSendGone(token: string, now = Date.now()): boolean { return noteGoneAnswer(chatGoneAnswers, outGoneKey(token), now); }
/** b77r2 (R2-A-1): a submit landed — the peer's inbound is there */
function noteSendLanded(token: string): void { clearGoneAnswers(chatGoneAnswers, outGoneKey(token)); }
/** b77r2 (R2-A-1): the peer's inbound answered 410 often enough, over long enough (P-4) */
export function outboundGoneConfirmed(token: string, now = Date.now()): boolean { return goneAnswersConfirmed(chatGoneAnswers, outGoneKey(token), now); }

export interface SealedEnvelope { ciphertext: string; iv: string; header: string; byteLength?: number }

function idOf(data: unknown): string | undefined {
  const d = data as { id?: unknown; data?: { id?: unknown } } | null;
  if (typeof d?.id === 'string' && d.id) return d.id;
  if (typeof d?.data?.id === 'string' && d.data.id) return d.data.id;
  return undefined;
}

function submissionOf(d: ChatDelivery, it: OutboxItem): SealedSubmission {
  return { mbox: d.outbound.mbox, send_cap: d.outbound.send, ciphertext: it.ciphertext, iv: it.iv, header: it.header, byte_length: it.byte_length, ttl_seconds: it.ttl_seconds, notify: it.notify, ...(d.outbound.wake ? { wake_cap: d.outbound.wake } : {}) };
}

export interface FlushResult {
  /** how many envelopes went out */
  sent: number;
  /** local message ids (OutboxItem.localId) whose every envelope has now gone out, with the
   *  relay id of the last one */
  delivered: { id: string; envId?: string }[];
  /** envelopes still waiting */
  waiting: number;
  /** local message ids that still have an envelope waiting */
  queuedIds: string[];
  /** when the oldest still-waiting envelope was queued (epoch ms) */
  oldestAt?: number;
}

/** Re-submit envelopes that met a 425, oldest first; stops at the first that still can't go.
 *  b77r1 (audit A-4 / A-5): a 410 (the chat was ended) throws MailboxRetiredError and keeps the
 *  queue — nothing is dropped on one answer; the queue goes with the chat when its end is
 *  confirmed (P-4). The caller counts the answer. */
export async function flushOutbox(relay: Pick<SealedRelay, 'sealedSubmit'>, sessions: MboxStore, token: string, d: ChatDelivery): Promise<FlushResult> {
  const q = (await sessions.outbox?.(token)) ?? [];
  if (!q.length) return { sent: 0, delivered: [], waiting: 0, queuedIds: [] };
  let sent = 0;
  const envIds = new Map<string, string | undefined>();
  let retired = false;
  for (; sent < q.length; sent++) {
    try {
      const r = await relay.sealedSubmit(submissionOf(d, q[sent]));
      assertSealedOk(r);
      noteSendLanded(token); // b77r2 (R2-A-1)
      const lid = q[sent].localId;
      if (lid) envIds.set(lid, idOf(r.data));
    } catch (e) {
      if (relayStatusOf(e) === 410) retired = true;
      break; // 425 / 410 / network: keep the rest, in order
    }
  }
  const rest = q.slice(sent);
  if (sent) await sessions.setOutbox?.(token, rest);
  if (sent) console.log(`[veil-mbox] #${token.slice(0, 4)}: ${sent} queued envelope(s) delivered`);
  if (retired) throw new MailboxRetiredError();
  const still = new Set(rest.map((it) => it.localId).filter((x): x is string => !!x));
  const delivered = [...envIds].filter(([id]) => !still.has(id)).map(([id, envId]) => ({ id, envId }));
  if (delivered.length) await sessions.markCachedDelivered?.(token, delivered).catch(() => undefined);
  return { sent, delivered, waiting: rest.length, queuedIds: [...still], ...(rest.length ? { oldestAt: rest[0].at } : {}) };
}

/** b77r1 (audit A-5): name the envelope a send just queued (the outbox's last item) with the
 *  local message id, so the app can show the bubble as "Waiting to deliver" until it goes.
 *  Sends are serialized per chat (serializeRatchetSend), so the last item is that send's. */
export async function tagQueued(sessions: MboxStore, token: string, localId: string): Promise<void> {
  const q = (await sessions.outbox?.(token)) ?? [];
  if (!q.length || q[q.length - 1].localId) return;
  q[q.length - 1] = { ...q[q.length - 1], localId };
  await sessions.setOutbox?.(token, q);
}

/** b77r1 (audit A-5): refuse a send BEFORE its ratchet step when the outbox can't take
 *  `n` more envelopes (after trying to flush it) — never drop a queued one */
export async function ensureOutboxRoom(relay: Pick<SealedRelay, 'sealedSubmit'>, sessions: MboxStore, token: string, d: ChatDelivery, n = 1): Promise<void> {
  let q = (await sessions.outbox?.(token)) ?? [];
  if (q.length + n <= OUTBOX_MAX) return;
  try { await flushOutbox(relay, sessions, token, d); } catch (e) {
    if (e instanceof MailboxRetiredError) { noteSendGone(token); throw e; }
  }
  q = (await sessions.outbox?.(token)) ?? [];
  if (q.length + n > OUTBOX_MAX) throw new OutboxFullError();
}

// b77m (audit VAR-20): app-written message; the relay's words only as relayMessage (logs)
function assertSealedOk(r: { data: unknown; status: number }): void {
  const d = r.data as { error?: unknown } | null;
  if (r.status >= 400 || (d && typeof d.error === 'string')) throw Object.assign(new Error(`The server refused the message — ${relayErrorText(r.status >= 400 ? r.status : 400, d).message}`), { status: r.status, relayMessage: cleanRelayText(d?.error) });
}

/**
 * Send one already-encrypted 1:1 envelope to the peer's inbound (spec §4.10). Nothing but the
 * send capability authorises it. A 425 (the peer's inbound is not open yet) queues the envelope
 * when `queue` is set (its ratchet step is already saved, so it must go out as it is), and
 * throws MailboxNotOpenError otherwise; a 410 throws MailboxRetiredError.
 */
export async function sealedSend(
  relay: Pick<SealedRelay, 'sealedSubmit'>, sessions: MboxStore, token: string, d: ChatDelivery,
  env: SealedEnvelope, ttlSeconds: number, notify: false | 'msg' | 'call', queue: boolean,
): Promise<{ id?: string; queued?: boolean }> {
  const item: OutboxItem = { ciphertext: env.ciphertext, iv: env.iv, header: env.header, byte_length: env.byteLength ?? env.ciphertext.length, ttl_seconds: ttlSeconds, notify, at: Date.now() };
  // envelopes already waiting go first (order is the peer's ratchet's business, but a fresh one
  // jumping a queue it can't reach anyway gains nothing)
  if (queue && ((await sessions.outbox?.(token)) ?? []).length) {
    try { await flushOutbox(relay, sessions, token, d); } catch (e) {
      if (e instanceof MailboxRetiredError) noteSendGone(token); // b77r1 (A-4)
      throw e;
    }
    const rest = (await sessions.outbox?.(token)) ?? [];
    if (rest.length) {
      // b77r1 (A-5): a full outbox refuses the send; it never drops the oldest
      if (rest.length >= OUTBOX_MAX || !sessions.setOutbox || !(await sessions.setOutbox(token, [...rest, item]))) throw new OutboxFullError();
      return { queued: true };
    }
  }
  try {
    const r = await relay.sealedSubmit(submissionOf(d, item));
    assertSealedOk(r);
    noteSendLanded(token); // b77r2 (R2-A-1)
    return { id: idOf(r.data) };
  } catch (e) {
    const s = relayStatusOf(e);
    if (s === 425) {
      if (!queue) throw new MailboxNotOpenError();
      const q = (await sessions.outbox?.(token)) ?? [];
      if (q.length >= OUTBOX_MAX) throw new OutboxFullError(); // b77r1 (A-5)
      if (sessions.setOutbox && (await sessions.setOutbox(token, [...q, item]))) {
        console.log(`[veil-mbox] #${token.slice(0, 4)}: the peer's inbound isn't open yet — envelope queued`);
        return { queued: true };
      }
      throw new MailboxNotOpenError();
    }
    if (s === 410) { noteSendGone(token); throw new MailboxRetiredError(); } // b77r1 (A-4): counted
    throw e;
  }
}

function withTimeout<T>(p: Promise<T>, ms: number): Promise<T | undefined> {
  return new Promise((resolve) => {
    const t = setTimeout(() => resolve(undefined), ms);
    p.then((v) => { clearTimeout(t); resolve(v); }, () => { clearTimeout(t); resolve(undefined); });
  });
}

/**
 * "End this chat" (spec §6): sealedEnd on my inbound with my read cap, then on the peer's inbound
 * with my send cap, so the peer's next fetch gets 410 and runs its "chat ended" path. Both best
 * effort, each bounded by `timeoutMs`; never throws. A chat without capabilities does nothing.
 */
export async function endSealedChat(relay: Pick<SealedRelay, 'sealedEnd'>, sealed: unknown, timeoutMs = 4_000): Promise<{ inbound: boolean; outbound: boolean }> {
  const d = chatDelivery(sealed);
  if (!d) return { inbound: false, outbound: false };
  const inbound = (await withTimeout(relay.sealedEnd(d.inbound.mbox, d.inbound.read).then(() => true), timeoutMs)) === true;
  const outbound = (await withTimeout(relay.sealedEnd(d.outbound.mbox, d.outbound.send).then(() => true), timeoutMs)) === true;
  return { inbound, outbound };
}

/** b77r2 (audit R2-A-1): my inbound's end is confirmed (P-4) — end the peer's inbound too (my
 *  outbound, with my send cap) so the peer's chat ends instead of refusing sends for ever. Best
 *  effort, bounded by `timeoutMs`, never throws; any answer (200, 410, or 425 from a relay past
 *  its unopened-end cap) is fine — the chat ends here either way. */
export async function endSealedOutbound(relay: Pick<SealedRelay, 'sealedEnd'>, sealed: unknown, timeoutMs = 2_000): Promise<boolean> {
  const d = chatDelivery(sealed);
  if (!d) return false;
  return (await withTimeout(relay.sealedEnd(d.outbound.mbox, d.outbound.send).then(() => true), timeoutMs)) === true;
}

/**
 * End every 1:1 chat this way, all at once, within `budgetMs` overall; never throws and never
 * holds the caller longer than the budget. b77g: no wipe path uses this any more (they take the
 * cached capabilities: wipeDeliveries / startWipeEnds). What an end misses, the relay's 30-day
 * sweeper retires once the mailbox's OWNER has been gone 30 days (b77g: a peer's submits no
 * longer keep it alive).
 */
export async function endAllSealedChats(relay: Pick<SealedRelay, 'sealedEnd'>, sessions: MboxStore, budgetMs = 3_000): Promise<number> {
  try {
    const ds = (await withTimeout(captureDeliveries(sessions), Math.max(250, budgetMs / 3))) ?? [];
    return await endSealedDeliveries(relay, ds, budgetMs);
  } catch { return 0; }
}

/** every 1:1 chat's capabilities on this phone (local reads only: one keystore read per chat).
 *  b77g (NaR-1): the wipes take the in-memory cache first (wipeDeliveries); this full read is
 *  only the fallback for chats missing from it */
export async function captureDeliveries(sessions: MboxStore): Promise<ChatDelivery[]> {
  const out: ChatDelivery[] = [];
  for (const t of (await sessions.listTokens?.()) ?? []) {
    const d = chatDelivery(await sessions.load(t).catch(() => null));
    if (d) out.push(d);
  }
  return out;
}

/** b77g (NaR-1): the fallback capture's bound (ms) — chats missing from the in-memory cache */
export const WIPE_CAPTURE_FALLBACK_MS = 3_000;
/** b77h (audit77g H-2): the Nothing-at-Rest wipe's fallback bound (ms), counted from when the
 *  fallback starts (after the wipe's own pre-shred reads were issued) */
export const NAR_CAPTURE_FALLBACK_MS = 1_500;

/** b77h (H-2): when (and whether) the fallback read for chats missing from the cache runs */
export interface WipeFallbackOptions {
  /** false: no fallback read at all (the cold-boot wipe: the shred never waits) */
  fallback?: boolean;
  /** the fallback starts only once this settles (the wipe's pre-shred reads have been issued) */
  after?: Promise<unknown>;
}

/** b77g (NaR-1): what a wipe ends — `cached` at once (no keystore read), `rest` (the chats missing
 *  from the cache) when the bounded fallback read resolves */
export interface WipeDeliveries { cached: ChatDelivery[]; rest: Promise<ChatDelivery[]> }

/**
 * b77g (NaR-1): every 1:1 chat's capabilities for a wipe. The cached ones (SessionStore
 * cachedDeliveries, filled by every load / save of a sealed record during normal use) are taken
 * synchronously; the chats missing from the cache are read from storage in the background,
 * bounded by `captureMs` overall (a chat not read by then is not ended). `cached`, when given, is
 * a snapshot taken earlier (before a beginWipe that empties the cache). Never throws.
 * b77h (audit77g H-2): the missing chats are read ONE AT A TIME. Android's keychain runs every
 * operation on one native queue, so N reads issued at once sat ahead of the wipe's own pre-shred
 * reads and the shred (N × latency; withTimeout only drops the JS promise). One at a time, at
 * most one fallback read is ever queued ahead of the wipe. `opts.after` holds the fallback back
 * until the wipe's pre-shred reads have been issued (the bound counts from then); `opts.fallback`
 * false skips it (the cold-boot wipe).
 */
export function wipeDeliveries(sessions: MboxStore, captureMs = WIPE_CAPTURE_FALLBACK_MS, cached?: Map<string, ChatDelivery>, opts: WipeFallbackOptions = {}): WipeDeliveries {
  let snap: Map<string, ChatDelivery>;
  try { snap = cached ?? sessions.cachedDeliveries?.() ?? new Map(); } catch { snap = new Map(); }
  const have = new Set(snap.keys());
  const rest = opts.fallback === false ? Promise.resolve<ChatDelivery[]>([]) : (async (): Promise<ChatDelivery[]> => {
    try {
      if (opts.after) await opts.after.then(() => undefined, () => undefined);
      const stopAt = Date.now() + Math.max(0, captureMs);
      const left = () => Math.max(0, stopAt - Date.now());
      const tokens = (await withTimeout(Promise.resolve().then(() => sessions.listTokens?.() ?? []), left())) ?? [];
      const out: ChatDelivery[] = [];
      for (const t of tokens) {
        if (have.has(t)) continue;
        if (left() <= 0) break;
        const d = await withTimeout(Promise.resolve().then(() => sessions.load(t)).then((s) => chatDelivery(s)), left());
        if (d) out.push(d);
      }
      return out;
    } catch { return []; }
  })();
  return { cached: [...snap.values()], rest };
}

/**
 * b77g (NaR-1): the Nothing-at-Rest wipe's mailbox ends. The cached chats' ends start NOW (no
 * keystore read, so a slow keystore can't cost them); the chats missing from the cache follow
 * when the fallback read (WIPE_CAPTURE_FALLBACK_MS) resolves. Returns at once — the caller never
 * awaits `done`, so the crypto-shred never waits on the capture or the network. Never throws.
 */
export function startWipeEnds(relay: Pick<SealedRelay, 'sealedEnd'>, sessions: MboxStore, opts: { captureMs?: number; budgetMs?: number; cached?: Map<string, ChatDelivery> } & WipeFallbackOptions = {}): { cached: number; done: Promise<number> } {
  const budget = opts.budgetMs ?? 8_000;
  // b77h (H-2): the cache snapshot is taken here, synchronously; the fallback waits for `after`
  const w = wipeDeliveries(sessions, opts.captureMs ?? WIPE_CAPTURE_FALLBACK_MS, opts.cached, { fallback: opts.fallback, after: opts.after });
  const first = w.cached.length ? endSealedDeliveries(relay, w.cached, budget) : Promise.resolve(0);
  const later = w.rest.then((ds) => (ds.length ? endSealedDeliveries(relay, ds, budget) : 0)).catch(() => 0);
  return { cached: w.cached.length, done: Promise.all([first, later]).then(([a, b]) => a + b, () => 0) };
}

/** end captured chats (both mailboxes each), all at once, within `budgetMs`; never throws */
export async function endSealedDeliveries(relay: Pick<SealedRelay, 'sealedEnd'>, ds: ChatDelivery[], budgetMs = 3_000): Promise<number> {
  try {
    const jobs = ds.map(async (d) => {
      const r = await endSealedChat(relay, { delivery: d }, budgetMs);
      return r.inbound || r.outbound ? 1 : 0;
    });
    return (await withTimeout(Promise.all(jobs).then((xs) => xs.reduce<number>((a, b) => a + b, 0)), budgetMs)) ?? 0;
  } catch { return 0; }
}

/** b77f (A-7, owner decision): bounds of the random wait before each delayed mailbox end (ms) */
export const DELAYED_END_MIN_MS = 3_000;
export const DELAYED_END_MAX_MS = 30_000;
/** b77f2 (audit F-4): the "+" supersede ends MY inbound sooner — 1–3 s (b77g, G-4: a 1 s floor, it
 *  was 0, which could put the end in the same burst as the contact request) — so the peer's sends
 *  to the old chat get 410 (and its "chat ended" path runs) quickly; the outbound end keeps 3–30 s */
export const SUPERSEDE_INBOUND_MIN_MS = 1_000;
export const SUPERSEDE_INBOUND_MAX_MS = 3_000;

/** b77f (A-7): how `scheduleDelayedSealedEnds` waits — injectable for tests */
export interface DelayedEndOptions {
  /** uniform [0, 1) source (default secureRandomUnit — b77m, audit VAR-40: was Math.random) */
  random?: () => number;
  /** timer (default setTimeout) */
  setTimer?: (fn: () => void, ms: number) => unknown;
  /** bound on each sealedEnd once it fires (default 8 s) */
  timeoutMs?: number;
  /** b77f2 (audit F-4): the wait window for MY inbound's end, [min, max] ms (default: the
   *  3–30 s window every end uses). The outbound end always keeps 3–30 s. */
  inboundWindowMs?: [number, number];
}

/**
 * b77f (A-7, owner decision): the mailbox ends that sit next to a signed-in call (the "+"
 * supersede's contact request, account delete) are no longer sent in the same burst, so the relay
 * can't tie the account to the mailboxes by timing. b77f2 (audit F-2, owner decision): the
 * Nothing-at-Rest wipe ends its mailboxes at once again (a backgrounded iOS app may never run a
 * later timer); this is for the supersede and account delete only.
 * Each mailbox (my inbound with its read cap, the peer's inbound with my send cap) gets its own
 * `sealedEnd` after its own random wait, uniform over [DELAYED_END_MIN_MS, DELAYED_END_MAX_MS]
 * (b77f2, F-4: my inbound's window can be narrowed with `inboundWindowMs`).
 * Nothing is awaited: this returns at once (the delays chosen, for tests). The mailbox ids and
 * capabilities are copied into the timers' closures, so the ends need no storage, no login and
 * no screen once scheduled (a wipe that runs meanwhile does not stop them). b77f2 (audit F-5):
 * each timer drops its copy of the mailbox id and capability as soon as it fires (a second call
 * of the same timer sends nothing). If the process dies before a timer fires, that end is lost
 * until the relay's 30-day sweeper retires the mailbox (b77g: only the OWNER's operations keep a
 * mailbox alive now, so an inbound whose owner is gone is retired 30 days on, however long the
 * peer keeps writing; see docs/protocol-spec.md, b77g). The duress wipe does NOT use this (it
 * ends at once, best effort).
 */
export function scheduleDelayedSealedEnds(relay: Pick<SealedRelay, 'sealedEnd'>, ds: (ChatDelivery | null | undefined)[], opts: DelayedEndOptions = {}): number[] {
  const random = opts.random ?? secureRandomUnit; // b77m (audit VAR-40)
  const setTimer = opts.setTimer ?? ((fn: () => void, ms: number) => setTimeout(fn, ms));
  const timeoutMs = opts.timeoutMs ?? 8_000;
  const send = relay.sealedEnd.bind(relay);
  const outWin: [number, number] = [DELAYED_END_MIN_MS, DELAYED_END_MAX_MS];
  const inWin: [number, number] = opts.inboundWindowMs ?? outWin;
  /** one slot per mailbox end; the timer empties it when it fires (F-5) */
  type Slot = { mbox: string | null; cap: string | null; win: [number, number] };
  let slots: Slot[] = [];
  for (const d of ds) {
    if (!d) continue;
    slots.push(
      { mbox: String(d.inbound.mbox), cap: String(d.inbound.read), win: inWin },
      { mbox: String(d.outbound.mbox), cap: String(d.outbound.send), win: outWin },
    );
  }
  const delays: number[] = [];
  for (const slot of slots) {
    const r = Math.min(Math.max(Number(random()) || 0, 0), 1);
    const lo = Math.max(0, Number(slot.win[0]) || 0);
    const hi = Math.max(lo, Number(slot.win[1]) || 0);
    const ms = Math.round(lo + r * (hi - lo));
    delays.push(ms);
    try {
      setTimer(() => {
        const mbox = slot.mbox, cap = slot.cap;
        slot.mbox = null; slot.cap = null; // b77f2 (audit F-5): the capability leaves memory with the end
        if (mbox === null || cap === null) return;
        void withTimeout(Promise.resolve().then(() => send(mbox, cap)), timeoutMs);
      }, ms);
    } catch { slot.mbox = null; slot.cap = null; /* best effort */ }
  }
  slots = []; // only the timers' closures hold the slots now
  return delays;
}

// ---------------------------------------------------------------------------------------------
// b77n (audit VAR-04, the full fix): TURN grants (spec §12.12). A call's relay credentials come
// only from a grant BOTH phones took part in: the caller opens it on its own inbound (turnGrant)
// before the invite goes out, the invite carries the grant id inside the encrypted chat, the
// callee's phone approves it on ITS own inbound as the call rings (turnApprove), and then each side
// redeems it through its own inbound (sealedTurn with the grant). The relay refuses an approval
// from the opener's own mailbox, so one phone holding one side of a chat can't mint credentials.
// ---------------------------------------------------------------------------------------------

/** the relay calls the grant flow needs (VeilRelay, or a test double) */
export type TurnGrantRelay = Partial<Pick<VeilRelay, 'turnGrant' | 'turnApprove' | 'sealedTurn'>>;
/** a grant id is 32 random bytes as 64 lowercase hex (the relay keys it on SHA-256 of that string) */
export const TURN_GRANT_RE = /^[0-9a-f]{64}$/;
export const isTurnGrant = (v: unknown): v is string => typeof v === 'string' && TURN_GRANT_RE.test(v);
/** a fresh grant id for one call attempt */
export function newTurnGrant(): string {
  return [...crypto.getRandomValues(new Uint8Array(32))].map((b) => b.toString(16).padStart(2, '0')).join('');
}
/** how often the caller asks again while the callee has not approved yet */
export const TURN_GRANT_POLL_MS = 1000;

async function inboundOf(sessions: MboxStore, token: string): Promise<ChatDelivery['inbound']> {
  const d = chatDelivery(await sessions.load(token).catch(() => null));
  if (!d) throw new Error('this chat has no delivery capabilities');
  return d.inbound;
}

/** the caller: open `grant` on my inbound (throws when the relay refuses: unverified, rate limit, …) */
export async function openTurnGrant(relay: TurnGrantRelay, sessions: MboxStore, token: string, grant: string): Promise<void> {
  if (!isTurnGrant(grant)) throw new Error('invalid call grant');
  if (!relay.turnGrant) throw new Error('relay not ready');
  const ib = await inboundOf(sessions, token);
  await relay.turnGrant(ib.mbox, ib.read, grant, ib.own); // b77u (audit 6 W4)
}

/** the callee: approve the caller's `grant` on my inbound (throws when the relay refuses) */
export async function approveTurnGrant(relay: TurnGrantRelay, sessions: MboxStore, token: string, grant: string): Promise<void> {
  if (!isTurnGrant(grant)) throw new Error('invalid call grant');
  if (!relay.turnApprove) throw new Error('relay not ready');
  const ib = await inboundOf(sessions, token);
  await relay.turnApprove(ib.mbox, ib.read, grant, ib.own); // b77u (audit 6 W4)
}

/** one redemption ask: the credentials answer, or 'pending' while the other side has not approved
 *  (throws when the relay refuses) */
export async function redeemTurnGrant(relay: TurnGrantRelay, sessions: MboxStore, token: string, grant: string): Promise<{ pending: true } | { pending: false; data: unknown }> {
  if (!isTurnGrant(grant)) throw new Error('invalid call grant');
  if (!relay.sealedTurn) throw new Error('relay not ready');
  const ib = await inboundOf(sessions, token);
  const r = await relay.sealedTurn(ib.mbox, ib.read, grant, ib.own); // b77u (audit 6 W4)
  const d = (r.data as { data?: unknown } | null)?.data ?? r.data;
  if (r.status === 202 || (d as { pending?: unknown } | null)?.pending === true) return { pending: true };
  return { pending: false, data: r.data };
}

/**
 * Redeem `grant`, asking again every `pollMs` while the other side has not approved yet, until
 * `deadline` (epoch ms; a function is read again before every wait — the ring window can grow) or
 * until `alive()` says the call is gone. The credentials answer, or null
 * (gave up / call gone). A DEFINITIVE refusal throws (see turnGrantRefusal).
 * b77n2 (review L1): a transient failure — a timeout, a network error, a 5xx, a 429 (the relay's
 * 120-a-minute ask limit), a 425 — no longer ends the call (it used to tear down a call that was
 * already ringing on the other phone): the caller keeps asking until the deadline, waiting what the
 * relay asked (retry_ms / retry_seconds / retry_minutes) or backing off (doubling up to
 * TURN_GRANT_BACKOFF_MAX_MS).
 */
export async function awaitTurnGrant(
  relay: TurnGrantRelay, sessions: MboxStore, token: string, grant: string,
  opts: { alive: () => boolean; deadline: number | (() => number); pollMs?: number; sleep?: (ms: number) => Promise<void> },
): Promise<unknown | null> {
  const sleep = opts.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
  const pollMs = opts.pollMs ?? TURN_GRANT_POLL_MS;
  // what can't change by asking again is checked once, up front (throws)
  if (!isTurnGrant(grant)) throw new Error('invalid call grant');
  if (!relay.sealedTurn) throw new Error('relay not ready');
  await inboundOf(sessions, token);
  let failures = 0;
  for (;;) {
    if (!opts.alive()) return null;
    let wait = pollMs;
    try {
      const r = await redeemTurnGrant(relay, sessions, token, grant);
      if (!r.pending) return r.data;
      failures = 0;
    } catch (e) {
      if (turnGrantRefusal(e)) throw e;
      failures++;
      wait = Math.max(pollMs, retryHintMs(e) ?? Math.min(TURN_GRANT_BACKOFF_MAX_MS, pollMs * 2 ** Math.min(failures - 1, 8)));
    }
    const deadline = typeof opts.deadline === 'function' ? opts.deadline() : opts.deadline;
    if (Date.now() + pollMs > deadline) return null;
    await sleep(Math.max(1, Math.min(wait, deadline - Date.now())));
  }
}

/** b77n2 (review L1): the longest wait between asks after transient failures (no hint from the relay) */
export const TURN_GRANT_BACKOFF_MAX_MS = 5000;

/** b77n2 (review L1): a refusal asking again can't change — 400 (malformed), 401, 403 (no approved
 *  call / wrong capability / not verified), 410 (the chat ended). Anything else is transient: a
 *  timeout or network error (no status, or 0), 425, 429, 5xx. */
export function turnGrantRefusal(e: unknown): boolean {
  const s = Number((e as { status?: unknown } | null)?.status);
  return s === 400 || s === 401 || s === 403 || s === 410;
}

/** the wait (ms) a relay answer asked for, if any */
function retryHintMs(e: unknown): number | null {
  const d = (e as { data?: Record<string, unknown> } | null)?.data;
  if (!d || typeof d !== 'object') return null;
  const ms = Number(d.retry_ms), s = Number(d.retry_seconds), m = Number(d.retry_minutes);
  if (Number.isFinite(ms) && ms > 0) return ms;
  if (Number.isFinite(s) && s > 0) return s * 1000;
  if (Number.isFinite(m) && m > 0) return m * 60_000;
  return null;
}

/** The initiator's handshake read (spec §3.3): the no-login gate `status` for this rendezvous
 *  token — the responder's fields, or null when the row has none yet. */
export async function readHandshakeStatus(relay: Pick<VeilRelay, 'sessionStatus'>, token: string, writeSecret: string | null): Promise<Record<string, unknown> | null> {
  const r = await relay.sessionStatus(token, writeSecret);
  const d = r.data as { data?: { session?: Record<string, unknown> } | Record<string, unknown>; session?: Record<string, unknown> } | null;
  const rec = (d?.data as { session?: Record<string, unknown> } | undefined)?.session ?? d?.session ?? (d?.data as Record<string, unknown> | undefined) ?? (d as Record<string, unknown> | null);
  return rec && typeof rec === 'object' ? rec : null;
}
