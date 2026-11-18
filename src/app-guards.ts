/**
 * b77m (external audit acaef32): the decisions App.tsx makes for the audit's App-side findings,
 * as small pure functions so the repro tests run the same code the app runs. No React Native
 * imports here (the tests load this file under plain Node).
 *
 *   VAR-01  historyTurnedOff
 *   VAR-02  chatOnScreen, supersedeTokens
 *   VAR-06  bootLocks, deviceAuthFailureUnlocks
 *   VAR-19  departureSteps
 *   VAR-21  groupDisplayBatch
 *   VAR-22  groupSenderLabel
 *   VAR-24  groupDeletePlan
 *   VAR-59  holdWhileLocked
 *   VAR-63  narColdBootWipe
 *   VAR-64  crashScreenText
 *   VAR-08  phraseOnClipboard
 *   VAR-54  groupMessageRow (the received group post as cached, with rcvAt)
 */
import type { ChatMessage } from '../vendor/device/src/chat';
import type { GroupInboxEvents } from '../vendor/device/src/group-session';
import { sealedPeer } from '../vendor/device/src/contact';
import { cleanName, nameSkeleton, nameRisk, idShaped } from '../vendor/device/src/names';
import { isFromBlocked } from '../vendor/device/src/block-list';
import { secureRandomUnit } from '../vendor/device/src/sealed';

// ---------------------------------------------------------------------------------------------
// VAR-01: "Keep history" switched from on to off — the stored history is erased (Settings asked)
// ---------------------------------------------------------------------------------------------
export function historyTurnedOff(prev: boolean | undefined, next: boolean | undefined): boolean {
  return prev !== false && next === false;
}

// ---------------------------------------------------------------------------------------------
// VAR-02: "the chat on screen" is the open chat only while the chat screen shows. Every ref the
// sync, banner, receipt and push paths read is derived from this, so a chat left by any route
// (the add-contact link included) is never treated as the one the user is in.
// ---------------------------------------------------------------------------------------------
export function chatOnScreen<C>(screen: string, chat: C | null): C | null {
  return screen === 'chat' ? chat : null;
}

/**
 * VAR-02: the chats a new 1:1 chat with `veilId` replaces (ended on both phones and deleted here).
 * Only chats whose SEALED peer is that same Vardum ID qualify: ready ones, and the chat the user is
 * standing in (`onScreen`, the 1:1 chat on the chat screen) even before it is ready. A stale ref to
 * a chat with someone else can never be ended this way.
 */
export function supersedeTokens(
  candidates: { token: string; sealed: unknown }[],
  newToken: string,
  veilId: string,
  onScreen: string | null,
): string[] {
  const out: string[] = [];
  for (const c of candidates) {
    if (c.token === newToken || !c.sealed) continue;
    const sp = sealedPeer(c.sealed);
    if (!sp || sp.veilId !== veilId) continue;
    const ready = (c.sealed as { ready?: unknown }).ready === true;
    if (ready || c.token === onScreen) out.push(c.token);
  }
  return out;
}

// ---------------------------------------------------------------------------------------------
// VAR-06: without an app password the lock is the phone's own authentication
// ---------------------------------------------------------------------------------------------
/** a cold start locks whenever a lock record exists OR an identity is loaded (it used to lock only
 *  with an app password, so swiping Vardum away and reopening it skipped the lock screen) */
export function bootLocks(hasLockRecord: boolean, hasIdentity: boolean): boolean {
  return hasLockRecord || hasIdentity;
}

/** expo-local-authentication SecurityLevel.NONE */
export const ENROLLED_NONE = 0;
/**
 * A failed or cancelled device prompt opens Vardum only when the phone has NO screen lock and no
 * biometrics at all (enrolled level NONE: there is nothing to check, and the phone is open to whoever
 * holds it anyway). A cancel on a phone with a PIN keeps the lock up, biometric hardware or not.
 * An unreadable level (-1) keeps it up too.
 */
export function deviceAuthFailureUnlocks(enrolledLevel: number): boolean {
  return enrolledLevel === ENROLLED_NONE;
}

// ---------------------------------------------------------------------------------------------
// VAR-19: on leaving the app the lock (and the Nothing-at-Rest wipe) start synchronously, before
// any keychain I/O
// ---------------------------------------------------------------------------------------------
export function departureSteps(
  s: string,
  o: { sheetOpen: boolean; guarded: boolean; locked: boolean; memoryMode: boolean },
): { lockNow: boolean; wipeNow: boolean } {
  const leaving = !o.sheetOpen && (s === 'inactive' || s === 'background');
  return {
    lockNow: !o.sheetOpen && s === 'background' && o.guarded && !o.locked,
    wipeNow: leaving && o.memoryMode,
  };
}

// ---------------------------------------------------------------------------------------------
// b77t (audit 5, owner decision "iOS screen lock: fix pre-emptively"): departureSteps locks only on
// 'background', but iOS may report a screen lock as 'inactive' only (the app then fell back to the
// one-minute idle timer). Now the app also locks
//   - when 'inactive' lasts longer than INACTIVE_LOCK_MS (a brief blip — Control Centre or the
//     notification shade pulled down and let go, a system alert — returns to 'active' first), and
//   - at once when iOS says protected data is about to become unavailable (the phone is locking;
//     native: VeilCrypto 'onProtectedData', modules/veil-crypto/ios), whatever else is open.
// A system sheet Vardum itself opened (withSystemSheet) starts no inactive timer, and nothing
// starts while already locked (the unlock's own Face ID prompt makes the app inactive).
// ---------------------------------------------------------------------------------------------
export const INACTIVE_LOCK_MS = 3_000;
export interface DepartureLockDeps {
  /** lock the app now */
  lock(): void;
  /** is there anything to lock (an identity or an app lock) */
  guarded(): boolean;
  locked(): boolean;
  /** the app state right now (AppState.currentState) */
  currentState(): string;
  setTimer(fn: () => void, ms: number): unknown;
  clearTimer(h: unknown): void;
  ms?: number;
}
export function createDepartureLock(d: DepartureLockDeps): { onState(s: string, sheetOpen: boolean): void; onProtectedDataUnavailable(): void; pending(): boolean } {
  let timer: unknown = null;
  const stop = () => { if (timer !== null) { try { d.clearTimer(timer); } catch { /* gone */ } timer = null; } };
  const lockIfGuarded = () => { try { if (d.guarded() && !d.locked()) d.lock(); } catch { /* never throws */ } };
  return {
    onState(s, sheetOpen) {
      if (s === 'active') { stop(); return; }
      if (s === 'background') { stop(); return; } // departureSteps locks on background (unchanged)
      if (s !== 'inactive' || sheetOpen || timer !== null) return;
      let start = false;
      try { start = d.guarded() && !d.locked(); } catch { start = false; }
      if (!start) return;
      timer = d.setTimer(() => {
        timer = null;
        let st = 'unknown';
        try { st = d.currentState(); } catch { st = 'unknown'; }
        if (st !== 'active') lockIfGuarded();
      }, d.ms ?? INACTIVE_LOCK_MS);
    },
    onProtectedDataUnavailable() { stop(); lockIfGuarded(); },
    pending: () => timer !== null,
  };
}

// ---------------------------------------------------------------------------------------------
// VAR-21: group posts are "displayed" (burn clock started, READ receipt sent) only when they are
// really on screen: the group open on the chat screen, the app in front, the phone unlocked.
// Blocked senders' posts are hidden, so they are never stamped or receipted.
// ---------------------------------------------------------------------------------------------
export function lookingAt(token: string, o: { screen: string; chatToken: string | null | undefined; appActive: boolean; locked: boolean }): boolean {
  return o.screen === 'chat' && !!o.chatToken && o.chatToken === token && o.appActive && !o.locked;
}

export function groupDisplayBatch(
  rows: { id: string; mine?: boolean; openedAt?: number; systemNote?: boolean; senderVid?: string | null; envId?: string }[],
  o: { blocked: ReadonlySet<string>; readReceipts: boolean },
): { stampIds: string[]; receiptIds: string[] } {
  const stampIds: string[] = [];
  const receiptIds: string[] = [];
  for (const m of rows) {
    if (m.mine || m.openedAt || m.systemNote) continue;
    if (isFromBlocked(m, o.blocked)) continue;
    stampIds.push(m.id);
    if (o.readReceipts) receiptIds.push(m.envId ?? m.id);
  }
  return { stampIds, receiptIds };
}

// ---------------------------------------------------------------------------------------------
// VAR-22: a group sender's self-chosen name that clashes with one of MY contacts (their Vardum ID
// or the name I gave them), or that nameRisk flags, keeps the app's ID mark after it — the 1:1 rule
// (names.ts peerNickTitle). The group already de-duplicates names inside the group
// (uniqueGroupNick); a name it already marked is left as it is.
// The contact's own ID is not excluded: the sender's Vardum ID in a group comes from the roster,
// and this phone does not check it against the pinned key here, so even a real "Mum" in a group
// shows as "Mum · 85vGxxxx" when I named a contact "Mum".
// ---------------------------------------------------------------------------------------------
export function groupSenderLabel(
  nickIn: string | null | undefined,
  senderVeilId: string | null | undefined,
  contacts: { veilId: string; name: string | null }[],
): string {
  const id8 = cleanName(String(senderVeilId ?? '')).slice(0, 8);
  const nick = cleanName(String(nickIn ?? ''));
  if (!nick) return id8 || 'member';
  if (id8 && nick.endsWith(` · ${id8}`)) return nick; // already marked by the group
  if (idShaped(nick)) return id8 || 'member';
  const others = contacts.flatMap((c) => [c.veilId, c.name ?? '']).map((o) => cleanName(o)).filter((o) => !!o);
  const sk = nameSkeleton(nick);
  const clash = others.some((o) => nameSkeleton(o) === sk || nameSkeleton(o.slice(0, 8)) === sk);
  const prefixes = others.filter(idShaped).map((o) => o.slice(0, 8));
  if (clash || nameRisk(nick, prefixes)) return id8 ? `${nick} · ${id8}` : nick;
  return nick;
}

// ---------------------------------------------------------------------------------------------
// VAR-24: what deleting a group thread does
//   creator, "Delete this group thread": this phone only — nothing ended on the relay, every row of
//     the group hidden here, the local record and keys removed; the group goes on for the others
//   creator, "End group for everyone": every token the creator holds ended (the old behaviour)
//   member: says it is leaving, ends its own seat and deletes the thread (leaving the group)
// ---------------------------------------------------------------------------------------------
export function groupDeletePlan(
  role: 'creator' | 'member' | null | undefined,
  forEveryone: boolean,
  ownTokens: string[],
  otherTokens: string[],
): { sendLeave: boolean; end: string[]; hide: string[]; removeLocal: string[] } {
  if (role === 'creator' && !forEveryone) {
    return { sendLeave: false, end: [], hide: [...ownTokens, ...otherTokens], removeLocal: [...ownTokens] };
  }
  return { sendLeave: role === 'member', end: [...ownTokens], hide: [...otherTokens], removeLocal: [...ownTokens] };
}

// ---------------------------------------------------------------------------------------------
// VAR-59: "Hold messages while locked" — one check for every sync path (1:1 and group)
// ---------------------------------------------------------------------------------------------
export function holdWhileLocked(locked: boolean, holdUntilUnlock: boolean | undefined): boolean {
  return locked && holdUntilUnlock === true;
}

// ---------------------------------------------------------------------------------------------
// VAR-63: the Nothing-at-Rest cold-boot wipe fails closed for Nothing-at-Rest phones, and never erases
// one that isn't (b77m review M1).
//  - either sealed record read cleanly saying "memory" wipes;
//  - a clean mode record saying device/hardware keeps (a stale marker is repaired by the caller);
//  - an unreadable mode record with a clean settings record: the settings decide;
//  - both sealed records unreadable (or the mode unreadable and no settings record) — the case one keystore
//    error makes (iOS background launch "User interaction is not allowed", an Android keystore stall): the
//    unsealed one-bit marker decides. 'on' wipes (fail closed for Nothing-at-Rest users); 'off' keeps; no
//    marker (an install from before it) or an unreadable one: nothing is wiped now and the check runs again
//    once the app is active and the keychain answers ('retry'). This used to wipe: a keystore hiccup erased
//    a Sealed-mode phone's identity.
// b77n (pre-audit LOW-1): a MISSING mode record (IdentityVault.modeChecked) is not a clean "device" answer
// (mode() defaults it): it is treated as unreadable, so the settings or the marker decide. The one exception
// is a fresh install — no mode record, no settings record, no marker and no identity or app lock at all
// (`freshInstall`, the caller's install signal) — which keeps (nothing to wipe; must not 'retry' forever).
// ---------------------------------------------------------------------------------------------
export type NarBootDecision = 'wipe' | 'keep' | 'retry';
export function narColdBootWipe(o: {
  mode: 'device' | 'hardware' | 'memory' | 'missing' | 'unreadable';
  settingsMode: string | undefined;
  settingsState: 'ok' | 'missing' | 'unreadable';
  marker: 'on' | 'off' | 'unset' | 'unreadable';
  /** no identity and no app lock on this phone (read cleanly); only consulted when nothing else answers */
  freshInstall?: boolean;
}): NarBootDecision {
  if (o.mode === 'memory') return 'wipe';
  if (o.settingsState === 'ok' && o.settingsMode === 'memory') return 'wipe';
  if (o.mode === 'device' || o.mode === 'hardware') return 'keep';
  // the mode record is missing or unreadable: the clean settings record, then the marker, decide
  if (o.settingsState === 'ok') return 'keep';
  if (o.marker === 'on') return 'wipe';
  if (o.marker === 'off') return 'keep';
  if (o.mode === 'missing' && o.settingsState === 'missing' && o.marker === 'unset' && o.freshInstall === true) return 'keep';
  return 'retry';
}

/** b77n (pre-audit LOW-1): the marker is repaired only from a clean, PRESENT mode record — never from a
 *  defaulted mode (a missing record), an unreadable one or the settings. null = leave the marker as it is. */
export function narMarkerRepair(
  mode: { mode: 'device' | 'hardware' | 'memory'; state: 'ok' } | { mode: null; state: 'missing' | 'unreadable' },
  marker: 'on' | 'off' | 'unset' | 'unreadable',
): 'device' | 'hardware' | 'memory' | null {
  if (mode.state !== 'ok') return null;
  return marker === (mode.mode === 'memory' ? 'on' : 'off') ? null : mode.mode;
}

// ---------------------------------------------------------------------------------------------
// b77n (pre-audit INFO-3): the 1:1 poll backoff (b196 / b71): 10 s doubling per empty pass, capped at 20 s,
// plus 0-3 s of jitter drawn from the CSPRNG (was Math.random: the poll timing is what the relay sees).
// `streak` = empty passes in a row (0 = this pass brought something).
// ---------------------------------------------------------------------------------------------
export function pollBackoffMs(streak: number, random: () => number = secureRandomUnit): number {
  const base = streak > 0 ? Math.min(10_000 * 2 ** (streak - 1), 20_000) : 10_000;
  return base + Math.floor(Math.min(Math.max(random(), 0), 0.999999) * 3_000);
}

// ---------------------------------------------------------------------------------------------
// VAR-64: release builds show fixed text and an opaque id, never the raw error or stack
// ---------------------------------------------------------------------------------------------
export function crashScreenText(e: unknown, dev: boolean, id: string): string {
  if (dev) {
    const err = e as Error;
    return String(err?.message || e) + '\n\n' + String(err?.stack || '');
  }
  return `Something went wrong and Vardum had to stop. Close Vardum and open it again. If this keeps happening, contact support and quote error ${id}.`;
}

/** a short random id for the crash screen (not derived from the error) */
export function crashId(rand: () => number = Math.random): string {
  let s = '';
  for (let i = 0; i < 8; i++) s += Math.floor(rand() * 16).toString(16);
  return s;
}

// ---------------------------------------------------------------------------------------------
// VAR-08: the recovery phrase pasted from the clipboard is cleared from it once it is used
// ---------------------------------------------------------------------------------------------
export function phraseOnClipboard(clip: string | null | undefined, phrase: string): boolean {
  // letters only (a pasted list may carry numbers or punctuation, as the restore screen accepts)
  const norm = (s: string) => s.toLowerCase().replace(/[^a-z]+/g, ' ').trim().split(' ').filter(Boolean).join(' ');
  const p = norm(phrase);
  return !!p && !!clip && norm(clip) === p;
}

// ---------------------------------------------------------------------------------------------
// VAR-54 (device fix, app half): a received group post is cached with rcvAt — when THIS phone
// received it — so the unopened-horizon purge runs from the receive time, never from the sender's
// (back-datable) sentAt. Also VAR-21 / VAR-22 / GR-4 / M-3 as the onMessage handler built them.
// ---------------------------------------------------------------------------------------------
export type GroupPostInfo = Parameters<GroupInboxEvents['onMessage']>[0];
export type GroupPostRow = ChatMessage & { sender?: string; senderVerified?: boolean; senderCreator?: boolean };
export function groupMessageRow(info: GroupPostInfo, contacts: { veilId: string; name: string | null }[]): GroupPostRow {
  return {
    id: info.envelopeId,
    text: info.text,
    mine: false,
    ts: info.sentAt,
    envId: info.envelopeId,
    // VAR-54: the receive time rides into the cache (rows without it keep the old ts rule)
    ...(Number.isFinite(info.rcvAt) && (info.rcvAt as number) > 0 ? { rcvAt: info.rcvAt } : {}),
    // M-3 (b69 audit): a post under group keys past the read limit is marked, never verified
    // audit VAR-22: a name that clashes with one of my contacts (or that nameRisk flags) keeps the ID mark
    sender: groupSenderLabel(info.senderNick, info.senderVeilId, contacts) + (info.staleKeys ? ' (old keys)' : ''),
    senderVerified: info.senderVerified && !info.staleKeys,
    // b75 (audit GR-4): the Creator badge comes from the creator key this phone holds, never from a name
    ...(info.senderIsCreator && !info.staleKeys ? { senderCreator: true } : {}),
    // audit VAR-21: no burn clock at decrypt. The display marker (the effect beside the 1:1 one)
    // stamps it, and sends the READ receipt, only while the post is really on screen; a blocked
    // sender's hidden post is never stamped or receipted. (b131's "stamp at first live display"
    // is that marker now.)
    ...(info.senderVeilId ? { senderVid: info.senderVeilId } : {}),
    ...(info.media ? { media: { uri: info.media.uri, k: info.media.k, iv: info.media.iv, mime: info.media.mime, name: info.media.name, size: info.media.size, dl: !!info.media.dl } } : {}),
  };
}

// ---------------------------------------------------------------------------------------------
// b77q review (J2-3): which row an open 1:1 chat moves to when the relay says it is gone (410 /
// superseded). That answer is unauthenticated, and a relay row's peer ID is the relay's word, so
// only a row this phone can stand behind qualifies: one listed from its own sealed state (local),
// or an incoming request signed under the pinned contact's key (incoming). Never an unsigned,
// forged or not-yet-accepted request row, a group row, or an ended one.
// ---------------------------------------------------------------------------------------------
export function gonePendingReplacement<R extends { token: string; groupToken?: string; peerVeilId?: string; status: string; local?: boolean; incoming?: boolean; request?: boolean }>(
  rows: R[], token: string, peerVeilId: string | null | undefined,
): R | undefined {
  if (!peerVeilId) return undefined;
  return rows.find((r) => r.token !== token && !r.groupToken && !!r.peerVeilId && r.peerVeilId === peerVeilId && r.status !== 'ended'
    && !r.request && (r.local === true || r.incoming === true));
}
