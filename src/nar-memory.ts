/**
 * b77k2 (IP77-5, owner decision): Nothing-at-Rest's dial flip keeps the chats working until the user
 * leaves the app, with nothing on disk.
 *
 * The flip used to shred every chat's ratchet state (vault.setMode('memory') deletes veil_rk_*, the
 * flip wipe's eraseLocal the rest) and only hold the chats' delivery capabilities: the chats could
 * not sync, send or be listed any more, and their mailboxes stayed open on the relay, unreadable, so
 * the peers' messages vanished. A chat started after the flip fared no better: the post-wipe barrier
 * refused its writes.
 *
 * Now, at the flip:
 *  1. captureForMemory, under the flip wipe's own write freeze (b77k2 re-review L3: setMode no longer
 *     deletes the chats first, so no sync or send can save a newer state after the read): every veil_
 *     record the flip will shred that the app needs
 *     (each chat's sealed record and per-chat records, the chat list's records, groups, notes;
 *     never the plaintext history, the saved-media list or the push caches, which the flip deletes
 *     for good as before) is read into memory;
 *  2. the flip wipe runs exactly as before (setMode, beginWipe, eraseLocal: nothing stored is left);
 *  3. carryIntoMemory, right after the erase: KeychainStorage serves those records from memory from
 *     now on (its memory session: no read or write of them reaches the platform store), the identity
 *     is put back from memory, and the capability cache is filled from the carried chats (and the
 *     capabilities taken before setMode are held as well), so the departure wipe ends every chat.
 * A chat started after the flip lives in the same memory session, so pre-existing and new chats are
 * in exactly the same state.
 *
 * The departure wipe (and duress and every other wipe) drops the memory session at its crypto-shred,
 * after its capture reads, and ends the chats' mailboxes as before. Turning Nothing-at-Rest down to a
 * stored mode writes the memory session to the store (leaveMemoryMode), so the chats stay when the
 * mode is turned down. b77s (audit 4 DV-6): this used to say a Nothing-at-Rest session that began
 * with a restore "already keeps its chats stored" — stale since audit VAR-12 (1f51): such a session
 * (a restore or a new identity) runs in a memory session from its first write (startNarSession
 * below), exactly like the flip's, so both Settings texts say "memory only while open". A process death between the flip and the departure loses
 * the memory session: the chats' mailboxes stay open until the relay's sweep (as for any chat whose
 * phone dies unwiped; protocol-spec.md, known gaps).
 *
 * Pure module (no React Native imports) so App.tsx and the tests share it.
 */
import type { ChatDelivery } from '../vendor/crypto-core/src/index';
import { KEYVAULT_KEY, type KeyvaultIdentity } from '../vendor/device/src/keyvault';

/** does the flip carry this record into memory? (kept records stay on disk regardless) */
export function narCarries(key: string): boolean {
  if (!key.startsWith('veil_')) return false;
  if (key === KEYVAULT_KEY) return false; // put back from memory (a hardware-mode read would prompt)
  if (key.startsWith('veil_msgcache_')) return false; // Nothing-at-Rest keeps no history
  if (key === 'veil_saved_media') return false; // the flip deletes those files for good
  if (key.startsWith('veil_push_')) return false; // the flip drops the push registration for good
  if (key === 'veil_wipe_pending' || key.startsWith('veil_keychain_index')) return false;
  return true;
}

type ReadStore = { keys(prefix: string): Promise<string[]>; get(key: string): Promise<string | null> };

/** read every record the flip carries (before setMode deletes the chats' records). Never throws. */
export async function captureForMemory(storage: ReadStore): Promise<Map<string, string>> {
  const out = new Map<string, string>();
  let keys: string[] = [];
  try { keys = await storage.keys('veil_'); } catch { return out; }
  for (const k of keys) {
    if (!narCarries(k)) continue;
    try { const v = await storage.get(k); if (v != null) out.set(k, v); } catch { /* not carried */ }
  }
  return out;
}

type MemoryStore = {
  startMemorySession?(entries: Map<string, string>, keep: string[], atFreeze?: number): boolean | void;
  dropMemorySession?(): void;
  scanMemorySessionLeftovers?(): Promise<number>;
  memorySessionActive?(): boolean;
  memorySessionLimited?(): boolean;
  commitMemorySession?(): Promise<number>;
  writesFrozen?(): boolean;
  onFreezeChange?(fn: (frozen: boolean) => void): () => void;
};
type CarrySessions = {
  listTokens(): Promise<string[]>;
  load(token: string): Promise<unknown>;
  resumeDeliveries(): void;
  holdDeliveries(caps: Map<string, ChatDelivery>): void;
};

/**
 * The flip, right after its erase: the captured records are served from memory, the identity is put
 * back, and every carried chat's capabilities are cached (the flip wipe's latch is lifted: these
 * chats go on, so the departure wipe must find them). Returns the chats carried. Never throws.
 */
export async function carryIntoMemory(
  d: { storage: unknown; sessions: CarrySessions; vault: { save(id: KeyvaultIdentity): Promise<void> } },
  captured: Map<string, string>, keep: string[],
  opts: { identity?: KeyvaultIdentity | null; flipCaps?: Map<string, ChatDelivery> | null; at?: { freeze?: number }; isCurrent?: () => boolean; reloadGroups?: () => Promise<unknown> } = {},
): Promise<number> {
  const st = d.storage as MemoryStore;
  if (opts.flipCaps) { try { d.sessions.holdDeliveries(opts.flipCaps); } catch { /* best-effort */ } }
  if (typeof st.startMemorySession !== 'function') return 0;
  // b77k2 (re-review M1): a wipe that ran during the flip (a departure, duress) already shredded the
  // phone and ended the mailboxes: the carry stands down (nothing comes back to life after a wipe)
  const current = () => !opts.isCurrent || opts.isCurrent();
  if (!current()) return 0;
  if (st.startMemorySession(captured, keep, opts.at?.freeze) === false) return 0;
  const standDown = (): boolean => { if (current()) return false; try { st.dropMemorySession?.(); } catch { /* gone */ } return true; };
  try { await st.scanMemorySessionLeftovers?.(); } catch { /* none known */ }
  if (standDown()) return 0;
  if (opts.identity) { try { await d.vault.save(opts.identity); } catch { /* the chats run from the identity in memory */ } }
  if (standDown()) return 0;
  try { d.sessions.resumeDeliveries(); } catch { /* best-effort */ }
  let tokens: string[] = [];
  try { tokens = await d.sessions.listTokens(); } catch { return 0; }
  for (const t of tokens) {
    if (standDown()) return 0;
    try { await d.sessions.load(t); } catch { /* held capabilities still cover it */ }
  }
  if (standDown()) return 0;
  // b77k2 (review L-2): the flip wipe's beginWipe emptied the in-memory group registry; the groups'
  // records were carried, so the registry is filled again from them (else every group send and
  // receive threw "Group keys are not established" until the next refresh)
  if (opts.reloadGroups) { try { await opts.reloadGroups(); } catch { /* the next refresh loads them */ } }
  return standDown() ? 0 : tokens.length;
}

/**
 * audit VAR-12 (1f51): the records Nothing-at-Rest keeps on the phone (on disk, sealed under the
 * kept slot): the login, the mode marker and record, the settings, the app lock and its attempt
 * rows and key, pinned contacts, the client id, the answered-request ledger (hashes), the
 * self-destruct clock, the wipe-pending marker, the notes' version marks, the presence list, the
 * decoy push hold, the registration-lock device key and the UnifiedPush choice flag. App.tsx's
 * departure wipe keeps exactly these; everything else is erased. 'veil_wipe_pending' =
 * duress-wipe WIPE_PENDING_KEY, 'vardum_push_hold_v1' = decoy-push PUSH_HOLD_KEY (b77p_app test).
 */
export const NAR_KEEP_KEYS: readonly string[] = Object.freeze([
  'veil_nar_marker', 'vardum_up_choice_v1', 'veil_auth_session', 'veil_storage_mode', 'veil_settings_v1', 'veil_app_lock',
  'veil_pins_v1', 'veil_client_id', 'veil_app_lock_key', 'veil_contact_seen_v1', 'veil_lockout', 'veil_lock_wrong_in_a_row',
  'veil_selfdestruct_seen', 'veil_wipe_pending', 'veil_notes_versions', 'veil_notes_bound_only', 'veil_ck_present_v1',
  'vardum_push_hold_v1', 'veil_reglock_device',
  'veil_lock_aux_v1', // b77t (audit 5 M-E): the decoy account's login and keys (decoy-account.ts)
  'veil_duress_purge_v1', // b77t (audit 5 L-5): the pre-authorised duress purge token
  'veil_aux_pending_v1', // b77t merge: the pending decoy-account deletes (decoy-account.ts DECOY_END_KEY)
]);

/**
 * audit VAR-12 (1f51): a Nothing-at-Rest session that begins with an identity fresh start (a restore from the
 * 24 words after a departure wipe, or a new identity) runs in a memory session from its first
 * write, exactly like the dial flip's: the identity, every ratchet state and chat record, the notes
 * key, groups and push caches are served from memory and never reach the platform keystore, so a
 * forced reboot, an out-of-memory kill or a crash leaves no key behind (there is nothing to wipe).
 * Only NAR_KEEP_KEYS (and the store's own unsealed markers and key-name index) are written to disk.
 * It used to write them all to the keystore and rely on the departure wipe (AppState 'inactive' /
 * 'background') or the next launch's cold-boot wipe to remove them.
 * Call it right after the fresh start's clearTombstones(). No-op outside Nothing-at-Rest or while a
 * memory session is already live. Returns true when a session was started. Never throws.
 */
export function startNarSession(storage: unknown, storageMode: string | undefined, keep: readonly string[] = NAR_KEEP_KEYS): boolean {
  if (storageMode !== 'memory') return false;
  const st = storage as MemoryStore & { freezeEpoch?(): number } | null | undefined;
  if (!st || typeof st.startMemorySession !== 'function') return false;
  try {
    // b77u2 (UC-M1): a live session limited to the decoy's veil_dk_ records (started by a decoy unlock) is no
    // session for the real records: it is dropped and the full one started, else the restore's identity and
    // ratchet records went to the keystore. A full session already live still stands.
    if (st.memorySessionActive?.() && st.memorySessionLimited?.()) st.dropMemorySession?.();
    if (st.memorySessionActive?.()) return false;
    if (st.startMemorySession(new Map(), [...keep]) === false) return false;
    // anything a cut-short wipe left in the store under these names is noted, so a wipe's sweep removes it
    void Promise.resolve().then(() => st.scanMemorySessionLeftovers?.()).catch(() => undefined);
    return true;
  } catch { return false; }
}

/**
 * b77u (audit 6 U-M5 / IH M1): the decoy under Nothing-at-Rest. Every departure wipe ends with the post-wipe
 * barrier (only the kept records may be written until a deliberate fresh start), and the decoy never makes one:
 * after the first departure every decoy save (veil_dk_*) was refused and its chats vanished, which told a captor
 * the decoy was a decoy. Opening the decoy now starts a memory session limited to the decoy's own records
 * (`decoyPrefix`): they live in memory only, like the real chats under Nothing-at-Rest, and the next wipe drops
 * them. Every other record keeps the barrier and the tombstones. A live memory session (the real account's, before
 * any departure) already serves them; then nothing changes.
 */
export function startDecoyNarSession(storage: unknown, storageMode: string | undefined, decoyPrefix: string, keep: readonly string[] = NAR_KEEP_KEYS): boolean {
  if (storageMode !== 'memory') return false;
  const st = storage as (MemoryStore & { startMemorySession?(e: Map<string, string>, k: string[], atFreeze?: number, prefixes?: string[]): boolean | void }) | null | undefined;
  if (!st || typeof st.startMemorySession !== 'function') return false;
  try {
    if (st.memorySessionActive?.()) return false;
    return st.startMemorySession(new Map(), [...keep], undefined, [decoyPrefix]) !== false;
  } catch { return false; }
}

/**
 * b77u2 (UC-M1): the real code unlocked: a memory session limited to the decoy's records (startDecoyNarSession)
 * ends here, with the decoy session it served (its records are gone, as at a departure). A full session (the real
 * account's) is never touched. Returns true when one was dropped. Never throws.
 */
export function dropDecoyNarSession(storage: unknown): boolean {
  const st = storage as MemoryStore | null | undefined;
  try {
    if (!st?.memorySessionActive?.() || !st.memorySessionLimited?.()) return false;
    st.dropMemorySession?.();
    return true;
  } catch { return false; }
}

/** resolves once no wipe freezes writes, or after `maxMs` */
function writesThawed(st: MemoryStore, maxMs: number): Promise<void> {
  if (!st.writesFrozen?.()) return Promise.resolve();
  return new Promise<void>((resolve) => {
    let off: (() => void) | undefined;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const done = () => { if (timer) clearTimeout(timer); try { off?.(); } catch { /* gone */ } resolve(); };
    timer = setTimeout(done, Math.max(0, maxMs));
    off = st.onFreezeChange?.((frozen) => { if (!frozen) done(); });
    if (!st.writesFrozen?.()) done();
  });
}

/**
 * Nothing-at-Rest turned down to a stored mode while a memory session is live: its records are
 * written to the store (after any wipe's write freeze ends, bounded by `maxWaitMs`) and its chats
 * are no longer held for an end. Returns the records not written (0 = all, -1 = not committed: a
 * wipe is still freezing writes or dropped the session; the chats then stay in memory).
 */
export async function leaveMemoryMode(
  d: { storage: unknown; sessions: { listTokens(): Promise<string[]>; releaseHeldDeliveries?(t: Iterable<string>): void } },
  maxWaitMs = 15_000,
): Promise<number> {
  const st = d.storage as MemoryStore;
  if (!st.memorySessionActive?.() || typeof st.commitMemorySession !== 'function') return 0;
  await writesThawed(st, maxWaitMs);
  let tokens: string[] = [];
  try { tokens = await d.sessions.listTokens(); } catch { /* none released */ }
  const r = await st.commitMemorySession();
  if (r === 0) { try { d.sessions.releaseHeldDeliveries?.(tokens); } catch { /* best-effort */ } }
  return r;
}

/**
 * b77k2 (review L-3): a memory session left live in a stored mode (the commit met a wipe's freeze, or
 * the store refused a record) is committed again whenever a wipe's freeze ends, and at most `everyMs`
 * apart otherwise, until it is stored. Returns the unsubscribe. `storedMode()` = the mode is not
 * 'memory' right now (never commits while Nothing-at-Rest is on).
 */
export function retryLeaveMemoryMode(
  d: { storage: unknown; sessions: { listTokens(): Promise<string[]>; releaseHeldDeliveries?(t: Iterable<string>): void } },
  storedMode: () => boolean, everyMs = 30_000,
): () => void {
  const st = d.storage as MemoryStore;
  let busy = false;
  const tryNow = () => {
    if (busy || !storedMode() || !st.memorySessionActive?.() || st.writesFrozen?.()) return;
    busy = true;
    void leaveMemoryMode(d, 0).catch(() => -1).finally(() => { busy = false; });
  };
  const off = st.onFreezeChange?.((frozen) => { if (!frozen) tryNow(); });
  const timer = setInterval(tryNow, Math.max(1_000, everyMs));
  return () => { try { off?.(); } catch { /* gone */ } clearInterval(timer); };
}

/**
 * b77k2 (re-review M1 / L3): the flip's read, under its own write freeze (call it right after the flip
 * wipe's beginWipe): the records, and the wipe generation and freeze epoch the carry must still find.
 */
export async function flipCapture(storage: ReadStore & { freezeEpoch?(): number }, generation: () => number, startGen?: number | null): Promise<{ captured: Map<string, string>; at: { freeze?: number }; isCurrent: () => boolean } | null> {
  const gen = generation();
  // b77k2 (review M-B): `startGen` = the generation when the dial flip began (before its first await).
  // Only the flip wipe's own bump may lie between: a departure (or any wipe) that ran before the flip
  // wipe began already shredded the phone, and nothing — not even the identity — is carried after it.
  if (startGen !== undefined && (startGen === null || gen !== startGen + 1)) return null;
  const at = { freeze: storage.freezeEpoch?.() };
  const captured = await captureForMemory(storage);
  return { captured, at, isCurrent: () => generation() === gen };
}
