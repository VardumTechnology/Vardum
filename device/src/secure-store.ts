/**
 * @veil/device — secure storage over the platform keystore.
 *
 * The ONLY primitive the Expo shell must implement: SecureStore
 * (react-native-keychain / expo-secure-store / Keychain on iOS, Keystore on
 * Android). Keychain-style stores are not enumerable, so VeilStorage's
 * keys(prefix) sweep is served through a maintained index record.
 *
 * Everything the web app kept in localStorage under veil_* keys lives here:
 * NO plaintext key material ever touches AsyncStorage or plain files.
 */

import type { VeilStorage } from '../../crypto-core/src/index';

/** Platform primitive the Expo shell provides. Never returns secrets in logs. */
export interface SecureStore {
  get(key: string): Promise<string | null>;
  set(key: string, value: string): Promise<void>;
  delete(key: string): Promise<void>;
  /** b71 (review): every key the platform store actually holds, when it can say
   *  (Keychain services / Keystore aliases). Wipes use it as well as the index,
   *  so a lost or unreadable index can no longer hide keys from a wipe. */
  list?(): Promise<string[]>;
  /** b75 (audit AL-6): whether an entry exists, without opening it (a wipe's verify
   *  pass; after a crypto-shred get() reads sealed entries as missing) */
  present?(key: string): Promise<boolean>;
  /** b75 (AL-6): destroy the container key (every sealed entry becomes unreadable) */
  shred?(): Promise<void>;
  /** b75 (AL-6): new container key, the kept entries re-sealed, the old key destroyed */
  rotate?(keep: string[]): Promise<void>;
  /** b75 (AL-6): destroy the key that seals the pending-media list */
  shredMedia?(): Promise<void>;
  /** b75 (AL-6): seal the plaintext entries left from before the container key.
   *  b75 (DEV-I2): `out.complete` says whether every entry was checked and none deferred */
  sealAll?(keys: string[], pauseMs?: number, out?: { complete?: boolean }): Promise<number>;
  /** b75 (audit DEV-L1): length of a value stored unsealed, 0 when sealed or absent (sizes
   *  a wipe's zero-fill without reading through get()) */
  plainLength?(key: string): Promise<number>;
  /** b75 (DEV-L1): a wipe begins / ends: no background migration and no new container
   *  key in between */
  beginWipe?(): void;
  endWipe?(): void;
  /** b75 (DEV-I2): a key that is never migrated in the background was read unsealed */
  needsSeal?(key: string): boolean;
  /** b75 round 2 (audit D1): move the kept records an older build sealed under the main
   *  key to the kept slot (`listKeys` is asked only when that was not done yet) */
  homeKept?(listKeys: () => Promise<string[]>): Promise<boolean>;
  /** b75 round 3 (audit DV-2): a wipe's overwrite of a value stored unsealed, with zeros of
   *  its length (an explicit call; zero-fills are never recognised by their value) */
  zeroFill?(key: string): Promise<void>;
  /** b75 round 3 (audit DV-1): has every entry been sealed (kept outside the store) */
  sealedInstall?(): Promise<boolean>;
  /** b75 round 3 (DV-1 / DV-6): mark the install sealed once a pass found nothing left */
  sealInstall?(keys: string[]): Promise<boolean>;
}

const INDEX_KEY = 'veil_keychain_index';
/** Batch C (B2): a second copy of the index — a corrupted copy can't hide keys from a wipe */
const INDEX_KEY_B = 'veil_keychain_index_b';
const isIndexKey = (k: string) => k === INDEX_KEY || k === INDEX_KEY_B;

/**
 * VeilStorage over a non-enumerable secure store, with a key index.
 * Batch C (B2; reviews P2 V-22, P3 R2, P4 F-16): every index read-modify-write
 * runs under one lock (concurrent saves used to drop entries — those keys then
 * escaped every wipe); the index is kept twice and read as the union of the
 * copies that parse; a wipe deletes key by key (one failure no longer stops
 * it) and finishes with a verify pass.
 */
export class KeychainStorage implements VeilStorage {
  constructor(private store: SecureStore) {}

  private indexLock: Promise<unknown> = Promise.resolve();
  private withIndex<T>(fn: () => Promise<T>): Promise<T> {
    const run = this.indexLock.catch(() => undefined).then(fn);
    this.indexLock = run.catch(() => undefined);
    return run;
  }

  /** b71 (review): the index copies, plus what the store itself lists when a copy
   *  is missing or unreadable (and always for a wipe or a sweep). An unreadable
   *  index used to read as empty: the next save rewrote it with one entry, and
   *  every later wipe missed the identity and chat keys while reporting clean. */
  private async readIndex(full = false): Promise<string[]> {
    const out = new Set<string>();
    let degraded = false;
    for (const k of [INDEX_KEY, INDEX_KEY_B]) {
      try {
        const raw = await this.store.get(k);
        if (raw === null) { degraded = true; continue; }
        const v = JSON.parse(raw) as unknown;
        if (Array.isArray(v)) { for (const x of v) if (typeof x === 'string') out.add(x); } else degraded = true;
      } catch { degraded = true; /* this copy is unreadable — the other one still counts */ }
    }
    if ((full || degraded) && this.store.list) {
      try {
        for (const x of await this.store.list()) if (typeof x === 'string' && !isIndexKey(x)) out.add(x);
      } catch { /* the index copies are all there is */ }
    }
    return [...out];
  }

  private async writeIndex(keys: string[]): Promise<void> {
    const v = JSON.stringify(keys);
    await this.store.set(INDEX_KEY, v);
    await this.store.set(INDEX_KEY_B, v);
  }

  // ---------- b77k2 (IP77-5, owner decision): the Nothing-at-Rest memory session ----------
  /**
   * From the dial flip to Nothing-at-Rest until the user leaves the app, the chats keep working
   * with NOTHING on disk: the flip copies the records it is about to shred (every veil_ record
   * outside its keep list: each chat's ratchet state and per-chat records, the chat list's
   * records; the identity from memory) into this map BEFORE the shred, and from then on every
   * read and write of such a record is served here, never by the platform store. A chat made
   * after the flip lives here too (the post-wipe barrier used to refuse its writes, so it could
   * not save its state at all). The departure wipe (and every other wipe) drops the map at its
   * crypto-shred (cryptoShred / rotateSealKey, the first step of eraseLocal), after its capture
   * reads; from the moment such a wipe freezes writes, the map takes no more writes. Leaving
   * Nothing-at-Rest for a stored mode writes the map to the store (commitMemorySession): the
   * chats of a Nothing-at-Rest session started from a restore are stored (sealed) and simply stay
   * when the mode is turned down, so the flip's chats end up the same. A process death loses the
   * map (the chats' mailboxes then stay open until the relay's sweep).
   */
  private ram: Map<string, string> | null = null;
  /** the records the flip kept on disk (they never move to memory) */
  private ramKeep = new Set<string>();
  /** the memory session takes writes under a freeze only until the next wipe freezes */
  private ramWritableFrozen = false;
  /** b77u (audit 6 U-M5): a memory session limited to these name prefixes (null: every veil_ record) */
  private ramPrefixes: string[] | null = null;
  /** keys written / removed while a commit runs (see commitMemorySession) */
  private ramCommit: { dirty: Set<string> } | null = null;
  private toRam(key: string): boolean {
    return !!this.ram && key.startsWith('veil_') && !isIndexKey(key) && !this.ramKeep.has(key) && !KeychainStorage.FREEZE_EXEMPT.has(key)
      && (!this.ramPrefixes || this.ramPrefixes.some((p) => key.startsWith(p)));
  }
  /** the flip: serve `entries` (minus the kept records) from memory from now on.
   *  b77k2 (re-review M1): `atFreeze` = freezeEpoch() when the flip's wipe froze writes; a wipe that
   *  froze writes since (a departure or duress wipe that ran during the flip) refuses it (false) */
  startMemorySession(entries: Map<string, string>, keep: string[], atFreeze?: number, prefixes?: string[]): boolean {
    if (atFreeze !== undefined && atFreeze !== this.freezeStarts) return false;
    // b77u (audit 6 U-M5): `prefixes` limits the session to those names (the decoy's veil_dk_ records under
    // Nothing-at-Rest); every other record keeps the post-wipe barrier and the tombstones
    this.ramPrefixes = prefixes && prefixes.length ? [...prefixes] : null;
    this.ramKeep = new Set(keep);
    const ram = new Map<string, string>();
    for (const [k, v] of entries) {
      if (k.startsWith('veil_') && !isIndexKey(k) && !this.ramKeep.has(k) && !KeychainStorage.FREEZE_EXEMPT.has(k)
        && (!this.ramPrefixes || this.ramPrefixes.some((p) => k.startsWith(p)))) ram.set(k, v);
    }
    this.ram = ram;
    this.ramDiskLeft = new Set();
    this.ramWritableFrozen = true; // the flip's own freeze (until its verify pass) is still on
    return true;
  }
  /** b77k2 (re-review M1): how many times a wipe has frozen writes (see startMemorySession) */
  private freezeStarts = 0;
  freezeEpoch(): number { return this.freezeStarts; }
  /** records under a memory-session name that the flip's erase could not remove from the store
   *  (normally none): a wipe's sweep still removes them from the store, never from memory */
  private ramDiskLeft = new Set<string>();
  /** the flip, once the session is live: note what its erase left in the store (see ramDiskLeft) */
  async scanMemorySessionLeftovers(): Promise<number> {
    if (!this.ram) return 0;
    try { this.ramDiskLeft = new Set((await this.diskKeys('veil_')).filter((k) => this.toRam(k))); } catch { /* none known */ }
    return this.ramDiskLeft.size;
  }
  /** is a memory session live? */
  memorySessionActive(): boolean { return !!this.ram; }
  /** b77u2 (UC-M1): is the live memory session limited to some name prefixes (the decoy's veil_dk_ one)? */
  memorySessionLimited(): boolean { return !!this.ram && !!this.ramPrefixes; }
  /** the records the memory session holds right now (tests, diagnostics) */
  memorySessionKeys(): string[] { return this.ram ? [...this.ram.keys()] : []; }
  /** end the memory session: everything in it is gone */
  dropMemorySession(): void {
    if (this.ram) this.ram.clear();
    this.ram = null;
    this.ramCommit = null;
    this.ramWritableFrozen = false;
    this.ramPrefixes = null;
    this.ramDiskLeft.clear();
  }
  /**
   * Leaving Nothing-at-Rest for a stored mode: the memory session's records go to the store and
   * the session ends (the flip's post-wipe barrier and tombstones go: the user turned the
   * protection down, password-checked). Refused (-1, nothing changes) while a wipe's write freeze
   * is on. Reads keep coming from memory until the last record is written, and a record written
   * or removed meanwhile is written (or removed) again, so no older copy overwrites a newer one.
   * Returns the records that could not be written (0 = all; > 0 = the session stays live, nothing
   * is lost, retry later).
   */
  async commitMemorySession(): Promise<number> {
    const ram = this.ram;
    if (!ram) return 0;
    if (this.frozen || this.ramCommit) return -1;
    this.clearTombstones();
    const dirty = new Set(ram.keys());
    this.ramCommit = { dirty };
    let failed = 0;
    try {
      while (dirty.size) {
        const k = dirty.values().next().value as string;
        dirty.delete(k);
        if (this.ram !== ram) return -1; // a wipe dropped it meanwhile
        const v = ram.get(k);
        if (v === undefined) { await this.removeStored(k); continue; }
        if (!(await this.setStored(k, v))) failed++;
      }
      if (this.ram !== ram) return -1;
      // b77k2 (review L-3): a record the store refused is never lost — the whole session stays in
      // memory (still serving every read and write) and the caller retries; the copies already
      // written are overwritten by that retry
      if (failed > 0) return failed;
      ram.clear();
      this.ram = null;
      this.ramWritableFrozen = false;
      return failed;
    } finally {
      this.ramCommit = null;
    }
  }

  async get(key: string): Promise<string | null> {
    if (this.toRam(key)) return this.ram!.get(key) ?? null; // b77k2 (IP77-5): the store holds none of these
    return this.store.get(key);
  }

  /** b70 (re-review): while a wipe runs, background syncs must not write keys
   *  back. Only the wipe's own zero-fill overwrites (and deletes) go through;
   *  any other write is refused (reported as a failed save). */
  private frozen = false;
  /**
   * b75 round 2 (audit D5): the records the running wipe keeps (Nothing-at-Rest's list;
   * empty for the full wipes). When the freeze ends, a barrier goes up: every OTHER veil_
   * write is refused for the rest of this run, until a deliberate fresh start
   * (clearTombstones: create / restore an identity, sign in). The tombstones below cover
   * only the secret prefixes, so work in flight when the wipe began (the group-invite
   * flush, a sync, a push registration) could write any other veil_ record back once the
   * freeze ended, sealed under a NEW container key, readable after a "complete" wipe.
   */
  private freezeKeep: Set<string> | null = null;
  private barrier: Set<string> | null = null;
  private freshDuringFreeze = false;
  /** b77k (IP77-6): told whenever the write freeze starts or ends (the lock screen waits it out) */
  private freezeSubs = new Set<(frozen: boolean) => void>();
  onFreezeChange(fn: (frozen: boolean) => void): () => void {
    this.freezeSubs.add(fn);
    return () => { this.freezeSubs.delete(fn); };
  }
  /** b77k (IP77-6): is a wipe's write freeze on right now? */
  writesFrozen(): boolean { return this.frozen; }
  freezeWrites(on: boolean, keep: string[] = []): void {
    const was = this.frozen;
    // b77k2 (IP77-5): a wipe beginning: the memory session takes no more writes (its shred drops it)
    if (on) { this.ramWritableFrozen = false; this.freezeStarts++; }
    if (on && !this.frozen) this.freshDuringFreeze = false;
    if (on && this.freshDuringFreeze) {
      // a fresh start already happened inside this freeze: nothing to protect any more
    } else if (on) {
      // overlapping wipes: only what every one of them keeps stays writable
      this.freezeKeep = this.freezeKeep ? new Set(keep.filter((k) => this.freezeKeep!.has(k))) : new Set(keep);
    } else if (this.frozen && !this.freshDuringFreeze) {
      const kept = this.freezeKeep ?? new Set<string>();
      this.barrier = this.barrier ? new Set([...kept].filter((k) => this.barrier!.has(k))) : kept;
      this.freezeKeep = null;
    }
    this.frozen = on;
    // b75 (audit DEV-L1): the store's wipe mode follows the freeze: from the moment a
    // wipe freezes writes until it ends, no read migrates and no container key is made
    try { if (on) this.store.beginWipe?.(); else this.store.endWipe?.(); } catch { /* never throws */ }
    if (was !== on) for (const fn of [...this.freezeSubs]) { try { fn(on); } catch { /* a listener never stops the freeze */ } }
  }

  /**
   * b70 (re-review 3): secret keys a wipe removed stay refused for the rest of
   * this run. Work that was already in flight (a send waiting on the relay, a
   * prekey rotation, a sync) would otherwise write chat keys, message text or
   * the identity back once the wipe's write freeze ended. Only creating or
   * restoring an identity (a deliberate fresh start) lifts this.
   */
  private tombstones = new Set<string>();
  /** b77r1 (audit A-9): + a 1:1 chat's mailbox state (cursor, wake reference) and its outbox of
   *  sealed envelopes — per-token records like the ratchet state, so a send or sync in flight
   *  can't write them back for a chat the wipe removed.
   *  b77z2 (Z-1): + a 1:1 chat's display marks (envelope ids the human saw), written outside the
   *  per-token chain by the display marker and the purge, so a mark in flight can't land after a
   *  wipe removed the chat */
  private static readonly SECRET_PREFIXES = ['veil_rk_', 'veil_msgcache_', 'veil_gk_', 'veil_keyvault_identity', 'veil_notes_key', 'veil_mbox_', 'veil_outbox_', 'veil_displayed_'];
  /** b70 (re-review 6): chats whose ratchet state a wipe removed — no secret key
   *  for them is written again this run (a send in flight used to write its
   *  message cache, a key that had never existed, after the wipe) */
  private tombTokens = new Set<string>();
  private tombstone(key: string): void {
    if (!this.frozen || !KeychainStorage.SECRET_PREFIXES.some((p) => key.startsWith(p))) return;
    this.tombstones.add(key);
    if (key.startsWith('veil_rk_') && !key.startsWith('veil_rk_wrap_')) this.tombTokens.add(key.slice('veil_rk_'.length));
  }
  private tombstoned(key: string): boolean {
    if (this.tombstones.has(key)) return true;
    if (!this.tombTokens.size) return false;
    for (const p of KeychainStorage.SECRET_PREFIXES) {
      if (!key.startsWith(p)) continue;
      const rest = key.slice(p.length);
      for (const t of this.tombTokens) if (rest === t || rest.startsWith(t + '_')) return true;
    }
    return false;
  }
  clearTombstones(): void {
    this.tombstones.clear();
    this.tombTokens.clear();
    this.barrier = null; // b75 round 2 (audit D5)
    if (this.frozen) { this.freezeKeep = null; this.freshDuringFreeze = true; } // the barrier then stays down
    // b75 (DEV-L1): a deliberate fresh start may make a new container key at once
    if (!this.frozen) { try { this.store.endWipe?.(); } catch { /* never throws */ } }
  }

  /** b75 (audit AL-7 / AL-9): the wipe's own bookkeeping may be written while it runs
   *  (the pending marker, the push-unregister marker, the pending-media list) */
  private static readonly FREEZE_EXEMPT = new Set(['veil_wipe_pending', 'vardum_push_unreg_pending', 'vardum_media_pending']);

  async set(key: string, value: string): Promise<boolean> {
    // b77k2 (IP77-5): a memory-session record is written to memory only (never the platform store)
    if (this.toRam(key)) {
      if (this.frozen && !this.ramWritableFrozen) return false;
      this.ram!.set(key, value);
      this.ramCommit?.dirty.add(key);
      return true;
    }
    return this.setStored(key, value);
  }

  private async setStored(key: string, value: string): Promise<boolean> {
    // b75 round 3 (audit DV-2): every write is checked, whatever it holds. A value of zeros
    // (or an empty one) used to pass the freeze, the tombstones and the barrier as if it
    // were a wipe's zero-fill; the wipe's overwrite is zeroFill() now.
    if (this.frozen && !KeychainStorage.FREEZE_EXEMPT.has(key)) return false;
    if (this.tombstoned(key)) return false; // b70 (re-review 3 / 6)
    // b75 round 2 (audit D5): after a wipe, no veil_ record outside its keep list.
    // b75 round 3 (audit DV-3): nor a vardum_ one (the decoy push hold, written by a step
    // queued before the wipe, used to make a new kept-slot key after it)
    if (this.barrier && (key.startsWith('veil_') || key.startsWith('vardum_')) && !isIndexKey(key)
      && !this.barrier.has(key) && !KeychainStorage.FREEZE_EXEMPT.has(key)) return false;
    try {
      // Batch I (local review V-04; RV-37): the index entry is written FIRST.
      // A value written before its entry escaped every wipe if the index write
      // then failed; an entry for a value that never landed is harmless.
      // b63 review (I3-1): the value write stays inside the index lock, so a
      // wipe can't run between the entry and the value and orphan the value.
      if (!isIndexKey(key)) {
        await this.withIndex(async () => {
          const keys = await this.readIndex();
          if (!keys.includes(key)) {
            keys.push(key);
            await this.writeIndex(keys);
          }
          await this.store.set(key, value);
        });
      } else {
        await this.store.set(key, value);
      }
      return true;
    } catch (e) {
      // b196-r7: never swallow silently — Metro must see the native failure
      // (user-facing copy stays sanitized elsewhere; this is the developer log).
      console.error('[veil-secure] KeychainStorage.set failed:', key, e);
      return false;
    }
  }

  async remove(key: string): Promise<void> {
    if (this.toRam(key)) { // b77k2 (IP77-5): the store holds none of these (but a leftover)
      this.ram!.delete(key);
      this.ramCommit?.dirty.add(key);
      if (this.ramDiskLeft.delete(key)) await this.removeStored(key);
      return;
    }
    return this.removeStored(key);
  }

  private async removeStored(key: string): Promise<void> {
    this.tombstone(key);
    try {
      if (isIndexKey(key)) {
        await this.store.delete(key);
      } else {
        // b63 review (I3-1): delete under the index lock, in order with set()
        await this.withIndex(async () => {
          await this.store.delete(key);
          const keys = await this.readIndex();
          const i = keys.indexOf(key);
          if (i >= 0) {
            keys.splice(i, 1);
            await this.writeIndex(keys);
          }
        });
      }
    } catch {
      /* never throws */
    }
  }

  /** b71 (audit): delete many keys, then rewrite the index ONCE (a close wipe used to
   *  rewrite both index copies after every key — slow, and a suspended wipe left
   *  more behind). In order; one failure doesn't stop the rest. */
  async removeMany(keysIn: string[]): Promise<void> {
    // b77k2 (IP77-5): a memory-session record leaves memory, and the store too (a wipe primitive: the
    // store copy, if any, must go whatever memory holds); a known leftover of the flip's erase
    // (a wipe's sweep lists the store only) leaves the store, and its live copy in memory stays
    if (this.ram) {
      for (const k of keysIn) {
        if (!this.toRam(k) || this.ramDiskLeft.delete(k)) continue;
        this.ram.delete(k); this.ramCommit?.dirty.add(k);
      }
    }
    const keys = keysIn;
    const doomed = keys.filter((k) => !isIndexKey(k));
    for (const k of doomed) this.tombstone(k);
    await this.withIndex(async () => {
      const gone: string[] = [];
      for (const k of doomed) {
        try { await this.store.delete(k); gone.push(k); } catch { /* left in the index: a later wipe retries it */ }
      }
      if (!gone.length) return;
      try { await this.writeIndex((await this.readIndex()).filter((k) => !gone.includes(k))); } catch { /* the entries stay; harmless */ }
    }).catch(() => undefined);
  }

  /** b75 round 3 (audit DV-2): a wipe's in-place overwrite of a value before its delete. Not
   *  subject to the freeze, the tombstones or the barrier (it only overwrites what is
   *  there; it never creates an entry and never adds one to the index). A sealing store
   *  overwrites only a value stored unsealed; a plain store gets `len` zeros. */
  async zeroFill(key: string, len: number): Promise<void> {
    if (this.toRam(key) && !this.ramDiskLeft.has(key)) return; // b77k2 (IP77-5): nothing of it is stored
    if (this.store.zeroFill) { await this.store.zeroFill(key); return; }
    if (len > 0) await this.store.set(key, '0'.repeat(len));
  }

  /** b75 (audit AL-6): is an entry still stored under this key (sealed or not)? */
  async present(key: string): Promise<boolean> {
    if (this.store.present) return this.store.present(key);
    return (await this.store.get(key)) !== null;
  }

  /** b75 (AL-6): crypto-shred: destroy the container key. false = this store has none
   *  (tests, the decoy store); a failed destroy throws. */
  async cryptoShred(): Promise<boolean> {
    this.dropMemorySession(); // b77k2 (IP77-5): every wipe's shred ends the memory session too
    if (!this.store.shred) return false;
    await this.store.shred();
    return true;
  }

  /** b77u2 (UC-L2): a shred run outside a wipe's write freeze (the set-up's settleLeftoverWipe) is over: the store may
   *  make a fresh container key again (a freeze in force keeps the store in wipe mode until it ends) */
  endShred(): void {
    if (this.frozen) return;
    try { this.store.endWipe?.(); } catch { /* never throws */ }
  }

  /** b75 (AL-6): Nothing-at-Rest's crypto-shred: a new container key for the kept
   *  entries, the old key (and with it everything else) destroyed. false = no
   *  container key on this store. Throws, destroying nothing, if a kept entry can't
   *  be moved. */
  async rotateSealKey(keep: string[]): Promise<boolean> {
    this.dropMemorySession(); // b77k2 (IP77-5): Nothing-at-Rest's departure shred ends the memory session
    if (!this.store.rotate) return false;
    await this.store.rotate(keep);
    return true;
  }

  /** b75 (AL-6): seal, in the background, every entry still stored in plaintext from
   *  before b75 (0 = nothing to do, or no container key on this store) */
  /** b75 (audit DEV-I2): once a pass finds nothing left (every entry checked, none
   *  deferred) it marks the install sealed, and later launches skip the full read of the
   *  store. The app runs it first thing at launch, under a deadline, and again in the
   *  background. b75 round 3 (audit DV-1): the mark is the store's slot-'s' file, outside
   *  the store (a store marker could be deleted, which reopened the migration and made an
   *  unsealed value trusted again). */
  private sealing: Promise<number> | null = null;
  sealOlderEntries(pauseMs?: number): Promise<number> {
    // one pass at a time (the launch's bounded pass may still be running when the
    // background one is asked for)
    if (!this.sealing) this.sealing = this.sealPass(pauseMs).finally(() => { this.sealing = null; });
    return this.sealing;
  }
  private async sealPass(pauseMs?: number): Promise<number> {
    // b75 round 2 (audit D1): first, the kept records go home to the kept slot (one read
    // of its mark once done), so the Nothing-at-Rest close wipe only destroys the main key
    if (this.store.homeKept && !this.frozen) {
      try { await this.store.homeKept(() => this.withIndex(() => this.readIndex(true))); } catch { /* the next launch retries */ }
    }
    if (!this.store.sealAll || this.frozen) return 0;
    try { if (this.store.sealedInstall && (await this.store.sealedInstall())) return 0; } catch { /* run the pass */ }
    const keys = await this.withIndex(() => this.readIndex(true));
    const out: { complete?: boolean } = {};
    const n = await this.store.sealAll(keys.filter((k) => !isIndexKey(k)), pauseMs, out);
    if (out.complete && !this.frozen && this.store.sealInstall) {
      try { await this.store.sealInstall(keys); } catch { /* the next pass tries again */ }
    }
    return n;
  }

  /** b75 (audit DEV-L1): the length of a value stored unsealed (a wipe's zero-fill size);
   *  stores without a container key report the plain value's length */
  async plainLength(key: string): Promise<number> {
    if (this.store.plainLength) return this.store.plainLength(key);
    const v = await this.store.get(key);
    return typeof v === 'string' ? v.length : 0;
  }

  /** b75 (audit DEV-I2): this run read a never-migrated key unsealed (no store access) */
  needsSeal(key: string): boolean {
    try { return !!this.store.needsSeal?.(key); } catch { return false; }
  }

  /** b75 (AL-6): the pending-media list is done with: destroy the key that sealed it */
  async shredMediaKey(): Promise<void> {
    try { await this.store.shredMedia?.(); } catch { /* best-effort */ }
  }

  async keys(prefix: string): Promise<string[]> {
    const stored = await this.diskKeys(prefix);
    if (!this.ram) return stored;
    // b77k2 (IP77-5): + the memory session's records
    const out = new Set(stored.filter((k) => !this.toRam(k)));
    for (const k of this.ram.keys()) if (k.startsWith(prefix)) out.add(k);
    return [...out];
  }

  /** b77k2 (IP77-5): only what the platform store holds — a wipe's sweep and verify pass (the
   *  flip's verify pass runs while its memory session is already live and must not touch it) */
  async diskKeys(prefix: string): Promise<string[]> {
    return (await this.withIndex(() => this.readIndex(true))).filter((k) => k.startsWith(prefix) && !isIndexKey(k));
  }

  /** Wipe every key under the prefixes (duress / storage-mode flip / end-session).
   *  Returns how many keys could NOT be removed (0 = clean). */
  async wipe(...prefixes: string[]): Promise<number> {
    // b77k2 (re-review M3): the store only, never the memory session — vault.setMode('memory') runs this
    // on every settings save while the mode is on, and it used to delete the carried chats from memory
    return this.withIndex(async () => {
      const all = await this.readIndex(true);
      const doomed = all.filter((k) => prefixes.some((p) => k.startsWith(p)));
      for (const k of doomed) this.tombstone(k);
      const failed: string[] = [];
      for (const k of doomed) {
        try { await this.store.delete(k); } catch { failed.push(k); }
      }
      // verify pass: anything still readable gets one more delete
      const stuck: string[] = [];
      for (const k of doomed) {
        let still = failed.includes(k);
        try { still = still || (await this.present(k)); } catch { /* unreadable counts as gone */ }
        if (!still) continue;
        try { await this.store.delete(k); if (await this.present(k)) stuck.push(k); } catch { stuck.push(k); }
      }
      await this.writeIndex(all.filter((k) => !doomed.includes(k) || stuck.includes(k)));
      return stuck.length;
    });
  }
}
