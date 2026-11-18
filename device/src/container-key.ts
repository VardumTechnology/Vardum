/**
 * @veil/device — b75 (audit AL-6; owner decision): every secure-store value is
 * sealed under a key that lives in the app's own container.
 *
 * iOS keeps Keychain items when the app is deleted, so deleting Vardum (the
 * natural panic move) used to leave the identity seed, every ratchet state, the
 * message cache and the login on the phone. Now each value is AES-256-GCM
 * ciphertext under a random 256-bit "container key" kept in a file inside the
 * app's sandbox (excluded from backups, see the native ck* functions). iOS
 * deletes that file with the app, so whatever the Keychain keeps is useless.
 * Android gets the same layer (its store dies with the app anyway; there the
 * file's key is itself wrapped by a Keystore key bound to an unlocked phone where
 * the phone supports it), so the code is exercised on the emulators.
 *
 * Wipes destroy the container key FIRST (a crypto-shred): a wipe cut short
 * leaves only ciphertext nobody can open. b75 round 2 (audit D1 / D8): the few
 * records Nothing-at-Rest keeps (CK_KEPT_KEYS) are sealed, from their first write
 * on, under their own slot 'k', never under the main key. The Nothing-at-Rest close
 * wipe is then a plain destroy of the main key: no new key is made and nothing is
 * re-sealed before the old key goes. It used to rotate (create key b, re-seal the
 * kept records one by one, and only then destroy key a), so a close wipe cut short
 * left everything openable, and on Android the unlock-bound wrap key could refuse
 * the new key on a phone that was locking.
 *
 * Format of a sealed value:  vck1.<slot>.<base64(iv12 || ct || tag16)>
 *   AAD = "vardum-ck-v1|<slot>|<gen>|<storage key>": a value can't be moved to
 *   another key name, and a recreated slot (new gen, new key) never opens old ones.
 * Slots: 'a' (or 'b', left by an older build's rotation) is the main key; 'k' seals
 * only the records Nothing-at-Rest keeps; 'm' seals only the pending-media list,
 * which must outlive a wipe until those files are deleted.
 *
 * Migration is lazy and loss-free: a plaintext value (written before b75) reads
 * as before, and is re-written sealed in the background, under a per-key lock,
 * only if it is still the same value. A kill at any point leaves either the old
 * plaintext or the new ciphertext, and the key file is written (durably) before
 * the first value is sealed under it.
 *
 * b75 round 3 (audit DV-1 / DV-2 / DV-6 / DV-7 / DV-8): the rule against someone who can
 * write the platform store but has no container key (spec §6.2). Once every entry is
 * sealed, the install is "sealed": a file in slot 's' (CK_SEALED_SLOT) says so. It lives
 * with the container keys, outside the store, so deleting store entries can't reopen
 * the migration (the old marker was a store entry anyone could delete). From then on:
 *   - a value that is not sealed is tampering (it can only have been planted): a
 *     fail-closed key throws SealedValueError, any other key reads as missing, and
 *     nothing re-seals it. An empty value is a value like any other;
 *   - the fail-closed records the store keeps (CK_FAIL_CLOSED_KEYS that are kept) are
 *     listed, sealed, in CK_PRESENT_KEY. One that is listed but missing, or any missing
 *     one while the list itself is missing or does not open, is tampering (it throws):
 *     deleting a record no longer turns its protection off. The list is updated before a
 *     record is deleted and after one is written, so a kill never makes a record look
 *     tampered.
 * A wipe's zero-fill is an explicit call (zeroFill), never recognised by its value.
 */

import { gcm } from '@noble/ciphers/aes';
import { hmac } from '@noble/hashes/hmac';
import { sha256 } from '@noble/hashes/sha256';
import { fromB64, toB64, utf8, fromUtf8, randomBytes } from '../../crypto-core/src/index';
import type { SecureStore } from './secure-store';

/** Native file store for the container keys (modules/veil-crypto ck*). */
export interface ContainerKeyFiles {
  /** the slot's key, null when the slot has no file. THROWS when the file exists
   *  but can't be read right now (never "absent" on a read error). */
  read(slot: string): Promise<{ key: string; gen: number } | null>;
  /** create a fresh random key in an EMPTY slot (refuses to overwrite), durably */
  create(slot: string, gen: number): Promise<{ key: string; gen: number }>;
  /** delete one slot's file (resolves once it is gone). b75 round 2 (audit I2): the
   *  protection is that the key is gone; the zero overwrite before the delete is
   *  best-effort only (flash storage may keep the old blocks). */
  remove(slot: string): Promise<void>;
  /** b75 round 2 (audit I1): delete the platform key that seals the slot files
   *  (Android Keystore vardum-ck-wrap) once no slot file is left. Optional. */
  dropWrapKeyIfIdle?(): Promise<void>;
}

export const CK_PREFIX = 'vck1.';

/** Stored unsealed: the key index copies (key names only; a wipe must still list
 *  keys after the shred), the wipe-pending marker ('1', read at launch after the
 *  shred), and the push-unregister marker ('1', kept outside every wipe).
 *  b75 round 3 (audit DV-1): the old "every entry sealed" store marker (veil_ck_sealed_v1)
 *  is gone: anyone who could write the store could delete it and reopen the migration.
 *  The sealed state is the slot-'s' file now (CK_SEALED_SLOT).
 *  b77m review (M1): the one-bit Nothing-at-Rest marker (keyvault.ts NAR_MARKER_KEY: read at a cold boot when
 *  the sealed records can't be), and (L7) the UnifiedPush choice migration flag ('1', unifiedpush.ts). */
export const CK_RAW_KEYS: ReadonlySet<string> = new Set(['veil_keychain_index', 'veil_keychain_index_b', 'veil_wipe_pending', 'vardum_push_unreg_pending', 'veil_nar_marker', 'vardum_up_choice_v1']);
/** b75 round 3 (DV-1): the store marker an earlier b75 build left; removed when the
 *  install is sealed, never read */
export const CK_OLD_SEALED_MARK = 'veil_ck_sealed_v1';
/** b75 round 3 (DV-1): the slot whose FILE says "every entry is sealed" (no value is ever
 *  sealed under it; the key in it is unused) */
export const CK_SEALED_SLOT = 's';
/** b75 round 3 (DV-6 / DV-7 / DV-8): the sealed list of the fail-closed records the store
 *  holds (kept, so Nothing-at-Rest keeps it with them) */
export const CK_PRESENT_KEY = 'veil_ck_present_v1';
/**
 * b75 round 3 (audit DV-1 / DV-6 / DV-7 / DV-8): the records whose damage, removal or
 * replacement must never read as "off". An altered or (once sealed) unsealed value throws
 * SealedValueError; a missing one throws when the presence list says it should be there.
 * The app lock, its attempt rows and key, the settings, the decoy push hold, the notes'
 * rollback marks; and the key index copies (raw: a damaged copy is rebuilt from list()).
 */
export const CK_FAIL_CLOSED_KEYS: ReadonlySet<string> = new Set([
  'veil_app_lock', 'veil_lockout', 'veil_app_lock_key', 'veil_lock_wrong_in_a_row', 'veil_settings_v1',
  'veil_keychain_index', 'veil_keychain_index_b',
  'vardum_push_hold_v1', 'veil_notes_versions', 'veil_notes_bound_only',
  // b77n (pre-audit LOW-1): the storage-mode record. Read as missing when it failed its check (or its slot
  // key was gone, or it was deleted), the cold-boot check took it for a clean "device" answer and kept a
  // Nothing-at-Rest phone. Now it throws (SealedValueError) and its presence is listed (it is kept).
  'veil_storage_mode',
]);
/** Sealed under the media slot: the list of saved photos/files a wipe still has to
 *  delete (it must outlive the wipe's shred until they are gone). */
export const CK_MEDIA_KEYS: ReadonlySet<string> = new Set(['vardum_media_pending']);
const MAIN_SLOTS = ['a', 'b'] as const;
export const CK_MEDIA_SLOT = 'm';
/** b75 round 2 (audit D1 / D8): the slot for the records Nothing-at-Rest keeps */
export const CK_KEPT_SLOT = 'k';
/** b75 round 2 (audit D1 / D3 / D4): the records Nothing-at-Rest keeps, sealed under
 *  CK_KEPT_SLOT from their first write: the login, storage mode, settings, app lock and
 *  its attempt rows and key, pinned contacts, client id, answered-request ledger
 *  (hashes), self-destruct clock; the notes' newest-version marks (D4: a restore after
 *  a Nothing-at-Rest departure no longer resets them); the decoy push hold (D3, outside
 *  the veil_ keys every wipe sweeps); and this slot's own "everything is home" mark.
 *  App.tsx's Nothing-at-Rest keep list is built from this set. */
export const CK_KEPT_KEYS: ReadonlySet<string> = new Set([
  'veil_auth_session', 'veil_storage_mode', 'veil_settings_v1', 'veil_app_lock', 'veil_pins_v1', 'veil_client_id',
  'veil_app_lock_key', 'veil_contact_seen_v1', 'veil_lockout', 'veil_lock_wrong_in_a_row', 'veil_selfdestruct_seen',
  'veil_notes_versions', 'veil_notes_bound_only', 'vardum_push_hold_v1', 'vardum_ck_kept_v1',
  CK_PRESENT_KEY, // b75 round 3 (DV-6): the presence list stays with the records it lists
  // b76r1 (registration lock, audit D2): the owning phone's device key stays with the login it
  // belongs to (auth.ts REGLOCK_DEVICE_STORAGE); dropping it made this phone need its own PIN
  'veil_reglock_device',
  // b77t (audit 5 L-5 / IH C-08): the pre-authorised duress purge token (src/duress-purge-token.ts): the duress
  // code at the lock screen of a Nothing-at-Rest phone (no identity in memory) still purges the account
  'veil_duress_purge_v1',
  // b77t (audit 5 M-E): the decoy account (src/decoy-account.ts DECOY_AUX_KEY): its login and identity keys, so the
  // decoy works after a Nothing-at-Rest departure and a restart. Present whenever an app lock is, fixed size
  'veil_lock_aux_v1',
  // b77t merge (owner decision: removing the decoy code deletes its relay account): the pending decoy-account deletes
  // (src/decoy-account.ts DECOY_END_KEY). On every install, fixed size; the delete runs after a random delay
  'veil_aux_pending_v1',
]);
/** b75 round 2 (D1): '1' once every kept record is sealed under CK_KEPT_SLOT (itself kept) */
export const CK_KEPT_MARK = 'vardum_ck_kept_v1';
const AAD_LABEL = 'vardum-ck-v1|';

/** b77p (audit VAR-15): a blinded record's name in the platform store: this prefix + 32 hex characters of
 *  HMAC-SHA256(name key, the record's real name). The name key is HMAC(main container key, label|slot|gen),
 *  so it dies with the main key (a crypto-shred): from then on the names are opaque for good. */
export const CK_NAME_PREFIX = 'veil_n_';
/** b77p (audit VAR-15): the sealed list of the real names stored blinded (for list()); sealed under the main
 *  key with the rest, deleted by shred() / rotate() with that key */
export const CK_NAME_MAP_KEY = 'veil_ck_names_v1';
const NAME_KEY_LABEL = 'vardum-ck-names-v1|';
const INDEX_KEYS: ReadonlySet<string> = new Set(['veil_keychain_index', 'veil_keychain_index_b']);
/** b77p (audit VAR-15): the record names the app blinds — every veil_ record sealed under the main key (the
 *  per-chat, per-group, per-mailbox and prekey records whose names carry relay identifiers), never a raw,
 *  kept or media record (their names are fixed words that name nothing, and Nothing-at-Rest keeps them) */
export function ckBlindable(key: string): boolean {
  return key.startsWith('veil_') && !key.startsWith(CK_NAME_PREFIX) && key !== CK_NAME_MAP_KEY && !CK_RAW_KEYS.has(key)
    && !CK_KEPT_KEYS.has(key) && !CK_MEDIA_KEYS.has(key) && key !== CK_PRESENT_KEY && key !== CK_KEPT_MARK
    && !CK_UNBLINDED_KEYS.has(key);
}
/** b77t (audit 5 M-A, R4 F-01): records never blinded although b77p-b77s blinded them. The identity keyvault
 *  entry: the platform adapter puts the Secure Enclave wrap / biometric access control on it by its literal
 *  name, so under a blinded name hardware mode silently stopped protecting it. Its name reveals nothing (every
 *  install has one). A copy an older build left blinded is read there and moved back to the literal name: in
 *  the background when the key may be lazily migrated, otherwise at its next deliberate save (needsSeal says
 *  so), so no biometric prompt ever comes from a background write. Must match keyvault.ts KEYVAULT_KEY. */
export const CK_UNBLINDED_KEYS: ReadonlySet<string> = new Set(['veil_keyvault_identity']);
const hex = (b: Uint8Array): string => [...b].map((x) => x.toString(16).padStart(2, '0')).join('');

export interface ContainerKeyOptions {
  /** keys stored as they are (read before any key exists, or after a wipe shred it) */
  raw(key: string): boolean;
  /** an altered value of these keys throws instead of reading as missing */
  failClosed?(key: string): boolean;
  /** keys sealed under the media slot instead of the main key */
  media?(key: string): boolean;
  /** b75 round 2 (audit D1): keys sealed under the kept slot (CK_KEPT_KEYS) */
  kept?(key: string): boolean;
  /** keys never re-written in the background (a write would show a prompt) */
  noLazyMigrate?(key: string): boolean;
  log?(msg: string): void;
  /** b77p (audit VAR-15): records stored under a BLINDED name (CK_NAME_PREFIX + HMAC). The platform store
   *  (and an after-first-unlock extraction of it) then shows no chat, group or mailbox identifier, not even
   *  how many of each there are by kind. Pass ckBlindable. Only raw, kept and media records keep their names. */
  blindNames?(key: string): boolean;
  /** b77p (audit VAR-15): the key index copies (veil_keychain_index, _b) are sealed under the main key instead
   *  of stored raw. Needs a platform store that can list its entries (inner.list): after a crypto-shred the
   *  index no longer opens and KeychainStorage reads what the store lists (blinded names then come back as
   *  opaque CK_NAME_PREFIX names, which a wipe deletes like any other). While a wipe runs with no main key,
   *  a write of the index deletes it instead (a missing index is read from the store's list). */
  sealIndex?: boolean;
}

/** Thrown when a sealed value fails its check (altered or swapped) for a fail-closed key. */
export class SealedValueError extends Error {
  constructor(key: string) {
    super(`A stored Vardum record could not be opened (${key.startsWith('veil_') ? 'it was altered' : 'damaged'}).`);
    this.name = 'SealedValueError';
  }
}

type SlotKey = { key: Uint8Array; gen: number };

/** every slot a file can be in (a new slot's generation is above all of them, DV-5) */
const ALL_SLOTS = ['a', 'b', CK_KEPT_SLOT, CK_MEDIA_SLOT, CK_SEALED_SLOT] as const;
/** the native files store the generation as a signed 32-bit number */
const MAX_GEN = 0x7fffffff;

/**
 * A SecureStore that seals every value under the container key. Sits directly on
 * the platform store (below the Android read cache and KeychainStorage's index).
 */
export class ContainerKeyStore implements SecureStore {
  private slots = new Map<string, SlotKey | null>();
  private slotLoads = new Map<string, Promise<SlotKey | null>>();
  private locks = new Map<string, Promise<unknown>>();
  /** bumped by every shred/rotation: background migrations started before it give up */
  private era = 0;
  private creating: Promise<SlotKey> | null = null;
  /**
   * b75 (audit DEV-L1): set by shred() and rotate(), cleared by endWipe() (the wipe's
   * write freeze ending). While set, a read never queues the background migration and no
   * main key is ever created. The wipe's own read pass used to queue the migration of an
   * entry left from before b75, which made a NEW container key after the shred and
   * re-sealed that entry under it: a wipe cut short there left it readable.
   */
  private wiping = false;
  /** b75 (audit DEV-I2): no-lazy-migrate keys read as plaintext this run (the app re-saves
   *  them at a deliberate moment; reading the store again would show a prompt) */
  private unsealedSeen = new Set<string>();
  /** b75 round 3 (DV-1): no-lazy-migrate keys read (or written) sealed this run: the
   *  install is marked sealed only once those are known to be sealed too */
  private sealedSeen = new Set<string>();
  /** b77t (audit 5 M-A): no-lazy-migrate keys read this run from a blinded copy an older build left (the
   *  app re-saves them at a deliberate moment, which puts them back under their real name) */
  private misplaced = new Set<string>();
  /** b75 round 3 (DV-5): the highest slot generation this run has seen or made */
  private genSeen = 0;
  /** b75 round 3 (DV-6): the presence list as last read or written, for one era;
   *  'broken' = missing or not opening (every missing tracked record is then tampering) */
  private presence: { era: number; v: Set<string> | 'broken' } | null = null;

  constructor(private inner: SecureStore, private files: ContainerKeyFiles, private opts: ContainerKeyOptions) {}

  // ---------- b77p (audit VAR-15): blinded record names, sealed index ----------
  /** name keys by main slot and generation (dropped with the slot keys) */
  private nameKeys = new Map<string, Uint8Array>();
  /** every platform name this run has used for a record (real name -> names). Never cleared by a wipe, so a
   *  delete after the shred still reaches a blinded entry whose name can no longer be computed. */
  private knownInner = new Map<string, Set<string>>();
  /** the sealed name list as last read or written, for one era and main key */
  private nameMap: { era: number; main: string; v: Set<string>; rev: Map<string, string> } | null = null;
  /** real names whose old (unblinded) entry was already looked for this run */
  private plainChecked = new Set<string>();

  /** is this a raw key (stored as it is)? The index copies are not, when they are sealed (sealIndex) */
  private isRaw(key: string): boolean {
    if (this.opts.sealIndex && this.inner.list && INDEX_KEYS.has(key)) return false;
    return this.opts.raw(key);
  }

  private blindable(key: string): boolean {
    return !!this.opts.blindNames && !key.startsWith(CK_NAME_PREFIX) && key !== CK_NAME_MAP_KEY && key !== CK_PRESENT_KEY
      && key !== CK_KEPT_MARK && !INDEX_KEYS.has(key) && !this.isRaw(key) && !this.opts.kept?.(key) && !this.opts.media?.(key)
      && this.opts.blindNames(key);
  }

  /** b77t (audit 5 M-A): a record stored under its real name that an older build may have left blinded */
  private wasBlinded(key: string): boolean {
    return !!this.opts.blindNames && CK_UNBLINDED_KEYS.has(key) && !this.blindable(key);
  }

  /** b77t (audit 5 M-A): move a blinded copy of an unblinded record back to its real name (the sealed value
   *  moves as it is: its AAD names the real key). Only when it is still the same value. */
  private moveToPlain(key: string, bn: string, raw: string): void {
    const era = this.era;
    void this.withKey(key, async () => {
      if (this.era !== era || this.wiping) return;
      if ((await this.inner.get(bn)) !== raw) return;
      if ((await this.inner.get(key)) == null) await this.inner.set(key, raw);
      await this.inner.delete(bn);
      this.misplaced.delete(key);
      await this.editNameMap(key, false);
    }).catch((e) => this.log(`[veil-secure] moving a record back to its real name deferred (${String((e as Error)?.message ?? e)})`));
  }

  private nameKeyOf(main: { slot: string; k: SlotKey }): Uint8Array {
    const id = `${main.slot}:${main.k.gen}`;
    let nk = this.nameKeys.get(id);
    if (!nk) { nk = hmac(sha256, main.k.key, utf8(`${NAME_KEY_LABEL}${main.slot}|${main.k.gen}`)); this.nameKeys.set(id, nk); }
    return nk;
  }

  private remember(key: string, inner: string): void {
    let set = this.knownInner.get(key);
    if (!set) { set = new Set(); this.knownInner.set(key, set); }
    set.add(inner);
  }

  /** the blinded platform name of a record under the current main key (null: no main key yet) */
  private async blindedName(key: string, main?: { slot: string; k: SlotKey } | null): Promise<string | null> {
    const m = main === undefined ? await this.activeMain() : main;
    if (!m) return null;
    const n = CK_NAME_PREFIX + hex(hmac(sha256, this.nameKeyOf(m), utf8(key))).slice(0, 32);
    this.remember(key, n);
    return n;
  }

  /** the sealed name list (real names stored blinded under the current main key) */
  private async readNameMap(): Promise<{ main: string; v: Set<string>; rev: Map<string, string> } | null> {
    const main = await this.activeMain();
    if (!main) return null;
    const id = `${main.slot}:${main.k.gen}`;
    if (this.nameMap && this.nameMap.era === this.era && this.nameMap.main === id) return this.nameMap;
    const era = this.era;
    const v = new Set<string>();
    const raw = await this.inner.get(CK_NAME_MAP_KEY);
    const p = raw ? ContainerKeyStore.parse(raw) : null;
    if (raw && p && p.slot === main.slot) {
      try {
        const b = fromB64(p.body);
        const list = JSON.parse(fromUtf8(gcm(main.k.key, b.subarray(0, 12), this.aad(main.slot, main.k.gen, CK_NAME_MAP_KEY)).decrypt(b.subarray(12)))) as unknown;
        if (Array.isArray(list)) for (const x of list) if (typeof x === 'string') v.add(x);
      } catch { this.log('[veil-secure] the list of blinded record names did not open — those records list as opaque names'); }
    }
    const rev = new Map<string, string>();
    for (const k of v) { const n = await this.blindedName(k, main); if (n) rev.set(n, k); }
    const out = { era, main: id, v, rev };
    if (this.era === era) this.nameMap = out;
    return out;
  }

  /** add or drop one real name in the sealed name list (never while a wipe runs: it deletes everything) */
  private async editNameMap(key: string, on: boolean): Promise<void> {
    if (this.wiping) return;
    await this.withKey(CK_NAME_MAP_KEY, async () => {
      if (this.wiping) return;
      const era = this.era;
      const cur = await this.readNameMap();
      if (!cur || cur.v.has(key) === on) return;
      const main = await this.activeMain();
      if (!main || this.era !== era) return;
      const v = new Set(cur.v);
      const rev = new Map(cur.rev);
      const n = await this.blindedName(key, main);
      if (on) { v.add(key); if (n) rev.set(n, key); } else { v.delete(key); if (n) rev.delete(n); }
      await this.inner.set(CK_NAME_MAP_KEY, this.seal(main.slot, main.k, CK_NAME_MAP_KEY, JSON.stringify([...v].sort())));
      if (this.era === era) this.nameMap = { era, main: `${main.slot}:${main.k.gen}`, v, rev };
    }).catch((e) => this.log(`[veil-secure] the blinded-name list was not updated (${String((e as Error)?.message ?? e)})`));
  }

  /** move a record an older build stored under its real name to its blinded name (the sealed value moves as
   *  it is: its AAD names the real key, not the platform name). Only when it is still the same value. */
  private moveToBlinded(key: string, raw: string): void {
    const era = this.era;
    void this.withKey(key, async () => {
      if (this.era !== era || this.wiping) return;
      const bn = await this.blindedName(key);
      if (!bn || this.era !== era || (await this.inner.get(key)) !== raw) return;
      if ((await this.inner.get(bn)) == null) await this.inner.set(bn, raw);
      await this.inner.delete(key);
      await this.editNameMap(key, true);
    }).catch((e) => this.log(`[veil-secure] moving a record to its blinded name deferred (${String((e as Error)?.message ?? e)})`));
  }

  /** b75 round 3 (DV-6): a fail-closed record the store keeps: its presence is listed */
  private tracked(key: string): boolean {
    return key !== CK_PRESENT_KEY && !this.isRaw(key) && !!this.opts.failClosed?.(key) && !!this.opts.kept?.(key);
  }

  /** b75 round 3 (DV-1): is the install sealed (the slot-'s' file exists)? A file that
   *  exists but can't be read right now counts as there (fail closed). */
  private async sealedNow(): Promise<boolean> {
    try { return (await this.loadSlot(CK_SEALED_SLOT)) !== null; } catch { return true; }
  }

  /** b75 round 3 (DV-6): is the presence list in force? Sealed, and the kept slot (which
   *  seals the list) exists: without it no kept record can be open, so a missing one is
   *  simply missing (a full wipe destroyed the slot). */
  private async presenceInForce(): Promise<boolean> {
    if (!this.opts.kept || !(await this.sealedNow())) return false;
    try { return (await this.loadSlot(CK_KEPT_SLOT)) !== null; } catch { return true; }
  }

  /** b75 round 3 (DV-6): the presence list. A read error throws (the caller's read then
   *  fails closed for now; nothing is decided from it). */
  private async presenceList(): Promise<Set<string> | 'broken'> {
    if (this.presence && this.presence.era === this.era) return this.presence.v;
    const era = this.era;
    const raw = await this.inner.get(CK_PRESENT_KEY);
    let v: Set<string> | 'broken' = 'broken';
    const p = raw ? ContainerKeyStore.parse(raw) : null;
    if (raw && p && p.slot === CK_KEPT_SLOT) {
      const k = await this.loadSlot(CK_KEPT_SLOT);
      if (k) {
        try {
          const b = fromB64(p.body);
          if (b.length < 12 + 16) throw new Error('short');
          const list = JSON.parse(fromUtf8(gcm(k.key, b.subarray(0, 12), this.aad(CK_KEPT_SLOT, k.gen, CK_PRESENT_KEY)).decrypt(b.subarray(12)))) as unknown;
          if (Array.isArray(list) && list.every((x) => typeof x === 'string')) v = new Set(list as string[]);
        } catch { /* altered: broken */ }
      }
    }
    if (v === 'broken') this.log('[veil-secure] the list of protected records is missing or altered: every missing one counts as tampering');
    if (this.era === era) this.presence = { era, v };
    return v;
  }

  /** b75 round 3 (DV-6): write the presence list (caller holds the CK_PRESENT_KEY lock) */
  private async writePresence(v: Set<string>, era: number): Promise<void> {
    const k = await this.keptSlot(false);
    if (this.era !== era) throw new Error('a wipe began');
    await this.inner.set(CK_PRESENT_KEY, this.seal(CK_KEPT_SLOT, k, CK_PRESENT_KEY, JSON.stringify([...v].sort())));
    this.presence = { era, v };
  }

  /** b75 round 3 (DV-6): add (after a write) or drop (before a delete) one record in the
   *  presence list. A broken list stays broken (it is never rebuilt from what is there:
   *  that would turn a deleted record into a legitimately absent one). */
  private async listPresence(key: string, on: boolean): Promise<void> {
    if (this.wiping || !(await this.presenceInForce())) return;
    const era = this.era;
    const cur = await this.presenceList();
    if (cur === 'broken' || cur.has(key) === on) return;
    // listed only while it is really there (a delete, under this same lock, may have won)
    if (on) { const raw = await this.inner.get(key); if (raw === null || raw === undefined) return; }
    const next = new Set(cur);
    if (on) next.add(key); else next.delete(key);
    await this.writePresence(next, era);
  }

  private log(m: string): void { try { this.opts.log?.(m); } catch { /* never throws */ } }

  private withKey<T>(key: string, fn: () => Promise<T>): Promise<T> {
    const prev = this.locks.get(key) ?? Promise.resolve();
    const run = prev.catch(() => undefined).then(fn);
    const tail = run.catch(() => undefined);
    this.locks.set(key, tail);
    void tail.then(() => { if (this.locks.get(key) === tail) this.locks.delete(key); });
    return run;
  }

  private loadSlot(slot: string): Promise<SlotKey | null> {
    if (this.slots.has(slot)) return Promise.resolve(this.slots.get(slot) ?? null);
    const pending = this.slotLoads.get(slot);
    if (pending) return pending;
    const era = this.era;
    const p = (async () => {
      const r = await this.files.read(slot); // a read error propagates: never "absent"
      const v = r ? { key: fromB64(r.key), gen: r.gen } : null;
      if (v && v.key.length !== 32) throw new Error('container key file is malformed');
      if (v && Number.isSafeInteger(v.gen)) this.genSeen = Math.max(this.genSeen, v.gen);
      if (this.era === era) this.slots.set(slot, v);
      return v;
    })();
    this.slotLoads.set(slot, p);
    p.then(() => this.slotLoads.delete(slot), () => this.slotLoads.delete(slot));
    return p;
  }

  /** the main slot new values are sealed under (the newest), or null */
  private async activeMain(): Promise<{ slot: string; k: SlotKey } | null> {
    let best: { slot: string; k: SlotKey } | null = null;
    for (const s of MAIN_SLOTS) {
      const k = await this.loadSlot(s);
      if (k && (!best || k.gen > best.k.gen)) best = { slot: s, k };
    }
    return best;
  }

  /** b75 (audit DV-5): a recreated slot gets a generation above every slot file still
   *  there and every one this run has seen or made (it used to be 1 every time). With
   *  the AAD binding the generation, a value from before can never open under it. */
  private async nextGen(): Promise<number> {
    let g = this.genSeen;
    for (const s of ALL_SLOTS) {
      try { const k = await this.loadSlot(s); if (k && Number.isSafeInteger(k.gen)) g = Math.max(g, k.gen); } catch { /* unreadable now: memory still counts */ }
    }
    return Math.min(Math.max(g, 0) + 1, MAX_GEN);
  }

  private async createSlot(slot: string, genIn?: number): Promise<SlotKey> {
    const gen = genIn ?? (await this.nextGen());
    const r = await this.files.create(slot, gen);
    // read back what the file holds: a key that didn't land is never used
    const back = await this.files.read(slot);
    if (!back || back.key !== r.key || back.gen !== gen) throw new Error('container key was not stored');
    const v = { key: fromB64(r.key), gen };
    if (v.key.length !== 32) throw new Error('container key file is malformed');
    this.genSeen = Math.max(this.genSeen, gen);
    this.slots.set(slot, v);
    return v;
  }

  private async sealSlotFor(key: string): Promise<{ slot: string; k: SlotKey }> {
    if (this.opts.media?.(key)) {
      const k = (await this.loadSlot(CK_MEDIA_SLOT)) ?? (await this.createSlot(CK_MEDIA_SLOT));
      return { slot: CK_MEDIA_SLOT, k };
    }
    // b75 round 2 (audit D1 / D8): a kept record is sealed under its own slot, never under
    // the main key, so the Nothing-at-Rest close wipe only has to destroy the main key.
    // The slot is made at the first kept write (the launch saves the settings), never by
    // a wipe: a full wipe destroys it and makes none until the wipe has ended.
    if (this.opts.kept?.(key)) return { slot: CK_KEPT_SLOT, k: await this.keptSlot(false) };
    const cur = await this.activeMain();
    if (cur) return cur;
    // b75 (audit DEV-L1): never a new main key while a wipe runs
    if (this.wiping) throw new Error('no container key while a wipe runs');
    // first sealed write (or the first after a wipe): one key, made once
    if (!this.creating) {
      const era = this.era;
      this.creating = (async () => {
        const again = await this.activeMain(); // another caller may have made it meanwhile
        if (again) return again.k;
        const made = await this.createSlot('a');
        // a shred that started while the file was being made: that key must not survive it
        if (this.era !== era || this.wiping) {
          this.slots.delete('a');
          await this.files.remove('a').catch(() => undefined);
          throw new Error('no container key while a wipe runs');
        }
        return made;
      })().finally(() => { this.creating = null; });
    }
    const k = await this.creating;
    const now = await this.activeMain();
    return now ?? { slot: 'a', k };
  }

  /** b75 round 2 (D1): the kept slot's key, made once. `internal` = a wipe's own move of
   *  an older build's kept records (allowed while wiping; see rotate) */
  private keptCreating: Promise<SlotKey> | null = null;
  private async keptSlot(internal: boolean): Promise<SlotKey> {
    const have = await this.loadSlot(CK_KEPT_SLOT);
    if (have) return have;
    if (this.wiping && !internal) throw new Error('no container key while a wipe runs');
    if (!this.keptCreating) {
      this.keptCreating = (async () => {
        const again = await this.loadSlot(CK_KEPT_SLOT);
        if (again) return again;
        // b75 round 3 (DV-6): a new kept slot holds no presence list yet, so the install
        // stops counting as sealed first (only after a full wipe that could not remove the
        // slot-'s' file); the next launch pass seals it again with a fresh list. Without
        // this, a kill between the new slot and its first list would read as tampering.
        if (await this.sealedNow()) {
          await this.files.remove(CK_SEALED_SLOT);
          this.slots.set(CK_SEALED_SLOT, null);
        }
        return this.createSlot(CK_KEPT_SLOT);
      })().finally(() => { this.keptCreating = null; });
    }
    return this.keptCreating;
  }

  private aad(slot: string, gen: number, key: string): Uint8Array {
    return utf8(`${AAD_LABEL}${slot}|${gen}|${key}`);
  }

  private seal(slot: string, k: SlotKey, key: string, value: string): string {
    const iv = randomBytes(12);
    const ct = gcm(k.key, iv, this.aad(slot, k.gen, key)).encrypt(utf8(value));
    const out = new Uint8Array(12 + ct.length);
    out.set(iv);
    out.set(ct, 12);
    return `${CK_PREFIX}${slot}.${toB64(out)}`;
  }

  /** parse a sealed value: [slot, bytes] or null when it isn't one */
  private static parse(raw: string): { slot: string; body: string } | null {
    if (!raw.startsWith(CK_PREFIX)) return null;
    const rest = raw.slice(CK_PREFIX.length);
    const dot = rest.indexOf('.');
    if (dot <= 0) return null;
    return { slot: rest.slice(0, dot), body: rest.slice(dot + 1) };
  }

  /** open a sealed value. null = its key is gone (shredded) or, for an ordinary
   *  key, it fails its check; a fail-closed key throws on a failed check. */
  private async open(key: string, raw: string): Promise<string | null> {
    const p = ContainerKeyStore.parse(raw)!;
    const k = await this.loadSlot(p.slot); // a read error throws (transient: not "gone")
    if (!k) return null; // the key was destroyed: the value is gone for good
    try {
      const b = fromB64(p.body);
      if (b.length < 12 + 16) throw new Error('short');
      return fromUtf8(gcm(k.key, b.subarray(0, 12), this.aad(p.slot, k.gen, key)).decrypt(b.subarray(12)));
    } catch {
      if (this.opts.failClosed?.(key)) throw new SealedValueError(key);
      this.log(`[veil-secure] a sealed entry failed its check and reads as missing: ${key}`);
      return null;
    }
  }

  async get(key: string): Promise<string | null> {
    // b77p (audit VAR-15): a blinded record is read under its blinded name; one an older build stored under
    // its real name is read there and moved (moveToBlinded)
    if (this.blindable(key)) {
      const bn = await this.blindedName(key);
      if (bn) {
        const rawB = await this.inner.get(bn);
        if (rawB !== null && rawB !== undefined) {
          if (!ContainerKeyStore.parse(rawB)) { this.log(`[veil-secure] an unsealed value under a blinded name reads as missing: ${key}`); return null; }
          const v = await this.open(key, rawB);
          if (v !== null && !this.wiping && !this.nameMap?.v.has(key)) void this.editNameMap(key, true); // a list a kill left behind
          if (v !== null && this.opts.noLazyMigrate?.(key)) this.sealedSeen.add(key);
          return v;
        }
      }
      const rawP = await this.inner.get(key);
      if (rawP === null || rawP === undefined) return null;
      const v = await this.getStored(key, rawP);
      if (v !== null && bn && !this.wiping && ContainerKeyStore.parse(rawP)) this.moveToBlinded(key, rawP);
      return v;
    }
    if (this.wasBlinded(key)) {
      // b77t (audit 5 M-A): the real name first; then the blinded copy a b77p-b77s build wrote
      const rawP = await this.inner.get(key);
      if (rawP !== null && rawP !== undefined) return this.getStored(key, rawP);
      const bn = await this.blindedName(key);
      const rawB = bn ? await this.inner.get(bn) : null;
      if (rawB === null || rawB === undefined || !bn) return this.getStored(key, rawP);
      if (!ContainerKeyStore.parse(rawB)) { this.log(`[veil-secure] an unsealed value under a blinded name reads as missing: ${key}`); return null; }
      const v = await this.open(key, rawB);
      if (v !== null) {
        if (this.opts.noLazyMigrate?.(key)) { this.sealedSeen.add(key); this.misplaced.add(key); }
        else if (!this.wiping) this.moveToPlain(key, bn, rawB);
      }
      return v;
    }
    const raw = await this.inner.get(key);
    return this.getStored(key, raw);
  }

  /** the read of a value stored under its real name (b75 rules) */
  private async getStored(key: string, raw: string | null | undefined): Promise<string | null> {
    if (raw !== null && raw !== undefined) {
      const sealed = ContainerKeyStore.parse(raw);
      if (sealed) {
        const v = await this.open(key, raw);
        if (v !== null) {
          // b75 round 2 (audit D1): a kept record an older build sealed under the main key
          // moves to the kept slot (never during a wipe)
          if (sealed.slot !== CK_KEPT_SLOT && !this.wiping && this.opts.kept?.(key)) this.rehome(key, raw, v);
          if (this.opts.noLazyMigrate?.(key)) this.sealedSeen.add(key); // b75 round 3 (DV-1)
          if (this.tracked(key)) this.relist(key); // b75 round 3 (DV-6): a list a kill left behind catches up
          return v;
        }
        // its key was destroyed: gone for good, which for a listed record is tampering (below)
      } else if (this.isRaw(key)) {
        return raw;
      } else if (await this.sealedNow()) {
        // b75 round 3 (audit DV-1): every entry was sealed, so an unsealed one was planted
        // (an empty value included): a fail-closed key throws, any other reads as missing,
        // and it is never re-sealed as if it were genuine
        if (this.opts.failClosed?.(key)) throw new SealedValueError(key);
        this.log(`[veil-secure] an unsealed entry after sealing reads as missing: ${key}`);
        return null;
      } else {
        // a plaintext value written before b75 (or a wipe's zero-fill left behind)
        if (this.opts.noLazyMigrate?.(key)) this.unsealedSeen.add(key);
        else if (!this.wiping) this.migrate(key, raw); // b75 (DEV-L1): never during a wipe
        return raw;
      }
    }
    // b75 round 3 (audit DV-6 / DV-7 / DV-8): a protected record that is missing although the
    // presence list says it is there (or the list itself is gone or altered) is tampering
    if (this.tracked(key) && (await this.presenceInForce())) {
      const list = await this.presenceList();
      if (list === 'broken' || list.has(key)) throw new SealedValueError(key);
    }
    return null;
  }

  /** b75 round 3 (DV-6): make sure a protected record that is there is listed (background,
   *  only when the list in memory does not already have it) */
  private relist(key: string): void {
    if (this.wiping) return;
    const p = this.presence;
    if (p && p.era === this.era && (p.v === 'broken' || p.v.has(key))) return;
    void this.withKey(CK_PRESENT_KEY, () => this.listPresence(key, true))
      .catch((e) => this.log(`[veil-secure] listing a protected entry deferred: ${key} (${String((e as Error)?.message ?? e)})`));
  }

  /** b75 (audit DEV-L1): the length of a value stored UNSEALED (left from before b75),
   *  0 for a sealed or absent one. A wipe sizes its zero-fill with this, without reading
   *  through get() (which queued a migration) and without overwriting ciphertext whose key
   *  the shred already destroyed. */
  async plainLength(key: string): Promise<number> {
    const raw = await this.inner.get(key);
    if (raw === null || raw === undefined || ContainerKeyStore.parse(raw)) return 0;
    return raw.length;
  }

  /** b75 round 3 (audit DV-2): a wipe's overwrite of a value stored UNSEALED (left from
   *  before b75), with zeros of its own length, before its delete. An explicit call: a
   *  value of zeros written through set() is sealed like any other (zero-fills used to be
   *  recognised by their value, so an empty or all-zero write skipped the sealing, and
   *  in KeychainStorage the write freeze and the post-wipe barrier). A sealed value is
   *  left alone (its key goes with the shred); nothing is ever created. */
  async zeroFill(key: string): Promise<void> {
    await this.withKey(key, async () => {
      const raw = await this.inner.get(key);
      if (raw === null || raw === undefined || raw.length === 0 || ContainerKeyStore.parse(raw)) return;
      await this.inner.set(key, '0'.repeat(raw.length));
    });
  }

  /** b75 round 3 (DV-1): has every entry been sealed (the slot-'s' file)? */
  sealedInstall(): Promise<boolean> {
    return this.sealedNow();
  }

  /**
   * b75 round 3 (audit DV-1 / DV-6): mark the install sealed, once the launch pass found
   * every entry sealed (and every kept record in the kept slot). First the presence list
   * of the protected records there now, then the slot-'s' file. A kill in between leaves
   * an unsealed install (the next pass does it again); the file never exists without the
   * list. Runs under the presence lock, so no protected record is deleted meanwhile.
   */
  async sealInstall(keys: string[]): Promise<boolean> {
    if (this.wiping || (this.opts.kept && !this.keptHomed)) return false;
    return this.withKey(CK_PRESENT_KEY, async () => {
      if (await this.sealedNow()) return true;
      const era = this.era;
      if (this.opts.kept) {
        const there = new Set<string>();
        for (const k of new Set([...keys, ...CK_FAIL_CLOSED_KEYS])) {
          if (!this.tracked(k)) continue;
          const raw = await this.inner.get(k);
          if (raw === null || raw === undefined) continue;
          if (!ContainerKeyStore.parse(raw)) return false; // still unsealed: not done yet
          // listed only when it opens (an altered one still throws when read; a slot that
          // can't be read right now throws here, and the next pass tries again)
          const v = await this.open(k, raw).catch((e) => { if (e instanceof SealedValueError) return null; throw e; });
          if (v !== null) there.add(k);
        }
        if (this.wiping || this.era !== era) return false;
        await this.writePresence(there, era);
      }
      if (this.wiping || this.era !== era) return false;
      await this.createSlot(CK_SEALED_SLOT);
      if (this.era !== era) return false;
      // the old store marker an earlier b75 build left (never read any more)
      await this.inner.delete(CK_OLD_SEALED_MARK).catch(() => undefined);
      return true;
    });
  }

  /** b75 (audit DEV-I2): a no-lazy-migrate key was read as plaintext this run (memory
   *  only: answering never touches the store, so never prompts) */
  needsSeal(key: string): boolean {
    return this.unsealedSeen.has(key) || this.misplaced.has(key); // b77t (M-A): a blinded copy is re-saved too
  }

  /** b75 (audit DEV-L1): a wipe begins (shred / rotate call this themselves) */
  beginWipe(): void {
    this.wiping = true;
    this.era++;
  }

  /** b75 (audit DEV-L1): the wipe is over (its write freeze ended): keys may be made again */
  endWipe(): void {
    this.wiping = false;
  }

  /** b75 (AL-6): re-write one plaintext value sealed, only if it is still the same */
  private migrate(key: string, plain: string): void {
    const era = this.era;
    void this.withKey(key, async () => {
      if (this.era !== era || this.wiping) return;
      if (await this.sealedNow()) return; // b75 round 3 (DV-1): never once the install is sealed
      const now = await this.inner.get(key);
      if (now !== plain || this.era !== era) return;
      const { slot, k } = await this.sealSlotFor(key);
      if (this.era !== era) return;
      await this.inner.set(key, this.seal(slot, k, key, plain));
    }).catch((e) => this.log(`[veil-secure] sealing an older entry deferred: ${key} (${String((e as Error)?.message ?? e)})`));
  }

  /** b75 round 2 (audit D1): re-seal one kept record under the kept slot, only if the
   *  store still holds the same sealed value */
  private rehome(key: string, raw: string, plain: string): void {
    const era = this.era;
    void this.withKey(key, async () => {
      if (this.era !== era || this.wiping) return;
      if ((await this.inner.get(key)) !== raw || this.era !== era) return;
      const k = await this.keptSlot(false);
      if (this.era !== era || this.wiping) return;
      await this.inner.set(key, this.seal(CK_KEPT_SLOT, k, key, plain));
    }).catch((e) => this.log(`[veil-secure] moving a kept entry deferred: ${key} (${String((e as Error)?.message ?? e)})`));
  }

  /** b75 round 2 (D1): every kept record lives under the kept slot (set by homeKept, or
   *  read from CK_KEPT_MARK). Then the Nothing-at-Rest close wipe reads nothing at all
   *  before it destroys the main key. */
  private keptHomed = false;

  /** move one kept record from a main slot to the kept slot (a wipe's own move is
   *  `internal`); a read error throws (the caller then destroys nothing) */
  private async homeOne(key: string, era: number, internal: boolean): Promise<boolean> {
    return this.withKey(key, async () => {
      if (this.era !== era || (this.wiping && !internal)) return false;
      const raw = await this.inner.get(key);
      if (raw === null || raw === undefined) return true;
      const p = ContainerKeyStore.parse(raw);
      if (!p) return true; // plaintext (pre-b75) or a zero-fill: no key to lose; sealAll seals it
      if (p.slot === CK_KEPT_SLOT || p.slot === CK_MEDIA_SLOT) return true;
      // an altered value has nothing to keep; a slot that cannot be read right now throws
      const plain = await this.open(key, raw).catch((e) => { if (e instanceof SealedValueError) return null; throw e; });
      if (plain === null) return true; // already unreadable: nothing to keep
      const k = await this.keptSlot(internal);
      if (this.era !== era) return false;
      await this.inner.set(key, this.seal(CK_KEPT_SLOT, k, key, plain));
      return true;
    });
  }

  /**
   * b75 round 2 (audit D1): the launch moves every kept record an older build sealed under
   * the main key to the kept slot, then leaves CK_KEPT_MARK (sealed under that slot); later
   * launches read only the mark. `listKeys` is asked only when the mark is missing.
   */
  async homeKept(listKeys: () => Promise<string[]>): Promise<boolean> {
    if (!this.opts.kept || this.wiping) return false;
    if (this.keptHomed) return true;
    try { if ((await this.get(CK_KEPT_MARK)) === '1') { this.keptHomed = true; return true; } } catch { /* unreadable: run the pass */ }
    const era = this.era;
    let complete = true;
    let keys: string[] = [];
    try { keys = await listKeys(); } catch { return false; }
    for (const key of keys) {
      if (key === CK_KEPT_MARK || !this.opts.kept(key) || this.isRaw(key)) continue;
      try { if (!(await this.homeOne(key, era, false))) complete = false; } catch { complete = false; }
    }
    if (!complete || this.era !== era || this.wiping) return false;
    try { await this.set(CK_KEPT_MARK, '1'); } catch { return false; }
    this.keptHomed = true;
    return true;
  }

  /** b75 (AL-6): seal every plaintext entry still left from before b75 (entries never
   *  read since the update would otherwise stay plaintext until a wipe). Same per-key
   *  rule as the lazy migration; one key at a time, with a pause between keys so the
   *  platform store's queue stays free for the app's own reads. */
  /** `out.complete` (b75, DEV-I2): true when every key was checked and nothing was deferred */
  async sealAll(keys: string[], pauseMs = 25, out?: { complete?: boolean }): Promise<number> {
    let sealed = 0;
    let complete = !this.wiping;
    const era = this.era;
    // b75 round 3 (DV-1): once sealed, an unsealed value was planted: never sealed as genuine
    if (await this.sealedNow()) { if (out) out.complete = complete; return 0; }
    let listed: string[] | null = null;
    for (const key of keys) {
      if (this.era !== era || this.wiping) { complete = false; break; } // a wipe or rotation started: stop
      if (this.isRaw(key)) continue;
      if (this.opts.noLazyMigrate?.(key)) {
        // b75 round 3 (DV-1): reading it here would show a prompt; the install counts as
        // sealed only once it was read (or saved) sealed this run, or is not stored at all
        if (!this.sealedSeen.has(key)) {
          try { listed = listed ?? (this.inner.list ? await this.inner.list() : null); } catch { listed = null; }
          if (!listed || listed.includes(key)) complete = false;
        }
        continue;
      }
      try {
        const done = await this.withKey(key, async () => {
          if (this.era !== era || this.wiping) { complete = false; return false; }
          const raw = await this.inner.get(key);
          if (raw === null || raw === undefined || ContainerKeyStore.parse(raw)) return false;
          const { slot, k } = await this.sealSlotFor(key);
          if (this.era !== era) return false;
          await this.inner.set(key, this.seal(slot, k, key, raw));
          return true;
        });
        if (done) sealed++;
      } catch (e) {
        complete = false;
        this.log(`[veil-secure] sealing an older entry deferred: ${key} (${String((e as Error)?.message ?? e)})`);
      }
      if (pauseMs > 0) await new Promise((r) => setTimeout(r, pauseMs));
    }
    if (out) out.complete = complete && this.era === era;
    return sealed;
  }

  /** wait for the background migrations queued so far (tests, and before a rotation) */
  async settle(): Promise<void> {
    await Promise.all([...this.locks.values()].map((p) => p.catch(() => undefined)));
  }

  async set(key: string, value: string): Promise<void> {
    await this.withKey(key, async () => {
      // the raw keys are stored as they are (no key is made for them). b75 round 3 (audit
      // DV-2): every other value is sealed, whatever it holds: a wipe's zero-fill is the
      // explicit zeroFill() now, never recognised by its value
      if (this.isRaw(key)) { await this.inner.set(key, value); return; }
      // b77p (audit VAR-15): with no main key while a wipe runs, the sealed index is deleted, not written
      // (a missing index is read from the store's list)
      let target: { slot: string; k: SlotKey };
      try { target = await this.sealSlotFor(key); } catch (e) {
        if (this.opts.sealIndex && INDEX_KEYS.has(key) && this.inner.list) { await this.inner.delete(key); return; }
        throw e;
      }
      const { slot, k } = target;
      if (this.blindable(key) && (slot === 'a' || slot === 'b')) {
        // b77p (audit VAR-15): under its blinded name; an entry an older build left under the real name goes
        const bn = (await this.blindedName(key, { slot, k }))!;
        await this.inner.set(bn, this.seal(slot, k, key, value));
        if (!this.plainChecked.has(key)) {
          if ((await this.inner.get(key)) != null) await this.inner.delete(key);
          this.plainChecked.add(key);
        }
        this.unsealedSeen.delete(key);
        if (this.opts.noLazyMigrate?.(key)) this.sealedSeen.add(key);
        if (!this.nameMap?.v.has(key) || this.nameMap.era !== this.era) await this.editNameMap(key, true);
        return;
      }
      await this.inner.set(key, this.seal(slot, k, key, value));
      this.unsealedSeen.delete(key);
      if (this.opts.noLazyMigrate?.(key)) this.sealedSeen.add(key);
      if (this.wasBlinded(key) && (slot === 'a' || slot === 'b')) {
        // b77t (audit 5 M-A): written under its real name (above, first); a blinded copy an older build left goes
        const names = new Set<string>([...(this.knownInner.get(key) ?? [])].filter((n) => n.startsWith(CK_NAME_PREFIX)));
        const bn = await this.blindedName(key, { slot, k });
        if (bn) names.add(bn);
        let had = false;
        for (const n of names) if ((await this.inner.get(n)) != null) { await this.inner.delete(n); had = true; }
        this.misplaced.delete(key);
        if (had || this.nameMap?.v.has(key)) await this.editNameMap(key, false);
      }
    });
    // b75 round 3 (DV-6): a protected record is listed AFTER it is written (a kill in between
    // leaves it there but unlisted, which reads fine and is listed at its next read)
    if (this.tracked(key)) {
      await this.withKey(CK_PRESENT_KEY, () => this.listPresence(key, true))
        .catch((e) => this.log(`[veil-secure] listing a protected entry deferred: ${key} (${String((e as Error)?.message ?? e)})`));
    }
  }

  async delete(key: string): Promise<void> {
    if (this.tracked(key)) {
      // b75 round 3 (DV-6): dropped from the presence list BEFORE the delete, under the list's
      // lock (a list that can't be written throws, and nothing is deleted: listed but gone
      // would read as tampering)
      await this.withKey(CK_PRESENT_KEY, async () => {
        await this.listPresence(key, false);
        await this.withKey(key, () => this.inner.delete(key));
      });
    } else if (key === CK_PRESENT_KEY) {
      // b75 round 3 (DV-6): only the app's own wipes delete the list; the install then stops
      // counting as sealed (first), and the next launch pass seals it again with a new list
      await this.withKey(CK_PRESENT_KEY, async () => {
        if (await this.sealedNow()) { await this.files.remove(CK_SEALED_SLOT); this.slots.set(CK_SEALED_SLOT, null); }
        await this.inner.delete(key);
        this.presence = null;
      });
    } else if (this.opts.blindNames && !key.startsWith(CK_NAME_PREFIX) && (this.blindable(key) || this.wasBlinded(key) || this.knownInner.has(key))) {
      // b77p (audit VAR-15): every platform name the record may be under — its blinded name now (if the key is
      // there), every name this run used for it (also after a shred), and its real name (an older build's)
      await this.withKey(key, async () => {
        const names = new Set<string>([key, ...(this.knownInner.get(key) ?? [])]);
        try { const bn = await this.blindedName(key); if (bn) names.add(bn); } catch { /* the key can't be read now: the known names */ }
        for (const n of names) await this.inner.delete(n);
        this.knownInner.delete(key);
      });
      await this.editNameMap(key, false);
    } else {
      await this.withKey(key, () => this.inner.delete(key));
    }
    this.unsealedSeen.delete(key);
    this.sealedSeen.delete(key);
    this.misplaced.delete(key);
  }

  /** b77p (audit VAR-15): the real names. A blinded entry is named from the sealed name list; one the list
   *  doesn't name (its key was shredded, or the list didn't open) comes back under its opaque platform name,
   *  which get() reads as nothing and delete() removes — so a wipe still reaches every entry. */
  async list(): Promise<string[]> {
    const names = this.inner.list ? await this.inner.list() : [];
    if (!this.opts.blindNames) return names;
    let rev: Map<string, string> | null = null;
    try { rev = (await this.readNameMap())?.rev ?? null; } catch { rev = null; }
    const out: string[] = [];
    for (const n of names) {
      // the name list itself is listed only once it no longer opens (after a shred), so the wipe deletes it in its
      // own order (AL-3: nothing is deleted before the identity); while it opens it is internal
      if (n === CK_NAME_MAP_KEY) { if (!rev) out.push(n); continue; }
      if (n.startsWith(CK_NAME_PREFIX)) {
        const real = rev?.get(n);
        if (real) { this.remember(real, n); out.push(real); } else out.push(n);
      } else out.push(n);
    }
    return out;
  }

  /** b75 (AL-6): does the platform store still hold an entry under this key, sealed
   *  or not? (A wipe's verify pass: after the shred, get() reads every sealed entry
   *  as missing, which must not count as deleted.) */
  async present(key: string): Promise<boolean> {
    if (this.opts.blindNames && !key.startsWith(CK_NAME_PREFIX) && (this.blindable(key) || this.wasBlinded(key) || this.knownInner.has(key))) {
      // b77p (audit VAR-15): under any name it may be stored under
      const names = new Set<string>([key, ...(this.knownInner.get(key) ?? [])]);
      try { const bn = await this.blindedName(key); if (bn) names.add(bn); } catch { /* the known names */ }
      for (const n of names) if ((await this.inner.get(n)) !== null) return true;
      return false;
    }
    return (await this.inner.get(key)) !== null;
  }

  /** b75 (AL-6): destroy the main container key(s). Every sealed entry becomes
   *  unreadable at once; the pending-media slot stays until its files are gone.
   *  b75 round 2 (audit D1): a full wipe destroys the kept slot too (it keeps nothing),
   *  and (audit I1) the platform wrap key once no slot file is left. */
  async shred(): Promise<void> {
    this.beginWipe(); // b75 (DEV-L1): no migration and no new main key until the wipe ends
    const errors: unknown[] = [];
    // b75 round 3 (DV-1 / DV-6): the sealed-install file goes last: a phone wiped clean starts
    // again unsealed (it holds nothing to protect), and the next launch pass seals it again
    for (const s of [...MAIN_SLOTS, CK_KEPT_SLOT, CK_SEALED_SLOT]) {
      this.slots.set(s, null);
      try { await this.files.remove(s); } catch (e) { errors.push(e); }
    }
    this.slots.clear(); // re-read from the files next time (a failed remove shows)
    // b77k (IP77-6, iPhone battery): the kept slot's own mark goes with the slot. It is written
    // here, below KeychainStorage's index, so no wipe's key sweep ever deleted it: it outlived the
    // slot it was sealed under, and the first launch after the next kept write (a new 'k') read it
    // under the new key — "a sealed entry failed its check and reads as missing: vardum_ck_kept_v1"
    // (harmless: homeKept then re-ran its pass and wrote it again). Best-effort; in-process every
    // kept write after the shred goes to the new slot, so keptHomed stays as it is.
    try { await this.withKey(CK_KEPT_MARK, () => this.inner.delete(CK_KEPT_MARK)); } catch { /* the next launch's pass replaces it */ }
    this.dropNameState(); // b77p (audit VAR-15): the name list stays until the wipe's sweep (list() shows it then)
    if (errors.length) throw new Error('container key could not be destroyed');
    await this.dropWrapIfIdle();
  }

  /** b75 round 2 (audit I1): best-effort; the platform keeps its key while a slot is left */
  private async dropWrapIfIdle(): Promise<void> {
    try { await this.files.dropWrapKeyIfIdle?.(); } catch (e) { this.log(`[veil-secure] wrap key not deleted yet (${String((e as Error)?.message ?? e)})`); }
  }

  /** b75: destroy the media slot (the pending-media list is done with) */
  async shredMedia(): Promise<void> {
    this.slots.delete(CK_MEDIA_SLOT);
    await this.files.remove(CK_MEDIA_SLOT);
    // b75 round 2 (I1): after a full wipe this was the last slot file
    if (this.wiping) await this.dropWrapIfIdle();
  }

  /**
   * b75 (AL-6): Nothing-at-Rest's crypto-shred. b75 round 2 (audit D1 / D8): the kept
   * records live under the kept slot, so this only DESTROYS the main key: no key is
   * made and nothing is re-sealed first (the old rotation made key b and re-sealed the
   * kept records one by one before key a went, so a wipe cut short left everything
   * openable, and on Android an unlock-bound wrap key could refuse the new key while
   * the phone locked). Every entry not kept was sealed under the main key and is
   * unreadable from the first step.
   * Kept records an older build sealed under the main key (or keys in `keep` the store
   * does not treat as kept) are moved first; the launch's homeKept pass normally did
   * that already, and then nothing at all is read or written before the destroy.
   * Throws (and destroys nothing) if such a record can't be read and moved.
   */
  async rotate(keep: string[]): Promise<void> {
    await this.settle();
    this.beginWipe(); // b75 (DEV-L1): the wipe that follows queues no migration
    const era = this.era;
    const allHome = this.keptHomed && keep.every((k) => this.isRaw(k) || !!this.opts.kept?.(k));
    if (!allHome) {
      for (const key of keep) {
        if (this.isRaw(key)) continue;
        if (!(await this.homeOne(key, era, true))) throw new Error('container key rotation interrupted');
      }
    }
    if (this.era !== era) throw new Error('container key rotation interrupted');
    const errors: unknown[] = [];
    for (const s of MAIN_SLOTS) {
      this.slots.set(s, null);
      try { await this.files.remove(s); } catch (e) { errors.push(e); }
      this.slots.delete(s); // re-read next time (a failed remove shows); the kept slot stays in memory
    }
    this.dropNameState(); // b77p (audit VAR-15): the name key went with the main key (the list goes with the sweep)
    if (errors.length) throw new Error('container key could not be destroyed');
  }

  /** b77p (audit VAR-15): forget the name keys and list (the main key is gone); the names used stay known */
  private dropNameState(): void {
    for (const k of this.nameKeys.values()) k.fill(0);
    this.nameKeys.clear();
    this.nameMap = null;
    this.plainChecked.clear();
  }
}

/** In-memory ContainerKeyFiles (tests, and the decoy store). */
export class MemoryContainerKeyFiles implements ContainerKeyFiles {
  readonly files = new Map<string, { key: string; gen: number }>();
  async read(slot: string) { const f = this.files.get(slot); return f ? { ...f } : null; }
  async create(slot: string, gen: number) {
    if (this.files.has(slot)) throw new Error('container key slot is in use');
    const f = { key: toB64(randomBytes(32)), gen };
    this.files.set(slot, f);
    return { ...f };
  }
  async remove(slot: string) { this.files.delete(slot); }
}
