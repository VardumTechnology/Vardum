/**
 * Expo shell — platform SecureStore over react-native-keychain.
 * Keychain items: service = "veil.<key>", account = "veil", value = the secret.
 * accessible WHEN_UNLOCKED_THIS_DEVICE_ONLY (matches web "locked until first
 * unlock" semantics). Errors are rethrown with a diagnostic hint so a failed
 * native link shows up as readable text on the ErrorBoundary screen instead
 * of a silent launch crash.
 *
 * "Locked in your phone's security chip" storage mode (Settings > Key
 * storage, web parity Sept 19): when active, the identity keyvault entry
 * (veil_keyvault_identity — the single highest-value secret; everything
 * else derives from it) is additionally written with a biometric
 * accessControl + secure-hardware securityLevel, so the OS itself demands
 * Face ID / Touch ID / device passcode before that one item can be read —
 * on top of, not instead of, the existing WHEN_UNLOCKED_THIS_DEVICE_ONLY
 * protection every key already has. Session and group keys (the veil_rk_ and
 * veil_gk_ prefixed entries)
 * are read too frequently during normal chat to gate the same way without
 * prompting on every message, so the gate is scoped to the identity keyvault
 * only — a deliberate, honest scoping decision, not the full-store gate the
 * web copy's wording alone might suggest.
 */
import { writeKeychainVerified, type KeychainLike } from './keychain-write'; // b77u (audit 6 R1 F-05)
import * as Keychain from 'react-native-keychain';
import { Platform } from 'react-native';
import type { SecureStore } from '../vendor/device/src/index';
import { AUTH_SESSION_KEY } from '../vendor/device/src/auth';
import { NAR_MARKER_KEY } from '../vendor/device/src/keyvault'; // b77m review (M1)
import { WRONG_IN_A_ROW_KEY } from '../vendor/device/src/applock';
import { ContainerKeyStore, ckBlindable, CK_RAW_KEYS, CK_MEDIA_KEYS, CK_KEPT_KEYS, CK_FAIL_CLOSED_KEYS, CK_KEPT_SLOT, CK_SEALED_SLOT, type ContainerKeyFiles } from '../vendor/device/src/container-key';

/**
 * b81 (owner report: "no notifications, locked or unlocked" — confirmed
 * directly from a device Metro log: "Keychain get('veil_auth_session')
 * failed — original: User interaction is not allowed"). EVERY key,
 * including the app-login session token, was stored WHEN_UNLOCKED_THIS_
 * DEVICE_ONLY — the strictest tier, which refuses the read unless the
 * screen is unlocked at the EXACT moment of access. That's correct and
 * wanted for actual crypto material (identity keyvault, ratchet/session
 * keys) — it's wrong for the login token, because it means literally every
 * background sync attempt (push-woken or timer-woken) fails before it ever
 * reaches the join/decrypt logic, the instant the phone is locked. This is
 * the standard tradeoff every secure messenger makes: the login session
 * uses the looser AFTER_FIRST_UNLOCK tier (readable in the background once
 * the device has been unlocked at least once since boot — true almost
 * always in practice) so delivery can keep working while locked, while
 * every actual Veil crypto key keeps the strict WHEN_UNLOCKED tier
 * unchanged. Losing this token to a live, already-unlocked-since-boot
 * seizure only exposes the account login — never message content or key
 * material, which stay independently gated exactly as before.
 *
 * b73 (audit V-12): the accessible tiers above are an iOS Keychain feature.
 * react-native-keychain 8 on Android ignores them: items are encrypted with an
 * Android Keystore key (AES-CBC, no MAC, no setUnlockedDeviceRequired), so on
 * Android they are readable by the app whenever it runs, locked screen or not.
 * Moving to an authenticated, unlock-bound Keystore cipher needs a keychain
 * library upgrade; it is a known limit until then (Settings says the app lock
 * is not encryption).
 * b75 (audit AL-6 / V7): every value is now sealed above that layer with AES-GCM
 * under the container key (ContainerKeyStore below), whose file on Android is
 * itself sealed by a Keystore key bound to an unlocked phone where supported.
 */
const AUTH_TOKEN_ACCESSIBLE = Keychain.ACCESSIBLE.AFTER_FIRST_UNLOCK_THIS_DEVICE_ONLY;

/**
 * b62 Secure Enclave seal: in hardware mode the keyvault master key never
 * rests in the keychain in readable form. set() wraps it with an AES-GCM key
 * derived from an ECDH agreement against a non-extractable Secure Enclave
 * P-256 key (biometry-gated); get() unwraps it — Face ID prompts at the
 * Secure Enclave key-use itself. Old raw entries (pre-b62 hardware mode or
 * standard mode) pass through untouched, so existing installs keep working
 * and re-seal on the next save.
 */
const SE_WRAP_PREFIX = '{"__veil_se":1';

interface NativeSeModule {
  seIsAvailable?: () => boolean;
  seWrapKey?: (masterKeyB64: string) => Promise<{ eph: string; salt: string; ct: string }>;
  seUnwrapKey?: (ephB64: string, saltB64: string, ctB64: string) => Promise<string>;
  seResetKey?: () => Promise<boolean>;
}

function nativeSe(): NativeSeModule | null {
  try {
    const emc = require('expo-modules-core') as {
      requireNativeModule?: <T = unknown>(name: string) => T;
    };
    if (typeof emc?.requireNativeModule !== 'function') return null;
    return emc.requireNativeModule<NativeSeModule>('VeilCrypto');
  } catch { return null; }
}

/**
 * b100 FIX (owner hardware finding, Sept 21): every hardware-mode flip threw
 * "Secure Enclave did not accept the seal" — Metro showed the real cause:
 * "[veil-se] wrap failed, falling back to gated keychain: Error: seWrapKey:
 * master key is not valid base64". The native Swift seWrapKey expects its
 * one argument to be base64 (it calls Data(base64Encoded:) on it), but the
 * value actually passed here is IdentityVault.save()'s
 * JSON.stringify(identity) — a JSON object string, never base64. So the SE
 * seal has never once succeeded since it was introduced (b62): every past
 * "hardware" flip silently fell back to the legacy BIOMETRY_CURRENT_SET
 * keychain path below (still correct/secure, just not SE-sealed) with only
 * a console.log — invisible until b96 added keyvaultEntrySealed() to PROVE
 * the seal at flip time, which correctly started detecting "plain" every
 * time and (rightly) began surfacing the failure as a reverted toggle.
 * Fix: base64-encode the JSON payload here (btoa — the whole string is
 * ASCII: base64 sub-fields, an ISO date, a hex veilId) so the native side's
 * base64 decode succeeds; reverse it in seUnwrap. No stored data migrates —
 * no entry was ever actually SE-sealed, so every device today still has the
 * plain legacy-gated JSON and will seal correctly on the next save.
 */
async function seWrap(value: string): Promise<string> {
  const mod = nativeSe();
  if (!mod?.seWrapKey || !mod.seIsAvailable?.()) throw new Error('Secure Enclave unavailable');
  const blob = await mod.seWrapKey(btoa(value));
  return `{"__veil_se":1,"eph":"${blob.eph}","salt":"${blob.salt}","ct":"${blob.ct}"}`;
}

async function seUnwrap(stored: string): Promise<string> {
  const mod = nativeSe();
  if (!mod?.seUnwrapKey) throw new Error('Secure Enclave unavailable');
  const blob = JSON.parse(stored) as { eph: string; salt: string; ct: string };
  const decoded = await mod.seUnwrapKey(blob.eph, blob.salt, blob.ct);
  return atob(decoded);
}

function isSeWrapped(v: string): boolean {
  return typeof v === 'string' && v.startsWith(SE_WRAP_PREFIX);
}

/** must match vendor/device/src/keyvault.ts KEYVAULT_KEY */
const HARDWARE_GATED_KEY = 'veil_keyvault_identity';

function diag(op: string, key: string, e: unknown): never {
  const msg = String((e as Error)?.message || e);
  throw new Error(
    `Keychain ${op}('${key}') failed — ` +
    (msg.includes('null') || msg.includes('undefined')
      ? `react-native-keychain native module did not link into this build. `
      : ``) +
    `original: ${msg}`
  );
}

export interface RnSecureStoreOptions {
  /** true while Settings > Key storage is set to "Locked in your phone's security chip" */
  isHardwareGated?: () => boolean;
}

/**
 * Android read cache. Every react-native-keychain item on Android is its own
 * Keystore key, and every read is a hardware AES op (on the Pixel 8 Pro the
 * old keys sit in the Titan M2 StrongBox: 100-300 ms each, all on one native
 * queue). The background loops re-read the same items every few seconds, so
 * a chat tap waited behind seconds of queued reads (device log Oct 20).
 * iOS reads are already fast, so iOS keeps the direct path.
 * The values are the same ones the app holds decrypted in memory anyway; the
 * hardware-gated identity entry is never cached (its OS prompt must stay).
 */
const CACHE_ON = Platform.OS === 'android';
const cache = new Map<string, string | null>();
const inflight = new Map<string, Promise<string | null>>();
const version = new Map<string, number>();
function bump(key: string): void { version.set(key, (version.get(key) ?? 0) + 1); inflight.delete(key); }

/** Android: an entry whose ciphertext the Keystore can no longer open (old
 *  StrongBox keys fail large finishes with IllegalBlockSizeException). It will
 *  never decrypt, so it reads as missing instead of throwing on every poll and
 *  blocking the chat open; the next write replaces it with a TEE-keyed copy. */
function isUnreadableEntry(e: unknown): boolean {
  return Platform.OS === 'android' && /Could not decrypt data with alias/.test(String((e as Error)?.message ?? e));
}
const unreadableLogged = new Set<string>();

/** b70 (audit VAR-13): the lock records fail CLOSED. An unreadable lock or
 *  lockout record must read as "locked", never as "no lock set", so these
 *  keys throw instead of reading as missing. */
// b71 (review): the two key-index copies too. Read as missing, the next save
// rewrote the index with one entry and wipes then missed every other key; now
// KeychainStorage sees the failure and rebuilds the index from list().
export const FAIL_CLOSED_KEYS = new Set(['veil_app_lock', 'veil_lockout', 'veil_app_lock_key', 'veil_keychain_index', 'veil_keychain_index_b']);
// b75 (audit AL-1): the wrong-in-a-row row too. Missing, it now counts as tampering, so
// an unreadable one must throw (the lock reads as locked) instead of reading as missing.
FAIL_CLOSED_KEYS.add(WRONG_IN_A_ROW_KEY);
// b75 round 2 (audit D10): the settings too. An altered or unreadable record used to read as
// missing, which meant the unprotected defaults (self-destruct off, erase-after-10 off,
// history on); now it throws and SettingsStore turns every protection on (App.tsx says so).
FAIL_CLOSED_KEYS.add('veil_settings_v1');
// b75 round 3 (audit DV-7 / DV-8): and every key the sealing layer treats as fail-closed (the
// decoy push hold, the notes' rollback marks): one list, CK_FAIL_CLOSED_KEYS (spec §6.2)
for (const k of CK_FAIL_CLOSED_KEYS) FAIL_CLOSED_KEYS.add(k);

/** b75 (audit AL-6): the native container-key files (modules/veil-crypto ck*), or null
 *  on a binary without them (values then stay as they are, unsealed). */
interface NativeCk {
  /** null (Android) or {} (iOS) when the slot has no file */
  ckRead?: (slot: string) => Promise<{ key?: string; gen?: number } | null>;
  ckCreate?: (slot: string, gen: number) => Promise<{ key: string; gen: number }>;
  ckRemove?: (slot: string) => Promise<boolean>;
  ckRemoveAll?: () => Promise<boolean>;
  /** b75 round 2 (audit I1): delete the Keystore wrap key when no slot file is left */
  ckDropWrapIfIdle?: () => Promise<boolean>;
  /** b75 round 3 (audit DV-11): Android, re-seal the slot files under a wrap key bound to an
   *  unlocked phone once the phone has a screen lock (true = bound) */
  ckRebindUnlocked?: () => Promise<boolean>;
  ckInfo?: () => { hardware: boolean; unlockBound: boolean };
  seDeleteKey?: () => Promise<boolean>;
}
function nativeCk(): NativeCk | null {
  const m = nativeSe() as unknown as NativeCk | null;
  return m && typeof m.ckRead === 'function' && typeof m.ckCreate === 'function' && typeof m.ckRemove === 'function' ? m : null;
}
export function nativeContainerKeyFiles(): ContainerKeyFiles | null {
  const m = nativeCk();
  if (!m) return null;
  return {
    read: async (slot) => {
      const r = await m.ckRead!(slot);
      return r && typeof r.key === 'string' ? { key: r.key, gen: Number(r.gen) } : null;
    },
    create: async (slot, gen) => {
      const r = await m.ckCreate!(slot, gen);
      return { key: r.key, gen: Number(r.gen) };
    },
    remove: async (slot) => {
      if (!(await m.ckRemove!(slot))) throw new Error('container key file could not be deleted');
    },
    // b75 round 2 (audit I1): a full wipe leaves no Vardum Keystore key behind (older
    // binaries without the function keep it, as before)
    dropWrapKeyIfIdle: m.ckDropWrapIfIdle ? async () => { await m.ckDropWrapIfIdle!(); } : undefined,
  };
}
/** b75 (AL-6): is there a container key on this install (the fresh-install guard's signal).
 *  b75 round 3 (audit DV-4): the kept slot and the sealed-install file count too. After a
 *  Nothing-at-Rest close wipe only those are left; with the launch flag lost as well, the
 *  guard used to take the phone for a reinstall and sweep the very records the wipe kept.
 *  (A reinstall on iOS has none of these files: they went with the old app.) */
export async function containerKeyPresent(): Promise<boolean> {
  const f = nativeContainerKeyFiles();
  if (!f) return false;
  for (const s of CONTAINER_KEY_SIGNAL_SLOTS) { try { if (await f.read(s)) return true; } catch { return true; /* present but unreadable now */ } }
  return false;
}
/** b75 round 3 (audit DV-4): the slots whose file means "this install wrote data since its
 *  last wipe" (the media slot can outlive a full wipe until its files are deleted) */
export const CONTAINER_KEY_SIGNAL_SLOTS: readonly string[] = ['a', 'b', CK_KEPT_SLOT, CK_SEALED_SLOT];
/** b75 round 3 (audit DV-11): Android. A phone that had no screen lock when Vardum first made
 *  its container wrap key got one that works while the phone is locked; once it has a screen
 *  lock, the next launch binds the key files to an unlocked phone. Best-effort; older
 *  binaries and iOS (which has no such key) do nothing. */
export async function rebindContainerKey(): Promise<boolean> {
  try { return !!(await nativeCk()?.ckRebindUnlocked?.()); } catch { return false; }
}
/** b75 (AL-6 / AL-10): every container-key file (a fresh install's sweep) */
export async function removeAllContainerKeys(): Promise<void> {
  try { await nativeCk()?.ckRemoveAll?.(); } catch { /* best-effort */ }
}
// b75 (audit DEV-I6): containerKeyInfo() was removed: nothing read it, and its iOS answer
// was a constant. The native ckInfo stays as a diagnostic (Android: whether the file's
// wrap key is in secure hardware and bound to an unlocked phone; iOS: always false,
// since the file is protected only by iOS file protection, readable after first unlock).
/** b75 (audit AL-10): delete the security-chip wrap key without making a new one
 *  (older binaries: reset it, which is what they did before) */
export async function deleteSecureEnclaveKey(): Promise<void> {
  const m = nativeCk();
  if (m?.seDeleteKey) { try { await m.seDeleteKey(); } catch { /* best-effort */ } return; }
  if (secureEnclaveAvailable()) await resetSecureEnclaveKey().catch(() => false);
}

/** b70 (VAR-13): keys that read as missing because they were unreadable this
 *  launch (the app tells the user rather than resetting them silently) */
export function unreadableKeysThisLaunch(): string[] {
  return [...unreadableLogged];
}

export function createRnSecureStore(opts: RnSecureStoreOptions = {}): SecureStore {
  const plain = createDirectStore(opts);
  // b75 (audit AL-6): every value sealed under the container key, below the read cache
  const files = nativeContainerKeyFiles();
  const direct: SecureStore = files
    ? new ContainerKeyStore(plain, files, {
      raw: (k) => CK_RAW_KEYS.has(k),
      media: (k) => CK_MEDIA_KEYS.has(k),
      kept: (k) => CK_KEPT_KEYS.has(k), // b75 round 2 (audit D1 / D8): their own slot
      failClosed: (k) => FAIL_CLOSED_KEYS.has(k),
      // re-sealing the hardware-gated identity in the background would ask for a
      // fingerprint on Android; it is re-sealed at its next deliberate save instead
      noLazyMigrate: (k) => k === HARDWARE_GATED_KEY && !!opts.isHardwareGated?.(),
      // b77p (audit 2, VAR-15): record names blinded and the key index sealed, so an extraction
      // can't list chat / group / mailbox identifiers from the platform store
      blindNames: ckBlindable,
      sealIndex: true,
      log: (m) => console.log(m),
    })
    : plain;
  if (!CACHE_ON) return direct;
  return {
    async get(key) {
      if (key === HARDWARE_GATED_KEY) return direct.get(key);
      if (cache.has(key)) return cache.get(key) ?? null;
      const pending = inflight.get(key);
      if (pending) return pending;
      const v0 = version.get(key) ?? 0;
      const p = (async () => {
        let value: string | null;
        try {
          value = await direct.get(key);
        } catch (e) {
          if (!isUnreadableEntry(e) || FAIL_CLOSED_KEYS.has(key)) throw e;
          if (!unreadableLogged.has(key)) {
            unreadableLogged.add(key);
            console.log(`[veil-secure] unreadable entry treated as missing: ${key}`);
          }
          value = null;
        }
        if ((version.get(key) ?? 0) === v0) cache.set(key, value);
        return value;
      })();
      inflight.set(key, p);
      try { return await p; } finally { if (inflight.get(key) === p) inflight.delete(key); }
    },
    async set(key, value) {
      bump(key);
      cache.delete(key);
      try { await direct.set(key, value); } finally { bump(key); } // a read that raced the write must not cache the old value
      if (key !== HARDWARE_GATED_KEY) cache.set(key, value);
    },
    async delete(key) {
      bump(key);
      cache.delete(key);
      try { await direct.delete(key); } finally { bump(key); }
      cache.set(key, null);
    },
    list: () => direct.list!(),
    // b75 (AL-6): straight to the sealing layer (the cached plaintext is what this
    // process already holds; the wipes delete those keys right after)
    present: direct.present ? (k) => direct.present!(k) : undefined,
    shred: direct.shred ? () => direct.shred!() : undefined,
    rotate: direct.rotate ? (keep) => direct.rotate!(keep) : undefined,
    shredMedia: direct.shredMedia ? () => direct.shredMedia!() : undefined,
    sealAll: direct.sealAll ? (keys, pauseMs, out) => direct.sealAll!(keys, pauseMs, out) : undefined,
    // b75 (audit DEV-L1 / DEV-I2): the wipe mode and the zero-fill size go to the sealing
    // layer (the cache holds plaintext the process already has; it never sizes a wipe)
    plainLength: direct.plainLength ? (k) => direct.plainLength!(k) : undefined,
    beginWipe: direct.beginWipe ? () => direct.beginWipe!() : undefined,
    endWipe: direct.endWipe ? () => direct.endWipe!() : undefined,
    needsSeal: direct.needsSeal ? (k) => direct.needsSeal!(k) : undefined,
    homeKept: direct.homeKept ? (l) => direct.homeKept!(l) : undefined, // b75 round 2 (audit D1)
    // b75 round 3 (audit DV-1 / DV-2): the sealed-install state, and the wipe's zero-fill (the
    // cached copy is dropped: the entry is about to go)
    sealedInstall: direct.sealedInstall ? () => direct.sealedInstall!() : undefined,
    sealInstall: direct.sealInstall ? (k) => direct.sealInstall!(k) : undefined,
    zeroFill: direct.zeroFill ? async (key) => {
      bump(key);
      cache.delete(key);
      try { await direct.zeroFill!(key); } finally { bump(key); }
    } : undefined,
  };
}

/** b71 (review): the keys the platform store really holds (services are "veil.<key>") */
async function listStoredKeys(): Promise<string[]> {
  const services = await Keychain.getAllGenericPasswordServices();
  return services.filter((sv) => sv.startsWith('veil.')).map((sv) => sv.slice('veil.'.length));
}

function createDirectStore(opts: RnSecureStoreOptions): SecureStore {
  return {
    async get(key) {
      try {
        // b97: an ACL-gated read with NO explicit authenticationPrompt can
        // silently fail (errSecAuthFailed / "-25293", surfaced by iOS as the
        // nonsensical "user name or passphrase you entered is not correct")
        // instead of showing Face ID/passcode UI, once any recent-unlock
        // grace window has lapsed — this is why a boot-time read can succeed
        // silently (fresh device unlock) while the SAME read moments later,
        // from deep in Settings, fails outright. Passing an explicit prompt
        // for the one gated key makes the OS reliably show the biometric UI
        // instead of guessing.
        const getOpts = key === HARDWARE_GATED_KEY
          ? { service: `veil.${key}`, authenticationPrompt: { title: 'Unlock Vardum', subtitle: 'Confirm to access your identity keys' } }
          : { service: `veil.${key}` };
        const rc = await Keychain.getGenericPassword(getOpts);
        if (!rc) return null;
        const stored = (rc as { password: string }).password;
        // b62: hardware-mode sealed entries unwrap via the Secure Enclave
        if (isSeWrapped(stored)) return await seUnwrap(stored);
        return stored;
      } catch (e) { diag('get', key, e); }
    },
    async set(key, value) {
      const gated = key === HARDWARE_GATED_KEY && !!opts.isHardwareGated?.();
      // b62: hardware mode with a Secure Enclave seals the master key; the
      // keychain then holds only the (useless-off-device) sealed blob. Without
      // a Secure Enclave the legacy biometric-gated entry path below applies.
      if (gated && secureEnclaveAvailable()) {
        try {
          const sealed = await seWrap(value);
          const seSet = { service: `veil.${key}`, accessible: Keychain.ACCESSIBLE.WHEN_UNLOCKED_THIS_DEVICE_ONLY } as const;
          try {
            await Keychain.setGenericPassword('veil', sealed, seSet);
            return;
          } catch {
            // same b60 class of iOS bug: an existing GATED entry (pre-b62
            // hardware mode) can't be attribute-updated in place — delete and
            // rewrite fresh once.
            await Keychain.resetGenericPassword({ service: `veil.${key}` });
            await Keychain.setGenericPassword('veil', sealed, seSet);
            return;
          }
        } catch (e) {
          console.log('[veil-se] wrap failed, falling back to gated keychain:', String(e));
          // fall through to the legacy path — a failed seal must not lose the key
        }
      }
      const opts_: Parameters<typeof Keychain.setGenericPassword>[2] = {
        service: `veil.${key}`,
        // b77m review (M1): the one-bit Nothing-at-Rest marker must be readable on a background launch too
        // (the cold-boot wipe decides by it when the sealed records answer "User interaction is not allowed")
        accessible: key === AUTH_SESSION_KEY || key === NAR_MARKER_KEY ? AUTH_TOKEN_ACCESSIBLE : Keychain.ACCESSIBLE.WHEN_UNLOCKED_THIS_DEVICE_ONLY,
        ...(gated ? {
          accessControl: Keychain.ACCESS_CONTROL.BIOMETRY_CURRENT_SET,
          securityLevel: Keychain.SECURITY_LEVEL.SECURE_HARDWARE,
        } : {}),
      };
      // b77u (audit 6 R1 F-05): a write that resolves false is a failed write, and the read-back runs after the whole
      // write (it sat inside the catch, so a normal write never checked); gated keys are still never read back
      await writeKeychainVerified(Keychain as unknown as KeychainLike, key, value, opts_ as { service: string } & Record<string, unknown>, gated, diag);
    },
    async delete(key) {
      try {
        await Keychain.resetGenericPassword({ service: `veil.${key}` });
      } catch (e) { diag('delete', key, e); }
    },
    list: listStoredKeys,
  };
}

/**
 * b96: peek the keyvault entry's RAW stored value WITHOUT unwrapping — lets
 * the app tell whether the Secure Enclave seal is actually in place (a failed
 * seal used to look exactly like a successful one; owner hardware finding:
 * "none of the modes asks me for biometrics"). Prompt-free on the SE path —
 * the record holding the sealed blob is an ordinary keychain item; the gate
 * lives at the SE key-use inside seUnwrap(). On the LEGACY gated-entry path
 * (no Secure Enclave) this read prompts exactly like any gated read.
 */
export async function keyvaultEntrySealed(): Promise<'sealed' | 'plain' | 'missing' | 'error'> {
  try {
    const rc = await Keychain.getGenericPassword({ service: `veil.${HARDWARE_GATED_KEY}` });
    if (!rc) return 'missing';
    const stored = (rc as { password: string }).password;
    return isSeWrapped(stored) ? 'sealed' : 'plain';
  } catch {
    // b77t2 (CL-5): a read that THREW (a transient Keychain error, "interaction not allowed") says nothing about
    // the entry. It used to read as 'missing', and the boot then reset the Secure Enclave key under a sealed entry
    return 'error';
  }
}

/** b77t2 (CL-5): hardware protection of the identity entry, three ways — 'protected' (confirmed), 'unprotected'
 *  (confirmed plain or confirmed absent) or 'unknown' (the check itself failed: nothing may be reset or rewritten
 *  on this answer) */
export async function keyvaultProtectionState(): Promise<'protected' | 'unprotected' | 'unknown'> {
  if (secureEnclaveAvailable()) {
    const st = await keyvaultEntrySealed();
    return st === 'sealed' ? 'protected' : st === 'error' ? 'unknown' : 'unprotected';
  }
  try { return (await listStoredKeys()).includes(HARDWARE_GATED_KEY) ? 'protected' : 'unprotected'; } catch { return 'unknown'; }
}

/**
 * b77t (audit 5 M-A, R4 F-01): an AFFIRMATIVE, prompt-free check that hardware mode really protects the
 * identity entry. 'missing' used to pass (b77p stored the entry under a blinded name, where set() never
 * applied the Secure Enclave wrap or the biometric access control, and the probe of the literal name
 * answered 'missing', which nobody treated as a failure). Now only a positive answer counts:
 *  - with a Secure Enclave: the literal entry holds an SE-sealed blob ('sealed');
 *  - without one (the biometric-gated keychain entry): the literal entry exists. Its value can't be read
 *    without a prompt, but set() puts the access control on every write of that name in hardware mode.
 */
export async function keyvaultHardwareProtected(): Promise<boolean> {
  return (await keyvaultProtectionState()) === 'protected';
}

/** b62: is the Secure Enclave path usable on this device? (true hardware mode
 *  requires it; otherwise hardware mode falls back to the biometric-gated
 *  keychain entry, which is what pre-b62 builds shipped). */
export function secureEnclaveAvailable(): boolean {
  try {
    return !!nativeSe()?.seIsAvailable?.();
  } catch { return false; }
}

/**
 * b102 FIX (owner hardware finding, Sept 21: "selecting locked in your
 * phone's security chip does not engage Face ID or anything else" — on b101,
 * with the seal verified 'sealed' and the flip clean): the Secure Enclave key
 * persisted on this device was created back when seAccessControl() carried no
 * biometry constraint, and loadOrCreateSeKey() reuses any existing key
 * forever — so the seal succeeds and unwrap runs WITHOUT ever prompting.
 * Every biometric gate since b62 has been decorative on devices from that
 * era. This deletes the legacy key and recreates it with TODAY's
 * biometryCurrentSet ACL. ONLY call it when the keyvault identity is in
 * memory and is re-sealed immediately after — the previous sealed blob
 * becomes unreadable the moment the old key dies.
 */
export async function resetSecureEnclaveKey(): Promise<boolean> {
  const mod = nativeSe();
  if (!mod?.seResetKey || !mod?.seIsAvailable?.()) return false;
  // Batch E (round-3 review R1-02): a failed reset is an error, not "no hardware".
  // The callers' try blocks then stop the mode flip / re-seal instead of sealing
  // under the old (ungated) key and reporting hardware mode.
  let ok = false;
  try { ok = !!(await mod.seResetKey()); } catch (e) { throw new Error(`Secure Enclave key reset failed: ${String((e as Error)?.message ?? e)}`); }
  if (!ok) throw new Error('Secure Enclave key reset failed');
  return true;
}
