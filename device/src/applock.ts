/**
 * @veil/device — app lock: passcode + Decoy code + Duress code.
 *
 * WEB PARITY (byte-exact from the live bundle, index-CXHmaNHA.js):
 *   storage key `veil_app_lock` -> {
 *     method: 'passcode',
 *     kdf: 'PBKDF2-SHA256-210000',
 *     salt: hex (16 random bytes),
 *     realHash: hex, decoyHash: hex|null, duressHash: hex|null,
 *     autoLockMinutes
 *   }
 *   hash = PBKDF2-SHA256(code, saltHex->bytes, 210000 iters, 32 bytes) -> hex
 *   rules: duress !== real, decoy !== real, decoy !== duress.
 *
 * Codes NEVER leave the device: PBKDF2 runs on-device, only salted hashes are
 * stored in the secure keystore. ANTI-GOAL ENFORCED: no network imports.
 *
 * b70 (audit VAR-07): record v2. The stored verifiers are
 *   tag = MAC(LABEL || kind || PBKDF2(code, salt))
 * where MAC is keyed by the phone's secure hardware (Secure Enclave / Keystore,
 * native `lockMac`), so a copied record can't be guessed offline. The three
 * tags sit in a shuffled, unlabelled list and unused slots hold random bytes,
 * so the record doesn't show whether a decoy or duress code exists.
 * b71 (audit F-21): all of that holds only with the hardware key (mac: 'hw').
 * Where the phone has none, the soft key is stored beside the record: a copy of
 * both allows offline guessing and shows which code is which. The app says so
 * before a decoy or duress code is set on such a phone (lockHardwareKeyAvailable).
 * A v1 record is moved to v2 the first time it is read (MAC over its hashes).
 */

import { pbkdf2 } from '@noble/hashes/pbkdf2';
import { sha256 } from '@noble/hashes/sha256';
import { hmac } from '@noble/hashes/hmac';

const ITERATIONS = 210000;
const DK_LEN = 32;
export const APPLOCK_KEY = 'veil_app_lock';
export const KDF_LABEL = `PBKDF2-SHA256-210000`;

export interface AppLockRecord {
  method: 'passcode';
  kdf: string;
  salt: string;
  /** b70: 2 for the MAC'd, slot-shuffled record */
  v: 2;
  /** where the MAC key lives: 'hw' = this phone's secure hardware */
  mac: 'hw' | 'soft';
  /** three unlabelled tags in random order; unused slots are random */
  tags: string[];
  /** b70 (re-review): MAC of a fixed label — tells "the key behind this record
   *  is gone" apart from "wrong code" (absent on the first v2 records) */
  kid?: string;
  /** b71 (audit): 1 = this lock's wrong-attempt row (veil_lockout) carries a MAC
   *  bound to this record. A missing or altered row then counts as tampering and
   *  locks (b77n: the one-hour tamper lockout), instead of resetting the attempt budget.
   *  b75 (audit AL-1 / AL-2 / V4): 2 = both attempt rows (veil_lockout and
   *  veil_lock_wrong_in_a_row) exist from the lock's creation, carry a per-write
   *  epoch under their MAC (an epoch also noted outside the secure store, so an old
   *  copy put back shows), and the lockout row counts duress-code guesses made during
   *  a lockout. A missing, altered or older row is tampering. */
  lo?: 1 | 2;
}

/** the pre-b70 record, read only to move it to v2 */
interface AppLockRecordV1 {
  method: 'passcode';
  kdf: string;
  salt: string;
  realHash: string;
  decoyHash: string | null;
  duressHash: string | null;
}

export type CodeKind = 'real' | 'decoy' | 'duress';

/** b70 (VAR-17): thrown when the current password given to change or remove
 *  the lock isn't the real one. `kind` tells the caller a duress code was used. */
export class AppLockWrongCodeError extends Error {
  constructor(public kind: CodeKind | null) {
    super('Incorrect password.');
    this.name = 'AppLockWrongCodeError';
  }
}

/** The MAC behind the lock tags. Native: keyed by secure hardware. */
export interface LockMac {
  kind: 'hw' | 'soft';
  mac(dataHex: string): Promise<string>;
}

type NativeLock = {
  lockMacAvailable?: () => boolean;
  /** b75 (audit AL-11): true only when the lock key is inside secure hardware */
  lockMacHardware?: () => boolean;
  lockMac?: (inputHex: string) => Promise<string>;
  lockMacReset?: () => Promise<boolean>;
  uptimeMs?: () => number;
};

function nativeLock(): NativeLock | null {
  return (getNativeCrypto() as unknown as NativeLock | null) ?? null;
}

/** the soft MAC key, used only where the phone has no secure hardware (tests,
 *  old devices). It sits beside the record, so it adds nothing there. */
export const APPLOCK_SOFT_KEY = 'veil_app_lock_key';
const MAC_LABEL = 'vardum-lock-v2:';
const KIND_BYTE: Record<CodeKind, string> = { real: '01', decoy: '02', duress: '03' };

/** b71 (audit F-21): whether this phone can keep the lock key in secure hardware */
export function lockHardwareKeyAvailable(): boolean {
  try {
    const n = nativeLock();
    if (!(n?.lockMac && n.lockMacAvailable?.())) return false;
    // b75 (audit AL-11): Android used to report hardware on every phone. The native side
    // now reads the key's real security level (KeyInfo); a software-only Keystore key
    // still works for the lock but is not called hardware here.
    if (typeof n.lockMacHardware === 'function') return !!n.lockMacHardware();
    return true; // an older binary without the check: what it always reported
  } catch { return false; }
}

/** delete the hardware lock key (wipes). Best-effort, never prompts. */
export async function resetLockMacKey(): Promise<void> {
  try { await nativeLock()?.lockMacReset?.(); } catch { /* best-effort */ }
}

let uptimeOverride: (() => number | null) | null = null;
/** tests only: stand in for the native boot clock */
export function __setUptimeSourceForTests(fn: (() => number | null) | null): void {
  uptimeOverride = fn;
}

/** Time since boot where the native module has it; it ignores the wall clock. */
export function uptimeMs(): number | null {
  if (uptimeOverride) return uptimeOverride();
  try {
    const n = nativeLock()?.uptimeMs?.();
    return typeof n === 'number' && Number.isFinite(n) ? n : null;
  } catch {
    return null;
  }
}

/** b123 (owner ask, Sept 25): 5 wrong passcode attempts -> timed keypad
 *  lockout, progressively longer each consecutive lockout: 5 min, then
 *  10, 20, 40, capped at 60. The counter and stage reset on a successful
 *  unlock (real or decoy); a duress wipe clears everything anyway. All
 *  state is device-local — the lockout never leaves the phone. */
export const LOCKOUT_KEY = 'veil_lockout';
/** b74 (review VAR-04): wrong passwords in a row since the last correct one, MAC'd and
 *  bound to the lock record. Counted inside verify(), so EVERY password check counts —
 *  the lock screen, the Notes gate, Settings prompts, change and remove — not only the
 *  lock screen (b73 kept it in the app shell, read by the lock screen alone). */
export const WRONG_IN_A_ROW_KEY = 'veil_lock_wrong_in_a_row';
export const MAX_ATTEMPTS = 5;
/** audit VAR-18 (b77m): the windows keep growing past an hour, to a hard cap of a day (they stayed at
 *  60 min, ~120 guesses a day for ever). At the cap: 5 guesses a day. */
const LOCKOUT_MINUTES = [5, 10, 20, 40, 60, 120, 240, 480, 960, 1440];
/** owner decision (30 Oct, b77n): the TAMPER lockout (an attempt row found missing, altered,
 *  older than the noted epoch, or a record turned back to an older lock) is capped at one
 *  hour, as before b77m — it is the 60-minute stage, not the 24-hour cap the wrong-password
 *  schedule above escalates to. It never LOWERS what is already known: a longer
 *  wrong-password lockout (and its stage) still governs — see tamperedLockout(). */
export const TAMPER_LOCKOUT_MINUTES = 60;
export const TAMPER_STAGE = LOCKOUT_MINUTES.indexOf(TAMPER_LOCKOUT_MINUTES) + 1; // = 5

export interface LockoutState {
  /** wrong attempts since the last lockout or successful unlock (0..MAX) */
  fails: number;
  /** consecutive lockouts without a successful unlock — the escalation stage */
  stage: number;
  /** epoch ms until which the keypad refuses input */
  lockedUntil: number;
  /** Batch D (D-11): wall-clock time the current lockout began (a clock set
   *  back past it restarts the window) */
  lockedAt?: number;
  /** b70 (VAR-14): time since boot when the window (re)started, and its length.
   *  The window ends only when the boot clock agrees, so a clock set forward
   *  can't end it; after a reboot it starts again from the reboot. */
  upAt?: number;
  windowMs?: number;
  /** b75 (audit V4): duress-code guesses made during the current lockout window
   *  (persisted, so restarting the app no longer resets that budget) */
  d?: number;
  /** b75 (audit AL-2): this row's write epoch (under the MAC; never the same twice) */
  e?: number;
  /** b71 (audit): MAC over the fields above and the lock record's salt */
  m?: string;
}

/** b75 (audit AL-2): where the latest epoch of each attempt row is noted, outside the
 *  secure store (the app's own storage). Optional: without it only this process's
 *  memory catches an older row. */
export interface LockEpochMirror {
  read(): Promise<string | null>;
  write(v: string): Promise<void>;
  clear?(): Promise<void>;
  /** b75 round 3 (audit DV-3): the app's wipe generation. A row written before a wipe has
   *  its epoch noted only if no wipe began meanwhile (a check in flight used to write the
   *  note back after the wipe removed it). */
  generation?(): number;
}

export const EMPTY_LOCKOUT: LockoutState = { fails: 0, stage: 0, lockedUntil: 0 };

/** Batch D (D-11, RV-18): thrown by verify() while a lockout runs. */
export class AppLockLockedError extends Error {
  constructor(public lockedUntil: number) {
    super('Too many incorrect attempts. Wait for the timer, then try again.');
    this.name = 'AppLockLockedError';
  }
}

/** Batch D (D-11, RV-18): the lock record exists but can't be read. Callers
 *  treat this as LOCKED — never as "no lock set". */
export class AppLockUnreadableError extends Error {
  constructor() {
    super('The app lock settings on this phone could not be read. Restart Vardum and try again.');
    this.name = 'AppLockUnreadableError';
  }
}

/** Batch I (local review V-02): the phone refused to save the wrong-attempt
 *  counter. verify() fails closed: no password is checked until it can be. */
/** b74 (VAR-04): the opt-in erase-after-N-wrong-passwords limit was reached and the
 *  erase ran. Callers stop: the phone has been wiped. */
export class AppLockErasedError extends Error {
  constructor() {
    super('Too many wrong passwords — Vardum was erased from this phone.');
    this.name = 'AppLockErasedError';
  }
}

export class AppLockStorageError extends Error {
  constructor() {
    super('This attempt could not be recorded on this phone. Try again in a moment.');
    this.name = 'AppLockStorageError';
  }
}

/** Batch D (D-11): a lockout also runs on the process's monotonic clock, so
 *  setting the phone's clock forward can't end it early while the app is open. */
const monoLockUntil = new WeakMap<object, number>();
/** Batch I (V-02): wrong attempts this process has seen, whatever the stored
 *  counter says, so a counter that keeps reading empty can't reset the budget. */
const memFails = new WeakMap<object, number>();
/** b70 (fuzz S1): the queue that serialises verify() per lock storage */
const verifyChains = new WeakMap<object, Promise<void>>();
/** b75 (audit AL-2): the highest epoch this process has seen or written for each row */
const epochSeen = new WeakMap<object, { lo: number; wr: number }>();
/** b75 (audit AL-1): the last wrong-in-a-row count this process knows */
const memWir = new WeakMap<object, number>();
/** b77n (owner, 30 Oct): the highest escalation stage this process has seen (a tamper
 *  lockout never drops below it) */
const memStage = new WeakMap<object, number>();
const noteStage = (k: object, stage: number): void => {
  if (Number.isFinite(stage) && stage > (memStage.get(k) ?? 0)) memStage.set(k, stage);
};
const monoNow = (): number => (typeof performance !== 'undefined' && typeof performance.now === 'function' ? performance.now() : Date.now());

export function lockoutMsForStage(stage: number): number {
  const idx = Math.min(Math.max(stage, 1), LOCKOUT_MINUTES.length) - 1;
  return LOCKOUT_MINUTES[idx] * 60_000;
}

/** human "5 min" / "90 min" label for the lockout banner */
export function lockoutLabelForStage(stage: number): string {
  const idx = Math.min(Math.max(stage, 1), LOCKOUT_MINUTES.length) - 1;
  const m = LOCKOUT_MINUTES[idx];
  return m >= 120 ? `${m / 60} hours` : `${m} min`; // audit VAR-18
}

const enc = new TextEncoder();
const toHex = (b: Uint8Array): string =>
  Array.from(b).map((x) => x.toString(16).padStart(2, '0')).join('');
const fromHex = (h: string): Uint8Array =>
  new Uint8Array((h.match(/.{2}/g) || []).map((x) => parseInt(x, 16)));

/** web Ex(): PBKDF2-SHA256(code, salt, 210000, 256 bits) -> hex string */
export function hashCode(code: string, saltHex: string): string {
  return toHex(pbkdf2(sha256, enc.encode(code), fromHex(saltHex), { c: ITERATIONS, dkLen: DK_LEN }));
}

/**
 * Native fast path: iOS CommonCrypto PBKDF2 (local Expo module `veil-crypto`).
 * Byte-identical to the web contract, computed in milliseconds by the OS.
 * Resolved lazily through expo-modules-core's NativeModulesProxy so this file
 * stays dependency-free outside the app (monorepo tests fall back to JS).
 */
type NativeVeilCrypto = { pbkdf2Sha256(password: string, saltHex: string, iterations: number, dkLen: number): Promise<string> };

let probeOnce = false;
export function getNativeCrypto(): NativeVeilCrypto | null {
  try {
    // BUG FIXED (Sept 19): this used to read NativeModulesProxy.VeilCrypto,
    // which is the legacy unimodules bridge. Our veil-crypto module is a
    // modern Expo module (Module + ModuleDefinition, Swift side) and is
    // exposed via requireNativeModule(), same as modules/veil-crypto/index.ts
    // already did correctly. The proxy lookup silently returned undefined —
    // no error, no fallback log — so every unlock ran the 210k-iteration JS
    // path even after the native module was compiled into the binary.
    //
    // B47 INSTRUMENTATION: the b46-full tree was confirmed extracted and
    // Metro reloaded, yet unlock STILL took ~80s. So we now log loudly and
    // exactly once per app load which of the three failure modes it is:
    //   A. 'VeilCrypto native module FOUND'  -> native path; unlock is fast.
    //   B. 'requireNativeModule threw: ...'  -> the installed BINARY has no
    //      VeilCrypto Swift module compiled in (stale/incomplete EAS build).
    //   C. no [veil-lock][probe] line at all -> this file never ran, i.e.
    //      the phone is still on the old bundle (extraction/Metro issue).
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const emc = require('expo-modules-core') as { requireNativeModule?: <T>(name: string) => T };
    if (typeof emc?.requireNativeModule !== 'function') {
      if (!probeOnce) { probeOnce = true; console.log('[veil-lock][probe] expo-modules-core resolved but has no requireNativeModule export'); }
      return null;
    }
    const mod = emc.requireNativeModule<NativeVeilCrypto>('VeilCrypto');
    if (typeof mod?.pbkdf2Sha256 !== 'function') {
      if (!probeOnce) { probeOnce = true; console.log('[veil-lock][probe] VeilCrypto resolved but pbkdf2Sha256 missing:', typeof mod); }
      return null;
    }
    if (!probeOnce) { probeOnce = true; console.log('[veil-lock][probe] VeilCrypto native module FOUND'); }
    return mod;
  } catch (e) {
    if (!probeOnce) { probeOnce = true; console.log('[veil-lock][probe] requireNativeModule threw:', String((e as Error)?.message || e)); }
    return null; // tests / no native module compiled in yet -> JS fallback
  }
}

/**
 * Identical digest to hashCode, but chunked: REAL setTimeout yields every 2000
 * iterations return the RN JS thread to the event loop, so touch events, timers
 * and the bridge keep flowing while the 210k-iteration hash runs.
 * (noble's pbkdf2Async was NOT a fix: it yields via an already-resolved promise
 * — a microtask — which RN never returns to the event loop with, so the UI
 * stayed frozen for the whole computation.)
 */
export async function hashCodeAsync(code: string, saltHex: string): Promise<string> {
  const native = getNativeCrypto();
  if (!native) console.log('[veil-lock] NO native path available — running 210k-iteration JS path (expect ~80s on device)');
  if (native) {
    const tN = Date.now();
    try {
      const h = await native.pbkdf2Sha256(code, saltHex, ITERATIONS, DK_LEN);
      console.log(`[veil-lock] pbkdf2 done NATIVE in ${Date.now() - tN} ms`);
      return h;
    } catch (e) {
      console.log('[veil-lock] native pbkdf2 failed, falling back to JS chunked:', String(e));
    }
  }
  const t0 = Date.now();
  const pw = enc.encode(code);
  const salt = fromHex(saltHex);

  // HMAC-SHA256 key preparation (RFC 2104): pad/hash key to the 64-byte block
  const key = pw.length > 64 ? sha256(pw) : pw;
  const kb = new Uint8Array(64);
  kb.set(key);
  const ipad = new Uint8Array(64);
  const opad = new Uint8Array(64);
  for (let i = 0; i < 64; i++) { ipad[i] = kb[i] ^ 0x36; opad[i] = kb[i] ^ 0x5c; }
  const ipadH = sha256.create().update(ipad);
  const opadH = sha256.create().update(opad);

  // U1 = HMAC(pw, salt || INT_32_BE(1)); DK = T1 = U1 ^ U2 ^ ... ^ Uc  (dkLen = 32 -> single block)
  const s1 = new Uint8Array(salt.length + 4);
  s1.set(salt);
  s1[salt.length + 3] = 1;
  let u = opadH.clone().update(ipadH.clone().update(s1).digest()).digest();
  const t = new Uint8Array(DK_LEN);
  t.set(u);

  let sinceYield = 0;
  for (let i = 1; i < ITERATIONS; i++) {
    u = opadH.clone().update(ipadH.clone().update(u).digest()).digest();
    for (let j = 0; j < DK_LEN; j++) t[j] ^= u[j];
    if (++sinceYield >= 2000) {
      sinceYield = 0;
      await new Promise<void>((r) => setTimeout(r, 0)); // true event-loop yield
      if (i % 42000 === 0) console.log(`[veil-lock] pbkdf2 ${Math.round((i / ITERATIONS) * 100)}%`);
    }
  }
  console.log(`[veil-lock] pbkdf2 done in ${Date.now() - t0} ms`);
  return toHex(t);
}

/** web Dx(): fresh 16-byte random salt as hex */
export function freshSalt(): string {
  const b = new Uint8Array(16);
  if (typeof globalThis.crypto?.getRandomValues !== 'function') {
    // audit fix (Sept 19): a predictable salt silently weakens the KDF —
    // fail loudly instead of falling back to Math.random.
    throw new Error('Secure random unavailable — cannot create a lock-code salt.');
  }
  globalThis.crypto.getRandomValues(b);
  return toHex(b);
}

type LockStorage = { get(k: string): Promise<string | null>; set(k: string, v: string): Promise<unknown>; remove(k: string): Promise<unknown> };

function randomHex(n: number): string {
  const b = new Uint8Array(n);
  if (typeof globalThis.crypto?.getRandomValues !== 'function') throw new Error('Secure random unavailable.');
  globalThis.crypto.getRandomValues(b);
  return toHex(b);
}

function shuffled<T>(xs: T[]): T[] {
  const a = xs.slice();
  for (let i = a.length - 1; i > 0; i--) {
    const r = new Uint32Array(1);
    globalThis.crypto.getRandomValues(r);
    const j = r[0] % (i + 1);
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a;
}

function constEq(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}

export class AppLockStore {
  private macImpl: LockMac | null;

  /** b74 (VAR-04): the opt-in erase after `limit` wrong passwords in a row */
  private wipeAfter: { limit: number; erase: () => Promise<void> } | null = null;

  /** `mac` is for tests; the app uses the phone's secure hardware when present.
   *  b75 (audit AL-2): `mirror` notes each attempt row's latest epoch outside the store. */
  constructor(private storage: LockStorage, mac?: LockMac, private mirror?: LockEpochMirror) {
    this.macImpl = mac ?? null;
  }

  /** b74 (VAR-04): arm (or, with null, disarm) the erase after N wrong passwords in a row */
  setWipeAfter(opt: { limit: number; erase: () => Promise<void> } | null): void {
    this.wipeAfter = opt && opt.limit > 0 ? opt : null;
  }

  private static readonly WR_LABEL = toHex(enc.encode('vardum-wrong-in-a-row-v1:'));
  private static readonly WR_LABEL2 = toHex(enc.encode('vardum-wrong-in-a-row-v2:'));

  private async wrongTag(rec: AppLockRecord, n: number, e?: number, t?: boolean | number): Promise<string> {
    const m = await this.macFor(rec.mac);
    // b75 (audit AL-1 / AL-2): a lo-2 row's MAC covers its epoch and its tamper mark too
    // (b77n2, review L2: the mark is 1, or the lockout stage kept at the tampering — see markOf)
    if (rec.lo === 2) return m.mac(AppLockStore.WR_LABEL2 + toHex(enc.encode(JSON.stringify([rec.salt, n, e ?? -1, AppLockStore.markOf(t)]))));
    return m.mac(AppLockStore.WR_LABEL + toHex(enc.encode(JSON.stringify([rec.salt, n]))));
  }

  /** b75 (audit AL-1): the wrong-in-a-row row, checked. 'tampered' = missing, altered
   *  or older than the latest one written (lo-2 locks); 'unreadable' = the store
   *  refused the read (the lock then reads as locked, nothing is changed).
   *  `t` = an earlier tampering was seen since the last correct password; `ts` = the mark as stored
   *  (b77n2, review L2: 1, or the lockout stage kept at the tampering; 0 without a mark). */
  private async readWrongRow(rec: AppLockRecord): Promise<{ n: number; t: boolean; ts: number } | 'tampered' | 'unreadable'> {
    let raw: string | null = null;
    try { raw = await this.storage.get(WRONG_IN_A_ROW_KEY); } catch { return 'unreadable'; }
    if (!raw) return rec.lo === 2 ? 'tampered' : { n: 0, t: false, ts: 0 };
    try {
      const v = JSON.parse(raw) as { n?: unknown; m?: unknown; e?: unknown; t?: unknown };
      const n = Number(v.n);
      if (!Number.isSafeInteger(n) || n < 0 || typeof v.m !== 'string') throw new Error('shape');
      const e = rec.lo === 2 ? Number(v.e) : undefined;
      const ts = rec.lo === 2 ? AppLockStore.markOf(v.t) : 0;
      const t = ts >= 1;
      if (rec.lo === 2 && !Number.isSafeInteger(e)) throw new Error('shape');
      if (!constEq(await this.wrongTag(rec, n, e, ts), v.m)) throw new Error('mac');
      if (rec.lo === 2 && !(await this.fresh(rec, 'wr', e!))) throw new Error('stale');
      return { n, t, ts };
    } catch {
      if (rec.lo === 2) return 'tampered';
      console.log('[veil-lock] the wrong-in-a-row count was unreadable or altered — read as 0');
      return { n: 0, t: false, ts: 0 };
    }
  }

  /** b75 (audit AL-1): after tampering the count is never believed lower than this:
   *  what this process knows, and — with the opt-in erase armed — one short of its
   *  limit, so deleting the row can no longer keep the erase from ever firing */
  private wrongFloor(tampered: boolean): number {
    const known = memWir.get(this.storage) ?? 0;
    return tampered && this.wipeAfter ? Math.max(known, this.wipeAfter.limit - 1) : known;
  }

  /** b77n2 (review L2): the tamper mark of a wrong-in-a-row row as stored and MAC'd — 0 (none), 1 (tampering
   *  seen; every row b75–b77n wrote), or the lockout STAGE kept when the tampering was seen (≥ 2). The stage rides
   *  in the mark so that a later delete of the lockout row (two-step tampering: corrupt this row — the lockout row
   *  still verifies, its 24-hour stage is kept —, restart, then delete the lockout row, restart) derives that stage
   *  again, not the tamper hour: the row used to be re-written with only this process's count (0 after a
   *  restart). The count itself is left alone (it is what the opt-in erase counts). */
  private static markOf(t: unknown): number {
    if (t === true) return 1;
    const v = Number(t);
    return Number.isSafeInteger(v) && v >= 1 && v <= 1000 ? v : 0;
  }
  /** the mark a tamper re-write stores: the stage kept (never below 1) */
  private static tamperMark(st: LockoutState): number {
    return Math.max(1, Math.min(1000, Math.floor(Number(st.stage) || 0)));
  }

  /** b74 (VAR-04): wrong passwords in a row.
   *  b75 (audit AL-1): for a lo-2 lock the row exists from the lock's creation, so a
   *  missing, altered or older row is tampering: lockout() arms the tamper lockout
   *  and re-writes the row with a tamper mark (kept until the next correct password). */
  async wrongInARow(): Promise<number> {
    const rec = await this.recordQuiet();
    if (!rec) return 0;
    const r = await this.readWrongRow(rec);
    if (r === 'unreadable') return memWir.get(this.storage) ?? 0;
    if (r === 'tampered') return this.wrongFloor(true);
    const n = r.t ? Math.max(r.n, this.wrongFloor(true)) : r.n;
    memWir.set(this.storage, n);
    return n;
  }

  private async setWrongInARow(n: number, recIn?: AppLockRecord | null, tamper?: boolean | number): Promise<void> {
    const gen = this.wipeGen(); // b75 round 3 (audit DV-3)
    const rec = recIn === undefined ? await this.recordQuiet() : recIn;
    if (!rec) { await this.storage.remove(WRONG_IN_A_ROW_KEY); return; }
    if (rec.lo !== 2) {
      if (n <= 0) { await this.storage.remove(WRONG_IN_A_ROW_KEY); memWir.set(this.storage, 0); return; }
      if ((await this.storage.set(WRONG_IN_A_ROW_KEY, JSON.stringify({ n, m: await this.wrongTag(rec, n) }))) === false) throw new AppLockStorageError();
      memWir.set(this.storage, n);
      return;
    }
    // b75 (audit AL-1 / AL-2): a lo-2 lock always keeps a row (n = 0 included), each
    // write with a new epoch under the MAC; the tamper mark is carried until the real
    // password resets the run (n = 0 with no mark)
    // (b77n2, review L2: the mark carries the stage kept at the tampering — markOf — and is carried as stored)
    let t = AppLockStore.markOf(tamper);
    if (tamper === undefined && n > 0) { const cur = await this.readWrongRow(rec); t = typeof cur === 'object' ? cur.ts : 1; }
    const e = await this.nextEpoch(rec);
    const row = t ? { n, e, t, m: await this.wrongTag(rec, n, e, t) } : { n, e, m: await this.wrongTag(rec, n, e, 0) };
    if ((await this.storage.set(WRONG_IN_A_ROW_KEY, JSON.stringify(row))) === false) throw new AppLockStorageError();
    memWir.set(this.storage, n);
    await this.noteEpoch(rec, 'wr', e, gen);
  }

  /** b75 round 3 (audit DV-3): the wipe generation now (undefined without a mirror that knows it) */
  private wipeGen(): number | undefined {
    try { return this.mirror?.generation?.(); } catch { return undefined; }
  }

  // ---------- b75 (audit AL-2): per-write epochs ----------

  /** a short tag of the lock's salt: the mirror's notes belong to one lock */
  private static saltTag(rec: AppLockRecord): string {
    return toHex(sha256(enc.encode('vardum-lock-epoch:' + rec.salt))).slice(0, 16);
  }

  private async readMirror(rec: AppLockRecord): Promise<{ lo: number; wr: number } | null> {
    if (!this.mirror) return null;
    try {
      const raw = await this.mirror.read();
      if (!raw) return null;
      const v = JSON.parse(raw) as { s?: unknown; lo?: unknown; wr?: unknown };
      if (v.s !== AppLockStore.saltTag(rec)) return null; // another (older) lock's notes
      return { lo: Number(v.lo) || 0, wr: Number(v.wr) || 0 };
    } catch { return null; }
  }

  /** the epoch a write uses: above every epoch known for either row */
  private async nextEpoch(rec: AppLockRecord): Promise<number> {
    const mem = epochSeen.get(this.storage) ?? { lo: 0, wr: 0 };
    const mir = (await this.readMirror(rec)) ?? { lo: 0, wr: 0 };
    return Math.max(mem.lo, mem.wr, mir.lo, mir.wr) + 1;
  }

  /** note a row's epoch (memory, then the mirror). The row is written first, so the
   *  mirror is never ahead of the store. */
  private async noteEpoch(rec: AppLockRecord, row: 'lo' | 'wr', e: number, gen?: number): Promise<void> {
    const mem = epochSeen.get(this.storage) ?? { lo: 0, wr: 0 };
    mem[row] = Math.max(mem[row], e);
    epochSeen.set(this.storage, mem);
    if (!this.mirror) return;
    // b75 round 3 (audit DV-3): a wipe began after this row was written: no note (the wipe
    // removes the notes, and one written back would read as a lock that was removed)
    if (gen !== undefined && this.wipeGen() !== gen) return;
    try {
      const mir = (await this.readMirror(rec)) ?? { lo: 0, wr: 0 };
      mir[row] = Math.max(mir[row], e);
      await this.mirror.write(JSON.stringify({ s: AppLockStore.saltTag(rec), lo: mir.lo, wr: mir.wr }));
    } catch { /* best-effort: memory still catches an older row this run */ }
  }

  /** a row is current unless an epoch newer than its own was noted for it */
  private async fresh(rec: AppLockRecord, row: 'lo' | 'wr', e: number): Promise<boolean> {
    const mem = epochSeen.get(this.storage);
    if (mem && e < mem[row]) return false;
    const mir = await this.readMirror(rec);
    if (mir && e < mir[row]) return false;
    const m2 = mem ?? { lo: 0, wr: 0 };
    m2[row] = Math.max(m2[row], e);
    epochSeen.set(this.storage, m2);
    return true;
  }

  /** the hardware MAC if the phone has one, else a soft key kept beside the record */
  private async macFor(want?: 'hw' | 'soft'): Promise<LockMac> {
    if (this.macImpl && (!want || this.macImpl.kind === want)) return this.macImpl;
    const n = nativeLock();
    let hwOk = false;
    try { hwOk = !!(n?.lockMac && n.lockMacAvailable?.()); } catch { hwOk = false; }
    if (hwOk && want !== 'soft') {
      const hw: LockMac = { kind: 'hw', mac: (d) => n!.lockMac!(d) };
      if (want === 'hw') return hw; // an existing hardware record: no fallback, ever
      // b70 (re-review): a NEW record uses the hardware key only if it really
      // works on this phone (some Keystores can't make an HMAC key)
      try { await hw.mac(AppLockStore.KID_INPUT); return hw; } catch { /* fall through to the soft key */ }
    }
    // a record made with the hardware key can't be checked without it: locked
    if (want === 'hw') throw new AppLockUnreadableError();
    const storage = this.storage;
    return {
      kind: 'soft',
      async mac(d: string) {
        let key = await storage.get(APPLOCK_SOFT_KEY);
        if (!key) {
          key = randomHex(32);
          if ((await storage.set(APPLOCK_SOFT_KEY, key)) === false) throw new Error('The app lock could not be saved on this phone. Try again.');
        }
        return toHex(hmac(sha256, fromHex(key), fromHex(d)));
      },
    };
  }

  private static macInput(kind: CodeKind, dkHex: string): string {
    return toHex(enc.encode(MAC_LABEL)) + KIND_BYTE[kind] + dkHex;
  }

  private static readonly KID_INPUT = toHex(enc.encode('vardum-lock-kid-v1'));

  /** Batch D (D-11, RV-18): null ONLY when no lock is set. A read or parse
   *  failure throws AppLockUnreadableError (fail closed). A v1 record is
   *  moved to v2 here (b70). */
  async load(): Promise<AppLockRecord | null> {
    let raw: string | null;
    try { raw = await this.storage.get(APPLOCK_KEY); } catch { throw new AppLockUnreadableError(); }
    // b75 round 3 (audit DV-6): an EMPTY record is never written (clear() deletes it), so it
    // is tampering, never "no lock"; so is a missing one while the lock's own traces remain
    if (raw === '') throw new AppLockUnreadableError();
    if (raw === null || raw === undefined) {
      if (await this.lockTraces()) throw new AppLockUnreadableError();
      return null;
    }
    let parsed: AppLockRecord | AppLockRecordV1;
    try {
      parsed = JSON.parse(raw);
      if (!parsed || typeof parsed !== 'object' || typeof parsed.salt !== 'string') throw new Error('shape');
    } catch {
      throw new AppLockUnreadableError();
    }
    if ((parsed as AppLockRecord).v === 2) {
      const rec = parsed as AppLockRecord;
      if (!Array.isArray(rec.tags) || rec.tags.length !== 3 || !rec.tags.every((t) => typeof t === 'string' && /^[0-9a-f]{64}$/.test(t))) throw new AppLockUnreadableError();
      if (rec.mac !== 'hw' && rec.mac !== 'soft') throw new AppLockUnreadableError();
      return rec;
    }
    const v1 = parsed as AppLockRecordV1;
    if (typeof v1.realHash !== 'string') throw new AppLockUnreadableError();
    return this.migrate(v1);
  }

  /**
   * b75 round 3 (audit DV-6): does anything say a lock exists, with the record gone? The
   * wrong-in-a-row row (a b75 lock keeps one from its creation; clear() deletes it before the
   * record) and the epoch notes kept outside the store (clear() and every wipe remove them).
   * Deleting or emptying only the record used to turn the lock off: no lock screen at the
   * next launch. A row that can't be read counts as a trace (fail closed); the notes are
   * best-effort (a read error there is not a trace).
   */
  private async lockTraces(): Promise<boolean> {
    try { if (await this.storage.get(WRONG_IN_A_ROW_KEY)) return true; } catch { return true; }
    try { if (this.mirror && (await this.mirror.read())) return true; } catch { /* not a trace */ }
    return false;
  }

  /** b70: v1 -> v2 without knowing any code (the MAC goes over the stored hashes) */
  private async migrate(v1: AppLockRecordV1): Promise<AppLockRecord> {
    const m = await this.macFor();
    const tagOf = (kind: CodeKind, h: string | null) => (h ? m.mac(AppLockStore.macInput(kind, h)) : Promise.resolve(randomHex(32)));
    const rec: AppLockRecord = {
      method: 'passcode',
      kdf: KDF_LABEL,
      salt: v1.salt,
      v: 2,
      mac: m.kind,
      // one at a time (re-review: parallel first-use key creation could race natively)
      tags: shuffled([await tagOf('real', v1.realHash), await tagOf('decoy', v1.decoyHash), await tagOf('duress', v1.duressHash)]),
      kid: await m.mac(AppLockStore.KID_INPUT),
    };
    // a refused write keeps the old record on disk; this read still uses v2
    await Promise.resolve(this.storage.set(APPLOCK_KEY, JSON.stringify(rec))).catch(() => undefined);
    return rec;
  }

  /**
   * web Ve(): set the codes with the three differ-rules; throws with web copy
   * on violation. b70 (VAR-01/VAR-17): only when NO lock is set. Changing an
   * existing lock goes through change(), which needs the current real code.
   */
  async save(passcode: string, decoy?: string | null, duress?: string | null): Promise<AppLockRecord> {
    if (await this.load()) throw new Error('An app lock is already set. Enter the current password to change it.');
    return this.write(passcode, decoy, duress);
  }

  /** b70 (VAR-01/VAR-17): replace the codes. `current` must be the real code;
   *  anything else throws AppLockWrongCodeError (and counts as an attempt). */
  async change(current: string, passcode: string, decoy?: string | null, duress?: string | null): Promise<AppLockRecord> {
    if (await this.load()) {
      const kind = await this.verify(current);
      if (kind !== 'real') throw new AppLockWrongCodeError(kind);
    }
    return this.write(passcode, decoy, duress);
  }

  private async write(passcode: string, decoy?: string | null, duress?: string | null): Promise<AppLockRecord> {
    if (duress && duress === passcode) throw new Error('The duress code must differ from the real passcode');
    if (decoy && decoy === passcode) throw new Error('The decoy code must differ from the real passcode');
    if (decoy && duress && decoy === duress) throw new Error('The decoy and duress codes must differ');
    const salt = freshSalt();
    const m = await this.macFor();
    const tagOf = async (kind: CodeKind, code: string | null | undefined) =>
      (code ? m.mac(AppLockStore.macInput(kind, await hashCodeAsync(code, salt))) : randomHex(32));
    const rec: AppLockRecord = {
      method: 'passcode',
      kdf: KDF_LABEL,
      salt,
      v: 2,
      mac: m.kind,
      tags: shuffled([await tagOf('real', passcode), await tagOf('decoy', decoy), await tagOf('duress', duress)]),
      kid: await m.mac(AppLockStore.KID_INPUT),
      lo: 2, // b71 (audit): the attempt counter is MAC'd from the start; b75: both rows, with epochs
    };
    // b75 (audit AL-1): both attempt rows exist from the start (wrong-in-a-row n = 0
    // included), written BEFORE the record so a lock never exists without them; a
    // refused write fails the whole save
    try {
      await this.saveLockout({ ...EMPTY_LOCKOUT }, rec);
      await this.setWrongInARow(0, rec);
    } catch {
      throw new Error('The app lock could not be saved on this phone. Try again.');
    }
    // Batch I (V-02): a refused write is reported, never shown as success
    if ((await this.storage.set(APPLOCK_KEY, JSON.stringify(rec))) === false) {
      throw new Error('The app lock could not be saved on this phone. Try again.');
    }
    return rec;
  }

  /** the kind a code matches, against a loaded record (no attempt counting) */
  private async classify(rec: AppLockRecord, code: string): Promise<CodeKind | null> {
    const m = await this.macFor(rec.mac);
    // b70 (re-review): the key this record was made with no longer exists —
    // no code can match, so say "can't be read" rather than "wrong"
    if (rec.kid && !constEq(await m.mac(AppLockStore.KID_INPUT), rec.kid)) throw new AppLockUnreadableError();
    const dk = await hashCodeAsync(code, rec.salt);
    let found: CodeKind | null = null;
    for (const kind of ['real', 'decoy', 'duress'] as CodeKind[]) {
      const t = await m.mac(AppLockStore.macInput(kind, dk));
      // every tag is compared every time: the timing doesn't say which slot matched
      for (const tag of rec.tags) if (constEq(t, tag) && !found) found = kind;
    }
    return found;
  }

  /**
   * web Ox(): classify an entered code.
   * Batch D (D-11, RV-18/RV-20): verify enforces the lockout itself (every caller
   * — lock screen, notes gate, removing the lock — gets it), and counts the
   * attempt as wrong BEFORE hashing, so killing the app mid-hash still costs an
   * attempt. The real code resets the budget; decoy and duress codes neither
   * count as wrong nor reset it (V-23). Nothing about the hash is logged.
   */
  /** `opts.decoy` (re-audit N2): the check runs inside decoy mode — the real code is
   *  then an ordinary wrong attempt (counted, no lockout or in-a-row reset), so a decoy
   *  screen can't be used to tell the real password from a wrong one. */
  async verify(code: string, opts: { decoy?: boolean } = {}): Promise<CodeKind | null> {
    // b70 (fuzz battery S1): one check at a time per lock. Parallel calls used
    // to all read the same attempt count before any of them wrote it, so 20
    // guesses at once were all checked against a 5-attempt budget.
    const prev = verifyChains.get(this.storage) ?? Promise.resolve();
    let release!: () => void;
    const mine = new Promise<void>((r) => { release = r; });
    verifyChains.set(this.storage, prev.then(() => mine));
    await prev;
    try {
      return await this.verifyOne(code, opts);
    } finally {
      release();
    }
  }

  private async verifyOne(code: string, opts: { decoy?: boolean } = {}): Promise<CodeKind | null> {
    const before = await this.lockout();
    if (before.lockedUntil > Date.now()) {
      // b70 (re-review): the duress code still works during a lockout — someone
      // forced into five wrong tries must still be able to erase the phone.
      // b75 (audit V4): its budget is persisted in the (MAC'd) lockout row, reserved
      // before hashing, so restarting the app no longer gives a fresh one; the
      // in-memory count still gates when the row can't be written.
      // b77u (audit 6 W3 / IH full L-4): every other code is refused WITHOUT counting. Each code here used to
      // add to the wrong-in-a-row count, the real one included, so the owner typing the correct password during
      // the countdown could set off "Erase after 10 wrong passwords". Nothing but duress is acted on during a
      // lockout, so nothing else is a guess there: a refused code is not a failure.
      const recL = await this.load();
      const seenL = memFails.get(this.storage) ?? 0;
      const usedL = Math.max(0, Number(before.d) || 0);
      if (recL && seenL < MAX_ATTEMPTS && usedL < MAX_ATTEMPTS) {
        memFails.set(this.storage, seenL + 1);
        if (recL.lo === 2) await this.bumpDuressBudget(recL, usedL + 1).catch(() => undefined);
        if ((await this.classify(recL, code)) === 'duress') { memFails.set(this.storage, seenL); return 'duress'; }
      }
      throw new AppLockLockedError(before.lockedUntil);
    }
    const rec = await this.load();
    if (!rec) return null;
    // Batch I (V-02): the process's own count also gates, in case the stored
    // counter keeps reading empty
    const seen = memFails.get(this.storage) ?? 0;
    if (seen >= MAX_ATTEMPTS) {
      const until = Date.now() + lockoutMsForStage(Math.max(before.stage, 1));
      monoLockUntil.set(this.storage, monoNow() + lockoutMsForStage(Math.max(before.stage, 1)));
      memFails.set(this.storage, 0);
      throw new AppLockLockedError(until);
    }
    // Batch I (V-02): the attempt is reserved BEFORE hashing, and a refused
    // reservation throws (AppLockStorageError): no password is checked
    let after: LockoutState | null = null;
    try {
      after = await this.recordFail();
    } catch (e) {
      // b63 review (I3-2): the counter can't be saved, so no password is
      // checked, but the duress code still is. Matching it only erases this
      // phone, so the in-memory budget is enough of a limit here.
      if (!(e instanceof AppLockStorageError)) throw e;
      memFails.set(this.storage, seen + 1);
      if ((await this.classify(rec, code)) === 'duress') {
        memFails.set(this.storage, seen);
        return 'duress';
      }
      throw e;
    }
    // b63 review (I3-3): once the stored lockout arms, it governs; the
    // in-memory count starts again so it can't add a second window
    memFails.set(this.storage, after.lockedUntil > Date.now() ? 0 : seen + 1);
    // b74 (VAR-04): the in-a-row count is also reserved BEFORE hashing (a killed app
    // can't save a guess), restored for duress, reset by the real (and, b77q AP-1, decoy) code
    const wirBefore = await this.wrongInARow();
    await this.setWrongInARow(wirBefore + 1);
    const t1 = Date.now();
    let kind = await this.classify(rec, code);
    console.log(`[veil-lock] verify: checked in ${Date.now() - t1} ms`);
    if (opts.decoy && kind === 'real') kind = null; // re-audit N2: in decoy mode, just a wrong code
    // b77q (audit 3 AP-1): the decoy code now resets the budget, the stage and the in-a-row
    // count exactly as the real code does. Batch C (V-23) restored them for the decoy, so the
    // lock screen's count (and the next lockout's length, and the stored rows) told a captor
    // in two wrong tries whether the code handed over was the decoy. Trade-off, accepted:
    // someone who holds the decoy code can earn a fresh budget by unlocking with it, so the
    // escalating lockout and the opt-in erase no longer bound their guesses at the real code
    // (each guess still costs a full PBKDF2 check). Duress (which erases) still restores.
    if (kind === 'real' || kind === 'decoy') {
      await this.clearLockout();
      await this.setWrongInARow(0).catch(() => undefined);
    } else if (kind) {
      monoLockUntil.delete(this.storage);
      memFails.set(this.storage, seen); // duress is not a wrong attempt
      await this.saveLockout(before).catch(() => undefined); // restoring is best-effort
      await this.setWrongInARow(wirBefore).catch(() => undefined);
    } else if (this.wipeAfter && wirBefore + 1 >= this.wipeAfter.limit) {
      // b74 (VAR-04): one place for the opt-in erase, whichever screen asked
      await this.wipeAfter.erase();
      throw new AppLockErasedError();
    }
    return kind;
  }

  /** b75 round 3 (audit DV-6): the lock's traces go FIRST and the record last, so a removal
   *  cut short leaves a lock (its rows missing: a lockout, the right code still opens it),
   *  never traces without a record (which now reads as a damaged lock). The epoch notes must
   *  go: if they can't be removed, nothing is removed (the caller reports the error). The
   *  attempt counter goes too (it used to stay behind, MAC'd for a lock that no longer existed). */
  async clear(): Promise<void> {
    await this.mirror?.clear?.();
    epochSeen.delete(this.storage);
    await this.storage.remove(WRONG_IN_A_ROW_KEY);
    memWir.delete(this.storage);
    await this.storage.remove(LOCKOUT_KEY);
    await this.storage.remove(APPLOCK_SOFT_KEY);
    await this.storage.remove(APPLOCK_KEY);
  }

  /** b70 (VAR-17): remove the lock; `current` must be the real code */
  async remove(current: string): Promise<void> {
    const kind = await this.verify(current);
    if (kind !== 'real') throw new AppLockWrongCodeError(kind);
    await this.clear();
  }

  // ---------- b123: progressive passcode-attempt lockout (device-local) ----------

  /**
   * Batch C (V-23; review P2): fail CLOSED. An unreadable or damaged lockout
   * record used to read as "no failures" — a reset an attacker could provoke.
   * Now it counts as a lockout window (the first stage), persisted when the
   * record was damaged so a restart doesn't skip it.
   */
  async lockout(): Promise<LockoutState> {
    let raw: string | null;
    try {
      raw = await this.storage.get(LOCKOUT_KEY);
    } catch {
      return { fails: 0, stage: 1, lockedUntil: Date.now() + lockoutMsForStage(1) };
    }
    // b71 (external audit F-20, known limit): the MAC proves a row is genuine, not that it
    // is the LATEST one. Someone able to write the app's keychain/keystore items (root, a
    // jailbreak, a file-level restore) can put back an old {fails: 0} row and keep
    // guessing. Closing that needs a hardware monotonic counter; such an attacker can
    // usually read the data directly anyway (the lock is a gate, not encryption).
    // b71 (audit): deleting or editing the stored counter used to reset the attempt
    // budget after a restart. For a lock whose counter is MAC'd (lo: 1), a missing
    // row or one whose MAC doesn't verify is tampering: the tamper lockout runs (b77n: 1 h, never lowering a known one).
    const rec = await this.recordQuiet();
    if (rec && (rec.lo === 1 || rec.lo === 2) && !(await this.rowGenuine(rec, raw))) return this.tamperedLockout(rec, null);
    // b75 (audit AL-2): a lock this phone already ran as lo 2 (its epochs are noted
    // outside the store) can't be turned back into an older one by editing the record
    if (rec && rec.lo !== 2 && (await this.readMirror(rec))) {
      const rec2: AppLockRecord = { ...rec, lo: 2 };
      // b77n: a lockout row that still verifies under the lo-2 MAC is a known lockout (never lowered)
      const known2 = (await this.rowGenuine(rec2, raw).catch(() => false)) ? await this.readLockout(raw).catch(() => null) : null;
      await Promise.resolve(this.storage.set(APPLOCK_KEY, JSON.stringify(rec2))).catch(() => undefined);
      const st2 = await this.tamperedLockout(rec2, known2);
      await this.setWrongInARow(this.wrongFloor(true), rec2, AppLockStore.tamperMark(st2)).catch(() => undefined);
      return st2;
    }
    // b75 (audit AL-1): the wrong-in-a-row row is checked here too, so a missing,
    // altered or older one arms the lockout before any password is checked
    if (rec && rec.lo === 2) {
      const w = await this.readWrongRow(rec);
      if (w === 'unreadable') return { fails: 0, stage: 1, lockedUntil: Date.now() + lockoutMsForStage(1) };
      if (w === 'tampered') {
        // b77n: the lockout row itself verified above — its lockout and stage are known
        const st2 = await this.tamperedLockout(rec, await this.readLockout(raw).catch(() => null));
        // re-written with the tamper mark, so the same tampering isn't re-detected (and the
        // window re-started) at every read, and the erase floor survives a restart
        await this.setWrongInARow(this.wrongFloor(true), rec, AppLockStore.tamperMark(st2)).catch(() => undefined);
        return st2;
      }
    }
    const st = await this.readLockout(raw);
    noteStage(this.storage, st.stage);
    // a lock made before b75: MAC its rows the new way once, then require them
    if (rec && rec.lo !== 2) await this.upgradeLockout(rec, st);
    return st;
  }

  /** the lock record, or null when there is none or it can't be read */
  private async recordQuiet(): Promise<AppLockRecord | null> {
    try { return await this.load(); } catch { return null; }
  }

  private static readonly LO_LABEL = toHex(enc.encode('vardum-lockout-v1:'));
  private static readonly LO_LABEL2 = toHex(enc.encode('vardum-lockout-v2:'));

  /** b71 (audit): MAC of a counter row, bound to the lock record's salt.
   *  b75 (audit AL-2 / V4): for a lo-2 lock it also covers the duress budget and the
   *  row's write epoch, so no two rows are alike. */
  private async lockoutTag(rec: AppLockRecord, st: LockoutState): Promise<string> {
    const m = await this.macFor(rec.mac);
    if (rec.lo === 2) {
      const core2 = JSON.stringify([rec.salt, st.fails, st.stage, st.lockedUntil, st.lockedAt ?? null, st.upAt ?? null, st.windowMs ?? null, st.d ?? 0, st.e ?? -1]);
      return m.mac(AppLockStore.LO_LABEL2 + toHex(enc.encode(core2)));
    }
    const core = JSON.stringify([rec.salt, st.fails, st.stage, st.lockedUntil, st.lockedAt ?? null, st.upAt ?? null, st.windowMs ?? null]);
    return m.mac(AppLockStore.LO_LABEL + toHex(enc.encode(core)));
  }

  private async rowGenuine(rec: AppLockRecord, raw: string | null): Promise<boolean> {
    if (!raw) return false;
    let st: LockoutState;
    try { st = JSON.parse(raw) as LockoutState; } catch { return false; }
    if (!st || typeof st !== 'object' || typeof st.m !== 'string') return false;
    const num = (x: unknown) => (x === undefined ? undefined : Number(x));
    let want: string;
    try {
      want = await this.lockoutTag(rec, { fails: Number(st.fails), stage: Number(st.stage), lockedUntil: Number(st.lockedUntil), lockedAt: num(st.lockedAt), upAt: num(st.upAt), windowMs: num(st.windowMs), d: num(st.d), e: num(st.e) });
    } catch {
      return true; // the MAC key itself is unavailable: the lock already reads as locked (classify)
    }
    if (!constEq(want, st.m)) return false;
    // b75 (audit AL-2): an older copy of the row (its epoch behind the latest noted) is not current
    if (rec.lo === 2) return Number.isSafeInteger(Number(st.e)) && this.fresh(rec, 'lo', Number(st.e));
    return true;
  }

  /** b71 (audit): a deleted or altered counter — a lockout window, persisted (MAC'd).
   *  b77n (owner decision, 30 Oct): the window is ONE HOUR (the 60-minute stage), not the
   *  24-hour cap — but it is the max of that and everything still known, so tampering can't
   *  shorten or reset a longer wrong-password lockout:
   *   - `known`: the lockout row when it still verifies (only the other row was tampered) —
   *     its remaining window and its stage;
   *   - this process's own memory: the running window (monotonic clock) and highest stage;
   *   - with the lockout row gone or forged (`known` null), the wrong-in-a-row count (its own
   *     MAC'd row; MAX_ATTEMPTS per lockout) gives a stage floor. That stage's window may
   *     still be running and can't be checked, so it is re-armed in full when longer than
   *     the hour (fail closed; this is what keeps "delete the row, restart" from turning
   *     the 24-hour cap into one hour).
   *  The stage is kept too, so the next wrong-password lockout escalates from there.
   *  Someone who deletes BOTH rows and restarts gets the hour (known limit, §8.2 item 21). */
  private async tamperedLockout(rec: AppLockRecord, known: LockoutState | null): Promise<LockoutState> {
    console.log('[veil-lock] an attempt row was missing or altered — tamper lockout');
    const now = Date.now();
    let derived = 0;
    if (!known) {
      const w = await this.readWrongRow(rec).catch(() => 'unreadable' as const);
      const n = typeof w === 'object' ? (w.t ? Math.max(w.n, this.wrongFloor(true)) : w.n) : (memWir.get(this.storage) ?? 0);
      // b77n2 (review L2): and the stage a previous tampering kept (the row's mark), so two-step tampering can't drop it
      derived = Math.max(Math.floor(n / MAX_ATTEMPTS), typeof w === 'object' && w.ts > 1 ? w.ts : 0);
    }
    const stage = Math.max(TAMPER_STAGE, known ? Number(known.stage) || 0 : 0, memStage.get(this.storage) ?? 0, derived);
    const mono = monoLockUntil.get(this.storage);
    const ms = Math.max(
      TAMPER_LOCKOUT_MINUTES * 60_000,
      known && known.lockedUntil > now ? known.lockedUntil - now : 0,
      mono !== undefined ? mono - monoNow() : 0,
      derived > TAMPER_STAGE ? lockoutMsForStage(derived) : 0,
    );
    const up = uptimeMs();
    const st: LockoutState = { fails: 0, stage, lockedUntil: now + ms, lockedAt: now, ...(up !== null ? { upAt: up, windowMs: ms } : {}) };
    monoLockUntil.set(this.storage, monoNow() + ms);
    noteStage(this.storage, stage);
    await this.saveLockout(st, rec).catch(() => undefined);
    return st;
  }

  /** b75 (audit V4): note one more duress-path guess in the stored row — the row as
   *  stored (not the clock-adjusted view lockout() returns, which would stretch the window) */
  private async bumpDuressBudget(rec: AppLockRecord, d: number): Promise<void> {
    const raw = await this.storage.get(LOCKOUT_KEY);
    if (!raw) return;
    const st = JSON.parse(raw) as LockoutState;
    const num = (x: unknown) => (x === undefined ? undefined : Number(x));
    const row: LockoutState = { fails: Number(st.fails), stage: Number(st.stage), lockedUntil: Number(st.lockedUntil) };
    for (const [k, v] of [['lockedAt', num(st.lockedAt)], ['upAt', num(st.upAt)], ['windowMs', num(st.windowMs)]] as const) if (v !== undefined) (row as unknown as Record<string, number>)[k] = v;
    row.d = d;
    await this.saveLockout(row, rec);
  }

  /** b75 (audit AL-1 / AL-2): a lock made before b75 gets both rows the new way (the
   *  wrong-in-a-row count carried over when its old MAC verifies), then lo: 2 */
  private async upgradeLockout(rec: AppLockRecord, st: LockoutState): Promise<void> {
    try {
      const old = await this.readWrongRow(rec);
      const n = typeof old === 'object' ? old.n : 0;
      const rec2: AppLockRecord = { ...rec, lo: 2 };
      await this.saveLockout(st, rec2);
      await this.setWrongInARow(n, rec2);
      if ((await this.storage.set(APPLOCK_KEY, JSON.stringify(rec2))) === false) throw new AppLockStorageError();
    } catch { /* tried again at the next read */ }
  }

  private async readLockout(raw: string | null): Promise<LockoutState> {
    if (!raw) {
      // b63 review (I3-4): an empty counter doesn't end a lockout this process is enforcing
      const mono = monoLockUntil.get(this.storage);
      const left = mono === undefined ? 0 : mono - monoNow();
      if (left > 0) return { fails: 0, stage: 1, lockedUntil: Date.now() + left };
      monoLockUntil.delete(this.storage);
      return { ...EMPTY_LOCKOUT };
    }
    try {
      const st = JSON.parse(raw) as LockoutState;
      const fails = Number(st.fails), stage = Number(st.stage);
      let lockedUntil = Number(st.lockedUntil);
      let lockedAt = st.lockedAt === undefined ? undefined : Number(st.lockedAt);
      if (![fails, stage, lockedUntil, lockedAt ?? 0].every((x) => Number.isFinite(x) && x >= 0)) throw new Error('shape');
      let upAt = st.upAt === undefined ? undefined : Number(st.upAt);
      const windowMs = st.windowMs === undefined ? undefined : Number(st.windowMs);
      // b75 (audit V4): the duress budget belongs to this window; it is carried through
      const d = Math.max(0, Number(st.d) || 0);
      const duress = d > 0 ? { d } : {};
      // Batch D (D-11): a clock set back past the lockout's start restarts the window.
      // b71 (review): the boot-clock anchor is kept. Saved without it, setting the
      // clock back and then forward again ended a 60-minute lockout in seconds.
      if (lockedAt !== undefined && Date.now() < lockedAt) {
        lockedAt = Date.now();
        lockedUntil = lockedAt + lockoutMsForStage(stage);
        await this.saveLockout({ fails, stage, lockedUntil, lockedAt, ...(upAt !== undefined && windowMs !== undefined ? { upAt, windowMs } : {}) }).catch(() => undefined);
      }
      // Batch D (D-11): while the app runs, the monotonic clock decides too
      const mono = monoLockUntil.get(this.storage);
      if (mono !== undefined) {
        const left = mono - monoNow();
        // only when the wall clock says the window is over (a clock set forward)
        if (left > 0 && lockedUntil <= Date.now()) lockedUntil = Date.now() + left;
        else monoLockUntil.delete(this.storage);
      }
      // b70 (VAR-14): the boot clock decides as well, so a clock set forward
      // (even across an app restart) can't end the window early
      const up = uptimeMs();
      if (upAt !== undefined && windowMs !== undefined && Number.isFinite(upAt) && Number.isFinite(windowMs) && up !== null) {
        if (up < upAt) {
          // the phone restarted: time can't be measured across it, so the window starts again
          upAt = up;
          lockedAt = Date.now();
          lockedUntil = lockedAt + windowMs;
          await this.saveLockout({ fails, stage, lockedUntil, lockedAt, upAt, windowMs }).catch(() => undefined);
        } else {
          const left = upAt + windowMs - up;
          if (left > 0 && lockedUntil < Date.now() + left) lockedUntil = Date.now() + left;
          if (left <= 0 && lockedUntil <= Date.now()) {
            // over by both clocks: forget the anchor so a later restart doesn't re-lock
            await this.saveLockout({ fails, stage, lockedUntil: 0 }).catch(() => undefined);
            return { fails, stage, lockedUntil: 0 };
          }
        }
        return { fails, stage, lockedUntil, ...(lockedAt !== undefined ? { lockedAt } : {}), upAt, windowMs, ...duress };
      }
      return { fails, stage, lockedUntil, ...(lockedAt !== undefined ? { lockedAt } : {}), ...duress };
    } catch {
      const locked = { fails: 0, stage: 1, lockedUntil: Date.now() + lockoutMsForStage(1) };
      await this.saveLockout(locked).catch(() => undefined);
      return locked;
    }
  }

  private async saveLockout(stIn: LockoutState, recIn?: AppLockRecord | null): Promise<void> {
    const gen = this.wipeGen(); // b75 round 3 (audit DV-3)
    const { m: _old, ...st } = stIn;
    void _old;
    // b71 (audit): MAC'd whenever a lock record exists, so a deleted or edited row shows
    const rec = recIn === undefined ? await this.recordQuiet() : recIn;
    delete (st as LockoutState).e;
    let row: LockoutState = st;
    let epoch = 0;
    if (rec && rec.lo === 2) { epoch = await this.nextEpoch(rec); row = { ...st, e: epoch }; } // b75 (audit AL-2)
    if (rec) { try { row = { ...row, m: await this.lockoutTag(rec, row) }; } catch { /* no MAC key: stored plain */ } }
    // Batch I (V-02): KeychainStorage.set reports a refused write as false
    if ((await this.storage.set(LOCKOUT_KEY, JSON.stringify(row))) === false) throw new AppLockStorageError();
    if (rec && rec.lo === 2) await this.noteEpoch(rec, 'lo', epoch, gen);
  }

  /** one wrong attempt. At MAX_ATTEMPTS the keypad locks: stage escalates
   *  (5 -> 10 -> 20 -> 40 -> 60 min) and the attempt counter resets so the
   *  next window again allows MAX_ATTEMPTS tries. */
  async recordFail(): Promise<LockoutState> {
    const st = await this.lockout();
    const fails = st.fails + 1;
    if (fails < MAX_ATTEMPTS) {
      const next = { fails, stage: st.stage, lockedUntil: st.lockedUntil };
      await this.saveLockout(next);
      return next;
    }
    const stage = st.stage + 1;
    const ms = lockoutMsForStage(stage);
    const up = uptimeMs();
    const next: LockoutState = { fails: 0, stage, lockedUntil: Date.now() + ms, lockedAt: Date.now(), ...(up !== null ? { upAt: up, windowMs: ms } : {}) };
    monoLockUntil.set(this.storage, monoNow() + ms);
    noteStage(this.storage, stage);
    await this.saveLockout(next);
    return next;
  }

  /** successful unlock — counter and escalation reset to zero */
  async clearLockout(): Promise<void> {
    monoLockUntil.delete(this.storage);
    memFails.delete(this.storage);
    memStage.delete(this.storage); // b77n: the real password resets the escalation
    // b71 (audit): a MAC'd lock keeps a (MAC'd) empty counter — a missing one means tampering
    const rec = await this.recordQuiet();
    if (rec && (rec.lo === 1 || rec.lo === 2)) {
      await this.saveLockout({ ...EMPTY_LOCKOUT }, rec).catch(() => undefined);
      return;
    }
    await this.storage.remove(LOCKOUT_KEY);
  }
}
