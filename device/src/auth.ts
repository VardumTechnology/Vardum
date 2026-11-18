/**
 * @veil/device — Base44 account auth (the app account, NOT the Veil identity).
 *
 * Endpoints extracted from the web bundle (index-DYGFL-4a.js):
 *   POST {base}/api/apps/{appId}/auth/login            {email, password, turnstile_token?} -> {access_token, user}
 *   POST {base}/api/apps/{appId}/auth/verify-otp       {email, otp_code}
 *   POST {base}/api/apps/{appId}/auth/resend-otp      {email}
 *   POST {base}/api/apps/{appId}/auth/reset-password-request {email}
 *   POST {base}/api/apps/{appId}/auth/reset-password   {reset_token, new_password}
 *
 * The session token lives ONLY in the secure store (never AsyncStorage/plain
 * files). The 5-attempt server-side lockout (VeilLoginGuard) is enforced by the
 * backend — the client surfaces its lock message verbatim.
 */

import type { VeilStorage } from '../../crypto-core/src/index';
import { sha256 as powSha256 } from '@noble/hashes/sha256';
import { currentWipeGeneration } from './wipe-generation';
import { relayErrorFor, relayErrorText } from './relay-errors';
import { RELAY_JSON_MAX_BYTES } from './relay-json'; // b77s (audit 4 A-01 / A-03); b77t2 (CL-6): read by relayJsonCall
import { fetchProofNonce, proofMessage, type ProofLabel } from './proof-nonce'; // b77t (audit 5 L-15)
// b77t2 (CL-6): the relay client's bounded JSON transport (a cycle with relay.ts, which imports withNetworkPow from
// here: both sides use the other's exports only inside functions, never while the modules load)
import { relayJsonCall, relayJsonXhr, type XhrCtor, type RelayAnswerInfo } from './relay';

/** b73 (audit V-11): find s with SHA-256(prefix + challenge + ":" + s) having `bits`
 *  leading zero bits. Runs in small chunks so the UI keeps drawing (16-22 bits:
 *  about 65 thousand to 4 million hashes). */
/** b74 (audit V-11): puzzles one sign-in solves before it gives up */
export const LOGIN_POW_TRIES = 3;
/** b77m (audit VAR-56): the hardest sign-in puzzle this phone solves. 24 bits is about 16 million hashes
 *  (tens of seconds on a slow phone); the relay asks for 16–22. A relay demanding more (60 bits would never
 *  finish) is refused at once instead of pinning the CPU. */
export const LOGIN_POW_MAX_BITS = 24;
/** b77m (audit VAR-56): bounds on the relay-chosen puzzle strings (the relay sends a short label and a
 *  32-byte hex challenge) */
const LOGIN_POW_MAX_PREFIX = 64;
const LOGIN_POW_MAX_CHALLENGE = 256;
/** b77m (audit VAR-56): thrown when the relay asks for a puzzle outside the bounds above */
export class LoginPowRefusedError extends Error {
  constructor() {
    super('The server asked for a sign-in check this phone will not run. Try again later.');
    this.name = 'LoginPowRefusedError';
    Object.setPrototypeOf(this, LoginPowRefusedError.prototype);
  }
}
/** b77m (audit VAR-56): is this relay-chosen puzzle one this phone will solve? */
export function loginPowAcceptable(prefix: unknown, challenge: unknown, bits: unknown): boolean {
  return typeof prefix === 'string' && prefix.length <= LOGIN_POW_MAX_PREFIX
    && typeof challenge === 'string' && challenge.length > 0 && challenge.length <= LOGIN_POW_MAX_CHALLENGE
    && Number.isInteger(bits) && (bits as number) >= 1 && (bits as number) <= LOGIN_POW_MAX_BITS;
}

/**
 * b77m (owner, carrier NAT): the relay answers a per-NETWORK cap with the same puzzle as sign-in
 * (429 { pow_required, pow_challenge, pow_bits, pow_prefix }). `send(extra)` makes the call ({} first, then
 * { pow_challenge, pow_solution }); a puzzle answer is solved (within loginPowAcceptable: at most
 * LOGIN_POW_MAX_BITS) and the call repeated, up to LOGIN_POW_TRIES puzzles. Anything else is rethrown.
 */
export async function withNetworkPow<T>(send: (extra: Record<string, string>) => Promise<T>): Promise<T> {
  let extra: Record<string, string> = {};
  for (let tries = 0; ; tries++) {
    try {
      return await send(extra);
    } catch (e) {
      const d = (e as { status?: number; data?: { pow_required?: boolean; pow_challenge?: string; pow_bits?: number; pow_prefix?: string } }).data;
      if (!d?.pow_required || !d.pow_challenge || !d.pow_bits || tries >= LOGIN_POW_TRIES) throw e;
      const prefix = d.pow_prefix ?? 'vardum-login-pow-v1:';
      if (!loginPowAcceptable(prefix, d.pow_challenge, d.pow_bits)) throw e;
      extra = { pow_challenge: d.pow_challenge, pow_solution: await solveLoginPow(prefix, d.pow_challenge, d.pow_bits) };
    }
  }
}

export async function solveLoginPow(prefix: string, challenge: string, bits: number): Promise<string> {
  if (!loginPowAcceptable(prefix, challenge, bits)) throw new LoginPowRefusedError(); // b77m (audit VAR-56)
  const enc = new TextEncoder();
  const head = prefix + challenge + ':';
  const ok = (h: Uint8Array): boolean => {
    let need = bits;
    for (let i = 0; need > 0; i++) {
      if (need >= 8) { if (h[i] !== 0) return false; need -= 8; } else { return (h[i] >> (8 - need)) === 0; }
    }
    return true;
  };
  for (let n = 0; n < 1e9; n++) {
    if (ok(powSha256(enc.encode(head + n)))) return String(n);
    if (n % 4000 === 3999) await new Promise((res) => setTimeout(res, 0));
  }
  throw new Error('Could not finish the sign-in check. Try again.');
}

/** b197-r8n (K-26 fix): the auth platform's login response stopped including a
 *  user `id` (observed live Oct 14: two fresh logins, both id-less — the list
 *  machinery broke for every fresh login). Derive a STABLE per-user id from
 *  the email (the JWT's sub is the same identity) — robust to whatever shape
 *  the auth platform returns, now and in future response changes. */
async function normalizeAuthUser(user: unknown, email: string): Promise<{ id: string } & Record<string, unknown>> {
  // (b77m: used only for a login record stored by an older build — every fresh sign-in takes the relay's id,
  // relayAuthUser below)
  const u = (user && typeof user === 'object') ? { ...(user as Record<string, unknown>) } : {};
  if (!u.id) {
    const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode('veil-user:' + String(email).toLowerCase()));
    u.id = 'u_' + [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('').slice(0, 24);
  }
  return u as { id: string } & Record<string, unknown>;
}

/** b77m (audit VAR-57): the shape of an account id this phone takes from the relay */
export const AUTH_USER_ID_RE = /^[A-Za-z0-9_-]{1,128}$/;

/** b77m (audit VAR-57): the account a sign-in / sign-up reply names. The relay always returns `user.id`
 *  (relay/main.ts login, register, provision); it is signed into proofs, so it is never made up here from the
 *  email or a token's unverified `sub` — a reply without a well-formed id is an error. */
export function relayAuthUser(user: unknown): { id: string } & Record<string, unknown> {
  const u = (user && typeof user === 'object') ? { ...(user as Record<string, unknown>) } : {};
  if (typeof u.id !== 'string' || !AUTH_USER_ID_RE.test(u.id)) throw new Error('The server’s sign-in reply did not name the account. Try again.');
  return u as { id: string } & Record<string, unknown>;
}

export const AUTH_SESSION_KEY = 'veil_auth_session';
/** b77 rollout (5 Nov 2026): every login this build saves is marked with the relay it belongs to. A saved login
 *  WITHOUT this mark was saved by an older build, on the older relay (src/relay-home.ts). */
export const AUTH_RELAY_HOME_KEY = 'veil_relay_home_v1';
/** b76 (registration lock): {email, key} — the owning phone's device key and the label it is for.
 *  A veil_* key, so a full wipe (duress, "erase this phone") removes it with the login.
 *  b76r1 (audit D2): Nothing-at-Rest's every-departure wipe KEEPS it, with the login it belongs to
 *  (container-key.ts CK_KEPT_KEYS, App.tsx naRWipeStorage): without it the owning phone needed the
 *  PIN at its next sign-in, and a sign-in move left the user at "PIN required" on their own phone.
 *  b76r2 (audit DEV-R2-03): what that costs. The kept key sits next to the kept login, so someone
 *  who copies this phone's data and has the 24 words can sign in on another phone without the PIN
 *  (the old rationale here did not say so). The relay now replaces the key at every sign-in made
 *  with it (`reglock_device_next`, see login), so a copy works once at most: after this phone's next
 *  sign-in it is stale, and if the copy is used first, this phone's own key stops working, its next
 *  sign-in asks for the PIN and Settings says the key no longer works. It does not stop one use of
 *  a fresh copy. */
export const REGLOCK_DEVICE_STORAGE = 'veil_reglock_device';
let authMigratedThisLaunch = false;

export interface AuthUser {
  id: string;
  email?: string;
  [k: string]: unknown;
}

export interface AuthSession {
  access_token: string;
  user: AuthUser;
  savedAt: string;
}

/** b77k (IP77-4): a session object that can actually authorize a call (a non-empty string token) */
export function hasUsableToken(s: unknown): s is AuthSession {
  const t = (s as { access_token?: unknown } | null | undefined)?.access_token;
  return !!s && typeof s === 'object' && typeof t === 'string' && t.length > 0;
}

export interface AuthFetchConfig {
  baseUrl: string;
  appId: string;
  fetchImpl?: typeof fetch;
  /** b77t2 (CL-6): as RelayConfig.xhrImpl - the XMLHttpRequest the auth calls go through where fetch doesn't stream
   *  (React Native), so an answer is bounded at its headers and while it arrives (xhrJsonBounded) instead of after
   *  RN's fetch has buffered all of it. Unset = the platform's, only when `fetchImpl` is not injected; null = never.
   *  The app passes relayTransport().xhrImpl. */
  xhrImpl?: XhrCtor | null;
  /** b77t2 (CL-6): as RelayConfig.onAnswer - sees every auth answer on either transport (the relay clock notes
   *  signed-in answers; the XMLHttpRequest path never touches `fetchImpl`). The app passes relayTransport().onAnswer. */
  onAnswer?: (a: RelayAnswerInfo) => void;
  /** b77t2 (CL-6): as RelayConfig.fetchStreams (unset = detected) */
  fetchStreams?: boolean;
  /** b77t2 (CL-6): how long a sign-in / sign-up / proof-nonce call may take, answer included (AUTH_TIMEOUT_MS) */
  timeoutMs?: number;
}

/** b77t2 (CL-6): a sign-in, sign-up or proof-nonce call is abandoned after this (ms): the relay's hashing queue waits
 *  at most 10 s, a 600k-round hash takes about a second */
export const AUTH_TIMEOUT_MS = 60_000;
/** b77t2 (CL-6): an account delete runs the whole cascade before it answers, so it gets longer */
export const AUTH_DELETE_TIMEOUT_MS = 120_000;
/** b77t2 (CL-6): a sign-out's revoke (best effort) */
const AUTH_LOGOUT_TIMEOUT_MS = 5_000;

export class Base44Auth {
  private cfg: AuthFetchConfig;
  private storage: VeilStorage;
  /** b70 (audit VAR-12): a login held only in memory (duress cleanup), never stored */
  private memory: AuthSession | null = null;
  /** b77k2 (IP77-4): `memory` holds a login whose stored write was refused (see persist) */
  private memoryUnsaved = false;

  /** b77k2 (re-review L1): every wipe drops a login that is only in memory because its write was
   *  refused (the wipes' own cleanup copy, holdInMemory, is not that) */
  forgetUnsaved(): AuthSession | null {
    if (!this.memoryUnsaved) return null;
    const s = this.memory;
    this.memory = null;
    this.memoryUnsaved = false;
    // b77k2 (review L-1): not lost — kept aside (never used for a call) for the wipe's cleanup to
    // revoke: takeOrphan (the duress / wipe-device capture holds and logs it out) or revokeOrphan
    if (s) this.orphan = s;
    return s;
  }
  /** b77k2 (review L-1): a login a wipe took out of memory, for that wipe's cleanup only */
  private orphan: AuthSession | null = null;
  takeOrphan(): AuthSession | null { const s = this.orphan; this.orphan = null; return s; }
  /** b77k2 (review L-1): a wipe with no remote cleanup (Nothing-at-Rest's departure): revoke the
   *  orphaned login on the server, best-effort (5 s), never awaited by the wipe */
  revokeOrphan(): Promise<void> { const s = this.takeOrphan(); return s ? this.revoke(s) : Promise.resolve(); }
  /** b77k2 (review L-1): POST logout with that login's bearer, bounded at 5 s; never throws */
  private async revoke(session: AuthSession): Promise<void> {
    try {
      // b77s (audit 4 A-01): bearer only, never cookies; b77t2 (CL-6): bounded (5 s, the answer's byte limit)
      await this.jsonCall('auth/logout', { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${session.access_token}` } }, 'auth/logout', AUTH_LOGOUT_TIMEOUT_MS);
    } catch { /* best-effort */ }
  }

  /** b70 (VAR-12): keep using this login after its stored copy is erased */
  holdInMemory(session: AuthSession | null): void {
    this.memory = session;
    this.memoryUnsaved = false;
  }

  constructor(cfg: AuthFetchConfig, storage: VeilStorage) {
    this.cfg = cfg;
    this.storage = storage;
  }

  /**
   * b77t2 (CL-6): every auth call goes through the relay client's bounded transport (relayJsonCall): a timeout, no
   * cookies (credentials 'omit' / withCredentials false), the answer read within RELAY_JSON_MAX_BYTES - on React
   * Native over XMLHttpRequest (relayJsonXhr), bounded at the headers and while the body arrives, because RN's fetch
   * hands over a response only after buffering all of it (readJsonBounded alone ran too late: the L-27 class) - and
   * `onAnswer` sees each answer. These calls used plain fetch with no timeout.
   */
  private jsonCall(path: string, init: RequestInit, fn: string, ms: number): Promise<{ res: Response; data: unknown }> {
    return relayJsonCall(this.cfg.fetchImpl ?? fetch, `${this.cfg.baseUrl}/api/apps/${this.cfg.appId}/${path}`, init, fn, ms, RELAY_JSON_MAX_BYTES, relayJsonXhr(this.cfg), this.cfg.onAnswer);
  }

  private async post(path: string, body: Record<string, unknown>): Promise<{ data: any; status: number }> {
    // b77s (audit 4 A-01 / A-03): no cookies, a bounded answer; b77t2 (CL-6): and a timeout, bounded before RN buffers it
    const { res, data } = await this.jsonCall(`auth/${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    }, `auth/${path}`, this.cfg.timeoutMs ?? AUTH_TIMEOUT_MS);
    if (!res.ok) {
      // b73 (audit V-11): the body rides along (a login may ask for a proof-of-work)
      // b77m (audit VAR-20): the message is app-written (relay-errors.ts); the relay's words stay on relayMessage
      throw relayErrorFor(res.status, data);
    }
    return { data, status: res.status };
  }

/** b198 ANONYMOUS SIGNUP: the relay creates the account in ONE step — the email
 *  is a self-declared label (real or invented, never verified, never contacted);
 *  the Base44-era 6-digit OTP flow is RETIRED. The 24-word phrase remains the
 *  only recovery path. Returns the live session (register → token, like login). */
  async signup(email: string, password: string): Promise<AuthSession> {
    const gen = currentWipeGeneration(); // b77k2 (re-review L1)
    // b77m (owner, carrier NAT): past the network's sign-up cap the relay asks for a puzzle (withNetworkPow)
    const r = await withNetworkPow((extra) => this.post('register', { email, password, ...extra }));
    const session: AuthSession = {
      access_token: r.data.access_token,
      user: relayAuthUser(r.data?.user), // b77m (audit VAR-57)
      savedAt: new Date().toISOString(),
    };
    await this.persist(session, gen);
    return session;
  }

  /** b76 (registration lock): this phone's device key for the account signing in with `email`,
   *  or null. Kept under that label only, so a sign-in to any other account (a decoy, a second
   *  account) never carries it — it would link the two accounts on the relay. */
  async regLockDevice(email: string): Promise<string | null> {
    try {
      const raw = await this.storage.get(REGLOCK_DEVICE_STORAGE);
      const v = raw ? JSON.parse(raw) as { email?: unknown; key?: unknown } : null;
      return v && typeof v.key === 'string' && typeof v.email === 'string' && v.email === String(email).toLowerCase().trim() ? v.key : null;
    } catch { return null; }
  }

  /** b76 (registration lock): keep the device key the relay just issued to this phone.
   *  b76r1 (audit I5): a refused write throws (it used to be ignored, and Settings then said the
   *  lock was on while this phone, holding no key, would itself need the PIN). */
  async saveRegLockDevice(email: string, key: string): Promise<void> {
    const ok = await this.storage.set(REGLOCK_DEVICE_STORAGE, JSON.stringify({ email: String(email).toLowerCase().trim(), key }));
    if (ok === false) throw new Error('This phone could not save its registration lock key.');
  }

  async forgetRegLockDevice(): Promise<void> {
    await this.storage.remove(REGLOCK_DEVICE_STORAGE).catch(() => undefined);
  }

  /** b76 (registration lock): a rebind moves the account to a new label — the device key follows it
   *  (only when it was this account's), so the sign-in right after the rebind needs no PIN */
  async relabelRegLockDevice(fromEmail: string, toEmail: string): Promise<void> {
    const key = await this.regLockDevice(fromEmail);
    // b76r1 (audit I5): a refused save doesn't stop the rebind's sign-in; without the key it is
    // answered "PIN required" and the app asks for the PIN, which is the honest outcome
    if (key) await this.saveRegLockDevice(toEmail, key).catch((e) => console.warn('[veil-reglock] device key not moved:', String((e as Error)?.message ?? e)));
  }

  /** b76 (registration lock): `regLockPin` = the PIN proof (dev/reglock.ts:regLockPinAuth) when the
   *  relay asked for it (423, see regLockInfo). This phone's device key for the label rides along
   *  when it has one. */
  async login(email: string, password: string, opts: { regLockPin?: string } = {}): Promise<AuthSession> {
    const gen = currentWipeGeneration(); // b77k2 (re-review L1)
    let r: { data: any; status: number } | null = null;
    const regLock: Record<string, string> = {};
    const dev = await this.regLockDevice(email);
    if (dev) regLock.reglock_device = dev;
    if (opts.regLockPin) regLock.reglock_pin = opts.regLockPin;
    // b73 (audit V-11): past the account's allowance the relay asks for a small
    // proof-of-work instead of locking the account; solve it and retry.
    // b74 (audit V-11): up to LOGIN_POW_TRIES puzzles — while someone else keeps guessing,
    // the puzzle the relay wants can grow (or a relay restart voids it) between the answer
    // and the retry, and one retry then left the owner with an error despite the right password
    let extra: Record<string, string> = { ...regLock }; // b76 (registration lock): rides on every try
    for (let tries = 0; !r; tries++) {
      try {
        r = await this.post('login', { email, password, ...extra });
      } catch (e) {
        const d = (e as { data?: { pow_required?: boolean; pow_challenge?: string; pow_bits?: number; pow_prefix?: string } }).data;
        if (!d?.pow_required || !d.pow_challenge || !d.pow_bits || tries >= LOGIN_POW_TRIES) throw e;
        // b77m (audit VAR-56): a puzzle past LOGIN_POW_MAX_BITS (or malformed) is refused, never attempted
        const prefix = d.pow_prefix ?? 'vardum-login-pow-v1:';
        if (!loginPowAcceptable(prefix, d.pow_challenge, d.pow_bits)) throw new LoginPowRefusedError();
        const sol = await solveLoginPow(prefix, d.pow_challenge, d.pow_bits);
        extra = { pow_challenge: d.pow_challenge, pow_solution: sol };
        Object.assign(extra, regLock);
      }
    }
    const session: AuthSession = {
      access_token: r.data.access_token,
      user: relayAuthUser(r.data?.user), // b77m (audit VAR-57)
      savedAt: new Date().toISOString(),
    };
    await this.persist(session, gen);
    // b76 (registration lock): the PIN was proven — this phone is now the account's owning phone
    const d = r.data as { reglock?: { device_key?: unknown; reglock_device_next?: unknown }; reglock_device_next?: unknown } | null;
    const issued = d?.reglock?.device_key;
    // b76r2 (audit DEV-R2-03): a sign-in made WITH the device key gets the next key back
    // (`reglock_device_next`), and the relay stops taking the one just used. It replaces the stored
    // key, so a copy of the old one (e.g. lifted from the record Nothing-at-Rest keeps) is stale
    // after this phone's next sign-in, and a copy used first makes this phone's own key stale
    // (Settings then says so). Taken only when this phone sent a key; an older relay sends no field
    // and the stored key stays as it was.
    const next = d?.reglock_device_next ?? d?.reglock?.reglock_device_next;
    const okKey = (v: unknown): v is string => typeof v === 'string' && v.length > 0 && v.length <= 512;
    const key = okKey(issued) ? issued : (dev && okKey(next) ? next : null);
    // b76r1 (audit I5): a refused save leaves the sign-in itself standing (the user is signed in);
    // this phone then isn't the owning phone and its next sign-in asks for the PIN again
    if (key) await this.saveRegLockDevice(email, key).catch((e) => console.warn('[veil-reglock] device key not saved:', String((e as Error)?.message ?? e)));
    return session;
  }

  async verifyOtp(email: string, otpCode: string): Promise<AuthSession> {
    const gen = currentWipeGeneration(); // b77k2 (re-review L1)
    const r = await this.post('verify-otp', { email, otp_code: otpCode });
    const session: AuthSession = { access_token: r.data.access_token, user: relayAuthUser(r.data?.user), savedAt: new Date().toISOString() }; // b77m (audit VAR-57)
    await this.persist(session, gen);
    return session;
  }

  async resendOtp(email: string): Promise<void> {
    await this.post('resend-otp', { email });
  }

  async requestPasswordReset(email: string): Promise<void> {
    await this.post('reset-password-request', { email });
  }

  async resetPassword(resetToken: string, newPassword: string): Promise<void> {
    await this.post('reset-password', { reset_token: resetToken, new_password: newPassword });
  }

  /**
   * b77k2 (IP77-4, iPhone: duress wipe, then Restore — the first tap failed, the second worked): the
   * store can refuse the write (a wipe's write freeze, or its post-wipe barrier until a fresh start),
   * and the refusal was ignored, so a sign-in that succeeded left no token and the restore then
   * registered the identity unauthenticated (401, hadToken=false). A refused write now keeps the login
   * in memory for this run (it is written again as soon as the store takes it: currentSession). Every
   * path that ends a login still drops it (logout; the wipes' cleanup holds its own copy and logs out).
   */
  private async persist(session: AuthSession, gen?: number): Promise<void> {
    const ok = await this.storage.set(AUTH_SESSION_KEY, JSON.stringify(session));
    // b77k2 (re-review L1): a sign-in that was in flight when a wipe began (duress, sign-out,
    // self-destruct) is never kept: it would outlive the wipe's logout (VAR-12)
    if (ok === false && gen !== undefined && gen !== currentWipeGeneration()) {
      console.warn('[veil-auth] a sign-in that finished after a wipe began was dropped');
      void this.revoke(session); // b77k2 (review L-1): and revoked on the server, best-effort
      return;
    }
    if (ok === false) {
      console.warn('[veil-auth] the sign-in could not be stored yet; kept in memory for now');
      this.memory = session;
      this.memoryUnsaved = true;
    } else if (this.memoryUnsaved) {
      this.memory = null;
      this.memoryUnsaved = false;
    }
    // b77 rollout: this login belongs to this build's relay (a stored-but-refused write is retried by the next save)
    if (ok !== false) await this.storage.set(AUTH_RELAY_HOME_KEY, this.cfg.baseUrl).catch(() => undefined);
  }

  async currentSession(): Promise<AuthSession | null> {
    // b77k (IP77-4, iPhone battery): a login with no usable token is no login. After a duress wipe
    // the first restore skipped the phrase sign-in on such a "session" and registered the identity
    // unauthenticated (401, hadToken=false); now it reads as none and the sign-in runs.
    if (this.memory) {
      if (hasUsableToken(this.memory)) {
        // b77k2 (IP77-4): a login kept in memory because its write was refused: store it once the store takes it
        if (this.memoryUnsaved) {
          const held = this.memory;
          void this.storage.set(AUTH_SESSION_KEY, JSON.stringify(held)).then((ok) => {
            if (ok !== false && this.memory === held) { this.memory = null; this.memoryUnsaved = false; }
          }, () => undefined);
        }
        return this.memory;
      }
      this.memory = null;
      this.memoryUnsaved = false;
    }
    const raw = await this.storage.get(AUTH_SESSION_KEY);
    if (!raw) return null;
    // b81 ONE-TIME MIGRATION: existing installs already have this keychain
    // item stored under the OLD, stricter WHEN_UNLOCKED accessible tier —
    // iOS does not necessarily upgrade that attribute on a plain re-set, so
    // without this the fix in secure-store.rn.ts would only take effect on
    // the NEXT fresh login. Since a get() only ever succeeds while the
    // device is unlocked anyway, this is exactly the right moment to force
    // a delete+recreate under the new AFTER_FIRST_UNLOCK tier — once per
    // process launch is enough; non-fatal if it fails (session still works,
    // just not yet upgraded for background reads).
    if (!authMigratedThisLaunch) {
      authMigratedThisLaunch = true;
      this.storage.set(AUTH_SESSION_KEY, raw).catch((e) =>
        console.log('[veil-auth] b81 keychain-tier migration skipped:', String((e as Error)?.message ?? e)));
    }
    try {
      const session = JSON.parse(raw) as AuthSession;
      // b197-r8o (K-26 root fix): the auth platform's login STOPPED returning a
      // user object AT ALL (verified live: the stored session is
      // {access_token, savedAt} — no user field). The previous gate
      // (`session.user && …`) skipped exactly these sessions, so the id-less
      // state persisted through every reload. Now: when the user object is
      // missing or id-less, the identity is derived from the JWT's `sub` (the
      // email — the platform still signs it into the token) and the user object
      // is rebuilt + persisted. No re-login required.
      if (session && session.access_token && !session.user?.id) {
        let email = String(session.user?.email || (session as any).email || '');
        try {
          const payload = JSON.parse(atob(session.access_token.split('.')[1]));
          if (payload?.sub) email = String(payload.sub);
        } catch { /* token not a decodable JWT — fall back to the stored email */ }
        session.user = await normalizeAuthUser(session.user, email);
        await this.persist(session).catch(() => undefined);
      }
      return hasUsableToken(session) ? session : null; // b77k (IP77-4)
    } catch { return null; }
  }

  /** Token provider for VeilRelay — drop-in: relay cfg getToken: auth.getToken. */
  async getToken(): Promise<string | null> {
    return (await this.currentSession())?.access_token ?? null;
  }

  /** Sign-out: server-side revocation + local wipe (tokens, session; NOT the keyvault). */
  /**
   * Permanently deletes everything this account owns (web parity: the
   * veilAccountDelete backend function, invoked with the account's client_ids).
   * The caller is responsible for wiping device data after this succeeds.
   */
  async deleteAccount(clientIds: string[] = [], signer?: { veilId: string; sign: (msgB64: string) => Promise<string> }): Promise<Record<string, unknown>> {
    const token = await this.getToken();
    // b70 (re-review 5): the account's identity signs the deletion
    let proof: Record<string, unknown> | undefined;
    if (signer) {
      // b77t (audit 5 L-15): a single-use nonce from the relay is signed in (none from an older relay: the old form)
      const nonce = await this.proofNonce('vardum-delete-v1', token);
      const ts = Date.now();
      const uid = (await this.currentSession())?.user?.id ?? '';
      proof = { veil_id: signer.veilId, ts, ...(nonce ? { nonce } : {}), sig: await signer.sign(btoa(proofMessage('vardum-delete-v1', uid, ts, nonce))) };
    }
    // b77f2 (audit F-3): a transport failure (the request may have reached the relay and committed,
    // with only the answer lost) is marked, and an HTTP refusal carries its status, so the caller
    // can tell "may have committed" from a definite refusal (deleteMayHaveCommitted)
    // b77s (audit 4 A-01 / A-03): no cookies, a bounded answer. b77t2 (CL-6): and a timeout (AUTH_DELETE_TIMEOUT_MS),
    // on XMLHttpRequest under RN; a timeout or an oversized answer is a transport failure too (the request may have
    // reached the relay and committed)
    let res: Response;
    let data: unknown;
    try {
      ({ res, data } = await this.jsonCall('functions/veilAccountDelete', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
        body: JSON.stringify({ client_ids: clientIds, ...(proof ? { proof } : {}) }),
      }, 'veilAccountDelete', AUTH_DELETE_TIMEOUT_MS));
    } catch (e) {
      const err = e instanceof Error ? e : new Error(String(e));
      throw Object.assign(err, { deleteTransportFailure: true });
    }
    // b77i (I-1): done = the relay's 200, or its 410 "account deleted" (a retry after a delete that
    // committed with the answer lost). Every other answer throws with its status, as before.
    if (!deleteAnswerDone(res.status, data)) {
      // b77m (audit VAR-20): app-written text only (a known relay message or the status sentence)
      const t = relayErrorText(res.status, data);
      throw Object.assign(new Error(data && typeof data === 'object' ? t.message : 'Vardum could not reach the relay — nothing was deleted. Try again in a moment.'), { status: res.status, relayMessage: t.relayMessage });
    }
    if (res.status === 410) return { already_deleted: true };
    return (data as { data?: Record<string, unknown> } | null)?.data ?? {};
  }

  /** b77t (audit 5 L-15): a proof nonce for `label` (veilProofNonce), or null (an older relay, or no answer) */
  private async proofNonce(label: ProofLabel, token: string | null): Promise<string | null> {
    if (!token) return null;
    return fetchProofNonce({
      invoke: async (fn, payload) => {
        // b77t2 (CL-6): bounded like every auth call
        const { res, data } = await this.jsonCall(`functions/${fn}`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
          body: JSON.stringify(payload),
        }, fn, this.cfg.timeoutMs ?? AUTH_TIMEOUT_MS);
        if (!res.ok) throw Object.assign(new Error('no nonce'), { status: res.status });
        return { data, status: res.status };
      },
    }, label);
  }

  /**
   * b77t (audit 5 L-6): the relay rotated this account's sign-in (accountSignOutOthers / accountChangePassword revoke
   * EVERY token, the caller's too, and answer with a new one): the new token replaces the stored one, keeping the
   * rest of the session. Refused for anything that isn't a plausible token, or with no current session.
   */
  async replaceToken(token: string): Promise<void> {
    if (typeof token !== 'string' || !/^[0-9a-f]{32,128}$/.test(token)) throw new Error('The server sent an invalid sign-in token.');
    const session = await this.currentSession();
    if (!session) throw new Error('Not signed in.');
    await this.persist({ ...session, access_token: token, savedAt: new Date().toISOString() });
  }

  async logout(): Promise<void> {
    const session = await this.currentSession();
    // b70 (re-review): the login leaves memory and storage FIRST, so an offline
    // revoke can't keep it usable; the revoke itself gets 5 seconds
    this.memory = null;
    this.memoryUnsaved = false;
    await this.storage.remove(AUTH_SESSION_KEY);
    await this.forgetRegLockDevice(); // b76 (registration lock): a signed-out phone is no longer the owning phone
    try {
      if (session) {
        // b77s (audit 4 A-01): bearer only, never cookies; b77t2 (CL-6): bounded (5 s, the answer's byte limit)
        await this.jsonCall('auth/logout', { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${session.access_token}` } }, 'auth/logout', AUTH_LOGOUT_TIMEOUT_MS);
      }
    } catch {
      /* offline sign-out still clears locally */
    }
  }
}

/**
 * b77f2 (audit F-3): may a failed `deleteAccount` have deleted the account anyway? Yes for a
 * transport failure or timeout (the request may have been committed with the answer lost) and for
 * a 500 / 504 (and any other 5xx); no for a definite 4xx refusal, and no for a failure before the
 * request was sent (no marker, no status). Account delete schedules the mailbox ends whenever
 * this is true.
 * b77g (G-3): no for a 502 or 503 either — the proxy in front of the relay, or the relay itself,
 * is down, so the request never reached the delete.
 */
export function deleteMayHaveCommitted(e: unknown): boolean {
  const x = (e && typeof e === 'object' ? e : {}) as { deleteTransportFailure?: unknown; status?: unknown };
  if (x.deleteTransportFailure === true) return true;
  const s = Number(x.status);
  if (!Number.isFinite(s) || s <= 0) return false;
  if (s === 502 || s === 503) return false;
  return !(s >= 400 && s < 500);
}

/** b77g (G-3): shown when an account delete failed in a way that may have committed.
 *  b77h: worded for both cases — the answer was lost (transport failure, timeout) or the relay
 *  answered with a server error (500 / 504); "the relay's answer did not arrive" was wrong for the
 *  second */
export const DELETE_UNCERTAIN_ENDING = 'Vardum could not confirm whether your account was deleted: the connection dropped or the relay reported an error before confirming. To be safe, your chats are being ended. Your data on this phone is still here; try Delete account again in a moment.';
export const DELETE_UNCERTAIN = 'Vardum could not confirm whether your account was deleted: the connection dropped or the relay reported an error before confirming. Your data on this phone is still here; try Delete account again in a moment.';

/**
 * b77i (I-1): is the relay's answer to an account delete "the account is deleted"? Only a 200, or a
 * 410 whose body says `account_deleted: true` (the relay's answer to a retry once the account is
 * gone). b77h counted a retry's 401 (or a 404 "Account not found") as deleted after an uncertain
 * delete, but the relay refused every token for 10 minutes once a delete had STARTED, finished or
 * not, so a delete interrupted half-way wiped the phone while the account was still partly on the
 * relay. Now the relay lets the account's own retry through and finishes the cascade (200), and a
 * 401 is always a refusal. Pure; never throws.
 */
export function deleteAnswerDone(status: number, data: unknown): boolean {
  if (status === 200) return !!data && typeof data === 'object' && (data as { ok?: unknown }).ok === true; // b77j (review I-1): the relay's own answer, not any 200
  return status === 410 && !!data && typeof data === 'object' && (data as { account_deleted?: unknown }).account_deleted === true;
}

/** b77g (G-3): an account delete whose result is uncertain (deleteMayHaveCommitted). It never says
 *  "nothing was deleted"; `chatsEnding` says the chats' mailbox ends were scheduled. */
export class DeleteUncertainError extends Error {
  readonly chatsEnding: boolean;
  constructor(chatsEnding: boolean) {
    super(chatsEnding ? DELETE_UNCERTAIN_ENDING : DELETE_UNCERTAIN);
    this.name = 'DeleteUncertainError';
    this.chatsEnding = chatsEnding;
  }
}
