/**
 * @veil/device — b76 (registration lock): an opt-in PIN that restoring the account on a NEW phone
 * also needs, while the lock is active. Relay side: `veilRegLock` and the sign-in / bind gate
 * (relay/main.ts, spec §12.17).
 *
 * Without it, the 24 words alone sign in to the account on any phone (the owner's phone then
 * shares it with whoever did). With it, a phone other than the owning phone must also show a
 * proof of the PIN, until the lock lapses: 7 days after the account last checked in (any
 * signed-in request from one of its phones renews it), so someone who lost their only phone
 * is not locked out for ever.
 *
 * The PIN proof (never the PIN) is what the relay sees:
 *   salt     = HMAC-SHA256(key = IK seed, "vardum-reglock-salt-v1")
 *   k        = PBKDF2-SHA256(NFKC(trim(PIN)), salt, 600 000 rounds, 32 bytes)
 *   pin_auth = HMAC-SHA256(k, "vardum-reglock-auth-v1")              (base64, 32 bytes)
 * The relay stores only PBKDF2-600k(pin_auth) under a salt of its own. Because the salt comes from
 * the identity seed — which only the 24 words (or this phone) hold — neither the relay nor a copy
 * of its database can test PIN guesses offline without ALSO the words. Someone holding the words
 * and a copy of the database can (each guess costs 2 x 600k PBKDF2): a short PIN then falls
 * quickly, which is why the app asks for at least REGLOCK_PIN_MIN characters and suggests a few
 * words. Against someone who must ask the relay (the usual case: a thief with the words), the
 * relay's attempt limits apply: 10 wrong PINs in all, with waits growing after the second.
 * There is no secure hardware behind this (Signal puts the equivalent in SGX); spec §8.2.
 *
 * The owning phone keeps a device key (REGLOCK_DEVICE_STORAGE, under its account label only) that
 * lets its own sign-ins through without the PIN (dev/auth.ts sends it; a rebind's sign-in needs it).
 * b76r2 (audit DEV-R2-03): the relay replaces that key at every sign-in made with it
 * (`reglock_device_next` in the login answer, stored by dev/auth.ts in place of the old one), so a
 * copy of it works at most once: whichever phone uses it second is asked for the PIN, and the owning
 * phone's Settings says its key no longer works (regLockNotOwnerText).
 */
import { pbkdf2Sha256Bytes } from './kdf';
import { hmacSha256, fromB64, toB64, utf8, sha256, ikSign } from '../../crypto-core/src/index';
import type { VeilRelay } from './relay';
import { fetchProofNonce, proofMessage } from './proof-nonce'; // b77t (audit 5 L-15)

export const REGLOCK_PIN_MIN = 6;
export const REGLOCK_PIN_MAX = 64;
export const REGLOCK_KDF_ITERATIONS = 600_000;
/** the relay's lapse period (REGLOCK_LAPSE_MS there) — for wording only; the relay decides */
export const REGLOCK_LAPSE_DAYS = 7;

/** the one form of a PIN both phones derive from: Unicode NFKC, outer spaces trimmed */
export function canonicalRegLockPin(pin: string): string {
  return String(pin ?? '').normalize('NFKC').trim();
}

/** Unicode code points in a string (a surrogate pair — an emoji — is one, not two) */
const codePoints = (s: string): number => Array.from(s).length;

/** why a PIN can't be used (null = fine).
 *  b76r1 (audit P-3): lengths are counted in Unicode code points, not UTF-16 units. The minimum
 *  must hold both for the PIN as typed (outer spaces trimmed) and for its NFKC form, so neither
 *  emoji (3 emoji were 6 units) nor a character that NFKC expands (U+FDFA is one character and 18
 *  after NFKC) can stand in for 6 characters. The maximum is counted on the NFKC form (what is
 *  derived from). */
export function regLockPinProblem(pin: string): string | null {
  const p = canonicalRegLockPin(pin);
  const typed = String(pin ?? '').trim();
  if (Math.min(codePoints(p), codePoints(typed)) < REGLOCK_PIN_MIN) return `Use at least ${REGLOCK_PIN_MIN} characters. A few words you will remember is best.`;
  if (codePoints(p) > REGLOCK_PIN_MAX) return `Use at most ${REGLOCK_PIN_MAX} characters.`;
  return null;
}

/** the PIN proof sent to the relay (see the header). `ikSeedB64` is the account's primary identity's seed. */
export async function regLockPinAuth(ikSeedB64: string, pin: string): Promise<string> {
  const p = canonicalRegLockPin(pin);
  if (regLockPinProblem(p)) throw new Error(regLockPinProblem(p) ?? 'Invalid PIN');
  const seed = fromB64(ikSeedB64);
  if (seed.length !== 32) throw new Error('No identity key to set the registration lock with.');
  const salt = await hmacSha256(seed, utf8('vardum-reglock-salt-v1'));
  const k = await pbkdf2Sha256Bytes(p, salt, REGLOCK_KDF_ITERATIONS, 32);
  return toB64(await hmacSha256(k, utf8('vardum-reglock-auth-v1')));
}

/** what the relay said about an active lock (423 reglock_required) */
export interface RegLockInfo {
  /** ms since 1970: when the lock lapses if the account's phones stay silent */
  lapseAt: number;
  attemptsLeft: number;
  /** ms since 1970: the next PIN is taken from then (0 = locked out) */
  retryAt: number;
  wrongPin: boolean;
  lockedOut: boolean;
  retryLater: boolean;
}

/** a relay error that is the registration lock asking for its PIN, or null */
export function regLockInfo(e: unknown): RegLockInfo | null {
  const err = e as { status?: number; data?: Record<string, unknown> } | null;
  const d = err?.data;
  if (!err || err.status !== 423 || !d || d.reglock_required !== true) return null;
  const num = (v: unknown) => (typeof v === 'number' && Number.isFinite(v) ? v : 0);
  return {
    lapseAt: num(d.lapse_at), attemptsLeft: Math.max(0, Math.floor(num(d.attempts_left))), retryAt: num(d.retry_at),
    wrongPin: d.wrong_pin === true, lockedOut: d.locked_out === true || num(d.attempts_left) <= 0, retryLater: d.retry_later === true,
  };
}

/** "on Mon 3 Nov (in about 6 days)" — when an unknown PIN stops mattering */
export function regLockLapseText(lapseAt: number, now = Date.now()): string {
  if (!lapseAt) return 'once the old phone has been offline for ' + REGLOCK_LAPSE_DAYS + ' days';
  const ms = lapseAt - now;
  if (ms <= 0) return 'now';
  const days = Math.round(ms / 86400_000), hours = Math.max(1, Math.ceil(ms / 3600_000));
  const when = new Date(lapseAt).toLocaleDateString(undefined, { weekday: 'short', day: 'numeric', month: 'short' });
  const span = ms >= 36 * 3600_000 ? `about ${days} days` : `about ${hours} hour${hours === 1 ? '' : 's'}`;
  return `on ${when} (in ${span})`;
}

/** the plain explanation the restore screen shows under the PIN box */
export function regLockPromptText(info: RegLockInfo, now = Date.now()): string {
  const lapse = regLockLapseText(info.lapseAt, now);
  if (info.lockedOut) return `Too many wrong PINs. The lock now holds until it lapses: ${lapse}, if the old phone stays offline until then.`;
  const parts: string[] = [];
  if (info.wrongPin) parts.push(`Wrong PIN. ${info.attemptsLeft} ${info.attemptsLeft === 1 ? 'try' : 'tries'} left.`);
  if (info.retryAt > now + 1000) parts.push(`You can try again in ${Math.max(1, Math.ceil((info.retryAt - now) / 60_000))} minute(s).`);
  parts.push(`Don’t know it? The lock lapses ${lapse} if the old phone stays offline until then. Using the old phone keeps the lock on.`);
  return parts.join(' ');
}

export interface RegLockStatus {
  enabled: boolean;
  /** wrong PINs tried since the PIN was set or last entered correctly */
  failedAttempts: number;
  lapseAt: number;
  /** b76r1 (audit D3): whether this phone's device key is still the lock's (true: this is the
   *  owning phone; false: it isn't — another phone restored with the PIN since, or this phone
   *  holds no key). Undefined when the relay doesn't say (an older relay): nothing is claimed. */
  deviceMatches?: boolean;
  /** b76r1 (audit D3): ms since 1970 of the last restore on another phone with the right PIN, or 0 */
  lastPinRestoreAt?: number;
  /** b76r2 (audit DEV-R2-02): ms since 1970 the PIN was last set (turned on or changed), from the
   *  relay's `pin_changed_at`; undefined when the relay doesn't say (an older relay) or never set */
  pinChangedAt?: number;
  /** b76r2: whether this phone sent a device key with the status call (so `deviceMatches: false`
   *  means its key stopped working, not that it never had one) */
  sentDeviceKey?: boolean;
}

/** status (and the owning phone's check-in). b76r1 (audit D3): `deviceKey` = this phone's device
 *  key for the signed-in account (auth.regLockDevice), sent as `reglock_device` so the relay can
 *  say whether it still matches (`device_matches`) and when the PIN last restored the account on
 *  another phone (`last_pin_restore_at`, ISO). Both are optional in the answer. */
export async function regLockStatus(relay: Pick<VeilRelay, 'invoke'>, deviceKey?: string | null): Promise<RegLockStatus> {
  const r = await relay.invoke('veilRegLock', { action: 'status', ...(deviceKey ? { reglock_device: deviceKey } : {}) });
  const d = (r.data ?? {}) as { enabled?: unknown; failed_attempts?: unknown; lapse_at?: unknown; device_matches?: unknown; last_pin_restore_at?: unknown; pin_changed_at?: unknown };
  const out: RegLockStatus = { enabled: d.enabled === true, failedAttempts: Number(d.failed_attempts) || 0, lapseAt: Number(d.lapse_at) || 0 };
  if (out.enabled && typeof d.device_matches === 'boolean') out.deviceMatches = d.device_matches;
  const isoAt = (v: unknown) => { const at = typeof v === 'string' && v ? Date.parse(v) : NaN; return Number.isFinite(at) && at > 0 ? at : 0; };
  if (out.enabled && isoAt(d.last_pin_restore_at)) out.lastPinRestoreAt = isoAt(d.last_pin_restore_at);
  // b76r2 (audit DEV-R2-02): ISO or null; absent from an older relay (then nothing is claimed)
  if (out.enabled && isoAt(d.pin_changed_at)) out.pinChangedAt = isoAt(d.pin_changed_at);
  if (out.enabled && deviceKey && out.deviceMatches !== undefined) out.sentDeviceKey = true;
  return out;
}

/** b76r2 (audit RL-01): when this phone last sent a PIN change whose answer was lost while the relay
 *  saved it (this run only), so Settings doesn't report this phone's own change as another phone's */
let lostOwnSetAt = 0;
const LOST_SET_WINDOW_MS = 10 * 60_000; // the relay's ±10 min on the set timestamp

const whenText = (at: number) => new Date(at).toLocaleString(undefined, { weekday: 'short', day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' });

/** b76r1 (audit D3): the Settings line for a lock this phone no longer holds, or null. A correct PIN
 *  on another phone makes that phone the owning phone and resets the wrong-PIN count, so without
 *  this the owner saw nothing at all. */
export function regLockNotOwnerText(s: RegLockStatus | null | undefined): string | null {
  if (!s?.enabled || s.deviceMatches !== false) return null;
  const changed = s.pinChangedAt ?? 0, restored = s.lastPinRestoreAt ?? 0;
  // b76r2 (audit DEV-R2-02): whichever happened LAST took the lock from this phone. A PIN change by
  // someone holding a signed-in session and the 24 words used to read as the owner's own earlier
  // PIN restore (the change kept that date), or as the neutral line at the end.
  if (changed && changed >= restored) {
    if (lostOwnSetAt && Math.abs(changed - lostOwnSetAt) <= LOST_SET_WINDOW_MS) {
      return `Your new PIN was saved on ${whenText(changed)}, but this phone didn’t get the server’s answer, so it doesn’t hold the lock and would need the PIN too. Change the PIN again to fix this.`;
    }
    return `The registration lock PIN was changed on another phone on ${whenText(changed)}, so this phone no longer holds the lock. If that wasn’t you, someone has your 24 words and a phone signed in to this account. Change the PIN here to take the lock back.`;
  }
  if (restored) {
    return `This phone is no longer the phone that holds the lock — someone restored this account with your PIN on another phone on ${whenText(restored)}. If that wasn’t you, someone has your 24 words and your PIN.`;
  }
  // b76r2 (audit DEV-R2-03): this phone's key stopped working with no PIN restore or change since:
  // another phone signed in with a copy of it (the relay then gave that phone the next key)
  if (s.sentDeviceKey) {
    return 'This phone’s registration lock key no longer works: another phone signed in to this account with it, or this phone could not save the new key it was given. If that wasn’t you, someone has your 24 words and a copy of this phone’s data. Change the PIN here to take the lock back.';
  }
  return 'This phone is not the phone that holds the lock, so restoring on it would need the PIN too.';
}

/** what turning the lock on / off needs from the app */
export interface RegLockDeps {
  relay: Pick<VeilRelay, 'invoke'>;
  auth: { saveRegLockDevice(email: string, key: string): Promise<void>; forgetRegLockDevice(): Promise<void>; regLockDevice?(email: string): Promise<string | null> };
}

/** the hex tag of a PIN proof that the `set` signature names (the relay's own rule) */
export async function regLockPinTag(pinAuth: string): Promise<string> {
  return [...await sha256(utf8('vardum-reglock-pin-tag-v1:' + pinAuth))].map((b) => b.toString(16).padStart(2, '0')).join('');
}

/** turn the lock on, or change its PIN. The primary identity signs; this phone becomes the owning phone. */
export async function regLockSet(
  deps: RegLockDeps,
  identity: { veilId: string; ikSeedB64: string },
  pin: string,
  account: { userId: string; email: string },
): Promise<void> {
  const pinAuth = await regLockPinAuth(identity.ikSeedB64, pin);
  const send = async () => {
    // b77u (audit 6 W2): a relay-issued single-use nonce is signed in (a replayed `set` re-installed an old PIN); an
    // older relay without the label: the old form
    const nonce = await fetchProofNonce(deps.relay, 'vardum-reglock-set-v1');
    const ts = Date.now();
    const tag = await regLockPinTag(pinAuth);
    const sig = await ikSign(identity.ikSeedB64, toB64(utf8(nonce ? `vardum-reglock-set-v1:${account.userId}:${ts}:${tag}:${nonce}` : `vardum-reglock-set-v1:${account.userId}:${ts}:${tag}`)));
    return deps.relay.invoke('veilRegLock', { action: 'set', pin_auth: pinAuth, veil_id: identity.veilId, ts, sig, ...(nonce ? { nonce } : {}) });
  };
  let r: { data: unknown };
  const startedAt = Date.now();
  try {
    r = await send();
  } catch (e) {
    // b76r2 (audit RL-01): a refusal (4xx) changed nothing. Anything else (no answer: offline
    // mid-request, a timeout, a 5xx) may have saved the new PIN on the relay with this phone's new
    // key lost in the answer: this phone would then not hold the lock and would need the PIN itself,
    // while Settings said "Nothing was changed". The status is read again to find out.
    const st = (e as { status?: unknown } | null)?.status;
    if (typeof st === 'number' && st >= 400 && st < 500) throw e;
    const own = deps.auth.regLockDevice ? await deps.auth.regLockDevice(account.email).catch(() => null) : null;
    const now = await regLockStatus(deps.relay, own).catch(() => null);
    if (!now) throw Object.assign(new Error('The server’s answer was lost, so this phone can’t tell whether the new PIN was saved. Check Registration lock in Settings once you are online again.'), { regLockChanged: true });
    const savedNow = now.enabled && now.deviceMatches !== true && !!now.pinChangedAt && now.pinChangedAt >= startedAt - LOST_SET_WINDOW_MS;
    const unsure = now.enabled && now.deviceMatches === false && now.pinChangedAt === undefined; // an older relay: no date to tell by
    if (!savedNow && !unsure) throw e; // the relay still has the old state: nothing was changed
    // the PIN went through (or may have): one more try makes this phone the owning phone again
    try {
      r = await send();
    } catch {
      lostOwnSetAt = now.pinChangedAt ?? Date.now();
      throw Object.assign(new Error(savedNow
        ? 'The new PIN was saved, but the server’s answer was lost, so this phone didn’t get its lock key and would need the PIN too. Change the PIN again to fix this.'
        : 'The server’s answer was lost. The new PIN may have been saved without this phone getting its lock key, so this phone may need the PIN too. Change the PIN again to fix this.'), { regLockChanged: true });
    }
  }
  const key = (r.data as { device_key?: unknown } | null)?.device_key;
  if (typeof key !== 'string' || !key) throw new Error('The server did not confirm the registration lock. Try again.');
  // b76r1 (audit I5): the relay has the new PIN now. If this phone can't keep the key, it is not
  // the owning phone (it would need the PIN itself), so the lock is not reported as on: it is
  // turned off again, and the error says what state it was left in.
  try {
    await deps.auth.saveRegLockDevice(account.email, key);
    lostOwnSetAt = 0;
  } catch {
    const off = await regLockOff(deps, identity, account.userId).then(() => true, () => false);
    throw Object.assign(new Error(off
      ? 'This phone could not save its registration lock key, so the lock is now off. Try turning it on again.'
      : 'This phone could not save its registration lock key, and the lock could not be turned off again. It is on, and this phone would need the PIN too. Try again, or turn it off.'), { regLockChanged: true });
  }
}

/** turn the lock off (the primary identity signs, as for an account delete) */
export async function regLockOff(deps: RegLockDeps, identity: { veilId: string; ikSeedB64: string }, userId: string): Promise<void> {
  // b77t (audit 5 L-15): a relay-issued single-use nonce is signed in (an older relay without the route: the old form)
  const nonce = await fetchProofNonce(deps.relay, 'vardum-reglock-off-v1');
  const ts = Date.now();
  const sig = await ikSign(identity.ikSeedB64, toB64(utf8(proofMessage('vardum-reglock-off-v1', userId, ts, nonce))));
  await deps.relay.invoke('veilRegLock', { action: 'off', proof: { veil_id: identity.veilId, ts, sig, ...(nonce ? { nonce } : {}) } });
  await deps.auth.forgetRegLockDevice();
}
