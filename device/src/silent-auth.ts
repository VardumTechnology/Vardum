/**
 * b112 — email-free native accounts (owner directive, Sept 22).
 *
 * The account (the thing that authenticates you to the relay) and the Veil
 * identity (the keypair) are separate. Until now the account was always an
 * email + password + OTP login. For the NATIVE app the account is now derived
 * silently from the 24-word identity phrase:
 *
 *   email    = v<sha256("veil:b112:account-email:" + phrase)[0..12]hex>@veil.app
 *   password = base64(sha256("veil:b112:account-pass:" + phrase))   (~44 chars)
 *
 * Properties:
 *   - deterministic: the same phrase on any device derives the SAME
 *     credentials — phrase restore recovers the account too, no email needed.
 *   - derived from a SECRET (the phrase), so a peer who knows your public
 *     veil-id cannot guess the account email and squat it.
 *   - nothing new leaves the device: only the standard register/login
 *     endpoints see (email, password) — exactly what the manual flow sent.
 *   - the phrase is already the root secret (it re-derives the identity keys);
 *     deriving the account from it adds no new compromise surface.
 *   - b77p (audit VAR-38): the password is unsalted and fast ON PURPOSE. Its input is the
 *     canonical 24-word BIP39 phrase (256 bits of entropy), so there is nothing to search;
 *     the label keeps it apart from the email derivation (the only value the relay can tie
 *     to it); the relay stores only a salted PBKDF2 (600k) verifier of it. A salt or slow
 *     KDF here would add nothing against a 256-bit input and would need a password migration
 *     on every account. Revisit if the phrase ever gets shorter (spec §8.2 item 62).
 *
 * Server side: provisioning a NEW account without a human reading an OTP
 * email needs the relay function `veilSilentAccount` (action: 'provision')
 * to create the account pre-verified server-side. Until that function is
 * live, provisionSilentAccount() throws SilentAccountUnavailableError and the
 * caller falls back to the classic email flow — build-35 users and the
 * review binary are never blocked.
 */
import { sha256, utf8, toB64, ikSign } from '../../crypto-core/src/index';
import type { VeilRelay } from './relay';
import type { Base44Auth, AuthSession } from './auth';
import { relayDetailOf } from './relay-errors'; // b77m (audit VAR-20)

export interface SilentCredentials {
  email: string;
  password: string;
}

/** Normalise a phrase exactly like the restore flow does (case/space tolerant). */
function normalisePhrase(phrase: string): string {
  return canonicalPhrase(phrase);
}

/**
 * b199 (owner hardware repro, Oct 16): the ONE canonical form of a recovery
 * phrase — lowercase a-z words separated by single spaces. Everything a
 * keyboard or a paste can add is dropped: iOS turns a double space into
 * ". ", notes apps add numbering ("1. abandon"), pastes carry newlines,
 * commas or non-breaking spaces. Without this, "ability. able" derived a
 * DIFFERENT sign-in than "ability able" and the restore fell through to the
 * email screen. BIP39 words are a-z only, so a correct phrase is unchanged —
 * every existing derivation (sign-up uses the generated words) still matches.
 */
export function canonicalPhrase(phrase: string): string {
  return String(phrase ?? '').normalize('NFKD').toLowerCase().replace(/[^a-z]+/g, ' ').trim();
}

function hex(bytes: Uint8Array): string {
  let out = '';
  for (let i = 0; i < bytes.length; i++) out += bytes[i].toString(16).padStart(2, '0');
  return out;
}

/** Deterministic synthetic credentials for the phrase. */
export async function deriveSilentCredentials(phrase: string): Promise<SilentCredentials> {
  const norm = normalisePhrase(phrase);
  if (!norm) throw new Error('Phrase is empty');
  const emailHash = await sha256(utf8(`veil:b112:account-email:${norm}`));
  const passHash = await sha256(utf8(`veil:b112:account-pass:${norm}`));
  return {
    // 24 hex chars (~96 bits) — unique per phrase, opaque, syntactically valid
    email: `v${hex(emailHash.subarray(0, 12))}@veil.app`,
    password: toB64(passHash),
  };
}

/** Typed "the server can't do silent accounts yet" signal — never fatal. */
export class SilentAccountUnavailableError extends Error {
  constructor(detail?: string) {
    super(detail || 'Silent accounts are not available on this relay yet');
    this.name = 'SilentAccountUnavailableError';
  }
}

export interface SilentAuthDeps {
  auth: Base44Auth;
  relay: VeilRelay;
}

function isUnavailable(e: unknown): boolean {
  if ((e as { status?: unknown } | null)?.status === 404) return true; // b77m (audit VAR-20)
  const s = relayDetailOf(e).toLowerCase();
  // relay rejects unknown functions with "Unknown action"/"not found";
  // anything else (network, lockout, bad credentials) is a REAL failure the
  // caller should surface, not a fallback trigger.
  return s.includes('unknown action') || s.includes('unknown function') || s.includes('not found') || s.includes('function_not_found') || s.includes('404');
}

/**
 * Fresh install, no account yet: ask the relay to create the phrase-derived
 * account server-side (pre-verified), then log in silently. The relay call
 * carries only the synthetic email + password — the phrase never leaves the
 * device.
 */
export async function provisionSilentAccount(deps: SilentAuthDeps, phrase: string): Promise<AuthSession> {
  const creds = await deriveSilentCredentials(phrase);
  try {
    const r = await deps.relay.invoke('veilSilentAccount', { action: 'provision', email: creds.email, password: creds.password });
    if (r.status >= 400) throw new SilentAccountUnavailableError(`relay status ${r.status}`);
  } catch (e) {
    if (isUnavailable(e)) throw new SilentAccountUnavailableError();
    // b199: a retry after a half-finished first attempt (account created,
    // app closed before sign-in) finds the account already there — that is
    // success, not an error: sign in with the same derived credentials
    if (!/already registered/i.test(relayDetailOf(e))) throw e; // b77m (audit VAR-20)
  }
  // standard platform login. b73 (audit): the Vardum relay has no emailed-code
  // step (accounts are created pre-verified); any error surfaces to the caller
  // exactly like a normal login would.
  return deps.auth.login(creds.email, creds.password);
}

/**
 * Returning device / phrase restore: the account already exists — just sign
 * in with the derived credentials. A plain auth failure means this phrase has
 * no account on this relay (pre-b112 identity, or the account was made the
 * classic way): the caller falls back to the email sign-in.
 */
export async function silentLogin(deps: SilentAuthDeps, phrase: string, opts: { regLockPin?: string } = {}): Promise<AuthSession> {
  const creds = await deriveSilentCredentials(phrase);
  // b76 (registration lock): a locked account answers 423 (dev/reglock.ts:regLockInfo); the
  // caller asks for the PIN and calls again with its proof
  return deps.auth.login(creds.email, creds.password, opts);
}

/** b199: true when an account label is a phrase-derived one (never a real
 *  or made-up email the user typed). */
export function isSilentAccountEmail(email: string | null | undefined): boolean {
  return /^v[0-9a-f]{24}@veil\.app$/.test(String(email ?? '').toLowerCase());
}

/**
 * b199: point the SIGNED-IN account at the credentials derived from `phrase`
 * (relay veilSilentAccount action 'rebind'). Used when "Generate new Veil ID"
 * retires the phrase the account was derived from, and when a made-up-email
 * account switches to 24-word sign-in. Only the derived label + password
 * leave the device; the account's data is untouched.
 */
export async function rebindSilentAccount(
  deps: SilentAuthDeps,
  phrase: string,
  /** b70 (re-review R2): an identity already bound to this account signs the change */
  signer: { veilId: string; ikSeedB64: string },
  /** b70 (re-review 3): the identity just made — it becomes the account's primary */
  nextVeilId = '',
  /** b77u (audit 6 U-M14): the account's CURRENT password (for a 24-word account, its phrase-derived secret). The relay
   *  asks for it (403 code current_password_required) when the account's primary was recorded after the account was set
   *  up (the old first-fresh-binder rule); a primary from the account's onboarding needs only its signature. */
  opts: { currentPassword?: string } = {},
): Promise<void> {
  const creds = await deriveSilentCredentials(phrase);
  const session = await deps.auth.currentSession();
  const ts = Date.now();
  // b75 (audit RL-13): v3 binds the new password too (as a labelled hash, rebindPasswordTag);
  // v2 left it out, so a captured signed request could be replayed with another password
  const sig = await ikSign(signer.ikSeedB64, toB64(utf8(`vardum-rebind-v3:${session?.user?.id ?? ''}:${creds.email}:${ts}:${nextVeilId}:${await rebindPasswordTag(creds.password)}`)));
  await deps.relay.invoke('veilSilentAccount', { action: 'rebind', email: creds.email, password: creds.password, proof: { veil_id: signer.veilId, ts, sig, next_veil_id: nextVeilId }, ...(opts.currentPassword ? { current_password: opts.currentPassword } : {}) });
  // b76 (registration lock): this phone's device key follows the account to its new label, so the
  // sign-in below needs no PIN (a lock the rebind ended leaves a key that no longer matters)
  if (session?.user?.email) await deps.auth.relabelRegLockDevice?.(String(session.user.email), creds.email);
  // b70 (audit RLY-6): a rebind revokes every token, this one too; sign in again
  await deps.auth.login(creds.email, creds.password);
}

/** b75 (audit RL-13): the new password as the rebind proof names it — never the password
 *  itself: hex(SHA-256(utf8('vardum-rebind-pw-v1:' + password))). Same as the relay's. */
export async function rebindPasswordTag(password: string): Promise<string> {
  return [...await sha256(utf8('vardum-rebind-pw-v1:' + password))].map((b) => b.toString(16).padStart(2, '0')).join('');
}

/** b70 (re-review 3): the account's primary identity names its successor, so a
 *  sign-in move that could not finish can be retried later with the new ID */
export async function handoverPrimaryIdentity(
  deps: SilentAuthDeps,
  signer: { veilId: string; ikSeedB64: string },
  nextVeilId: string,
): Promise<void> {
  const session = await deps.auth.currentSession();
  const ts = Date.now();
  const sig = await ikSign(signer.ikSeedB64, toB64(utf8(`vardum-primary-v1:${session?.user?.id ?? ''}:${nextVeilId}:${ts}`)));
  await deps.relay.invoke('veilIdentityGate', { action: 'handover', veil_id: signer.veilId, next_veil_id: nextVeilId, ts, sig });
}
