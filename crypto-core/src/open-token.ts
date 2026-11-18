/**
 * @veil/crypto-core — b77p (audit 2 VAR-01): blind mailbox-open tokens (spec §12.19.2).
 *
 * A mailbox open used to present a ticket whose hash the joiner had sent in the same request as the
 * rendezvous token, so a relay that logged requests could tie every anonymous mailbox to the join
 * (and through the pending row to both Vardum IDs). Now each side gets ONE RSA blind signature
 * (RSA-2048, e = 65537, full-domain hash) at the join / gate `issue`, on a random value the relay
 * never sees, and opens its inbound later with the unblinded token. The blinded value is uniform
 * and independent of the token, so no VALUE ties the issuance (at the join / gate `issue`) to the open. Timing can:
 * b77u (audit 6 U-M7) the requests that name the rendezvous (gate `issue`, gate `end`) run on their own timers,
 * each an independent 5-30 s CSPRNG delay from the open (device sealed.ts); a relay that logs times and
 * addresses still sees which opens fall in that window, a weaker link at low traffic (spec §12.19.2).
 *
 *   m     = OS2IP(first k-1 bytes of SHA256(seed || I2OSP(0,4)) || SHA256(seed || I2OSP(1,4)) || ...) mod n
 *   seed  = utf8('vardum-open-token/v1:' || kid || ':' || x)       x = 64 random lowercase hex
 *   blind = m * r^e mod n            (r uniform in Z_n*)           -> open_blind (base64url, k bytes)
 *   sig'  = blind^d mod n            (the relay)                    -> open_sig
 *   s     = sig' * r^-1 mod n, checked s^e = m (mod n)             -> token {kid, x, s}
 *
 * BigInt only (Hermes has it); public-key operations (e = 65537) and one inverse — fast on a phone.
 */
import { sha256 } from './kdf';
import { utf8, concat } from './bytes';

export const OPEN_TOKEN_LABEL = 'vardum-open-token/v1';

/** the relay's `openKey` answer */
export interface OpenKeyWire { kid: string; n: string; e: string; until: number }
export interface OpenKey { kid: string; n: bigint; e: bigint; k: number; until: number }
/** what a phone keeps between asking and the answer (r is secret: it unblinds) */
export interface OpenBlind { kid: string; x: string; r: string }
/** the redeemable token (mailboxOpen's open_token) */
export interface OpenToken { kid: string; x: string; s: string }

const HEX64 = /^[0-9a-f]{64}$/;
const KID_RE = /^[0-9a-f]{16}$/;
const B64U_RE = /^[A-Za-z0-9_-]+$/;
const hexOf = (b: Uint8Array): string => [...b].map((x) => x.toString(16).padStart(2, '0')).join('');

export function b64uToBytes(s: string): Uint8Array {
  if (typeof s !== 'string' || !s || !B64U_RE.test(s) || s.length % 4 === 1) throw new Error('Bad base64url');
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (s.length % 4)) % 4);
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
export function bytesToB64u(b: Uint8Array): string {
  let s = '';
  for (let i = 0; i < b.length; i += 0x2000) s += String.fromCharCode.apply(null, b.subarray(i, i + 0x2000) as unknown as number[]);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
export function os2ip(b: Uint8Array): bigint {
  let h = '';
  for (const x of b) h += x.toString(16).padStart(2, '0');
  return h ? BigInt('0x' + h) : 0n;
}
export function i2osp(v: bigint, len: number): Uint8Array {
  let h = v.toString(16);
  if (h.length > len * 2) throw new Error('Integer too large');
  h = h.padStart(len * 2, '0');
  const out = new Uint8Array(len);
  for (let i = 0; i < len; i++) out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  return out;
}
export function modPow(b: bigint, e: bigint, m: bigint): bigint {
  let r = 1n;
  b %= m;
  if (b < 0n) b += m;
  while (e > 0n) { if (e & 1n) r = (r * b) % m; b = (b * b) % m; e >>= 1n; }
  return r;
}
/** a^-1 mod m, or null when gcd(a, m) != 1 */
export function modInv(a: bigint, m: bigint): bigint | null {
  let [r0, r1] = [((a % m) + m) % m, m];
  let [s0, s1] = [1n, 0n];
  while (r1 !== 0n) { const q = r0 / r1; [r0, r1] = [r1, r0 - q * r1]; [s0, s1] = [s1, s0 - q * s1]; }
  if (r0 !== 1n) return null;
  return ((s0 % m) + m) % m;
}

/** A key from the relay's `openKey` answer, checked: kid = first 16 hex of SHA-256(n bytes), a
 *  2048–4096-bit odd modulus, e = 65537. Throws on anything else.
 *  b77q (audit 3 CR-1): `until` must be a positive integer (it used to be any number, a non-number read as 0), and
 *  the modulus must have no prime factor below OPEN_KEY_SMALL_PRIME_BOUND. How long a key is kept is not decided
 *  here: the device's pin (sealed.ts currentOpenKey) does that. */
export async function parseOpenKey(w: unknown): Promise<OpenKey> {
  const o = w as Partial<OpenKeyWire> | null;
  if (!o || typeof o.kid !== 'string' || !KID_RE.test(o.kid) || typeof o.n !== 'string' || typeof o.e !== 'string') throw new Error('Bad open key');
  const nb = b64uToBytes(o.n);
  if (nb.length < 256 || nb.length > 512 || nb[0] === 0 || (nb[nb.length - 1] & 1) === 0) throw new Error('Bad open key modulus');
  const e = os2ip(b64uToBytes(o.e));
  if (e !== 65537n) throw new Error('Bad open key exponent');
  const kid = hexOf(await sha256(nb)).slice(0, 16);
  if (kid !== o.kid) throw new Error('Open key id does not match the key');
  const until = o.until;
  if (typeof until !== 'number' || !Number.isSafeInteger(until) || until <= 0) throw new Error('Bad open key lifetime');
  const n = os2ip(nb);
  if (hasSmallFactor(n)) throw new Error('Bad open key modulus');
  return { kid, n, e, k: nb.length, until };
}

/** b77q (audit 3 CR-1): a relay-chosen modulus with a small prime factor is refused (a real RSA modulus is the
 *  product of two ~1024-bit primes). Cheap (about 1900 small divisions, once per key fetched). This does NOT prove
 *  the key well-formed: a large factor p with p = 1 (mod e) is not ruled out, and only a proof from the relay
 *  (RFC 9474-style key proof, or a published key, roadmap b78) can do that. */
export const OPEN_KEY_SMALL_PRIME_BOUND = 1 << 14;
let smallPrimes: bigint[] | null = null;
function hasSmallFactor(n: bigint): boolean {
  if (!smallPrimes) {
    const sieve = new Uint8Array(OPEN_KEY_SMALL_PRIME_BOUND);
    const out: bigint[] = [];
    for (let i = 2; i < OPEN_KEY_SMALL_PRIME_BOUND; i++) {
      if (sieve[i]) continue;
      out.push(BigInt(i));
      for (let j = i * i; j < OPEN_KEY_SMALL_PRIME_BOUND; j += i) sieve[j] = 1;
    }
    smallPrimes = out;
  }
  for (const p of smallPrimes) if (n % p === 0n) return true;
  return false;
}

/** the full-domain hash of x under this key */
export async function openTokenMessage(key: Pick<OpenKey, 'kid' | 'n' | 'k'>, x: string): Promise<bigint> {
  const seed = utf8(`${OPEN_TOKEN_LABEL}:${key.kid}:${x}`);
  const parts: Uint8Array[] = [];
  let have = 0;
  for (let i = 0; have < key.k - 1; i++) {
    const h = await sha256(concat(seed, i2osp(BigInt(i), 4)));
    parts.push(h);
    have += h.length;
  }
  return os2ip(concat(...parts).subarray(0, key.k - 1)) % key.n;
}

function randomBelow(n: bigint, k: number): bigint {
  for (;;) {
    const v = os2ip(crypto.getRandomValues(new Uint8Array(k + 8))) % n;
    if (v > 1n) return v;
  }
}

/** Start a token: a fresh x and r; returns what to keep and the blinded value to send. */
export async function blindOpenToken(key: OpenKey): Promise<{ blind: OpenBlind; open_blind: string; open_kid: string }> {
  const x = hexOf(crypto.getRandomValues(new Uint8Array(32)));
  let r = 0n;
  for (;;) { r = randomBelow(key.n, key.k); if (modInv(r, key.n) !== null) break; }
  return { blind: { kid: key.kid, x, r: r.toString(16) }, ...(await reblind(key, { kid: key.kid, x, r: r.toString(16) })) };
}

/** The same blinded value again (a request whose answer was lost is re-sent with it). */
export async function reblind(key: OpenKey, blind: OpenBlind): Promise<{ open_blind: string; open_kid: string }> {
  if (blind.kid !== key.kid) throw new Error('Open key changed');
  const m = await openTokenMessage(key, blind.x);
  const r = BigInt('0x' + blind.r);
  return { open_blind: bytesToB64u(i2osp((m * modPow(r, key.e, key.n)) % key.n, key.k)), open_kid: key.kid };
}

/** Unblind the relay's answer and check it; throws when the signature is not valid for x. */
export async function finishOpenToken(key: OpenKey, blind: OpenBlind, openSig: string): Promise<OpenToken> {
  if (blind.kid !== key.kid) throw new Error('Open key changed');
  const sp = os2ip(b64uToBytes(openSig));
  if (sp <= 0n || sp >= key.n) throw new Error('Bad open signature');
  const inv = modInv(BigInt('0x' + blind.r), key.n);
  if (inv === null) throw new Error('Bad blinding factor');
  const s = (sp * inv) % key.n;
  const m = await openTokenMessage(key, blind.x);
  if (modPow(s, key.e, key.n) !== m) throw new Error('The relay\'s open signature does not verify');
  return { kid: key.kid, x: blind.x, s: bytesToB64u(i2osp(s, key.k)) };
}

/** shape checks for stored values */
export const isOpenBlind = (v: unknown): v is OpenBlind => {
  const b = v as OpenBlind | null;
  return !!b && typeof b === 'object' && KID_RE.test(String(b.kid)) && HEX64.test(String(b.x)) && /^[0-9a-f]{1,1100}$/.test(String(b.r));
};
export const isOpenToken = (v: unknown): v is OpenToken => {
  const t = v as OpenToken | null;
  return !!t && typeof t === 'object' && KID_RE.test(String(t.kid)) && HEX64.test(String(t.x)) && typeof t.s === 'string' && B64U_RE.test(t.s) && t.s.length <= 700;
};
