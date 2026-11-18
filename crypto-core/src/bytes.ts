/**
 * @veil/crypto-core — byte & encoding helpers.
 * Mirrors the web bundle exactly: b64 via btoa/atob semantics, Bitcoin base58
 * alphabet for veil_id / fingerprints, TextEncoder for UTF-8.
 */

const encoder = new TextEncoder();
const decoder = new TextDecoder();

export function utf8(s: string): Uint8Array {
  return encoder.encode(s);
}

export function fromUtf8(b: Uint8Array): string {
  return decoder.decode(b);
}

/** b76r1 (audit P-2): true iff `b` is well-formed UTF-8 (WHATWG / RFC 3629: shortest form only, no
 *  surrogates, nothing above U+10FFFF, no truncated sequence). Checked by hand rather than with
 *  a TextDecoder in fatal mode: the Hermes polyfill (fast-text-encoding) throws on
 *  the `fatal` option itself, so on the phone that would have refused every message. */
export function isWellFormedUtf8(b: Uint8Array): boolean {
  const n = b.length;
  let i = 0;
  while (i < n) {
    const c = b[i];
    if (c < 0x80) { i++; continue; }
    let need: number, lo = 0x80, hi = 0xbf;
    if (c >= 0xc2 && c <= 0xdf) need = 1;
    else if (c >= 0xe0 && c <= 0xef) { need = 2; if (c === 0xe0) lo = 0xa0; else if (c === 0xed) hi = 0x9f; }
    else if (c >= 0xf0 && c <= 0xf4) { need = 3; if (c === 0xf0) lo = 0x90; else if (c === 0xf4) hi = 0x8f; }
    else return false;
    if (i + need >= n) return false; // truncated
    if (b[i + 1] < lo || b[i + 1] > hi) return false;
    for (let j = 2; j <= need; j++) if (b[i + j] < 0x80 || b[i + j] > 0xbf) return false;
    i += need + 1;
  }
  return true;
}

const strictDecoder = new TextDecoder('utf-8', { ignoreBOM: true });
/** b76r1 (audit P-2): decode UTF-8 strictly — malformed bytes throw instead of turning into U+FFFD,
 *  so two different byte strings never read as the same text. A leading U+FEFF stays part of the
 *  text (as the Hermes polyfill already does), so every platform reads the same string. */
export function fromUtf8Strict(b: Uint8Array): string {
  if (!isWellFormedUtf8(b)) throw new Error('Malformed UTF-8');
  return strictDecoder.decode(b);
}

export function toB64(bytes: Uint8Array): string {
  // b199 (owner hardware test Oct 16: a 2.4 MB photo took up to 12 s around
  // the native AES call): one String.fromCharCode per byte is millions of
  // tiny string appends under Hermes. Build the binary string in chunks
  // instead (8 KB at a time) — same output, a fraction of the work.
  const CHUNK = 0x2000; // 8 KB: well inside Hermes's argument-count limit for apply()
  let s = '';
  for (let i = 0; i < bytes.length; i += CHUNK) {
    s += String.fromCharCode.apply(null, bytes.subarray(i, i + CHUNK) as unknown as number[]);
  }
  return btoaSafe(s);
}

/** b70 (audit PRIM-5): standard base64 alphabet. b71: canonical only — fromB64 also
 *  requires the padded form that round-trips exactly (see the check below). */
const B64_STRICT = /^[A-Za-z0-9+/]*={0,2}$/;

export function fromB64(b64: string): Uint8Array {
  // b70 (audit PRIM-5): strict decoding. The decoders used to skip characters
  // they didn't know (the RN polyfill dropped them silently), so different
  // strings decoded to the same bytes. Only the canonical form is accepted now.
  if (typeof b64 !== 'string' || !B64_STRICT.test(b64) || b64.length % 4 === 1) {
    throw new Error(`base64 decode failed: not standard base64 (len=${typeof b64 === 'string' ? b64.length : -1})`);
  }
  const s = atobSafe(b64);
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  // the same bytes must encode back to the same string (no stray bits in the last character)
  // b70 (re-review 8): padding included — one spelling per value (an unpadded key used
  // to compare as a different string, and slipped past a group's deny list)
  if (toB64(out) !== b64) {
    throw new Error(`base64 decode failed: not canonical base64 (len=${b64.length})`);
  }
  return out;
}

function btoaSafe(s: string): string {
  if (typeof btoa === 'function') return btoa(s);
  return (Buffer as any).from(s, 'binary').toString('base64');
}

function atobSafe(s: string): string {
  try {
    if (typeof atob === 'function') return atob(s);
    return (Buffer as any).from(s, 'base64').toString('binary');
  } catch (e) {
    // b188-r6 (owner repro: "Found invalid character when decoding base 64
    // string" on a first send, exact field unknown): name the culprit.
    // b70 (audit PRIM-6): by its length and position only — the input's own
    // characters are never quoted (the string may be a corrupted secret)
    let bad = -1;
    for (let i = 0; i < s.length; i++) {
      const c = s[i];
      if (!/[A-Za-z0-9+/=\s]/.test(c)) { bad = i; break; }
    }
    const m = /length (\d+)|position (\d+)/.exec(String((e as Error).message || e));
    throw new Error(
      `base64 decode failed: len=${s.length} firstBadCharIdx=${bad >= 0 ? bad : (m ? (m[1] || m[2]) : '?')}`
    );
  }
}

const B58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

/** Bitcoin-alphabet base58, leading zero bytes -> '1' (matches bundle impl). */
export function base58(bytes: Uint8Array): string {
  let n = 0n;
  for (const b of bytes) n = (n << 8n) | BigInt(b);
  let out = '';
  while (n > 0n) {
    out = B58_ALPHABET[Number(n % 58n)] + out;
    n /= 58n;
  }
  for (const b of bytes) {
    if (b === 0) out = '1' + out;
    else break;
  }
  return out;
}

export function concat(...arrays: Uint8Array[]): Uint8Array {
  const total = arrays.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrays) {
    out.set(a, off);
    off += a.length;
  }
  return out;
}

export function randomBytes(n: number): Uint8Array {
  const out = new Uint8Array(n);
  crypto.getRandomValues(out);
  return out;
}

export function assert(cond: unknown, msg: string): asserts cond {
  if (!cond) throw new Error(msg);
}
