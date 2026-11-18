/**
 * noble-subtle — pure-JS WebCrypto (the exact `crypto.subtle` subset VEIL uses),
 * implemented with audited @noble libraries. No WebView, no native crypto module,
 * no async bridge — deterministic, Hermes-safe, and testable under Node.
 *
 * WHY: build 12 launched and logged in fine, but BOTH identity flows (create and
 * restore) died at the first crypto.subtle call. The old path routed every crypto
 * op through a hidden WKWebView (react-native-webview-crypto, last updated 2021)
 * — if that bridge fails to load, every op hangs or errors, and the keys pass
 * through a WebView we don't control. This shim replaces it: pure JS, same API,
 * byte-identical outputs (verified against Node WebCrypto + live web vectors).
 *
 * Supported algorithms (everything vendor/crypto-core + vendor/device call):
 *   digest:        SHA-256, SHA-512
 *   importKey:     raw:  HKDF, PBKDF2, HMAC{SHA-256|SHA-512}, AES-GCM, X25519, Ed25519
 *                  pkcs8: X25519, Ed25519 (48-byte fixed prefixes)
 *                  jwk:   X25519, Ed25519, ECDH P-256
 *   exportKey:     raw:  X25519 pub, Ed25519 pub, P-256 pub, AES
 *                  jwk:  X25519 priv/pub, Ed25519 priv/pub, P-256 priv/pub
 *   generateKey:   X25519, Ed25519, ECDH P-256, AES-GCM
 *   sign/verify:    HMAC, Ed25519
 *   deriveBits:    HKDF{SHA-256}, PBKDF2{SHA-256|SHA-512}, X25519, ECDH P-256
 *   encrypt/decrypt: AES-GCM (iv + optional additionalData)
 */

import { sha256 } from '@noble/hashes/sha256';
import { sha512 } from '@noble/hashes/sha512';
import { hmac } from '@noble/hashes/hmac';
import { hkdf } from '@noble/hashes/hkdf';
import { pbkdf2 } from '@noble/hashes/pbkdf2';
import { ed25519, x25519 } from '@noble/curves/ed25519';
import { p256 as P256 } from '@noble/curves/p256';
import { gcm } from '@noble/ciphers/aes';
import type { CHash } from '@noble/hashes/utils';
import { toB64, fromB64 } from '../vendor/crypto-core/src/bytes';
import { isStrongEd25519Pub } from '../vendor/crypto-core/src/identity';

// ---------- native AES-GCM fast path (b54) ----------
// The VeilCrypto Swift module (CryptoKit) exposes aesGcmEncrypt/aesGcmDecrypt
// with the exact same ciphertext||tag layout as noble. For multi-MB payloads
// (vault/stego/transfer/media) the JS path costs ~30s+ on Hermes; native is
// ~instant. Only used above the size threshold below — small per-message
// ratchet ops stay on the proven JS path (bridge overhead would exceed any
// gain, and the ratchet path is the one thing we never want to perturb).


/** b77u (audit 6 IH I-12): WebCrypto's deriveBits length for X25519 / ECDH. null (or undefined) = the whole secret
 *  (WebCrypto gives all 32 bytes; this shim gave an EMPTY secret); otherwise a positive multiple of 8 no longer than
 *  the secret, else it throws (WebCrypto's OperationError), never a short or empty key. */
export function deriveBitsBytes(length: unknown, secretLen: number): number {
  if (length === null || length === undefined) return secretLen;
  const n = Number(length);
  if (!Number.isInteger(n) || n <= 0 || n % 8 !== 0 || n / 8 > secretLen) throw new Error('noble-subtle: deriveBits length must be a positive multiple of 8 within the secret');
  return n / 8;
}

const NATIVE_AES_MIN_BYTES = 262144; // 256 KB

type NativeVeilCryptoAes = {
  aesGcmEncrypt(keyHex: string, ivHex: string, plaintextBase64: string, aadHex: string): Promise<string>;
  aesGcmDecrypt(keyHex: string, ivHex: string, combinedBase64: string, aadHex: string): Promise<string>;
};

let nativeAes: NativeVeilCryptoAes | null | undefined;
let nativeAesLogged = false;

function getNativeAes(): NativeVeilCryptoAes | null {
  if (nativeAes !== undefined) return nativeAes;
  nativeAes = null;
  try {
    // resolve the same way kdf.ts does (b51 pattern): requireNativeModule only
    // exists in the Expo runtime; the typeof guard keeps Node tests importable
    // without expo polyfills.
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const emc = require('expo-modules-core') as { requireNativeModule?: <T>(name: string) => T };
    if (typeof emc?.requireNativeModule !== 'function') {
      if (!nativeAesLogged) { nativeAesLogged = true; console.log('[veil-aes] no requireNativeModule — JS AES-GCM only'); }
      return nativeAes;
    }
    const mod = emc.requireNativeModule<Partial<NativeVeilCryptoAes>>('VeilCrypto');
    if (mod && typeof mod.aesGcmEncrypt === 'function' && typeof mod.aesGcmDecrypt === 'function') {
      nativeAes = mod as NativeVeilCryptoAes;
    } else if (!nativeAesLogged) {
      nativeAesLogged = true;
      console.log('[veil-aes] VeilCrypto lacks aesGcm* — large payloads on slow JS AES-GCM (need EAS rebuild)');
    }
  } catch (e) {
    if (!nativeAesLogged) { nativeAesLogged = true; console.log('[veil-aes] requireNativeModule threw — JS AES-GCM only'); }
  }
  return nativeAes;
}

function toHexLocal(bytes: Uint8Array): string {
  let out = '';
  for (let i = 0; i < bytes.length; i++) out += bytes[i].toString(16).padStart(2, '0');
  return out;
}

/** b77t (audit 5 L-31, IH DEV-8): the hex handed to the native AES-GCM bridge, checked before the call. The
 *  native side read malformed AAD hex as NO AAD (fail open); now a value that is not exactly two lowercase hex
 *  digits per byte is refused here (and natively). '' only for an absent or empty AAD. */
export function nativeHexArg(b: Uint8Array | undefined | null): string {
  if (b === undefined || b === null) return '';
  const hex = toHexLocal(b);
  if (hex.length !== b.length * 2 || !/^(?:[0-9a-f]{2})*$/.test(hex)) throw new Error('noble-subtle: malformed bytes for the native AES-GCM bridge');
  return hex;
}

// ---------- small utils (no Buffer — Hermes has none) ----------

const B64URL = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

function b64uEncode(bytes: Uint8Array): string {
  let out = '';
  for (let i = 0; i < bytes.length; i += 3) {
    const b0 = bytes[i];
    const b1 = i + 1 < bytes.length ? bytes[i + 1] : 0;
    const b2 = i + 2 < bytes.length ? bytes[i + 2] : 0;
    out += B64URL[b0 >> 2];
    out += B64URL[((b0 & 3) << 4) | (b1 >> 4)];
    out += i + 1 < bytes.length ? B64URL[((b1 & 15) << 2) | (b2 >> 6)] : '';
    out += i + 2 < bytes.length ? B64URL[b2 & 63] : '';
  }
  return out;
}

function b64uDecode(s: string, length: number): Uint8Array {
  // b71: exactly the expected length, with no stray bits (it used to truncate or zero-pad)
  if (typeof s !== 'string' || s.length !== Math.ceil((length * 8) / 6)) throw new Error('noble-subtle: JWK field has the wrong length');
  const out = new Uint8Array(length);
  let acc = 0;
  let bits = 0;
  let o = 0;
  for (const ch of s) {
    const v = B64URL.indexOf(ch);
    if (v < 0) throw new Error('invalid base64url character');
    acc = (acc << 6) | v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[o++] = (acc >> bits) & 0xff;
    }
  }
  if (bits > 0 && (acc & ((1 << bits) - 1)) !== 0) throw new Error('noble-subtle: non-canonical base64url');
  return out;
}

/** b71: the fixed 16-byte PKCS#8 prefixes (RFC 8410) — the algorithm OID is checked */
const PKCS8_PREFIX: Record<string, string> = {
  Ed25519: '302e020100300506032b657004220420',
  X25519: '302e020100300506032b656e04220420',
};
const hexOf = (u: Uint8Array) => Array.from(u).map((b) => b.toString(16).padStart(2, '0')).join('');
/** b71: what WebCrypto accepts for the key types this shim makes */
const USAGES: Record<string, string[]> = {
  HKDF: ['deriveBits', 'deriveKey'], PBKDF2: ['deriveBits', 'deriveKey'], HMAC: ['sign', 'verify'],
  'AES-GCM': ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey'], X25519: ['deriveBits', 'deriveKey'], ECDH: ['deriveBits', 'deriveKey'],
  Ed25519: ['sign', 'verify'],
};
function checkUsages(name: string, usages: string[]): void {
  const ok = USAGES[name];
  if (ok && usages.some((u) => !ok.includes(u))) throw new Error(`noble-subtle: usage not valid for ${name}`);
}

function bytes(data: ArrayBuffer | Uint8Array | DataView): Uint8Array {
  if (data instanceof Uint8Array) return data;
  if (ArrayBuffer.isView(data)) return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  return new Uint8Array(data);
}

function ab(u: Uint8Array): ArrayBuffer {
  const out = new ArrayBuffer(u.byteLength);
  new Uint8Array(out).set(u);
  return out;
}

function hashFn(name: string): CHash {
  if (name === 'SHA-256') return sha256;
  if (name === 'SHA-512') return sha512;
  throw new Error(`noble-subtle: unsupported hash ${name}`);
}

// ---------- key model ----------

type Kind =
  | { k: 'hkdf'; ikm: Uint8Array }
  | { k: 'pbkdf2'; pass: Uint8Array }
  | { k: 'hmac'; key: Uint8Array; hash: string }
  | { k: 'aes'; key: Uint8Array }
  | { k: 'ed25519'; priv: Uint8Array | null; pub: Uint8Array }
  | { k: 'x25519'; priv: Uint8Array | null; pub: Uint8Array }
  | { k: 'p256'; priv: Uint8Array | null; pub: Uint8Array }; // pub = uncompressed 65B

export interface NobleCryptoKey {
  type: 'secret' | 'public' | 'private';
  algorithm: Record<string, unknown>;
  extractable: boolean;
  usages: string[];
  m: Kind;
}

interface Pair {
  privateKey: NobleCryptoKey;
  publicKey: NobleCryptoKey;
  [k: string]: unknown;
}

const ED25519_PKCS8_PREFIX = [48, 46, 2, 1, 0, 48, 5, 6, 3, 43, 101, 112, 4, 34, 4, 32];
const X25519_PKCS8_PREFIX = [48, 46, 2, 1, 0, 48, 5, 6, 3, 43, 101, 110, 4, 34, 4, 32];

function keyOf(type: NobleCryptoKey['type'], algo: Record<string, unknown>, m: Kind, usages: string[], extractable: boolean): NobleCryptoKey {
  // b70 (audit PRIM-4): as in WebCrypto, a public key is always extractable
  return { type, algorithm: algo, m, usages: [...(usages ?? [])], extractable: type === 'public' ? true : !!extractable };
}

/** b70 (audit PRIM-4): a key does only what it was imported or generated for */
function requireUsage(key: NobleCryptoKey, usage: string): void {
  if (!key.usages.includes(usage)) throw new Error(`noble-subtle: key usage "${usage}" not allowed for this key`);
}

// ---------- the shim ----------

export const nobleSubtle = {
  fake: true as const, // webview-crypto serializer compat (harmless)

  async digest(algorithm: string, data: ArrayBuffer | Uint8Array): Promise<ArrayBuffer> {
    return ab(hashFn(algorithm)(bytes(data)));
  },

  async importKey(
    format: string,
    data: unknown,
    algorithm: unknown,
    extractable: boolean,
    usages: string[],
  ): Promise<NobleCryptoKey> {
    const alg = algorithm as string | Record<string, string>;
    const name = typeof alg === 'string' ? alg : alg.name;

    checkUsages(name, usages); // b71
    if (format === 'raw') {
      // b71: a copy (WebCrypto copies too). b74 (review VAR-16): key zeroisation in this
      // app is BEST-EFFORT — this copy lives in the CryptoKey until garbage collection,
      // keys also pass through base64 strings (immutable in JS) and hex strings to the
      // native AES path. Zero-filling a caller's buffer narrows the window; it is not a
      // guarantee that no copy of the key remains in memory.
      const raw = bytes(data as ArrayBuffer | Uint8Array).slice();
      if (name === 'HKDF') return keyOf('secret', { name: 'HKDF' }, { k: 'hkdf', ikm: raw }, usages, false);
      if (name === 'PBKDF2') return keyOf('secret', { name: 'PBKDF2' }, { k: 'pbkdf2', pass: raw }, usages, false);
      if (name === 'HMAC') {
        const hash = (alg as Record<string, string>).hash;
        if (raw.length === 0) throw new Error('noble-subtle: HMAC key must not be empty'); // b71
        return keyOf('secret', { name: 'HMAC', hash }, { k: 'hmac', key: raw, hash }, usages, extractable);
      }
      if (name === 'AES-GCM') {
        // b70 (audit PRIM-4): Vardum only uses AES-256
        if (raw.length !== 32) throw new Error('noble-subtle: AES-GCM keys must be 256-bit');
        return keyOf('secret', { name: 'AES-GCM' }, { k: 'aes', key: raw }, usages, extractable);
      }
      if (name === 'X25519') return keyOf('public', { name: 'X25519' }, { k: 'x25519', priv: null, pub: raw }, usages, false);
      if (name === 'Ed25519') {
        // b71: only canonical, prime-order public keys (identity, torsion and mixed-order
        // points are refused, as the app's own checks do)
        if (!isStrongEd25519Pub(raw)) throw new Error('noble-subtle: Ed25519 public key is not a valid prime-order point');
        return keyOf('public', { name: 'Ed25519' }, { k: 'ed25519', priv: null, pub: raw }, usages, false);
      }
      if (name === 'ECDH') {
        // raw P-256 public (uncompressed 65B)
        return keyOf('public', { name: 'ECDH', namedCurve: 'P-256' }, { k: 'p256', priv: null, pub: raw }, usages, false);
      }
      throw new Error(`noble-subtle: importKey raw ${name} unsupported`);
    }

    if (format === 'pkcs8') {
      const der = bytes(data as ArrayBuffer | Uint8Array);
      if (der.length !== 48) throw new Error('noble-subtle: pkcs8 must be the 48-byte fixed-prefix form');
      if (!PKCS8_PREFIX[name] || hexOf(der.subarray(0, 16)) !== PKCS8_PREFIX[name]) throw new Error(`noble-subtle: pkcs8 is not an ${name} key`); // b71
      const seed = der.slice(16);
      if (name === 'Ed25519') {
        return keyOf('private', { name: 'Ed25519' }, { k: 'ed25519', priv: seed, pub: ed25519.getPublicKey(seed) }, usages, extractable);
      }
      if (name === 'X25519') {
        return keyOf('private', { name: 'X25519' }, { k: 'x25519', priv: seed, pub: x25519.getPublicKey(seed) }, usages, extractable);
      }
      throw new Error(`noble-subtle: importKey pkcs8 ${name} unsupported`);
    }

    if (format === 'jwk') {
      const jwk = data as Record<string, string>;
      if (name === 'Ed25519') {
        const pub = b64uDecode(jwk.x, 32);
        const priv = jwk.d ? b64uDecode(jwk.d, 32) : null;
        if (priv && hexOf(ed25519.getPublicKey(priv)) !== hexOf(pub)) throw new Error('noble-subtle: JWK x does not match d'); // b71
        if (!priv && !isStrongEd25519Pub(pub)) throw new Error('noble-subtle: Ed25519 public key is not a valid prime-order point'); // b71
        return keyOf(priv ? 'private' : 'public', { name: 'Ed25519' }, { k: 'ed25519', priv, pub }, usages, extractable);
      }
      if (name === 'X25519') {
        const pub = b64uDecode(jwk.x, 32);
        const priv = jwk.d ? b64uDecode(jwk.d, 32) : null;
        if (priv && hexOf(x25519.getPublicKey(priv)) !== hexOf(pub)) throw new Error('noble-subtle: JWK x does not match d'); // b71
        return keyOf(priv ? 'private' : 'public', { name: 'X25519' }, { k: 'x25519', priv, pub }, usages, extractable);
      }
      if (name === 'ECDH' && (alg as Record<string, string>).namedCurve === 'P-256') {
        const pub = new Uint8Array(65);
        pub[0] = 0x04;
        pub.set(b64uDecode(jwk.x, 32), 1);
        pub.set(b64uDecode(jwk.y, 32), 33);
        const priv = jwk.d ? b64uDecode(jwk.d, 32) : null;
        return keyOf(priv ? 'private' : 'public', { name: 'ECDH', namedCurve: 'P-256' }, { k: 'p256', priv, pub }, usages, extractable);
      }
      throw new Error(`noble-subtle: importKey jwk ${name} unsupported`);
    }

    throw new Error(`noble-subtle: importKey format ${format} unsupported`);
  },

  async exportKey(format: string, key: NobleCryptoKey): Promise<ArrayBuffer | Record<string, unknown>> {
    const m = key.m;
    // b70 (audit PRIM-4): a non-extractable secret or private key never leaves
    if (key.type !== 'public' && !key.extractable) throw new Error('noble-subtle: key is not extractable');

    if (format === 'raw') {
      if (m.k === 'aes') return ab(m.key);
      if (m.k === 'x25519' || m.k === 'ed25519') return ab(m.pub);
      if (m.k === 'p256') return ab(m.pub);
      throw new Error(`noble-subtle: raw export of ${m.k} unsupported`);
    }

    if (format === 'jwk') {
      if (m.k === 'x25519') {
        const jwk: Record<string, unknown> = { kty: 'OKP', crv: 'X25519', x: b64uEncode(m.pub) };
        if (m.priv) jwk.d = b64uEncode(m.priv);
        return jwk;
      }
      if (m.k === 'ed25519') {
        const jwk: Record<string, unknown> = { kty: 'OKP', crv: 'Ed25519', x: b64uEncode(m.pub) };
        if (m.priv) jwk.d = b64uEncode(m.priv);
        return jwk;
      }
      if (m.k === 'p256') {
        const jwk: Record<string, unknown> = {
          kty: 'EC',
          crv: 'P-256',
          x: b64uEncode(m.pub.slice(1, 33)),
          y: b64uEncode(m.pub.slice(33)),
        };
        if (m.priv) jwk.d = b64uEncode(m.priv);
        return jwk;
      }
      throw new Error(`noble-subtle: jwk export of ${m.k} unsupported`);
    }

    throw new Error(`noble-subtle: exportKey format ${format} unsupported`);
  },

  async generateKey(
    algorithm: unknown,
    extractable: boolean,
    usages: string[],
  ): Promise<Pair | NobleCryptoKey> {
    const alg = algorithm as Record<string, string>;
    if (alg.name === 'X25519') {
      const priv = x25519.utils.randomPrivateKey();
      const pub = x25519.getPublicKey(priv);
      return {
        privateKey: keyOf('private', { name: 'X25519' }, { k: 'x25519', priv, pub }, usages, extractable),
        publicKey: keyOf('public', { name: 'X25519' }, { k: 'x25519', priv: null, pub }, usages, extractable),
      };
    }
    if (alg.name === 'Ed25519') {
      const priv = ed25519.utils.randomPrivateKey();
      const pub = ed25519.getPublicKey(priv);
      return {
        privateKey: keyOf('private', { name: 'Ed25519' }, { k: 'ed25519', priv, pub }, usages, extractable),
        publicKey: keyOf('public', { name: 'Ed25519' }, { k: 'ed25519', priv: null, pub }, usages, extractable),
      };
    }
    if (alg.name === 'ECDH' && alg.namedCurve === 'P-256') {
      const priv = P256.utils.randomPrivateKey();
      const pub = p256PubFromPriv(priv);
      return {
        privateKey: keyOf('private', { name: 'ECDH', namedCurve: 'P-256' }, { k: 'p256', priv, pub }, usages, extractable),
        publicKey: keyOf('public', { name: 'ECDH', namedCurve: 'P-256' }, { k: 'p256', priv: null, pub }, usages, extractable),
      };
    }
    if (alg.name === 'AES-GCM') {
      const raw = x25519.utils.randomPrivateKey(); // 32 random bytes
      return keyOf('secret', { name: 'AES-GCM' }, { k: 'aes', key: raw }, usages, extractable);
    }
    throw new Error(`noble-subtle: generateKey ${alg.name} unsupported`);
  },

  async sign(algorithm: unknown, key: NobleCryptoKey, data: ArrayBuffer | Uint8Array): Promise<ArrayBuffer> {
    requireUsage(key, 'sign');
    const name = typeof algorithm === 'string' ? algorithm : (algorithm as Record<string, string>).name;
    if (name === 'HMAC' && key.m.k === 'hmac') {
      return ab(hmac(hashFn(key.m.hash), key.m.key, bytes(data)));
    }
    if (name === 'Ed25519' && key.m.k === 'ed25519') {
      if (!key.m.priv) throw new Error('noble-subtle: sign needs a private key');
      return ab(ed25519.sign(bytes(data), key.m.priv));
    }
    throw new Error(`noble-subtle: sign ${name} unsupported`);
  },

  async verify(
    algorithm: unknown,
    key: NobleCryptoKey,
    signature: ArrayBuffer | Uint8Array,
    data: ArrayBuffer | Uint8Array,
  ): Promise<boolean> {
    requireUsage(key, 'verify');
    const name = typeof algorithm === 'string' ? algorithm : (algorithm as Record<string, string>).name;
    if (name === 'Ed25519' && key.m.k === 'ed25519') {
      // b54 (pre-audit T-2): strict RFC 8032 verification — noble's default
      // ZIP-215 rules accept a forged signature under a small-order public key
      // and disagree with the relay's (WebCrypto, strict) verifier
      try { return ed25519.verify(bytes(signature), bytes(data), key.m.pub, { zip215: false }); } catch { return false; }
    }
    if (name === 'HMAC' && key.m.k === 'hmac') {
      const expect = hmac(hashFn(key.m.hash), key.m.key, bytes(data));
      const got = bytes(signature);
      if (expect.length !== got.length) return false;
      let diff = 0;
      for (let i = 0; i < expect.length; i++) diff |= expect[i] ^ got[i];
      return diff === 0;
    }
    throw new Error(`noble-subtle: verify ${name} unsupported`);
  },

  async deriveBits(algorithm: unknown, key: NobleCryptoKey, length: number): Promise<ArrayBuffer> {
    requireUsage(key, 'deriveBits');
    const alg = algorithm as Record<string, unknown>;
    const name = alg.name as string;

    if (name === 'HKDF' && key.m.k === 'hkdf') {
      // b71: the hash parameter is honoured (it used to be ignored: SHA-512 gave SHA-256)
      const h = String((alg.hash as { name?: string } | string | undefined) && typeof alg.hash === 'object' ? (alg.hash as { name: string }).name : alg.hash);
      if (h !== 'SHA-256') throw new Error('noble-subtle: HKDF supports SHA-256 only');
      if (!Number.isInteger(length) || length <= 0 || length % 8 !== 0) throw new Error('noble-subtle: HKDF length must be a positive multiple of 8');
      return ab(hkdf(sha256, key.m.ikm, bytes(alg.salt as Uint8Array), bytes(alg.info as Uint8Array), length / 8));
    }
    if (name === 'PBKDF2' && key.m.k === 'pbkdf2') {
      return ab(
        pbkdf2(hashFn(alg.hash as string), key.m.pass, bytes(alg.salt as Uint8Array), { c: alg.iterations as number, dkLen: length / 8 }),
      );
    }
    if (name === 'X25519' && key.m.k === 'x25519') {
      if (!key.m.priv) throw new Error('noble-subtle: deriveBits needs a private key');
      const pub = (alg.public as NobleCryptoKey).m;
      if (pub.k !== 'x25519') throw new Error('noble-subtle: X25519 with non-X25519 public key');
      const shared = x25519.getSharedSecret(key.m.priv, pub.pub);
      return ab(shared.slice(0, deriveBitsBytes(length, shared.length))); // b77u (audit 6 IH I-12)
    }
    if (name === 'ECDH' && key.m.k === 'p256') {
      if (!key.m.priv) throw new Error('noble-subtle: deriveBits needs a private key');
      const pubKey = (alg.public as NobleCryptoKey).m;
      if (pubKey.k !== 'p256') throw new Error('noble-subtle: ECDH with non-P256 public key');
      const shared = p256Shared(key.m.priv, pubKey.pub);
      return ab(shared.slice(0, deriveBitsBytes(length, shared.length))); // b77u (audit 6 IH I-12)
    }
    throw new Error(`noble-subtle: deriveBits ${name} unsupported`);
  },

  async encrypt(
    algorithm: unknown,
    key: NobleCryptoKey,
    data: ArrayBuffer | Uint8Array,
  ): Promise<ArrayBuffer> {
    requireUsage(key, 'encrypt');
    const alg = algorithm as Record<string, unknown>;
    if (alg.name === 'AES-GCM' && key.m.k === 'aes') {
      if (alg.tagLength !== undefined && alg.tagLength !== 128) throw new Error('noble-subtle: AES-GCM supports 128-bit tags only'); // b71
      const iv = bytes(alg.iv as Uint8Array);
      const aad = alg.additionalData ? bytes(alg.additionalData as Uint8Array) : undefined;
      const pt = bytes(data);
      // native fast path for the big payloads only (vaults/stego/transfer/media)
      if (pt.length >= NATIVE_AES_MIN_BYTES) {
        const nat = getNativeAes();
        if (nat) {
          try {
            const t0 = Date.now();
            const inB64 = toB64(pt);
            const t1 = Date.now();
            const outB64 = await nat.aesGcmEncrypt(nativeHexArg(key.m.key), nativeHexArg(iv), inB64, nativeHexArg(aad)); // b77t (audit 5 L-31)
            const t2 = Date.now();
            const out = fromB64(outB64);
            console.log(`[veil-aes] encrypt NATIVE ${pt.length}B in ${Date.now() - t0} ms (b64 in ${t1 - t0}, native ${t2 - t1}, b64 out ${Date.now() - t2})`);
            return ab(out);
          } catch (e) {
            console.log('[veil-aes] native encrypt failed, JS fallback:', String(e));
          }
        }
      }
      return ab(gcm(key.m.key, iv, aad).encrypt(pt));
    }
    throw new Error('noble-subtle: only AES-GCM encrypt supported');
  },

  async decrypt(
    algorithm: unknown,
    key: NobleCryptoKey,
    data: ArrayBuffer | Uint8Array,
  ): Promise<ArrayBuffer> {
    requireUsage(key, 'decrypt');
    const alg = algorithm as Record<string, unknown>;
    if (alg.name === 'AES-GCM' && key.m.k === 'aes') {
      if (alg.tagLength !== undefined && alg.tagLength !== 128) throw new Error('noble-subtle: AES-GCM supports 128-bit tags only'); // b71
      const iv = bytes(alg.iv as Uint8Array);
      const aad = alg.additionalData ? bytes(alg.additionalData as Uint8Array) : undefined;
      const ct = bytes(data);
      // native fast path for the big payloads only (vaults/stego/transfer/media)
      if (ct.length >= NATIVE_AES_MIN_BYTES) {
        const nat = getNativeAes();
        if (nat) {
          try {
            const t0 = Date.now();
            const inB64 = toB64(ct);
            const t1 = Date.now();
            const outB64 = await nat.aesGcmDecrypt(nativeHexArg(key.m.key), nativeHexArg(iv), inB64, nativeHexArg(aad)); // b77t (audit 5 L-31)
            const t2 = Date.now();
            const out = fromB64(outB64);
            console.log(`[veil-aes] decrypt NATIVE ${ct.length}B in ${Date.now() - t0} ms (b64 in ${t1 - t0}, native ${t2 - t1}, b64 out ${Date.now() - t2})`);
            return ab(out);
          } catch (e) {
            const msg = String(e);
            // VeilCrypto code 20 = GCM authentication failure (wrong key /
            // passphrase / corrupted data). noble would throw the SAME
            // verdict after ~30s of JS — propagate now instead of re-running
            // the whole payload in JS. Only bridge/module errors fall back.
            console.log(`[veil-aes] native decrypt rejected ${ct.length}B: ${msg.slice(0, 160)}`);
            if (msg.includes('code 20') || msg.includes('authentication failure')) {
              throw new Error('noble-subtle: AES-GCM authentication failed (bad key or data)');
            }
            console.log('[veil-aes] native decrypt failed, JS fallback:', msg);
          }
        }
      }
      return ab(gcm(key.m.key, iv, aad).decrypt(ct));
    }
    throw new Error('noble-subtle: only AES-GCM decrypt supported');
  },
};

// ---------- P-256 helpers ----------

function p256PubFromPriv(priv: Uint8Array): Uint8Array {
  return P256.getPublicKey(priv, false); // uncompressed 65 bytes (0x04 || x || y)
}

function p256Shared(priv: Uint8Array, pubUncompressed: Uint8Array): Uint8Array {
  // noble v1.9 returns the full point; WebCrypto ECDH deriveBits(256) is the x-coordinate.
  // uncompressed: 0x04||x||y -> x = [1..33]; compressed: 0x02|0x03||x -> x = [1..33].
  const out = P256.getSharedSecret(priv, pubUncompressed, false);
  return out.slice(1, 33);
}

/** Install as the global Hermes crypto.subtle (getRandomValues comes from react-native-get-random-values). */
export function installNobleSubtle(): void {
  const g = globalThis as unknown as { crypto?: Record<string, unknown> };
  const c = (g.crypto ?? {}) as Record<string, unknown>;
  c.subtle = nobleSubtle;
  c.fake = true;
  g.crypto = c;
}
