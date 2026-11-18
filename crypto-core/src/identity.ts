/**
 * @veil/crypto-core — account identity (Phase-1 design, verified live).
 *
 * Derivation chain (extracted from the web bundle, byte-exact):
 *   24-word BIP39 phrase
 *     -> PBKDF2-SHA-512('mnemonic', 2048, 512-bit) seed
 *     -> HKDF-SHA256(seed, salt=empty, info='veil-identity-ed25519', 32) = ikSeed
 *     -> Ed25519 private key (PKCS#8 DER prefix + ikSeed)
 *     -> IK_pub (32-byte raw, b64)
 *     -> veil_id  = base58(SHA-256(IK_pub))[0:16]
 *     -> identity fingerprint = full base58(SHA-256(IK_pub)) in 4-char groups
 *
 * SPK is an X25519 keypair (fresh per device); PQ prekey is ML-KEM-768. All public
 * material only ever leaves the device.
 * b75 (audit 2 V9): both prekey signatures are domain-labelled and dated —
 *   SPK_sig = b64(Ed25519(IK, "vardum-spk-v2:" || SPK_pub || ":" || ts)) + "." + ts
 *   pq_sig  = b64(Ed25519(IK, "vardum-pq-prekey-v2:" || pq_pub || ":" || ts)) + "." + ts
 * and a prekey signed more than PREKEY_SIG_MAX_AGE_MS ago is refused.
 */

import { toB64, fromB64, base58, concat, randomBytes, utf8 } from './bytes';
import { SPK_SIG_LABEL_V2, PQ_PREKEY_SIG_LABEL_V2, PREKEY_SIG_MAX_AGE_MS, PREKEY_SIG_MAX_FUTURE_MS, OPK_SIG_LABEL, OPK_ID_RE, MLKEM768_PUB_BYTES } from './constants';
import { hkdf, sha256 } from './kdf';
import { phraseSeed, validatePhrase, entropyToWords } from './bip39';
import { mlkemKeypair, type MlKemKeypairB64 } from './mlkem';
import { ed25519 } from '@noble/curves/ed25519';

/**
 * b71: a peer's Ed25519 public key must be a canonical encoding of a point of prime order.
 * The identity point, the small-order (torsion) points and mixed-order points can't come
 * from a real key (every key made from a seed is prime-order), and some verifiers accept
 * signatures under them for any message ("universal forgery" under the identity key).
 */
export function isStrongEd25519Pub(pub: Uint8Array): boolean {
  if (pub.length !== 32) return false;
  try {
    const pt = ed25519.ExtendedPoint.fromHex(pub); // strict by default (zip215 off): no non-canonical encodings
    return !pt.isSmallOrder() && pt.isTorsionFree();
  } catch { return false; }
}

/** 48-byte PKCS#8 DER prefix for a raw Ed25519 seed (xv() in the bundle). */
const PKCS8_ED25519_PREFIX = new Uint8Array([48, 46, 2, 1, 0, 48, 5, 6, 3, 43, 101, 112, 4, 34, 4, 32]);

function pkcs8Wrap(seed: Uint8Array): Uint8Array {
  const out = new Uint8Array(48);
  out.set(PKCS8_ED25519_PREFIX, 0);
  out.set(seed, 16);
  return out;
}

/** ikSeed -> Ed25519 keypair; returns raw 32-byte public key. */
export async function ikFromSeed(seed: Uint8Array): Promise<{ pubBytes: Uint8Array; privKey: CryptoKey }> {
  const privKey = await crypto.subtle.importKey('pkcs8', pkcs8Wrap(seed) as BufferSource, { name: 'Ed25519' }, true, ['sign']);
  const jwk = await crypto.subtle.exportKey('jwk', privKey);
  if (!jwk.x) throw new Error('Could not derive the identity public key');
  return { pubBytes: b64ToBytes(jwk.x), privKey };
}

function b64ToBytes(b64url: string): Uint8Array {
  const b64 = b64url.replace(/-/g, '+').replace(/_/g, '/');
  const pad = '='.repeat((4 - (b64.length % 4)) % 4);
  return fromB64(b64 + pad);
}

/** veil_id = base58(SHA-256(IK_pub))[0:16] — verified against live relay vectors. */
export async function veilIdFromIkPub(ikPubB64: string): Promise<string> {
  const h = await sha256(fromB64(ikPubB64));
  return base58(h).slice(0, 16);
}

/** Human fingerprint card: full base58 digest in 4-char groups (Iv() in the bundle). */
export async function identityFingerprint(ikPubB64: string): Promise<string> {
  const h = await sha256(fromB64(ikPubB64));
  return (base58(h).match(/.{1,4}/g) || []).join(' ');
}

export interface X25519KeypairB64 {
  pubB64: string;
  privSeedB64: string;
}

/** X25519 SPK (Tv() in the bundle). */
export async function generateSpk(): Promise<X25519KeypairB64> {
  const kp = (await crypto.subtle.generateKey({ name: 'X25519' }, true, ['deriveKey', 'deriveBits'])) as CryptoKeyPair;
  const pub = new Uint8Array(await crypto.subtle.exportKey('raw', kp.publicKey));
  const jwk = await crypto.subtle.exportKey('jwk', kp.privateKey);
  return { pubB64: toB64(pub), privSeedB64: toB64(b64ToBytes(jwk.d!)) };
}

export interface VeilIdentityMaterial {
  mnemonic: string[];
  veilId: string;
  ikSeedB64: string;
  ikPubB64: string;
  spkPubB64: string;
  spkPrivB64: string;
  /** b75 (V9): dated, labelled (see the header comment) — published as SPK_sig */
  spkSigB64: string;
  pq: MlKemKeypairB64;
  /** b54; b75 (V9): dated, labelled — published as pq_sig */
  pqSigB64: string;
  /** b75 (V9): when both prekeys were signed (seconds since 1970, decimal) */
  prekeyTs: string;
}

/** Create a brand-new identity (ov+K_ path in the bundle). */
export async function createIdentity(): Promise<VeilIdentityMaterial> {
  const words = await entropyToWords(randomBytes(32));
  return restoreIdentity(words.join(' '), undefined, true);
}

/**
 * Restore an identity from a 24-word phrase.
 * Reproduces the exact veil_id on any device (verified live).
 * If expectedVeilId is provided and mismatches, throws (Dv() in the bundle).
 * The `withFreshPrekeys` flag makes this usable for creation (fresh SPK + PQ pair).
 */
export async function restoreIdentity(
  phrase: string,
  expectedVeilId?: string,
  withFreshPrekeys = false,
): Promise<VeilIdentityMaterial> {
  const words = await validatePhrase(phrase);
  const seed = await phraseSeed(words);
  const ikSeed = await hkdf(seed, new Uint8Array(), 'veil-identity-ed25519', 32);
  const { pubBytes } = await ikFromSeed(ikSeed);
  const ikPubB64 = toB64(pubBytes);
  const veilId = await veilIdFromIkPub(ikPubB64);
  if (expectedVeilId && veilId !== expectedVeilId) {
    throw new Error('This recovery phrase belongs to a different Vardum identity.');
  }
  const spk = await generateSpk();
  const pq = await mlkemKeypair();
  const prekeyTs = prekeyTsNow();
  return {
    mnemonic: words,
    veilId,
    ikSeedB64: toB64(ikSeed),
    ikPubB64,
    spkPubB64: spk.pubB64,
    spkPrivB64: spk.privSeedB64,
    spkSigB64: await signSpk(toB64(ikSeed), spk.pubB64, prekeyTs),
    pq,
    pqSigB64: await signPqPrekey(toB64(ikSeed), pq.pub, prekeyTs),
    prekeyTs,
  };
}

/** Re-publish path: existing ikSeed, fresh SPK + PQ prekeys (Ov() in the bundle). */
export async function republishPrekeys(ikSeedB64: string): Promise<{
  ikPubB64: string;
  spkPubB64: string;
  spkPrivB64: string;
  spkSigB64: string;
  pq: MlKemKeypairB64;
  pqSigB64: string;
  prekeyTs: string;
  veilId: string;
}> {
  const { pubBytes } = await ikFromSeed(fromB64(ikSeedB64));
  const spk = await generateSpk();
  const pq = await mlkemKeypair();
  const prekeyTs = prekeyTsNow();
  return {
    ikPubB64: toB64(pubBytes),
    spkPubB64: spk.pubB64,
    spkPrivB64: spk.privSeedB64,
    spkSigB64: await signSpk(ikSeedB64, spk.pubB64, prekeyTs),
    pq,
    pqSigB64: await signPqPrekey(ikSeedB64, pq.pub, prekeyTs),
    prekeyTs,
    veilId: await veilIdFromIkPub(toB64(pubBytes)),
  };
}

/** Ed25519 sign with the identity key (kv() in the bundle) — nonce-signed auth. */
export async function ikSign(ikSeedB64: string, messageB64: string): Promise<string> {
  const { privKey } = await ikFromSeed(fromB64(ikSeedB64));
  const sig = new Uint8Array(await crypto.subtle.sign('Ed25519', privKey, fromB64(messageB64) as BufferSource));
  return toB64(sig);
}

/** b75 (audit 2 V9): a signing time for prekeys made now (whole seconds, decimal) */
export function prekeyTsNow(nowMs = Date.now()): string {
  return String(Math.floor(nowMs / 1000));
}

/** b75 (V9): split a published prekey signature `sigB64.ts`; null if it isn't one */
export function parseSignedPrekeySig(s: unknown): { sigB64: string; ts: string } | null {
  if (typeof s !== 'string') return null;
  const m = /^([A-Za-z0-9+/]{86}==)\.([1-9][0-9]{0,11})$/.exec(s);
  return m ? { sigB64: m[1], ts: m[2] } : null;
}

/** b75 (V9): the signing time of a published prekey signature in ms, or null */
export function prekeySigTimeMs(s: unknown): number | null {
  const p = parseSignedPrekeySig(s);
  return p ? Number(p.ts) * 1000 : null;
}

/** b75 (V9): signed within PREKEY_SIG_MAX_AGE_MS (and not more than a day in the future) */
export function prekeySigFresh(s: unknown, nowMs = Date.now()): boolean {
  const t = prekeySigTimeMs(s);
  return t !== null && nowMs - t <= PREKEY_SIG_MAX_AGE_MS && t - nowMs <= PREKEY_SIG_MAX_FUTURE_MS;
}

function datedPrekeyMessage(label: string, keyB64: string, ts: string): Uint8Array {
  return concat(utf8(label), fromB64(keyB64), utf8(':' + ts));
}

/** b75 (V9): sign the X25519 signed prekey — labelled and dated (it used to be the raw key bytes) */
export async function signSpk(ikSeedB64: string, spkPubB64: string, ts: string): Promise<string> {
  return `${await ikSign(ikSeedB64, toB64(datedPrekeyMessage(SPK_SIG_LABEL_V2, spkPubB64, ts)))}.${ts}`;
}

/** Verify a peer's SPK signature against their pinned IK (client-side trust anchor).
 *  b75 (audit 2 V9): only the labelled, dated form, signed within PREKEY_SIG_MAX_AGE_MS. Never throws. */
export async function verifySpkSig(ikPubB64: string, spkPubB64: string, spkSigB64: string, nowMs = Date.now()): Promise<boolean> {
  const p = parseSignedPrekeySig(spkSigB64);
  if (!p || !spkPubB64 || !prekeySigFresh(spkSigB64, nowMs)) return false;
  try {
    return await verifyWithIk(ikPubB64, toB64(datedPrekeyMessage(SPK_SIG_LABEL_V2, spkPubB64, p.ts)), p.sigB64);
  } catch {
    return false;
  }
}

/** Generic Ed25519 verify against a peer's raw IK pub (initiator_sig check, SPEC §3.1). */
export async function verifyWithIk(ikPubB64: string, messageB64: string, sigB64: string): Promise<boolean> {
  if (!isStrongEd25519Pub(fromB64(ikPubB64))) return false; // b71
  const pubKey = await crypto.subtle.importKey('raw', fromB64(ikPubB64) as BufferSource, { name: 'Ed25519' }, true, ['verify']);
  return crypto.subtle.verify('Ed25519', pubKey, fromB64(sigB64) as BufferSource, fromB64(messageB64) as BufferSource);
}

/** b54 (Batch A, review H-1): sign the published ML-KEM prekey with the identity key.
 *  b75 (audit 2 V9): labelled v2 and dated (ts = the signing time, as for the SPK). */
export async function signPqPrekey(ikSeedB64: string, pqPubB64: string, ts: string = prekeyTsNow()): Promise<string> {
  return `${await ikSign(ikSeedB64, toB64(datedPrekeyMessage(PQ_PREKEY_SIG_LABEL_V2, pqPubB64, ts)))}.${ts}`;
}

/** b54: verify a peer's pq_sig against their PINNED / verified IK. Never throws.
 *  b75 (audit 2 V9): only the dated v2 form, signed within PREKEY_SIG_MAX_AGE_MS — a relay
 *  can no longer keep serving an old, validly signed prekey. */
export async function verifyPqPrekeySig(ikPubB64: string, pqPubB64: string, pqSigB64: string, nowMs = Date.now()): Promise<boolean> {
  const p = parseSignedPrekeySig(pqSigB64);
  if (!ikPubB64 || !pqPubB64 || !p || !prekeySigFresh(pqSigB64, nowMs)) return false;
  try {
    return await verifyWithIk(ikPubB64, toB64(datedPrekeyMessage(PQ_PREKEY_SIG_LABEL_V2, pqPubB64, p.ts)), p.sigB64);
  } catch {
    return false;
  }
}

// ---------- b76 (one-time prekeys) ----------

/** b76 (one-time prekeys): a one-time prekey pair — one X25519 key and one ML-KEM-768 key under
 *  one id, signed together (OPK_SIG_LABEL). The private halves never leave the phone. */
export interface OneTimePrekey {
  id: string;
  xPubB64: string;
  xPrivB64: string;
  pqPubB64: string;
  pqPrivB64: string;
  /** dated signature `sigB64.ts` (published) */
  sig: string;
  /** signing time in ms */
  madeAt: number;
}

function oneTimePrekeyMessage(id: string, xPubB64: string, pqPubB64: string, ts: string): Uint8Array {
  return concat(utf8(OPK_SIG_LABEL + id + ':'), fromB64(xPubB64), fromB64(pqPubB64), utf8(':' + ts));
}

/** b76: sign a one-time prekey pair (id, X25519 pub, ML-KEM pub), dated */
export async function signOneTimePrekey(ikSeedB64: string, id: string, xPubB64: string, pqPubB64: string, ts: string = prekeyTsNow()): Promise<string> {
  if (!OPK_ID_RE.test(id)) throw new Error('Malformed one-time prekey id.');
  return `${await ikSign(ikSeedB64, toB64(oneTimePrekeyMessage(id, xPubB64, pqPubB64, ts)))}.${ts}`;
}

/** b76: verify a peer's one-time prekey pair against their PINNED IK — the id, both keys (right
 *  sizes) and a fresh dated signature. Never throws. */
export async function verifyOneTimePrekeySig(ikPubB64: string, id: string, xPubB64: string, pqPubB64: string, sig: string, nowMs = Date.now()): Promise<boolean> {
  const p = parseSignedPrekeySig(sig);
  if (!ikPubB64 || typeof id !== 'string' || !OPK_ID_RE.test(id) || !p || !prekeySigFresh(sig, nowMs)) return false;
  try {
    if (fromB64(xPubB64).length !== 32 || fromB64(pqPubB64).length !== MLKEM768_PUB_BYTES) return false;
    return await verifyWithIk(ikPubB64, toB64(oneTimePrekeyMessage(id, xPubB64, pqPubB64, p.ts)), p.sigB64);
  } catch {
    return false;
  }
}

/** b76: make `n` fresh one-time prekey pairs, signed by the identity key */
export async function generateOneTimePrekeys(ikSeedB64: string, n: number, nowMs = Date.now()): Promise<OneTimePrekey[]> {
  const out: OneTimePrekey[] = [];
  const ts = prekeyTsNow(nowMs);
  for (let i = 0; i < n; i++) {
    const id = [...randomBytes(8)].map((b) => b.toString(16).padStart(2, '0')).join('');
    const x = await generateSpk();
    const pq = await mlkemKeypair();
    out.push({ id, xPubB64: x.pubB64, xPrivB64: x.privSeedB64, pqPubB64: pq.pub, pqPrivB64: pq.priv, sig: await signOneTimePrekey(ikSeedB64, id, x.pubB64, pq.pub, ts), madeAt: Number(ts) * 1000 });
  }
  return out;
}

/** b54 (pre-audit T-1, cross-protocol signature oracle): the identity-bind
 *  challenge is RELAY-CHOSEN. Signing it raw let a malicious relay pick
 *  32 bytes that are its own X25519 key and receive a valid SPK_sig (also a
 *  raw signature over 32 bytes). The client now signs only a domain-separated
 *  message: utf8("vardum-identity-bind-v1:") || nonce || utf8(":" + veil_id). */
export const BIND_SIG_LABEL = 'vardum-identity-bind-v1:';
export function bindChallengeMessage(nonceB64: string, veilId: string): Uint8Array {
  return concat(utf8(BIND_SIG_LABEL), fromB64(nonceB64), utf8(':' + veilId));
}
