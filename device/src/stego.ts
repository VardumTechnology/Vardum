/**
 * @veil/device — steganographic embed/extract (web parity, extracted from
 * the live bundle Tools-ES0JAH-6.js on Sept 19 2026).
 *
 * Payload format (byte-exact):
 *   [8B magic "VEILSTG1"][1B encrypted flag 0|1][4B u32 BE payload length][payload]
 *   max payload 262,144 bytes; message up to 256 KB of text (b57 raise).
 *   encrypted payload (optional passphrase): [16B salt][12B iv][AES-256-GCM ct]
 *   key = PBKDF2-SHA256(passphrase, salt, 600k) — same derivation as vaults.
 *
 * Embedding: LSB into the R,G,B channels (alpha untouched), 1 bit per channel
 * byte, MSB-first, pixels in reading order; capacity check
 *   bits needed = (13 + payload length) * 8  <=  floor(data.length / 4) * 3
 * Output is always PNG (lossless — the payload survives; the web warns that
 * re-uploading through any lossy pipeline destroys it).
 *
 * b71 (audit F-23): WITH a passphrase the stream is v2 — no magic, no clear
 * length: [16B salt][12B iv][AES-256-GCM( [4B u32 BE length][message][random] )]
 * filling the WHOLE carrier, so every LSB of the image looks like noise and
 * neither the message nor its size can be found without the passphrase.
 * WITHOUT a passphrase the v1 format above stays (nothing can hide it; the app
 * says so). Old v1 images still open.
 *
 * b75 (audit VS-1 / VS-2): v2 replaced EVERY red/green/blue low bit, which a
 * pairs-of-values test spots at once (the low-bit plane of a real photo is not
 * random). Passphrase images are now v3 (embedStego):
 *   - a random 16-byte salt in the first 128 channel low bits (read in order);
 *   - master = PBKDF2-SHA256(passphrase, salt, 600k); HKDF-SHA256 gives a position
 *     key, a length pad and the AES-256-GCM key (one key per image, so a zero IV);
 *   - only the bits the message needs ([4B length XOR pad][AES-GCM(message)]) go
 *     into channels chosen by a ChaCha20 stream under the position key, spread over
 *     the whole picture; nobody without the passphrase knows which ones;
 *   - each of those channels gets its low bit by +-1 matching (add or subtract one
 *     at random), not by overwriting it, so the pairs-of-values signature is gone;
 *   - every random fill is done in 64 KiB pieces (getRandomValues refuses more:
 *     v2 threw on any carrier over ~175k pixels).
 * Old v2 images still open (one PBKDF2 serves both: same salt place, same KDF).
 * Not claimed: resistance to a determined steganalyst with modern tools; a lossy
 * re-encode destroys the message.
 */
import { utf8 } from '../../crypto-core/src/index';
import { aesGcmKey, pbkdf2Sha256Bytes, VAULT_PBKDF2_ITERATIONS } from './kdf';
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha256';
import { chacha20 } from '@noble/ciphers/chacha';

export const STEGO_MAGIC = 'VEILSTG1';
export const STEGO_HEADER_BYTES = 13;
export const STEGO_MAX_PAYLOAD = 262144; // b57: 32 KB -> 256 KB (owner request)
export const STEGO_MAX_MESSAGE = 262144;

function magicBytes(): Uint8Array {
  return utf8(STEGO_MAGIC);
}

/** web J(): capacity in BITS — floor(pixels) * 3 channel bytes. */
export function stegoCapacityBits(rgbaByteLength: number): number {
  // Batch E (F-7): ONE bit per R, G, B byte. This used to multiply by 8 more, so
  // the capacity checks passed for carriers 8x too small and lsbEmbed silently
  // wrote a truncated stream.
  return Math.floor(rgbaByteLength / 4) * 3;
}

/** web rt(): optional-payload encryption — salt16 + iv12 + AES-256-GCM. */
export async function encryptStegoPayload(message: string, passphrase: string): Promise<Uint8Array> {
  const salt = new Uint8Array(16);
  const iv = new Uint8Array(12);
  globalThis.crypto.getRandomValues(salt);
  globalThis.crypto.getRandomValues(iv);
  const key = await aesGcmKey(await pbkdf2Sha256Bytes(passphrase, salt, VAULT_PBKDF2_ITERATIONS));
  const ct = new Uint8Array(
    await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv as unknown as BufferSource }, key, utf8(message) as unknown as BufferSource),
  );
  const out = new Uint8Array(28 + ct.byteLength);
  out.set(salt, 0);
  out.set(iv, 16);
  out.set(ct, 28);
  return out;
}

/** web it(): payload decryption — salt + iv prefix, AES-256-GCM. */
export async function decryptStegoPayload(payload: Uint8Array, passphrase: string): Promise<string> {
  if (payload.length < 29) throw new Error('Corrupted payload');
  const salt = payload.slice(0, 16);
  const iv = payload.slice(16, 28);
  const key = await aesGcmKey(await pbkdf2Sha256Bytes(passphrase, salt, VAULT_PBKDF2_ITERATIONS));
  const pt = new Uint8Array(
    await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: iv as unknown as BufferSource },
      key,
      payload.slice(28) as unknown as BufferSource,
    ),
  );
  return new TextDecoder().decode(pt);
}

/** b75 (audit VS-2): crypto.getRandomValues takes at most 64 KiB per call */
export function fillRandom(buf: Uint8Array): Uint8Array {
  for (let i = 0; i < buf.length; i += 65536) globalThis.crypto.getRandomValues(buf.subarray(i, Math.min(i + 65536, buf.length)));
  return buf;
}

/** b75 (audit VS-1): a file name like a camera's, nothing that says Vardum or stego */
export function neutralImageName(at: Date = new Date(), ext = 'png'): string {
  const p = (n: number) => String(n).padStart(2, '0');
  return 'IMG_' + at.getFullYear() + p(at.getMonth() + 1) + p(at.getDate()) + '_' + p(at.getHours()) + p(at.getMinutes()) + p(at.getSeconds()) + '.' + ext;
}

/** v3: the first channels hold the salt (read in order, like v2's salt) */
const V3_SALT_SLOTS = 128;
const V3_INFO_POS = utf8('vardum-stego-v3-pos');
const V3_INFO_LEN = utf8('vardum-stego-v3-len');
const V3_INFO_ENC = utf8('vardum-stego-v3-enc');
const ZERO_IV = new Uint8Array(12);

/** channel number (red/green/blue only, in reading order) -> byte offset in RGBA */
const chanAt = (i: number): number => ((i / 3) | 0) * 4 + (i % 3);

/** b75 (VS-1): the channels the message bits go into, in order: distinct, keyed by
 *  the passphrase (ChaCha20 under the position key), never the salt channels. The
 *  first k positions are the same whatever the count, so the reader can take the
 *  length first. */
function v3Positions(posKey: Uint8Array, channels: number, count: number): Uint32Array {
  const span = channels - V3_SALT_SLOTS;
  if (count > span) throw new Error('Image is too small to hold this message');
  const used = new Uint8Array(Math.ceil(span / 8));
  const out = new Uint32Array(count);
  let ks: Uint8Array = new Uint8Array(0);
  let ksAt = 0;
  let block = 0;
  const nonce = new Uint8Array(12);
  const limit = Math.floor(0x100000000 / span) * span; // unbiased draws
  for (let n = 0; n < count;) {
    if (ksAt + 4 > ks.length) {
      new DataView(nonce.buffer).setUint32(0, block++);
      ks = chacha20(posKey, nonce, new Uint8Array(65536));
      ksAt = 0;
    }
    const r = ((ks[ksAt] << 24) | (ks[ksAt + 1] << 16) | (ks[ksAt + 2] << 8) | ks[ksAt + 3]) >>> 0;
    ksAt += 4;
    if (r >= limit) continue;
    const i = r % span;
    if (used[i >> 3] & (1 << (i & 7))) continue;
    used[i >> 3] |= 1 << (i & 7);
    out[n++] = V3_SALT_SLOTS + i;
  }
  return out;
}

function v3Keys(master: Uint8Array, salt: Uint8Array): { pos: Uint8Array; pad: Uint8Array; enc: Uint8Array } {
  return { pos: hkdf(sha256, master, salt, V3_INFO_POS, 32), pad: hkdf(sha256, master, salt, V3_INFO_LEN, 4), enc: hkdf(sha256, master, salt, V3_INFO_ENC, 32) };
}

/** +-1 matching: give channel byte off the low bit `bit` by adding or subtracting one */
function matchBit(rgba: Uint8Array, off: number, bit: number, coin: number): void {
  const v = rgba[off];
  if ((v & 1) === bit) return;
  rgba[off] = v === 0 ? 1 : v === 255 ? 254 : (coin & 1 ? v + 1 : v - 1);
}

/** b75 (audit VS-1 / VS-2): hide the message in rgba, in place. With a passphrase: v3
 *  (keyed positions, +-1 matching, only the bits needed). Without: v1 (findable). */
export async function embedStego(rgba: Uint8Array, message: string, passphrase: string | null): Promise<void> {
  if (!passphrase) { lsbEmbed(rgba, await buildStegoStream(message, null, rgba.length)); return; }
  const msg = utf8(message);
  if (msg.length === 0) throw new Error('Message is empty');
  if (msg.length > STEGO_MAX_MESSAGE) throw new Error('Message exceeds the 256 KB limit');
  const channels = stegoCapacityBits(rgba.length);
  const bits = (4 + msg.length + 16) * 8;
  // the room is checked before the (slow) key derivation
  if (V3_SALT_SLOTS + bits > channels) throw new Error('Image is too small to hold this message');
  const salt = fillRandom(new Uint8Array(16));
  const master = await pbkdf2Sha256Bytes(passphrase, salt, VAULT_PBKDF2_ITERATIONS);
  const k = v3Keys(master, salt);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: ZERO_IV as unknown as BufferSource }, await aesGcmKey(k.enc), msg as unknown as BufferSource));
  const body = new Uint8Array(4 + ct.length);
  new DataView(body.buffer).setUint32(0, msg.length);
  for (let i = 0; i < 4; i++) body[i] ^= k.pad[i];
  body.set(ct, 4);
  const coins = fillRandom(new Uint8Array(V3_SALT_SLOTS + bits));
  for (let i = 0; i < V3_SALT_SLOTS; i++) matchBit(rgba, chanAt(i), (salt[i >> 3] >> (7 - (i & 7))) & 1, coins[i]);
  const pos = v3Positions(k.pos, channels, bits);
  for (let i = 0; i < bits; i++) matchBit(rgba, chanAt(pos[i]), (body[i >> 3] >> (7 - (i & 7))) & 1, coins[V3_SALT_SLOTS + i]);
}

/** v3 read with the master key derived from the in-order salt; null when it isn't v3 */
async function extractV3(rgba: Uint8Array, master: Uint8Array, salt: Uint8Array): Promise<string | null> {
  const channels = stegoCapacityBits(rgba.length);
  if (channels < V3_SALT_SLOTS + (4 + 16) * 8) return null;
  const k = v3Keys(master, salt);
  const readBits = (pos: Uint32Array, from: number, nBytes: number) => {
    const out = new Uint8Array(nBytes);
    for (let i = 0; i < nBytes * 8; i++) out[i >> 3] |= (rgba[chanAt(pos[from + i])] & 1) << (7 - (i & 7));
    return out;
  };
  const head = readBits(v3Positions(k.pos, channels, 32), 0, 4);
  for (let i = 0; i < 4; i++) head[i] ^= k.pad[i];
  const len = new DataView(head.buffer).getUint32(0);
  const bits = (4 + len + 16) * 8;
  if (len === 0 || len > STEGO_MAX_MESSAGE || V3_SALT_SLOTS + bits > channels) return null;
  const ct = readBits(v3Positions(k.pos, channels, bits), 32, len + 16);
  try {
    const pt = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: ZERO_IV as unknown as BufferSource }, await aesGcmKey(k.enc), ct as unknown as BufferSource));
    return new TextDecoder().decode(pt);
  } catch { return null; }
}

/** b71 (audit F-23): the passphrase stream (v2), sized to fill the carrier.
 *  b75 (audit VS-1): no longer written (new images are v3); kept to document v2 */
async function buildStegoStreamV2(message: string, passphrase: string, rgbaLength?: number): Promise<Uint8Array> {
  const msg = utf8(message);
  if (msg.length === 0) throw new Error('Message is empty');
  if (msg.length > STEGO_MAX_MESSAGE) throw new Error('Message exceeds the 256 KB limit');
  const need = 28 + 16 + 4 + msg.length;
  // without a carrier size (self-test), round up to whole KB
  const total = rgbaLength !== undefined ? Math.floor(stegoCapacityBits(rgbaLength) / 8) : Math.ceil(need / 1024) * 1024;
  if (need > total) throw new Error('Image is too small to hold this message');
  const plain = fillRandom(new Uint8Array(total - 28 - 16)); // b75 (audit VS-2): 64 KiB at a time
  new DataView(plain.buffer).setUint32(0, msg.length);
  plain.set(msg, 4);
  const salt = new Uint8Array(16);
  const iv = new Uint8Array(12);
  globalThis.crypto.getRandomValues(salt);
  globalThis.crypto.getRandomValues(iv);
  const key = await aesGcmKey(await pbkdf2Sha256Bytes(passphrase, salt, VAULT_PBKDF2_ITERATIONS));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv as unknown as BufferSource }, key, plain as unknown as BufferSource));
  const out = new Uint8Array(28 + ct.byteLength);
  out.set(salt, 0);
  out.set(iv, 16);
  out.set(ct, 28);
  return out;
}

/** web at(): build the full embedded stream for an RGBA buffer. */
export async function buildStegoStream(message: string, passphrase: string | null, rgbaLength?: number): Promise<Uint8Array> {
  // b75 (audit VS-1): a passphrase image is v3, written by embedStego (it needs the
  // carrier itself); the v2 whole-plane stream is no longer produced
  if (passphrase) throw new Error('A passphrase image is made with embedStego');
  void buildStegoStreamV2;
  // Batch E (Superagent round 3, F-7): check the carrier's room BEFORE the (slow)
  // passphrase encryption. Encrypted payloads add salt 16 + iv 12 + tag 16 bytes.
  if (rgbaLength !== undefined && (STEGO_HEADER_BYTES + utf8(message).length + (passphrase ? 44 : 0)) * 8 > stegoCapacityBits(rgbaLength)) {
    throw new Error('Image is too small to hold this message');
  }
  const payload = passphrase ? await encryptStegoPayload(message, passphrase) : utf8(message);
  if (payload.length === 0) throw new Error('Message is empty');
  if (payload.length > STEGO_MAX_PAYLOAD) throw new Error('Message exceeds the 256 KB limit');
  const stream = new Uint8Array(STEGO_HEADER_BYTES + payload.length);
  stream.set(magicBytes(), 0);
  stream[8] = passphrase ? 1 : 0;
  new DataView(stream.buffer).setUint32(9, payload.length);
  stream.set(payload, STEGO_HEADER_BYTES);
  return stream;
}

/** web at() LSB write: bits into R,G,B of each pixel, MSB-first, alpha untouched. */
export function lsbEmbed(rgba: Uint8Array, stream: Uint8Array): void {
  const bits = stream.length * 8;
  if (bits > stegoCapacityBits(rgba.length)) throw new Error('Image is too small to hold this message');
  let u = 0;
  for (let p = 0; p < rgba.length && u < bits; p += 4) {
    for (let c = 0; c < 3 && u < bits; c++) {
      rgba[p + c] = (rgba[p + c] & 0xfe) | ((stream[u >> 3] >> (7 - (u & 7))) & 1);
      u++;
    }
  }
}

/** web ot(): LSB read back n bytes from an RGBA buffer. */
export function lsbExtract(rgba: Uint8Array, byteCount: number): Uint8Array {
  const out = new Uint8Array(byteCount);
  const bits = byteCount * 8;
  let a = 0;
  for (let p = 0; p < rgba.length && a < bits; p += 4) {
    for (let c = 0; c < 3 && a < bits; c++) {
      out[a >> 3] |= (rgba[p + c] & 1) << (7 - (a & 7));
      a++;
    }
  }
  return out;
}

/** web st(): extract a hidden message from RGBA pixels. */
export async function extractStego(rgba: Uint8Array, passphrase: string | null): Promise<string> {
  const header = lsbExtract(rgba, STEGO_HEADER_BYTES);
  if (new TextDecoder().decode(header.slice(0, 8)) !== STEGO_MAGIC) {
    // b71 (audit F-23): a v2 (passphrase) image has no marker — try the passphrase
    if (!passphrase) throw new Error('No Vardum message found. If it was hidden with a passphrase, enter it.');
    const total = Math.floor(stegoCapacityBits(rgba.length) / 8);
    if (total < 28 + 16 + 4) throw new Error('No Vardum message found in this image');
    // b75 (audit VS-1): v3 first, then v2. The salt sits in the same place, so one key
    // derivation serves both.
    const salt = lsbExtract(rgba, 16);
    const master = await pbkdf2Sha256Bytes(passphrase, salt, VAULT_PBKDF2_ITERATIONS);
    const v3 = await extractV3(rgba, master, salt);
    if (v3 !== null) return v3;
    const all = lsbExtract(rgba, total);
    let plain: Uint8Array;
    try {
      const key = await aesGcmKey(master);
      plain = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: all.slice(16, 28) as unknown as BufferSource }, key, all.slice(28) as unknown as BufferSource));
    } catch {
      throw new Error('No Vardum message found, or the passphrase is wrong');
    }
    const len = new DataView(plain.buffer, plain.byteOffset).getUint32(0);
    if (len > plain.length - 4) throw new Error('Corrupted payload');
    return new TextDecoder().decode(plain.subarray(4, 4 + len));
  }
  const encrypted = header[8] === 1;
  const payloadLen = new DataView(header.buffer).getUint32(9);
  if (payloadLen > STEGO_MAX_PAYLOAD || STEGO_HEADER_BYTES + payloadLen > stegoCapacityBits(rgba.length) / 8) {
    throw new Error('Corrupted payload');
  }
  const payload = lsbExtract(rgba, STEGO_HEADER_BYTES + payloadLen).slice(STEGO_HEADER_BYTES);
  if (encrypted) {
    if (!passphrase) throw new Error('This payload is encrypted — enter the passphrase');
    return decryptStegoPayload(payload, passphrase);
  }
  return new TextDecoder().decode(payload);
}
