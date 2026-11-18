/**
 * @veil/crypto-core — the size scheme: padded message frames, padded blob frames, cover filler.
 *
 * b76 (padding everywhere, spec §8.3): every ciphertext that leaves the phone or is stored by
 * the relay is padded INSIDE its AEAD by one of two frames, under one documented size rule:
 *
 *   - Message frames (1:1 ratchet messages, group posts and group control messages) take the
 *     smallest of the MESSAGE CLASSES [1024, 4096, 16384, 32768] — powers of four from a
 *     1 KiB floor, capped by the relay's envelope limit — that holds them. Envelopes are small
 *     and frequent, so a few coarse classes cost little and leak at most which class.
 *   - Blob frames (media files, device-move bundles, group names) take PADME of their length
 *     (Nikitin et al., PETS 2019) with a floor (1 KiB; 256 bytes for names). Blobs can be
 *     large, so powers of two or four would cost up to 100–300 %; PADME costs at most 12 %
 *     (about 1 % on average for photos and videos, spec §8.3) and a size leaks only
 *     O(log log n) bits.
 *
 * Every frame carries its own length and is stripped strictly: the frame must be exactly the
 * length its content needs, every padding byte must be zero, and anything else is refused. So
 * a padded frame has one spelling, and a mismatched length is never accepted.
 *
 * Message frame (1:1 ratchet, §4.8; groups, §11.8):
 *   [1 byte cover flag 0|1][2 bytes BE length][utf8 text][sender trailer?][zero padding]
 * b70 (audit L-1): the optional sender trailer right after the text:
 *   [0xA7][8 bytes BE sent-at ms][4 bytes BE sequence]
 * The relay can no longer set a message's time or order unseen.
 *
 * Blob frame (b76):
 *   [0x56 'V'][0x01 version][4 bytes BE length][bytes][zero padding]
 * sized so that the CIPHERTEXT (frame + the 16-byte GCM tag) is exactly blobPaddedLength(...).
 */

import { utf8, fromUtf8Strict } from './bytes';
import { PAD_FRAME_HEADER_BYTES, PADDED_BUCKETS } from './constants';

/** b76: the classes a message frame may take (1:1 uses the first two, PADDED_BUCKETS; group
 *  posts the first two; group control messages all four). A receipt, a reaction, a call signal
 *  and a short text all land in the first. */
export const MESSAGE_CLASSES: readonly number[] = [1024, 4096, 16384, 32768];
/** b76: a blob's ciphertext is never shorter than this (group names: GROUP_NAME_FLOOR, 256) */
export const BLOB_FLOOR = 1024;
/** AES-GCM tag length: blob frames are sized so frame + tag is the padded length */
export const GCM_TAG_BYTES = 16;

/** floor(log2 n) for a positive safe integer, exactly (no floating-point rounding near powers of two) */
function ilog2(n: number): number {
  let e = 0;
  while (2 ** (e + 1) <= n) e++;
  return e;
}

/** PADME (Nikitin, Barman, Lueks, Underwood, Hubaux, Ford: "Reducing Metadata Leakage from
 *  Encrypted Files and Communication with PURBs", PETS 2019, §4): E = floor(log2 L),
 *  S = floor(log2 E) + 1, and the low E − S bits of L are rounded up to zero.
 *  Arithmetic (not 32-bit bit operations), so it is exact for any safe integer. */
export function padmeLength(len: number): number {
  if (!Number.isSafeInteger(len) || len < 0) throw new Error('Bad length');
  if (len < 2) return len;
  const e = ilog2(len);
  const s = ilog2(e) + 1;
  const step = 2 ** (e - s);
  return Math.ceil(len / step) * step;
}

/** b76: the padded length of a blob of n bytes (ciphertext, tag included): PADME, with a floor */
export function blobPaddedLength(n: number, floor = BLOB_FLOOR): number {
  if (!Number.isSafeInteger(n) || n < 0) throw new Error('Bad length');
  return n <= floor ? floor : padmeLength(n);
}

// ---------- message frames ----------

/** b70 (L-1): what the sender says about a message, authenticated with it */
export interface PlainMeta { sentAt: number; seq: number }
const META_MAGIC = 0xa7;
export const META_TRAILER_BYTES = 13;

/** b76: pad a message into the smallest of `classes` that holds it (header, text, trailer).
 *  Throws (before anything else happens) when it fits none. */
export function padMessageFrame(text: string, cover: boolean, meta: PlainMeta | undefined, classes: readonly number[]): Uint8Array {
  const payload = utf8(text);
  if (payload.length > 0xffff) throw new Error('Message too long for the padded bucket sizes');
  const total = PAD_FRAME_HEADER_BYTES + payload.length + (meta ? META_TRAILER_BYTES : 0);
  const bucket = classes.find((b) => b >= total);
  if (!bucket) throw new Error('Message too long for the padded bucket sizes');
  const frame = new Uint8Array(bucket);
  frame[0] = cover ? 1 : 0;
  const dv = new DataView(frame.buffer);
  dv.setUint16(1, payload.length);
  frame.set(payload, PAD_FRAME_HEADER_BYTES);
  if (meta) {
    const at = PAD_FRAME_HEADER_BYTES + payload.length;
    frame[at] = META_MAGIC;
    // two 32-bit halves (no BigInt DataView methods on every JS engine)
    const ms = Math.max(0, Math.floor(meta.sentAt));
    dv.setUint32(at + 1, Math.floor(ms / 0x100000000));
    dv.setUint32(at + 5, ms % 0x100000000);
    dv.setUint32(at + 9, meta.seq >>> 0);
  }
  return frame;
}

function textOf(b: Uint8Array, bad: () => Error): string {
  try { return fromUtf8Strict(b); } catch { throw bad(); }
}

/** b76: strip a message frame, strictly. Refused unless: the frame is one of `classes`; the
 *  flag is 0 or 1; the text fits; what follows the text is either a well-formed trailer or
 *  nothing; every byte after that is zero; and the frame is exactly the smallest class that
 *  holds its content (one spelling per message — no frame larger than it needs to be).
 *  b76r1 (audit P-2): and the text is well-formed UTF-8. */
export function unpadMessageFrame(bytes: Uint8Array, classes: readonly number[], what = 'message'): { cover: boolean; text: string; meta?: PlainMeta } {
  const bad = () => new Error(`Corrupted ${what} payload`);
  if (!classes.includes(bytes.length)) throw bad();
  if (bytes[0] !== 0 && bytes[0] !== 1) throw bad();
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const len = dv.getUint16(1);
  const end = PAD_FRAME_HEADER_BYTES + len;
  if (end > bytes.length) throw bad();
  let meta: PlainMeta | undefined;
  let contentEnd = end;
  if (end < bytes.length && bytes[end] === META_MAGIC) {
    if (end + META_TRAILER_BYTES > bytes.length) throw bad();
    const sentAt = dv.getUint32(end + 1) * 0x100000000 + dv.getUint32(end + 5);
    if (!Number.isSafeInteger(sentAt)) throw bad();
    meta = { sentAt, seq: dv.getUint32(end + 9) };
    contentEnd = end + META_TRAILER_BYTES;
  }
  for (let i = contentEnd; i < bytes.length; i++) if (bytes[i] !== 0) throw bad();
  if (classes.find((b) => b >= contentEnd) !== bytes.length) throw bad();
  return {
    cover: bytes[0] === 1,
    // b76r1 (audit P-2): strict UTF-8 — a malformed text (e.g. a lone 0xFF) is refused, never read
    // as U+FFFD, so the one-spelling rule above also holds for the text bytes
    text: textOf(bytes.subarray(PAD_FRAME_HEADER_BYTES, end), bad),
    ...(meta ? { meta } : {}),
  };
}

/** 1:1 ratchet frame (§4.8): buckets [1024, 4096] — the first two message classes */
export function padPlaintext(text: string, cover: boolean, meta?: PlainMeta): Uint8Array {
  return padMessageFrame(text, cover, meta, PADDED_BUCKETS);
}

/** 1:1 ratchet frame, stripped strictly (b76: see unpadMessageFrame) */
export function unpadPlaintext(bytes: Uint8Array): { cover: boolean; text: string; meta?: PlainMeta } {
  return unpadMessageFrame(bytes, PADDED_BUCKETS);
}

/**
 * b197 (audit M-4): split text into chunks that each fit the largest padded
 * bucket, at UTF-8-safe code-point boundaries (a surrogate pair or multi-byte
 * character is never split). No-op for messages that already fit.
 * b70: room is kept for the sender trailer.
 * b77p (audit VAR-28): `reserveBytes` keeps room in every chunk for a prefix the caller adds after the
 * split (the 3-byte word joiner userText puts before a chunk that starts like JSON), so no chunk can
 * outgrow the largest bucket after it was split.
 */
/** b77p (audit VAR-28): the most UTF-8 text bytes one 1:1 message frame holds (largest bucket, trailer kept) */
export const BUCKET_TEXT_MAX = PADDED_BUCKETS[PADDED_BUCKETS.length - 1] - PAD_FRAME_HEADER_BYTES - META_TRAILER_BYTES;
export function splitForBuckets(text: string, reserveBytes = 0): string[] {
  const max = BUCKET_TEXT_MAX - Math.max(0, Math.floor(reserveBytes));
  if (utf8(text).length <= max) return [text];
  const enc = new TextEncoder();
  const chunks: string[] = [];
  let cur = '';
  let curBytes = 0;
  for (const ch of Array.from(text)) { // code points — surrogate-safe
    const b = enc.encode(ch).length;
    if (curBytes + b > max && cur) { chunks.push(cur); cur = ''; curBytes = 0; }
    cur += ch;
    curBytes += b;
  }
  if (cur) chunks.push(cur);
  return chunks;
}

// ---------- blob frames ----------

const BLOB_MAGIC = 0x56; // 'V'
const BLOB_VERSION = 0x01;
/** b76: blob frame header: magic, version, 4-byte BE length */
export const BLOB_HEADER_BYTES = 6;
/** b76: what a blob frame adds before padding, GCM tag included */
export const BLOB_OVERHEAD_BYTES = BLOB_HEADER_BYTES + GCM_TAG_BYTES;

/** b76: the frame length for `n` content bytes — so that frame + tag = blobPaddedLength(header + n + tag) */
export function blobFrameLength(n: number, floor = BLOB_FLOOR): number {
  return blobPaddedLength(BLOB_OVERHEAD_BYTES + n, floor) - GCM_TAG_BYTES;
}

/** b76: pad bytes into a blob frame (encrypt the result with AES-GCM: the ciphertext is then
 *  exactly blobPaddedLength(n + 22)) */
export function padBlob(bytes: Uint8Array, floor = BLOB_FLOOR): Uint8Array {
  if (bytes.length > 0xffffffff) throw new Error('Too large to pad');
  const frame = new Uint8Array(blobFrameLength(bytes.length, floor));
  frame[0] = BLOB_MAGIC;
  frame[1] = BLOB_VERSION;
  new DataView(frame.buffer).setUint32(2, bytes.length);
  frame.set(bytes, BLOB_HEADER_BYTES);
  return frame;
}

/** b76: strip a blob frame, strictly: magic and version, a length that fits, every padding
 *  byte zero, and the frame exactly the length its content needs (a frame of any other length
 *  — truncated, extended, or padded further — is refused). Returns a view. */
export function unpadBlob(frame: Uint8Array, floor = BLOB_FLOOR): Uint8Array {
  const bad = () => new Error('This item is damaged or from an older version, so it was not opened.');
  if (frame.length < BLOB_HEADER_BYTES || frame[0] !== BLOB_MAGIC || frame[1] !== BLOB_VERSION) throw bad();
  const len = new DataView(frame.buffer, frame.byteOffset, frame.byteLength).getUint32(2);
  if (BLOB_HEADER_BYTES + len > frame.length) throw bad();
  if (blobFrameLength(len, floor) !== frame.length) throw bad();
  for (let i = BLOB_HEADER_BYTES + len; i < frame.length; i++) if (frame[i] !== 0) throw bad();
  return frame.subarray(BLOB_HEADER_BYTES, BLOB_HEADER_BYTES + len);
}

// ---------- cover filler ----------

/** b71 (audit) / b76: cover filler whose padded size follows real messages — 85 % land
 *  in the 1 KiB class (as short texts, receipts, reactions and call signals do), the rest in
 *  the 4 KiB one. Random hex of a random length from the CSPRNG. Used by 1:1 cover and (b76)
 *  group cover, which before b76 always fell in the 1 KiB class.
 *  b76r1 (audit AUD-I2): the long branch used to be 550–2448 characters, so about a quarter of it
 *  still fit 1 KiB and the real split was about 88.6 % / 11.4 %. It is 1100–2998 characters now
 *  (always the 4 KiB class, with or without the 13-byte trailer), and the short branch stays 16–974
 *  (always 1 KiB, trailer included), so the split is the 85 / 15 the spec states. */
export function coverFillerText(): string {
  const rnd = crypto.getRandomValues(new Uint16Array(2));
  const hexLen = rnd[0] % 100 < 85 ? 16 + (rnd[1] % 480) * 2 : 1100 + (rnd[1] % 950) * 2;
  const bytes = crypto.getRandomValues(new Uint8Array(Math.ceil(hexLen / 2)));
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('').slice(0, hexLen);
}
