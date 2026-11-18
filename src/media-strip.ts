/**
 * b77s (audit 4 DV-4): every picked image is re-encoded before it is sent, so the camera metadata
 * the picker copies into its result (EXIF make, model, original time, image unique id, maker note;
 * Android already redacts GPS, iOS was not verified) never leaves the phone. The re-encode used to
 * run only for JPEG/HEIC over 2048 px, and was kept only when smaller.
 *
 *  - JPEG / HEIC / HEIF and any other still image: re-encoded as JPEG (shrunk to 2048 px if larger);
 *  - PNG: b77s (confirmation review, stego regression) NOT decoded or resized — the metadata chunks are removed
 *    LOSSLESSLY (stripPngMetadata): the file is rewritten keeping only the chunks that draw the pixels, with the
 *    image data (IDAT) byte for byte. A re-encode (and the 2048 px resize) destroyed a hidden (stego) message, and
 *    even a same-size re-encode through the image library is not guaranteed pixel-exact;
 *  - WebP: re-encoded as PNG, so transparency is kept;
 *  - GIF: b77u (audit 6 W10 / IH full L-9) its comment, text and application blocks (XMP, editor tags) are removed
 *    losslessly (stripGifMetadata); the frames and the loop count are kept byte for byte;
 *  - video: b77u (audit 6 W10) MP4 / MOV / 3GP (ISO base media files): every metadata box (udta, meta, uuid: the
 *    iOS location, make, model, software, XMP) is overwritten in place with a 'free' box of the same size, and the
 *    creation / modification times in mvhd, tkhd and mdhd are zeroed (neutralizeVideoMetadata). Nothing moves, so the
 *    chunk offsets stay valid. Any other video format (WebM, …) can't be cleaned here: the app says so plainly and
 *    asks before sending it (VIDEO_META_WARNING).
 *
 * Pure module (no React Native imports) so App.tsx and the tests share it.
 */

export interface ImageReencodePlan {
  /** 'png-strip': a PNG, its metadata chunks removed losslessly (stripPngMetadata) — never decoded or resized */
  format: 'jpeg' | 'png' | 'png-strip';
  /** the new long edge, when the image is larger than the cap */
  resize?: { width: number; height: number };
  /** the sent file's extension and MIME type */
  ext: 'jpg' | 'png';
  mime: 'image/jpeg' | 'image/png';
}

/** null = sent as it is (not a still image, or a GIF) */
export function imageReencodePlan(
  a: { type?: string | null; mime?: string | null; width?: number | null; height?: number | null },
  maxEdge: number,
): ImageReencodePlan | null {
  const mime = String(a.mime || '').toLowerCase();
  const isImage = a.type === 'image' || (!a.type && mime.startsWith('image/'));
  if (!isImage) return null;
  if (mime === 'image/gif') return null;
  // b77s (confirmation review): a PNG keeps its pixels exactly (a stego message survives) — no resize
  if (mime === 'image/png') return { format: 'png-strip', ext: 'png', mime: 'image/png' };
  const png = mime === 'image/webp';
  const w = Math.max(0, Math.floor(a.width || 0)), h = Math.max(0, Math.floor(a.height || 0));
  const long = Math.max(w, h);
  const resize = w > 0 && h > 0 && long > maxEdge
    ? { width: Math.max(1, Math.round(w * (maxEdge / long))), height: Math.max(1, Math.round(h * (maxEdge / long))) }
    : undefined;
  return png
    ? { format: 'png', resize, ext: 'png', mime: 'image/png' }
    : { format: 'jpeg', resize, ext: 'jpg', mime: 'image/jpeg' };
}

/** the sent file's name: the picked name's extension replaced by the re-encoded one */
export function reencodedName(name: string, ext: string): string {
  const base = String(name || 'media').replace(/\.[A-Za-z0-9]{1,5}$/, '') || 'media';
  return `${base}.${ext}`;
}

/**
 * b77t (audit 5 L-19 / IH DEV-3): the name a picked file is sent under. Never the picked name: camera
 * apps name files after the capture time and device (PXL_20261101_093012345.jpg), screenshots after the
 * app on screen. The sent name says only the kind and the format: image.jpg, video.mp4, audio.m4a, file.bin.
 */
const SEND_EXT: Record<string, string> = {
  'image/jpeg': 'jpg', 'image/jpg': 'jpg', 'image/png': 'png', 'image/gif': 'gif', 'image/webp': 'webp', 'image/heic': 'heic', 'image/heif': 'heif',
  'video/mp4': 'mp4', 'video/quicktime': 'mov', 'video/webm': 'webm', 'video/3gpp': '3gp',
  'audio/mp4': 'm4a', 'audio/m4a': 'm4a', 'audio/x-m4a': 'm4a', 'audio/aac': 'aac', 'audio/mpeg': 'mp3', 'audio/ogg': 'ogg', 'audio/wav': 'wav',
};
export function neutralSendName(mime: string | null | undefined, pickedName?: string | null): string {
  const m = String(mime || '').toLowerCase();
  const kind = m.startsWith('image/') ? 'image' : m.startsWith('video/') ? 'video' : m.startsWith('audio/') ? 'audio' : 'file';
  // the picked name's extension only when the MIME type gives none (an extension names a format, nothing more)
  const fromName = /\.([A-Za-z0-9]{1,5})$/.exec(String(pickedName || ''))?.[1]?.toLowerCase();
  const ext = SEND_EXT[m] ?? fromName ?? 'bin';
  return `${kind}.${ext}`;
}

/** shown when an image could not be re-encoded (it is never sent with its metadata) */
export const IMAGE_STRIP_FAILED = 'This image couldn’t be prepared for sending (Vardum removes the camera details from every photo first). Try a different image.';

/**
 * b77s (confirmation review, stego regression): the chunks a stripped PNG keeps — the critical ones (IHDR, PLTE, IDAT,
 * IEND) and the ancillary ones that change how the pixels are drawn and carry nothing about the camera, the person
 * or the time: tRNS (transparency), gAMA / cHRM / sRGB / sBIT / cICP (colour, fixed small values) and the APNG
 * animation chunks (acTL / fcTL / fdAT: frames, not metadata). Everything else goes: tEXt / zTXt / iTXt (text, XMP),
 * eXIf, tIME, pHYs, iCCP (an embedded profile can name the device), bKGD, hIST, sPLT, private chunks.
 */
export const PNG_KEPT_CHUNKS: ReadonlySet<string> = new Set(['IHDR', 'PLTE', 'IDAT', 'IEND', 'tRNS', 'gAMA', 'cHRM', 'sRGB', 'sBIT', 'cICP', 'acTL', 'fcTL', 'fdAT']);
const PNG_SIGNATURE = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];

/**
 * b77s (confirmation review, stego regression): removes a PNG's metadata without decoding it. The kept chunks are
 * copied whole (length, type, data, CRC), in order, so the image data is unchanged byte for byte. Throws on anything
 * that isn't a well-formed PNG (the caller refuses to send it, as for a failed re-encode).
 */
export function stripPngMetadata(png: Uint8Array): Uint8Array {
  if (png.length < 8 + 12 + 12 || PNG_SIGNATURE.some((b, i) => png[i] !== b)) throw new Error('not a PNG');
  const dv = new DataView(png.buffer, png.byteOffset, png.byteLength);
  const keep: [number, number][] = [];
  let off = 8, total = 8, first = true, ended = false;
  while (off < png.length) {
    if (off + 12 > png.length) throw new Error('truncated PNG chunk');
    const len = dv.getUint32(off);
    const end = off + 12 + len;
    if (len > 0x7fffffff || end > png.length) throw new Error('truncated PNG chunk');
    const type = String.fromCharCode(png[off + 4], png[off + 5], png[off + 6], png[off + 7]);
    if (!/^[A-Za-z]{4}$/.test(type)) throw new Error('bad PNG chunk type');
    if (first && type !== 'IHDR') throw new Error('PNG does not start with IHDR');
    first = false;
    if (PNG_KEPT_CHUNKS.has(type)) { keep.push([off, end]); total += end - off; }
    off = end;
    if (type === 'IEND') { ended = true; break; }
  }
  if (!ended) throw new Error('PNG has no IEND');
  if (!keep.some(([o]) => png[o + 4] === 0x49 && png[o + 5] === 0x44 && png[o + 6] === 0x41 && png[o + 7] === 0x54)) throw new Error('PNG has no image data');
  const out = new Uint8Array(total);
  out.set(png.subarray(0, 8), 0);
  let w = 8;
  for (const [o, e] of keep) { out.set(png.subarray(o, e), w); w += e - o; }
  return out;
}

// ---------------------------------------------------------------- b77u (audit 6 W10 / IH full L-9)

/** b77u (W10): what is done to a picked video or GIF before it is sent */
export type MotionStripPlan = 'gif-strip' | 'video-strip' | 'video-warn' | null;
const ISO_VIDEO = new Set(['video/mp4', 'video/quicktime', 'video/3gpp', 'video/3gpp2', 'video/x-m4v', 'video/m4v']);
export function motionStripPlan(mime: string | null | undefined, type?: string | null): MotionStripPlan {
  const m = String(mime || '').toLowerCase();
  if (m === 'image/gif') return 'gif-strip';
  if (m.startsWith('video/') || type === 'video') return ISO_VIDEO.has(m) ? 'video-strip' : 'video-warn';
  return null;
}

/** b77u (W10): asked before a video Vardum could not clean is sent */
export const VIDEO_META_WARNING = 'Vardum can’t remove the details stored inside this video. It may say where and when it was recorded and which phone recorded it. Send it anyway?';

/**
 * b77u (W10): a GIF without its metadata. Kept: the header, the screen descriptor and colour tables, every image
 * (graphic control extension, image descriptor, local colour table, LZW data) byte for byte, and the NETSCAPE2.0 /
 * ANIMEXTS1.0 loop block. Removed: comment blocks, plain-text blocks and every other application block (XMP,
 * editor and camera tags). Throws on a malformed GIF (the caller refuses to send it).
 */
export function stripGifMetadata(gif: Uint8Array): Uint8Array {
  const sig = String.fromCharCode(...gif.subarray(0, 6));
  if (gif.length < 14 || (sig !== 'GIF87a' && sig !== 'GIF89a')) throw new Error('not a GIF');
  const parts: [number, number][] = [];
  const flags = gif[10];
  let off = 13 + ((flags & 0x80) ? 3 * (1 << ((flags & 7) + 1)) : 0);
  if (off > gif.length) throw new Error('truncated GIF');
  parts.push([0, off]);
  const skipSubBlocks = (o: number): number => {
    while (true) {
      if (o >= gif.length) throw new Error('truncated GIF');
      const n = gif[o];
      o += 1 + n;
      if (n === 0) return o;
    }
  };
  let ended = false;
  while (off < gif.length) {
    const b = gif[off];
    if (b === 0x3b) { parts.push([off, off + 1]); ended = true; break; }
    if (b === 0x2c) { // image descriptor (+ local colour table) + LZW minimum code size + data sub-blocks
      if (off + 10 > gif.length) throw new Error('truncated GIF');
      const lf = gif[off + 9];
      let o = off + 10 + ((lf & 0x80) ? 3 * (1 << ((lf & 7) + 1)) : 0);
      o = skipSubBlocks(o + 1);
      parts.push([off, o]); off = o; continue;
    }
    if (b === 0x21) {
      if (off + 2 > gif.length) throw new Error('truncated GIF');
      const label = gif[off + 1];
      const end = skipSubBlocks(off + 2);
      let keep = label === 0xf9; // graphic control: frame delay, disposal, transparency
      if (label === 0xff && gif[off + 2] === 11) {
        const app = String.fromCharCode(...gif.subarray(off + 3, off + 14));
        keep = app === 'NETSCAPE2.0' || app === 'ANIMEXTS1.0'; // the loop count
      }
      if (keep) parts.push([off, end]);
      off = end; continue;
    }
    throw new Error('bad GIF block');
  }
  if (!ended) throw new Error('GIF has no trailer');
  const total = parts.reduce((t, [a, e]) => t + (e - a), 0);
  const out = new Uint8Array(total);
  let w = 0;
  for (const [a, e] of parts) { out.set(gif.subarray(a, e), w); w += e - a; }
  return out;
}

const META_BOXES = new Set(['udta', 'meta', 'uuid', 'XMP_']);
const DESCEND = new Set(['moov', 'trak', 'mdia', 'edts']);
const TIMED_HEADERS = new Set(['mvhd', 'tkhd', 'mdhd']);

/**
 * b77u (W10): an MP4 / MOV / 3GP with its metadata neutralised IN PLACE (a copy; the length never changes). Every
 * udta / meta / uuid box at the top level, in moov and in each track becomes a 'free' box of the same size with
 * its contents zeroed; the creation and modification times of mvhd, tkhd and mdhd are zeroed. Throws on anything
 * that isn't a well-formed ISO base media file (the caller then asks before sending it).
 */
export function neutralizeVideoMetadata(src: Uint8Array): Uint8Array {
  const buf = new Uint8Array(src); // a copy
  const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  let sawMoov = false;
  const walk = (start: number, end: number, depth: number): void => {
    let off = start;
    while (off < end) {
      if (off + 8 > end) throw new Error('truncated box');
      let size = dv.getUint32(off);
      const type = String.fromCharCode(buf[off + 4], buf[off + 5], buf[off + 6], buf[off + 7]);
      let header = 8;
      if (size === 1) {
        if (off + 16 > end) throw new Error('truncated box');
        const hi = dv.getUint32(off + 8), lo = dv.getUint32(off + 12);
        size = hi * 2 ** 32 + lo; header = 16;
      } else if (size === 0) size = end - off; // to the end of the enclosing box / file
      if (size < header || off + size > end) throw new Error('bad box size');
      if (!/^[ -~]{4}$/.test(type) && !/^©/.test(type)) throw new Error('bad box type');
      if (type === 'moov') sawMoov = true;
      if (META_BOXES.has(type)) {
        buf[off + 4] = 0x66; buf[off + 5] = 0x72; buf[off + 6] = 0x65; buf[off + 7] = 0x65; // 'free'
        buf.fill(0, off + header, off + size);
      } else if (TIMED_HEADERS.has(type) && depth > 0) {
        const v = buf[off + header];
        const t = off + header + 4; // after version + flags
        const n = v === 1 ? 16 : 8; // creation + modification time
        if (t + n <= off + size) buf.fill(0, t, t + n);
      } else if (DESCEND.has(type)) {
        walk(off + header, off + size, depth + 1);
      }
      off += size;
    }
  };
  walk(0, buf.length, 0);
  if (!sawMoov) throw new Error('no moov box');
  return buf;
}

// b77u2 (UC info): GPS in timed-metadata tracks
const TRACK_DESCEND = new Set(['moov', 'trak', 'mdia', 'minf', 'stbl']);
const TIMED_META_ENTRIES = ['gpmd', 'camm', 'mebx'];
const TIMED_META_HANDLERS = new Set(['meta', 'camm']);

/**
 * b77u2 (UC info): does this MP4 / MOV carry a timed-metadata track? GoPro GPMF ('gpmd'), camera motion ('camm') and
 * Apple's 'mebx' tracks (handler 'meta') hold their location and motion samples in mdat, which
 * neutralizeVideoMetadata never touches (it would change the media data), so such a video gets the "can't remove the
 * details" warning. Never throws (an unparsable file: false; neutralizeVideoMetadata decides about that one).
 */
export function hasTimedMetadataTrack(src: Uint8Array): boolean {
  try {
    const dv = new DataView(src.buffer, src.byteOffset, src.byteLength);
    const tag = (o: number) => String.fromCharCode(src[o], src[o + 1], src[o + 2], src[o + 3]);
    let found = false;
    const walk = (start: number, end: number): void => {
      let off = start;
      while (off + 8 <= end && !found) {
        let size = dv.getUint32(off);
        const type = tag(off + 4);
        let header = 8;
        if (size === 1) { if (off + 16 > end) return; size = dv.getUint32(off + 8) * 2 ** 32 + dv.getUint32(off + 12); header = 16; }
        else if (size === 0) size = end - off;
        if (size < header || off + size > end) return;
        if (type === 'hdlr' && off + header + 12 <= off + size) {
          if (TIMED_META_HANDLERS.has(tag(off + header + 8))) found = true; // version/flags, pre_defined, handler_type
        } else if (type === 'stsd') {
          // the sample entries' formats; scanned as bytes, so a malformed entry list can't hide one
          for (let i = off + header; i + 4 <= off + size && !found; i++) if (TIMED_META_ENTRIES.includes(tag(i))) found = true;
        } else if (TRACK_DESCEND.has(type)) {
          walk(off + header, off + size);
        }
        off += size;
      }
    };
    walk(0, src.length);
    return found;
  } catch { return false; }
}
