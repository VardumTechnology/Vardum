/**
 * audit VAR-39 (1f51): the type a received file is saved as. The MIME type comes from the
 * sender (inside the encrypted message), so it must never decide what kind of file lands on the
 * phone: a peer's 'application/vnd.android.package-archive' with "allow save" on used to write
 * vardum-<ts>.apk. Only the image, video and audio types Vardum itself sends or plays are saved,
 * under a fixed extension for each; anything else is refused (null).
 * Pure module (no React Native imports) so App.tsx and the tests share it.
 */
const SAVE_TYPES: Readonly<Record<string, string>> = Object.freeze({
  'image/jpeg': 'jpg',
  'image/png': 'png',
  'image/gif': 'gif',
  'image/webp': 'webp',
  'image/heic': 'heic',
  'image/heif': 'heif',
  'video/mp4': 'mp4',
  'video/quicktime': 'mov',
  'video/webm': 'webm',
  'video/3gpp': '3gp',
  'audio/mp4': 'm4a',
  'audio/x-m4a': 'm4a',
  'audio/m4a': 'm4a',
  'audio/aac': 'aac',
  'audio/mpeg': 'mp3',
  'audio/ogg': 'ogg',
  'audio/wav': 'wav',
  'audio/webm': 'webm',
});

/** the saved file's MIME type and extension, or null when the type is not one Vardum saves */
export function mediaSaveType(mime: string | null | undefined): { mime: string; ext: string } | null {
  if (typeof mime !== 'string') return null;
  const base = mime.split(';')[0].trim().toLowerCase();
  if (!Object.prototype.hasOwnProperty.call(SAVE_TYPES, base)) return null;
  return { mime: base, ext: SAVE_TYPES[base] };
}

/** b77s (audit 4 DV-5): a saved chat photo, video or recording gets a camera-style name (as Stego saves
 *  already do: vendor/device/src/stego.ts neutralImageName), never one that says Vardum or Veil
 *  (they were vardum-<ms>.<ext> and veil-save-<ms>.<ext>, which Photos and file managers keep) */
export function neutralSaveName(mime: string, ext: string, at: Date = new Date()): string {
  const p = (n: number) => String(n).padStart(2, '0');
  const stamp = at.getFullYear() + p(at.getMonth() + 1) + p(at.getDate()) + '_' + p(at.getHours()) + p(at.getMinutes()) + p(at.getSeconds());
  const kind = mime.startsWith('video/') ? 'VID' : mime.startsWith('audio/') ? 'REC' : 'IMG';
  return `${kind}_${stamp}.${ext}`;
}
