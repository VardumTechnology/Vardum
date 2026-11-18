/**
 * b77q (audit 3 AQ-2): a peer-chosen media file name as Vardum shows it (chat caption, lightbox).
 * The name comes straight from the decrypted payload (parseMediaPayload), so it is cleaned like
 * sender and group names (VAR-58): no bidi controls, newlines or other invisible characters
 * (cleanName), at most MEDIA_NAME_MAX characters, isolated from the text around it. A U+202E name
 * used to fake its extension, and a multi-line one painted text that looked like app status.
 */
import { cleanName, isolateName } from '../vendor/device/src/names';

export const MEDIA_NAME_MAX = 80;

export function mediaDisplayName(name: string | null | undefined): string {
  const c = Array.from(cleanName(String(name ?? '')));
  return isolateName(c.length > MEDIA_NAME_MAX ? c.slice(0, MEDIA_NAME_MAX - 1).join('') + '…' : c.join(''));
}
