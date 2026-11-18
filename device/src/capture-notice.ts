/**
 * @veil/device — screenshot / screen-recording notices (b75r2, audit P-1).
 *
 * b61 sent the notice as plain chat text starting with "⚠", and the chat screen drew ANY
 * message starting with "⚠" as a centred, unattributed system line. A peer (or a group
 * member) could type "⚠ Safety codes were confirmed on both phones…" and it rendered
 * exactly like a notice from the app itself, with no sender label and no long-press menu.
 *
 * Now the notice is a typed control payload, {"__veil_capture":1,"k":"screenshot"|"recording"},
 * and the RECEIVING phone writes the words, always naming who it came from. Peer text is
 * never classified by its first character: a message starting with "⚠" is an ordinary,
 * attributed bubble. A user can't type the payload either: userText() puts a word joiner
 * in front of anything that starts with "{", so it no longer starts with the tag.
 */
import { isolateName } from './names';

export type CaptureKind = 'screenshot' | 'recording';

const CAPTURE_TAG = '{"__veil_capture":';

export function buildCapturePayload(kind: CaptureKind): string {
  return JSON.stringify({ __veil_capture: 1, k: kind });
}

/** the notice kind when `text` is exactly a capture payload, else null (ordinary text) */
export function parseCapturePayload(text: unknown): CaptureKind | null {
  if (typeof text !== 'string' || !text.startsWith(CAPTURE_TAG)) return null;
  try {
    const t = JSON.parse(text) as Record<string, unknown>;
    if (t && t.__veil_capture === 1 && (t.k === 'screenshot' || t.k === 'recording')) return t.k;
  } catch { /* not a capture payload */ }
  return null;
}

/**
 * The line shown for a capture notice. Always attributed: "this phone" for my own, the
 * sender's name in a group (the same name the bubble would carry), "the other person" in a
 * 1:1 chat (the only other party).
 */
export function captureNoticeText(kind: CaptureKind, mine: boolean, sender?: string | null): string {
  const what = kind === 'screenshot' ? 'A screenshot was taken' : 'Screen recording was detected';
  if (mine) return `⚠ ${what} on this phone while this conversation was open. The other side was told.`;
  const who = sender ? isolateName(sender) : '';
  return `⚠ ${what} on ${who ? `${who}’s phone` : 'the other person’s phone'} while this conversation was open.`;
}
