/**
 * b70 (audit L-6): text copied out of a chat doesn't stay on the clipboard.
 * It is cleared 60 seconds after the copy if it is still what Vardum put
 * there; if the app was in the background at that moment, it is cleared the
 * next time Vardum comes to the front.
 *
 * b77q (audit 3 AP-3): the JS timer below never fires while Vardum is in the background
 * (React Native pauses timers with the activity), so on Android the native sensitive copy
 * now clears itself after the same minute (VeilCryptoModule setSensitiveClipboard, a main-looper
 * Handler; iOS already expired it natively). Known limit: if the process dies within the
 * minute, the copy stays until the OS clears it (the "ours" record lives in memory only).
 */
import * as Clipboard from 'expo-clipboard';
import { AppState } from 'react-native';
import { phraseOnClipboard } from './app-guards';
import { cleanPastedPhrase } from './secret-entry';

export const CLIPBOARD_CLEAR_MS = 60_000;
let last: { text: string; at: number } | null = null;
let timer: ReturnType<typeof setTimeout> | null = null;

async function clearIfOurs(): Promise<void> {
  const mine = last;
  if (!mine || Date.now() - mine.at < CLIPBOARD_CLEAR_MS) return;
  last = null;
  try {
    if ((await Clipboard.getStringAsync()) === mine.text) await Clipboard.setStringAsync('');
  } catch { /* best-effort */ }
}

AppState.addEventListener('change', (s) => { if (s === 'active') void clearIfOurs(); });

/** b71 (audit): the native copy that marks the text sensitive (Android 13+:
 *  ClipDescription EXTRA_IS_SENSITIVE, no preview, kept out of keyboard
 *  clipboard history; iOS: this phone only — no Universal Clipboard — and it
 *  expires by itself). A build without it falls back to a plain copy. */
type SensitiveClip = { setSensitiveClipboard?: (text: string, expireSeconds: number) => Promise<boolean> };
function nativeClip(): SensitiveClip | null {
  try {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const emc = require('expo-modules-core') as { requireOptionalNativeModule?: <T>(name: string) => T | null };
    return emc.requireOptionalNativeModule?.<SensitiveClip>('VeilCrypto') ?? null;
  } catch {
    return null;
  }
}

/** true when this build marks copies sensitive (otherwise a plain copy is made) */
export function sensitiveCopySupported(): boolean {
  return typeof nativeClip()?.setSensitiveClipboard === 'function';
}

export async function copySensitive(text: string): Promise<void> {
  const nat = nativeClip();
  let done = false;
  if (typeof nat?.setSensitiveClipboard === 'function') {
    try { done = (await nat.setSensitiveClipboard(text, CLIPBOARD_CLEAR_MS / 1000)) !== false; } catch { done = false; }
  }
  if (!done) await Clipboard.setStringAsync(text);
  last = { text, at: Date.now() };
  if (timer) clearTimeout(timer);
  timer = setTimeout(() => { void clearIfOurs(); }, CLIPBOARD_CLEAR_MS + 50);
}

/** b70 (re-review 4): at a wipe, anything Vardum put on the clipboard goes now
 *  (a transfer link copied minutes earlier must not outlive the wipe) */
export async function clearSensitiveNow(): Promise<void> {
  const mine = last;
  last = null;
  if (timer) { clearTimeout(timer); timer = null; }
  if (!mine) return;
  try {
    if ((await Clipboard.getStringAsync()) === mine.text) await Clipboard.setStringAsync('');
  } catch { /* best-effort */ }
}

/** audit VAR-08 (b77m): the recovery phrase, once used, does not stay on the clipboard (where iOS
 *  Universal Clipboard and keyboard clipboard histories can carry it). Cleared only when the
 *  clipboard holds that phrase, so nothing else the user copied is touched. */
export async function clearPhraseFromClipboard(phrase: string): Promise<boolean> {
  try {
    if (!(await Clipboard.hasStringAsync())) return false;
    const clip = await Clipboard.getStringAsync();
    if (!phraseOnClipboard(clip, phrase)) return false;
    await Clipboard.setStringAsync('');
    return true;
  } catch { return false; }
}

/** b77n (owner decision, 30 Oct): the Paste key of the phrase keypad. The Vardum keypad has no
 *  native text field, so pasting is this explicit key: it reads the clipboard once, keeps letters
 *  and single spaces (cleanPastedPhrase), and clears the clipboard at once when it held that phrase
 *  (clearPhraseFromClipboard — it is cleared again after use, as before). null = nothing to paste. */
export async function pastePhraseFromClipboard(): Promise<string | null> {
  try {
    if (!(await Clipboard.hasStringAsync())) return null;
    const phrase = cleanPastedPhrase(await Clipboard.getStringAsync());
    if (!phrase) return null;
    await clearPhraseFromClipboard(phrase);
    return phrase;
  } catch { return null; }
}
