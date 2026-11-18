/**
 * audit VAR-08 / VAR-14 (b77m): the keyboard flags for text that must not be learned, suggested,
 * autofilled or kept by the phone's keyboard. Pure (the platform is passed in) so the repro tests
 * check the exact props the screens spread.
 *
 * What these flags do — and what they can't:
 *  - Android: `visible-password` makes the field a password-variation field
 *    (TYPE_TEXT_VARIATION_VISIBLE_PASSWORD): Gboard and AOSP-based keyboards turn off suggestions,
 *    learning and clipboard/autofill strips for it, while the text stays readable (the recovery
 *    phrase must be checked word by word). autoCorrect=false adds TYPE_TEXT_FLAG_NO_SUGGESTIONS;
 *    importantForAutofill=no keeps Autofill services out. React Native 0.76 exposes no prop for
 *    IME_FLAG_NO_PERSONALIZED_LEARNING, so that flag is NOT set: a keyboard that ignores the
 *    password variation (or a malicious one) still receives every keystroke.
 *  - iOS: no autocorrect, spell check, smart quotes/dashes/insert-delete, textContentType none, so
 *    QuickType offers nothing and the system keyboard's learning is skipped. A third-party keyboard
 *    with Full Access still sees every keystroke.
 *  - Masked fields (lock / decoy / duress / notes / vault codes) keep secureTextEntry (+ the
 *    oneTimeCode content type on iOS, which stops "Use Strong Password"): already a password
 *    variation on Android and the secure keyboard on iOS.
 * The only entry no keyboard sees is Vardum's own SecureKeypad. b77n (owner decision, 30 Oct — it
 * replaces the b77m decision that kept the phrase and codes on the phone keyboard): the sign-in
 * password, the 24-word phrase (restore screen, Settings phrase prompts) and the app lock password,
 * decoy and duress codes (lock screen, Notes gate, onboarding, Settings set / change / remove) are all
 * typed on it. phraseEntryProps stays for any phrase field still on a system keyboard; the
 * phone-keyboard fallback for an EXISTING code (PHONE_KEYBOARD_FALLBACK) keeps the masked flags.
 */
import { BIP39_WORDLIST } from '../vendor/crypto-core/src/bip39-wordlist';
export type Os = 'ios' | 'android' | string;

/** the 24-word recovery phrase (readable, never learned or suggested) */
export function phraseEntryProps(os: Os) {
  return {
    autoCapitalize: 'none' as const,
    autoCorrect: false,
    spellCheck: false,
    autoComplete: 'off' as const,
    importantForAutofill: 'no' as const,
    textContentType: 'none' as const,
    smartInsertDelete: false,
    keyboardType: (os === 'android' ? 'visible-password' : 'ascii-capable') as 'visible-password' | 'ascii-capable',
    contextMenuHidden: false, // pasting the phrase stays possible (the clipboard is cleared after use)
  };
}

/** chat composer with Settings → Private keyboard on: no suggestions, autocorrect or autofill.
 *  Not the password variation (it would drop non-Latin layouts and emoji on many keyboards). */
export function privateComposerProps(on: boolean) {
  return on
    ? { autoCorrect: false, spellCheck: false, autoComplete: 'off' as const, importantForAutofill: 'no' as const, textContentType: 'none' as const, smartInsertDelete: false }
    : { autoCorrect: true, spellCheck: true };
}

/** audit VAR-14: the Settings line for Private keyboard — what it asks, not a promise */
export const PRIVATE_KEYBOARD_NOTE = 'Asks your keyboard not to autocorrect, suggest or autofill. Keyboards can still learn or keep what you type — third-party ones especially — so it is a request, not a guarantee.';

/** audit VAR-23: what a key announces — its control name (Shift, Delete, Space, Done…), or just
 *  "Key" for a character key */
export function keyA11yLabel(_label: string | undefined, a11y: string | undefined): string {
  return a11y ?? 'Key';
}

/** audit VAR-23: what the field reports — a count of characters (or words for the phrase) */
export function fieldA11yValue(value: string, masked: boolean): string {
  if (masked) return `${Array.from(value).length} characters`;
  const words = value.trim().split(' ').filter(Boolean).length; // the keypad types plain spaces
  return `${words} word${words === 1 ? '' : 's'}`;
}

// ---------------------------------------------------------------------------------------------
// b77n (owner decision, 30 Oct): the phrase and the lock codes on Vardum's own keypad
// ---------------------------------------------------------------------------------------------

/** which ThemedPrompt inputs type on the Vardum keypad, and with which layout: 'code' = an app lock
 *  password / decoy / duress code (masked, full keypad), 'phrase' = the 24 words (a–z + space, word
 *  suggestions). 'secure' (vault passphrases, the registration lock PIN) and 'text' stay on the phone
 *  keyboard. */
export function promptKeypadVariant(input: string | undefined): 'password' | 'phrase' | null {
  return input === 'code' ? 'password' : input === 'phrase' ? 'phrase' : null;
}

/** the note on fields where an EXISTING code is typed (lock screen, Notes gate, "enter your current
 *  password" prompts): a password set before b77n may hold characters the keypad lacks, and a
 *  screen-reader user can't hear which key the keypad types (audit VAR-23) — both can switch that one
 *  entry to the phone keyboard. New codes are set on the keypad only. */
export const PHONE_KEYBOARD_FALLBACK = 'Password has characters this keyboard lacks, or you use a screen reader? Use the phone keyboard';
export const VARDUM_KEYBOARD_BACK = 'Use the Vardum keyboard';

/** text typed on the phrase keypad: lowercase letters, one space between words, none in front */
export function normalizePhraseTyping(v: string): string {
  return v.toLowerCase().replace(/[^a-z ]+/g, '').replace(/ {2,}/g, ' ').replace(/^ +/, '');
}

/** a phrase pasted from the clipboard: letters only, one space between words (numbers and
 *  punctuation of a numbered list dropped — the same reading as phraseOnClipboard and the
 *  restore screen's canonical form) */
export function cleanPastedPhrase(clip: string | null | undefined): string {
  return (clip ?? '').toLowerCase().replace(/[^a-z]+/g, ' ').trim();
}

/** the word being typed: the letters after the last space ('' right after a space) */
export function phrasePartialWord(value: string): string {
  const m = /([a-z]+)$/.exec(value);
  return m ? m[1] : '';
}

/** BIP39 words starting with the word being typed, computed on the phone from the app's own
 *  wordlist (vendor/crypto-core/src/bip39-wordlist.ts — sorted, so a binary search finds the
 *  first match). Nothing is sent, stored or learned. */
export function phraseSuggestions(value: string, max = 4): string[] {
  const p = phrasePartialWord(value);
  if (!p || max <= 0) return [];
  const list = BIP39_WORDLIST;
  let lo = 0, hi = list.length;
  while (lo < hi) { const mid = (lo + hi) >> 1; if (list[mid] < p) lo = mid + 1; else hi = mid; }
  const out: string[] = [];
  for (let i = lo; i < list.length && out.length < max && list[i].startsWith(p); i++) out.push(list[i]);
  return out;
}

/** a tapped suggestion replaces the word being typed and adds the space before the next word */
export function applyPhraseSuggestion(value: string, word: string): string {
  return value.replace(/[a-z]*$/, '') + word + ' ';
}
