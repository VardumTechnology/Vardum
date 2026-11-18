/**
 * b77n (owner decision, 30 Oct): the key layout of Vardum's own SecureKeypad
 * (src/components/SecureKeypad.tsx), kept pure so the repro tests check exactly
 * what the keypad draws.
 *
 * The 24-word phrase and the lock / decoy / duress codes are typed on this keypad,
 * never the phone keyboard. A lock code may contain ANY characters (src/password.ts:
 * b199, "letters, numbers, symbols or spaces", nothing restricted), so the
 * password keypad carries every printable ASCII character (space to '~') across
 * its three pages, plus € £ ¥. An existing password with anything else (an
 * accented letter, an emoji…) can't be typed here: the screens where an EXISTING
 * code is entered offer the phone keyboard as a fallback (PHONE_KEYBOARD_FALLBACK,
 * src/secret-entry.ts). New codes are set on the keypad only.
 */

export const LETTERS: readonly (readonly string[])[] = [
  ['q', 'w', 'e', 'r', 't', 'y', 'u', 'i', 'o', 'p'],
  ['a', 's', 'd', 'f', 'g', 'h', 'j', 'k', 'l'],
  ['z', 'x', 'c', 'v', 'b', 'n', 'm'],
];
export const NUMBERS: readonly (readonly string[])[] = [
  ['1', '2', '3', '4', '5', '6', '7', '8', '9', '0'],
  ['-', '/', ':', ';', '(', ')', '$', '&', '@', '"'],
  ['.', ',', '?', '!', "'"],
];
export const SYMBOLS: readonly (readonly string[])[] = [
  ['[', ']', '{', '}', '#', '%', '^', '*', '+', '='],
  ['_', '\\', '|', '~', '<', '>', '€', '£', '¥', '`'],
  ['.', ',', '?', '!', "'"],
];

/** every character the password keypad can type (letters in both cases, space included) */
export function passwordKeypadChars(): Set<string> {
  const out = new Set<string>([' ']);
  for (const row of LETTERS) for (const ch of row) { out.add(ch); out.add(ch.toUpperCase()); }
  for (const page of [NUMBERS, SYMBOLS]) for (const row of page) for (const ch of row) out.add(ch);
  return out;
}

/** every character the phrase keypad can type: a–z and space */
export function phraseKeypadChars(): Set<string> {
  const out = new Set<string>([' ']);
  for (const row of LETTERS) for (const ch of row) out.add(ch);
  return out;
}

/** can this text be typed on the password keypad? (false → the phone-keyboard fallback is needed) */
export function keypadCanType(text: string): boolean {
  const set = passwordKeypadChars();
  return Array.from(text).every((ch) => set.has(ch));
}

/**
 * b77q (audit 3 AP-6): VAR-23 announces every character key as "Key", but the layout above is
 * fixed and public, and an accessibility click event carries the bounds of the key pressed, so a
 * service could map each "Key" press back to its glyph from its position (FLAG_SECURE does not
 * stop the accessibility tree). Two counter-measures, chosen per keypad:
 *  - hideGrid: with no accessibility service at all the key grid is hidden from accessibility
 *    (no-hide-descendants). Owner decision (31 Oct): a service that is on (Switch Access, Voice
 *    Access, TalkBack) keeps the keys reachable, and the shuffle below is the protection there;
 *  - shuffle: while any accessibility service is on (Android reports it; a screen reader counts)
 *    the characters of each page are dealt in a fresh random order every time the keypad opens,
 *    so a key's position no longer names its character.
 * Residual (written down, not closed): a service that asks to see views not important for
 * accessibility can still read the hidden glyph text of the nodes. Screen-reader users keep the
 * keypad reachable (keys still announced only as "Key"; the phone-keyboard fallback stays where an
 * existing code is entered), and anyone with an accessibility service on types on a shuffled pad.
 */
export type KeypadPage = readonly (readonly string[])[];

export function keypadA11yPlan(s: { screenReader: boolean; anyService: boolean }): { hideGrid: boolean; shuffle: boolean } {
  return { hideGrid: !s.screenReader && !s.anyService, shuffle: s.anyService || s.screenReader };
}

function randomIndex(n: number): number {
  const c = (globalThis as { crypto?: { getRandomValues?: (a: Uint32Array) => Uint32Array } }).crypto;
  if (typeof c?.getRandomValues === 'function') { const a = new Uint32Array(1); c.getRandomValues(a); return a[0] % n; }
  return Math.floor(Math.random() * n);
}

/** b77q (audit 3 AP-6): the page's characters dealt into the same row shapes in a random order */
export function shufflePage(page: KeypadPage, rand: (n: number) => number = randomIndex): string[][] {
  const all = ([] as string[]).concat(...page.map((r) => [...r]));
  for (let i = all.length - 1; i > 0; i--) { const j = rand(i + 1); const t = all[i]; all[i] = all[j]; all[j] = t; }
  let k = 0;
  return page.map((row) => row.map(() => all[k++]));
}
