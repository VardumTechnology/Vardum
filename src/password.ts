/**
 * b199 (owner, Oct 16): the app-lock code is a PASSWORD — any characters
 * (letters, numbers, symbols, spaces), up to 50 long. Numeric passcodes set
 * before this keep working: digits are characters. The same rule covers the
 * optional Decoy and Duress codes. Nothing is trimmed — the exact text is the
 * password (a leading or trailing space counts).
 *
 * audit VAR-18 (b77m): at least 8 characters for every NEW password, decoy or duress code (was 4:
 * with ~120 guesses a day a 4-digit code fell in under three months). A shorter password set before
 * keeps unlocking — nobody is locked out — and the app asks its owner to make it longer after each
 * unlock with it (passwordNeedsUpgrade). b77q owner (1 Nov): at most once a week (passwordReminderDue), not after
 * every unlock; the 8-character minimum for new codes stays. The lockouts now keep growing past an hour, to a day
 * (applock.ts LOCKOUT_MINUTES).
 */
export const PASSWORD_MIN = 8;
export const PASSWORD_MAX = 50;

/** b70 (audit PRIM-2 / VAR-18): passphrases that encrypt a file kept on the
 *  relay or saved on the phone (vaults, hidden messages, encrypted exports) can
 *  be guessed offline by whoever holds the file, so they need more than a lock
 *  code: at least 8 characters. Existing files still open with what they used.
 *  b71 (audit): 12 characters for every NEW passphrase (vaults, hidden messages,
 *  encrypted exports); opening an existing one never checks the length. */
export const PASSPHRASE_MIN = 12;
export function passphraseProblem(p: string): string | null {
  if (p.length < PASSPHRASE_MIN) return `Use a passphrase of at least ${PASSPHRASE_MIN} characters. Anyone who gets the file can try guesses as fast as their computer allows.`;
  return null;
}

/** audit VAR-18: an existing password shorter than today's minimum (it still unlocks; the owner is
 *  asked to change it) */
export function passwordNeedsUpgrade(p: string): boolean {
  return p.length > 0 && p.length < PASSWORD_MIN;
}

/** b77m review (L3): ask for a longer password after an unlock? The SAME answer for the real password and the
 *  decoy code (both must be ≥ PASSWORD_MIN when set now): asking only after a real unlock told someone watching
 *  which of two short codes was the real one. Never for the duress code (the phone is being erased) or a wrong
 *  one; once per app run, shared by both. */
export function askPasswordUpgradeAfter(kind: 'real' | 'decoy' | 'duress' | 'wrong' | string, code: string, askedThisRun: boolean): boolean {
  return (kind === 'real' || kind === 'decoy') && !askedThisRun && passwordNeedsUpgrade(code);
}

/** b77q owner (1 Nov): the "make it longer" reminder comes at most this often */
export const PASSWORD_REMIND_MS = 7 * 86400_000;
/** b77q owner (1 Nov): when the reminder was last shown (epoch ms, as text). A `veil_` record of the app store, so
 *  every wipe removes it (none keeps it); read and written the same way after a real and a decoy unlock (b77q AP-1:
 *  what it holds depends only on the code's length and the time, never on which code it was). */
export const PASSWORD_REMINDED_KEY = 'veil_pw_upgrade_reminded_at';
/** b77q owner (1 Nov): is the weekly reminder due, given when it was last shown (the stored text, or null)? A clock
 *  that went back more than a day (the stored time is in the future) counts as due. */
export function passwordReminderDue(lastShown: string | null | undefined, now = Date.now()): boolean {
  const last = Number(lastShown);
  if (!lastShown || !Number.isFinite(last) || last <= 0) return true;
  if (last > now + 86400_000) return true;
  return now - last >= PASSWORD_REMIND_MS;
}

/** audit VAR-18: the line shown when a short password was just used to unlock */
export const PASSWORD_UPGRADE_NOTE = `Your password is shorter than ${PASSWORD_MIN} characters, which makes it easier to guess. It still works — change it to a longer one in Settings → Lock and emergency.`;

/** audit VAR-18: the password-setup question about erasing after repeated wrong guesses (off unless
 *  the owner turns it on) */
/** b77s (audit 4 DV-1): no longer claims it "stops someone guessing your password for good" — a decoy
 *  unlock resets the count (AP-1, kept by owner decision), so someone who knows the decoy code is not stopped */
export const WIPE_AFTER_FAILS_SETUP = 'Erase Vardum from this phone after 10 wrong passwords in a row? It limits how many guesses someone gets at your password, but a child or a pocket tapping the lock screen could erase it too. It doesn’t limit someone who knows your decoy code: opening the decoy resets the count. You can change this later in Settings → Lock and emergency.';

/** b77s (audit 4 DV-1): the honest disclosure shown where the decoy code is set up and explained. A decoy
 *  unlock clears the wrong-password count and lockout (AP-1, kept by owner decision: otherwise the decoy
 *  would look different from a real unlock) */
/** b77t (audit 5 M-E / IH V-02, owner decision "a real throwaway account"): what the decoy code opens, shown where it
 *  is set up (onboarding, Settings). It used to say "empty chats, notes and vaults" / "a harmless empty environment"
 *  while every network action failed; it is a working account now */
export const DECOY_SETUP_NOTE = 'Entered at the lock screen, it opens a separate, empty Vardum with its own Vardum ID and its own account, which Vardum sets up on its server now. It works like a new Vardum: you can add contacts, chat and use groups (it starts with none). Your real data stays hidden on the phone, and nothing done in the decoy reaches it. The decoy’s own 24 words are kept on this phone, sealed, so it opens without them (your real 24 words are never stored). Under Nothing at rest its chats are wiped each time you leave Vardum, like your real ones.'; // b77u (audit 6 ID-04 claim; U-M5)
export const DECOY_LOCKOUT_NOTE = ' Opening the decoy resets the wrong-password count, so someone who knows your decoy code isn’t slowed down or stopped by the lockout when guessing your real password.';

/** null when acceptable, otherwise a short reason to show the user */
export function passwordProblem(p: string): string | null {
  if (p.length < PASSWORD_MIN) return `Use at least ${PASSWORD_MIN} characters.`;
  if (p.length > PASSWORD_MAX) return `Use at most ${PASSWORD_MAX} characters.`;
  return null;
}

/** b71 (audit F-21): added to the decoy and duress prompts on a phone without a
 *  hardware lock key (the code is checked against a key stored beside it) */
export const SOFT_LOCK_NOTE = ' On this phone the lock key can’t be kept in secure hardware, so someone who copies Vardum’s storage could test codes offline and tell which code is which.';

/** b77s (owner decision, "Change password"): an email account's password follows the sign-up minimum
 *  (LoginScreen's `password.length < 12`; the relay's PASSWORD_MIN_LEN) and the relay's 512 cap.
 *  Separate from the app lock's PASSWORD_MIN. */
export const EMAIL_PASSWORD_MIN = 12;
export const EMAIL_PASSWORD_MAX = 512;
/** null when acceptable as a new email-account password, otherwise a short reason */
export function emailPasswordProblem(p: string): string | null {
  if (typeof p !== 'string' || p.length < EMAIL_PASSWORD_MIN) return `Use at least ${EMAIL_PASSWORD_MIN} characters.`;
  if (p.length > EMAIL_PASSWORD_MAX) return `Use at most ${EMAIL_PASSWORD_MAX} characters.`;
  return null;
}
