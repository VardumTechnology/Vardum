/**
 * b77f (audit ZTE77-4): a 24-word restore skips the onboarding on purpose, so after a duress wipe
 * plus restore, or a restore on a fresh install, the phone had no app password and the lock screen
 * fell back to the device's own authentication: on a phone without a screen lock, no lock at all.
 * A restore that leaves no app lock now goes through the onboarding's "Set your password" step
 * (OnboardingScreen mode 'passwordOnly') before the app opens. The pending flag is saved first, so
 * a phone closed midway resumes at that step on the next launch, as a new sign-up's onboarding
 * does. A restore where the lock survived (Nothing-at-Rest keeps `veil_app_lock`) is not asked.
 * Pure helpers: App.tsx holds the state, these decide the route (and the tests drive them).
 */

export interface RestorePasswordSettings {
  onboardingPending?: boolean;
  restorePasswordPending?: boolean;
  /** the full onboarding / the checkup finished (b77f2, F-1) */
  setupDone?: boolean;
  /** the post-restore password step finished once (b77f2, F-1) */
  passwordStepDone?: boolean;
}

/** right after a successful phrase restore: does the password step come first?
 *  b77f2 (audit F-1): asked BEFORE the restore writes the identity, so the flag is on disk first */
export function restoreNeedsPassword(hasAppLock: boolean): boolean {
  return !hasAppLock;
}

/** at launch (or after a sign-in that finds an identity on this phone): which onboarding (if any)
 *  must run before the app opens.
 *  'full' = a new sign-up's unfinished onboarding (b199); 'passwordOnly' = a restore that still
 *  has no app lock; 'clear' = a restore flag left over although a lock now exists (drop the flag,
 *  open the app); null = straight into the app.
 *  b77f2 (audit F-1, belt and braces): an identity with no lock record on a phone that never
 *  finished an onboarding (setupDone false, password step never done) gets the password step too,
 *  even with no flag — whatever lost the flag (a kill, a failed write, an unreadable settings
 *  record) can't open the app unlocked. A lock that exists, or a finished onboarding, is never
 *  asked. Only call it with an identity present. */
export function bootOnboardingRoute(st: RestorePasswordSettings, hasAppLock: boolean): 'full' | 'passwordOnly' | 'clear' | null {
  if (st.onboardingPending) return 'full';
  if (st.restorePasswordPending) return hasAppLock ? 'clear' : 'passwordOnly';
  if (!hasAppLock && !st.setupDone && !st.passwordStepDone) return 'passwordOnly';
  return null;
}

/** b77g (G-1): the password step's line after a phrase restore (the restore flag is set) */
export const PASSWORD_STEP_RESTORED = 'Your identity is restored. This phone has no Vardum password yet: set one before Vardum opens, so it never opens without it.';
/** b77g (G-1): the password step's line when the launch rule asks for it with no restore behind it
 *  (an identity with no lock that never finished an onboarding): it claims no restore */
export const PASSWORD_STEP_NO_LOCK = 'Set a password to keep Vardum locked. This phone has no Vardum password yet: set one before Vardum opens, so it never opens without it.';

/** b77g (G-1): which line the 'passwordOnly' step shows — the restore line only while the restore
 *  flag is set (a restore put this phone here); otherwise the plain "set a password" line */
export function passwordStepCopy(st: RestorePasswordSettings): string {
  return st.restorePasswordPending ? PASSWORD_STEP_RESTORED : PASSWORD_STEP_NO_LOCK;
}

/** b77f2 (audit F-1): what `restoreWithPasswordFlag` needs from the app */
export interface RestoreFlagDeps<S extends RestorePasswordSettings> {
  /** is an app lock set on this phone? (an unreadable lock record counts as one) */
  hasLock: () => Promise<boolean>;
  loadSettings: () => Promise<S>;
  saveSettings: (s: S) => Promise<void>;
  /** the phrase restore; writing the identity to the vault is its LAST step */
  restore: () => Promise<unknown>;
  /** after a failed restore: is an identity on disk? ('unknown' when that can't be read) */
  identityOnDisk: () => Promise<boolean | 'unknown'>;
}

/** b77f2 (audit F-1): thrown when the pending flag can't be written — the restore did not run */
export const RESTORE_FLAG_SAVE_FAILED = 'Vardum could not save this phone’s settings, so the restore was stopped before anything was restored. Nothing changed. Try again; if it keeps failing, restart the phone first.';

/**
 * b77f2 (audit F-1): the phrase restore with its password flag in the right order. The lock is
 * checked and `restorePasswordPending` is saved BEFORE the restore writes the identity, so a kill
 * at any point after the identity lands (the notes adoption that follows makes relay round trips)
 * resumes the password step at the next launch instead of opening the app with no lock.
 * A failed flag write throws RESTORE_FLAG_SAVE_FAILED and the restore never runs. A restore that
 * fails before its identity write drops the flag again (best effort; an identity that did land,
 * or can't be checked, keeps it). A flag left over from an earlier attempt is dropped when a lock
 * exists now. Returns whether the password step comes next, with the settings as saved.
 */
export async function restoreWithPasswordFlag<S extends RestorePasswordSettings>(d: RestoreFlagDeps<S>): Promise<{ needsPassword: boolean; settings: S }> {
  let hasLock: boolean;
  try { hasLock = !!(await d.hasLock()); } catch { hasLock = true; }
  const needsPassword = restoreNeedsPassword(hasLock);
  const st0 = await d.loadSettings();
  const settings = { ...st0, restorePasswordPending: needsPassword } as S;
  if (needsPassword || st0.restorePasswordPending) {
    try { await d.saveSettings(settings); } catch { throw new Error(RESTORE_FLAG_SAVE_FAILED); }
  }
  try {
    await d.restore();
  } catch (e) {
    if (needsPassword) {
      let landed: boolean | 'unknown';
      try { landed = await d.identityOnDisk(); } catch { landed = 'unknown'; }
      if (landed === false) await d.saveSettings({ ...settings, restorePasswordPending: false } as S).catch(() => undefined);
    }
    throw e;
  }
  return { needsPassword, settings };
}

/**
 * b77k2 (review L4): handleRestore signs in with the phrase only when there is no token at all, so
 * a stored token that has expired or been revoked still reached the identity register and got a
 * 401. Now a 401 from the restore runs the phrase sign-in once and retries the restore once.
 * `signIn` resolves false when it handled the outcome itself (a registration-lock PIN prompt, the
 * email sign-in offer): the restore is then not retried. Any other error, a second 401, or a 401
 * after a sign-in this same restore already made is thrown as is.
 */
export async function restoreRetryingSignIn<T>(run: () => Promise<T>, signIn: () => Promise<boolean>, opts: { signedInAlready?: boolean } = {}): Promise<T | undefined> {
  try {
    return await run();
  } catch (e) {
    if (opts.signedInAlready || Number((e as { status?: unknown } | null)?.status) !== 401) throw e;
    if (!(await signIn())) return undefined;
    return run();
  }
}
