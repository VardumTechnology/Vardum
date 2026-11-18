/**
 * b199 (owner report, Oct 17): the 1-minute inactivity auto-lock fired in
 * the middle of a vault download (a 24 MB container from the relay can take
 * longer than a minute), killing the transfer — "the first one or two opens
 * never load". A screen running a long, user-started job holds the
 * INACTIVITY lock off until it finishes. Backgrounding / locking the phone
 * still locks instantly (AppState path, untouched); this only pauses the
 * no-touch timer. b70 (audit L-8): the job itself is not activity, so when it
 * ends the timer counts from the last real touch (an idle phone locks at once).
 */
let holds = 0;
let holdSeq = 0;

/** b199 (ZTE device run): the PHONE's own screen timeout (30 s on a fresh
 *  Android) blanked the screen ~30 s into a ~60 s vault create; Android then
 *  cut the network and the upload failed. A hold now keeps the screen on too. */
function keepAwake(tag: string, on: boolean): void {
  try {
    const ka = require('expo-keep-awake') as typeof import('expo-keep-awake');
    if (on) void ka.activateKeepAwakeAsync(tag).then(() => console.log(`[veil-awake] screen held on (${tag})`)).catch((e) => console.log(`[veil-awake] hold FAILED (${tag}): ${(e as Error)?.message ?? e}`));
    else void ka.deactivateKeepAwake(tag).then(() => console.log(`[veil-awake] released (${tag})`)).catch(() => undefined);
  } catch (e) { console.log(`[veil-awake] module unavailable: ${(e as Error)?.message ?? e}`); }
}

/** b70 (re-review 5): a hold ends by itself after this long (a stalled relay or
 *  network used to keep the app unlocked and the screen on for good).
 *  audit VAR-16: 5 minutes (was 15) — a 24 MB vault moves well inside it on a working
 *  connection, and the stall watchdog ends a dead transfer after 30 s anyway. */
export const HOLD_MAX_MS = 5 * 60_000;

/** audit VAR-16: every live hold's release, so a departure can end them all */
const live = new Set<() => void>();
/** audit VAR-16: run when the LAST hold ends (the App checks the inactivity rule at once, so a
 *  phone left alone during a job locks before the job's result — a vault listing — is shown) */
let holdEndedHook: (() => void) | null = null;
export function setHoldEndedHook(fn: (() => void) | null): void { holdEndedHook = fn; }

/** Start a hold; call the returned function exactly when the job ends. */
export function holdAutoLock(): () => void {
  holds++;
  const tag = `veil-job-${++holdSeq}`;
  keepAwake(tag, true);
  let released = false;
  const release = () => {
    if (released) return;
    released = true;
    live.delete(release);
    clearTimeout(deadline);
    holds = Math.max(0, holds - 1);
    keepAwake(tag, false);
    if (holds === 0) { try { holdEndedHook?.(); } catch { /* never throws into the job */ } }
  };
  const deadline = setTimeout(release, HOLD_MAX_MS);
  live.add(release);
  return release;
}

/** audit VAR-16: leaving the app ends every hold (the screen-on request included); a hold never
 *  carries across a departure */
export function releaseAllHolds(): number {
  const all = [...live];
  for (const r of all) r();
  return all.length;
}

export function autoLockHeld(): boolean {
  return holds > 0;
}

/**
 * b199 (owner, ZTE device run Oct 17): on Android the photo picker, camera,
 * file picker, share sheet and permission prompts are separate activities —
 * opening one sends Vardum to 'background', which engaged the passcode lock
 * mid-send (every photo/voice note from the ZTE locked the app). Call this
 * right before Vardum itself opens such a screen: the NEXT backgrounding
 * within 2 minutes is expected and does not lock. Cleared on return to the
 * foreground, so any other departure still locks instantly.
 */
let systemSheetUntil = 0;
/** b70 (audit L-8): was 2 minutes */
export const SYSTEM_SHEET_MS = 60_000;
/** b75 (audit AL-5): whether a departure may be treated as expected at all. The app
 *  sets it to "not in Nothing-at-Rest": there EVERY departure wipes and locks, a
 *  picker or share sheet included (the grace used to skip both, for good if Vardum
 *  never came back to the foreground). */
let sheetGraceAllowed: () => boolean = () => true;
export function setSystemSheetPolicy(allowed: () => boolean): void { sheetGraceAllowed = allowed; }
export function expectSystemSheet(ms = SYSTEM_SHEET_MS): void { systemSheetUntil = Date.now() + ms; }
export function systemSheetExpected(): boolean {
  let allowed = true;
  try { allowed = sheetGraceAllowed(); } catch { allowed = false; }
  return allowed && Date.now() < systemSheetUntil;
}
export function systemSheetDone(): void { systemSheetUntil = 0; }
/** b75 (audit AL-5): how much of the grace is left (the app backs it with a timer that
 *  locks when it runs out, whether or not Vardum comes back to the foreground) */
export function systemSheetLeftMs(): number { return Math.max(0, systemSheetUntil - Date.now()); }

/** Run `open` (a picker / prompt / share sheet) with the departure expected
 *  only while it is open — cleared the moment it returns or throws. */
export async function withSystemSheet<T>(open: () => Promise<T>): Promise<T> {
  expectSystemSheet();
  try { return await open(); } finally { systemSheetDone(); }
}
