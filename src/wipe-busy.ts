/**
 * b77k (IP77-6, iPhone battery): "a wipe is still running". The first password attempt after a
 * Nothing-at-Rest departure reached the lock store while the departure (or cold-boot) wipe still
 * froze writes, and failed closed ("This attempt could not be recorded on this phone"). The lock
 * screen now waits behind "Finishing a wipe…" while this is set, and handleCode waits for it
 * (bounded) before it checks a password. The fail-closed rule is unchanged: an attempt that can't
 * be recorded is still never checked.
 *
 * Every wipe holds it from its start until its write freeze ends (beginWipe's end pass). Each hold
 * lets go by itself after `maxMs`, so a wipe that threw half-way can't keep the lock screen shut.
 */

let running = 0;
const subs = new Set<(busy: boolean) => void>();

function emit(): void {
  const busy = running > 0;
  for (const fn of [...subs]) { try { fn(busy); } catch { /* a listener never stops the others */ } }
}

/** b77u (audit 6 R4 #24): the safety cap. A hold used to let go by itself after 20-60 s while the wipe could still be
 *  running (a slow keystore, a long file sweep), so the lock screen took a password whose attempt row the wipe then
 *  refused or erased. Each hold is now released by the wipe's real end (its release call: the erase finished, or its
 *  write freeze ended); this cap only covers a wipe that threw before releasing. */
export const WIPE_BUSY_CAP_MS = 10 * 60_000;

/** a wipe starts; call the returned function once it is over (idempotent). Lets go after `maxMs` (the safety cap). */
export function wipeStarted(maxMs = WIPE_BUSY_CAP_MS): () => void {
  running++;
  let done = false;
  const timer = setTimeout(() => release(), Math.max(0, maxMs));
  const release = () => {
    if (done) return;
    done = true;
    clearTimeout(timer);
    running = Math.max(0, running - 1);
    emit();
  };
  emit();
  return release;
}

/** true while any wipe is still running */
export function wipeBusy(): boolean {
  return running > 0;
}

/** subscribe to changes (called with the new state); returns the unsubscribe */
export function onWipeBusy(fn: (busy: boolean) => void): () => void {
  subs.add(fn);
  return () => { subs.delete(fn); };
}

/** resolves true once no wipe is running, or false after `maxMs` (whichever comes first) */
export function waitWipeIdle(maxMs = 20_000): Promise<boolean> {
  if (!wipeBusy()) return Promise.resolve(true);
  return new Promise((resolve) => {
    let off: () => void = () => undefined;
    const t = setTimeout(() => { off(); resolve(!wipeBusy()); }, Math.max(0, maxMs));
    off = onWipeBusy((busy) => { if (!busy) { clearTimeout(t); off(); resolve(true); } });
  });
}
