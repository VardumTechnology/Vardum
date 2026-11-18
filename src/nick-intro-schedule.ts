/**
 * b77k2 (review L2): the 1:1 nickname intro ({"__veil_intro":1,"nick":…}, chat.ts sendNicknameIntro)
 * no longer goes to every chat in one burst. A nickname change made every ready chat due at once, and
 * the next sync pass sent one envelope into each of them back to back, which let the relay link this
 * user's mailboxes by timing. Now each chat's intro waits its own random delay, uniform over
 * [NICK_INTRO_MIN_MS, NICK_INTRO_MAX_MS] (the same 3–30 s window as the delayed mailbox ends), and a
 * chat that becomes ready gets its own delay too, so no two intros go out in lockstep. The send
 * re-checks at fire time (the nickname then current, and whether it is still due).
 *
 * b77k2 (review, optional item): a peer whose intro keeps changing can make the chat list refresh at
 * most once per PEER_NICK_REFRESH_MS per chat; a change inside that window is shown by one refresh
 * at the window's end.
 *
 * Pure module (no React Native imports) so App.tsx and the tests share it.
 *
 * b77n (pre-audit INFO-3): the delays come from the CSPRNG (secureRandomUnit), not Math.random: the timing
 * is what the relay sees.
 */
import { secureRandomUnit } from '../vendor/device/src/sealed';

export const NICK_INTRO_MIN_MS = 3_000;
export const NICK_INTRO_MAX_MS = 30_000;
export const PEER_NICK_REFRESH_MS = 30_000;
/** b77k2 (review I-2): after a failed intro send (its ratchet step is spent) the chat's next try waits
 *  at least this long, so a long run of failures can't keep widening the peer's skipped-key gap */
export const NICK_INTRO_RETRY_MS = 5 * 60_000;

type Timer = unknown;
export interface ScheduleOptions {
  /** uniform [0, 1) (default secureRandomUnit, the CSPRNG; b77n INFO-3: was Math.random) */
  random?: () => number;
  setTimer?: (fn: () => void, ms: number) => Timer;
  clearTimer?: (t: Timer) => void;
  now?: () => number;
  /** b77k2 (re-review, info): a wipe epoch (currentWipeGeneration); an intro scheduled before a wipe
   *  does not fire after it */
  epoch?: () => number;
}

/** one chat's wait before its intro, ms */
export function nickIntroDelayMs(random: () => number = secureRandomUnit): number {
  const r = Math.min(Math.max(random(), 0), 0.999999);
  return Math.round(NICK_INTRO_MIN_MS + r * (NICK_INTRO_MAX_MS - NICK_INTRO_MIN_MS));
}

/** per-chat delayed intros: `schedule(token)` arms one timer per chat (false when one is already
 *  waiting or sending); `send` runs when it fires; `cancelAll` drops every waiting one */
export function createNickIntroScheduler(send: (token: string) => Promise<unknown>, o: ScheduleOptions = {}) {
  const setTimer = o.setTimer ?? ((fn, ms) => setTimeout(fn, ms));
  const clearTimer = o.clearTimer ?? ((t) => clearTimeout(t as ReturnType<typeof setTimeout>));
  const waiting = new Map<string, Timer>();
  const sending = new Set<string>();
  const failedAt = new Map<string, number>();
  const now = o.now ?? (() => Date.now());
  return {
    schedule(token: string): number | null {
      if (waiting.has(token) || sending.has(token)) return null;
      const f = failedAt.get(token);
      if (f !== undefined && now() - f < NICK_INTRO_RETRY_MS) return null; // b77k2 (review I-2)
      const ms = nickIntroDelayMs(o.random);
      const at = o.epoch?.();
      waiting.set(token, setTimer(() => {
        waiting.delete(token);
        if (o.epoch && o.epoch() !== at) return; // a wipe since: nothing to send for

        sending.add(token);
        void Promise.resolve().then(() => send(token))
          .then(() => { failedAt.delete(token); }, () => { failedAt.set(token, now()); })
          .finally(() => { sending.delete(token); });
      }, ms));
      return ms;
    },
    pending(token: string): boolean { return waiting.has(token) || sending.has(token); },
    cancelAll(): void { for (const t of waiting.values()) clearTimer(t); waiting.clear(); },
  };
}

/** at most one `refresh` per chat per PEER_NICK_REFRESH_MS; a change inside the window gets one
 *  refresh at its end. `changed(token)` returns 'now' | 'later' | 'skip' (for tests). */
export function createPeerNickRefreshLimiter(refresh: () => void, o: ScheduleOptions = {}) {
  const setTimer = o.setTimer ?? ((fn, ms) => setTimeout(fn, ms));
  const now = o.now ?? (() => Date.now());
  const last = new Map<string, number>();
  const deferred = new Set<string>();
  return {
    changed(token: string): 'now' | 'later' | 'skip' {
      const t = now();
      const prev = last.get(token);
      if (prev === undefined || t - prev >= PEER_NICK_REFRESH_MS) { last.set(token, t); refresh(); return 'now'; }
      if (deferred.has(token)) return 'skip';
      deferred.add(token);
      setTimer(() => { deferred.delete(token); last.set(token, now()); refresh(); }, prev + PEER_NICK_REFRESH_MS - t);
      return 'later';
    },
  };
}

/**
 * audit VAR-21 (1f51): the 1:1 nickname intro goes only into a chat whose safety code THIS phone has
 * confirmed (its own sealed confirmation, chat.ts locallyVerified; a revoked one doesn't count), like
 * every other automatic 1:1 send ("sending unlocks once you compare the safety code"). Checked when the
 * intro is scheduled and again when it fires. The device calls are passed in (pure module).
 */
export function nickIntroAllowed(
  sealed: unknown, nick: string,
  d: { due: (sealed: unknown, nick: string) => boolean; verified: (sealed: unknown) => boolean; revoked?: boolean },
): boolean {
  if (d.revoked) return false;
  if (!d.verified(sealed)) return false;
  return d.due(sealed, nick);
}
