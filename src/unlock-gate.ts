/**
 * b77u (audit 6 U-M2 / R1 F-02): an unlock result belongs to one attempt.
 *
 * A password check (PBKDF2, the lockout record, the decoy account) and the OS
 * authentication prompt all await before they unlock. Meanwhile the phone may
 * have left the foreground, been locked by hand or by the departure timer, or
 * been wiped. The old code unlocked anyway when the stale check came back, so
 * a lock that came AFTER the attempt began was undone by it.
 *
 * Every attempt takes a ticket. Any lock, departure or wipe moves the
 * generation on, and a newer attempt replaces an older one: a success unlocks
 * only for the newest attempt, in the same generation (and wipe generation),
 * while Vardum is in the foreground.
 */
export type UnlockTicket = { readonly attempt: number; readonly gen: number; readonly away: number; readonly wipe: number };

export class UnlockGate {
  private attempt = 0;
  private gen = 0;
  private away = 0;

  constructor(private readonly wipeGeneration: () => number, private readonly foreground: () => boolean) {}

  /** a new attempt starts (a typed code, an OS-auth prompt): any older attempt's result is void */
  begin(): UnlockTicket {
    this.attempt += 1;
    return { attempt: this.attempt, gen: this.gen, away: this.away, wipe: this.wipeGeneration() };
  }

  /** a lock (manual, timer, phone lock) or a wipe */
  invalidate(): void {
    this.gen += 1;
  }

  /** Vardum left the foreground (a real departure, not a picker Vardum opened) */
  depart(): void {
    this.away += 1;
  }

  /** the attempt is still the newest and nothing locked or wiped since it began */
  current(t: UnlockTicket): boolean {
    return t.attempt === this.attempt && t.gen === this.gen && t.wipe === this.wipeGeneration();
  }

  /**
   * May this result unlock? A typed code: current, no departure since it began, and Vardum in the
   * foreground. The OS-auth prompt (`osAuth`) can itself send Vardum to the background (Android's
   * device-credential screen), so a departure during it does not void it; a lock, a wipe or a newer
   * attempt still does, and so does being in the background when it returns.
   */
  accept(t: UnlockTicket, o: { osAuth?: boolean; notBackground?: () => boolean } = {}): boolean {
    if (!this.current(t)) return false;
    if (o.osAuth) return o.notBackground ? o.notBackground() : this.foreground();
    return t.away === this.away && this.foreground();
  }

  /**
   * b77u2 (UC-M2): the OS-auth success. On Android 10 and earlier with a PIN and no biometrics, the
   * device-credential screen is an activity: its result (onActivityResult) reaches JS BEFORE onResume, so
   * AppState still reads 'background' when the promise resolves, and reading it then refused every correct
   * PIN. A success that is still current waits for the next 'active' event (bounded by `maxMs`) instead.
   * A real departure (depart()), a lock, a wipe or a newer attempt during that wait voids it, and so does
   * the wait running out.
   */
  async acceptOsAuth(t: UnlockTicket, env: { state(): string; nextActive(maxMs: number): Promise<boolean> }, maxMs = OS_AUTH_RESUME_MS): Promise<boolean> {
    if (!this.current(t)) return false;
    if (env.state() !== 'background') return true;
    const away = this.away; // departures during the prompt itself never count (see accept)
    const resumed = await env.nextActive(maxMs);
    return resumed && this.current(t) && this.away === away && env.state() !== 'background';
  }
}

/** b77u2 (UC-M2): how long an OS-auth success waits for Vardum to come back to the foreground */
export const OS_AUTH_RESUME_MS = 2_000;

/**
 * b77u2 (UC-M2): resolves true at the next 'active' state event, false after `maxMs`. Subscribe synchronously
 * right after reading the state as 'background' (the event cannot slip in between: it is a later task).
 */
export function nextActiveEvent(
  subscribe: (fn: (s: string) => void) => { remove(): void },
  maxMs: number,
  timers: { set(fn: () => void, ms: number): unknown; clear(h: unknown): void } = { set: (fn, ms) => setTimeout(fn, ms), clear: (h) => clearTimeout(h as ReturnType<typeof setTimeout>) },
): Promise<boolean> {
  return new Promise<boolean>((resolve) => {
    let done = false;
    let sub: { remove(): void } | null = null;
    let timer: unknown = null;
    const finish = (v: boolean) => {
      if (done) return;
      done = true;
      if (timer !== null) timers.clear(timer);
      try { sub?.remove(); } catch { /* gone */ }
      resolve(v);
    };
    sub = subscribe((s) => { if (s === 'active') finish(true); });
    if (done) { try { sub.remove(); } catch { /* gone */ } return; }
    timer = timers.set(() => finish(false), Math.max(0, maxMs));
  });
}
