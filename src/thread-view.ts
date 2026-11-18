/**
 * b77u (audit 6 U-M3 / R1 F-03, and the receive-handler review RH-M1, RH-I1, RH-I2): which thread is on screen.
 *
 * Syncs, sends and group passes await the relay and then wrote into the ONE shared message list (and the
 * group info panel) of whatever thread was open when they came back: a pass for chat A that finished after
 * the user opened chat B appended A's messages to B, and a real-account pass could write into the decoy's
 * view. Every such pass now takes a ticket at its start (thread, account, view generation, wipe generation)
 * and writes to the screen only while the ticket still matches. What it fetched is still cached by the
 * store, so the thread shows it when it is opened.
 *
 * `show` is called synchronously by the wrapped setChat, so the check sees a switch at once (chatRef only
 * catches up at the next render). `bump` marks an account switch or a wipe of the view.
 */
export type ThreadTicket = { readonly token: string; readonly account: unknown; readonly gen: number; readonly wipe: number };

export class ThreadView {
  private token: string | null = null;
  private gen = 0;
  private openSeq = 0;

  constructor(private readonly wipeGeneration: () => number, private readonly account: () => unknown) {}

  /** the thread now on screen (null: none) */
  show(token: string | null): void {
    this.token = token;
  }

  current(): string | null {
    return this.token;
  }

  /** the account in use changed, or the view was reset (a wipe, a sign-out) */
  bump(): void {
    this.gen += 1;
    this.token = null;
  }

  /** taken when a pass starts, with the account (app) the pass runs for */
  ticket(token: string, account: unknown): ThreadTicket {
    return { token, account, gen: this.gen, wipe: this.wipeGeneration() };
  }

  /** the pass's account is still the one in use, and nothing was wiped since it began */
  live(t: ThreadTicket): boolean {
    return t.gen === this.gen && t.wipe === this.wipeGeneration() && t.account === this.account();
  }

  /** live, and its thread is the one on screen: only then may it write to the thread's view */
  shows(t: ThreadTicket): boolean {
    return this.live(t) && this.token === t.token;
  }

  /** b77u (RH-I2): a chat open begins; a later open supersedes it */
  beginOpen(): number {
    this.openSeq += 1;
    return this.openSeq;
  }

  openCurrent(seq: number): boolean {
    return seq === this.openSeq;
  }
}

/** b77u (U-M3): append messages a pass fetched, once each (an open meanwhile may have loaded them from the cache) */
export function mergeById<M extends { id: string }>(prev: M[], add: readonly M[]): M[] {
  if (!add.length) return prev;
  const have = new Set(prev.map((m) => m.id));
  const fresh = add.filter((m) => !have.has(m.id));
  return fresh.length ? [...prev, ...fresh] : prev;
}
