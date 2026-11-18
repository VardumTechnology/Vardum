/**
 * b77t2 (CM-2): the app-level in-window prompt belongs to ONE account.
 *
 * There is one app-wide ThemedPrompt (App.tsx). Dialogs raised by the real account's work (a key change naming a
 * real contact, the move code, the old-group member list, a move's keep/remove choice) used to stay pending behind
 * the lock and then appear over the DECOY session after the decoy code; answering acted on the real account.
 *
 * Every app-level prompt now goes through this gate, tagged with the account (the VeilApp) it belongs to:
 *  - a prompt asked while the app is locked, or for an account that isn't the one in use, is never shown;
 *  - a prompt still open at a lock or an account switch is withdrawn (settled null) and closed (`check`, called by
 *    the app on every change of `locked` or of the account in use);
 *  - an answer that arrives after such a change is not passed on;
 *  - while locked, or while the open prompt belongs to another account, nothing is drawn (`visible`).
 * A withdrawn or withheld prompt answers null and calls `onWithheld`, so the caller can tell "the user never saw
 * it" from "the user said no" (a key change is asked again at the next real chat open; a member list asks again).
 */
export type PromptAnswer = string | boolean | null;

export interface PromptGateState<A> {
  /** the account in use (the decoy's in a decoy session) */
  account: A | null;
  locked: boolean;
}

export interface AskForOptions {
  /** called when the prompt was never shown, or was withdrawn by a lock or account switch, before it was answered */
  onWithheld?: () => void;
}

export class AccountPromptGate<A, S = unknown> {
  private pending: { owner: A; id: number; withheld: boolean } | null = null;
  private seq = 0;

  constructor(
    private readonly state: () => PromptGateState<A>,
    private readonly ask: (spec: S) => Promise<PromptAnswer>,
    private readonly dismiss: () => void,
  ) {}

  private showable(owner: A | null | undefined): boolean {
    const st = this.state();
    return !!owner && !st.locked && st.account === owner;
  }

  /** ask on behalf of `owner`; null (and onWithheld) when it can't be shown to that account, or stops being shown */
  async askFor(owner: A | null | undefined, spec: S, opts: AskForOptions = {}): Promise<PromptAnswer> {
    if (!owner || !this.showable(owner)) { opts.onWithheld?.(); return null; }
    const p = { owner, id: ++this.seq, withheld: false };
    this.pending = p;
    let answer: PromptAnswer;
    try { answer = await this.ask(spec); } finally { if (this.pending === p) this.pending = null; }
    if (p.withheld || !this.showable(owner)) { opts.onWithheld?.(); return null; }
    return answer;
  }

  /** the app calls this on every lock and every switch of the account in use: an open prompt that no longer
   *  belongs on screen is withdrawn (its caller gets null) and closed */
  check(): void {
    const p = this.pending;
    if (!p || this.showable(p.owner)) return;
    p.withheld = true;
    this.pending = null;
    this.dismiss();
  }

  /** may the prompt layer be drawn now? Never while locked, nor while the open prompt is another account's */
  visible(): boolean {
    const st = this.state();
    if (st.locked) return false;
    return !this.pending || this.pending.owner === st.account;
  }

  /** tests / diagnostics: whose prompt is open (undefined: none) */
  pendingOwner(): A | undefined { return this.pending?.owner; }
}
