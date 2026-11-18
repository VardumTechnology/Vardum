/**
 * b77u (audit 6 W8 / website C-1): "End quiet chats after" does what it says.
 *
 * The setting went into each new chat's dials (key_retention_hours, bound into the safety code) and the relay used
 * it only for the legacy rendezvous rows; a sealed-sender chat's mailboxes followed a fixed 30-day idle rule, so
 * 1 hour, Off and 30 days all meant 30 days. Now the PHONE ends a 1:1 chat that has been quiet for long enough,
 * exactly as "End chat" does (the in-band END inside the chat's encryption, then the mailbox ends).
 *
 * Which setting applies: each chat carries the quiet time agreed when it started (its dials, set by whoever started
 * it and the same on both phones), and this phone also has its own current setting. The SHORTER of the two that is
 * not Off applies on this phone; when both are Off the chat is never ended for being quiet. Either phone may end
 * the chat (ending is always one-sided), so the earlier of the two phones' windows ends it for both. The relay's
 * own 30-day idle rule still applies on top.
 *
 * "Quiet" = no message sent or received on this phone (cover traffic, receipts and other control messages don't
 * count). The time of the last message is kept per chat in a veil_ record (every wipe removes it); a chat first
 * seen by this code starts its window then, so an update never ends chats that were already quiet.
 *
 * Pure (storage and clock passed in) so the tests drive it.
 */
export const QUIET_LEDGER_KEY = 'veil_quiet_seen_v1';
/** how often the phone looks for quiet chats while unlocked and in front */
export const QUIET_CHECK_MS = 10 * 60_000;

/** the window in ms on this phone (0 = never): the shorter of the chat's own dial and this phone's setting, Off ignored */
export function quietWindowMs(chatHours: number | null | undefined, myHours: number | null | undefined): number {
  const hs = [Number(chatHours) || 0, Number(myHours) || 0].filter((h) => h > 0);
  return hs.length ? Math.min(...hs) * 3600_000 : 0;
}

type Store = { get(k: string): Promise<string | null>; set(k: string, v: string): Promise<unknown> };

export class QuietLedger {
  private cache: Record<string, number> | null = null;
  constructor(private readonly store: Store, private readonly now: () => number = Date.now) {}

  private async load(): Promise<Record<string, number>> {
    if (this.cache) return this.cache;
    let m: Record<string, number> = {};
    try {
      const raw = await this.store.get(QUIET_LEDGER_KEY);
      const v = raw ? JSON.parse(raw) : {};
      if (v && typeof v === 'object') for (const [k, t] of Object.entries(v)) if (Number.isFinite(Number(t))) m[k] = Number(t);
    } catch { m = {}; }
    this.cache = m;
    return m;
  }

  private async save(m: Record<string, number>): Promise<void> {
    await Promise.resolve(this.store.set(QUIET_LEDGER_KEY, JSON.stringify(m))).catch(() => undefined);
  }

  /** a message was sent or received in this chat now */
  async touch(token: string): Promise<void> {
    const m = await this.load();
    m[token] = this.now();
    await this.save(m);
  }

  /** the chats (of `tokens`, with their windows) that have been quiet past their window; a chat seen for the first
   *  time starts its window now. Forgets chats no longer listed. */
  async due(chats: { token: string; windowMs: number }[]): Promise<string[]> {
    const m = await this.load();
    const t = this.now();
    let dirty = false;
    const listed = new Set(chats.map((c) => c.token));
    for (const k of Object.keys(m)) if (!listed.has(k)) { delete m[k]; dirty = true; }
    const out: string[] = [];
    for (const c of chats) {
      if (m[c.token] === undefined) { m[c.token] = t; dirty = true; continue; }
      if (c.windowMs > 0 && t - m[c.token] >= c.windowMs) out.push(c.token);
    }
    if (dirty) await this.save(m);
    return out;
  }

  async forget(token: string): Promise<void> {
    const m = await this.load();
    if (m[token] === undefined) return;
    delete m[token];
    await this.save(m);
  }

  /** b77u2 (UC-L1): is this one chat still quiet past `windowMs`? (a chat the ledger doesn't know is not) */
  async quietFor(token: string, windowMs: number): Promise<boolean> {
    const m = await this.load();
    const last = m[token];
    return last !== undefined && windowMs > 0 && this.now() - last >= windowMs;
  }

  /** a wipe or an account switch: nothing cached in memory */
  reset(): void {
    this.cache = null;
  }
}

/**
 * b77u2 (UC-L1): the ledger only knows what THIS phone has fetched, so a chat whose peer wrote inside the window was
 * ended (and, with the U-M8 purge, both copies removed) before those messages arrived. Each due chat now gets a normal
 * sync pass first (`syncFirst`: true only when the fetch ran to the end; never while messages are held), and is ended
 * only if it is still quiet after it. A failed or held fetch leaves the chat for a later round. Returns the chats ended.
 */
export async function endQuietChats(
  due: { token: string; windowMs: number }[],
  d: {
    ledger: QuietLedger;
    stillOn(): boolean;
    held(): boolean;
    syncFirst(token: string): Promise<boolean | undefined | void>;
    end(token: string): Promise<void>;
  },
): Promise<string[]> {
  const ended: string[] = [];
  for (const c of due) {
    if (!d.stillOn() || d.held()) break; // hold-until-unlock: nothing fetched, nothing ended
    let synced = false;
    try { synced = (await d.syncFirst(c.token)) === true; } catch { synced = false; }
    if (!synced) continue; // the fetch failed (or was held / already running): not this round
    if (!d.stillOn() || d.held()) break;
    if (!(await d.ledger.quietFor(c.token, c.windowMs))) continue; // a message arrived in that pass
    await d.end(c.token);
    ended.push(c.token);
  }
  return ended;
}
