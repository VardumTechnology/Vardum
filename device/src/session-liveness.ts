/**
 * @veil/device — does a session still exist on the relay? (Batch E, round-3
 * review R3-02, Oct 19 2026)
 *
 * The app used to delete an open chat's local keys when the chat was missing
 * from the session list. That list is capped, and other accounts can add rows
 * to it, so a missing row is NOT proof the session ended: a flood of rows (or a
 * busy group creator's own seats) pushed real chats off the list and the phone
 * erased them. Now the app asks the relay about that ONE session first, and
 * only a definite "Session not found" counts as gone. Anything else — the row
 * exists but is inactive, the credential is refused, a network error, a 5xx —
 * keeps the keys.
 *
 * Residual (disclosed): the relay itself (A2) can still answer "not found" for
 * a session it deleted; it can also withhold the envelopes, so this is the
 * same availability boundary as before, not a new capability.
 */
import { relayDetailOf } from './relay-errors'; // b77m (audit VAR-20)

export type SessionLiveness = 'gone' | 'alive' | 'unknown';

export async function relaySessionLiveness(
  relay: { sessionHeartbeat(token: string, writeSecret: string | null): Promise<unknown> },
  token: string,
  writeSecret: string | null,
): Promise<SessionLiveness> {
  try {
    await relay.sessionHeartbeat(token, writeSecret);
    return 'alive';
  } catch (e) {
    const msg = relayDetailOf(e); // b77m (audit VAR-20): the relay's words (cleaned), for classification only
    if (/^Session not found$/i.test(msg.trim())) return 'gone';
    // the row exists: inactive, ended-but-present, or our credential refused
    if (/not active|has ended|invalid session credential|already in use/i.test(msg)) return 'alive';
    return 'unknown';
  }
}

/**
 * b75r1 (audit G-10): a group is marked ended for good only on REPEATED answers. b75 marked it ended (polling
 * stopped, the thread closed) on the first "Session not found" from a background poll — one bad answer, from
 * a relay hiccup or a hostile relay, ended the group on this phone for ever. Now `GROUP_GONE_ANSWERS` such
 * answers are needed, spread over at least `GROUP_GONE_SPAN_MS`, with no good poll in between (a good poll
 * clears the count); the app then asks the relay about that one session directly (relaySessionLiveness) and
 * marks it ended only on a definite "gone". The relay can still end a group it really deleted, as before.
 */
export const GROUP_GONE_ANSWERS = 3;
export const GROUP_GONE_SPAN_MS = 2 * 60_000;
export type GoneAnswers = Map<string, { n: number; first: number }>;

/** count one "Session not found" for `key`; true once it has been said often enough, over long enough */
export function noteGoneAnswer(seen: GoneAnswers, key: string, now = Date.now()): boolean {
  const cur = seen.get(key);
  const next = cur ? { n: cur.n + 1, first: cur.first } : { n: 1, first: now };
  seen.set(key, next);
  return next.n >= GROUP_GONE_ANSWERS && now - next.first >= GROUP_GONE_SPAN_MS;
}

/** b77r2 (audit R2-A-1): true when `key`'s answers already meet the rule (counts nothing) */
export function goneAnswersConfirmed(seen: GoneAnswers, key: string, now = Date.now()): boolean {
  const cur = seen.get(key);
  return !!cur && cur.n >= GROUP_GONE_ANSWERS && now - cur.first >= GROUP_GONE_SPAN_MS;
}

/** b77r2 (audit R2-A-1): a 1:1 chat's OUTBOUND answers (410 to a submit: the peer's inbound is
 *  retired) are counted under their own key. Only a submit that lands clears them — a good
 *  fetch of my own inbound says nothing about the peer's, so it no longer wipes them (it did:
 *  a half-ended chat refused every send for ever and was never removed). */
export const outGoneKey = (token: string): string => `out:${token}`;

/** a good poll for `key`: forget the "not found" answers counted so far */
export function clearGoneAnswers(seen: GoneAnswers, key: string): void {
  seen.delete(key);
}

/**
 * b75r2 (audit P-4): 1:1 chats get the group treatment (G-10). One "Session not found" (from a
 * burn refusal, or the list/heartbeat check) used to erase a 1:1 chat's keys and history on
 * this phone, so a single forged answer was enough. Now each answer is a direct liveness check
 * of that one session, and the chat is removed only after GROUP_GONE_ANSWERS definite "gone"
 * answers spread over at least GROUP_GONE_SPAN_MS; an "alive" answer clears the count. The
 * relay can still end a chat it really deleted (it holds the envelopes either way).
 */
export const chatGoneAnswers: GoneAnswers = new Map();

export async function confirmSessionGone(
  seen: GoneAnswers,
  relay: { sessionHeartbeat(token: string, writeSecret: string | null): Promise<unknown> },
  token: string,
  writeSecret: string | null,
  now: () => number = Date.now,
): Promise<{ live: SessionLiveness; confirmed: boolean }> {
  const live = await relaySessionLiveness(relay, token, writeSecret);
  if (live === 'alive') { clearGoneAnswers(seen, token); return { live, confirmed: false }; }
  if (live !== 'gone') return { live, confirmed: false };
  return { live, confirmed: noteGoneAnswer(seen, token, now()) };
}

/**
 * b75r2 (audit P-4): keep asking about a chat the view already left (the same-peer switch
 * moves to the new thread at once, but the old chat's keys stay until its end is confirmed).
 * Stops when the chat is gone from this phone, the relay says it is alive, or `tries` run out.
 */
export function confirmGoneLater(
  opts: {
    seen: GoneAnswers;
    relay: { sessionHeartbeat(token: string, writeSecret: string | null): Promise<unknown> };
    load: (token: string) => Promise<unknown>;
    remove: (token: string) => Promise<unknown>;
    token: string;
    delayMs?: number;
    tries?: number;
    now?: () => number;
    schedule?: (fn: () => void, ms: number) => unknown;
  },
): void {
  const tries = opts.tries ?? 4;
  if (tries <= 0) return;
  const schedule = opts.schedule ?? ((fn, ms) => setTimeout(fn, ms));
  schedule(() => {
    void (async () => {
      try {
        const sealed = await opts.load(opts.token);
        if (!sealed) return;
        const ws = (sealed as { writeSecret?: string | null }).writeSecret ?? null;
        const r = await confirmSessionGone(opts.seen, opts.relay, opts.token, ws, opts.now);
        if (r.confirmed) { await opts.remove(opts.token); clearGoneAnswers(opts.seen, opts.token); return; }
        if (r.live !== 'alive') confirmGoneLater({ ...opts, tries: tries - 1 });
      } catch { /* the chat stays; nothing is removed on an error */ }
    })();
  }, opts.delayMs ?? 50_000);
}
