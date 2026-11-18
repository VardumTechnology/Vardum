/**
 * b77t (audit 5 L-4 / IH DEV-2, owner decision "relay time check + disclose"): the relay's clock, for the
 * self-destruct countdown.
 *
 * The countdown used the phone's own clocks only, so a restart (which resets the boot clock) plus a date
 * set back before Vardum was opened again held it off for good. Now every successful answer to a signed-in
 * relay request carries the relay's time (the HTTP Date header, 1 s resolution); the latest one is kept in
 * memory with the boot clock at that moment, and relayClockNow() moves it on by the boot clock since. The
 * countdown (App.tsx selfDestructDue / noteSelfDestructClock) counts the larger of that and the phone's
 * clocks, and stores the result as its high-water mark. No new relay route: the header is on every answer.
 *
 * Trust: the time is only what the relay says (over TLS). A hostile relay could bring an armed countdown
 * forward (it can't hold it off: the phone's own clocks still count). Offline, a clock set back after a
 * restart still delays the wipe until the phone next reaches the relay (disclosed: SELF_DESTRUCT_CLOCK_NOTE).
 *
 * Pure module (the boot clock is passed in).
 */

/** shown with the countdown (Settings, onboarding) */
export const SELF_DESTRUCT_CLOCK_NOTE = 'Whenever the phone is online, the countdown is checked against Vardum’s server clock. Offline, changing the phone’s clock can delay the wipe until Vardum next reaches the server. A server that lies about its clock could set the wipe off early.'; // b77t2 (info)

/** b77t2 (info): when an arming (or an extension) of the self-destruct countdown starts — the relay's time when this
 *  run has one, else the phone's. The EARLIER of the two, so neither a phone clock set forward nor a relay clock
 *  set forward can push the wipe back (a slow one only brings it forward, the disclosed direction). */
export function selfDestructArmNow(now: number = Date.now()): number {
  const r = relayClockNow();
  return r === null ? now : Math.min(now, r);
}

/** dates before this are not a relay's answer (a broken header) */
const MIN_PLAUSIBLE = Date.UTC(2025, 0, 1);

let anchor: { relay: number; up: number | null; wall: number } | null = null;
let uptimeFn: () => number | null = () => null;

/** the boot clock (applock.ts uptimeMs); set once by the app */
export function setRelayClockUptime(fn: () => number | null): void { uptimeFn = fn; }

/** a relay answer's Date header. Only a later relay time moves the anchor (one answer delayed in flight
 *  never pulls it back). Returns whether it was taken. */
export function noteRelayDate(header: string | null | undefined): boolean {
  if (!header) return false;
  const t = Date.parse(header);
  if (!Number.isFinite(t) || t < MIN_PLAUSIBLE) return false;
  const now = relayClockNow();
  if (now !== null && t <= now) return false;
  let up: number | null = null;
  try { up = uptimeFn(); } catch { up = null; }
  anchor = { relay: t, up: Number.isFinite(up as number) ? up : null, wall: Date.now() };
  return true;
}

/** the relay's time now (its last answer moved on by the boot clock since), or null when none was seen in
 *  this run. Without a boot clock, by the wall clock (never backwards). */
export function relayClockNow(): number | null {
  if (!anchor) return null;
  let up: number | null = null;
  try { up = uptimeFn(); } catch { up = null; }
  if (anchor.up !== null && up !== null && up >= anchor.up) return anchor.relay + (up - anchor.up);
  return anchor.relay + Math.max(0, Date.now() - anchor.wall);
}

/** tests (and a wipe): forget the relay's time */
export function forgetRelayClock(): void { anchor = null; }

/** fetch that notes the Date header of every successful answer from `baseUrl` to a request that carried a
 *  session token (Authorization). Everything else passes through unchanged. */
export function withRelayClock(fetchImpl: typeof fetch, baseUrl: string): typeof fetch {
  const wrapped = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const res = await fetchImpl(input as RequestInfo, init);
    try {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.href : (input as Request).url;
      const h = init?.headers;
      const auth = !!h && (h instanceof Headers ? h.get('Authorization') : Array.isArray(h)
        ? h.find(([k]) => k.toLowerCase() === 'authorization')?.[1]
        : (h as Record<string, string>).Authorization ?? (h as Record<string, string>).authorization);
      if (res.ok && auth && String(url).startsWith(`${baseUrl}/`)) noteRelayDate(res.headers?.get?.('date') ?? null);
    } catch { /* the clock is a hint; the request's answer is what matters */ }
    return res;
  };
  return wrapped as typeof fetch;
}

/** b77t (audit 5 L-4 x L-27): the same rule as withRelayClock, as a VeilRelay `onAnswer` hook. On React Native the
 *  relay client sends its JSON calls through XMLHttpRequest (relay.ts xhrJsonBounded, L-27), which never touches
 *  the wrapped fetch, so without this a phone never noted the relay's time from them. Only successful answers to
 *  signed-in requests to `baseUrl` count. */
export function relayClockAnswerHook(baseUrl: string): (a: { url: string; ok: boolean; signedIn: boolean; header(name: string): string | null }) => void {
  return (a) => {
    try {
      if (a.ok && a.signedIn && String(a.url).startsWith(`${baseUrl}/`)) noteRelayDate(a.header('date'));
    } catch { /* a hint only */ }
  };
}
