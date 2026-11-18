/**
 * b77m merge (audit VAR-20, app half): the app branches on a relay error's status / stable code
 * (RelayError.status, relayErrorCode) rather than on its message text. Since VAR-20 a RelayError's
 * message is app-written (a known relay string, a code's text or the HTTP status sentence), so a
 * message regex can silently stop matching — e.g. a 429 with code `rate_limited` reads "Rate limit —
 * the server is busy…", which /rate limit exceeded/ never matched. Each check keeps the old message
 * match as well (errors the library throws itself carry no status or code), so nothing that matched
 * before stops matching. No React Native imports (the repro tests load this file).
 */
import { relayErrorCode } from '../vendor/device/src/relay-errors';

function messageOf(e: unknown): string {
  return String((e as { message?: unknown } | null)?.message ?? e ?? '');
}

/** the HTTP status a relay error carries, if any */
export function relayStatusOf(e: unknown): number | undefined {
  const st = e && typeof e === 'object' ? (e as { status?: unknown }).status : undefined;
  return typeof st === 'number' && Number.isInteger(st) ? st : undefined;
}

/** the relay's limiter refused the call (429 / code rate_limited / the relay's "Rate limit exceeded") */
export function isRateLimitedError(e: unknown): boolean {
  return relayStatusOf(e) === 429 || relayErrorCode(e) === 'rate_limited' || /rate limit exceeded/i.test(messageOf(e));
}

/** the relay says the session is gone (code session_not_found / "Session not found"); with
 *  `superseded`, also the library's "superseded" errors (the sync / cover-send paths) */
export function isSessionGoneError(e: unknown, opts: { superseded?: boolean } = {}): boolean {
  if (relayErrorCode(e) === 'session_not_found') return true;
  return (opts.superseded ? /session not found|superseded/i : /session not found/i).test(messageOf(e));
}
