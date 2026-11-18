/**
 * @veil/device — b77m (audit VAR-20): what a relay error says on screen.
 *
 * A relay's error body used to become `Error.message` verbatim, and the app shows error messages in
 * its own banners and alerts — so a hostile relay could write "Your safety key was reset. Re-enter
 * your 24 words at https://…" in Vardum's own red banner. Now:
 *
 *  - `Error.message` is always text written HERE: the relay's `code` (when it sends a known one), else
 *    one of the relay messages this build knows (an exact, case-insensitive match against the
 *    allow-list below — the relay only picks WHICH of our strings is shown, it can't add words), else a
 *    fixed sentence for the HTTP status.
 *  - The relay's own prose is kept on the error as `relayMessage` — cleaned (no control, bidi or
 *    invisible characters) and cut to RELAY_DETAIL_MAX characters — for logs and for the library's
 *    internal classification (relayDetailOf), never for display.
 *  - `status`, `code` and `data` (the parsed body) ride along unchanged for callers that branch on them
 *    (registration lock 423, proof-of-work, rate-limit windows).
 */

/** the most characters of relay prose kept on an error (logs only) */
export const RELAY_DETAIL_MAX = 240;

/** an error from the relay, with only app-written text in `message` */
export class RelayError extends Error {
  readonly status: number;
  readonly code?: string;
  readonly data: unknown;
  /** the relay's own words, cleaned and truncated — for logs / classification, never the UI */
  readonly relayMessage: string;
  constructor(message: string, o: { status: number; code?: string; data: unknown; relayMessage: string }) {
    super(message);
    this.name = 'RelayError';
    this.status = o.status;
    if (o.code) this.code = o.code;
    this.data = o.data;
    this.relayMessage = o.relayMessage;
    Object.setPrototypeOf(this, RelayError.prototype);
  }
}

/** control, bidi and invisible characters a log line or a match should never carry */
// eslint-disable-next-line no-control-regex
const UNSAFE_CHARS = /[\u0000-\u001f\u007f-\u009f\u00ad\u061c\u115f\u1160\u180e\u200b-\u200f\u2028-\u202e\u2060-\u206f\u3164\ufe00-\ufe0f\ufeff\uffa0\ufff9-\ufffb]/g;

/** relay prose made safe to log and to match on: unsafe characters gone, at most `max` characters */
export function cleanRelayText(v: unknown, max = RELAY_DETAIL_MAX): string {
  if (typeof v !== 'string') return '';
  const s = v.replace(UNSAFE_CHARS, '').replace(/\s+/g, ' ').trim();
  return s.length > max ? s.slice(0, max) + '…' : s;
}

/**
 * Relay messages this build knows and may show as they are (the client's own copy of each string is
 * what is shown). Every one is a string relay/main.ts sends; several are matched by the app or the
 * library ("Session not found", "already registered", "registered to another account", …).
 */
const KNOWN_RELAY_MESSAGES: readonly string[] = [
  'Session not found',
  'This session has ended.',
  'This session is not active',
  'Invalid session credential',
  'This session is already in use.',
  'This session was just accepted — try again.',
  'This session was already accepted with different keys — it cannot be re-joined. Start a new session.',
  'This session was already accepted from this device with different keys — it cannot be re-joined here. Start a new session.',
  'Invitation has expired.',
  'Only the invited side can join this session',
  'Only the invited side can view this session',
  'Only the session creator can activate',
  'Only group sessions can be activated without a peer',
  'Group seats use the signed-in session gate',
  'This seat has ended',
  'This chat has ended',
  'Sender is not a member of this group epoch',
  'Message epoch does not match the group epoch',
  'Sender tag does not match the group header',
  'joined_epoch does not match the current group epoch',
  'The group creator has not let you in yet — only your request to join can be sent',
  'You are not a member of this group.',
  'Not a member of this group',
  'Already on the current epoch',
  'Wrap request signature verification failed',
  'Identity not found',
  'Account not found',
  'Account deleted',
  'Another phone already answered this code',
  'This Vardum ID does not match its identity key',
  'Identity does not match the published key',
  'A registered identity keeps its prekeys — send new signed ones to replace them',
  'Too many one-time keys',
  'Invalid one-time keys',
  'Email already registered',
  'Invalid email or password',
  'Unauthorized',
  'That membership belongs to another account',
  'This device\'s notification address is registered to another account',
  'Confirm this device\'s notification address — Vardum does this by itself',
  'Invalid mailbox',
  'Invalid mailbox credential',
  'Invalid or used ticket',
  'Mailbox not open yet',
  'This mailbox is already open',
  'Busy — try again',
  'Envelope too large',
  'File too large',
  'Unknown file',
  'Unknown action',
  'Daily message limit reached',
  'Daily upload limit reached — try again tomorrow',
  'Too many requests from this network — try again later',
  'Too many requests for this chat — try again later',
  'Too many uploads at once from this network — try again in a moment',
  'Upload busy — try again',
  'Upload too slow — try again on a better connection',
  'Calls need a conversation you have verified',
  'Calling relay not configured',
  'Rate limit exceeded',
];
const KNOWN_BY_KEY = new Map(KNOWN_RELAY_MESSAGES.map((m) => [m.toLowerCase(), m]));

/** known relay messages with a variable tail: the pattern, and the fixed text shown for it */
const KNOWN_RELAY_PATTERNS: ReadonlyArray<[RegExp, string]> = [
  [/^entity veilenvelope with id \S{1,128} not found$/i, 'Entity VeilEnvelope with ID (unknown) not found'],
  [/^invalid one-time keys: /i, 'Invalid one-time keys'],
];

/**
 * Stable error codes (relay `code` field, being added relay-side). Unknown codes fall back to the
 * status text. Codes are lower-case ASCII words with underscores.
 */
const CODE_TEXT: Readonly<Record<string, string>> = {
  session_not_found: 'Session not found',
  session_ended: 'This session has ended.',
  chat_ended: 'This chat has ended',
  seat_ended: 'This seat has ended',
  not_member: 'You are not a member of this group.',
  not_admitted: 'The group creator has not let you in yet — only your request to join can be sent',
  invalid_credential: 'Invalid session credential',
  invalid_login: 'Invalid email or password',
  unauthorized: 'Unauthorized',
  account_deleted: 'Account deleted',
  account_not_found: 'Account not found',
  identity_not_found: 'Identity not found',
  already_registered: 'Email already registered',
  mailbox_not_open: 'Mailbox not open yet',
  mailbox_retired: 'This chat has ended',
  too_large: 'That is too large for the server.',
  rate_limited: 'Rate limit — the server is busy, try again shortly.',
  daily_limit: 'Daily message limit reached',
  busy: 'Busy — try again',
  not_found: 'Not found on the server — it may no longer exist.',
  bad_request: 'The server refused this request.',
  forbidden: 'The server refused this request (not allowed).',
  conflict: 'That already exists on the server.',
  reglock: 'This Vardum ID has a registration lock — its PIN is needed to sign in.',
  pow_required: 'The server asked for a sign-in check.',
  push_other_account: 'This device\'s notification address is registered to another account',
  push_confirm: 'Confirm this device\'s notification address — Vardum does this by itself',
};

const CODE_RE = /^[a-z][a-z0-9_]{0,47}$/;

/** the fixed text for an HTTP status (no relay words) */
export function relayStatusText(status: number): string {
  switch (status) {
    case 400: return 'The server refused this request.';
    case 401: return 'Sign-in not accepted — check your email and password, or sign in again.';
    case 403: return 'The server refused this request (not allowed).';
    case 404: return 'Not found on the server — it may no longer exist.';
    case 408: return 'The server timed out — try again on a better connection.';
    case 409: return 'That already exists on the server.';
    case 410: return 'This has ended on the server — it is no longer available.';
    case 413: return 'That is too large for the server.';
    case 423: return 'This Vardum ID has a registration lock — its PIN is needed to sign in.';
    case 425: return 'Not ready on the server yet — try again shortly.';
    case 429: return 'Rate limit — the server is busy, try again shortly.';
    default:
      if (status >= 500 && status <= 599) return 'The server had a problem — try again shortly.';
      return `Server error (HTTP ${Number.isInteger(status) ? status : 0}).`;
  }
}

/**
 * The app-written message for a relay error body. `locked` + `retry_minutes` (the identity gate's 429
 * shape) gives the lock sentence with the minutes as a bounded integer (the app reads it back).
 */
export function relayErrorText(status: number, body: unknown): { message: string; code?: string; relayMessage: string } {
  const d = (body && typeof body === 'object' ? body : {}) as { message?: unknown; error?: unknown; code?: unknown; locked?: unknown; retry_minutes?: unknown };
  const prose = typeof d.message === 'string' && d.message ? d.message : typeof d.error === 'string' ? d.error : '';
  const relayMessage = cleanRelayText(prose);
  const code = typeof d.code === 'string' && CODE_RE.test(d.code) ? d.code : undefined;
  if (code && Object.prototype.hasOwnProperty.call(CODE_TEXT, code)) return { message: CODE_TEXT[code], code, relayMessage };
  if (d.locked === true) {
    const n = Number(d.retry_minutes);
    const mins = Number.isFinite(n) && n > 0 ? String(Math.min(Math.max(Math.floor(n), 1), 1440)) : '?';
    return { message: `Rate limit — locked, try again in about ${mins} minutes`, ...(code ? { code } : {}), relayMessage };
  }
  const known = KNOWN_BY_KEY.get(relayMessage.toLowerCase());
  if (known) return { message: known, ...(code ? { code } : {}), relayMessage };
  for (const [re, text] of KNOWN_RELAY_PATTERNS) if (re.test(relayMessage)) return { message: text, ...(code ? { code } : {}), relayMessage };
  return { message: relayStatusText(status), ...(code ? { code } : {}), relayMessage };
}

/** a RelayError for an HTTP error answer */
export function relayErrorFor(status: number, body: unknown): RelayError {
  const t = relayErrorText(status, body);
  return new RelayError(t.message, { status, code: t.code, data: body, relayMessage: t.relayMessage });
}

/**
 * The relay's own words for an error (cleaned, truncated) when it is a RelayError, else the error's
 * message — for logs and for the library's classification of relay answers ("session not found",
 * "rate limit", …), never for display.
 */
export function relayDetailOf(e: unknown): string {
  if (e && typeof e === 'object') {
    const rm = (e as { relayMessage?: unknown }).relayMessage;
    if (typeof rm === 'string' && rm) return rm;
    const m = (e as { message?: unknown }).message;
    if (typeof m === 'string') return m;
  }
  return String(e ?? '');
}

/** the relay's stable error code, if it sent a well-formed one */
export function relayErrorCode(e: unknown): string | undefined {
  const c = e && typeof e === 'object' ? (e as { code?: unknown }).code : undefined;
  return typeof c === 'string' && CODE_RE.test(c) ? c : undefined;
}
