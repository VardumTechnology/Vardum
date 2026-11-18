// VEIL RELAY — self-hosted Phase 1 (b197-r9) + UnifiedPush (GrapheneOS push, 19 Oct)
// The exact URL contract the native client speaks (extracted from relay.ts/auth.ts/chat.ts).
// Deno + Deno KV. Zero external dependencies.
//
// RUN:  deno run -A main.ts          (listens on :8000)
// SEED: deno run -A seed.ts          (creates the founder's user — see seed.ts)
//
// PHASE 1 SCOPE (honest):
//   ✓ auth: login/register/verify-otp/logout (register auto-verifies — OTP email is Phase 2)
//   ✓ generic entity REST: VeilSession, VeilEnvelope, User, VeilAuthNonce, VeilVault, VeilNote...
//   ✓ functions: submitEnvelope, veilSessionGate (activate/notify/burn), purgeExpiredEnvelopes
//   ✓ sweeper: internal interval, purges expired envelopes every 10 min
//   ✗ Phase 2: OTP email delivery, group gate details, agents, vault signed-URLs, TLS (proxy in front)
//
// ---------------------------------------------------------------------------
// b71 (audit F-30): WHAT THIS RELAY STORES (Deno KV at VEIL_KV_PATH, files in
// VEIL_BLOB_DIR). Message content is end-to-end encrypted; everything below is
// metadata the operator (anyone with the database) can read.
//   Accounts   ["user", id]: the sign-in label (an email, real or invented, or a
//              phrase-derived v…@veil.app), a salted PBKDF2 password hash, created
//              time, primary Vardum ID. ["user_email", label] → id. Login tokens are
//              stored only as one-way hashes (["auth", "h:…"]). b75r1 (audit REL-03): a
//              label given up by a rebind is kept only as unkeyed hashes (retired-label
//              tag, group-account hash) on the user row and ["label_retired_h", tag].
//   Identities ["veil_identity", vid]: public keys (IK, signed prekeys), and
//              account_hash = SHA-256("veil-acct:" + account id) — UNKEYED, so the
//              operator can tie every identity to its account. (Keying it with a
//              secret held outside KV would orphan every existing row; not done.)
//              b75r1: a retired identity's row is deleted when the primary moves on
//              (REL-01); ["veil_identity_pending", vid, account hash] holds a register
//              made beside another account's unbound row, 30 min (REL-02).
//              b76: ["veil_opk", vid, ts, id] — the identity's signed one-time prekey
//              pairs (public halves; each deleted when handed out, at most 21 days),
//              and ["veil_opk_owner", vid] — the random tag of the phone that published
//              them. Hand-outs leave per-account / per-ID rate-limit rows (Throttles).
//   Reg. lock  b76: ["reglock", account hash] when the owner turned the registration lock
//              on: a random salt, a PBKDF2 verifier of the phone's PIN proof (never the
//              PIN), the hash of the owning phone's device key, the primary Vardum ID,
//              when the account last checked in, and the wrong-PIN count. Deleted by
//              "off", a duress purge, an account delete and a primary-identity change.
//   Chats      b77 (sealed sender): a 1:1 VeilSession row is a RENDEZVOUS only. While a
//              request is pending it holds the two Vardum IDs (contact chats: the
//              addressee's request inbox is found by responder_veil_id) and the
//              initiator's request signature, public handshake keys, write-secret
//              hashes and dials — but no account id and no owner tag (only _init_tag,
//              an HMAC of the creating account under a memory-only key). The join (no
//              login) clears both Vardum IDs and the signature and stores no joiner
//              account; the initiator reads the answer with the no-login gate "status"
//              and then ends the row ("end": deleted, token retired), so a finished
//              setup leaves nothing. A joined row nobody ends dies 7 days after the
//              join. Invite-link rows never carried Vardum IDs. Rows made by apps
//              before b77 keep what they stored (both account ids, both Vardum IDs)
//              until they end or age out. Group rows are unchanged: the creator's
//              account id and owner tag on every seat; each joined seat names its
//              member's account (Groups below).
//   Mailboxes  b77: ["mbox", id] — an anonymous 1:1 delivery address (one per chat
//              direction; the id is derived on both phones from the chat's root and
//              never sent with any account, token or Vardum ID): SHA-256 of its send,
//              read capabilities, a TTL cap, the recipient's "verified" flag, b77p: an
//              optional sealed wake box (the recipient's push address, AES-GCM under a key
//              from the chat's wake capability, which the relay sees only when the peer
//              submits and never stores — see Push), the hour it was last used and the
//              next sequence number. b77p (audit 2 VAR-01): a mailbox is opened with a
//              BLIND-SIGNED open token: ["open_spent", H(token)] (until the key lapses).
//              Nothing ties a token to the join it was issued at. b77p round 2 (owner
//              decision 3): the RSA issuer key (a secret — it can mint opens of new
//              mailboxes, nothing else) is NOT in the database: it lives in the file
//              VEIL_OPEN_ISSUER_KEY_FILE names (current + previous key, mode 600, never in
//              a backup). During the transition window (VEIL_COMPAT_UNTIL, round 2,
//              decision 4) a legacy mailbox may carry b77's push_ref instead of a box, and
//              ["mbox_ticket", H(ticket)] rows exist for legacy joins; both go when it ends.
//              ["compat_until_default"]: the window's default end (30 days from the first start).
//              ["mbox_retired_h", SHA-256("veil-mbox-retired:" + id)] (400 days; b77r1: a
//              hash, it was the plain id) marks an ended / swept mailbox; b77r2: a
//              mailbox ended before it was opened gets an 8-day marker {pre, cap_h, exp}
//              instead (cap_h: SHA-256 of the capability that ended it; b77r3: and at
//              most one more, cap_h2, from a second end naming another one). Nothing
//              stored pairs the two mailboxes of a chat, or ties one to a token or an
//              account; every 1:1 delivery route takes no login.
//              b77n (audit VAR-04): a call's TURN grant ["turn_grant", SHA-256("veil-turn-grant:" + id)]
//              = {o, a, exp, ro, ra} holds the TAGS of the two mailboxes that opened and
//              approved it for at most 5 minutes (KV expiry), then nothing (spec §12.12).
//   Messages   ["entity","VeilEnvelope",…]. b77: a 1:1 envelope is {id, mbox, seq,
//              ciphertext, iv, header (an encrypted, fixed-length string), byte_length,
//              protocolVersion, expires_at} — no sender tag, no owner tag, no token, no
//              creation time (b77n, pre-audit L2: expires_at is rounded DOWN to a step of at
//              most a tenth of the life, at most an hour, so it no longer gives the submit
//              time to the second; see coarseExpiry). ["env_by_mbox", mbox, id] indexes it. A GROUP envelope
//              keeps the posting seat's token, the group sender tag, created/expiry
//              time and a per-row owner tag SHA-256("veil-owner:" + account id + row
//              id) (unkeyed: peers can't link them across rows, the operator can
//              recompute them). ["env_by_sess", token, id] indexes envelopes by seat.
//   Groups     member rows (Vardum ID, IK, account hash, b73: whether the creator has
//              admitted the member yet), the group name (an encrypted blob), epoch and
//              group PQ key, deny entries, wrap requests. b75r1: burn votes are
//              opaque markers under a memory-only key, i.e. a count (REL-05); a
//              creator's account delete or purge removes the whole group (REL-04/06).
//   Files      encrypted blobs; per-blob owner / chat tags (unkeyed hashes). b77: a 1:1
//              file (sealedUpload) carries only ["blob_mbox", id] =
//              SHA-256("veil-blob-mbox:" + mailbox), no owner and no account (b77r1: and
//              the index entry ["blob_by_mbox", that hash, id]).
//   Push       b77p round 2 (owner decision 1): NO ACCOUNT-LEVEL PUSH. A mailbox's wake is its
//              own sealed box (Mailboxes); the relay sends no push addressed by account or
//              Vardum ID (no contact-request, group-post or group-seat pushes), and b77p
//              phones keep no push row. VeilPushToken rows (a push address tagged with the
//              account hash, b77's push_refs and their ["push_ref", ref, row id] index)
//              exist only for LEGACY (pre-b77p) phones during the transition window — they
//              wake those phones' push_ref mailboxes, exactly b77's mailbox -> account link
//              (spec §12.19.4) — and are all deleted when it ends.
//   Analytics  OnboardingStep / AttributionSource rows the app sends (step names,
//              times; b77t (audit 5 C-10): no owner tag, nothing naming the account) — deleted after ANALYTICS_KEEP_DAYS (30). The
//              Vardum ID older apps put on attribution rows is dropped.
//   Throttles  rate-limit / lockout rows keyed by account id, label hash, chat-token
//              hash, push-address hash, Vardum ID or a network tag (an HMAC of the
//              address under a daily key held outside the database — b77s (audit 4 WS-01): in
//              this process's MEMORY only, today's and yesterday's key; never on disk, so a
//              restart starts per-network throttles afresh; see ipTagKey).
//              b73: used login puzzles (["login_pow_used", random nonce], 10 min).
//              b77: per-mailbox limits are keyed by SHA-256("veil-mbox-tag:" + mailbox),
//              never by an account; the request-per-addressee cap ("req:") by two
//              memory-only HMAC tags (account, Vardum ID), like the one-time-key caps.
//              b77q (audit 3 RF-1): the TURN limiters ("turngrant:", "turnappr:", "turnpoll:",
//              "turnmb:") by a memory-only HMAC of the mailbox (turnLimitTag) — the unkeyed tag
//              paired a chat's two mailboxes. b77q (RF-2): the ring / push-coalesce rows hold
//              the minute of the last wake, not its millisecond.
//              All expire on their own (b77n, pre-audit I1: this said "the longest after 25 h",
//              which was wrong): per-minute / per-hour buckets within 2 h; per-day caps and the
//              daily byte counters (env_quota*, upload_quota*, vault_pin_net*, ent_bytes_net*,
//              mbox_*quota/count) after 48 h (2 × the window + 1 min); login guards after 24–25 h.
//              Not throttles, and longer: retired session tokens and ended-mailbox markers
//              (400 days, hashes), the per-account row-cap sequence (["row_cap_seq"], until the
//              account is deleted). b77n (pre-audit L3): ["ix_acct" / "ix_gmem" / "ix_vault_uri" /
//              "ix_push_tok" / "ix_devlink_uri"] index entries live exactly as long as their rows;
//              b77s (audit 4 RE-02): so do ["ix_gsess" / "ix_gsess_init" / "ix_gdeny"] (group seats by group
//              and by creating account, deny entries by group), and (b77s accounts) ["auth_acct", account
//              id, token hash] beside each sign-in token row (it names nothing the token row doesn't).
//   Secrets    b73 (audit): V-18 — none in the database any more. The blob-URL signing
//              key, the peer-pseudonym key, the login-puzzle key and (b77s, audit 4 WS-01) the
//              network-tag day keys are made at start-up and held only in this process's memory (older
//              relays' stored copies are deleted at boot). A restart voids signed file
//              links issued in the 10 minutes before it, open login puzzles, and changes
//              every peer pseudonym (the app does not rely on them staying the same).
//   Stats      daily totals only (no who).
// Account delete removes every row naming the account (fnVeilAccountDelete); the
// nightly backups (backup.sh) keep copies until they age out (7–14 days).
// b75 (audit RL-03, audit 2 V6): WHAT "DELETED" MEANS ON DISK. Every delete here (burn,
// expiry, chat end, account delete) removes the row from the live database at once, but
// Deno KV stores it in SQLite, and a SQLite delete only marks space free: the row's bytes
// (ciphertext and the metadata above) stay in the write-ahead log (kv.db-wal) and in free
// pages of kv.db until overwritten. Deno KV offers no secure_delete or VACUUM, so the
// nightly backup.sh, with the relay stopped, checkpoints and truncates the WAL and VACUUMs
// kv.db, then backs up only that compacted file. Precisely, deleted data can remain:
//   - in the live database files: rows deleted since the last nightly run, up to ~1 day;
//   - in backups: each backup holds the rows that were live when it was taken, for 7 days
//     (nightly) or 14 days (pre-update), each up to a day longer (whole-day ageing), so a
//     deleted row can sit in a backup for up to about 15 days;
//   - on the disk: blocks the old files used are freed, not overwritten, until reused
//     (no full-disk encryption is assumed here);
//   - media blobs: deleted files are unlinked (same disk caveat); a never-opened one waits
//     for the 49 h sweep.
// Message contents stay end-to-end encrypted in every one of these places.
// The relay never stores IP addresses, message plaintext, nicknames or contacts'
// names. It does see each request's address in memory while handling it.
// ---------------------------------------------------------------------------

import { KV } from "./kv.ts";

// Port is env-configurable so a TEST instance can run beside production without
// touching it (systemd sets nothing → 8000; sandbox runs set VEIL_PORT=8001)
const PORT = Number(Deno.env.get("VEIL_PORT") || 8000);
const j = (body: unknown, status = 200, headers: Record<string, string> = {}) =>
  new Response(JSON.stringify(withErrorCode(body, status)), { status, headers: { "Content-Type": "application/json", ...headers } });
const json = j; // alias — both spellings used across handlers

/**
 * b77m (audit VAR-20, relay half): every error answer (status >= 400 with a JSON object body)
 * carries a STABLE machine-readable `code` beside its prose `message` / `error`, so the app can
 * show its own text for each code instead of whatever prose a relay sends (a hostile relay's
 * prose was shown verbatim in trusted banners). `message` is unchanged (older apps read it).
 * A handler that sets `code` itself keeps it. The message
 * patterns map to specific codes, anything else to the status's generic one. Never rename a
 * code: apps map them to local text.
 */
const ERROR_CODE_BY_STATUS: Record<number, string> = {
  400: "bad_request", 401: "unauthorized", 403: "forbidden", 404: "not_found", 405: "bad_request", 408: "too_slow",
  409: "conflict", 410: "session_ended", 413: "too_large", 423: "reglock", 425: "mailbox_not_open", 429: "rate_limited",
  500: "internal", 502: "busy", 503: "busy", 507: "storage_full",
};
/** first match wins. The names the app maps (device library, b77m) are used wherever they fit:
 *  session_not_found session_ended chat_ended seat_ended not_member not_admitted invalid_credential
 *  invalid_login unauthorized account_deleted account_not_found identity_not_found already_registered
 *  mailbox_not_open mailbox_retired too_large rate_limited daily_limit busy not_found bad_request
 *  forbidden conflict reglock pow_required push_other_account push_confirm; a few relay-only ones
 *  (storage_full, vault_storage_limit, too_slow, stale_request, calls_need_verified, ...) fall back to
 *  the app's per-status sentence. */
const ERROR_CODE_BY_MESSAGE: [RegExp, string][] = [
  [/^Unauthorized$/, "unauthorized"],
  [/^Invalid email or password$/, "invalid_login"],
  [/^Account deleted$/, "account_deleted"],
  [/^Account not found$/, "account_not_found"],
  [/Email already registered/, "already_registered"],
  [/^Could not create an account with that email/, "signup_refused"],
  [/isn't taking new accounts/, "signups_closed"],
  [/^Choose a password of at least/, "weak_password"],
  [/^Enter an email address/, "bad_label"],
  [/^Daily upload limit reached|^Daily message limit reached|new vaults from this network today/, "daily_limit"],
  [/storage is full/i, "storage_full"],
  [/^Vault storage limit/, "vault_storage_limit"],
  [/^Vault limit reached/, "vault_limit"],
  [/^Note limit reached/, "note_limit"],
  [/^This group is full$/, "group_full"],
  [/too slow/i, "too_slow"],
  [/too large/i, "too_large"],
  [/^This request is too old/, "stale_request"],
  [/^Session not found$/, "session_not_found"],
  [/^This session is not active$|^Session is not available$/, "session_ended"],
  [/^This chat has ended$/, "chat_ended"],
  [/^This seat has ended$/, "seat_ended"],
  [/^Mailbox not open yet$/, "mailbox_not_open"],
  [/^Identity not found$|^Unknown identity$/, "identity_not_found"],
  [/^Calls need a conversation/, "calls_need_verified"],
  [/^No approved call|^A call is approved from the other phone/, "call_not_approved"], // b77n (audit VAR-04): TURN grants
  [/^Calling relay not configured$/, "calls_unavailable"],
  [/^Invalid (session|mailbox) credential$/, "invalid_credential"],
  [/has not let you in yet/, "not_admitted"],
  [/not a member of this group|^Not a member of this group$|removed from the group|^Only members of this group/i, "not_member"],
  [/notification address is registered to another account/, "push_other_account"],
  [/^Confirm this device's notification address/, "push_confirm"],
  [/^Busy|busy — try again|^Try again|^Upload busy|relay is busy/i, "busy"],
  [/^Too many|try again later|try again tomorrow/i, "rate_limited"],
  [/^Update Vardum/, "update_required"],
  [/^Not found$|^Unknown file$/, "not_found"],
  [/^Not your |^Not authorised$|^Not allowed$|^That .* belongs to another/, "forbidden"],
  [/signature verification failed|^Bad signature$|signatures do not verify/i, "bad_signature"],
  [/^Malformed|^Invalid |^Missing |required$|malformed$/, "bad_request"],
];
function errorCodeFor(status: number, body: Record<string, unknown>): string {
  if (body.pow_required === true) return "pow_required";
  if (body.reglock_required === true) return "reglock";
  if (body.push_verify_required === true) return "push_confirm";
  if (body.ended === true) return "chat_ended";
  if (body.not_open === true) return "mailbox_not_open";
  const text = String(body.message ?? body.error ?? "");
  if (text) for (const [re, code] of ERROR_CODE_BY_MESSAGE) if (re.test(text)) return code;
  if (status === 429 || body.locked === true) return "rate_limited";
  return ERROR_CODE_BY_STATUS[status] ?? (status >= 500 ? "busy" : "bad_request");
}
function withErrorCode(body: unknown, status: number): unknown {
  if (status < 400 || !body || typeof body !== "object" || Array.isArray(body)) return body;
  const b = body as Record<string, unknown>;
  if (typeof b.code === "string" && b.code) return body;
  return { ...b, code: errorCodeFor(status, b) };
}
const nowIso = () => new Date().toISOString();
const rid = () => crypto.randomUUID().replace(/-/g, "").slice(0, 24);

// ---------- password hashing (PBKDF2-SHA256, 100k — WebCrypto, works in Deno) ----------
/** b54 (audit L-4 / Q-8): constant-time equality for secret-derived strings
 *  (write-secret hashes, password hashes). Length is not secret (fixed-size
 *  hex digests); the content comparison never short-circuits. */
function ctEq(a: string, b: string): boolean {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}

/** b71 (audit F-03): PBKDF2 rounds for every NEW password hash. A user row records the
 *  rounds its hash used (`iter`); rows without it are the old 100k hashes, which still
 *  verify and are re-hashed at this count on the next successful sign-in. */
const PBKDF2_ITERATIONS = 600_000;
const PBKDF2_LEGACY_ITERATIONS = 100_000;
/** b71 (audit F-03): new email accounts need at least this many characters */
const PASSWORD_MIN_LEN = 12;

/**
 * b77m (audit VAR-28): a relay-wide budget for password hashing. Every login (unknown labels
 * included), sign-up and provision costs a 600k-round PBKDF2 (~0.5 s of one core); nothing
 * capped how many ran at once, so rotating /64s of one /56 (whose wider budgets fall back to a
 * cheap puzzle) could keep a 2-vCPU host hashing for strangers and queue real sign-ins.
 *  - at most PBKDF2_MAX_CONCURRENT hashes run at once; up to PBKDF2_MAX_QUEUE more wait (at most
 *    PBKDF2_QUEUE_WAIT_MS); past either the request fails fast: 429 "busy" with Retry-After
 *  - one network holds at most PBKDF2_PER_NETWORK of those places (running or waiting), its /56
 *    and /48 at most PBKDF2_PER_WIDE_NETWORK (flat, as the upload slots: there are only so many)
 *  - "local" (a trusted loopback test relay) skips the per-network part only.
 * In memory only. Env overrides are for tests.
 */
const PBKDF2_MAX_CONCURRENT = Number(Deno.env.get("VEIL_PBKDF2_MAX_CONCURRENT")) || 2;
const PBKDF2_MAX_QUEUE = Number(Deno.env.get("VEIL_PBKDF2_MAX_QUEUE")) || 16;
const PBKDF2_QUEUE_WAIT_MS = Number(Deno.env.get("VEIL_PBKDF2_QUEUE_WAIT_MS")) || 10_000;
const PBKDF2_PER_NETWORK = Number(Deno.env.get("VEIL_PBKDF2_PER_NETWORK")) || 2;
const PBKDF2_PER_WIDE_NETWORK = Number(Deno.env.get("VEIL_PBKDF2_PER_WIDE_NETWORK")) || 4;
/** thrown when the hashing budget is spent; the router answers 429 { code: "busy" } */
class PbkdfBusyError extends Error {
  constructor() { super("password hashing busy"); this.name = "PbkdfBusyError"; }
}
let pbkdfActive = 0;
const pbkdfWaiters: (() => void)[] = [];
const pbkdfNetUse = new Map<string, number>();
// (b77m owner round: pbkdfWouldRefuse split into pbkdfGlobalFull, which still refuses "busy", and pbkdfNetFull, which asks for the network puzzle — next to netPowGate)
/**
 * b77s (audit 4 RA-04): requests that solved the network puzzle because their network's share was full (`overflow`)
 * used to hash with NO per-network limit (withPbkdfSlot(null)), so one IPv6 /48 (65 536 /64s, ~256 puzzle passes a
 * minute) could take the whole relay's hashing capacity and turn every email sign-in into 429 "busy". Now they run in
 * a LOW-PRIORITY lane:
 *  - they wait behind every normal request (a freed slot goes to a normal waiter first) and never queue among them;
 *  - at most PBKDF2_OVERFLOW_PER_NETWORK of them (running or waiting) per network — its /64 or IPv4 tag, and its
 *    /56 and /48 each — and at most PBKDF2_OVERFLOW_MAX relay-wide;
 * so one wide network holds at most its normal share (PBKDF2_PER_WIDE_NETWORK) plus one overflow place, well under
 * the relay's PBKDF2_MAX_CONCURRENT + PBKDF2_MAX_QUEUE.
 */
const PBKDF2_OVERFLOW_PER_NETWORK = Number(Deno.env.get("VEIL_PBKDF2_OVERFLOW_PER_NETWORK")) || 1;
const PBKDF2_OVERFLOW_MAX = Number(Deno.env.get("VEIL_PBKDF2_OVERFLOW_MAX")) || Math.max(1, Math.floor(PBKDF2_MAX_QUEUE / 4));
const pbkdfLowWaiters: (() => void)[] = [];
const pbkdfOvfUse = new Map<string, number>();
let pbkdfOvfTotal = 0;
/** `overflowOk`: this request solved the network puzzle that covers a full per-network share — it hashes in its
 *  network's normal share if there is room, else in the low-priority overflow lane (never outside every limit) */
async function withPbkdfSlot<T>(req: Request | null, run: () => Promise<T>, overflowOk = false): Promise<T> {
  // per network first (nothing taken yet, so a refusal holds nothing)
  const netKeys: string[] = [];
  let overflow = false;
  let use = pbkdfNetUse;
  let ovfTaken = false;
  if (req) {
    const net = await clientTag(req);
    if (net !== "local") {
      const wide = await clientWideTags(req);
      const keys: [string, number][] = [[net, PBKDF2_PER_NETWORK]];
      for (const w of wide) keys.push([w.bits + ":" + w.tag, PBKDF2_PER_WIDE_NETWORK]);
      if (keys.some(([k, cap]) => (pbkdfNetUse.get(k) ?? 0) >= cap)) {
        if (!overflowOk) throw new PbkdfBusyError();
        // b77s (audit 4 RA-04): the overflow lane's own, much smaller, per-network and relay-wide caps
        overflow = true;
        use = pbkdfOvfUse;
        for (const kc of keys) kc[1] = PBKDF2_OVERFLOW_PER_NETWORK;
        if (keys.some(([k, cap]) => (use.get(k) ?? 0) >= cap) || pbkdfOvfTotal >= PBKDF2_OVERFLOW_MAX) throw new PbkdfBusyError();
        pbkdfOvfTotal++; ovfTaken = true;
      }
      for (const [k] of keys) { use.set(k, (use.get(k) ?? 0) + 1); netKeys.push(k); }
    }
  }
  const releaseNet = () => {
    for (const k of netKeys) { const m = (use.get(k) ?? 1) - 1; if (m <= 0) use.delete(k); else use.set(k, m); }
    if (ovfTaken) pbkdfOvfTotal = Math.max(0, pbkdfOvfTotal - 1);
  };
  try {
    // b77s (audit 4 RA-04): an overflow request takes a free slot only when no normal request is waiting
    const mustWait = overflow ? (pbkdfActive >= PBKDF2_MAX_CONCURRENT || pbkdfWaiters.length > 0) : pbkdfActive >= PBKDF2_MAX_CONCURRENT;
    if (mustWait) {
      const queue = overflow ? pbkdfLowWaiters : pbkdfWaiters;
      if (!overflow && pbkdfWaiters.length >= PBKDF2_MAX_QUEUE) throw new PbkdfBusyError();
      const got = await new Promise<boolean>((res) => {
        const wake = () => { clearTimeout(timer); res(true); };
        const timer = setTimeout(() => { const i = queue.indexOf(wake); if (i >= 0) queue.splice(i, 1); res(false); }, PBKDF2_QUEUE_WAIT_MS);
        queue.push(wake);
      });
      if (!got) throw new PbkdfBusyError();
      // (a woken waiter inherits the slot its waker gave up: pbkdfActive was not decremented)
    } else pbkdfActive++;
    try { return await run(); } finally {
      const next = pbkdfWaiters.shift() ?? pbkdfLowWaiters.shift(); // b77s (audit 4 RA-04): normal waiters first
      if (next) next(); else pbkdfActive = Math.max(0, pbkdfActive - 1);
    }
  } finally { releaseNet(); }
}

/** PBKDF2-SHA256 of a password, inside the relay-wide hashing budget (withPbkdfSlot; `req` adds
 *  the caller's per-network share). Throws PbkdfBusyError when the budget is spent.
 *  b77m (owner, carrier NAT): `skipNet` — this request already solved a per-network puzzle (netPowGate),
 *  so only the relay-wide part of the budget applies to it. */
function hashPassword(password: string, salt: string, iterations = PBKDF2_ITERATIONS, req: Request | null = null, skipNet = false): Promise<string> {
  return withPbkdfSlot(req, () => pbkdf2Hex(password, salt, iterations), skipNet && !!req); // b77s (audit 4 RA-04): a puzzle-passed request hashes in the low-priority lane
}

/**
 * b77m (owner, VAR-28 follow-up): phrase-derived accounts are checked with ONE salted SHA-256, not a 600k-round
 * PBKDF2, and never wait for the hashing budget. Their "password" is not chosen by a person: the app derives it
 * on the phone as base64(SHA-256("veil:b112:account-pass:" + the 24 words)) (vendor/device/src/silent-auth.ts),
 * a 256-bit value from a 256-bit phrase, so stretching adds nothing an attacker with the database could not
 * already not do (2^256 guesses), while it made every 24-word sign-in compete with strangers for two hashing
 * slots — and one shared carrier NAT address could keep a whole network's users out.
 * Eligible = a phrase label (v<24 hex>@veil.app, PHRASE_LABEL_RE) AND a secret of exactly that form (44 base64
 * characters = 32 bytes). The relay can't prove a secret came from the phrase: someone who hand-makes a
 * phrase-format label and picks a weak 32-byte value weakens only their own account. Every other account (an
 * email and a person's password) keeps PBKDF2 and the budget. Stored as { kdf: "phrase-sha256-v1", salt,
 * passHash = hex SHA-256("vardum-phrase-acct-v1:" + salt + ":" + secret) }; compared in constant time. A row
 * from before (PBKDF2) is checked with PBKDF2 once and rewritten in the cheap form after that correct sign-in.
 */
const PHRASE_KDF = "phrase-sha256-v1";
const PHRASE_SECRET_RE = /^[A-Za-z0-9+/]{43}=$/;
function phraseCheapEligible(email: string, password: string): boolean {
  return PHRASE_LABEL_RE.test(email) && PHRASE_SECRET_RE.test(password);
}
async function phraseSecretHash(password: string, salt: string): Promise<string> {
  return sha256hex("vardum-phrase-acct-v1:" + salt + ":" + password);
}
/** the stored hash of a new account's secret: the cheap form for an eligible phrase account, else PBKDF2 */
async function newPasswordRecord(email: string, password: string, salt: string, req: Request | null, skipNet = false): Promise<{ passHash: string; iter?: number; kdf?: string }> {
  if (phraseCheapEligible(email, password)) return { passHash: await phraseSecretHash(password, salt), kdf: PHRASE_KDF };
  return { passHash: await hashPassword(password, salt, PBKDF2_ITERATIONS, req, skipNet), iter: PBKDF2_ITERATIONS };
}
/** equal-time work for a refused sign-up (a taken label): the same hash a new account of that kind costs */
async function dummyPasswordWork(email: string, password: string, req: Request | null, skipNet = false): Promise<void> {
  if (phraseCheapEligible(email, password)) await phraseSecretHash(password, "x".repeat(32));
  else await hashPassword(password, "x".repeat(32), PBKDF2_ITERATIONS, req, skipNet);
}
async function pbkdf2Hex(password: string, salt: string, iterations: number): Promise<string> {
  const keyMaterial = new TextEncoder().encode(salt + ":" + password);
  const key = await crypto.subtle.importKey("raw", keyMaterial, "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt: new TextEncoder().encode(salt), iterations, hash: "SHA-256" },
    key,
    256,
  );
  return [...new Uint8Array(bits)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

// ---------- auth ----------
async function createUser(email: string, password: string, req: Request | null = null, skipNet = false) {
  email = email.toLowerCase().trim();
  // b198 ANONYMOUS SIGNUP: the email is a self-declared label — invented
  // addresses are FINE (never verified, never contacted). Only structural
  // sanity is enforced so KV keys stay usable; the signup screen discloses
  // that a forgotten password + lost phrase = unrecoverable account.
  if (!email || email.length > 64 || !email.includes("@")) throw new Error("Enter an email address — it can be invented; it is never verified or contacted");
  // b70 (audit RLY-5): no empty or trivially short passwords
  // b71 (audit F-03): 12 characters for new accounts (existing accounts keep signing in)
  if (typeof password !== "string" || password.length < PASSWORD_MIN_LEN || password.length > 512) throw new Error(`Choose a password of at least ${PASSWORD_MIN_LEN} characters`);
  const existing = (await KV.get<string>(["user_email", email])).value;
  if (existing) throw new Error("Email already registered");
  // Batch D (D-17, RV-12): a label given up by a rebind is never handed out again —
  // legacy group rows are keyed on a hash of the label
  if (await labelRetired(email)) throw new Error("Email already registered"); // b75r1 (audit REL-03): by hash
  const uid = "u_" + rid();
  const salt = crypto.randomUUID().replace(/-/g, "");
  // b77m (audit VAR-28); b77m (owner): a phrase account's secret takes the cheap form (newPasswordRecord)
  const rec = await newPasswordRecord(email, password, salt, req, skipNet);
  const user = { id: uid, email, salt, ...rec, verified: true, created: nowIso(), primary_scan_none: true /* b77u (audit 6 U-M14 / IH L-7): a new account has no pre-b70 identity rows to scan for */ };
  // b70 (re-review): the label is claimed atomically — two sign-ups racing for
  // one label used to both succeed and leave an orphaned account
  const claimed = await KV.atomic().check({ key: ["user_email", email], versionstamp: null }).set(["user_email", email], uid).set(["user", uid], user).commit();
  if (!claimed.ok) throw new Error("Email already registered");
  // b77s (audit 4 RA-01): the relay-wide sign-up budget counts accounts that exist — charged only now, after the
  // claim committed (a refused or failed sign-up never spends it); "local" is never counted
  if (req && (await clientTag(req)) !== "local") await signupCharge(signupKindOf(email)).catch(() => undefined);
  void bumpStat("accounts");
  return user;
}


/** b77m (audit VAR-49): the "[auth-debug]" lines (they log request paths, which carry entity ids)
 *  are written only by a relay started with VEIL_AUTH_DEBUG=1 (a test relay); production logs none */
const AUTH_DEBUG = Deno.env.get("VEIL_AUTH_DEBUG") === "1";
/** b77m (audit VAR-44): a sign-in token's sliding window — set when the token is issued (an unused
 *  token used to get its 30 days only at first use, so it lived the full 180-day maximum) */
const TOKEN_IDLE_MS = 30 * 86400_000;
/** b70 (audit RLY-6): the longest any sign-in token lives, used or not */
const TOKEN_MAX_AGE_MS = 180 * 86400_000;

/**
 * b70 (re-review 13): one handler at a time per key, for read-then-write handlers that two
 * requests could interleave (identity register vs bind, group attest/rotate/evict). The
 * relay is one process, so an in-memory queue is enough; with more than one process these
 * would need KV versionstamp checks instead.
 * b75r2: the single-process assumption (these locks, the memory-only keys) is stated in
 * docs/protocol-spec.md §12.15.
 */
const handlerLocks = new Map<string, Promise<void>>();
async function withLock<T>(key: string, fn: () => Promise<T>): Promise<T> {
  const prev = handlerLocks.get(key) ?? Promise.resolve();
  let release!: () => void;
  const mine = new Promise<void>((res) => { release = res; });
  const tail = prev.then(() => mine);
  handlerLocks.set(key, tail);
  await prev;
  try { return await fn(); } finally {
    release();
    if (handlerLocks.get(key) === tail) handlerLocks.delete(key);
  }
}

async function authUser(req: Request): Promise<{ userId: string; email: string; tokenCreated: number } | null> {
  const a = await authCheck(req, false);
  return a && "userId" in a && !("gone" in a) ? a : null;
}

/** b77i (I-1): the tombstone a finished account delete leaves for each of the account's sign-in
 *  tokens, keyed by the token's at-rest hash (it names no account), so the delete's own retry can
 *  answer 410 "account deleted" instead of a generic 401 */
const acctGoneKey = (tokenHashPart: string): Deno.KvKey => ["acct_gone", tokenHashPart];
/** b77j: the sweeper's orphan pass (account rows a stopped delete left) runs this often; VEIL_ORPHAN_SWEEP_MS is for TEST relays only */
const ORPHAN_SWEEP_MS = Number(Deno.env.get("VEIL_ORPHAN_SWEEP_MS")) || 3600_000;
let lastOrphanSweep = 0;
const ACCT_GONE_TTL_MS = TOKEN_MAX_AGE_MS; // b77j (M-1): as long as any token could be retried (a hash of a random token, no account id)
/** b77i (I-1): a half-done account delete's work rows (the identities, chats and push addresses it
 *  had started on), so a retry finishes what the interrupted run began; they go with the account */
const acctDelKey = (userId: string, ...rest: string[]): Deno.KvKey => ["acct_del", userId, ...rest];
const ACCT_DEL_WORK_TTL_MS = 30 * 86400_000;

/**
 * The token check. `deleteRoute` is true ONLY for veilAccountDelete (b77i, I-1):
 *  - while the account is being deleted (deleting_at) every other route is refused; the delete
 *    route lets the account's OWN still-valid token through (every other token check still applies:
 *    expiry, maximum age, tokens_after), so a retry re-runs (and finishes) the cascade
 *  - a token whose account is already gone (no user row, or the tombstone a finished delete left)
 *    answers { gone } — the route turns it into 410 "account deleted"
 */
async function authCheck(req: Request, deleteRoute: boolean): Promise<{ userId: string; email: string; tokenCreated: number } | { gone: string; userId?: string } | null> {
  const auth = req.headers.get("Authorization") || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : null;
  // b199: never log header/token bytes — a partial bearer token in journald is
  // a credential fragment on disk. Path only.
  if (!token) {
    if (AUTH_DEBUG) console.log("[auth-debug] NO TOKEN | url: " + new URL(req.url).pathname); // b77m (audit VAR-49): off unless VEIL_AUTH_DEBUG=1
    return null;
  }
  if (token.length > MAX_KEY_PART) return null;
  // b54 hotfix (code review V-18): "h:<hex>" is the at-rest KEY of a hashed
  // token row; presenting it as a bearer token hit that row through the raw
  // fallback below, so a database copy still yielded live logins. Real
  // tokens never start with "h:".
  if (token.startsWith("h:")) return null;
  // b199 (audit: "auth tokens stored raw as KV keys — a DB copy = live
  // tokens"): tokens are stored under a one-way hash. A raw row from before
  // this change is migrated on first use, so nobody is signed out.
  const hk = await authKey(token);
  let r = await KV.get<{ userId: string; email: string; exp?: number; last_used?: number }>(hk);
  if (!r.value) {
    const raw = await KV.get<{ userId: string; email: string; exp?: number; last_used?: number }>(["auth", keySafe(token)]);
    if (raw.value) {
      // b77m (audit VAR-27): moved in ONE step, only if the raw row is still there (a logout that
      // deleted it meanwhile used to be undone by this write)
      // b77s (audit 4 F-01): the boot and sweeper passes (migrateRawAuthRows) move every raw row; this lazy path stays as a fallback
      await KV.atomic().check(raw).check({ key: hk, versionstamp: null }).set(hk, raw.value, { expireIn: TOKEN_MAX_AGE_MS }).set(authIxKey(String(raw.value.userId), String(hk[1])), 1, { expireIn: TOKEN_MAX_AGE_MS }).delete(raw.key).commit();
      r = await KV.get<{ userId: string; email: string; exp?: number; last_used?: number }>(hk);
    }
  }
  // STOLEN-TOKEN WINDOW: auth tokens expire (30 days) and slide while in use —
  // a leaked token is not a lifetime passport. Refresh throttled to 1/hour.
  // b77i (I-1): a token a finished account delete removed — only the delete route asks
  if (!r.value && deleteRoute && (await KV.get(acctGoneKey(String(hk[1])))).value) return { gone: String(hk[1]) };
  let deleting = false;
  if (r.value) {
    const now = Date.now();
    if (r.value.exp && r.value.exp < now) { await dropAuthRow(hk, r.value.userId); return null; }
    // b70 (audit RLY-6): a token older than the account's last sign-in change
    // (rebind) is dead, and no token lives past TOKEN_MAX_AGE_MS however often
    // it is used (the 30-day window slides only inside that)
    let created = Date.parse(String((r.value as { created?: string }).created || "")) || 0;
    if (!created) {
      // a token from before tokens carried their age: its age starts now
      created = now;
      // b77m (audit VAR-27): versionstamp-checked (a logout in between wins)
      await KV.atomic().check(r).set(hk, { ...r.value, created: new Date(now).toISOString(), age_unknown: true }, { expireIn: TOKEN_MAX_AGE_MS }).commit(); // b70 (re-review 4): never "fresh"
      r = await KV.get<{ userId: string; email: string; exp?: number; last_used?: number }>(hk);
      if (!r.value) return null;
    }
    if (now - created > TOKEN_MAX_AGE_MS) { await dropAuthRow(hk, r.value.userId); return null; }
    const userRow = (await KV.get<Record<string, unknown>>(["user", r.value.userId])).value;
    // b70 (re-review 12): no account, no token (a sign-in overlapping an account delete
    // used to leave one that worked)
    // b77i (I-1): on the delete route this is an account delete that got as far as the user row
    // (or a sign-in that overlapped one): the account is gone — 410, never a generic 401
    if (!userRow) {
      if (deleteRoute) await KV.set(acctGoneKey(String(hk[1])), 1, { expireIn: ACCT_GONE_TTL_MS }); await KV.delete(authIxKey(r.value.userId, String(hk[1]))); // (its next retry: 410 too; b77s: the token index entry goes)
      await KV.delete(hk);
      return deleteRoute ? { gone: String(hk[1]), userId: r.value.userId } : null;
    }
    // b70 (re-review 13): while the account is being deleted no request gets in (a note or
    // a prekey rotation written mid-delete used to outlive it).
    // b77i (I-1): except the delete itself, from the account's own token (checked below like any
    // other), so a retry after an interrupted cascade finishes it instead of meeting a 401
    deleting = Number(userRow.deleting_at || 0) > now - 10 * 60_000;
    if (deleting && !deleteRoute) return null;
    // b77s (confirmation review N-3): "sign out other devices" and "change password" set tokens_after too, and name
    // the ONE token that stays (tokens_after_keep: the caller's token hash) — so the cutoff is account-wide (a sign-in
    // that raced the change, or a token the index scan missed, is dead) while the caller stays signed in. (A rebind
    // clears tokens_after_keep, so its cutoff spares no token.)
    const keptByCutoff = !!userRow.tokens_after_keep && String(userRow.tokens_after_keep) === String(hk[1]);
    const after = keptByCutoff ? 0 : Number(userRow.tokens_after || 0);
    if (after && created < after) { await dropAuthRow(hk, r.value.userId); return null; }
    // (a token of unknown age can't prove it is newer than a sign-in change: dead after one)
    if (after && (r.value as { age_unknown?: boolean }).age_unknown) { await KV.delete(hk); return null; } // (b77s: its index entry, if any, is dropped on read / by the sweeper)
    // (b77i: no refresh mid-delete — the write could bring back a token row the cascade just removed)
    // b77m (audit VAR-27): the refresh is checked against the row as read at the top. A logout (or
    // any other revocation) that deleted the row while this request awaited the reads above used to
    // be overwritten by a plain set, so the "logged out" token kept working. Now the write commits
    // only if the row is unchanged; otherwise the row is read again and a deleted token is refused.
    if (!deleting && (!r.value.last_used || now - r.value.last_used > 3600_000)) {
      const ok = (await KV.atomic().check(r).set(hk, { ...r.value, last_used: now, exp: now + TOKEN_IDLE_MS }, { expireIn: Math.max(60_000, TOKEN_MAX_AGE_MS - (now - created)) }).commit()).ok;
      if (!ok && !(await KV.get(hk, { consistency: "strong" })).value) return null;
    }
  }
  if (!r.value) { if (AUTH_DEBUG) console.log("[auth-debug] token MISS | url: " + new URL(req.url).pathname); } // b77m (audit VAR-49)
  // b76 (registration lock): a signed-in request is the account checking in (renews its lock)
  else if (!deleting) { try { await regLockRenew(r.value.userId, r.value as { rl?: string; created?: string }); } catch { /* never blocks a request */ } }
  // b70 (re-review 4): the token's age goes with it (a primary identity needs a fresh sign-in)
  return r.value ? { userId: r.value.userId, email: r.value.email, tokenCreated: (r.value as { age_unknown?: boolean }).age_unknown ? 0 : (Date.parse(String((r.value as { created?: string }).created || "")) || 0) } : null;
}

/**
 * b199 NETWORK-ADDRESS MINIMISATION. The per-network throttles (signup cap,
 * password-guessing lockout) need a stable per-network handle, never the
 * address itself. Each address is replaced by an HMAC tag under a key that
 * rotates every UTC day. b71 (audit F-16): that key now lives ONLY in this
 * process's memory — random per process, never written to the database (it
 * used to sit in KV beside the tags, so a database copy or backup mapped tags
 * back to addresses in seconds per /16). A copy of the database therefore holds
 * tags but no key; once the process restarts or the day rolls over, those tags
 * can't be mapped back by anyone. (Someone able to read this process's memory
 * while it runs could still recover the current key.) A restart just starts
 * every per-network bucket afresh. Every KV row that holds a tag also expires
 * on its own (see THROTTLE_TTL_MS).
 * b71 (audit): a request with no X-Forwarded-For (a direct loopback hit, or
 * anything that reached the relay without going through Caddy) is ONE
 * throttled network, "direct". It is passed through as the unthrottled
 * "local" only when the operator sets VEIL_TRUST_LOCAL=1 (test relays, an
 * operator's SSH-tunnel session). Rate limits used to fail open here.
 */
const TRUST_LOCAL = Deno.env.get("VEIL_TRUST_LOCAL") === "1";
/**
 * b77p (audit VAR-33, VAR-27): PRODUCTION MODE. A relay is in production when VEIL_ENV=production (the
 * deploy scripts write it into the unit) or when VEIL_PUBLIC_ORIGIN is an https origin on a host that is not
 * loopback. In production the relay REFUSES TO START (exit 78) when:
 *   - any test / debug switch is set: VEIL_TEST_* (e.g. VEIL_TEST_ANY_SESSION_TOKEN, VEIL_TEST_DISK_FREE_FILE),
 *     VEIL_AUTH_DEBUG=1, or VEIL_TRUST_LOCAL=1 (unthrottled loopback) — they exist for test relays only;
 *   - VEIL_PUBLIC_ORIGIN is missing or not an https origin (signed file links need it; VAR-27).
 * Any other VEIL_* setting outside the operator list below (the ~40 limit overrides, VEIL_SWEEP_MS, ...) is
 * named in one warning line at start-up, so a forgotten test-sized limit is visible in the journal.
 */
const OPERATOR_SETTINGS = new Set(["VEIL_ENV", "VEIL_PUBLIC_ORIGIN", "VEIL_KV_PATH", "VEIL_BLOB_DIR", "VEIL_PORT", "VEIL_HOST", "VEIL_STATS_TOKEN", "VEIL_UP_HOSTS",
  "VEIL_TRUSTED_PROXY_HOPS", "VEIL_NET_TAG_KEY_FILE", "VEIL_DISK_MIN_FREE_GB", "VEIL_KV_MIN_FREE_GB", "VEIL_KV_MIN_FREE_MB", "VEIL_BACKUP_BLOBS", "VEIL_PROXY_SECRET",
  "VEIL_OPEN_ISSUER_KEY_FILE", "VEIL_COMPAT_UNTIL", // b77p round 2 (owner decisions 3 and 4)
  "VEIL_TURN_TOTAL_QUOTA", "VEIL_TURN_USER_QUOTA"]); // b77q (audit 3 RF-4): the coturn host's own quotas, mirrored
function productionRefusals(env: Record<string, string>): { production: boolean; refusals: string[]; overrides: string[] } {
  const rawOrigin = (env.VEIL_PUBLIC_ORIGIN || "").trim();
  let httpsOrigin = false, publicHost = false;
  try {
    const u = new URL(rawOrigin);
    httpsOrigin = u.protocol === "https:" && (u.pathname === "/" || u.pathname === "") && !u.search && !u.hash && !u.username && !u.password;
    publicHost = !/^(localhost|127\.\d+\.\d+\.\d+|\[::1\])$/i.test(u.hostname) && !u.hostname.endsWith(".localhost");
  } catch { /* not a URL */ }
  const production = (env.VEIL_ENV || "").trim().toLowerCase() === "production" || (httpsOrigin && publicHost);
  const refusals: string[] = [];
  const overrides: string[] = [];
  for (const [k, v] of Object.entries(env)) {
    if (!k.startsWith("VEIL_") || v === "") continue;
    if (k.startsWith("VEIL_TEST_")) refusals.push(k);
    else if (k === "VEIL_AUTH_DEBUG" && v === "1") refusals.push(k);
    else if (k === "VEIL_TRUST_LOCAL" && v === "1") refusals.push(k);
    else if (!OPERATOR_SETTINGS.has(k) && k !== "VEIL_AUTH_DEBUG" && k !== "VEIL_TRUST_LOCAL") overrides.push(k);
  }
  if (production && !httpsOrigin) refusals.push("VEIL_PUBLIC_ORIGIN (missing or not an https origin)");
  // b77t (audit 5 L-26, R3/R5/IH I-01): production without the proxy secret used to only warn, and then trusted any
  // loopback X-Forwarded-For (every per-network limit, the sign-up puzzle included, reset by a forged header)
  if (production && (env.VEIL_PROXY_SECRET || "").trim().length < 16) refusals.push("VEIL_PROXY_SECRET (missing or shorter than 16 characters)");
  return { production, refusals: production ? refusals.sort() : [], overrides: overrides.sort() };
}
{
  const pr = productionRefusals(Deno.env.toObject());
  if (pr.production && pr.refusals.length) {
    console.error(`[relay] REFUSING TO START: production relay (VEIL_ENV=production or an https VEIL_PUBLIC_ORIGIN) with test/debug settings or no public origin: ${pr.refusals.join(", ")}. Remove them from the unit / env file (or, on a test relay, don't set VEIL_ENV=production).`);
    Deno.exit(78);
  }
  if (pr.overrides.length) console.warn(`[relay] non-default limit / tuning settings in effect${pr.production ? " (PRODUCTION)" : ""}: ${pr.overrides.join(", ")}`);
}
/**
 * b77p round 2 (owner decision 4, 31 Oct): THE TRANSITION WINDOW. b77p was a clean break (an app without it could
 * not open mailboxes or bind wakes). Until VEIL_COMPAT_UNTIL the relay ALSO serves pre-b77p ("legacy", b77) phones:
 *   - a join carrying mbox_ticket_hashes (and no open_blind) stores the two one-time open tickets, and mailboxOpen
 *     takes a ticket instead of a blind token;
 *   - mailboxPush takes a push_ref, and a legacy phone may create its account push row (VeilPushToken) and list its
 *     push_refs on it (PUT), so sealedSubmit can wake a mailbox that has no wake box through that row.
 * b77p phones never use any of this (they always join with a blinded token, open with a blind-signed token, seal a
 * wake box and hold no account push row), so the window adds no linkage for them; what the relay CAN still link
 * during the window, for legacy phones only, is listed in docs/protocol-spec.md §12.19.4.
 * VEIL_COMPAT_UNTIL = an ISO date / date-time (UTC when no zone is given: "2026-12-01" is that day's 00:00 UTC);
 * set but EMPTY (or "off") = off (the clean break); UNSET = 30 days from this relay's first start with the setting (recorded
 * once in the database as ["compat_until_default"], so restarts keep the date). After the date every legacy path
 * answers as in the clean break (400 / 410 "Update Vardum"), and the legacy rows (every VeilPushToken row, the
 * ["push_ref"] index, mailbox push_refs, open tickets) are deleted — at boot and by the sweeper.
 * A malformed value refuses to start (exit 78): an operator typo must not silently reopen or close the window.
 */
const COMPAT_RAW = Deno.env.get("VEIL_COMPAT_UNTIL");
const COMPAT_DEFAULT_MS = 30 * 86400_000;
/** the end of the window (ms since the epoch), or null (off); an unset setting is resolved at boot (resolveCompatWindow) */
let compatUntil: number | null = (() => {
  if (COMPAT_RAW === undefined) return null;
  const v = COMPAT_RAW.trim();
  if (!v || v.toLowerCase() === "off") return null; // ("off" too: an empty value is awkward to pass on some platforms)
  const t = /^\d{4}-\d{2}-\d{2}([T ][0-9:.]+(Z|[+-]\d{2}:?\d{2})?)?$/.test(v) ? Date.parse(v.length === 10 ? v + "T00:00:00Z" : v) : NaN;
  if (!Number.isFinite(t)) {
    console.error(`[relay] REFUSING TO START: VEIL_COMPAT_UNTIL="${v.slice(0, 40)}" is not an ISO date (e.g. 2026-12-01 or 2026-12-01T12:00:00Z); leave it empty to turn the transition window off`);
    Deno.exit(78);
  }
  return t;
})();
/** true while the transition window is open (legacy tickets, push_refs and legacy push rows are accepted) */
function compatOn(now = Date.now()): boolean { return compatUntil !== null && now < compatUntil; }
/** boot: an UNSET VEIL_COMPAT_UNTIL means 30 days from the first start that saw it (kept in the database) */
async function resolveCompatWindow(): Promise<void> {
  if (COMPAT_RAW === undefined) {
    const k: Deno.KvKey = ["compat_until_default"];
    for (let attempt = 0; attempt < 5 && compatUntil === null; attempt++) {
      const cur = await KV.get<number>(k, { consistency: "strong" });
      if (typeof cur.value === "number" && Number.isFinite(cur.value)) { compatUntil = cur.value; break; }
      const t = Date.now() + COMPAT_DEFAULT_MS;
      if ((await KV.atomic().check(cur).set(k, t).commit()).ok) compatUntil = t;
    }
  }
  console.log(compatUntil === null
    ? "[relay] transition window OFF (VEIL_COMPAT_UNTIL empty): pre-b77p tickets, push_refs and account push rows are refused"
    : `[relay] transition window ${compatOn() ? "OPEN" : "ENDED"} until ${new Date(compatUntil).toISOString()}${COMPAT_RAW === undefined ? " (default: 30 days from the first start)" : ""}: pre-b77p tickets, push_refs and legacy push rows ${compatOn() ? "accepted" : "refused"}`);
}
console.log(TRUST_LOCAL
  ? "[relay] VEIL_TRUST_LOCAL=1: requests without X-Forwarded-For are UNTHROTTLED (test/operator mode)"
  : "[relay] requests without X-Forwarded-For share one throttled network bucket (\"direct\")");
async function clientTag(req: Request): Promise<string> {
  // Batch D (D-24; report 3 §3.3): the RIGHTMOST value — the address Caddy
  // itself saw. Anything to its left came from the client, so the old
  // leftmost pick let every per-network throttle be dodged with a fresh fake
  // address on each request.
  // b70 (audit RLY-4): "local" only when there is NO forwarded header at all
  // (a direct connection on the loopback interface). A header that is present
  // but empty or malformed ("1.2.3.4," / " ") is one shared, throttled bucket.
  // b71: and only when the operator trusts loopback (VEIL_TRUST_LOCAL=1);
  // otherwise it is the one throttled "direct" network.
  // b71 (review R-6): this assumes EXACTLY ONE trusted proxy (Caddy on the same
  // server, which appends the address it saw). With a second hop in front (a CDN or
  // load balancer) the rightmost value would be that hop's address and every client
  // would share one bucket; such a setup must pick the value N-from-the-right here.
  // b75r2 (audit R2-02): it can — VEIL_TRUSTED_PROXY_HOPS (see TRUSTED_PROXY_HOPS).
  if (!req.headers.has("x-forwarded-for") && TRUST_LOCAL) return "local";
  return await networkTag(networkOf(clientIpOf(req)));
}
/** b75r2 (audit R2-02): how many trusted proxies append to X-Forwarded-For in front of the
 *  relay; the client address is the value this many places from the right. Default 1 (Caddy
 *  on the same server, the deployed setup). A CDN or load balancer in front of Caddy makes
 *  it 2 — and then the server must accept connections ONLY from that hop, or a client
 *  reaching Caddy directly picks its own throttle address (the value one place to its left
 *  is whatever it sent). Anything but a whole number 1–10 is refused at start-up as 1. */
const TRUSTED_PROXY_HOPS = (() => {
  const raw = (Deno.env.get("VEIL_TRUSTED_PROXY_HOPS") ?? "").trim();
  if (!raw) return 1;
  const n = /^\d{1,2}$/.test(raw) ? Number(raw) : NaN;
  if (n >= 1 && n <= 10) return n;
  console.error(`[relay] VEIL_TRUSTED_PROXY_HOPS="${raw.slice(0, 20)}" is not a whole number 1-10; using 1`);
  return 1;
})();
if (TRUSTED_PROXY_HOPS !== 1) console.log(`[relay] client address: X-Forwarded-For value ${TRUSTED_PROXY_HOPS} places from the right (VEIL_TRUSTED_PROXY_HOPS)`);
/**
 * b77p (audit VAR-22): X-Forwarded-For only from Caddy. The relay listens on loopback, and it took the
 * rightmost X-Forwarded-For value from ANY loopback connection, so any local process (a compromised stats
 * service, anything able to open 127.0.0.1:8000) could name any client address and step around every
 * per-network throttle. With VEIL_PROXY_SECRET set (16+ characters; in the root-only env file), Caddy adds
 *     header_up X-Veil-Proxy {env.VEIL_PROXY_SECRET}
 * to the relay's reverse_proxy (header_up REPLACES any value a client sent), and the relay uses
 * X-Forwarded-For only when X-Veil-Proxy matches (constant-time compare). Missing or wrong: the header is
 * ignored and the request is the one shared, throttled "direct" network (never the unthrottled "local").
 * Unset: b77t (audit 5 L-26) — production refuses to start; elsewhere X-Forwarded-For is ignored unless VEIL_TRUST_LOCAL=1.
 */
const PROXY_SECRET = (() => {
  const v = (Deno.env.get("VEIL_PROXY_SECRET") || "").trim();
  if (v && v.length < 16) { console.error("[relay] VEIL_PROXY_SECRET is shorter than 16 characters — ignored (b77t: X-Forwarded-For is then ignored too, except on a VEIL_TRUST_LOCAL test relay)"); return ""; }
  return v;
})();
if (!PROXY_SECRET && !TRUST_LOCAL) console.warn("[relay] VEIL_PROXY_SECRET is not set: X-Forwarded-For is IGNORED (every request is one shared, throttled network); set it, and the matching header_up in Caddy (b77t L-26; production refuses to start without it)");
/** b77t (audit 5 L-26, IH I-01): with no proxy secret, X-Forwarded-For is trusted ONLY on a test relay that trusts
 *  loopback (VEIL_TRUST_LOCAL=1, where the suites name networks with it). Anywhere else (a production relay can't start
 *  without the secret; a staging or "prod-like" relay without one) it is ignored and every request is the one shared,
 *  throttled "direct" network, so a forged header can never buy a fresh per-network budget (it used to reset the
 *  sign-up puzzle). */
function proxyHeaderTrusted(req: Request): boolean {
  if (!PROXY_SECRET) return TRUST_LOCAL;
  const got = req.headers.get("x-veil-proxy") || "";
  // constant time over the secret's length whatever was sent (a length mismatch fails too)
  let d = got.length ^ PROXY_SECRET.length;
  for (let i = 0; i < PROXY_SECRET.length; i++) d |= (got.charCodeAt(i) || 0) ^ PROXY_SECRET.charCodeAt(i);
  return d === 0;
}
/** the client address as the throttles see it (see clientTag) — never "local".
 *  b75r2 (audit R2-02): the value TRUSTED_PROXY_HOPS places from the right. A header with
 *  fewer values than that (a request that skipped a trusted hop) has no trustworthy client
 *  address: it lands in the one shared "malformed" bucket, like an empty value. */
function clientIpOf(req: Request): string {
  if (!req.headers.has("x-forwarded-for")) return "direct";
  // b77p (audit VAR-22): with VEIL_PROXY_SECRET set, X-Forwarded-For counts only on a request that carries
  // the secret Caddy adds (X-Veil-Proxy); anything else on loopback is the one shared "direct" bucket
  if (!proxyHeaderTrusted(req)) return "direct";
  const parts = (req.headers.get("x-forwarded-for") || "").split(",");
  if (parts.length < TRUSTED_PROXY_HOPS) return "malformed";
  return parts[parts.length - TRUSTED_PROXY_HOPS].trim() || "malformed";
}
async function networkTag(net: string): Promise<string> {
  const day = Math.floor(Date.now() / 86400_000);
  const tagUnder = async (k: CryptoKey) => "nt_" + [...new Uint8Array(await crypto.subtle.sign("HMAC", k, enc.encode(net.slice(0, MAX_KEY_PART)))).slice(0, 16)].map((b) => b.toString(16).padStart(2, "0")).join("");
  const tag = await tagUnder(await ipTagKey(day));
  // b77p (audit VAR-16): the same network's tag under YESTERDAY's key, so the throttles keyed by it keep
  // counting across 00:00 UTC (see netTagAlias / altThrottleKey). Only when that key is still held.
  const prev = await ipTagKeyIfHeld(day - 1);
  if (prev) noteNetTagAlias(day, tag, await tagUnder(prev));
  return tag;
}
/** b77p (audit VAR-16): today's network tag -> the same network's tag under yesterday's key. Filled by
 *  networkTag (every throttled request computes its tags first), dropped at each new UTC day, bounded. */
const netTagAlias = new Map<string, string>();
let netTagAliasDay = -1;
function noteNetTagAlias(day: number, tag: string, prevTag: string) {
  if (day !== netTagAliasDay || netTagAlias.size >= 200_000) { netTagAlias.clear(); netTagAliasDay = day; }
  netTagAlias.set(tag, prevTag);
}
/** b77p (audit VAR-16): a throttle key (string or KV key) with every network tag in it replaced by that
 *  network's tag under yesterday's key; null when it names no tag that has one. The throttles (rateLimit,
 *  reserveLoginAttempt, netPowGate) read this key's rows as well as their own, so a count, a lock or a guard
 *  made before 00:00 UTC still applies after it (it used to start from zero: a fresh budget every midnight). */
function altThrottleKey(key: string): string | null;
function altThrottleKey(key: Deno.KvKey): Deno.KvKey | null;
function altThrottleKey(key: string | Deno.KvKey): string | Deno.KvKey | null {
  let hit = false;
  const swap = (s: string) => s.replace(/nt_[0-9a-f]{32}/g, (t) => { const a = netTagAlias.get(t); if (a) { hit = true; return a; } return t; });
  const out = typeof key === "string" ? swap(key) : key.map((p) => (typeof p === "string" ? swap(p) : p));
  return hit ? out : null;
}
/** b74 (audit VAR-14): an IPv6 client's WIDER networks, the /56 and the /48 (a subscriber
 *  is often given a whole /56 or /48, i.e. 256 or 65 536 /64s — each of which used to get
 *  its own fresh throttle budgets). [] for IPv4, "local" and anything unparsable. */
async function clientWideTags(req: Request): Promise<WideTag[]> {
  if (!req.headers.has("x-forwarded-for") && TRUST_LOCAL) return [];
  const out: WideTag[] = [];
  for (const w of widerNetworksOf(clientIpOf(req))) out.push({ bits: w.bits, tag: await networkTag(w.net) });
  return out;
}
type WideTag = { bits: 56 | 48; tag: string };
/** b74 (audit VAR-14): a wider network's share of a per-network limit (x the /64 cap) */
const WIDE_FACTOR: Record<56 | 48, number> = { 56: 4, 48: 16 };
function widerNetworksOf(ip: string): { bits: 56 | 48; net: string }[] {
  if (!ip.includes(":") || /^\d+\.\d+\.\d+\.\d+$/.test(ip)) return [];
  const bare = ip.replace(/^\[|\](:\d+)?$/g, "").split("%")[0].toLowerCase();
  if (!/^[0-9a-f:.]+$/.test(bare)) return [];
  const [head, tail = ""] = bare.split("::");
  const h = head ? head.split(":") : [];
  const t = tail ? tail.split(":") : [];
  const groups = bare.includes("::") ? [...h, ...Array(Math.max(0, 8 - h.length - t.length)).fill("0"), ...t] : h;
  if (groups.length < 4 || groups.slice(0, 4).some((g) => !/^[0-9a-f]{1,4}$/.test(g))) return [];
  const g = groups.slice(0, 4).map((x) => x.padStart(4, "0"));
  return [
    { bits: 56, net: `v6:${g[0]}:${g[1]}:${g[2]}:${g[3].slice(0, 2)}00::/56` },
    { bits: 48, net: `v6:${g[0]}:${g[1]}:${g[2]}::/48` },
  ];
}
/** b74 (audit VAR-14): the same limit on the request's wider IPv6 networks */
/** b77q (audit 3 RF-4): `factors` — a limit with its own wide-network shares (the TURN budget); default WIDE_FACTOR */
async function wideRateLimit(prefix: string, wide: WideTag[], cap: number, windowMs: number, lockMinutes: number, factors: Record<56 | 48, number> = WIDE_FACTOR): Promise<{ locked: boolean; retry_minutes: number } | null> {
  for (const w of wide) {
    const rl = await rateLimit(`${prefix}/${w.bits}:${w.tag}`, cap * factors[w.bits], windowMs, lockMinutes);
    if (rl) return rl;
  }
  return null;
}
/** b74 (audit VAR-14): accounts made on the whole relay (every network together, "local"
 *  excepted), per hour and per day. The per-network caps alone let anyone with many
 *  networks make accounts without limit. */
const SIGNUPS_RELAY_PER_HOUR = Number(Deno.env.get("VEIL_SIGNUPS_PER_HOUR")) || 300;
const SIGNUPS_RELAY_PER_DAY = Number(Deno.env.get("VEIL_SIGNUPS_PER_DAY")) || 3000;
/** accounts one /64 (or IPv4 address) may make per hour (the /56 and /48 get x4, x16) */
const SIGNUPS_NETWORK_PER_HOUR = Number(Deno.env.get("VEIL_SIGNUPS_PER_NETWORK_PER_HOUR")) || 10;
/**
 * b77s (audit 4 RA-01): the relay-wide sign-up budget.
 * It used to be charged by signupRefusal BEFORE anything was validated, per request: 300 junk registers with a
 * 1-character password (each answered 400 at once, no account made) closed sign-up AND phrase / silent (duress)
 * provisioning for every network for 10 minutes, repeatably. Now:
 *  - the input is validated first (newAccountInputError): a request that can't make an account spends nothing;
 *  - the relay-wide counters count ACCOUNTS ACTUALLY CREATED, charged in createUser right after its atomic label
 *    claim commits (signupCharge) — a refused, taken or failed sign-up never spends them;
 *  - past the hourly (SIGNUPS_RELAY_PER_HOUR) or daily (SIGNUPS_RELAY_PER_DAY) cap, each further sign-up needs a
 *    solved puzzle (the network puzzle's format, at least SIGNUP_ALL_POW_BITS and growing with the overrun)
 *    instead of a hard close;
 *  - b77s (audit 4 RA-01 residual; owner decision "puzzle, no hard stop", as for TURN): there is NO hard close at
 *    all any more. It used to refuse ("signups_closed") at 4x a cap, and since phrase labels are free to invent,
 *    an attacker could close silent / duress provisioning through its own budget. Past a cap the puzzle grows
 *    steeply with how far over it the hour / day is (signupPowBits: +1 bit per 1/8 of the cap over, from
 *    SIGNUP_ALL_POW_BITS 16 up to SIGNUP_ALL_POW_MAX_BITS 24 at twice the cap — the most the app solves,
 *    LOGIN_POW_MAX_BITS), so every account past the cap costs real CPU (24 bits: ~16M hashes) while a real user
 *    can always get in. The storage / disk guards (kvStorageFull, the free-disk floor) still refuse;
 *  - phrase-label accounts (v<24 hex>@veil.app: the 24-word, silent and duress accounts, whichever route makes
 *    them) have their OWN budget ("phrase"), so a flood of email sign-ups can't close silent / duress provisioning.
 * In KV (sliding-window rows like rateLimit's), expiring on their own; "local" (a trusted loopback test relay) is
 * never counted.
 */
type SignupKind = "email" | "phrase";
const SIGNUP_ALL_POW_BITS = Number(Deno.env.get("VEIL_SIGNUP_POW_BASE_BITS")) || 16;
/** b77s (audit 4 RA-01 residual): the relay-wide sign-up puzzle's ceiling — the app's LOGIN_POW_MAX_BITS (24);
 *  VEIL_SIGNUP_POW_MAX_BITS may only lower it (test relays) */
const SIGNUP_ALL_POW_MAX_BITS = Math.min(24, Number(Deno.env.get("VEIL_SIGNUP_POW_MAX_BITS")) || 24);
/** b77s (audit 4 RA-01 residual): the relay-wide sign-up puzzle for an overrun (0 = at the cap, 1 = twice it) */
function signupPowBits(overrun: number): number {
  return Math.min(SIGNUP_ALL_POW_MAX_BITS, SIGNUP_ALL_POW_BITS + Math.floor(Math.max(0, overrun) * 8));
}
const signupKindOf = (email: string): SignupKind => PHRASE_LABEL_RE.test(email.toLowerCase().trim()) ? "phrase" : "email";
const signupWindows = (kind: SignupKind): [string, number, number][] => [
  [`regall2:${kind}:hour`, SIGNUPS_RELAY_PER_HOUR, 3600_000], [`regall2:${kind}:day`, SIGNUPS_RELAY_PER_DAY, 86400_000]];
/** the sliding-window estimate of a counter (rateLimit's arithmetic), read only */
async function slidingCount(key: string, windowMs: number): Promise<number> {
  const now = Date.now();
  const bucket = Math.floor(now / windowMs);
  const frac = (now - bucket * windowMs) / windowMs;
  const [cur, prev] = await KV.getMany<number[]>([["rl", key, String(bucket), String(windowMs)], ["rl", key, String(bucket - 1), String(windowMs)]]);
  return (cur.value ?? 0) + (prev.value ?? 0) * (1 - frac);
}
/** adds one to a sliding-window counter (no cap: the caller already decided) */
async function slidingCharge(key: string, windowMs: number): Promise<void> {
  for (let attempt = 0; attempt < 50; attempt++) {
    const k = ["rl", key, String(Math.floor(Date.now() / windowMs)), String(windowMs)];
    const cur = await KV.get<number>(k);
    if ((await KV.atomic().check(cur).set(k, (cur.value ?? 0) + 1, { expireIn: 2 * windowMs + 60_000 }).commit()).ok) return;
    await new Promise((r) => setTimeout(r, Math.random() * 5));
  }
}
/** after an account is created: one more on its kind's relay-wide counters */
async function signupCharge(kind: SignupKind): Promise<void> {
  for (const [key, , windowMs] of signupWindows(kind)) await slidingCharge(key, windowMs);
}
/** how far over its relay-wide caps a kind is: overrun 0 = under every cap (b77s RA-01 residual: never a refusal) */
async function signupRelayState(kind: SignupKind): Promise<{ overrun: number }> {
  let overrun = 0;
  for (const [key, cap, windowMs] of signupWindows(kind)) {
    const n = await slidingCount(key, windowMs);
    if (n + 1 > cap) overrun = Math.max(overrun, (n + 1 - cap) / cap);
  }
  return { overrun };
}
/** b77s (audit 4 RA-01): the structural checks createUser makes, run BEFORE any budget is touched
 *  (null = this could make an account). The messages are createUser's own (their codes: bad_label, weak_password). */
function newAccountInputError(email: string, password: unknown): string | null {
  const e = String(email ?? "").toLowerCase().trim();
  if (!e || e.length > 64 || !e.includes("@")) return "Enter an email address — it can be invented; it is never verified or contacted";
  if (typeof password !== "string" || password.length < PASSWORD_MIN_LEN || password.length > 512) return `Choose a password of at least ${PASSWORD_MIN_LEN} characters`;
  return null;
}
/** the sign-up guards, shared by both routes that create accounts: per /64 (10 an hour),
 *  per /56 and /48 (x4, x16), then relay-wide */
/** b77m (owner, carrier NAT): `powPassed` — the network was over its sign-up cap and this request solved the
 *  network puzzle instead (netPowGate).
 *  b77s (audit 4 RA-01): call it only for input that passed newAccountInputError. The relay-wide part only READS
 *  the counters (createUser charges them once an account exists); past a cap the network puzzle is asked for
 *  even if this network is under its own cap (one puzzle covers both), at least SIGNUP_ALL_POW_BITS and growing
 *  steeply with the overrun (signupPowBits); b77s (RA-01 residual): the relay-wide budget never refuses. */
async function signupRefusal(req: Request, body: Record<string, unknown> = {}, kind: SignupKind = "email"): Promise<Response | { powPassed: boolean }> {
  const regIp = await clientTag(req);
  if (regIp === "local") return { powPassed: false };
  const relay = await signupRelayState(kind);
  const regRl = await rateLimit("regip:" + regIp, SIGNUPS_NETWORK_PER_HOUR, 3600_000, 0) || await wideRateLimit("regip", await clientWideTags(req), SIGNUPS_NETWORK_PER_HOUR, 3600_000, 0);
  if (regRl || relay.overrun > 0) {
    // b77m (owner): past the network's hourly sign-ups a puzzle, not a refusal (a carrier NAT address is many people)
    // b77s (audit 4 RA-01): and past a relay-wide cap (one puzzle, the larger of the two sizes)
    const minBits = relay.overrun > 0 ? signupPowBits(relay.overrun) : 0; // b77s (audit 4 RA-01 residual): steep, up to 24 bits
    const g = await netPowGate(req, "signup", SIGNUPS_NETWORK_PER_HOUR, 3600_000, body, "Too many signups from this network — try again later", { minBits });
    if (g instanceof Response) return g;
  }
  return { powPassed: !!regRl };
}

/** b70 (audit RLY-4): an IPv6 address is throttled per /64 (one subscriber
 *  network), so rotating addresses inside it doesn't buy fresh budgets */
function networkOf(ip: string): string {
  if (!ip.includes(":") || /^\d+\.\d+\.\d+\.\d+$/.test(ip)) return ip;
  const bare = ip.replace(/^\[|\](:\d+)?$/g, "").split("%")[0].toLowerCase();
  const [head, tail = ""] = bare.split("::");
  const h = head ? head.split(":") : [];
  const t = tail ? tail.split(":") : [];
  const groups = bare.includes("::") ? [...h, ...Array(Math.max(0, 8 - h.length - t.length)).fill("0"), ...t] : h;
  if (groups.length < 4) return bare;
  return "v6:" + groups.slice(0, 4).map((g) => g.replace(/^0+(?=.)/, "")).join(":") + "::/64";
}

/** b71 (audit F-16): the day's network-tag key (one per UTC day). F-16 kept it out of the database:
 *  stored in KV, anyone holding kv.db (or a backup of it) could recompute the tag of every IPv4 address
 *  (2^32 tries) and read the throttle rows as "this address did this".
 *  b77p (audit VAR-16) had moved the day keys into a file beside kv.db (net-tag-keys.json) so per-network throttles
 *  survived restarts.
 *  b77s (audit 4 WS-01; owner decision 1 Nov "memory only, and say so"): that file sat on the same disk as the
 *  database, so anyone holding the disk (the host, a seizure, an intruder) could brute-force the tags back to
 *  addresses (all of IPv4 in hours on one core). The day keys are now held IN MEMORY ONLY — never written to disk:
 *   - a new random key each UTC day; today's and yesterday's are kept (yesterday's still reads yesterday's rows across
 *     00:00 UTC — networkTag -> altThrottleKey — while the process runs), older ones are zeroed and dropped;
 *   - a net-tag-keys.json (and .tmp) an earlier relay left is DELETED at boot (dropNetTagKeyFile);
 *   - the accepted cost (this deliberately reverses VAR-16): every relay restart (each deploy) starts every
 *     per-network throttle afresh — login guards, sign-up caps, puzzle counts, one-time-key and quota caps keyed
 *     by network. Per-account and relay-wide limits are unaffected (they don't use network tags).
 *  The database and the backups never held the key; now nothing on disk does. */
const NET_TAG_KEY_FILE_LEGACY: string[] = (() => {
  const out: string[] = [];
  const explicit = (Deno.env.get("VEIL_NET_TAG_KEY_FILE") || "").trim();
  if (explicit && explicit !== "memory") out.push(explicit);
  const kv = (Deno.env.get("VEIL_KV_PATH") || "").trim();
  if (kv && kv !== ":memory:") out.push(kv.replace(/[^\\/]*$/, "") + "net-tag-keys.json");
  return out;
})();
/** b77s (audit 4 WS-01): boot — the key file an earlier relay wrote goes (with its temp file) */
async function dropNetTagKeyFile(): Promise<number> {
  let n = 0;
  for (const f of NET_TAG_KEY_FILE_LEGACY) {
    for (const p of [f, f + ".tmp"]) {
      try { await Deno.remove(p); n++; } catch (e) {
        if (!(e instanceof Deno.errors.NotFound)) console.error(`[relay] WARNING: could not delete the old network-tag key file ${p} (${(e as Error).name}) — delete it by hand: it lets anyone holding the disk map recent throttle rows back to addresses`);
      }
    }
  }
  return n;
}
const netTagRaw = new Map<number, Uint8Array>();
const importNetTagKey = (raw: Uint8Array) => crypto.subtle.importKey("raw", raw as BufferSource, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
const ipTagKeys = new Map<number, Promise<CryptoKey>>();
function ipTagKey(day: number): Promise<CryptoKey> {
  let k = ipTagKeys.get(day);
  if (!k) {
    k = (async () => {
      // b77s (audit 4 WS-01): memory only — nothing is written anywhere
      let raw = netTagRaw.get(day);
      if (!raw) { raw = crypto.getRandomValues(new Uint8Array(32)); netTagRaw.set(day, raw); }
      for (const d of [...netTagRaw.keys()]) if (d < day - 1 || d > day + 1) { netTagRaw.get(d)!.fill(0); netTagRaw.delete(d); }
      return importNetTagKey(raw);
    })();
    ipTagKeys.set(day, k);
    for (const d of ipTagKeys.keys()) if (d < day - 1) ipTagKeys.delete(d);
  }
  return k;
}
/** b77p (audit VAR-16): a day's key only if it is still held (never made up) */
function ipTagKeyIfHeld(day: number): Promise<CryptoKey | null> {
  const k = ipTagKeys.get(day);
  if (k) return k;
  const raw = netTagRaw.get(day);
  if (!raw) return Promise.resolve(null);
  const p = importNetTagKey(raw);
  ipTagKeys.set(day, p);
  return p;
}
/** b71 (audit F-16): once, at boot — the day keys older relays kept in KV.
 *  b73 (audit): V-18 — and the blob-signing and peer-pseudonym keys (now memory-only) */
async function dropStoredIpTagKeys(): Promise<number> {
  let n = 0;
  for await (const e of KV.list({ prefix: ["secret", "ipTag"] })) { await KV.delete(e.key); n++; }
  for (const k of [["secret", "blobSign"], ["secret", "peerPseudo"]] as Deno.KvKey[]) {
    if ((await KV.get(k)).value !== null) { await KV.delete(k); n++; }
  }
  return n;
}

// ---------- b199 anonymous daily totals (owner dashboard, Oct 16) ----------
// One counter per metric per UTC day: ["stats", metric, "YYYY-MM-DD"] → count.
// Nothing about who, which account or which chat is stored — only how many.
// Read by GET /admin/stats (local-only via Caddy, token-gated). Days older
// than STATS_KEEP_DAYS are pruned by the sweeper.
const STATS_KEEP_DAYS = 400;
const statDay = (t = Date.now()) => new Date(t).toISOString().slice(0, 10);
async function bumpStat(metric: "accounts" | "identities" | "chats" | "envelopes") {
  try { await KV.atomic().sum(["stats", metric, statDay()], 1n).commit(); } catch { /* a missed count never blocks a request */ }
}
async function pruneStats() {
  const cutoff = statDay(Date.now() - STATS_KEEP_DAYS * 86400_000);
  for await (const e of KV.list({ prefix: ["stats"] })) if (String(e.key[2]) < cutoff) await KV.delete(e.key);
}
async function statsSnapshot() {
  const count = async (prefix: Deno.KvKey) => { let n = 0; for await (const _ of KV.list({ prefix })) n++; return n; };
  const groups = new Set<string>();
  for await (const e of KV.list({ prefix: ["veil_gmember"] })) groups.add(String(e.key[1]));
  let liveChats = 0, liveGroupSessions = 0;
  for await (const e of KV.list<Record<string, unknown>>({ prefix: ["entity", "VeilSession"] })) {
    if (e.value?.group_token) liveGroupSessions++; else liveChats++;
  }
  const daily: Record<string, Record<string, number>> = {};
  for await (const e of KV.list<Deno.KvU64>({ prefix: ["stats"] })) {
    const [, metric, day] = e.key as [string, string, string];
    (daily[day] ??= {})[metric] = Number(e.value?.value ?? 0);
  }
  return {
    generated: new Date().toISOString(),
    totals: {
      accounts: await count(["user"]),
      identities: await count(["veil_identity"]),
      live_chats: liveChats,
      live_group_sessions: liveGroupSessions,
      groups: groups.size,
      stored_envelopes: await count(["entity", "VeilEnvelope"]),
      devices_with_alerts: await count(["entity", "VeilPushToken"]), // b77p round 2: legacy phones only (transition window)
      mailboxes: await count(["mbox"]), // b77 (sealed sender)
    },
    daily,
  };
}

/** b75r3 (audit R-I1): /admin/stats serves a snapshot at most this old (one full scan per window, shared by
 *  concurrent calls), and takes at most STATS_ROUTE_PER_MIN calls a minute */
const STATS_CACHE_MS = 45_000;
const STATS_ROUTE_PER_MIN = 20;
let statsCache: { at: number; value: Promise<Awaited<ReturnType<typeof statsSnapshot>>> } | null = null;
function cachedStatsSnapshot(): Promise<Awaited<ReturnType<typeof statsSnapshot>>> {
  if (statsCache && Date.now() - statsCache.at < STATS_CACHE_MS) return statsCache.value;
  const value = statsSnapshot();
  const entry = { at: Date.now(), value };
  statsCache = entry;
  value.catch(() => { if (statsCache === entry) statsCache = null; }); // a failed scan is not cached
  return value;
}

/** Throttle/lockout rows expire on their own — no permanent per-network or
 *  per-account trail accumulates in the database. */
const THROTTLE_TTL_MS = 24 * 3600_000;
/** Push-coalescing stamps only matter for their 30 s window; they used to be
 *  kept forever (a per-session / per-veil-id "last pinged" trail). */
const COALESCE_TTL_MS = 5 * 60_000;

// ---------- b77n (pre-audit L3): secondary indexes ----------
// Hot authenticated paths used to read whole tables: every note / vault / push list, every push
// registration (twice), every group post (all member rows of every group), the group read check,
// the group gate's roster and the file-delete protection check. These indexes answer them instead:
//   ["ix_acct", entity, account hash, row id]   VeilNote / VeilVault / VeilPushToken, by owner
//   ["ix_push_tok", SHA-256("veil-push-ix:" + address), row id]   push rows, by address
//   ["ix_gmem", group token, member row id]      VeilGroupMember, by group
//   ["ix_vault_uri", file uri, vault row id]     VeilVault, by container file
//   ["ix_devlink_uri", file uri, link token]     device-transfer links, by bundle file
// Each holds only what its row already holds (no new link between anything). An entry is written in
// the same atomic step as its row; a delete that misses its entry leaves a STALE one, which every
// reader checks against the row (dropping it only if the row is still as read) and the sweeper drops
// (sweepStaleIndexes). Rows written before this build are indexed at boot (backfillIndexes), before
// the relay serves.
const ACCT_IX_ENTITIES = new Set(["VeilVault", "VeilNote", "VeilPushToken"]);
const URI_IX_RE = /^blob:[A-Za-z0-9_-]{1,128}$/;
const pushTokIxTag = (tok: string) => sha256hex("veil-push-ix:" + tok);
/** the index entries a row of `name` should have */
async function entityIxKeys(name: string, id: string, row: Record<string, unknown> | null | undefined): Promise<Deno.KvKey[]> {
  if (!row) return [];
  const out: Deno.KvKey[] = [];
  if (ACCT_IX_ENTITIES.has(name) && row._acct) out.push(["ix_acct", name, String(row._acct), id]);
  if (name === "VeilPushToken" && row.expo_token) out.push(["ix_push_tok", await pushTokIxTag(String(row.expo_token)), id]);
  if (name === "VeilVault" && URI_IX_RE.test(String(row.container_uri || ""))) out.push(["ix_vault_uri", String(row.container_uri), id]);
  if (name === "VeilGroupMember" && typeof row.group_token === "string" && row.group_token && row.group_token.length <= MAX_KEY_PART) out.push(["ix_gmem", row.group_token, id]);
  // b77s (audit 4 RE-02): group seats (and main rows) by group and by creating account; deny entries by group
  if (name === "VeilSession" && typeof row.group_token === "string" && row.group_token && row.group_token.length <= MAX_KEY_PART) {
    out.push(["ix_gsess", row.group_token, id]);
    const init = String(row.initiator_client_id || "");
    if (init && init.length <= MAX_KEY_PART) out.push(["ix_gsess_init", init, id]);
  }
  if (name === "VeilGroupDenyEntry" && typeof row.group_token === "string" && row.group_token && row.group_token.length <= MAX_KEY_PART) out.push(["ix_gdeny", row.group_token, id]);
  return out;
}
/** the rows an index prefix names (the last key part is the row id), checked against `matches`; an entry
 *  whose row is gone or no longer matches is dropped (only if the row is unchanged since read) */
async function* indexedRows(prefix: Deno.KvKey, name: string, matches: (row: Record<string, unknown>) => boolean): AsyncGenerator<{ key: Deno.KvKey; value: Record<string, unknown> }> {
  // b77n2 (review M1): until this process's boot backfill has COMPLETED, an index may lack entries for rows
  // an older build wrote, and a reader trusting it would see too few rows (an empty member list made the
  // next attester a group's "creator"). Fail closed: read the whole table instead.
  if (!ixReady) {
    for await (const e of KV.list<Record<string, unknown>>({ prefix: ["entity", name] }, { consistency: "strong" })) if (e.value && matches(e.value)) yield { key: e.key, value: e.value };
    return;
  }
  const it = KV.list({ prefix }, { consistency: "strong" });
  for (let done = false; !done;) {
    const batch: Deno.KvKey[] = [];
    while (batch.length < 10) { const n = await it.next(); if (n.done) { done = true; break; } batch.push(n.value.key); }
    if (!batch.length) break;
    const rows = await KV.getMany<Record<string, unknown>[]>(batch.map((k) => ["entity", name, String(k[k.length - 1])]), { consistency: "strong" });
    for (let i = 0; i < batch.length; i++) {
      const r = rows[i];
      if (r.value && matches(r.value)) yield { key: r.key, value: r.value };
      else await KV.atomic().check(r).delete(batch[i]).commit();
    }
  }
}
/** one account's rows of an owner-scoped entity */
const acctRows = (name: string, acct: string) => indexedRows(["ix_acct", name, acct], name, (r) => String(r._acct ?? "") === acct);
/** one group's member rows */
const groupMemberRows = (gt: string) => indexedRows(["ix_gmem", keySafe(gt)], "VeilGroupMember", (r) => String(r.group_token ?? "") === gt);
/** b77s (audit 4 RE-02): one group's session rows (seats and main rows); its deny entries; the group rows one account created */
const groupSessionRows = (gt: string) => indexedRows(["ix_gsess", keySafe(gt)], "VeilSession", (r) => String(r.group_token ?? "") === gt);
const groupDenyRows = (gt: string) => indexedRows(["ix_gdeny", keySafe(gt)], "VeilGroupDenyEntry", (r) => String(r.group_token ?? "") === gt);
const groupRowsCreatedBy = (userId: string) => indexedRows(["ix_gsess_init", keySafe(userId)], "VeilSession", (r) => !!r.group_token && String(r.initiator_client_id || "") === userId);
/** the push rows naming one address */
async function* pushRowsOf(tok: string) { yield* indexedRows(["ix_push_tok", await pushTokIxTag(tok)], "VeilPushToken", (r) => String(r.expo_token ?? "") === tok); }
/** deletes a row and its index entries in one step (the row as read; retried if it changed) */
async function deleteIndexedRow(name: string, id: string): Promise<Record<string, unknown> | null> {
  const key: Deno.KvKey = ["entity", name, id];
  for (let attempt = 0; attempt < 5; attempt++) {
    const cur = await KV.get<Record<string, unknown>>(key);
    if (!cur.value) return null;
    const tx = KV.atomic().check(cur).delete(key);
    for (const k of await entityIxKeys(name, id, cur.value)) tx.delete(k);
    if ((await tx.commit()).ok) return cur.value;
  }
  const row = (await KV.get<Record<string, unknown>>(key)).value;
  await KV.delete(key); // contended: the row goes; a stale entry is dropped on its next use or sweep
  return row;
}
/**
 * b77n2 (review M1): true only once backfillIndexes has run to the end IN THIS PROCESS. Until then every
 * index reader (indexedRows) falls back to a full table scan. Deliberately not a stored marker: a marker in
 * the database would outlive a rollback to a build that writes rows without index entries, and the next boot
 * would trust the index again; the backfill is idempotent and runs at every boot anyway. A failed backfill is
 * retried in the background (the relay serves on the slow but complete path meanwhile).
 */
let ixReady = false;
const IX_BACKFILL_RETRY_MS = Number(Deno.env.get("VEIL_IX_BACKFILL_RETRY_MS")) || 60_000;
/** boot: index entries for every row written before this build (idempotent) */
async function backfillIndexes(): Promise<number> {
  // test relays only: an interrupted backfill (readers must not trust the half-built index)
  if (Deno.env.get("VEIL_TEST_IX_BACKFILL_FAIL") === "1") throw new Error("test: backfill interrupted");
  let n = 0;
  for (const name of [...ACCT_IX_ENTITIES, "VeilGroupMember", "VeilSession", "VeilGroupDenyEntry"]) { // b77s (audit 4 RE-02): + group seats and deny entries
    for await (const e of KV.list<Record<string, unknown>>({ prefix: ["entity", name] }, { consistency: "strong" })) {
      for (const k of await entityIxKeys(name, String(e.key[2]), e.value)) {
        if ((await KV.atomic().check({ key: k, versionstamp: null }).set(k, 1).commit()).ok) n++;
      }
    }
  }
  for await (const e of KV.list<Record<string, unknown>>({ prefix: ["devlink"] }, { consistency: "strong" })) {
    const uri = String(e.value?.container_uri || "");
    if (!URI_IX_RE.test(uri)) continue;
    const k: Deno.KvKey = ["ix_devlink_uri", uri, String(e.key[1])];
    if ((await KV.atomic().check({ key: k, versionstamp: null }).set(k, 1).commit()).ok) n++;
  }
  return n;
}
/** the sweeper: drops entries whose row is gone or no longer matches (rows deleted on paths that
 *  don't clear their entries: account delete scans, group teardown, member removals) */
async function sweepStaleIndexes(): Promise<number> {
  let n = 0;
  const drop = async (ix: Deno.KvKey, rowKey: Deno.KvKey, ok: (r: Record<string, unknown>) => boolean | Promise<boolean>) => {
    const r = await KV.get<Record<string, unknown>>(rowKey);
    if (r.value && await ok(r.value)) return;
    if ((await KV.atomic().check(r).delete(ix).commit()).ok) n++;
  };
  for await (const e of KV.list({ prefix: ["ix_acct"] }, { consistency: "strong" })) await drop(e.key, ["entity", String(e.key[1]), String(e.key[3])], (r) => String(r._acct ?? "") === String(e.key[2]));
  for await (const e of KV.list({ prefix: ["ix_push_tok"] }, { consistency: "strong" })) await drop(e.key, ["entity", "VeilPushToken", String(e.key[2])], async (r) => await pushTokIxTag(String(r.expo_token ?? "")) === String(e.key[1]));
  for await (const e of KV.list({ prefix: ["ix_gmem"] }, { consistency: "strong" })) await drop(e.key, ["entity", "VeilGroupMember", String(e.key[2])], (r) => String(r.group_token ?? "") === String(e.key[1]));
  // b77s (audit 4 RE-02)
  for await (const e of KV.list({ prefix: ["ix_gsess"] }, { consistency: "strong" })) await drop(e.key, ["entity", "VeilSession", String(e.key[2])], (r) => String(r.group_token ?? "") === String(e.key[1]));
  for await (const e of KV.list({ prefix: ["ix_gsess_init"] }, { consistency: "strong" })) await drop(e.key, ["entity", "VeilSession", String(e.key[2])], (r) => !!r.group_token && String(r.initiator_client_id ?? "") === String(e.key[1]));
  for await (const e of KV.list({ prefix: ["ix_gdeny"] }, { consistency: "strong" })) await drop(e.key, ["entity", "VeilGroupDenyEntry", String(e.key[2])], (r) => String(r.group_token ?? "") === String(e.key[1]));
  for await (const e of KV.list({ prefix: ["ix_vault_uri"] }, { consistency: "strong" })) await drop(e.key, ["entity", "VeilVault", String(e.key[2])], (r) => String(r.container_uri ?? "") === String(e.key[1]));
  for await (const e of KV.list({ prefix: ["ix_devlink_uri"] }, { consistency: "strong" })) await drop(e.key, ["devlink", String(e.key[2])], (r) => String(r.container_uri ?? "") === String(e.key[1]));
  return n;
}

// ---------- generic entities ----------
// Rows: ["entity", name, id] → { id, created_date, updated_date, ...fields }
// Token index for VeilSession: ["veil_sess_token", token] → id

async function listEntity(name: string, url: URL, auth?: { userId: string }) {
  // b70 (re-review 4): every check runs BEFORE the table is read, and the scan
  // keeps only matching rows (it used to load every account's rows into memory
  // on each call); list calls are rate-limited per account
  if (auth) {
    const lrl = await rateLimit("list:" + auth.userId, 1200, 60_000, 2); // (a 100-chat phone polls ~600/min)
    if (lrl) return { __limited: lrl.retry_minutes } as any;
  }
  const q = url.searchParams;
  const filters: [string, string][] = [];
  let limit = 200;
  let skip = 0;
  let sortField: string | null = null;
  let sortDesc = false;
  for (const [k, v] of q) {
    // b77t (audit 5 L-13, IH R-05): at most ENTITY_LIST_MAX rows a page (the limit had no maximum)
    if (k === "limit") { limit = Math.min(ENTITY_LIST_MAX, Math.max(1, parseInt(v) || 200)); continue; }
    if (k === "sort") {
      sortField = v.replace(/^-/, "");
      sortDesc = v.startsWith("-");
      continue;
    }
    if (k === "skip") { skip = Math.min(ENTITY_LIST_MAX_SKIP, Math.max(0, parseInt(v) || 0)); continue; } // b77t (L-13)
    if (k === "page" || k === "page_size") continue;
    filters.push([k, v]);
  }
  const out: any[] = [];
  // HARVEST GUARD: shared-entity lists MUST carry their scoping filter — an
  // unfiltered list would dump every user's sessions/envelopes to any
  // authenticated account (metadata + ciphertext harvesting)
  // b198 (live-caught, group battery): GROUP envelopes are scoped by
  // group_token — the group receive channel is one shared stream, so a
  // session_token filter is structurally impossible for groups. A group_token
  // list is accepted as valid scoping ONLY for group members: the gmember row
  // written at attest carries the member's account_hash, so the check is
  // exact and cheap. Every other account keeps the 403 — the guard keeps its
  // teeth (an outsider knowing a group token still cannot read its stream).
  const groupScoped = name === "VeilEnvelope" && !!q.get("group_token");
  // b75 (audit RL-10): a field the caller can't see can't be a filter or a sort key either.
  // Server fields (_owner, _acct, any "_" name) never leave the relay, and on a GROUP
  // envelope list the posting seat's session_token is shown to the group's creator only
  // (envelopeRowsView). Both used to work as filters and sort keys, so a member could
  // test which rows a seat posted, or sort the stream by seat (rows of one seat adjacent)
  // and link posts to members across epochs, exactly what hiding the field prevents.
  {
    const keys = [...filters.map(([k]) => k), ...(sortField ? [sortField] : [])];
    if (keys.some((k) => k.startsWith("_"))) return { __badquery: "That field can't be used to filter or sort" } as any;
    if (groupScoped && auth && keys.includes("session_token") && !(await groupOwnedBy(String(q.get("group_token")), await accountHashOf(auth.userId)))) {
      return { __badquery: "That field can't be used to filter or sort" } as any;
    }
  }
  // b77p round 2 (review M1): an owner-scoped list is ALWAYS scoped to its caller (none without one: no table scan)
  if (OWNER_SCOPED_ENTITIES.has(name) && !auth) return { __blocked: "list requires a signed-in caller" } as any;
  const requiredFilter = REQUIRED_LIST_FILTER[name];
  if (requiredFilter && !q.get(requiredFilter) && !groupScoped) {
    return { __blocked: `list requires a ${requiredFilter} filter` } as any;
  }
  // b74 (audit VAR-01): an ADMITTED membership reads the stream; a claimant the creator
  // has not let in reads only the rows of its own seat (its seat intros). Any member row,
  // admitted or not, used to open the whole stream.
  let claimantSeats: Set<string> | null = null;
  if (groupScoped && auth) {
    const access = await groupReadAccess(q.get("group_token") as string, auth.userId);
    if (!access.admitted && !access.seats.size) return { __blocked: "group envelope list requires group membership" } as any;
    if (!access.admitted) claimantSeats = access.seats;
  }
  // b198 DELETION OBSERVABILITY (live battery Oct 15): a VeilEnvelope list
  // scoped to a session that no longer exists (or has ended) must NOT answer
  // 200 + empty — the native sync reads an empty page as "nothing new" and
  // loops inside a dead thread forever (✕-end, + supersede and the sweeper
  // all left the peer blind; the auto-switch needs the sync ERROR to trigger
  // its forced list refresh). A 404 "Session not found" makes every deletion
  // path observable to every client in one pass.
  if (name === "VeilEnvelope") {
    const st = q.get("session_token");
    if (st) {
      const sess = await findSessionByToken(st);
      if (!sess || String(sess.state || "") === "ended") {
        return { __notfound: "Session not found" } as any;
      }
      // b199 AUTHZ (audit finding #6, Oct 17): a session_token list returns
      // only to the two accounts in that conversation. Anyone holding a token
      // used to page through its ciphertext and metadata. Group streams are
      // listed by group_token (member-gated above); a device transfer keeps
      // the same account, and an identity can't be re-bound to another
      // account (register refuses), so participants never lose access.
      if (auth) {
        const uid = auth.userId;
        if (String(sess.initiator_client_id || "") !== uid && String(sess.responder_client_id || "") !== uid) {
          return { __blocked: "envelope list requires being in this conversation" } as any;
        }
      }
    }
  }
  // owner-scoped entities only ever answer their owner's queries
  const ownerAcct = auth && OWNER_SCOPED_ENTITIES.has(name) ? await accountHashOf(auth.userId) : null;
  // b71 (audit F-09): a chat's envelopes are read through the per-chat index, not by
  // scanning every envelope on the relay (this list is the app's main poll)
  const sessIdx = name === "VeilEnvelope" && q.get("session_token") ? String(q.get("session_token")) : "";
  const rows: AsyncIterable<{ key: Deno.KvKey; value: unknown }> = sessIdx
    ? envelopesOfSession(sessIdx)
    : groupScoped ? envelopesOfGroup(String(q.get("group_token")))
    // b77n (pre-audit L3): an owner-scoped list reads the owner's rows through ["ix_acct"] (it scanned the table)
    : ownerAcct !== null ? acctRows(name, ownerAcct)
    : KV.list({ prefix: ["entity", name] }, { consistency: "strong" });
  const keep = skip + limit;
  const cmp = sortField
    ? (a: any, b: any) => { const av = String(a[sortField!] ?? ""), bv = String(b[sortField!] ?? ""); return sortDesc ? bv.localeCompare(av) : av.localeCompare(bv); }
    : (a: any, b: any) => String(b.created_date ?? "").localeCompare(String(a.created_date ?? ""));
  for await (const e of rows) {
    const r = e.value as Record<string, unknown>;
    // b75r1 (audit REL-07): an envelope past its expires_at is never served — it is deleted
    // here and now (with its index rows) instead of waiting for the next sweep (up to 2 min)
    if (name === "VeilEnvelope" && envelopeExpired(r)) { await deleteEnvelopeRow(e.key, r); continue; }
    if (ownerAcct !== null && String(r?._acct ?? "") !== ownerAcct) continue;
    if (claimantSeats && !claimantSeats.has(String(r?.session_token ?? ""))) continue; // b74 (audit VAR-01)
    if (!filters.every(([k, v]) => String((r as any)?.[k] ?? "") === v)) continue;
    // b77t (audit 5 L-29, IH R-06): server-only fields (_acct, _owner, any "_" name) never leave the relay
    out.push({ ...clientRow(r), id: e.key[e.key.length - 1] as string });
    // b77t (audit 5 L-13): only the best skip + limit rows are kept while scanning (every match used to be buffered
    // and sorted): the buffer is cut back to them whenever it reaches twice that
    if (out.length >= 2 * keep) { out.sort(cmp); out.length = keep; }
  }
  out.sort(cmp);
  return out.slice(skip, skip + limit);
}
/** b77t (audit 5 L-13): a list page's maximum size, and the furthest it can skip */
const ENTITY_LIST_MAX = 500;
const ENTITY_LIST_MAX_SKIP = 5000;
/** b77t (audit 5 L-29, IH R-06): a row as a client may see it — every server field ("_" name: _acct, _owner,
 *  _init_tag, ...) removed */
function clientRow<T extends Record<string, unknown>>(r: T): T {
  if (!r || typeof r !== "object") return r;
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(r)) if (!k.startsWith("_")) out[k] = v;
  return out as T;
}

const OWNER_SCOPED_ENTITIES = new Set(["VeilVault", "VeilNote", "VeilPushToken"]);
/** Batch D (D-13): the only fields a client may write when it creates a session row
 *  (invite.ts createInviteSession, contact.ts createOneTapSession)
 *  b71 (review R-1): initiator_display_name is no longer kept — the relay never used
 *  the nickname, and storing it in clear put a user-chosen name on every row. Older
 *  apps still send it; it is dropped here (and responder_display_name at join). */
const VEIL_SESSION_CREATE_FIELDS = [
  "token", "passphrase_required", "session_fingerprint",
  "initiator_pub_jwk", "initiator_pq_pub", "initiator_pq_ct", "initiator_ek_pub", "initiator_sig", "initiator_veil_id",
  "responder_veil_id", "contact_session", "initiator_write_hash", "responder_write_hash",
  "default_ttl_seconds", "expire_after_seconds", "key_retention_hours", "burn_after_open", "last_activity", "expires_at",
  "group_token", "group_name", "group_epoch", "invitee_veil_id",
  // b70 (audit L-2): which of the responder's prekeys the request used (unsigned hint; a wrong one only fails the join)
  "responder_spk_id",
  // b76 (one-time prekeys): the one-time pair the request used and the ML-KEM ct to its PQ key
  // (both signed into the request by the initiator; the relay only carries them)
  "responder_opk_id", "initiator_opk_pq_ct",
] as const;
/** Batch D (D-13, RV-11): requests one account may file to one other Vardum ID per day */
const REQUESTS_PER_TARGET_PER_DAY = 10;
/** Batch E (R3-10): session rows one account may create per day (a 100-member
 *  group is 101 rows; the app's own use is far below this) */
const SESSION_CREATES_PER_DAY = 200;
/** b70 (re-review 7): group rows (seats + main rows) one account may hold in all */
const GROUP_ROWS_PER_ACCOUNT = 1500;
/** b70 (re-review R7): per-account daily row creation, per entity */
const ENTITY_CREATES_PER_DAY: Record<string, number> = { VeilVault: 100, VeilNote: 500, VeilPushToken: 50, OnboardingStep: 100, AttributionSource: 20, VeilSession: 1000 };
/** b70 (re-review P6): analytics rows are small; a 60 KB one is storage abuse */
/** b70 (re-review 5): rows kept until deleted, per account (a vault container is up to 25 MB) */
const VAULTS_PER_ACCOUNT = 40;
const NOTES_PER_ACCOUNT = 2000;
/** b77n (pre-audit M1): note bytes one account may keep in all (the rows as stored). The app lists 100 notes;
 *  20 MB is ~400 notes at the 48 KB row maximum. VEIL_NOTE_ACCOUNT_KB is for test relays. */
const NOTE_BYTES_PER_ACCOUNT = (Number(Deno.env.get("VEIL_NOTE_ACCOUNT_KB")) || 20 * 1024) * 1024;
/** b77n (pre-audit M1): entity-row bytes (creates and updates, all kinds) one network may write per UTC day
 *  (its /64 or IPv4 address; the /56 and /48 at x4, x16). Kept rows (notes, vaults, group seats) used to be
 *  capped per account only, so fresh accounts from one place multiplied it. 256 MB is generous for a carrier
 *  NAT full of real users (a busy user writes well under 1 MB a day). VEIL_ENTITY_NETWORK_DAILY_KB: tests. */
const ENTITY_NETWORK_DAILY_BYTES = (Number(Deno.env.get("VEIL_ENTITY_NETWORK_DAILY_KB")) || 256 * 1024) * 1024;
const ANALYTICS_ENTITIES = new Set(["OnboardingStep", "AttributionSource"]);
/** b71 (audit F-05): analytics rows are deleted this many days after they were written */
const ANALYTICS_KEEP_DAYS = 30;
/** b71 (audit F-05): fields never stored on analytics rows, whatever an older app sends
 *  (the attribution answer used to carry the Vardum ID, tying it to the identity) */
const ANALYTICS_DROPPED_FIELDS = ["veil_id", "veilId", "IK_pub", "email"];
/** b77u (audit 6): the only fields an analytics row keeps (short strings) */
const ANALYTICS_FIELDS: Record<string, string[]> = { OnboardingStep: ["step"], AttributionSource: ["source", "medium", "campaign"] };
const ANALYTICS_ROW_MAX_BYTES = 4096;
/** Batch E (R3-02): rows that only NAME the caller (requests, restore matches) listed at most */
const LIST_NAMING_CAP = 100;
/** Batch D (D-13, RV-09): one call ring per conversation per ring window */
const CALL_RING_WINDOW_MS = 20_000;
/** b71 (audit F-08): ring bursts one conversation may cause per hour */
const RINGS_PER_CHAT_PER_HOUR = 10;
/** b71 (audit F-15): throttle rows name a chat only by this hash of its token */
const sessionTokenTag = (token: string) => sha256hex("veil-sess-tag:" + token).then((h) => "st_" + h.slice(0, 32));
const REQUIRED_LIST_FILTER: Record<string, string> = {
  VeilSession: "token",
  VeilEnvelope: "session_token",
  // b77p round 2 (review M1): VeilPushToken no longer needs an expo_token filter. It is owner-scoped (the list answers
  // the caller's own rows only, through ["ix_acct"]), and a lookup BY address told a logging relay "this account owns
  // this push address" — the address the phone's wake boxes carry (§12.19.1). The app lists its own rows unfiltered.
};

/** b77p (audit VAR-32): the ONLY fields a client may write on a note or a vault row, on create and on update
 *  (vendor/device notes.ts noteRecord + the owner tag; vaults.ts vaultRecord + the owner tag). Anything else a
 *  body carries (created_by, is_admin, expires_at, _init_tag, ...) is dropped, so no later code can trust a
 *  field a client planted. The server-owned fields (id, _acct, _owner, created/updated dates) were already
 *  stamped by the relay. */
const CLIENT_ENTITY_FIELDS: Record<string, readonly string[]> = {
  VeilNote: ["payload_ciphertext", "payload_iv", "byte_length", "note_nid", "note_v", "owner_veil_id"],
  VeilVault: ["name", "container_uri", "byte_length", "kdf", "cipher", "owner_veil_id"],
  // b77s (audit 4 RE-03): a push row kept ANY field a client sent (up to the 48 KB row limit). Now only what a legacy
  // (pre-b77p) phone's registration sends (src/notifications.ts before b77p round 2: the address, its transport and
  // UnifiedPush keys, the device id, the challenge code, its push_refs) — each a short string, push_refs cleaned
  // by cleanPushRefs as before
  VeilPushToken: ["expo_token", "transport", "up_endpoint", "up_p256dh", "up_auth", "device_id", "verify_code", "push_refs"],
};
/** b77s (audit 4 RE-03): a push row's string fields stay short (an address is at most 512 characters) */
const PUSH_FIELD_MAX = 1024;
function pickClientFields(name: string, body: Record<string, unknown>): Record<string, unknown> {
  const allow = CLIENT_ENTITY_FIELDS[name];
  if (!allow || !body || typeof body !== "object") return body;
  const out: Record<string, unknown> = {};
  for (const k of allow) {
    if (body[k] === undefined) continue;
    if (name === "VeilPushToken" && k !== "push_refs" && (typeof body[k] !== "string" || (body[k] as string).length > PUSH_FIELD_MAX)) continue;
    out[k] = body[k];
  }
  return out;
}
async function createEntity(name: string, body: Record<string, unknown>, auth?: { userId: string; email?: string }) {
  // b199 AUTHZ: the row id is ALWAYS server-chosen — a client-supplied id used
  // to overwrite any existing row of the same entity (another account's vault,
  // note, session). Ownership fields are server-stamped, never client-supplied.
  const ridv = rid();
  // Batch D (D-13, RV-09): server fields are never client-supplied (the row spread
  // used to let a body set created_date / updated_date)
  const { id: _ignoredId, _acct: _ignoredAcct, _owner: _ignoredOwner, created_date: _ignoredC, updated_date: _ignoredU, ...clean } = body;
  body = pickClientFields(name, clean); // b77p (audit VAR-32): notes and vaults keep only the fields the app writes
  // b71 (audit F-05): analytics rows never keep an identifier (older apps sent veil_id)
  if (ANALYTICS_ENTITIES.has(name)) for (const f of ANALYTICS_DROPPED_FIELDS) delete body[f];
  // b77u (audit 6, IH website C-7 "usage counts linkable"): and keep ONLY the count's own fields (any other field a client
  // sent was kept for 30 days and could carry anything that singles a phone out)
  if (ANALYTICS_ENTITIES.has(name)) { const keep = ANALYTICS_FIELDS[name] ?? []; for (const f of Object.keys(body)) if (!keep.includes(f) || typeof body[f] !== "string" || (body[f] as string).length > 64) delete body[f]; }
  // Batch D (D-13, RV-09/RV-11): a session row is built from a whitelist. It is
  // always owned by its creator, and responder fields are set
  // only by the gate's join (so a row can't claim to be already joined or to be
  // someone else's conversation).
  if (name === "VeilSession") {
    // b77m (audit VAR-26, relay half): a chat/seat token is 48 lowercase hex (the app's 24 random
    // bytes: invite.ts hexRand(24), contact.ts). Any other string used to be accepted (<= 256 chars)
    // and became a KV key part and a storage-key suffix on the phones ("<T0>_p0", "wrap_…").
    if (!sessionTokenOk(body.token)) return { __badRequest: "Invalid session token" } as any;
    const picked: Record<string, unknown> = {};
    for (const f of VEIL_SESSION_CREATE_FIELDS) if (body[f] !== undefined) picked[f] = body[f];
    // b70 (re-review 5): every field has a real size (keys, ciphertexts, hashes,
    // names); one field used to carry the whole 48 KB, and group rows never expire
    for (const [f, v] of Object.entries(picked)) {
      if (typeof v === "string" && utf8Len(v) > 4096) return { __forbidden: `Field too large: ${f}` } as any;
    }
    if (utf8Len(JSON.stringify(picked)) > 24_000) return { __forbidden: "Session row too large" } as any;
    // b75 (audit 2 V3): every new row starts "pending", whatever the request says. A
    // client-sent state:"active" used to be honoured (outside the field whitelist), so any
    // account could mint a peerless active row; no app sends it — a group's main row is
    // made active through the gate's "activate" (initiator slot, group rows only) and a
    // 1:1 row through "join".
    // b77 (sealed sender): a 1:1 row (no group_token) stores NO account id — it is a
    // rendezvous for the handshake only (the caller's account is used for the spam caps
    // below, in memory). Group rows keep the creator's account id (groups unchanged).
    const isGroupRow = typeof picked.group_token === "string" && !!picked.group_token;
    // A pending 1:1 row carries _init_tag instead: an HMAC of the creating account under the memory-only key
    // (initTag), so the addressee's request list can still show at most 3 requests per initiating account and
    // the creator's own account delete / purge can still find its pending rows; the database alone can't map it
    // to an account. The join deletes it.
    body = isGroupRow
      ? { ...picked, state: "pending", initiator_client_id: auth?.userId ?? "", responder_client_id: "", initiator_verified: false, responder_verified: false }
      : { ...picked, state: "pending", initiator_verified: false, responder_verified: false, ...(auth ? { _init_tag: await initTag(auth.userId) } : {}) };
    // Batch E (round-3 review R3-06): the initiator's Vardum ID must be one bound
    // to the caller's own account. It was taken as written, so a row could show
    // as a request "from" any contact (and pose as that contact's new chat).
    const initVid = String(body.initiator_veil_id ?? "");
    if (initVid) {
      const iid = auth ? (await KV.get<Record<string, unknown>>(["veil_identity", keySafe(initVid)])).value : null;
      if (!iid || iid.bound !== true || String(iid.account_hash || "") !== await accountHashOf(auth!.userId)) {
        return { __forbidden: "That Vardum ID is not yours" } as any;
      }
    }
    // Batch E (R3-10): lifetimes are the relay's, not the client's. A pending
    // row dies at expires_at, clamped to [now, now + its unopened-message dial]
    // (24 h minimum, 30 days at most); last_activity
    // starts now. Far-future values used to make rows the sweeper never removed.
    const nowMs = Date.now();
    const dialS = Number(body.expire_after_seconds);
    const maxLife = Math.min(30 * 86400_000, Math.max(86400_000, Number.isFinite(dialS) ? dialS * 1000 : 0));
    const askedExp = Date.parse(String(body.expires_at ?? ""));
    body.expires_at = new Date(Number.isFinite(askedExp) ? Math.min(nowMs + maxLife, Math.max(nowMs, askedExp)) : nowMs + maxLife).toISOString();
    body.last_activity = new Date(nowMs).toISOString();
    // Batch F (round-4 reviews R4-3-01 / R4-4-20): key_retention_hours, as the app
    // clamps it (whole hours, 0-720; 0 = Off, which the sweeper reads as a year).
    // An unbounded value made rows the sweeper never removed. Same rule as the
    // app's clampDials, so an invite link's dials still match the row.
    { const h = Number(body.key_retention_hours); body.key_retention_hours = Number.isInteger(h) ? Math.min(720, Math.max(0, h)) : 168; }
    // b70 (re-review 9): the time dials too (an unbounded one made every later join a 500)
    for (const f of ["default_ttl_seconds", "expire_after_seconds"] as const) {
      if (body[f] !== undefined) { const v = Number(body[f]); body[f] = Number.isFinite(v) ? Math.min(30 * 86400, Math.max(0, Math.floor(v))) : undefined; }
    }
    // one account can't flood (or fill) another user's request list
    const target = String(body.responder_veil_id || "");
    if (auth && validVeilId(target)) {
      const tid = (await KV.get<Record<string, unknown>>(["veil_identity", keySafe(target)])).value;
      const mine = !!tid && String(tid.account_hash || "") === await accountHashOf(auth.userId);
      // b77: the limiter row names the pair by two memory-only HMAC tags (reqPairKey), not
      // by "req:<account hash>:<Vardum ID>" (a who-asked-whom row anyone with the database read)
      if (!mine && await rateLimit(await reqPairKey(auth.userId, target), REQUESTS_PER_TARGET_PER_DAY, 86400_000, 0)) {
        return { __forbidden: "Too many requests to this Vardum ID today" } as any;
      }
    }
    // b70 (re-review 7): group rows live with their group, so one account's total is capped
    // (b75 (audit RL-07): checked atomically with the row's write — see rowCapCheck)
    // Batch E (R3-10): and no account mints session rows without limit
    if (auth && await rateLimit(`vscreate:${auth.userId}`, SESSION_CREATES_PER_DAY, 86400_000, 0)) {
      return { __forbidden: "Too many new conversations today — try again tomorrow" } as any;
    }
  }
  // Batch E (RV-39): a vault row may point only at a file its own account
  // uploaded — the sweeper keeps vault containers, so a row naming someone
  // else's blob kept that file forever (and its delete removed it)
  if (name === "VeilVault" && auth && !(await blobHeldBy(String(body.container_uri ?? ""), await accountHashOf(auth.userId)))) {
    return { __forbidden: "Not your file" } as any;
  }
  // b70 (re-review 5): kept-forever rows are capped per account (daily limits alone let
  // storage grow without end: vault containers are never swept, notes never expire)
  // (b75 (audit RL-07): checked atomically with the row's write — see rowCapCheck)
  // owner-scoped entities (vaults/notes/push tokens) are tagged with the creating account
  if (auth && OWNER_SCOPED_ENTITIES.has(name)) {
    body = { ...body, _acct: await accountHashOf(auth.userId) };
  }
  // Batch H (round-6 reviews R6-3-01, R6-3-06, N6-1): a UnifiedPush row names a plain
  // topic on an allowed host and carries valid Web Push keys; one row per token
  // (the newest registration wins, so the sender's lookup is unambiguous); and at
  // most PUSH_ROWS_PER_ACCOUNT rows per account, the oldest replaced.
  if (name === "VeilPushToken" && auth) {
    const tok = String(body.expo_token || "");
    if (!tok || tok.length > 512) return { __forbidden: "Invalid push token" } as any;
    // b77p (audit 2 VAR-01): push rows carry nothing about mailboxes any more (b77's push_refs
    // joined each inbound mailbox to this account); a mailbox holds its own sealed wake box.
    // b77p round 2 (owner decisions 1 and 4): a push row exists only for a LEGACY (pre-b77p) phone during the
    // transition window (the POST route refuses it after VEIL_COMPAT_UNTIL), which may list its push_refs again
    if (body.push_refs !== undefined) {
      const refs = compatOn() ? cleanPushRefs(body.push_refs) : null;
      if (!refs) return { __forbidden: compatOn() ? "Invalid push references" : "push_refs is retired: update Vardum" } as any;
      body = { ...body, push_refs: refs };
    }
    if (tok.startsWith(UP_TOKEN_PREFIX)) {
      const url = tok.slice(UP_TOKEN_PREFIX.length);
      if (!upEndpointAllowed(url)) return { __forbidden: "Push endpoint not allowed" } as any;
      if (body.up_endpoint !== undefined && String(body.up_endpoint) !== url) return { __forbidden: "Push endpoint mismatch" } as any;
      if (!upKeysValid(body.up_p256dh, body.up_auth)) return { __forbidden: "Push keys missing or invalid" } as any;
    }
    // b71 (audit F-19): ONE account per push address. A second account registering an
    // address another account already holds is refused (it used to be accepted, so
    // anyone knowing a phone's token or ntfy topic could have the relay push to it on
    // their own account's events). The other account's row is replaced only when the
    // new registrant proves it receives that address's pushes: the relay sends a
    // silent challenge push (Expo tokens) and the app re-registers with verify_code.
    const verifyCode = typeof body.verify_code === "string" ? body.verify_code : "";
    delete body.verify_code;
    delete body.up_verified; // b74 (audit VAR-13): set by the relay only
    const myAcct = String(body._acct || "");
    // b74 (audit VAR-13): a UnifiedPush address is proven with a challenge encrypted to the
    // Web Push keys this registration names (only the phone holding them can read it)
    const upKeys: UpKeys | null = tok.startsWith(UP_TOKEN_PREFIX) ? { p256: String(body.up_p256dh || ""), auth: String(body.up_auth || "") } : null;
    const ownSame: Deno.KvKey[] = [], otherSame: Deno.KvKey[] = [];
    let ownProvenSameKeys = false;
    for await (const e of pushRowsOf(tok)) { // b77n (pre-audit L3): by ["ix_push_tok"] (it scanned every push row)
      const r = e.value as Record<string, unknown>;
      if (String(r.expo_token || "") === tok) {
        const own = String(r._acct || "") === myAcct;
        (own ? ownSame : otherSame).push(e.key);
        if (own && upKeys && r.up_verified === true && String(r.up_p256dh || "") === upKeys.p256 && String(r.up_auth || "") === upKeys.auth) ownProvenSameKeys = true;
      }
    }
    // b71 (audit F-19): an address another account holds needs the proof. b74 (audit VAR-13):
    // so does a UnifiedPush address on its FIRST registration (or with new keys) — it used to
    // be first come, first served (only Expo tokens were ever challenged). Re-registering an
    // address this account already proved, with the same keys, needs nothing.
    // b75 (audit RL-11): an Expo token's FIRST registration still needs no proof (disclosed in
    // docs/protocol-spec.md §8.2): the proof would ride an iOS background push, which APNs
    // throttles or drops and a backgrounded app may never see, leaving that iPhone with no
    // notifications at all. The token is known only to the phone, Expo and this relay.
    if (otherSame.length || (upKeys && !ownProvenSameKeys)) {
      const proven = !!verifyCode && await pushChallengeOk(tok, myAcct, verifyCode, upKeys);
      if (!proven) {
        const sent = await sendPushChallenge(tok, myAcct, upKeys);
        if (otherSame.length) return { __pushTaken: true, push_verify: sent ? "sent" : "unavailable" } as any;
        return { __pushVerify: true, push_verify: sent ? "sent" : "unavailable" } as any;
      }
      if (upKeys) body = { ...body, up_verified: true };
      // proven: an Expo token's challenge reached the device itself (only the phone holding
      // the token receives it), so the stale row of the other account goes.
      // b75 (audit PU-1): a UnifiedPush proof does NOT remove the other account's row. On
      // ntfy.sh anyone who knows a topic name can subscribe to it, so the "proof" (reading
      // the challenge the newcomer's own registration caused, encrypted to the newcomer's
      // own keys) shows topic read access, not that the address is the newcomer's phone; a
      // squatter used to delete the victim's row this way and stop the victim's pushes.
      // Both rows stay: each account's pushes are encrypted to that account's own row's keys
      // only (pushFetch / sendUnifiedPush), and a phone drops what it can't decrypt.
      if (!upKeys) for (const k of otherSame) await deletePushRow(k);
    }
    if (upKeys && ownProvenSameKeys) body = { ...body, up_verified: true };
    for (const k of ownSame) await deletePushRow(k); // this account's own row for the address is replaced
    // (b75 (audit RL-07): the per-account row cap — the oldest replaced — is applied
    // atomically with the row's write, see rowCapCheck)
  }
  // every other row records its creator as a per-row tag (unlinkable across
  // rows FOR PEERS, so a peer reading a session row learns nothing about the
  // account). b71 (audit F-30): the tag is an unkeyed hash of the account id and
  // row id, so the operator — who has both — can recompute it and link the rows.
  // b77 (sealed sender): not on a 1:1 session row (no account link at all)
  // b77t (audit 5 C-10): and not on an analytics row (OnboardingStep / AttributionSource): the opt-in usage rows carried
  // an _owner tag the operator can recompute from the account id, so they were linkable to the account for their 30
  // days. They now carry nothing that names the account (rows already stored lose the tag in the sweeper, see below).
  else if (auth && !ANALYTICS_ENTITIES.has(name) && !(name === "VeilSession" && !(typeof body.group_token === "string" && body.group_token))) {
    body = { ...body, _owner: await ownerTag(auth.userId, ridv) };
  }
  // Batch C (V-20): a group_token must be a hex string or absent — a non-string
  // (e.g. an array that stringifies to a real token) used to skip the creator rule
  if (name === "VeilSession" && body.group_token !== undefined && body.group_token !== "" && !(typeof body.group_token === "string" && /^[0-9a-f]{8,128}$/.test(body.group_token))) {
    return { __forbidden: "Invalid group token" } as any;
  }
  // b199 AUTHZ: group rows are minted only by the group's creator (createGroup
  // makes the main row and every invite row; members only JOIN invite rows).
  // Anyone else minting a row with a known group_token became a valid group
  // credential — attest a fresh key, read the roster and stream, rotate.
  if (name === "VeilSession" && auth && typeof body.group_token === "string" && body.group_token) {
    if (!(await claimOrCheckGroupOwner(body.group_token, auth))) {
      return { __forbidden: "Only the group's creator can add sessions to it" } as any;
    }
  }
  // Batch D (add-later seats, found by the addlater check): a seat added to an
  // EXISTING group gets the group's current epoch and PQ key from the relay's own
  // group record — rotate stamps only the rows that exist at that moment, so a
  // seat made later used to peek as epoch 0 with no key and could never be joined.
  // (A brand-new group has no record yet: its creation rotate stamps every row.)
  if (name === "VeilSession" && typeof body.group_token === "string" && body.group_token) {
    const grec = await groupRecord(body.group_token);
    if (Number(grec.epoch) > 0) body = { ...body, group_epoch: Number(grec.epoch), group_pq_pub: String(grec.pq_pub || "") };
    // b75 (audit V12): the group's burn policy, from the creator's first row (only the
    // creator mints rows — checked just above)
    if (!grec.burn_policy) await recordGroupBurnPolicy(String(body.group_token), body);
  }
  // session tokens are unique pointers — a duplicate create must NOT overwrite
  // the index (it would silently repoint submitEnvelope/burn at a hashless row)
  // b70 (re-review 2): a session token becomes a KV key part
  if (name === "VeilSession" && (typeof body.token !== "string" || !body.token || body.token.length > MAX_KEY_PART)) return { __forbidden: "Invalid session token" } as any;
  if (name === "VeilSession" && (await KV.get(await retiredTokenKey(String(body.token)))).value) return { __conflict: true, id: "" } as any; // b70 (re-review 5)
  if (name === "VeilSession" && typeof body.token === "string" && body.token) {
    const existing = (await KV.get<string>(["veil_sess_token", body.token])).value;
    if (existing) return { __conflict: true, id: existing } as any;
  }
  // b77u (audit 6): an analytics row's time is the UTC day only — an exact time could be matched against the account's
  // other timed rows (token use, identity binds) and link the "anonymous" count back to the account
  const stamp = ANALYTICS_ENTITIES.has(name) ? new Date().toISOString().slice(0, 10) + "T00:00:00.000Z" : nowIso();
  const row = { id: ridv, created_date: stamp, updated_date: stamp, ...body };
  // b75 (audit RL-07): the row, its per-account cap and (for a session) its token claim are
  // written in ONE atomic step. The caps used to be a count followed, later, by a plain
  // write, so parallel creates at cap-1 all passed. Each attempt reads the account's
  // per-kind sequence row, counts what the account holds, and commits only if that
  // sequence row is unchanged — a create that raced another one retries and counts again.
  // (The session token is claimed in the same step, check-and-set: two creates of one
  // token can't both pass the existence check above.)
  const capKind = auth ? rowCapKind(name, body) : null;
  const capAcct = auth ? await accountHashOf(auth.userId) : "";
  for (let attempt = 0; ; attempt++) {
    if (attempt >= 25) return { __forbidden: "Busy — try again" } as any;
    const tx = KV.atomic();
    // b77s (audit 4 RA-02): only while the account is live (checked in this same step)
    if (auth) {
      const ue = await liveAccountEntry(auth.userId);
      if (!ue) return { __response: ACCOUNT_GONE_WRITE() } as any;
      tx.check(ue);
    }
    if (capKind && auth) {
      const refused = await rowCapCheck(tx, capKind, auth.userId, capAcct, String(body.expo_token ?? ""), utf8Len(JSON.stringify(row)));
      if (refused) return { __forbidden: refused } as any;
    }
    if (name === "VeilSession") tx.check({ key: ["veil_sess_token", String(body.token)], versionstamp: null }).set(["veil_sess_token", String(body.token)], ridv);
    tx.set(["entity", name, ridv], row);
    for (const k of await entityIxKeys(name, ridv, row)) tx.set(k, 1); // b77n (pre-audit L3)
    if (name === "VeilPushToken") for (const k of pushRefIndexKeys(ridv, row)) tx.set(k, 1); // b77r1 (R-6); legacy rows, transition window only
    if ((await tx.commit()).ok) break;
    if (name === "VeilSession") {
      const taken = (await KV.get<string>(["veil_sess_token", String(body.token)])).value;
      if (taken) return { __conflict: true, id: taken } as any;
    }
    await new Promise((r) => setTimeout(r, Math.random() * 5));
  }
  if (name === "VeilSession" && !(body as Record<string, unknown>).group_token) void bumpStat("chats");
  // b77p round 2 (owner decision 1): a NEW contact request no longer pushes its addressee (that push was
  // account-level: addressed by Vardum ID -> account -> the account's push row, so a relay logging its pushes could
  // tie the account to the push address its mailbox wakes use). The addressee finds the request when the app next
  // opens or is woken (a 1:1 message wake), or on its foreground poll.
  return row;
}

/** b75 (audit RL-07): the per-account row caps, by kind */
type RowCapKind = "VeilVault" | "VeilNote" | "group" | "push";
function rowCapKind(name: string, body: Record<string, unknown>): RowCapKind | null {
  if (name === "VeilVault" || name === "VeilNote") return name;
  if (name === "VeilPushToken") return "push";
  if (name === "VeilSession" && typeof body.group_token === "string" && body.group_token) return "group";
  return null;
}
/**
 * b75 (audit RL-07): adds one account's cap check to `tx`, the atomic step that writes the
 * new row. ["row_cap_seq", kind, account hash] is a per-account sequence: the step checks it
 * is unchanged since read and bumps it, so of two creates that counted the same rows only
 * one commits; the other retries and counts again. Returns the refusal, or null.
 *   VeilVault / VeilNote: at most VAULTS_PER_ACCOUNT / NOTES_PER_ACCOUNT rows (refused past it);
 *   group: at most GROUP_ROWS_PER_ACCOUNT group rows (seats + main rows) the account created;
 *   push: at most PUSH_ROWS_PER_ACCOUNT rows, the oldest REPLACED (their deletes join the step).
 * Deleting rows never touches the sequence: a create racing a delete counts the deleted row
 * at worst (a conservative refusal), never one too few.
 */
async function rowCapCheck(tx: Deno.AtomicOperation, kind: RowCapKind, userId: string, acct: string, pushTok: string, rowBytes = 0): Promise<string | null> {
  const seqKey: Deno.KvKey = ["row_cap_seq", kind, acct];
  const seq = await KV.get<number>(seqKey);
  tx.check(seq).set(seqKey, (Number(seq.value) || 0) + 1);
  if (kind === "push") {
    const mine: { key: Deno.KvKey; at: string; row: Record<string, unknown> }[] = [];
    for await (const e of acctRows("VeilPushToken", acct)) { // b77n (pre-audit L3): by ["ix_acct"]
      if (String(e.value?._acct || "") === acct && String(e.value?.expo_token || "") !== pushTok) mine.push({ key: e.key, at: String(e.value?.created_date || ""), row: e.value });
    }
    mine.sort((x, y) => x.at.localeCompare(y.at));
    let ixBudget = 500; // (one atomic step holds at most 1000 mutations; entries past this go on their next use or sweep)
    for (const old of mine.slice(0, Math.max(0, mine.length - (PUSH_ROWS_PER_ACCOUNT - 1)))) {
      tx.delete(old.key);
      for (const k of pushRefIndexKeys(String(old.key[2]), old.row)) if (ixBudget-- > 0) tx.delete(k); // b77r1 (audit R-6), legacy rows
      for (const k of await entityIxKeys("VeilPushToken", String(old.key[2]), old.row)) if (ixBudget-- > 0) tx.delete(k); // b77n (L3)
    }
    return null;
  }
  const cap = kind === "VeilVault" ? VAULTS_PER_ACCOUNT : kind === "VeilNote" ? NOTES_PER_ACCOUNT : GROUP_ROWS_PER_ACCOUNT;
  let held = 0;
  if (kind === "group") {
    for await (const _e of groupRowsCreatedBy(userId)) if (++held >= cap) break; // b77s (audit 4 RE-02): by ["ix_gsess_init"] (it read every session row)
  } else if (kind === "VeilNote") {
    // b77n (pre-audit M1): notes never expire, so the account's note BYTES are capped too (the row cap alone
    // let one account keep 2000 × 48 KB); the whole table is read through ["ix_acct"] (pre-audit L3)
    let bytes = rowBytes;
    for await (const e of acctRows("VeilNote", acct)) { held++; bytes += utf8Len(JSON.stringify(e.value)); }
    if (held < cap && bytes > NOTE_BYTES_PER_ACCOUNT) return "Notes storage limit reached — delete some notes first";
  } else {
    for await (const e of acctRows(kind, acct)) if (String(e.value?._acct ?? "") === acct && ++held >= cap) break; // b77n (L3)
  }
  if (held < cap) return null;
  return kind === "VeilVault" ? "Vault limit reached — delete a vault first"
    : kind === "VeilNote" ? "Note limit reached — delete some notes first"
    : "Too many group seats on this account — remove a group first";
}

/** b71 (review R-2): invite pushes one Vardum ID receives, from ALL callers together.
 *  REQUESTS_PER_TARGET_PER_DAY is per calling account, so fresh accounts multiplied it;
 *  this cap is per addressee. A request past it is still created (it shows in the
 *  list), it just doesn't buzz the phone. */
// b77p round 2 (owner decision 1): pushInvitePing (the contact-request push, by Vardum ID -> account -> push rows)
// and its per-addressee caps (INVITE_PUSHES_PER_TARGET_PER_HOUR / _DAY, "invpush:" limiter rows) are gone with
// account-level push. ["push_coalesce_invite", ...] rows an older relay left are still deleted where they were.

/**
 * b199: which account owns (created) a group. Recorded at the group's first
 * session row; groups from before the record existed are resolved from their
 * rows — a session row the caller created (_owner tag), or the creator's
 * member row (_acct, or the label-derived group account hash). A group with
 * no rows yet is claimed atomically by the caller.
 */
/** Batch C (B1): veil_id = base58(SHA-256(IK_pub))[0:16] — the client's derivation */
async function veilIdOfIk(ikPubB64: string): Promise<string> {
  const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  const h = new Uint8Array(await crypto.subtle.digest("SHA-256", Uint8Array.from(atob(ikPubB64), (c) => c.charCodeAt(0))));
  let n = 0n;
  for (const b of h) n = (n << 8n) | BigInt(b);
  let out = "";
  while (n > 0n) { out = B58[Number(n % 58n)] + out; n /= 58n; }
  for (const b of h) { if (b === 0) out = "1" + out; else break; }
  return out.slice(0, 16);
}

async function claimOrCheckGroupOwner(groupToken: string, auth: { userId: string; email?: string }): Promise<boolean> {
  const k = ["veil_group_owner", keySafe(groupToken)];
  const acct = await accountHashOf(auth.userId);
  const recorded = (await KV.get<string>(k)).value;
  if (recorded) return recorded === acct;
  let seen = false, owns = false;
  for await (const e of groupSessionRows(groupToken)) { // b77s (audit 4 RE-02): by ["ix_gsess"] (it read every session row)
    const s = e.value as Record<string, unknown>;
    if (String(s.group_token || "") !== groupToken) continue;
    seen = true;
    if (s._owner && String(s._owner) === await ownerTag(auth.userId, String(e.key[e.key.length - 1]))) { owns = true; break; }
  }
  if (!owns) {
    const gAcct = await sha256hex("veil-group-account:" + String(auth.email || "").trim().toLowerCase());
    for await (const e of groupMemberRows(groupToken)) { // b77n (pre-audit L3): by ["ix_gmem"]
      const m = e.value as Record<string, unknown>;
      if (String(m.group_token || "") !== groupToken) continue;
      seen = true;
      if (m.role === "creator" && (String(m._acct || "") === acct || (!!auth.email && String(m.account_hash || "") === gAcct))) { owns = true; break; }
    }
  }
  if (seen && !owns) return false;
  const claim = await KV.atomic().check({ key: k, versionstamp: null }).set(k, acct).commit();
  return claim.ok || (await KV.get<string>(k)).value === acct;
}

async function getEntity(name: string, eid: string) {
  return (await KV.get(["entity", name, eid])).value ?? null;
}

async function deleteEntity(name: string, eid: string) {
  const row = (await KV.get(["entity", name, eid])).value as Record<string, unknown> | null;
  if (name === "VeilEnvelope") await deleteEnvelopeRow(["entity", name, eid], row); // b71 (audit F-09): with its index rows
  else if (name === "VeilPushToken") await deletePushRow(["entity", name, eid]); // b77r1 (audit R-6): with its push_ref index
  else await deleteIndexedRow(name, eid); // b77n (pre-audit L3): with its index entries
  if (row && name === "VeilSession" && typeof row.token === "string") {
    await KV.delete(["veil_sess_token", row.token]);
    // b70 (re-review 7): a group seat's token is retired however the row goes
    // b75 (audit RL-05): and so is a 1:1 chat's
    await retireSessionToken(row.token);
    if (row.group_token) await dropSeatMembership(String(row.token)); // b70 (re-review 11)
    // b199: the session's envelopes go with it. The client falls back to this
    // generic delete when the gate's end-with-proof is refused (peer-created
    // rows), which used to orphan every envelope of the thread.
    // b70 (re-review R13): not a group seat's posts — they are the group's
    // shared history (the gate's end keeps them too, W-19)
    if (!row.group_token) await deleteSessionEnvelopes(row.token);
  }
  if (row && name === "VeilVault") await removeVaultBlob(row);
  return row;
}

/** b77m (audit VAR-26): the one session-token format (48 lowercase hex). VEIL_TEST_ANY_SESSION_TOKEN=1
 *  (set ONLY by repro/run-relay-suites.mjs for the older suites, which predate the rule and use
 *  readable tokens) lifts it; production never sets it. */
const SESSION_TOKEN_RE = /^[0-9a-f]{48}$/;
const ANY_SESSION_TOKEN = Deno.env.get("VEIL_TEST_ANY_SESSION_TOKEN") === "1";
function sessionTokenOk(t: unknown): t is string {
  return typeof t === "string" && (SESSION_TOKEN_RE.test(t) || (ANY_SESSION_TOKEN && t.length > 0 && t.length <= MAX_KEY_PART));
}
async function findSessionByToken(token: string) {
  // b77m (audit VAR-26): a malformed token names no session (and never becomes a key)
  if (!sessionTokenOk(token)) return null;
  const eid = (await KV.get<string>(["veil_sess_token", keySafe(token)])).value;
  if (!eid) return null;
  return (await KV.get(["entity", "VeilSession", eid])).value as Record<string, unknown> | null;
}

// ---------- functions: submitEnvelope ----------
/** b77 (veil-ratchet-8, spec §4.10, §12.18): a 1:1 header is opaque — 'h8.' and 5160 standard base64
 *  characters, 5163 in all (3870 sealed bytes, no '='; the '==' form of 3868 bytes is accepted too).
 *  sealedSubmit (the only 1:1 route) checks this shape and nothing else; it parses, stores and derives
 *  nothing from it. submitEnvelope uses it only to exempt such a header from its 4096 cap, so an old
 *  1:1 client gets the clean 410. (crypto-core isSealedHeaderString is the same rule) */
export const SEALED_HEADER_LENGTH = 5163;
export function isSealedHeaderString(h: unknown): h is string {
  return typeof h === "string" && h.length === SEALED_HEADER_LENGTH && /^h8\.(?:[A-Za-z0-9+/]{5158}==|[A-Za-z0-9+/]{5160})$/.test(h);
}

async function fnSubmitEnvelope(auth: { userId: string; email?: string }, body: Record<string, any>, net = "local", wideNets: WideTag[] = []) {
  // b198 HARDENING (live-caught during the vault battery): Deno KV values cap
  // at 64KB — an oversized envelope used to crash the handler into a 500
  // ("Value too large"). Legit chat never approaches this (M-4 chunks cap at
  // 4096 bytes); the guard turns a hostile/buggy oversized envelope into a
  // clean 413. Media never rides envelopes at all (ciphertext lives in blob
  // storage; the envelope carries only the descriptor).
  const b64Ct = String(body?.ciphertext || "");
  if (b64Ct.length > 48000) return j({ error: "Envelope too large", message: "Envelope too large" }, 413);
  // b70 (audit RLY-8): the other stored fields are capped too, and so is the
  // whole envelope, so nothing reaches the 64 KB store limit as a 500
  for (const f of ["header", "iv", "sender_client_id", "sender_pseudonym"] as const) {
    // b77: a sealed 1:1 header is exactly SEALED_HEADER_LENGTH (over this cap by design)
    if (f === "header" && isSealedHeaderString(body?.header)) continue;
    if (body?.[f] !== undefined && String(body[f]).length > 4096) return j({ error: "Envelope too large", message: "Envelope too large" }, 413);
  }
  if (utf8Len(JSON.stringify(body ?? {})) > 56000) return j({ error: "Envelope too large", message: "Envelope too large" }, 413);
  const { session_token, ciphertext, iv, header, ttl_seconds } = body;
  // b77 (sealed sender): 1:1 chats deliver through anonymous mailboxes (sealedSubmit); this
  // logged-in, token-scoped path is for GROUP posts only. A 1:1 envelope (no group_token)
  // is refused before anything is written (no rate row, no quota row).
  if (typeof body?.group_token !== "string" || !body.group_token) return j({ error: LEGACY_1TO1, message: LEGACY_1TO1 }, 410);
  if (!session_token || !ciphertext || !iv || !header) {
    return j({ error: "Missing envelope fields", message: "Missing envelope fields" }, 400);
  }
  // b70 (re-review R11): the token is a string (an array used to reach a 500 after the envelope was stored)
  if (typeof session_token !== "string" || session_token.length > MAX_KEY_PART) return j({ error: "Session not found", message: "Session not found" }, 404);
  const session = await findSessionByToken(session_token);
  if (!session) return j({ error: "Session not found", message: "Session not found" }, 404);
  if (!session.group_token) return j({ error: LEGACY_1TO1, message: LEGACY_1TO1 }, 410); // b77
  // SPEC §3/§4: 150 envelopes/min per account (group posts)
  const rl = await rateLimit("env:" + auth.userId, 150, 60_000, 2);
  if (rl) return j({ locked: true, retry_minutes: rl.retry_minutes }, 429);
  if (session.state !== "active") return j({ error: "Session is not available", message: "Session is not available" }, 409);
  // (b70 re-review P3: a peerless "active" row is bounded by the per-account
  // and relay-wide daily envelope quotas below; requiring a joined peer would
  // add nothing, since a second account can join it)

  // b198 GROUP CLAUSE — faithful port of the Base44 submit's veil-group-1
  // branch (this was entirely MISSING from my submit: group envelopes were
  // stored without their group_token, so the group-scoped receive channel
  // could never see them — One's 'hey' vanished exactly there).
  let headerObj: Record<string, unknown> | null = null;
  try { headerObj = JSON.parse(String(header)); } catch { /* 1:1 path: opaque header string is fine */ }
  // b74 (clean-break protocol bump): the group protocol moved to veil-group-2; veil-group-1
  // stays accepted, with the same checks, for older apps still talking to each other
  const isGroupEnvelope = !!headerObj && GROUP_PROTOCOLS.has(String((headerObj as Record<string, unknown>).v));
  // b70 (re-review R12): a group session takes only group envelopes (anything
  // else skipped the roster and epoch checks)
  if (session.group_token && !isGroupEnvelope) return j({ error: "Group sessions take group messages only", message: "Group sessions take group messages only" }, 400);
  let groupToken = "";
  let seatIntroSeat = ""; // b73 (audit): V-01 — set when this is a not-yet-admitted member's seat intro
  // b75r3 (audit R3G-01): the keyed-tag binding this post makes, written only after every check passed
  let gtagBindKey: Deno.KvKey | null = null, gtagCallerAcct = "";
  // b76r2 (audit GB-1 / R2-B1, GB-2, R2-B2): a burn-after-open group's envelope records who may vote on its burn
  // (the accounts admitted now, minus the sender) — see burnEligOf
  let burnEligAccts: string[] | null = null, burnEligLegacy = 0;
  if (isGroupEnvelope) {
    const gh = headerObj as Record<string, unknown>;
    groupToken = typeof body.group_token === "string" ? body.group_token : "";
    if (!groupToken || !/^[0-9a-f]{8,128}$/.test(groupToken)) return j({ error: "Missing or invalid group_token", message: "Missing or invalid group_token" }, 400);
    if (!GROUP_PROTOCOLS.has(String(gh.v)) || typeof gh.sid !== "string" || !gh.sid || !Number.isInteger(gh.ge) || (gh.ge as number) < 0 || !Number.isInteger(gh.n) || (gh.n as number) < 0) {
      return j({ error: "Invalid group message header", message: "Invalid group message header" }, 400);
    }
    if (String(body.sender_client_id || "") !== String(gh.sid)) return j({ error: "Sender tag does not match the group header", message: "Sender tag does not match the group header" }, 400);
  }
  // (b77: the b71 1:1 sender-tag check — 'a' + H(header.rp) — is gone with the 1:1 path:
  // sealed 1:1 envelopes carry an encrypted header and no sender tag at all)

  // write-secret authorization: sha256(write_secret) must match a stored hash
  const writeSecret = String(body.write_secret || "");
  const sha256 = async (v: string) => [...new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(v)))].map((b) => b.toString(16).padStart(2, "0")).join("");
  const wHash = writeSecret ? await sha256(writeSecret) : "";
  const iHash = String(session.initiator_write_hash || "");
  const rHash = String(session.responder_write_hash || "");
  if (!wHash || (!ctEq(wHash, iHash) && !ctEq(wHash, rHash))) { // Batch C (B7): constant time (V-30)
    console.log("[submit] write-secret mismatch (session details not logged — b199 audit)");
    return j({ error: "Invalid session credential", message: "Invalid session credential" }, 403);
  }

  // b198 GROUP VALIDATIONS (Base44 order): session-group binding, header epoch
  // vs the server-side group epoch, and roster membership of the sender tag.
  if (isGroupEnvelope) {
    const gh = headerObj as Record<string, unknown>;
    if (typeof session.group_token !== "string" || session.group_token !== groupToken) { // Batch C (V-20): strict
      return j({ error: "This session does not belong to that group", message: "This session does not belong to that group" }, 403);
    }
    if (Number(session.group_epoch || 0) !== Number(gh.ge)) {
      return j({ error: "Message epoch does not match the group epoch", message: "Message epoch does not match the group epoch" }, 400);
    }
    // The fetch limit MUST cover the whole roster — a limit below the cohort
    // cap silently refuses legitimate members (Base44 shared-limits lesson).
    const members: Record<string, unknown>[] = [];
    for await (const e of groupMemberRows(groupToken)) { // b77n (pre-audit L3): by ["ix_gmem"]
      const m = e.value as Record<string, unknown>;
      if (String(m.group_token || "") === groupToken) members.push(m);
    }
    let rostered = false;
    // b70 (audit GRP-3 / GRP-6): the sender tag must be the caller's OWN
    // membership — the row bound to this session, or one its account holds.
    // Any rostered tag used to pass, so a member (or an evicted member's left-
    // over seat) could post under someone else's tag.
    const callerAcctTag = await accountHashOf(auth.userId);
    // b71 (audit): a legacy row with no _acct is the caller's only when its
    // label-derived account_hash is the caller's (the same rule attest uses);
    // an _acct-less seat row used to count for whoever held the seat's secret
    const callerGroupAcct = auth.email ? await sha256hex("veil-group-account:" + String(auth.email).trim().toLowerCase()) : "";
    const heldByCaller = (m: Record<string, unknown>) => m._acct ? String(m._acct) === callerAcctTag : (!!callerGroupAcct && String(m.account_hash || "") === callerGroupAcct);
    // b71 (external audit F-13): members may also post under a tag keyed with the group
    // key (only members can compute it; the relay can't map it to a Vardum ID). Accepted
    // from a caller holding a membership row when it isn't another member's public tag
    // (clients check every post's sender signature, so a tag alone can't impersonate).
    const sentTag = String(body.sender_client_id || "");
    let holdsRow = false;
    const othersPublic = new Set<string>();
    for (const m of members.slice(0, 100)) { // b198: cohort cap 100
      const vid = String(m.veil_id || "");
      if (!vid) continue;
      const tag = "g" + [...new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(`veil-group-sender:${groupToken}:${gh.ge}:${vid}`))).slice(0, 6)].map((b) => b.toString(16).padStart(2, "0")).join("");
      // b70 (re-review 14): the seat's row counts only if the caller's account holds it (the
      // creator, who has every seat's initiator secret, used to post under any member's tag)
      const seatRow = String(m.session_token || "") === String(session_token) && heldByCaller(m);
      if (!seatRow && String(m._acct || "") !== callerAcctTag) { othersPublic.add(tag); continue; }
      holdsRow = true;
      if (tag === sentTag) { rostered = true; break; }
    }
    let keyedTag = false;
    if (!rostered && holdsRow && /^g[0-9a-f]{12}$/.test(sentTag) && !othersPublic.has(sentTag)) { rostered = true; keyedTag = true; }
    if (!rostered) return j({ error: "Sender is not a member of this group epoch", message: "Sender is not a member of this group epoch" }, 403);
    // b75r1 (audit G-9): a keyed tag (which the relay can't map to a Vardum ID) is bound to the first account that
    // posts under it in an epoch; another account posting under the same tag in that epoch is refused. b75 let any
    // admitted member post under another member's keyed tag (every phone then discarded it — the signature is the
    // other member's — and showed a discard note). A member whose tag someone took first gets this same refusal,
    // and its app re-sends that post under its public tag (group-session.ts, F-13 fallback). Kept 7 days (an epoch
    // lasts at most a day; members stop sending on keys older than 48 h).
    // b75r3 (audit R3G-01): only CHECKED here; the binding is written further down, once the post has passed the
    // admission and quota checks. b75r1 committed it here, before the admission check, so a claimant the creator
    // never let in (its post then refused as "not let in yet"), or any seat intro (sv 3), bound an admitted
    // member's keyed tag and that member was refused under its own tag for the rest of the epoch.
    if (keyedTag) {
      gtagBindKey = ["gtag_bind", await sha256hex("gtag:" + groupToken), Number(gh.ge), sentTag];
      // b77n (pre-audit L1): the binding holds a memory-keyed marker of the account, not its hash (see gtagMarker)
      gtagCallerAcct = await gtagMarker(gtagBindKey, callerAcctTag);
      const cur = await KV.get<GtagBindRow>(gtagBindKey);
      const held = gtagBoundTo(cur.value);
      if (held && !ctEq(held, gtagCallerAcct)) return j({ error: "Sender is not a member of this group epoch", message: "Sender is not a member of this group epoch" }, 403);
    }
    // b73 (audit): V-01 — a member the creator has not admitted (memberAdmitted) posts only
    // its seat intro (header sv 3, the "let me in" note only the creator can open), a few
    // an hour, and only its newest SEAT_INTROS_KEPT stay on the relay. Any of its rows used
    // to let it post anything, so a never-approved or declined link holder could bury the
    // group's real messages under hundreds of junk posts (the app pages 500 rows).
    const callerAdmitted = members.slice(0, 100).some((m) => !!String(m.veil_id || "")
      && ((String(m.session_token || "") === String(session_token) && heldByCaller(m)) || String(m._acct || "") === callerAcctTag)
      && memberAdmitted(m));
    if (!callerAdmitted) {
      if (gh.sv !== 3) return j({ error: "The group creator has not let you in yet — only your request to join can be sent", message: "The group creator has not let you in yet — only your request to join can be sent", not_admitted: true }, 403);
      const irl = await rateLimit("seatintro:" + await sessionTokenTag(String(session_token)), SEAT_INTROS_PER_HOUR, 3600_000, 0);
      if (irl) return j({ locked: true, retry_minutes: irl.retry_minutes, message: "Too many requests to join — try again later" }, 429);
      seatIntroSeat = String(session_token);
    }
    // b75r3 (audit R3G-01): a seat intro (sv 3) never binds a keyed tag (the app sends intros under the public
    // tag; a keyed one would only take the tag from the member it belongs to), and nor does a caller not let in
    if (gh.sv === 3 || !callerAdmitted) gtagBindKey = null;
    // b76r2 (audit GB-1 / R2-B1, GB-2, R2-B2): the burn snapshot — admitted accounts other than the sender's. A
    // seat intro (only the creator can open it) gets none: it is never shortened, as before (no quorum reached it).
    if (callerAdmitted && gh.sv !== 3 && (await groupBurnPolicy(groupToken)).burn_after_open) {
      const accts = new Set<string>();
      for (const m of members) {
        if (!memberAdmitted(m)) continue;
        if (m._acct) { if (String(m._acct) !== callerAcctTag) accts.add(String(m._acct)); } else burnEligLegacy++;
      }
      burnEligAccts = [...accts];
    }
  }

  // b198 DIAGNOSTIC (two-dial burn investigation): log the incoming ttl + the
  // session's dials — numbers only, never content. Remove after the root cause lands.
  // b198: the clamp rises to the 30-day tier — was 36h, which would have killed
  // a 30-day-dial group's messages in a day and a half.
  // b70 (re-review R1): an envelope lives no longer than its chat's own dials
  // allow (the 36 h relay default when they are off; 30 days at most)
  // b75 (audit RL-02): the cap is the chat's OWN unopened-message dial. It used to be
  // max(expire dial, burn dial, 36 h), so the 36 h floor applied even to a chat whose dials
  // said 60 s, and the sender's ttl_seconds was taken up to it (a peer, or a modified app,
  // kept every envelope 36 h). See envelopeLifeCapS.
  const dialCap = envelopeLifeCapS(session);
  // b70 (re-review 9): finite and positive (a huge negative made an invalid date, a 500)
  const ttlIn = Number(ttl_seconds);
  const ttl = Math.max(1, Math.min(Number.isFinite(ttlIn) && ttlIn > 0 ? ttlIn : 86400, dialCap, 2592000));
  // b70 (re-review R1): envelope bytes are capped per account and relay-wide
  // per UTC day (free accounts used to be able to fill the disk)
  {
    const size = utf8Len(JSON.stringify(body ?? {})); // b70 (re-review 5): bytes
    const day = new Date().toISOString().slice(0, 10);
    // b70 (re-review 3): past 60% of the relay-wide total only light senders
    // (under 2 MB today) still get through, so heavy senders filling the relay
    // can't stop everyone's messaging; the total itself still guards the disk.
    // Networks have their own daily cap too.
    // (net: the caller's network tag, from the route)
    const acctKey: Deno.KvKey = ["env_quota", await accountHashOf(auth.userId), day];
    const caps: [Deno.KvKey, number][] = [[acctKey, ENVELOPE_ACCOUNT_DAILY_BYTES], [["env_quota_all", day], ENVELOPE_RELAY_DAILY_BYTES]];
    if (net !== "local") caps.push([["env_quota_net", net, day], ENVELOPE_NETWORK_DAILY_BYTES]);
    for (const w of wideNets) caps.push([["env_quota_net" + w.bits, w.tag, day], ENVELOPE_NETWORK_DAILY_BYTES * WIDE_FACTOR[w.bits]]); // b74 (audit VAR-14)
    let counted = false;
    for (let attempt = 0; attempt < 5 && !counted; attempt++) {
      const tx = KV.atomic();
      let acctUsed = 0, allUsed = 0;
      for (const [key, cap] of caps) {
        const cur = await KV.get<Deno.KvU64>(key);
        const used = Number(cur.value?.value ?? 0n);
        if (key === acctKey) acctUsed = used;
        if (key[0] === "env_quota_all") allUsed = used;
        if (used + size > cap) return j({ locked: true, retry_minutes: 60, message: "Daily message limit reached" }, 429);
        tx.check(cur).set(key, new Deno.KvU64(BigInt(used + size)), { expireIn: 2 * 86400_000 });
      }
      if (allUsed + size > ENVELOPE_RELAY_DAILY_BYTES * 0.6 && acctUsed > ENVELOPE_LIGHT_USER_BYTES) return j({ locked: true, retry_minutes: 60, message: "Daily message limit reached" }, 429);
      counted = (await tx.commit()).ok;
    }
    if (!counted) return j({ message: "Busy — try again" }, 429);
  }
  // b75r1 (audit G-9) / b75r3 (audit R3G-01): the keyed tag is bound to this account now that the post passed
  // every check (membership, admission, quota). Another account that bound it in the meantime wins.
  if (gtagBindKey) {
    let bound = false;
    for (let attempt = 0; attempt < 3 && !bound; attempt++) {
      const cur = await KV.get<GtagBindRow>(gtagBindKey);
      const held = gtagBoundTo(cur.value);
      if (held) {
        if (!ctEq(held, gtagCallerAcct)) return j({ error: "Sender is not a member of this group epoch", message: "Sender is not a member of this group epoch" }, 403);
        bound = true;
      } else {
        bound = (await KV.atomic().check(cur).set(gtagBindKey, { k: BURN_VOTE_KEY_ID, m: gtagCallerAcct }, { expireIn: 7 * 86400_000 }).commit()).ok;
      }
    }
    if (!bound) return j({ error: "Try again in a moment", message: "Try again in a moment" }, 503);
  }
  const envId = rid();
  const env = {
    id: envId,
    session_token,
    // b198: group envelopes carry their group_token + header epoch — the
    // group-scoped receive channel filters on exactly these.
    ...(groupToken ? { group_token: groupToken, group_epoch: Number((headerObj as Record<string, unknown>).ge) } : {}),
    // Batch C (V-13): the sender's stable account id is no longer stored on
    // envelopes (it made the per-rotation sender pseudonym pointless). A
    // per-envelope owner tag (unlinkable across envelopes) lets account
    // deletion still find this account's envelopes.
    _owner: await ownerTag(auth.userId, envId),
    // b77: group envelopes only (a 1:1 envelope has none — refused above — and stores none)
    ...(groupToken ? { sender_client_id: String(body.sender_client_id || "") } : {}),
    ciphertext: String(body.ciphertext || ""),
    iv: String(body.iv || ""),
    header: String(body.header || ""),
    byte_length: Number(body.byte_length) || 0,
    // b77: the app sends protocol_version (snake case); the relay used to read only
    // protocolVersion, so every row said "veil-ratchet-4"
    protocolVersion: String(body.protocol_version || body.protocolVersion || "veil-group-2").slice(0, 32),
    created_date: nowIso(),
    expires_at: new Date(Date.now() + ttl * 1000).toISOString(),
  };
  // b71 (audit F-09): the envelope and its index entries in one step
  // b76r2 (audit GB-1 / R2-B1, GB-2, R2-B2): and its burn snapshot (who may vote), so no vote can come before it
  {
    const tx = KV.atomic().set(["entity", "VeilEnvelope", envId], env);
    for (const k of envIndexKeys(env, envId)) tx.set(k, 1);
    if (burnEligAccts) {
      const m = await Promise.all(burnEligAccts.map((a) => burnVoteMarker(envId, a)));
      tx.set(["burn_elig", keySafe(envId)], { k: BURN_VOTE_KEY_ID, m, x: burnEligLegacy }, { expireIn: ttl * 1000 + 60_000 });
    }
    await tx.commit();
  }
  // b70 (re-review 13): a chat ended (or deleted) while this ran already swept its
  // envelopes, so this one is taken back rather than kept with no chat to reach it
  {
    const still = await findSessionByToken(session_token);
    if (!still || String(still.id || "") !== String(session.id || "")) {
      await deleteEnvelopeRow(["entity", "VeilEnvelope", envId], env);
      return j({ error: "This chat has ended", message: "This chat has ended" }, 409);
    }
  }
  // b73 (audit): V-01 — a not-yet-admitted seat keeps only its newest few intros (each is a
  // re-send of the same request, so the older ones are dropped)
  if (seatIntroSeat) {
    const mine: { key: Deno.KvKey; value: Record<string, unknown> }[] = [];
    for await (const e of envelopesOfSession(seatIntroSeat)) if (String(e.key[2]) !== envId) mine.push(e);
    mine.sort((a, b) => String(b.value.created_date ?? "").localeCompare(String(a.value.created_date ?? "")));
    for (const e of mine.slice(SEAT_INTROS_KEPT - 1)) await deleteEnvelopeRow(e.key, e.value);
  }
  // b199 (Oct 16 audit): a second copy used to be written to ["veil_env",
  // session_token, envId] here. Nothing ever read it and NOTHING deleted it —
  // burn, expiry, ✕ and account deletion all removed only the entity row, so
  // every envelope ever sent survived on disk (ciphertext). Removed; the boot
  // migration below purges the copies already written.
  await touchSession(session_token); // b70 (re-review R11): no token-index rewrite per submit
  void bumpStat("envelopes"); // includes cover traffic: the relay can't tell decoys apart
  return json({ id: envId });
}

/**
 * b77n (pre-audit L1): a keyed-tag binding (["gtag_bind", …], b75r1 G-9 / b75r3 R3G-01) used to hold the posting
 * account's hash — unkeyed, so it named the account in the database for 7 days, and an account delete or purge
 * left it (only a group teardown removed them). It now holds {k, m}: m = HMAC(the memory-only burn-vote key,
 * "veil-gtag:" ‖ binding key ‖ ":" ‖ account hash), truncated, k = that key's id (BURN_VOTE_KEY_ID) — the same
 * scheme as the burn markers, so the database alone can't say which account posted under a tag, and nothing
 * names the account after it is gone. A row made under an earlier key (after a restart), or a pre-b77n row
 * (a plain hash string, deleted at boot), binds nobody: the next poster under the tag takes it.
 */
type GtagBindRow = { k?: string; m?: string } | string;
async function gtagMarker(bindKey: Deno.KvKey, acct: string): Promise<string> {
  if (!burnVoteKey) burnVoteKey = crypto.subtle.generateKey({ name: "HMAC", hash: "SHA-256", length: 256 }, false, ["sign"]) as Promise<CryptoKey>;
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", await burnVoteKey, enc.encode("veil-gtag:" + JSON.stringify(bindKey) + ":" + acct)));
  return "gt_" + [...mac.slice(0, 16)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
/** the marker a binding row holds under the current key, or "" (no row, an earlier key's row, a legacy row) */
function gtagBoundTo(row: GtagBindRow | null | undefined): string {
  return row && typeof row === "object" && row.k === BURN_VOTE_KEY_ID && typeof row.m === "string" ? row.m : "";
}
/** boot: pre-b77n bindings (a plain account hash) go */
async function dropLegacyGtagBinds(): Promise<number> {
  let n = 0;
  for await (const e of KV.list({ prefix: ["gtag_bind"] }, { consistency: "strong" })) if (typeof e.value === "string") { await KV.delete(e.key); n++; }
  return n;
}
/** b75 (audit RL-02): the relay's default envelope life (36 h), used only when the chat
 *  sets no unopened-message dial — or sets it to Off (0), which the app documents (and
 *  sends) as this standard window */
const RELAY_DEFAULT_ENVELOPE_LIFE_S = 129_600;
/**
 * b75 (audit RL-02): the longest an envelope of this chat lives on the relay, in seconds.
 *   expire_after_seconds > 0         → that dial (the unopened-message window; an opened
 *                                      message goes sooner: its receiver's burn deletes it);
 *   expire_after_seconds = 0 (Off)   → RELAY_DEFAULT_ENVELOPE_LIFE_S;
 *   no expire dial, burn dial > 0    → the burn dial (a row from an app that sent only it);
 *   neither dial                     → RELAY_DEFAULT_ENVELOPE_LIFE_S.
 * Never above 30 days (createEntity clamps both dials to that). The sender's ttl_seconds
 * can only shorten it.
 */
function envelopeLifeCapS(session: Record<string, unknown>): number {
  const rawE = session.expire_after_seconds, rawT = session.default_ttl_seconds;
  const e = Number(rawE), t = Number(rawT);
  const eSet = rawE !== undefined && rawE !== null && rawE !== "" && Number.isFinite(e) && e >= 0;
  if (eSet) return e > 0 ? Math.min(2_592_000, Math.floor(e)) : RELAY_DEFAULT_ENVELOPE_LIFE_S;
  if (Number.isFinite(t) && t > 0) return Math.min(2_592_000, Math.floor(t));
  return RELAY_DEFAULT_ENVELOPE_LIFE_S;
}

/** b74: group envelope header versions submit accepts (every one gets the same checks).
 *  The 1:1 protocol tag (veil-ratchet-*) is opaque to the relay: it only stores it. */
// b77m review (INFO): + veil-group-3 (b77m: hybrid wraps, chain-bound message keys); every tag gets the same checks
const GROUP_PROTOCOLS: ReadonlySet<string> = new Set(["veil-group-1", "veil-group-2", "veil-group-3"]);

/**
 * b73 (audit): V-01 — has the group's creator admitted this member row?
 * What the relay can see of an admission: the creator delivering that identity its first
 * group key through veilGroupGate wrap_deliver (every admission does it — a plain link
 * after the creator's Approve tap, a contact seat automatically — and nothing else
 * does). Rows attest writes from b73 on carry admitted:false until then; the creator's
 * own row is admitted at once.
 * b75 (audit GR-7): a row WITHOUT the flag is NOT admitted. Rows from before b73 carry no
 * flag and used to count as admitted ("admitted !== false"); b74/b75 is a clean protocol
 * break (no b73 group carries over), so every live member row has the flag, and a row
 * without one can only be stale or forged — it fails closed.
 */
function memberAdmitted(m: Record<string, unknown> | null | undefined): boolean {
  return !!m && m.admitted === true;
}

/**
 * b74 (audit VAR-01): is this ["veil_gmember", group, IK] entry an ADMITTED membership?
 * attest writes admitted (true for the creator, false for anyone else), wrap_deliver sets
 * it, evict and decline delete the entry. An entry written before b74 carries no flag:
 * then the member row decides (memberAdmitted — the rule submit already uses), and an
 * entry with NO member row behind it is not admitted (fail closed).
 */
async function gmemberAdmitted(groupToken: string, ikPub: string, g: Record<string, unknown> | null | undefined): Promise<boolean> {
  if (!g) return false;
  if (typeof g.admitted === "boolean") return g.admitted;
  for await (const e of groupMemberRows(groupToken)) { // b77n (pre-audit L3): by ["ix_gmem"]
    const m = e.value;
    if (m && String(m.group_token || "") === groupToken && String(m.IK_pub || "") === ikPub) return memberAdmitted(m);
  }
  return false;
}

/**
 * b74 (audit VAR-01): what of a group's stream this account may read.
 *   admitted: it holds an admitted membership — the whole stream;
 *   seats:    otherwise, the seats of its NOT-admitted memberships — only the rows posted
 *             through those (its own seat intros), never the roster or anyone else's rows.
 * A claimant the creator never let in used to read the roster and every row's metadata.
 */
async function groupReadAccess(groupToken: string, userId: string): Promise<{ admitted: boolean; seats: Set<string> }> {
  const acct = await accountHashOf(userId);
  const seats = new Set<string>();
  const claimIks = new Set<string>();
  for await (const e of KV.list<Record<string, unknown>>({ prefix: ["veil_gmember", keySafe(groupToken)] }, { consistency: "strong" })) {
    if (String(e.value?.account_hash || "") !== acct) continue;
    const ik = String(e.key[2] ?? "");
    if (await gmemberAdmitted(groupToken, ik, e.value)) return { admitted: true, seats };
    claimIks.add(ik);
  }
  if (claimIks.size) {
    for await (const e of groupMemberRows(groupToken)) { // b77n (pre-audit L3): by ["ix_gmem"]
      const m = e.value;
      if (m && String(m.group_token || "") === groupToken && claimIks.has(String(m.IK_pub || "")) && m.session_token) seats.add(String(m.session_token));
    }
  }
  return { admitted: false, seats };
}

/**
 * b77n2 (review M1): may an attester whose member list read EMPTY become the group's "creator"? Only when the
 * authoritative records agree the group has nobody yet: no recorded owner other than this account (a group
 * torn down reads "deleted"), no ["veil_gmember", group, …] entry of another identity (written with every
 * membership), and no member row for the group in the table itself (read directly, never through an index).
 * Otherwise the attester joins as an ordinary, not-admitted member (fail closed).
 */
async function groupCreatorFree(groupToken: string, ikPub: string, acct: string): Promise<boolean> {
  const owner = (await KV.get<string>(["veil_group_owner", keySafe(groupToken)])).value;
  if (owner && owner !== acct) return false;
  for await (const e of KV.list({ prefix: ["veil_gmember", groupToken] }, { consistency: "strong" })) if (String(e.key[2] ?? "") !== ikPub) return false;
  for await (const e of KV.list<Record<string, unknown>>({ prefix: ["entity", "VeilGroupMember"] }, { consistency: "strong" })) {
    if (String(e.value?.group_token ?? "") === groupToken) return false;
  }
  return true;
}

/** b74 (audit VAR-01): the group's creator account, read-only (no claim — compare
 *  claimOrCheckGroupOwner, which records an owner for an unclaimed group) */
async function groupOwnedBy(groupToken: string, acct: string): Promise<boolean> {
  const rec = (await KV.get<string>(["veil_group_owner", keySafe(groupToken)])).value;
  if (rec) return rec === acct;
  for await (const e of groupMemberRows(groupToken)) { // b77n (pre-audit L3): by ["ix_gmem"]
    const m = e.value;
    if (m && String(m.group_token || "") === groupToken && m.role === "creator" && String(m._acct || "") === acct) return true;
  }
  return false;
}

/**
 * b74 (audit VAR-01): what a client sees of envelope rows. The owner tag never leaves the
 * relay (b70 re-review R3); on a GROUP row the posting seat's session_token is shown only
 * to the group's creator, who needs it to open a seat intro (and holds every seat anyway).
 * Members used to see each row's seat token, which links posts to members across epochs.
 */
async function envelopeRowsView(rows: Record<string, unknown>[], userId: string): Promise<Record<string, unknown>[]> {
  const acct = await accountHashOf(userId);
  const owner = new Map<string, boolean>();
  const out: Record<string, unknown>[] = [];
  for (const r of rows) {
    const { _owner: _o, ...rest } = r;
    const gt = typeof rest.group_token === "string" ? rest.group_token : "";
    if (gt) {
      if (!owner.has(gt)) owner.set(gt, await groupOwnedBy(gt, acct));
      if (!owner.get(gt)) delete rest.session_token;
    }
    out.push(rest);
  }
  return out;
}
/** b73 (audit): V-01 — seat intros (the only posts of a member not admitted yet) per seat
 *  and hour, and how many of them stay on the relay at once (the newest; the creator
 *  needs one). The app re-sends its intro at most every 10 minutes. */
const SEAT_INTROS_PER_HOUR = 8;
const SEAT_INTROS_KEPT = 3;

/**
 * b70 (re-review 11): write back only the fields a request changed, onto a fresh,
 * versionstamp-checked copy of the row. Whole-row writes raced: an "end" racing a
 * heartbeat re-created the ended chat, a heartbeat racing a rotation put the old
 * epoch back. A row deleted meanwhile is never re-created (returns false).
 */
/**
 * b75r1 (audit REL-04, REL-06): the groups an account created go with the account. Account
 * delete used to drop only the creator's own rows and tombstone the owner record, and the
 * duress purge not even that (["veil_group_owner", group] kept the purged account's hash): every
 * other member's VeilGroupMember / veil_gmember rows (Vardum ID, IK, account hashes), the group
 * record, its stream, wrap requests and bans stayed for ever, reachable by nobody. Now every
 * row of such a group goes: its seats (tokens retired), its envelopes and their burn votes,
 * every member row, the group record, wrap requests/deliveries, push coalescers and bans. The
 * owner record stays as the tombstone "deleted" (no account hash), so nobody can claim the
 * token afterwards. Groups are found by the owner record, or (a group no gate call has
 * recorded yet) by a creator member row of the account. Returns the number of groups.
 */
async function teardownOwnedGroups(acct: string): Promise<number> {
  const tokens = new Set<string>();
  for await (const e of KV.list<string>({ prefix: ["veil_group_owner"] }, { consistency: "strong" })) if (e.value === acct) tokens.add(String(e.key[1]));
  for await (const e of KV.list<Record<string, unknown>>({ prefix: ["entity", "VeilGroupMember"] }, { consistency: "strong" })) {
    const m = e.value;
    if (m && m.role === "creator" && String(m._acct || "") === acct && m.group_token) {
      const rec = (await KV.get<string>(["veil_group_owner", keySafe(String(m.group_token))])).value;
      if (!rec || rec === acct) tokens.add(String(m.group_token));
    }
  }
  for (const gt of tokens) {
    for await (const e of groupSessionRows(gt)) { // b77s (audit 4 RE-02): by ["ix_gsess"]
      const s = e.value;
      if (!s || String(s.group_token || "") !== gt) continue;
      const tok = String(s.token || "");
      await deleteIndexedRow("VeilSession", String(e.key[2]));
      if (tok) {
        await KV.delete(["veil_sess_token", keySafe(tok)]);
        await retireSessionToken(tok);
        await deleteSessionEnvelopes(tok);
        for await (const c of KV.list({ prefix: ["push_coalesce", tok] }, { consistency: "strong" })) await KV.delete(c.key);
      }
    }
    for await (const e of envelopesOfGroup(gt)) { await deleteEnvelopeRow(e.key, e.value); await KV.delete(["burn_votes", keySafe(String(e.key[2]))]); }
    for await (const e of groupMemberRows(gt)) { // b77n (pre-audit L3): by ["ix_gmem"]
      if (String(e.value?.group_token || "") === gt) await KV.delete(e.key);
    }
    for await (const e of KV.list({ prefix: ["ix_gmem", keySafe(gt)] }, { consistency: "strong" })) await KV.delete(e.key); // b77n (L3)
    for await (const e of groupDenyRows(gt)) { // b77s (audit 4 RE-02): by ["ix_gdeny"]
      if (String(e.value?.group_token || "") === gt) await deleteIndexedRow("VeilGroupDenyEntry", String(e.key[2]));
    }
    for (const p of ["veil_gmember", "veil_wrapreq", "veil_wrapdel", "push_coalesce_group"]) {
      for await (const e of KV.list({ prefix: [p, keySafe(gt)] }, { consistency: "strong" })) await KV.delete(e.key);
    }
    // b75 round 1 (merge): the keyed-tag bindings go with the group too (they name posting accounts per epoch)
    for await (const e of KV.list({ prefix: ["gtag_bind", await sha256hex("gtag:" + gt)] }, { consistency: "strong" })) await KV.delete(e.key);
    await KV.delete(["veil_group", gt]);
    await KV.set(["veil_group_owner", keySafe(gt)], "deleted");
  }
  return tokens.size;
}

/** b70 (re-review 11): a group seat that ends takes its membership with it (the
 *  departed account kept reading the group, and stayed on the roster) */
/** b77u (audit 6, IH full L-6): a member that ENDED ITS OWN seat is remembered (by a group-salted hash of its IK, 30 days)
 *  so it can't attest on a spare (unlocked) seat of the group and be auto re-admitted by the creator's app, taking the
 *  seat meant for someone else; only a seat locked to its own Vardum ID takes it back */
const GROUP_LEFT_TTL_MS = 30 * 86400_000;
const groupLeftKey = async (groupToken: string, ikPub: string): Promise<Deno.KvKey> => ["veil_gleft", await denyHash(groupToken, ikPub)];
async function dropSeatMembership(seatToken: string, selfLeave = false): Promise<number> {
  if (!seatToken) return 0;
  let n = 0;
  for await (const e of KV.list<Record<string, unknown>>({ prefix: ["entity", "VeilGroupMember"] }, { consistency: "strong" })) {
    const m = e.value;
    if (!m || String(m.session_token || "") !== seatToken) continue;
    if (selfLeave && m.group_token && m.IK_pub) await KV.set(await groupLeftKey(String(m.group_token), String(m.IK_pub)), 1, { expireIn: GROUP_LEFT_TTL_MS });
    // b77u (audit 6, IH relay F-09): a seat that ends takes its member's pending wrap request and undelivered wrap with it
    if (m.group_token && m.IK_pub) { await KV.delete(["veil_wrapreq", keySafe(String(m.group_token)), String(m.IK_pub)]); await KV.delete(["veil_wrapdel", keySafe(String(m.group_token)), String(m.IK_pub)]); }
    await KV.delete(e.key);
    if (m.group_token && m.IK_pub) await KV.delete(["veil_gmember", String(m.group_token), String(m.IK_pub)]);
    // b76r2 (audit GB-1 / R2-B1): a member that leaves takes its burn votes and its place in every burn quorum with it
    if (m.group_token && m._acct) await dropBurnEligibility(String(m.group_token), String(m._acct));
    n++;
  }
  return n;
}

const PATCH_FREE_FIELDS = new Set(["last_activity", "initiator_seen_at", "responder_seen_at", "updated_date", "expires_at"]);
async function patchSessionRow(before: Record<string, unknown>, after: Record<string, unknown>): Promise<boolean> {
  const key = ["entity", "VeilSession", String(after.id ?? before.id)];
  const patch: Record<string, unknown> = {};
  for (const k of new Set([...Object.keys(before), ...Object.keys(after)])) {
    if (JSON.stringify(before[k]) !== JSON.stringify(after[k])) patch[k] = after[k];
  }
  for (let attempt = 0; attempt < 10; attempt++) {
    const cur = await KV.get<Record<string, unknown>>(key);
    if (!cur.value) return false;
    // a field this request changes that someone else changed meanwhile (two joins at
    // once): refused, never silently overwritten (timestamps are just refreshed)
    for (const k of Object.keys(patch)) {
      if (PATCH_FREE_FIELDS.has(k)) continue;
      if (JSON.stringify(cur.value[k]) !== JSON.stringify(before[k])) return false;
    }
    if ((await KV.atomic().check(cur).set(key, { ...cur.value, ...patch }).commit()).ok) return true;
  }
  return false;
}

async function touchSession(token: string, side?: "initiator" | "responder") {
  const eid = (await KV.get<string>(["veil_sess_token", keySafe(token)])).value;
  if (!eid) return;
  const row = (await KV.get(["entity", "VeilSession", eid])).value as Record<string, unknown> | null;
  if (!row) return;
  const before = structuredClone(row);
  row.last_activity = nowIso();
  // b162 presence parity: the client reads initiator_seen_at / responder_seen_at
  if (side === "initiator") row.initiator_seen_at = nowIso();
  if (side === "responder") row.responder_seen_at = nowIso();
  await patchSessionRow(before, row); // b70 (re-review 11): never re-creates an ended chat
}

// (veilSessionGate moved to the PHASE 2 section below — full action set)

// ---------- functions: purgeExpiredEnvelopes ----------
/** b77p (audit VAR-24): ONE full sweep at a time, relay-wide. A caller arriving while a sweep runs does not
 *  start a second one beside it: it waits for the single follow-up sweep queued behind the running one (shared
 *  by every caller that arrives meanwhile), so it still sees rows that expired before it asked, and the sweeper
 *  interval and the route can never stack scans. The client route is also capped relay-wide (see the route). */
const PURGE_ROUTE_RELAY_PER_10MIN = Number(Deno.env.get("VEIL_PURGE_ROUTE_RELAY_PER_10MIN")) || 30;
type SweepResult = Record<string, unknown>;
let sweepRunning: Promise<SweepResult> | null = null;
let sweepQueued: Promise<SweepResult> | null = null;
let lastSweepResult: { at: number; value: SweepResult } | null = null;
/** b77p (audit VAR-24): sweeps started since boot; each result carries its number (sweep_seq), so callers that
 *  shared one sweep see the same number */
let sweepsStarted = 0;
function startSweep(): Promise<SweepResult> {
  const seq = ++sweepsStarted;
  const p = (async () => ({ ...((await (await fnPurgeExpired()).json()) as SweepResult), sweep_seq: seq }))();
  sweepRunning = p;
  p.then((v) => { lastSweepResult = { at: Date.now(), value: v }; }, () => undefined).finally(() => { if (sweepRunning === p) sweepRunning = null; });
  return p;
}
function coalescedPurge(): Promise<SweepResult> {
  if (sweepQueued) return sweepQueued;
  if (sweepRunning) {
    const q: Promise<SweepResult> = sweepRunning.catch(() => undefined).then(() => { if (sweepQueued === q) sweepQueued = null; return startSweep(); });
    sweepQueued = q;
    return q;
  }
  return startSweep();
}
async function fnPurgeExpired() {
  let deleted = 0;
  const now = Date.now();
  for await (const e of KV.list({ prefix: ["entity", "VeilEnvelope"] }, { consistency: "strong" })) {
    const row = e.value as Record<string, unknown>;
    const exp = new Date(String(row.expires_at || "")).getTime();
    if (Number.isFinite(exp) && exp < now) { await deleteEnvelopeRow(e.key, row); deleted++; } // b71 (audit F-09): with its index rows
  }
  // Batch C (B4; reviews P2 V-19, P3 R9): sessions now age out as the spec says.
  // 1:1 only — a quiet GROUP must never vanish (its rows are the members'
  // credentials). Pending invites die at expires_at; active chats die after
  // key_retention_hours without activity. Envelopes go with them.
  let sessions = 0;
  for await (const e of KV.list<Record<string, unknown>>({ prefix: ["entity", "VeilSession"] }, { consistency: "strong" })) {
    const s = e.value;
    if (!s) continue;
    const state = String(s.state || "");
    const pendingDead = state === "pending" && Number.isFinite(Date.parse(String(s.expires_at || ""))) && Date.parse(String(s.expires_at)) < now;
    // b70 (re-review 7): a group seat nobody joined before it expired can't be joined
    // any more; it goes (its token retired). Active group rows live with the group.
    if (s.group_token) {
      if (!pendingDead) continue;
      const gt = String(s.token || "");
      await KV.delete(e.key);
      if (gt) { await KV.delete(["veil_sess_token", keySafe(gt)]); await KV.set(await retiredTokenKey(gt), 1, { expireIn: 400 * 86400_000 }); }
      sessions++;
      continue;
    }
    const lastSeen = Date.parse(String(s.last_activity || s.updated_date || s.created_date || ""));
    const quietDead = state === "active" && !!(s.initiator_client_id || s.responder_client_id) && Number.isFinite(lastSeen) && now - lastSeen > retentionMs(s);
    // b77 (sealed sender): a joined 1:1 rendezvous row (no account ids) dies at its expires_at
    // (the join sets it 7 days ahead) — the initiator reads it with "status" and ends it
    const rendezvousDead = state === "active" && !s.initiator_client_id && !s.responder_client_id
      && Number.isFinite(Date.parse(String(s.expires_at || ""))) && Date.parse(String(s.expires_at)) < now;
    if (!pendingDead && !quietDead && !rendezvousDead) continue;
    const tok = String(s.token || "");
    await KV.delete(e.key); // b70 (re-review 14): the session first, then its envelopes
    if (tok) { await KV.delete(["veil_sess_token", keySafe(tok)]); await retireSessionToken(tok) /* b75 (audit RL-05) */; deleted += await deleteSessionEnvelopes(tok); }
    sessions++;
  }
  // b77 (sealed sender): mailboxes whose OWNER has not used them for MBOX_IDLE_MS go (with their
  // envelopes and files) and their ids are retired; expired open tickets go. b77g: a peer's
  // submit is not owner use (see touchMbox)
  let mailboxes = 0;
  try { mailboxes = await sweepIdleMailboxes(now); } catch (e) { console.error("[sweeper] mailbox sweep error", e); }
  // b77j (L-1): what an account delete stopped after its user row left behind — its work rows, and
  // sign-in tokens with no account (each leaves its tombstone, so a retry still gets 410). A token
  // under 10 min old is skipped (a sign-in overlapping the sweep). A full scan of the tokens, so
  // hourly, not every sweep (re-review L2)
  let orphans = 0;
  if (now - lastOrphanSweep >= ORPHAN_SWEEP_MS) try {
    lastOrphanSweep = now;
    const userKnown = new Map<string, boolean>();
    const hasUser = async (uid: string) => {
      if (!userKnown.has(uid)) userKnown.set(uid, !!(await KV.get(["user", uid])).value);
      return userKnown.get(uid)!;
    };
    // b77s (audit 4 F-01): any raw (pre-b199) token row still in the table moves to its hashed key (or goes, if expired)
    { const m = await migrateAuthRows(false); if (m.moved || m.expired) console.log(`[sweeper] b77s: ${m.moved} raw sign-in token row(s) moved to their hashed key, ${m.expired} expired one(s) deleted`); }
    for await (const e of KV.list({ prefix: ["acct_del"] }, { consistency: "strong" })) {
      if (!(await hasUser(String(e.key[1] ?? "")))) { await KV.delete(e.key); orphans++; }
    }
    for await (const e of KV.list<Record<string, unknown>>({ prefix: ["auth"] }, { consistency: "strong" })) {
      const uid = String(e.value?.userId || "");
      if (!uid || (await hasUser(uid))) continue;
      if (now - (Date.parse(String(e.value?.created || "")) || 0) < 10 * 60_000) continue;
      const k1 = String(e.key[1] ?? "");
      await KV.set(acctGoneKey(k1.startsWith("h:") ? k1 : String((await authKey(k1))[1])), 1, { expireIn: ACCT_GONE_TTL_MS });
      await dropAuthRow(e.key, uid); // b77s: with its index entry
      orphans++;
    }
    // b77s: token index entries whose token row is gone (a token that expired on its own)
    for await (const e of KV.list({ prefix: ["auth_acct"] }, { consistency: "strong" })) {
      const row = await KV.get<Record<string, unknown>>(["auth", String(e.key[2] ?? "")], { consistency: "strong" });
      if (!row.value || String(row.value.userId || "") !== String(e.key[1])) { if ((await KV.atomic().check(row).delete(e.key).commit()).ok) orphans++; }
    }
    // b77s (audit 4 RA-02): rows naming a deleted account that an in-flight request wrote
    orphans += await sweepDeletedAccountRows();
  } catch (e) { console.error("[sweeper] orphan account rows error", e); }
  // Batch C (B5): expired device-transfer links and their bundles
  let links = 0;
  for await (const e of KV.list<Record<string, unknown>>({ prefix: ["devlink"] }, { consistency: "strong" })) {
    if (Number(e.value?.exp || 0) >= now) continue;
    // b75r1 (lead, b75-xfer M5a flake): the file and its owner record first, the row after —
    // a fetch arriving in between used to find no row and answer before the file was gone
    await dropDevlinkBlob(e.value); // b75 (audit RL-04): the file's owner record goes too
    await KV.atomic().check(e).delete(e.key).commit();
    links++;
  }
  // b71 (audit F-05): analytics rows (OnboardingStep / AttributionSource) are kept
  // ANALYTICS_KEEP_DAYS, then deleted (they used to live until the account was); and
  // the Vardum ID older apps put on attribution rows is removed from rows already stored
  let analytics = 0;
  const analyticsCut = now - ANALYTICS_KEEP_DAYS * 86400_000;
  for (const name of ANALYTICS_ENTITIES) {
    for await (const e of KV.list<Record<string, unknown>>({ prefix: ["entity", name] }, { consistency: "strong" })) {
      const at = Date.parse(String(e.value?.created_date || ""));
      if (!e.value || !Number.isFinite(at) || at < analyticsCut) { await KV.delete(e.key); analytics++; continue; }
      // b77t (audit 5 C-10): and the _owner tag (an account link) older rows carry
      if ("veil_id" in e.value || "_owner" in e.value) { const { veil_id: _v, _owner: _o, ...rest } = e.value; await KV.atomic().check(e).set(e.key, rest).commit(); }
    }
  }
  return json({ mailboxes: { success: true, deleted: mailboxes }, analytics: { success: true, deleted: analytics }, purged: { success: true, deleted }, sessions: { success: true, deleted: sessions }, links: { success: true, deleted: links }, orphans: { success: true, deleted: orphans }, loginGuards: { success: true, deleted: 0 }, nonces: { success: true, deleted: 0 } });
}

// ==================== PHASE 2 — full client contract (b198 port) ====================
// Contract extracted from vendor/device/src/{relay,contact,group-session,groups,transfer,
// silent-auth,restore,auth}.ts + docs/audit/RELAY-PORT-SPEC.md. Every response shape
// below matches what the client actually parses (data-wrapped and/or bare).

const enc = new TextEncoder();
const b64e = (b: Uint8Array) => btoa(String.fromCharCode(...b));
const b64d = (s: string) => new Uint8Array([...atob(s)].map((c) => c.charCodeAt(0)));
/** b199: storage key for a login token — a one-way hash, never the token */
const authKey = async (token: string) => ["auth", "h:" + await sha256hex("veil-auth-token:" + token)];
const sha256hex = async (v: string) =>
  [...new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(v)))].map((b) => b.toString(16).padStart(2, "0")).join("");

// ---------- b77s: the per-account sign-in token index ----------
// ["auth_acct", userId, "h:<token hash>"] -> 1, one per token row, written in the same atomic step as the token
// (storeAuthToken), removed with it (dropAuthRow), expiring with it (TOKEN_MAX_AGE_MS, which no token outlives), and
// rebuilt at boot from the token rows (migrateAuthRows). It lets "sign out other devices" and "change password"
// find one account's tokens without reading every token row. It holds nothing new: each token row already names its
// account. An entry whose token row is gone is dropped when read and by the sweeper's orphan pass.
const authIxKey = (userId: string, hashPart: string): Deno.KvKey => ["auth_acct", userId, hashPart];
/** true once this process's boot pass has indexed every token row (until then readers scan the token table) */
let authIxReady = false;
/** b77u (audit 6 W2 / R4 #3): `rl` — the registration lock's owning-phone device tag this token was issued against (a
 *  sign-in that showed the device key or proved the PIN, or the phone that set the PIN). Only such a token renews the
 *  lock (regLockRenew). */
type AuthRow = { userId: string; email: string; created: string; exp: number; rl?: string };
/** a new sign-in token: the hashed row and its index entry, in one step */
async function storeAuthToken(token: string, row: AuthRow): Promise<void> {
  const hk = await authKey(token);
  await KV.atomic().set(hk, row, { expireIn: TOKEN_MAX_AGE_MS }).set(authIxKey(row.userId, String(hk[1])), 1, { expireIn: TOKEN_MAX_AGE_MS }).commit();
}
/** removes a token row and (for a hashed row) its index entry */
async function dropAuthRow(key: Deno.KvKey, userId?: string): Promise<void> {
  await KV.delete(key);
  const k1 = String(key[1] ?? "");
  if (userId && k1.startsWith("h:")) await KV.delete(authIxKey(userId, k1));
}
/** the token-row keys of one account (index entries whose row is gone are dropped) */
async function accountTokenKeys(userId: string): Promise<Deno.KvKey[]> {
  const out: Deno.KvKey[] = [];
  if (!authIxReady) {
    for await (const e of KV.list<Record<string, unknown>>({ prefix: ["auth"] }, { consistency: "strong" })) if (String(e.value?.userId || "") === userId) out.push(e.key);
    return out;
  }
  for await (const e of KV.list({ prefix: ["auth_acct", userId] }, { consistency: "strong" })) {
    const hp = String(e.key[2] ?? "");
    const row = await KV.get<Record<string, unknown>>(["auth", hp], { consistency: "strong" });
    if (row.value && String(row.value.userId || "") === userId) out.push(row.key);
    else await KV.atomic().check(row).delete(e.key).commit();
  }
  return out;
}
/** b77s (owner decision, Accounts): revokes every sign-in token of the account except `keepHashPart` (the caller's);
 *  returns how many went */
/** b77s (confirmation review N-3): the account-wide cutoff — every token created before now is dead (authCheck),
 *  except the one named (the caller's). Checked against the user row as read; retried on a conflict. */
async function setTokenCutoff(userId: string, keepHashPart: string): Promise<boolean> {
  for (let attempt = 0; attempt < 20; attempt++) {
    const ue = await KV.get<Record<string, unknown>>(["user", userId], { consistency: "strong" });
    if (!ue.value) return false;
    if ((await KV.atomic().check(ue).set(["user", userId], { ...ue.value, tokens_after: Date.now(), tokens_after_keep: keepHashPart }).commit()).ok) return true;
    await new Promise((r) => setTimeout(r, Math.random() * 5));
  }
  return false;
}
async function revokeOtherTokens(userId: string, keepHashPart: string): Promise<number> {
  let n = 0;
  for (const k of await accountTokenKeys(userId)) {
    if (String(k[1]) === keepHashPart) continue;
    await dropAuthRow(k, userId);
    n++;
  }
  return n;
}
/**
 * b77s (audit 4 F-01): pre-b199 RAW token rows (["auth", <the bearer token itself>]) were moved to their hashed key
 * only when the token was next presented, so a dormant account's raw token sat in KV (and in every backup) as a
 * working credential until the row expired. This pass moves EVERY raw row to its hashed key (authKey) in one atomic
 * step each (only if the raw row is unchanged and no hashed row exists; an existing hashed row wins and the raw copy
 * goes), and deletes raw rows that are already expired or past the maximum age. It runs at boot before the relay
 * serves, and in the sweeper's hourly orphan pass. `index` (boot only): also writes the per-account index entry of
 * every hashed row (authIxKey). authCheck's lazy migration stays as a fallback.
 */
async function migrateAuthRows(index: boolean): Promise<{ moved: number; expired: number; indexed: number }> {
  let moved = 0, expired = 0, indexed = 0;
  const now = Date.now();
  for await (const e of KV.list<Record<string, unknown>>({ prefix: ["auth"] }, { consistency: "strong" })) {
    const k1 = String(e.key[1] ?? "");
    const v = e.value ?? {};
    const uid = String(v.userId || "");
    if (k1.startsWith("h:")) {
      if (index && uid) {
        const ik = authIxKey(uid, k1);
        if ((await KV.atomic().check({ key: ik, versionstamp: null }).set(ik, 1, { expireIn: TOKEN_MAX_AGE_MS }).commit()).ok) indexed++;
      }
      continue;
    }
    const created = Date.parse(String(v.created || "")) || 0;
    const dead = !uid || !k1 || k1 === "\u0000oversized" || k1.length > MAX_KEY_PART || (Number(v.exp) > 0 && Number(v.exp) < now) || (created > 0 && now - created > TOKEN_MAX_AGE_MS);
    if (dead) {
      if ((await KV.atomic().check(e).delete(e.key).commit()).ok) expired++;
      continue;
    }
    const hk = await authKey(k1);
    const life = created > 0 ? Math.max(60_000, TOKEN_MAX_AGE_MS - (now - created)) : TOKEN_MAX_AGE_MS;
    const ok = (await KV.atomic().check(e).check({ key: hk, versionstamp: null }).set(hk, v, { expireIn: life }).set(authIxKey(uid, String(hk[1])), 1, { expireIn: life }).delete(e.key).commit()).ok;
    if (ok) moved++;
    else if ((await KV.get(hk)).value && (await KV.atomic().check(e).delete(e.key).commit()).ok) moved++; // the hashed row already exists: the raw copy goes
  }
  return { moved, expired, indexed };
}

// ---------- b77m (audit VAR-35): strict Ed25519 ----------
// Deno's WebCrypto Ed25519 imports ANY 32-byte point, including small-order ones: with the identity
// point as the key (01 00…00) the trivial signature R = identity, S = 0 verifies for EVERY message,
// so anyone could register such a Vardum ID and pass every relay-side proof for it (bind, OPK upload,
// attest, wrap request, handover, reglock, move offer) without a private key. The relay now accepts
// only keys that are canonical encodings of points in the prime-order subgroup, and signatures whose
// R is a canonical point of more than small order and whose S is below the group order L (as
// libsodium's crypto_sign_verify_detached). Plain BigInt arithmetic on edwards25519 (a = -1):
// public data only, so constant time does not matter here.
const ED_P = 2n ** 255n - 19n;
const ED_L = 2n ** 252n + 27742317777372353535851937790883648493n;
const edMod = (a: bigint): bigint => { const r = a % ED_P; return r < 0n ? r + ED_P : r; };
function edPow(b: bigint, e: bigint): bigint {
  let r = 1n;
  b = edMod(b);
  while (e > 0n) { if (e & 1n) r = (r * b) % ED_P; b = (b * b) % ED_P; e >>= 1n; }
  return r;
}
const ED_D = edMod(-121665n * edPow(121666n, ED_P - 2n));
const ED_D2 = edMod(2n * ED_D);
const ED_SQRT_M1 = edPow(2n, (ED_P - 1n) / 4n);
/** extended coordinates (X, Y, Z, T), x = X/Z, y = Y/Z, xy = T/Z */
type EdPoint = [bigint, bigint, bigint, bigint];
const ED_ZERO: EdPoint = [0n, 1n, 1n, 0n];
/** RFC 8032 §5.1.3 decoding; null for a non-canonical or off-curve encoding */
function edDecode(b: Uint8Array): EdPoint | null {
  if (b.length !== 32) return null;
  let y = 0n;
  for (let i = 31; i >= 0; i--) y = (y << 8n) | BigInt(i === 31 ? b[i] & 0x7f : b[i]);
  const sign = (b[31] >> 7) & 1;
  if (y >= ED_P) return null;
  const y2 = (y * y) % ED_P;
  const u = edMod(y2 - 1n), v = edMod(ED_D * y2 + 1n);
  const v3 = (v * v % ED_P) * v % ED_P;
  let x = edMod((u * v3 % ED_P) * edPow((u * v3 % ED_P) * v3 % ED_P * v % ED_P, (ED_P - 5n) / 8n));
  const vx2 = edMod(v * x % ED_P * x);
  if (vx2 !== u) {
    if (vx2 === edMod(-u)) x = (x * ED_SQRT_M1) % ED_P;
    else return null;
  }
  if (x === 0n && sign === 1) return null;
  if (Number(x & 1n) !== sign) x = ED_P - x;
  return [x, y, 1n, (x * y) % ED_P];
}
/** unified addition (add-2008-hwcd-3, complete on edwards25519; also doubles) */
function edAdd(p: EdPoint, q: EdPoint): EdPoint {
  const [x1, y1, z1, t1] = p, [x2, y2, z2, t2] = q;
  const a = edMod((y1 - x1) * (y2 - x2)), b = edMod((y1 + x1) * (y2 + x2));
  const c = edMod(t1 * ED_D2 % ED_P * t2), d = edMod(2n * z1 * z2);
  const e = edMod(b - a), f = edMod(d - c), g = edMod(d + c), h = edMod(b + a);
  return [(e * f) % ED_P, (g * h) % ED_P, (f * g) % ED_P, (e * h) % ED_P];
}
function edMul(p: EdPoint, n: bigint): EdPoint {
  let r = ED_ZERO;
  for (let i = BigInt(n.toString(2).length - 1); i >= 0n; i--) {
    r = edAdd(r, r);
    if ((n >> i) & 1n) r = edAdd(r, p);
  }
  return r;
}
const edIsZero = (p: EdPoint): boolean => edMod(p[0]) === 0n && edMod(p[1] - p[2]) === 0n;
/** a point of order 1, 2, 4 or 8 */
const edSmallOrder = (p: EdPoint): boolean => edIsZero(edMul(p, 8n));
const edKeyOkCache = new Map<string, boolean>();
/** b77m (audit VAR-35): a public key the relay accepts — canonical, on the curve, in the prime-order
 *  subgroup (so not small-order and not mixed with a small-order component) */
function ed25519KeyStrictOk(raw: Uint8Array): boolean {
  // b77m review (INFO): the length first — the cache key used to be built from whatever was sent (a spread of
  // an arbitrarily long array: a large string per call, and a stack overflow past ~100k bytes)
  if (raw.length !== 32) return false;
  const k = String.fromCharCode(...raw);
  const hit = edKeyOkCache.get(k);
  if (hit !== undefined) return hit;
  const p = edDecode(raw);
  const ok = !!p && !edSmallOrder(p) && edIsZero(edMul(p, ED_L));
  if (edKeyOkCache.size >= 4096) edKeyOkCache.clear();
  edKeyOkCache.set(k, ok);
  return ok;
}
/** b77m (audit VAR-35): the signature checks WebCrypto leaves out — S < L, R canonical and not of small order */
function ed25519SigStrictOk(sig: Uint8Array): boolean {
  if (sig.length !== 64) return false;
  let s = 0n;
  for (let i = 63; i >= 32; i--) s = (s << 8n) | BigInt(sig[i]);
  if (s >= ED_L) return false;
  const r = edDecode(sig.subarray(0, 32));
  return !!r && !edSmallOrder(r);
}

async function ed25519Verify(pubB64: string, msgBytes: Uint8Array, sigB64: string): Promise<boolean> {
  try {
    const pubRaw = b64d(pubB64), sigRaw = b64d(sigB64);
    if (!ed25519KeyStrictOk(pubRaw) || !ed25519SigStrictOk(sigRaw)) return false; // b77m (audit VAR-35)
    const key = await crypto.subtle.importKey("raw", pubRaw as BufferSource, { name: "Ed25519" }, false, ["verify"]);
    return await crypto.subtle.verify("Ed25519", key, b64d(sigB64) as BufferSource, msgBytes as BufferSource);
  } catch (e) {
    console.log("[verify] ed25519 verify error:", String((e as Error).message).slice(0, 120));
    return false;
  }
}

// ---------- per-account rate limiter (SPEC §3: 150 env/min; identity gate 429 shape) ----------
/**
 * b71 (audit F-17): a SLIDING window (two-bucket estimate) plus a real lock.
 *  - The count is this window's bucket plus the previous bucket weighted by how much
 *    of it still overlaps the last `windowMs`. Fixed windows used to accept about 2×
 *    the cap across a boundary (cap at :59, cap again at :00).
 *  - `lockMinutes` > 0: going over the cap writes a lock row; every call is refused
 *    until it expires (it used to only lengthen the bucket's expiry, so nothing locked).
 *    The lock is written once and never extended by the refused calls, so it always ends.
 *  - `retry_minutes` is the real wait: the lock's remaining time, or (no lock) when the
 *    window will have room again, at least 1.
 */
/** b77t (audit 5 L-10): whether `key`'s window (as rateLimit counts it) is already full — read only, nothing counted */
async function rateFull(key: string, cap: number, windowMs: number): Promise<boolean> {
  const now = Date.now();
  const bucket = Math.floor(now / windowMs);
  const frac = (now - bucket * windowMs) / windowMs;
  const [cur, prev] = await Promise.all([KV.get<number>(["rl", key, String(bucket), String(windowMs)]), KV.get<number>(["rl", key, String(bucket - 1), String(windowMs)])]);
  return (cur.value ?? 0) + 1 + (prev.value ?? 0) * (1 - frac) > cap;
}
async function rateLimit(key: string, cap: number, windowMs: number, lockMinutes: number): Promise<{ locked: boolean; retry_minutes: number } | null> {
  const lockKey: Deno.KvKey = ["rl", key, "lock", String(windowMs)];
  const lock = await KV.get<number>(lockKey);
  if (lock.value && lock.value > Date.now()) return { locked: true, retry_minutes: Math.max(1, Math.ceil((lock.value - Date.now()) / 60_000)) };
  // b77p (audit VAR-16): a network-tag key also counts the same network's rows under yesterday's tag
  // (a lock made before 00:00 UTC still holds, and the window keeps its count); read only, never written
  const alt = altThrottleKey(key);
  if (alt) {
    const altLock = (await KV.get<number>(["rl", alt, "lock", String(windowMs)])).value;
    if (altLock && altLock > Date.now()) return { locked: true, retry_minutes: Math.max(1, Math.ceil((altLock - Date.now()) / 60_000)) };
  }
  // Batch D (D-15, RV-13): read and write the count in ONE versionstamp-checked
  // step, retrying if another request got in between. The old read-then-write
  // let parallel requests all read the same count and all pass. (Not a `sum`
  // mutation: Deno KV can't put an expiry on one, and these rows must expire.)
  // Once the window is full nothing is written, so contention ends at `cap`.
  for (let attempt = 0; attempt < 100; attempt++) {
    const now = Date.now();
    const bucket = Math.floor(now / windowMs);
    const frac = (now - bucket * windowMs) / windowMs;
    const k = ["rl", key, String(bucket), String(windowMs)]; // b70 (re-review 2): the window rides in the key (see the sweeper)
    const [cur, prev, altCur, altPrev] = await Promise.all([KV.get<number>(k), KV.get<number>(["rl", key, String(bucket - 1), String(windowMs)]),
      alt ? KV.get<number>(["rl", alt, String(bucket), String(windowMs)]) : null, alt ? KV.get<number>(["rl", alt, String(bucket - 1), String(windowMs)]) : null]);
    const c = (cur.value ?? 0) + (altCur?.value ?? 0), p = (prev.value ?? 0) + (altPrev?.value ?? 0);
    if (c + 1 + p * (1 - frac) > cap) {
      if (lockMinutes > 0) {
        const until = now + lockMinutes * 60_000;
        // only the first refusal writes the lock (refusals during it never extend it)
        await KV.atomic().check(lock).set(lockKey, until, { expireIn: lockMinutes * 60_000 + 60_000 }).commit();
        return { locked: true, retry_minutes: lockMinutes };
      }
      return { locked: true, retry_minutes: Math.max(1, Math.ceil(rateRoomInMs(c, p, frac, cap, windowMs) / 60_000)) };
    }
    // b199: buckets expire once they can no longer count (this window + the next,
    // which reads this one as its previous) — they used to be kept forever
    if ((await KV.atomic().check(cur).set(k, (cur.value ?? 0) + 1, { expireIn: 2 * windowMs + 60_000 }).commit()).ok) return null; // (its own count: the alt rows are only read)
    await new Promise((r) => setTimeout(r, Math.random() * 5));
  }
  return { locked: true, retry_minutes: 1 }; // still contended: fail closed
}

/** b71 (audit F-17): how long until one more call fits under the sliding estimate */
function rateRoomInMs(c: number, p: number, frac: number, cap: number, windowMs: number): number {
  // still in this window: the previous bucket's weight shrinks as time passes
  if (c + 1 <= cap && p > 0) {
    const need = 1 - (cap - c - 1) / p; // fraction of this window at which it fits
    if (need < 1) return Math.max(0, (need - frac) * windowMs);
  }
  // next window: this bucket becomes the weighted previous one
  const needNext = c > 0 ? Math.max(0, 1 - (cap - 1) / c) : 0;
  return (1 - frac) * windowMs + needNext * windowMs;
}

/** Batch D (D-15, RV-13): login lockout counter — reads the guard and writes
 *  fails+1 (or the lock) in ONE versionstamp-checked step, retrying if another
 *  attempt got in between. ok=false: locked (or still contended after the
 *  retries — fail closed). The guard row keeps its { fails, lockedUntil } shape. */
async function reserveLoginAttempt(k: Deno.KvKey, max: number, lockMs: number): Promise<{ ok: boolean; lockedUntil: number }> {
  // b77p (audit VAR-16): a guard keyed by a network tag also reads the same network's guard under
  // yesterday's tag: its lock still holds after 00:00 UTC, and a fresh guard starts from its count
  const altK = altThrottleKey(k);
  const altV = altK ? (await KV.get<{ fails: number; lockedUntil: number; since?: number }>(altK)).value : null;
  if (altV && altV.lockedUntil > Date.now()) return { ok: false, lockedUntil: altV.lockedUntil };
  for (let attempt = 0; attempt < 50; attempt++) {
    const got = await KV.get<{ fails: number; lockedUntil: number; since?: number }>(k);
    const now = Date.now();
    // (the alt guard's count only seeds a guard that does not exist yet; the write goes to k alone)
    const cur = !got.value && altV && altV.since && now - altV.since <= lockMs ? { ...got, value: altV } : got;
    if (cur.value && cur.value.lockedUntil > now) return { ok: false, lockedUntil: cur.value.lockedUntil };
    // b70 (re-review 2): attempts count within one window (the lock length);
    // they used to pile up for a whole day, so a busy shared network locked out
    const fresh = !cur.value || !cur.value.since || now - cur.value.since > lockMs;
    const fails = (fresh ? 0 : cur.value!.fails ?? 0) + 1;
    const since = fresh ? now : cur.value!.since!;
    const next = fails >= max ? { fails: 0, lockedUntil: now + lockMs, since: 0 } : { fails, lockedUntil: 0, since };
    if ((await KV.atomic().check(cur).set(k, next, { expireIn: THROTTLE_TTL_MS }).commit()).ok) return { ok: true, lockedUntil: 0 };
    await new Promise((r) => setTimeout(r, Math.random() * 5));
  }
  return { ok: false, lockedUntil: Date.now() + 60_000 };
}

/** b71 (audit F-03): the account-wide (every network) login guard.
 *  b73 (audit): V-11 — it no longer LOCKS a label. A hard lock let anyone who knew a
 *  sign-in label (a typed email) keep its owner from signing in, even with the right
 *  password. Now, past LOGIN_ACCT_FREE_PER_HOUR checked passwords in an hour (or
 *  LOGIN_ACCT_FREE_PER_DAY in a day, from every network together), every further
 *  attempt on that label must carry a solved proof-of-work puzzle the relay handed out
 *  (issueLoginPow): an attempt without one is refused BEFORE the password is checked
 *  (and is not counted), one with one is checked normally — so the right password always
 *  works, at the price of a puzzle. The puzzle gets harder as the day's attempts grow
 *  (LOGIN_POW_BASE_BITS + 1 bit per doubling, up to LOGIN_POW_MAX_BITS), so distributed
 *  guessing past the free allowance costs real work per guess, on top of the
 *  per-network limits (which still refuse outright). A correct password clears the
 *  guard. Apps that can't solve puzzles (b72 and older) see "too many attempts" until the
 *  hour (or day) of quiet passes — no worse than the lock they saw before. */
const LOGIN_ACCT_FREE_PER_HOUR = 10;
const LOGIN_ACCT_WINDOW_MS = 3600_000;
const LOGIN_ACCT_FREE_PER_DAY = 30;
/** quiet time after which the day's count (and the puzzle size) starts again */
const LOGIN_ACCT_LEVEL_RESET_MS = 24 * 3600_000;
const LOGIN_POW_BASE_BITS = 16;
const LOGIN_POW_MAX_BITS = 22;
const LOGIN_POW_TTL_MS = 10 * 60_000;
const LOGIN_POW_LABEL = "vardum-login-pow-v1:";
/** b74 (audit V-11): the puzzle while one network's guard on a label is tripped */
const LOGIN_POW_NET_BITS = LOGIN_POW_BASE_BITS + 2;
/** b77s (audit 4 RA-05): the hard ceiling of sign-in attempts from one /64 or IPv4 address in 15 minutes (past 15 the
 *  label puzzle is asked for instead; see the login route). VEIL_LOGIN_IP_HARD_PER_15MIN is for TEST relays. */
const LOGIN_IP_HARD_PER_15MIN = Number(Deno.env.get("VEIL_LOGIN_IP_HARD_PER_15MIN")) || 150;
/**
 * b77s (audit 4 RA-03): past LOGIN_POW_MAX_BITS the puzzle keeps growing while failures keep coming. Capped at 22
 * bits, an attacker rotating addresses was held back only by the relay's hashing throughput (~4 checks a second,
 * ~345k guesses a day against one label) — a 22-bit puzzle is ~4M SHA-256, a few milliseconds of a GPU.
 * Now, once the label's decayed failure count reaches LOGIN_POW_GROWTH_FROM (640: where the old curve reached 22
 * bits), every LOGIN_POW_GROWTH_STEP (16) more failures add one bit. The work to make n guesses past that point is
 * about the last puzzle's cost x 2 x 16, so for n failures in a day:
 *   n = 800  -> 32-bit puzzles (~4e9 hashes each)
 *   n = 1000 -> 44-bit puzzles (~1.8e13 hashes each, ~30 min per guess for a 1e10-hash/s GPU)
 * A GPU doing 1e10 SHA-256/s all day (8.6e14 hashes) gets to about n = 1000 and no further; a CPU core (~1e7/s)
 * stops near n = 800. So any attacker gets roughly <= 1000 guesses a day at one email account, however many
 * addresses they use. (Before 640 the curve is unchanged: 16 bits past the free allowance, +1 per doubling.)
 * The owner is never locked out for good: the count DECAYS (LOGIN_POW_DECAY_HALF_LIFE_MS, 6 h half-life, plus the
 * old reset after 24 h of quiet), and a failure is counted only once its puzzle is solved, so the size falls back as
 * soon as the guessing stops. While an attack keeps it above what the app solves (24 bits), a NEW sign-in to that
 * account waits for the decay; phones already signed in are never affected, and 24-word accounts never use this.
 * b77t (audit 5 L-2): SUPERSEDED in part — the growth now stops at the app's ceiling (APP_POW_MAX_BITS, 24 bits, at
 * 672 failures), because the lockout above hit the owner as hard as the guesser. The 32/44-bit figures and the
 * ~1000-a-day bound no longer hold; past 24 bits the per-network limits and the relay's hashing budget bound guessing.
 */
const LOGIN_POW_GROWTH_FROM = 640;
const LOGIN_POW_GROWTH_STEP = 16;
/** b77t (audit 5 L-2, IH R-01): the demanded puzzle never passes what the app solves (vendor/device/src/auth.ts
 *  LOGIN_POW_MAX_BITS, 24). RA-03's growth to 60 bits locked the OWNER out too (the app refuses a puzzle past 24 bits,
 *  so ~700 solved wrong guesses a day blocked every new sign-in and the password change). Past 24 bits the relay relies
 *  on its other limits: the per-address hard ceiling (LOGIN_IP_HARD_PER_15MIN), the per-(label, network) hourly cap,
 *  the /56 and /48 guards and the relay-wide hashing budget (one 600k-round PBKDF2 per guess). */
const APP_POW_MAX_BITS = 24;
const LOGIN_POW_HARD_MAX_BITS = APP_POW_MAX_BITS;
const LOGIN_POW_DECAY_HALF_LIFE_MS = 6 * 3600_000;
function loginPowBits(hourFails: number, dayFails: number): number {
  if (hourFails < LOGIN_ACCT_FREE_PER_HOUR && dayFails < LOGIN_ACCT_FREE_PER_DAY) return 0;
  const base = Math.min(LOGIN_POW_MAX_BITS, LOGIN_POW_BASE_BITS + Math.floor(Math.log2(Math.max(1, dayFails / LOGIN_ACCT_FREE_PER_HOUR))));
  if (dayFails < LOGIN_POW_GROWTH_FROM) return base;
  return Math.min(LOGIN_POW_HARD_MAX_BITS, LOGIN_POW_MAX_BITS + Math.floor((dayFails - LOGIN_POW_GROWTH_FROM) / LOGIN_POW_GROWTH_STEP));
}
/** the puzzle-signing key: this process's memory only (a restart voids open puzzles) */
let loginPowKey: Promise<CryptoKey> | null = null;
const powKey = () => (loginPowKey ??= crypto.subtle.generateKey({ name: "HMAC", hash: "SHA-256", length: 256 }, false, ["sign"]) as Promise<CryptoKey>);
async function powMac(body: string): Promise<string> {
  return [...new Uint8Array(await crypto.subtle.sign("HMAC", await powKey(), enc.encode(body)))].slice(0, 16).map((b) => b.toString(16).padStart(2, "0")).join("");
}
/** b73 (audit): V-11 — a puzzle for one label: "p1.<bits>.<expiry ms>.<nonce>.<mac>".
 *  Solve: find any string s (1-64 printable ASCII characters) such that
 *  SHA-256(utf8("vardum-login-pow-v1:" + challenge + ":" + s)) starts with <bits> zero bits.
 *  Send it back on the next /auth/login as pow_challenge + pow_solution. Single use,
 *  valid LOGIN_POW_TTL_MS, only for the label it was issued for. */
async function issueLoginPow(labelHash: string, bits: number): Promise<string> {
  const body = `p1.${bits}.${Date.now() + LOGIN_POW_TTL_MS}.${crypto.randomUUID().replace(/-/g, "")}`;
  return `${body}.${await powMac(labelHash + ":" + body)}`;
}
function leadingZeroBits(b: Uint8Array): number {
  let n = 0;
  for (const x of b) { if (x === 0) { n += 8; continue; } n += Math.clz32(x) - 24; break; }
  return n;
}
async function checkLoginPow(labelHash: string, needBits: number, challenge: unknown, solution: unknown): Promise<boolean> {
  if (typeof challenge !== "string" || typeof solution !== "string" || challenge.length > 200 || !/^[\x21-\x7e]{1,64}$/.test(solution)) return false;
  const m = /^(p1\.(\d{1,2})\.(\d{1,15})\.([0-9a-f]{32}))\.([0-9a-f]{32})$/.exec(challenge);
  if (!m) return false;
  const bits = Number(m[2]), exp = Number(m[3]);
  if (!ctEq(m[5], await powMac(labelHash + ":" + m[1]))) return false;
  if (exp < Date.now() || bits < needBits) return false;
  const h = new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(LOGIN_POW_LABEL + challenge + ":" + solution)));
  if (leadingZeroBits(h) < bits) return false;
  // single use
  const used: Deno.KvKey = ["login_pow_used", m[4]];
  return (await KV.atomic().check({ key: used, versionstamp: null }).set(used, 1, { expireIn: Math.max(60_000, exp - Date.now() + 60_000) }).commit()).ok;
}
/**
 * b77m (owner, carrier NAT): per-NETWORK caps answer with a proof-of-work puzzle instead of a flat refusal. A
 * carrier NAT (or a café, a campus) puts many real people behind one address; a flat per-network cap let one of
 * them — or one attacker — keep all the others out. Now, past the cap:
 *  - the answer is 429 { code: "pow_required", pow_required, pow_challenge, pow_bits, pow_prefix } (the login
 *    puzzle's format: SHA-256(prefix + challenge + ":" + s) with pow_bits leading zero bits); the app solves it
 *    and repeats the same call with { pow_challenge, pow_solution } (vendor/device/src/relay.ts);
 *  - a solved, fresh (NET_POW_TTL: the login puzzle's 10 min), single-use challenge, issued for THIS scope and
 *    THIS network, lets that one request through;
 *  - the size grows with how many puzzles this network already passed in the cap's window: NET_POW_BASE_BITS
 *    (16: ~65k hashes, well under a second on a phone) + 1 bit per doubling past the cap, at most NET_POW_MAX_BITS
 *    (22; the app solves up to 24);
 *  - a hard ceiling stays: once a network (or its /56, /48, at x4 / x16) passed NET_POW_HARD_FACTOR x the cap in
 *    puzzles in the window, it is refused outright until the window rolls, so a flood still stops (an attacker
 *    has to SOLVE puzzles to get there; unsolved requests count for nothing).
 * Per-account limits and relay-wide limits are unchanged and still refuse outright.
 */
const NET_POW_BASE_BITS = Number(Deno.env.get("VEIL_NET_POW_BASE_BITS")) || 16;
const NET_POW_MAX_BITS = Math.min(24, Number(Deno.env.get("VEIL_NET_POW_MAX_BITS")) || 22);
const NET_POW_HARD_FACTOR = Number(Deno.env.get("VEIL_NET_POW_HARD_FACTOR")) || 8;
async function netPowTags(req: Request, factors: Record<56 | 48, number> = WIDE_FACTOR): Promise<[string, number][]> {
  const net = await clientTag(req);
  const tags: [string, number][] = [[net, 1]];
  for (const w of await clientWideTags(req)) tags.push([w.bits + ":" + w.tag, factors[w.bits]]);
  return tags;
}
const netPowKey = (scope: string, tag: string, windowMs: number): Deno.KvKey => ["netpow", scope, tag, String(Math.floor(Date.now() / windowMs)), String(windowMs)];
/** the puzzle size for a network that already passed `passes` puzzles in a window of a cap of `cap` */
function netPowBits(passes: number, cap: number): number {
  return Math.min(NET_POW_MAX_BITS, NET_POW_BASE_BITS + Math.floor(Math.log2(1 + passes / Math.max(1, cap))));
}
/** null = let this request through (it solved the puzzle); a Response = the puzzle (or the hard refusal) */
/** b77q (audit 3 RF-4): `opts` — a hard ceiling factor and wide-network shares of its own (the TURN budget)
 *  b77q review (RF-4, owner decision "Puzzle, no hard stop"): `noHardStop` — never the network_limit refusal; `bitsStep`
 *  — the puzzle grows one bit per `bitsStep` puzzles this network already passed in the window (steeper than the
 *  default one bit per doubling), up to NET_POW_MAX_BITS (netPowStepBits) */
type NetPowOpts = { hardFactor?: number; wide?: Record<56 | 48, number>; noHardStop?: boolean; bitsStep?: number; minBits?: number }; // b77s (audit 4 RA-01): minBits — at least this size (the relay-wide sign-up puzzle)
/** b77q review (RF-4): the puzzle size after `passes` puzzles in the window, growing one bit every `step` of them */
function netPowStepBits(passes: number, step: number): number {
  return Math.min(NET_POW_MAX_BITS, NET_POW_BASE_BITS + Math.floor(Math.max(0, passes) / Math.max(1, step)));
}
async function netPowGate(req: Request, scope: string, cap: number, windowMs: number, body: Record<string, unknown> | null | undefined, refusal: string, opts: NetPowOpts = {}): Promise<Response | null> {
  const tags = await netPowTags(req, opts.wide);
  if (tags[0][0] === "local") return null;
  let passes = 0;
  for (const [tag, factor] of tags) {
    // b77p (audit VAR-16): + the same network's passes under yesterday's tag (counts survive 00:00 UTC)
    const altTag = altThrottleKey(tag);
    const own = Number((await KV.get<number>(netPowKey(scope, tag, windowMs))).value ?? 0);
    const prior = altTag ? Number((await KV.get<number>(netPowKey(scope, altTag, windowMs))).value ?? 0) : 0;
    passes = Math.max(passes, (own + prior) / factor);
  }
  if (!opts.noHardStop && passes >= cap * (opts.hardFactor ?? NET_POW_HARD_FACTOR)) {
    return j({ error: refusal, message: refusal, code: "network_limit", locked: true, retry_minutes: Math.max(1, Math.ceil((windowMs - (Date.now() % windowMs)) / 60_000)) }, 429);
  }
  // b77t (audit 5 L-2): never past what the app solves (APP_POW_MAX_BITS), whatever minBits asks
  const bits = Math.min(APP_POW_MAX_BITS, Math.max(opts.minBits ?? 0, opts.bitsStep ? netPowStepBits(passes, opts.bitsStep) : netPowBits(passes, cap)));
  const scopeKey = "netpow:" + scope + ":" + tags[0][0];
  if (await checkLoginPow(scopeKey, bits, body?.pow_challenge, body?.pow_solution)) {
    for (const [tag] of tags) {
      const k = netPowKey(scope, tag, windowMs);
      for (let i = 0; i < 20; i++) {
        const cur = await KV.get<number>(k);
        if ((await KV.atomic().check(cur).set(k, (cur.value ?? 0) + 1, { expireIn: windowMs * 2 }).commit()).ok) break;
      }
    }
    return null;
  }
  const msg = "Many people on this network are using Vardum — your phone does a short check first";
  return j({ error: msg, message: msg, code: "pow_required", pow_required: true, pow_challenge: await issueLoginPow(scopeKey, bits), pow_bits: bits, pow_prefix: LOGIN_POW_LABEL }, 429);
}
/** b77m (owner): the PBKDF2 budget's per-network part alone is full for this request (the relay-wide part is not) */
async function pbkdfNetFull(req: Request): Promise<boolean> {
  const net = await clientTag(req);
  if (net === "local") return false;
  if ((pbkdfNetUse.get(net) ?? 0) >= PBKDF2_PER_NETWORK) return true;
  for (const w of await clientWideTags(req)) if ((pbkdfNetUse.get(w.bits + ":" + w.tag) ?? 0) >= PBKDF2_PER_WIDE_NETWORK) return true;
  return false;
}
const pbkdfGlobalFull = () => pbkdfActive >= PBKDF2_MAX_CONCURRENT && pbkdfWaiters.length >= PBKDF2_MAX_QUEUE;

/**
 * b77t2 (CL-1, owner decision 2 Nov): a HARD daily cap on failed password guesses per sign-in label, from every
 * network together. b77t (L-2) stopped the label puzzle at the app's 24 bits, so a guesser rotating addresses was
 * bounded only by the per-network limits and the relay's hashing budget. Now each label has its own counter
 * (["login_label_cap", labelHash] = { n, last }): every password-only sign-in attempt reserves one place in it
 * BEFORE the password is checked (parallel guesses all count) and a correct password gives its place back, so it
 * counts failures. It decays exponentially (half-life LOGIN_LABEL_CAP_HALF_LIFE_MS = ln 2 days, ~16.6 h), chosen so
 * that a guesser holding it at the cap gets at most LOGIN_LABEL_DAILY_FAIL_CAP (1,000) guesses a day in the long
 * run. At the cap a password-only sign-in is refused (429 code "label_day_cap", before any hashing, no puzzle) until
 * the count decays below it. Unknown labels are counted the same way (no existence oracle).
 * NOT capped (the owner must not be locked out by a guesser):
 *  - a sign-in presenting the label's valid registration-lock device key (`reglock_device`: the phone that last
 *    signed in to the account, regLockGate) - a 256-bit secret only that phone holds; checked read-only here (the
 *    key still rotates in regLockGate after the password);
 *  - 24-word phrase labels (v<24 hex>@veil.app): a 256-bit secret, on its own cheap path;
 *  - device-transfer sign-ins: the relay has no separate one - a move's new phone restores with the 24 words first,
 *    so it signs in with the phrase label (exempt above) or, for an email account, with the password (capped);
 *  - phones already signed in (their tokens are not touched), the password change and sign-out-others
 *    (accountPasswordRefusal: a signed-in route with its own 30-a-day limit; its failures still count here), and
 *    the 24-word rebind / restore (signed in, or the phrase label).
 * Kept apart from the puzzle's row (["login_guard_acct"]), which a correct sign-in deletes: the owner's own sign-in
 * must not hand the guesser a fresh 1,000.
 */
const LOGIN_LABEL_DAILY_FAIL_CAP = Number(Deno.env.get("VEIL_LOGIN_LABEL_DAILY_FAIL_CAP")) || 1000;
const LOGIN_LABEL_CAP_HALF_LIFE_MS = Math.round(Math.LN2 * 86400_000);
/** b77u (audit 6, IH website C/claims "label counter 96 h vs 48 h"): the row deletes itself 48 h + 1 min after its last change,
 *  like every other rate-limit record (privacy page: "the longest after 48 hours and 1 minute"); it was kept 96 h. By then
 *  the count has decayed to e^-2 (about 14 %) of its value. */
const LOGIN_LABEL_CAP_TTL_MS = 48 * 3600_000 + 60_000;
const loginLabelCapKey = (labelHash: string): Deno.KvKey => ["login_label_cap", labelHash];
/** the label's decayed failure count now */
function labelCapDecayed(v: { n?: number; last?: number } | null | undefined, now: number): number {
  if (!v) return 0;
  return (Number(v.n) || 0) * Math.pow(0.5, Math.max(0, now - (Number(v.last) || now)) / LOGIN_LABEL_CAP_HALF_LIFE_MS);
}
/** reserve one failure in the label's count (null = reserved) or the refusal at the cap; `count` false = only check */
async function reserveLabelCap(labelHash: string, count = true): Promise<Response | null> {
  const k = loginLabelCapKey(labelHash);
  for (let attempt = 0; attempt < 50; attempt++) {
    const cur = await KV.get<{ n: number; last: number }>(k);
    const now = Date.now();
    const n = labelCapDecayed(cur.value, now);
    if (n + 1 > LOGIN_LABEL_DAILY_FAIL_CAP) {
      // minutes until the count decays to one place under the cap
      const mins = Math.max(1, Math.ceil((LOGIN_LABEL_CAP_HALF_LIFE_MS * Math.log2(n / Math.max(1, LOGIN_LABEL_DAILY_FAIL_CAP - 1))) / 60_000));
      const msg = "Too many wrong passwords for this account today. Sign in from a phone that was signed in to it before, or try again later.";
      return j({ error: msg, message: msg, code: "label_day_cap", locked: true, retry_minutes: mins }, 429, { "Retry-After": String(mins * 60) });
    }
    if (!count) return null;
    if ((await KV.atomic().check(cur).set(k, { n: n + 1, last: now }, { expireIn: LOGIN_LABEL_CAP_TTL_MS }).commit()).ok) return null;
    await new Promise((r) => setTimeout(r, Math.random() * 5));
  }
  return j({ message: "Busy — try again" }, 429);
}
/** a correct password gives its reserved place back */
async function refundLabelCap(labelHash: string): Promise<void> {
  const k = loginLabelCapKey(labelHash);
  for (let attempt = 0; attempt < 20; attempt++) {
    const cur = await KV.get<{ n: number; last: number }>(k);
    if (!cur.value) return;
    const now = Date.now();
    const n = Math.max(0, labelCapDecayed(cur.value, now) - 1);
    if ((await KV.atomic().check(cur).set(k, { n, last: now }, { expireIn: LOGIN_LABEL_CAP_TTL_MS }).commit()).ok) return;
  }
}
/** a failure on a route that is not capped (accountPasswordRefusal) still counts */
async function countLabelFailure(labelHash: string): Promise<void> {
  const k = loginLabelCapKey(labelHash);
  for (let attempt = 0; attempt < 20; attempt++) {
    const cur = await KV.get<{ n: number; last: number }>(k);
    const now = Date.now();
    if ((await KV.atomic().check(cur).set(k, { n: labelCapDecayed(cur.value, now) + 1, last: now }, { expireIn: LOGIN_LABEL_CAP_TTL_MS }).commit()).ok) return;
  }
}
/** b77t2 (CL-1): does this sign-in carry the account's current registration-lock device key? (read-only) */
async function loginDeviceKeyValid(user: { id?: unknown } | null, body: Record<string, unknown>): Promise<boolean> {
  const dev = body?.reglock_device;
  if (!user || typeof user.id !== "string" || typeof dev !== "string" || !dev || dev.length > 128) return false;
  const row = (await KV.get<RegLockRow>(regLockKey(await accountHashOf(user.id)))).value;
  return !!row?.device_tag && ctEq(await regLockDeviceTag(dev), row.device_tag);
}

/** Reserves one attempt (before the password is hashed, so parallel guesses all count).
 *  ok=false: a puzzle is needed (pow = a fresh one, bits = its size), or still contended. */
async function reserveAccountLoginAttempt(k: Deno.KvKey, labelHash: string, body: Record<string, unknown>, minBits = 0): Promise<{ ok: boolean; pow?: string; bits?: number }> {
  type G = { fails: number; since: number; day: number; last: number };
  let powDone = false;
  for (let attempt = 0; attempt < 50; attempt++) {
    const cur = await KV.get<G>(k);
    const now = Date.now();
    const v = cur.value;
    const freshHour = !v || now - (v.since || 0) > LOGIN_ACCT_WINDOW_MS;
    const freshDay = !v || now - (v.last || v.since || 0) > LOGIN_ACCT_LEVEL_RESET_MS;
    const hourFails = freshHour ? 0 : Number(v!.fails) || 0;
    // b77s (audit 4 RA-03): the day count decays (half-life LOGIN_POW_DECAY_HALF_LIFE_MS since the last attempt)
    // b77s (confirmation review, decay rounding): the decayed count is kept EXACT (a float in the row, with `last`).
    // It used to be rounded on every attempt, so attempts under ~20 s apart (each decaying it by less than half an
    // attempt) never decayed at all. Only the puzzle size reads a rounded value (half an attempt either way).
    const dayFails = freshDay ? 0 : (Number(v!.day) || hourFails) * Math.pow(0.5, Math.max(0, now - (v!.last || v!.since || now)) / LOGIN_POW_DECAY_HALF_LIFE_MS); // (a row from b72: day = its hour count)
    // b74 (audit V-11): minBits — the per-network label guard's puzzle (see the login route)
    const need = Math.min(APP_POW_MAX_BITS, Math.max(loginPowBits(hourFails, Math.round(dayFails)), minBits)); // b77t (audit 5 L-2)
    if (need > 0 && !powDone) {
      if (!(await checkLoginPow(labelHash, need, body?.pow_challenge, body?.pow_solution))) return { ok: false, pow: await issueLoginPow(labelHash, need), bits: need };
      powDone = true;
    }
    const next: G = { fails: hourFails + 1, since: freshHour ? now : v!.since, day: dayFails + 1, last: now };
    if ((await KV.atomic().check(cur).set(k, next, { expireIn: LOGIN_ACCT_LEVEL_RESET_MS + 3600_000 }).commit()).ok) return { ok: true };
    await new Promise((r) => setTimeout(r, Math.random() * 5));
  }
  return { ok: false };
}

/** b70 (re-review 2): a successful login gives back the attempt it reserved
 *  (only its own: earlier wrong guesses still count, and nothing is reset) */
async function refundLoginAttempt(k: Deno.KvKey): Promise<void> {
  for (let attempt = 0; attempt < 20; attempt++) {
    const cur = await KV.get<{ fails: number; lockedUntil: number; since?: number }>(k);
    if (!cur.value || cur.value.lockedUntil > Date.now() || !(cur.value.fails > 0)) return;
    if ((await KV.atomic().check(cur).set(k, { ...cur.value, fails: cur.value.fails - 1 }, { expireIn: THROTTLE_TTL_MS }).commit()).ok) return;
  }
}

async function accountHashOf(userId: string) {
  return "ah_" + (await sha256hex("veil-acct:" + userId));
}

/**
 * b77s (audit 4 RA-02): rows written by requests still in flight when the account was deleted outlived the delete
 * (the token was checked before a slow body arrived; the cascade had already run). The account-scoped writes (entity
 * create / update, identity register / rotate / bind, an upload's owner record) now commit only in ONE atomic step
 * with a check of the account's user row as read: present, and not being deleted (deleting_at). The delete sets
 * deleting_at (which changes the row) BEFORE its cascade, so a write is either committed before that — and the
 * cascade finds it — or refused. The sweeper's orphan pass (sweepDeletedAccountRows) is the backstop.
 */
async function liveAccountEntry(userId: string): Promise<Deno.KvEntry<Record<string, unknown>> | null> {
  const ue = await KV.get<Record<string, unknown>>(["user", userId], { consistency: "strong" });
  if (!ue.value) return null;
  if (Number(ue.value.deleting_at || 0) > Date.now() - 10 * 60_000) return null; // (authCheck's rule)
  return ue as Deno.KvEntry<Record<string, unknown>>;
}
/** b77s (audit 4 RA-02): `sets` (and `deletes`) in one step, only while the account is live; false = it is gone or
 *  being deleted (nothing written) */
async function writeIfAccountLive(userId: string, sets: [Deno.KvKey, unknown, { expireIn?: number }?][], deletes: Deno.KvKey[] = []): Promise<boolean> {
  for (let attempt = 0; attempt < 10; attempt++) {
    const ue = await liveAccountEntry(userId);
    if (!ue) return false;
    const tx = KV.atomic().check(ue);
    for (const [k, v, o] of sets) tx.set(k, v, o);
    for (const k of deletes) tx.delete(k);
    if ((await tx.commit()).ok) return true;
    await new Promise((r) => setTimeout(r, Math.random() * 5));
  }
  return false;
}
const ACCOUNT_GONE_WRITE = () => j({ message: "Unauthorized" }, 401);
/** b77s (audit 4 RA-02): account hashes this process deleted in the last day (memory only: an in-flight request dies
 *  with the process anyway) — the orphan pass checks upload owner records against them (a keyed tag per file) */
const recentlyDeletedAccts = new Map<string, number>();
/**
 * b77s (audit 4 RA-02): the orphan pass's backstop for rows naming a deleted account (whatever wrote them):
 *  - owner-scoped entity rows (notes, vaults, push rows, through their ["ix_acct"] entries), their per-account
 *    sequence rows (["row_cap_seq"]) and Vardum ID rows (veil_identity) whose account hash is no live account's;
 *  - upload owner records (a keyed tag per file) of the accounts this process deleted in the last day.
 * Candidates are collected FIRST and the live accounts read after, so an account made meanwhile is always seen as
 * live; each row goes only if it is unchanged since collected.
 */
async function sweepDeletedAccountRows(): Promise<number> {
  let n = 0;
  type Cand = { kind: "ix" | "seq" | "id"; entry: Deno.KvEntry<unknown>; acct: string };
  const cands: Cand[] = [];
  for await (const e of KV.list({ prefix: ["ix_acct"] }, { consistency: "strong" })) cands.push({ kind: "ix", entry: e, acct: String(e.key[2] ?? "") });
  for await (const e of KV.list({ prefix: ["row_cap_seq"] }, { consistency: "strong" })) cands.push({ kind: "seq", entry: e, acct: String(e.key[2] ?? "") });
  for await (const e of KV.list<Record<string, unknown>>({ prefix: ["veil_identity"] }, { consistency: "strong" })) {
    const a = String(e.value?.account_hash || "");
    if (a.startsWith("ah_")) cands.push({ kind: "id", entry: e, acct: a });
  }
  if (cands.length) {
    const live = new Set<string>();
    for await (const e of KV.list({ prefix: ["user"] }, { consistency: "strong" })) live.add(await accountHashOf(String(e.key[1] ?? "")));
    for (const c of cands) {
      if (!c.acct.startsWith("ah_") || live.has(c.acct)) continue;
      if (c.kind === "ix") {
        const name = String(c.entry.key[1]), id = String(c.entry.key[3]);
        const row = await KV.get<Record<string, unknown>>(["entity", name, id], { consistency: "strong" });
        if (row.value && String(row.value._acct ?? "") === c.acct) { await deleteEntity(name, id); n++; }
        await KV.atomic().check(c.entry).delete(c.entry.key).commit();
      } else if (c.kind === "seq") {
        if ((await KV.atomic().check(c.entry).delete(c.entry.key).commit()).ok) n++;
      } else {
        if ((await KV.atomic().check(c.entry).delete(c.entry.key).commit()).ok) { await dropOpks(String((c.entry.value as Record<string, unknown>)?.veil_id || c.entry.key[1] || "")); n++; }
      }
    }
  }
  for (const [a, at] of recentlyDeletedAccts) if (Date.now() - at > 86400_000) recentlyDeletedAccts.delete(a);
  if (recentlyDeletedAccts.size) {
    for await (const e of KV.list<string>({ prefix: ["blob_owner"] }, { consistency: "strong" })) {
      const id = String(e.key[1]);
      for (const a of recentlyDeletedAccts.keys()) {
        if (e.value !== await blobOwnerTag(a, id)) continue;
        const p = blobPathOf("blob:" + id);
        if (p) await Deno.remove(p).catch(() => undefined);
        await KV.delete(e.key);
        await KV.delete(["blob_session", id]); await KV.delete(["blob_group", id]); // b77u (U-M9)
        n++;
        break;
      }
    }
  }
  return n;
}

/** b199: per-row creator tag — proves "this account created this row" without
 *  putting a cross-row account identifier into rows peers can read.
 *  b71 (audit F-30): unlinkable for PEERS only. It is unkeyed, and account ids sit in
 *  KV, so anyone with the database can recompute it. Keying it (and accountHashOf) with
 *  a secret held outside KV would orphan every existing row's tag; not done — see the
 *  WHAT THIS RELAY STORES block at the top. */
async function ownerTag(userId: string, rowId: string) {
  return "ow_" + (await sha256hex("veil-owner:" + userId + ":" + rowId));
}

/** b199: group-salted hash of a banned identity's veil id / IK — what a deny
 *  entry keeps once the banned account is deleted (the ban outlives the
 *  account; the identifiers do not). */
async function denyHash(groupToken: string, value: string) {
  return "dh_" + (await sha256hex("veil-deny:" + groupToken + ":" + value));
}

// ---------- veilIdentityGate (public keys only — never private material) ----------
/** b70 (re-review 13): one identity action at a time per Vardum ID (a prekey rotation
 *  overlapping a bind wrote the row back unbound) */
/** b71 (audit F-32): how long a freshly registered, signed, unbound identity row is safe
 *  from replacement by another account (register → challenge → bind takes seconds).
 *  b75r1 (audit REL-02): counted from the row's created_date, which a re-register by the
 *  same account never moves, and it no longer refuses anyone — see the register rules. */
const UNBOUND_SETUP_GUARD_MS = 2 * 60_000;
/** b75r1 (audit REL-02): how long a registration held aside for one account (because another
 *  account's unbound row sits on the Vardum ID) waits for that account's bind */
const PENDING_IDENTITY_MS = 30 * 60_000;
const pendingIdentityKey = (veilId: string, acct: string): Deno.KvKey => ["veil_identity_pending", keySafe(veilId), acct];
/** b75r1 (audit REL-01): what the relay kept for an identity the account just retired
 *  ("Generate new Vardum ID": the primary moved to the new ID) — its bind challenges, held
 *  registrations and invite-push coalescer. The identity row itself is deleted atomically
 *  with the primary change by the caller. */
async function dropRetiredIdentityRows(veilId: string): Promise<void> {
  for await (const e of KV.list({ prefix: ["id_nonce", veilId] })) await KV.delete(e.key);
  await dropPendingIdentities(veilId);
  await KV.delete(["push_coalesce_invite", keySafe(veilId)]); // (a row from before b77m)
  await KV.delete(["push_coalesce_invite", await vidTag(veilId)]); // b77m (audit VAR-48)
  await dropOpks(veilId); // b76 (one-time prekeys)
}

// ---------- b76 (one-time prekeys) ----------
// Each phone publishes signed one-time prekey PAIRS (one X25519 key + one ML-KEM-768 key under one
// id; Ed25519(IK, "vardum-opk-v1:" || id || ":" || x_pub || pq_pub || ":" || ts), dated). A contact
// lookup with claim_opk hands out exactly one unused pair and deletes it in the same step; every
// other lookup leaves the pool alone. Rows: ["veil_opk", vid, ts (12 digits), id] =
// {id, x_pub, pq_pub, sig, ts}, oldest handed out first; ["veil_opk_owner", vid] = {device} — the
// phone tag whose pairs these are (an upload from another tag, i.e. a new phone or a restore,
// replaces the pool: the old phone's pairs can't be opened by the new one).
/** most pairs held per Vardum ID, and per upload */
const OPK_MAX_STORED = 100;
const OPK_UPLOAD_MAX = 50;
/** a pair is served for at most this long after it was signed (clients accept 28 days) */
const OPK_RELAY_TTL_MS = 21 * 86_400_000;
/** b77t (audit 5 L-14): signed prekeys older than this (or more than a day ahead) are refused when NEWLY published —
 *  crypto-core constants.ts PREKEY_SIG_MAX_AGE_MS / PREKEY_SIG_MAX_FUTURE_MS, what every client accepts */
const PREKEY_SIG_MAX_AGE_MS = 28 * 86_400_000;
const PREKEY_SIG_MAX_FUTURE_MS = 86_400_000;
/** hand-out caps — what one account (or everyone together) can take from one Vardum ID's pool. Past
 *  a cap the lookup still answers, with the signed prekeys only (opk_status "limited"), so starting a
 *  chat never fails on them; they bound how cheaply someone can drain a victim's pool. */
const OPK_CLAIMS_PER_ACCOUNT_PER_HOUR = 30;
/**
 * b77m (audit VAR-09): the per-ID cap was ONE shared budget (60 a day, everyone together) and each
 * account could take 10 of it, so six throwaway accounts spent it and every honest new contact of
 * that ID got the signed prekeys only for the rest of the day, whatever the owner topped up. Now:
 *  - one account → one ID: 2 a day (the app claims one per new chat; one retry);
 *  - one network → one ID: OPK_CLAIMS_PER_NETWORK_TARGET_PER_DAY (/56, /48 at x4, x16), and one
 *    network → every ID: OPK_CLAIMS_PER_NETWORK_PER_HOUR — fresh accounts on one network add nothing;
 *  - the shared per-ID budget (OPK_CLAIMS_PER_TARGET_PER_DAY) is spent ONLY by accounts younger than
 *    OPK_SEASONED_ACCOUNT_MS; older accounts are served past it (still within the caps above). So
 *    throwaway accounts can at worst push other NEW accounts to the signed-prekey path (the
 *    last-resort behaviour is unchanged), and draining the pool itself takes seasoned accounts on
 *    many networks, two pairs each.
 * The per-ID and per-network rows name the ID by a memory-keyed tag (vidTag, audit VAR-48).
 */
const OPK_CLAIMS_PER_PAIR_PER_DAY = 2; // one account → one Vardum ID
const OPK_CLAIMS_PER_TARGET_PER_DAY = Number(Deno.env.get("VEIL_OPK_CLAIMS_PER_TARGET_PER_DAY")) || 30; // new accounts together → one Vardum ID
const OPK_CLAIMS_PER_NETWORK_TARGET_PER_DAY = Number(Deno.env.get("VEIL_OPK_CLAIMS_PER_NETWORK_TARGET_PER_DAY")) || 4;
const OPK_CLAIMS_PER_NETWORK_PER_HOUR = Number(Deno.env.get("VEIL_OPK_CLAIMS_PER_NETWORK_PER_HOUR")) || 60;
/** b77t (audit 5 L-10): pairs one Vardum ID hands out a day past the per-network caps through solved puzzles, all
 *  networks together — a hard ceiling (see the lookup) */
const OPK_POW_CLAIMS_PER_TARGET_PER_DAY = Number(Deno.env.get("VEIL_OPK_POW_CLAIMS_PER_TARGET_PER_DAY")) || 8;
const OPK_SEASONED_ACCOUNT_MS = Number(Deno.env.get("VEIL_OPK_SEASONED_ACCOUNT_MS")) || 3 * 86_400_000;
const opkPrefix = (vid: string): Deno.KvKey => ["veil_opk", keySafe(vid)];
const opkOwnerKey = (vid: string): Deno.KvKey => ["veil_opk_owner", keySafe(vid)];
const OPK_ID_RE = /^[0-9a-f]{16}$/;
const OPK_DEVICE_RE = /^[0-9a-f]{32}$/;
/** b76r1 (one-time prekeys): every retire path (purge, handover, rebind, delete, a bind that moves the
 *  ID, a replaced unbound row) drops the pool under the same per-ID lock an upload writes under, and
 *  after it removed or moved the identity row. An upload that verified the ID before the retire then
 *  either wrote first (and its rows go here) or runs after and finds the identity gone (it re-reads
 *  it inside the lock). Without the lock an upload in flight during a duress purge wrote its 50 rows
 *  and the phone tag back for an ID that no longer existed. */
function dropOpks(veilId: string): Promise<void> {
  return withLock("opk:" + veilId, () => dropOpksLocked(veilId));
}
/** the caller already holds withLock("opk:" + veilId) (the lock is not re-entrant) */
async function dropOpksLocked(veilId: string): Promise<void> {
  for await (const e of KV.list({ prefix: opkPrefix(veilId) }, { consistency: "strong" })) await KV.delete(e.key);
  await KV.delete(opkOwnerKey(veilId));
}
const opkFresh = (v: Record<string, unknown> | null | undefined, nowMs: number) => !!v && nowMs - Number(v.ts) * 1000 <= OPK_RELAY_TTL_MS;
/** b76r2 (one-time prekeys, audit OP-1): the per-(account, Vardum ID) hand-out cap is keyed by two
 *  opaque tags, "opkpair:<tag(account)>:<tag(ID)>", HMACs under a key that lives only in this
 *  process's memory (as the network tags and burn votes, §12.15). The row was
 *  "opkpair:<account hash>:<ID>", which said in clear whose one-time keys the account fetched, so a
 *  duress purge had to delete it (b76r1) — and deleting it gave the purging account a fresh cap: a
 *  purge + re-bind loop took 10 more pairs a day from the same victim each time. Now the row names
 *  nobody to anyone holding only the database, so it is KEPT across a purge (it expires within two
 *  days); account delete and a purge of the TARGET ID still find their rows by tag while this process
 *  runs. A restart starts every pair cap afresh (the old tags can no longer be matched). */
let opkPairKeyP: Promise<CryptoKey> | null = null;
async function opkPairTag(s: string): Promise<string> {
  if (!opkPairKeyP) opkPairKeyP = crypto.subtle.generateKey({ name: "HMAC", hash: "SHA-256", length: 256 }, false, ["sign"]) as Promise<CryptoKey>;
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", await opkPairKeyP, enc.encode("veil-opkpair:" + s)));
  return [...mac.slice(0, 16)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
const opkPairAcctPrefix = async (userId: string) => "opkpair:" + await opkPairTag("a:" + userId) + ":";
const opkPairTargetSuffix = async (veilId: string) => ":" + await opkPairTag("v:" + keySafe(veilId));
const opkPairKey = async (userId: string, veilId: string) => (await opkPairAcctPrefix(userId)) + (await opkPairTargetSuffix(veilId)).slice(1);
/** b77 (sealed sender): the per-(account, addressee) contact-request cap is keyed the same way —
 *  "req:<tag(account)>:<tag(Vardum ID)>" under the memory-only key — instead of
 *  "req:<account hash>:<Vardum ID>", which said in clear who asked whom (and outlived a 1:1
 *  row that no longer names either account). A restart starts every request cap afresh. */
const reqPairAcctPrefix = async (userId: string) => "req:" + await opkPairTag("ra:" + userId) + ":";
const reqPairTargetSuffix = async (veilId: string) => ":" + await opkPairTag("rv:" + keySafe(veilId));
const reqPairKey = async (userId: string, veilId: string) => (await reqPairAcctPrefix(userId)) + (await reqPairTargetSuffix(veilId)).slice(1);
/** the request-cap suffixes of these Vardum IDs, and whether a limiter key is a request cap on one of them */
const reqTargetSuffixesOf = (vids: string[]) => Promise.all(vids.filter(Boolean).map((v) => reqPairTargetSuffix(v)));
/** b77: the tag a pending 1:1 row carries for its creating account (memory-only key; see createEntity) */
const initTag = async (userId: string) => "it_" + await opkPairTag("ri:" + userId);
const reqHit = (k: string, sfx: string[]) => k.startsWith("req:") && sfx.some((s) => k.endsWith(s));
/** b77m (audit VAR-48): the memory-keyed tag that stands for a Vardum ID in the rows that count what
 *  happens TO that ID — the invite-push caps and their coalescer, the one-time-key hand-out budgets.
 *  They held the ID in clear ("invpush:<ID>", "opktarget:<ID>", ["push_coalesce_invite", <ID>]), so
 *  a database copy showed which IDs got contact requests and key claims, and when. */
const vidTag = async (veilId: string) => "vt" + await opkPairTag("vt:" + keySafe(veilId));
/** b76r2 (one-time prekeys, audit OP-2): a marker for every pair the relay handed out, kept for as long
 *  as that pair could still be uploaded (its 21-day signing window, plus the day of clock skew an
 *  upload allows), so an upload of a pair that was already served is refused. Without it the bound
 *  account's token (the owner's buggy phone, or a stolen token: no identity key needed, the pair
 *  carries its own signature) could put a served pair back, and a second requester got the same
 *  one-time keys, whose private half the owner's phone had already used and deleted — that contact's
 *  first message then fails. Keyed by a hash of (ID, pair id), so the row names neither, and it
 *  outlives a purge or a pool drop (a re-bind of the same ID must not re-serve its old pairs either). */
const opkServedKey = async (veilId: string, pairId: string): Promise<Deno.KvKey> => ["opk_served", await sha256hex("veil-opk-served-v1:" + keySafe(veilId) + ":" + pairId)];
const opkServedTtl = (ts: unknown, nowMs: number) => Math.max(60_000, OPK_RELAY_TTL_MS - (nowMs - Number(ts) * 1000) + 86_400_000);
async function countOpks(veilId: string, nowMs = Date.now()): Promise<number> {
  let n = 0;
  for await (const e of KV.list<Record<string, unknown>>({ prefix: opkPrefix(veilId) }, { consistency: "strong" })) if (opkFresh(e.value, nowMs)) n++;
  return n;
}
/** hand out ONE unused pair and delete it, atomically: the per-ID lock serialises claims in this
 *  process, and each delete is versionstamp-checked, so no two requesters ever get the same pair */
function claimOpk(veilId: string): Promise<Record<string, string> | null> {
  return withLock("opk:" + veilId, async () => {
    const nowMs = Date.now();
    for await (const e of KV.list<Record<string, unknown>>({ prefix: opkPrefix(veilId) }, { consistency: "strong" })) {
      if (!opkFresh(e.value, nowMs)) { await KV.delete(e.key); continue; } // expired: never served
      const v = e.value!;
      // b76r2 (audit OP-2): the "handed out" marker is written in the same step as the delete
      const served = await opkServedKey(veilId, String(v.id));
      if (!(await KV.atomic().check(e).delete(e.key).set(served, 1, { expireIn: opkServedTtl(v.ts, nowMs) }).commit()).ok) continue; // someone else took it
      return { id: String(v.id), x_pub: String(v.x_pub), pq_pub: String(v.pq_pub), sig: String(v.sig) };
    }
    return null;
  });
}
/** every registration held aside for one Vardum ID (any account) goes */
async function dropPendingIdentities(veilId: string): Promise<void> {
  for await (const e of KV.list({ prefix: ["veil_identity_pending", keySafe(veilId)] })) await KV.delete(e.key);
}
/** base64 → bytes, empty on malformed input (never throws) */
const b64dLoose = (s: string): Uint8Array => { try { return b64d(s); } catch { return new Uint8Array(0); } };
async function fnVeilIdentityGate(auth: { userId: string }, body: Record<string, any>, req: Request | null = null) {
  if (String(body?.action || "") === "lookup") return fnVeilIdentityGateInner(auth, body, req);
  return withLock("vid:" + String(body?.veil_id || "").trim(), () => fnVeilIdentityGateInner(auth, body, req));
}
async function fnVeilIdentityGateInner(auth: { userId: string }, body: Record<string, any>, req: Request | null = null) {
  const action = String(body.action || "");
  const veilId = String(body.veil_id || "").trim();
  if (veilId.length > MAX_VEIL_ID) return j({ error: "Invalid identity", message: "Invalid identity" }, 400); // P7 fix
  if (action === "register") {
    // b198 tuning: 20/min + 10-min lock punished real testing (background
    // loops + manual retries trip it instantly). 60/min + 2-min lock keeps
    // the abuse wall while letting humans + heartbeats coexist.
    const rl = await rateLimit("idreg:" + auth.userId, 60, 60_000, 2);
    if (rl) return j({ locked: true, retry_minutes: rl.retry_minutes }, 429);
    if (!veilId || !body.IK_pub) return j({ error: "Invalid identity", message: "Invalid identity" }, 400);
    // Batch C (B1; reviews P2 V-8, P3 R4): a Vardum ID IS the hash of its
    // identity key — a registration whose ID doesn't derive from its key is refused
    let ikLen = 0;
    try { ikLen = atob(String(body.IK_pub)).length; } catch { ikLen = 0; }
    // b70 (re-review 9): the canonical spelling only — another spelling of someone's key
    // used to squat their Vardum ID for good (their own register then got 409)
    if (!canonicalB64(body.IK_pub) || ikLen !== 32 || (await veilIdOfIk(String(body.IK_pub))) !== veilId) {
      return j({ error: "This Vardum ID does not match its identity key", message: "This Vardum ID does not match its identity key" }, 400);
    }
    // b77m (audit VAR-35): and the key is a real Ed25519 public key (prime-order subgroup) — a
    // small-order one (e.g. the identity point) let anyone "sign" for its ID without a private key
    if (!ed25519KeyStrictOk(b64d(String(body.IK_pub)))) return j({ error: "Invalid identity key", message: "Invalid identity key", code: "bad_identity_key" }, 400);
    // b70 (re-review 2): prekeys have fixed sizes (X25519 32 B, Ed25519 sig 64 B,
    // ML-KEM-768 pub 1184 B as base64); anything bigger is storage abuse
    for (const [f, max] of [["SPK_pub", 64], ["SPK_sig", 128], ["pq_pub", 1700], ["pq_sig", 128]] as const) {
      if (body[f] !== undefined && (typeof body[f] !== "string" || String(body[f]).length > max)) return j({ error: "Invalid identity", message: "Invalid identity" }, 400);
    }
    // IDENTITY-HIJACK GUARD + b198 RESTORE FIX v2 (the v1 byte-identical rule
    // was wrong: the IK is the identity and derives deterministically from the
    // phrase, but SPK/PQ are FRESHLY GENERATED PREKEYS per restore — no restore
    // can ever reproduce them, and it must not: they are rotatable by design).
    // Rules, mirroring the key hierarchy:
    //   - a DIFFERENT IK on an existing veil_id = a different identity claiming
    //     the label -> 409 always (bound or not — the IK defines the identity);
    //   - same IK + BOUND: prekey rotation allowed ONLY for the bound account
    //     (the signed-in caller proves ownership by session) -> update, 200;
    //   - same IK + UNBOUND: rotate freely (unbound rows are trusted for
    //     nothing until bound).
    // b54: pq_sig = Ed25519(IK, label || pq_pub) — stored and served as-is;
    // clients verify it against the pinned IK (the relay is not trusted to).
    // Shape check only: 64 raw bytes, else stored empty (pre-b54 clients).
    // b75 (audit 2 V9): prekey signatures are labelled and dated: "<b64 sig>.<unix seconds>"
    // (crypto-core identity.ts). The relay checks the form and the signature; clients also
    // refuse one signed too long ago.
    const datedSig = (v: unknown): { sig: string; ts: string } | null => {
      const m = typeof v === "string" ? /^([A-Za-z0-9+/]{86}==)\.([1-9][0-9]{0,11})$/.exec(v) : null;
      return m ? { sig: m[1], ts: m[2] } : null;
    };
    let pqSig = "";
    if (typeof body.pq_sig === "string" && body.pq_sig && datedSig(body.pq_sig)) pqSig = body.pq_sig;
    // b71 (audit F-32): the relay now checks the prekey signatures itself. A signed
    // prekey (SPK) must carry a valid Ed25519(IK, SPK) signature, and a pq_sig must be
    // a valid Ed25519(IK, "vardum-pq-prekey-v1:" || pq_pub) — exactly what the app
    // signs (crypto-core identity.ts) and what every client already re-checks against
    // its pinned key. Unsigned or wrongly signed prekeys are refused (they used to be
    // stored and served). A row with no prekeys at all is still accepted (it is useless
    // to peers, and it never earns the set-up protection below).
    const spkPub = String(body.SPK_pub ?? ""), spkSig = String(body.SPK_sig ?? ""), pqPub = String(body.pq_pub ?? "");
    const badPrekeys = () => j({ error: "The prekey signatures do not verify", message: "The prekey signatures do not verify" }, 400);
    if (spkPub || spkSig) {
      const ds = datedSig(spkSig);
      if (!canonicalB64(spkPub) || b64d(spkPub).length !== 32 || !ds || !canonicalB64(ds.sig) || b64d(ds.sig).length !== 64) return badPrekeys();
      if (!(await ed25519Verify(String(body.IK_pub), new Uint8Array([...enc.encode("vardum-spk-v2:"), ...b64d(spkPub), ...enc.encode(":" + ds.ts)]), ds.sig))) return badPrekeys();
    }
    if (typeof body.pq_sig === "string" && body.pq_sig) {
      const dp = datedSig(pqSig);
      if (!dp || !pqPub || !(await ed25519Verify(String(body.IK_pub), new Uint8Array([...enc.encode("vardum-pq-prekey-v2:"), ...b64dLoose(pqPub), ...enc.encode(":" + dp.ts)]), dp.sig))) return badPrekeys();
    }
    // b77p (audit VAR-37): a PQ key is stored ONLY with its verified signature. A pq_pub sent without pq_sig used
    // to be stored and served as is (the comment above said unsigned prekeys were refused; this one was not), so
    // on a bound row the account token alone could keep replacing it. Clients re-verify (pins.ts) and refused it
    // anyway — the effect was a denial of service on contact set-up. Now it is dropped (stored empty, as pre-b54
    // apps' rows were), and lookup never serves an unsigned one left by an older relay.
    const pqStored = pqSig ? pqPub : "";
    const existingId = (await KV.get<Record<string, unknown>>(["veil_identity", veilId])).value;
    // b77t (audit 5 L-14, IH R-07 / V-04): a signed prekey is checked for freshness too, as the one-time keys are. A NEW
    // signature (one that is not the row's current one, which a phone may re-send unchanged) must be signed within
    // PREKEY_SIG_MAX_AGE_MS (28 days, what clients accept), at most a day ahead, and — on the same identity's row — not
    // before the signature it replaces. The bearer token alone could put a 90-day-old (or ts=1) prekey back.
    // (checked after the "another identity / another account" refusals, which keep their 409)
    const staleRefusal = (): Response | null => {
      const sameRow = !!existingId && String(existingId.IK_pub || "") === String(body.IK_pub);
      const stale = (sig: string, stored: unknown): boolean => {
        if (!sig || (sameRow && sig === String(stored ?? ""))) return false;
        const d = datedSig(sig);
        if (!d) return false; // (an unsigned value never gets this far: refused or dropped above)
        const tsMs = Number(d.ts) * 1000, nowMs = Date.now();
        if (nowMs - tsMs > PREKEY_SIG_MAX_AGE_MS || tsMs - nowMs > PREKEY_SIG_MAX_FUTURE_MS) return true;
        const prev = sameRow ? datedSig(String(stored ?? "")) : null;
        return !!prev && Number(d.ts) < Number(prev.ts); // (the same second is allowed: a quick re-rotation)
      };
      if (stale(spkSig, existingId?.SPK_sig) || stale(pqSig, existingId?.pq_sig)) {
        console.warn("register-refused", { reason: "stale-prekey" });
        return j({ error: "This prekey is out of date — Vardum makes a new one by itself", message: "This prekey is out of date — Vardum makes a new one by itself", code: "stale_prekey" }, 400);
      }
      return null;
    };
    if (existingId) {
      const sameIk = String(existingId.IK_pub || "") === String(body.IK_pub);
      if (!sameIk) {
        console.warn("register-refused", { reason: "different-identity" });
        return j({ error: "Identity already bound", message: "Identity already bound" }, 409);
      }
      if (existingId.bound === true && String(existingId.account_hash || "") !== String(await accountHashOf(auth.userId))) {
        console.warn("register-refused", { reason: "bound-to-another-account" });
        return j({ error: "Identity already bound", message: "Identity already bound" }, 409);
      }
      { const st = staleRefusal(); if (st) return st; } // b77t (audit 5 L-14)
      // b70 (audit RLY-14): an UNBOUND row registered by another account is
      // replaced by this caller's (only a bind proves the key, and the bind
      // that follows decides) instead of having its prekeys overwritten in place
      if (existingId.bound !== true && String(existingId.account_hash || "") !== String(await accountHashOf(auth.userId))) {
        // b71 (audit F-32): ...except while it is being set up. An unbound row with
        // signed prekeys, registered in the last UNBOUND_SETUP_GUARD_MS, can't be
        // replaced by another account: that was the bind race (re-registering between
        // the owner's register and bind made the owner's bind fail).
        // b75r1 (audit REL-02): the b71 comment said a squatter "delays a restore by minutes
        // at most". Wrong: the window ran from updated_date, every re-register by the
        // holder refreshed it, and the newcomer got 409 — so another account could keep a
        // Vardum ID out of restore and lookup for as long as it liked (replaying the old
        // signed prekeys anyone can read via lookup). The relay can't tell who holds the
        // private key at register time, so register no longer decides between accounts at
        // all. Rules now:
        //   - the window is measured from created_date, which a re-register by the holder
        //     never moves (the prekey-rotation path below keeps it);
        //   - inside the window the holder's row stays (the bind race stays fixed), and
        //     the newcomer's registration is HELD ASIDE for the newcomer's account
        //     (["veil_identity_pending", id, account], PENDING_IDENTITY_MS) — answered 200,
        //     never 409;
        //   - a bind wins for whichever account proves the key: an account whose bind
        //     verifies against the IK gets ITS OWN held registration (its own prekeys)
        //     published as the bound row (see bind). Only the real key holder can sign,
        //     so no other account can keep it out, and a held row can't bind for anyone
        //     who can't sign;
        //   - past the window an unbound row of another account is replaced, as before.
        const age = Date.now() - (Date.parse(String(existingId.created_date || existingId.updated_date || "")) || 0);
        if (existingId.SPK_sig && age < UNBOUND_SETUP_GUARD_MS) {
          const newRl = await rateLimit("idnew:" + auth.userId, 20, 86_400_000, 60);
          if (newRl) return j({ locked: true, retry_minutes: newRl.retry_minutes }, 429);
          const held = { veil_id: veilId, IK_pub: String(body.IK_pub), SPK_pub: spkPub, SPK_sig: spkSig, pq_pub: pqStored, pq_sig: pqSig, account_hash: await accountHashOf(auth.userId), bound: false, created_date: nowIso(), updated_date: nowIso() };
          await KV.set(pendingIdentityKey(veilId, held.account_hash), held, { expireIn: PENDING_IDENTITY_MS });
          console.info("register-held", { reason: "unbound-row-in-setup" });
          return json({ ok: true, data: { veil_id: veilId, pending: true } });
        }
        await KV.delete(["veil_identity", veilId]);
        await dropOpks(veilId); // b76 (one-time prekeys): the replaced row's one-time keys go with it
      } else {
      // b74 (audit VAR-12): a BOUND identity's signed prekeys are replaced, never removed. A
      // register without them used to store them blank, so new contacts could no longer
      // start a chat with the identity (and a pq-less bundle invites a downgrade).
      if (existingId.bound === true && ((!!existingId.SPK_pub && !spkPub) || (!!existingId.pq_pub && !!existingId.pq_sig && (!pqPub || !pqSig)))) {
        console.warn("register-refused", { reason: "would-remove-prekey" });
        return j({ error: "A registered identity keeps its prekeys — send new signed ones to replace them", message: "A registered identity keeps its prekeys — send new signed ones to replace them" }, 400);
      }
      // prekey rotation (SPK/PQ) — binding untouched
      if (!(await writeIfAccountLive(auth.userId, [[["veil_identity", veilId], { ...existingId, SPK_pub: String(body.SPK_pub || ""), SPK_sig: String(body.SPK_sig || ""), pq_pub: pqStored, pq_sig: pqSig, updated_date: nowIso() }]]))) return ACCOUNT_GONE_WRITE(); // b77s (audit 4 RA-02)
      return json({ ok: true, data: { veil_id: veilId, restored: existingId.bound === true } });
      }
    }
    { const st = staleRefusal(); if (st) return st; } // b77t (audit 5 L-14): a new row too
    // b70 (re-review 2): new identity rows one account may create per day
    const newRl = await rateLimit("idnew:" + auth.userId, 20, 86_400_000, 60);
    if (newRl) return j({ locked: true, retry_minutes: newRl.retry_minutes }, 429);
    const rec = {
      veil_id: veilId,
      IK_pub: String(body.IK_pub),
      SPK_pub: String(body.SPK_pub || ""),
      SPK_sig: String(body.SPK_sig || ""),
      pq_pub: pqStored,
      pq_sig: pqSig,
      account_hash: await accountHashOf(auth.userId),
      bound: false,
      created_date: nowIso(),
      updated_date: nowIso(),
    };
    if (!(await writeIfAccountLive(auth.userId, [[["veil_identity", veilId], rec]]))) return ACCOUNT_GONE_WRITE(); // b77s (audit 4 RA-02)
    await KV.delete(pendingIdentityKey(veilId, rec.account_hash)); // b75r1 (audit REL-02): superseded
    void bumpStat("identities");
    return json({ ok: true, data: { veil_id: veilId } });
  }
  if (action === "challenge") {
    // b167: the 429 body carries ONLY {locked:true, retry_minutes} — NO message field
    const rl = await rateLimit("idchallenge:" + auth.userId, 60, 60_000, 2);
    if (rl) return j({ locked: true, retry_minutes: rl.retry_minutes }, 429);
    if (!veilId) return j({ error: "Invalid identity", message: "Invalid identity" }, 400);
    // nonce is base64 — ikSign(seed, nonce) signs fromB64(nonce), so verification
    // at bind time decodes the nonce the same way
    const nonce = b64e(crypto.getRandomValues(new Uint8Array(32)));
    // Batch C (B1): the nonce belongs to the account that asked for it — another
    // account can neither overwrite it nor present the owner's signed answer
    // b70 (audit RLY-11): only for a Vardum ID that has an identity row, and the
    // row expires on its own (it used to stay forever)
    if (!(await KV.get(["veil_identity", keySafe(veilId)])).value) return j({ error: "Invalid identity", message: "Invalid identity" }, 400);
    await KV.set(["id_nonce", veilId, await accountHashOf(auth.userId)], { nonce, exp: Date.now() + 10 * 60_000 }, { expireIn: 10 * 60_000 });
    return json({ data: { nonce } });
  }
  if (action === "bind") {
    // an unknown identity is "not found" before anything about nonces is said
    if (!(await KV.get(["veil_identity", veilId])).value) return j({ error: "Identity not found", message: "Identity not found" }, 404);
    const nonceKey = ["id_nonce", veilId, await accountHashOf(auth.userId)];
    const nonceRow = (await KV.get<{ nonce: string; exp: number }>(nonceKey)).value;
    if (!nonceRow || nonceRow.exp < Date.now()) return j({ error: "Nonce expired", message: "Nonce expired" }, 400);
    let rec = (await KV.get<Record<string, unknown>>(["veil_identity", veilId])).value;
    if (!rec) return j({ error: "Identity not found", message: "Identity not found" }, 404);
    // b70 (re-review R8): an unbound row binds only for the account that
    // registered it (another account's re-registration in between would
    // otherwise publish ITS prekeys under this bind) — register again first
    // b75r1 (audit REL-02): ...or for an account whose registration was held aside while
    // another account's unbound row sat here: a verified bind publishes THAT account's own
    // held registration (its own prekeys) as the bound row, replacing the unbound one. The
    // IK is the same (the ID derives from it, and a different IK is refused at register),
    // so the signature below is checked against the very key either row names.
    if (rec.bound !== true && String(rec.account_hash || "") !== String(await accountHashOf(auth.userId))) {
      const held = (await KV.get<Record<string, unknown>>(pendingIdentityKey(veilId, await accountHashOf(auth.userId)))).value;
      if (!held || String(held.IK_pub || "") !== String(rec.IK_pub || "")) {
        return j({ error: "Register this identity again, then bind", message: "Register this identity again, then bind" }, 409);
      }
      rec = { ...held };
    }
    // b54 (T-1): clients sign the domain-separated bind message
    // ("vardum-identity-bind-v1:" || nonce || ":" || veil_id). Batch C (D5):
    // the old raw-nonce form (b53) is no longer accepted.
    const nonceBytes = b64d(nonceRow.nonce);
    const labelled = new Uint8Array([...enc.encode("vardum-identity-bind-v1:"), ...nonceBytes, ...enc.encode(":" + veilId)]);
    const sigIn = String(body.signature || "");
    const ok = await ed25519Verify(String(rec.IK_pub), labelled, sigIn);
    if (!ok) return j({ error: "Signature verification failed", message: "Signature verification failed" }, 403);
    // Batch C (B1 follow-up): the identity belongs to the account that just
    // proved the key — not to whichever account registered the row first
    // (a pre-registration of someone else's IK can't capture their bind)
    const callerHash = await accountHashOf(auth.userId);
    // b76 (registration lock): moving a BOUND identity to another account is a restore onto a new
    // account — while the holding account's lock is active it needs that lock's PIN proof
    // (`reglock_pin`), checked only now that the caller proved the key (so nobody without the
    // 24 words can spend the lock's attempts). Refused: 423, and the nonce stays for a retry.
    if (rec.bound === true && String(rec.account_hash || "") !== callerHash) {
      const lg = await regLockGate(String(rec.account_hash || ""), body, false);
      if (lg.refused) return lg.refused;
    }
    // b77u (audit 6 R4 #28): an account with a primary identity takes a SECOND identity only when the primary signs an
    // "add identity" proof over this bind's nonce: `vardum-add-identity-v1:<userId>:<veil_id>:<nonce>` (body.add_proof
    // = {veil_id: <primary>, sig}). A password holder used to bind their own identity beside the owner's. Re-binding
    // the primary itself, or an identity already bound here, needs none. (No proof: 403 code add_identity_proof.)
    const userNow = (await KV.get<Record<string, any>>(["user", auth.userId], { consistency: "strong" })).value;
    if (!userNow) return ACCOUNT_GONE_WRITE();
    let primaryNow = await ensurePrimaryIdentity(auth.userId);
    const alreadyHere = rec.bound === true && String(rec.account_hash || "") === callerHash;
    const created = Date.parse(String(userNow.created || "")) || 0;
    const tokenFresh = Date.now() - ((auth as { tokenCreated?: number }).tokenCreated || 0) <= PRIMARY_FRESH_SIGNIN_MS;
    let onboard = !primaryNow && !!created && Date.now() - created <= PRIMARY_ONBOARD_MS && tokenFresh;
    // b77u2 (UC-L4): an account with no primary (a late first bind, an older account) used to stay without one for
    // good: no reglock, no rebind, and a password holder could bind a second identity with no add_proof. Now a bind that
    // proves the CURRENT password (body.current_password, checked as a sign-in checks it) records a primary
    // (primary_trust "password"): the OLDEST identity already bound to the account, or, only when none is bound,
    // this one (a password holder then gains nothing the password didn't give, and the owner has no identity to lose).
    // Only an identity bound from a fresh sign-in (bound_fresh), from before bound_at, or the one being re-bound with
    // the password now, can be chosen: one bound with an old (stolen) token never becomes primary (b70 re-review 4).
    // Without the password such a bind never becomes primary, and it can't add an identity beside a bound one
    // (403 code current_password_required). (spec §8.2)
    let pwPrimarySelf = false;
    if (!primaryNow) {
      const boundHere: { vid: string; at: number; ok: boolean }[] = [];
      // (an onboarding account's first bind skips the scan: nothing can be bound to it yet — every bind since b77u sets
      // first_bind_at — so a sign-up doesn't read every identity row)
      const scan = !(onboard && !userNow.first_bind_at);
      if (scan) for await (const e of KV.list<Record<string, unknown>>({ prefix: ["veil_identity"] }, { consistency: "strong" })) {
        const r = e.value;
        if (!r || r.bound !== true || String(r.account_hash || "") !== callerHash) continue;
        const vid = String(r.veil_id || e.key[1] || "");
        // rows from before bound_at existed are older than any that have it
        const at = r.bound_at ? (Date.parse(String(r.bound_at)) || Infinity) : (Date.parse(String(r.created_date || "")) || 0) - 1e15;
        boundHere.push({ vid, at, ok: !r.bound_at || r.bound_fresh === true || vid === veilId });
      }
      const others = boundHere.filter((b) => b.vid !== veilId);
      // an onboarding bind never makes a primary beside an identity that could be one (an old-token bind can't)
      if (others.some((b) => b.ok) && !alreadyHere) onboard = false;
      const cur = typeof body.current_password === "string" ? body.current_password : "";
      if (cur && !onboard) {
        if (!req) return j({ message: "Enter your current password", code: "current_password_required" }, 403);
        const refused = await accountPasswordRefusal(req, { ...userNow, id: auth.userId }, body, cur, "bindpw-day");
        if (refused) return refused;
        const cands = boundHere.filter((b) => b.ok).sort((a, b) => a.at - b.at || (a.vid < b.vid ? -1 : 1));
        const target = cands.length ? cands[0].vid : (others.length && !alreadyHere) ? "" : veilId;
        // bound identities, none of which may become primary, and this one new beside them: nothing is recorded
        if (!target) return j({ error: "Bind the Vardum ID already on this account again first", message: "Bind the Vardum ID already on this account again first", code: "current_password_required" }, 403);
        if (target === veilId) pwPrimarySelf = true; // recorded with the bind itself, below
        else {
          for (let attempt = 0; attempt < 10; attempt++) {
            const ue = await liveAccountEntry(auth.userId);
            if (!ue) return ACCOUNT_GONE_WRITE();
            const u = ue.value as Record<string, any>;
            if (typeof u.primary_veil_id === "string" && u.primary_veil_id) break; // another step set one first
            if ((await KV.atomic().check(ue).set(["user", auth.userId], { ...u, primary_veil_id: target, primary_trust: "password", primary_scan_none: true }).commit()).ok) break;
          }
          primaryNow = await ensurePrimaryIdentity(auth.userId);
        }
      } else if (!onboard && others.length && !alreadyHere) {
        return j({ error: "Enter your current password to add a Vardum ID to this account", message: "Enter your current password to add a Vardum ID to this account", code: "current_password_required" }, 403);
      }
    }
    if (primaryNow && primaryNow !== veilId && !alreadyHere) {
      const ap = (body.add_proof ?? {}) as { veil_id?: unknown; sig?: unknown };
      const prow = (await KV.get<Record<string, unknown>>(["veil_identity", keySafe(primaryNow)])).value;
      const apSig = String(ap.sig ?? "");
      const apOk = String(ap.veil_id ?? "") === primaryNow && !!prow && prow.bound === true && String(prow.account_hash || "") === callerHash
        && canonicalB64(apSig) && await ed25519Verify(String(prow.IK_pub || ""), enc.encode(`vardum-add-identity-v1:${auth.userId}:${veilId}:${nonceRow.nonce}`), apSig);
      if (!apOk) return j({ error: "Adding another Vardum ID to this account needs your current Vardum ID to approve it", message: "Adding another Vardum ID to this account needs your current Vardum ID to approve it", code: "add_identity_proof" }, 403);
    }
    // b77u (audit 6 U-M14): an ONBOARDING bind — from a fresh sign-in, while the account is new (PRIMARY_ONBOARD_MS) and
    // has no primary — makes this identity the primary (the first such bind wins, in one step with the user row). Nothing
    // else does: a bind on an older account without a primary never makes one.
    await KV.delete(nonceKey); // single use
    // b70 (re-review 2, H): when the identity becomes bound to THIS account
    // (first bind, or moved from another account). A rebind needs it to be
    // old; the identity's own age said nothing about how long it was here.
    // (Rows bound before this change have none; every move from now on sets it.)
    if (rec.bound !== true || String(rec.account_hash || "") !== callerHash) {
      // b76 (one-time prekeys): a pool published before this bind belongs to whoever held the ID
      // before; the phone binding now publishes its own (none is handed out meanwhile)
      await dropOpks(veilId);
      rec.bound_at = nowIso();
      // b70 (re-review 4): only a bind made right after a password sign-in may ever
      // make this identity the account's primary (a stolen token is not that fresh)
      rec.bound_fresh = Date.now() - ((auth as { tokenCreated?: number }).tokenCreated || 0) <= PRIMARY_FRESH_SIGNIN_MS;
    }
    rec.account_hash = callerHash;
    rec.bound = true;
    rec.updated_date = nowIso();
    // b77s (audit 4 RA-02): only while the account is live. b77u (U-M14): in the same step the account records its
    // first bind (first_bind_at) and, for an onboarding bind, its primary — checked against the user row as read, so
    // two first binds racing can't both become primary (the loser is an ordinary later bind)
    let wrote = false;
    for (let attempt = 0; attempt < 10 && !wrote; attempt++) {
      const ue = await liveAccountEntry(auth.userId);
      if (!ue) return ACCOUNT_GONE_WRITE();
      const u = ue.value as Record<string, any>;
      const noPrimary = !(typeof u.primary_veil_id === "string" && u.primary_veil_id);
      const stillOnboard = onboard && noPrimary;
      const stillPw = !stillOnboard && pwPrimarySelf && noPrimary; // b77u2 (UC-L4)
      const r2 = stillOnboard ? { ...rec, bound_onboard: true } : rec;
      const tx = KV.atomic().check(ue).set(["veil_identity", veilId], r2);
      if (!u.first_bind_at || stillOnboard || stillPw) tx.set(["user", auth.userId], { ...u, first_bind_at: u.first_bind_at || nowIso(), ...(stillOnboard ? { primary_veil_id: veilId, primary_trust: "onboard" } : {}), ...(stillPw ? { primary_veil_id: veilId, primary_trust: "password", primary_scan_none: true } : {}) });
      wrote = (await tx.commit()).ok;
      if (!wrote) await new Promise((r) => setTimeout(r, Math.random() * 5));
    }
    if (!wrote) return j({ error: "Try again", message: "Try again" }, 409);
    await dropPendingIdentities(veilId); // b75r1 (audit REL-02): held registrations are moot once the key holder bound
    return json({ ok: true, data: { bound: true } });
  }
  if (action === "handover") {
    { const lim = await routeLimited("handover", auth.userId, 10); if (lim) return lim; } // b70 (re-review 7)
    // b70 (re-review 3): the primary identity names its successor (the app does
    // this when "Generate new Vardum ID" could not finish moving the sign-in,
    // so a later retry signed by the new ID works)
    const next = String(body.next_veil_id ?? ""), ts = Number(body.ts), sig = String(body.sig ?? "");
    if (!next || !Number.isFinite(ts) || !sig || next.length > MAX_KEY_PART) return j({ error: "Invalid handover", message: "Invalid handover" }, 400);
    if (Math.abs(Date.now() - ts) > 10 * 60_000) return j({ error: "This request is too old — try again", message: "This request is too old — try again" }, 403);
    const mine = await accountHashOf(auth.userId);
    const cur = (await KV.get<Record<string, unknown>>(["veil_identity", keySafe(veilId)])).value;
    const nid = (await KV.get<Record<string, unknown>>(["veil_identity", keySafe(next)])).value;
    if (!cur || cur.bound !== true || String(cur.account_hash || "") !== mine || veilId !== await ensurePrimaryIdentity(auth.userId)) return j({ error: "Not authorised", message: "Not authorised" }, 403);
    if (!nid || nid.bound !== true || String(nid.account_hash || "") !== mine) return j({ error: "The new Vardum ID isn't set up on this account yet", message: "The new Vardum ID isn't set up on this account yet" }, 409);
    if (!(await ed25519Verify(String(cur.IK_pub || ""), enc.encode(`vardum-primary-v1:${auth.userId}:${next}:${ts}`), sig))) return j({ error: "Not authorised", message: "Not authorised" }, 403);
    const ue = await KV.get<Record<string, any>>(["user", auth.userId]);
    // b75r1 (audit REL-01): the retiring identity's row goes in the same step — it stops
    // answering lookup and the database no longer holds two identity rows under one account
    // hash (only the account itself still links the two IDs; spec §8.2)
    // b76 (registration lock): the lock's PIN proof is salted with the retiring identity's seed,
    // so it ends in the same step (as at a rebind that moves the primary)
    const lockEntry = await KV.get<RegLockRow>(regLockKey(mine));
    const htx = KV.atomic().check(ue).check(lockEntry).delete(lockEntry.key);
    const trustH = ue.value && await primaryTrusted(ue.value) ? "chain" : "untrusted"; // b77u (U-M14): a handover passes on the trust it had
    if (!ue.value || !(await htx.set(["user", auth.userId], { ...ue.value, primary_veil_id: next, primary_trust: trustH }).delete(["veil_identity", keySafe(veilId)]).commit()).ok) return j({ error: "Try again", message: "Try again" }, 409);
    await dropRetiredIdentityRows(veilId);
    return json({ ok: true, ...(lockEntry.value ? { reglock_off: true } : {}) });
  }
  if (action === "lookup") {
    const rl = await rateLimit("idlookup:" + auth.userId, 300, 60_000, 2);
    if (rl) return j({ locked: true, retry_minutes: rl.retry_minutes }, 429);
    const rec = (await KV.get<Record<string, unknown>>(["veil_identity", veilId])).value;
    // lookup serves BOUND identities only — binding is the key-possession proof;
    // an unbound (unproven) record would let an attacker publish fake keys
    if (!rec || rec.bound !== true) return j({ error: "Identity not found", message: "Identity not found" }, 404);
    // b198: BARE bundle — exactly Base44's lookup shape (Response.json({veil_id,
    // ...keys...})). My {data:...} wrap made the group rotate's pq_pub read
    // resolve undefined ("no published PQ prekey") while the key sat published
    // on the row; the other lookup consumers were already shape-tolerant.
    const bundle = { veil_id: rec.veil_id, IK_pub: rec.IK_pub, SPK_pub: rec.SPK_pub, SPK_sig: rec.SPK_sig, pq_pub: rec.pq_sig ? rec.pq_pub : "", pq_sig: rec.pq_sig || "" }; // b77p (audit VAR-37): an unsigned PQ key (older rows) is never served
    if (body.claim_opk !== true) return json(bundle);
    // b76 (one-time prekeys): a contact chat is starting — hand out one one-time pair with the
    // bundle. Only to an account whose own Vardum ID (requester_veil_id) is bound to it, never for
    // the ID itself, and within the caps above. Otherwise, or when the pool is empty, the signed
    // prekeys alone are served and the answer says so (opk: null, last_resort: true, opk_status).
    const lastResort = (status: string) => json({ ...bundle, opk: null, last_resort: true, opk_status: status });
    const reqVid = String(body.requester_veil_id ?? "");
    if (!reqVid || reqVid === veilId || reqVid.length > MAX_VEIL_ID) return lastResort("not_eligible");
    const rid0 = (await KV.get<Record<string, unknown>>(["veil_identity", keySafe(reqVid)])).value;
    if (!rid0 || rid0.bound !== true || String(rid0.account_hash || "") !== await accountHashOf(auth.userId)) return lastResort("not_eligible");
    if (await rateLimit("opkclaim:" + auth.userId, OPK_CLAIMS_PER_ACCOUNT_PER_HOUR, 3_600_000, 0)) return lastResort("limited");
    if (await rateLimit(await opkPairKey(auth.userId, veilId), OPK_CLAIMS_PER_PAIR_PER_DAY, 86_400_000, 0)) return lastResort("limited"); // b76r2 (audit OP-1): opaque tags
    // b77m (audit VAR-09): per network (to this ID, and to every ID), then the shared per-ID budget
    // for NEW accounts only (see OPK_CLAIMS_PER_PAIR_PER_DAY)
    const vt = await vidTag(veilId);
    const net = req ? await clientTag(req) : "local";
    if (net !== "local") {
      const wide = await clientWideTags(req!);
      // b77m (owner, carrier NAT): past a per-network cap the answer is still the signed prekeys (opk: null), now
      // with the network puzzle beside it (opk_status "pow_required"); the app may solve it and ask again for a
      // one-time pair (relay.ts identityLookup). A refused or unsolved puzzle leaves the last-resort answer, as before.
      const over = await rateLimit("opknett:" + net + ":" + vt, OPK_CLAIMS_PER_NETWORK_TARGET_PER_DAY, 86_400_000, 0)
        || await wideRateLimit("opknett:" + vt, wide, OPK_CLAIMS_PER_NETWORK_TARGET_PER_DAY, 86_400_000, 0)
        || await rateLimit("opknet:" + net, OPK_CLAIMS_PER_NETWORK_PER_HOUR, 3_600_000, 0)
        || await wideRateLimit("opknet", wide, OPK_CLAIMS_PER_NETWORK_PER_HOUR, 3_600_000, 0);
      if (over) {
        // b77t (audit 5 L-10, IH R-02): puzzles lift the per-network caps by at most OPK_POW_CLAIMS_PER_TARGET_PER_DAY
        // pairs a day per Vardum ID, from every network together — a HARD ceiling. Solved puzzles used to fall through
        // to a claim each, turning the 4-a-day network cap into ~36 (/64) or ~512 (/48) and draining the pool. Past
        // the ceiling no puzzle is offered (the signed prekeys alone, as at any cap).
        if (await rateFull("opkpowt:" + vt, OPK_POW_CLAIMS_PER_TARGET_PER_DAY, 86_400_000)) return lastResort("limited");
        const g = await netPowGate(req!, "opknet:" + vt, OPK_CLAIMS_PER_NETWORK_TARGET_PER_DAY, 86_400_000, body, "limited");
        if (g) {
          const d = await g.json().catch(() => ({})) as Record<string, unknown>;
          if (d.pow_required) return json({ ...bundle, opk: null, last_resort: true, opk_status: "pow_required", pow_required: true, pow_challenge: d.pow_challenge, pow_bits: d.pow_bits, pow_prefix: d.pow_prefix });
          return lastResort("limited");
        }
        // a solved puzzle: counted against the ceiling now (atomically; a race past it is refused here)
        if (await rateLimit("opkpowt:" + vt, OPK_POW_CLAIMS_PER_TARGET_PER_DAY, 86_400_000, 0)) return lastResort("limited");
      }
    }
    const me = (await KV.get<Record<string, unknown>>(["user", auth.userId])).value;
    const age = Date.now() - (Date.parse(String(me?.created || "")) || Date.now());
    if (age < OPK_SEASONED_ACCOUNT_MS && await rateLimit("opktarget:" + vt, OPK_CLAIMS_PER_TARGET_PER_DAY, 86_400_000, 0)) return lastResort("limited");
    const opk = await claimOpk(veilId);
    if (!opk) return lastResort("exhausted");
    return json({ ...bundle, opk, last_resort: false, opk_status: "one-time" });
  }
  if (action === "opk_drop") {
    // b76r1 (one-time prekeys): the owner empties its own pool — the app's Nothing-at-Rest close
    // destroys the private halves on the phone, so pairs left on the relay would only be handed out
    // to requests that then fail. Only the account the Vardum ID is bound to; under the pool's lock
    // (dropOpks). Answers how many pairs went.
    const lim = await rateLimit("opkdrop:" + auth.userId, 30, 3_600_000, 0);
    if (lim) return j({ locked: true, retry_minutes: lim.retry_minutes }, 429);
    const rec = (await KV.get<Record<string, unknown>>(["veil_identity", keySafe(veilId)])).value;
    if (!rec || rec.bound !== true || String(rec.account_hash || "") !== await accountHashOf(auth.userId)) return j({ error: "Not authorised", message: "Not authorised" }, 403);
    const dropped = await withLock("opk:" + veilId, async () => {
      let c = 0;
      for await (const _ of KV.list({ prefix: opkPrefix(veilId) }, { consistency: "strong" })) c++;
      await dropOpksLocked(veilId);
      return c;
    });
    return json({ ok: true, data: { dropped, count: 0 } });
  }
  if (action === "opk_upload" || action === "opk_count") {
    // b76 (one-time prekeys): only the account the Vardum ID is bound to manages its pool
    const lim = await rateLimit((action === "opk_upload" ? "opkup:" : "opkcount:") + auth.userId, action === "opk_upload" ? 30 : 120, 3_600_000, 0);
    if (lim) return j({ locked: true, retry_minutes: lim.retry_minutes }, 429);
    const rec = (await KV.get<Record<string, unknown>>(["veil_identity", keySafe(veilId)])).value;
    if (!rec || rec.bound !== true || String(rec.account_hash || "") !== await accountHashOf(auth.userId)) return j({ error: "Not authorised", message: "Not authorised" }, 403);
    const device = String(body.device ?? "");
    if (!OPK_DEVICE_RE.test(device)) return j({ error: "Invalid one-time keys", message: "Invalid one-time keys" }, 400);
    if (action === "opk_count") {
      const owner = (await KV.get<Record<string, unknown>>(opkOwnerKey(veilId))).value;
      const mine = !owner || String(owner.device || "") === device;
      return json({ ok: true, data: { count: mine ? await countOpks(veilId) : 0, mine, max: OPK_MAX_STORED } });
    }
    const list = Array.isArray(body.opks) ? body.opks as Record<string, unknown>[] : null;
    const bad = (why: string) => j({ error: "Invalid one-time keys: " + why, message: "Invalid one-time keys: " + why }, 400);
    if (!list || !list.length || list.length > OPK_UPLOAD_MAX) return bad("count");
    const nowMs = Date.now();
    const rows: { id: string; x_pub: string; pq_pub: string; sig: string; ts: string }[] = [];
    const seen = new Set<string>();
    for (const o of list) {
      if (!o || typeof o !== "object") return bad("shape");
      const id = String(o.id ?? ""), xPub = String(o.x_pub ?? ""), pqPub = String(o.pq_pub ?? ""), sig = String(o.sig ?? "");
      if (!OPK_ID_RE.test(id) || seen.has(id)) return bad("id");
      seen.add(id);
      if (!canonicalB64(xPub) || b64d(xPub).length !== 32 || !canonicalB64(pqPub) || b64d(pqPub).length !== 1184) return bad("key");
      const m = /^([A-Za-z0-9+/]{86}==)\.([1-9][0-9]{0,11})$/.exec(sig);
      if (!m || !canonicalB64(m[1])) return bad("signature");
      const tsMs = Number(m[2]) * 1000;
      if (nowMs - tsMs > OPK_RELAY_TTL_MS || tsMs - nowMs > 86_400_000) return bad("date");
      const msg = new Uint8Array([...enc.encode("vardum-opk-v1:" + id + ":"), ...b64d(xPub), ...b64d(pqPub), ...enc.encode(":" + m[2])]);
      if (!(await ed25519Verify(String(rec.IK_pub), msg, m[1]))) return bad("signature");
      rows.push({ id, x_pub: xPub, pq_pub: pqPub, sig, ts: m[2] });
    }
    return withLock("opk:" + veilId, async () => {
      // b76r1 (one-time prekeys): the identity is read again now that the pool's lock is held — a
      // duress purge, handover, rebind or delete that ran while the pairs were being verified has
      // removed it (or it moved to another account, or its key changed), and nothing may be written
      // for it then (see dropOpks)
      const now = (await KV.get<Record<string, unknown>>(["veil_identity", keySafe(veilId)], { consistency: "strong" })).value;
      if (!now || now.bound !== true || String(now.account_hash || "") !== String(rec.account_hash || "") || String(now.IK_pub || "") !== String(rec.IK_pub || "")) return j({ error: "Not authorised", message: "Not authorised" }, 403);
      // b76r2 (audit OP-2): a pair the relay already handed out is never taken back (checked under
      // the pool's lock, which a claim holds while it deletes the pair and writes its marker)
      for (const r of rows) if ((await KV.get(await opkServedKey(veilId, r.id), { consistency: "strong" })).value !== null) return bad("already used");
      const owner = (await KV.get<Record<string, unknown>>(opkOwnerKey(veilId))).value;
      const replace = body.replace === true || !owner || String(owner.device || "") !== device;
      if (replace) await dropOpksLocked(veilId);
      const have = replace ? 0 : await countOpks(veilId, nowMs);
      if (have + rows.length > OPK_MAX_STORED) return j({ error: "Too many one-time keys", message: "Too many one-time keys", count: have }, 409);
      for (const r of rows) {
        const left = OPK_RELAY_TTL_MS - (nowMs - Number(r.ts) * 1000);
        await KV.set([...opkPrefix(veilId), r.ts.padStart(12, "0"), r.id], r, { expireIn: Math.max(60_000, left) });
      }
      await KV.set(opkOwnerKey(veilId), { device, updated_date: nowIso() });
      return json({ ok: true, data: { count: have + rows.length, mine: true, replaced: replace } });
    });
  }
  return j({ error: "Unknown action", message: "Unknown action" }, 400);
}

// ---------- veilSessionGate — the full action set ----------
function wsHashOf(writeSecret: unknown) {
  return writeSecret ? sha256hex(String(writeSecret)) : "";
}

function sessionMatchesClient(session: Record<string, any>, clientId: string, veilId?: string) {
  if (clientId) {
    if (String(session.initiator_client_id || "") === clientId) return true;
    if (String(session.responder_client_id || "") === clientId) return true;
  }
  if (veilId) {
    if (String(session.initiator_veil_id || "") === veilId) return true;
    if (String(session.responder_veil_id || "") === veilId) return true;
  }
  return false;
}

/**
 * b71 (audit F-09): secondary indexes for envelopes, so the hot paths (a chat's poll,
 * a group's poll, a chat's deletion) read only that chat's rows instead of scanning
 * every envelope on the relay. ["env_by_sess", session_token, id] for every envelope,
 * ["env_by_group", group_token, id] for group posts. Written with the envelope in one
 * atomic step, removed with it (deleteEnvelopeRow), rebuilt at boot (backfillEnvelopeIndex).
 */
function envIndexKeys(row: Record<string, unknown>, id: string): Deno.KvKey[] {
  const keys: Deno.KvKey[] = [];
  if (row.session_token) keys.push(["env_by_sess", keySafe(String(row.session_token)), id]);
  if (row.group_token) keys.push(["env_by_group", keySafe(String(row.group_token)), id]);
  if (row.mbox) keys.push(["env_by_mbox", keySafe(String(row.mbox)), id]); // b77 (sealed sender)
  return keys;
}
/** an envelope row and its index entries, gone together */
async function deleteEnvelopeRow(key: Deno.KvKey, row: Record<string, unknown> | null): Promise<void> {
  const tx = KV.atomic().delete(key);
  if (row) for (const k of envIndexKeys(row, String(key[key.length - 1]))) tx.delete(k);
  // b76r2 (audit GB-1): a group envelope's burn snapshot and votes go with it (they used to wait for their expiry)
  if (row?.group_token) tx.delete(["burn_elig", keySafe(String(key[key.length - 1]))]).delete(["burn_votes", keySafe(String(key[key.length - 1]))]);
  await tx.commit();
}
/** b75r1 (audit REL-07): past its expires_at (a row without a readable one never counts as expired) */
function envelopeExpired(row: Record<string, unknown> | null | undefined): boolean {
  const exp = Date.parse(String(row?.expires_at ?? ""));
  return Number.isFinite(exp) && exp < Date.now();
}
/** the envelopes one index prefix points at (a stale entry is dropped on the way) */
async function* envelopesByIndex(prefix: Deno.KvKey, field: "session_token" | "group_token", value: string): AsyncGenerator<{ key: Deno.KvKey; value: Record<string, unknown> }> {
  for await (const ix of KV.list({ prefix }, { consistency: "strong" })) {
    const key: Deno.KvKey = ["entity", "VeilEnvelope", String(ix.key[2])];
    const got = await KV.get<Record<string, unknown>>(key);
    if (!got.value || String(got.value[field] || "") !== value) { await KV.delete(ix.key); continue; }
    yield { key, value: got.value };
  }
}
const envelopesOfSession = (token: string) => envelopesByIndex(["env_by_sess", keySafe(token)], "session_token", token);
const envelopesOfGroup = (groupToken: string) => envelopesByIndex(["env_by_group", keySafe(groupToken)], "group_token", groupToken);
/** once, at boot: index every envelope stored before the index existed, drop stale entries */
async function backfillEnvelopeIndex(): Promise<number> {
  let n = 0;
  for await (const e of KV.list<Record<string, unknown>>({ prefix: ["entity", "VeilEnvelope"] }, { consistency: "strong" })) {
    if (!e.value) continue;
    for (const k of envIndexKeys(e.value, String(e.key[2]))) {
      if ((await KV.atomic().check({ key: k, versionstamp: null }).set(k, 1).commit()).ok) n++;
    }
  }
  for (const p of ["env_by_sess", "env_by_group", "env_by_mbox"]) {
    for await (const ix of KV.list({ prefix: [p] }, { consistency: "strong" })) {
      if (!(await KV.get(["entity", "VeilEnvelope", String(ix.key[2])])).value) await KV.delete(ix.key);
    }
  }
  return n;
}

async function deleteSessionEnvelopes(sessionToken: string) {
  let n = 0;
  // b71 (audit F-09): through the chat's index (was a scan of every envelope)
  for await (const e of envelopesOfSession(sessionToken)) { await deleteEnvelopeRow(e.key, e.value); n++; }
  // b199: legacy per-session copies under ["veil_env", token, id] (no longer
  // written; the sweeper drops old ones) die with the session too
  if (sessionToken) {
    for await (const e of KV.list({ prefix: ["veil_env", sessionToken] }, { consistency: "strong" })) await KV.delete(e.key);
  }
  return n;
}

// ---------- UnifiedPush / Web Push delivery (GrapheneOS: no Google) ----------
// Android phones without Google Play register a UnifiedPush endpoint (ntfy)
// instead of an Expo token: their VeilPushToken row carries
// expo_token "up:<endpoint>" + up_p256dh / up_auth. Every push site below
// calls pushFetch() exactly where it used to call fetch() on Expo: Expo tokens
// go to Expo unchanged; "up:" tokens get a Web Push (RFC 8030) with an RFC
// 8291 aes128gcm body that only the phone can decrypt. Same contentless
// threat model: the only plaintext the phone sees is {"kind": ...}; the push
// server (ntfy) sees ciphertext and timing only.
const EXPO_PUSH_URL = "https://exp.host/--/api/v2/push/send";
/** b77m (audit VAR-46): what a push log line says about Expo's answer — its ticket status and, on an
 *  error, the error NAME (details.error, e.g. DeviceNotRegistered), never its `message`: Expo's
 *  messages embed the ExponentPushToken[…] the push went to, and a token holder can push to that
 *  phone (the relay sends without an Expo access token) */
function expoTicketLog(d: unknown, httpStatus: number): string {
  const data = (d as { data?: { status?: unknown; details?: { error?: unknown } } } | null)?.data;
  const status = typeof data?.status === "string" && /^[a-z]{1,20}$/.test(data.status) ? data.status : "http-" + httpStatus;
  const err = data?.details?.error;
  return status + (typeof err === "string" && /^[A-Za-z]{1,40}$/.test(err) ? " (" + err + ")" : "");
}
/** b75 round 2 (audit D7): the ONLY banner text any push carries, for every kind (message,
 *  invite, group, call): fixed and neutral, no name, no kind-specific wording. On iOS and
 *  with Google push the OS shows this text itself while Vardum is in the background. */
const PUSH_TITLE = "Vardum";
/** b77p (audit 2 VAR-14): "Notification" — the one text the app's own banners use too (it was "New activity") */
const PUSH_BODY = "Notification";
/** b77p (audit 2 VAR-35 / VAR-14): EVERY activity push has this one payload — message or call wake: the same text,
 *  and data.kind "wake". Expo, APNs and FCM used to see kind "call" / "new-invite" / "new-message".
 *  (A UnifiedPush message is encrypted to the phone; its plaintext kind comes from pushFetch's upKind.)
 *  b77p round 2 (owner decision 1): there are no contact-request or group-post pushes any more (no account-level push).
 *  b77p round 2 (owner decision 2): a CALL wake rings again. On Expo the platform forces the ring into the
 *  provider-visible payload: iOS plays only a sound NAMED in the APNs payload (no notification service extension
 *  here to decide on the phone), and Android picks the sound by the notification CHANNEL, fixed per channel. So a
 *  call wake adds sound "veil_ring.wav" and channelId "vardum-ring" (what Expo / APNs / FCM can now see on a call,
 *  beside the 9-push burst pattern that already showed it); the text and data.kind stay the same. On UnifiedPush the
 *  ring is decided on the phone from the kind inside the Web Push encryption (the push server sees no difference). */
const PUSH_WIRE_KIND = "wake";
const RING_SOUND = "veil_ring.wav"; // b77 rollout: matches the res/raw name Android needs (no hyphens)
const RING_CHANNEL = "vardum-ring";
function activityPush(to: string, ring = false): RequestInit {
  const msg = ring
    ? { to, title: PUSH_TITLE, body: PUSH_BODY, sound: RING_SOUND, priority: "high", channelId: RING_CHANNEL, data: { kind: PUSH_WIRE_KIND } }
    : { to, title: PUSH_TITLE, body: PUSH_BODY, sound: "default", priority: "high", data: { kind: PUSH_WIRE_KIND } };
  return { method: "POST", headers: { "Content-Type": "application/json", "Accept": "application/json" }, body: JSON.stringify(msg) };
}
const UP_TOKEN_PREFIX = "up:";
// SSRF guard: the endpoint is client-supplied, so the relay only ever POSTs
// to push servers on this list (https, default port, no redirects).
// VEIL_UP_HOSTS adds more, comma-separated (e.g. the self-hosted ntfy).
const UP_ALLOWED_HOSTS = new Set<string>([
  "ntfy.sh",
  ...String(Deno.env.get("VEIL_UP_HOSTS") || "").split(",").map((s) => s.trim().toLowerCase()).filter(Boolean),
]);
const upTe = new TextEncoder();

function upB64uDecode(s: string): Uint8Array {
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/").replace(/=+$/, "");
  const pad = b64.length % 4 === 0 ? "" : "=".repeat(4 - (b64.length % 4));
  const bin = atob(b64 + pad);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function upConcat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

async function upHkdf(salt: Uint8Array, ikm: Uint8Array, info: Uint8Array, bytes: number): Promise<Uint8Array> {
  const k = await crypto.subtle.importKey("raw", ikm as unknown as BufferSource, "HKDF", false, ["deriveBits"]); // Batch G: type-only casts (Deno 2 Uint8Array typing)
  return new Uint8Array(await crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt: salt as unknown as BufferSource, info: info as unknown as BufferSource }, k, bytes * 8));
}

/** RFC 8291 aes128gcm Web Push encryption (single record). `opts` is for the RFC test vector only. */
async function webPushEncrypt(
  uaPublicB64u: string,
  authB64u: string,
  plaintext: Uint8Array,
  opts?: { asKeyPair?: CryptoKeyPair; salt?: Uint8Array },
): Promise<Uint8Array> {
  const uaPublic = upB64uDecode(uaPublicB64u);
  const auth = upB64uDecode(authB64u);
  if (uaPublic.length !== 65 || uaPublic[0] !== 0x04 || auth.length !== 16) throw new Error("bad web push keys");
  const asKp = opts?.asKeyPair ?? await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]) as CryptoKeyPair;
  const asPublic = new Uint8Array(await crypto.subtle.exportKey("raw", asKp.publicKey));
  const uaKey = await crypto.subtle.importKey("raw", uaPublic as unknown as BufferSource, { name: "ECDH", namedCurve: "P-256" }, false, []);
  const ecdh = new Uint8Array(await crypto.subtle.deriveBits({ name: "ECDH", public: uaKey }, asKp.privateKey, 256));
  const ikm = await upHkdf(auth, ecdh, upConcat(upTe.encode("WebPush: info\0"), uaPublic, asPublic), 32);
  const salt = opts?.salt ?? crypto.getRandomValues(new Uint8Array(16));
  const cek = await upHkdf(salt, ikm, upTe.encode("Content-Encoding: aes128gcm\0"), 16);
  const nonce = await upHkdf(salt, ikm, upTe.encode("Content-Encoding: nonce\0"), 12);
  const key = await crypto.subtle.importKey("raw", cek as unknown as BufferSource, "AES-GCM", false, ["encrypt"]);
  // single record: plaintext + 0x02 delimiter (last record), no padding
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce as unknown as BufferSource }, key, upConcat(plaintext, new Uint8Array([2])) as unknown as BufferSource));
  const header = new Uint8Array(21 + asPublic.length);
  header.set(salt, 0);
  new DataView(header.buffer).setUint32(16, 4096);
  header[20] = asPublic.length;
  header.set(asPublic, 21);
  return upConcat(header, ct);
}

// Batch H (round-6 review R6-3-01): the endpoint must be a plain topic on an
// allowed host. A path or query used to be free, so a row could make the relay
// call any of the push host's API (for example ntfy.sh publish options).
const UP_TOPIC_RE = /^\/[A-Za-z0-9_-]{1,64}$/;
function upEndpointAllowed(raw: string): boolean {
  try {
    const u = new URL(raw);
    return u.protocol === "https:" && (u.port === "" || u.port === "443") && !u.username && !u.password &&
      UP_ALLOWED_HOSTS.has(u.hostname.toLowerCase()) &&
      UP_TOPIC_RE.test(u.pathname) && (u.search === "" || u.search === "?up=1") && u.hash === "";
  } catch { return false; }
}

/** Batch H (N6-1 / R6-3-03): Web Push keys of the right shape (P-256 point, 16-byte auth) */
function upKeysValid(p256: unknown, auth: unknown): boolean {
  try {
    const p = upB64uDecode(String(p256 || "")), a = upB64uDecode(String(auth || ""));
    return p.length === 65 && p[0] === 4 && a.length === 16;
  } catch { return false; }
}
/** Batch H (R6-3-01): push rows one account may hold (the oldest is replaced) */
const PUSH_ROWS_PER_ACCOUNT = 5;
/** Batch H (R6-3-07): every Web Push plaintext is padded to this length */
const UP_PLAINTEXT_LEN = 64;

/** b71 (audit F-19): pushes one push address receives per hour (a call ring is 9; messages
 *  coalesce per 30 s per chat). b75r2 (audit R2-01): counted per (address, notified
 *  account) — see pushCapKey. */
const PUSHES_PER_TARGET_PER_HOUR = 240;
/** b71 (audit F-15/F-19): limiter and challenge rows name a push address only by a hash */
const pushTargetTag = (token: string) => sha256hex("veil-push-target:" + token);
/** b75r2 (audit R2-01): the hourly push cap's limiter key, per push address AND per account
 *  the push is for. A UnifiedPush address can be held by two accounts at once (b75 PU-1: the
 *  owner's row and a squatter's who can read the public ntfy topic), and the cap used to be
 *  shared: the squatter could spend the whole hour's allowance on events on its own account
 *  (pushes the phone can't even decrypt) and the owner's real pings were then "capped". Now
 *  each account has its own allowance on the address. That doesn't let a squatter buzz the
 *  phone any more than before in a way that matters: its pushes are encrypted to its own keys
 *  (the phone drops them, no banner), each squatting account needs its own possession proof
 *  and its own sign-up, and anyone who knows a public topic can post to it directly anyway.
 *  An Expo token has one holder at a time (F-19), so for it nothing changes. The account
 *  part is a hash too (F-15: limiter rows never name an account in clear); "-" is a push
 *  with no account (an Expo possession challenge, itself limited per address by pushchal:). */
async function pushCapKey(token: string, forAcct: string): Promise<string> {
  const who = forAcct ? (await sha256hex("veil-push-cap-acct:" + forAcct)).slice(0, 32) : "-";
  return "pushto:" + await pushTargetTag(token) + ":" + who;
}
/** b71 (audit F-19): the possession challenge for a push address another account holds */
const PUSH_CHALLENGE_TTL_MS = 10 * 60_000;
/** b74 (audit VAR-13): the Web Push keys a UnifiedPush registration names */
type UpKeys = { p256: string; auth: string };
/** b74 (audit VAR-13): what a challenge record holds — the code's hash, bound (for a
 *  UnifiedPush address) to the keys it was encrypted to, so a proof only ever confirms
 *  that key set */
/** b74 (audit VAR-13): one open challenge per (address, account) — and, for UnifiedPush,
 *  per key set, so a registration naming other keys doesn't void the real phone's code */
const pushChallengeKey = async (token: string, acct: string, keys: UpKeys | null): Promise<Deno.KvKey> =>
  keys ? ["push_challenge", await pushTargetTag(token), acct, (await sha256hex(keys.p256 + ":" + keys.auth)).slice(0, 32)] : ["push_challenge", await pushTargetTag(token), acct];
const pushCodeHash = (code: string, keys: UpKeys | null) => sha256hex("veil-push-code:" + code + (keys ? ":" + keys.p256 + ":" + keys.auth : ""));
async function sendPushChallenge(token: string, acct: string, upKeys: UpKeys | null = null): Promise<boolean> {
  try {
    const tag = await pushTargetTag(token);
    if (upKeys) {
      // b74 (audit VAR-13): a UnifiedPush address gets the challenge as a Web Push encrypted
      // to the submitted keys. One per (address, key set) per TTL, so a registration naming
      // other keys can't hold back the real phone's; a few per account an hour; and the
      // address's own hourly push cap applies.
      if (!upKeysValid(upKeys.p256, upKeys.auth)) return false;
      if (await rateLimit("pushchal-acct:" + acct, 6, 3600_000, 0)) return false;
      if (await rateLimit("pushchal:" + tag + ":" + (await sha256hex(upKeys.p256 + ":" + upKeys.auth)).slice(0, 32), 1, PUSH_CHALLENGE_TTL_MS, 0)) return true;
      const code = upChallengeCode();
      await KV.set(await pushChallengeKey(token, acct, upKeys), await pushCodeHash(code, upKeys), { expireIn: PUSH_CHALLENGE_TTL_MS });
      void sendUnifiedPushChallenge(token, upKeys, code, acct).then((s) => console.log("[push] unifiedpush push-verify: " + s)).catch(() => undefined);
      return true;
    }
    // one challenge per address per TTL, whoever asks (a phone can't be buzzed by it:
    // the push is silent, data only)
    if (await rateLimit("pushchal:" + tag, 1, PUSH_CHALLENGE_TTL_MS, 0)) return true;
    const code = b64e(crypto.getRandomValues(new Uint8Array(16))).replace(/[+/=]/g, "");
    await KV.set(["push_challenge", tag, acct], await pushCodeHash(code, null), { expireIn: PUSH_CHALLENGE_TTL_MS });
    // fire-and-forget, like every other push (the request doesn't wait on Expo)
    void pushFetch(EXPO_PUSH_URL, { method: "POST", headers: { "Content-Type": "application/json", "Accept": "application/json" }, body: JSON.stringify({ to: token, priority: "high", _contentAvailable: true, data: { kind: "push-verify", code } }) })
      .then((r) => r.body?.cancel()).catch(() => undefined);
    return true;
  } catch { return false; }
}
async function pushChallengeOk(token: string, acct: string, code: string, upKeys: UpKeys | null = null): Promise<boolean> {
  if (!code || code.length > 64) return false;
  const k = await pushChallengeKey(token, acct, upKeys);
  const got = await KV.get<string>(k);
  if (!got.value || !ctEq(got.value, await pushCodeHash(code, upKeys))) return false;
  return (await KV.atomic().check(got).delete(k).commit()).ok; // single use
}
/** b74 (audit VAR-13): a UnifiedPush challenge code — 80 random bits, base64url (14
 *  characters, so the push-verify message fits the one padded length every push has) */
function upChallengeCode(): string {
  return b64e(crypto.getRandomValues(new Uint8Array(10))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
/** b74 (audit VAR-13): the possession challenge for a UnifiedPush address — the same RFC
 *  8291 encryption and padded length as every other push, encrypted to the keys the
 *  registration names (not to whatever rows already exist), sent to the allowed endpoint
 *  only. The phone's push service keeps the code (no banner) and the app re-registers with
 *  it. Returns an Expo-style status string. */
async function sendUnifiedPushChallenge(token: string, keys: UpKeys, code: string, acct: string): Promise<string> {
  const url = token.slice(UP_TOKEN_PREFIX.length);
  if (!upEndpointAllowed(url)) return "up-host-not-allowed";
  if (!upKeysValid(keys.p256, keys.auth)) return "up-no-keys";
  // b75r2 (audit R2-01): counted against the registering account's allowance on the address
  if (await rateLimit(await pushCapKey(token, acct), PUSHES_PER_TARGET_PER_HOUR, 3600_000, 0)) return "capped";
  const plain = JSON.stringify({ kind: "push-verify", code, t: Date.now() });
  if (plain.length > UP_PLAINTEXT_LEN) return "up-too-long"; // (never: 14-character codes fit)
  const body = await webPushEncrypt(keys.p256, keys.auth, upTe.encode(plain.padEnd(UP_PLAINTEXT_LEN)));
  const r = await fetch(url, { method: "POST", headers: { "TTL": "86400", "Urgency": "high", "Content-Encoding": "aes128gcm", "Content-Type": "application/octet-stream" }, body: body as unknown as BodyInit, redirect: "manual", signal: AbortSignal.timeout(10_000) });
  await r.body?.cancel().catch(() => undefined);
  return r.ok ? "ok" : "up-http-" + r.status;
}

/** Send one contentless Web Push ping to a "up:" token. Returns an Expo-style status string. */
async function sendUnifiedPush(token: string, kind: string, forAcct = ""): Promise<string> {
  const url = token.slice(UP_TOKEN_PREFIX.length);
  if (!upEndpointAllowed(url)) return "up-host-not-allowed";
  // b70 (audit RLY-7): two accounts may hold a row for the same endpoint (one of
  // them possibly a squatter with made-up keys). Each distinct key set gets its
  // own ping, so the phone always receives the one encrypted to its real keys
  // (it drops the rest).
  // b75 (audit PU-1): and only the rows of the account being notified (forAcct). Since a
  // UnifiedPush proof no longer removes another account's row (createEntity), a squatter's
  // row and the victim's can share an endpoint: an event on the squatter's account is
  // never encrypted to the victim's keys (the victim's phone would show it), and an event
  // on the victim's account still reaches the victim's keys whatever the squatter did.
  const rows: { row: Record<string, unknown>; key: Deno.KvKey }[] = [];
  const allRows: Deno.KvKey[] = [];
  for await (const e of pushRowsOf(token)) { // b77n (pre-audit L3): by ["ix_push_tok"]
    const r = e.value as Record<string, unknown>;
    if (String(r.expo_token || "") !== token) continue;
    allRows.push(e.key);
    if (!forAcct || String(r._acct || "") === forAcct) rows.push({ row: r, key: e.key });
  }
  if (!rows.length) return "up-no-row";
  const k = kind === "call" ? "call" : kind === "new-invite" ? "new-invite" : "new-message";
  const seen = new Set<string>();
  let result = "up-no-keys";
  for (const { row } of rows) {
    const p256 = String(row.up_p256dh || "");
    const auth = String(row.up_auth || "");
    // Batch H (N6-1 / R6-3-03): no plaintext path — a row without valid keys gets nothing
    if (!upKeysValid(p256, auth) || seen.has(p256 + auth)) continue;
    seen.add(p256 + auth);
    // Batch H (round-6 review R6-3-07): one TTL and one padded length for every kind,
    // so no single UnifiedPush message tells the push server a call from a message.
    // b71 (audit F-26): the PATTERN still does — a call is a burst of CALL_BURST_COUNT
    // pushes 2.5 s apart, a message is one. (Expo/APNs/FCM pushes are worse: their
    // sound and channel ring on a call, b77p round 2; see activityPush.) The send time rides inside the
    // encryption; the phone rings (the calls channel, the same "Notification" text) only while it is fresh.
    const headers: Record<string, string> = { "TTL": "86400", "Urgency": "high" };
    const body = await webPushEncrypt(p256, auth, upTe.encode(JSON.stringify({ kind: k, t: Date.now() }).padEnd(UP_PLAINTEXT_LEN)));
    headers["Content-Encoding"] = "aes128gcm";
    headers["Content-Type"] = "application/octet-stream";
    const r = await fetch(url, { method: "POST", headers, body: body as unknown as BodyInit, redirect: "manual", signal: AbortSignal.timeout(10_000) });
    await r.body?.cancel().catch(() => undefined);
    if (r.status === 404 || r.status === 410) {
      // the distributor dropped this endpoint: prune the dead rows
      for (const k of allRows) await KV.delete(k).catch(() => undefined);
      return "up-gone";
    }
    if (result !== "ok") result = r.ok ? "ok" : "up-http-" + r.status;
  }
  return result;
}

/** Drop-in for fetch(EXPO_PUSH_URL, …) at every push site: routes "up:" tokens to Web Push.
 *  b75 (audit PU-1): `forAcct` is the account hash the push is for — a "up:" token's Web
 *  Push is then encrypted only to that account's own rows' keys (see sendUnifiedPush). */
async function pushFetch(url: string, init: RequestInit, forAcct = "", upKind = ""): Promise<Response> {
  let msg: Record<string, any> | null = null;
  try { msg = JSON.parse(String(init.body ?? "")); } catch { msg = null; }
  const to = String(msg?.to ?? "");
  // b71 (audit F-19): a per-address hourly cap, whatever event causes the push.
  // b75r2 (audit R2-01): per (address, notified account), so another account holding a row
  // for the same address can't spend the owner's allowance (pushCapKey)
  if (url === EXPO_PUSH_URL && to && await rateLimit(await pushCapKey(to, forAcct), PUSHES_PER_TARGET_PER_HOUR, 3600_000, 0)) {
    console.log("[push] skipped: this device's hourly push cap is reached");
    return new Response(JSON.stringify({ data: { status: "capped" } }), { status: 200, headers: { "Content-Type": "application/json" } });
  }
  if (url !== EXPO_PUSH_URL || !to.startsWith(UP_TOKEN_PREFIX)) return fetch(url, init);
  let status: string;
  // b77p (audit 2 VAR-35): the wire payload says "wake" for every kind; the UnifiedPush plaintext (encrypted to
  // the phone, never seen by the push server) keeps the kind the caller names
  try { status = await sendUnifiedPush(to, upKind || String(msg?.data?.kind ?? "new-message"), forAcct); }
  // Batch H (R6-3-08): fetch errors start with the URL — never log the endpoint
  catch (e) { status = "up-error " + String((e as Error).message || e).replace(/https?:\/\/\S+/g, "<endpoint>").slice(0, 80); }
  console.log("[push] unifiedpush " + String(msg?.data?.kind ?? "") + ": " + status);
  return new Response(JSON.stringify({ data: { status } }), { status: 200, headers: { "Content-Type": "application/json" } });
}

// ---------- push delivery (b85 parity — zero-content banner) ----------
// b77p round 2 (owner decision 1): NO ACCOUNT-LEVEL PUSH. pushNewMessageAlert / pushCallBurst / pushAlertCoalesced
// (veil_id -> identity -> account -> the account's push rows, for pre-sealed 1:1 chats and group seats) and the
// group-post push (groupMemberPushTokens) are gone: a relay that logs its pushes could tie those accounts to the push
// address their mailbox wake boxes carry. The only pushes left are mailbox wakes (sealedNotify: the sealed wake box,
// or during the transition window a legacy phone's push_ref row) and the legacy registration's possession challenge.
// b198 CALL RING BURST: a call rings with a burst of pushes across the ring window (one every 2.5 s for ~20 s), so
// the callee's lock screen keeps sounding until they open. b77p round 2 (owner decision 2): with the ring sound again
// (activityPush(t, true)); the text stays the one fixed "Vardum / Notification". (F-08) a burst rings only on a
// mailbox its owner marked verified, at most RINGS_PER_CHAT_PER_HOUR.
const CALL_BURST_COUNT = 9;
const CALL_BURST_GAP_MS = 2500;
/** b77: one push address and the account its row belongs to (pushFetch's per-account cap / keys) */
type PushTarget = { t: string; acct: string };
/** the call ring burst to these devices (fire-and-forget) — b77p round 2: the legacy push_ref path only (a b77p
 *  mailbox rings through its wake box, wakeRing) */
function ringPushTargets(targets: PushTarget[]): void {
  const list = targets.filter((x) => !!x.t);
  if (!list.length) return;
  void (async () => {
    for (let i = 0; i < CALL_BURST_COUNT; i++) {
      if (i > 0) await new Promise((res) => setTimeout(res, CALL_BURST_GAP_MS));
      await Promise.allSettled(list.map(async ({ t, acct }) => {
        const r = await pushFetch(EXPO_PUSH_URL, {
          method: "POST",
          headers: { "Content-Type": "application/json", "Accept": "application/json" },
          // b198 (owner): the burst pushes carry the app's ring sound (b77p round 2, owner decision 2: again)
          body: activityPush(t, true).body,
        }, acct, "call");
        const d = await r.json().catch(() => null) as { data?: { status?: string; message?: string } } | null;
        console.log("[push] call burst " + (i + 1) + "/" + CALL_BURST_COUNT + " for  device : " + (d?.data?.status ?? r.status));
      }));
    }
    console.log("[push] call ring burst complete for " + "recipient");
  })().catch(() => undefined);
}
/** b77r1 (audit R-6): deletes a push row (b77p: and its index entries; round 2: and, during the transition window,
 *  its legacy push_ref index entries) in one step */
async function deletePushRow(key: Deno.KvKey): Promise<void> {
  for (let attempt = 0; attempt < 5; attempt++) {
    const cur = await KV.get<Record<string, unknown>>(key);
    if (!cur.value) return;
    const tx = KV.atomic().check(cur).delete(key);
    for (const k of pushRefIndexKeys(String(key[2]), cur.value)) tx.delete(k); // b77r1 (audit R-6), legacy rows only
    for (const k of await entityIxKeys("VeilPushToken", String(key[2]), cur.value)) tx.delete(k); // b77n (pre-audit L3)
    if ((await tx.commit()).ok) return;
  }
  await KV.delete(key); // contended: the row goes; a stale index entry is dropped on its next use or sweep
}

// ---- b77p round 2 (owner decision 4): the LEGACY wake path, served only during the transition window ----
// A pre-b77p (b77) phone binds a random push_ref to each inbound (mailboxPush) and lists those refs on its ACCOUNT
// push row (VeilPushToken.push_refs, indexed by ["push_ref", ref, row id]); a submit to a mailbox with a push_ref and
// no wake box wakes every push row listing it. This is exactly b77's stored mailbox -> account link (audit 2 VAR-01),
// kept for legacy phones only until VEIL_COMPAT_UNTIL; b77p phones never create it (spec §12.19.4).
/** b77: push_refs as a push row stores them — at most 256 distinct lowercase hex strings of 32-64 characters */
const PUSH_REF_RE = /^[0-9a-f]{32,64}$/;
const PUSH_REFS_MAX = 256;
function cleanPushRefs(v: unknown): string[] | null {
  if (!Array.isArray(v) || v.length > PUSH_REFS_MAX) return null;
  const out = new Set<string>();
  for (const x of v) { if (typeof x !== "string" || !PUSH_REF_RE.test(x)) return null; out.add(x); }
  return [...out];
}
/** b77r1 (audit R-6): the ["push_ref", ref, row id] index entries of a (legacy) push row, one per listed ref */
function pushRefIndexKeys(rowId: string, row: Record<string, unknown> | null | undefined): Deno.KvKey[] {
  const refs = Array.isArray(row?.push_refs) ? (row!.push_refs as unknown[]) : [];
  return refs.filter((r): r is string => typeof r === "string" && PUSH_REF_RE.test(r)).map((r) => ["push_ref", r, rowId]);
}
/** b77: the devices a legacy mailbox wakes — every push row whose push_refs lists the mailbox's push_ref (in memory,
 *  per push; a stale index entry is dropped). Nothing during the window ends: [] */
async function pushTargetsOfRef(pushRef: string): Promise<PushTarget[]> {
  const out: PushTarget[] = [];
  if (!compatOn() || !pushRef || !PUSH_REF_RE.test(pushRef)) return out;
  for await (const ix of KV.list({ prefix: ["push_ref", pushRef] }, { consistency: "strong" })) {
    const rowId = String(ix.key[2]);
    const row = (await KV.get<Record<string, unknown>>(["entity", "VeilPushToken", rowId])).value;
    if (!row || !Array.isArray(row.push_refs) || !(row.push_refs as unknown[]).some((r) => typeof r === "string" && ctEq(r, pushRef))) { await KV.delete(ix.key); continue; }
    const t = String(row.expo_token || "");
    if (t) out.push({ t, acct: String(row._acct || "") });
  }
  return out;
}
/** b77: one wake alert to these legacy devices (fire-and-forget; the one uniform payload) */
function alertPushTargets(targets: PushTarget[]): void {
  for (const { t, acct } of targets) {
    void pushFetch(EXPO_PUSH_URL, activityPush(t), acct, "new-message")
      .then(async (r) => { const d = await r.json().catch(() => null) as { data?: { status?: string } } | null; console.log("[push] legacy wake: " + (d?.data?.status ?? r.status)); })
      .catch(() => undefined);
  }
}
/** b77p round 2: set once the legacy rows are gone (at boot after the window, or by the sweeper when it ends) */
let legacyRowsDropped = false;

/** b77p (audit 2 VAR-01): b77's mailbox-to-account links go — every push row (round 2, owner decision 1: EVERY push
 *  row, since account-level push is gone; they listed push_refs or served contact-request / group pushes), every
 *  ["push_ref", ref, row id] index entry, push_ref on every mailbox row, and every ["mbox_ticket"] row (open tickets
 *  were sent beside the rendezvous token). Run at boot when the transition window is not open, and by the sweeper
 *  once it ends. Idempotent. */
async function migrateB77pLinks(): Promise<number> {
  let n = 0;
  for await (const e of KV.list<Record<string, unknown>>({ prefix: ["entity", "VeilPushToken"] }, { consistency: "strong" })) {
    await deletePushRow(e.key); n++;
  }
  for await (const e of KV.list({ prefix: ["push_ref"] }, { consistency: "strong" })) { await KV.delete(e.key); n++; }
  for await (const e of KV.list({ prefix: ["mbox_ticket"] }, { consistency: "strong" })) { await KV.delete(e.key); n++; }
  for await (const e of KV.list<Record<string, unknown>>({ prefix: ["mbox"] }, { consistency: "strong" })) {
    if (!e.value || (e.value as Record<string, unknown>).push_ref === undefined) continue;
    for (let attempt = 0; attempt < 5; attempt++) {
      const cur = await KV.get<Record<string, unknown>>(e.key, { consistency: "strong" });
      if (!cur.value || cur.value.push_ref === undefined) break;
      const { push_ref: _gone, ...rest } = cur.value;
      if ((await KV.atomic().check(cur).set(e.key, rest).commit()).ok) { n++; break; }
    }
  }
  return n;
}
/** b77r2 (audit R2-R-3): retired markers of the old plain-id shape, ["mbox_retired", id], re-keyed
 *  on the id's hash. AWAITED before Deno.serve (it ran in the background, after the blob index
 *  backfill, so a retired id read as "absent" — and could be re-opened — until it was reached).
 *  A hashed marker that already exists is left as it is (its expiry is not reset). Deno KV does
 *  not return a row's expiry, so a row that IS re-keyed gets a fresh MBOX_RETIRED_TTL_MS: the
 *  marker is kept at most that much longer than the old row would have been (never shorter). */
async function migrateRetiredMarkers(): Promise<number> {
  let n = 0;
  for await (const e of KV.list({ prefix: ["mbox_retired"] }, { consistency: "strong" })) {
    const m = String(e.key[1] ?? "");
    for (let attempt = 0; attempt < 5; attempt++) {
      const tx = KV.atomic().check(e).delete(e.key);
      if (isMboxHex(m)) {
        const nKey = await mboxRetiredKey(m);
        const cur = await KV.get(nKey, { consistency: "strong" });
        if (!cur.value) tx.check(cur).set(nKey, 1, { expireIn: MBOX_RETIRED_TTL_MS });
      }
      if ((await tx.commit()).ok) { n++; break; }
    }
  }
  legacyRetiredPending = false;
  return n;
}
/** b77r1 (audit R-6): at boot, in the background — ["blob_by_mbox"] entries for files bound
 *  before the index existed (b77r2: the retired markers moved to migrateRetiredMarkers, awaited
 *  before serving; b77p: the push_ref index is gone, migrateB77pLinks) */
async function migrateB77r1Rows(): Promise<number> {
  let n = 0;
  for await (const e of KV.list<string>({ prefix: ["blob_mbox"] }, { consistency: "strong" })) {
    const k: Deno.KvKey = ["blob_by_mbox", String(e.value ?? ""), String(e.key[1])];
    if (e.value && (await KV.atomic().check({ key: k, versionstamp: null }).set(k, 1).commit()).ok) n++;
  }
  return n;
}
/** b77r3: a transient SQLite lock (another handle on the same database file mid-write — a test
 *  harness, a backup tool) */
const isKvLocked = (e: unknown): boolean => /database is locked|SQLITE_BUSY/i.test(String((e as Error)?.message ?? e));
/** b77r3: the background boot migration retries a transient "database is locked" (it logged once
 *  and gave up, so the indexes waited for the next sweep's reconcile — the blob index never). Each
 *  step is idempotent (checked writes of missing entries only), so a re-run from the top is safe.
 *  At most 8 tries, backing off 0.25 s, 0.5 s … 16 s (about 32 s in all); anything else throws. */
async function migrateB77r1RowsRetrying(): Promise<number> {
  for (let attempt = 1; ; attempt++) {
    try { return await migrateB77r1Rows(); } catch (e) {
      if (attempt >= 8 || !isKvLocked(e)) throw e;
      console.error(`[boot] b77r1 row migration: database is locked — retrying (${attempt}/7)`);
      await new Promise((res) => setTimeout(res, 250 * 2 ** (attempt - 1)));
    }
  }
}


// ---------- veilGroupGate ----------
async function groupRecord(groupToken: string) {
  return (await KV.get<Record<string, any>>(["veil_group", groupToken])).value ?? { epoch: 0, pq_pub: "", created_date: nowIso() };
}

/** b75 (audit V12): what a group's burn rule is built from (the creator's dials) */
type GroupBurnPolicy = { burn_after_open: boolean; default_ttl_seconds: number };
function burnPolicyOf(row: Record<string, unknown>): GroupBurnPolicy {
  const t = Number(row.default_ttl_seconds);
  return { burn_after_open: row.burn_after_open === true, default_ttl_seconds: Number.isFinite(t) && t > 0 ? Math.floor(t) : 0 };
}
/** b75 (audit V12): records the policy on the group record, once (the first row the
 *  creator mints; every later seat carries the same dials). Versionstamp-checked onto the
 *  record as it is now, so it never overwrites an epoch a rotate just wrote. */
async function recordGroupBurnPolicy(groupToken: string, row: Record<string, unknown>): Promise<void> {
  const k: Deno.KvKey = ["veil_group", groupToken];
  for (let attempt = 0; attempt < 10; attempt++) {
    const cur = await KV.get<Record<string, unknown>>(k);
    if (cur.value?.burn_policy) return;
    const base = cur.value ?? { epoch: 0, pq_pub: "", created_date: nowIso() };
    if ((await KV.atomic().check(cur).set(k, { ...base, burn_policy: burnPolicyOf(row) }).commit()).ok) return;
  }
}
/**
 * b75 (audit V12): a group's burn policy. From the group record; a group whose record has
 * none (a policy write lost to a racing rotate) takes it from ANY row the group's owner
 * account minted — main row or seat, any state (seats are minted by the creator with the
 * group's dials) — and records it. It used to be ownerRows[0] of a scan for the creator's
 * active MAIN row only, so once that row was gone every burn was refused. No owner row at
 * all: not burn-after-open (fail closed: the relay copy keeps its normal expiry).
 */
async function groupBurnPolicy(groupToken: string): Promise<GroupBurnPolicy> {
  const rec = (await KV.get<Record<string, unknown>>(["veil_group", groupToken])).value;
  if (rec?.burn_policy && typeof rec.burn_policy === "object") return burnPolicyOf(rec.burn_policy as Record<string, unknown>);
  const ownerAcct = (await KV.get<string>(["veil_group_owner", keySafe(groupToken)])).value ?? "";
  if (!ownerAcct || ownerAcct === "deleted") return { burn_after_open: false, default_ttl_seconds: 0 };
  for await (const e of groupSessionRows(groupToken)) { // b77s (audit 4 RE-02)
    const s = e.value;
    if (!s || String(s.group_token || "") !== groupToken || !s.initiator_client_id) continue;
    if (await accountHashOf(String(s.initiator_client_id)) !== ownerAcct) continue;
    await recordGroupBurnPolicy(groupToken, s);
    return burnPolicyOf(s);
  }
  return { burn_after_open: false, default_ttl_seconds: 0 };
}

/** b77s (audit 4 RE-02): rotations / attestations one group may make in 10 minutes (a full group of 100 joining at
 *  once attests 100 times; rotations follow membership changes). VEIL_GROUP_*_PER_10MIN are for TEST relays. */
const GROUP_ROTATES_PER_10MIN = Number(Deno.env.get("VEIL_GROUP_ROTATES_PER_10MIN")) || 60;
const GROUP_ATTESTS_PER_10MIN = Number(Deno.env.get("VEIL_GROUP_ATTESTS_PER_10MIN")) || 300;
/** b70 (re-review 13): attest, rotate and evict run one at a time per group (two attests
 *  could both become "creator" or share a seat; two rotates to one epoch both answered ok) */
async function fnVeilGroupGate(auth: { userId: string; email?: string }, body: Record<string, any>) {
  const a = String(body?.action || "");
  // b73 (audit): V-01 — decline and wrap_deliver (the admission) take the same lock
  // b75r3 (audit R3G-I1): and retire_seats (it reads the member rows, then deletes seats)
  if (a === "decline" || a === "wrap_deliver" || a === "retire_seats") return withLock("group:" + String(body?.group_token || ""), () => fnVeilGroupGateInner(auth, body));
  if (a !== "attest" && a !== "rotate" && a !== "evict") return fnVeilGroupGateInner(auth, body);
  return withLock("group:" + String(body?.group_token || ""), () => fnVeilGroupGateInner(auth, body));
}
async function fnVeilGroupGateInner(auth: { userId: string; email?: string }, body: Record<string, any>) {
  // b198 FAITHFUL PORT of base44_functions_veilGroupGate_entry.ts (the
  // founder's directive: stop interpreting, mirror the proven source
  // action-for-action). Every response shape, validation order and storage
  // semantic below mirrors the extracted Base44 entry — the client was built
  // against THIS contract, and my improvised KV-row variant diverged from it
  // in four ways (double-wrapped roster, wrong epoch source, no member
  // entity rows, no role/deny-list) which broke groups end to end.
  const tryB64Len = (v: unknown, bytes: number): boolean => {
    if (!canonicalB64(v)) return false; // b70 (re-review 9): one spelling only (no padding games, no whitespace)
    try {
      const raw = Uint8Array.from(atob(v), (c) => c.charCodeAt(0));
      return raw.length === bytes;
    } catch { return false; }
  };
  const HEX_TOKEN = /^[0-9a-f]{8,128}$/;
  const B58_ID = /^[1-9A-HJ-NP-Za-km-z]{16}$/;
  const action = ["attest", "rotate", "evict", "roster", "notify", "wrap_request", "wrap_requests", "wrap_deliver", "wrap_fetch", "decline", "retire_seats"].includes(String(body?.action || "")) ? String(body.action) : null;
  if (!action) return j({ error: "Unknown action", message: "Unknown action" }, 400);
  const groupToken = typeof body.group_token === "string" ? body.group_token : "";
  const sessionToken = typeof body.session_token === "string" ? body.session_token : "";
  if (!HEX_TOKEN.test(groupToken) || !HEX_TOKEN.test(sessionToken)) {
    return j({ error: "Invalid group or session token", message: "Invalid group or session token" }, 400);
  }
  const session = await findSessionByToken(sessionToken);
  if (!session) return j({ error: "Session not found", message: "Session not found" }, 404);
  if (!session.group_token || session.group_token !== groupToken) {
    return j({ error: "This session does not belong to that group", message: "This session does not belong to that group" }, 403);
  }
  if (String(session.state || "") !== "active") {
    return j({ error: "This session is not active", message: "This session is not active" }, 400);
  }
  const wHash = await wsHashOf(body?.write_secret);
  const slot = wHash && (ctEq(wHash, String(session.initiator_write_hash || "")) ? "initiator" : (ctEq(wHash, String(session.responder_write_hash || "")) ? "responder" : null));
  if (!slot) {
    console.warn("group-credential-refused", { action, state: String(session.state), presented: typeof body?.write_secret === "string" ? String(body.write_secret).length : 0 });
    return j({ error: "Invalid session credential", message: "Invalid session credential" }, 403);
  }
  // Base44's group-account hash — reproducible from the auth token's email.
  const groupAccountHash = await sha256hex("veil-group-account:" + String(auth.email || "").trim().toLowerCase());
  const callerAcct = await accountHashOf(auth.userId);

  const memberRows = async (): Promise<Record<string, any>[]> => {
    const out: Record<string, any>[] = [];
    for await (const e of groupMemberRows(groupToken)) { // b77n (pre-audit L3): by ["ix_gmem"]
      const r = e.value as Record<string, any>;
      if (String(r.group_token || "") === groupToken) out.push({ ...r, id: e.key[e.key.length - 1] });
    }
    return out.slice(0, 100); // b198: MAX_GROUP_MEMBERS — the roster page MUST cover the whole cohort
  };
  const denyRows = async (limit = 200): Promise<Record<string, any>[]> => {
    const out: Record<string, any>[] = [];
    for await (const e of groupDenyRows(groupToken)) { // b77s (audit 4 RE-02): by ["ix_gdeny"] (it read every deny entry)
      const r = e.value as Record<string, any>;
      if (String(r.group_token || "") === groupToken) out.push({ ...r, id: e.key[e.key.length - 1] });
    }
    return out.slice(0, limit); // b198: deny-list page scales with the cohort (Batch H: attest reads all)
  };

  if (action === "roster") {
    const members = await memberRows();
    // Membership fence on CURRENT membership: the credential proves a slot; a
    // slot can outlive the membership it was issued for. Resolved from the
    // roster itself against the bindings written at attestation time.
    const isMember = members.some((m) => m.session_token === sessionToken || (!!groupAccountHash && m.account_hash === groupAccountHash) || (!!callerAcct && m._acct === callerAcct));
    if (!isMember) return j({ error: "You are not a member of this group.", membership_gone: true, message: "You are not a member of this group." }, 403);
    // Deliberately narrow projection — exactly Base44's field set. SINGLE wrap:
    // { members, epoch } at the top level (the client reads res.data.members).
    const project = (list: Record<string, any>[]) => list.map((m) => ({ veil_id: m.veil_id || "", IK_pub: m.IK_pub, role: m.role, joined_epoch: m.joined_epoch, attestation_sig: m.attestation_sig || "" }));
    // b74 (audit VAR-01): the whole roster only for a caller holding an ADMITTED membership.
    // A claimant the creator has not let in sees its own row(s) and the epoch (it addresses
    // its seat intro with it) — it used to see every member's Vardum ID and key.
    const heldByCallerR = (m: Record<string, any>) => m._acct ? String(m._acct) === callerAcct : (!!groupAccountHash && m.account_hash === groupAccountHash);
    if (!members.some((m) => heldByCallerR(m) && memberAdmitted(m))) {
      return json({ members: project(members.filter((m) => heldByCallerR(m) || m.session_token === sessionToken)), epoch: Number(session.group_epoch || 0), admitted: false });
    }
    return json({
      members: project(members),
      epoch: Number(session.group_epoch || 0),
    });
  }

  // b77s (audit 4 RE-02): per GROUP limits on the two expensive actions (each reads the group's rows and writes
  // them); the per-account gate limit (1200 a minute) alone let one account hammer one group. The limiter rows name
  // the group only by a hash of its token.
  // b77s (audit 4 N-1): neither limit can be used up by someone else. Both used to be charged here, before rotate's
  // creator check, so a member's refused rotates starved the creator's real ones (429) and froze the group. Now the
  // rotate limit is charged only once the caller is proven to be the group's owner (below), and the attest limit is
  // kept per group AND per account, so a refused attest only spends the caller's own budget.
  const groupRlTag = async () => "gt_" + (await sha256hex("veil-group-rl:" + groupToken)).slice(0, 32);
  const groupBusy = (grl: { retry_minutes: number }) => j({ locked: true, retry_minutes: grl.retry_minutes, message: "This group is busy — try again in a few minutes" }, 429);
  if (action === "attest") {
    const gtag = (await groupRlTag()) + ":" + callerAcct.slice(0, 40);
    const grl = await rateLimit("gattest:" + gtag, GROUP_ATTESTS_PER_10MIN, 10 * 60_000, 0);
    if (grl) return groupBusy(grl);
  }
  if (action === "attest") {
    const ikPub = typeof body.IK_pub === "string" ? body.IK_pub : "";
    const veilId = typeof body.veil_id === "string" ? body.veil_id.trim() : "";
    const sig = typeof body.sig === "string" ? body.sig : "";
    const joinedEpoch = Number(body?.joined_epoch);
    if (!tryB64Len(ikPub, 32) || !tryB64Len(sig, 64)) return j({ error: "Invalid attestation material", message: "Invalid attestation material" }, 400);
    if (veilId !== "" && !B58_ID.test(veilId)) return j({ error: "Invalid veil_id", message: "Invalid Vardum ID" }, 400);
    // Deny-list FIRST — an evicted identity learns they were removed even if
    // their stale attestation no longer matches the current epoch.
    // Batch H (round-6 review R6-2-04): every deny entry is checked (the first 200,
    // in random-id order, used to be the only ones)
    const denies = await denyRows(Infinity);
    // tombstoned entries (banned account since deleted) match by hash only
    const ikHash = await denyHash(groupToken, ikPub);
    const vidHash = veilId !== "" ? await denyHash(groupToken, veilId) : "";
    const bannedIn = (list: Record<string, unknown>[]) => list.some((d) => d.target_IK_pub === ikPub || (veilId !== "" && d.target_veil_id === veilId)
      || d.target_ik_hash === ikHash || (vidHash !== "" && d.target_vid_hash === vidHash));
    if (bannedIn(denies)) {
      return j({ error: "This identity was removed from the group", message: "This identity was removed from the group" }, 403);
    }
    /** b70 (re-review 12): an evict that landed while this attest ran wins — the membership
     *  just written is taken back (it used to survive and re-admit the evicted member) */
    const undoIfBannedMeanwhile = async (memberId: string): Promise<Response | null> => {
      // (re-review 12: also when the seat itself ended while this attest ran — a
      // membership with no seat used to stay, still passing the group-stream check)
      const seatGone = !(await findSessionByToken(String(sessionToken)));
      if (!seatGone && !bannedIn(await denyRows(Infinity))) return null;
      if (seatGone) {
        await deleteIndexedRow("VeilGroupMember", String(memberId)); // b77n (L3)
        await KV.delete(["veil_gmember", groupToken, ikPub]);
        return j({ error: "This seat has ended", message: "This seat has ended" }, 409);
      }
      await deleteIndexedRow("VeilGroupMember", String(memberId)); // b77n (L3)
      await KV.delete(["veil_gmember", groupToken, ikPub]);
      return j({ error: "This identity was removed from the group", message: "This identity was removed from the group" }, 403);
    };
    if (!Number.isInteger(joinedEpoch) || joinedEpoch < 0 || joinedEpoch !== Number(session.group_epoch || 0)) {
      return j({ error: "joined_epoch does not match the current group epoch", message: "joined_epoch does not match the current group epoch" }, 400);
    }
    // Batch C (A1, reviews P1 NF-2 / P2 V-2 V-3 V-21): membership is bound to
    // the CALLER's own published, bound identity and to ONE seat.
    if (veilId === "") return j({ error: "A Vardum ID is required to join a group", message: "A Vardum ID is required to join a group" }, 400);
    const identity = (await KV.get<Record<string, unknown>>(["veil_identity", keySafe(veilId)])).value;
    if (!identity) return j({ error: "Unknown identity", message: "Unknown identity" }, 404);
    if (String(identity.IK_pub || "") !== ikPub) return j({ error: "Identity does not match the published key", message: "Identity does not match the published key" }, 403);
    if (identity.bound !== true || String(identity.account_hash || "") !== callerAcct) {
      return j({ error: "That identity is not bound to your account", message: "That identity is not bound to your account" }, 403);
    }
    // the invitee seat lock applies to attest exactly as to peek/join — a
    // forwarded link (or a relay-held w) can't attest a different identity
    const lockedInvitee = String(session.invitee_veil_id || "");
    if (lockedInvitee && lockedInvitee !== veilId) {
      return j({ error: "This invitation was sent to someone else.", message: "This invitation was sent to someone else." }, 403);
    }
    const payloadJson = JSON.stringify({ group_token: groupToken, veil_id: veilId, IK_pub: ikPub, joined_epoch: joinedEpoch });
    // b75 (audit GR-8): only the labelled form 'vardum-group-attest-v2:' + JSON is accepted. The bare-JSON form
    // was dropped (b74 never shipped, so no client signs it), so an attestation can't be confused with any other
    // JSON an identity key signs.
    const sigOk = await ed25519Verify(ikPub, enc.encode("vardum-group-attest-v2:" + payloadJson), sig);
    if (!sigOk) return j({ error: "Attestation signature verification failed", message: "Attestation signature verification failed" }, 401);
    const members = await memberRows();
    // one identity per seat: a seat already attested by another key can't be reused
    const seatTaken = members.find((m) => m.session_token === sessionToken && m.IK_pub !== ikPub);
    if (seatTaken) return j({ error: "This seat already belongs to another member", message: "This seat already belongs to another member" }, 403);
    const existing = members.find((m) => m.IK_pub === ikPub);
    // b77u (audit 6, IH full L-6): a member that ended its own seat doesn't move onto a spare one (only a seat locked to it)
    if (!existing && !(lockedInvitee && lockedInvitee === veilId) && (await KV.get(await groupLeftKey(groupToken, ikPub))).value) {
      return j({ error: "You left this group. Ask its creator for an invitation to your Vardum ID.", message: "You left this group. Ask its creator for an invitation to your Vardum ID.", code: "left_group" }, 403);
    }
    const heldByCaller = (m: Record<string, any>) => m._acct ? String(m._acct) === callerAcct : String(m.account_hash || "") === groupAccountHash;
    if (existing && !heldByCaller(existing)) {
      // re-attest only by the account that holds the membership (V-21)
      return j({ error: "That membership belongs to another account", message: "That membership belongs to another account" }, 403);
    }
    if (existing) {
      // b70 (audit GRP-3): moving to a new seat retires the old one. Its session
      // used to stay active with the member's write secret, so an evicted
      // member could keep posting / notifying / burning through it.
      const oldSeat = String(existing.session_token || "");
      // b75r3 (audit R3G-02): a membership moves to ANOTHER seat only when the creator approved it: the seat is
      // locked to this Vardum ID (a contact invite the creator made for it). b75r2 let an admitted member move onto
      // any seat of the group whose credential it held (a spare plain link seen in the group, say), keeping its
      // admission — and the person the link was meant for was then refused the seat. A move onto a plain link seat
      // is refused while the membership's own seat still exists; a membership whose seat is gone (ended) may take a
      // plain seat like any newcomer, and is NOT admitted there until the creator lets it in again.
      let keepAdmission = true;
      if (oldSeat !== sessionToken && lockedInvitee !== veilId) {
        const oldRow = oldSeat ? await findSessionByToken(oldSeat) : null;
        if (oldRow && String(oldRow.group_token || "") === groupToken) {
          return j({ error: "You are already in this group through another invitation", message: "You are already in this group through another invitation" }, 409);
        }
        keepAdmission = false;
      }
      if (oldSeat && oldSeat !== sessionToken) {
        const old = await findSessionByToken(oldSeat);
        // only a joined seat (it has a responder side); never the creator's main group row
        if (old && String(old.group_token || "") === groupToken && String(old.responder_write_hash || "")) {
          await KV.delete(["entity", "VeilSession", String(old.id)]);
          await KV.delete(["veil_sess_token", keySafe(oldSeat)]);
          await KV.set(await retiredTokenKey(oldSeat), 1, { expireIn: 400 * 86400_000 }); // b70 (re-review 7)
        }
      }
      // Re-attest: rebind to the current session and epoch.
      // (b75r3, R3G-02: an orphaned membership taking a plain seat starts over, not admitted)
      const admittedNow = keepAdmission && memberAdmitted(existing);
      {
        const re = { ...existing, veil_id: veilId, account_hash: groupAccountHash, _acct: callerAcct, session_token: sessionToken, joined_epoch: joinedEpoch, attestation_sig: sig, updated_date: nowIso(), ...(keepAdmission ? {} : { admitted: false }) };
        const tx = KV.atomic().set(["entity", "VeilGroupMember", existing.id], re);
        for (const k of await entityIxKeys("VeilGroupMember", String(existing.id), re)) tx.set(k, 1); // b77n (pre-audit L3)
        await tx.commit();
      }
      // b74 (audit VAR-01): a re-attest keeps the membership's admission as it was
      await KV.set(["veil_gmember", groupToken, ikPub], { veil_id: veilId, ik_pub: ikPub, joined_epoch: joinedEpoch, sig, account_hash: callerAcct, admitted: admittedNow, created_date: nowIso() });
      { const undone = await undoIfBannedMeanwhile(String(existing.id)); if (undone) return undone; }
      return json({ ok: true, rejoined: true });
    }
    if (members.length >= 100) return j({ error: "This group is full", message: "This group is full" }, 403); // b198: cohort 100
    // W-21: 'creator' belongs to the group's FIRST attester, never to whoever
    // happens to hold an initiator slot.
    // b77n2 (review M1): an empty list alone no longer makes a creator — the owner record, the membership
    // entries and the member table itself must agree (an index missing entries let a joiner take a group)
    const role = members.length === 0 && await groupCreatorFree(groupToken, ikPub, callerAcct) ? "creator" : "member";
    // b73 (audit): V-01 — a new member row is NOT admitted until the creator delivers this
    // identity its first group key (wrap_deliver below); until then the relay takes only
    // its seat intro (see fnSubmitEnvelope). The creator's own row is admitted at once.
    const row = { id: rid(), created_date: nowIso(), updated_date: nowIso(), group_token: groupToken, veil_id: veilId, account_hash: groupAccountHash, _acct: callerAcct, IK_pub: ikPub, session_token: sessionToken, joined_epoch: joinedEpoch, role, attestation_sig: sig, admitted: role === "creator" };
    { const tx = KV.atomic().set(["entity", "VeilGroupMember", row.id], row); for (const k of await entityIxKeys("VeilGroupMember", row.id, row)) tx.set(k, 1); await tx.commit(); } // b77n (pre-audit L3): with its ["ix_gmem"] entry
    // b74 (audit VAR-01): the read gates (roster, group list, row reads) check this flag
    await KV.set(["veil_gmember", groupToken, ikPub], { veil_id: veilId, ik_pub: ikPub, joined_epoch: joinedEpoch, sig, account_hash: callerAcct, admitted: row.admitted, created_date: nowIso() });
    { const undone = await undoIfBannedMeanwhile(String(row.id)); if (undone) return undone; }
    return json({ ok: true, role });
  }

  if (action === "rotate") {
    // b198: every rotate refusal is DIAGNOSED (slot/epoch/pq) — silent guards
    // made the stuck-epoch state undebuggable from the journal.
    if (slot !== "initiator") {
      console.warn("rotate-refused", { reason: "slot", slot, groupEpoch: Number(session.group_epoch || 0) });
      return j({ error: "Only the group creator can rotate the epoch", message: "Only the group creator can rotate the epoch" }, 403);
    }
    // b199 AUTHZ: the initiator slot alone is not creatorship — the slot's
    // account must own the group (a forged row used to rotate anyone's group).
    if (!(await claimOrCheckGroupOwner(groupToken, auth))) {
      console.warn("rotate-refused", { reason: "not-owner" });
      return j({ error: "Only the group creator can rotate the epoch", message: "Only the group creator can rotate the epoch" }, 403);
    }
    { // b77s (audit 4 N-1): the per-group rotate limit is charged only for the proven owner
      const grl = await rateLimit("grotate:" + (await groupRlTag()), GROUP_ROTATES_PER_10MIN, 10 * 60_000, 0);
      if (grl) return groupBusy(grl);
    }
    const newEpoch = Number(body?.new_epoch);
    if (!Number.isInteger(newEpoch) || newEpoch !== Number(session.group_epoch || 0) + 1) {
      console.warn("rotate-refused", { reason: "epoch", newEpoch: body?.new_epoch, serverEpoch: Number(session.group_epoch || 0) });
      return j({ error: "new_epoch must be the current epoch + 1", message: "new_epoch must be the current epoch + 1" }, 400);
    }
    // group epochs are PQ-only: raw ML-KEM-768 encapsulation key (FIPS 203).
    if (!tryB64Len(body?.group_pq_pub, 1184)) {
      console.warn("rotate-refused", { reason: "pq", pqLen: typeof body?.group_pq_pub === "string" ? body.group_pq_pub.length : 0 });
      return j({ error: "group_pq_pub must be a base64 ML-KEM-768 public key — group epochs are PQ-only, no silent downgrade", message: "group_pq_pub must be a base64 ML-KEM-768 public key — group epochs are PQ-only, no silent downgrade" }, 400);
    }
    // stamp the new epoch + PQ key on every session row carrying this group
    for await (const e of groupSessionRows(groupToken)) { // b77s (audit 4 RE-02): by ["ix_gsess"] (it read every session row)
      const row = e.value as Record<string, unknown>;
      if (String(row.group_token || "") === groupToken) {
        // b70 (re-review 12): only the epoch fields, onto the row as it is now (a whole-row
        // write undid a join, end or evict that landed during this scan)
        for (let attempt = 0; attempt < 10; attempt++) {
          const cur = await KV.get<Record<string, unknown>>(e.key);
          if (!cur.value) break;
          if ((await KV.atomic().check(cur).set(e.key, { ...cur.value, group_epoch: newEpoch, group_pq_pub: String(body.group_pq_pub || ""), updated_date: nowIso() }).commit()).ok) break;
        }
      }
    }
    const rec = await groupRecord(groupToken);
    await KV.set(["veil_group", groupToken], { ...rec, epoch: newEpoch, pq_pub: String(body.group_pq_pub || ""), updated_date: nowIso() });
    return json({ ok: true, epoch: newEpoch });
  }

  if (action === "evict") {
    // Batch G (round-5 review R5-3-01): relay `evict` changes no key (the app's
    // rotation is a separate `rotate`)
    if (slot !== "initiator") return j({ error: "Only the group creator can remove members", message: "Only the group creator can remove members" }, 403);
    // b70 (re-review 2): each evict scans the envelope table; bounded per account
    { const erl = await rateLimit("evict:" + auth.userId, 200, 86_400_000, 60); if (erl) return j({ locked: true, retry_minutes: erl.retry_minutes }, 429); }
    const removerIkPub = typeof body.remover_IK_pub === "string" ? body.remover_IK_pub : "";
    const targetIkPub = typeof body.target_IK_pub === "string" ? body.target_IK_pub : "";
    const targetVeilId = typeof body.target_veil_id === "string" ? body.target_veil_id.trim() : "";
    const denySig = typeof body.deny_sig === "string" ? body.deny_sig : "";
    if (!tryB64Len(removerIkPub, 32) || !tryB64Len(targetIkPub, 32) || !tryB64Len(denySig, 64) || targetVeilId.length > 64) return j({ error: "Invalid eviction material", message: "Invalid eviction material" }, 400);
    if (removerIkPub === targetIkPub) return j({ error: "The creator cannot evict themselves — end the group instead", message: "The creator cannot evict themselves — end the group instead" }, 400);
    const members = await memberRows();
    const remover = members.find((m) => m.IK_pub === removerIkPub);
    if (!remover || remover.role !== "creator") {
      return j({ error: "Remover is not the group creator", message: "Remover is not the group creator" }, 403);
    }
    const denyEpoch = Number(session.group_epoch || 0);
    const denyPayload = JSON.stringify({ group_token: groupToken, target_IK_pub: targetIkPub, deny_epoch: denyEpoch });
    // b75 (audit GR-8): only the labelled form 'vardum-group-deny-v2:' + JSON is accepted (no bare-JSON fallback)
    const denyOk = await ed25519Verify(removerIkPub, enc.encode("vardum-group-deny-v2:" + denyPayload), denySig);
    if (!denyOk) return j({ error: "Deny-list signature verification failed", message: "Deny-list signature verification failed" }, 401);
    const target = members.find((m) => m.IK_pub === targetIkPub);
    // b70 (re-review 2): one entry per (group, member, epoch) — replaying the same
    // signature used to add a new row each time
    const denyId = "deny_" + (await sha256hex("veil-deny:" + groupToken + ":" + targetIkPub + ":" + denyEpoch)).slice(0, 32);
    const denyRow = { id: denyId, created_date: nowIso(), group_token: groupToken, target_veil_id: targetVeilId, target_IK_pub: targetIkPub, deny_epoch: denyEpoch, remover_IK_pub: removerIkPub, deny_sig: denySig };
    { // b77s (audit 4 RE-02): with its ["ix_gdeny"] entry, in one step
      const dtx = KV.atomic().set(["entity", "VeilGroupDenyEntry", denyRow.id], denyRow);
      for (const k of await entityIxKeys("VeilGroupDenyEntry", denyRow.id, denyRow)) dtx.set(k, 1);
      await dtx.commit();
    }
    let removedSession = false;
    if (target) {
      await deleteIndexedRow("VeilGroupMember", String(target.id)); // b77n (L3)
      await KV.delete(["veil_gmember", groupToken, targetIkPub]);
      // b76r2 (audit GB-1 / R2-B1): its burn votes and its place in every burn quorum go with it
      if (target._acct) await dropBurnEligibility(groupToken, String(target._acct));
      if (target.session_token) {
        // Base44 cascade: the evicted member's envelopes + session row go too.
        // (b71 (audit F-09): through the seat's index, not a scan of every envelope)
        // b77u (audit 6, IH relay F-11): the SEAT first, then its envelopes — a post racing the evict found its seat still
        // there after the envelopes had gone, and stayed (submitEnvelope re-checks the seat before it writes)
        const doomed = await findSessionByToken(String(target.session_token));
        if (doomed) {
          await KV.set(await retiredTokenKey(String(target.session_token)), 1, { expireIn: 400 * 86400_000 }); // b70 (re-review 9): never minted again
          await KV.delete(["entity", "VeilSession", String(doomed.id)]);
          await KV.delete(["veil_sess_token", keySafe(String(target.session_token))]);
          removedSession = true;
        }
        await deleteSessionEnvelopes(String(target.session_token));
      }
    }
    // b77u (audit 6, IH relay F-09): its pending key-wrap request and any undelivered wrap for it go too (they lived 7 days)
    await KV.delete(["veil_wrapreq", keySafe(groupToken), targetIkPub]);
    await KV.delete(["veil_wrapdel", keySafe(groupToken), targetIkPub]);
    return json({ ok: true, denied: true, removed_session: removedSession });
  }

  // Batch C (A3 follow-up): missing-wrap requests. A member that missed a
  // rotation cannot use the group channel (submit refuses envelopes off the
  // current epoch), so it asks here; the creator answers with a creator-signed
  // rekey whose wrap only that member can open. The relay stores and forwards:
  // requests are signed by the member's IK, deliveries are opaque to it.
  if (action === "wrap_request" || action === "wrap_requests" || action === "wrap_deliver" || action === "wrap_fetch") {
    const WRAP_TTL_MS = 7 * 24 * 3600 * 1000;
    const heldBy = (m: Record<string, any>) => m._acct ? String(m._acct) === callerAcct : String(m.account_hash || "") === groupAccountHash;
    const isOwner = async () => slot === "initiator" && await claimOrCheckGroupOwner(groupToken, auth);
    const reqPrefix = ["veil_wrapreq", keySafe(groupToken)];
    const delPrefix = ["veil_wrapdel", keySafe(groupToken)];

    if (action === "wrap_request") {
      const ikPub = typeof body.IK_pub === "string" ? body.IK_pub : "";
      const veilId = typeof body.veil_id === "string" ? body.veil_id.trim() : "";
      const sig = typeof body.sig === "string" ? body.sig : "";
      const haveEpoch = Number(body?.have_epoch);
      if (!tryB64Len(ikPub, 32) || !tryB64Len(sig, 64) || !B58_ID.test(veilId) || !Number.isInteger(haveEpoch) || haveEpoch < 0) {
        return j({ error: "Invalid wrap request", message: "Invalid wrap request" }, 400);
      }
      const members = await memberRows();
      const mine = members.find((m) => m.IK_pub === ikPub && String(m.veil_id || "") === veilId);
      if (!mine || !heldBy(mine)) return j({ error: "You are not a member of this group.", message: "You are not a member of this group." }, 403);
      if (haveEpoch >= Number(session.group_epoch || 0)) return j({ error: "Already on the current epoch", message: "Already on the current epoch" }, 400);
      // b75 (audit GR-8): only a v2 request is accepted — it also signs its time (at) and a nonce, which the
      // creator's phone checks (fresh, used once); they are stored and handed back with the request. The v1 form
      // (no freshness) was dropped: b74 never shipped, so no client produces it.
      const reqAt = Number(body?.at);
      const reqNonce = typeof body?.nonce === "string" ? body.nonce : "";
      if (!Number.isInteger(reqAt) || reqAt <= 0 || !/^[0-9a-f]{32}$/.test(reqNonce)) {
        return j({ error: "Invalid wrap request", message: "Invalid wrap request" }, 400);
      }
      const msg = JSON.stringify({ v: "vardum-wrap-request-v2", group_token: groupToken, veil_id: veilId, IK_pub: ikPub, have_epoch: haveEpoch, at: reqAt, nonce: reqNonce });
      if (!(await ed25519Verify(ikPub, enc.encode(msg), sig))) return j({ error: "Wrap request signature verification failed", message: "Wrap request signature verification failed" }, 401);
      await KV.set([...reqPrefix, ikPub], { veil_id: veilId, IK_pub: ikPub, have_epoch: haveEpoch, sig, at: reqAt, nonce: reqNonce, created_date: nowIso() }, { expireIn: WRAP_TTL_MS });
      return json({ ok: true });
    }

    if (action === "wrap_requests") {
      if (!(await isOwner())) return j({ error: "Only the group creator can read wrap requests", message: "Only the group creator can read wrap requests" }, 403);
      const requests: Record<string, unknown>[] = [];
      for await (const e of KV.list<Record<string, unknown>>({ prefix: reqPrefix }, { consistency: "strong" })) {
        const r = e.value;
        requests.push({ veil_id: r.veil_id, IK_pub: r.IK_pub, have_epoch: r.have_epoch, sig: r.sig, ...(r.at !== undefined ? { at: r.at, nonce: r.nonce } : {}), created_date: r.created_date });
        if (requests.length >= 100) break;
      }
      return json({ requests });
    }

    if (action === "wrap_deliver") {
      if (!(await isOwner())) return j({ error: "Only the group creator can deliver wraps", message: "Only the group creator can deliver wraps" }, 403);
      const target = typeof body.target_IK_pub === "string" ? body.target_IK_pub : "";
      const payload = typeof body.payload === "string" ? body.payload : "";
      if (!tryB64Len(target, 32)) return j({ error: "Invalid target", message: "Invalid target" }, 400);
      if (utf8Len(payload) > 40000) return j({ error: "Wrap payload too large", message: "Wrap payload too large" }, 413); // b70 (re-review 7): bytes
      if (!payload.startsWith('{"__veil_group_rekey":')) return j({ error: "Not a rekey payload", message: "Not a rekey payload" }, 400);
      const members = await memberRows();
      const tRow = members.find((m) => m.IK_pub === target);
      if (!tRow) return j({ error: "Not a member of this group", message: "Not a member of this group" }, 404);
      // b73 (audit): V-01 — a key delivered by the creator IS the admission the relay can
      // see: from now on this member posts like any other (see memberAdmitted)
      const mk: Deno.KvKey = ["entity", "VeilGroupMember", String(tRow.id)];
      for (let attempt = 0; attempt < 10; attempt++) {
        const cur = await KV.get<Record<string, unknown>>(mk);
        if (!cur.value || cur.value.admitted === true) break; // b75 (audit GR-7): a row without the flag is admitted here too
        if ((await KV.atomic().check(cur).set(mk, { ...cur.value, admitted: true, admitted_date: nowIso() }).commit()).ok) break;
      }
      // b74 (audit VAR-01): and the membership entry the read gates check
      {
        const gk: Deno.KvKey = ["veil_gmember", groupToken, target];
        for (let attempt = 0; attempt < 10; attempt++) {
          const cur = await KV.get<Record<string, unknown>>(gk);
          if (!cur.value || cur.value.admitted === true) break;
          if ((await KV.atomic().check(cur).set(gk, { ...cur.value, admitted: true }).commit()).ok) break;
        }
      }
      await KV.atomic()
        .set([...delPrefix, target], { payload, created_date: nowIso() }, { expireIn: WRAP_TTL_MS })
        .delete([...reqPrefix, target])
        .commit();
      return json({ ok: true });
    }

    // wrap_fetch — the target member only, single use
    const ikPub = typeof body.IK_pub === "string" ? body.IK_pub : "";
    if (!tryB64Len(ikPub, 32)) return j({ error: "Invalid key", message: "Invalid key" }, 400);
    const members = await memberRows();
    const mine = members.find((m) => m.IK_pub === ikPub);
    if (!mine || !heldBy(mine)) return j({ error: "You are not a member of this group.", message: "You are not a member of this group." }, 403);
    const k = [...delPrefix, ikPub];
    const got = await KV.get<{ payload: string }>(k);
    if (!got.value) return json({ payload: null });
    const del = await KV.atomic().check(got).delete(k).commit();
    return json({ payload: del.ok ? got.value.payload : null });
  }

  // b73 (audit): V-01 — the creator declines a claimant (the app's declineGroupClaim used to
  // be local only, so the claimant kept its seat, its row and its posts on the relay).
  //   { action: "decline", group_token, session_token: <creator's main session>,
  //     write_secret: <its secret>, target_IK_pub: <the claimant's IK, base64> }
  // Creator only (the owner account on its initiator slot, as rotate). The target must be
  // a member row the creator has NOT admitted (a member it let in is removed with evict,
  // which bans). Removes that row, every envelope posted through its seat, the seat
  // itself (retired: its link can't be used again — the app retires it too) and any wrap
  // request it filed. No ban: the person can be invited again with a new link.
  // Answers { ok: true, declined: true, removed_session, removed_envelopes }; a target with
  // no row answers 404 (nothing left to remove), an admitted one 409.
  if (action === "decline") {
    if (slot !== "initiator" || !(await claimOrCheckGroupOwner(groupToken, auth))) return j({ error: "Only the group creator can decline a request to join", message: "Only the group creator can decline a request to join" }, 403);
    { const drl = await rateLimit("evict:" + auth.userId, 200, 86_400_000, 60); if (drl) return j({ locked: true, retry_minutes: drl.retry_minutes }, 429); }
    const targetIkPub = typeof body.target_IK_pub === "string" ? body.target_IK_pub : "";
    if (!tryB64Len(targetIkPub, 32)) return j({ error: "Invalid target", message: "Invalid target" }, 400);
    const members = await memberRows();
    const target = members.find((m) => m.IK_pub === targetIkPub);
    if (!target) return j({ error: "Not a member of this group", message: "Not a member of this group" }, 404);
    if (target.role === "creator") return j({ error: "The creator cannot decline themselves", message: "The creator cannot decline themselves" }, 400);
    if (target.admitted === true) return j({ error: "That person was already let in — remove them instead", message: "That person was already let in — remove them instead" }, 409);
    await deleteIndexedRow("VeilGroupMember", String(target.id)); // b77n (L3)
    await KV.delete(["veil_gmember", groupToken, targetIkPub]);
    await KV.delete(["veil_wrapreq", keySafe(groupToken), targetIkPub]);
    if (target._acct) await dropBurnEligibility(groupToken, String(target._acct)); // b76r2 (audit GB-1 / R2-B1)
    let removedEnvelopes = 0, removedSession = false;
    const seat = String(target.session_token || "");
    // never the creator's own main row (a seat has a responder side)
    const seatRow = seat ? await findSessionByToken(seat) : null;
    if (seatRow && String(seatRow.group_token || "") === groupToken && String(seatRow.responder_write_hash || "") && seat !== sessionToken) {
      await KV.delete(["entity", "VeilSession", String(seatRow.id)]);
      await KV.delete(["veil_sess_token", keySafe(seat)]);
      await KV.set(await retiredTokenKey(seat), 1, { expireIn: 400 * 86400_000 });
      removedSession = true;
    }
    if (seat && seat !== sessionToken) removedEnvelopes = await deleteSessionEnvelopes(seat);
    return json({ ok: true, declined: true, removed_session: removedSession, removed_envelopes: removedEnvelopes });
  }

  // b75r3 (audit R3G-I1): the creator ends seats it retired on its phone — the unused invite links and the seats of
  // claims it never approved, which a removal retires (evictGroupMember). They used to be retired only on the
  // creator's phone, so the seat stayed open on the relay: whoever held the link (the removed member, say) could
  // still join, attest and post its "let me in" note through it.
  //   { action: "retire_seats", group_token, session_token: <creator's main session>, write_secret,
  //     seat_tokens: [<seat token>, ...] (at most 64) }
  // Creator only (the owner account on its initiator slot, as decline). Each seat must be a session of THIS group
  // other than the caller's own; a seat holding the creator's membership or an ADMITTED membership is kept (a member
  // it let in is removed with evict). For every other seat: its not-admitted member rows (and their wrap requests),
  // its envelopes and the seat itself go, and the token is retired (never minted again). Seats not found are skipped.
  // Answers { ok: true, retired: <n>, kept: <n> }.
  if (action === "retire_seats") {
    if (slot !== "initiator" || !(await claimOrCheckGroupOwner(groupToken, auth))) return j({ error: "Only the group creator can end invite links", message: "Only the group creator can end invite links" }, 403);
    { const rrl = await rateLimit("evict:" + auth.userId, 200, 86_400_000, 60); if (rrl) return j({ locked: true, retry_minutes: rrl.retry_minutes }, 429); }
    const list = Array.isArray(body.seat_tokens) ? body.seat_tokens : null;
    if (!list || list.length > 64 || !list.every((t: unknown) => typeof t === "string" && HEX_TOKEN.test(t))) return j({ error: "Invalid seat list", message: "Invalid seat list" }, 400);
    const members = await memberRows();
    let retired = 0, kept = 0;
    for (const seat of [...new Set(list as string[])]) {
      if (seat === sessionToken) { kept++; continue; }
      const row = await findSessionByToken(seat);
      if (!row || String(row.group_token || "") !== groupToken) continue;
      const onSeat = members.filter((m) => String(m.session_token || "") === seat);
      if (onSeat.some((m) => m.role === "creator" || memberAdmitted(m))) { kept++; continue; }
      for (const m of onSeat) {
        await deleteIndexedRow("VeilGroupMember", String(m.id)); // b77n (L3)
        await KV.delete(["veil_gmember", groupToken, String(m.IK_pub || "")]);
        await KV.delete(["veil_wrapreq", keySafe(groupToken), String(m.IK_pub || "")]);
      }
      await deleteSessionEnvelopes(seat);
      await KV.delete(["entity", "VeilSession", String(row.id)]);
      await KV.delete(["veil_sess_token", keySafe(seat)]);
      await KV.set(await retiredTokenKey(seat), 1, { expireIn: 400 * 86400_000 });
      retired++;
    }
    return json({ ok: true, retired, kept });
  }

  // b198 notify — every OTHER member's account got a contentless ping.
  // b77p round 2 (owner decision 1): NO GROUP-POST PUSH. It was account-level (member rows carry _acct; the push went
  // to each member account's push rows), so a relay logging its pushes could tie each member account to the push
  // address that account's mailbox wake boxes carry. A per-seat / per-mailbox wake can't avoid naming accounts here:
  // the group gate is signed in and every seat maps to a member row tagged with its account, so whoever opens a
  // seat's wake box learns "this account's phone = this push address" — the very link decision 1 removes. Group
  // posts are found on the member's next poll or wake (a 1:1 message wake, the app coming to the foreground).
  // The action stays (older apps call it) and keeps its membership check; it pushes nothing.
  if (action === "notify") {
    {
      const held = (await memberRows()).filter((m) => (m._acct ? String(m._acct) === callerAcct : (!!groupAccountHash && m.account_hash === groupAccountHash)));
      if (!held.some((m) => memberAdmitted(m))) return j({ error: "Only members of this group can notify it", message: "Only members of this group can notify it" }, 403);
    }
    return json({ ok: true, data: { pinged: 0 } });
  }
  return j({ error: "Unknown action", message: "Unknown action" }, 400);
}

// ---------- deviceLink (moving chats to a new phone) ----------
// b75 (audit XF-1 / RL-04): the receiver-bound move (spec §7). The NEW phone opens
// the row with its ML-KEM public key and its identity-key signature ("open"; b75r1,
// PX-01); the OLD phone reads both ("peek"),
// posts its offer ("offer"), and after the user compared the check codes uploads the
// encrypted bundle ("store"). The new phone polls ("poll"), collects ("fetch") and
// acknowledges ("ack"); the old phone asks "status". Either phone may "cancel".
// The relay can't read the bundle and can't forge the ack (an HMAC under a key only
// the two phones derive); it only stores and forwards. Every path that ends a row
// deletes its bundle file and the file's owner records with it.
/** b71: how long the ack survives after the old phone first reads it
 *  (VEIL_ACK_TTL_MS overrides it for test relays only) */
const ACK_SECRET_AFTER_READ_MS = Number(Deno.env.get("VEIL_ACK_TTL_MS")) || 3_600_000;
const DEVLINK_TTL_MS = 10 * 60_000;
const DEVLINK_GONE = "Transfer not found — expired or already used.";
/** b75 (audit RL-04): a move's bundle file goes with its row — file, owner record and
 *  chat binding. Never a vault container (store refuses one, re-checked here). */
async function dropDevlinkBlob(row: Record<string, unknown> | null | undefined) {
  const uri = String(row?.container_uri || "");
  const path = blobPathOf(uri);
  if (!path) return;
  // b77n (pre-audit L3): the link's file index entries go with it (every path that ends a link row calls this)
  if (URI_IX_RE.test(uri)) for await (const e of KV.list({ prefix: ["ix_devlink_uri", uri] }, { consistency: "strong" })) await KV.delete(e.key);
  if (await vaultUsesUri(uri)) return; // b77n (pre-audit L3): by ["ix_vault_uri"]
  await Deno.remove(path).catch(() => undefined);
  await KV.delete(["blob_owner", blobIdOf(uri)]);
  await KV.delete(["blob_session", blobIdOf(uri)]); await KV.delete(["blob_group", blobIdOf(uri)]); // b77u (U-M9)
}
async function fnDeviceLink(auth: { userId: string }, body: Record<string, any>) {
  const action = String(body.action || "");
  const token = String(body.token || "");
  if (!token || token.length > MAX_KEY_PART) return j({ error: "token required", message: "token required" }, 400);
  const me = await accountHashOf(auth.userId);
  const k = ["devlink", keySafe(token)];
  /** the live row, or null — an expired one is deleted with its bundle on the spot (RL-04) */
  const live = async () => {
    const got = await KV.get<Record<string, any>>(k);
    if (!got.value) return null;
    if (Number(got.value.exp) < Date.now()) {
      // b75r1 (lead, b75-xfer M5a flake): a race with the sweeper (1 s in the test runner).
      // The sweeper deleted an expired row and THEN its file and owner record; a fetch that
      // read the row first lost its check-and-delete and answered 404 while the sweeper was
      // still cleaning up (or, arriving between the sweeper's two steps, found no row at
      // all), so the caller could see the owner record after "expired". Now every path drops
      // the file first and the row after (dropDevlinkBlob is idempotent): once a move row is
      // gone, so is its bundle, and this request finishes the cleanup before answering.
      await dropDevlinkBlob(got.value);
      await KV.atomic().check(got).delete(k).commit();
      return null;
    }
    return got;
  };

  if (action === "open") {
    // the new phone: its ML-KEM-768 public key (the QR carries only its hash)
    const kemPub = String(body.kem_pub || "");
    if (!/^[A-Za-z0-9+/]{1500,1700}={0,2}$/.test(kemPub)) return j({ error: "kem_pub required", message: "kem_pub required" }, 400);
    // b75r1 (audit PX-01): the new phone's identity-key signature over its half of the
    // transcript. Stored and handed to the old phone unchanged: the old phone checks it
    // against its own identity key and refuses a code without it, so the relay only
    // checks its shape (an Ed25519 signature, 64 bytes as base64).
    const rsig = String(body.rsig ?? "");
    if (rsig && !/^[A-Za-z0-9+/]{86}==$/.test(rsig)) return j({ error: "rsig malformed", message: "rsig malformed" }, 400);
    // b75r3 (audit I-1): the Vardum ID the move is for (it is in the code too). When given, only
    // an offer signed by that ID's registered identity key is taken (see "offer"), so someone
    // who saw the code can no longer answer it first and kill the move.
    const veilId = String(body.veil_id ?? "");
    // b77u (audit 6 R4 #2): the Vardum ID is REQUIRED, so every offer is signature-checked. An open without one took the
    // first offer from anyone who saw the code (a race that killed the move). Every app since b75r3 sends it; an older
    // one is still served while the transition window (§12.19.4) is open.
    if (!veilId && !compatOn()) return j({ error: "Update Vardum to move to this phone", message: "Update Vardum to move to this phone", code: "veil_id_required" }, 400);
    if (veilId && !validVeilId(veilId)) return j({ error: "veil_id malformed", message: "veil_id malformed" }, 400);
    const put = await KV.atomic().check({ key: k, versionstamp: null }).set(k, {
      acct: me, // the receiving account (fetch / poll / ack)
      kem_pub: kemPub,
      rsig,
      ...(veilId ? { veil_id: veilId } : {}),
      exp: Date.now() + DEVLINK_TTL_MS,
      created_date: nowIso(),
    }).commit();
    if (!put.ok) return j({ error: "Transfer already exists", message: "Transfer already exists" }, 409);
    return json({ ok: true });
  }
  if (action === "peek") {
    // public material only: anyone holding the code may read the key it names
    const got = await live();
    if (!got || got.value!.offer) return j({ error: DEVLINK_GONE, message: DEVLINK_GONE }, 404);
    return json({ kem_pub: String(got.value!.kem_pub || ""), rsig: String(got.value!.rsig || "") });
  }
  if (action === "offer") {
    // the old phone: its ephemeral key, ML-KEM ciphertext, bundle commitment and an
    // identity-key signature (checked by the new phone, which holds that identity).
    // First offer wins; a second is refused, so the old phone learns someone else answered.
    const offer = String(body.offer || "");
    if (!offer || offer.length > 4096) return j({ error: "offer required", message: "offer required" }, 400);
    const got = await live();
    if (!got) return j({ error: DEVLINK_GONE, message: DEVLINK_GONE }, 404);
    if (got.value!.offer) return j({ error: "Another phone already answered this code", message: "Another phone already answered this code" }, 409);
    // b75r3 (audit I-1): a move opened for a Vardum ID takes only an offer that ID's identity key
    // signed over this token (domain-separated label). Checked BEFORE the first-offer-wins slot is
    // taken, so a refused offer leaves the code open for the real old phone.
    const forVid = String(got.value!.veil_id || "");
    if (forVid) {
      const id = (await KV.get<Record<string, unknown>>(["veil_identity", keySafe(forVid)])).value;
      const osig = String(body.osig ?? "");
      const ok = !!id && /^[A-Za-z0-9+/]{86}==$/.test(osig)
        && await ed25519Verify(String(id.IK_pub || ""), enc.encode("vardum-move-offer-relay-v1:" + token), osig);
      if (!ok) return j({ error: "This offer isn’t signed by the Vardum ID the move is for", message: "This offer isn’t signed by the Vardum ID the move is for" }, 403);
    }
    const done = await KV.atomic().check(got).set(k, { ...got.value, offer, sacct: me }).commit();
    if (!done.ok) return j({ error: "Another phone already answered this code", message: "Another phone already answered this code" }, 409);
    return json({ ok: true });
  }
  if (action === "poll") {
    // the new phone only
    const got = await live();
    if (!got || got.value!.acct !== me) return json({ state: "expired" });
    const v = got.value!;
    if (!v.offer) return json({ state: "open" });
    return json({ state: v.container_uri ? "ready" : "offered", offer: String(v.offer) });
  }
  if (action === "store") {
    // the old phone that made the offer, once, with a bundle file it uploaded itself
    const uri = canonBlobUri(String(body.container_uri || "")); // b77u (audit 6 U-M9 / F-05): canonical case
    // Batch E (RV-39) / b70 (re-review 7): a real blob this account uploaded.
    // b75: and never a vault container or another move's bundle (fetch deletes the file)
    if (!blobPathOf(uri) || !(await blobHeldBy(uri, me)) || await blobIsProtected(uri)) {
      return j({ error: "Not your file", message: "Not your file" }, 403);
    }
    const got = await live();
    if (!got || !got.value!.offer || got.value!.sacct !== me) return j({ error: DEVLINK_GONE, message: DEVLINK_GONE }, 404);
    if (got.value!.container_uri) return j({ error: "Transfer already sent", message: "Transfer already sent" }, 409);
    const done = await KV.atomic().check(got).set(k, { ...got.value, container_uri: uri, byte_length: Number(body.byte_length) || 0 })
      .set(["ix_devlink_uri", uri, String(k[1])], 1).commit(); // b77n (pre-audit L3): the bundle file's link index
    if (!done.ok) return j({ error: "Transfer already sent", message: "Transfer already sent" }, 409);
    return json({ ok: true });
  }
  if (action === "fetch") {
    // the new phone only; consume-once, atomically (two fetches can't both win)
    const got = await live();
    if (!got || got.value!.acct !== me) return j({ error: DEVLINK_GONE, message: DEVLINK_GONE }, 404);
    const row = got.value!;
    if (!row.container_uri) return j({ error: "Nothing sent yet", message: "Nothing sent yet" }, 409);
    const claim = await KV.atomic().check(got).delete(k)
      .set(["devlink_fetched", keySafe(token)], { acct: String(row.sacct || ""), racct: me, at: nowIso() }, { expireIn: 30 * 86_400_000 })
      .commit();
    if (!claim.ok) return j({ error: DEVLINK_GONE, message: DEVLINK_GONE }, 404);
    const path = blobPathOf(String(row.container_uri));
    let text = "";
    try { if (path) text = await Deno.readTextFile(path); } catch { text = ""; }
    await dropDevlinkBlob(row); // the file and its owner record, read or not
    if (!text) return j({ error: DEVLINK_GONE, message: DEVLINK_GONE }, 404);
    return json({ data: { blob: text } });
  }
  if (action === "ack") {
    // the new phone, after it saved everything. The relay can't check the ack (it is an
    // HMAC under a key only the two phones hold); the old phone does.
    const ack = String(body.ack || "");
    if (!/^[0-9a-f]{64}$/.test(ack)) return j({ error: "Transfer acknowledgement refused", message: "Transfer acknowledgement refused" }, 400);
    const fk = ["devlink_fetched", keySafe(token)];
    const fetched = await KV.get<Record<string, any>>(fk);
    if (!fetched.value || fetched.value.racct !== me) return j({ error: "Transfer acknowledgement refused", message: "Transfer acknowledgement refused" }, 403);
    const done = await KV.atomic().check(fetched).delete(fk)
      .set(["devlink_used", keySafe(token)], { acct: fetched.value.acct, ack, at: nowIso() }, { expireIn: 30 * 86_400_000 })
      .commit();
    if (!done.ok) return j({ error: "Transfer acknowledgement refused", message: "Transfer acknowledgement refused" }, 409);
    return json({ ok: true });
  }
  if (action === "status") {
    // the old phone (the account that made the offer) only
    const got = await live();
    if (got && got.value!.sacct === me) return json({ state: "waiting" });
    const usedKey = ["devlink_used", keySafe(token)];
    const usedGot = await KV.get<Record<string, any>>(usedKey);
    const used = usedGot.value;
    if (used && used.acct === me) {
      // b71 (audit): RETENTION of the ack. It rests on the relay until the old phone's
      // first status read, which rewrites the row to expire ACK_SECRET_AFTER_READ_MS
      // (1 h) later, so a lost reply can be retried; after that it is gone.
      if (!used.read_at) {
        await KV.atomic().check(usedGot).set(usedKey, { ...used, read_at: nowIso() }, { expireIn: ACK_SECRET_AFTER_READ_MS }).commit();
      } else if (Date.parse(String(used.read_at)) + ACK_SECRET_AFTER_READ_MS < Date.now()) {
        await KV.delete(usedKey); // expireIn is lazy; enforce the hour here too
        return json({ state: "expired" });
      }
      return json({ state: "used", ack: String(used.ack || "") });
    }
    const fetchedRow = (await KV.get<Record<string, any>>(["devlink_fetched", keySafe(token)])).value;
    if (fetchedRow && fetchedRow.acct === me) return json({ state: "fetched" });
    return json({ state: "expired" });
  }
  if (action === "cancel") {
    // either phone of a live move: the row and its bundle go now
    const got = await live();
    if (!got) return json({ ok: true, gone: true });
    if (got.value!.acct !== me && got.value!.sacct !== me) return json({ ok: true, gone: true });
    const del = await KV.atomic().check(got).delete(k).commit();
    if (del.ok) await dropDevlinkBlob(got.value);
    return json({ ok: true });
  }
  return j({ error: "Unknown action", message: "Unknown action" }, 400);
}

// ---------- veilSilentAccount (duress/silent provisioning — phrase never leaves the device) ----------
/** b77m (audit VAR-43): the only labels the app provisions — v<24 hex>@veil.app, derived from the
 *  24 words on the phone (vendor/device/src/silent-auth.ts isPhraseLabel) */
const PHRASE_LABEL_RE = /^v[0-9a-f]{24}@veil\.app$/;
async function fnVeilSilentAccount(auth: { userId: string }, body: Record<string, any>, req: Request | null = null, skipNet = false) {
  if (String(body.action || "") !== "provision") return j({ error: "Unknown action", message: "Unknown action" }, 400);
  // b77m (audit VAR-43): this pre-auth route accepted ANY label and answered "Email already
  // registered" at once (before any hash) — a fast label-existence oracle beside register's neutral,
  // equal-time reply. Now: a label that is not phrase-derived is refused with one fixed reply,
  // before anything is looked up (it says nothing about existence); a phrase-derived label that is
  // taken still answers "already registered" (the app relies on it for a retried provision; such
  // labels are 96-bit hashes of the words, not guessable), after the same hash a new account costs.
  const email = String(body.email || "").toLowerCase().trim();
  if (!PHRASE_LABEL_RE.test(email)) return j({ message: "Could not create an account with these details", code: "provision_refused" }, 400);
  try {
    const user = await createUser(email, String(body.password || ""), req, skipNet);
    const token = "vt_" + rid() + rid();
    await storeAuthToken(token, { userId: user.id, email: user.email, created: nowIso(), exp: Date.now() + TOKEN_IDLE_MS }); // b77s: with its per-account index entry; // b77m (audit VAR-44): exp at issue; b70 (re-review 7): expires on its own
    return json({ ok: true, access_token: token, user: { id: user.id, email: user.email } });
  } catch (e) {
    if (e instanceof PbkdfBusyError) throw e; // b77m (audit VAR-28): the router answers 429 busy
    const msg = String((e as Error).message);
    if (msg === "Email already registered") await dummyPasswordWork(email, String(body.password || ""), req, skipNet); // (equal time; b77m: the work this kind of account costs)
    return j({ message: msg }, 400);
  }
}

/**
 * b199 rebind — the 24-word sign-in follows the identity. The client derives
 * the new credentials from a NEW phrase on-device (silent-auth.ts) and sends
 * only the derived label + password; the phrase never leaves the phone.
 * Used when (a) "Generate new Veil ID" retires the phrase the account was
 * derived from, and (b) a classic made-up-email account switches its sign-in
 * to the 24 words. The old label stops working; the account, its vaults,
 * notes and identities are untouched. b70 (audit RLY-6): every existing token
 * (other devices included) is revoked; the caller signs in again.
 */
/**
 * b70 (re-review 3): the account's PRIMARY identity — the only one that may
 * move the sign-in (rebind). It is the first identity ever bound (for older
 * accounts: the earliest-bound one, recorded at the next bind), and a rebind
 * hands it to the identity the user just made. An identity someone binds with
 * a stolen token never becomes primary, however long it waits.
 */
/** b70 (re-review 4): how fresh a sign-in must be for its bind to establish a primary identity */
/** b70 (re-review 13): how long an account delete waits for requests already in flight */
const ACCOUNT_DELETE_DRAIN_MS = Number(Deno.env.get("VEIL_DELETE_DRAIN_MS") || 1500);
const PRIMARY_FRESH_SIGNIN_MS = Number(Deno.env.get("VEIL_PRIMARY_FRESH_MS")) || 30 * 60_000; // (env: test relays only)
/** b77u (audit 6 U-M14, R4 #27): an account is "new" for this long after it was created; only a bind inside it (the
 *  account's FIRST bind, from a fresh sign-in) is an onboarding bind and makes its identity the primary */
const PRIMARY_ONBOARD_MS = Number(Deno.env.get("VEIL_PRIMARY_ONBOARD_MS")) || 30 * 60_000; // (env: test relays only)

/**
 * The account's primary identity ("" = none).
 * b77u (audit 6 U-M14, R4 #27): the primary is set ONLY by (a) a proven onboarding bind (the account's first bind, from
 * a fresh sign-in, while the account is new: fnVeilIdentityGate bind), (b) a handover or rebind signed by the primary,
 * or (c) for an account from before b70, its earliest identity bound before bound_at existed (a row nobody can create
 * any more). It used to fall to the first identity bound from a FRESH sign-in on an account without one — so whoever
 * had the password signed in, bound their own identity, became primary, moved the sign-in and locked the owner out
 * (executed, R4 u3). A later bind on an account without a primary no longer makes one; the account keeps the no-primary
 * rules (a fresh sign-in for delete/purge; no rebind at all).
 * b77u (IH L-7): the pre-b70 scan reads every identity row, so it runs at most once per account: a scan that finds
 * nothing is recorded (primary_scan_none; new accounts are created with it) and never repeated — after (c) no row
 * can ever become eligible again.
 */
async function ensurePrimaryIdentity(userId: string): Promise<string> {
  for (let attempt = 0; attempt < 10; attempt++) {
    const ue = await KV.get<Record<string, any>>(["user", userId]);
    if (!ue.value) return "";
    // (b70 re-review 10: a primary whose row a purge removed is KEPT on purpose — clearing it
    // would let a stolen token purge and then delete the account unsigned; the owner
    // restores that identity from the 24 words to delete, rebind or hand over)
    if (typeof ue.value.primary_veil_id === "string" && ue.value.primary_veil_id) return ue.value.primary_veil_id;
    if (ue.value.primary_scan_none === true) return "";
    const mine = await accountHashOf(userId);
    let best = "", bestAt = Infinity;
    for await (const e of KV.list<Record<string, unknown>>({ prefix: ["veil_identity"] })) {
      const r = e.value;
      if (!r || r.bound !== true || String(r.account_hash || "") !== mine) continue;
      // only identities bound before b70's bound_at existed (b77u: no longer any bound later from a fresh sign-in)
      if (r.bound_at) continue;
      const vid = String(r.veil_id || e.key[1] || "");
      const at = Date.parse(String(r.created_date || "")) || Infinity;
      if (at < bestAt) { best = vid; bestAt = at; }
    }
    const next = best ? { ...ue.value, primary_veil_id: best, primary_trust: "legacy" } : { ...ue.value, primary_scan_none: true };
    if ((await KV.atomic().check(ue).set(["user", userId], next).commit()).ok) return best;
  }
  return "";
}
/**
 * b77u (audit 6 U-M14): is the account's primary one the account was set up with (or one such a primary handed on)?
 * "onboard" (an onboarding bind), "legacy" (pre-b70), "password" (a rebind proven with the current password) and
 * "chain" (handed over / rebound by a trusted primary) are; a primary recorded after the account's creation by the old
 * rule (no primary_trust: an identity bound from a fresh sign-in any time later — possibly by a password holder) is
 * trusted only when its identity was bound within PRIMARY_ONBOARD_MS of the account's creation, or before bound_at.
 */
async function primaryTrusted(user: Record<string, any>): Promise<boolean> {
  const t = String(user.primary_trust || "");
  if (t === "onboard" || t === "legacy" || t === "password" || t === "chain") return true;
  if (t) return false; // "untrusted" (a handover from an untrusted primary)
  const pid = String(user.primary_veil_id || "");
  if (!pid) return false;
  const row = (await KV.get<Record<string, unknown>>(["veil_identity", keySafe(pid)])).value;
  if (!row) return false;
  if (!row.bound_at) return true;
  const created = Date.parse(String(user.created || "")) || 0;
  const boundAt = Date.parse(String(row.bound_at || "")) || Infinity;
  return !!created && boundAt - created <= PRIMARY_ONBOARD_MS;
}

/** b75 (audit RL-13): the new password as the rebind proof names it:
 *  hex(SHA-256(utf8("vardum-rebind-pw-v1:" + password))) — never the password itself */
function rebindPasswordTag(password: string): Promise<string> {
  return sha256hex("vardum-rebind-pw-v1:" + password);
}

// b75r1 (audit REL-03): retired labels are kept as hashes only. A label given up by a rebind
// (an email the user moved away from, or the previous 24 words' label) must never sign up or
// be rebound again (Batch D D-17, R3-07), so the relay keeps a labelled hash of it
// (["label_retired_h", retiredLabelTag(label)] → account id, and the same tag on
// user.retired_labels), plus the label's group-account hash on user.retired_group_accts so an
// account delete still finds legacy label-keyed group rows. Both are unkeyed hashes: whoever
// holds the database and guesses the email can confirm the guess (a dictionary test), but the
// label is no longer stored readable. Rows from before b75r1 are converted at boot
// (migrateRetiredLabels); until then the old plaintext row is still honoured.
async function retiredLabelTag(label: string): Promise<string> {
  return "rl_" + await sha256hex("veil-retired-label:" + label.toLowerCase().trim());
}
function groupAccountOfLabel(label: string): Promise<string> {
  return sha256hex("veil-group-account:" + label.toLowerCase().trim());
}
async function labelRetired(label: string): Promise<boolean> {
  const l = label.toLowerCase().trim();
  if ((await KV.get<string>(["label_retired_h", await retiredLabelTag(l)])).value) return true;
  return !!(await KV.get<string>(["label_retired", l])).value; // a pre-b75r1 row the boot migration has not reached yet
}
/** the retired-label tags and group-account hashes on a user row (legacy plaintext entries converted) */
async function retiredLabelSets(user: Record<string, any> | null | undefined): Promise<{ tags: Set<string>; groupAccts: Set<string> }> {
  const tags = new Set<string>(), groupAccts = new Set<string>();
  for (const v of Array.isArray(user?.retired_labels) ? user!.retired_labels.map(String) : []) {
    if (v.includes("@")) { tags.add(await retiredLabelTag(v)); groupAccts.add(await groupAccountOfLabel(v)); } // a label (pre-b75r1)
    else if (v) tags.add(v);
  }
  for (const g of Array.isArray(user?.retired_group_accts) ? user!.retired_group_accts.map(String) : []) if (g) groupAccts.add(g);
  return { tags, groupAccts };
}
/** a label's sign-in throttle rows (b70 RLY-2 / b71 F-03 keys) */
async function dropLabelLoginGuards(label: string): Promise<void> {
  const l = label.toLowerCase().trim();
  await KV.delete(["login_guard", keySafe(l)]);
  for await (const e of KV.list({ prefix: ["login_guard_h", await sha256hex("veil-login-guard:" + l)] })) await KV.delete(e.key);
  await KV.delete(["login_guard_acct", await sha256hex("veil-login-guard:" + l)]);
  await KV.delete(loginLabelCapKey(await sha256hex("veil-login-guard:" + l))); // b77t2 (CL-1)
}
/** once, at boot: plaintext retired labels (index rows and user rows) become hashes */
async function migrateRetiredLabels(): Promise<number> {
  let n = 0;
  for await (const e of KV.list<string>({ prefix: ["label_retired"] }, { consistency: "strong" })) {
    const label = String(e.key[1] ?? "");
    if (label) await KV.set(["label_retired_h", await retiredLabelTag(label)], e.value);
    await KV.delete(e.key);
    n++;
  }
  for await (const e of KV.list<Record<string, any>>({ prefix: ["user"] }, { consistency: "strong" })) {
    const u = e.value;
    if (!u || !Array.isArray(u.retired_labels) || !u.retired_labels.some((v: unknown) => String(v).includes("@"))) continue;
    const sets = await retiredLabelSets(u);
    if ((await KV.atomic().check(e).set(e.key, { ...u, retired_labels: [...sets.tags], retired_group_accts: [...sets.groupAccts] }).commit()).ok) n++;
  }
  return n;
}

async function fnSilentAccountRebind(auth: { userId: string }, body: Record<string, any>, req: Request | null = null) {
  const email = String(body.email || "").toLowerCase().trim();
  const password = String(body.password || "");
  if (!/^v[0-9a-f]{24}@veil\.app$/.test(email) || password.length < 32) {
    return j({ message: "Invalid phrase-derived credentials" }, 400);
  }
  if (!(await KV.get<Record<string, any>>(["user", auth.userId])).value) return j({ message: "Account not found" }, 404);
  { const lim = await routeLimited("rebind", auth.userId, 10); if (lim) return lim; } // b70 (re-review 7)
  let nextPrimary = "", signerVid = "", trustNext = "chain";
  // b70 (re-review R2): a token alone can't move the sign-in. The caller signs
  // the change with an identity bound to this account for at least 72 hours
  // (someone holding a stolen token could bind a NEW identity, but not an old one).
  {
    const proof = (body.proof ?? {}) as { veil_id?: unknown; ts?: unknown; sig?: unknown; next_veil_id?: unknown };
    const pvid = String(proof.veil_id ?? ""), pts = Number(proof.ts), psig = String(proof.sig ?? ""), pnext = String(proof.next_veil_id ?? "");
    if (!pvid || !Number.isFinite(pts) || !psig) return j({ message: "Update Vardum to change how you sign in" }, 403);
    if (Math.abs(Date.now() - pts) > 10 * 60_000) return j({ message: "This request is too old — try again" }, 403);
    const pid = (await KV.get<Record<string, unknown>>(["veil_identity", keySafe(pvid)])).value;
    // b70 (re-review 3): the signer must be the account's PRIMARY identity. (This
    // replaces the 72-hour age rule, which only delayed a stolen-token takeover:
    // an identity bound with a stolen token simply aged into eligibility.)
    const boundHere = !!pid && pid.bound === true && String(pid.account_hash || "") === await accountHashOf(auth.userId);
    if (!boundHere || pvid !== await ensurePrimaryIdentity(auth.userId)) return j({ message: "Changing how you sign in needs the Vardum ID this account was set up with" }, 403);
    // b75 (audit RL-13): v3 also binds the NEW PASSWORD (as rebindPasswordTag, a labelled
    // hash), so the identity signature covers every credential the change installs. v2 named
    // the label but not the password, so whoever relayed or replayed a signed request inside
    // its 10 minutes could swap in a password of their own.
    const msg = enc.encode(`vardum-rebind-v3:${auth.userId}:${email}:${pts}:${pnext}:${await rebindPasswordTag(password)}`);
    if (!(await ed25519Verify(String(pid!.IK_pub || ""), msg, psig))) return j({ message: "Sign-in change not authorised" }, 403);
    if (pnext) {
      const nid = (await KV.get<Record<string, unknown>>(["veil_identity", keySafe(pnext)])).value;
      if (!nid || nid.bound !== true || String(nid.account_hash || "") !== await accountHashOf(auth.userId)) return j({ message: "The new Vardum ID isn't set up on this account yet — try again" }, 409);
    }
    nextPrimary = pnext || pvid;
    // b77u (audit 6 U-M14): a primary recorded AFTER the account was set up (the old first-fresh-binder rule: possibly a
    // password holder's own identity) can't move the sign-in on its signature alone: the request also carries the
    // account's CURRENT password (body.current_password; for a 24-word account its phrase-derived secret), checked as a
    // sign-in checks it. Without it: 403 code current_password_required. A primary from an onboarding bind (or handed on by
    // one) needs only its signature, as before.
    const uNow = (await KV.get<Record<string, any>>(["user", auth.userId], { consistency: "strong" })).value;
    if (!uNow) return j({ message: "Account not found" }, 404);
    if (!(await primaryTrusted(uNow))) {
      const cur = typeof body.current_password === "string" ? body.current_password : "";
      if (!cur || !req) return j({ message: "Enter your current password to change how you sign in", code: "current_password_required" }, 403);
      const refused = await accountPasswordRefusal(req, { ...uNow, id: auth.userId }, body, cur, "rebind-day");
      if (refused) return refused;
      trustNext = "password";
    }
    signerVid = pvid;
  }
  // read after the checks: ensurePrimaryIdentity may have just recorded the primary
  const userEntry = await KV.get<Record<string, any>>(["user", auth.userId]);
  const user = userEntry.value;
  if (!user) return j({ message: "Account not found" }, 404);
  const ownerEntry = await KV.get<string>(["user_email", email]);
  const owner = ownerEntry.value;
  if (owner && owner !== auth.userId) return j({ message: "That recovery phrase already signs in to a different account" }, 409);
  // Batch E (round-3 review R3-07): a retired label is never taken again, by a
  // rebind any more than by a sign-up (D-17) — whoever holds a retired phrase
  // could rebind to it and reach the label-keyed legacy group rows
  if (await labelRetired(email)) return j({ message: "That recovery phrase was retired and can't be used again" }, 409);
  const oldEmail = String(user.email || "");
  const salt = crypto.randomUUID().replace(/-/g, "");
  // Batch D (D-17): the old label is retired, not freed (see createUser)
  // b75r1 (audit REL-03): kept as hashes only — retiredLabelTag for the "never again" check,
  // and the label's group-account hash (what legacy label-keyed group rows carry, so an
  // account delete can still find them). The label itself (an email, after a switch to
  // 24-word sign-in) used to stay in clear here and in a ["label_retired", label] row.
  const retiredSets = await retiredLabelSets(user);
  if (oldEmail && oldEmail !== email) { retiredSets.tags.add(await retiredLabelTag(oldEmail)); retiredSets.groupAccts.add(await groupAccountOfLabel(oldEmail)); }
  // b70 (audit RLY-6): every token issued before this moment stops working,
  // the caller's too (the client signs in again with the new credentials)
  // b77m (owner): the new phrase-derived secret takes the cheap form (newPasswordRecord); kdf / iter never carry over
  const pw = await newPasswordRecord(email, password, salt, null);
  const { kdf: _oldKdf, iter: _oldIter, tokens_after_keep: _oldKeep, ...userRest } = user as Record<string, unknown>; // b77s (N-3): a rebind keeps no token
  const next = { ...userRest, email, salt, ...pw /* b71 (audit F-03): PBKDF2 at the current count otherwise */, retired_labels: [...retiredSets.tags], retired_group_accts: [...retiredSets.groupAccts], updated: nowIso(), tokens_after: Date.now(), primary_veil_id: nextPrimary /* b70 (re-review 3): the new identity takes over */, primary_trust: trustNext /* b77u (U-M14) */ };
  // b70 (re-review): the new label is claimed atomically (checked unchanged since read)
  const tx = KV.atomic().check(ownerEntry).check(userEntry).set(["user", auth.userId], next).set(["user_email", email], auth.userId);
  if (oldEmail && oldEmail !== email) tx.delete(["user_email", oldEmail]).set(["label_retired_h", await retiredLabelTag(oldEmail)], auth.userId);
  // b75r1 (audit REL-01): "Generate new Vardum ID" — the signer hands the primary role to the
  // new identity, and its own row goes in the same step (it stops answering lookup; the two
  // identity rows no longer sit side by side under one account hash)
  const retiring = nextPrimary !== signerVid ? signerVid : "";
  if (retiring) tx.delete(["veil_identity", keySafe(retiring)]);
  // b76 (registration lock): its PIN proof is salted with the retiring identity's seed, which
  // no phone holds any more — it could never be answered again, so it ends in the same step
  // (answered reglock_off; the app asks the user to turn it on again with the new ID)
  const lockEntry = retiring ? await KV.get<RegLockRow>(regLockKey(await accountHashOf(auth.userId))) : null;
  if (lockEntry?.value) tx.check(lockEntry).delete(lockEntry.key);
  const done = await tx.commit();
  if (!done.ok) return j({ message: "Could not update sign-in — try again" }, 409);
  if (retiring) await dropRetiredIdentityRows(retiring);
  await withLock("purgetok:" + auth.userId, () => dropPurgeToken(auth.userId)); // b77u (audit 6 W1, IH relay F-01): every sign-in is revoked; so is the purge token
  // b75r1 (audit REL-03): the old label's sign-in throttle rows go now (it can't sign in any more)
  if (oldEmail && oldEmail !== email) await dropLabelLoginGuards(oldEmail);
  // ...and the account's login-token rows, which carry the old label: tokens_after has just
  // revoked every one of them, but the rows lived on (with the label) until they aged out
  for await (const e of KV.list<Record<string, unknown>>({ prefix: ["auth"] }, { consistency: "strong" })) {
    if (String(e.value?.userId || "") === auth.userId) await KV.delete(e.key);
  }
  for await (const e of KV.list({ prefix: ["auth_acct", auth.userId] }, { consistency: "strong" })) await KV.delete(e.key); // b77s: the token index entries go with them
  return json({ ok: true, user: { id: auth.userId, email }, ...(lockEntry?.value ? { reglock_off: true } : {}) });
}

// ---------- veilAccountDelete (the K-11 cascade) ----------
// "Deleted means deleted" (from the live database): every row keyed to the account
// — its id, its label (the sign-in email / phrase-derived v…@veil.app), its account
// hash, its per-row owner tags, its veil ids and the sessions it took part in —
// goes, and so (b71, audit F-15) do the throttle rows that name it or its chats:
// the call-ring and ring-cap rows and the notify limiter of each of its chats, its
// TURN eligibility row, its account-wide login guard, and the push-address caps and
// challenges of its devices. relay/account-delete-test.mjs and
// relay/b71-audit-ext-relay-test.mjs prove it against the database itself. Nightly
// backups (backup.sh) still hold older copies until they age out (7–14 days).
/**
 * b74 (audit VAR-12): the proof an account-destroying request carries — shared by account
 * delete ("vardum-delete-v1") and the session purge ("vardum-purge-v1"). Where the account
 * has a primary identity, only the primary signs `<label>:<userId>:<ts>` (ts within 10
 * minutes). Without one (no identity was ever bound right after a real sign-in), the
 * request must come from a FRESH sign-in instead. null = proven; otherwise the refusal.
 */
/**
 * b77t (audit 5 L-15, IH R-08): SINGLE-USE proofs. A proof could be replayed for its whole 10-minute window (no
 * used-marker, no nonce). Now:
 *  - the current form carries a relay-issued nonce (veilProofNonce {label} -> {nonce}; 10 minutes, for this account
 *    and this label only): the primary signs `<label>:<userId>:<ts>:<nonce>`, and the nonce is consumed (deleted, in
 *    one atomic step) by the request that uses it;
 *  - the older form (no nonce: `<label>:<userId>:<ts>`) is accepted only where `legacy` allows it — "compat" while the
 *    transition window is open (§12.19.4; old apps' delete and lock-off), "always" for the duress purge (its proof is
 *    signed in memory before the erase, which may make no network call) — and then only ONCE: a used-marker keyed on
 *    a hash of the proof is written in the same check (10 minutes plus a margin). An account delete retried while its
 *    first run is still in progress (deleting_at fresh) may present the same proof again (b77i retries);
 *  - the new sign-out-others proof ("vardum-signout-others-v1") takes the nonce form only.
 */
const PROOF_NONCE_TTL_MS = 10 * 60_000;
const PROOF_LABELS = new Set(["vardum-delete-v1", "vardum-purge-v1", "vardum-reglock-off-v1", "vardum-signout-others-v1", "vardum-purge-token-v1", "vardum-reglock-set-v1" /* b77u (audit 6 W2) */]);
/** b77u (audit 6, IH relay F-03): a nonce-less proof's used-marker lives until the proof itself is dead (ts + 10 min,
 *  whatever the clock skew) plus a margin. A fixed 15 minutes let a proof dated up to 10 minutes ahead replay once the
 *  marker had expired (it stays valid until ts + 10 min). */
const proofUsedTtl = (ts: number) => Math.max(0, ts + PROOF_NONCE_TTL_MS - Date.now()) + 5 * 60_000;
const proofNonceKey = (userId: string, nonce: string): Deno.KvKey => ["proof_nonce", userId, nonce];
async function primaryProofRefusal(auth: { userId: string }, body: Record<string, any>, label: string, msgs: { proof: string; fresh: string }, opts: { deleteRetry?: boolean; legacy?: "compat" | "always" | "never"; noFreshSignIn?: boolean } = {}): Promise<Response | null> {
  const primary = await ensurePrimaryIdentity(auth.userId);
  // b70 (re-review 12, revised): with a primary, only the primary signs. Without one,
  // a fresh sign-in — letting any bound identity sign let a stolen token bind its own
  // key and sign, and a purge left nobody to sign at all
  if (primary) {
    const proof = (body?.proof ?? {}) as { veil_id?: unknown; ts?: unknown; sig?: unknown; nonce?: unknown };
    const ts = Number(proof.ts), pid = (await KV.get<Record<string, unknown>>(["veil_identity", keySafe(primary)])).value;
    // b77i (I-1): an account delete interrupted after it removed the primary's identity row kept
    // that row's key in its work rows (written by this account's own signed delete, just before the
    // row went); the retry is verified against it. Nothing else reads those rows.
    let ik = pid ? String(pid.IK_pub || "") : "";
    if (!pid && opts.deleteRetry) ik = String((await KV.get<{ ik?: string }>(acctDelKey(auth.userId, "v", keySafe(primary)))).value?.ik || "");
    const nonce = typeof proof.nonce === "string" && /^[0-9a-f]{32}$/.test(proof.nonce) ? proof.nonce : null;
    if (proof.nonce !== undefined && !nonce) return j({ message: msgs.proof }, 403);
    const base = String(proof.veil_id ?? "") === primary && Number.isFinite(ts) && Math.abs(Date.now() - ts) <= 10 * 60_000 && !!ik;
    if (!base) return j({ message: msgs.proof }, 403);
    const sig = String(proof.sig ?? "");
    // b77t2 (CL-2): the signature must be CANONICAL base64 (padded, no whitespace, unused low bits zero). atob() took
    // other spellings of the same 64 bytes, and the nonce-less "used once" marker hashed the string, so a re-spelled
    // signature replayed the proof. The marker below is keyed on the decoded bytes as well.
    if (!canonicalB64(sig)) return j({ message: msgs.proof }, 403);
    if (nonce) {
      // b77t (L-15): the nonce must be live, this account's and this label's; consumed in one step by its first use
      const row = await KV.get<{ label?: string }>(proofNonceKey(auth.userId, nonce), { consistency: "strong" });
      if (!row.value || row.value.label !== label) return j({ message: msgs.proof }, 403);
      if (!(await ed25519Verify(ik, enc.encode(`${label}:${auth.userId}:${ts}:${nonce}`), sig))) return j({ message: msgs.proof }, 403);
      if (!(await KV.atomic().check(row).delete(row.key).commit()).ok) return j({ message: msgs.proof }, 403);
      return null;
    }
    const legacy = opts.legacy ?? "compat";
    if (legacy === "never" || (legacy === "compat" && !compatOn())) return j({ message: msgs.proof, code: "proof_nonce_required" }, 403);
    if (!(await ed25519Verify(ik, enc.encode(`${label}:${auth.userId}:${ts}`), sig))) return j({ message: msgs.proof }, 403);
    // b77t (L-15): a nonce-less proof is used once
    const sigHex = [...b64d(sig)].map((b) => b.toString(16).padStart(2, "0")).join(""); // b77t2 (CL-2): the bytes, not the spelling
    const used: Deno.KvKey = ["proof_used", await sha256hex(`veil-proof-used-v2:${label}:${auth.userId}:${ts}:${sigHex}`)];
    if ((await KV.atomic().check({ key: used, versionstamp: null }).set(used, 1, { expireIn: proofUsedTtl(ts) }).commit()).ok) return null; // b77u (IH F-03)
    if (opts.deleteRetry) {
      const u = (await KV.get<Record<string, unknown>>(["user", auth.userId])).value;
      if (!u || Number(u.deleting_at || 0) > Date.now() - 10 * 60_000) return null; // (a retry of a delete already under way)
    }
    return j({ message: msgs.proof, code: "proof_used" }, 403);
  }
  if (opts.noFreshSignIn) return j({ message: msgs.fresh }, 403); // b77t (L-6): a fresh sign-in alone is not a fresh credential here
  const created = (auth as { tokenCreated?: number }).tokenCreated || 0;
  if (!created || Date.now() - created > PRIMARY_FRESH_SIGNIN_MS) return j({ message: msgs.fresh }, 403);
  return null;
}

// ---------- b76 (registration lock): an opt-in PIN for signing in to the account on a new phone ----------
// Without it, the 24 words alone sign in to the phrase-derived account on any phone (and can
// bind the identity to another account), and the owner's phone then shares the account with
// whoever did it. With the lock on, while it is ACTIVE (the account's phones checked in within
// REGLOCK_LAPSE_MS) a sign-in from a phone that is not the owning phone, and a bind of one of the
// account's identities from another account, also need a proof of the PIN. Spec §12.17, §8.2.
//
// What the relay holds (["reglock", account hash]): a random salt and
// verifier = PBKDF2-SHA256-600k("vardum-reglock-v1:" ‖ pin_auth, salt), where the phone computes
// pin_auth = HMAC(PBKDF2-SHA256-600k(PIN, HMAC(IK seed, "vardum-reglock-salt-v1")), "vardum-reglock-auth-v1")
// (dev/reglock.ts). The PIN itself never reaches the relay, and its salt comes from the identity
// seed, which the relay never sees: from the database alone (or as a malicious relay that sees
// pin_auth arrive) a PIN can't be guessed offline without ALSO the 24 words. With the words, a
// short PIN can be guessed offline from the verifier at 2 x 600k PBKDF2 per guess — only rate
// limits protect it, and only against someone who must ask an honest relay. No secure hardware
// (Signal uses SGX) stands behind this; spec §8.2.
// Attempts: counted per account, only from callers who already proved the words (right password,
// or a valid identity signature on a bind), reserved atomically before the check (parallel
// guesses each count), REGLOCK_FREE_FAILS free, then exponential back-off, and after
// REGLOCK_MAX_FAILS the lock refuses every PIN until it lapses (the owning phone is unaffected).
// The owning phone: holds a device key (only its hash is stored), returned by `set` and by a sign-in
// that proved the PIN; a sign-in presenting it needs no PIN (e.g. the sign-in after a rebind).
/** b76 (registration lock): how long the lock stays active after the account's last check-in */
const REGLOCK_LAPSE_MS = 7 * 86400_000;
/** b76 (registration lock): wrong PINs before the lock refuses every PIN until it lapses */
const REGLOCK_MAX_FAILS = 10;
/** b76 (registration lock): wrong PINs without a wait; then 1, 2, 4 … 128 minutes */
const REGLOCK_FREE_FAILS = 2;
/** b76 (registration lock): an authenticated request renews the lock at most this often per account */
const REGLOCK_RENEW_EVERY_MS = 10 * 60_000;
const regLockKey = (acct: string): Deno.KvKey => ["reglock", acct];
/** b76r1 (registration lock): `pin_restore_at` — when a PIN sign-in last made a new owning phone (ms;
 *  absent: never). `status` reports it so the old phone can say what happened. */
/** b76r2 (registration lock, audit DEV-R2-02): `pin_set_at` — when the PIN was last set (`set`, ms) —
 *  and `pin_set_tag` — the device tag of the phone that set it (the key `set` handed out; it follows
 *  that phone's key rotations while it stays the owning phone). `status` turns them into
 *  `pin_changed_at` for any other phone. Rows written before b76r2 have neither. */
type RegLockRow = { v: 1; salt: string; verifier: string; device_tag: string; veil_id: string; enabled_at: number; last_seen: number; fails: number; next_try: number; pin_restore_at?: number; pin_set_at?: number; pin_set_tag?: string };
/** b76r1 (registration lock): refusals that spend no attempt (no PIN, a PIN inside the wait, a PIN
 *  after the lockout) per locked account and hour, past which the sign-in / bind answers 429 */
const REGLOCK_FREE_REFUSALS_PER_HOUR = 20;
const DAY_MS = 86_400_000;
function regLockActive(row: RegLockRow | null | undefined, now = Date.now()): row is RegLockRow {
  return !!row && now - (Number(row.last_seen) || 0) < REGLOCK_LAPSE_MS;
}
function regLockBackoffMs(fails: number): number {
  return fails <= REGLOCK_FREE_FAILS ? 0 : Math.min(2 ** (fails - REGLOCK_FREE_FAILS - 1), 24 * 60) * 60_000;
}
const regLockDeviceTag = (key: string) => sha256hex("vardum-reglock-device-v1:" + key);
// b77m (audit VAR-28): outside the hashing budget — a PIN try is already reserved (counted) before it is
// hashed, and the lock allows only a few a day, so a busy refusal must not spend one
const regLockVerifier = (pinAuth: string, salt: string) => pbkdf2Hex("vardum-reglock-v1:" + pinAuth, salt, PBKDF2_ITERATIONS);
/** the phone's PIN proof: canonical base64 of 32 bytes */
function pinAuthShape(v: unknown): v is string {
  return canonicalB64(v) && b64d(v).length === 32;
}
/** 423: the lock is active and no (valid) PIN came with the request. Only callers that proved
 *  the words see it; it says how many tries are left.
 *  b76r1 (registration lock): `lapse_at` was last_seen + 7 days on every 423, so repeated PIN-less
 *  sign-ins (free) told a holder of the words when the owner was last online, to within 10 minutes.
 *  Now it comes only with a refusal that SPENT an attempt (a wrong PIN: at most 10 until the lock
 *  lapses), rounded up to the next UTC midnight (the app shows a date); every other 423 says 0, which
 *  the app shows as "once the old phone has been offline for 7 days". */
function regLockRefusal(row: RegLockRow, extra: Record<string, unknown> = {}): Response {
  const now = Date.now(), left = Math.max(0, REGLOCK_MAX_FAILS - (Number(row.fails) || 0));
  const lockedOut = left === 0;
  const message = lockedOut ? "Too many wrong registration lock PINs. The lock now holds until it lapses."
    : extra.wrong_pin ? "Wrong registration lock PIN."
    : extra.retry_later ? "Wait a little before the next registration lock PIN."
    : "This account has a registration lock. Enter its PIN to finish on this phone.";
  const lapseAt = extra.wrong_pin ? Math.ceil(((Number(row.last_seen) || 0) + REGLOCK_LAPSE_MS) / DAY_MS) * DAY_MS : 0;
  return j({ message, reglock_required: true, lapse_at: lapseAt, attempts_left: left, retry_at: lockedOut ? 0 : Math.max(Number(row.next_try) || 0, now), ...(lockedOut ? { locked_out: true } : {}), ...extra }, 423);
}
/** b76r1 (registration lock): a refusal that spends no attempt, capped per locked account (see
 *  REGLOCK_FREE_REFUSALS_PER_HOUR) — it still costs the caller the password check before it, and
 *  now says nothing about the owner, but repeating it can still tell "active" from "lapsed" (a
 *  lapsed lock lets the sign-in through, and ends) */
async function regLockFreeRefusal(acct: string, row: RegLockRow, extra: Record<string, unknown> = {}): Promise<Response> {
  const lim = await rateLimit("reglockask:" + acct, REGLOCK_FREE_REFUSALS_PER_HOUR, 3_600_000, 0);
  if (lim) return j({ message: "Too many sign-in attempts on this account — try again later", locked: true, retry_minutes: lim.retry_minutes }, 429);
  return regLockRefusal(row, extra);
}
/**
 * b76 (registration lock): the lock check for one account. `refused` = the answer to send;
 * otherwise the request may go on (`deviceKey`: the PIN was proven, this is the new owning
 * phone's key; `lapsed`: the lock's entry, when it is there but has lapsed).
 * `allowDevice` is true for a sign-in (the device key passes, and a proven PIN makes a new owning
 * phone) and false for a bind of a bound identity from another account.
 * b76r1 (registration lock): a bind that proves the PIN no longer touches the holding account's
 * device tag. It used to replace it with the tag of a fresh key that nobody received, so the
 * account's own (still owning) phone needed the PIN at its next sign-in. Only a PIN SIGN-IN makes
 * a new owning phone, and it records when (`pin_restore_at`).
 */
async function regLockGate(acct: string, body: Record<string, any>, allowDevice: boolean): Promise<{ refused: Response | null; deviceKey?: string; deviceKeyNext?: string; lapsed?: Deno.KvEntryMaybe<RegLockRow> }> {
  for (let attempt = 0; attempt < 10; attempt++) {
    const e = await KV.get<RegLockRow>(regLockKey(acct));
    const row = e.value;
    if (!row) return { refused: null };
    const now = Date.now();
    // the owning phone (its device key) gets in, lapsed or not, and that counts as a check-in.
    // b76r2 (registration lock, audit DEV-R2-03): and its key is ROTATED: the sign-in answers a new
    // device key (`reglock_device_next`) and the presented one stops passing, in one
    // versionstamp-checked step. A copy of the key (Nothing-at-Rest keeps it with the login, §6.2) plus
    // the words used to sign in from any phone without the PIN and leave no trace; now the first use
    // of a copy makes the owner's own key stale (its next sign-in needs the PIN and `status` says
    // device_matches: false), and a copy made before the owner's last sign-in is already dead. Of two
    // sign-ins racing with the same key one wins; the other reads the row again, its key no longer
    // matches, and it is treated as a phone without the key.
    const dev = body?.reglock_device;
    if (allowDevice && typeof dev === "string" && dev && dev.length <= 128 && row.device_tag && ctEq(await regLockDeviceTag(dev), row.device_tag)) {
      const nextKey = b64e(crypto.getRandomValues(new Uint8Array(32)));
      const nextTag = await regLockDeviceTag(nextKey);
      const setterMoves = !!row.pin_set_tag && ctEq(row.pin_set_tag, row.device_tag); // the phone that set the PIN keeps being it
      const upd: RegLockRow = { ...row, last_seen: now, device_tag: nextTag, ...(setterMoves ? { pin_set_tag: nextTag } : {}) };
      if (!(await KV.atomic().check(e).set(regLockKey(acct), upd).commit()).ok) continue;
      return { refused: null, deviceKeyNext: nextKey };
    }
    if (!regLockActive(row, now)) return { refused: null, lapsed: e };
    const pin = body?.reglock_pin;
    if (pin === undefined || pin === null || pin === "") return { refused: await regLockFreeRefusal(acct, row) };
    // not a guess: never counted. b76r2 (audit RL-1): but it says "the lock is active" as plainly as
    // a PIN-less refusal does, so it spends the same capped budget of free refusals (it used to be an
    // uncapped probe that kept answering after the cap had turned PIN-less sign-ins into 429s)
    if (!pinAuthShape(pin)) {
      const lim = await rateLimit("reglockask:" + acct, REGLOCK_FREE_REFUSALS_PER_HOUR, 3_600_000, 0);
      if (lim) return { refused: j({ message: "Too many sign-in attempts on this account — try again later", locked: true, retry_minutes: lim.retry_minutes }, 429) };
      return { refused: j({ message: "Malformed registration lock proof" }, 400) };
    }
    if ((Number(row.fails) || 0) >= REGLOCK_MAX_FAILS) return { refused: await regLockFreeRefusal(acct, row) };
    if (now < (Number(row.next_try) || 0)) return { refused: await regLockFreeRefusal(acct, row, { retry_later: true }) };
    // reserve this attempt BEFORE the slow check, against the row as read: of parallel guesses
    // each one counts (a lost race reads again)
    const fails = (Number(row.fails) || 0) + 1;
    const reserved: RegLockRow = { ...row, fails, next_try: now + regLockBackoffMs(fails) };
    if (!(await KV.atomic().check(e).set(regLockKey(acct), reserved).commit()).ok) continue;
    if (!ctEq(await regLockVerifier(pin, row.salt), String(row.verifier || ""))) return { refused: regLockRefusal(reserved, { wrong_pin: true }) };
    // proven: the count clears. A sign-in: this phone becomes the owning phone (new device key,
    // pin_restore_at) and the lock is renewed. A bind: nothing else changes on the holding
    // account's lock (its owning phone and its check-in time stay as they were).
    const deviceKey = allowDevice ? b64e(crypto.getRandomValues(new Uint8Array(32))) : "";
    const tag = allowDevice ? await regLockDeviceTag(deviceKey) : "";
    for (let w = 0; w < 10; w++) {
      const cur = await KV.get<RegLockRow>(regLockKey(acct));
      // the lock was turned off or its PIN changed meanwhile: the new rule decides (ask again)
      if (!cur.value || cur.value.verifier !== row.verifier) return cur.value ? { refused: regLockRefusal(cur.value) } : { refused: null };
      const t = Date.now();
      const next: RegLockRow = allowDevice ? { ...cur.value, fails: 0, next_try: 0, last_seen: t, device_tag: tag, pin_restore_at: t } : { ...cur.value, fails: 0, next_try: 0 };
      if ((await KV.atomic().check(cur).set(regLockKey(acct), next).commit()).ok) return allowDevice ? { refused: null, deviceKey } : { refused: null };
    }
    return { refused: j({ message: "Busy — try again" }, 429) };
  }
  return { refused: j({ message: "Busy — try again" }, 429) };
}
/** b76 (registration lock): an authenticated request is the account checking in — renews the
 *  lock (at most every REGLOCK_RENEW_EVERY_MS per account and process) */
// b77u (audit 6 W2, R4 #3): only from the OWNING phone — a token issued against the lock's current device tag (`rl`: a
// sign-in with the device key or the PIN, or the phone that set the PIN). Any signed-in token used to keep the lock from
// lapsing, so a stolen or second phone's token held it on for good while the owner's phone was gone. A token issued by a
// build before this rule (created before rlMarkEpoch, recorded at the first start of this build) keeps the old rule until
// it expires.
const regLockSeen = new Map<string, number>();
let rlMarkEpoch = 0;
async function regLockRenew(userId: string, tok?: { rl?: string; created?: string }): Promise<void> {
  const now = Date.now();
  if (now - (regLockSeen.get(userId) ?? 0) < REGLOCK_RENEW_EVERY_MS) return;
  const k = regLockKey(await accountHashOf(userId));
  const e = await KV.get<RegLockRow>(k);
  if (!e.value) return;
  const legacyTok = !!tok && tok.rl === undefined && (Date.parse(String(tok.created || "")) || 0) < rlMarkEpoch;
  const owning = !!tok && typeof tok.rl === "string" && !!e.value.device_tag && ctEq(tok.rl, e.value.device_tag);
  if (!owning && !legacyTok) return;
  if (regLockSeen.size > 100_000) regLockSeen.clear();
  regLockSeen.set(userId, now);
  await KV.atomic().check(e).set(k, { ...e.value, last_seen: now }).commit();
}
/** b77u (audit 6 W2): boot — the first start of this build records when tokens began carrying `rl` */
async function resolveRlMarkEpoch(): Promise<void> {
  const k: Deno.KvKey = ["rl_mark_epoch"];
  for (let i = 0; i < 5 && !rlMarkEpoch; i++) {
    const cur = await KV.get<number>(k, { consistency: "strong" });
    if (typeof cur.value === "number") { rlMarkEpoch = cur.value; break; }
    const t = Date.now();
    if ((await KV.atomic().check(cur).set(k, t).commit()).ok) rlMarkEpoch = t;
  }
}
/** b77u (audit 6 W2): marks the presented token as issued against device tag `tag` (the phone that just set the PIN) */
async function markTokenOwning(req: Request, tag: string): Promise<void> {
  const a = req.headers.get("Authorization") || "";
  const token = a.startsWith("Bearer ") ? a.slice(7) : "";
  if (!token || token.length > MAX_KEY_PART) return;
  const hk = await authKey(token);
  for (let i = 0; i < 5; i++) {
    const cur = await KV.get<Record<string, unknown>>(hk);
    if (!cur.value) return;
    const created = Date.parse(String(cur.value.created || "")) || Date.now();
    if ((await KV.atomic().check(cur).set(hk, { ...cur.value, rl: tag }, { expireIn: Math.max(60_000, TOKEN_MAX_AGE_MS - (Date.now() - created)) }).commit()).ok) return;
  }
}
async function fnVeilRegLock(auth: { userId: string; tokenCreated?: number }, body: Record<string, any>, req: Request | null = null) {
  const action = String(body?.action || "");
  const k = regLockKey(await accountHashOf(auth.userId));
  if (action === "status") {
    const e = await KV.get<RegLockRow>(k);
    if (!e.value) return json({ enabled: false });
    const now = Date.now();
    // b76r1 (registration lock): `device_matches` — the caller presented (`reglock_device`) the
    // current owning phone's device key; false after a PIN sign-in elsewhere made another phone
    // the owning phone (or when the caller sent none). `last_pin_restore_at` — when that last
    // happened (ISO), or null. The old phone used to learn nothing: its warning count reset and it
    // silently stopped being the owning phone.
    const dev = body?.reglock_device;
    const deviceMatches = typeof dev === "string" && !!dev && dev.length <= 128 && !!e.value.device_tag && ctEq(await regLockDeviceTag(dev), e.value.device_tag);
    // b77u (audit 6 W2, R4 #3): the check-in renews the lock only from the owning phone (its device key); the status
    // itself is answered to any signed-in phone
    let seenAt = Number(e.value.last_seen) || 0;
    if (deviceMatches && (await KV.atomic().check(e).set(k, { ...e.value, last_seen: now }).commit()).ok) { regLockSeen.set(auth.userId, now); seenAt = now; }
    const restoredAt = Number(e.value.pin_restore_at) || 0;
    // b76r2 (audit DEV-R2-02): `pin_changed_at` — when the PIN was last set (ISO), unless the caller's
    // device key is the one the setting phone holds (it set the PIN itself); null then, and for a row
    // from before b76r2. A `set` with a token and the words (§8.2 item 53) used to show on the owner's
    // phone only as "someone restored with your PIN", dated to the owner's own earlier restore.
    // `last_pin_restore_at` stays separate: a PIN sign-in elsewhere, not a PIN change.
    const setAt = Number(e.value.pin_set_at) || 0;
    const setterIsCaller = typeof dev === "string" && !!dev && dev.length <= 128 && !!e.value.pin_set_tag && ctEq(await regLockDeviceTag(dev), e.value.pin_set_tag);
    // b77u2 (Info): the real lapse time; it said now + 7 days even when this call didn't renew the lock
    return json({ enabled: true, lapse_at: seenAt + REGLOCK_LAPSE_MS, lapse_ms: REGLOCK_LAPSE_MS, failed_attempts: Number(e.value.fails) || 0, veil_id: e.value.veil_id, device_matches: deviceMatches, last_pin_restore_at: restoredAt ? new Date(restoredAt).toISOString() : null, pin_changed_at: setAt && !setterIsCaller ? new Date(setAt).toISOString() : null });
  }
  if (action === "set") {
    // turn on or change the PIN: the account's PRIMARY identity signs the request (a stolen
    // token alone can't set a PIN the owner doesn't know), over the PIN proof it installs
    const pinAuth = body.pin_auth, ts = Number(body.ts), sig = String(body.sig ?? ""), vid = String(body.veil_id ?? "");
    if (!pinAuthShape(pinAuth) || !Number.isFinite(ts) || !sig || !vid || vid.length > MAX_VEIL_ID || sig.length > 200) return j({ message: "Invalid request" }, 400);
    if (Math.abs(Date.now() - ts) > 10 * 60_000) return j({ message: "This request is too old — try again" }, 403);
    const primary = await ensurePrimaryIdentity(auth.userId);
    // the PIN proof is salted with the primary identity's seed, so a restore with its 24 words can answer it
    if (!primary) return j({ message: "Set up your Vardum ID on this phone first" }, 409);
    const pid = (await KV.get<Record<string, unknown>>(["veil_identity", keySafe(primary)])).value;
    if (vid !== primary || !pid || pid.bound !== true || String(pid.account_hash || "") !== await accountHashOf(auth.userId)) return j({ message: "The registration lock is set with the Vardum ID this account was set up with" }, 403);
    // b77u (audit 6 W2, IH relay F-02 / full L-1): SINGLE USE. The current form signs a relay-issued nonce (veilProofNonce
    // label "vardum-reglock-set-v1"): `vardum-reglock-set-v1:<uid>:<ts>:<pin tag>:<nonce>`, consumed in one step. A replayed
    // `set` used to re-install an old PIN, hand the replayer a fresh owning-phone key and reset the back-off. The old form
    // (no nonce) only while the transition window is open, and then once (a used-marker that outlives the proof).
    const pinTag = await sha256hex("vardum-reglock-pin-tag-v1:" + pinAuth);
    const nonce = typeof body.nonce === "string" && /^[0-9a-f]{32}$/.test(body.nonce) ? body.nonce : null;
    if (body.nonce !== undefined && !nonce) return j({ message: "Invalid request" }, 400);
    if (!canonicalB64(sig)) return j({ message: "Not authorised" }, 403);
    if (nonce) {
      const nrow = await KV.get<{ label?: string }>(proofNonceKey(auth.userId, nonce), { consistency: "strong" });
      if (!nrow.value || nrow.value.label !== "vardum-reglock-set-v1") return j({ message: "Not authorised" }, 403);
      if (!(await ed25519Verify(String(pid.IK_pub || ""), enc.encode(`vardum-reglock-set-v1:${auth.userId}:${ts}:${pinTag}:${nonce}`), sig))) return j({ message: "Not authorised" }, 403);
      if (!(await KV.atomic().check(nrow).delete(nrow.key).commit()).ok) return j({ message: "Not authorised" }, 403);
    } else {
      if (!compatOn()) return j({ message: "Update Vardum to set the registration lock", code: "proof_nonce_required" }, 403);
      if (!(await ed25519Verify(String(pid.IK_pub || ""), enc.encode(`vardum-reglock-set-v1:${auth.userId}:${ts}:${pinTag}`), sig))) return j({ message: "Not authorised" }, 403);
      const sigHex = [...b64d(sig)].map((b) => b.toString(16).padStart(2, "0")).join("");
      const used: Deno.KvKey = ["proof_used", await sha256hex(`veil-proof-used-v2:vardum-reglock-set-v1:${auth.userId}:${ts}:${sigHex}`)];
      if (!(await KV.atomic().check({ key: used, versionstamp: null }).set(used, 1, { expireIn: proofUsedTtl(ts) }).commit()).ok) return j({ message: "Not authorised", code: "proof_used" }, 403);
    }
    const salt = [...crypto.getRandomValues(new Uint8Array(16))].map((b) => b.toString(16).padStart(2, "0")).join("");
    const deviceKey = b64e(crypto.getRandomValues(new Uint8Array(32)));
    const prev = (await KV.get<RegLockRow>(k)).value;
    const now = Date.now();
    const deviceTag = await regLockDeviceTag(deviceKey);
    // b76r1: a new PIN keeps the last PIN restore's time. b76r2 (audit DEV-R2-02): and records when it
    // was set and by which phone (the tag of the key handed out here)
    const row: RegLockRow = { v: 1, salt, verifier: await regLockVerifier(pinAuth, salt), device_tag: deviceTag, veil_id: primary, enabled_at: prev?.enabled_at || now, last_seen: now, fails: 0, next_try: 0, ...(prev?.pin_restore_at ? { pin_restore_at: prev.pin_restore_at } : {}), pin_set_at: now, pin_set_tag: deviceTag };
    await KV.set(k, row);
    if (req) await markTokenOwning(req, deviceTag); // b77u (audit 6 W2): this phone's token renews the lock
    regLockSeen.delete(auth.userId); // the next request renews it again
    return json({ ok: true, enabled: true, device_key: deviceKey, lapse_at: now + REGLOCK_LAPSE_MS, lapse_ms: REGLOCK_LAPSE_MS });
  }
  if (action === "off") {
    // the same proof as the account-destroying requests (§12.3): turning the lock off with a
    // stolen token would hand the account to the next holder of the words
    const refused = await primaryProofRefusal(auth, body, "vardum-reglock-off-v1", { proof: "Turning off the registration lock needs the Vardum ID this account was set up with", fresh: "Sign in again, then turn off the registration lock" });
    if (refused) return refused;
    await KV.delete(k);
    return json({ ok: true, enabled: false });
  }
  return j({ message: "Unknown action" }, 400);
}

/** b77i (I-1): the answer for an account that is already gone — distinct from a 401 (a login the
 *  relay refuses, account still there), so the app's retry after an uncertain delete can tell */
const accountGone = () => j({ message: "Account deleted", account_deleted: true }, 410);

/** b77i (I-1): the last step of an account delete — each of the account's sign-in tokens leaves a
 *  tombstone (its at-rest hash, no account id, ACCT_GONE_TTL_MS) and goes (the delete's work rows before them) */
async function retireAccountTokens(userId: string) {
  // b77j (L-1): the work rows first — the user row is gone, so no retry reruns the cascade, and a
  // run stopped after the caller's token went used to leave them (that retry has no account id)
  for await (const e of KV.list({ prefix: acctDelKey(userId) }, { consistency: "strong" })) await KV.delete(e.key);
  for await (const e of KV.list({ prefix: ["auth"] }, { consistency: "strong" })) {
    const t = (e.value ?? {}) as Record<string, unknown>;
    if (String(t.userId || "") !== userId) continue;
    const k1 = String(e.key[1] ?? "");
    await KV.set(acctGoneKey(k1.startsWith("h:") ? k1 : String((await authKey(k1))[1])), 1, { expireIn: ACCT_GONE_TTL_MS });
    await KV.delete(e.key);
  }
  for await (const e of KV.list({ prefix: ["auth_acct", userId] }, { consistency: "strong" })) await KV.delete(e.key); // b77s: the token index entries too
  // b77t (audit 5 L-15, L-5): the account's proof nonces and its duress purge token go too
  for await (const e of KV.list({ prefix: ["proof_nonce", userId] }, { consistency: "strong" })) await KV.delete(e.key);
  await dropPurgeToken(userId);
}

/** b77p (audit VAR-36): WHAT AN ACCOUNT DELETE CANNOT REACH — the account's INBOUND 1:1 MAILBOXES. By the
 *  sealed-sender design (b77) a mailbox row names no account, token or Vardum ID (its id is derived on the two
 *  phones from the chat root), so the relay has no account -> mailbox link to follow and this cascade can't
 *  find them. (The device push rows' push_refs group a device's mailboxes for wake-ups, but are being redesigned
 *  so that they no longer tie mailboxes to an account either; nothing here relies on them.) What is left after
 *  a delete, and how it goes:
 *   - the app ends its mailboxes alongside the delete (vendor/device sealed.ts: one sealedEnd per mailbox, each
 *     after its own random 3-30 s wait, so the relay can't tie them to the account by timing): rows,
 *     envelopes and files go then and the ids are retired;
 *   - a mailbox the app could not end (offline phone, a crash mid-delete, an older app) stays until the
 *     sweeper's idle rule: no owner use for MBOX_IDLE_MS (30 days) -> the row, its envelopes and its files go
 *     and the id is retired. Its envelopes expire on their own sooner (at most 7 days), and its sealed files at
 *     the 49 h backstop. Everything held there is ciphertext the relay can't read, tied to nobody.
 *  The account's OTHER rows (tokens, identities, notes, vaults, push rows, groups, quotas) go below. */
async function fnVeilAccountDelete(auth: { userId: string; email?: string }, body: Record<string, any>) {
  // b77i (I-1): a retry queued behind the run that finished the delete (withLock on the route)
  if (!(await KV.get(["user", auth.userId])).value) return accountGone();
  // b70 (re-review 5): deleting the account locks the owner out for good, so where
  // the account has a primary identity, that identity signs the request (a
  // stolen token alone can't)
  {
    const refused = await primaryProofRefusal(auth, body, "vardum-delete-v1", { proof: "Deleting this account needs the Vardum ID it was set up with on this phone", fresh: "Sign in again, then delete the account" }, { deleteRetry: true });
    if (refused) return refused;
  }
  // client_id IS the account id (b65), so the account is always one of its own clients
  // b54 hotfix (code review V-1): the set is derived from the CALLER ONLY.
  // It used to merge caller-supplied body.client_ids, so any account could
  // name another user's id and delete their threads and envelopes. The
  // caller's sessions are still found via its identities and owner tags.
  void body;
  // b70 (re-review 13): from here on the account's tokens are refused, and requests already
  // in flight get a moment to finish before the sweep (their writes used to outlive it)
  // b77i (I-1): a retry (deleting_at already set) renews it and runs the whole cascade again; every
  // step is idempotent, and what an interrupted run had already removed but not finished with
  // (identities, chats, push addresses) comes back from its work rows (acctDelKey)
  {
    for (let attempt = 0; attempt < 10; attempt++) {
      const ue = await KV.get<Record<string, unknown>>(["user", auth.userId]);
      if (!ue.value || (await KV.atomic().check(ue).set(["user", auth.userId], { ...ue.value, deleting_at: Date.now() }).commit()).ok) break;
    }
    await new Promise((res) => setTimeout(res, ACCOUNT_DELETE_DRAIN_MS));
    // b77s (audit 4 RA-02): writes from requests still in flight are refused from deleting_at on (writeIfAccountLive);
    // the orphan pass also checks upload owner records against this account for a day
    recentlyDeletedAccts.set(await accountHashOf(auth.userId), Date.now());
  }
  const clientIds = new Set([auth.userId]);
  const acct = await accountHashOf(auth.userId);
  const user = (await KV.get<Record<string, unknown>>(["user", auth.userId])).value;
  // the label lives on the user row; the token's copy can be stale after a rebind
  // b75r1 (audit REL-03): retired labels are hashes now (tags + group-account hashes); a
  // legacy plaintext entry is still a label and handled as one
  const legacyRetired = (Array.isArray(user?.retired_labels) ? (user!.retired_labels as unknown[]).map(String) : []).filter((l) => l.includes("@"));
  const labels = new Set([String(user?.email || ""), String(auth.email || ""), ...legacyRetired].map((l) => l.toLowerCase().trim()).filter(Boolean));
  const retiredSets = await retiredLabelSets(user);
  const groupAccts = new Set<string>(retiredSets.groupAccts);
  for (const l of labels) groupAccts.add(await sha256hex("veil-group-account:" + l));
  const ownsRow = async (row: Record<string, unknown>, id: string) =>
    !!row._owner && String(row._owner) === await ownerTag(auth.userId, id);
  // this account's published identities (+ their bind nonces and invite-ping coalescers)
  const veilIds = new Set<string>(), ikPubs = new Set<string>();
  // b77i (I-1): the identities an interrupted run already removed
  for await (const e of KV.list<{ ik?: string }>({ prefix: acctDelKey(auth.userId, "v") }, { consistency: "strong" })) {
    const vid = String(e.key[3] ?? "");
    if (vid) { veilIds.add(vid); await dropOpks(vid); }
    if (e.value?.ik) ikPubs.add(String(e.value.ik));
  }
  for await (const e of KV.list({ prefix: ["veil_identity"] }, { consistency: "strong" })) {
    const rec = (e.value ?? {}) as Record<string, unknown>; // b75: a malformed row never stops a delete
    // b77u (audit 6, IH relay F-07): an UNBOUND row this account registered is simply deleted (with its prekeys) — it
    // proves nothing about the key. It used to feed the cascade below: bans by that IK lost their signatures, pending
    // requests to the ID and other accounts' bind nonces for it went (anyone could register an unbound row naming a
    // retired ID's IK, then delete their own account).
    if (String(rec.account_hash || "") === acct && rec.bound !== true) {
      await KV.delete(e.key);
      await dropOpks(String(rec.veil_id || e.key[1] || ""));
      continue;
    }
    if (String(rec.account_hash || "") === acct) {
      veilIds.add(String(rec.veil_id));
      if (rec.IK_pub) ikPubs.add(String(rec.IK_pub));
      // b77i (I-1): kept until the account goes, so a retry still finds what names this identity
      await KV.set(acctDelKey(auth.userId, "v", keySafe(String(rec.veil_id || e.key[1] || ""))), { ik: String(rec.IK_pub || "") }, { expireIn: ACCT_DEL_WORK_TTL_MS });
      await KV.delete(e.key);
      await dropOpks(String(rec.veil_id || e.key[1] || "")); // b76 (one-time prekeys)
    }
  }
  // group bans on those identities: the ban stays (an evicted member must not
  // rejoin by deleting their account), the identifiers go — the entry keeps
  // only group-salted hashes, and the signature over the plaintext IK is dropped
  for await (const e of KV.list({ prefix: ["entity", "VeilGroupDenyEntry"] }, { consistency: "strong" })) {
    const d = (e.value ?? {}) as Record<string, unknown>;
    const vid = String(d.target_veil_id || ""), ik = String(d.target_IK_pub || "");
    if (!veilIds.has(vid) && !ikPubs.has(ik)) continue;
    const gt = String(d.group_token || "");
    await KV.set(e.key, {
      id: d.id, created_date: d.created_date, group_token: gt, deny_epoch: d.deny_epoch, remover_IK_pub: d.remover_IK_pub,
      target_ik_hash: ik ? await denyHash(gt, ik) : "",
      target_vid_hash: vid ? await denyHash(gt, vid) : "",
    });
  }
  // Batch C (B1): bind challenges are keyed [veil_id, account] — drop every
  // one for this account's identities and every one this account asked for
  const delAcct = await accountHashOf(auth.userId);
  for await (const e of KV.list({ prefix: ["id_nonce"] })) {
    if (veilIds.has(String(e.key[1])) || String(e.key[2] ?? "") === delAcct) await KV.delete(e.key);
  }
  // b75r1 (audit REL-02): registrations held aside for this account
  for await (const e of KV.list({ prefix: ["veil_identity_pending"] })) if (String(e.key[2] ?? "") === delAcct) await KV.delete(e.key);
  // b70 (audit RLY-13): group key-wrap requests and deliveries that name the
  // account's identities, its upload counters, and the remover side of bans it
  // made (the ban stays; the remover's key and signature go)
  for (const prefix of [["veil_wrapreq"], ["veil_wrapdel"]]) {
    for await (const e of KV.list<Record<string, unknown>>({ prefix }, { consistency: "strong" })) {
      const v = e.value ?? {};
      const named = e.key.some((k) => ikPubs.has(String(k)) || veilIds.has(String(k)))
        || ikPubs.has(String(v.IK_pub || "")) || veilIds.has(String(v.veil_id || ""));
      if (named) await KV.delete(e.key);
    }
  }
  for await (const e of KV.list({ prefix: ["upload_quota", delAcct] })) await KV.delete(e.key);
  for await (const e of KV.list({ prefix: ["env_quota", delAcct] })) await KV.delete(e.key);
  for (const kind of ["VeilVault", "VeilNote", "group", "push"]) await KV.delete(["row_cap_seq", kind, delAcct]); // b75 (audit RL-07)
  await KV.delete(regLockKey(delAcct)); // b76 (registration lock): its salt, verifier and device tag
  regLockSeen.delete(auth.userId);
  // b70 (re-review): group burn votes this account cast
  // b75r1 (audit REL-05): the rows hold opaque per-(message, account) markers now
  for await (const e of KV.list<BurnVoteRow>({ prefix: ["burn_votes"] })) {
    const v = burnVotesOf(e.value), mine = await burnVoteMarker(String(e.key[1] ?? ""), delAcct);
    if (v.includes(mine)) await KV.set(e.key, { k: BURN_VOTE_KEY_ID, m: v.filter((x) => x !== mine) }, { expireIn: 24 * 3600_000 });
  }
  // b76r2 (audit GB-1 / R2-B1): and its place in every burn quorum
  for await (const e of KV.list<BurnEligRow>({ prefix: ["burn_elig"] })) {
    const v = burnEligOf(e.value), mine = await burnVoteMarker(String(e.key[1] ?? ""), delAcct);
    if (v && v.m.includes(mine)) await KV.set(e.key, { k: BURN_VOTE_KEY_ID, m: v.m.filter((x) => x !== mine), x: v.x }, { expireIn: 24 * 3600_000 });
  }
  for await (const e of KV.list({ prefix: ["entity", "VeilGroupDenyEntry"] }, { consistency: "strong" })) {
    const d = (e.value ?? {}) as Record<string, unknown>;
    const rik = String(d.remover_IK_pub || "");
    if (!rik || !ikPubs.has(rik)) continue;
    const { remover_IK_pub: _r, deny_sig: _s, ...rest } = d;
    await KV.set(e.key, { ...rest, remover_ik_hash: await denyHash(String(d.group_token || ""), rik) });
  }
  for (const vid of veilIds) {
    await KV.delete(["id_nonce", vid]);
    await KV.delete(["push_coalesce_invite", keySafe(vid)]); // (a row from before b77m)
    await KV.delete(["push_coalesce_invite", await vidTag(vid)]); // b77m (audit VAR-48)
  }
  // sessions + envelopes: by client_id, by veil_id binding, or by the b199
  // creator tag (rows created before either field is filled in)
  let sessions = 0, envelopes = 0;
  const doomed: string[] = [];
  /** b71 (audit F-15): limiter keys that name this account's chats or devices (by hash) */
  const rlPrefixes: string[] = [];
  const myInitTag = await initTag(auth.userId);
  for await (const e of KV.list({ prefix: ["entity", "VeilSession"] }, { consistency: "strong" })) {
    const row = (e.value ?? {}) as Record<string, unknown>;
    const id = e.key[e.key.length - 1] as string;
    const hit = clientIds.has(String(row.initiator_client_id || "")) || clientIds.has(String(row.responder_client_id || ""))
      || veilIds.has(String(row.initiator_veil_id || "")) || veilIds.has(String(row.responder_veil_id || ""))
      || (!!row._init_tag && row._init_tag === myInitTag) // b77: its pending 1:1 requests (while this process runs)
      || await ownsRow(row, id);
    if (hit) doomed.push(id);
  }
  // b77i (I-1): chats an interrupted run had removed but not finished (their envelopes, token rows)
  const unfinished = new Map<string, string>();
  for await (const e of KV.list<string>({ prefix: acctDelKey(auth.userId, "s") }, { consistency: "strong" })) {
    const id = String(e.key[3] ?? "");
    if (id) { unfinished.set(id, String(e.value || "")); if (!doomed.includes(id)) doomed.push(id); }
  }
  for (const id of doomed) {
    const row = (await KV.get<Record<string, unknown>>(["entity", "VeilSession", id])).value;
    if (!row && !unfinished.has(id)) continue;
    const tok = row ? String(row.token || "") : unfinished.get(id)!;
    if (row) await KV.set(acctDelKey(auth.userId, "s", keySafe(id)), tok, { expireIn: ACCT_DEL_WORK_TTL_MS }); // b77i (I-1)
    await KV.delete(["entity", "VeilSession", id]); // b70 (re-review 14): the session first
    envelopes += await deleteSessionEnvelopes(tok);
    if (tok) {
      await KV.delete(["veil_sess_token", tok]);
      await KV.set(await retiredTokenKey(tok), 1, { expireIn: 400 * 86400_000 }); // b70 (re-review 9): never minted again
      for await (const e of KV.list({ prefix: ["push_coalesce", tok] }, { consistency: "strong" })) await KV.delete(e.key);
      // b71 (audit F-15): the chat's call-ring row, ring cap and notify limiter (keyed by
      // the token's hash now; older relays used the raw token)
      const tag = await sessionTokenTag(tok);
      await KV.delete(["call_ring", tag]);
      await KV.delete(["call_ring", keySafe(tok)]);
      rlPrefixes.push(`notify:${tag}:`, `ringcap:${tag}`, `notify:${tok}:`);
    }
    if (row) sessions++;
  }
  // envelopes this account sent into sessions that survive it
  for await (const e of KV.list({ prefix: ["entity", "VeilEnvelope"] }, { consistency: "strong" })) {
    const env = (e.value ?? {}) as Record<string, unknown>;
    // Batch C (V-13): owner tag on new envelopes; legacy rows still carry client_id
    const mine = (env._owner && String(env._owner) === await ownerTag(auth.userId, String(e.key[e.key.length - 1])))
      || clientIds.has(String(env.client_id || ""));
    if (!mine) continue;
    await deleteEnvelopeRow(e.key, env); // b71 (audit F-09): with its index rows
    envelopes++;
  }
  // group memberships: the gate's index rows (account hash) and the member
  // entity rows (account hash, or the label-derived group account hash)
  let memberships = 0;
  await teardownOwnedGroups(acct); // b75r1 (audit REL-04): the groups it created, every member's rows included
  for await (const e of KV.list({ prefix: ["veil_gmember"] }, { consistency: "strong" })) {
    const m = (e.value ?? {}) as Record<string, unknown>;
    if (String(m.account_hash || "") === acct) { await KV.delete(e.key); memberships++; }
  }
  for await (const e of KV.list({ prefix: ["entity", "VeilGroupMember"] }, { consistency: "strong" })) {
    const m = (e.value ?? {}) as Record<string, unknown>;
    if (String(m._acct || "") === acct || groupAccts.has(String(m.account_hash || ""))) await KV.delete(e.key);
  }
  // groups this account created: the owner record keeps no account hash, but
  // stays tombstoned so nobody can claim the orphaned group's token afterwards
  // (b75r1 (audit REL-04): teardownOwnedGroups above did it, with the whole group)
  // owner-scoped entities: vaults, notes, push tokens (a device's push address
  // must not stay linked to a dead account)
  let vaults = 0, notes = 0, pushTokens = 0;
  // b71 (audit F-15/F-19): its devices' push-address caps and challenges (by hash)
  // b77i (I-1): with the addresses of push rows an interrupted run already removed
  for await (const e of KV.list<{ cap?: string }>({ prefix: acctDelKey(auth.userId, "p") }, { consistency: "strong" })) {
    const tag = String(e.key[3] ?? "");
    if (!tag) continue;
    if (e.value?.cap) rlPrefixes.push(String(e.value.cap));
    rlPrefixes.push(`pushto:${tag}:-`, `pushchal:${tag}`);
    for await (const c of KV.list({ prefix: ["push_challenge", tag] })) await KV.delete(c.key);
  }
  for await (const e of KV.list<Record<string, unknown>>({ prefix: ["entity", "VeilPushToken"] }, { consistency: "strong" })) {
    if (String(e.value?._acct || "") !== acct || !e.value?.expo_token) continue;
    const tag = await pushTargetTag(String(e.value.expo_token));
    // b75r2 (audit R2-01): this account's own allowance on the address (another account
    // holding the same UnifiedPush address keeps its count), and the address-wide ones
    const cap = await pushCapKey(String(e.value.expo_token), acct);
    await KV.set(acctDelKey(auth.userId, "p", tag), { cap }, { expireIn: ACCT_DEL_WORK_TTL_MS }); // b77i (I-1)
    rlPrefixes.push(cap, `pushto:${tag}:-`, `pushchal:${tag}`);
    for await (const c of KV.list({ prefix: ["push_challenge", tag] })) await KV.delete(c.key);
  }
  for await (const c of KV.list({ prefix: ["push_challenge"] })) if (String(c.key[2] ?? "") === acct) await KV.delete(c.key);
  // (b77: the TURN eligibility cache ["turn_ok", account hash] is gone — nothing to delete)
  for (const [name, counter] of [["VeilVault", () => vaults++], ["VeilNote", () => notes++], ["VeilPushToken", () => pushTokens++]] as const) {
    for await (const e of KV.list({ prefix: ["entity", name] }, { consistency: "strong" })) {
      const row = (e.value ?? {}) as Record<string, unknown>;
      if (String(row._acct || "") === acct) {
        if (name === "VeilPushToken") await deletePushRow(e.key); // b77r1 (audit R-6): with its push_ref index
        else await deleteIndexedRow(name, String(e.key[2])); // b77n (pre-audit L3): with its index entries
        if (name === "VeilVault") await removeVaultBlob(row);
        counter();
      }
    }
    // b77n (pre-audit L3): and any index entry still naming the account (a stale one a missed delete left)
    for await (const e of KV.list({ prefix: ["ix_acct", name, acct] }, { consistency: "strong" })) await KV.delete(e.key);
  }
  // b77s (audit 4 RE-02): the per-creator group-row index names the account id: every entry goes (the rows went with
  // the account's groups above; a stale entry left elsewhere is checked against its row on read anyway)
  for await (const e of KV.list({ prefix: ["ix_gsess_init", auth.userId] }, { consistency: "strong" })) await KV.delete(e.key);
  // every other row this account created (owner-tagged: analytics and the like)
  for await (const e of KV.list({ prefix: ["entity"] }, { consistency: "strong" })) {
    if (await ownsRow((e.value ?? {}) as Record<string, unknown>, e.key[e.key.length - 1] as string)) await KV.delete(e.key);
  }
  // Batch E (RV-39): files this account uploaded (media, bundles) and their owner records
  for await (const e of KV.list<string>({ prefix: ["blob_owner"] }, { consistency: "strong" })) {
    const id = String(e.key[1]);
    if (e.value !== await blobOwnerTag(acct, id)) continue;
    const p = blobPathOf("blob:" + id);
    if (p) await Deno.remove(p).catch(() => undefined);
    await KV.delete(e.key);
    await KV.delete(["blob_session", id]); // b70 (VAR-06)
    await KV.delete(["blob_group", id]); // b77u (U-M9); b77u2: it sat inside the comment above and never ran
  }
  // transfer links owned by the account
  for await (const e of KV.list({ prefix: ["devlink"] }, { consistency: "strong" })) {
    const row = (e.value ?? {}) as Record<string, unknown>;
    // b75: either phone's account (receiver `acct`, sender `sacct`), and the bundle file with it
    if (String(row.acct || "") === acct || String(row.sacct || "") === acct) { await KV.delete(e.key); await dropDevlinkBlob(row); }
  }
  // Batch E (F-3) / Batch F (R4-4-06): their "used" and "fetched" markers, kept 30 days
  // b77n (pre-audit I2): by either phone's account — the receiving phone's (racct) too, which was never cleared
  for await (const e of KV.list({ prefix: ["devlink_fetched"] }, { consistency: "strong" })) {
    const f = (e.value ?? {}) as Record<string, unknown>;
    if (String(f.acct || "") === acct || String(f.racct || "") === acct) await KV.delete(e.key);
  }
  for await (const e of KV.list({ prefix: ["devlink_used"] }, { consistency: "strong" })) {
    if (String(((e.value ?? {}) as Record<string, unknown>).acct || "") === acct) await KV.delete(e.key);
  }
  // per-account rate-limit buckets ("env:<uid>", "idreg:<uid>", ...) — they
  // self-expire, but deletion does not wait for them
  // (b70 re-review 10: and the per-target request limiter, keyed by the account hash —
  // a "who asked whom" row used to outlive the account by a day)
  const reqPrefix = "req:" + (await accountHashOf(auth.userId)) + ":"; // (rows from before b77)
  rlPrefixes.push(await reqPairAcctPrefix(auth.userId)); // b77: this account's per-addressee request caps (by tag)
  const reqSfx = await reqTargetSuffixesOf([...veilIds]); // b77: other accounts' request caps on its IDs
  rlPrefixes.push(await opkPairAcctPrefix(auth.userId)); // b76 (one-time prekeys): this account's pair caps (b76r2, audit OP-1: by tag)
  rlPrefixes.push("reglockask:" + acct); // b76r1 (registration lock): the free-refusal counter
  for (const l of labels) rlPrefixes.push("loginall:" + await sha256hex("veil-login-guard:" + l) + ":"); // b71 (audit F-15)
  const opkTargetSuffixes = await Promise.all([...veilIds].filter(Boolean).map((v) => opkPairTargetSuffix(v))); // b76r2: other accounts' pair caps on its IDs
  const vtags = await Promise.all([...veilIds].filter(Boolean).map((v) => vidTag(v))); // b77m (audit VAR-48): rows that count what happens TO its IDs (by tag)
  for await (const e of KV.list({ prefix: ["rl"] }, { consistency: "strong" })) {
    const k = String(e.key[1] || "");
    // (b71 (audit F-15): and limiter rows that name one of its Vardum IDs — the per-addressee
    // invite-push caps and other accounts' per-target request limiters)
    if (k.endsWith(":" + auth.userId) || k.startsWith(reqPrefix) || rlPrefixes.some((p) => k.startsWith(p)) || [...veilIds].some((v) => !!v && k.includes(v)) || vtags.some((t) => k.includes(t)) || (k.startsWith("opkpair:") && opkTargetSuffixes.some((s) => k.endsWith(s))) || reqHit(k, reqSfx)) await KV.delete(e.key);
  }
  // the label: its sign-in index (left behind, the label stayed on the server
  // and could never register again) and its password-guessing lockout row
  for (const l of labels) {
    if ((await KV.get<string>(["label_retired", l])).value === auth.userId) await KV.delete(["label_retired", l]); // Batch D (D-17)
    retiredSets.tags.add(await retiredLabelTag(l));
    await KV.delete(["login_guard", keySafe(l)]);
    // b70 (RLY-2): the lockout rows are now per (label, network)
    for await (const e of KV.list({ prefix: ["login_guard_h", await sha256hex("veil-login-guard:" + l)] })) await KV.delete(e.key);
    await KV.delete(["login_guard_acct", await sha256hex("veil-login-guard:" + l)]); // b71 (audit F-03/F-15)
    await KV.delete(loginLabelCapKey(await sha256hex("veil-login-guard:" + l))); // b77t2 (CL-1)
  }
  // b75r1 (audit REL-03): the hashed "retired label" rows this account left
  for (const t of retiredSets.tags) if ((await KV.get<string>(["label_retired_h", t])).value === auth.userId) await KV.delete(["label_retired_h", t]);
  // the account itself + its auth tokens
  // b77i (I-1): the user row first — from then on a retry's token answers 410 (authCheck), and the
  // tokens each leave a tombstone that keeps answering 410 once they are gone (retireAccountTokens)
  // b77j (L-2): the sign-in index last but one — until here the label can still sign in, which an
  // account with no primary identity needs (its retry takes a fresh token) to finish the delete
  for (const l of labels) if ((await KV.get<string>(["user_email", l])).value === auth.userId) await KV.delete(["user_email", l]);
  await KV.delete(["user", auth.userId]);
  await retireAccountTokens(auth.userId);
  return json({ ok: true, data: { deleted: { sessions, envelopes, memberships, vaults, notes, push_tokens: pushTokens, identities: veilIds.size } } });
}

// ---------- private blob storage + signed URLs (encrypted media + vault files) ----------
// b74 (audit VAR-21a): every blob path is BLOB_DIR + id, so the folder always ends in a
// separator — VEIL_BLOB_DIR=/srv/x/blobs (no slash) used to put files at /srv/x/blobs<id>,
// beside the folder instead of in it
const BLOB_DIR = withTrailingSep(Deno.env.get("VEIL_BLOB_DIR") || "/opt/veil-relay/blobs/"); // env override: local sandbox only
function withTrailingSep(dir: string): string {
  return /[\\/]$/.test(dir) ? dir : dir + "/";
}
/** b199 PATH-TRAVERSAL FIX: a "blob:<id>" uri is client-supplied (deviceLink
 *  store, DeletePrivateFile) — "blob:../../etc/passwd" used to read or delete
 *  files outside the blob directory. Ids are rid() (24 hex); anything that
 *  is not a plain token resolves to null. */
function blobPathOf(uri: string): string | null {
  if (!uri.startsWith("blob:")) return null;
  const id = uri.slice(5);
  // b77u (audit 6 U-M9 / IH relay F-05): ids are canonicalised to lower case (rid() ids are lowercase hex). The
  // protection records key on the exact string and a case-insensitive filesystem opened "ABC…" for "abc…", so a
  // re-cased id skipped every owner/binding check. Paths and record keys now both use the lower-case id.
  return /^[A-Za-z0-9_-]{1,128}$/.test(id) ? BLOB_DIR + id.toLowerCase() : null;
}
/** b77u (audit 6 U-M9 / F-05): a "blob:<id>" uri with its id in canonical (lower) case; anything else unchanged */
function canonBlobUri(uri: string): string {
  return uri.startsWith("blob:") && /^[A-Za-z0-9_-]{1,128}$/.test(uri.slice(5)) ? "blob:" + uri.slice(5).toLowerCase() : uri;
}
/** b77u (audit 6 U-M9): the canonical (lower-case) id of a "blob:<id>" uri */
const blobIdOf = (uri: string): string => uri.slice(5).toLowerCase();

/**
 * Batch E (Superagent report 2, RV-39): who uploaded a blob. ["blob_owner", id]
 * holds a per-blob tag of the uploading account (unlinkable across blobs, like
 * the row owner tags), or "legacy" for a file from before the record existed.
 * A blob id alone used to be a cross-account key: any account knowing one could
 * delete a vault container (DeletePrivateFile), read and delete it through a
 * transfer link (deviceLink store + fetch), or keep any file from the sweeper
 * with a vault row pointing at it.
 */
async function blobOwnerTag(acct: string, blobId: string) {
  return "bo_" + (await sha256hex("veil-blob-owner:" + acct + ":" + blobId));
}
/** true when `uri` is a blob the account uploaded — or names no stored file at all */
async function blobHeldBy(uri: string, acct: string): Promise<boolean> {
  const path = blobPathOf(uri);
  if (!path) return true; // not a blob reference: nothing on disk to protect
  const id = blobIdOf(uri);
  const rec = (await KV.get<string>(["blob_owner", id])).value;
  if (rec) return rec === await blobOwnerTag(acct, id);
  return !(await Deno.stat(path).then(() => true).catch(() => false));
}
/**
 * b70 (audit VAR-06 / RLY-1): a media file uploaded for a chat is bound to that
 * chat. ["blob_session", id] holds a tag of the chat's token. Deleting or
 * reading a bound file needs that chat's credential (token + a party's write
 * secret); a chat-scoped delete of a file NOT bound to that chat is refused —
 * so a message can't make the receiver's phone delete the receiver's own vault
 * containers or transfer bundles.
 */
async function blobSessionTag(sessionToken: string): Promise<string> {
  return "bs_" + (await sha256hex("veil-blob-session:" + sessionToken));
}
/** true when token + write secret are a real party credential for that chat.
 *  b77r1 (audit R-9): a GROUP seat only. A 1:1 chat's files go through sealedUpload / sealedFile
 *  (mailbox capabilities), and a 1:1 rendezvous row (or a pre-b77 1:1 row) is not a chat
 *  credential any more — it used to bind, sign and delete files on these signed-in routes. */
async function sessionCredOk(sessionToken: unknown, writeSecret: unknown): Promise<boolean> {
  if (typeof sessionToken !== "string" || !sessionToken) return false;
  const session = await findSessionByToken(sessionToken);
  if (!session || !session.group_token) return false;
  const wHash = await wsHashOf(writeSecret);
  return !!(wHash && (ctEq(wHash, String(session.initiator_write_hash || "")) || ctEq(wHash, String(session.responder_write_hash || ""))));
}
/**
 * b77u (audit 6 U-M9, R4 #1 / IH W7): GROUP media is bound to its GROUP. An upload naming a seat's token plus its
 * write secret records ["blob_group", id] = blobGroupTag(group_token); signing (and deleting) such a file then needs
 * a live seat credential of that same group, or the uploader. (A ["blob_session"] binding to one seat token would
 * have shut out every other member.) An evicted member's seat row is gone, so its credential no longer passes.
 */
async function blobGroupTag(groupToken: string): Promise<string> {
  return "bg_" + (await sha256hex("veil-blob-group:" + groupToken));
}
/** the group token behind a valid seat credential (token + write secret), or null */
async function seatCredGroup(sessionToken: unknown, writeSecret: unknown): Promise<string | null> {
  if (!(await sessionCredOk(sessionToken, writeSecret))) return null;
  const session = await findSessionByToken(String(sessionToken));
  return session && session.group_token ? String(session.group_token) : null;
}
/**
 * b77u (audit 6 U-M9): may a NON-uploader sign / delete this blob? Only with a valid binding credential: a group-bound
 * file with a seat credential of its group, a seat-bound file (["blob_session"], b70) with that seat's credential.
 * An unbound file (no binding, or a legacy file with no owner record) is its uploader's alone — the id is no longer a
 * capability (any signed-in account holding it used to sign AND delete it). A DELETE (`op` "delete") takes only the seat
 * binding: a member may read every member's media but remove only a file posted on its own seat (the b70 rule that a
 * file bound to another seat can't be deleted through this one stands; the seat's two parties keep the burn path).
 */
async function blobBindingAllows(id: string, body: Record<string, unknown>, op: "sign" | "delete" = "sign"): Promise<boolean> {
  if (body.session_token === undefined || body.session_token === null || body.session_token === "") return false;
  const [g, s] = await Promise.all([KV.get<string>(["blob_group", id]), KV.get<string>(["blob_session", id])]);
  if (g.value && op === "sign") {
    const gt = await seatCredGroup(body.session_token, body.write_secret);
    return !!gt && ctEq(g.value, await blobGroupTag(gt));
  }
  if (s.value) return await sessionCredOk(body.session_token, body.write_secret) && ctEq(s.value, await blobSessionTag(String(body.session_token)));
  return false;
}

/** a vault container or a live transfer bundle: deleted only by its owner */
async function blobIsProtected(uri: string): Promise<boolean> {
  // b77n (pre-audit L3): by ["ix_vault_uri"] and ["ix_devlink_uri"] (it read every vault and link row)
  return await vaultUsesUri(uri) || await devlinkUsesUri(uri);
}
/** b77n (pre-audit L3): does a vault row name this file? (a uri the index can't hold: the old scan) */
async function vaultUsesUri(uri: string): Promise<boolean> {
  if (URI_IX_RE.test(uri)) { for await (const _ of indexedRows(["ix_vault_uri", uri], "VeilVault", (r) => String(r.container_uri ?? "") === uri)) return true; return false; }
  for await (const e of KV.list<Record<string, unknown>>({ prefix: ["entity", "VeilVault"] }, { consistency: "strong" })) if (String(e.value?.container_uri || "") === uri) return true;
  return false;
}
/** b77n (pre-audit L3): does a device-transfer link name this file? */
async function devlinkUsesUri(uri: string): Promise<boolean> {
  if (URI_IX_RE.test(uri) && ixReady) { // b77n2 (review M1): the index only once the boot backfill completed
    for await (const ix of KV.list({ prefix: ["ix_devlink_uri", uri] }, { consistency: "strong" })) {
      const row = await KV.get<Record<string, unknown>>(["devlink", String(ix.key[2])]);
      if (row.value && String(row.value.container_uri || "") === uri) return true;
      await KV.atomic().check(row).delete(ix.key).commit();
    }
    return false;
  }
  for await (const e of KV.list<Record<string, unknown>>({ prefix: ["devlink"] }, { consistency: "strong" })) if (String(e.value?.container_uri || "") === uri) return true;
  return false;
}
/** RV-39: once, at boot — records owners for the files already on disk (a vault
 *  container belongs to its vault row's account; anything else is "legacy") */
async function migrateBlobOwners(): Promise<number> {
  let n = 0;
  for await (const e of KV.list<Record<string, unknown>>({ prefix: ["entity", "VeilVault"] }, { consistency: "strong" })) {
    const uri = String(e.value?.container_uri || ""), acct = String(e.value?._acct || "");
    const path = blobPathOf(uri);
    if (!path || !acct || !(await Deno.stat(path).then(() => true).catch(() => false))) continue;
    const id = blobIdOf(uri);
    if ((await KV.atomic().check({ key: ["blob_owner", id], versionstamp: null }).set(["blob_owner", id], await blobOwnerTag(acct, id)).commit()).ok) n++;
  }
  try {
    for await (const f of Deno.readDir(BLOB_DIR)) {
      if (!f.isFile || !/^[A-Za-z0-9_-]{1,128}$/.test(f.name)) continue;
      if ((await KV.get(["blob_mbox", f.name])).value) continue; // b77: a 1:1 file has no owner, by design
      if ((await KV.atomic().check({ key: ["blob_owner", f.name], versionstamp: null }).set(["blob_owner", f.name], "legacy").commit()).ok) n++;
    }
  } catch { /* no blob directory yet */ }
  return n;
}

/** b71 (review R-1): once, at boot — removes the clear-text nicknames older relays kept
 *  on session rows (initiator_display_name / responder_display_name). Nothing on the
 *  relay reads them; each row is rewritten only if unchanged since it was read. */
async function dropSessionDisplayNames(): Promise<number> {
  let n = 0;
  for await (const e of KV.list<Record<string, unknown>>({ prefix: ["entity", "VeilSession"] }, { consistency: "strong" })) {
    const r = e.value;
    if (!r || (!("initiator_display_name" in r) && !("responder_display_name" in r))) continue;
    const { initiator_display_name: _i, responder_display_name: _r, ...rest } = r;
    if ((await KV.atomic().check(e).set(e.key, rest).commit()).ok) n++;
  }
  return n;
}

/** b199: a deleted vault takes its encrypted file with it (unless another
 *  vault row still points at the same blob). Media blobs are unattributed to
 *  any session and age out via BLOB_RETENTION_MS. Batch E (RV-39): only a file
 *  the vault's own account uploaded. */
async function removeVaultBlob(row: Record<string, unknown> | null) {
  const uri = String(row?.container_uri || "");
  const path = blobPathOf(uri);
  if (!path) return;
  if (await vaultUsesUri(uri)) return; // b77n (pre-audit L3): by ["ix_vault_uri"]
  const rec = (await KV.get<string>(["blob_owner", blobIdOf(uri)])).value;
  if (rec && rec !== await blobOwnerTag(String(row?._acct || ""), blobIdOf(uri))) return;
  try { await Deno.remove(path); } catch { /* already gone */ }
  await KV.delete(["blob_owner", blobIdOf(uri)]);
}
/** b73 (audit): V-18 — the blob-URL signing key lives in this process's memory only
 *  (non-extractable, made at start-up). It used to be stored in KV in clear, so a copy of
 *  the database could mint signed /files/ links. Signed links last 10 minutes, so a
 *  restart only ends the links issued in the minutes before it (the app asks again). */
let blobSignKey: Promise<CryptoKey> | null = null;
function blobSecret(): Promise<CryptoKey> {
  if (!blobSignKey) blobSignKey = crypto.subtle.generateKey({ name: "HMAC", hash: "SHA-256", length: 256 }, false, ["sign", "verify"]) as Promise<CryptoKey>;
  return blobSignKey;
}

/**
 * b75 (audit RL-12): the origin signed file links carry. VEIL_PUBLIC_ORIGIN (an http(s)
 * origin, no path) when the operator sets it; otherwise, on a relay trusting loopback
 * (VEIL_TRUST_LOCAL=1: a test or operator relay) its own loopback address, and on any
 * other relay none (b77p, audit VAR-27: it was the vendor's live origin). Never anything from a request.
 */
function configuredPublicOrigin(): string {
  const raw = (Deno.env.get("VEIL_PUBLIC_ORIGIN") || "").trim();
  if (raw) {
    try {
      const u = new URL(raw);
      if ((u.protocol === "https:" || u.protocol === "http:") && !u.username && !u.password && (u.pathname === "/" || u.pathname === "") && !u.search && !u.hash) return u.origin;
    } catch { /* fall through */ }
    console.warn("[relay] VEIL_PUBLIC_ORIGIN is not an http(s) origin — ignored");
  }
  // b77p (audit VAR-27): no more vendor default. A relay without a configured origin used to sign links to
  // https://relay.tryveil.app, so a self-hosted relay leaked blob ids, signed tokens and timing to the vendor's
  // host. Now: a loopback test/operator relay (VEIL_TRUST_LOCAL=1) signs for its OWN loopback address (never
  // another host); any other relay without VEIL_PUBLIC_ORIGIN signs NOTHING (the link routes answer 503
  // "file links not configured"), and a production relay without it does not start (productionRefusals).
  if (TRUST_LOCAL) return `http://127.0.0.1:${PORT}`;
  console.error("[relay] VEIL_PUBLIC_ORIGIN is not set: signed file links are refused until it is (set it to this relay's https origin)");
  return "";
}
const PUBLIC_ORIGIN = configuredPublicOrigin();
/** b77p (audit VAR-27): thrown by signBlobUrl when no origin is configured; the router answers 503 */
class NoPublicOriginError extends Error {
  constructor() { super("no public origin configured"); this.name = "NoPublicOriginError"; }
}
async function signBlobUrl(blobId: string, ttlMs: number, origin: string) {
  if (!origin) throw new NoPublicOriginError();
  const key = await blobSecret();
  const exp = Date.now() + ttlMs;
  const mac = await crypto.subtle.sign("HMAC", key, enc.encode(`${blobId}:${exp}`));
  const m = b64e(new Uint8Array(mac)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  return `${origin}/files/${blobId}?e=${exp}&m=${m}`;
}

// ---------- router ----------
// b77n (pre-audit I3): each route keeps its PATTERN ("/entities/:entity/:id"), which the error log names instead
// of the request path (that held entity ids, file ids and Vardum IDs)
const routes: [string, RegExp, (req: Request, m: RegExpMatchArray, url: URL) => Promise<Response>, string][] = [];

function route(method: string, pattern: string, handler: (req: Request, m: RegExpMatchArray, url: URL) => Promise<Response>) {
  routes.push([method, new RegExp("^" + pattern.replace(/:([a-zA-Z]+)/g, "(?<$1>[^/]+)") + "$"), handler, pattern.replace(/^\/api\/apps\/:appId/, "")]);
}

// auth (open)
route("POST", "/api/apps/:appId/auth/login", async (req) => {
  const body = await readJson(req);
  const email = String(body.email || "").toLowerCase().trim();
  if (email.length > MAX_KEY_PART) return j({ message: "Invalid email or password" }, 401);
  const password = String(body.password || "");
  // SPEC §1: the 5-attempt server-side lockout (VeilLoginGuard) — the client
  // surfaces the lock message verbatim.
  // Batch D (D-15, RV-13): every attempt RESERVES its place in the count
  // (atomically) before the password is checked, and a correct password
  // clears the count afterwards. The old code read the count, checked the
  // password, then wrote count+1 — parallel guesses all read the same count,
  // so 20 at once were all checked against a 5-attempt lockout.
  const uid = (await KV.get<string>(["user_email", keySafe(email)])).value;
  const user = uid ? (await KV.get<any>(["user", uid])).value : null;
  // b77m (owner, VAR-28 follow-up): a phrase account stored in the cheap form, or an unknown label with a
  // phrase-format secret (equal work for both), is checked with one salted SHA-256 — no PBKDF2, no budget.
  // A phrase account still on PBKDF2 is checked with it once and rewritten (below).
  // b77n (pre-audit I4): an unknown phrase-FORMAT label is cheap whatever secret is sent, exactly like a known one
  // in the cheap form (whose check is cheap for any secret). It was cheap only for a phrase-format secret, so a
  // phrase label sent with any other secret answered fast if the account existed and after PBKDF2 if not.
  const cheap = user ? user.kdf === PHRASE_KDF : PHRASE_LABEL_RE.test(email);
  // b77m (audit VAR-28): the relay-wide hashing budget is full — refused before any guard
  // attempt is reserved (the hash below can still meet a full budget: the router answers 429 then).
  // b77m (owner, carrier NAT): only the relay-wide part refuses outright; a full per-NETWORK share asks for the
  // network puzzle instead (folded into the account guard's one puzzle below)
  if (!cheap && pbkdfGlobalFull()) return pbkdfBusy();
  const pbkdfNetOver = !cheap && await pbkdfNetFull(req);
  let pbkdfNetBits = 0;
  if (pbkdfNetOver) {
    // the hard ceiling (and the size) of the network puzzle, as netPowGate; its single puzzle is the account guard's
    const tags = await netPowTags(req);
    let passes = 0;
    for (const [tag, factor] of tags) passes = Math.max(passes, Number((await KV.get<number>(netPowKey("pbkdf", tag, 60_000))).value ?? 0) / factor);
    if (passes >= PBKDF2_PER_NETWORK * NET_POW_HARD_FACTOR) return pbkdfBusy();
    pbkdfNetBits = netPowBits(passes, PBKDF2_PER_NETWORK);
  }
  // b70 (audit RLY-2): the per-network throttle runs FIRST, so a network that is
  // already throttled can't keep feeding a label's count. The label lockout is
  // kept per (label, network): guesses from one network lock that network out
  // of that label, never the owner on another network. ("local" = the server
  // itself / an SSH tunnel — never throttled.)
  const ip = await clientTag(req);
  const ipLocal = ip === "local";
  // b77s (audit 4 RA-05): past 15 attempts in 15 minutes from one /64 or IPv4 address, each further attempt needs the
  // label puzzle (LOGIN_POW_NET_BITS, through the account guard below) instead of a 15-minute hard 429: the refusal
  // let one person on a shared address (carrier NAT, a café, a campus) keep everyone else there — the owner with the
  // right password included, and 24-word sign-ins too — out of signing in. A hard refusal stays only at
  // LOGIN_IP_HARD_PER_15MIN attempts (10x), counted whatever the puzzle.
  let ipOver = false;
  if (!ipLocal) {
    if (await rateLimit("login_ip_hard:" + ip, LOGIN_IP_HARD_PER_15MIN, 15 * 60_000, 15)) return j({ message: "Too many failed attempts — try again later" }, 429);
    if (!(await reserveLoginAttempt(["login_guard_ip", ip], 15, 15 * 60_000)).ok) ipOver = true;
  }
  // b74 (audit VAR-14): and per /56 and /48 (x4, x16), so rotating /64s inside one
  // subscriber's prefix doesn't buy fresh budgets. Re-audit N5: past those budgets each
  // attempt needs a solved puzzle (as the label guard below) instead of being refused —
  // a refusal let one person lock every bystander in a shared carrier /56 or /48 out of
  // signing in with the right password.
  const wideNets = ipLocal ? [] : await clientWideTags(req);
  let wideOver = false;
  for (const w of wideNets) {
    if (!(await reserveLoginAttempt(["login_guard_ip" + w.bits, w.tag], 15 * WIDE_FACTOR[w.bits], 15 * 60_000)).ok) wideOver = true;
  }
  // b70 (audit RLY-3): the same guard runs for labels that don't exist, so the
  // lockout can't tell real labels from invented ones
  // b70: keyed by a hash of the label, so a guess at an invented label leaves
  // no readable label in the database
  const labelHash = await sha256hex("veil-login-guard:" + email);
  const labelGuard = ["login_guard_h", labelHash, ip];
  // b74 (audit V-11): past 5 wrong passwords in 10 minutes from one network, that network's
  // attempts on the label each need a solved puzzle (LOGIN_POW_NET_BITS, through the account
  // guard below) instead of being refused for 10 minutes. The refusal let anyone sharing the
  // owner's network (carrier NAT, an IPv6 /64, a café, or the owner's own Wi-Fi) keep the
  // owner from signing in with the right password. Each guess still costs a puzzle, and the
  // network-wide guard above and the hourly cap below still refuse outright.
  const g = await reserveLoginAttempt(labelGuard, 5, 10 * 60_000);
  const labelNetPow = Math.max(g.ok && !wideOver && !ipOver ? 0 : LOGIN_POW_NET_BITS, pbkdfNetBits); // b77s (audit 4 RA-05): + ipOver // b77m (owner): + the hashing budget's network puzzle
  // b71 (audit F-03): and per ACCOUNT across every network. The checks above are per
  // network, so guesses spread over many networks (a botnet, IPv6 /64s) were never
  // capped. Same for labels that don't exist (no oracle). Existing sign-in tokens are
  // never affected.
  // b73 (audit): V-11 — past the free allowance the guard asks for a solved puzzle
  // instead of locking the label (see reserveAccountLoginAttempt): the owner's right
  // password always gets through. The 429 carries the puzzle:
  //   { pow_required: true, pow_challenge, pow_bits, pow_prefix: "vardum-login-pow-v1:" }
  // and the app retries the same login with { pow_challenge, pow_solution } added.
  const acctGuard: Deno.KvKey = ["login_guard_acct", labelHash];
  // b77t2 (CL-1): the label's hard daily cap on failed guesses (see LOGIN_LABEL_DAILY_FAIL_CAP) - checked before the
  // label puzzle, so a capped label hands out no puzzles. Phrase labels and the account's own device key skip it.
  const capExempt = PHRASE_LABEL_RE.test(email) || await loginDeviceKeyValid(user, body);
  if (!capExempt) {
    const capped = await reserveLabelCap(labelHash, false);
    if (capped) return capped;
  }
  const ag = await reserveAccountLoginAttempt(acctGuard, labelHash, body, labelNetPow);
  if (!ag.ok) {
    if (ag.pow) return j({ message: "Too many sign-in attempts on this account — update Vardum, or try again in an hour", pow_required: true, pow_challenge: ag.pow, pow_bits: ag.bits, pow_prefix: LOGIN_POW_LABEL }, 429);
    return j({ message: "Busy — try again" }, 429);
  }
  const loginStartedAt = nowIso(); // b70 (re-review 12): the token's age starts BEFORE the hash (a rebind during it kills the token)
  // b70 (re-review 7): every attempt (good ones too) costs a 100k-round hash, so attempts
  // per (label, network) are capped per hour before hashing; only that network is affected
  if (!ipLocal && await rateLimit("loginall:" + labelHash + ":" + ip, 60, 3600_000, 10)) {
    return j({ message: "Too many sign-ins — try again later" }, 429);
  }
  // b77t2 (CL-1): the place in the label's count is reserved only once the puzzle (if any) is solved (and the per-network hourly cap passed) - an unsolved
  // ask costs the guesser nothing and must cost the owner nothing either
  if (!capExempt) {
    const capped = await reserveLabelCap(labelHash, true);
    if (capped) return capped;
  }
  // b70 (audit RLY-3): an unknown label costs the same password hash as a real one
  // b71 (audit F-03): at the rounds the account's hash used (old rows: 100k); an unknown
  // label costs the current (600k) rounds
  const iter = user ? (Number(user.iter) || PBKDF2_LEGACY_ITERATIONS) : PBKDF2_ITERATIONS;
  // b77m (owner, carrier NAT): this request solved the puzzle that covered the network's hashing share
  if (pbkdfNetOver) {
    for (const [tag] of await netPowTags(req)) {
      const k = netPowKey("pbkdf", tag, 60_000);
      for (let i = 0; i < 20; i++) { const cur = await KV.get<number>(k); if ((await KV.atomic().check(cur).set(k, (cur.value ?? 0) + 1, { expireIn: 120_000 }).commit()).ok) break; }
    }
  }
  // b75 (audit RL-08): every attempt costs the same PBKDF2 work. An account whose hash is
  // older (100k rounds) used to answer in a sixth of the time an unknown label (600k)
  // took, which told those accounts apart from invented labels; the difference is now
  // spent on a throwaway hash before the answer. (A correct password on such an account
  // then also pays its re-hash at 600k below; that path already proves the password.)
  // b77m (audit VAR-28): both inside ONE place of the relay-wide hashing budget (with this
  // network's share)
  const hash = cheap
    ? await phraseSecretHash(password, user ? String(user.salt) : "x".repeat(32)) // b77m (owner): one SHA-256, no budget
    : await withPbkdfSlot(req, async () => {
      const h = await pbkdf2Hex(password, user ? user.salt : "x".repeat(32), iter);
      if (iter < PBKDF2_ITERATIONS) await pbkdf2Hex(password, "pad:" + (user ? user.salt : ""), PBKDF2_ITERATIONS - iter);
      return h;
    }, pbkdfNetOver); // b77s (audit 4 RA-04): a request past its network share (puzzle solved) hashes in the low-priority lane
  if (!user || !ctEq(hash, String(user.passHash || ""))) {
    return j({ message: "Invalid email or password" }, 401);
  }
  // b77m (owner, VAR-28 follow-up): a phrase account still on PBKDF2 is rewritten in the cheap form now that its
  // secret is proven (only if the row is unchanged since it was read)
  if (!cheap && phraseCheapEligible(email, password)) {
    const ue = await KV.get<Record<string, unknown>>(["user", user.id]);
    if (ue.value && ctEq(String(ue.value.passHash || ""), String(user.passHash || ""))) {
      const salt = crypto.randomUUID().replace(/-/g, "");
      const { iter: _i, ...rest } = ue.value;
      await KV.atomic().check(ue).set(["user", user.id], { ...rest, salt, passHash: await phraseSecretHash(password, salt), kdf: PHRASE_KDF }).commit();
    }
  }
  await KV.delete(labelGuard);
  await KV.delete(acctGuard); // b71 (audit F-03): a correct password ends the account-wide lockout
  if (!capExempt) await refundLabelCap(labelHash); // b77t2 (CL-1): only failures stay counted
  // b71 (audit F-03): an old 100k-round hash is upgraded now that the password is known
  // (written only if the user row is unchanged since it was read)
  if (!cheap && !phraseCheapEligible(email, password) && iter < PBKDF2_ITERATIONS) {
    const ue = await KV.get<Record<string, unknown>>(["user", user.id]);
    if (ue.value && ctEq(String(ue.value.passHash || ""), String(user.passHash || ""))) {
      const salt = crypto.randomUUID().replace(/-/g, "");
      await KV.atomic().check(ue).set(["user", user.id], { ...ue.value, salt, passHash: await pbkdf2Hex(password, salt, PBKDF2_ITERATIONS), iter: PBKDF2_ITERATIONS }).commit(); // (b77m: a proven password only — outside the budget, so a busy relay never fails a correct sign-in here)
    }
  }
  // b70 (re-review R5): the per-network counter is NOT cleared by a success (an
  // attacker's own good login every 14 guesses used to reset it); it expires.
  // b70 (re-review 2): the success only takes back its own attempt, so ordinary
  // logins on a shared network (carrier NAT) never add up to a lockout
  if (!ipLocal) await refundLoginAttempt(["login_guard_ip", ip]);
  for (const w of wideNets) await refundLoginAttempt(["login_guard_ip" + w.bits, w.tag]); // b74 (audit VAR-14)
  // b76 (registration lock): the right password (for a 24-word account: the words) is not enough
  // while the account's lock is active — the owning phone shows its device key, any other phone
  // the PIN proof. Checked only after the password, so nobody else learns the lock exists or can
  // spend its attempts. A lock that has lapsed ends here (as Signal's does): the words alone
  // get in, and the new phone can turn it on again.
  let regLockReply: Record<string, unknown> = {};
  {
    const lg = await regLockGate(await accountHashOf(user.id), body, true);
    if (lg.refused) return lg.refused;
    if (lg.deviceKey) regLockReply = { reglock: { device_key: lg.deviceKey } };
    if (lg.deviceKeyNext) regLockReply = { reglock_device_next: lg.deviceKeyNext }; // b76r2 (audit DEV-R2-03): the owning phone's rotated key
    if (lg.lapsed?.value && (await KV.atomic().check(lg.lapsed).delete(lg.lapsed.key).commit()).ok) regLockReply = { reglock_lapsed: true };
    if (lg.deviceKey || lg.deviceKeyNext) regLockSeen.delete(user.id); // b77u (audit 6 W2): the owning phone just checked in; its token renews from now on
  }
  // b77s (owner decision, Accounts): a password changed while this sign-in was checking the OLD one wins — no token
  { const pc = Number((await KV.get<Record<string, unknown>>(["user", user.id], { consistency: "strong" })).value?.pw_changed_at || 0); if (pc && pc >= Date.parse(loginStartedAt)) return j({ message: "Invalid email or password" }, 401); }
  const token = crypto.randomUUID().replace(/-/g, "") + crypto.randomUUID().replace(/-/g, "");
  // b77u (audit 6 W2): a sign-in that showed the device key or proved the PIN is the owning phone: its token renews the lock
  const rlTag = regLockReply.reglock_device_next ? await regLockDeviceTag(String(regLockReply.reglock_device_next)) : (regLockReply.reglock as { device_key?: string } | undefined)?.device_key ? await regLockDeviceTag(String((regLockReply.reglock as { device_key: string }).device_key)) : "";
  await storeAuthToken(token, { userId: user.id, email: user.email, created: loginStartedAt, exp: Date.now() + TOKEN_IDLE_MS, ...(rlTag ? { rl: rlTag } : {}) }); // b77s: with its per-account index entry; // b77m (audit VAR-44): exp at issue; // b70 (re-review 7 / 12): expires on its own; aged from the start of the login
  return json({ access_token: token, user: { id: user.id, email: user.email }, ...regLockReply });
});

route("POST", "/api/apps/:appId/auth/register", async (req) => {
  const body = await readJson(req);
  // mass-registration guard (unauthenticated endpoint): 10 accounts/hour/network
  // ("local" exempt — the server's own console / test batteries). b74 (audit VAR-14): and
  // per /56 and /48, and relay-wide
  // b77s (audit 4 RA-01): input that can't make an account is refused FIRST, before any budget is touched
  { const bad = newAccountInputError(String(body.email || ""), String(body.password || "")); if (bad) return j({ message: bad }, 400); }
  const su = await signupRefusal(req, body, signupKindOf(String(body.email || ""))); // b77m (owner): a puzzle past the network's cap
  if (su instanceof Response) return su;
  // b77m (owner, carrier NAT): a full per-network hashing share asks for the network puzzle (one per request)
  const regEmail = String(body.email || "").toLowerCase().trim(), regPw = String(body.password || "");
  let skipNet = su.powPassed;
  if (!skipNet && !phraseCheapEligible(regEmail, regPw) && await pbkdfNetFull(req)) {
    const g = await netPowGate(req, "pbkdf", PBKDF2_PER_NETWORK, 60_000, body, "Busy — try again");
    if (g) return g;
    skipNet = true;
  }
  try {
    const user = await createUser(String(body.email || ""), String(body.password || ""), req, skipNet);
    // b198 ANONYMOUS SIGNUP (founder decision, Oct 15): the email is a
    // SELF-DECLARED account label — real or invented, never verified, never
    // contacted. The Base44-era OTP mandate died with the platform. The
    // account is created + verified + usable in ONE step; the 24-word phrase
    // remains the only recovery path (disclosed at signup). Login lockouts,
    // the per-IP register cap, and the deletion cascade are unchanged.
    user.verified = true;
    await KV.set(["user", user.id], user);
    const token = crypto.randomUUID().replace(/-/g, "") + crypto.randomUUID().replace(/-/g, "");
    await storeAuthToken(token, { userId: user.id, email: user.email, created: nowIso(), exp: Date.now() + TOKEN_IDLE_MS }); // b77s: with its per-account index entry; // b77m (audit VAR-44): exp at issue; // b70 (re-review 7): expires on its own
    return json({ id: user.id, access_token: token, user: { id: user.id, email: user.email }, message: "Account created — no email verification" });
  } catch (e) {
    // b71 (review R-5): a taken (or retired) label gets a neutral refusal, after the
    // same password hash a new account costs — the reply text and timing no longer
    // say "this account exists". (Sign-up must still fail for a taken label; the
    // per-network sign-up cap above bounds how many labels one network can test, as
    // login's lockouts do.) The app maps any reply naming the email to its generic
    // "sign-in details did not work" text, so this stays compatible. veilSilentAccount
    // keeps "already registered": the app relies on it there, and its labels are
    // phrase-derived (not guessable).
    if (e instanceof PbkdfBusyError) throw e; // b77m (audit VAR-28): the router answers 429 busy
    const msg = String((e as Error).message);
    if (msg === "Email already registered") {
      await dummyPasswordWork(regEmail, regPw, req, skipNet); // b77m (owner): the work this kind of account costs
      return j({ message: "Could not create an account with that email and password — try a different email" }, 400);
    }
    return j({ message: msg }, 400);
  }
});

// b199 ACCOUNT-TAKEOVER FIX: this route used to accept ANY code and mint a
// token for whatever email it was given — anyone knowing an account's email
// could sign in as it. Signup is one step (register returns the token) and
// there is no OTP to verify, so the route mints nothing. Kept (not removed)
// so an old client gets a clear message instead of a bare 404.
route("POST", "/api/apps/:appId/auth/verify-otp", async () =>
  j({ message: "Email codes are not used on this relay — sign in with your email and password" }, 410));

// b199: logout revokes the presented token server-side (it used to be a no-op,
// so a copied token stayed valid for up to 30 days after sign-out)
route("POST", "/api/apps/:appId/auth/logout", async (req) => {
  const auth = req.headers.get("Authorization") || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : "";
  // b77m (audit VAR-27): the raw (pre-hash) rows go FIRST (authCheck's migration moves a raw row to
  // the hashed key only while the raw row is unchanged), then the hashed row
  // (an "h:" value is a hashed row's KEY, never a token: it deletes nothing raw)
  if (token && token.length <= MAX_KEY_PART) {
    if (!token.startsWith("h:")) { await KV.delete(["auth", token]); await KV.delete(["auth", keySafe(token)]); }
    { const hk = await authKey(token); const row = await KV.get<{ userId?: string }>(hk); await dropAuthRow(hk, row.value?.userId ? String(row.value.userId) : undefined); } // b77s: with its index entry
  }
  return json({ ok: true });
});

// ---------- b77s (owner decision, 1 Nov: Accounts) ----------
// "Sign out all other devices" (every account) and "Change password" (email accounts; signs out everywhere else).
// Both find the account's tokens through the per-account token index (authIxKey), never a scan of every token row.
/** the at-rest key part ("h:<hash>") of the token this request presents */
async function presentedTokenHashPart(req: Request): Promise<string> {
  const a = req.headers.get("Authorization") || "";
  const token = a.startsWith("Bearer ") ? a.slice(7) : "";
  return token ? String((await authKey(token))[1]) : "";
}
/**
 * b77t (audit 5 L-6, IH V-03): both routes revoke EVERY sign-in token of the account — the caller's too — and answer
 * with a FRESH token for the caller (`access_token`), which the app stores in place of the old one. They used to keep
 * the caller's token, so a stolen copy of the very token that ran "sign out other devices" or "change password" kept
 * working. The cutoff (tokens_after) names only the new token as the one that stays.
 * Returns how many OTHER tokens went (the caller's old one is not counted) and the new token.
 */
async function rotateAllTokens(userId: string, email: string, oldHashPart: string): Promise<{ token: string; signedOut: number }> {
  const token = crypto.randomUUID().replace(/-/g, "") + crypto.randomUUID().replace(/-/g, "");
  const keep = String((await authKey(token))[1]);
  // b77u (audit 6 W2): the caller's new token stays the owning phone's if its old one was
  const oldRl = oldHashPart ? (await KV.get<{ rl?: string }>(["auth", oldHashPart])).value?.rl : undefined;
  return await withLock("acctok:" + userId, async () => {
    let n = 0;
    for (const k of await accountTokenKeys(userId)) {
      if (String(k[1]) === keep) continue;
      await dropAuthRow(k, userId);
      if (String(k[1]) !== oldHashPart) n++;
    }
    await storeAuthToken(token, { userId, email, created: nowIso(), exp: Date.now() + TOKEN_IDLE_MS, ...(typeof oldRl === "string" ? { rl: oldRl } : {}) });
    return { token, signedOut: n };
  });
}
/** b77t (audit 5 L-6): a password (an email account's, or a 24-word account's phrase-derived secret) checked exactly as
 *  a sign-in checks it — the label's account-wide guard and puzzle, the relay-wide hashing budget, the same verifier.
 *  null = right; otherwise the refusal. */
async function accountPasswordRefusal(req: Request, user: Record<string, any>, body: Record<string, unknown>, password: string, dayKey: string): Promise<Response | null> {
  const label = String(user.email || "").toLowerCase().trim();
  if (!password || password.length > 512 || !label) return j({ error: "Wrong password", message: "Wrong password", code: "wrong_password" }, 401);
  { const drl = await rateLimit(dayKey + ":" + String(user.id || label), 30, 86400_000, 60); if (drl) return j({ locked: true, retry_minutes: drl.retry_minutes }, 429); }
  const cheap = user.kdf === PHRASE_KDF;
  if (!cheap && pbkdfGlobalFull()) return pbkdfBusy();
  const labelHash = await sha256hex("veil-login-guard:" + label);
  const acctGuard: Deno.KvKey = ["login_guard_acct", labelHash];
  const ag = await reserveAccountLoginAttempt(acctGuard, labelHash, body);
  if (!ag.ok) {
    if (ag.pow) return j({ message: "Too many password attempts on this account — try again in an hour", pow_required: true, pow_challenge: ag.pow, pow_bits: ag.bits, pow_prefix: LOGIN_POW_LABEL }, 429);
    return j({ message: "Busy — try again" }, 429);
  }
  const hash = cheap ? await phraseSecretHash(password, String(user.salt)) : await withPbkdfSlot(req, () => pbkdf2Hex(password, String(user.salt), Number(user.iter) || PBKDF2_LEGACY_ITERATIONS));
  if (!ctEq(hash, String(user.passHash || ""))) {
    await countLabelFailure(labelHash); // b77t2 (CL-1): counted, never capped here (the owner's password change must work)
    return j({ error: "Wrong password", message: "Wrong password", code: "wrong_password" }, 401);
  }
  await KV.delete(acctGuard); // (the right password ends the account-wide guard, as a sign-in does)
  return null;
}
// accountSignOutOthers {password} | {proof} -> { ok: true, signed_out: n, access_token }: every sign-in token of this
// account goes (the other phones' next request answers 401 and they sign in again); the caller gets a new token.
// b77t (audit 5 L-6): a FRESH credential is required, not the bearer token alone: the account's password (for a
// 24-word account, the phrase-derived secret), checked as a sign-in checks it, or the primary identity's proof with a
// relay-issued nonce (label "vardum-signout-others-v1", see primaryProofRefusal; an account with no primary identity:
// its password — a fresh sign-in alone is NOT enough here, unlike the account-destroying routes).
route("POST", "/api/apps/:appId/functions/accountSignOutOthers", async (req) => {
  const auth = await authUser(req);
  if (!auth) return j({ message: "Unauthorized" }, 401);
  { const lim = await routeLimited("signoutothers", auth.userId, 10); if (lim) return lim; }
  const body = await readJson(req);
  const user = (await KV.get<Record<string, any>>(["user", auth.userId], { consistency: "strong" })).value;
  if (!user) return j({ message: "Unauthorized" }, 401);
  if (typeof body.password === "string" && body.password) {
    const refused = await accountPasswordRefusal(req, { ...user, id: auth.userId }, body, body.password, "signout-day");
    if (refused) return refused;
  } else {
    const refused = await primaryProofRefusal(auth, body, "vardum-signout-others-v1", { proof: "Confirm with your password or this phone's Vardum ID to sign out other devices", fresh: "Confirm with your password to sign out other devices" }, { legacy: "never", noFreshSignIn: true });
    if (refused) return refused;
  }
  const old = await presentedTokenHashPart(req);
  // b77s (confirmation review N-3) / b77t (L-6): the account-wide cutoff first (every token is dead from now on,
  // whatever the index holds), then the index scan as cleanup, then the caller's new token
  const fresh = crypto.randomUUID(); // (placeholder keep: no token has this hash part; the new token is created after the cutoff)
  if (!(await setTokenCutoff(auth.userId, "h:" + fresh))) return j({ error: "Could not sign out other devices — try again", message: "Could not sign out other devices — try again", code: "conflict" }, 409);
  // b77u (audit 6 W1, IH relay F-01): the duress purge token (a no-login wipe credential) is revoked with the sign-ins —
  // a lost phone's copy used to keep working after the owner signed it out. The caller's phone mints a fresh one.
  await withLock("purgetok:" + auth.userId, () => dropPurgeToken(auth.userId));
  const r = await rotateAllTokens(auth.userId, String(user.email || auth.email || ""), old);
  return json({ ok: true, signed_out: r.signedOut, access_token: r.token });
});
// accountChangePassword { old_password, new_password } -> { ok: true, signed_out: n, access_token }
//  - email-label accounts only (a 24-word / silent / duress account has no password a person chose): else 400
//    code "not_email_account";
//  - the new password must meet the new-account minimum (PASSWORD_MIN_LEN, at most 512): else 400 "weak_password";
//  - the old password is checked exactly as a sign-in checks it — the same account-wide guard and puzzle
//    (reserveAccountLoginAttempt on the label's ["login_guard_acct"] row, so wrong guesses here count against the
//    same budget as sign-in guesses), the same PBKDF2 verifier, inside the relay-wide hashing budget (429 "busy");
//    wrong: 401 code "wrong_password";
//  - the new verifier (PBKDF2, the current rounds, a new salt) is stored in one step checked against the user row as
//    read, with pw_changed_at (a sign-in that was checking the OLD password meanwhile gets no token), and EVERY
//    sign-in token of the account goes — b77t (audit 5 L-6): the caller's too; the caller gets a new one.
route("POST", "/api/apps/:appId/functions/accountChangePassword", async (req) => {
  const auth = await authUser(req);
  if (!auth) return j({ message: "Unauthorized" }, 401);
  { const lim = await routeLimited("chpw", auth.userId, 10); if (lim) return lim; }
  const body = await readJson(req);
  const ue = await KV.get<Record<string, any>>(["user", auth.userId], { consistency: "strong" });
  const user = ue.value;
  if (!user) return j({ message: "Unauthorized" }, 401);
  const label = String(user.email || "").toLowerCase().trim();
  if (!label || PHRASE_LABEL_RE.test(label) || user.kdf === PHRASE_KDF) {
    return j({ error: "Only email accounts have a password to change", message: "Only email accounts have a password to change", code: "not_email_account" }, 400);
  }
  const oldPw = typeof body.old_password === "string" ? body.old_password : "";
  const newPw = typeof body.new_password === "string" ? body.new_password : "";
  if (newPw.length < PASSWORD_MIN_LEN || newPw.length > 512) {
    const msg = `Choose a password of at least ${PASSWORD_MIN_LEN} characters`;
    return j({ error: msg, message: msg, code: "weak_password" }, 400);
  }
  if (!oldPw || oldPw.length > 512) return j({ error: "Wrong password", message: "Wrong password", code: "wrong_password" }, 401);
  // (the sign-in's account-wide guard and puzzle, on the same row; see accountPasswordRefusal)
  { const refused = await accountPasswordRefusal(req, { ...user, id: auth.userId }, body, oldPw, "chpw-day"); if (refused) return refused; }
  const salt = crypto.randomUUID().replace(/-/g, "");
  const passHash = await withPbkdfSlot(req, () => pbkdf2Hex(newPw, salt, PBKDF2_ITERATIONS));
  const { kdf: _k, ...rest } = user;
  const old = await presentedTokenHashPart(req);
  // b77s (confirmation review N-3): with the account-wide cutoff (tokens_after) in the same step — a sign-in that
  // started before it (it checked the OLD password) is refused on use even if it stored its token after the
  // pw_changed_at check. b77t (L-6): no existing token is kept (the caller's new one is created after the cutoff).
  const changedAt = Date.now();
  const ok = (await KV.atomic().check(ue).set(["user", auth.userId], { ...rest, salt, passHash, iter: PBKDF2_ITERATIONS, pw_changed_at: changedAt, tokens_after: changedAt, tokens_after_keep: "h:" + crypto.randomUUID(), updated: nowIso() }).commit()).ok;
  if (!ok) return j({ error: "Could not change the password — try again", message: "Could not change the password — try again", code: "conflict" }, 409);
  await withLock("purgetok:" + auth.userId, () => dropPurgeToken(auth.userId)); // b77u (audit 6 W1, IH relay F-01)
  const r = await rotateAllTokens(auth.userId, String(user.email || ""), old);
  return json({ ok: true, signed_out: r.signedOut, access_token: r.token });
});


// ---------- b77t (audit 5 L-15): single-use nonces for the primary identity's proofs ----------
// veilProofNonce {label} -> {nonce, expires_in_s}: a 32-hex nonce for THIS account and label, live PROOF_NONCE_TTL_MS,
// consumed by the request it is signed into (primaryProofRefusal). Labels: PROOF_LABELS. Works while the account is
// being deleted (an account delete's retry signs a new proof), like veilAccountDelete itself.
route("POST", "/api/apps/:appId/functions/veilProofNonce", async (req) => {
  const auth = await authCheck(req, true);
  if (auth && "gone" in auth) return accountGone();
  if (!auth) return j({ message: "Unauthorized" }, 401);
  { const lim = await routeLimited("proofnonce", auth.userId, 30); if (lim) return lim; }
  const body = await readJson(req);
  const label = String(body?.label ?? "");
  if (!PROOF_LABELS.has(label)) return j({ error: "Unknown proof label", message: "Unknown proof label" }, 400);
  const nonce = [...crypto.getRandomValues(new Uint8Array(16))].map((b) => b.toString(16).padStart(2, "0")).join("");
  await KV.set(proofNonceKey(auth.userId, nonce), { label }, { expireIn: PROOF_NONCE_TTL_MS });
  return json({ nonce, expires_in_s: PROOF_NONCE_TTL_MS / 1000 });
});

// ---------- b77t (audit 5 L-5, IH C-08): the pre-authorised duress purge ----------
// The duress wipe purged the relay only with a proof the identity signs in memory, so a duress code entered while the
// identity was NOT in memory (e.g. Nothing at Rest after a reopen) left the relay's identity records, vaults and notes
// in place. Now the phone mints a PURGE TOKEN while the identity is present and keeps it on the device:
//   veilPurgeToken {action: "mint", proof} (signed in; the primary identity's nonce proof, label
//     "vardum-purge-token-v1"; an account with no primary: a fresh sign-in) -> {purge_token}: 64 hex, one per account
//     (a new mint replaces the old one); the relay keeps only SHA-256("veil-purge-token:" + token) -> the account id;
//   veilPurgeToken {action: "revoke", purge_token} | {action: "revoke", proof} (signed in) -> {ok}: the account's token
//     goes. b77t2 (CL-3): the bearer token alone no longer revokes it (a stolen copy of the token could silently disarm
//     the duress purge; the phone is not told). The caller proves it holds the purge token itself (`purge_token`: the
//     account's CURRENT token, else 403 and nothing changes) or the primary identity's nonce proof (label
//     "vardum-purge-token-v1", as mint; an account with no primary: a fresh sign-in);
//   veilDuressPurge {purge_token} (NO login: the token is the credential; per network 10 an hour) -> {ok, deleted}:
//     single use (the token's rows go in one atomic step before anything else), then the same purge as the gate's
//     "purge" (identities, chats, groups, transfer links, the registration lock) PLUS every vault (and its file) and
//     note of the account. The account and its sign-in tokens stay (the wipe's own logout ends the phone's token).
//     An unknown or used token: 403, nothing done.
const purgeTokenKey = async (token: string): Promise<Deno.KvKey> => ["purge_token", await sha256hex("veil-purge-token:" + token)];
const purgeTokenAcctKey = (userId: string): Deno.KvKey => ["purge_token_acct", userId];
/** the account's purge token rows go (account delete, revoke, a new mint) */
async function dropPurgeToken(userId: string): Promise<void> {
  const a = await KV.get<string>(purgeTokenAcctKey(userId));
  if (a.value) await KV.delete(["purge_token", a.value]);
  await KV.delete(purgeTokenAcctKey(userId));
}
route("POST", "/api/apps/:appId/functions/veilPurgeToken", async (req) => {
  const auth = await authUser(req);
  if (!auth) return j({ message: "Unauthorized" }, 401);
  { const lim = await routeLimited("purgetoken", auth.userId, 10); if (lim) return lim; }
  const body = await readJson(req);
  const action = String(body?.action ?? "");
  if (action === "revoke") {
    // b77t2 (CL-3): the purge token itself, or the identity's proof
    if (body?.purge_token !== undefined) {
      const tok = typeof body.purge_token === "string" ? body.purge_token : "";
      if (!/^[0-9a-f]{64}$/.test(tok)) return j({ error: "Invalid purge token", message: "Invalid purge token" }, 400);
      const k = await purgeTokenKey(tok);
      return await withLock("purgetok:" + auth.userId, async () => {
        const cur = (await KV.get<string>(purgeTokenAcctKey(auth.userId), { consistency: "strong" })).value;
        if (!cur || !ctEq(cur, String(k[1]))) return j({ error: "Invalid purge token", message: "Invalid purge token" }, 403);
        await dropPurgeToken(auth.userId);
        return json({ ok: true });
      });
    }
    await ensurePrimaryIdentity(auth.userId);
    const refusedRevoke = await primaryProofRefusal(auth, body, "vardum-purge-token-v1", { proof: "Turning off the emergency wipe needs this phone's purge token or the Vardum ID this account was set up with", fresh: "Sign in again, then turn off the emergency wipe" }, { legacy: "never" });
    if (refusedRevoke) return refusedRevoke;
    await withLock("purgetok:" + auth.userId, () => dropPurgeToken(auth.userId));
    return json({ ok: true });
  }
  if (action !== "mint") return j({ error: "Unknown action", message: "Unknown action" }, 400);
  await ensurePrimaryIdentity(auth.userId);
  const refused = await primaryProofRefusal(auth, body, "vardum-purge-token-v1", { proof: "Setting up the emergency wipe needs the Vardum ID this account was set up with", fresh: "Sign in again, then set up the emergency wipe" }, { legacy: "never" });
  if (refused) return refused;
  const token = [...crypto.getRandomValues(new Uint8Array(32))].map((b) => b.toString(16).padStart(2, "0")).join("");
  const k = await purgeTokenKey(token);
  return await withLock("purgetok:" + auth.userId, async () => {
    await dropPurgeToken(auth.userId);
    if (!(await writeIfAccountLive(auth.userId, [[k, { uid: auth.userId, created: Date.now() }], [purgeTokenAcctKey(auth.userId), String(k[1])]]))) return ACCOUNT_GONE_WRITE();
    return json({ purge_token: token });
  });
});
route("POST", "/api/apps/:appId/functions/veilDuressPurge", async (req) => {
  const body = await readJson(req);
  const token = typeof body?.purge_token === "string" ? body.purge_token : "";
  if (!/^[0-9a-f]{64}$/.test(token)) return j({ error: "Invalid purge token", message: "Invalid purge token" }, 400);
  const net = await clientTag(req);
  if (net !== "local") { const rl = await rateLimit("duresspurge:" + net, 10, 3600_000, 0); if (rl) return j({ locked: true, retry_minutes: rl.retry_minutes }, 429); }
  const k = await purgeTokenKey(token);
  const row = await KV.get<{ uid?: string }>(k, { consistency: "strong" });
  const uid = String(row.value?.uid || "");
  if (!uid) return j({ error: "Invalid purge token", message: "Invalid purge token" }, 403);
  const ak = await KV.get<string>(purgeTokenAcctKey(uid), { consistency: "strong" });
  // single use: both rows go in one step (a second use, or a concurrent one, finds nothing)
  const tx = KV.atomic().check(row).delete(k);
  if (ak.value === String(k[1])) tx.check(ak).delete(ak.key);
  if (!(await tx.commit()).ok) return j({ error: "Invalid purge token", message: "Invalid purge token" }, 403);
  if (!(await KV.get(["user", uid])).value) return json({ ok: true, deleted: null });
  await ensurePrimaryIdentity(uid); // (recorded before the identities go, as the gate's purge does: the account stays deletable only with a proof)
  const deleted = await purgeAccountRelayData({ userId: uid }, uid);
  // and the account's vaults (with their files) and notes
  const acct = await accountHashOf(uid);
  let vaults = 0, notes = 0;
  for (const name of ["VeilVault", "VeilNote"] as const) {
    const ids: string[] = [];
    for await (const e of acctRows(name, acct)) ids.push(String(e.key[2]));
    for (const id of ids) {
      const gone = await deleteIndexedRow(name, id);
      if (!gone) continue;
      if (name === "VeilVault") { await removeVaultBlob(gone); vaults++; } else notes++;
    }
  }
  return json({ ok: true, deleted: { ...deleted, vaults, notes } });
});

// ---------- b199 entity access policy ----------
// Every generic /entities route is checked against this table. An entity not
// listed is unknown to the generic API (404) — gate functions own those rows
// (VeilGroupMember, VeilGroupDenyEntry, ...). Writes the native client never
// makes through this API are refused: envelopes only enter via submitEnvelope
// (write-secret + rate limit + group roster checks), sessions only change via
// veilSessionGate.
type EntityOp = "list" | "get" | "create" | "update" | "delete";
const ENTITY_POLICY: Record<string, ReadonlySet<EntityOp>> = {
  // b54 hotfix (code review V-14): no generic list — it returned full rows to
  // any token holder. Clients use the participant-scoped veilSessionGate list.
  VeilSession: new Set<EntityOp>(["get", "create", "delete"]),
  VeilEnvelope: new Set<EntityOp>(["list", "get", "delete"]),
  VeilVault: new Set<EntityOp>(["list", "get", "create", "update", "delete"]),
  VeilNote: new Set<EntityOp>(["list", "get", "create", "update", "delete"]),
  // b77p: "update" is refused by the PUT route (b77's push_refs are retired). b77p round 2: "create" and "update" are
  // taken only from legacy phones during the transition window (POST 410 / PUT 400 after it); list / get / delete stay
  // (a b77p phone retires the row an earlier build made)
  VeilPushToken: new Set<EntityOp>(["list", "get", "create", "update", "delete"]),
  // anonymous funnel analytics: write-only
  OnboardingStep: new Set<EntityOp>(["create"]),
  AttributionSource: new Set<EntityOp>(["create"]),
};

/** null = allowed; otherwise the refusal response. */
function entityOpRefusal(entity: string, op: EntityOp): Response | null {
  // b70 (re-review 8): own keys only ("constructor", "toString" used to reach a 500)
  const ops = Object.prototype.hasOwnProperty.call(ENTITY_POLICY, entity) ? ENTITY_POLICY[entity] : undefined;
  if (!ops) return j({ message: "Not found" }, 404);
  if (!ops.has(op)) return j({ message: "Not allowed" }, 403);
  return null;
}

/** Row-level check for get/update/delete by id. */
async function canAccessRow(entity: string, row: Record<string, unknown>, auth: { userId: string }, op: EntityOp): Promise<boolean> {
  if (entity === "VeilSession") return sessionParticipant(row, auth);
  if (entity === "VeilEnvelope") {
    // b71 (audit F-35): an envelope is deleted through this API only by the account
    // that SENT it (its per-row owner tag; legacy rows: their client_id). Being a party
    // to the sending session used to be enough, so a group's creator — who holds every
    // seat's initiator side — could delete any member's posts, rekeys included. Expiry,
    // burn, chat end and account delete remove envelopes on the relay's own paths. (No
    // app build deletes envelopes through this API.)
    if (op === "delete") {
      const id = String(row.id || "");
      if (row._owner) return !!id && String(row._owner) === await ownerTag(auth.userId, id);
      return !!row.client_id && String(row.client_id) === auth.userId;
    }
    const session = await findSessionByToken(String(row.session_token || ""));
    if (session && await sessionParticipant(session, auth)) return true;
    // Batch C (V-15): group members may READ the group stream. b74 (audit VAR-01): ADMITTED
    // members; a claimant the creator has not let in reads only its own seat's rows (any
    // member row, admitted or not, used to open every row)
    const gt = String(row.group_token || "");
    if (!gt) return false;
    const access = await groupReadAccess(gt, auth.userId);
    return access.admitted || access.seats.has(String(row.session_token || ""));
  }
  if (OWNER_SCOPED_ENTITIES.has(entity)) {
    const owner = String(row._acct || "");
    // b77u (audit 6 R4 #6): an ownerless (pre-b199) push row is no longer deletable by any account — that let anyone
    // who could list or guess a row id silence another phone's legacy wakes. Such rows age out (the transition window's
    // end deletes every legacy push row, and an account delete takes its own).
    if (!owner) return false;
    return owner === await accountHashOf(auth.userId);
  }
  return false;
}

// entities (auth required)
route("GET", "/api/apps/:appId/entities/:entity", async (req, m, url) => {
  const auth = await authUser(req);
  if (!auth) return j({ message: "Unauthorized" }, 401);
  const refused = entityOpRefusal(m.groups!.entity!, "list");
  if (refused) return refused;
  const listed = await listEntity(m.groups!.entity!, url, auth);
  if (listed && (listed as any).__limited !== undefined) return j({ locked: true, retry_minutes: (listed as any).__limited }, 429);
  if (listed && (listed as any).__blocked) {
    return j({ message: String((listed as any).__blocked) }, 403);
  }
  if (listed && (listed as any).__badquery) return j({ error: String((listed as any).__badquery), message: String((listed as any).__badquery) }, 400); // b75 (audit RL-10)
  if (listed && (listed as any).__notfound) {
    return j({ error: String((listed as any).__notfound), message: String((listed as any).__notfound) }, 404);
  }
  // b70 (re-review R3): envelope owner tags are an unkeyed hash of the sender's
  // account id; they are the relay's bookkeeping and never leave it
  // b74 (audit VAR-01): and a group row's seat token is shown to the group's creator only
  if (m.groups!.entity! === "VeilEnvelope" && Array.isArray(listed)) return json(await envelopeRowsView(listed, auth.userId));
  return json(listed);
});

route("POST", "/api/apps/:appId/entities/:entity", async (req, m) => {
  const auth = await authUser(req);
  if (!auth) return j({ message: "Unauthorized" }, 401);
  const refused = entityOpRefusal(m.groups!.entity!, "create");
  if (refused) return refused;
  // b77p round 2 (owner decisions 1 and 4): an account push row exists only for a pre-b77p phone during the transition
  // window (it wakes that phone's legacy push_ref mailboxes). b77p phones never create one; after VEIL_COMPAT_UNTIL
  // nobody can.
  if (m.groups!.entity! === "VeilPushToken" && !compatOn()) {
    const msg = "Update Vardum: notifications now come only through your chats";
    return j({ error: msg, message: msg, code: "push_rows_retired" }, 410);
  }
  const body = await readJson(req);
  // b70 (re-review 2): a row must fit one KV value (64 KB); bigger ones used to reach a 500
  if (utf8Len(JSON.stringify(body ?? {})) > MAX_ROW_BYTES) return TOO_LARGE("This item is too large");
  // b77n (pre-audit M1): no new rows while the disk is nearly full (see kvStorageFull)
  if (await kvStorageFull()) return KV_STORAGE_FULL();
  // b70 (re-review R7): rows of each kind one account may create per day (the
  // app's own use is far below this; rows used to be unlimited)
  const createRl = await rateLimit("create:" + m.groups!.entity! + ":" + auth.userId, ENTITY_CREATES_PER_DAY[m.groups!.entity!] ?? 500, 86_400_000, 60);
  if (createRl) return j({ locked: true, retry_minutes: createRl.retry_minutes, message: "Too many new items today — try again later" }, 429);
  // b70 (re-review P6): analytics rows hold a step name and a few short fields
  if (ANALYTICS_ENTITIES.has(m.groups!.entity!) && utf8Len(JSON.stringify(body ?? {})) > ANALYTICS_ROW_MAX_BYTES) return TOO_LARGE();
  // b77n (pre-audit M1): the row's bytes count against the caller's network for the day (given back if no row is made)
  const netBytes = await reserveEntityNetBytes(req, utf8Len(JSON.stringify(body ?? {})));
  if (!netBytes) return ENTITY_NET_DAILY_LIMIT();
  const created = await createEntityRoute(req, m, body, auth);
  if (!created || Object.keys(created as Record<string, unknown>).some((k) => k.startsWith("__"))) await netBytes.undo();
  return createdResponse(created);
});
/** the create itself (POST /entities/:entity), as before b77n */
async function createEntityRoute(req: Request, m: RegExpMatchArray, body: any, auth: { userId: string; email?: string }) {
  if (m.groups!.entity! === "VeilVault" && body && typeof body.container_uri === "string") body.container_uri = canonBlobUri(body.container_uri); // b77u (audit 6 U-M9 / F-05)
  // b71 (audit F-19): registrations of one push address run one at a time (the
  // one-account-per-address rule is a read-then-write)
  // b77m (audit VAR-03): a vault row pins its file (the sweeper keeps it), so it is checked against
  // the pinned-bytes caps first — one create at a time per account (the account total is a sum)
  return m.groups!.entity! === "VeilPushToken"
    ? await withLock("pushtok:" + String(body?.expo_token ?? "").slice(0, 600), () => createEntity(m.groups!.entity!, body, auth))
    : m.groups!.entity! === "VeilVault"
    ? await withLock("vaultpin:" + auth.userId, async () => {
      const pin = await vaultPinGate(req, auth.userId, String(body?.container_uri ?? ""), null);
      if (pin instanceof Response) return { __response: pin } as any;
      const out = await createEntity("VeilVault", body, auth);
      if (out && !(out as any).__forbidden && !(out as any).__conflict && !(out as any).__response) pin.commit(); else await pin.undo(); // b77s: __response = account gone (RA-02)
      return out;
    })
    : await createEntity(m.groups!.entity!, body, auth);
}
function createdResponse(created: any): Response {
  if (created && (created as any).__response instanceof Response) return (created as any).__response;
  // b74 (audit VAR-13): a UnifiedPush address's first registration waits for its challenge code
  if (created && (created as any).__pushVerify) {
    const msg = "Confirm this device's notification address — Vardum does this by itself";
    return j({ error: msg, message: msg, push_verify: (created as any).push_verify, push_verify_required: true }, 409);
  }
  if (created && (created as any).__pushTaken) {
    const msg = "This device's notification address is registered to another account";
    return j({ error: msg, message: msg, push_verify: (created as any).push_verify }, 409);
  }
  if (created && (created as any).__conflict) {
    return j({ error: "Conflict", message: "A session with this token already exists" }, 409);
  }
  if (created && (created as any).__badRequest) { // b77m (audit VAR-26)
    return j({ error: String((created as any).__badRequest), message: String((created as any).__badRequest), code: "bad_request" }, 400);
  }
  if (created && (created as any).__forbidden) {
    return j({ error: String((created as any).__forbidden), message: String((created as any).__forbidden) }, 403);
  }
  return json(clientRow(created)); // b77t (audit 5 L-29)
}

route("PUT", "/api/apps/:appId/entities/:entity/:id", async (req, m) => {
  const auth = await authUser(req);
  if (!auth) return j({ message: "Unauthorized" }, 401);
  const refused = entityOpRefusal(m.groups!.entity!, "update");
  if (refused) return refused;
  { const lim = await routeLimited("entput", auth.userId, 120); if (lim) return lim; } // b77u (audit 6 R4 #8): a PUT limiter (each update rewrites the row and its indexes)
  let body = await readJson(req);
  body = pickClientFields(m.groups!.entity!, body); // b77p (audit VAR-32): a note / vault update keeps only the app's fields
  if (utf8Len(JSON.stringify(body ?? {})) > MAX_ROW_BYTES) return TOO_LARGE("This item is too large"); // b70 (re-review 2)
  if (m.groups!.id!.length > MAX_KEY_PART) return j({ message: "Not found" }, 404);
  if (await kvStorageFull()) return KV_STORAGE_FULL(); // b77n (pre-audit M1)
  // b77p (audit 2 VAR-01): nothing of a push row can be changed — b77's update carried push_refs only, and those are
  // retired (the address, its keys and its verification are set by create, with the possession proof).
  // b77p round 2 (owner decision 4): during the transition window a LEGACY phone's update of its push_refs (and
  // nothing else) is taken again, as b77 did; after VEIL_COMPAT_UNTIL it is refused as above.
  if (m.groups!.entity! === "VeilPushToken") {
    if (!compatOn()) return j({ error: "Push rows can't be changed", message: "Push rows can't be changed" }, 400);
    const keys = Object.keys(body ?? {});
    const refs = cleanPushRefs(body?.push_refs);
    if (keys.length !== 1 || keys[0] !== "push_refs" || !refs) return j({ error: "Only push_refs can be changed", message: "Only push_refs can be changed" }, 400);
    body = { push_refs: refs };
    { const lim = await routeLimited("pushrefs", auth.userId, 60); if (lim) return lim; }
  }
  // b77m review (L4): a vault update that repoints the row runs under the same per-account lock as a vault
  // create ("vaultpin:"): the account total is a sum, so two PUTs in parallel each passed the gate on the
  // same total and together went past the per-account cap
  if (m.groups!.entity! === "VeilVault" && body && typeof body.container_uri === "string") body.container_uri = canonBlobUri(body.container_uri); // b77u (audit 6 U-M9 / F-05)
  const repoint = m.groups!.entity! === "VeilVault" && body?.container_uri !== undefined;
  const runUpdate = async (): Promise<Response> => {
  // b70 (re-review 14): the write is checked against the row as read, and retried (two
  // overlapping edits used to lose one; an edit overlapping a delete could bring it back)
  for (let attempt = 0; attempt < 10; attempt++) {
  const got = await KV.get<Record<string, unknown>>(["entity", m.groups!.entity!, m.groups!.id!]);
  const row = got.value;
  // b199: someone else's row answers exactly like a missing one (no existence oracle)
  if (!row || !(await canAccessRow(m.groups!.entity!, row, auth, "update"))) return j({ message: "Not found" }, 404);
  // Batch E (RV-39): a vault update can't repoint the row at someone else's file
  if (m.groups!.entity! === "VeilVault" && body.container_uri !== undefined && String(body.container_uri) !== String(row.container_uri ?? "")
    && !(await blobHeldBy(String(body.container_uri), await accountHashOf(auth.userId)))) return j({ message: "Not your file" }, 403);
  // b77m (audit VAR-03): repointing a vault at another file pins that file — the pinned-bytes caps
  let pin: { commit: () => void; undo: () => Promise<void> } | null = null;
  if (m.groups!.entity! === "VeilVault" && body.container_uri !== undefined && String(body.container_uri) !== String(row.container_uri ?? "")) {
    const g = await vaultPinGate(req, auth.userId, String(body.container_uri), String(row.container_uri ?? ""));
    if (g instanceof Response) return g;
    pin = g;
  }
  // server-owned fields can never be rewritten by a client merge
  const merged = { ...row, ...body, id: m.groups!.id!, created_date: row.created_date, _acct: row._acct, _owner: row._owner, updated_date: nowIso() };
  for (const k of ["_acct", "_owner"] as const) if (merged[k] === undefined) delete merged[k];
  // b70 (re-review 3): the MERGED row must fit one KV value too
  if (utf8Len(JSON.stringify(merged)) > MAX_ROW_BYTES) { if (pin) await pin.undo(); return TOO_LARGE("This item is too large"); }
  // b77n (pre-audit M1): a note that GROWS is checked against the account's note bytes (NOTE_BYTES_PER_ACCOUNT), in
  // step with creates (the per-account sequence row); an edit that keeps or shrinks a note always goes through
  let noteSeq: { key: Deno.KvKey; entry: Deno.KvEntryMaybe<number> } | null = null;
  if (m.groups!.entity! === "VeilNote" && utf8Len(JSON.stringify(merged)) > utf8Len(JSON.stringify(row))) {
    const acct = String(row._acct ?? "");
    const key: Deno.KvKey = ["row_cap_seq", "VeilNote", acct];
    noteSeq = { key, entry: await KV.get<number>(key) };
    let bytes = utf8Len(JSON.stringify(merged));
    for await (const e of acctRows("VeilNote", acct)) if (String(e.key[2]) !== m.groups!.id!) bytes += utf8Len(JSON.stringify(e.value));
    if (bytes > NOTE_BYTES_PER_ACCOUNT) return j({ error: "Notes storage limit reached — delete some notes first", message: "Notes storage limit reached — delete some notes first" }, 403);
  }
  // b77n (pre-audit L3): the row's index entries follow it in the same step (a vault repoint moves its ["ix_vault_uri"] entry)
  const ixWant = await entityIxKeys(m.groups!.entity!, m.groups!.id!, merged);
  const ixDrop = (await entityIxKeys(m.groups!.entity!, m.groups!.id!, row)).filter((k) => !ixWant.some((w) => JSON.stringify(w) === JSON.stringify(k)));
  const utx = KV.atomic().check(got).set(["entity", m.groups!.entity!, m.groups!.id!], merged);
  // b77s (audit 4 RA-02): only while the caller's account is live (checked in this same step)
  { const ue = await liveAccountEntry(auth.userId); if (!ue) { if (pin) await pin.undo(); return ACCOUNT_GONE_WRITE(); } utx.check(ue); }
  if (noteSeq) utx.check(noteSeq.entry).set(noteSeq.key, (Number(noteSeq.entry.value) || 0) + 1);
  for (const k of ixDrop) utx.delete(k);
  for (const k of ixWant) utx.set(k, 1);
  // b77r1 (audit R-6): the legacy push_ref index follows the row's push_refs in the same step (transition window only)
  if (m.groups!.entity! === "VeilPushToken") {
    const keep = new Set(pushRefIndexKeys(m.groups!.id!, merged).map((k) => JSON.stringify(k)));
    for (const k of pushRefIndexKeys(m.groups!.id!, row)) if (!keep.has(JSON.stringify(k))) utx.delete(k);
    for (const k of pushRefIndexKeys(m.groups!.id!, merged)) utx.set(k, 1);
  }
  if (!(await utx.commit()).ok) { if (pin) await pin.undo(); continue; }
  if (pin) pin.commit();
  return json(clientRow(merged)); // b77t (audit 5 L-29)
  }
  return j({ message: "Busy, try again" }, 409);
  };
  // b77n (pre-audit M1): an update's bytes count against the network's day too (given back if it is not written)
  const netBytes = await reserveEntityNetBytes(req, utf8Len(JSON.stringify(body ?? {})));
  if (!netBytes) return ENTITY_NET_DAILY_LIMIT();
  const run = async (): Promise<Response> => { return repoint ? await withLock("vaultpin:" + auth.userId, runUpdate) : await runUpdate(); };
  const res = await run();
  if (res.status !== 200) await netBytes.undo();
  return res;
});

route("GET", "/api/apps/:appId/entities/:entity/:id", async (req, m) => {
  const auth = await authUser(req);
  if (!auth) return j({ message: "Unauthorized" }, 401);
  const refused = entityOpRefusal(m.groups!.entity!, "get");
  if (refused) return refused;
  { const lim = await routeLimited("entget", auth.userId, 600); if (lim) return lim; } // b77u (audit 6 R4 #11): the read by id had no limiter
  if (m.groups!.id!.length > MAX_KEY_PART) return j({ message: "Not found" }, 404);
  const row = await getEntity(m.groups!.entity!, m.groups!.id!) as Record<string, unknown> | null;
  if (!row || !(await canAccessRow(m.groups!.entity!, row, auth, "get"))) return j({ message: "Not found" }, 404);
  // b75r1 (audit REL-07): an expired envelope is gone, not served until the sweep
  if (m.groups!.entity! === "VeilEnvelope" && envelopeExpired(row)) { await deleteEnvelopeRow(["entity", "VeilEnvelope", keySafe(m.groups!.id!)], row); return j({ message: "Not found" }, 404); }
  if (m.groups!.entity! === "VeilSession") return json(await sessionView(row, auth.userId)); // b70 (RLY-10)
  if (m.groups!.entity! === "VeilEnvelope") return json((await envelopeRowsView([row], auth.userId))[0]); // b70 (re-review R3); b74 (audit VAR-01)
  return json(clientRow(row)); // b77t (audit 5 L-29)
});

/**
 * b70 (audit RLY-10): what a client sees of a session row. The other side's
 * account id is replaced by a pseudonym that is stable for this chat (b73: and
 * this relay process) only and can't be turned back into the id (keyed by a
 * memory-only relay secret); the owner tags (unkeyed hashes of the account id)
 * are left out, and (b73, audit V-17) so is the other side's write hash. The
 * caller's own id stays, so "which side am I" checks still work.
 */
/** b73 (audit): V-18 — the pseudonym key lives in this process's memory only (it used to
 *  be stored in KV in clear, so a database copy could undo every pseudonym). A restart
 *  gives every peer a new pseudonym; the app never compares them across answers (it only
 *  checks "is this my own id" and "has someone joined"). */
let peerPseudoKey: Promise<CryptoKey> | null = null;
/**
 * b75r1 (audit REL-05): group burn votes. ["burn_votes", envelope id] used to hold the
 * account hashes of the members who opened the message — read receipts at rest, for
 * anyone with the database. It now holds {k, m}: m = HMAC(memory-only key, "veil-burn-vote:"
 * ‖ envelope id ‖ ":" ‖ account hash), truncated — one opaque marker per (message, member),
 * so a second open by the same member still counts once, and the database alone can't say
 * who voted. k names the key (a random id made at boot, not the key). The key never leaves
 * memory, so after a restart earlier markers can't be matched; rather than risk counting a
 * member twice (which would cut the relay copy short for a member still offline), a vote
 * row from an earlier key is ignored and the count starts again (the copy then keeps its
 * normal expiry unless the votes reach the quorum again). What stays at rest: how many
 * members opened each message, until the envelope expires.
 */
let burnVoteKey: Promise<CryptoKey> | null = null;
const BURN_VOTE_KEY_ID = [...crypto.getRandomValues(new Uint8Array(8))].map((b) => b.toString(16).padStart(2, "0")).join("");
type BurnVoteRow = { k?: string; m?: string[] } | string[];
async function burnVoteMarker(envelopeId: string, acct: string): Promise<string> {
  if (!burnVoteKey) burnVoteKey = crypto.subtle.generateKey({ name: "HMAC", hash: "SHA-256", length: 256 }, false, ["sign"]) as Promise<CryptoKey>;
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", await burnVoteKey, enc.encode("veil-burn-vote:" + envelopeId + ":" + acct)));
  return "bv_" + [...mac.slice(0, 16)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
/** the markers of a vote row made under the current key (an older row, or a pre-b75r1 list of account hashes, counts nothing) */
function burnVotesOf(row: BurnVoteRow | null | undefined): string[] {
  return row && !Array.isArray(row) && row.k === BURN_VOTE_KEY_ID && Array.isArray(row.m) ? row.m.map(String) : [];
}
/**
 * b76r2 (audit GB-1 / R2-B1, GB-2, R2-B2): who may vote on a group envelope's burn is fixed when it is SUBMITTED.
 * ["burn_elig", envelope id] = {k, m, x}: m = the burnVoteMarker of every account the creator had admitted to the
 * group at that moment except the sender's (they are the ones who can open it), x = admitted member rows with no
 * account tag (they can never vote, so the envelope then keeps its normal expiry — fail closed). Same key and same
 * markers as the vote row, so the database alone still can't say who could read or who opened which message.
 * The quorum used to be worked out at vote time as "admitted roster − 1": a member that voted and then left or was
 * removed still counted while the roster shrank (GB-1), the sender's own seat was subtracted even after it had left
 * (GB-2), and a member admitted while the envelope waited — who starts on a later epoch and can never open it —
 * raised the count for good (R2-B2). Now a vote counts only from an account in the snapshot that is still admitted,
 * the quorum is the snapshot's accounts that are still admitted, and a departing account's markers are taken out of
 * both rows (dropBurnEligibility: evict, decline, leave). No snapshot (an envelope from before this build, a seat
 * intro, a row from an earlier key after a restart): never shortened — it keeps its normal expiry.
 */
type BurnEligRow = { k?: string; m?: string[]; x?: number };
function burnEligOf(row: BurnEligRow | null | undefined): { m: string[]; x: number } | null {
  return row && row.k === BURN_VOTE_KEY_ID && Array.isArray(row.m) ? { m: row.m.map(String), x: Number(row.x) || 0 } : null;
}
/** b76r2 (audit GB-1, R2-B1): an account leaves a group (evict, decline, its seat ends): unless it still holds an
 *  admitted membership there, its markers leave every burn snapshot and vote row of the group's envelopes */
async function dropBurnEligibility(groupToken: string, acct: string): Promise<void> {
  if (!groupToken || !acct) return;
  for await (const e of groupMemberRows(groupToken)) { // b77n (pre-audit L3): by ["ix_gmem"]
    const m = e.value;
    if (m && String(m.group_token || "") === groupToken && String(m._acct || "") === acct && memberAdmitted(m)) return;
  }
  for await (const e of envelopesOfGroup(groupToken)) {
    const eid = String(e.key[2]);
    const mine = await burnVoteMarker(eid, acct);
    for (const key of [["burn_elig", keySafe(eid)], ["burn_votes", keySafe(eid)]] as Deno.KvKey[]) {
      for (let attempt = 0; attempt < 10; attempt++) {
        const cur = await KV.get<BurnEligRow>(key);
        const v = cur.value;
        if (!v || Array.isArray(v) || v.k !== BURN_VOTE_KEY_ID || !Array.isArray(v.m) || !v.m.includes(mine)) break;
        const exp = Date.parse(String(e.value.expires_at ?? ""));
        if ((await KV.atomic().check(cur).set(key, { ...v, m: v.m.filter((x) => x !== mine) }, { expireIn: Math.max(60_000, (Number.isFinite(exp) ? exp : Date.now() + 86400_000) - Date.now()) }).commit()).ok) break;
      }
    }
  }
}
async function peerPseudonym(sessionKey: string, id: string): Promise<string> {
  if (!peerPseudoKey) peerPseudoKey = crypto.subtle.generateKey({ name: "HMAC", hash: "SHA-256", length: 256 }, false, ["sign"]) as Promise<CryptoKey>;
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", await peerPseudoKey, enc.encode("veil-peer:" + sessionKey + ":" + id)));
  return "peer_" + [...mac.slice(0, 12)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
async function sessionView(row: Record<string, unknown>, userId: string): Promise<Record<string, unknown>> {
  const out: Record<string, unknown> = { ...row };
  // (the responder's write hash stays for the responder: it checks its own against it to
  // confirm which prekeys a contact request used — b70 re-review P2 — and that a join
  // took its fresh credential)
  delete out._owner; delete out._acct; delete out._init_tag; // b77
  // b73 (audit): V-17 — only the caller's OWN side's write hash. The initiator (and only
  // the initiator: not the joined responder, nor the addressee of a request) sees the
  // initiator hash; everyone else who can see the row sees only the responder hash. The
  // peer's hash used to come back too (more than any caller needs).
  let callerIsInitiator = String(row.initiator_client_id || "") === userId && String(row.responder_client_id || "") !== userId;
  // b77 (sealed sender): a 1:1 row names no account; while pending, the initiator is the
  // account its initiator_veil_id is bound to (the addressee — responder_veil_id — never is)
  if (!row.group_token && !row.initiator_client_id && row.initiator_veil_id && userId) {
    const acct = await accountHashOf(userId);
    const boundTo = async (v: unknown) => { if (!v) return false; const id = (await KV.get<Record<string, unknown>>(["veil_identity", keySafe(v)])).value; return !!id && id.bound === true && String(id.account_hash || "") === acct; };
    callerIsInitiator = await boundTo(row.initiator_veil_id) && !(await boundTo(row.responder_veil_id));
  }
  if (callerIsInitiator) delete out.responder_write_hash; else delete out.initiator_write_hash;
  const key = String(row.token || row.id || "");
  for (const f of ["initiator_client_id", "responder_client_id"] as const) {
    const v = String(row[f] || "");
    if (v && v !== userId) out[f] = await peerPseudonym(key, v);
  }
  return out;
}

// b198 OWNERSHIP GUARD: sessions may only be modified/deleted by their
// participants (client_id IS the account id — b65 participation proof; or a
// veil_id bound to the caller's account). Without this, one device's supersede
// could destroy the OTHER device's brand-new thread (live battery catch).
async function sessionParticipant(session: Record<string, unknown> | null, auth: { userId: string }): Promise<boolean> {
  if (!session) return false;
  // b199: the account that created the row (one-tap/invite creator, even
  // before any client_id field is filled in)
  if (session._owner && String(session._owner) === await ownerTag(auth.userId, String(session.id || ""))) return true;
  if (String(session.initiator_client_id || "") === auth.userId) return true;
  if (String(session.responder_client_id || "") === auth.userId) return true;
  const acct = await accountHashOf(auth.userId);
  for (const vid of [String(session.initiator_veil_id || ""), String(session.responder_veil_id || "")]) {
    if (!vid) continue;
    const id = (await KV.get<Record<string, unknown>>(["veil_identity", keySafe(vid)])).value;
    if (id && id.bound === true && String(id.account_hash || "") === acct) return true; // b70 (RLY-14): bound identities only
  }
  return false;
}

const WIPE_DELETE_ENTITIES = new Set(["VeilVault", "VeilNote", "VeilSession"]);
const WIPE_DELETES_PER_MIN = 12_000;
route("DELETE", "/api/apps/:appId/entities/:entity/:id", async (req, m) => {
  const auth = await authUser(req);
  if (!auth) return j({ message: "Unauthorized" }, 401);
  const refused = entityOpRefusal(m.groups!.entity!, "delete");
  if (refused) return refused;
  // b77u2 (Info): a wipe's per-row deletes (?wipe=1: the duress wipe when its purge failed) of the caller's own vault,
  // note and session rows have a bucket of their own, large enough for the whole list (the wipe's deadline bounds it):
  // at 120 a minute (and a 2-minute lock after) a wipe left most of a long vault or note list behind
  const wipeDel = new URL(req.url).searchParams.get("wipe") === "1" && WIPE_DELETE_ENTITIES.has(m.groups!.entity!);
  { const lim = wipeDel ? await routeLimited("entdelwipe", auth.userId, WIPE_DELETES_PER_MIN) : await routeLimited("entdel", auth.userId, 120); if (lim) return lim; } // b77u (audit 6 R4 #8/#11)
  if (m.groups!.id!.length > MAX_KEY_PART) return j({ message: "Not found" }, 404);
  const existing = (await KV.get<Record<string, unknown>>(["entity", m.groups!.entity!, m.groups!.id!])).value;
  if (!existing) return j({ message: "Not found" }, 404);
  if (!(await canAccessRow(m.groups!.entity!, existing, auth, "delete"))) {
    // b77p (audit VAR-31): someone else's row answers exactly like a missing one, sessions included. The
    // session 403 ("Not your session") against 404 for a missing id told any account which row ids exist.
    // (No app reads the 403: entityDelete callers catch every refusal alike.)
    return j({ message: "Not found" }, 404);
  }
  const row = await deleteEntity(m.groups!.entity!, m.groups!.id!);
  return row ? json({ ok: true }) : j({ message: "Not found" }, 404);
});

// functions (auth required)
route("POST", "/api/apps/:appId/functions/submitEnvelope", async (req) => {
  const auth = await authUser(req);
  if (!auth) return j({ message: "Unauthorized" }, 401);
  const body = await readJson(req);
  if (await kvStorageFull()) return KV_STORAGE_FULL(); // b77n (pre-audit M1): no envelopes kept while the disk is nearly full
  return fnSubmitEnvelope(auth, body, await clientTag(req), await clientWideTags(req)); // b70 (re-review 3): per-network quota; b74 (VAR-14): and /56, /48
});

route("POST", "/api/apps/:appId/functions/veilSessionGate", async (req) => {
  const body = await readJson(req);
  // b77 (sealed sender): the 1:1 handshake actions take NO login — the write secret is the
  // capability. "status" always; "join" / "peek" / "end" (end with a write secret) whenever
  // the token is not a group seat's (a missing token included). The Authorization header is
  // never read on this path (no authUser call, no token row touched, no log line).
  {
    const act = String(body?.action ?? "");
    // b77p (audit 2 VAR-01): and "issue" (one blind open signature per side), always without a login
    if (act === "status" || act === "issue" || ((act === "join" || act === "peek" || (act === "end" && !!body?.write_secret)))) {
      const tok = typeof body?.token === "string" ? body.token : "";
      const sess = tok && tok.length <= MAX_KEY_PART ? await findSessionByToken(tok) : null;
      if (act === "status" || act === "issue" || !sess || !sess.group_token) return fnSessionGateAnon(req, body, sess);
    }
  }
  const auth = await authUser(req);
  if (!auth) return j({ message: "Unauthorized" }, 401);
  // b70 (re-review 5): the gate is rate-limited, list and purge (full-table scans) far tighter
  const act = String(body?.action ?? "");
  const grl = await rateLimit("sgate:" + auth.userId, 1200, 60_000, 2)
    || (act === "list" ? await rateLimit("sgate-list:" + auth.userId, 30, 60_000, 2) : null)
    || (act === "purge" ? await rateLimit("sgate-purge:" + auth.userId, 5, 10 * 60_000, 10) : null);
  if (grl) return j({ locked: true, retry_minutes: grl.retry_minutes }, 429);
  return fnVeilSessionGateAligned(auth, body);
});

route("POST", "/api/apps/:appId/functions/veilIdentityGate", async (req) => {
  const auth = await authUser(req);
  if (!auth) return j({ message: "Unauthorized" }, 401);
  const body = await readJson(req);
  return fnVeilIdentityGate(auth, body, req);
});

route("POST", "/api/apps/:appId/functions/veilGroupGate", async (req) => {
  const auth = await authUser(req);
  if (!auth) return j({ message: "Unauthorized" }, 401);
  const body = await readJson(req);
  { const grl = await rateLimit("ggate:" + auth.userId, 1200, 60_000, 2); if (grl) return j({ locked: true, retry_minutes: grl.retry_minutes }, 429); } // b70 (re-review 5)
  return fnVeilGroupGate(auth, body);
});

// Batch H (round-6 review R6-3-09): a phone removes ITS OWN earlier push rows (by
// the device id it registered them with) when it registers a new token and at every
// wipe. Stale rows used to stay live (an old ntfy.sh topic, an old Expo token).
route("POST", "/api/apps/:appId/functions/veilPushReset", async (req) => {
  const auth = await authUser(req);
  if (!auth) return j({ message: "Unauthorized" }, 401);
  { const lim = await routeLimited("pushreset", auth.userId, 20); if (lim) return lim; } // b70 (re-review 7)
  const body = await readJson(req);
  const dev = typeof body?.device_id === "string" ? body.device_id : "";
  if (!/^[A-Za-z0-9_-]{4,64}$/.test(dev)) return j({ error: "Invalid device id", message: "Invalid device id" }, 400);
  const acctHash = await accountHashOf(auth.userId);
  let deleted = 0;
  for await (const e of acctRows("VeilPushToken", acctHash)) { // b77n (pre-audit L3)
    const r = e.value as Record<string, unknown>;
    if (String(r._acct || "") === acctHash && String(r.device_id || "") === dev) { await deletePushRow(e.key); deleted++; }
  }
  return json({ ok: true, deleted });
});

route("POST", "/api/apps/:appId/functions/deviceLink", async (req) => {
  const auth = await authUser(req);
  if (!auth) return j({ message: "Unauthorized" }, 401);
  { const lim = await routeLimited("devlink", auth.userId, 60); if (lim) return lim; } // b70 (re-review 7); b75: 60 — both phones poll on one account
  const body = await readJson(req);
  return fnDeviceLink(auth, body);
});

// b198 (audit P0-2, live-confirmed): provisioning IS the account-creation call —
// the caller definitionally has no credentials yet, so requiring auth here 401'd
// every fresh duress account. The route is pre-auth, guarded by the same per-IP
// register cap as /auth/register.
route("POST", "/api/apps/:appId/functions/veilSilentAccount", async (req) => {
  const body = await readJson(req);
  // b199: 'rebind' moves the SIGNED-IN account onto new phrase-derived
  // credentials — token required; never reachable pre-auth
  if (String(body.action || "") === "rebind") {
    const auth = await authUser(req);
    if (!auth) return j({ message: "Unauthorized" }, 401);
    return fnSilentAccountRebind(auth, body, req);
  }
  // b77s (audit 4 RA-01): what can't make an account is refused FIRST (no budget spent): an unknown action, a label
  // that is not phrase-derived (the same fixed reply fnVeilSilentAccount gives), a malformed password
  if (String(body.action || "") !== "provision") return j({ error: "Unknown action", message: "Unknown action" }, 400);
  if (!PHRASE_LABEL_RE.test(String(body.email || "").toLowerCase().trim())) return j({ message: "Could not create an account with these details", code: "provision_refused" }, 400);
  { const bad = newAccountInputError(String(body.email || ""), String(body.password || "")); if (bad) return j({ message: bad }, 400); }
  // b77s (audit 4 RA-01): phrase labels only, so the phrase budget (never the email sign-ups' one)
  const su = await signupRefusal(req, body, "phrase"); // b74 (audit VAR-14); b77m (owner): a puzzle past the network's cap
  if (su instanceof Response) return su;
  const pvEmail = String(body.email || "").toLowerCase().trim(), pvPw = String(body.password || "");
  let skipNet = su.powPassed;
  if (!skipNet && !phraseCheapEligible(pvEmail, pvPw) && await pbkdfNetFull(req)) {
    const g = await netPowGate(req, "pbkdf", PBKDF2_PER_NETWORK, 60_000, body, "Busy — try again");
    if (g) return g;
    skipNet = true;
  }
  return fnVeilSilentAccount({ userId: "preauth-provision" }, body, req, skipNet);
});

// b76 (registration lock): status (and check-in) / set / off — spec §12.17
route("POST", "/api/apps/:appId/functions/veilRegLock", async (req) => {
  const auth = await authUser(req);
  if (!auth) return j({ message: "Unauthorized" }, 401);
  { const lim = await routeLimited("reglock", auth.userId, 20); if (lim) return lim; }
  const body = await readJson(req);
  return withLock("reglock:" + auth.userId, () => fnVeilRegLock(auth, body, req));
});

route("POST", "/api/apps/:appId/functions/veilAccountDelete", async (req) => {
  // b77i (I-1): the one route that gets in while its account is being deleted (the account's own
  // valid token only; authCheck), so a retry after an interrupted cascade finishes it. An account
  // already gone answers 410 "account deleted" (never the generic 401 an expired login gets).
  const auth = await authCheck(req, true);
  if (auth && "gone" in auth) {
    { const lim = await rateLimit("acctgone:" + auth.gone, 10, 60_000, 2); if (lim) return j({ locked: true, retry_minutes: lim.retry_minutes }, 429); }
    // (the user row went but the run stopped before its last step: finish it)
    const uid = auth.userId;
    if (uid) await withLock("acctdel:" + uid, () => retireAccountTokens(uid));
    return accountGone();
  }
  if (!auth) return j({ message: "Unauthorized" }, 401);
  { const lim = await routeLimited("acctdel", auth.userId, 10); if (lim) return lim; } // b70 (re-review 7)
  const body = await readJson(req);
  return withLock("acctdel:" + auth.userId, () => fnVeilAccountDelete(auth, body)); // b77i: one run at a time
});

route("POST", "/api/apps/:appId/functions/vaultFileSignedUrl", async (req, m) => {
  const auth = await authUser(req);
  if (!auth) return j({ message: "Unauthorized" }, 401);
  { const lim = await routeLimited("signedurl", auth.userId, 120); if (lim) return lim; } // b70 (re-review 7)
  const body = await readJson(req);
  const fileUri = canonBlobUri(String(body.file_uri || "")); // b77u (audit 6 U-M9 / F-05): canonical case
  // b71 (audit): the same canonical blob-id rule the /files/:id download uses —
  // a non-canonical id ("blob:../x", "blob:a/b") is never signed
  if (!fileUri.startsWith("blob:") || fileUri.length > MAX_KEY_PART + 5 || !blobPathOf(fileUri)) return j({ error: "Unknown file", message: "Unknown file" }, 404);
  // vault-unlock path passes NO session context; media path passes both — verify when present
  if (body.session_token) {
    // b77r1 (audit R-9): a group seat's credential only (sessionCredOk)
    const ok = await sessionCredOk(body.session_token, body.write_secret);
    if (!ok) return j({ error: "Invalid session credential", message: "Invalid session credential" }, 403);
  }
  // Batch F (round-4 reviews R4-3-04 / R4-4-22): a vault container or a pending
  // transfer bundle is readable only by its uploader.
  // b77u (audit 6 U-M9, R4 #1): and so is every other file, unless the caller presents a valid binding credential
  // (blobBindingAllows: a group file and a seat credential of that group). The id alone used to be the capability
  // for any unbound file (group media was uploaded unbound), for any signed-in account.
  {
    const id = blobIdOf(fileUri);
    // b77 (sealed sender): a 1:1 file is reached only through its mailbox (sealedFile)
    if ((await KV.get(["blob_mbox", id])).value) return j({ error: "Not your file", message: "Not your file" }, 403);
    const rec = (await KV.get<string>(["blob_owner", id])).value;
    const isUploader = !!rec && rec === await blobOwnerTag(await accountHashOf(auth.userId), id);
    if (!isUploader && await blobIsProtected(fileUri)) return j({ error: "Not your file", message: "Not your file" }, 403);
    if (!isUploader && !(await blobBindingAllows(id, body))) return j({ error: "Not your file", message: "Not your file" }, 403);
  }
  // b75 (audit RL-12): the link's origin is the relay's CONFIGURED public origin
  // (PUBLIC_ORIGIN), never the request's Host / X-Forwarded-Proto headers — those are the
  // client's to write, so a request could have the relay sign a link pointing anywhere.
  // (The b198 fix this replaces kept the two proto spellings consistent; the origin is now
  // one fixed string.)
  const url = await signBlobUrl(blobIdOf(fileUri), 10 * 60_000, PUBLIC_ORIGIN);
  return json({ signed_url: url });
});

/** b71 (audit F-10): uploads read into memory at once, relay-wide. Each can hold up to
 *  26 MB twice (raw body + parsed form) while it is processed; more wait their turn
 *  (up to UPLOAD_SLOT_WAIT_MS, then 503) instead of all buffering together. */
const UPLOAD_MAX_CONCURRENT = Number(Deno.env.get("VEIL_UPLOAD_CONCURRENCY")) || 4;
const UPLOAD_SLOT_WAIT_MS = 15_000;
let uploadsActive = 0;
/** b77t (audit 5 M-D): slots held by sealed (no-account) uploads. They may hold at most UPLOAD_SEALED_MAX_CONCURRENT, so
 *  UPLOAD_RESERVED_SIGNED_IN slots always stay for signed-in uploads (UploadPrivateFile: vaults, transfer bundles, group
 *  media) — anonymous callers can't starve them. */
let sealedUploadsActive = 0;
const UPLOAD_RESERVED_SIGNED_IN = 1;
const UPLOAD_SEALED_MAX_CONCURRENT = Math.max(1, UPLOAD_MAX_CONCURRENT - UPLOAD_RESERVED_SIGNED_IN);
type UploadKind = "signed-in" | "sealed";
/** b77t2 (CM-1): `spare` — this body may take only a slot that leaves UPLOAD_RESERVED_SIGNED_IN free (an account's
 *  SECOND signed-in body in flight: one account used to fill the reserved slot as well as its first one) */
const uploadWaiters: { kind: UploadKind; spare: boolean; wake: () => void }[] = [];
const uploadSlotFree = (kind: UploadKind, spare = false) => uploadsActive < UPLOAD_MAX_CONCURRENT
  && (!spare || uploadsActive < UPLOAD_MAX_CONCURRENT - UPLOAD_RESERVED_SIGNED_IN)
  && (kind !== "sealed" || sealedUploadsActive < UPLOAD_SEALED_MAX_CONCURRENT);
const takeUploadSlot = (kind: UploadKind) => { uploadsActive++; if (kind === "sealed") sealedUploadsActive++; };
async function acquireUploadSlot(kind: UploadKind = "signed-in", spare = false): Promise<boolean> {
  if (uploadSlotFree(kind, spare)) { takeUploadSlot(kind); return true; }
  return await new Promise<boolean>((res) => {
    const w = { kind, spare, wake: () => { clearTimeout(t); takeUploadSlot(kind); res(true); } };
    const t = setTimeout(() => { const i = uploadWaiters.indexOf(w); if (i >= 0) uploadWaiters.splice(i, 1); res(false); }, UPLOAD_SLOT_WAIT_MS);
    uploadWaiters.push(w);
  });
}
function releaseUploadSlot(kind: UploadKind = "signed-in") {
  uploadsActive = Math.max(0, uploadsActive - 1);
  if (kind === "sealed") sealedUploadsActive = Math.max(0, sealedUploadsActive - 1);
  // the first waiter that may take the freed slot (a sealed waiter can't take the signed-in reserve)
  const i = uploadWaiters.findIndex((w) => uploadSlotFree(w.kind, w.spare));
  if (i >= 0) uploadWaiters.splice(i, 1)[0].wake();
}
/**
 * b77t2 (CM-1, confirmation review of b77t): holding an upload slot must cost BYTES, not time. One free account and
 * three IPv4 addresses still held every slot: 2 addresses x 2 slow named sealed bodies + 1 slow UploadPrivateFile,
 * each trickling ~1 byte / 1.5 s, cut only at the 30 s zero-rate grace and re-opened every 30 s. Now:
 *  - the zero-rate grace is UPLOAD_BODY_LIMITS.graceMs (5 s, was 30 s), then the minimum average rate (8 KB/s)
 *    measured from the start of the body (readCapped);
 *  - at most ONE body per mailbox in flight (takeMboxUploadSlot): a second upload to the same mailbox waits for the
 *    first (up to UPLOAD_SLOT_WAIT_MS, holding no slot), then 429;
 *  - an account's SECOND signed-in body may not take the reserved slot (acquireUploadSlot `spare`);
 *  - a body CUT for being too slow (throughput or stall) is a strike against its network (/64 or IPv4), its mailbox
 *    and its account for UPLOAD_STRIKE_WINDOW_MS (10 min): a network with a strike gets UPLOAD_PENALTY_GRACE_MS (1 s)
 *    of grace instead of 5 s; a mailbox or account with UPLOAD_STRIKES_REFUSE (3) strikes is refused (429
 *    upload_too_slow_recently) until the oldest strike ages out. Networks are never refused outright (a carrier NAT
 *    shares one address), only charged from the first second.
 * Memory only (like the other upload counters); a restart forgets strikes.
 */
const UPLOAD_STRIKE_WINDOW_MS = 10 * 60_000;
const UPLOAD_STRIKES_REFUSE = 3;
const UPLOAD_PENALTY_GRACE_MS = Number(Deno.env.get("VEIL_UPLOAD_PENALTY_GRACE_MS")) || 1_000;
const uploadStrikes = new Map<string, number[]>();
function uploadStrikeCount(key: string, now = Date.now()): number {
  const list = uploadStrikes.get(key);
  if (!list) return 0;
  const live = list.filter((t) => now - t < UPLOAD_STRIKE_WINDOW_MS);
  if (live.length) uploadStrikes.set(key, live); else uploadStrikes.delete(key);
  return live.length;
}
/** a body was cut for its rate: one strike on each key (net:/mb:/acct:); deadline cuts are not strikes */
function noteUploadCut(e: unknown, keys: string[]): void {
  if (!(e instanceof BodyTooSlowError) || e.why === "deadline") return;
  if (uploadStrikes.size > 50_000) uploadStrikes.clear();
  const now = Date.now();
  for (const k of keys) { uploadStrikeCount(k, now); const l = uploadStrikes.get(k) ?? []; l.push(now); uploadStrikes.set(k, l.slice(-10)); }
}
/** the refusal for a mailbox / account with UPLOAD_STRIKES_REFUSE recent strikes, or null */
function uploadStrikeRefusal(key: string): Response | null {
  if (uploadStrikeCount(key) < UPLOAD_STRIKES_REFUSE) return null;
  const msg = "Recent uploads here were too slow — try again in a few minutes on a better connection";
  return j({ error: msg, message: msg, code: "upload_too_slow_recently", retry_minutes: Math.ceil(UPLOAD_STRIKE_WINDOW_MS / 60_000) }, 429, { "Retry-After": String(UPLOAD_STRIKE_WINDOW_MS / 1000) });
}
/** the body limits for a request from `net`: the short penalty grace once the network has a strike */
function uploadLimitsFor(net: string): BodyReadLimits {
  return net !== "local" && uploadStrikeCount("net:" + net) > 0 ? { ...UPLOAD_BODY_LIMITS, graceMs: Math.min(UPLOAD_BODY_LIMITS.graceMs, UPLOAD_PENALTY_GRACE_MS) } : UPLOAD_BODY_LIMITS;
}
/** b77t2 (CM-1): one body per mailbox (its tag) in flight; a second waits up to UPLOAD_SLOT_WAIT_MS. A release
 *  function, or null when the wait ran out (or too many already wait). */
const mboxUploadBusy = new Map<string, (() => void)[]>();
async function takeMboxUploadSlot(mtag: string): Promise<(() => void) | null> {
  const release = () => {
    const q = mboxUploadBusy.get(mtag);
    const next = q?.shift();
    if (next) next(); else mboxUploadBusy.delete(mtag);
  };
  const once = () => { let done = false; return () => { if (!done) { done = true; release(); } }; };
  const q = mboxUploadBusy.get(mtag);
  if (!q) { mboxUploadBusy.set(mtag, []); return once(); }
  if (q.length >= 4) return null;
  return await new Promise((res) => {
    const w = () => { clearTimeout(t); res(once()); };
    const t = setTimeout(() => { const i = q.indexOf(w); if (i >= 0) q.splice(i, 1); res(null); }, UPLOAD_SLOT_WAIT_MS);
    q.push(w);
  });
}
/** b77t (audit 5 M-D): signed-in uploads in flight per account (memory only), so one account can't hold every slot
 *  either; checked before a relay-wide slot is taken */
const UPLOAD_PER_ACCOUNT_CONCURRENT = Number(Deno.env.get("VEIL_UPLOAD_PER_ACCOUNT_CONCURRENCY")) || 2;
const acctUploadsActive = new Map<string, number>();
function takeAccountUploadSlot(userId: string): (() => void) | null {
  const n = acctUploadsActive.get(userId) ?? 0;
  if (n >= UPLOAD_PER_ACCOUNT_CONCURRENT) return null;
  acctUploadsActive.set(userId, n + 1);
  let released = false;
  return () => {
    if (released) return;
    released = true;
    const m = (acctUploadsActive.get(userId) ?? 1) - 1;
    if (m <= 0) acctUploadsActive.delete(userId); else acctUploadsActive.set(userId, m);
  };
}
/** b77r1 (audit R-3): bodies being read from ONE network (its /64 or IPv4 tag) at once, on both
 *  upload routes (UploadPrivateFile and sealedUpload), taken BEFORE a relay-wide slot — so one
 *  network can hold at most this many of the UPLOAD_MAX_CONCURRENT slots (four slow anonymous
 *  bodies from one place used to hold them all). In memory only. "local" (a trusted loopback
 *  test relay, VEIL_TRUST_LOCAL=1) is exempt, as from every per-network limit. */
const UPLOAD_PER_NETWORK_CONCURRENT = Number(Deno.env.get("VEIL_UPLOAD_PER_NET_CONCURRENCY")) || 2;
/** b77r2 (audit R2-R-2): and per wider IPv6 network, the /56 and the /48, a flat cap (not x4 / x16:
 *  there are only UPLOAD_MAX_CONCURRENT slots in all) — the per-/64 cap alone let two /64s of one
 *  /48 hold all four */
const UPLOAD_PER_WIDE_NETWORK_CONCURRENT = Number(Deno.env.get("VEIL_UPLOAD_PER_WIDE_NET_CONCURRENCY")) || 3;
const netUploadsActive = new Map<string, number>();
/** a release function, or null when the network (its /64 or IPv4 tag, or its /56 or /48) already
 *  has its cap of bodies in flight */
async function takeNetUploadSlot(req: Request): Promise<(() => void) | null> {
  const net = await clientTag(req);
  if (net === "local") return () => undefined;
  const keys: [string, number][] = [[net, UPLOAD_PER_NETWORK_CONCURRENT]];
  for (const w of await clientWideTags(req)) keys.push([w.bits + ":" + w.tag, UPLOAD_PER_WIDE_NETWORK_CONCURRENT]);
  if (keys.some(([k, cap]) => (netUploadsActive.get(k) ?? 0) >= cap)) return null;
  for (const [k] of keys) netUploadsActive.set(k, (netUploadsActive.get(k) ?? 0) + 1);
  let released = false;
  return () => {
    if (released) return;
    released = true;
    for (const [k] of keys) {
      const m = (netUploadsActive.get(k) ?? 1) - 1;
      if (m <= 0) netUploadsActive.delete(k); else netUploadsActive.set(k, m);
    }
  };
}
type QuotaResult = "ok" | "over" | "busy";
/** b77r2 (audit R2-R-6): the day's reservation, with the network slot given back if the
 *  reservation fails OR throws (a throw used to leak the slot: it came before the try/finally) */
async function reserveUploadQuota(netSlot: () => void, reserve: () => Promise<QuotaResult>): Promise<QuotaResult> {
  let r: QuotaResult;
  try { r = await reserve(); } catch (e) { netSlot(); throw e; }
  if (r !== "ok") netSlot();
  return r;
}
/** b77r1 (audit R-3): how long an upload body may take. readCapped used to wait for ever, so a
 *  body trickled a byte at a time held its relay-wide slot for as long as the client liked.
 *  Overall: 300 s (25 MB then needs ~87 KB/s, ~0.7 Mbit/s). Stall: no byte for 20 s. Throughput:
 *  after a 30 s grace, at least 16 KB/s on average (128 kbit/s). Caddy's servers.timeouts.read_body
 *  (website/deploy/Caddyfile, 5m30s since b77r2) sits above the 15 s slot wait plus the overall
 *  deadline. Env overrides are for tests.
 *  b77q owner (1 Nov, slow links): the stall limit is 60 s and the minimum average 8 KB/s, as for downloads. The
 *  300 s overall deadline stays: the relay has only UPLOAD_MAX_CONCURRENT (4) upload slots, and an hour-long upload
 *  deadline would let a handful of slow senders hold all of them, so a full 25 MB upload still needs ~87 KB/s
 *  (smaller files go at 8 KB/s; owner to decide whether uploads get the download's hour). Caddy's 5m30s is
 *  unchanged (it depends only on the deadline and the slot wait).
 *  b77t2 (CM-1): the zero-rate grace is 5 s (was 30 s); after it the average since the body's first byte was awaited
 *  must stay >= 8 KB/s (so 40 KB by 5 s, 80 KB by 10 s). Why 8 KB/s still fits real phones: a phone on a poor link
 *  (EDGE ~20-30 KB/s, weak 3G/LTE 50+ KB/s) sends well above it, a small file (a voice note, a compressed photo of
 *  tens of KB) is finished before the grace ends, and the reading starts only once the slot is taken, so bytes the
 *  phone sent while waiting arrive at once. A link under ~8 KB/s (GPRS) could not finish a photo inside the old
 *  rules either (240 KB by 30 s). The minimum is unchanged; only the free start shrank, so holding a slot now costs
 *  ~8 KB/s from the fifth second instead of nothing for 30 s. */
const UPLOAD_BODY_LIMITS: BodyReadLimits = {
  deadlineMs: Number(Deno.env.get("VEIL_UPLOAD_BODY_DEADLINE_MS")) || 300_000,
  stallMs: Number(Deno.env.get("VEIL_UPLOAD_BODY_STALL_MS")) || 60_000,
  graceMs: Number(Deno.env.get("VEIL_UPLOAD_BODY_GRACE_MS")) || 5_000, // b77t2 (CM-1): was 30 s (see UPLOAD_STRIKE_WINDOW_MS)
  minBytesPerSec: Number(Deno.env.get("VEIL_UPLOAD_BODY_MIN_BPS")) || 8 * 1024,
};
/**
 * b77s (audit 4 RS-2): the relay has UPLOAD_MAX_CONCURRENT (4) upload slots, 2 per network, and a body may take the
 * 300 s deadline at 8 KB/s (the owner keeps that deadline): two networks trickling bodies could hold every slot
 * in repeating 300 s windows and block media and vault uploads for everyone. Now:
 *  - a body that has NOT named its target before it is read gets UPLOAD_UNNAMED_BODY_LIMITS: the same stall and
 *    throughput rules, but a short overall deadline (90 s). An upload names its target when the relay knows it
 *    before reading the body: UploadPrivateFile always (the signed-in account), sealedUpload when the request
 *    carries X-Veil-Mbox and X-Veil-Send-Cap headers that open a live mailbox (checked BEFORE a slot is taken; the
 *    form's mbox / send_cap must then match). A sealed upload without them (today's apps put mbox / send_cap after
 *    the file part) is "unnamed";
 *  - each network (/64 or IPv4; /56 and /48 at x4 / x16) may START at most UPLOAD_STARTS_PER_NETWORK_PER_MIN uploads a
 *    minute on the two routes together, so a network can't keep re-taking slots the moment its bodies time out.
 *  - b77s (confirmation review N-4): that cap was 30 a minute per address, a hard refusal — so one person behind a
 *    carrier NAT (or a café, a campus: one IPv4 address for everyone) could block uploads for everyone there (the
 *    RA-05 pattern). It is now 300 a minute per /64 or IPv4 address (x4 / x16 for the /56 and /48): far above what
 *    real phones on one address start, still a ceiling on slot re-taking. The rest of RS-2's protection is
 *    unchanged and does not depend on it: the short deadline for unnamed bodies, 2 of the 4 upload slots per
 *    network, the per-account upload limit (30 a minute), sealedUpload's own per-network limit (120 a minute,
 *    pre-RS-2) and the account, network and relay-wide daily byte quotas.
 * Env overrides are for tests.
 */
// b77t (audit 5 M-D): the unnamed-body deadline (UPLOAD_UNNAMED_BODY_LIMITS, 90 s) is gone with unnamed sealed uploads:
// they are refused before any slot now (sealedUpload); every body that is read has named its target.
const UPLOAD_STARTS_PER_NETWORK_PER_MIN = Number(Deno.env.get("VEIL_UPLOAD_STARTS_PER_NETWORK_PER_MIN")) || 300; // b77s (N-4): was 30
async function uploadStartRefusal(req: Request): Promise<Response | null> {
  const net = await clientTag(req);
  if (net === "local") return null;
  const rl = await rateLimit("upstart:" + net, UPLOAD_STARTS_PER_NETWORK_PER_MIN, 60_000, 0) || await wideRateLimit("upstart", await clientWideTags(req), UPLOAD_STARTS_PER_NETWORK_PER_MIN, 60_000, 0);
  if (!rl) return null;
  const msg = "Too many uploads from this network — try again in a minute";
  return j({ error: msg, message: msg, code: "rate_limited", retry_minutes: rl.retry_minutes }, 429, { "Retry-After": "60" });
}
/** b77r1 (audit R-2): a mailbox or account under this many upload bytes today is "light" */
const UPLOAD_LIGHT_ACCOUNT_BYTES = 50 * 1024 * 1024;
/** b77r1 (audit R-2): a network (/64 or IPv4; the /56 and /48 at ×4 / ×16) under this many upload
 *  bytes today is "light" — the sealed upload path judges the network as well as the mailbox,
 *  because mailboxes are cheap to mint */
const UPLOAD_LIGHT_NETWORK_BYTES = Number(Deno.env.get("VEIL_UPLOAD_LIGHT_NETWORK_BYTES")) || 200 * 1024 * 1024;
/** b70 (re-review 3) / b77r1 (audit R-1, R-2): the "light sender" rule of a quota step. Once the
 *  relay-wide counter `allKey` would pass `frac` of `allCap`, the step is refused when ANY of the
 *  `heavy` counters already holds more than its `limit` today (`own` = bytes this same request
 *  already put in that counter, e.g. its earlier reservation, which don't count against it).
 *  The relay-wide key and the threshold are explicit: the rule used to be hard-wired to
 *  "upload_quota_all", so the sealed envelope path (env_quota_all) never had it (R-1), and the
 *  sealed upload path passed the relay-wide key as "the caller's" counter (R-2). */
type LightRule = { allKey: Deno.KvKey; allCap: number; frac: number; heavy: { key: Deno.KvKey; limit: number; own?: number }[] };
/** the share of a relay-wide daily total past which only light senders get through */
const LIGHT_RULE_FRACTION = 0.6;
/** b71 (audit F-10): add each item's `delta` to its counter, all in ONE atomic step. A positive
 *  delta is a RESERVATION: refused ("over") if its counter would pass its cap, or by the light
 *  rule; a negative delta gives bytes back (never below zero). */
async function adjustQuotaItems(items: { key: Deno.KvKey; cap: number; delta: number }[], light?: LightRule): Promise<"ok" | "over" | "busy"> {
  const keyStr = (k: Deno.KvKey) => JSON.stringify(k);
  for (let attempt = 0; attempt < 10; attempt++) {
    const tx = KV.atomic();
    const usedOf = new Map<string, number>();
    let adding = false, allAfter = -1;
    for (const { key, cap, delta } of items) {
      const cur = await KV.get<Deno.KvU64>(key);
      const used = Number(cur.value?.value ?? 0n);
      usedOf.set(keyStr(key), used);
      if (delta > 0) adding = true;
      if (delta > 0 && used + delta > cap) return "over";
      if (light && keyStr(key) === keyStr(light.allKey)) allAfter = used + delta;
      tx.check(cur).set(key, new Deno.KvU64(BigInt(Math.max(0, used + delta))), { expireIn: 2 * 86400_000 });
    }
    if (light && adding) {
      if (allAfter < 0) allAfter = Number((await KV.get<Deno.KvU64>(light.allKey)).value?.value ?? 0n);
      if (allAfter > light.allCap * light.frac) {
        for (const h of light.heavy) {
          const used = usedOf.get(keyStr(h.key)) ?? Number((await KV.get<Deno.KvU64>(h.key)).value?.value ?? 0n);
          if (used - (h.own ?? 0) > h.limit) return "over";
        }
      }
    }
    if ((await tx.commit()).ok) return "ok";
  }
  return "busy";
}
/** the same `delta` on every counter of `caps` (see adjustQuotaItems) */
function adjustQuota(caps: [Deno.KvKey, number][], delta: number, light?: LightRule): Promise<"ok" | "over" | "busy"> {
  return adjustQuotaItems(caps.map(([key, cap]) => ({ key, cap, delta })), light);
}
/** b77r1 (audit R-1, R-2): the network counters of `caps` (the /64 and the wider /56, /48) as
 *  light-rule "heavy" entries, each at `limit` × its share (WIDE_FACTOR) */
function networkHeavy(caps: [Deno.KvKey, number][], netPrefix: string, limit: number, own = 0): LightRule["heavy"] {
  const out: LightRule["heavy"] = [];
  for (const [key] of caps) {
    const p = String(key[0]);
    if (p === netPrefix) out.push({ key, limit, own });
    else if (p === netPrefix + "56") out.push({ key, limit: limit * WIDE_FACTOR[56], own });
    else if (p === netPrefix + "48") out.push({ key, limit: limit * WIDE_FACTOR[48], own });
  }
  return out;
}

// private blob upload — the web SDK's Core.UploadPrivateFile contract (multipart)
route("POST", "/api/apps/:appId/integration-endpoints/Core/UploadPrivateFile", async (req) => {
  const auth = await authUser(req);
  if (!auth) return j({ message: "Unauthorized" }, 401);
  // size gate BEFORE spooling the multipart body into memory/temp files
  // b198 MEDIA CAP ALIGNED (owner decision): 25 MB files, 26 MB gate to allow
  // multipart overhead. The client cap (MEDIA_LIMIT_BYTES) matches exactly.
  const UPLOAD_BODY_CAP = 26 * 1024 * 1024;
  const declared = Number(req.headers.get("content-length") || "0");
  if (declared > UPLOAD_BODY_CAP) return TOO_LARGE("File too large");
  // b70 (re-review 8): limited per account, and an account past its daily quota is
  // refused BEFORE the body is read
  { const lim = await routeLimited("upload", auth.userId, 30); if (lim) return lim; }
  { const lim = uploadStrikeRefusal("acct:" + auth.userId); if (lim) return lim; } // b77t2 (CM-1): 3 rate cuts in 10 min
  { const lim = await uploadStartRefusal(req); if (lim) return lim; } // b77s (audit 4 RS-2)
  // b71 (audit F-10): the day's quota is RESERVED before the body is read (the declared
  // size, or the whole cap for a chunked body) in one atomic step over the account,
  // network and relay-wide counters, then trimmed to the file's real size. The old
  // pre-check reserved nothing, so many parallel uploads all passed it.
  const day = new Date().toISOString().slice(0, 10);
  const qKey: Deno.KvKey = ["upload_quota", await accountHashOf(auth.userId), day];
  // b70 (audit RLY-15): accounts are cheap, so the same day's uploads are also
  // capped per network and for the whole relay (all three in one atomic step)
  const net = await clientTag(req);
  const reserved = declared > 0 ? declared : UPLOAD_BODY_CAP;
  // b77m (audit VAR-03): room on the disk first; the day's relay-wide cap follows the room left
  const allKey: Deno.KvKey = ["upload_quota_all", day];
  const store = await storageGate(reserved, allKey);
  if (!store) return j({ message: STORAGE_FULL_MSG, code: "storage_full" }, 507, { "Retry-After": "600" });
  const caps: [Deno.KvKey, number][] = [[qKey, UPLOAD_DAILY_CAP], [allKey, store.allCap]];
  if (net !== "local") caps.push([["upload_quota_net", net, day], UPLOAD_NETWORK_DAILY_CAP]);
  for (const w of await clientWideTags(req)) caps.push([["upload_quota_net" + w.bits, w.tag, day], UPLOAD_NETWORK_DAILY_CAP * WIDE_FACTOR[w.bits]]); // b74 (audit VAR-14)
  // b70 (re-review 3): past 60% of the relay-wide total only light uploaders (under 50 MB today) get through
  // b77m (audit VAR-03): judged by the account AND its network (/64 or IPv4; /56, /48 at x4, x16) —
  // accounts are free, so the account alone let one network stay "light" with fresh accounts
  const light: LightRule = { allKey, allCap: store.allCap, frac: LIGHT_RULE_FRACTION, heavy: [{ key: qKey, limit: UPLOAD_LIGHT_ACCOUNT_BYTES }, ...networkHeavy(caps, "upload_quota_net", UPLOAD_LIGHT_NETWORK_BYTES)] };
  // b77r1 (audit R-3): at most UPLOAD_PER_NETWORK_CONCURRENT bodies from one network at once,
  // checked BEFORE a relay-wide slot is taken
  // b77t (audit 5 M-D): and at most UPLOAD_PER_ACCOUNT_CONCURRENT bodies per account
  // b77t2 (CM-1): an account's second body in flight may not take the reserved slot (acquireUploadSlot `spare`)
  const acctSpare = (acctUploadsActive.get(auth.userId) ?? 0) > 0;
  const acctSlot = takeAccountUploadSlot(auth.userId);
  if (!acctSlot) { store.release(); return j({ message: "Too many uploads at once from this account — try again in a moment" }, 429, { "Retry-After": "10" }); }
  let netSlot0: (() => void) | null = null;
  const netSlot = () => { netSlot0?.(); acctSlot(); }; // (both given back together)
  netSlot0 = await takeNetUploadSlot(req);
  if (!netSlot0) { acctSlot(); store.release(); return j({ message: "Too many uploads at once from this network — try again in a moment" }, 429, { "Retry-After": "10" }); }
  const r0 = await reserveUploadQuota(netSlot, () => adjustQuota(caps, reserved, light)).catch((e) => { store.release(); throw e; });
  if (r0 === "over") { store.release(); return j({ message: "Daily upload limit reached — try again tomorrow" }, 429); }
  if (r0 === "busy") { store.release(); return j({ message: "Upload busy — try again" }, 429); }
  let charged = reserved; // what the counters hold for this upload right now
  // b71 (audit F-10): and at most UPLOAD_MAX_CONCURRENT bodies in memory at once
  // (b77t audit 5 M-D: signed-in uploads may also use the slots kept back from sealed ones)
  if (!(await acquireUploadSlot("signed-in", acctSpare))) {
    netSlot();
    store.release();
    await adjustQuota(caps, -charged);
    return j({ message: "The relay is busy with other uploads — try again in a moment" }, 503, { "Retry-After": "10" });
  }
  try {
    // Batch D (D-16, RV-15): a chunked body has no content-length, and
    // req.formData() buffered it without any cap. Read it through a byte counter
    // (as readJson does), refuse past the cap BEFORE parsing, then parse only
    // the bounded bytes as multipart. b77r1 (audit R-3): within UPLOAD_BODY_LIMITS.
    let bodyBytes: Uint8Array;
    try {
      const got = await readCapped(req, UPLOAD_BODY_CAP, uploadLimitsFor(net)); // b77t2 (CM-1): a struck network gets the short grace
      if (!got) return TOO_LARGE("File too large");
      bodyBytes = got;
    } catch (e) {
      noteUploadCut(e, ["net:" + net, "acct:" + auth.userId]); // b77t2 (CM-1)
      if (e instanceof BodyTooSlowError) return j({ message: "Upload too slow — try again on a better connection" }, 408);
      return j({ message: "Upload failed" }, 400);
    }
    // b70 (re-review 10): a body that isn't multipart is the caller's error (a 400), not ours
    let form: FormData;
    try { form = await new Response(bodyBytes as BodyInit, { headers: { "content-type": req.headers.get("content-type") || "" } }).formData(); }
    catch { return j({ message: "Upload failed — not a file upload" }, 400); }
    let file: File | null = null;
    for (const [, v] of form.entries()) { if (v instanceof File) { file = v; break; } }
    if (!file) return j({ message: "No file part" }, 400);
    // b70 (audit VAR-06): a chat upload names its chat (and proves it is a party)
    // b70 (re-review R4): no write secret = no binding (a plain upload), not a refusal
    const bindWs = form.get("write_secret");
    const bindToken = bindWs ? form.get("session_token") : null;
    // b77r1 (audit R-9): a group seat's credential only (sessionCredOk) — a 1:1 file goes through sealedUpload
    if (bindToken !== null && !(await sessionCredOk(bindToken, bindWs))) return j({ message: "Invalid session credential" }, 403);
    // disk-fill guard: encrypted media/vault files cap at 25 MB (aligned with
    // the client's MEDIA_LIMIT_BYTES — b198 media cap decision)
    if (file.size > 25 * 1024 * 1024) return j({ message: "File too large" }, 413);
    // b199 (audit: "no per-account upload quota → disk fill"): 1 GB of
    // encrypted files per account per day — about 40 vaults or full-size
    // media files; real use is a small fraction. Counted per UTC day.
    // b71 (audit F-10): the reservation is trimmed to the file's real size
    if (file.size !== charged) {
      const r1 = await adjustQuota(caps, file.size - charged, light);
      if (r1 === "over") return j({ message: "Daily upload limit reached — try again tomorrow" }, 429);
      if (r1 === "busy") return j({ message: "Upload busy — try again" }, 429);
      charged = file.size;
    }
    const id = rid();
    await Deno.mkdir(BLOB_DIR, { recursive: true });
    await Deno.writeFile(BLOB_DIR + id, new Uint8Array(await file.arrayBuffer()));
    noteBlobWritten(file.size); // b77m (audit VAR-03)
    // Batch E (RV-39): the owner is recorded before the id is handed out (and
    // after the file exists, so the sweeper never drops the record as orphaned)
    // b77s (audit 4 RA-02): the owner record (and chat binding) commit only while the account is live — an upload
    // still in flight when its account was deleted is refused and its file removed
    {
      const sets: [Deno.KvKey, unknown][] = [[["blob_owner", id], await blobOwnerTag(await accountHashOf(auth.userId), id)]];
      // b77u (audit 6 U-M9): a seat credential binds the file to its GROUP (every member may then sign it), not to the one seat
      // (and, as since b70, to its seat: a chat-scoped delete needs a credential of THAT seat — a member reads every
      // member's media but deletes only through the seat the file was posted on)
      if (typeof bindToken === "string") { const gt = await seatCredGroup(bindToken, bindWs); sets.push([["blob_session", id], await blobSessionTag(bindToken)]); if (gt) sets.push([["blob_group", id], await blobGroupTag(gt)]); }
      if (!(await writeIfAccountLive(auth.userId, sets))) {
        await Deno.remove(BLOB_DIR + id).catch(() => undefined);
        noteBlobWritten(-file.size);
        return ACCOUNT_GONE_WRITE();
      }
    }
    charged = -1; // kept: this upload's bytes stay counted
    return json({ file_uri: "blob:" + id });
  } catch (e) {
    console.error("upload error", e); return j({ message: "Upload failed" }, 500); // Batch C (B7)
  } finally {
    releaseUploadSlot();
    netSlot();
    store.release(); // b77m (audit VAR-03)
    // anything refused or failed gives its reservation back
    if (charged > 0) await adjustQuota(caps, -charged).catch(() => undefined);
  }
});

// b198 MEDIA DELETION: the blob id exists ONLY inside the E2E-encrypted media
// payload (the relay never sees it), so knowledge of an unguessable blob id IS
// the decryption proof — an authenticated caller presenting one is the deletion
// capability. The client's burn/✕ paths call this so burnt media leaves NOTHING
// on the relay's disk (text envelopes were already hard-deleted; this closes the
// media half of the burn/✕ claim). Idempotent: an already-gone blob is success.
route("POST", "/api/apps/:appId/integration-endpoints/Core/DeletePrivateFile", async (req) => {
  const auth = await authUser(req);
  if (!auth) return j({ message: "Unauthorized" }, 401);
  { const lim = await routeLimited("delfile", auth.userId, 120); if (lim) return lim; } // b70 (re-review 7)
  let body: Record<string, unknown> = {};
  try { body = await readJson(req); } catch { /* empty body tolerated */ }
  const uri = canonBlobUri(String(body.file_uri || "")); // b77u (audit 6 U-M9 / F-05): canonical case
  if (!uri.startsWith("blob:") || uri.length > MAX_KEY_PART + 5) return j({ message: "Unknown file" }, 404);
  const path = blobPathOf(uri);
  if (!path) return j({ message: "Unknown file" }, 404);
  // Batch E (RV-39): the uploader may always delete; a vault container or a pending transfer bundle is its owner's alone.
  // b77u (audit 6 U-M9, R4 #1): anyone else needs a valid BINDING credential (blobBindingAllows: a group file and a
  // seat credential of its group; a b70 seat-bound file and that seat's credential). An unbound file — and a legacy
  // file with no owner record — is no longer deletable by whoever holds its id (group media was unbound, so any
  // signed-in account with the id could delete it).
  const id = blobIdOf(uri);
  // b77 (sealed sender): a 1:1 file is deleted only through its mailbox (sealedFile)
  if ((await KV.get(["blob_mbox", id])).value) return j({ message: "Not your file" }, 403);
  const rec = (await KV.get<string>(["blob_owner", id])).value;
  const isUploader = !!rec && rec === await blobOwnerTag(await accountHashOf(auth.userId), id);
  if (body.session_token !== undefined) {
    // b70 (audit VAR-06): the chat-scoped (burn) path deletes "the file of this chat": a valid seat credential, and the
    // file bound to that chat or group — never a vault container, transfer bundle or another chat's file, whoever
    // uploaded it. b77u: a file with no binding is refused here too (the b70 R4 "older build" exception is gone).
    if (!(await sessionCredOk(body.session_token, body.write_secret))) return j({ message: "Invalid session credential" }, 403);
    if (await blobIsProtected(uri) || !(await blobBindingAllows(id, body, "delete"))) return j({ message: "Not this chat's file" }, 403);
  } else if (!isUploader) {
    // (an id that names nothing at all stays an idempotent success: there is nothing to protect)
    const exists = !!rec || await Deno.stat(path).then(() => true).catch(() => false);
    if (exists) return j({ message: "Not your file" }, 403);
  }
  try { await Deno.remove(path); } catch { /* already gone — deletion is idempotent */ }
  await KV.delete(["blob_owner", id]);
  await KV.delete(["blob_session", id]);
  await KV.delete(["blob_group", id]); // b77u (audit 6 U-M9)
  return json({ ok: true });
});

// pre-signed blob download (HMAC + expiry, no auth header by design)
route("GET", "/files/:id", async (req, m, url) => {
  const blobId = keySafe(m.groups!.id!).toLowerCase(); // b77u (audit 6 U-M9 / F-05): canonical case
  const exp = Number(url.searchParams.get("e") || "0");
  const mac = url.searchParams.get("m") || "";
  if (!exp || exp < Date.now() || !mac) return j({ error: "Link expired", message: "Link expired" }, 403);
  const key = await blobSecret();
  const expect = b64e(new Uint8Array(await crypto.subtle.sign("HMAC", key, enc.encode(`${blobId}:${exp}`))))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  if (!ctEq(expect, mac)) return j({ error: "Bad signature", message: "Bad signature" }, 403); // Batch C (B7): constant time (V-30)
  const path = blobPathOf("blob:" + blobId);
  if (!path) return j({ error: "Not found", message: "Not found" }, 404);
  // b77n (pre-audit M2): each file used to be read WHOLE into memory (up to 25 MB), with no limit on how many at
  // once, from anywhere, and a link reused as often as liked for its 10 minutes. Now: a link serves at most
  // DOWNLOAD_USES_PER_LINK downloads; at most DOWNLOAD_MAX_CONCURRENT run relay-wide, DOWNLOAD_PER_NETWORK_CONCURRENT
  // per network (/64 or IPv4) and DOWNLOAD_PER_WIDE_NETWORK_CONCURRENT per /56 and /48; and the file is STREAMED
  // from disk, its slots released when the stream ends, fails or the client goes away.
  const slot = await takeDownloadSlot(req);
  if (!slot) return j({ error: "Too many downloads at once — try again in a moment", message: "Too many downloads at once — try again in a moment", retry_seconds: 5 }, 429, { "Retry-After": "5" });
  if (!takeLinkUse(blobId, exp, mac)) { slot(); return j({ error: "This link has been used too many times — ask for a new one", message: "This link has been used too many times — ask for a new one" }, 429); }
  let file: Deno.FsFile;
  try { file = await Deno.open(path, { read: true }); }
  catch { slot(); return j({ error: "Not found", message: "Not found" }, 404); }
  let size: number | null = null;
  try { size = (await file.stat()).size; } catch { /* unknown: no Content-Length */ }
  const reader = file.readable.getReader();
  let closed = false;
  // b77n2 (review M2): a reader that stops pulling (or pulls a trickle) used to hold its slots for as long as it
  // liked — 8 such clients filled a network's share, 64 the relay's. Each download now has a wall-clock deadline
  // sized for the file (size / DOWNLOAD_MIN_BYTES_PER_S, at least DOWNLOAD_DEADLINE_FLOOR_MS, at most
  // DOWNLOAD_DEADLINE_CAP_MS) and an idle limit (no bytes pulled for DOWNLOAD_IDLE_MS); either one ends the
  // stream: the file reader is cancelled (the file closed) and the slots are released at once.
  let ctlRef: ReadableStreamDefaultController<Uint8Array> | null = null;
  let lastPull = Date.now();
  const deadlineMs = Math.min(DOWNLOAD_DEADLINE_CAP_MS, Math.max(DOWNLOAD_DEADLINE_FLOOR_MS, Math.ceil(((size ?? 0) / DOWNLOAD_MIN_BYTES_PER_S) * 1000)));
  // b77p (audit VAR-26): the timer types current Deno gives setTimeout / setInterval (2.1 typed them number)
  let deadlineTimer: ReturnType<typeof setTimeout> | undefined, idleTimer: ReturnType<typeof setInterval> | undefined;
  const finish = () => {
    if (closed) return;
    closed = true;
    if (deadlineTimer !== undefined) clearTimeout(deadlineTimer);
    if (idleTimer !== undefined) clearInterval(idleTimer);
    slot();
  };
  const cutOff = (why: string) => {
    if (closed) return;
    finish();
    reader.cancel(why).catch(() => undefined);
    try { ctlRef?.error(new Error(why)); } catch { /* already closed */ }
  };
  deadlineTimer = setTimeout(() => cutOff("download deadline"), deadlineMs);
  idleTimer = setInterval(() => { if (Date.now() - lastPull >= DOWNLOAD_IDLE_MS) cutOff("download idle"); }, Math.max(250, Math.min(5000, Math.floor(DOWNLOAD_IDLE_MS / 4))));
  const body = new ReadableStream<Uint8Array>({
    start(ctl) { ctlRef = ctl; },
    async pull(ctl) {
      lastPull = Date.now();
      if (closed) return;
      try {
        const { done, value } = await reader.read();
        if (closed) return; // cut off while the read was in flight
        lastPull = Date.now();
        if (done) { finish(); ctl.close(); } else ctl.enqueue(value);
      } catch (e) { if (!closed) { finish(); ctl.error(e); } }
    },
    async cancel(reason) { finish(); await reader.cancel(reason).catch(() => undefined); }, // the client went away
  });
  req.signal?.addEventListener("abort", () => { if (!closed) { finish(); reader.cancel().catch(() => undefined); } });
  return new Response(body, { headers: { "Content-Type": "application/octet-stream", "Cache-Control": "no-store", ...(size !== null ? { "Content-Length": String(size) } : {}) } });
});
/** b77n (pre-audit M2): download limits (env overrides are for TEST relays) */
/** b77n2 (review M2): the slowest pace a download may average, the shortest and longest deadline, and how long a
 *  reader may pull nothing before it is cut off.
 *  b77q owner (1 Nov): 64 KB/s and 20 s idle cut 10-25 MB media (and backups) on weak mobile links that b64 served.
 *  Now 8 KB/s (64 kbit/s) and 60 s idle; the cap follows so a full 25 MiB file at 8 KB/s fits (26214400 / 8192 =
 *  3200 s, ~53 min: cap 60 min), and the floor stays above the idle limit (90 s). The cost: a slow reader holds a
 *  download slot longer — up to 60 min, still at most 8 per network, 16 per /56 or /48 and 64 relay-wide, and each
 *  held slot has to keep pulling 8 KB/s (an idle one is cut after 60 s). The app's own clocks
 *  (vendor/device/src/relay.ts MEDIA_FETCH_LIMITS) sit above these. */
const DOWNLOAD_MIN_BYTES_PER_S = Number(Deno.env.get("VEIL_DOWNLOAD_MIN_BPS")) || 8 * 1024;
const DOWNLOAD_DEADLINE_FLOOR_MS = Number(Deno.env.get("VEIL_DOWNLOAD_DEADLINE_FLOOR_MS")) || 90_000;
const DOWNLOAD_DEADLINE_CAP_MS = Number(Deno.env.get("VEIL_DOWNLOAD_DEADLINE_CAP_MS")) || 60 * 60_000;
const DOWNLOAD_IDLE_MS = Number(Deno.env.get("VEIL_DOWNLOAD_IDLE_MS")) || 60_000;
const DOWNLOAD_MAX_CONCURRENT = Number(Deno.env.get("VEIL_DOWNLOAD_MAX_CONCURRENCY")) || 64;
const DOWNLOAD_PER_NETWORK_CONCURRENT = Number(Deno.env.get("VEIL_DOWNLOAD_PER_NET_CONCURRENCY")) || 8;
const DOWNLOAD_PER_WIDE_NETWORK_CONCURRENT = Number(Deno.env.get("VEIL_DOWNLOAD_PER_WIDE_NET_CONCURRENCY")) || 16;
/** a signed link is made per fetch by the app (createFileSignedUrl); a few retries are normal */
const DOWNLOAD_USES_PER_LINK = Number(Deno.env.get("VEIL_DOWNLOAD_USES_PER_LINK")) || 20;
let downloadsActive = 0;
const netDownloadsActive = new Map<string, number>();
/** a release function, or null when the relay or the caller's network already has its cap of downloads running
 *  (in memory only; a trusted loopback test relay's "local" is exempt from the per-network caps, not the relay-wide one) */
async function takeDownloadSlot(req: Request): Promise<(() => void) | null> {
  if (downloadsActive >= DOWNLOAD_MAX_CONCURRENT) return null;
  const net = await clientTag(req);
  const keys: [string, number][] = net === "local" ? [] : [[net, DOWNLOAD_PER_NETWORK_CONCURRENT]];
  if (net !== "local") for (const w of await clientWideTags(req)) keys.push([w.bits + ":" + w.tag, DOWNLOAD_PER_WIDE_NETWORK_CONCURRENT]);
  if (downloadsActive >= DOWNLOAD_MAX_CONCURRENT || keys.some(([k, cap]) => (netDownloadsActive.get(k) ?? 0) >= cap)) return null;
  downloadsActive++;
  for (const [k] of keys) netDownloadsActive.set(k, (netDownloadsActive.get(k) ?? 0) + 1);
  let released = false;
  return () => {
    if (released) return;
    released = true;
    downloadsActive = Math.max(0, downloadsActive - 1);
    for (const [k] of keys) { const n = (netDownloadsActive.get(k) ?? 1) - 1; if (n <= 0) netDownloadsActive.delete(k); else netDownloadsActive.set(k, n); }
  };
}
/** per-link use counts, in memory only (keyed by the link's MAC; an entry goes once its link has expired) */
const linkUses = new Map<string, { exp: number; n: number }>();
function takeLinkUse(blobId: string, exp: number, mac: string): boolean {
  const now = Date.now();
  if (linkUses.size > 50_000) for (const [k, v] of linkUses) if (v.exp < now) linkUses.delete(k);
  const k = mac.slice(0, 43) + ":" + blobId.slice(0, 64);
  const cur = linkUses.get(k) ?? { exp, n: 0 };
  if (cur.n >= DOWNLOAD_USES_PER_LINK) return false;
  cur.n++;
  linkUses.set(k, cur);
  return true;
}

// auth extras — resend-otp is a no-op success (phase 1 auto-verifies);
// reset-password is HONESTLY offline until SMTP exists (no fake reset path)
route("POST", "/api/apps/:appId/auth/resend-otp", async () => json({ ok: true }));
route("POST", "/api/apps/:appId/auth/reset-password-request", async () =>
  j({ message: "Password reset email delivery is not available on this relay yet" }, 503));
route("POST", "/api/apps/:appId/auth/reset-password", async () =>
  j({ message: "Reset tokens are not issued while email delivery is offline" }, 400));

route("POST", "/api/apps/:appId/functions/purgeExpiredEnvelopes", async (req) => {
  const auth = await authUser(req);
  if (!auth) return j({ message: "Unauthorized" }, 401);
  // b70 (audit RLY-9): the full-database sweep is the sweeper's job; a client
  // call is rate-limited per account and per network so many accounts can't
  // keep the whole database busy. No app build depends on it.
  const net = await clientTag(req);
  const rl = await rateLimit("purge:" + auth.userId, 3, 10 * 60_000, 10)
    || (net === "local" ? null : await rateLimit("purgenet:" + net, 6, 10 * 60_000, 10) || await wideRateLimit("purgenet", await clientWideTags(req), 6, 10 * 60_000, 10));
  if (rl) return j({ locked: true, retry_minutes: rl.retry_minutes }, 429);
  // b77p (audit VAR-24): relay-wide, client calls start at most PURGE_ROUTE_RELAY_PER_10MIN sweeps in 10 min
  // (every account and network together); past that a call gets the last sweep's result (coalesced: true) and
  // starts nothing. And a call never runs a sweep of its own beside another: it shares the one in flight or the
  // single follow-up queued behind it (coalescedPurge), so many accounts can't stack full-database scans.
  if (await rateLimit("purgeall", PURGE_ROUTE_RELAY_PER_10MIN, 10 * 60_000, 0)) {
    return lastSweepResult ? json({ ...lastSweepResult.value, coalesced: true, swept_at: new Date(lastSweepResult.at).toISOString() }) : j({ locked: true, retry_minutes: 10 }, 429);
  }
  return json(await coalescedPurge());
});

// b199 CALL RELAY CREDENTIALS (owner-approved Oct 16): short-lived TURN
// credentials for the self-hosted coturn hosts (TURN REST scheme: username
// "<expiry>:<pseudonym>", credential = base64 HMAC-SHA1(secret, username)).
// Calls run relay-only, so the two phones never learn each other's IP; audio
// stays DTLS-SRTP end to end and coturn cannot hear it. Signed-in users only.
// b71 (audit F-06/F-15/F-31): what this stores: nothing about the credential
// itself. Only the rate-limit rows below, expiring on their own (b77: the short-lived
// ["turn_ok", account hash] eligibility row, which named the chat that qualified, is gone;
// boot deletes any left by an older relay).
// The coturn side (relay/coturn/turnserver.conf.example) lets allocations reach ONLY
// the TURN hosts' own relay addresses, so a credential can't be used as an open relay.
const TURN_SECRET = Deno.env.get("TURN_SECRET") ?? "";
/** b71 (audit F-06): credential lifetime, 1 h by default. A shorter one could drop long
 *  calls (the app does not refresh credentials mid-call), and the coturn peer allow-list
 *  already stops a credential being used as an open relay. TURN_TTL_S overrides it
 *  (600–86400 s). */
const TURN_TTL_S = Math.min(86400, Math.max(600, Number(Deno.env.get("TURN_TTL_S")) || 3600));
// 20 Oct 2026: the coturn hosts, nearest first (comma list; all share TURN_SECRET).
// Sydney (BinaryLane) answers Australian phones in ~25 ms vs ~230 ms for this VPS.
/** b75 (audit CA-1, relay half): a TURN host the relay may hand out — a public DNS name or a
 *  public IPv4 address. Loopback, private (RFC 1918), CGNAT, link-local, multicast and
 *  reserved addresses, "localhost" and single-label / .local / .internal / .localhost names
 *  are refused (a misconfigured TURN_HOSTS used to be served as given, and the app connects
 *  to whatever host the relay names). The relay serves ONLY hosts from TURN_HOSTS (or its
 *  own default); nothing in a request can add one. */
function turnHostAllowed(h: string): boolean {
  const host = h.toLowerCase();
  if (!/^[a-z0-9.-]{1,253}$/.test(host) || host.startsWith(".") || host.endsWith(".")) return false;
  const v4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(host);
  if (v4) {
    const [a, b] = [Number(v4[1]), Number(v4[2])];
    if (v4.slice(1).some((x) => Number(x) > 255)) return false;
    if (a === 0 || a === 10 || a === 127 || a >= 224) return false; // this-network, private, loopback, multicast/reserved
    if (a === 169 && b === 254) return false; // link-local
    if (a === 172 && b >= 16 && b <= 31) return false; // private
    if (a === 192 && b === 168) return false; // private
    if (a === 100 && b >= 64 && b <= 127) return false; // CGNAT
    return true;
  }
  const labels = host.split(".");
  if (labels.length < 2 || labels.some((l) => !l || l.length > 63 || l.startsWith("-") || l.endsWith("-"))) return false;
  if (/^\d+$/.test(labels[labels.length - 1])) return false; // not a name, not a dotted quad
  return !["localhost", "local", "internal", "localdomain", "home", "lan"].includes(labels[labels.length - 1]);
}
const TURN_HOSTS_SET = (Deno.env.get("TURN_HOSTS") ?? "")
  .split(",").map((h) => h.trim()).filter((h) => {
    if (!h) return false;
    if (turnHostAllowed(h)) return true;
    console.warn(`[relay] TURN_HOSTS entry refused (not a public host name or address): ${h.slice(0, 80)}`);
    return false;
  });
/** b77q (audit 3 RF-3): no fallback host. Empty or all refused used to mean "relay.tryveil.app", so a self-hoster
 *  with no valid TURN_HOSTS handed out credentials (signed with THEIR secret) for the vendor's TURN host, and calls
 *  were attempted against a third party's server. Now: a production relay with TURN_SECRET set and no valid host
 *  refuses to start (exit 78); any other relay treats calling as not configured (503, as with no TURN_SECRET). */
const TURN_HOSTS: string[] = TURN_HOSTS_SET;
if (TURN_SECRET && !TURN_HOSTS.length) {
  if (productionRefusals(Deno.env.toObject()).production) {
    console.error("[relay] REFUSING TO START: TURN_SECRET is set but TURN_HOSTS names no valid public TURN host (empty, or every entry refused). Set TURN_HOSTS to this relay's coturn host name(s), or remove TURN_SECRET to turn calls off.");
    Deno.exit(78);
  }
  console.warn("[relay] TURN_SECRET is set but TURN_HOSTS names no valid host: calls are not configured (no fallback host is handed out)");
}
/** b77q (audit 3 RF-3): calling needs a secret AND a host */
const turnConfigured = () => !!TURN_SECRET && TURN_HOSTS.length > 0;
/** b71 (audit F-31): turns: (TURN over TLS, port 5349 — where the example coturn config
 *  listens) is handed out too, for every host given by NAME (a certificate can't match a
 *  bare IP), so the TURN user name and the call's timing don't cross the network in the
 *  clear on networks that take it. TURN_TLS=0 leaves it out (hosts without a certificate). */
const TURN_TLS = Deno.env.get("TURN_TLS") !== "0";
const turnUrls = () => [
  ...TURN_HOSTS.map((h) => `turn:${h}:3478?transport=udp`),
  ...TURN_HOSTS.map((h) => `turn:${h}:3478?transport=tcp`),
  ...(TURN_TLS ? TURN_HOSTS.filter((h) => !/^\d+\.\d+\.\d+\.\d+$/.test(h)).map((h) => `turns:${h}:5349?transport=tcp`) : []),
];
/** b71 (audit F-06): credentials per account and per network per hour.
 *  b77m (audit VAR-04): per network 300 → 30 (the /56 and /48 at x4 / x16: 120 / 480). The app
 *  fetches ONE credential per call and caches it per chat until 5 minutes before it expires, so a
 *  household making many calls an hour uses a handful; 300 let one IPv4 address hold 300 live
 *  credentials (x8 allocations each under the old user-quota) against a TURN host's total-quota of
 *  1200. With coturn's user-quota at 3 (relay/coturn/turnserver.conf.example) one network now holds
 *  at most ~90 allocations per host (a /48 ~1440) against a total-quota of 4000.
 *  b77n (audit VAR-04, the full fix): 30 → 300, and past it a puzzle (never a plain refusal below the
 *  netPowGate hard ceiling). A credential now needs a call the OTHER phone of the chat approved (the
 *  TURN grant, see turnGrant below), so the per-network cap is no longer what stops one phone
 *  minting credentials alone; at 30 it refused real calls from phones behind one carrier-NAT address. */
/**
 * b77q (audit 3 RF-4): ONE stated budget. The coturn quotas (relay/coturn/turnserver.conf.example) and these caps used
 * to be sized apart: the conf assumed 30 credentials per network per hour, the code allowed 300 (x8 past the puzzle,
 * x16 for an IPv6 /48), so a few networks could hold every allocation a TURN host has and stop calls for everyone.
 * The budget, per TURN host:
 *   - TURN_TOTAL_QUOTA allocations in all (coturn total-quota; VEIL_TURN_TOTAL_QUOTA mirrors it, default 4000);
 *   - each credential opens at most TURN_USER_QUOTA of them (coturn user-quota, default 3: udp, tcp, tls);
 *   - one network (an IPv4 address or an IPv6 /64) gets TURN_CREDS_PER_NETWORK_PER_HOUR credentials an hour (30) and
 *     past that solves the network puzzle for each; the /56 and /48 reach the puzzle at TURN_WIDE_FACTOR x the cap
 *     (x2, x4 — not the x4 / x16 of the other limits);
 *   - a credential lives TURN_TTL_S (1 h).
 * b77q review (RF-4, owner decision "Puzzle, no hard stop"): b77q refused outright at TURN_POW_HARD_FACTOR (2) x the
 * cap, which cut off real callers behind one carrier-NAT address once the hour's 60 were used. Now there is NO hard
 * stop: past the cap each credential needs a puzzle that grows one bit (double the work) every TURN_POW_STEP puzzles
 * the network already passed this hour (10 by default: 16 bits for the 31st-40th, 17 for the 41st-50th, ...), up to
 * NET_POW_MAX_BITS (22, ~4M SHA-256 per credential, several seconds on a phone). Callers behind a shared address get
 * through, slower; a flood pays for every credential. What bounds the total is not a count per network any more:
 * the per-mailbox cap (MBOX_TURN_PER_HOUR, 6), the per-pair grant cap (TURN_PAIR_GRANTS_PER_HOUR) and coturn's own
 * quotas (TURN_TOTAL_QUOTA / TURN_USER_QUOTA). Without solving puzzles one network holds at most cap x user-quota x
 * TTL hours = 90 allocations (2.25 % of a host; /56 x2, /48 x4); the start-up log (below) says so.
 */
const TURN_CREDS_PER_ACCOUNT_PER_HOUR = 30;
const TURN_CREDS_PER_NETWORK_PER_HOUR = Number(Deno.env.get("VEIL_TURN_CREDS_PER_NETWORK_PER_HOUR")) || 30;
/** b77q review (RF-4): puzzles per extra bit of the TURN network puzzle (no hard stop) */
const TURN_POW_STEP = Number(Deno.env.get("VEIL_TURN_POW_STEP")) || Math.max(1, Math.round(TURN_CREDS_PER_NETWORK_PER_HOUR / 3));
const TURN_WIDE_FACTOR: Record<56 | 48, number> = { 56: 2, 48: 4 };
const TURN_TOTAL_QUOTA = Number(Deno.env.get("VEIL_TURN_TOTAL_QUOTA")) || 4000;
const TURN_USER_QUOTA = Number(Deno.env.get("VEIL_TURN_USER_QUOTA")) || 3;
/** the network-limit options every credential route passes (sealedNetPowLimited / netPowGate / wideRateLimit) */
const TURN_NET_OPTS: NetPowOpts = { noHardStop: true, bitsStep: TURN_POW_STEP, wide: TURN_WIDE_FACTOR }; // b77q review (RF-4)
/** b77q (audit 3 RF-4): the share of one TURN host's allocations a network of each size holds live WITHOUT solving a
 *  puzzle (b77q review: past that there is no hard count, only the growing puzzle) */
function turnBudgetShare(): { net: number; w56: number; w48: number } {
  const perNet = TURN_CREDS_PER_NETWORK_PER_HOUR * TURN_USER_QUOTA * Math.ceil(TURN_TTL_S / 3600);
  return { net: perNet / TURN_TOTAL_QUOTA, w56: perNet * TURN_WIDE_FACTOR[56] / TURN_TOTAL_QUOTA, w48: perNet * TURN_WIDE_FACTOR[48] / TURN_TOTAL_QUOTA };
}
/** b77m (audit VAR-04): mailboxes one network may newly mark verified per day (/56, /48 at x4, x16;
 *  "local" exempt). "verified" is the mailbox owner's own word (the relay can't check a safety-code
 *  comparison it never sees) and it gated sealedTurn (b77n: now the TURN grants, both sides), so cheap self-joined rendezvous rows could mint
 *  verified mailboxes without limit. A phone marks one inbound per chat it verifies; re-asserting a
 *  mailbox that is already verified (the app does on every call offer) costs nothing. */
const MBOX_VERIFIES_PER_NETWORK_PER_DAY = Number(Deno.env.get("VEIL_MBOX_VERIFIES_PER_NETWORK_PER_DAY")) || 20;
/**
 * b71 (review R-3) / b75 (audit RL-09): call-relay credentials used to go to an account with a
 * bound Vardum ID and an active, verified 1:1 chat with another account (rescanned per request).
 * b77r1 (audit R-9): no 1:1 row qualifies any more — a b77 chat's rendezvous row names no account,
 * and a pre-b77 1:1 row is a retired protocol (its chat answers 410 everywhere else). 1:1 calls
 * take their credentials from sealedTurn (a verified inbound mailbox); groups have no calls. The
 * signed-in route keeps its caps and answers 403.
 */
/** the TURN REST credential every call-relay route hands out (veilTurnCredentials, sealedTurn) */
async function turnCredentialResponse(): Promise<Response> {
  // b71 (audit F-31): the user part is a fresh RANDOM pseudonym per credential (it was
  // one per account per day, so every credential of that day linked to the others).
  // coturn's user-quota therefore counts per credential; the per-account and per-network
  // caps bound how many credentials (and so allocations) one account can hold.
  const pseud = "u" + Array.from(crypto.getRandomValues(new Uint8Array(8)), (b) => b.toString(16).padStart(2, "0")).join("");
  const username = `${Math.floor(Date.now() / 1000) + TURN_TTL_S}:${pseud}`;
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(TURN_SECRET) as BufferSource, { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(username) as BufferSource));
  const credential = btoa(String.fromCharCode(...mac));
  return j({
    iceServers: [{ urls: turnUrls(), username, credential }],
    ttl: TURN_TTL_S,
  });
}
// b77t (audit 5 L-17, IH V-05): RETIRED. Since b77r1 no session row qualified (1:1 calls use sealedTurn), but the route
// still ran its per-account and per-network limiters first, so any account could spend the shared per-network TURN
// budget (pushing callers on that network to the puzzle). It now answers 410 at once: no login read, no limiter.
route("POST", "/api/apps/:appId/functions/veilTurnCredentials", async () =>
  j({ error: "Update Vardum: calls now get their relay through the chat", message: "Update Vardum: calls now get their relay through the chat", code: "retired" }, 410));

// ==================== b77 SEALED SENDER: anonymous 1:1 mailboxes ====================
// Spec: docs/protocol-spec.md §12.x "Anonymous delivery" (design: B77-DESIGN.md Part B).
// Every route below is POST /api/apps/:appId/functions/NAME and takes NO login: it never reads
// the Authorization header, never calls authUser, never writes a token or account row, and
// logs nothing per request. A mailbox is addressed by a 64-hex id both phones derive from the
// chat's root; the relay holds only SHA-256 (of the UTF-8 hex string, as the write hashes) of
// its send and read capabilities, and sees a capability only when it is presented. Limits are
// keyed on SHA-256("veil-mbox-tag:" + mailbox), the network tag, and relay-wide totals — never
// on an account. Every error body is {error, message}.
const LEGACY_1TO1 = "Update Vardum: this chat uses an older protocol";
const MBOX_HEX_RE = /^[0-9a-f]{64}$/;
/** Part A: a 1:1 header is 'h8.' + base64 of 3870 sealed bytes (header nonce + AES-GCM of the 3810-byte frame +
 *  the session header tag) — 5160 base64 characters, no '=', exactly 5163 characters. The 5158 + '==' spelling
 *  (3868 bytes, an earlier draft of Part A) has the same length and is taken too; the receiver refuses it as junk.
 *  The one rule is isSealedHeaderString (next to submitEnvelope), also used by the legacy path's size-cap exemption. */
const SEALED_PROTOCOL = "veil-ratchet-8";
const MBOX_TICKET_TTL_MS = 7 * 86400_000;
const MBOX_RETIRED_TTL_MS = 400 * 86400_000;
/** b77r2 (audit R2-R-1): a PRE-OPEN marker (sealedEnd on a mailbox that was never opened, A-4)
 *  lives only this long, the open ticket's 7 days plus a day, instead of 400 days: the open it
 *  answers can only come while a ticket is alive. It is an unauthenticated write, so it is also
 *  capped per network and relay-wide per day (below). The 400 days stay for mailboxes that existed. */
const MBOX_PRE_RETIRED_TTL_MS = MBOX_TICKET_TTL_MS + 86400_000;
/** b77r2 (audit R2-R-1): end-before-open answers per network per day (/56 x4, /48 x16), and for
 *  the whole relay per day ("local" excepted). Past either, the answer is the old 425 "not open
 *  yet" and nothing is written (the app's existing handling of a 425 applies). */
const END_BEFORE_OPEN_PER_NETWORK_PER_DAY = Number(Deno.env.get("VEIL_END_BEFORE_OPEN_PER_NETWORK_PER_DAY")) || 50;
const END_BEFORE_OPEN_RELAY_PER_DAY = Number(Deno.env.get("VEIL_END_BEFORE_OPEN_RELAY_PER_DAY")) || 20_000;
/** the sweeper retires a mailbox its OWNER has not used for this long (b77g: owner operations
 *  only — sealedFetch, sealedBurn, mailboxVerify, mailboxPush, mailboxOpen; it was "no submit or
 *  fetch", so a peer that kept writing kept an abandoned inbound alive for ever) */
const MBOX_IDLE_MS = 30 * 86400_000;
const MBOX_TTL_CAP_MIN_S = 60;
const MBOX_TTL_CAP_MAX_S = 7 * 86400;
const MBOX_SUBMITS_PER_MIN = 60;
const MBOX_FETCHES_PER_MIN = Number(Deno.env.get("VEIL_MBOX_FETCHES_PER_MIN")) || 600; // b77t: env for test relays
/** control calls (burn, push, verify, end, file) per mailbox per minute */
const MBOX_CONTROL_PER_MIN = Number(Deno.env.get("VEIL_MBOX_CONTROL_PER_MIN")) || 600; // b77t: env for test relays
const MBOX_UPLOADS_PER_MIN = 30;
const MBOX_DAILY_BYTES = 50 * 1024 * 1024;
const MBOX_UPLOAD_DAILY_BYTES = 1024 * 1024 * 1024;
/** b77r1 (audit R-6): files one mailbox may receive per UTC day (bounds its ["blob_by_mbox"] list,
 *  which endMailbox walks) */
const MBOX_FILES_PER_DAY = Number(Deno.env.get("VEIL_MBOX_FILES_PER_DAY")) || 500;
const MBOX_NOTIFY_PER_MIN = 60;
/** b77m (audit VAR-04): 30 → 6 credentials per mailbox per hour (the app caches one per chat for
 *  ~55 minutes; a redial after a failed call fetches again) */
const MBOX_TURN_PER_HOUR = Number(Deno.env.get("VEIL_MBOX_TURN_PER_HOUR")) || 6;
// b77q (audit 3 RF-4): the start-up budget line (b77q review: after MBOX_TURN_PER_HOUR, which it names)
if (turnConfigured()) {
  const s = turnBudgetShare();
  const pct = (x: number) => (x * 100).toFixed(1) + "%";
  // b77q review (RF-4): says what bounds use now — no per-network ceiling past the puzzle, so the other bounds are named
  const budget = `without a puzzle a network holds at most ${pct(s.net)} of a TURN host's ${TURN_TOTAL_QUOTA} allocations (/56 ${pct(s.w56)}, /48 ${pct(s.w48)}); past ${TURN_CREDS_PER_NETWORK_PER_HOUR} credentials an hour each needs the network puzzle, ${NET_POW_BASE_BITS} bits growing 1 bit per ${TURN_POW_STEP} up to ${NET_POW_MAX_BITS}, with NO hard stop — total use is bounded by ${MBOX_TURN_PER_HOUR} credentials an hour per mailbox and coturn's total-quota / user-quota (${TURN_TOTAL_QUOTA} / ${TURN_USER_QUOTA})`;
  if (s.w48 > 0.25) console.warn(`[relay] TURN budget: ${budget}; lower VEIL_TURN_CREDS_PER_NETWORK_PER_HOUR / TURN_TTL_S, or raise coturn total-quota and VEIL_TURN_TOTAL_QUOTA together`);
  else console.log(`[relay] TURN budget: ${budget}`);
}
/** b77n (audit VAR-04, the full fix): TURN grants. A credential is issued only for a call that BOTH
 *  mailboxes of a chat took part in: the caller opens a grant on its own inbound (turnGrant, read
 *  cap), the callee's phone approves it on ITS own inbound when the call rings (turnApprove, read
 *  cap; the caller's mailbox can't approve its own grant), and then each of the two may redeem it
 *  (sealedTurn with the grant). One mailbox alone — one phone holding only its own side of a chat —
 *  can never complete a grant. The grant row ["turn_grant", H(grant)] holds the two mailboxes' MEMORY-KEYED tags
 *  (b77n2 review L4: turnSideTag; never the ids), its expiry and the redemption counts, and is deleted by its KV expiry. */
const TURN_GRANT_TTL_MS = 5 * 60_000;
/** redemptions per side of one grant: one, plus a retry after an answer lost on the way back */
const TURN_GRANT_REDEEMS_PER_SIDE = 2;
/** grants a mailbox may open (as the caller) / approve (as the callee) per hour */
const MBOX_TURN_GRANTS_PER_HOUR = Number(Deno.env.get("VEIL_MBOX_TURN_GRANTS_PER_HOUR")) || 12;
const MBOX_TURN_APPROVALS_PER_HOUR = Number(Deno.env.get("VEIL_MBOX_TURN_APPROVALS_PER_HOUR")) || 12;
/** approved grants per mailbox PAIR per hour (whichever side called): what one chat — real, or two
 *  cooperating phones / one phone running both ends of a self-joined chat — can turn into credentials */
const TURN_PAIR_GRANTS_PER_HOUR = Number(Deno.env.get("VEIL_TURN_PAIR_GRANTS_PER_HOUR")) || 12;
/** sealedTurn asks per mailbox per minute (the caller polls about once a second while the call rings
 *  and the callee has not approved yet; a "pending" answer costs no credential budget) */
const MBOX_TURN_POLLS_PER_MIN = Number(Deno.env.get("VEIL_MBOX_TURN_POLLS_PER_MIN")) || 120;
/** grants opened per network per hour (/56, /48 at x4, x16); past it a puzzle, as for credentials */
const TURN_GRANTS_PER_NETWORK_PER_HOUR = Number(Deno.env.get("VEIL_TURN_GRANTS_PER_NETWORK_PER_HOUR")) || 600;
/** per network (the HMAC'd network tags; /56 and /48 get x4 / x16) */
const SEALED_SUBMITS_PER_NETWORK_PER_MIN = 1200;
const SEALED_FETCHES_PER_NETWORK_PER_MIN = 3000;
const SEALED_OPENS_PER_NETWORK_PER_HOUR = 120;
const SEALED_CONTROL_PER_NETWORK_PER_MIN = 3000;
const SEALED_UPLOADS_PER_NETWORK_PER_MIN = 120;
const SESSION_GATE_ANON_PER_NETWORK_PER_MIN = 600;
/** b77r1 (audit R-5): the "sealed-any" budget — the FIRST step of every sealed route (before the
 *  body is even parsed), per network, in memory (no database write per request). Every request
 *  costs 1; an answer that names no live mailbox — 400 (malformed), 410 (retired), 425 (absent),
 *  and an end-before-open (A-4) — costs SEALED_MISS_WEIGHT in all, because those answers used to
 *  bypass every limiter (the per-mailbox and per-network limits sat behind the mailbox lookup).
 *  Sized from what the app does: an open chat fetches every 1.5 s (40 a minute, plus its sends and
 *  the outbox flush), a call being set up every 0.75 s (80), and the background pass every 10 s
 *  fetches each chat once (6 a minute per chat: 600 for a phone with 100 chats) — about 750 a
 *  minute for a busy phone. 8000 sits above the sum of the per-route network caps below (3000
 *  fetches + 1200 submits + 3000 control calls), so ordinary traffic always meets those first;
 *  misses are held to 1600 a minute per network. The /56 and /48 get x4 and x16. */
const SEALED_ANY_PER_NETWORK_PER_MIN = Number(Deno.env.get("VEIL_SEALED_ANY_PER_NETWORK_PER_MIN")) || 8000;
const SEALED_MISS_WEIGHT = 5;
/** at most this many networks are tracked in one minute (memory stays bounded under an
 *  address-spraying flood). b77r2 (audit R2-R-5): beyond it a request none of whose keys is tracked
 *  is charged to an overflow bucket of SEALED_ANY_OVERFLOW_PER_MIN (one /48's share); it used to go
 *  unlimited. b77r3 (audit R3-2): the overflow is SHARDED into SEALED_ANY_OVERFLOW_SHARDS buckets by
 *  the request's widest network tag (/48, else /56, else the /64 or IPv4 one), and a request with ANY
 *  key already tracked is charged to its tracked keys only, never to overflow — one shared bucket
 *  let a single /48 (or one sprayer) fill the map, drain it and lock out every fresh network. */
const SEALED_ANY_TRACK_MAX = Number(Deno.env.get("VEIL_SEALED_ANY_TRACK_MAX")) || 200_000;
const SEALED_ANY_OVERFLOW_PER_MIN = Number(Deno.env.get("VEIL_SEALED_ANY_OVERFLOW_PER_MIN")) || SEALED_ANY_PER_NETWORK_PER_MIN * 16;
const SEALED_ANY_OVERFLOW_SHARDS = 1024;
const SEALED_FETCH_MAX = 100;
const SEALED_BURN_MAX = 50;
/** a joined 1:1 rendezvous row lives this long (the initiator reads it with "status", then ends it) */
const RENDEZVOUS_TTL_MS = 7 * 86400_000;

/** `last_hour`: the hour (floored) of the OWNER's last operation on the mailbox — the open, a
 *  fetch, a burn, a verify or a push-ref change (b77g: a peer's submit no longer refreshes it).
 *  Read only by the idle sweep (sweepIdleMailboxes, and its R-7 re-check in endMailbox). */
type MboxRow = { send_hash: string; read_hash: string; /** b77u (audit 6 W4): H(owner cap) — a random cap only the owner's phone holds */ own_hash?: string; ttl_cap_s: number; verified: boolean; /** b77p: the sealed wake box */ wake?: string; /** b77 legacy (transition window only) */ push_ref?: string; last_hour: number; next_seq: number; created_day: string };
const mboxKey = (m: string): Deno.KvKey => ["mbox", m];
/** b77r1 (audit A-4 / known item): the retired marker is keyed on a HASH of the mailbox id (it
 *  stored the plain id for 400 days). Rows of the old shape are converted at boot. */
const mboxRetiredKey = async (m: string): Promise<Deno.KvKey> => ["mbox_retired_h", await sha256hex("veil-mbox-retired:" + m)];
/** b77r2 (audit R2-R-1): a pre-open marker's value — the capability hash that ended the mailbox
 *  before it was opened, and when the marker lapses (its KV expiry, also checked on read).
 *  b77r3 (audit R3-3): and at most ONE more, `cap_h2`, from a later end-before-open naming another
 *  capability (a junk marker written first used to swallow the peer's real end) */
type PreRetired = { pre: 1; cap_h: string; cap_h2?: string; exp: number };
const asPreRetired = (v: unknown): PreRetired | null =>
  v && typeof v === "object" && (v as PreRetired).pre === 1 && typeof (v as PreRetired).cap_h === "string" ? v as PreRetired : null;
/** b77r3 (audit R3-3): whether a pre-open marker names `h` (its cap_h, or its cap_h2) */
const preNames = (pre: PreRetired, h: string): boolean => ctEq(pre.cap_h, h) || (typeof pre.cap_h2 === "string" && ctEq(pre.cap_h2, h));
/** whether a ["mbox_retired_h"] value retires the id (a real marker, or a pre-open one not yet lapsed) */
const retiredLive = (v: unknown): boolean => { if (!v) return false; const p = asPreRetired(v); return !p || Number(p.exp) > Date.now(); };
/** b77r2 (audit R2-R-3): true until the boot step re-keying old ["mbox_retired", id] rows has
 *  finished; while true, the old key is checked as well (that step runs before Deno.serve, so
 *  this matters only if it failed) */
let legacyRetiredPending = true;
async function legacyRetired(m: string): Promise<boolean> {
  return legacyRetiredPending && !!(await KV.get(["mbox_retired", m])).value;
}
/** b77 legacy (transition window only): a one-time open ticket a legacy join stored, by H(ticket) */
const mboxTicketKey = (h: string): Deno.KvKey => ["mbox_ticket", h];
const mboxTag = (m: string) => sha256hex("veil-mbox-tag:" + m);
const blobMboxTag = (m: string) => sha256hex("veil-blob-mbox:" + m);
const hourFloor = (t = Date.now()) => Math.floor(t / 3600_000) * 3600_000;
const sealedErr = (status: number, msg: string, extra: Record<string, unknown> = {}) => j({ error: msg, message: msg, ...extra }, status);
const isMboxHex = (v: unknown): v is string => typeof v === "string" && MBOX_HEX_RE.test(v);
/** SHA-256 of a capability: lowercase hex of SHA-256 over the UTF-8 bytes of the hex string
 *  (the same convention as the write-secret hashes) */
const capHash = (cap: string) => sha256hex(cap);
async function capMatches(cap: unknown, hash: unknown): Promise<boolean> {
  if (!isMboxHex(cap) || typeof hash !== "string") return false;
  return ctEq(await capHash(cap), hash);
}
/**
 * b77u (audit 6 W4, IH full L-2): the OWNER-only operations (mailboxPush, mailboxVerify, turnGrant, turnApprove,
 * sealedTurn). Every 1:1 capability (mbox, send, read, ticket, wake, both directions) is HKDF-derived from the root both
 * phones share, so the peer could compute the victim's read cap: mark the victim's inbound verified (its phone then rang
 * before its owner had verified anything), approve TURN grants on it, or replace its wake box. A mailbox opened with an
 * `own_hash` (the hash of a random cap the owner's phone made and keeps; the peer never sees it) takes those operations
 * only with that `own_cap`. A mailbox opened without one (an older app) keeps the read-cap rule.
 */
async function ownerCapOk(row: MboxRow, body: Record<string, unknown>): Promise<boolean> {
  if (typeof row.own_hash === "string" && row.own_hash) return await capMatches(body.own_cap, row.own_hash);
  return await capMatches(body.read_cap, row.read_hash);
}
/** a sealed envelope id: the sequence number (12 hex) then 12 random hex, so ["env_by_mbox", mbox, id] lists in seq order */
const sealedEnvId = (seq: number) => seq.toString(16).padStart(12, "0") + [...crypto.getRandomValues(new Uint8Array(6))].map((b) => b.toString(16).padStart(2, "0")).join("");
const seqPrefix = (seq: number) => Math.max(0, seq).toString(16).padStart(12, "0");

type MboxState = { status: "ok"; entry: Deno.KvEntry<MboxRow>; row: MboxRow } | { status: "retired" } | { status: "absent" };
async function mboxState(m: string): Promise<MboxState> {
  const e = await KV.get<MboxRow>(mboxKey(m), { consistency: "strong" });
  if (e.value) return { status: "ok", entry: e as Deno.KvEntry<MboxRow>, row: e.value };
  if (retiredLive((await KV.get(await mboxRetiredKey(m))).value) || await legacyRetired(m)) return { status: "retired" };
  return { status: "absent" };
}
const mboxGone = (st: MboxState): Response => st.status === "retired"
  ? sealedErr(410, "This chat has ended", { ended: true })
  : sealedErr(425, "Mailbox not open yet", { not_open: true });
/** per-network limit for these routes ("local" — a trusted loopback test relay — is exempt) */
async function sealedNetLimited(req: Request, prefix: string, cap: number, windowMs: number): Promise<Response | null> {
  const net = await clientTag(req);
  if (net === "local") return null;
  const rl = await rateLimit(prefix + ":" + net, cap, windowMs, 0) || await wideRateLimit(prefix, await clientWideTags(req), cap, windowMs, 0);
  return rl ? sealedErr(429, "Too many requests from this network — try again later", { locked: true, retry_minutes: rl.retry_minutes }) : null;
}
/** b77m (owner, carrier NAT): sealedNetLimited, but past the per-network cap the network puzzle (netPowGate) */
async function sealedNetPowLimited(req: Request, prefix: string, cap: number, windowMs: number, body: Record<string, unknown>, opts: NetPowOpts = {}): Promise<Response | null> {
  const net = await clientTag(req);
  if (net === "local") return null;
  const rl = await rateLimit(prefix + ":" + net, cap, windowMs, 0) || await wideRateLimit(prefix, await clientWideTags(req), cap, windowMs, 0, opts.wide);
  return rl ? await netPowGate(req, prefix, cap, windowMs, body, "Too many requests from this network — try again later", opts) : null;
}
async function mboxLimited(key: string, cap: number, windowMs: number): Promise<Response | null> {
  const rl = await rateLimit(key, cap, windowMs, 0);
  return rl ? sealedErr(429, "Too many requests for this chat — try again later", { locked: true, retry_minutes: rl.retry_minutes }) : null;
}
/** records "the owner used it this hour" (only when the hour changed: one write an hour at most).
 *  b77g (A-8 / F-2 residual): called for the OWNER's operations only (read-cap routes: sealedFetch,
 *  sealedBurn; mailboxVerify and mailboxPush set last_hour in their own patch; mailboxOpen creates
 *  the row with it). sealedSubmit (the peer, send cap) never refreshes it, so an inbound whose
 *  owner is gone (wiped, lost phone) is retired 30 days after the owner's last use however long the
 *  peer keeps writing; the peer's sends then get 410 and its chat ends (P-4 / R2-A-1). */
async function touchMbox(m: string): Promise<void> {
  const h = hourFloor();
  for (let attempt = 0; attempt < 3; attempt++) {
    const cur = await KV.get<MboxRow>(mboxKey(m));
    if (!cur.value || cur.value.last_hour === h) return;
    if ((await KV.atomic().check(cur).set(mboxKey(m), { ...cur.value, last_hour: h }).commit()).ok) return;
  }
}
/** applies `patch` to the mailbox row, versionstamp-checked; false when the mailbox is gone */
async function patchMbox(m: string, patch: (row: MboxRow) => MboxRow): Promise<boolean> {
  for (let attempt = 0; attempt < 10; attempt++) {
    const cur = await KV.get<MboxRow>(mboxKey(m));
    if (!cur.value) return false;
    if ((await KV.atomic().check(cur).set(mboxKey(m), patch(cur.value)).commit()).ok) return true;
  }
  return false;
}
/** ends a mailbox: the row goes and the id is retired in one step, then its envelopes and files.
 *  b77r1 (audit R-7): `stillDue`, when given, is evaluated on the row as re-read inside the retry
 *  loop — the sweeper passes "still idle", so a mailbox used after the sweep listed it is kept. */
async function endMailbox(m: string, stillDue?: (row: MboxRow) => boolean): Promise<boolean> {
  const rKey = await mboxRetiredKey(m);
  let done = false;
  for (let attempt = 0; attempt < 10 && !done; attempt++) {
    const cur = await KV.get<MboxRow>(mboxKey(m), { consistency: "strong" });
    if (!cur.value) break;
    if (stillDue && !stillDue(cur.value)) return false;
    done = (await KV.atomic().check(cur).delete(mboxKey(m)).set(rKey, 1, { expireIn: MBOX_RETIRED_TTL_MS }).commit()).ok;
  }
  if (!done) return false;
  for await (const ix of KV.list({ prefix: ["env_by_mbox", m] }, { consistency: "strong" })) {
    const key: Deno.KvKey = ["entity", "VeilEnvelope", String(ix.key[2])];
    const got = await KV.get<Record<string, unknown>>(key);
    if (got.value && String(got.value.mbox || "") === m) await deleteEnvelopeRow(key, got.value);
    else await KV.delete(ix.key);
  }
  // b77r1 (audit R-6): this mailbox's files through ["blob_by_mbox", btag, id] (it used to scan
  // every blob_mbox row on the relay)
  const tag = await mboxTag(m), btag = await blobMboxTag(m);
  for await (const e of KV.list({ prefix: ["blob_by_mbox", btag] }, { consistency: "strong" })) {
    const id = String(e.key[2]);
    const bound = await KV.get<string>(["blob_mbox", id]);
    if (bound.value === btag) {
      const p = blobPathOf("blob:" + id);
      if (p) await Deno.remove(p).catch(() => undefined);
      await KV.atomic().check(bound).delete(["blob_mbox", id]).delete(e.key).commit();
    } else await KV.delete(e.key);
  }
  await KV.delete(["push_coalesce_mbox", tag]);
  await KV.delete(["call_ring", "mb_" + tag]);
  exactWakeAt.delete("c" + tag); exactWakeAt.delete("r" + tag); // b77q (audit 3 RF-2)
  return true;
}
/** the sweeper: mailboxes idle for MBOX_IDLE_MS are ended (retired) (b77p: open tickets are gone; spent open
 *  tokens expire with their key) */
async function sweepIdleMailboxes(now: number): Promise<number> {
  let n = 0;
  const idle = (row: MboxRow) => now - Number(row?.last_hour || 0) > MBOX_IDLE_MS;
  for await (const e of KV.list<MboxRow>({ prefix: ["mbox"] }, { consistency: "strong" })) {
    // b77r1 (audit R-7): idleness is judged again on the row endMailbox re-reads
    if (!e.value || idle(e.value)) { if (await endMailbox(String(e.key[1]), idle)) n++; }
  }
  // b77 legacy tickets (transition window): expired ones go (after the window migrateB77pLinks drops them all)
  for await (const e of KV.list<{ exp?: number }>({ prefix: ["mbox_ticket"] }, { consistency: "strong" })) {
    if (Number(e.value?.exp || 0) < now) await KV.delete(e.key);
  }
  return n;
}
// ---- b77r1 (audit R-5): the per-network "sealed-any" budget (see SEALED_ANY_PER_NETWORK_PER_MIN) ----
let sealedAnyWindow = 0;
const sealedAnyUse = new Map<string, number>();
/** a 2xx answer that still counts as a miss (sealedEnd on a never-opened mailbox, A-4) */
const sealedMissAnswers = new WeakSet<Response>();
const sealedMiss = (r: Response): Response => { sealedMissAnswers.add(r); return r; };
type SealedAnyKey = { k: string; cap: number };
async function sealedAnyKeys(req: Request): Promise<SealedAnyKey[]> {
  const net = await clientTag(req);
  if (net === "local") return [];
  const out: SealedAnyKey[] = [{ k: net, cap: SEALED_ANY_PER_NETWORK_PER_MIN }];
  for (const w of await clientWideTags(req)) out.push({ k: w.bits + ":" + w.tag, cap: SEALED_ANY_PER_NETWORK_PER_MIN * WIDE_FACTOR[w.bits] });
  return out;
}
/** b77r3 (audit R3-1): the units given back this minute for route-limiter 429s, per bucket */
const sealedAnyRefunds = new Map<string, number>();
function sealedAnyRoll(): void {
  const w = Math.floor(Date.now() / 60_000);
  if (w !== sealedAnyWindow) { sealedAnyWindow = w; sealedAnyUse.clear(); sealedAnyRefunds.clear(); }
}
/** b77r3 (audit R3-2): the overflow shard for a request: a hash of its widest key's tag (the last
 *  of `keys`: /48, else /56, else /64 or IPv4). The tags are HMAC output, so their hex tail is uniform. */
function sealedAnyOverflowKey(keys: SealedAnyKey[]): SealedAnyKey {
  const tag = keys[keys.length - 1].k;
  const h = parseInt(tag.slice(-6), 16);
  return { k: "overflow:" + ((Number.isFinite(h) ? h : 0) % SEALED_ANY_OVERFLOW_SHARDS), cap: SEALED_ANY_OVERFLOW_PER_MIN };
}
/** b77r2 (audit R2-R-5): the buckets this request is counted in — every key while there is room to
 *  track them. b77r3 (audit R3-2): with the map full, only the keys already tracked (the /48 or /56
 *  bounds a new /64 inside it), and the overflow shard only when none of them is tracked. */
function sealedAnySlots(keys: SealedAnyKey[]): SealedAnyKey[] {
  sealedAnyRoll();
  if (!keys.length) return [];
  const tracked = keys.filter((key) => sealedAnyUse.has(key.k));
  if (tracked.length === keys.length || sealedAnyUse.size < SEALED_ANY_TRACK_MAX) return keys;
  if (tracked.length) return tracked;
  return [sealedAnyOverflowKey(keys)];
}
function sealedAnyCharge(slots: SealedAnyKey[], n: number): void {
  sealedAnyRoll();
  for (const { k } of slots) {
    const v = (sealedAnyUse.get(k) ?? 0) + n;
    if (v <= 0) sealedAnyUse.delete(k); else sealedAnyUse.set(k, v);
  }
}
/** b77r3 (audit R3-1): gives a route-limiter 429 its unit back while every bucket it was charged
 *  to has had fewer than its cap (the budget once more) of such refunds this minute; past that the
 *  refused calls are charged like any other, so they meet the budget and are then refused before
 *  the body is parsed. Unlimited refunds let one network hammer a route past its per-mailbox limit
 *  for ever (each refused call still parsed JSON and did strong KV reads). */
function sealedAnyRefund(slots: SealedAnyKey[]): void {
  sealedAnyRoll();
  if (slots.some(({ k, cap }) => (sealedAnyRefunds.get(k) ?? 0) >= cap)) return;
  // b77r3 (verify R3V-1): a refund takes its use entry to 0 (deleted), so refunds alone never fill
  // the use map; the refund map is bounded by TRACK_MAX itself — past it a new key gets no refund
  if (sealedAnyRefunds.size >= SEALED_ANY_TRACK_MAX && slots.some(({ k }) => !sealedAnyRefunds.has(k))) return;
  for (const { k } of slots) sealedAnyRefunds.set(k, (sealedAnyRefunds.get(k) ?? 0) + 1);
  sealedAnyCharge(slots, -1);
}
/** runs a sealed route behind the budget: refused once spent; charged 1, and a miss more.
 *  b77r2 (audit R2-R-4): a 429 from the route's own limiters (or quotas) gives its 1 back — the
 *  refused calls of a network already at a per-route cap used to drain the shared budget and
 *  then block that network's other sealed routes too. (A miss is never refunded.)
 *  b77r3 (audit R3-1): at most the budget again in refunds per bucket per minute (sealedAnyRefund),
 *  so a network's route calls stay bounded at twice its budget a minute. */
async function sealedGuarded(req: Request, run: () => Promise<Response>): Promise<Response> {
  const slots = sealedAnySlots(await sealedAnyKeys(req));
  if (slots.some(({ k, cap }) => (sealedAnyUse.get(k) ?? 0) >= cap)) {
    return sealedErr(429, "Too many requests from this network — try again later", { locked: true, retry_minutes: 1 });
  }
  sealedAnyCharge(slots, 1);
  let res: Response;
  try { res = await run(); } catch (e) { sealedAnyCharge(slots, SEALED_MISS_WEIGHT - 1); throw e; } // a malformed body (400)
  if (res.status === 400 || res.status === 410 || res.status === 425 || sealedMissAnswers.has(res)) sealedAnyCharge(slots, SEALED_MISS_WEIGHT - 1);
  else if (res.status === 429) sealedAnyRefund(slots);
  return res;
}
function sealedRoute(name: string, handler: (req: Request, body: Record<string, any>) => Promise<Response>) {
  route("POST", "/api/apps/:appId/functions/" + name, (req) => sealedGuarded(req, async () => handler(req, await readJson(req))));
}

// ---- b77p (audit 2 VAR-01): blind open tokens and sealed wake boxes (spec §12.19) ----
/** an issuer key issues open signatures this long, and is accepted for opens MBOX_TICKET_TTL_MS + 1 h beyond */
const OPEN_KEY_ISSUE_MS = Number(Deno.env.get("VEIL_OPEN_KEY_ISSUE_MS")) || 7 * 86400_000;
const OPEN_KEY_ACCEPT_EXTRA_MS = MBOX_TICKET_TTL_MS + 3600_000;
const OPEN_TOKEN_LABEL = "vardum-open-token/v1";
type OpenKeyRow = { n: string; e: string; d: string; p: string; q: string; dp: string; dq: string; qi: string; from: number; until: number };
type OpenKeyNum = { kid: string; row: OpenKeyRow; n: bigint; e: bigint; d: bigint; p: bigint; q: bigint; dp: bigint; dq: bigint; qi: bigint; k: number };
const openKeyMem = new Map<string, OpenKeyNum>();
const b64uBytes = (s: string): Uint8Array => upB64uDecode(s);
const bytesB64u = (b: Uint8Array): string => { let t = ""; for (let i = 0; i < b.length; i += 0x2000) t += String.fromCharCode(...b.subarray(i, i + 0x2000)); return btoa(t).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""); };
const os2ip = (b: Uint8Array): bigint => { let h = ""; for (const x of b) h += x.toString(16).padStart(2, "0"); return h ? BigInt("0x" + h) : 0n; };
function i2osp(v: bigint, len: number): Uint8Array {
  const h = v.toString(16).padStart(len * 2, "0");
  if (h.length > len * 2) throw new Error("integer too large");
  const out = new Uint8Array(len);
  for (let i = 0; i < len; i++) out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  return out;
}
function bigPow(b: bigint, e: bigint, m: bigint): bigint {
  let r = 1n; b %= m; if (b < 0n) b += m;
  while (e > 0n) { if (e & 1n) r = (r * b) % m; b = (b * b) % m; e >>= 1n; }
  return r;
}
async function openKeyNum(kid: string, row: OpenKeyRow): Promise<OpenKeyNum> {
  const hit = openKeyMem.get(kid);
  if (hit && hit.row.until === row.until) return hit;
  const nb = b64uBytes(row.n);
  const v: OpenKeyNum = { kid, row, n: os2ip(nb), e: os2ip(b64uBytes(row.e)), d: os2ip(b64uBytes(row.d)), p: os2ip(b64uBytes(row.p)), q: os2ip(b64uBytes(row.q)), dp: os2ip(b64uBytes(row.dp)), dq: os2ip(b64uBytes(row.dq)), qi: os2ip(b64uBytes(row.qi)), k: nb.length };
  openKeyMem.set(kid, v);
  return v;
}
/**
 * b77p round 2 (owner decision 3, 31 Oct): THE ISSUER KEY LIVES IN A FILE, NEVER IN THE DATABASE. It was the
 * ["open_key", kid] / ["open_key_current"] rows, so every database copy and every backup held a key that mints
 * mailbox opens. Now VEIL_OPEN_ISSUER_KEY_FILE names a JSON file (mode 600, written atomically, like the
 * network-tag key file): {v: 1, current: kid, keys: {kid: {n, e, d, p, q, dp, dq, qi, from, until}}} holding the
 * CURRENT key and at most the PREVIOUS one. A key issues for OPEN_KEY_ISSUE_MS (7 days); then the relay makes a new
 * one, keeps the old one as "previous" (still accepted for opens until the next rotation, or until its own
 * acceptance window ends, whichever is first) and rewrites the file. (b77p: backup.sh never copied it; see below.)
 * b77q owner (1 Nov): backup.sh copies it now, inside the age-encrypted archive only (never an unencrypted run, never the
 * pre-update backup), so a rebuilt relay keeps its key and phones don't stall on a new one.
 *  - production (VAR-33's rule: VEIL_ENV=production or an https public origin) REFUSES TO START (exit 78) without the
 *    setting, or when the file is missing, unreadable or malformed: deploy-relay.sh generates it on the first deploy
 *    (relay/gen-open-issuer-key.ts);
 *  - a test relay (not production) without the setting makes an ephemeral key in memory (gone at a restart: an open
 *    token not yet redeemed then gets 403 and the phone asks again); with the setting and no file yet, it creates it.
 * Old database rows (["open_key", kid], ["open_key_current"]) are deleted at boot (dropOpenKeyRows).
 */
const OPEN_ISSUER_KEY_FILE = (Deno.env.get("VEIL_OPEN_ISSUER_KEY_FILE") || "").trim();
const OPEN_KEYS_KEPT = 2; // current + previous
const openKeyStore: { current: string | null; keys: Map<string, OpenKeyRow> } = { current: null, keys: new Map() };
const OPEN_KEY_ROW_FIELDS = ["n", "e", "d", "p", "q", "dp", "dq", "qi"] as const;
const isOpenKeyRow = (v: unknown): v is OpenKeyRow => {
  const r = v as Record<string, unknown> | null;
  return !!r && typeof r === "object" && OPEN_KEY_ROW_FIELDS.every((f) => typeof r[f] === "string" && /^[A-Za-z0-9_-]{1,1200}$/.test(r[f] as string))
    && Number.isFinite(r.from) && Number.isFinite(r.until) && Number(r.until) > Number(r.from);
};
async function openKidOf(nB64u: string): Promise<string> {
  return [...new Uint8Array(await crypto.subtle.digest("SHA-256", b64uBytes(nB64u) as BufferSource))].slice(0, 8).map((b) => b.toString(16).padStart(2, "0")).join("");
}
/** reads and checks the key file (every kid must be its modulus' id; at most two keys; the current one present) */
async function readOpenKeyFile(path: string): Promise<{ current: string; keys: Map<string, OpenKeyRow> }> {
  const parsed = JSON.parse(await Deno.readTextFile(path)) as { v?: unknown; current?: unknown; keys?: Record<string, unknown> };
  if (parsed?.v !== 1 || typeof parsed.current !== "string" || !parsed.keys || typeof parsed.keys !== "object") throw new Error("not a v1 issuer key file");
  const keys = new Map<string, OpenKeyRow>();
  for (const [kid, row] of Object.entries(parsed.keys)) {
    if (!isOpenKeyRow(row)) throw new Error("a key entry is malformed");
    if (await openKidOf(row.n) !== kid) throw new Error("a key id does not match its modulus");
    keys.set(kid, { n: row.n, e: row.e, d: row.d, p: row.p, q: row.q, dp: row.dp, dq: row.dq, qi: row.qi, from: Number(row.from), until: Number(row.until) });
  }
  if (!keys.has(parsed.current) || keys.size > OPEN_KEYS_KEPT) throw new Error("the current key is missing, or more than two keys");
  return { current: parsed.current, keys };
}
let openKeyFileWarned = false;
/** b77p round 2 (review L1): the file is behind memory (a write failed) — retried by the sweeper and, at most every
 *  OPEN_KEY_FILE_RETRY_MS, when the key is used */
let openKeyFileDirty = false;
let openKeyFileLastTry = 0;
const OPEN_KEY_FILE_RETRY_MS = 30_000;
/** the in-memory keys back to the file (tmp + rename, mode 600); memory-only relays write nothing. false = not written */
async function writeOpenKeyFile(): Promise<boolean> {
  if (!OPEN_ISSUER_KEY_FILE) return true;
  openKeyFileLastTry = Date.now();
  const keys: Record<string, OpenKeyRow> = {};
  for (const [kid, row] of openKeyStore.keys) keys[kid] = row;
  const tmp = OPEN_ISSUER_KEY_FILE + ".tmp";
  try {
    await Deno.writeTextFile(tmp, JSON.stringify({ v: 1, current: openKeyStore.current, keys }), { mode: 0o600 });
    try { await Deno.chmod(tmp, 0o600); } catch { /* not supported here (Windows) */ }
    await Deno.rename(tmp, OPEN_ISSUER_KEY_FILE);
    if (openKeyFileDirty) console.log(`[open-key] issuer key file written (current ${openKeyStore.current}) — memory and file agree again`);
    openKeyFileWarned = false; openKeyFileDirty = false;
    return true;
  } catch (e) {
    // the keys stay in memory (opens keep working until a restart) and the write is retried. b77p round 2 (review
    // L1): a production relay says so at EVERY failed attempt — a restart before the file is written loses the new
    // key, and every token issued under it then fails (the phones re-issue, within OPEN_ISSUES_PER_SIDE); a test
    // relay once per failure streak
    openKeyFileDirty = true;
    if (!openKeyFileWarned || productionRefusals(Deno.env.toObject()).production) console.error(`[open-key] ISSUER KEY FILE NOT WRITTEN (${(e as Error).name}) — the current key ${openKeyStore.current} is in memory only and is lost at a restart; retrying. Fix ${OPEN_ISSUER_KEY_FILE}'s folder permissions`);
    openKeyFileWarned = true;
    return false;
  }
}
/** b77p round 2 (review L1): a write that failed, tried again (one at a time, at most every OPEN_KEY_FILE_RETRY_MS) */
async function retryOpenKeyFile(): Promise<void> {
  if (!openKeyFileDirty || Date.now() - openKeyFileLastTry < OPEN_KEY_FILE_RETRY_MS) return;
  await withOpenKeyLock(async () => { if (openKeyFileDirty) await writeOpenKeyFile(); });
}
/** a fresh issuer key (RSA-2048, e = 65537), issuing from now for OPEN_KEY_ISSUE_MS */
async function makeOpenKey(now: number): Promise<{ kid: string; row: OpenKeyRow }> {
  const kp = await crypto.subtle.generateKey({ name: "RSA-PSS", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, true, ["sign", "verify"]) as CryptoKeyPair;
  const jwk = await crypto.subtle.exportKey("jwk", kp.privateKey) as Record<string, string>;
  return { kid: await openKidOf(jwk.n), row: { n: jwk.n, e: jwk.e, d: jwk.d, p: jwk.p, q: jwk.q, dp: jwk.dp, dq: jwk.dq, qi: jwk.qi, from: now, until: now + OPEN_KEY_ISSUE_MS } };
}
/** one rotation at a time (the relay is one process, b75r2) */
let openKeyLock: Promise<unknown> = Promise.resolve();
function withOpenKeyLock<T>(fn: () => Promise<T>): Promise<T> {
  const p = openKeyLock.then(fn, fn);
  openKeyLock = p.catch(() => undefined);
  return p;
}
/** the key that issues now: the file's current key, or — once it stops issuing — a new one (the old one is kept as
 *  the previous key; anything older leaves the file) */
async function currentOpenKey(): Promise<OpenKeyNum> {
  const live = () => { const k = openKeyStore.current; const row = k ? openKeyStore.keys.get(k) : undefined; return k && row && row.until > Date.now() ? { k, row } : null; };
  const hit = live();
  if (hit && openKeyFileDirty) void retryOpenKeyFile().catch(() => undefined); // b77p round 2 (review L1)
  if (hit) return await openKeyNum(hit.k, hit.row);
  return await withOpenKeyLock(async () => {
    const again = live();
    if (again) return await openKeyNum(again.k, again.row);
    const now = Date.now();
    const made = await makeOpenKey(now);
    const prev = openKeyStore.current;
    const keep = new Map<string, OpenKeyRow>();
    keep.set(made.kid, made.row);
    const prevRow = prev ? openKeyStore.keys.get(prev) : undefined;
    if (prev && prevRow && now <= prevRow.until + OPEN_KEY_ACCEPT_EXTRA_MS) keep.set(prev, prevRow);
    for (const k of openKeyStore.keys.keys()) if (!keep.has(k)) openKeyMem.delete(k);
    openKeyStore.keys = keep;
    openKeyStore.current = made.kid;
    await writeOpenKeyFile();
    console.log(`[open-key] new issuer key ${made.kid}${prev ? ` (previous ${prev} still accepted)` : ""}${OPEN_ISSUER_KEY_FILE ? "" : " — memory only (test relay)"}`);
    return await openKeyNum(made.kid, made.row);
  });
}
/** a key still accepted for opens (the current or previous one, within OPEN_KEY_ISSUE_MS + OPEN_KEY_ACCEPT_EXTRA_MS of
 *  its start), or null */
async function acceptedOpenKey(kid: unknown): Promise<OpenKeyNum | null> {
  if (typeof kid !== "string" || !/^[0-9a-f]{16}$/.test(kid)) return null;
  const row = openKeyStore.keys.get(kid);
  if (!row || Date.now() > row.until + OPEN_KEY_ACCEPT_EXTRA_MS) return null;
  return await openKeyNum(kid, row);
}
/** the sweeper: a previous key past its acceptance window leaves memory and the file (spent markers expire alone) */
async function sweepOpenKeys(now: number): Promise<number> {
  return await withOpenKeyLock(async () => {
    let n = 0;
    for (const [kid, row] of [...openKeyStore.keys]) {
      if (kid !== openKeyStore.current && now > row.until + OPEN_KEY_ACCEPT_EXTRA_MS) { openKeyStore.keys.delete(kid); openKeyMem.delete(kid); n++; }
    }
    if (n || openKeyFileDirty) await writeOpenKeyFile(); // b77p round 2 (review L1): and a write that failed, at every sweep
    return n;
  });
}
/** boot: the issuer key file is loaded (production: it must be there, or the relay refuses to start), and the
 *  database rows an earlier b77p build kept the key in are deleted */
async function loadOpenIssuerKey(): Promise<void> {
  const production = productionRefusals(Deno.env.toObject()).production;
  const refuse = (why: string): never => {
    console.error(`[relay] REFUSING TO START: production relay without a usable open-token issuer key file (${why}). Generate it once with: deno run --allow-read=<file> --allow-write=<file> gen-open-issuer-key.ts <file> (deploy-relay.sh does), set VEIL_OPEN_ISSUER_KEY_FILE=<file>, owned by the relay user, mode 600, never in the database (backup.sh copies it only inside the age-encrypted archive).`); // b77t merge (audit 5 IH I-03): it said "never in a backup"
    Deno.exit(78);
  };
  if (!OPEN_ISSUER_KEY_FILE) {
    if (production) refuse("VEIL_OPEN_ISSUER_KEY_FILE is not set");
    console.warn("[relay] VEIL_OPEN_ISSUER_KEY_FILE is not set: the open-token issuer key is EPHEMERAL (memory only; test relays only — production refuses to start without it)");
  } else {
    try {
      const got = await readOpenKeyFile(OPEN_ISSUER_KEY_FILE);
      openKeyStore.current = got.current; openKeyStore.keys = got.keys;
      console.log(`[relay] open-token issuer key file loaded (${got.keys.size} key(s), current ${got.current})`);
    } catch (e) {
      const missing = e instanceof Deno.errors.NotFound;
      if (production) refuse(missing ? "the file does not exist" : `the file is unusable: ${(e as Error).message}`);
      if (!missing) { console.error(`[relay] open-token issuer key file unusable (${(e as Error).message}) — refusing to overwrite it; fix or remove it`); Deno.exit(78); }
      console.warn("[relay] open-token issuer key file not found: creating it (test relay)");
    }
  }
  for await (const e of KV.list({ prefix: ["open_key"] }, { consistency: "strong" })) await KV.delete(e.key);
  await KV.delete(["open_key_current"]);
  await currentOpenKey();
}
/** the full-domain hash of a token value x (spec §12.19.2; crypto-core open-token.ts openTokenMessage) */
async function openTokenMessage(key: OpenKeyNum, x: string): Promise<bigint> {
  const seed = enc.encode(`${OPEN_TOKEN_LABEL}:${key.kid}:${x}`);
  const out = new Uint8Array(Math.ceil((key.k - 1) / 32) * 32);
  for (let i = 0; i * 32 < key.k - 1; i++) {
    const buf = new Uint8Array(seed.length + 4);
    buf.set(seed, 0); new DataView(buf.buffer).setUint32(seed.length, i);
    out.set(new Uint8Array(await crypto.subtle.digest("SHA-256", buf as BufferSource)), i * 32);
  }
  return os2ip(out.subarray(0, key.k - 1)) % key.n;
}
/** signs a blinded value (CRT), checked against the public key; null for a value out of range */
/** b77u (audit 6 L-8): the cheap checks openSignBlinded makes before any RSA work */
function openBlindShapeOk(key: OpenKeyNum, blindB64u: unknown): boolean {
  if (typeof blindB64u !== "string" || blindB64u.length > 700 || !/^[A-Za-z0-9_-]+$/.test(blindB64u)) return false;
  try { const c = os2ip(b64uBytes(blindB64u)); return c > 1n && c < key.n; } catch { return false; }
}
function openSignBlinded(key: OpenKeyNum, blindB64u: unknown): string | null {
  if (typeof blindB64u !== "string" || blindB64u.length > 700 || !/^[A-Za-z0-9_-]+$/.test(blindB64u)) return null;
  let c: bigint;
  try { c = os2ip(b64uBytes(blindB64u)); } catch { return null; }
  if (c <= 1n || c >= key.n) return null;
  const m1 = bigPow(c, key.dp, key.p), m2 = bigPow(c, key.dq, key.q);
  let h = (key.qi * (m1 - m2)) % key.p; if (h < 0n) h += key.p;
  const sig = m2 + h * key.q;
  if (bigPow(sig, key.e, key.n) !== c) return null; // (a fault never leaves the relay)
  return bytesB64u(i2osp(sig, key.k));
}
/** a redeemed token: {kid, x, s} valid under an accepted key -> its spent-marker key and expiry */
async function openTokenCheck(tok: unknown): Promise<{ spentKey: Deno.KvKey; expireIn: number } | null> {
  const t = tok as { kid?: unknown; x?: unknown; s?: unknown } | null;
  if (!t || typeof t !== "object" || typeof t.x !== "string" || !MBOX_HEX_RE.test(t.x) || typeof t.s !== "string" || t.s.length > 700 || !/^[A-Za-z0-9_-]+$/.test(t.s)) return null;
  const key = await acceptedOpenKey(t.kid);
  if (!key) return null;
  let sv: bigint;
  try { sv = os2ip(b64uBytes(t.s)); } catch { return null; }
  if (sv <= 0n || sv >= key.n) return null;
  if (bigPow(sv, key.e, key.n) !== await openTokenMessage(key, t.x)) return null;
  return { spentKey: ["open_spent", await sha256hex("veil-open-spent:" + key.kid + ":" + t.x)], expireIn: Math.max(60_000, key.row.until + OPEN_KEY_ACCEPT_EXTRA_MS - Date.now()) };
}
/** a blinded value's record on the rendezvous row (a hash of a uniformly random value: links to nothing) */
const openBlindHash = (blind: string) => sha256hex("veil-open-blind:" + blind);

/** b77p: wake caps — counted per (push address, mailbox) and per push address over every mailbox wake, under
 *  HMAC tags with a key made at start-up and never stored (a database copy can't test a token or mailbox against them) */
const WAKES_PER_ADDRESS_MAILBOX_PER_HOUR = Number(Deno.env.get("VEIL_WAKES_PER_ADDRESS_MAILBOX_PER_HOUR")) || 120;
const WAKES_PER_ADDRESS_PER_HOUR = Number(Deno.env.get("VEIL_WAKES_PER_ADDRESS_PER_HOUR")) || 600;
const wakeTagKey = crypto.subtle.generateKey({ name: "HMAC", hash: "SHA-256", length: 256 }, false, ["sign"]) as Promise<CryptoKey>;
async function wakeTag(v: string): Promise<string> {
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", await wakeTagKey, enc.encode("veil-wake:" + v)));
  return [...mac.slice(0, 16)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
const WAKE_BOX_LABEL = "vardum-wake-box/v1";
/** 'w1.' + base64 of 12 + 1024 + 16 bytes (crypto-core wake.ts WAKE_BOX_LENGTH) */
const WAKE_BOX_LENGTH = 3 + 4 * Math.ceil((12 + 1024 + 16) / 3);
const isWakeBox = (v: unknown): v is string => typeof v === "string" && v.length === WAKE_BOX_LENGTH && v.startsWith("w1.") && canonicalB64(v.slice(3));
/** b77u (audit 6 W6): `k` — the owner phone's wake key (32-64 hex, the same in every box that phone seals; a stranger who
 *  knows only the push address doesn't have it) */
type WakeTarget = { t: string; p?: string; a?: string; k?: string };
/** opens a mailbox's wake box with the wake capability the sender presented; null when it doesn't open */
async function openWakeBox(wakeCap: unknown, mbox: string, box: unknown): Promise<WakeTarget | null> {
  try {
    if (!isMboxHex(wakeCap) || !isWakeBox(box)) return null;
    const raw = b64d(box.slice(3));
    const info = enc.encode(`${WAKE_BOX_LABEL}/${mbox}`);
    const k = await upHkdf(enc.encode(WAKE_BOX_LABEL), enc.encode(wakeCap), info, 32);
    const key = await crypto.subtle.importKey("raw", k as BufferSource, "AES-GCM", false, ["decrypt"]);
    k.fill(0);
    const pt = new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: raw.subarray(0, 12) as BufferSource, additionalData: info as BufferSource }, key, raw.subarray(12) as BufferSource));
    const o = JSON.parse(new TextDecoder().decode(pt).trimEnd()) as Record<string, unknown>;
    if (o.v !== 1 || typeof o.t !== "string" || !o.t || o.t.length > 512) return null;
    return { t: o.t, ...(typeof o.p === "string" ? { p: o.p } : {}), ...(typeof o.a === "string" ? { a: o.a } : {}), ...(typeof o.k === "string" && /^[0-9a-f]{32,64}$/.test(o.k) ? { k: o.k } : {}) };
  } catch { return null; }
}
/** one wake push to a box's target (fire-and-forget by the caller): Expo, or a Web Push to an allowed
 *  UnifiedPush endpoint encrypted to the box's own keys. Nothing is written but the memory-keyed caps. */
/** b77t (audit 5 L-12, IH R-04): the push address the wake caps are keyed on, NORMALISED as the allow-list reads it
 *  (upEndpointAllowed): a UnifiedPush URL by its lower-case host and its topic path only — so "https://NTFY.sh:443/t",
 *  "https://ntfy.sh/t?up=1" and "https://ntfy.sh/t" share one cap. An Expo token is used as it is. */
function wakeAddressKey(t: string): string {
  if (!t.startsWith(UP_TOKEN_PREFIX)) return t;
  try {
    const u = new URL(t.slice(UP_TOKEN_PREFIX.length));
    return UP_TOKEN_PREFIX + "https://" + u.hostname.toLowerCase() + u.pathname;
  } catch { return t; }
}
/** b77u2 (UC-L5): per push address (by memory-keyed tag), the wake keys that have a bucket of their own and when each
 *  was last seen. In memory only, like the tag key (a restart forgets both); bounded in size. */
const WAKE_KNOWN_KEYS_PER_ADDRESS = Number(Deno.env.get("VEIL_WAKE_KNOWN_KEYS_PER_ADDRESS")) || 3;
const WAKE_KNOWN_TTL_MS = 30 * 86400_000;
const WAKE_KNOWN_MAX_ADDRESSES = 200_000;
const wakeKnownKeys = new Map<string, Map<string, number>>();
async function wakeKeyKnown(addr: string, k: string): Promise<boolean> {
  const at = await wakeTag("kn:" + addr), kt = await wakeTag("kk:" + addr + ":" + k), now = Date.now();
  let m = wakeKnownKeys.get(at);
  if (!m) {
    if (wakeKnownKeys.size >= WAKE_KNOWN_MAX_ADDRESSES) { const oldest = wakeKnownKeys.keys().next().value; if (oldest !== undefined) wakeKnownKeys.delete(oldest); }
    m = new Map();
    wakeKnownKeys.set(at, m);
  }
  for (const [t, seen] of m) if (now - seen > WAKE_KNOWN_TTL_MS) m.delete(t);
  if (m.has(kt) || m.size < WAKE_KNOWN_KEYS_PER_ADDRESS) { m.set(kt, now); return true; }
  return false;
}
async function sendWake(target: WakeTarget, mtag: string, upKind: "call" | "new-message"): Promise<string> {
  const addr = wakeAddressKey(target.t);
  // b77u (audit 6 W6, IH full L-3): the per-address ceiling is keyed on the address AND the owner phone's wake key (box
  // field `k`). It was the address alone, over every mailbox, with no proof of ownership: anyone who knew a phone's push
  // token sealed boxes naming it into mailboxes of their own and spent its 600 wakes an hour, silencing every real wake.
  // A stranger without the key now fills only a bucket of its own; the per-(address, mailbox) cap below is unchanged. A
  // box without a key (an older app) keeps the shared address bucket.
  // b77u2 (UC-L5): but `k` is chosen by whoever seals the box, so a stranger with many k values had many buckets. Only
  // the first WAKE_KNOWN_KEYS_PER_ADDRESS keys seen for an address (kept while used within 30 days) have a bucket of
  // their own; every other key shares ONE "unproven" bucket per address (apart from the no-key bucket). An address
  // now gets at most (WAKE_KNOWN_KEYS_PER_ADDRESS + 2) x WAKES_PER_ADDRESS_PER_HOUR wakes an hour, and the owner
  // phone's key, in use since before a stranger turned up, keeps its own bucket.
  const at = await wakeTag(!target.k ? "a:" + addr : (await wakeKeyKnown(addr, target.k)) ? "a:" + addr + ":k:" + target.k : "a:" + addr + ":unproven");
  // (a push runs after the submit answered: a transient "database is locked" — another handle mid-write — is retried
  // rather than dropping the wake)
  const limited = async (key: string, cap: number) => {
    for (let attempt = 1; ; attempt++) {
      try { return !!(await rateLimit(key, cap, 3600_000, 0)); } catch (e) {
        if (attempt >= 6 || !isKvLocked(e)) throw e;
        await new Promise((res) => setTimeout(res, 20 * 2 ** attempt));
      }
    }
  };
  if (await limited("wakeaddr:" + at, WAKES_PER_ADDRESS_PER_HOUR)) return "capped";
  if (await limited("wakebox:" + await wakeTag("m:" + addr + ":" + mtag), WAKES_PER_ADDRESS_MAILBOX_PER_HOUR)) return "capped";
  if (target.t.startsWith(UP_TOKEN_PREFIX)) {
    const url = target.t.slice(UP_TOKEN_PREFIX.length);
    if (!upEndpointAllowed(url)) return "up-host-not-allowed";
    if (!upKeysValid(target.p, target.a)) return "up-no-keys";
    const body = await webPushEncrypt(String(target.p), String(target.a), upTe.encode(JSON.stringify({ kind: upKind, t: Date.now() }).padEnd(UP_PLAINTEXT_LEN)));
    const r = await fetch(url, { method: "POST", headers: { "TTL": "86400", "Urgency": "high", "Content-Encoding": "aes128gcm", "Content-Type": "application/octet-stream" }, body: body as unknown as BodyInit, redirect: "manual", signal: AbortSignal.timeout(10_000) });
    await r.body?.cancel().catch(() => undefined);
    return r.ok ? "ok" : "up-http-" + r.status;
  }
  const res = await fetch(EXPO_PUSH_URL, { ...activityPush(target.t, upKind === "call"), signal: AbortSignal.timeout(10_000) });
  return expoTicketLog(await res.json().catch(() => null), res.status); // b77m (audit VAR-46): never Expo's message
}
/** b77t (audit 5 L-30, IH I-02): NO log line per wake. Each wake used to log "[push] wake: <status>", and journald
 *  timestamps every line, so the log held the time of every notified message and call (spec §12.18: the sealed routes
 *  log nothing per request; §12.19.1: nothing about a push is written down). The outcomes are now counted in memory
 *  and logged as ONE line of totals per hour (no times, no mailboxes, no addresses), and only when there were any. */
const wakeOutcomes = new Map<string, number>();
const WAKE_SUMMARY_MS = 3600_000;
function noteWake(kind: "wake" | "ring", status: string): void {
  const k = kind + ":" + String(status).replace(/[^a-z0-9-]/gi, "").slice(0, 32);
  wakeOutcomes.set(k, (wakeOutcomes.get(k) ?? 0) + 1);
}
{
  const t = setInterval(() => {
    if (!wakeOutcomes.size) return;
    const parts = [...wakeOutcomes.entries()].sort().map(([k, n]) => `${k}=${n}`);
    wakeOutcomes.clear();
    console.log("[push] wake totals, last hour: " + parts.join(" "));
  }, WAKE_SUMMARY_MS);
  try { Deno.unrefTimer(t); } catch { /* older Deno: the server keeps running anyway */ }
}
function wakeOnce(target: WakeTarget, mtag: string): void {
  void sendWake(target, mtag, "new-message").then((st) => noteWake("wake", st)).catch(() => noteWake("wake", "error"));
}
function wakeRing(target: WakeTarget, mtag: string): void {
  void (async () => {
    for (let i = 0; i < CALL_BURST_COUNT; i++) {
      if (i > 0) await new Promise((res) => setTimeout(res, CALL_BURST_GAP_MS));
      const st = await sendWake(target, mtag, "call").catch(() => "error");
      if (i === 0) noteWake("ring", st);
    }
  })().catch(() => undefined);
}

// ---- openKey {} — the open-token issuer key (b77p) ----
sealedRoute("openKey", async (req) => {
  { const lim = await sealedNetLimited(req, "openkey", SEALED_CONTROL_PER_NETWORK_PER_MIN, 60_000); if (lim) return lim; }
  const key = await currentOpenKey();
  return json({ kid: key.kid, n: key.row.n, e: key.row.e, until: key.row.until });
});

// ---- mailboxOpen {mbox, send_hash, read_hash, open_token: {kid, x, s}, ttl_cap_s} ----
// b77p (audit 2 VAR-01): a blind-signed open token (issued at the join / gate issue on a value the relay never saw)
// replaces the ticket whose hash rode the join next to the rendezvous token
// b77p round 2 (owner decision 4): during the transition window a LEGACY (pre-b77p) phone opens with the one-time
// ticket its join stored (b77's path, unchanged); never both, and never after VEIL_COMPAT_UNTIL
sealedRoute("mailboxOpen", async (req, body) => {
  const { mbox, send_hash, read_hash } = body;
  // b77u (audit 6 W4): optional own_hash (64 hex, unlike the other two): the owner-only operations then need own_cap
  const own_hash = body.own_hash === undefined || body.own_hash === null ? undefined : body.own_hash;
  if (own_hash !== undefined && (!isMboxHex(own_hash) || own_hash === send_hash || own_hash === read_hash)) return sealedErr(400, "Invalid mailbox fields");
  const legacy = body.ticket !== undefined;
  if (legacy && body.open_token !== undefined) return sealedErr(400, "An open takes an open_token or (older apps) a ticket, not both");
  if (legacy && !compatOn()) return sealedErr(400, "Update Vardum: mailbox tickets are retired");
  if (legacy && !isMboxHex(body.ticket)) return sealedErr(400, "Invalid mailbox fields");
  if (![mbox, send_hash, read_hash].every(isMboxHex)) return sealedErr(400, "Invalid mailbox fields");
  if (!legacy && (!body.open_token || typeof body.open_token !== "object")) return sealedErr(400, "Missing open_token");
  if (send_hash === read_hash) return sealedErr(400, "The send and read capabilities must differ");
  { const lim = await sealedNetLimited(req, "mboxopen", SEALED_OPENS_PER_NETWORK_PER_HOUR, 3600_000); if (lim) return lim; }
  const ttlIn = Number(body.ttl_cap_s);
  const ttl_cap_s = Number.isFinite(ttlIn) ? Math.min(MBOX_TTL_CAP_MAX_S, Math.max(MBOX_TTL_CAP_MIN_S, Math.floor(ttlIn))) : MBOX_TTL_CAP_MAX_S;
  const rKey = await mboxRetiredKey(mbox);
  if (await legacyRetired(mbox)) return sealedErr(410, "This chat has ended", { ended: true }); // b77r2 (audit R2-R-3)
  let tokenOk: { spentKey: Deno.KvKey; expireIn: number } | null | undefined;
  const tKey = legacy ? mboxTicketKey(await capHash(body.ticket)) : null;
  for (let attempt = 0; attempt < 10; attempt++) {
    const [mb, rt] = await Promise.all([KV.get(mboxKey(mbox)), KV.get(rKey)]);
    if (retiredLive(rt.value)) {
      // b77r2 (audit R2-R-1): a pre-open marker ends only the mailbox whose open names the
      // capability that ended it (the peer ends with its send cap, the owner with its read cap).
      // One written with any other capability is not this mailbox's end: the open replaces it.
      // b77r3 (audit R3-3): either of its (at most two) capability hashes counts.
      const pre = asPreRetired(rt.value);
      // b77u (audit 6, IH relay F-08): and a marker whose BOTH slots are taken ends it too — two junk ends written first
      // used to fill them, so the peer's real end recorded nothing and the open then went through
      if (!pre || preNames(pre, send_hash) || preNames(pre, read_hash) || typeof pre.cap_h2 === "string") return sealedErr(410, "This chat has ended", { ended: true });
    }
    // b77u (audit 6 W4): an open naming an own_hash learns whether the open mailbox is ITS (a retry after a lost answer:
    // owned true) or someone else's (owned false: another party — e.g. a peer that derived the id — opened it first)
    if (mb.value) return sealedErr(409, "This mailbox is already open", own_hash !== undefined ? { owned: typeof (mb.value as MboxRow).own_hash === "string" && ctEq(String((mb.value as MboxRow).own_hash), own_hash) } : {});
    if (tKey) {
      // b77 legacy: the ticket is consumed, and the mailbox created, in ONE step (a second open of either loses)
      const tk = await KV.get<{ exp?: number }>(tKey);
      if (!tk.value || Number(tk.value.exp || 0) < Date.now()) {
        if (tk.value) await KV.atomic().check(tk).delete(tKey).commit();
        return sealedErr(403, "Invalid or used ticket");
      }
      const now = Date.now();
      const row: MboxRow = { send_hash, read_hash, ...(own_hash ? { own_hash } : {}), ttl_cap_s, verified: false, last_hour: hourFloor(now), next_seq: 1, created_day: statDay(now) };
      const tx = KV.atomic().check(tk).check(mb).check(rt).delete(tKey).set(mboxKey(mbox), row);
      if (rt.value) tx.delete(rKey);
      if ((await tx.commit()).ok) return json({ ok: true });
      continue;
    }
    if (tokenOk === undefined) tokenOk = await openTokenCheck(body.open_token);
    if (!tokenOk) return sealedErr(403, "Invalid or used open token");
    const spent = await KV.get(tokenOk.spentKey);
    if (spent.value) return sealedErr(403, "Invalid or used open token");
    const now = Date.now();
    const row: MboxRow = { send_hash, read_hash, ...(own_hash ? { own_hash } : {}), ttl_cap_s, verified: false, last_hour: hourFloor(now), next_seq: 1, created_day: statDay(now) };
    // the token is spent, and the mailbox created, in ONE step (a second open of either loses)
    const tx = KV.atomic().check(spent).check(mb).check(rt).set(tokenOk.spentKey, 1, { expireIn: tokenOk.expireIn }).set(mboxKey(mbox), row);
    if (rt.value) tx.delete(rKey); // a lapsed or foreign pre-open marker (b77r2)
    const ok = await tx.commit();
    if (ok.ok) return json({ ok: true });
  }
  return sealedErr(503, "Busy — try again");
});

// ---- sealedSubmit {mbox, send_cap, wake_cap?, ciphertext, iv, header, byte_length, ttl_seconds, notify} ----
sealedRoute("sealedSubmit", async (req, body) => {
  const { mbox, send_cap, ciphertext, iv, header } = body;
  if (!isMboxHex(mbox)) return sealedErr(400, "Invalid mailbox");
  // nothing that names a chat, a side or an account rides a sealed envelope
  for (const f of ["session_token", "write_secret", "sender_client_id", "sender_pseudonym", "group_token", "client_id"]) {
    if (body[f] !== undefined) return sealedErr(400, `A sealed envelope takes no ${f}`);
  }
  if (typeof ciphertext !== "string" || !ciphertext || typeof iv !== "string" || !iv || typeof header !== "string") return sealedErr(400, "Missing envelope fields");
  if (ciphertext.length > 48000 || iv.length > 512) return sealedErr(413, "Envelope too large");
  if (!isSealedHeaderString(header)) return sealedErr(400, "Invalid message header (a veil-ratchet-8 header is exactly 5163 characters)");
  const notify = body.notify === undefined || body.notify === null ? false : body.notify;
  if (notify !== false && notify !== "msg" && notify !== "call") return sealedErr(400, "Invalid notify (false, 'msg' or 'call')");
  const byteLength = Number(body.byte_length);
  if (body.byte_length !== undefined && (!Number.isFinite(byteLength) || byteLength < 0 || byteLength > 64 * 1024 * 1024)) return sealedErr(400, "Invalid byte_length");
  const size = utf8Len(JSON.stringify(body ?? {}));
  if (size > 56000) return sealedErr(413, "Envelope too large");
  if (await kvStorageFull()) return sealedErr(507, STORAGE_FULL_MSG, { code: "storage_full" }); // b77n (pre-audit M1)
  const st = await mboxState(mbox);
  if (st.status !== "ok") return mboxGone(st);
  const mtag = await mboxTag(mbox);
  // b77u (audit 6 W5, IH relay F-04): the send cap BEFORE the mailbox's submit limiter — 60 junk submits a minute
  // (wrong cap) from whoever knows the id used to block every real incoming message
  { const lim = await sealedNetLimited(req, "sealednet", SEALED_SUBMITS_PER_NETWORK_PER_MIN, 60_000); if (lim) return lim; }
  if (!(await capMatches(send_cap, st.row.send_hash))) return sealedErr(403, "Invalid mailbox credential");
  { const lim = await mboxLimited("mboxsub:" + mtag, MBOX_SUBMITS_PER_MIN, 60_000); if (lim) return lim; }
  // life: the sender's ttl_seconds (the relay's 36 h default when absent), never past the
  // mailbox's ttl_cap_s (7 days at most)
  const ttlIn = Number(body.ttl_seconds);
  const ttl = Math.max(1, Math.min(Number.isFinite(ttlIn) && ttlIn > 0 ? ttlIn : RELAY_DEFAULT_ENVELOPE_LIFE_S, Number(st.row.ttl_cap_s) || MBOX_TTL_CAP_MAX_S, MBOX_TTL_CAP_MAX_S));
  // daily bytes: per mailbox, per network, relay-wide (one atomic step; nothing per account)
  const day = statDay();
  const qKey: Deno.KvKey = ["mbox_quota", mtag, day];
  const caps: [Deno.KvKey, number][] = [[qKey, MBOX_DAILY_BYTES], [["env_quota_all", day], ENVELOPE_RELAY_DAILY_BYTES]];
  const net = await clientTag(req);
  if (net !== "local") caps.push([["env_quota_net", net, day], ENVELOPE_NETWORK_DAILY_BYTES]);
  for (const w of await clientWideTags(req)) caps.push([["env_quota_net" + w.bits, w.tag, day], ENVELOPE_NETWORK_DAILY_BYTES * WIDE_FACTOR[w.bits]]);
  // b77r1 (audit R-1): past 60% of the relay-wide envelope total only LIGHT senders get through,
  // judged by the mailbox (under ENVELOPE_LIGHT_MBOX_BYTES today) AND by the caller's network
  // (under ENVELOPE_LIGHT_NETWORK_BYTES today; the /56, /48 at x4, x16) — mailboxes are cheap to
  // mint, so the mailbox alone would let one sender fill the relay with fresh ones and stop
  // every 1:1 chat for the rest of the UTC day. (submitEnvelope's group rule is unchanged.)
  const light: LightRule = { allKey: ["env_quota_all", day], allCap: ENVELOPE_RELAY_DAILY_BYTES, frac: LIGHT_RULE_FRACTION,
    heavy: [{ key: qKey, limit: ENVELOPE_LIGHT_MBOX_BYTES }, ...networkHeavy(caps, "env_quota_net", ENVELOPE_LIGHT_NETWORK_BYTES)] };
  // (several senders' submits can race on the relay-wide counter: a contended step is retried, never failed)
  let q = await adjustQuota(caps, size, light);
  for (let i = 0; i < 8 && q === "busy"; i++) { await new Promise((r) => setTimeout(r, 2 + Math.random() * 10)); q = await adjustQuota(caps, size, light); }
  if (q === "over") return sealedErr(429, "Daily message limit reached", { locked: true, retry_minutes: 60 });
  if (q === "busy") return sealedErr(503, "Busy — try again");
  // the sequence number is allocated, and the envelope and its index written, in ONE step
  const expiresAt = coarseExpiry(Date.now(), ttl); // b77n (pre-audit L2): rounded down (no exact submit time at rest)
  let stored: { id: string; row: MboxRow } | null = null;
  for (let attempt = 0; attempt < 100 && !stored; attempt++) {
    const cur = await KV.get<MboxRow>(mboxKey(mbox));
    if (!cur.value) break;
    const seq = Math.max(1, Math.floor(Number(cur.value.next_seq) || 1));
    const id = sealedEnvId(seq);
    const env = { id, mbox, seq, ciphertext, iv, header, byte_length: Number.isFinite(byteLength) ? byteLength : 0, protocolVersion: SEALED_PROTOCOL, expires_at: expiresAt };
    const next: MboxRow = { ...cur.value, next_seq: seq + 1 }; // b77g: a peer's submit is not owner activity (last_hour untouched)
    const tx = KV.atomic().check(cur).set(mboxKey(mbox), next).set(["entity", "VeilEnvelope", id], env);
    for (const k of envIndexKeys(env, id)) tx.set(k, 1);
    if ((await tx.commit()).ok) stored = { id, row: next };
    else await new Promise((r) => setTimeout(r, 1 + Math.random() * Math.min(20, 2 + attempt)));
  }
  if (!stored) {
    await adjustQuota(caps, -size).catch(() => undefined);
    const again = await mboxState(mbox);
    return again.status === "ok" ? sealedErr(503, "Busy — try again") : mboxGone(again);
  }
  void bumpStat("envelopes"); // includes cover traffic: the relay can't tell decoys apart
  // b77p: the wake capability (never stored) opens the recipient's sealed wake box for this push only
  if (notify !== false) { try { await sealedNotify(mbox, mtag, stored.row, notify, body.wake_cap); } catch { /* a push never fails a send */ } }
  return json({ id: stored.id });
});
/**
 * b77n (pre-audit L2): a 1:1 envelope's expires_at, rounded DOWN to a coarse step, so the row no longer gives its
 * exact submit time (expires_at − ttl, and the app's ttls are a few standard values). The step is the largest of
 * 1 h, 10 min, 1 min, 10 s, 1 s that is at most a tenth of the life: a 36 h or 7-day envelope gives its submit
 * hour only, a 1 h one its minute. Rounding DOWN never keeps a message past its dial (an envelope goes at most one
 * step — ≤ 10 % of its life, ≤ 1 h — early); rounding up would have kept a 60 s message up to twice as long. The
 * sweep and reads compare against expires_at as before.
 */
function coarseExpiry(nowMs: number, ttlS: number): string {
  const step = [3600_000, 600_000, 60_000, 10_000, 1000].find((s) => s <= ttlS * 100) ?? 1000;
  return new Date(Math.max(nowMs + 1000, Math.floor((nowMs + ttlS * 1000) / step) * step)).toISOString();
}
/** the recipient's wake: 'msg' → one "New activity" alert, coalesced per mailbox (30 s);
 *  'call' → the ring burst, only on a mailbox its owner marked verified, one burst per ring
 *  window and RINGS_PER_CHAT_PER_HOUR an hour, keyed on the mailbox tag */
async function sealedNotify(mbox: string, mtag: string, row: MboxRow, kind: "msg" | "call", wakeCap: unknown): Promise<void> {
  // b77p (audit 2 VAR-01): the target is sealed in the mailbox's own wake box (no push row, no account)
  const target = isWakeBox(row.wake) && isMboxHex(wakeCap) ? await openWakeBox(wakeCap, mbox, row.wake) : null;
  // b77p round 2 (owner decision 4): during the transition window a LEGACY mailbox (a push_ref, no wake box) wakes
  // the legacy push rows listing that ref, as b77 did (b77p phones never bind one)
  const legacyRef = !target && compatOn() && typeof row.push_ref === "string" ? row.push_ref : "";
  if (!target && !legacyRef) return;
  if (kind === "call") {
    if (row.verified !== true) return;
    const rk: Deno.KvKey = ["call_ring", "mb_" + mtag];
    const last = await KV.get<number>(rk);
    if (last.value && Date.now() - lastWakeAt("r" + mtag, last.value) < CALL_RING_WINDOW_MS) return;
    if (await rateLimit("ringcap:mb_" + mtag, RINGS_PER_CHAT_PER_HOUR, 3600_000, 0)) return;
    const at = Date.now();
    if (!(await KV.atomic().check(last).set(rk, coarseWakeAt(at), { expireIn: CALL_RING_WINDOW_MS * 3 }).commit()).ok) return; // b77q (audit 3 RF-2)
    noteWakeAt("r" + mtag, at);
    if (target) wakeRing(target, mtag); else ringPushTargets(await pushTargetsOfRef(legacyRef));
    return;
  }
  const ck: Deno.KvKey = ["push_coalesce_mbox", mtag];
  const last = await KV.get<number>(ck);
  if (last.value && Date.now() - lastWakeAt("c" + mtag, last.value) < 30_000) return;
  if (await rateLimit("mboxnotify:" + mtag, MBOX_NOTIFY_PER_MIN, 60_000, 0)) return;
  const at = Date.now();
  if (!(await KV.atomic().check(last).set(ck, coarseWakeAt(at), { expireIn: COALESCE_TTL_MS }).commit()).ok) return; // b77q (audit 3 RF-2)
  noteWakeAt("c" + mtag, at);
  if (target) wakeOnce(target, mtag); else alertPushTargets(await pushTargetsOfRef(legacyRef));
}
/**
 * b77q (audit 3 RF-2): the call-ring and push-coalesce rows held the exact millisecond of a submit (about 60 s and
 * 5 minutes), so a database snapshot taken then gave the exact time a message was sent or a call rung, though the
 * envelope itself keeps only a coarse expiry. The row now holds that time rounded DOWN to the minute; the exact time
 * stays in this process's memory only (keyed by row, dropped with the row), and is used only while it matches the
 * row. A row deleted (chat end, a test) stops the coalescing as before; after a restart the rounded time is used,
 * which can only shorten a window (one extra wake at most), never lengthen it.
 */
const WAKE_COARSE_MS = 60_000;
const coarseWakeAt = (t: number) => Math.max(WAKE_COARSE_MS, Math.floor(t / WAKE_COARSE_MS) * WAKE_COARSE_MS);
const exactWakeAt = new Map<string, number>();
function lastWakeAt(id: string, stored: number): number {
  const t = exactWakeAt.get(id);
  return t !== undefined && coarseWakeAt(t) === Number(stored) ? t : Number(stored);
}
function noteWakeAt(id: string, t: number): void {
  if (exactWakeAt.size >= 100_000) {
    for (const [k, v] of exactWakeAt) if (t - v > COALESCE_TTL_MS) exactWakeAt.delete(k);
    if (exactWakeAt.size >= 100_000) exactWakeAt.clear(); // (at worst one extra wake each)
  }
  exactWakeAt.set(id, t);
}

// ---- sealedFetch {mbox, read_cap, after_seq?, limit?} ----
sealedRoute("sealedFetch", async (req, body) => {
  const { mbox, read_cap } = body;
  if (!isMboxHex(mbox)) return sealedErr(400, "Invalid mailbox");
  const afterIn = body.after_seq === undefined || body.after_seq === null ? 0 : Number(body.after_seq);
  if (!Number.isInteger(afterIn) || afterIn < 0 || afterIn > 0xffffffffffff) return sealedErr(400, "Invalid after_seq");
  const limIn = body.limit === undefined || body.limit === null ? SEALED_FETCH_MAX : Number(body.limit);
  if (!Number.isInteger(limIn) || limIn < 1) return sealedErr(400, "Invalid limit");
  const limit = Math.min(SEALED_FETCH_MAX, limIn);
  const st = await mboxState(mbox);
  if (st.status !== "ok") return mboxGone(st);
  const mtag = await mboxTag(mbox);
  // b77t (audit 5 L-11, IH R-03): the capability is checked BEFORE the mailbox's own limiter is charged (as sealedTurn
  // does), so wrong-cap requests from a peer can't spend the owner's fetch budget; they still cost the caller's network
  { const lim = await sealedNetLimited(req, "mboxfetchnet", SEALED_FETCHES_PER_NETWORK_PER_MIN, 60_000); if (lim) return lim; }
  if (!(await capMatches(read_cap, st.row.read_hash))) return sealedErr(403, "Invalid mailbox credential");
  { const lim = await mboxLimited("mboxfetch:" + mtag, MBOX_FETCHES_PER_MIN, 60_000); if (lim) return lim; }
  const items: Record<string, unknown>[] = [];
  for await (const ix of KV.list({ start: ["env_by_mbox", mbox, seqPrefix(afterIn + 1)], end: ["env_by_mbox", mbox, "z"] }, { consistency: "strong" })) {
    const key: Deno.KvKey = ["entity", "VeilEnvelope", String(ix.key[2])];
    const got = await KV.get<Record<string, unknown>>(key);
    const env = got.value;
    if (!env || String(env.mbox || "") !== mbox) { await KV.delete(ix.key); continue; }
    if (envelopeExpired(env)) { await deleteEnvelopeRow(key, env); continue; }
    items.push({ id: env.id, seq: env.seq, ciphertext: env.ciphertext, iv: env.iv, header: env.header, byte_length: env.byte_length, expires_at: env.expires_at });
    if (items.length >= limit) break;
  }
  await touchMbox(mbox);
  // next_seq: the after_seq for the next page (the last seq returned, or the cursor unchanged)
  const next_seq = items.length ? Number(items[items.length - 1].seq) : afterIn;
  return json({ items, next_seq });
});

// ---- sealedBurn {mbox, read_cap, ids} ----
sealedRoute("sealedBurn", async (req, body) => {
  const { mbox, read_cap, ids } = body;
  if (!isMboxHex(mbox)) return sealedErr(400, "Invalid mailbox");
  if (!Array.isArray(ids) || !ids.length || ids.length > SEALED_BURN_MAX || !ids.every((x) => typeof x === "string" && /^[0-9a-f]{24}$/.test(x))) return sealedErr(400, `ids: 1-${SEALED_BURN_MAX} envelope ids`);
  const st = await mboxState(mbox);
  if (st.status !== "ok") return mboxGone(st);
  const mtag = await mboxTag(mbox);
  // b77t (audit 5 L-11): the capability before the mailbox's limiter (see sealedFetch)
  { const lim = await sealedNetLimited(req, "mboxctlnet", SEALED_CONTROL_PER_NETWORK_PER_MIN, 60_000); if (lim) return lim; }
  if (!(await capMatches(read_cap, st.row.read_hash))) return sealedErr(403, "Invalid mailbox credential");
  { const lim = await mboxLimited("mboxctl:" + mtag, MBOX_CONTROL_PER_MIN, 60_000); if (lim) return lim; }
  let burned = 0;
  for (const id of new Set(ids as string[])) {
    const key: Deno.KvKey = ["entity", "VeilEnvelope", id];
    const got = await KV.get<Record<string, unknown>>(key);
    if (!got.value || String(got.value.mbox || "") !== mbox) continue; // another mailbox's envelope is never touched
    await deleteEnvelopeRow(key, got.value);
    burned++;
  }
  await touchMbox(mbox); // b77g: an owner operation keeps the mailbox alive
  return json({ burned });
});

// ---- sealedEnd {mbox, cap} — the owner's read cap or the peer's send cap ----
sealedRoute("sealedEnd", async (req, body) => {
  const { mbox, cap } = body;
  if (!isMboxHex(mbox)) return sealedErr(400, "Invalid mailbox");
  if (!isMboxHex(cap)) return sealedErr(400, "Invalid mailbox credential");
  let preAllowed = false; // b77r2: the end-before-open caps are charged once per request
  for (let attempt = 0; attempt < 5; attempt++) {
    const st = await mboxState(mbox);
    if (st.status === "retired") {
      // b77r3 (audit R3-3): a live PRE-OPEN marker written with another capability (whoever knows
      // the id — the relay — can write one first) used to swallow the peer's real end: answered
      // "already ended", and the open then replaced the marker. Its hash is added as cap_h2 (one
      // slot only, so the marker stays bounded); mailboxOpen answers 410 for either.
      const rKey = await mboxRetiredKey(mbox);
      const rt = await KV.get(rKey);
      const pre = retiredLive(rt.value) ? asPreRetired(rt.value) : null;
      if (pre && typeof pre.cap_h2 !== "string") {
        const h = await capHash(cap);
        if (!preNames(pre, h)) {
          { const lim = await sealedNetLimited(req, "mboxctlnet", SEALED_CONTROL_PER_NETWORK_PER_MIN, 60_000); if (lim) return lim; }
          if (!preAllowed) {
            if (await endBeforeOpenCapped(req)) return json({ ok: true, already_ended: true });
            preAllowed = true;
          }
          const ttl = Math.max(1000, Number(pre.exp) - Date.now());
          const ok = await KV.atomic().check({ key: mboxKey(mbox), versionstamp: null }).check(rt)
            .set(rKey, { ...pre, cap_h2: h } satisfies PreRetired, { expireIn: ttl }).commit();
          if (ok.ok) return sealedMiss(json({ ok: true, ended_before_open: true }));
          continue; // opened, ended or changed just now: look again
        }
      }
      return json({ ok: true, already_ended: true });
    }
    if (st.status === "absent") {
      // b77r1 (audit A-4): a chat ended while the peer's mailbox was still in its open delay used
      // to answer 425 and retire nothing, so the peer never learned of the end. Now the id is
      // retired on the spot: its later mailboxOpen and every submit get 410. The 256-bit id is
      // derived on the two phones from the chat's root; only the relay and the peer can know it
      // (the relay sees it on any submit or fetch, a 425 included), so knowing it is the proof.
      // Counted as a miss in the sealed-any budget.
      { const lim = await sealedNetLimited(req, "mboxctlnet", SEALED_CONTROL_PER_NETWORK_PER_MIN, 60_000); if (lim) return lim; }
      // b77r2 (audit R2-R-1): this is an unauthenticated write, so it is capped per network and
      // relay-wide per day; past either the answer is the old 425 and nothing is written. The
      // marker lives MBOX_PRE_RETIRED_TTL_MS (8 days), not 400, and records H(cap): only an open
      // naming that capability as its send or read hash is answered 410 (mailboxOpen).
      if (!preAllowed) {
        if (await endBeforeOpenCapped(req)) return mboxGone({ status: "absent" });
        preAllowed = true;
      }
      const rKey = await mboxRetiredKey(mbox);
      const rt = await KV.get(rKey); // empty, or a lapsed pre-open marker (mboxState said "absent")
      if (retiredLive(rt.value)) continue;
      const marker: PreRetired = { pre: 1, cap_h: await capHash(cap), exp: Date.now() + MBOX_PRE_RETIRED_TTL_MS };
      const ok = await KV.atomic().check({ key: mboxKey(mbox), versionstamp: null }).check(rt)
        .set(rKey, marker, { expireIn: MBOX_PRE_RETIRED_TTL_MS }).commit();
      if (ok.ok) return sealedMiss(json({ ok: true, ended_before_open: true }));
      continue; // opened (or ended) just now: look again
    }
    const mtag = await mboxTag(mbox);
    // b77u (audit 6 W5): the capability before the mailbox's limiter
    { const lim = await sealedNetLimited(req, "mboxctlnet", SEALED_CONTROL_PER_NETWORK_PER_MIN, 60_000); if (lim) return lim; }
    const [isRead, isSend] = await Promise.all([capMatches(cap, st.row.read_hash), capMatches(cap, st.row.send_hash)]);
    if (!isRead && !isSend) return sealedErr(403, "Invalid mailbox credential");
    { const lim = await mboxLimited("mboxctl:" + mtag, MBOX_CONTROL_PER_MIN, 60_000); if (lim) return lim; }
    await endMailbox(mbox);
    return json({ ok: true });
  }
  return sealedErr(503, "Busy — try again");
});

/** b77r2 (audit R2-R-1): true when this network (/64 or IPv4; /56 x4, /48 x16) or the whole relay
 *  has used its end-before-open allowance for today ("local" is exempt from both) */
async function endBeforeOpenCapped(req: Request): Promise<boolean> {
  const net = await clientTag(req);
  if (net === "local") return false;
  if (await rateLimit("mboxendpre:" + net, END_BEFORE_OPEN_PER_NETWORK_PER_DAY, 86400_000, 0)) return true;
  if (await wideRateLimit("mboxendpre", await clientWideTags(req), END_BEFORE_OPEN_PER_NETWORK_PER_DAY, 86400_000, 0)) return true;
  return !!(await rateLimit("mboxendpre:all", END_BEFORE_OPEN_RELAY_PER_DAY, 86400_000, 0));
}

// ---- mailboxPush {mbox, read_cap, wake: box | null} ----
// b77p (audit 2 VAR-01): the recipient's push target, sealed under its wake capability (spec §12.19.1); b77's
// push_ref (listed again on the account's push row) is refused
// b77p round 2 (owner decision 4): during the transition window a LEGACY phone binds a push_ref (32-64 lowercase hex, or
// null) as in b77; a mailbox holds a wake box or a push_ref, never both (setting one clears the other)
sealedRoute("mailboxPush", async (req, body) => {
  const { mbox, read_cap } = body;
  if (!isMboxHex(mbox)) return sealedErr(400, "Invalid mailbox");
  const legacy = body.push_ref !== undefined && body.wake === undefined;
  if (body.push_ref !== undefined && (!legacy || !compatOn())) return sealedErr(400, "Update Vardum: push_ref is retired");
  const ref = legacy ? body.push_ref : null;
  if (legacy && ref !== null && !(typeof ref === "string" && PUSH_REF_RE.test(ref))) return sealedErr(400, "Invalid push_ref (32-64 lowercase hex, or null)");
  const box = legacy ? null : body.wake;
  if (box !== null && !isWakeBox(box)) return sealedErr(400, `Invalid wake box ('w1.' + base64, ${WAKE_BOX_LENGTH} characters, or null)`);
  const st = await mboxState(mbox);
  if (st.status !== "ok") return mboxGone(st);
  const mtag = await mboxTag(mbox);
  // b77u (audit 6 W5, IH relay F-04): the capability BEFORE the mailbox's own limiter (as sealedFetch since b77t L-11):
  // wrong-cap requests from whoever knows the id cost only the caller's network, never the owner's mailbox budget
  // b77u (audit 6 W4): the owner's cap (own_cap) where the mailbox has one
  { const lim = await sealedNetLimited(req, "mboxctlnet", SEALED_CONTROL_PER_NETWORK_PER_MIN, 60_000); if (lim) return lim; }
  void read_cap;
  if (!(await ownerCapOk(st.row, body))) return sealedErr(403, "Invalid mailbox credential");
  { const lim = await mboxLimited("mboxctl:" + mtag, MBOX_CONTROL_PER_MIN, 60_000); if (lim) return lim; }
  // b77g: an owner operation keeps the mailbox alive (last_hour, hour granularity)
  const ok = await patchMbox(mbox, (r) => {
    const { wake: _old, push_ref: _oldRef, ...rest } = r as MboxRow;
    const h = { ...rest, last_hour: hourFloor() };
    return box ? { ...h, wake: box } : typeof ref === "string" ? { ...h, push_ref: ref } : h;
  });
  return ok ? json({ ok: true }) : mboxGone(await mboxState(mbox));
});

// ---- mailboxVerify {mbox, read_cap, verified} ----
sealedRoute("mailboxVerify", async (req, body) => {
  const { mbox, read_cap, verified } = body;
  if (!isMboxHex(mbox)) return sealedErr(400, "Invalid mailbox");
  if (typeof verified !== "boolean") return sealedErr(400, "verified must be true or false");
  const st = await mboxState(mbox);
  if (st.status !== "ok") return mboxGone(st);
  const mtag = await mboxTag(mbox);
  // b77u (audit 6 W5): the capability before the mailbox's limiter; W4: the owner's cap where the mailbox has one
  { const lim = await sealedNetLimited(req, "mboxctlnet", SEALED_CONTROL_PER_NETWORK_PER_MIN, 60_000); if (lim) return lim; }
  void read_cap;
  if (!(await ownerCapOk(st.row, body))) return sealedErr(403, "Invalid mailbox credential");
  { const lim = await mboxLimited("mboxctl:" + mtag, MBOX_CONTROL_PER_MIN, 60_000); if (lim) return lim; }
  // b77m (audit VAR-04): a NEW "verified" (false → true) counts against the network's daily budget
  if (verified && st.row.verified !== true) {
    const lim = await sealedNetPowLimited(req, "mbverifynet", MBOX_VERIFIES_PER_NETWORK_PER_DAY, 86400_000, body); // b77m (owner): a puzzle past the network cap
    if (lim) return lim;
  }
  const ok = await patchMbox(mbox, (r) => ({ ...r, verified, last_hour: hourFloor() })); // b77g: an owner operation keeps the mailbox alive
  return ok ? json({ ok: true, verified }) : mboxGone(await mboxState(mbox));
});

// ---- b77n (audit VAR-04, the full fix): TURN grants — turnGrant, turnApprove, sealedTurn ----
// Spec: docs/protocol-spec.md §12.12. The caller's phone opens a grant on its own inbound and sends
// the grant id inside the end-to-end encrypted call invite; the callee's phone approves it on ITS own
// inbound as the call rings; then each side redeems it once (sealedTurn). Both mailboxes must be
// verified by their owners, the approver must be a different mailbox from the opener, and the pair
// is rate-limited as a pair. Nothing names a chat, an account or a Vardum ID; the grant row holds
// the two mailbox tags for at most TURN_GRANT_TTL_MS.
type TurnGrant = { o: string; a?: string; exp: number; ro: number; ra: number };
const turnGrantKey = async (grant: string): Promise<Deno.KvKey> => ["turn_grant", await sha256hex("veil-turn-grant:" + grant)];
/** memory-only: the per-pair rate rows are keyed on a salted hash of the two tags, so after a restart
 *  nothing stored can be tested against a pair of mailboxes */
const TURN_PAIR_SALT = [...crypto.getRandomValues(new Uint8Array(16))].map((b) => b.toString(16).padStart(2, "0")).join("");
const turnPairTag = (t1: string, t2: string) => sha256hex("veil-turn-pair:" + TURN_PAIR_SALT + ":" + [t1, t2].sort().join(":"));
const NO_APPROVED_CALL = "No approved call — start the call again";
/**
 * b77n2 (review L4): the grant row names its two mailboxes by a MEMORY-KEYED tag (HMAC under a key made at
 * start-up, non-extractable, never stored), not by mboxTag — sha256("veil-mbox-tag:" + mailbox) is unkeyed, so
 * anyone holding a copy of the database and a mailbox id could test it against a grant row and pair a chat's two
 * mailboxes ("nothing stored pairs the two mailboxes"). A restart makes every open grant unredeemable (a call
 * being set up at that moment is started again; grants live 5 minutes anyway).
 */
const turnSideKey = crypto.subtle.generateKey({ name: "HMAC", hash: "SHA-256", length: 256 }, false, ["sign"]) as Promise<CryptoKey>;
async function turnSideTag(mbox: string): Promise<string> {
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", await turnSideKey, enc.encode("veil-turn-side:" + mbox)));
  return "ts_" + [...mac.slice(0, 16)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
/**
 * b77q (audit 3 RF-1): the per-mailbox TURN limiter rows ("turngrant:", "turnappr:", "turnpoll:", "turnmb:") name the
 * mailbox by this tag, an HMAC under the same memory-only key (another label), not by mboxTag. They used the unkeyed
 * mboxTag, so anyone with a copy of the database could hash every ["mbox", id], find the caller's "turngrant" row and
 * the callee's "turnappr" row in the same hourly bucket, and pair a chat's two mailboxes. Nothing stored can be tested
 * against a mailbox id now. A restart starts these hourly limits afresh (open grants die with it anyway).
 */
async function turnLimitTag(mbox: string): Promise<string> {
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", await turnSideKey, enc.encode("veil-turn-limit:" + mbox)));
  return "tl_" + [...mac.slice(0, 16)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
/** the owner of a verified inbound, by its read cap: the limiter tag (rate rows; b77q RF-1: memory-keyed), the grant-row tag, or the refusal */
async function turnOwner(body: Record<string, any>): Promise<{ mtag: string; gtag: string } | Response> {
  const { mbox, read_cap, grant } = body;
  if (!isMboxHex(mbox)) return sealedErr(400, "Invalid mailbox");
  if (!isMboxHex(grant)) return sealedErr(400, "Invalid call grant (64 hex)");
  if (!turnConfigured()) return sealedErr(503, "Calling relay not configured"); // b77q (audit 3 RF-3): a host too
  const st = await mboxState(mbox);
  if (st.status !== "ok") return mboxGone(st);
  void read_cap;
  if (!(await ownerCapOk(st.row, body))) return sealedErr(403, "Invalid mailbox credential"); // b77u (audit 6 W4): the owner's cap
  if (st.row.verified !== true) return sealedErr(403, "Calls need a conversation you have verified");
  return { mtag: await turnLimitTag(mbox), gtag: await turnSideTag(mbox) }; // b77q (audit 3 RF-1): was mboxTag
}

// ---- turnGrant {mbox, read_cap, grant} — the CALLER opens a grant on its own verified inbound ----
sealedRoute("turnGrant", async (req, body) => {
  const who = await turnOwner(body);
  if (who instanceof Response) return who;
  const k = await turnGrantKey(String(body.grant));
  // b77n2 (review L1): idempotent for its opener — a retry after an answer lost on the way back gets OK (it used
  // to get 409, and the call failed before it rang); the grant's expiry is not extended, and nothing is charged
  const opened = (g: TurnGrant | null): boolean => !!g && Number(g.exp) > Date.now() && ctEq(g.o, who.gtag);
  const okBody = (g: TurnGrant) => json({ ok: true, expires_in_s: Math.max(1, Math.round((Number(g.exp) - Date.now()) / 1000)) });
  { const pre = await KV.get<TurnGrant>(k, { consistency: "strong" }); if (pre.value) return opened(pre.value) ? okBody(pre.value) : sealedErr(409, "This call grant already exists"); }
  { const lim = await mboxLimited("turngrant:" + who.mtag, MBOX_TURN_GRANTS_PER_HOUR, 3600_000); if (lim) return lim; }
  { const lim = await sealedNetPowLimited(req, "turngrantnet", TURN_GRANTS_PER_NETWORK_PER_HOUR, 3600_000, body); if (lim) return lim; }
  const cur = await KV.get<TurnGrant>(k, { consistency: "strong" });
  if (cur.value) return opened(cur.value) ? okBody(cur.value) : sealedErr(409, "This call grant already exists");
  const row: TurnGrant = { o: who.gtag, exp: Date.now() + TURN_GRANT_TTL_MS, ro: 0, ra: 0 };
  const ok = await KV.atomic().check(cur).set(k, row, { expireIn: TURN_GRANT_TTL_MS }).commit();
  if (ok.ok) return json({ ok: true, expires_in_s: TURN_GRANT_TTL_MS / 1000 });
  const again = (await KV.get<TurnGrant>(k, { consistency: "strong" })).value; // a concurrent retry of the same open
  return again && opened(again) ? okBody(again) : sealedErr(409, "This call grant already exists");
});

// ---- turnApprove {mbox, read_cap, grant} — the CALLEE approves it on its own verified inbound ----
sealedRoute("turnApprove", async (req, body) => {
  const who = await turnOwner(body);
  if (who instanceof Response) return who;
  const k = await turnGrantKey(String(body.grant));
  let cur = await KV.get<TurnGrant>(k, { consistency: "strong" });
  const live = (g: TurnGrant | null): g is TurnGrant => !!g && Number(g.exp) > Date.now();
  if (!live(cur.value)) return sealedErr(403, NO_APPROVED_CALL);
  if (ctEq(cur.value.o, who.gtag)) return sealedErr(403, "A call is approved from the other phone's mailbox, never the caller's own");
  if (cur.value.a) return ctEq(cur.value.a, who.gtag) ? json({ ok: true, approved: true }) : sealedErr(409, "This call was already approved");
  { const lim = await mboxLimited("turnappr:" + who.mtag, MBOX_TURN_APPROVALS_PER_HOUR, 3600_000); if (lim) return lim; }
  { const lim = await mboxLimited("turnpair:" + await turnPairTag(cur.value.o, who.gtag), TURN_PAIR_GRANTS_PER_HOUR, 3600_000); if (lim) return lim; }
  for (let attempt = 0; attempt < 10; attempt++) {
    const g = cur.value;
    if (!live(g)) return sealedErr(403, NO_APPROVED_CALL);
    if (g.a) return ctEq(g.a, who.gtag) ? json({ ok: true, approved: true }) : sealedErr(409, "This call was already approved");
    const left = Math.max(1000, Number(g.exp) - Date.now());
    if ((await KV.atomic().check(cur).set(k, { ...g, a: who.gtag }, { expireIn: left }).commit()).ok) return json({ ok: true, approved: true });
    cur = await KV.get<TurnGrant>(k, { consistency: "strong" });
  }
  return sealedErr(503, "Busy — try again");
});

// ---- sealedTurn {mbox, read_cap, grant} — same response as veilTurnCredentials ----
// b77n (audit VAR-04): only for a grant the OTHER mailbox approved, once per side (plus one retry);
// 202 {pending} while the callee has not approved yet (the caller asks again in a second).
sealedRoute("sealedTurn", async (req, body) => {
  const { mbox, read_cap, grant } = body;
  if (!isMboxHex(mbox)) return sealedErr(400, "Invalid mailbox");
  if (!isMboxHex(grant)) return sealedErr(400, "Invalid call grant (64 hex)"); // b77n: a mailbox alone gets nothing
  if (!turnConfigured()) return sealedErr(503, "Calling relay not configured"); // b77q (audit 3 RF-3): a host too
  const st = await mboxState(mbox);
  if (st.status !== "ok") return mboxGone(st);
  const mtag = await turnLimitTag(mbox); // b77q (audit 3 RF-1): the limiter rows too (was mboxTag)
  const gtag = await turnSideTag(mbox); // b77n2 (review L4): the grant row holds memory-keyed tags
  // the read cap first: a peer (who knows the mailbox id) can't use up the owner's asks with wrong caps
  // b77u (audit 6 W4): the owner's cap where the mailbox has one (the peer derives the read cap)
  void read_cap;
  if (!(await ownerCapOk(st.row, body))) return sealedErr(403, "Invalid mailbox credential");
  { const lim = await mboxLimited("turnpoll:" + mtag, MBOX_TURN_POLLS_PER_MIN, 60_000); if (lim) return lim; }
  const k = await turnGrantKey(grant);
  let cur = await KV.get<TurnGrant>(k, { consistency: "strong" });
  let limited = false;
  for (let attempt = 0; attempt < 10; attempt++) {
    const g = cur.value;
    if (!g || Number(g.exp) <= Date.now()) return sealedErr(403, NO_APPROVED_CALL);
    const side: "ro" | "ra" | null = ctEq(g.o, gtag) ? "ro" : g.a && ctEq(g.a, gtag) ? "ra" : null;
    if (!side) return sealedErr(403, NO_APPROVED_CALL); // not one of this call's two mailboxes (or the callee before it approved)
    if (!g.a) return json({ pending: true, retry_ms: 1000 }, 202);
    if (Number(g[side]) >= TURN_GRANT_REDEEMS_PER_SIDE) return sealedErr(403, NO_APPROVED_CALL);
    if (!limited) {
      limited = true;
      // b77q (audit 3 RF-4): the network check (and its puzzle) FIRST: with the network cap back at 30, phones behind
      // one carrier-NAT address meet the puzzle in normal use, and the puzzle round trip used to spend one of the
      // mailbox's 6 credentials an hour each time (the puzzle answer, then the solved ask)
      { const lim = await sealedNetPowLimited(req, "turnnet", TURN_CREDS_PER_NETWORK_PER_HOUR, 3600_000, body, TURN_NET_OPTS); if (lim) return lim; } // b77m (owner): a puzzle past the network cap; b77q (audit 3 RF-4): the TURN budget's factors
      { const lim = await mboxLimited("turnmb:" + mtag, MBOX_TURN_PER_HOUR, 3600_000); if (lim) return lim; }
    }
    const left = Math.max(1000, Number(g.exp) - Date.now());
    if ((await KV.atomic().check(cur).set(k, { ...g, [side]: Number(g[side]) + 1 }, { expireIn: left }).commit()).ok) return turnCredentialResponse();
    cur = await KV.get<TurnGrant>(k, { consistency: "strong" });
  }
  return sealedErr(503, "Busy — try again");
});

// ---- sealedUpload: multipart as UploadPrivateFile, plus form fields mbox and send_cap ----
route("POST", "/api/apps/:appId/functions/sealedUpload", (req) => sealedGuarded(req, () => sealedUpload(req)));
async function sealedUpload(req: Request): Promise<Response> {
  const UPLOAD_BODY_CAP = 26 * 1024 * 1024;
  const declared = Number(req.headers.get("content-length") || "0");
  if (declared > UPLOAD_BODY_CAP) return TOO_LARGE("File too large");
  // b77t (audit 5 M-D, IH V-01): EVERY sealed upload names its mailbox in headers (X-Veil-Mbox + X-Veil-Send-Cap; the
  // app sends them since f45968e, vendor/device/src/relay.ts sealedUpload). An unnamed body used to take an upload
  // slot with no account and no capability and hold it to the 90 s unnamed deadline, so two networks held every slot
  // (media, vault and transfer uploads 503 for everyone). It is now refused before anything is spent: no limiter, no
  // quota, no slot.
  const hdrMbox = req.headers.get("x-veil-mbox"), hdrCap = req.headers.get("x-veil-send-cap");
  if (hdrMbox === null || hdrCap === null) return sealedErr(400, "Update Vardum: this upload doesn't name its chat", { code: "upload_unnamed" });
  if (!isMboxHex(hdrMbox)) return sealedErr(400, "Invalid mailbox");
  { const lim = await sealedNetLimited(req, "sealedupnet", SEALED_UPLOADS_PER_NETWORK_PER_MIN, 60_000); if (lim) return lim; }
  { const lim = await uploadStartRefusal(req); if (lim) return lim; } // b77s (audit 4 RS-2)
  // b77s (audit 4 RS-2): the named mailbox and its send capability are checked now, before a slot is taken
  const hst = await mboxState(hdrMbox);
  if (hst.status !== "ok") return mboxGone(hst);
  if (!(await capMatches(hdrCap, hst.row.send_hash))) return sealedErr(403, "Invalid mailbox credential");
  const namedMbox: string = hdrMbox;
  // b77t2 (CM-1): a mailbox whose bodies were cut for their rate 3 times in 10 minutes is refused; otherwise ONE body
  // per mailbox in flight (a second waits for it, holding no slot)
  const mtag0 = await mboxTag(namedMbox);
  { const lim = uploadStrikeRefusal("mb:" + mtag0); if (lim) return lim; }
  const mboxSlot = await takeMboxUploadSlot(mtag0);
  if (!mboxSlot) return sealedErr(429, "Another upload to this chat is still in progress — try again in a moment", { retry_seconds: 10 });
  try { // (the outer finally gives the mailbox's turn back once this request is done, whatever path it took)
  // the network and relay-wide day quotas are RESERVED before the body is read (as UploadPrivateFile);
  // the mailbox's own quota is charged once the form names it
  // (b77r1 audit R-3: the app's multipart client puts mbox / send_cap AFTER the file part and sends
  // no header naming them, so they can't be checked before a slot is taken without an app change)
  const day = statDay();
  const net = await clientTag(req);
  const allKey: Deno.KvKey = ["upload_quota_all", day];
  const reserved = declared > 0 ? declared : UPLOAD_BODY_CAP;
  // b77m (audit VAR-03): room on the disk first; the day's relay-wide cap follows the room left
  const store = await storageGate(reserved, allKey);
  if (!store) return sealedErr(507, STORAGE_FULL_MSG, { code: "storage_full" });
  const caps: [Deno.KvKey, number][] = [[allKey, store.allCap]];
  if (net !== "local") caps.push([["upload_quota_net", net, day], UPLOAD_NETWORK_DAILY_CAP]);
  for (const w of await clientWideTags(req)) caps.push([["upload_quota_net" + w.bits, w.tag, day], UPLOAD_NETWORK_DAILY_CAP * WIDE_FACTOR[w.bits]]);
  // b77r1 (audit R-2): "light" is judged by the caller's network here (the mailbox is not known
  // yet) and by the mailbox AND the network once the form names it — never by the relay-wide
  // counter itself, which made every 1:1 upload "heavy" past 60% of the relay-wide total
  const lightNet: LightRule = { allKey, allCap: store.allCap, frac: LIGHT_RULE_FRACTION, heavy: networkHeavy(caps, "upload_quota_net", UPLOAD_LIGHT_NETWORK_BYTES) };
  // b77r1 (audit R-3): the per-network concurrency cap BEFORE a relay-wide slot is taken
  let netOnly: (() => void) | null = null;
  const netSlot = () => { netOnly?.(); mboxSlot(); }; // b77t2 (CM-1): the mailbox's turn goes back with the network slot
  netOnly = await takeNetUploadSlot(req);
  if (!netOnly) { mboxSlot(); store.release(); return sealedErr(429, "Too many uploads at once from this network — try again in a moment", { retry_seconds: 10 }); }
  const r0 = await reserveUploadQuota(netSlot, () => adjustQuota(caps, reserved, lightNet)).catch((e) => { store.release(); throw e; });
  if (r0 === "over") { store.release(); return sealedErr(429, "Daily upload limit reached — try again tomorrow"); }
  if (r0 === "busy") { store.release(); return sealedErr(429, "Upload busy — try again"); }
  let charged = reserved;
  let mboxCharge: { bytesKey: Deno.KvKey; countKey: Deno.KvKey; bytes: number } | null = null;
  if (!(await acquireUploadSlot("sealed"))) { // b77t (audit 5 M-D): never the signed-in reserve
    netSlot();
    store.release();
    await adjustQuota(caps, -charged);
    return j({ error: "The relay is busy with other uploads — try again in a moment", message: "The relay is busy with other uploads — try again in a moment" }, 503, { "Retry-After": "10" });
  }
  try {
    let bodyBytes: Uint8Array;
    try {
      const got = await readCapped(req, UPLOAD_BODY_CAP, uploadLimitsFor(net)); // b77r1 (audit R-3); b77t (audit 5 M-D): every sealed upload is named now; b77t2 (CM-1): a struck network gets the short grace
      if (!got) return TOO_LARGE("File too large");
      bodyBytes = got;
    } catch (e) {
      noteUploadCut(e, ["net:" + net, "mb:" + mtag0]); // b77t2 (CM-1)
      if (e instanceof BodyTooSlowError) return sealedErr(408, "Upload too slow — try again on a better connection");
      return sealedErr(400, "Upload failed");
    }
    let form: FormData;
    try { form = await new Response(bodyBytes as BodyInit, { headers: { "content-type": req.headers.get("content-type") || "" } }).formData(); }
    catch { return sealedErr(400, "Upload failed — not a file upload"); }
    let file: File | null = null;
    for (const [, v] of form.entries()) { if (v instanceof File) { file = v; break; } }
    if (!file) return sealedErr(400, "No file part");
    const mbox = form.get("mbox"), sendCap = form.get("send_cap");
    if (!isMboxHex(mbox)) return sealedErr(400, "Invalid mailbox");
    if (mbox !== namedMbox) return sealedErr(400, "Invalid mailbox"); // b77s (audit 4 RS-2): the form names the header's mailbox
    const st = await mboxState(mbox);
    if (st.status !== "ok") return mboxGone(st);
    const mtag = await mboxTag(mbox);
    { const lim = await mboxLimited("mboxup:" + mtag, MBOX_UPLOADS_PER_MIN, 60_000); if (lim) return lim; }
    if (!(await capMatches(sendCap, st.row.send_hash))) return sealedErr(403, "Invalid mailbox credential");
    if (file.size > 25 * 1024 * 1024) return sealedErr(413, "File too large");
    // b77r1 (audit R-2, R-6): ONE atomic step trims the relay-wide and network reservation to the
    // file's real size and charges the mailbox's bytes and its daily file count, with the light
    // rule on the mailbox and the network (the network's own reservation for this upload excluded)
    const bytesKey: Deno.KvKey = ["mbox_upload_quota", mtag, day], countKey: Deno.KvKey = ["mbox_upload_count", mtag, day];
    const items = [...caps.map(([key, cap]) => ({ key, cap, delta: file!.size - charged })),
      { key: bytesKey, cap: MBOX_UPLOAD_DAILY_BYTES, delta: file.size }, { key: countKey, cap: MBOX_FILES_PER_DAY, delta: 1 }];
    const lightBoth: LightRule = { allKey, allCap: store.allCap, frac: LIGHT_RULE_FRACTION,
      heavy: [{ key: bytesKey, limit: UPLOAD_LIGHT_ACCOUNT_BYTES }, ...networkHeavy(caps, "upload_quota_net", UPLOAD_LIGHT_NETWORK_BYTES, charged)] };
    let r1 = await adjustQuotaItems(items, lightBoth);
    for (let i = 0; i < 5 && r1 === "busy"; i++) { await new Promise((r) => setTimeout(r, 2 + Math.random() * 10)); r1 = await adjustQuotaItems(items, lightBoth); }
    if (r1 === "over") return sealedErr(429, "Daily upload limit reached — try again tomorrow");
    if (r1 === "busy") return sealedErr(429, "Upload busy — try again");
    charged = file.size;
    mboxCharge = { bytesKey, countKey, bytes: file.size };
    const id = rid();
    await Deno.mkdir(BLOB_DIR, { recursive: true });
    await Deno.writeFile(BLOB_DIR + id, new Uint8Array(await file.arrayBuffer()));
    noteBlobWritten(file.size); // b77m (audit VAR-03)
    // bound to the mailbox only (no owner, no account, no chat token); b77r1 (audit R-6): and
    // listed under the mailbox's blob tag, in the same step
    const btag = await blobMboxTag(mbox);
    // b77n (pre-audit L4): the binding commits only while the mailbox row still exists (checked against the row as
    // read now). It used to be written unchecked, so an endMailbox running between the mailbox check above and this
    // write (it deletes the row, then the files it finds bound) missed the file, which stayed until the 49 h blob
    // sweep with a binding to a retired mailbox. A mailbox gone meanwhile: the file is removed and the upload refused.
    let bound = false;
    for (let attempt = 0; attempt < 20 && !bound; attempt++) {
      const cur = await KV.get<MboxRow>(mboxKey(mbox), { consistency: "strong" });
      if (!cur.value) break;
      bound = (await KV.atomic().check(cur).set(["blob_mbox", id], btag).set(["blob_by_mbox", btag, id], 1).commit()).ok;
    }
    if (!bound) {
      await Deno.remove(BLOB_DIR + id).catch(() => undefined);
      noteBlobWritten(-file.size);
      const again = await mboxState(mbox);
      return again.status === "ok" ? sealedErr(503, "Busy — try again") : mboxGone(again);
    }
    charged = -1; mboxCharge = null; // kept
    return json({ file_uri: "blob:" + id });
  } catch (e) {
    console.error("sealed upload error", (e as Error)?.name || "error"); return sealedErr(500, "Upload failed");
  } finally {
    releaseUploadSlot("sealed");
    netSlot();
    store.release(); // b77m (audit VAR-03)
    if (charged > 0) await adjustQuota(caps, -charged).catch(() => undefined);
    if (mboxCharge) await adjustQuotaItems([{ key: mboxCharge.bytesKey, cap: MBOX_UPLOAD_DAILY_BYTES, delta: -mboxCharge.bytes }, { key: mboxCharge.countKey, cap: MBOX_FILES_PER_DAY, delta: -1 }]).catch(() => undefined);
  }
  } finally { mboxSlot(); } // b77t2 (CM-1)
}

// ---- sealedFile {mbox, cap, uri, op: 'url' | 'delete'} — read cap (receiver) or send cap (uploader) ----
sealedRoute("sealedFile", async (req, body) => {
  const { mbox, cap, uri, op } = body;
  if (!isMboxHex(mbox)) return sealedErr(400, "Invalid mailbox");
  if (op !== "url" && op !== "delete") return sealedErr(400, "op must be 'url' or 'delete'");
  if (typeof uri !== "string" || uri.length > MAX_KEY_PART + 5 || !blobPathOf(uri)) return sealedErr(404, "Unknown file");
  const st = await mboxState(mbox);
  if (st.status !== "ok") return mboxGone(st);
  const mtag = await mboxTag(mbox);
  // b77u (audit 6 W5): the capability before the mailbox's limiter
  { const lim = await sealedNetLimited(req, "mboxctlnet", SEALED_CONTROL_PER_NETWORK_PER_MIN, 60_000); if (lim) return lim; }
  const [isRead, isSend] = await Promise.all([capMatches(cap, st.row.read_hash), capMatches(cap, st.row.send_hash)]);
  if (!isRead && !isSend) return sealedErr(403, "Invalid mailbox credential");
  { const lim = await mboxLimited("mboxctl:" + mtag, MBOX_CONTROL_PER_MIN, 60_000); if (lim) return lim; }
  const id = blobIdOf(uri);
  const bound = (await KV.get<string>(["blob_mbox", id])).value;
  if (!bound) return op === "delete" ? json({ ok: true, already_gone: true }) : sealedErr(404, "Unknown file");
  if (!ctEq(bound, await blobMboxTag(mbox))) return sealedErr(403, "Not this chat's file");
  if (op === "url") return json({ signed_url: await signBlobUrl(id, 10 * 60_000, PUBLIC_ORIGIN) });
  await Deno.remove(BLOB_DIR + id).catch(() => undefined);
  await KV.atomic().delete(["blob_mbox", id]).delete(["blob_by_mbox", bound, id]).commit(); // b77r1 (audit R-6)
  return json({ ok: true });
});

// ---- b77q (audit 3 AQ-1): veilKeyLookup {veil_id} — a contact's published keys, with NO login ----
// The app's key-change sweep (src/key-change-sweep.ts) checked every pinned contact about every 6 h through the
// signed-in veilIdentityGate lookup, so each pass handed the relay the account's whole contact list under its
// account token. This route answers the same bundle (bound identities only; never a one-time prekey — that stays
// on the signed-in claim_opk lookup) to anyone: no Authorization header is read, nothing is stored or logged per
// request. An ID with no bound identity answers 200 {found: false} (not 404), so the app's decoy lookups (random
// IDs mixed into each pass) don't come back as errors; a relay operator can still tell those apart from its own
// identity table, and still sees the network address and timing (spec §8.2). Limits: the sealed-any budget, then
// KEY_LOOKUPS_PER_NETWORK_PER_HOUR per network (/56 x4, /48 x16), past it the network puzzle (carrier NAT).
const KEY_LOOKUPS_PER_NETWORK_PER_HOUR = Number(Deno.env.get("VEIL_KEY_LOOKUPS_PER_NETWORK_PER_HOUR")) || 120;
sealedRoute("veilKeyLookup", async (req, body) => {
  const veilId = typeof body?.veil_id === "string" ? body.veil_id.trim() : "";
  if (!veilId || veilId.length > MAX_VEIL_ID) return sealedErr(400, "Invalid identity");
  { const lim = await sealedNetPowLimited(req, "keylookupnet", KEY_LOOKUPS_PER_NETWORK_PER_HOUR, 3_600_000, body); if (lim) return lim; }
  const rec = (await KV.get<Record<string, unknown>>(["veil_identity", keySafe(veilId)])).value;
  if (!rec || rec.bound !== true) return json({ found: false });
  // the bundle exactly as the signed-in lookup serves it (b77p, audit VAR-37: an unsigned PQ key is never served)
  return json({ veil_id: rec.veil_id, IK_pub: rec.IK_pub, SPK_pub: rec.SPK_pub, SPK_sig: rec.SPK_sig, pq_pub: rec.pq_sig ? rec.pq_pub : "", pq_sig: rec.pq_sig || "" });
});

// ---------- veilSessionGate, no-login half (b77): status / join / peek / end on 1:1 rows ----------
/** what the initiator (status) and the joiner (join) need of a 1:1 rendezvous row — nothing
 *  that names an account or an identity */
function rendezvousView(s: Record<string, unknown>, extra: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    token: s.token, state: s.state, contact_session: s.contact_session === true,
    responder_pub_jwk: s.responder_pub_jwk ?? "", responder_ratchet_pub_jwk: s.responder_ratchet_pub_jwk ?? "", responder_pq_ct: s.responder_pq_ct ?? "",
    session_fingerprint: s.session_fingerprint ?? "", expires_at: s.expires_at,
    default_ttl_seconds: s.default_ttl_seconds, expire_after_seconds: s.expire_after_seconds, key_retention_hours: s.key_retention_hours, burn_after_open: s.burn_after_open === true,
    ...extra,
  };
}
/** fields a 1:1 join removes from the row: who the two sides are (Vardum IDs, account ids, owner
 *  tag), the initiator's request signature, and which of the responder's prekeys were used */
const JOIN_CLEARED_FIELDS = ["initiator_veil_id", "responder_veil_id", "initiator_sig", "initiator_client_id", "responder_client_id", "_owner", "_init_tag", "responder_spk_id", "responder_opk_id", "responder_display_name", "initiator_display_name"];
/** b77p round 2 (review L1): blind open signatures one side of a rendezvous may get. Each signature still opens ONE
 *  mailbox (its spent marker), so a side opens at most this many; the extra ones replace a token the relay can no
 *  longer accept (its issuer key gone at a restart of a test relay, two rotations, or a key file that was not written).
 *  The relay can't tell whether the side's earlier token opened a mailbox (opens name no rendezvous, §12.19.2), so the
 *  count is the bound. */
const OPEN_ISSUES_PER_SIDE = 3;
/** b77u (audit 6, IH full L-8): re-sends of the same blinded value per side */
const OPEN_REPEATS_PER_SIDE = 5;
/** b77p round 2 (review L1): the open signature for `slot` of an active rendezvous row: the same blinded value again
 *  (a lost answer, not counted), or a new one while the side has had fewer than OPEN_ISSUES_PER_SIDE (counted in
 *  open_n_i / open_n_r; a row written before the count counts 1); else 409 */
async function signOpenForSide(session: Record<string, unknown>, slot: "initiator" | "responder", key: OpenKeyNum, openBlind: unknown): Promise<string | Response> {
  const field = slot === "initiator" ? "open_bh_i" : "open_bh_r";
  const nField = slot === "initiator" ? "open_n_i" : "open_n_r";
  const bh = await openBlindHash(String(openBlind ?? ""));
  const k: Deno.KvKey = ["entity", "VeilSession", String(session.id)];
  for (let attempt = 0; attempt < 10; attempt++) {
    const cur = await KV.get<Record<string, unknown>>(k);
    if (!cur.value) return sealedErr(404, "Session not found");
    const have = cur.value[field];
    const same = typeof have === "string" && ctEq(have, bh);
    const n = Number(cur.value[nField]) || (typeof have === "string" ? 1 : 0);
    if (!same && n >= OPEN_ISSUES_PER_SIDE) return sealedErr(409, "An open token was already issued for this side");
    // b77u (audit 6, IH full L-8): a REPEAT of the same blinded value (a lost answer) is counted too, OPEN_REPEATS_PER_SIDE
    // at most — each is an RSA-2048 signature on the event loop, and repeats used to be free and unlimited
    const repField = slot === "initiator" ? "open_rep_i" : "open_rep_r";
    const reps = Number(cur.value[repField]) || 0;
    if (same && reps >= OPEN_REPEATS_PER_SIDE) return sealedErr(409, "An open token was already issued for this side");
    if (!openBlindShapeOk(key, openBlind)) return sealedErr(400, "Invalid open_blind");
    const next = same ? { ...cur.value, [repField]: reps + 1 } : { ...cur.value, [field]: bh, [nField]: n + 1 };
    if (!(await KV.atomic().check(cur).set(k, next).commit()).ok) continue;
    const sig = openSignBlinded(key, openBlind);
    if (!sig) return sealedErr(400, "Invalid open_blind");
    return sig;
  }
  return sealedErr(503, "Busy — try again");
}
async function fnSessionGateAnon(req: Request, body: Record<string, any>, session: Record<string, unknown> | null): Promise<Response> {
  { const lim = await sealedNetLimited(req, "sgate-anon", SESSION_GATE_ANON_PER_NETWORK_PER_MIN, 60_000); if (lim) return lim; }
  const action = String(body?.action || "");
  const token = String(body?.token || "");
  if (!session) {
    if (action === "end") return json({ ok: true });
    return sealedErr(404, "Session not found");
  }
  if (session.group_token) return sealedErr(400, "Group seats use the signed-in session gate");
  const wsHash = body?.write_secret ? await sha256hex(String(body.write_secret)) : "";
  const isI = !!wsHash && ctEq(wsHash, String(session.initiator_write_hash || ""));
  const isR = !!wsHash && ctEq(wsHash, String(session.responder_write_hash || ""));
  const slot = isI ? "initiator" : isR ? "responder" : null;
  if (!slot) return sealedErr(403, "Invalid session credential");
  if (action === "status") return json({ session: rendezvousView(session) });
  if (action === "issue") {
    // b77p (audit 2 VAR-01): one blind open signature per side per rendezvous (the responder's normally comes with
    // its join); the same blinded value is signed again (a lost answer). b77p round 2 (review L1): another one is
    // signed too, up to OPEN_ISSUES_PER_SIDE per side (a token whose key the relay no longer has — a restart, a key
    // file not written — is re-issued), then refused
    if (String(session.state || "") !== "active") return sealedErr(409, "This session has not been accepted yet");
    const key = await acceptedOpenKey(body?.open_kid);
    if (!key || Date.now() > key.row.until) return sealedErr(409, "Open key expired — fetch it again", { open_key_stale: true });
    const got = await signOpenForSide(session, slot, key, body?.open_blind);
    return got instanceof Response ? got : json({ open_sig: got, open_kid: key.kid });
  }
  if (action === "end") {
    // the row first (token retired before its index goes, so no create slips in), then any
    // envelope a pre-b77 chat left under the token
    await retireSessionToken(token);
    await KV.delete(["entity", "VeilSession", String(session.id)]);
    await KV.delete(["veil_sess_token", keySafe(token)]);
    await deleteSessionEnvelopes(token);
    return json({ ok: true });
  }
  if (action === "peek") {
    if (slot !== "responder") return sealedErr(403, "Only the invited side can view this session");
    return json({ session: { state: session.state, responder_client_id: "", expires_at: session.expires_at, initiator_pub_jwk: session.initiator_pub_jwk, initiator_pq_pub: session.initiator_pq_pub, passphrase_required: session.passphrase_required, group_token: "", group_epoch: 0, group_name: "", group_pq_pub: "",
      default_ttl_seconds: session.default_ttl_seconds, expire_after_seconds: session.expire_after_seconds, key_retention_hours: session.key_retention_hours, burn_after_open: session.burn_after_open === true } });
  }
  if (action !== "join") return sealedErr(400, "Unknown action");
  if (slot !== "responder") return sealedErr(403, "Only the invited side can join this session");
  if (String(session.state || "") === "ended") return sealedErr(400, "This session has ended.");
  for (const [k, v] of Object.entries({ responder_pub_jwk: body?.responder_pub_jwk, responder_ratchet_pub_jwk: body?.responder_ratchet_pub_jwk, fingerprint: body?.fingerprint })) {
    if (typeof v !== "string" || !v) return sealedErr(400, `Missing join field: ${k}`);
  }
  for (const f of ["responder_pub_jwk", "responder_ratchet_pub_jwk", "fingerprint", "responder_pq_ct", "new_responder_write_hash"]) {
    if (body?.[f] !== undefined && String(body[f]).length > 4096) return sealedErr(413, "Join field too large");
  }
  // b77p (audit 2 VAR-01): the responder's blinded open token (open_blind under open_kid) — an app that sends
  // ticket hashes (or nothing) speaks a retired protocol. Nothing written here can be tied to a later open.
  // b77p round 2 (owner decision 4): during the transition window a LEGACY join (mbox_ticket_hashes, no open_blind)
  // stores its two one-time tickets as b77 did; a b77p join (open_blind) never writes a ticket, so the window adds no
  // join -> mailbox link for b77p phones. Both in one join: 400.
  const hasTickets = body?.mbox_ticket_hashes !== undefined, hasBlind = body?.open_blind !== undefined;
  // b77p round 2 (review L2): a join repeated with the SAME keys on a row it already made active (its answer was lost)
  // is answered before the protocol check: a b77p phone re-sent it without open_blind when the issuer key had moved on
  // (its kept blind is under the old key), and that got 410 "older protocol", so the chat never finished. The answer
  // is the same; open_sig comes for the same blinded value, or a new one within the side's re-issues (review L1);
  // without a blind there is none (gate `issue` recovers it). A repeated legacy (ticket) join keeps its own path below.
  if (String(session.state) === "active" && !hasTickets
    && String(session.responder_pub_jwk || "") === String(body.responder_pub_jwk) && String(session.responder_ratchet_pub_jwk || "") === String(body.responder_ratchet_pub_jwk)) {
    const view = (extra: Record<string, unknown> = {}) => json({ session: rendezvousView(session, { responder_write_hash: session.responder_write_hash, ...extra }) });
    if (!hasBlind) return view();
    const key = await acceptedOpenKey(body?.open_kid);
    if (!key || Date.now() > key.row.until) return sealedErr(409, "Open key expired — fetch it again", { open_key_stale: true });
    const got = await signOpenForSide(session, "responder", key, body.open_blind);
    if (got instanceof Response) return got.status === 409 ? view() : got; // past the re-issues: the answer, no signature
    return view({ open_sig: got, open_kid: key.kid });
  }
  if (!compatOn() ? (hasTickets || !hasBlind) : (!hasTickets && !hasBlind)) return sealedErr(410, LEGACY_1TO1);
  if (hasTickets && hasBlind) return sealedErr(400, "A join takes open_blind or (older apps) mbox_ticket_hashes, not both");
  const legacyTickets = hasTickets ? body.mbox_ticket_hashes : null;
  if (legacyTickets && (!Array.isArray(legacyTickets) || legacyTickets.length !== 2 || !legacyTickets.every(isMboxHex) || legacyTickets[0] === legacyTickets[1])) return sealedErr(400, "mbox_ticket_hashes must be two different 64-hex strings");
  const openKey = legacyTickets ? null : await acceptedOpenKey(body?.open_kid);
  if (!legacyTickets && (!openKey || Date.now() > openKey.row.until)) return sealedErr(409, "Open key expired — fetch it again", { open_key_stale: true });
  // b77u (audit 6, IH full L-8): signed only for a join that can still take the row (a refused re-join on an active row
  // used to cost an RSA signature first, for free)
  const openSig = openKey && String(session.state) !== "active" ? openSignBlinded(openKey, body?.open_blind) : null;
  if (!legacyTickets && String(session.state) !== "active" && !openSig) return sealedErr(400, "Invalid open_blind");
  const openBh = legacyTickets ? "" : await openBlindHash(String(body.open_blind));
  const sameKeys = String(session.responder_pub_jwk || "") === String(body.responder_pub_jwk) && String(session.responder_ratchet_pub_jwk || "") === String(body.responder_ratchet_pub_jwk);
  if (String(session.state) === "active") {
    // a join whose answer was lost is repeated with the same keys: the same answer, and the open signature only
    // for the SAME blinded value (b77p: another one would let one join open mailboxes without end)
    if (sameKeys) {
      // (b77 legacy: the same answer and NO new tickets — the first join wrote them)
      const have = session.open_bh_r;
      return json({ session: rendezvousView(session, { responder_write_hash: session.responder_write_hash, ...(openKey && openSig && typeof have === "string" && ctEq(have, openBh) ? { open_sig: openSig, open_kid: openKey.kid } : {}) }) });
    }
    return sealedErr(409, "This session was already accepted with different keys — it cannot be re-joined. Start a new session.");
  }
  if (new Date(String(session.expires_at)) < new Date()) return sealedErr(400, "Invitation has expired.");
  const nextHash = typeof body?.new_responder_write_hash === "string" ? body.new_responder_write_hash : "";
  if (nextHash && !/^[0-9a-f]{64}$/.test(nextHash)) return sealedErr(400, "Invalid new responder credential");
  const key: Deno.KvKey = ["entity", "VeilSession", String(session.id)];
  for (let attempt = 0; attempt < 10; attempt++) {
    const cur = await KV.get<Record<string, unknown>>(key);
    if (!cur.value) return sealedErr(409, "This session has ended.");
    if (String(cur.value.state || "") !== "pending") return sealedErr(409, "This session was just accepted — try again.");
    const row: Record<string, unknown> = { ...cur.value };
    for (const f of JOIN_CLEARED_FIELDS) delete row[f];
    if (nextHash) { row.responder_write_hash = nextHash; row.responder_cred_own = true; }
    row.state = "active";
    row.expires_at = new Date(Date.now() + RENDEZVOUS_TTL_MS).toISOString();
    row.responder_pub_jwk = String(body.responder_pub_jwk);
    row.responder_ratchet_pub_jwk = String(body.responder_ratchet_pub_jwk);
    row.responder_pq_ct = typeof body?.responder_pq_ct === "string" ? String(body.responder_pq_ct) : "";
    row.session_fingerprint = String(body.fingerprint);
    row.last_activity = nowIso(); row.updated_date = nowIso();
    if (openBh) { row.open_bh_r = openBh; row.open_n_r = 1; } // b77p: a hash of a uniformly random blinded value — goes with the row (review L1: + its count)
    const tx = KV.atomic().check(cur).set(key, row);
    if (legacyTickets) {
      // b77 legacy (transition window): the row and both tickets in ONE step; the tickets name nothing (no token, no
      // account) — but the join request carried their hashes next to the rendezvous token (audit 2 VAR-01 path 2)
      const ticketExp = hourFloor(Date.now() + MBOX_TICKET_TTL_MS) + 3600_000;
      for (const h of legacyTickets as string[]) tx.set(mboxTicketKey(h), { exp: ticketExp }, { expireIn: ticketExp - Date.now() });
      if ((await tx.commit()).ok) return json({ session: rendezvousView(row, { responder_write_hash: row.responder_write_hash }) });
      continue;
    }
    if ((await tx.commit()).ok) return json({ session: rendezvousView(row, { responder_write_hash: row.responder_write_hash, open_sig: openSig, open_kid: openKey!.kid }) });
  }
  return sealedErr(503, "Busy — try again");
}

// unknown function → 404 (the client tolerates)
route("POST", "/api/apps/:appId/functions/:fn", async (req, m) => {
  return j({ error: `Backend function '${m.groups!.fn!}' not found or not deployed`, message: `Backend function '${m.groups!.fn!}' not found or not deployed` }, 404);
});

// health
route("GET", "/status", async () => json({ ok: true, relay: "veil-phase1" }));
// b199 owner dashboard: aggregate counts only. Caddy refuses /admin/* from the
// internet; the stats service on the same server calls it with this token.
route("GET", "/admin/stats", async (req) => {
  const want = Deno.env.get("VEIL_STATS_TOKEN") || "";
  const got = req.headers.get("x-veil-stats-token") || "";
  if (want.length < 32 || got.length !== want.length) return j({ message: "Not found" }, 404);
  let diff = 0;
  for (let i = 0; i < want.length; i++) diff |= want.charCodeAt(i) ^ got.charCodeAt(i);
  if (diff !== 0) return j({ message: "Not found" }, 404);
  // b75r3 (audit R-I1): every call used to scan the whole database (users, identities, sessions, envelopes),
  // unthrottled. The snapshot is now cached for STATS_CACHE_MS (concurrent calls share one scan) and the route is
  // limited to STATS_ROUTE_PER_MIN calls a minute.
  { const srl = await rateLimit("adminstats", STATS_ROUTE_PER_MIN, 60_000, 0); if (srl) return j({ locked: true, retry_minutes: srl.retry_minutes }, 429); }
  return json({ ...(await cachedStatsSnapshot()), disk_free: { ...diskFreeStatus } }); // b77s (audit 4 F-02): whether the free-disk floor works
});

// ---------- request hardening (b198 attack-probe fixes) ----------
const MAX_JSON_BYTES = 1 * 1024 * 1024;      // JSON routes — envelopes are ≤ ~8 KB
/** b70 (re-review 4): sizes are BYTES (Deno KV's 64 KB is bytes; a CJK character is 2-3) */
/** (re-review 9: also as Deno KV stores it — a string with any character above U+00FF
 *  is kept at 2 bytes per character, so the larger of the two counts) */
const utf8Len = (v: string) => Math.max(new TextEncoder().encode(v).length, /[^\u0000-\u00ff]/.test(v) ? v.length * 2 : v.length);
/** b70 (re-review 9): standard base64 in its one canonical spelling (padding included,
 *  no stray bits) — a key spelled two ways compared as two different keys */
function canonicalB64(v: unknown): v is string {
  if (typeof v !== "string" || !v || v.length % 4 !== 0 || !/^[A-Za-z0-9+/]+={0,2}$/.test(v)) return false;
  try { return btoa(atob(v)) === v; } catch { return false; }
}
const MAX_ROW_BYTES = 48_000;                // b70 (re-review 2): one entity row, under the 64 KB KV value limit
const MAX_KEY_PART = 256;                    // any user string that becomes a KV key part
const MAX_VEIL_ID = 128;                     // veil_ids are short (#veil format)

/** b77r1 (audit R-3): how long a body may take (see UPLOAD_BODY_LIMITS) */
type BodyReadLimits = { deadlineMs: number; stallMs: number; graceMs: number; minBytesPerSec: number };
/** b77r1 (audit R-3): a body that broke its BodyReadLimits (the caller answers 408) */
class BodyTooSlowError extends Error {
  readonly why: string; // b77t2 (CM-1): "deadline" | "stall" | "throughput" (a rate cut is an upload strike)
  constructor(why: string) { super("body too slow: " + why); this.name = "BodyTooSlowError"; this.why = why; }
}
/** Batch D (D-16): reads a request body, counting bytes as they arrive.
 *  Returns null (and stops reading) as soon as the body passes `cap`.
 *  b77r1 (audit R-3): with `limits`, throws BodyTooSlowError (and stops reading) when the whole
 *  body takes longer than deadlineMs, no byte arrives for stallMs, or — after graceMs — the
 *  average rate is under minBytesPerSec. It used to wait for ever. */
async function readCapped(req: Request, cap: number, limits?: BodyReadLimits): Promise<Uint8Array | null> {
  if (!req.body) return new Uint8Array(0);
  const reader = req.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  const t0 = Date.now();
  const give = async (why: string): Promise<never> => { try { await reader.cancel(); } catch { /* already closed */ } throw new BodyTooSlowError(why); };
  for (;;) {
    let step: ReadableStreamReadResult<Uint8Array>;
    if (limits) {
      const left = limits.deadlineMs - (Date.now() - t0);
      if (left <= 0) return await give("deadline");
      // b77t (audit 5 M-D, IH V-01): the minimum average rate is enforced while WAITING too, not only when a byte
      // arrives — a body that sends nothing more is cut off the moment its average falls under minBytesPerSec past
      // the grace (it used to keep its slot up to grace + a full stall)
      const rateEnds = Math.max(limits.graceMs, (total * 1000) / Math.max(1, limits.minBytesPerSec)) - (Date.now() - t0);
      const wait = Math.max(1, Math.min(limits.stallMs, left, rateEnds));
      let timer: ReturnType<typeof setTimeout> | undefined;
      const timedOut = new Promise<"timeout">((res) => { timer = setTimeout(() => res("timeout"), wait); });
      const got = await Promise.race([reader.read(), timedOut]).finally(() => clearTimeout(timer));
      if (got === "timeout") return await give(wait === rateEnds ? "throughput" : wait === limits.stallMs ? "stall" : "deadline");
      step = got;
    } else step = await reader.read();
    const { done, value } = step;
    if (done) break;
    total += value.length;
    if (total > cap) { try { await reader.cancel(); } catch { /* already closed */ } return null; }
    chunks.push(value);
    if (limits) {
      const el = Date.now() - t0;
      if (el > limits.graceMs && total / (el / 1000) < limits.minBytesPerSec) return await give("throughput");
    }
  }
  const buf = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) { buf.set(c, off); off += c.length; }
  return buf;
}

/** b77m (audit VAR-29): how long a JSON request body may take. Bodies are small (envelopes ≤ ~56 KB,
 *  MAX_JSON_BYTES 1 MB): the whole body within 60 s, no byte-free gap over 15 s, and after 20 s at
 *  least 512 B/s on average (1 MB still fits a 2G link's ~20 KB/s well inside the deadline).
 *  Caddy's read_body (5m30s) sits above. Env overrides are for tests. */
const JSON_BODY_LIMITS: BodyReadLimits = {
  deadlineMs: Number(Deno.env.get("VEIL_JSON_BODY_DEADLINE_MS")) || 60_000,
  stallMs: Number(Deno.env.get("VEIL_JSON_BODY_STALL_MS")) || 15_000,
  graceMs: Number(Deno.env.get("VEIL_JSON_BODY_GRACE_MS")) || 20_000,
  minBytesPerSec: Number(Deno.env.get("VEIL_JSON_BODY_MIN_BPS")) || 512,
};
/** Reads a JSON body with a hard size cap; throws tagged errors on violations. */
async function readJson(req: Request): Promise<Record<string, any>> {
  const len = Number(req.headers.get("content-length") || "0");
  if (len > MAX_JSON_BYTES) throw new Error("__too_large__");
  // Batch C (B10; review P4 F-5): count bytes WHILE reading — a chunked body
  // has no content-length and used to be buffered without any cap
  // b77m (audit VAR-29): and within JSON_BODY_LIMITS (a deadline and a stall limit, as uploads got
  // in b77r1) — the loop used to wait for ever on a body trickled or stalled by the client, so
  // anyone could hold relay memory and connections with unauthenticated half-sent bodies. A body
  // that breaks them throws BodyTooSlowError (the router answers 408 "too_slow").
  let text = "";
  if (req.body) {
    const buf = await readCapped(req, MAX_JSON_BYTES, JSON_BODY_LIMITS);
    if (!buf) throw new Error("__too_large__");
    text = new TextDecoder().decode(buf);
  }
  let body: unknown;
  try { body = text ? JSON.parse(text) : {}; } catch { throw new Error("__bad_json__"); } // malformed or over-deep JSON → clean 400
  // b70 (re-review 5): no request needs deep nesting; a very deep body parsed but then
  // overflowed the stack in String()/JSON.stringify (a 500 with a trace in the journal)
  if (jsonDepthOver(body, 32)) throw new Error("__bad_json__");
  // b75 (audit RL-06): every request body is a plain JSON object (no route takes an array
  // or a bare value; one used to reach handlers as-is), and no object anywhere in it may
  // carry a key that changes how String() treats it. A JSON object's only way to make
  // String(v) throw is an own "toString" / "valueOf" that is not a function (e.g.
  // {"toString":1}), which crashed veilIdentityGate lookup and others into a 500 with a
  // stack trace in the journal. Handlers String() fields everywhere, so the rule lives
  // here, once, for the whole tree (the prototype keys were checked at the top level only).
  if (!body || typeof body !== "object" || Array.isArray(body)) return {};
  if (hasForbiddenKey(body)) throw new Error("__bad_keys__");
  return body as Record<string, any>;
}

/** b75 (audit RL-06): keys refused anywhere in a request body (see readJson) */
const FORBIDDEN_BODY_KEYS: ReadonlySet<string> = new Set(["__proto__", "constructor", "prototype", "toString", "valueOf"]);
/** iterative walk (never recurses; the depth is already capped) */
function hasForbiddenKey(v: unknown): boolean {
  const stack: unknown[] = [v];
  while (stack.length) {
    const x = stack.pop();
    if (x === null || typeof x !== "object") continue;
    if (!Array.isArray(x)) for (const k of Object.keys(x as Record<string, unknown>)) if (FORBIDDEN_BODY_KEYS.has(k)) return true;
    for (const c of Array.isArray(x) ? x : Object.values(x as Record<string, unknown>)) if (c !== null && typeof c === "object") stack.push(c);
  }
  return false;
}

/** b75 (audit RL-06): errors that only bad input can raise inside a handler (a field of the
 *  wrong type reaching String(), atob, a Date or a KV key). They answer 400 and log one line
 *  with no stack and no request content; anything else is still a 500 (a real fault). */
function isInputError(e: unknown): boolean {
  return e instanceof TypeError || e instanceof RangeError || e instanceof SyntaxError || e instanceof URIError
    || (e instanceof DOMException && (e.name === "InvalidCharacterError" || e.name === "SyntaxError"));
}

/** b70 (re-review 9): the retired-token marker is keyed by a hash, so a deleted
 *  chat's token is not kept in the clear ("deleted means deleted") */
async function retiredTokenKey(token: string): Promise<Deno.KvKey> {
  return ["sess_token_retired", await sha256hex("veil-retired-token:" + String(token))];
}
/** b75 (audit RL-05): how long a retired session token stays unmintable */
const RETIRED_TOKEN_TTL_MS = 400 * 86400_000;
/** b75 (audit RL-05): marks a session token as never to be minted again. Every path that
 *  ends or deletes a session row calls it, 1:1 and group alike — only group tokens used to
 *  be retired, so after a 1:1 chat ended any account could create a row under its token
 *  (the old peer's polls then got 403 instead of the 404 that says "this chat is gone",
 *  and media bound to the old token answered to the new row's write secret). */
async function retireSessionToken(token: string): Promise<void> {
  if (!token) return;
  await KV.set(await retiredTokenKey(token), 1, { expireIn: RETIRED_TOKEN_TTL_MS });
}

/** b70 (re-review 7): per-account limit for routes that scan whole tables */
async function routeLimited(name: string, userId: string, perMinute: number): Promise<Response | null> {
  const rl = await rateLimit("route-" + name + ":" + userId, perMinute, 60_000, 2);
  return rl ? j({ locked: true, retry_minutes: rl.retry_minutes }, 429) : null;
}

/** iterative depth check (never recurses itself) */
function jsonDepthOver(v: unknown, max: number): boolean {
  const stack: [unknown, number][] = [[v, 0]];
  while (stack.length) {
    const [x, d] = stack.pop()!;
    if (x === null || typeof x !== "object") continue;
    if (d >= max) return true;
    for (const c of Array.isArray(x) ? x : Object.values(x as Record<string, unknown>)) if (c !== null && typeof c === "object") stack.push([c, d + 1]);
  }
  return false;
}

/** Caps a user-supplied string used as a KV key part — oversized input misses instead of crashing. */
/** b77t (audit 5 R3): an oversized value used to map to ONE shared key ("\u0000oversized"), so two different
 *  oversized inputs met in the same row wherever a caller forgot its own length check. Each oversized value now maps
 *  to its own digest under a prefix no real key part has ("\u0000h:" + SHA-256 hex): a lookup still misses, and two
 *  inputs never share a row. */
function keySafe(v: unknown): string {
  const s = String(v ?? "");
  return s.length <= MAX_KEY_PART ? s : "\u0000h:" + sha256HexSync(enc.encode(s));
}
/** b77t (audit 5 R3): FIPS 180-4 SHA-256, synchronous (keySafe can't await; Web Crypto is async only) */
const SHA256_K = new Uint32Array([0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]);
function sha256HexSync(msg: Uint8Array): string {
  const len = msg.length, total = (((len + 9) >> 6) + 1) << 6;
  const buf = new Uint8Array(total);
  buf.set(msg); buf[len] = 0x80;
  const dv = new DataView(buf.buffer);
  dv.setUint32(total - 8, Math.floor(len / 0x20000000)); dv.setUint32(total - 4, (len << 3) >>> 0);
  const h = new Uint32Array([0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]);
  const w = new Uint32Array(64);
  const rotr = (x: number, n: number) => (x >>> n) | (x << (32 - n));
  for (let off = 0; off < total; off += 64) {
    for (let i = 0; i < 16; i++) w[i] = dv.getUint32(off + i * 4);
    for (let i = 16; i < 64; i++) {
      const s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3), s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
    }
    let [a, b, c, d, e, f, g, hh] = h;
    for (let i = 0; i < 64; i++) {
      const t1 = (hh + (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) + ((e & f) ^ (~e & g)) + SHA256_K[i] + w[i]) >>> 0;
      const t2 = ((rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) + ((a & b) ^ (a & c) ^ (b & c))) >>> 0;
      hh = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
  }
  return [...h].map((x) => x.toString(16).padStart(8, "0")).join("");
}

const TOO_LARGE = (msg = "Request body too large") => j({ error: msg, message: msg }, 413);
const BAD_KEYS = () => j({ error: "Invalid field name", message: "Invalid field name" }, 400);
const BAD_JSON = () => j({ error: "Malformed JSON", message: "Malformed JSON" }, 400);
/** b77m (audit VAR-28): the relay-wide password-hashing budget is spent */
const pbkdfBusy = () => j({ error: "Busy — try again", message: "Busy — try again", code: "busy" }, 429, { "Retry-After": "5" });
/** b77m (audit VAR-29): a JSON body that broke JSON_BODY_LIMITS */
const BODY_TOO_SLOW = () => j({ error: "Request too slow — try again", message: "Request too slow — try again", code: "too_slow" }, 408);

// ---------- b75r3 (audit R-I2): ONE relay process per database, enforced ----------
// The per-group handler locks (withLock), the rate-limit lock rows read-then-written in one process and the
// memory-only keys (network tags, blob signing, burn votes) are correct only with a single relay process on a
// database (spec §12.15). That used to be a documented assumption only. Now:
//  - an environment that asks for more than one instance (VEIL_INSTANCES or WEB_CONCURRENCY above 1) is refused;
//  - each process holds a lease row in the database, renewed every RELAY_LEASE_BEAT_MS. A process starting while
//    another's lease is fresh waits for it to go stale (a restart: the old process has just stopped), and refuses to
//    start if the holder keeps renewing it (a second process is running). A process that finds its lease taken over
//    (it stalled long enough to be thought gone) stops at once, so two never serve together for long.
const RELAY_LEASE_KEY: Deno.KvKey = ["relay_instance_lease"];
const RELAY_LEASE_BEAT_MS = 5_000;
const RELAY_LEASE_STALE_MS = 15_000;
const relayInstanceId = rid();
{
  for (const name of ["VEIL_INSTANCES", "WEB_CONCURRENCY"]) {
    const v = Deno.env.get(name);
    if (v !== undefined && v.trim() !== "" && Number(v) > 1) {
      console.error(`[boot] REFUSING TO START: ${name}=${v} asks for more than one relay process. This relay must run as ONE process per database (spec §12.15).`);
      Deno.exit(1);
    }
  }
  const waitUntil = Date.now() + RELAY_LEASE_STALE_MS + 2 * RELAY_LEASE_BEAT_MS;
  let warned = false;
  for (;;) {
    const cur = await KV.get<{ id: string; beat: number }>(RELAY_LEASE_KEY);
    const fresh = !!cur.value && cur.value.id !== relayInstanceId && Date.now() - Number(cur.value.beat || 0) < RELAY_LEASE_STALE_MS;
    if (!fresh) {
      if ((await KV.atomic().check(cur).set(RELAY_LEASE_KEY, { id: relayInstanceId, beat: Date.now() }).commit()).ok) break;
      continue;
    }
    if (Date.now() > waitUntil) {
      console.error("[boot] REFUSING TO START: another relay process is running on this database (its lease is still being renewed). This relay must run as ONE process per database (spec §12.15).");
      Deno.exit(1);
    }
    if (!warned) { console.warn("[boot] another relay process held this database a moment ago — waiting for it to stop"); warned = true; }
    await new Promise((r) => setTimeout(r, 500));
  }
  // b76r2 (audit I-1): when the lease was last renewed for sure. A renewal whose commit failed (or
  // threw) used to be ignored, so a process that could not write its lease kept serving while a new
  // process, seeing the lease go stale, started on the same database. Now a process that has not
  // renewed for the stale window (RELAY_LEASE_STALE_MS, after which another may take over) stops.
  let leaseRenewedAt = Date.now();
  const leaseLapsed = () => {
    if (Date.now() - leaseRenewedAt < RELAY_LEASE_STALE_MS) return;
    console.error("[relay] STOPPING: this process could not renew its database lease for longer than the stale window, so another relay process may have started on this database (spec §12.15).");
    Deno.exit(1);
  };
  let leaseRenewing = false;
  setInterval(async () => {
    if (leaseRenewing) { leaseLapsed(); return; } // the previous renewal is still hanging
    leaseRenewing = true;
    try {
      const cur = await KV.get<{ id: string; beat: number }>(RELAY_LEASE_KEY);
      if (cur.value && cur.value.id !== relayInstanceId) {
        console.error("[relay] STOPPING: another relay process took over this database. This relay must run as ONE process per database (spec §12.15).");
        Deno.exit(1);
      }
      const beat = Date.now();
      if ((await KV.atomic().check(cur).set(RELAY_LEASE_KEY, { id: relayInstanceId, beat }).commit()).ok) leaseRenewedAt = beat;
      else { console.error("[relay] lease renewal did not commit"); leaseLapsed(); }
    } catch (e) { console.error("[relay] lease renewal error", e); leaseLapsed(); }
    finally { leaseRenewing = false; }
  }, RELAY_LEASE_BEAT_MS);
  // a clean stop hands the database over at once (a restart then doesn't wait for the lease to go stale)
  const release = async () => {
    try { const cur = await KV.get<{ id: string }>(RELAY_LEASE_KEY); if (cur.value?.id === relayInstanceId) await KV.atomic().check(cur).delete(RELAY_LEASE_KEY).commit(); } catch { /* best effort */ }
    Deno.exit(0);
  };
  for (const sig of ["SIGTERM", "SIGINT"] as const) { try { Deno.addSignalListener(sig, release); } catch { /* not on this platform */ } }
}

// b70: the forum was removed; drop the identifiers older builds remembered for it
await KV.delete(["forum_known"]).catch(() => undefined);
// b71 (audit F-09): BEFORE serving — chat and group lists read through the envelope
// index, so it must cover every envelope stored before the index existed
try { const n = await backfillEnvelopeIndex(); if (n) console.log(`[boot] envelope index: ${n} entries added`); }
catch (e) { console.error("[boot] envelope index backfill error", e); }
// b77s (audit 4 F-01): BEFORE serving — every raw (pre-b199) sign-in token row moves to its hashed key (expired ones
// go), and every token row gets its per-account index entry (b77s accounts routes); counts are logged
try {
  const m = await migrateAuthRows(true);
  authIxReady = true;
  console.log(`[boot] b77s: sign-in tokens — ${m.moved} raw row(s) moved to their hashed key, ${m.expired} expired raw row(s) deleted, ${m.indexed} index entr${m.indexed === 1 ? "y" : "ies"} added`);
} catch (e) { console.error("[boot] sign-in token migration error (the sweeper retries; account token lookups scan the table meanwhile)", e); }
// b75r1 (audit REL-03): BEFORE serving — retired labels are kept as hashes only
try { const n = await migrateRetiredLabels(); if (n) console.log(`[boot] retired labels: ${n} row(s) now kept as hashes`); }
catch (e) { console.error("[boot] retired label migration error", e); }
// b75r1 (audit REL-05): vote rows from before (account hashes) or from an earlier key (unmatchable) go
try {
  let n = 0;
  for await (const e of KV.list<BurnVoteRow>({ prefix: ["burn_votes"] })) if (Array.isArray(e.value) || (e.value as { k?: string })?.k !== BURN_VOTE_KEY_ID) { await KV.delete(e.key); n++; }
  // b76r2 (audit GB-1): burn snapshots made under an earlier key can't be matched any more (their envelopes keep
  // their normal expiry)
  for await (const e of KV.list<BurnEligRow>({ prefix: ["burn_elig"] })) if ((e.value as { k?: string })?.k !== BURN_VOTE_KEY_ID) { await KV.delete(e.key); n++; }
  if (n) console.log(`[boot] dropped ${n} group burn-vote row(s) from an earlier format or key`);
} catch (e) { console.error("[boot] burn vote cleanup error", e); }
// b77 (sealed sender): the TURN eligibility cache is gone; rows an older relay left (each named an
// account hash with the chat and the two Vardum IDs that qualified) are deleted
(async () => { let n = 0; for await (const e of KV.list({ prefix: ["turn_ok"] })) { await KV.delete(e.key); n++; } if (n) console.log(`[boot] removed ${n} TURN eligibility row(s)`); })().catch((e) => console.error("[boot] turn_ok cleanup error", e));
// b71 (audit F-16): the network-tag day keys older relays stored in the database
dropStoredIpTagKeys().then((n) => { if (n) console.log(`[boot] removed ${n} stored key(s) (blob-signing / pseudonym keys are memory-only; network-tag keys are memory-only too)`); }).catch((e) => console.error("[boot] network-tag key cleanup error", e));
// b77s (audit 4 WS-01): the network-tag key FILE an earlier relay kept beside kv.db goes (keys are memory-only now)
try { const n = await dropNetTagKeyFile(); if (n) console.log(`[boot] b77s: deleted ${n} old network-tag key file(s) — the day keys are held in memory only (a restart resets per-network throttles)`); }
catch (e) { console.error("[boot] network-tag key file cleanup error", e); }

// b77r2 (audit R2-R-3): old-shape retired markers are re-keyed BEFORE the relay serves, so no
// retired mailbox id ever reads as "absent" (a failure is logged and the old key stays checked)
try { const n = await migrateRetiredMarkers(); if (n) console.log(`[boot] b77r2: re-keyed ${n} retired mailbox marker(s)`); }
catch (e) { console.error("[boot] retired marker migration error (old keys stay checked)", e); }
// b77p (audit 2 VAR-01): b77's stored mailbox links (push_refs, their index, mailbox push_ref, open tickets) go
// BEFORE the relay serves; and the open-token issuer key exists before the first join
// b77p round 2 (owner decisions 1, 3, 4): ...unless the transition window is open (legacy phones keep their rows until
// it ends; the sweeper drops them then), and with them every account push row (account-level push is gone); the
// issuer key comes from its file (production refuses to start without it)
await resolveCompatWindow();
await resolveRlMarkEpoch(); // b77u (audit 6 W2)
if (!compatOn()) {
  try { const n = await migrateB77pLinks(); legacyRowsDropped = true; if (n) console.log(`[boot] b77p: removed ${n} legacy link / push row(s)`); }
  catch (e) { console.error("[boot] b77p link migration error", e); }
}
await loadOpenIssuerKey();
// b77n (pre-audit L3): the secondary indexes cover every row BEFORE the relay serves (the hot paths read only them)
// b77n2 (review M1): readers trust the indexes only after a COMPLETE backfill (ixReady); a failure leaves them on
// full table scans and the backfill is retried in the background until it completes
{
  const runBackfill = async (): Promise<boolean> => {
    try { const n = await backfillIndexes(); if (n) console.log(`[boot] b77n: indexed ${n} row(s)`); ixReady = true; return true; }
    catch (e) { console.error("[boot] index backfill error — index readers stay on full table scans until it completes", e); return false; }
  };
  if (!(await runBackfill())) {
    const retry = () => setTimeout(async () => { if (!(await runBackfill())) retry(); }, IX_BACKFILL_RETRY_MS);
    retry();
  }
}
// b77n (pre-audit L1): keyed-tag bindings that held a plain account hash
dropLegacyGtagBinds().then((n) => { if (n) console.log(`[boot] b77n: dropped ${n} legacy keyed-tag binding(s)`); }).catch((e) => console.error("[boot] keyed-tag binding cleanup error", e));

// ---------- serve ----------
// b199 (audit: bound 0.0.0.0, only UFW stopped direct :8000 access — and a
// direct hit looks "local", i.e. unthrottled): listen on loopback only; Caddy
// is the sole way in. VEIL_HOST can override for local test setups.
Deno.serve({ port: PORT, hostname: Deno.env.get("VEIL_HOST") || "127.0.0.1" }, async (req, info) => {
  const url = new URL(req.url);
  for (const [method, re, handler, pattern] of routes) {
    if (req.method !== method) continue;
    const m = url.pathname.match(re);
    if (m) {
      try { return await handler(req, m, url); }
      catch (e) {
        const msg = String((e as Error).message || e);
        if (msg === "__too_large__") return TOO_LARGE();
        if (e instanceof PbkdfBusyError) return pbkdfBusy(); // b77m (audit VAR-28)
        if (e instanceof BodyTooSlowError) return BODY_TOO_SLOW(); // b77m (audit VAR-29)
        if (e instanceof NoPublicOriginError) return j({ error: "File links are not configured on this relay", message: "File links are not configured on this relay", code: "no_public_origin" }, 503); // b77p (audit VAR-27)
        if (msg === "__bad_keys__") return BAD_KEYS();
        if (msg === "__bad_json__") return BAD_JSON();
        // b75 (audit RL-06): no handler answers bad input with a 500 (or logs its stack)
        if (isInputError(e)) {
          console.warn("bad request input", pattern, (e as Error).name); // b77n (pre-audit I3): the route, not the path
          return j({ error: "Malformed request", message: "Malformed request" }, 400);
        }
        console.error("handler error", method, pattern, e); // b77n (pre-audit I3): the route pattern, never the path (ids)
        return j({ error: "Internal error", message: "Internal error" }, 500); // Batch C (B7): details stay in the server log
      }
    }
  }
  return j({ message: "Not found" }, 404);
});

console.log(`VEIL RELAY Phase 1 — listening on http://localhost:${PORT}`);
console.log("Contract: /api/apps/:appId/{auth/*,entities/*,functions/*} — matches the native client exactly.");

// ---------- sweeper: every 10 min, purge expired envelopes + stale limiter keys (K-30) ----------
// b198 BLOB RETENTION BACKSTOP: media ciphertext whose envelope was deleted
// WITHOUT a client-driven blob delete (never-opened media, ✕ of a session whose
// media was never decrypted) is swept at bounded retention — the max unopened
// horizon (48h chip) + margin. Claim wording: media is deleted at burn, or at
// latest 49h after upload if never opened.

/** b199: per-account daily cap on encrypted file uploads (disk-fill guard) */
const UPLOAD_DAILY_CAP = 1024 * 1024 * 1024;
/** b70 (re-review R1): envelope bytes per UTC day */
const ENVELOPE_ACCOUNT_DAILY_BYTES = 50 * 1024 * 1024; // ~1000 full-size messages (media rides blobs, not envelopes)
/** b70 (re-review 3): per network (an IPv6 /64), and the "light user" line under a full relay */
const ENVELOPE_NETWORK_DAILY_BYTES = 300 * 1024 * 1024;
const ENVELOPE_LIGHT_USER_BYTES = 2 * 1024 * 1024;
/** b77r1 (audit R-1): the sealed path's light lines — a mailbox under 2 MB today (as an account on
 *  the group path) AND a network under 20 MB today (the /56 and /48 at x4, x16). 20 MB is ten
 *  light mailboxes' worth, about 2500 typical text envelopes: a household or office behind one
 *  address stays light, while filling the last 40% of a 10 GB relay day then needs ~200 networks
 *  (or ~13 IPv6 /48s) instead of one sender with fresh mailboxes. A carrier-grade NAT can cross
 *  it — its users then wait for the next UTC day only while the relay is past 60%. Env overrides
 *  are for tests. */
const ENVELOPE_LIGHT_MBOX_BYTES = Number(Deno.env.get("VEIL_ENVELOPE_LIGHT_MBOX_BYTES")) || ENVELOPE_LIGHT_USER_BYTES;
const ENVELOPE_LIGHT_NETWORK_BYTES = Number(Deno.env.get("VEIL_ENVELOPE_LIGHT_NETWORK_BYTES")) || 20 * 1024 * 1024;
const ENVELOPE_RELAY_DAILY_BYTES = (Number(Deno.env.get("VEIL_ENVELOPE_RELAY_DAILY_GB")) || 10) * 1024 * 1024 * 1024;
/** b70 (audit RLY-15): per network, and for the whole relay, per UTC day.
 *  Overridable for a bigger disk (VEIL_UPLOAD_RELAY_DAILY_GB). */
const UPLOAD_NETWORK_DAILY_CAP = 3 * 1024 * 1024 * 1024;
const UPLOAD_RELAY_DAILY_CAP = (Number(Deno.env.get("VEIL_UPLOAD_RELAY_DAILY_GB")) || 40) * 1024 * 1024 * 1024;
const BLOB_RETENTION_MS = 49 * 3600 * 1000;

// ---------- b77m (audit VAR-03): storage the relay may still fill ----------
// The relay-wide upload cap was a fixed 40 GB a day — about the documented server's whole disk — and
// vault containers are never swept, so free accounts could fill the disk (then every KV write, and so
// every route, fails). Now every upload (both routes) first needs room in STORAGE HEADROOM:
//   headroom = min(BLOB_DIR_BUDGET − bytes in the blob folder,  free disk − DISK_MIN_FREE)
// (the free-disk half needs --allow-sys=statfs, which deploy-relay.sh grants; without it the folder
// budget alone applies). An upload larger than the headroom left (minus uploads in flight) is refused
// with 507 "storage_full", and the day's relay-wide cap is min(UPLOAD_RELAY_DAILY_CAP, today's bytes +
// headroom), so the 60 % "light uploaders only" rule closes in as the disk does. Vault pins have their
// own caps (VAULT_PIN_*, below). Env sizes in GB, or MB for tests.
const envBytes = (gbName: string, mbName: string, gbDefault: number) =>
  Number(Deno.env.get(mbName)) > 0 ? Number(Deno.env.get(mbName)) * 1024 * 1024 : (Number(Deno.env.get(gbName)) || gbDefault) * 1024 * 1024 * 1024;
const BLOB_DIR_BUDGET_BYTES = envBytes("VEIL_BLOB_DIR_BUDGET_GB", "VEIL_BLOB_DIR_BUDGET_MB", 16);
const DISK_MIN_FREE_BYTES = envBytes("VEIL_DISK_MIN_FREE_GB", "VEIL_DISK_MIN_FREE_MB", 4);
/** pinned (vault-referenced, never swept) bytes: per account in all, per network per UTC day
 *  (/56, /48 at x4, x16), and for the whole relay. A vault container is always 24 MB
 *  (vendor/device/src/vaults.ts CONTAINER_BYTES), so the defaults are 20 vaults per account (the
 *  row cap stays 40, for small legacy containers), 10 new vaults a day per network, 8 GB relay-wide. */
const VAULT_PIN_ACCOUNT_BYTES = envBytes("VEIL_VAULT_PIN_ACCOUNT_GB", "VEIL_VAULT_PIN_ACCOUNT_MB", 0.5);
const VAULT_PIN_NETWORK_DAILY_BYTES = envBytes("VEIL_VAULT_PIN_NETWORK_DAILY_GB", "VEIL_VAULT_PIN_NETWORK_DAILY_MB", 0.25);
const VAULT_PIN_RELAY_BYTES = envBytes("VEIL_VAULT_PIN_RELAY_GB", "VEIL_VAULT_PIN_RELAY_MB", 8);
/** b77m review (L4): the relay-wide pin budget could be used up for good — pins never expire, and two /48s a day
 *  of fresh anonymous accounts fill 8 GB in about two weeks, after which nobody could make a vault. Now the last
 *  VAULT_PIN_RESERVE_PCT % of it (default 25 %) is only for accounts older than VAULT_PIN_NEW_ACCOUNT_MS
 *  (default 7 days): new accounts can fill at most the first 75 %. (Accounts from before the relay recorded a
 *  creation time count as old.) The per-account and per-network daily caps are unchanged. VEIL_VAULT_PIN_NEW_
 *  ACCOUNT_MS is for TEST relays; VEIL_VAULT_PIN_RESERVE_PCT=0 turns the reserve off. */
const VAULT_PIN_RESERVE_PCT = (() => { const v = Number(Deno.env.get("VEIL_VAULT_PIN_RESERVE_PCT") ?? "25"); return Number.isFinite(v) && v >= 0 && v < 100 ? v : 25; })();
const VAULT_PIN_NEW_ACCOUNT_MS = Number(Deno.env.get("VEIL_VAULT_PIN_NEW_ACCOUNT_MS")) || 7 * 86400_000;
/** b77m review (L4): an account younger than VAULT_PIN_NEW_ACCOUNT_MS (its user row's `created`) */
async function vaultPinNewAccount(userId: string): Promise<boolean> {
  const u = (await KV.get<Record<string, unknown>>(["user", userId])).value;
  const created = Date.parse(String(u?.created ?? ""));
  return Number.isFinite(created) && Date.now() - created < VAULT_PIN_NEW_ACCOUNT_MS;
}
/** bytes in the blob folder: counted by the sweeper (and at first use), raised by every write between sweeps */
let blobDirBytes: number | null = null;
/** upload bytes reserved by bodies being read right now */
let storageInFlight = 0;
async function blobDirUsage(): Promise<number> {
  if (blobDirBytes === null) {
    let n = 0;
    try { for await (const f of Deno.readDir(BLOB_DIR)) if (f.isFile) n += (await Deno.stat(BLOB_DIR + f.name).catch(() => null))?.size ?? 0; } catch { /* no folder yet */ }
    blobDirBytes = n;
  }
  return blobDirBytes;
}
const noteBlobWritten = (bytes: number) => { if (blobDirBytes !== null) blobDirBytes += bytes; };
let diskFreeCache: { at: number; free: number | null } | null = null;
/**
 * b77s (audit 4 F-02): whether the free-disk reading works. It used to trust Deno.permissions.querySync({sys:
 * statfs}) and treat any statfs failure as "unknown" in silence — but node:fs statfs also needs READ access to the
 * folder, so a unit with --allow-sys=statfs and a narrower --allow-read threw NotCapable and every free-disk floor
 * (uploads' DISK_MIN_FREE, the database's KV_MIN_FREE) was quietly off. Now a REAL statfs of BLOB_DIR runs at boot
 * (checkDiskFreeAtBoot), a failure is logged loudly (and again whenever the reading starts failing), and the state
 * is in /admin/stats ("disk_free"). deploy-relay.sh grants both: --allow-sys=statfs and --allow-read=VEIL_DIR.
 */
const diskFreeStatus: { state: "unchecked" | "ok" | "failing" | "test_file"; checked_at: string; error?: string; free_bytes?: number } = { state: "unchecked", checked_at: "" };
async function statfsFree(): Promise<number> {
  // (without the sys permission the call would prompt or throw: say so plainly instead)
  if (Deno.permissions.querySync({ name: "sys", kind: "statfs" } as Deno.PermissionDescriptor).state !== "granted") throw new Error("no --allow-sys=statfs");
  const nodeFs = "node:fs/promises"; // (a computed specifier: no @types/node lookup at type-check time)
  const { statfs } = await import(nodeFs) as { statfs: (p: string) => Promise<{ bavail: number | bigint; bsize: number | bigint }> };
  const s = await statfs(BLOB_DIR);
  const free = Number(s.bavail) * Number(s.bsize);
  if (!Number.isFinite(free)) throw new Error("statfs gave no usable number");
  return free;
}
function noteDiskFreeState(free: number | null, err?: unknown) {
  const was = diskFreeStatus.state;
  diskFreeStatus.checked_at = new Date().toISOString();
  if (free !== null) { diskFreeStatus.state = "ok"; diskFreeStatus.free_bytes = free; delete diskFreeStatus.error; return; }
  diskFreeStatus.state = "failing";
  diskFreeStatus.error = String((err as Error)?.message === "no --allow-sys=statfs" ? "no --allow-sys=statfs" : (err as Error)?.name || err || "error").slice(0, 80);
  delete diskFreeStatus.free_bytes;
  if (was !== "failing") console.error(`[relay] WARNING: the free-disk reading FAILED (${diskFreeStatus.error}) — the disk-free floors (uploads, database writes) are OFF until it works. The relay needs BOTH --allow-sys=statfs and read access to ${BLOB_DIR} (deploy-relay.sh: --allow-read=${"$"}{VEIL_DIR}).`);
}
async function checkDiskFreeAtBoot(): Promise<void> {
  if (TEST_DISK_FREE_FILE) { diskFreeStatus.state = "test_file"; diskFreeStatus.checked_at = new Date().toISOString(); return; }
  try { await Deno.mkdir(BLOB_DIR, { recursive: true }).catch(() => undefined); noteDiskFreeState(await statfsFree()); }
  catch (e) { noteDiskFreeState(null, e); }
}
/** free bytes on the blob folder's filesystem, or null when unknown (the reading fails: see diskFreeStatus); cached 10 s */
async function diskFreeBytes(): Promise<number | null> {
  // b77n: VEIL_TEST_DISK_FREE_FILE (TEST relays only; production never sets it) names a file holding the free
  // space in MB, read on every call, so a suite can run a relay "with a nearly full disk" and back
  if (TEST_DISK_FREE_FILE) { const mb = Number((await Deno.readTextFile(TEST_DISK_FREE_FILE).catch(() => "")).trim()); return Number.isFinite(mb) && mb >= 0 ? mb * 1024 * 1024 : null; }
  if (diskFreeCache && Date.now() - diskFreeCache.at < 10_000) return diskFreeCache.free;
  let free: number | null = null;
  // b77s (audit 4 F-02): a real statfs every time (no permission-query shortcut); a failure is recorded and logged
  try { free = await statfsFree(); noteDiskFreeState(free); } catch (e) { free = null; noteDiskFreeState(null, e); }
  diskFreeCache = { at: Date.now(), free };
  return free;
}
/** bytes uploads may still add (never below 0) */
async function storageHeadroom(): Promise<number> {
  let room = BLOB_DIR_BUDGET_BYTES - await blobDirUsage();
  const free = await diskFreeBytes();
  if (free !== null) room = Math.min(room, free - DISK_MIN_FREE_BYTES);
  return Math.max(0, room - storageInFlight);
}
/** the storage gate of an upload reserving `reserved` bytes: null (refuse: 507 storage_full) or the
 *  day's effective relay-wide cap and a release (call once the body is stored or refused) */
async function storageGate(reserved: number, allKey: Deno.KvKey): Promise<{ allCap: number; release: () => void } | null> {
  const room = await storageHeadroom();
  if (reserved > room) return null;
  storageInFlight += reserved;
  const used = Number((await KV.get<Deno.KvU64>(allKey)).value?.value ?? 0n);
  let done = false;
  return { allCap: Math.min(UPLOAD_RELAY_DAILY_CAP, used + room), release: () => { if (!done) { done = true; storageInFlight = Math.max(0, storageInFlight - reserved); } } };
}
const STORAGE_FULL_MSG = "The relay's storage is full — try again later";
const TEST_DISK_FREE_FILE = Deno.env.get("VEIL_TEST_DISK_FREE_FILE") || "";
// b77s (audit 4 F-02): a real free-disk reading at boot (here, once its settings exist; a failure is logged loudly and shown in
// /admin/stats). It runs as the relay finishes starting (diskFreeBytes does the same reading on every use anyway).
await checkDiskFreeAtBoot();
/**
 * b77n (pre-audit M1): the DATABASE's disk gate. The upload routes had the storage gate, but rows kept in the
 * database (notes and vaults never expire, group seats, envelopes up to 30 days) were capped only per day, so
 * they could still fill the disk — and then every write, on every route, fails. Every write that keeps rows —
 * entity creates and updates (POST / PUT /entities), group envelopes (submitEnvelope) and 1:1 envelopes
 * (sealedSubmit) — is refused with 507 "storage_full" while the disk's free space is under KV_MIN_FREE (default
 * 2 GB: half of DISK_MIN_FREE, so uploads stop first and messages keep flowing as long as possible). Reads,
 * deletes, burns and sign-ins are never gated (they free space or write little). Needs --allow-sys=statfs
 * (deploy-relay.sh grants it); without it free space is unknown and this gate is open (the daily caps remain).
 */
const KV_MIN_FREE_BYTES = envBytes("VEIL_KV_MIN_FREE_GB", "VEIL_KV_MIN_FREE_MB", 2);
async function kvStorageFull(): Promise<boolean> {
  const free = await diskFreeBytes();
  return free !== null && free < KV_MIN_FREE_BYTES;
}
const KV_STORAGE_FULL = () => j({ error: STORAGE_FULL_MSG, message: STORAGE_FULL_MSG, code: "storage_full" }, 507, { "Retry-After": "600" });
const ENTITY_NET_DAILY_LIMIT = () => j({ error: "Too much new data from this network today — try again tomorrow", message: "Too much new data from this network today — try again tomorrow", code: "daily_limit", locked: true, retry_minutes: 60 }, 429);
/** b77n (pre-audit M1): reserves an entity write's bytes on the caller's network day counters (ENTITY_NETWORK_DAILY_BYTES;
 *  the /56 and /48 at x4, x16; a trusted loopback test relay's "local" is exempt). null = over the cap. */
async function reserveEntityNetBytes(req: Request, bytes: number): Promise<{ undo: () => Promise<void> } | null> {
  const net = await clientTag(req);
  const day = new Date().toISOString().slice(0, 10);
  const caps: [Deno.KvKey, number][] = [];
  if (net !== "local") caps.push([["ent_bytes_net", net, day], ENTITY_NETWORK_DAILY_BYTES]);
  for (const w of await clientWideTags(req)) caps.push([["ent_bytes_net" + w.bits, w.tag, day], ENTITY_NETWORK_DAILY_BYTES * WIDE_FACTOR[w.bits]]);
  if (!caps.length || bytes <= 0) return { undo: async () => undefined };
  let q = await adjustQuota(caps, bytes);
  for (let i = 0; i < 5 && q === "busy"; i++) { await new Promise((r) => setTimeout(r, 2 + Math.random() * 10)); q = await adjustQuota(caps, bytes); }
  if (q !== "ok") return null;
  return { undo: async () => { await adjustQuota(caps, -bytes).catch(() => undefined); } };
}
/** relay-wide pinned bytes: recounted by the sweeper (and at first use), raised by every pin between */
let vaultPinnedBytes: number | null = null;
const blobSizeOf = async (uri: string): Promise<number> => { const p = blobPathOf(uri); return p ? (await Deno.stat(p).catch(() => null))?.size ?? 0 : 0; };
async function countVaultPinned(): Promise<number> {
  const seen = new Set<string>();
  let n = 0;
  for await (const e of KV.list<Record<string, unknown>>({ prefix: ["entity", "VeilVault"] }, { consistency: "strong" })) {
    const uri = String(e.value?.container_uri || "");
    if (!uri.startsWith("blob:") || seen.has(uri)) continue;
    seen.add(uri);
    n += await blobSizeOf(uri);
  }
  return n;
}
/**
 * b77m (audit VAR-03): may this account point a vault row at `uri` (replacing `replacing`, on an
 * update)? Checks the account's pinned total (its other vaults' files + this one), the relay-wide
 * pinned total and the free storage, then RESERVES the bytes on the caller's network day counters.
 * Returns the refusal, or a commit/undo pair: commit() once the row is written (adds to the relay
 * total), undo() if it was not (gives the network bytes back).
 */
async function vaultPinGate(req: Request, userId: string, uri: string, replacing: string | null): Promise<Response | { commit: () => void; undo: () => Promise<void> }> {
  const size = uri.startsWith("blob:") ? await blobSizeOf(uri) : 0;
  const noop = { commit: () => undefined, undo: async () => undefined };
  if (size <= 0 || uri === replacing) return noop;
  const acct = await accountHashOf(userId);
  const seen = new Set<string>([uri]);
  let mine = size;
  for await (const e of acctRows("VeilVault", acct)) { // b77n (pre-audit L3): by ["ix_acct"]
    if (String(e.value?._acct ?? "") !== acct) continue;
    const u = String(e.value?.container_uri || "");
    if (!u.startsWith("blob:") || seen.has(u) || u === replacing) continue;
    seen.add(u);
    mine += await blobSizeOf(u);
  }
  if (mine > VAULT_PIN_ACCOUNT_BYTES) return j({ message: "Vault storage limit reached — delete a vault first", code: "vault_storage_limit" }, 403);
  if (vaultPinnedBytes === null) vaultPinnedBytes = await countVaultPinned();
  if (vaultPinnedBytes + size > VAULT_PIN_RELAY_BYTES) return j({ message: STORAGE_FULL_MSG, code: "storage_full" }, 507, { "Retry-After": "3600" });
  // b77m review (L4): the reserve — new accounts can't take the last VAULT_PIN_RESERVE_PCT % of the relay budget
  if (VAULT_PIN_RESERVE_PCT > 0 && vaultPinnedBytes + size > VAULT_PIN_RELAY_BYTES * (1 - VAULT_PIN_RESERVE_PCT / 100) && await vaultPinNewAccount(userId)) {
    return j({ message: STORAGE_FULL_MSG, code: "storage_full" }, 507, { "Retry-After": "3600" });
  }
  const free = await diskFreeBytes();
  if (free !== null && free < DISK_MIN_FREE_BYTES) return j({ message: STORAGE_FULL_MSG, code: "storage_full" }, 507, { "Retry-After": "3600" });
  const net = await clientTag(req);
  const day = new Date().toISOString().slice(0, 10);
  const caps: [Deno.KvKey, number][] = [];
  if (net !== "local") caps.push([["vault_pin_net", net, day], VAULT_PIN_NETWORK_DAILY_BYTES]);
  for (const w of await clientWideTags(req)) caps.push([["vault_pin_net" + w.bits, w.tag, day], VAULT_PIN_NETWORK_DAILY_BYTES * WIDE_FACTOR[w.bits]]);
  if (caps.length) {
    const q = await adjustQuota(caps, size);
    if (q !== "ok") return j({ message: "Too many new vaults from this network today — try again tomorrow", code: "daily_limit" }, 429);
  }
  return {
    commit: () => { if (vaultPinnedBytes !== null) vaultPinnedBytes += size; },
    undo: async () => { if (caps.length) await adjustQuota(caps, -size).catch(() => undefined); },
  };
}
// b199: submitEnvelope used to write a second full ciphertext copy under
// ["veil_env", token, id] that nothing read and that expiry/burn never removed,
// so expired and burnt messages kept a server copy forever. The write is gone;
// this drops every copy left from before, once at boot and on every sweep
// (an empty scan once they are cleared).
// Push-coalesce rows written before they carried an expireIn go the same way.
async function sweepLegacyRows(): Promise<number> {
  let n = 0;
  for await (const e of KV.list({ prefix: ["veil_env"] }, { consistency: "strong" })) { await KV.delete(e.key); n++; }
  for (const p of ["push_coalesce", "push_coalesce_invite", "push_coalesce_group", "push_coalesce_mbox"]) {
    for await (const e of KV.list<number>({ prefix: [p] }, { consistency: "strong" })) {
      if (Date.now() - Number(e.value || 0) > COALESCE_TTL_MS) { await KV.delete(e.key); n++; }
    }
  }
  // b199: daily upload-quota counters are only needed for their own day
  const today = new Date().toISOString().slice(0, 10);
  for await (const e of KV.list({ prefix: ["upload_quota"] }, { consistency: "strong" })) {
    if (String(e.key[2]) < today) { await KV.delete(e.key); n++; }
  }
  return n;
}
migrateBlobOwners().then((n) => { if (n) console.log(`[boot] recorded owners for ${n} existing blob file(s)`); }).catch((e) => console.error("[boot] blob owner migration error", e));
dropSessionDisplayNames().then((n) => { if (n) console.log(`[boot] removed stored nicknames from ${n} session row(s)`); }).catch((e) => console.error("[boot] session nickname cleanup error", e));
sweepLegacyRows().then((n) => { if (n) console.log(`[boot] dropped ${n} legacy envelope-copy / push-coalesce row(s)`); }).catch((e) => console.error("[boot] legacy row cleanup error", e));
migrateB77r1RowsRetrying().then((n) => { if (n) console.log(`[boot] b77r1: indexed ${n} row(s)`); }).catch((e) => console.error("[boot] b77r1 row migration error", e));
setInterval(async () => {
  try { const d = ((await coalescedPurge()).purged as { deleted?: number } | undefined)?.deleted; if (d) console.log(`[sweeper] purged ${d} expired envelope(s)`); } // b77p (audit VAR-24): shares an in-flight sweep
  catch (e) { console.error("[sweeper] error", e); }
  try { await pruneStats(); } catch (e) { console.error("[sweeper] stats prune error", e); }
  try {
    let bn = 0;
    // Batch C (A4b; reviews P2 V-10, P4 F-1; port of the b200 fix): vault
    // containers live in the same directory but are kept until their vault is
    // deleted — the 49 h backstop is for media and transfer bundles only.
    const vaultBlobs = new Set<string>();
    for await (const e of KV.list({ prefix: ["entity", "VeilVault"] }, { consistency: "strong" })) {
      const v = e.value as Record<string, unknown>;
      const uri = String(v.container_uri || "");
      if (!uri.startsWith("blob:")) continue;
      // Batch E (RV-39): only a container the vault's own account uploaded
      const rec = (await KV.get<string>(["blob_owner", blobIdOf(uri)])).value;
      if (!rec || rec === await blobOwnerTag(String(v._acct || ""), blobIdOf(uri))) vaultBlobs.add(blobIdOf(uri));
    }
    // b77m (audit VAR-03): the folder's bytes and the pinned bytes are recounted on the way
    let kept = 0, pinned = 0;
    for await (const f of Deno.readDir(BLOB_DIR)) {
      if (!f.isFile) continue;
      const st = await Deno.stat(BLOB_DIR + f.name).catch(() => null);
      if (vaultBlobs.has(f.name)) { kept += st?.size ?? 0; pinned += st?.size ?? 0; continue; }
      if (st && st.mtime && Date.now() - st.mtime.getTime() > BLOB_RETENTION_MS) {
        await Deno.remove(BLOB_DIR + f.name).catch(() => undefined);
        bn++;
      } else kept += st?.size ?? 0;
    }
    blobDirBytes = kept;
    vaultPinnedBytes = pinned;
    // owner records of files that are gone (burnt, swept, collected)
    for await (const e of KV.list({ prefix: ["blob_owner"] }, { consistency: "strong" })) {
      const p = blobPathOf("blob:" + String(e.key[1]));
      if (!p || !(await Deno.stat(p).then(() => true).catch(() => false))) await KV.delete(e.key);
    }
    // b70 (VAR-06): and their chat bindings (b77: and their mailbox bindings; b77r1 (audit R-6):
    // with the ["blob_by_mbox"] entry, and any entry whose binding is gone or moved)
    for await (const e of KV.list<string>({ prefix: ["blob_mbox"] }, { consistency: "strong" })) {
      const p = blobPathOf("blob:" + String(e.key[1]));
      if (!p || !(await Deno.stat(p).then(() => true).catch(() => false))) {
        await KV.atomic().delete(e.key).delete(["blob_by_mbox", String(e.value ?? ""), String(e.key[1])]).commit();
      }
    }
    for await (const e of KV.list({ prefix: ["blob_by_mbox"] }, { consistency: "strong" })) {
      if ((await KV.get<string>(["blob_mbox", String(e.key[2])])).value !== String(e.key[1])) await KV.delete(e.key);
    }
    for (const pfx of ["blob_session", "blob_group"]) for await (const e of KV.list({ prefix: [pfx] }, { consistency: "strong" })) { // b77u (U-M9): group bindings too
      const p = blobPathOf("blob:" + String(e.key[1]));
      if (!p || !(await Deno.stat(p).then(() => true).catch(() => false))) await KV.delete(e.key);
    }
    if (bn) console.log(`[sweeper] deleted ${bn} expired blob file(s)`);
  } catch (e) { console.error("[sweeper] blob cleanup error", e); }
  try { await sweepOpenKeys(Date.now()); } catch (e) { console.error("[sweeper] open key error", e); } // b77p (audit 2 VAR-01)
  // b77p round 2 (owner decision 4): the window ended while the relay ran — the legacy rows go now (once)
  if (!compatOn() && !legacyRowsDropped) {
    try { const n = await migrateB77pLinks(); legacyRowsDropped = true; console.log(`[sweeper] transition window over: removed ${n} legacy link / push row(s)`); }
    catch (e) { console.error("[sweeper] legacy row cleanup error", e); }
  }
  try { const n = await sweepStaleIndexes(); if (n) console.log(`[sweeper] dropped ${n} stale index entr(ies)`); } catch (e) { console.error("[sweeper] index sweep error", e); } // b77n (pre-audit L3)
  try {
    // rate-limit buckets live one window; anything from a previous window is dead weight
    const curMinute = Math.floor(Date.now() / 60_000);
    const curHour = Math.floor(Date.now() / 3_600_000);
    let n = 0;
    for await (const e of KV.list({ prefix: ["rl"] }, { consistency: "strong" })) {
      // b70 (re-review 2): new buckets carry their window size, so any window
      // (10 min, 15 min, ...) is told apart exactly; a 10-minute bucket used to
      // read as a minute bucket and be deleted every sweep
      if (e.key.length === 4) {
        const win = Number(e.key[3]);
        if (win > 0 && Number(e.key[2]) < Math.floor(Date.now() / win) - 1) { await KV.delete(e.key); n++; }
        continue;
      }
      const bucket = Number(e.key[e.key.length - 1]);
      // minute buckets are epoch-minutes (~29.6 M in 2026); hour keys are epoch-hours
      // (~0.49 M). Batch D (D-15 follow-up): the old test (`bucket < 1e6`) was the
      // wrong way round — every sweep deleted the CURRENT hour's buckets, so the
      // 10-signups-per-hour limit reset every sweep.
      // Batch E (round-3 review R3-03): day buckets (epoch-days, ~20 k in 2026) were
      // read as hour keys and deleted every sweep, so a "per day" cap reset every
      // 2 min. Buckets are told apart by size: minutes > hours > days.
      const curDay = Math.floor(Date.now() / 86_400_000);
      const isMinuteKey = bucket > curHour + 1;
      const isHourKey = !isMinuteKey && bucket > curDay + 1;
      const stale = isMinuteKey ? bucket < curMinute - 2 : isHourKey ? bucket < curHour - 2 : bucket < curDay - 2;
      if (stale) { await KV.delete(e.key); n++; }
    }
    if (n) console.log(`[sweeper] dropped ${n} stale limiter key(s)`);
  } catch (e) { console.error("[sweeper] rl cleanup error", e); }
  try {
    const n = await sweepLegacyRows();
    if (n) console.log(`[sweeper] dropped ${n} legacy envelope-copy / push-coalesce row(s)`);
  } catch (e) { console.error("[sweeper] legacy row cleanup error", e); }
}, Number(Deno.env.get("VEIL_SWEEP_MS")) || 2 * 60 * 1000); // Batch C: VEIL_SWEEP_MS is for TEST relays only; production never sets it. b198 (audit follow-up): 10-min sweeper granularity left burnt/expired rows visible up to 10 min past their death — an auditor checking right after a burn sees the row and reads the burn as a no-op. 2-min cadence: deletion lands close to the promised moment; scan cost is trivial at current scale.

// ========== BASE44-ALIGNED veilSessionGate (b198 mirror of the proven source) ==========
const validClientId = (v: unknown) => /^[A-Za-z0-9_-]{4,64}$/.test(String(v ?? "").trim());
const validVeilId = (v: unknown) => /^[1-9A-HJ-NP-Za-km-z]{16}$/.test(String(v ?? "").trim());
const retentionMs = (s: Record<string, any>) => { const h = Number(s.key_retention_hours); return h === 0 ? 365 * 24 * 3600 * 1000 : ((Number.isFinite(h) && h) || 168) * 3600 * 1000; };
const declaredMessageMs = (s: Record<string, any>) => { const a = Number(s?.default_ttl_seconds), b = Number(s?.expire_after_seconds); return Math.max(0, Math.max(Number.isFinite(a) ? a : 0, Number.isFinite(b) ? b : 0)) * 1000; };
const sessionHorizonMs = (s: Record<string, any>) => Math.max(retentionMs(s), declaredMessageMs(s));
// b75r3 (audit I-2): the identity-signed session end ({v:1,end,ts} under the IK, end_veil_id /
// end_ts / end_sig) is gone. No client ever sent it, and it was an unlabelled IK signature: any
// other IK-signed JSON of that shape would have counted. Ending a session takes the write
// secret, or the caller's own account / bound Vardum ID (below). Spec §2.8.
/** b77t (audit 5 L-5): the account purge itself (identities, chats, group memberships and owned groups, transfer links,
 *  the registration lock, the rows that name who it reached), shared by the gate's proven "purge" and the duress purge
 *  with a purge token (veilDuressPurge). The caller has authorised it. */
async function purgeAccountRelayData(auth: { userId: string }, clientId: string): Promise<Record<string, unknown>> {
    const acct = await accountHashOf(auth.userId);
    // b77u (audit 6 W1 / R4 #22): a purge (the duress wipe's signed one included) ends the duress purge token too
    await withLock("purgetok:" + auth.userId, () => dropPurgeToken(auth.userId));
    const myVeilIds: string[] = [];
    const myUnbound: string[] = []; // b77u (audit 6, IH relay F-06): identities this account registered but never bound
    for await (const e of KV.list({ prefix: ["veil_identity"] }, { consistency: "strong" })) { const r = e.value as Record<string, unknown>; if (String(r.account_hash || "") !== acct) continue; if (r.bound === true) myVeilIds.push(String(r.veil_id)); else myUnbound.push(String(r.veil_id || e.key[1] || "")); } // b70 (RLY-14)
    let sessions = 0, envelopes = 0;
    const doomed: string[] = [];
    const myTag = await initTag(auth.userId);
    for await (const e of KV.list({ prefix: ["entity", "VeilSession"] }, { consistency: "strong" })) { const s = e.value as Record<string, unknown>; if (String(s.initiator_client_id || "") === clientId || String(s.responder_client_id || "") === clientId || myVeilIds.includes(String(s.initiator_veil_id || "")) || myVeilIds.includes(String(s.responder_veil_id || "")) || s._init_tag === myTag) { if (s.token) doomed.push(String(s.token)); } } // b70 (re-review): never "every token-less row"
    // b70 (re-review 14): the sessions go first, then their envelopes
    // b77m (audit VAR-30): ONE more scan of the session table for all of them together (it used to be
    // one full scan per doomed row — quadratic: 200 rows on a 2,000-row table took ~27 s, from any
    // new account). Same rows go: every row carrying one of the doomed tokens.
    const doomedSet = new Set(doomed);
    for (const tok of doomedSet) { await KV.delete(["veil_sess_token", keySafe(tok)]); await KV.set(await retiredTokenKey(tok), 1, { expireIn: 400 * 86400_000 }); }
    if (doomedSet.size) {
      for await (const e of KV.list({ prefix: ["entity", "VeilSession"] }, { consistency: "strong" })) {
        if (doomedSet.has(String((e.value as Record<string, unknown>).token || ""))) { await KV.delete(e.key); sessions++; }
      }
    }
    for (const tok of doomedSet) { envelopes += await deleteSessionEnvelopes(tok); }
    // b75r1 (audit REL-06): the groups this account created go as on an account delete (the
    // owner record used to keep mapping them to the purged account, every other member's
    // rows stayed)
    const groups = await teardownOwnedGroups(acct);
    // b70 (re-review 10): bans on these identities keep only group-salted hashes (the
    // plain ID and key used to stay)
    {
      const ikSet = new Set<string>();
      for (const vid of myVeilIds) { const r = (await KV.get<Record<string, unknown>>(["veil_identity", keySafe(vid)])).value; if (r?.IK_pub) ikSet.add(String(r.IK_pub)); }
      const vidSet = new Set(myVeilIds);
      for await (const e of KV.list({ prefix: ["entity", "VeilGroupDenyEntry"] }, { consistency: "strong" })) {
        const d = e.value as Record<string, unknown>;
        const vid = String(d.target_veil_id || ""), ik = String(d.target_IK_pub || "");
        if (!vidSet.has(vid) && !ikSet.has(ik)) continue;
        const gt = String(d.group_token || "");
        await KV.set(e.key, {
          id: d.id, created_date: d.created_date, group_token: gt, deny_epoch: d.deny_epoch, remover_IK_pub: d.remover_IK_pub,
          target_ik_hash: ik ? await denyHash(gt, ik) : "", target_vid_hash: vid ? await denyHash(gt, vid) : "",
        });
      }
    }
    // b70 (re-review 11): and their group memberships (rosters kept showing them, and the
    // account kept passing the group-stream membership check)
    {
      const vidSet = new Set(myVeilIds);
      for await (const e of KV.list<Record<string, unknown>>({ prefix: ["entity", "VeilGroupMember"] }, { consistency: "strong" })) {
        const m = e.value;
        if (!m || !(vidSet.has(String(m.veil_id || "")) || String(m._acct || "") === acct)) continue;
        await KV.delete(e.key);
        if (m.group_token && m.IK_pub) await KV.delete(["veil_gmember", String(m.group_token), String(m.IK_pub)]);
      }
      for await (const e of KV.list<Record<string, unknown>>({ prefix: ["veil_gmember"] }, { consistency: "strong" })) {
        const g = e.value;
        if (g && (vidSet.has(String(g.veil_id || "")) || String(g.account_hash || "") === acct)) await KV.delete(e.key);
      }
    }
    for (const vid of myVeilIds) await KV.delete(["veil_identity", keySafe(vid)]);
    for (const vid of myVeilIds) await dropOpks(vid); // b76 (one-time prekeys)
    // b77u (audit 6, IH relay F-06): and the account's UNBOUND identity rows (an IK_pub, prekeys and the account hash: after
    // a duress wipe the relay still linked an identity key to the account), each only if still unbound and still this
    // account's; with their one-time prekeys, bind nonces, and this account's proof nonces and finished-move markers
    for (const vid of myUnbound) {
      if (!vid) continue;
      const cur = await KV.get<Record<string, unknown>>(["veil_identity", keySafe(vid)]);
      if (cur.value && cur.value.bound !== true && String(cur.value.account_hash || "") === acct && (await KV.atomic().check(cur).delete(cur.key).commit()).ok) await dropOpks(vid);
      await KV.delete(["id_nonce", vid, acct]);
    }
    for await (const e of KV.list({ prefix: ["proof_nonce", auth.userId] }, { consistency: "strong" })) await KV.delete(e.key);
    for (const p of ["devlink_fetched", "devlink_used"]) for await (const e of KV.list<Record<string, unknown>>({ prefix: [p] }, { consistency: "strong" })) {
      if (String(e.value?.acct || "") === acct || String(e.value?.racct || "") === acct) await KV.delete(e.key);
    }
    // b70 (re-review 4): pending device-transfer links go too (one carries the
    // identity and every chat key; a duress wipe left it fetchable for 10 minutes)
    let links = 0;
    for await (const e of KV.list({ prefix: ["devlink"] }, { consistency: "strong" })) {
      const row = e.value as Record<string, unknown>;
      if (String(row?.acct || "") === acct || String(row?.sacct || "") === acct) {
        await KV.delete(e.key); links++;
        // b70 (re-review 12): and its bundle file (unprotected once its link row is gone)
        await dropDevlinkBlob(row); // b75: whichever phone uploaded it
      }
    }
    // b75r1 (audit REL-02): registrations held aside for this account
    for await (const e of KV.list({ prefix: ["veil_identity_pending"] })) if (String(e.key[2] ?? "") === acct) await KV.delete(e.key);
    // b76 (registration lock): the lock record goes with the identities (its PIN proof is
    // salted with one of them, and after a duress purge nothing on the relay should say a lock
    // was ever set). The account then signs in with the 24 words alone, as before b76.
    const reglock = !!(await KV.get(regLockKey(acct))).value;
    await KV.delete(regLockKey(acct));
    regLockSeen.delete(auth.userId);
    // b76r1 (one-time prekeys): the limiter rows that say who this account reached go as on an
    // account delete — "req:<acct hash>:<target>" (chat requests), "opkpair:<acct hash>:<ID>" (whose
    // one-time keys it fetched), "opkclaim:<uid>", and every row that names one of the purged IDs
    // ("opktarget:<ID>", other accounts' "opkpair:…:<ID>", invite-push caps). They used to outlive the
    // purge by up to two days, and the account hash links straight to the surviving account. The
    // account's plain per-account counters (no other party in them) stay: the account itself stays,
    // and they are what stops a register / purge loop from resetting its caps.
    // b76r2 (audit OP-1): "opkclaim:<uid>" is one of those plain counters, and the account's own
    // "opkpair:" rows now name nobody (opaque tags, see opkPairTag) — both STAY. Deleting them let a
    // purge + re-bind loop take a fresh 10 pairs a day from the same victim each time. Other accounts'
    // pair rows for one of the purged IDs still go (found by the ID's tag).
    {
      const reqPrefix = "req:" + acct + ":", askKey = "reglockask:" + acct;
      const targetSuffixes = await Promise.all(myVeilIds.filter(Boolean).map((v) => opkPairTargetSuffix(v)));
      // b77: "req:" by tag: own stay, others' on its IDs go
      const reqSfx = await reqTargetSuffixesOf(myVeilIds);
      const myVtags = await Promise.all(myVeilIds.filter(Boolean).map((v) => vidTag(v))); // b77m (audit VAR-48)
      for await (const e of KV.list({ prefix: ["rl"] }, { consistency: "strong" })) {
        const k = String(e.key[1] || "");
        // (and the lock's free-refusal counter: after the purge nothing should say a lock was set)
        if (k.startsWith(reqPrefix) || k === askKey || myVeilIds.some((v) => !!v && k.includes(v)) || myVtags.some((t) => k.includes(t)) || (k.startsWith("opkpair:") && targetSuffixes.some((s) => k.endsWith(s))) || reqHit(k, reqSfx)) await KV.delete(e.key);
      }
    }
    return { sessions, envelopes, identities: myVeilIds.length, transfer_links: links, groups, reglock };
}

async function fnVeilSessionGateAligned(auth: { userId: string }, body: Record<string, any>) {
  const action = String(body?.action || "");
  // b199 AUTHZ: client_id IS the account id (the app always sends its own), so
  // a client_id naming any other account is refused — it used to let anyone
  // list (and purge) every conversation of an account whose id they'd seen in
  // a shared session row.
  const callerAcctP = accountHashOf(auth.userId);
  const ownVeilId = async (v: string) => {
    if (!validVeilId(v)) return false;
    const id = (await KV.get<Record<string, unknown>>(["veil_identity", keySafe(v)])).value;
    return !!id && id.bound === true && String(id.account_hash || "") === await callerAcctP; // b70 (RLY-14)
  };
  if ((action === "list" || action === "purge") && String(body?.client_id || "").trim() !== auth.userId) {
    return j({ error: "client_id must be your own account" }, 403);
  }
  if (action === "list") {
    const clientId = String(body?.client_id || "").trim();
    if (!validClientId(clientId)) return j({ error: "Invalid client id" }, 400);
    const veilId = String(body?.veil_id || "").trim();
    // pending contact requests addressed to a Veil ID are only listed for the
    // account that Veil ID is bound to (it used to be anyone who knew the ID)
    const veilIdMine = await ownVeilId(veilId);
    let restoreOk = false;
    if (validVeilId(veilId) && body?.list_ts && body?.list_sig) {
      const ts = Number(body.list_ts);
      if (Number.isFinite(ts) && Math.abs(Date.now() - ts) <= 300000) {
        const id = (await KV.get<Record<string, unknown>>(["veil_identity", keySafe(veilId)])).value;
        if (id) restoreOk = await ed25519Verify(String(id.IK_pub || ""), enc.encode(JSON.stringify({ v: 1, list: clientId, ts })), String(body.list_sig || ""));
      }
    }
    // Batch E (round-3 review R3-02): the caller's OWN sessions (it is a side of
    // the row) are always listed in full. The list used to be cut to the newest
    // 100 rows of everything, so rows that merely name the caller (requests from
    // others, restore matches) pushed its real chats off the end, and the app
    // read a missing chat as ended. Only those naming rows are capped now.
    // Optional paging: `limit` (1-500) + the `next_cursor` of the previous page;
    // without `limit` every own row comes back in one answer (older apps).
    const own: Record<string, unknown>[] = [];
    const naming: Record<string, unknown>[] = [];
    const pendingOnly = new WeakSet<Record<string, unknown>>();
    for await (const e of KV.list({ prefix: ["entity", "VeilSession"] }, { consistency: "strong" })) {
      const s = e.value as Record<string, unknown>;
      // b77 (sealed sender): a joined 1:1 row is a rendezvous (the initiator reads it with the
      // no-login "status"), and a ready 1:1 chat lives on the phones; the list serves pending
      // requests and groups only. (A pre-b77 active 1:1 row, which still names both accounts,
      // is left out too: its chat can no longer send.)
      if (!s.group_token && String(s.state || "") === "active") continue;
      const match = String(s.initiator_client_id || "") === clientId || String(s.responder_client_id || "") === clientId;
      const pendingForMe = veilIdMine && !!s.contact_session && String(s.state || "") === "pending" && !String(s.responder_client_id || "") && String(s.responder_veil_id || "") === veilId;
      const identityClause = restoreOk && !!s.contact_session && (String(s.initiator_veil_id || "") === veilId || String(s.responder_veil_id || "") === veilId);
      if (match) own.push({ ...(s as any), id: e.key[e.key.length - 1] });
      else if (pendingForMe || identityClause) {
        const row = { ...(s as any), id: e.key[e.key.length - 1] };
        if (pendingForMe && !identityClause) pendingOnly.add(row); // Batch H (R6-3-11)
        naming.push(row);
      }
    }
    // newest first; the row id breaks ties so the paging order is total
    const newestFirst = (a: Record<string, unknown>, b: Record<string, unknown>) =>
      String(b.created_date ?? "").localeCompare(String(a.created_date ?? "")) || String(b.id).localeCompare(String(a.id));
    own.sort(newestFirst);
    naming.sort(newestFirst);
    // Batch G (round-5 review R5-3-05): at most the 3 newest rows per initiating
    // account, so a few throwaway accounts can't bury a real request under paging
    {
      const perInit = new Map<string, number>();
      const kept: Record<string, unknown>[] = [];
      // Batch H (round-6 review R6-3-11): only requests are capped. Restore matches
      // (the user's own old chats, whose initiator is the user's own old account) are not.
      for (const r of naming) {
        if (!pendingOnly.has(r)) { kept.push(r); continue; }
        const k = String(r.initiator_client_id || r._init_tag || r.initiator_veil_id || r.id); // b77: _init_tag (a 1:1 row names no account)
        const c = perInit.get(k) ?? 0;
        if (c < 3) { kept.push(r); perInit.set(k, c + 1); }
      }
      naming.length = 0; naming.push(...kept);
    }
    const cursor = typeof body?.cursor === "string" ? body.cursor : "";
    const limitRaw = Number(body?.limit);
    const limit = body?.limit === undefined ? Infinity : (Number.isInteger(limitRaw) ? Math.min(500, Math.max(1, limitRaw)) : 100);
    let start = 0;
    if (cursor) {
      const cut = cursor.indexOf("|");
      if (cut < 0 || cursor.length > MAX_KEY_PART) return j({ error: "Invalid cursor" }, 400);
      const at = { created_date: cursor.slice(0, cut), id: cursor.slice(cut + 1) };
      start = own.findIndex((r) => newestFirst(at, r) < 0);
      if (start < 0) start = own.length;
    }
    // Batch F (round-4 reviews R4-3-02 / R4-4-21): rows that only NAME the caller
    // are paged too, with their own cursor (naming_cursor / naming_next_cursor),
    // so other accounts can't push real requests out of reach. A call with a
    // naming_cursor returns only naming rows.
    const namingCursor = typeof body?.naming_cursor === "string" ? body.naming_cursor : "";
    let nStart = 0;
    if (namingCursor) {
      const cut = namingCursor.indexOf("|");
      if (cut < 0 || namingCursor.length > MAX_KEY_PART) return j({ error: "Invalid cursor" }, 400);
      const at = { created_date: namingCursor.slice(0, cut), id: namingCursor.slice(cut + 1) };
      nStart = naming.findIndex((r) => newestFirst(at, r) < 0);
      if (nStart < 0) nStart = naming.length;
    }
    const nPage = (cursor && !namingCursor) ? [] : naming.slice(nStart, nStart + LIST_NAMING_CAP);
    const nLast = nPage[nPage.length - 1];
    const naming_next_cursor = nStart + nPage.length < naming.length && nLast ? `${String(nLast.created_date ?? "")}|${String(nLast.id)}` : null;
    const view = (rows: Record<string, unknown>[]) => Promise.all(rows.map((r) => sessionView(r, auth.userId))); // b70 (RLY-10)
    if (namingCursor) return json({ sessions: await view(nPage), next_cursor: null, naming_next_cursor });
    const page = own.slice(start, start + limit);
    const last = page[page.length - 1];
    const next_cursor = start + page.length < own.length && last ? `${String(last.created_date ?? "")}|${String(last.id)}` : null;
    return json({ sessions: await view([...page, ...nPage]), next_cursor, naming_next_cursor });
  }
  if (action === "purge") {
    const clientId = String(body?.client_id || "").trim();
    if (!validClientId(clientId)) return j({ error: "Invalid client id" }, 400);
    // b70 (re-review 11): the account's primary is recorded BEFORE its identities go (an
    // older account had none recorded, so a purge left it deletable with a token alone)
    // b74 (audit VAR-12): and the purge needs the same proof as an account delete — the
    // primary identity signs "vardum-purge-v1:<userId>:<ts>" (or, with no primary, a fresh
    // sign-in). A bearer token alone used to remove the account's identities, chats,
    // group memberships and transfer links.
    await ensurePrimaryIdentity(auth.userId);
    {
      const refused = await primaryProofRefusal(auth, body, "vardum-purge-v1", { proof: "Clearing this account needs the Vardum ID it was set up with on this phone", fresh: "Sign in again, then clear the account" }, { legacy: "always" }); // b77t (L-15): the duress proof is signed before the erase, with no network call: single-use, nonce optional
      if (refused) return refused;
    }
    return json({ ok: true, deleted: await purgeAccountRelayData(auth, clientId) });
  }
  const token = String(body?.token || "");
  const session = await findSessionByToken(token);
  // b70 (re-review 11): what the row was when read, so writes below patch only what changed
  const sessionBefore: Record<string, unknown> | null = session ? structuredClone(session) : null;
  if (!session) {
    if (action === "end") return json({ ok: true });
    if (action === "burn") return json({ ok: true, already_gone: true, burned: false, reason: "session_gone" });
    return j({ error: "Session not found" }, 404);
  }
  const wsHash = body?.write_secret ? await sha256hex(String(body.write_secret)) : "";
  let slot: string | null = wsHash && ctEq(wsHash, String(session.initiator_write_hash || "")) ? "initiator" : (wsHash && ctEq(wsHash, String(session.responder_write_hash || "")) ? "responder" : null);
  if (!slot && action === "end") {
    const clientId = String(body?.client_id || "").trim();
    const veilId = String(body?.veil_id || "").trim();
    // b199 AUTHZ: the client_id / veil_id fallbacks prove participation only
    // when they are the CALLER's own — an account id or Veil ID read off a
    // shared row used to be enough to delete someone else's conversation.
    let participant = clientId === auth.userId && validClientId(clientId) && (clientId === String(session.initiator_client_id || "") || clientId === String(session.responder_client_id || ""));
    if (!participant && await ownVeilId(veilId)) {
      const addresseeEnd = veilId === String(session.responder_veil_id || "");
      if (!(String(session.state || "") === "pending" && addresseeEnd) && (veilId === String(session.initiator_veil_id || "") || addresseeEnd)) participant = true;
    }
    if (participant) slot = "participant";
  }
  if (!slot) {
    console.warn("session-credential-refused", { action, state: session.state, presented: typeof body?.write_secret === "string" ? String(body.write_secret).length : 0 });
    return j({ error: "Invalid session credential" }, 403);
  }
  // b77 (sealed sender): the old token-scoped 1:1 actions are retired — presence heartbeats,
  // the verify flags, notify (push / call ring) and burn now run on the anonymous mailboxes
  // (mailboxVerify, sealedSubmit notify, sealedBurn); "bump" kept a 1:1 row alive. Group seats
  // are unchanged.
  if (!session.group_token && (action === "heartbeat" || action === "verify" || action === "notify" || action === "burn" || action === "bump")) {
    return j({ error: LEGACY_1TO1, message: LEGACY_1TO1 }, 410);
  }
  const horizon = () => new Date(Date.now() + sessionHorizonMs(session)).toISOString();
  // b199: a seat locked to one Veil ID (group invites sent to a pinned contact)
  // can only be viewed or joined by the account that owns that identity — the
  // write secret alone is not enough, so a forwarded invite is useless.
  const lockedInvitee = String(session.invitee_veil_id || "");
  const notTheInvitee = async () => {
    if (!lockedInvitee) return false;
    const id = (await KV.get<Record<string, unknown>>(["veil_identity", keySafe(lockedInvitee)])).value;
    // b70 (re-review 12): a BOUND identity of the caller (an unbound row anyone can register)
    return !id || id.bound !== true || String(id.account_hash || "") !== await accountHashOf(auth.userId);
  };
  if ((action === "peek" || action === "join") && slot === "responder" && await notTheInvitee()) {
    return j({ error: "This invitation was sent to someone else." }, 403);
  }
  if (action === "peek") {
    if (slot !== "responder") return j({ error: "Only the invited side can view this session" }, 403);
    return json({ session: { state: session.state, responder_client_id: session.responder_client_id && session.responder_client_id !== auth.userId ? await peerPseudonym(String(session.token || ""), String(session.responder_client_id)) : session.responder_client_id, expires_at: session.expires_at, initiator_pub_jwk: session.initiator_pub_jwk, initiator_pq_pub: session.initiator_pq_pub, passphrase_required: session.passphrase_required, group_token: session.group_token || "", group_epoch: Number(session.group_epoch) || 0, group_name: session.group_name || "", group_pq_pub: session.group_pq_pub || "",
      // Batch D (found by the D-21 spec rewrite): the joiner binds the dials into the
      // fingerprint and its expiry — without them it fell back to the defaults
      default_ttl_seconds: session.default_ttl_seconds, expire_after_seconds: session.expire_after_seconds, key_retention_hours: session.key_retention_hours, burn_after_open: session.burn_after_open === true } });
  }
  if (action === "join") {
    if (slot !== "responder") return j({ error: "Only the invited side can join this session" }, 403);
    // Batch E (round-3 review R3-01): the joiner's client id IS its account id
    // (the app always sends its own). Any other id used to be stored as the
    // responder, planting rows in that account's session list and passing the
    // push-target check with someone else's identity (RV-59, RV-09, RV-11).
    if (String(body?.client_id || "").trim() !== auth.userId) return j({ error: "client_id must be your own account" }, 403);
    if (String(session.state || "") === "ended") return j({ error: "This session has ended." }, 400);
    if (String(session.state) === "active" && String(session.responder_client_id || "") === String(body?.client_id || "") && (String(session.responder_pub_jwk || "") !== String(body?.responder_pub_jwk || "") || String(session.responder_ratchet_pub_jwk || "") !== String(body?.responder_ratchet_pub_jwk || ""))) return j({ error: "This session was already accepted from this device with different keys — it cannot be re-joined here. Start a new session." }, 409);
    if (String(session.state) === "active" && String(session.responder_client_id || "") && String(session.responder_client_id || "") !== String(body?.client_id || "")) return j({ error: "This session is already in use." }, 400);
    if (String(session.state) === "pending" && new Date(String(session.expires_at)) < new Date()) return j({ error: "Invitation has expired." }, 400);
    for (const [k, v] of Object.entries({ responder_client_id: body?.client_id, responder_pub_jwk: body?.responder_pub_jwk, responder_ratchet_pub_jwk: body?.responder_ratchet_pub_jwk, fingerprint: body?.fingerprint })) { if (typeof v !== "string" || !v) return j({ error: `Missing join field: ${k}` }, 400); }
    // b70 (re-review 2): the join writes these into the row (a KV value is 64 KB at most)
    for (const f of ["responder_pub_jwk", "responder_ratchet_pub_jwk", "fingerprint", "responder_pq_ct", "display_name", "new_responder_write_hash"]) {
      if (body?.[f] !== undefined && String(body[f]).length > 4096) return j({ error: "Join field too large", message: "Join field too large" }, 413);
    }
    // Batch C (V-16, relay half): a joiner may replace the responder credential
    // with a fresh one, so the link's w stops working once the invite is used.
    // Optional — older apps keep using w.
    const nextHash = typeof body?.new_responder_write_hash === "string" ? body.new_responder_write_hash : "";
    if (nextHash) {
      if (!/^[0-9a-f]{64}$/.test(nextHash)) return j({ error: "Invalid new responder credential" }, 400);
      session.responder_write_hash = nextHash;
      // b73 (audit): V-04 — the responder credential is now the joiner's alone (the
      // initiator never saw this secret); verify may trust it (see "verify")
      session.responder_cred_own = true;
    }
    session.responder_client_id = String(body.client_id);
    // b71 (review R-1): the joiner's display_name is accepted from older apps but never
    // stored (the relay has no use for a nickname); a value an older relay left is removed
    delete session.responder_display_name; delete session.initiator_display_name;
    session.state = "active"; session.expires_at = horizon(); session.responder_pub_jwk = String(body.responder_pub_jwk); session.responder_ratchet_pub_jwk = String(body.responder_ratchet_pub_jwk); session.responder_pq_ct = typeof body?.responder_pq_ct === "string" ? String(body.responder_pq_ct) : ""; session.session_fingerprint = String(body.fingerprint); session.last_activity = nowIso(); session.updated_date = nowIso();
    if (!(await patchSessionRow(sessionBefore!, session))) return j({ error: "This session has ended." }, 409); // b70 (re-review 11)
    return json({ session: await sessionView(session, auth.userId) }); // b70 (re-review R3)
  }
  if (action === "activate") {
    if (slot !== "initiator") return j({ error: "Only the session creator can activate this session" }, 403);
    if (!session.group_token) return j({ error: "Only group sessions can be activated without a peer" }, 400);
    if (String(session.state || "") === "ended") return j({ error: "This session has ended." }, 400);
    if (String(session.state) === "active") return json({ session: await sessionView(session, auth.userId) }); // b70 (re-review R3)
    session.state = "active"; session.expires_at = horizon(); session.last_activity = nowIso();
    if (!(await patchSessionRow(sessionBefore!, session))) return j({ error: "This session has ended." }, 409); // b70 (re-review 11)
    return json({ session: await sessionView(session, auth.userId) }); // b70 (re-review R3)
  }
  if (action === "verify") {
    // b73 (audit): V-04 — each side sets only its OWN verified flag. Which flag used to be
    // picked from which write-secret hash the presented secret matched; in a contact
    // chat both secrets derive from the shared root (each side holds both), and an invite
    // creator holds the link's w until the joiner replaces it, so one party could set
    // BOTH flags and clear the call-ring gate below on a chat its peer never verified.
    // The side is now the caller's account (initiator_client_id / responder_client_id,
    // both server-stamped), else (a chat restored onto a new account) the side whose
    // Vardum ID is a bound identity of the caller (contact chats). Only when neither
    // names the caller does the secret decide, and only a secret that is that side's
    // alone: an invite initiator's own secret, or a responder secret the joiner replaced
    // at join (responder_cred_own). Otherwise: refused. No app change needed.
    if (slot !== "initiator" && slot !== "responder") return j({ error: "Invalid session credential" }, 403);
    let side: "initiator" | "responder" | null = null;
    const iAcct = String(session.initiator_client_id || "") === auth.userId, rAcct = String(session.responder_client_id || "") === auth.userId;
    if (session.group_token) side = slot; // group seats: no verify ceremony, unchanged
    else if (iAcct && rAcct) side = slot; // one account on both sides: nobody else to speak for
    else if (iAcct) side = "initiator";
    else if (rAcct) side = "responder";
    else if (session.contact_session && await ownVeilId(String(session.initiator_veil_id || ""))) side = "initiator";
    else if (session.contact_session && await ownVeilId(String(session.responder_veil_id || ""))) side = "responder";
    else if (!session.contact_session && slot === "initiator") side = "initiator";
    else if (!session.contact_session && slot === "responder" && session.responder_cred_own === true) side = "responder";
    if (!side) return j({ error: "Only each side of a conversation can confirm its own verification" }, 403);
    const early = side === "initiator" && !!session.contact_session && String(session.state || "") === "pending";
    if (String(session.state || "") !== "active" && !early) return j({ error: "This conversation is not open yet, so the confirmation could not be recorded. Confirm once the other side has accepted the request." }, 409);
    const flag = side === "initiator" ? "initiator_verified" : "responder_verified";
    (session as any)[flag] = true; session.updated_date = nowIso();
    if (!(await patchSessionRow(sessionBefore!, session))) return j({ error: "This session has ended." }, 409); // b70 (re-review 11)
    console.info("verify-ceremony", { state: session.state, early_confirm: early, iv: !!session.initiator_verified, rv: !!session.responder_verified }); // b77: no slot / side (direction)
    return json({ session: await sessionView(session, auth.userId) }); // b70 (re-review R3)
  }
  if (action === "bump") {
    if (String(session.state || "") !== "active") return j({ error: "This session is not active" }, 409);
    session.last_activity = nowIso(); session.expires_at = horizon();
    if (!(await patchSessionRow(sessionBefore!, session))) return j({ error: "This session has ended." }, 409); // b70 (re-review 11)
    return json({ ok: true });
  }
  if (action === "notify") {
    // b77p round 2 (owner decision 1): no account-level push. A 1:1 chat's notify was retired in b77 (410 above;
    // mailbox wakes replaced it); a group seat's notify (push / call ring to the other side's ACCOUNT push rows) is
    // answered without pushing anything — the other side finds the post on its next poll or wake.
    if (String(session.state || "") !== "active") return j({ error: "This session is not active" }, 409);
    return json({ ok: true, pushed: false });
  }
  if (action === "burn") {
    const envelopeId = String(body?.envelope_id || "");
    if (!envelopeId) return j({ error: "Missing envelope id" }, 400);
    // b75 (audit V12): a group's burn policy is the one recorded on its group record when
    // the creator minted its first row (groupBurnPolicy). It used to be read from the
    // creator's MAIN row, found by a scan of every session row, so a group whose main row
    // was gone answered "not burn-after-open" to every burn.
    const policy: Record<string, any> = session.group_token ? await groupBurnPolicy(String(session.group_token)) : session;
    if (!policy.burn_after_open) return j({ error: "This session is not burn-after-open" }, 400);
    if (String(session.state || "") !== "active") return j({ error: "This session is not active" }, 409);
    const env = (await KV.get<Record<string, any>>(["entity", "VeilEnvelope", keySafe(envelopeId)])).value;
    if (!env) return json({ ok: true, already_gone: true, burned: false, reason: "envelope_gone" });
    if (String(env.session_token || "") !== token && !(session.group_token && String(env.group_token || "") === String(session.group_token))) return j({ error: "Envelope does not belong to this session" }, 403);
    // b75 (audit RL-01): in a 1:1 chat the RECEIVER's burn deletes the relay copy (the row
    // and its index entries) at once. It used to move the expiry to now + the burn dial —
    // and do nothing at all when that was later than the expiry already set (a long dial),
    // so an opened message stayed on the relay for its whole unopened window. The receiver
    // is a side of the chat (its account, as the envelope list requires) that did not send
    // the envelope (its per-row owner tag; legacy rows: client_id). The sender's own copy
    // is never deleted by its sender's burn (the app never asks; the receiver's open owns
    // the clock). A media file the message points at is not known to the relay (its id is
    // inside the encrypted payload): the receiving app deletes it when the burn window ends
    // (chat.ts), and the 49 h blob sweep is the backstop.
    if (!session.group_token) {
      const eid = String(env.id || envelopeId);
      const isSender = env._owner ? String(env._owner) === await ownerTag(auth.userId, eid) : (!!env.client_id && String(env.client_id) === auth.userId);
      if (isSender) return json({ ok: true, burned: false, reason: "sender_copy" });
      if (String(session.initiator_client_id || "") !== auth.userId && String(session.responder_client_id || "") !== auth.userId) {
        return j({ error: "Only a side of this conversation can burn its messages" }, 403);
      }
      await deleteEnvelopeRow(["entity", "VeilEnvelope", keySafe(envelopeId)], env);
      console.info("burn-executed", { deleted: true }); // b77: no slot (direction)
      return json({ ok: true, burned: true, reason: "deleted" });
    }
    const cur = new Date(String(env.expires_at)).getTime();
    if (!Number.isFinite(cur) || cur <= Date.now()) return json({ ok: true, burned: false, reason: "already_expired" });
    const burnSeconds = Number(policy.default_ttl_seconds) || 3600;
    const burnAt = Date.now() + burnSeconds * 1000;
    if (burnAt >= cur) return json({ ok: true, burned: false, reason: "already_within_burn_window", expires_at: env.expires_at, burn_window_seconds: burnSeconds });
    // b70 (audit GRP-4): in a group, one member's burn no longer shortens the
    // relay copy for everyone (a hostile member could cut rekeys short so that
    // offline members missed them). The relay copy's window starts once every
    // member other than the sender has opened it; until then it waits for its
    // normal expiry. Each phone still burns its own copy on opening.
    if (session.group_token) {
      if (env._owner && String(env._owner) === await ownerTag(auth.userId, String(env.id || envelopeId))) {
        return json({ ok: true, burned: false, reason: "sender_copy" });
      }
      // b76r2 (audit GB-1 / R2-B1, GB-2, R2-B2): the voters are the snapshot taken when the envelope was submitted
      // (burnEligOf: the accounts admitted then, minus the sender) — no snapshot, or one holding an account-less
      // member row: never shortened (the copy keeps its normal expiry)
      const elig = burnEligOf((await KV.get<BurnEligRow>(["burn_elig", keySafe(envelopeId)])).value);
      if (!elig || elig.x > 0) return json({ ok: true, burned: false, reason: "waiting_for_other_members" });
      // b70 (re-review 13): accounts, not rows (one account holding two seats votes once)
      const memberAccts = new Set<string>();
      for await (const e of groupMemberRows(String(session.group_token))) { // b77n (pre-audit L3): by ["ix_gmem"]
        const m = e.value as Record<string, unknown>;
        if (String(m.group_token || "") !== String(session.group_token)) continue;
        // b73 (audit): V-10 — only members the creator admitted count (and vote): a
        // claimant the creator never let in (or declined) holds no key, can't open the
        // message, never votes, and used to keep every message from burning
        if (!memberAdmitted(m)) continue;
        if (m._acct) memberAccts.add(String(m._acct));
      }
      // b70 (re-review 10): a vote counts only from an account that holds a seat on this
      // roster, one per account — one member with a seat credential used to cast every
      // vote from throwaway accounts and cut anyone's message (rekeys too) short
      let voter = await accountHashOf(auth.userId);
      if (!memberAccts.has(voter)) return json({ ok: true, burned: false, reason: "waiting_for_other_members" });
      // b76r2: the quorum = the snapshot's accounts that are STILL admitted (one that left, was removed or declined
      // no longer counts, nor does its vote); a member admitted after the envelope was submitted is not in it
      const eligSet = new Set(elig.m);
      const stillIn = new Set<string>();
      for (const a of memberAccts) { const mk = await burnVoteMarker(String(envelopeId), a); if (eligSet.has(mk)) stillIn.add(mk); }
      // b75r1 (audit REL-05): the vote row holds opaque markers (burnVoteMarker), not the
      // voters' account hashes — it used to say at rest which members opened which message
      const voteKey = ["burn_votes", keySafe(envelopeId)];
      voter = await burnVoteMarker(String(envelopeId), voter);
      if (!stillIn.has(voter)) return json({ ok: true, burned: false, reason: "waiting_for_other_members" });
      // b70 (re-review 13): versionstamp-checked, so two members voting at once both count
      let votes = new Set<string>();
      for (let attempt = 0; ; attempt++) {
        const curVotes = await KV.get<BurnVoteRow>(voteKey);
        votes = new Set(burnVotesOf(curVotes.value));
        votes.add(voter);
        const res = await KV.atomic().check(curVotes).set(voteKey, { k: BURN_VOTE_KEY_ID, m: [...votes] }, { expireIn: Math.max(60_000, cur - Date.now()) }).commit();
        if (res.ok) break;
        if (attempt >= 20) return json({ error: "Busy, try again" }, 503);
      }
      const opened = [...votes].filter((v) => stillIn.has(v)).length;
      if (opened < stillIn.size) return json({ ok: true, burned: false, reason: "waiting_for_other_members", opened, needed: stillIn.size });
    }
    // b70 (re-review 12): onto the envelope as it is now — an envelope deleted meanwhile (end,
    // evict, expiry) is never written back with its ciphertext
    {
      const ek = ["entity", "VeilEnvelope", keySafe(envelopeId)];
      let done = false;
      for (let attempt = 0; attempt < 10 && !done; attempt++) {
        const curEnv = await KV.get<Record<string, unknown>>(ek);
        if (!curEnv.value) return json({ ok: true, already_gone: true, burned: false, reason: "envelope_gone" });
        done = (await KV.atomic().check(curEnv).set(ek, { ...curEnv.value, expires_at: new Date(burnAt).toISOString(), delivery_state: "delivered" }).commit()).ok;
      }
      env.expires_at = new Date(burnAt).toISOString();
    }
    console.info("burn-executed", { window: burnSeconds }); // b77: no slot (direction)
    return json({ ok: true, burned: true, reason: "shortened", expires_at: env.expires_at });
  }
  if (action === "heartbeat") {
    if (String(session.state || "") !== "active") return j({ error: "This session is not active" }, 409);
    session.last_activity = nowIso();
    if (slot === "initiator") session.initiator_seen_at = nowIso(); else if (slot === "responder") session.responder_seen_at = nowIso();
    if (!(await patchSessionRow(sessionBefore!, session))) return j({ error: "This session has ended." }, 409); // b70 (re-review 11)
    return json({ ok: true });
  }
  if (action === "end") {
    // b77t (audit 5 L-16, IH R-09): a seat locked to one Vardum ID is ended through its responder secret only by that
    // ID's own account (the check peek and join already make) — a forwarded seat secret could end the seat and drop its
    // member from the group
    if (slot === "responder" && await notTheInvitee()) return j({ error: "This invitation was sent to someone else." }, 403);
    // b70 (re-review 14): the session goes first, then its envelopes — a submit landing in
    // between now sees no chat and takes its envelope back (the other order kept it)
    // b70 (re-review 5): a group seat's token stays visible on its old envelopes and
    // member row, so it is never minted again (another account re-creating it became a
    // "participant" of the old posts and passed the roster check)
    // b75 (audit RL-05): a 1:1 chat's token too — any account could re-create a row under
    // an ended 1:1 token (only group tokens were retired). Retired BEFORE the index goes, so
    // no create can slip in between.
    await retireSessionToken(token);
    await KV.delete(["entity", "VeilSession", String(session.id)]);
    await KV.delete(["veil_sess_token", keySafe(token)]);
    if (!session.group_token) await deleteSessionEnvelopes(token); // W-19: group envelopes are shared history
    if (session.group_token) await dropSeatMembership(token, slot === "responder"); // b70 (re-review 11); b77u (L-6): a member leaving
    return json({ ok: true });
  }
  return j({ error: "Unknown action" }, 400);
}
