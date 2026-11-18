/**
 * @veil/device — Base44 relay client.
 *
 * Speaks the EXACT contract the web bundle speaks (extracted from
 * index-DYGFL-4a.js, Sept 13 2026):
 *   POST {baseURL}/api/apps/{appId}/functions/{fn}   (JSON body = payload)
 *   Authorization: session token (supplied by the shell's token provider)
 *
 * The relay never sees private keys, phrases, pins, or nicknames. It stores
 * ciphertext envelopes and public session records only. All crypto happens
 * in @veil/crypto-core before anything reaches this client.
 */
import { relayErrorFor } from './relay-errors';
import { withNetworkPow, loginPowAcceptable, solveLoginPow } from './auth'; // b77m (owner, carrier NAT)
import { readJsonBounded, relayJsonLimitFor, RelayResponseTooLargeError, utf8ByteLength } from './relay-json'; // b77s (audit 4 A-01 / A-03)
import { secureRandomUnit } from './secure-random'; // b77t (audit 5 L-28)
import { fetchProofNonce, proofMessage } from './proof-nonce'; // b77t (audit 5 L-6, L-15, L-5)

export const RATCHET_PROTOCOL = 'veil-ratchet-8'; // spec §4 wire tag (b54); b77: veil-ratchet-8 (sealed sender, a clean break)
export const GROUP_PROTOCOL = 'veil-group-3'; // b74 (owner decision: clean break) — must equal groups.ts GROUP_PROTO; b77m review: veil-group-3

/** b74 (audit VAR-12): the purge proof — the primary identity's Ed25519 signature over
 *  purgeProofMessage(userId, ts) (base64), with that time and that identity's Vardum ID */
export interface PurgeProof { veil_id: string; ts: number; sig: string; nonce?: string }
/** b77t (audit 5 L-15): with the relay's nonce when there is one (see proof-nonce.ts). The duress wipe signs without
 *  one (it signs before the erase and makes no network call then); the relay takes that form once. */
export const purgeProofMessage = (userId: string, ts: number, nonce?: string | null): string => proofMessage('vardum-purge-v1', userId, ts, nonce);

/** a signer for the account's primary identity: Ed25519 over the base64 of the message (crypto-core ikSign) */
export interface PrimarySigner { veilId: string; sign: (msgB64: string) => Promise<string> }

export interface RelayConfig {
  /** b77t (audit 5 L-6): stores a new sign-in token the relay issued in place of the current one (accountSignOutOthers
   *  and accountChangePassword revoke every token, the caller's too). The app: auth.replaceToken. */
  setToken?: (token: string) => Promise<void>;
  /** The relay's origin. b73 (audit): there is deliberately NO default — every caller
   *  passes one (the app: VEIL_BASE_URL in src/veil-app.ts; tests: a loopback relay or a
   *  fake fetchImpl), so nothing built on this client reaches a live host by accident.
   *  (This comment used to name the retired Base44 backend as the example.) */
  baseUrl: string;
  /** the Base44 app id */
  appId: string;
  /** session token provider (Base44 auth). Refresh handled by the shell. */
  getToken: () => Promise<string | null>;
  /** injectable for tests */
  fetchImpl?: typeof fetch;
  /**
   * RN has no working Blob-from-bytes constructor (Hermes/RN's FormData
   * throws "Creating blobs from 'ArrayBuffer' and 'ArrayBufferView' are
   * not supported" — VEIL-P1, Sept 19). uploadPrivateFile's bytes path
   * uses this hook to write the bytes to a temp file and upload via the
   * proven {uri,name,type} FormData part (same path media sends already
   * use successfully). Pure-TS tests never supply it — Node's real Blob
   * accepts ArrayBufferView directly, so the fallback branch covers them.
   */
  bytesToTempFile?: (bytes: Uint8Array, name: string) => Promise<{ uri: string; cleanup: () => void }>;
  /** b77z2 (Z-1): how long one function call (invoke / invokeAnon, so every sealed route) may
   *  take, answer body included, before it is abandoned with RelayTimeoutError. Default
   *  RELAY_TIMEOUT_MS. */
  timeoutMs?: number;
  /** b77p (audit VAR-11): media transfer limits (ms); MEDIA_FETCH_LIMITS by default */
  mediaLimits?: Partial<typeof MEDIA_FETCH_LIMITS>;
  /** b77p round 2 (review M2): whether `fetchImpl` hands over the response before its body has arrived (streams).
   *  Unset = detected (fetchStreams()); false = React Native's fetch, which answers only once the whole body is in */
  fetchStreams?: boolean;
  /** b77q (audit 3 DV-2): the XMLHttpRequest a non-streaming platform downloads media with (xhrBytesBounded: its
   *  progress events let a body past the cap be aborted while it arrives). Unset = the platform's own, used only
   *  when `fetchImpl` is not injected and fetch doesn't stream (React Native); null = never (fetch as before). */
  xhrImpl?: XhrCtor | null;
  /** b77t (audit 5 L-4 x L-27): called with every answer to a JSON relay call, whichever transport carried it
   *  (fetch, or XMLHttpRequest on React Native, which bypasses `fetchImpl`). The app notes the relay's Date header
   *  from successful signed-in answers here (src/relay-clock.ts relayClockAnswerHook). Must not throw (a throw is
   *  swallowed; the call's answer is what matters). */
  onAnswer?: (a: RelayAnswerInfo) => void;
}

/** b77t (audit 5 L-4 x L-27): what RelayConfig.onAnswer sees of one answer */
export interface RelayAnswerInfo {
  url: string;
  status: number;
  ok: boolean;
  /** the request carried a session token (Authorization) */
  signedIn: boolean;
  /** a response header (case-insensitive), or null */
  header(name: string): string | null;
}

/** b77q (audit 3 DV-2): the part of XMLHttpRequest a bounded download uses (React Native's, or a test double) */
export interface XhrLike {
  open(method: string, url: string): void;
  send(body?: string | null): void;
  /** b77t (audit 5 L-27): JSON relay calls on a non-streaming platform go through XMLHttpRequest too */
  setRequestHeader?(name: string, value: string): void;
  abort(): void;
  getResponseHeader(name: string): string | null;
  responseType: string;
  /** b77s (audit 4 A-01): set false before every send — React Native's XMLHttpRequest defaults it to true, which
   *  sends and stores the platform's cookies (Android's cookie jar) with a media download */
  withCredentials: boolean;
  readonly readyState: number;
  readonly status: number;
  readonly response: unknown;
  readonly responseURL?: string;
  onreadystatechange: (() => void) | null;
  onprogress: ((ev: { loaded: number; total?: number; lengthComputable?: boolean }) => void) | null;
  onload: (() => void) | null;
  onerror: (() => void) | null;
  onabort: (() => void) | null;
  ontimeout: (() => void) | null;
}
export type XhrCtor = new () => XhrLike;

/** b77z2 (Z-1): one relay function call never waits longer than this (ms) by default */
export const RELAY_TIMEOUT_MS = 30_000;

/** b77z2 (Z-1): a relay call that did not answer in time (status 0: a transient failure, so a burn
 *  stays queued for the next pass and a sync pass ends with an error instead of hanging) */
export class RelayTimeoutError extends Error {
  readonly status = 0;
  constructor(fn: string, ms: number) {
    super(`The relay did not answer in time (${fn}, ${Math.round(ms / 1000)} s)`);
    this.name = 'RelayTimeoutError';
  }
}

/** b77z2 (Z-1): fetch + read the JSON body, abandoned after `ms`. VeilRelay.invoke had no
 *  timeout, and syncChat holds the per-token chain for its whole pass, so one hung request held
 *  every later pass and send of that chat for as long as it hung. The request is aborted
 *  (AbortController, where the platform has one) and the wait itself is bounded too, so a fetch
 *  that ignores the signal can't hang the caller either. */
/** b77s (audit 4 A-01 / A-03): and every call is made with credentials 'omit' (no platform cookies: React Native's
 *  fetch defaults to same-origin, which its XHR sends as withCredentials = true), and its answer is read within a
 *  byte limit (readJsonBounded: Content-Length first, then counted while read; `maxBytes` defaults to the route's,
 *  relayJsonLimitFor(fn)) and never parsed past it. */
/** b77t (audit 5 L-27, R2 A-03): `xhr` (React Native, see VeilRelay.jsonXhr): the call goes through XMLHttpRequest,
 *  whose Content-Length is checked when the headers arrive and whose body is counted as it arrives
 *  (xhrJsonBounded), because RN's fetch hands over a response only after the native side buffered all of it. */
async function fetchJsonWithTimeout(fetchImpl: typeof fetch, url: string, init: RequestInit, fn: string, ms: number, maxBytes = relayJsonLimitFor(fn), xhr: XhrCtor | null = null): Promise<{ res: Response; data: unknown }> {
  if (xhr && typeof xhr.prototype?.setRequestHeader === 'function' && (init.body === undefined || init.body === null || typeof init.body === 'string')) {
    return xhrJsonBounded(xhr, url, init, fn, maxBytes, ms);
  }
  const ctl = typeof AbortController === 'function' ? new AbortController() : null;
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => { try { ctl?.abort(); } catch { /* never throws */ } reject(new RelayTimeoutError(fn, ms)); }, ms);
  });
  try {
    return await Promise.race([
      (async () => {
        const res = await fetchImpl(url, { ...init, credentials: 'omit', ...(ctl ? { signal: ctl.signal } : {}) }); // b77s (audit 4 A-01)
        const data = await readJsonBounded(res, maxBytes, fn, () => { try { ctl?.abort(); } catch { /* never throws */ } }); // b77s (audit 4 A-03)
        return { res, data };
      })(),
      timeout,
    ]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

/**
 * b77t (audit 5 L-27, R2 A-03): one JSON relay call over XMLHttpRequest, bounded at the headers. React Native's
 * fetch answers only once its native networking module has read the whole body (Android: responseBody.string()),
 * so readJsonBounded's Content-Length check came after a hostile relay's oversized answer was already in memory.
 * Here a declared Content-Length over `maxBytes` aborts the request when the headers arrive (before the body is
 * read), and a body without one is aborted the moment the bytes received pass the limit (onprogress). Never
 * parsed past it (RelayResponseTooLargeError). No cookies (withCredentials false, b77s A-01).
 */
export function xhrJsonBounded(Xhr: XhrCtor, url: string, init: RequestInit, route: string, maxBytes: number, ms: number): Promise<{ res: Response; data: unknown }> {
  return new Promise((resolve, reject) => {
    const x = new Xhr();
    let done = false;
    const finish = (err: Error | null, out?: { res: Response; data: unknown }) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      x.onprogress = null; x.onreadystatechange = null; x.onload = null; x.onerror = null; x.onabort = null; x.ontimeout = null;
      if (err) { try { x.abort(); } catch { /* never throws */ } reject(err); } else resolve(out!);
    };
    const tooBig = () => finish(new RelayResponseTooLargeError(route, maxBytes));
    const timer = setTimeout(() => finish(new RelayTimeoutError(route, ms)), ms);
    x.onreadystatechange = () => {
      if (x.readyState < 2 || done) return; // HEADERS_RECEIVED: before the body
      const len = Number(x.getResponseHeader('content-length') ?? NaN);
      if (Number.isFinite(len) && len > maxBytes) tooBig();
    };
    x.onprogress = (ev) => {
      if (done) return;
      if (Number(ev?.loaded) > maxBytes || (ev?.lengthComputable && Number(ev.total) > maxBytes)) tooBig();
    };
    x.onload = () => {
      if (done) return;
      const r = x.response;
      const text = typeof r === 'string' ? r : '';
      if (text.length > maxBytes || utf8ByteLength(text) > maxBytes) { tooBig(); return; }
      let data: unknown = null;
      try { data = text ? JSON.parse(text) : null; } catch { data = null; }
      const status = x.status;
      const res = { ok: status >= 200 && status <= 299, status, headers: { get: (n: string) => x.getResponseHeader(n) } } as unknown as Response;
      finish(null, { res, data });
    };
    x.onerror = () => finish(new TypeError('Network request failed')); // what RN's fetch throws
    x.onabort = () => finish(new TypeError('Network request failed'));
    x.ontimeout = () => finish(new RelayTimeoutError(route, ms));
    try {
      x.open(String(init.method ?? 'GET'), url);
      x.responseType = 'text';
      x.withCredentials = false; // b77s (audit 4 A-01)
      if (x.withCredentials !== false) throw new Error('This phone could not turn off cookies for a relay call — nothing was sent.');
      const h = init.headers as Record<string, string> | undefined;
      for (const [k, v] of Object.entries(h ?? {})) x.setRequestHeader!(k, String(v));
      x.send(typeof init.body === 'string' ? init.body : null);
    } catch (e) { finish(e instanceof Error ? e : new Error(String(e))); }
  });
}

/** b77p (audit VAR-11): the relay's file cap (relay/main.ts: 25 MiB) — the same value as chat.ts
 *  MEDIA_RELAY_FILE_CAP (a padded media blob, or a vault container, is never larger) */
export const RELAY_FILE_CAP_BYTES = 26214400;

/** b77p (audit VAR-11): media transfer limits (ms). connect = until the response headers; idle = the longest
 *  gap between body chunks; total = the whole download; upload = an upload's request and answer. 25 MiB in
 *  10 minutes is about 45 KB/s.
 *  b77q owner (1 Nov, slow links): the relay now serves a download down to 8 KB/s, idle up to 60 s, for at most 60
 *  minutes (relay/main.ts DOWNLOAD_*), so the phone's clocks sit above them: idle 75 s, total 65 minutes (a 25 MiB
 *  file at 8 KB/s takes ~53 min). Uploads keep 10 minutes (the relay's upload deadline is 300 s plus a 15 s slot wait). */
export const MEDIA_FETCH_LIMITS = { connectMs: 30_000, idleMs: 75_000, totalMs: 65 * 60_000, uploadMs: 10 * 60_000 };

/** b77p (audit VAR-11): a download (or upload) larger than the relay's file cap — refused, never buffered */
export class MediaTooLargeError extends Error {
  constructor(what = 'download') {
    super(`The ${what} is larger than the 25 MB media limit — refused.`);
    this.name = 'MediaTooLargeError';
  }
}

/** b77p round 2 (review M2): does this platform's fetch resolve at the response headers (and stream the body)?
 *  React Native's (0.76: the XMLHttpRequest polyfill, no res.body.getReader) resolves only once the WHOLE body has
 *  arrived, so a clock around `await fetch(...)` there bounds the entire download. RN says so in navigator.product;
 *  elsewhere a platform without ReadableStream can't stream either. */
export function fetchStreams(): boolean {
  const nav = (globalThis as { navigator?: { product?: unknown } }).navigator;
  if (nav && nav.product === 'ReactNative') return false;
  return typeof (globalThis as { ReadableStream?: unknown }).ReadableStream === 'function';
}

/** b77q (audit 3 DV-1): a download the relay redirected somewhere else — refused */
export class MediaRedirectError extends Error {
  constructor() {
    super('The relay redirected a download elsewhere — refused.');
    this.name = 'MediaRedirectError';
  }
}
const sameUrl = (a: string, b: string): boolean => {
  try { return new URL(a).href === new URL(b).href; } catch { return false; }
};

/** b77p (audit VAR-11): bytes to upload larger than the relay's file cap are refused before anything is sent */
function assertUploadSize(bytes: Uint8Array | undefined): void {
  if (bytes && bytes.length > RELAY_FILE_CAP_BYTES) throw new MediaTooLargeError('upload');
}

/** b77p (audit VAR-11): fetch a body as bytes with a size cap and three clocks. `fetchBytes` used to buffer
 *  the whole answer with no abort signal or length check, so a hostile relay could stall a download for ever
 *  ("Decrypting…" never ends) or stream gigabytes into memory (Hermes dies every time the chat opens). Now:
 *  the headers must come within connectMs; a Content-Length over maxBytes is refused unread; the body is read
 *  chunk by chunk where the platform streams (res.body.getReader) and aborted the moment it passes maxBytes
 *  or a chunk takes longer than idleMs; the whole download is bounded by totalMs. Where the body can't be
 *  streamed (React Native's fetch), arrayBuffer() is raced against the clocks and its length checked. The
 *  request is aborted (AbortController) on every failure; the wait is bounded even if fetch ignores it.
 *  b77p round 2 (review M2): where fetch does NOT stream (`lim.streams` false, by default fetchStreams()), it answers
 *  only once the whole body is in, so connectMs (30 s) there bounded the entire download: 10–25 MB media and the
 *  backup restore always failed on a slower link. On such a platform the wait for the answer, and for its bytes,
 *  runs to totalMs instead; the Content-Length and the post-read size checks are unchanged. */
export async function fetchBytesBounded(
  fetchImpl: typeof fetch, url: string, init: RequestInit,
  lim: { maxBytes: number; connectMs: number; idleMs: number; totalMs: number; streams?: boolean },
): Promise<Uint8Array> {
  const streams = lim.streams ?? fetchStreams();
  const ctl = typeof AbortController === 'function' ? new AbortController() : null;
  const abort = () => { try { ctl?.abort(); } catch { /* never throws */ } };
  const timers: Array<ReturnType<typeof setTimeout>> = [];
  let fail!: (e: Error) => void;
  const failed = new Promise<never>((_, reject) => { fail = (e) => { abort(); reject(e); }; });
  failed.catch(() => undefined);
  const clock = (ms: number, what: string): ReturnType<typeof setTimeout> => {
    const t = setTimeout(() => fail(new RelayTimeoutError(what, ms)), ms);
    timers.push(t);
    return t;
  };
  clock(lim.totalMs, 'media download');
  try {
    // b77p round 2 (review M2): a non-streaming fetch answers with the whole body: only totalMs bounds that wait
    const connect = streams ? clock(lim.connectMs, 'media download (no answer)') : undefined;
    // b77q (audit 3 DV-1): redirects are refused — the link was checked against the relay's origin (assertSignedUrl),
    // and a 3xx from there used to be followed to any host (a GET from the phone's network to a third party)
    const res = await Promise.race([fetchImpl(url, { ...init, redirect: 'error', credentials: 'omit', ...(ctl ? { signal: ctl.signal } : {}) }), failed]);
    if (connect !== undefined) clearTimeout(connect);
    // (a platform that ignores `redirect` — React Native's fetch — still says where the answer came from)
    if (res.redirected === true || (typeof res.url === 'string' && res.url !== '' && !sameUrl(res.url, url))) { abort(); throw new MediaRedirectError(); }
    if (!res.ok) throw new Error(`Media fetch failed (${res.status})`);
    const len = Number(res.headers?.get?.('content-length') ?? NaN);
    if (Number.isFinite(len) && len > lim.maxBytes) { abort(); throw new MediaTooLargeError(); }
    const reader = (res.body as ReadableStream<Uint8Array> | null | undefined)?.getReader?.();
    if (!reader) {
      const idle = streams ? clock(lim.idleMs, 'media download (stalled)') : undefined; // (review M2: as above)
      const buf = new Uint8Array(await Promise.race([res.arrayBuffer(), failed]));
      if (idle !== undefined) clearTimeout(idle);
      if (buf.length > lim.maxBytes) { buf.fill(0); throw new MediaTooLargeError(); }
      return buf;
    }
    const parts: Uint8Array[] = [];
    let total = 0;
    for (;;) {
      const idle = clock(lim.idleMs, 'media download (stalled)');
      let step: ReadableStreamReadResult<Uint8Array>;
      try { step = await Promise.race([reader.read(), failed]); } finally { clearTimeout(idle); }
      if (step.done) break;
      const chunk = step.value;
      total += chunk.length;
      if (total > lim.maxBytes) {
        abort();
        try { await reader.cancel(); } catch { /* aborted already */ }
        for (const p of parts) p.fill(0);
        throw new MediaTooLargeError();
      }
      parts.push(chunk);
    }
    const out = new Uint8Array(total);
    let at = 0;
    for (const p of parts) { out.set(p, at); at += p.length; p.fill(0); }
    return out;
  } finally {
    for (const t of timers) clearTimeout(t);
  }
}

/**
 * b77q (audit 3 DV-2): the bounded download where fetch can't stream (React Native). fetch there answers only once
 * the whole body is in memory, so the 25 MiB cap was checked after a hostile relay's chunked answer (no
 * Content-Length) had been read whole — up to whatever the link carries in totalMs. XMLHttpRequest reports the
 * bytes as they arrive (onprogress, RN's networking module: `loaded`), so the request is aborted the moment the
 * count passes maxBytes, or a Content-Length (at the headers) is over it. Only totalMs bounds the wait (review M2:
 * no connect / idle clock on such a platform). A redirect can't be refused before it is followed (XHR always
 * follows), but its answer is: responseURL other than the link -> aborted, MediaRedirectError.
 * b77q review (DV-1 residual, spec §12.8): so on the phone a relay that answers its own /files/ link with a
 * 3xx still makes ONE GET reach the host it names (the phone's address and the time; the URL is the relay's choice),
 * with no cookie, token or app header. The honest relay never redirects /files/, and the link was checked against its
 * origin, path and scheme first (assertSignedUrl). Closing it needs a native no-redirect download (not done).
 */
export function xhrBytesBounded(Xhr: XhrCtor, url: string, lim: { maxBytes: number; totalMs: number }): Promise<Uint8Array> {
  return new Promise<Uint8Array>((resolve, reject) => {
    const x = new Xhr();
    let done = false;
    const finish = (err: Error | null, out?: Uint8Array) => {
      if (done) return;
      done = true;
      clearTimeout(total);
      x.onprogress = null; x.onreadystatechange = null; x.onload = null; x.onerror = null; x.onabort = null; x.ontimeout = null;
      if (err) { try { x.abort(); } catch { /* never throws */ } reject(err); } else resolve(out as Uint8Array);
    };
    const total = setTimeout(() => finish(new RelayTimeoutError('media download', lim.totalMs)), lim.totalMs);
    const redirected = () => typeof x.responseURL === 'string' && x.responseURL !== '' && !sameUrl(x.responseURL, url);
    x.onreadystatechange = () => {
      if (x.readyState < 2 || done) return; // HEADERS_RECEIVED
      if (redirected()) { finish(new MediaRedirectError()); return; }
      const len = Number(x.getResponseHeader('content-length') ?? NaN);
      if (Number.isFinite(len) && len > lim.maxBytes) finish(new MediaTooLargeError());
    };
    x.onprogress = (ev) => {
      if (done) return;
      if (Number(ev?.loaded) > lim.maxBytes || (ev?.lengthComputable && Number(ev.total) > lim.maxBytes)) finish(new MediaTooLargeError());
    };
    x.onload = () => {
      if (done) return;
      if (redirected()) { finish(new MediaRedirectError()); return; }
      if (x.status < 200 || x.status > 299) { finish(new Error(`Media fetch failed (${x.status})`)); return; }
      const r = x.response;
      const buf = r instanceof ArrayBuffer ? new Uint8Array(r) : ArrayBuffer.isView(r) ? new Uint8Array(r.buffer, r.byteOffset, r.byteLength) : null;
      if (!buf) { finish(new Error('Media fetch failed (no body)')); return; }
      if (buf.length > lim.maxBytes) { buf.fill(0); finish(new MediaTooLargeError()); return; }
      finish(null, buf);
    };
    x.onerror = () => finish(new Error('Media fetch failed (network)'));
    x.onabort = () => finish(new Error('Media fetch failed (aborted)'));
    x.ontimeout = () => finish(new RelayTimeoutError('media download', lim.totalMs));
    try {
      x.open('GET', url);
      x.responseType = 'arraybuffer';
      x.withCredentials = false; // b77s (audit 4 A-01): no cookies (RN's default is true)
      if (x.withCredentials !== false) throw new Error('This phone could not turn off cookies for a media download — nothing was fetched.');
      x.send(null);
    } catch (e) { finish(e instanceof Error ? e : new Error(String(e))); }
  });
}

/** b77 (sealed sender): what a sealedSubmit carries. No session token, write secret, sender tag,
 *  account id or bearer token — the send capability for the peer's inbound mailbox is the only
 *  credential (spec §4.10). */
export interface SealedSubmission {
  mbox: string;
  send_cap: string;
  ciphertext: string;
  iv: string;
  header: string;
  byte_length: number;
  ttl_seconds: number;
  /** wake the recipient: 'msg' (a human message), 'call' (a ring; only when the callee's inbound
   *  is verified), false (cover, receipts, control) */
  notify: false | 'msg' | 'call';
  /** b77p (audit 2 VAR-01): the peer inbound's wake capability — opens its sealed wake box for this push only
   *  (sent with every submit, so its presence says nothing; never stored by the relay) */
  wake_cap?: string;
}

/** b77: one stored envelope as sealedFetch returns it */
export interface SealedItem { id: string; seq: number; ciphertext: string; iv: string; header: string; byte_length?: number; expires_at?: string }

/** b77: a relay error carries its HTTP status (425 = mailbox not open yet, 410 = retired) */
export function relayStatusOf(e: unknown): number {
  const s = Number((e as { status?: unknown } | null)?.status);
  return Number.isFinite(s) ? s : 0;
}

export interface EnvelopeSubmission {
  session_token: string;
  /** Batch D (D-12, RV-48): accepted from callers but never sent — the relay
   *  doesn't need the account's client id on an envelope (V-13) */
  client_id?: string;
  write_secret: string | null;
  /** group envelopes only: the group sender tag (b77: never on a 1:1 envelope) */
  sender_client_id?: string;
  ciphertext: string;
  iv: string;
  header: string;
  byte_length: number;
  ttl_seconds: number;
  protocolVersion?: string;
  /** b76r1 (audit AUD-I3): no longer sent — the file id travels only inside the encrypted body (the web
   *  bundle added media_uri for media bodies; the relay never stored or used it). Kept in the type so an
   *  old caller fails loudly in review rather than silently; never forwarded (see submitEnvelope). */
  media_uri?: never;
  /** group messages only: the veil-group-2 channel token — group envelopes
   *  carry BOTH session_token and group_token (web parity). */
  group_token?: string;
}

/**
 * b74 (audit VAR-20): is a relay-supplied download link one this app may fetch? Only a
 * file link (/files/<id>) on the CONFIGURED relay's own origin, over https — or plain http
 * when the configured relay itself is a loopback test relay (http://127.0.0.1:…). The
 * relay's answer used to be fetched wherever it pointed (any host, any scheme), so a
 * hostile or broken relay could aim the phone at a third party.
 */
export function relaySignedUrlAllowed(url: string, baseUrl: string): boolean {
  let u: URL, b: URL;
  try { u = new URL(url); b = new URL(baseUrl); } catch { return false; }
  if (u.origin !== b.origin || u.username || u.password) return false;
  if (!/^\/files\/[A-Za-z0-9_-]{1,128}$/.test(u.pathname)) return false;
  const loopback = b.hostname === '127.0.0.1' || b.hostname === 'localhost' || b.hostname === '[::1]';
  return u.protocol === 'https:' || (loopback && u.protocol === 'http:');
}

/** b77t2 (CL-6): the transport choices one JSON client makes (VeilRelay's RelayConfig, Base44Auth's AuthFetchConfig) */
export interface RelayJsonTransport {
  fetchImpl?: typeof fetch;
  xhrImpl?: XhrCtor | null;
  fetchStreams?: boolean;
  onAnswer?: (a: RelayAnswerInfo) => void;
}

/** b77t (audit 5 L-27): the XMLHttpRequest JSON calls go through where fetch doesn't stream (React Native): the
 *  injected one, else the platform's when fetch is not injected; null where fetch streams.
 *  b77t2 (CL-6): exported (was VeilRelay.jsonXhr's body) so Base44Auth makes the same choice. */
export function relayJsonXhr(t: RelayJsonTransport): XhrCtor | null {
  if (t.fetchStreams ?? fetchStreams()) return null;
  if (t.xhrImpl !== undefined) return t.xhrImpl;
  const platformXhr = (globalThis as { XMLHttpRequest?: unknown }).XMLHttpRequest;
  return !t.fetchImpl && typeof platformXhr === 'function' ? platformXhr as XhrCtor : null;
}

/** b77t (audit 5 L-4 x L-27): one bounded JSON call (fetchJsonWithTimeout: a timeout, credentials 'omit', the answer
 *  read within a byte limit, on XMLHttpRequest where fetch doesn't stream), then `onAnswer` sees the answer whichever
 *  transport carried it. b77t2 (CL-6): exported (was VeilRelay.fetchJson's body) for Base44Auth. */
export async function relayJsonCall(fetchImpl: typeof fetch, url: string, init: RequestInit, fn: string, ms: number, maxBytes?: number, xhr: XhrCtor | null = null, onAnswer?: (a: RelayAnswerInfo) => void): Promise<{ res: Response; data: unknown }> {
  const out = await fetchJsonWithTimeout(fetchImpl, url, init, fn, ms, maxBytes ?? relayJsonLimitFor(fn), xhr);
  if (onAnswer) {
    try {
      const h = init.headers;
      const signedIn = !!h && (typeof (h as Headers).get === 'function' ? !!(h as Headers).get('Authorization')
        : Object.keys(h as Record<string, string>).some((k) => k.toLowerCase() === 'authorization' && !!(h as Record<string, string>)[k]));
      const res = out.res;
      onAnswer({ url, status: res.status, ok: res.ok, signedIn, header: (n) => { try { return res.headers?.get?.(n) ?? null; } catch { return null; } } });
    } catch { /* a hint only */ }
  }
  return out;
}

export class VeilRelay {
  private cfg: RelayConfig;

  /** b77t (audit 5 L-27): the XMLHttpRequest JSON calls go through where fetch doesn't stream (React Native):
   *  the injected one, else the platform's when fetch is not injected; null where fetch streams */
  private jsonXhr(): XhrCtor | null {
    return relayJsonXhr(this.cfg); // b77t2 (CL-6): shared with Base44Auth
  }

  /** b77t (audit 5 L-4 x L-27): every JSON call goes through here, so RelayConfig.onAnswer sees the answer on both
   *  transports (fetch, and the XMLHttpRequest path React Native takes, which never touches `fetchImpl`) */
  private async fetchJson(fetchImpl: typeof fetch, url: string, init: RequestInit, fn: string, ms: number, maxBytes?: number, xhr: XhrCtor | null = null): Promise<{ res: Response; data: unknown }> {
    return relayJsonCall(fetchImpl, url, init, fn, ms, maxBytes, xhr, this.cfg.onAnswer); // b77t2 (CL-6): shared with Base44Auth
  }

  /** b74 (audit VAR-20): the link, if this relay's own file link (relaySignedUrlAllowed); throws otherwise */
  assertSignedUrl(url: string): string {
    if (!relaySignedUrlAllowed(url, this.cfg.baseUrl)) throw new Error('The relay sent a download link Vardum does not trust — nothing was fetched.');
    return url;
  }

  // b190 (owner Metro log Oct 11, 20:34): background pollers (auto-rotate's
  // identity lookups, group roster polls, heartbeats, session list) each had
  // their own — or no — backoff, so together they hammered the relay's
  // per-account limiter, re-locking it for minutes at a time while ONE idle
  // device sat in the owner's pocket. Every rate-limit response now stamps
  // a SHARED quiet window on the relay client; background loops consult
  // gateHot() before firing and go silent together, letting the lock
  // actually expire instead of resetting it every few seconds.
  private gateHotUntil = 0;

  /** True while the shared rate-limit quiet window is active. */
  gateHot(): boolean {
    return Date.now() < this.gateHotUntil;
  }

  constructor(cfg: RelayConfig) {
    this.cfg = cfg;
  }

  /** b77p (audit VAR-11): how long an upload (request body and answer) may take */
  private uploadTimeoutMs(): number {
    return { ...MEDIA_FETCH_LIMITS, ...(this.cfg.mediaLimits ?? {}) }.uploadMs;
  }

  /** Raw function invoke — the V.functions.invoke contract.
   *  b77m (owner, carrier NAT): a per-network cap answers with a puzzle; it is solved and the call repeated
   *  (withNetworkPow) — every function route (sign-up / provision, TURN, mailbox verify, …) gets it. */
  invoke(fn: string, payload: Record<string, unknown>): Promise<{ data: unknown; status: number }> {
    return withNetworkPow((extra) => this.invokeOnce(fn, { ...payload, ...extra }));
  }

  private async invokeOnce(fn: string, payload: Record<string, unknown>): Promise<{ data: unknown; status: number }> {
    const fetchImpl = this.cfg.fetchImpl ?? fetch;
    const token = await this.cfg.getToken();
    const action = typeof payload.action === 'string' ? payload.action : '(none)';
    const { res, data } = await this.fetchJson(fetchImpl, `${this.cfg.baseUrl}/api/apps/${this.cfg.appId}/functions/${fn}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
      },
      body: JSON.stringify(payload),
    }, fn, this.cfg.timeoutMs ?? RELAY_TIMEOUT_MS, undefined, this.jsonXhr()); // b77z2 (Z-1)
    if (!res.ok) {
      const d = data as { message?: string; error?: string; locked?: boolean; retry_minutes?: number } | null;
      // b167 (owner Metro log Oct 2: veilIdentityGate 429 body had ONLY
      // {locked:true, retry_minutes:10} — no message/error field, so the
      // thrown error was a useless 'relay error 429'). Surface the lock and
      // its window so the UI can tell the user exactly what to do.
      // b77m (audit VAR-20): what the error SAYS is app-written (relay-errors.ts: a known code, a known
      // relay message, or a fixed sentence for the status); the relay's own words (cleaned, cut to 240
      // characters) are kept only for these logs and the matches below — never for the UI
      const rerr = relayErrorFor(res.status, data);
      const msg = rerr.relayMessage || rerr.message;
      // b79 DIAGNOSTIC: "Unknown action" has been unreproducible against the
      // live server via every known action string — log the FULL context at
      // the exact point of failure (function, action, http status, raw
      // body, auth-token presence) so the next occurrence is conclusive
      // instead of another guess.
      // b87/b88 (owner repro): openChat() calls sessionActivate
      // unconditionally on every open (App.tsx) and already .catch()es the
      // result — it's fire-and-forget, the outcome never affects the UI.
      // The server can reject it for more than one KNOWN, harmless reason
      // depending on session type/role, and this blanket console.error was
      // painting every one of them as a scary red failure on ordinary
      // thread-opens. b87 covered the non-creator case; b88 adds the
      // "not a group, no peer yet" case (owner repro Sept 21 ~03:15 Bris,
      // Metro: veilSessionGate(activate) 400 "Only group sessions can be
      // activated without a peer" — a 1:1 session activated before this
      // device's own join call recorded a peer). Only these two specific,
      // well-understood messages drop to info level; every other relay
      // failure (including any OTHER activate rejection) still logs at
      // error level unchanged.
      const isExpectedActivateRejection = action === 'activate' && (
        /only the session creator can activate/i.test(msg)
        || /only group sessions can be activated without a peer/i.test(msg)
      );
      // b88: burn's "Entity VeilEnvelope with ID ... not found" means the
      // envelope is ALREADY gone (already burned by a prior pass, expired
      // and swept by the relay, or removed as part of session cleanup) —
      // the state burn wants (this envelope not sitting around) is already
      // true. chat.ts's own burn loop (see the sibling isExpectedBurnMiss
      // check there) treats this the same way; this invoke()-level log
      // just needs to stop screaming about it too.
      const isExpectedBurnMiss = action === 'burn' && /entity veilenvelope with id .* not found/i.test(msg);
      // b166 (owner Metro log Oct 2, native→web supersede flow): the b155
      // presence heartbeat (30s tick) and the cover-traffic sender (b164's
      // 15%-roll filler envelope) both run on their OWN interval, decoupled
      // from the 10s session-list poll that detects a dead/superseded
      // session. In the window between the peer superseding a thread
      // server-side and this device's next list refresh noticing it, a
      // heartbeat or cover-send can land on the now-gone session and 404.
      // Both call sites already swallow the throw and never affect the UI
      // (see the heartbeat loop's bare catch and sendCoverEnvelope's
      // .catch() in App.tsx) — this was purely a cosmetic console.error
      // scaring the owner into thinking something broke, same class as the
      // b87/b88 cases right above. Downgraded to info level; the underlying
      // behavior (bounded, self-resolving via the next supersede-switch) is
      // unchanged.
      const isExpectedHeartbeatMiss = action === 'heartbeat' && /session not found/i.test(msg);
      const isExpectedSendMiss = fn === 'submitEnvelope' && /session (not found|is not available)/i.test(msg);
      // TURN credentials: the caller (CallManager turnIce) falls back to
      // host-only and logs its own line — not an error worth a red LogBox.
      const isTurnFallback = fn === 'veilTurnCredentials';
      if (isTurnFallback) {
        console.log(`[veil-relay] ${fn} unavailable — HTTP ${res.status}`);
      } else if (isExpectedActivateRejection) {
        console.log(`[veil-relay] ${fn}(activate) skipped — expected rejection for this session's type/role (${msg})`);
      } else if (isExpectedBurnMiss) {
        console.log(`[veil-relay] ${fn}(burn) skipped — envelope already gone (${msg})`);
      } else if (isExpectedHeartbeatMiss) {
        console.log(`[veil-relay] ${fn}(heartbeat) skipped — session already superseded/gone, next poll will switch away (${msg})`);
      } else if (isExpectedSendMiss) {
        console.log(`[veil-relay] ${fn}(${action}) skipped — session already superseded/gone, next poll will switch away (${msg})`);
      } else {
        // b197 (audit L-4): truncate server-controlled response bodies before
        // they land in device logs — a hostile relay could plant oversized or
        // crafted strings there. 240 chars is ample for diagnosis.
        const rawBody = JSON.stringify(data) ?? '';
        console.error(`[veil-relay] ${fn}(${action}) FAILED — HTTP ${res.status}, hadToken=${!!token}, body=${rawBody.length > 240 ? rawBody.slice(0, 240) + '…(' + rawBody.length + 'B truncated)' : rawBody}`);
      }
      // b190: stamp the shared quiet window — a locked limiter (locked:true +
      // retry_minutes) sets it for the full lock window + jitter; a plain
      // 429/500 rate-limit sets a short 30s cool-off. gateHot() consulters
      // (heartbeat, session list, group polls, auto-rotate, cover sends) go
      // quiet together and stop re-triggering the limiter.
      // (b77m, owner: a network puzzle is not a rate limit — it is solved and the call repeated at once)
      if ((res.status === 429 && !(data as { pow_required?: boolean } | null)?.pow_required) || (res.status === 500 && /rate limit/i.test(msg))) {
        const mins = Math.max(0, Math.floor(Number(d?.retry_minutes) || 0));
        const quietMs = (mins > 0 ? mins * 60_000 + 5_000 : 30_000) + Math.floor(secureRandomUnit() * 5_000); // b77t (audit 5 L-28, R5 F-4): CSPRNG, not Math.random
        this.gateHotUntil = Math.max(this.gateHotUntil, Date.now() + quietMs);
        console.log(`[veil-relay] rate-limited (${fn}/${action}) — background gate traffic paused for ${Math.round(quietMs / 1000)}s`);
      }
      // b76 (registration lock): status and body ride along (a 423 from the lock is read by
      // dev/reglock.ts:regLockInfo); the message is unchanged for every existing caller
      throw rerr;
    }
    return { data, status: res.status };
  }

  /**
   * b77 (sealed sender): an ANONYMOUS function invoke. It never sends an Authorization header,
   * never asks the token provider, and never sends cookies or other credentials — the body's
   * capability is the only proof (spec §4.10). Every sealed route and the no-login gate actions
   * (join of a 1:1 row, status) go through here.
   */
  invokeAnon(fn: string, payload: Record<string, unknown>): Promise<{ data: unknown; status: number }> {
    return withNetworkPow((extra) => this.invokeAnonOnce(fn, { ...payload, ...extra })); // b77m (owner): the network puzzle
  }

  private async invokeAnonOnce(fn: string, payload: Record<string, unknown>): Promise<{ data: unknown; status: number }> {
    const fetchImpl = this.cfg.fetchImpl ?? fetch;
    const { res, data } = await this.fetchJson(fetchImpl, `${this.cfg.baseUrl}/api/apps/${this.cfg.appId}/functions/${fn}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'omit',
      body: JSON.stringify(payload),
    } as RequestInit, fn, this.cfg.timeoutMs ?? RELAY_TIMEOUT_MS, undefined, this.jsonXhr()); // b77z2 (Z-1): every sealed route
    if (!res.ok) {
      // b77m (audit VAR-20): app-written message; the relay's words only in the log line
      const rerr = relayErrorFor(res.status, data);
      const msg = rerr.relayMessage || rerr.message;
      // 425 (not open yet) and 410 (retired) are expected states the callers handle
      if (res.status === 425 || res.status === 410) console.log(`[veil-relay] ${fn} — HTTP ${res.status} (${String(msg).slice(0, 80)})`);
      else {
        const rawBody = JSON.stringify(data) ?? '';
        console.log(`[veil-relay] ${fn} FAILED — HTTP ${res.status}, body=${rawBody.length > 240 ? rawBody.slice(0, 240) + '…' : rawBody}`);
      }
      throw rerr;
    }
    return { data, status: res.status };
  }

  // ---------- b77 sealed-sender mailboxes (no login; spec §4.10, Relay API) ----------

  /** open MY inbound mailbox with its blind-signed open token (b77p, audit 2 VAR-01: no ticket the join named).
   *  403 bad/used token, 409 exists, 410 retired. */
  /** b77u (audit 6 W4): `own_hash` — H(owner cap); the relay then takes the owner-only operations only with that cap.
   *  A 409 says `owned` (true: this phone's own earlier open; false: someone else opened this mailbox first). */
  mailboxOpen(o: { mbox: string; send_hash: string; read_hash: string; open_token: { kid: string; x: string; s: string }; ttl_cap_s: number; own_hash?: string }) {
    return this.invokeAnon('mailboxOpen', { mbox: o.mbox, send_hash: o.send_hash, read_hash: o.read_hash, open_token: { kid: o.open_token.kid, x: o.open_token.x, s: o.open_token.s }, ttl_cap_s: o.ttl_cap_s, ...(o.own_hash ? { own_hash: o.own_hash } : {}) });
  }

  /** b77p (audit 2 VAR-01): the relay's open-token issuer key {kid, n, e, until} (no login) */
  openKey() {
    return this.invokeAnon('openKey', {});
  }

  /** b77p (audit 2 VAR-01): one blind open signature for my side of a joined rendezvous (no login; the write secret
   *  is the proof). The responder's normally comes with its join. */
  sessionIssue(token: string, writeSecret: string | null, openBlind: string, openKid: string) {
    return this.invokeAnon('veilSessionGate', { action: 'issue', token, write_secret: writeSecret, open_blind: openBlind, open_kid: openKid });
  }

  /** submit to the PEER's inbound with the send capability. 425 not open yet, 410 retired, 403 bad cap. */
  sealedSubmit(sub: SealedSubmission) {
    return this.invokeAnon('sealedSubmit', {
      mbox: sub.mbox, send_cap: sub.send_cap, ciphertext: sub.ciphertext, iv: sub.iv, header: sub.header,
      byte_length: sub.byte_length, ttl_seconds: sub.ttl_seconds, notify: sub.notify,
      ...(sub.wake_cap ? { wake_cap: sub.wake_cap } : {}),
    });
  }

  /** read MY inbound after a cursor. {items, next_seq}; 410 retired, 425 never opened. */
  async sealedFetch(mbox: string, readCap: string, afterSeq?: number, limit = 100): Promise<{ items: SealedItem[]; next_seq: number | null }> {
    const r = await this.invokeAnon('sealedFetch', {
      mbox, read_cap: readCap, ...(afterSeq !== undefined && afterSeq > 0 ? { after_seq: afterSeq } : {}), limit: Math.min(Math.max(1, limit), 100),
    });
    const d = (r.data as { data?: unknown } | null)?.data ?? r.data;
    const items = Array.isArray((d as { items?: unknown })?.items) ? (d as { items: SealedItem[] }).items : [];
    const ns = Number((d as { next_seq?: unknown })?.next_seq);
    return { items, next_seq: Number.isFinite(ns) ? ns : null };
  }

  /** delete these envelopes from MY inbound now (up to 50 ids) */
  sealedBurn(mbox: string, readCap: string, ids: string[]) {
    return this.invokeAnon('sealedBurn', { mbox, read_cap: readCap, ids: ids.slice(0, 50) });
  }

  /** delete and retire a mailbox: my inbound with my read cap, or the peer's inbound with my send cap */
  sealedEnd(mbox: string, cap: string) {
    return this.invokeAnon('sealedEnd', { mbox, cap });
  }

  /** bind (or with null unbind) the wake reference of MY inbound */
  mailboxPush(mbox: string, readCap: string, wakeBox: string | null, ownCap?: string) {
    return this.invokeAnon('mailboxPush', { mbox, read_cap: readCap, wake: wakeBox, ...(ownCap ? { own_cap: ownCap } : {}) }); // b77u (audit 6 W4)
  }

  /** set `verified` on MY inbound (call rings and TURN need it) */
  mailboxVerify(mbox: string, readCap: string, verified: boolean, ownCap?: string) {
    return this.invokeAnon('mailboxVerify', { mbox, read_cap: readCap, verified, ...(ownCap ? { own_cap: ownCap } : {}) }); // b77u (audit 6 W4)
  }

  /** b77n (audit VAR-04): the CALLER opens a TURN grant (64 hex, fresh per call) on MY verified inbound */
  turnGrant(mbox: string, readCap: string, grant: string, ownCap?: string) {
    return this.invokeAnon('turnGrant', { mbox, read_cap: readCap, grant, ...(ownCap ? { own_cap: ownCap } : {}) }); // b77u (audit 6 W4)
  }

  /** b77n (audit VAR-04): the CALLEE approves the caller's grant on MY verified inbound (as the call rings) */
  turnApprove(mbox: string, readCap: string, grant: string, ownCap?: string) {
    return this.invokeAnon('turnApprove', { mbox, read_cap: readCap, grant, ...(ownCap ? { own_cap: ownCap } : {}) }); // b77u (audit 6 W4)
  }

  /** TURN credentials (the same answer as veilTurnCredentials) for a call grant the OTHER side of
   *  the chat approved, through MY inbound. b77n: 202 {pending: true} while it is not approved yet. */
  sealedTurn(mbox: string, readCap: string, grant: string, ownCap?: string) {
    return this.invokeAnon('sealedTurn', { mbox, read_cap: readCap, grant, ...(ownCap ? { own_cap: ownCap } : {}) }); // b77u (audit 6 W4)
  }

  /** a media blob for the PEER's inbound (send cap); no owner, no account. Returns the file uri. */
  async sealedUpload(source: { uri?: string; bytes?: Uint8Array; name?: string; mbox: string; sendCap: string }): Promise<string> {
    const fetchImpl = this.cfg.fetchImpl ?? fetch;
    assertUploadSize(source.bytes); // b77p (audit VAR-11)
    const name = source.name ?? 'veil-media';
    let cleanup: (() => void) | null = null;
    try {
      const form = new FormData();
      if (source.uri) {
        form.append('file', { uri: source.uri, name, type: 'application/octet-stream' } as unknown as Blob);
      } else if (source.bytes && this.cfg.bytesToTempFile) {
        const tmp = await this.cfg.bytesToTempFile(source.bytes, name);
        cleanup = tmp.cleanup;
        form.append('file', { uri: tmp.uri, name, type: 'application/octet-stream' } as unknown as Blob);
      } else if (source.bytes) {
        form.append('file', new Blob([source.bytes as unknown as BlobPart], { type: 'application/octet-stream' }), name);
      } else {
        throw new Error('sealedUpload: needs a uri or bytes');
      }
      form.append('mbox', source.mbox);
      form.append('send_cap', source.sendCap);
      // no Authorization, no cookies; the FormData sets its own multipart boundary
      // b77p (audit VAR-11): bounded — a relay that never answers can't hold the send for ever
      const { res, data } = await this.fetchJson(fetchImpl, `${this.cfg.baseUrl}/api/apps/${this.cfg.appId}/functions/sealedUpload`, {
        method: 'POST', credentials: 'omit', body: form as unknown as BodyInit,
        // b77s (audit 4 RS-2): name the mailbox up front, so the relay checks it before taking an upload slot and
        // gives the body its full deadline (an unnamed upload gets 90 s, too short for a large file on a slow link)
        headers: { 'X-Veil-Mbox': source.mbox, 'X-Veil-Send-Cap': source.sendCap },
      } as RequestInit, 'sealedUpload', this.uploadTimeoutMs());
      if (!res.ok) {
        throw relayErrorFor(res.status, data); // b77m (audit VAR-20)
      }
      const d = data as { file_uri?: string; data?: { file_uri?: string } } | null;
      const uri = d?.file_uri ?? d?.data?.file_uri;
      if (!uri) throw new Error('upload returned no file_uri');
      return uri;
    } finally {
      cleanup?.();
    }
  }

  /** a sealed blob: op 'url' → this relay's signed download link; op 'delete' → removed.
   *  cap = the receiver's read cap (its inbound) or the uploader's send cap (the peer's inbound). */
  async sealedFile(mbox: string, cap: string, uri: string, op: 'url' | 'delete'): Promise<string | null> {
    const r = await this.invokeAnon('sealedFile', { mbox, cap, uri, op });
    if (op === 'delete') return null;
    const d = r.data as { signed_url?: string; data?: { signed_url?: string } } | null;
    const url = d?.signed_url ?? d?.data?.signed_url;
    if (!url) throw new Error('Signed URL unavailable');
    return this.assertSignedUrl(url); // b74 (audit VAR-20)
  }

  // ---------- entity REST (client-created records, same auth scope as the web SDK) ----------

  /**
   * Entity REST LIST — the exact receive channel the web client uses
   * (S.entities.VeilEnvelope.filter(...)). GET /entities/{entity} with the
   * filter as a bare query param, sort, limit.
   */
  async entityList(entity: string, params: Record<string, string | number>): Promise<unknown> {
    const fetchImpl = this.cfg.fetchImpl ?? fetch;
    const qs = new URLSearchParams();
    for (const [k, v] of Object.entries(params)) qs.set(k, String(v));
    const token = await this.cfg.getToken();
    // b77p (audit VAR-11): bounded like every function call (RELAY_TIMEOUT_MS)
    const { res, data } = await this.fetchJson(fetchImpl, `${this.cfg.baseUrl}/api/apps/${this.cfg.appId}/entities/${entity}?${qs.toString()}`, {
      method: 'GET',
      headers: { ...(token ? { Authorization: `Bearer ${token}` } : {}) },
    }, 'entities', this.cfg.timeoutMs ?? RELAY_TIMEOUT_MS, undefined, this.jsonXhr());
    if (!res.ok) {
      throw relayErrorFor(res.status, data); // b77m (audit VAR-20): app-written text only
    }
    return data;
  }

  async entityCreate(entity: string, record: Record<string, unknown>): Promise<unknown> {
    const fetchImpl = this.cfg.fetchImpl ?? fetch;
    const token = await this.cfg.getToken();
    // b77p (audit VAR-11): bounded like every function call (RELAY_TIMEOUT_MS)
    const { res, data } = await this.fetchJson(fetchImpl, `${this.cfg.baseUrl}/api/apps/${this.cfg.appId}/entities/${entity}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}) },
      body: JSON.stringify(record),
    }, 'entities', this.cfg.timeoutMs ?? RELAY_TIMEOUT_MS, undefined, this.jsonXhr());
    if (!res.ok) {
      throw relayErrorFor(res.status, data); // b77m (audit VAR-20): app-written text only
    }
    return data;
  }

  /**
   * SDK contract (base44Client-BZUbQGvX.js): update(t,n){return e.put(`${i}/${t}`,n)}
   * -> PUT /api/apps/{app}/entities/{entity}/{id} with the record body.
   */
  async entityUpdate(entity: string, id: string, patch: Record<string, unknown>): Promise<unknown> {
    const fetchImpl = this.cfg.fetchImpl ?? fetch;
    const token = await this.cfg.getToken();
    // b77p (audit VAR-11): bounded like every function call (RELAY_TIMEOUT_MS)
    const { res, data } = await this.fetchJson(fetchImpl, `${this.cfg.baseUrl}/api/apps/${this.cfg.appId}/entities/${entity}/${id}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}) },
      body: JSON.stringify(patch),
    }, 'entities', this.cfg.timeoutMs ?? RELAY_TIMEOUT_MS, undefined, this.jsonXhr());
    if (!res.ok) {
      throw relayErrorFor(res.status, data); // b77m (audit VAR-20): app-written text only
    }
    return data;
  }

  /**
   * SDK contract: async delete(t){return e.delete(`${i}/${t}`)}
   * -> DELETE /api/apps/{app}/entities/{entity}/{id}.
   */
  async entityDelete(entity: string, id: string, opts: { wipe?: boolean } = {}): Promise<unknown> {
    const fetchImpl = this.cfg.fetchImpl ?? fetch;
    const token = await this.cfg.getToken();
    // b77u2 (Info): a wipe's per-row deletes use the relay's wipe bucket (?wipe=1), not the 120-a-minute one
    const q = opts.wipe ? '?wipe=1' : '';
    // b77p (audit VAR-11): bounded like every function call (RELAY_TIMEOUT_MS)
    const { res, data } = await this.fetchJson(fetchImpl, `${this.cfg.baseUrl}/api/apps/${this.cfg.appId}/entities/${entity}/${id}${q}`, {
      method: 'DELETE',
      headers: { ...(token ? { Authorization: `Bearer ${token}` } : {}) },
    }, 'entities', this.cfg.timeoutMs ?? RELAY_TIMEOUT_MS, undefined, this.jsonXhr());
    if (!res.ok) {
      throw relayErrorFor(res.status, data); // b77m (audit VAR-20): app-written text only
    }
    return data;
  }

  // ---------- identity gate (public keys only — never private material) ----------

  identityRegister(material: { veil_id: string; IK_pub: string; SPK_pub: string; SPK_sig: string; pq_pub: string; pq_sig: string }) {
    return this.invoke('veilIdentityGate', { action: 'register', ...material });
  }

  async identityChallenge(veilId: string): Promise<string> {
    const r = await this.invoke('veilIdentityGate', { action: 'challenge', veil_id: veilId });
    const nonce = (r.data as { data?: { nonce?: string } })?.data?.nonce ?? (r.data as { nonce?: string })?.nonce;
    if (!nonce) throw new Error('identity gate returned no nonce');
    return nonce;
  }

  /** b77u (audit 6 R4 #28): `addProof` — the account's PRIMARY identity approves binding a second identity to the
   *  account: its signature over `vardum-add-identity-v1:<userId>:<veil_id>:<nonce>` (this bind's nonce). The relay
   *  refuses a second identity without it (403 code add_identity_proof). */
  /** b77u2 (UC-L4): `currentPassword` — on an account with no primary identity, the account's current password makes
   *  a primary (the oldest identity already bound, or this one when none is); without it such an account can't add an
   *  identity beside a bound one (403 code current_password_required). */
  identityBind(veilId: string, nonce: string, signature: string, addProof?: { veilId: string; sig: string }, currentPassword?: string) {
    return this.invoke('veilIdentityGate', { action: 'bind', veil_id: veilId, nonce, signature, ...(addProof ? { add_proof: { veil_id: addProof.veilId, sig: addProof.sig } } : {}), ...(currentPassword ? { current_password: currentPassword } : {}) });
  }

  /** b76 (one-time prekeys): `claimOpk` asks the relay to hand out (and delete) one of the peer's
   *  one-time prekey pairs with the bundle — only when starting a contact chat; every other
   *  lookup leaves them alone. `requesterVeilId` is my own Vardum ID (the relay hands one-time
   *  keys only to accounts with a bound identity, and rate-limits per requester and target). */
  identityLookup(veilId: string, opts?: { claimOpk?: boolean; requesterVeilId?: string }) {
    if (opts?.claimOpk) return this.claimOpkLookup(veilId, opts.requesterVeilId ?? '');
    return this.invoke('veilIdentityGate', { action: 'lookup', veil_id: veilId });
  }

  /** b77q (audit 3 AQ-1): the same published bundle with NO login (invokeAnon: no Authorization header, no
   *  cookies), for the key-change sweep, so a pass no longer hands the relay the contact list under the account.
   *  An ID with no bound identity answers 200 `{ found: false }`. Never a one-time prekey (claimOpk stays signed in). */
  identityLookupAnon(veilId: string) {
    return this.invokeAnon('veilKeyLookup', { veil_id: veilId });
  }

  /** b77m (owner, carrier NAT): past a per-network one-time-key cap the relay still answers with the signed
   *  prekeys (opk: null) plus the network puzzle (opk_status 'pow_required'). Solved once and asked again; if
   *  the puzzle is out of bounds or the second answer has no pair, the last-resort answer stands (as before). */
  private async claimOpkLookup(veilId: string, requester: string): Promise<{ data: unknown; status: number }> {
    const ask = (extra: Record<string, string>) => this.invoke('veilIdentityGate', { action: 'lookup', veil_id: veilId, claim_opk: true, requester_veil_id: requester, ...extra });
    const first = await ask({});
    const d = first.data as { opk_status?: string; pow_challenge?: string; pow_bits?: number; pow_prefix?: string } | null;
    if (d?.opk_status !== 'pow_required' || !d.pow_challenge || !d.pow_bits) return first;
    const prefix = d.pow_prefix ?? 'vardum-login-pow-v1:';
    if (!loginPowAcceptable(prefix, d.pow_challenge, d.pow_bits)) return first;
    try {
      return await ask({ pow_challenge: d.pow_challenge, pow_solution: await solveLoginPow(prefix, d.pow_challenge, d.pow_bits) });
    } catch { return first; }
  }

  /** b76 (one-time prekeys): publish signed one-time prekey pairs (public halves only). `device`
   *  is this phone's one-time-key tag; an upload from another tag (a new phone, a restore)
   *  replaces the whole pool, as does `replace`. Answers { count } — the pairs now held. */
  opkUpload(veilId: string, device: string, opks: { id: string; x_pub: string; pq_pub: string; sig: string }[], replace = false) {
    return this.invoke('veilIdentityGate', { action: 'opk_upload', veil_id: veilId, device, opks, replace });
  }

  /** b76 (one-time prekeys): how many of my one-time pairs the relay still holds, and whether this
   *  phone (`device`) is the one whose pairs they are */
  opkCount(veilId: string, device: string) {
    return this.invoke('veilIdentityGate', { action: 'opk_count', veil_id: veilId, device });
  }

  /** b76r2 (one-time prekeys, audit PK-01): empty the relay's pool of my one-time pairs (the
   *  Nothing-at-Rest close destroys their private halves). Answers { dropped, count: 0 }. */
  opkDrop(veilId: string) {
    return this.invoke('veilIdentityGate', { action: 'opk_drop', veil_id: veilId });
  }

  // ---------- session gate ----------

  sessionActivate(token: string, writeSecret: string | null) {
    return this.invoke('veilSessionGate', { action: 'activate', token, write_secret: writeSecret });
  }

  sessionJoin(join: {
    token: string;
    write_secret: string | null;
    client_id: string;
    /** b71 (review): no longer sent; older relays accept the join without it */
    display_name?: string;
    responder_pub_jwk: string;
    responder_ratchet_pub_jwk: string;
    responder_pq_ct: string;
    fingerprint: string;
    /** Batch C (V-16): replace the link's responder credential at join */
    new_responder_write_hash?: string;
    /** b77p (audit 2 VAR-01): my blinded open token and the key it is blinded for; the answer carries open_sig */
    open_blind?: string;
    open_kid?: string;
  }, opts?: { /** b77: a 1:1 join needs no login and no client id — sent anonymously */ anon?: boolean }) {
    if (opts?.anon) {
      const { client_id: _noAccount, ...rest } = join;
      void _noAccount;
      return this.invokeAnon('veilSessionGate', { action: 'join', ...rest });
    }
    return this.invoke('veilSessionGate', { action: 'join', ...join });
  }

  /** b77 (sealed sender): the no-login gate action the initiator polls instead of list — the
   *  responder's handshake fields for this one rendezvous token */
  sessionStatus(token: string, writeSecret: string | null) {
    return this.invokeAnon('veilSessionGate', { action: 'status', token, write_secret: writeSecret });
  }

  /** b77: the no-login gate `end` (write secret only) — the initiator retires its rendezvous row
   *  after opening its inbound, without naming its account next to that moment */
  sessionEndAnon(token: string, writeSecret: string | null) {
    return this.invokeAnon('veilSessionGate', { action: 'end', token, write_secret: writeSecret });
  }

  /** b77: the no-login gate `peek` for a 1:1 invite (responder write secret only) */
  sessionPeekAnon(token: string, writeSecret: string | null) {
    return this.invokeAnon('veilSessionGate', { action: 'peek', token, write_secret: writeSecret });
  }

  /** Batch F (round-4 reviews R4-3-02 / R4-4-21): rows that only name the caller
   *  (contact requests, restore matches) come in pages of 100; follow
   *  naming_next_cursor (at most 10 more pages) and return one merged list. */
  async sessionList(clientId: string, veilId?: string) {
    const first = await this.invoke('veilSessionGate', { action: 'list', client_id: clientId, ...(veilId ? { veil_id: veilId } : {}) });
    const d = first.data as { sessions?: unknown[]; naming_next_cursor?: string | null } | null;
    let next = d?.naming_next_cursor ?? null;
    if (!next || !Array.isArray(d?.sessions)) return first;
    const merged = [...(d!.sessions as unknown[])];
    for (let guard = 0; next && guard < 10; guard++) {
      const pg = await this.invoke('veilSessionGate', { action: 'list', client_id: clientId, ...(veilId ? { veil_id: veilId } : {}), naming_cursor: next });
      const pd = pg.data as { sessions?: unknown[]; naming_next_cursor?: string | null } | null;
      if (Array.isArray(pd?.sessions)) merged.push(...pd!.sessions);
      next = pd?.naming_next_cursor ?? null;
    }
    return { data: { ...d, sessions: merged, naming_next_cursor: null }, status: first.status };
  }

  sessionPeek(token: string, writeSecret: string | null) {
    return this.invoke('veilSessionGate', { action: 'peek', token, write_secret: writeSecret });
  }

  sessionHeartbeat(token: string, writeSecret: string | null) {
    return this.invoke('veilSessionGate', { action: 'heartbeat', token, write_secret: writeSecret });
  }

  sessionBump(token: string, writeSecret: string | null) {
    return this.invoke('veilSessionGate', { action: 'bump', token, write_secret: writeSecret });
  }

  sessionVerify(token: string, writeSecret: string | null) {
    return this.invoke('veilSessionGate', { action: 'verify', token, write_secret: writeSecret });
  }

  /**
   * b85 LOCKED-SCREEN DELIVERY: ask the relay to push a "New message" ALERT to
   * the session's other participant(s). The gate verifies write_secret first
   * (so only a session participant can trigger it) and the push carries ZERO
   * content — same generic-banner threat model as the local post-decrypt
   * banner, but delivered BY THE SERVER at send time, so it lands on the lock
   * screen instantly even when the app is suspended/JS can't run and the
   * session can't even be joined yet (pending one-taps). Cover traffic NEVER
   * calls this (sendCoverEnvelope must not), so decoys stay silent. Until the
   * gate action exists server-side this 400s — notifySent() swallows that
   * gracefully and logs once.
   */
  sessionNotify(token: string, writeSecret: string | null) {
    return this.invoke('veilSessionGate', { action: 'notify', token, write_secret: writeSecret });
  }

  /** b197-r8i: burn-priority hold — while burn deletions are pending, AMBIENT
   *  traffic (heartbeats, cover sends — the callers that consult gateHot)
   *  yields the per-account limiter budget to the privacy-critical deletes.
   *  Root cause it fixes: under saturation, burns starved behind 7s
   *  heartbeats + cover + re-fetches, exhausted their 20-attempt budget, and
   *  envelopes the product calls "burnt" stayed on the relay (K-22). */
  holdAmbientFor(ms: number) {
    this.gateHotUntil = Math.max(this.gateHotUntil, Date.now() + ms);
  }

  /** SPEC §4: burn-after-open — destroy an envelope after this receiver read it. */
  sessionBurn(token: string, writeSecret: string | null, envelopeId: string) {
    return this.invoke('veilSessionGate', { action: 'burn', token, write_secret: writeSecret, envelope_id: envelopeId });
  }

  /** b64: bulk duress purge — service-role delete of EVERY session (and its
   *  envelopes) this client participates in, including peer-created rows the
   *  user-scoped entity API can never reach under RLS. Falls back (caller) to
   *  the per-thread end/delete loop until the gate action is deployed. */
  /** b74 (audit VAR-12): the relay refuses a purge without the account's primary identity's
   *  proof (purgeProofMessage, signed by that identity; ts within 10 minutes) — the same
   *  rule as an account delete. A bearer token alone used to be enough. */
  sessionPurge(clientId: string, proof?: PurgeProof) {
    return this.invoke('veilSessionGate', { action: 'purge', client_id: clientId, ...(proof ? { proof } : {}) });
  }

  // b65: client_id is PARTICIPATION PROOF — the relay (once the gate update
  // deploys) accepts it as an alternative to write_secret, which only the
  // initiator ever has. This is what lets the invited party end peer-created
  // threads (and what duress uses to kill them server-side).
  sessionEnd(token: string, writeSecret: string | null, clientId?: string) {
    return this.invoke('veilSessionGate', {
      action: 'end', token, write_secret: writeSecret,
      ...(clientId ? { client_id: clientId } : {}),
    });
  }

  /**
   * PRIMARY receive channel — the web client polls the VeilEnvelope ENTITY
   * (S.entities.VeilEnvelope.filter({session_token}, 'created_date', 200));
   * it NEVER calls a gate 'fetch' action. Polled oldest-first (ascending
   * created_date), 200 records, expiry checked client-side.
   */
  /** b198 MEDIA DELETION: the blob id exists only inside the E2E media payload,
   * so presenting it (authenticated) is the deletion capability. Idempotent on
   * the relay — an already-gone blob is {ok:true}. */
  /** b70 (audit VAR-06): `chat` scopes the delete to that chat's own files
   *  (the relay refuses any file not bound to it, e.g. the caller's vaults) */
  async deleteBlob(fileUri: string, chat?: { sessionToken: string; writeSecret: string | null }): Promise<unknown> {
    const fetchImpl = this.cfg.fetchImpl ?? fetch;
    const token = await this.cfg.getToken();
    // b77s (audit 4 A-01 / A-03): no cookies, a bounded answer, and (like every other call) a timeout
    const { res, data } = await this.fetchJson(fetchImpl, `${this.cfg.baseUrl}/api/apps/${this.cfg.appId}/integration-endpoints/Core/DeletePrivateFile`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}) },
      body: JSON.stringify({ file_uri: fileUri, ...(chat ? { session_token: chat.sessionToken, write_secret: chat.writeSecret } : {}) }),
    }, 'DeletePrivateFile', this.cfg.timeoutMs ?? RELAY_TIMEOUT_MS, undefined, this.jsonXhr());
    if (!res.ok) {
      throw relayErrorFor(res.status, data); // b77m (audit VAR-20): app-written text only
    }
    return data;
  }

  envelopeList(token: string, skip = 0): Promise<unknown> {
    return this.entityList('VeilEnvelope', {
      session_token: token,
      sort: 'created_date',
      limit: 200,
      // b87: pagination cursor — see SessionStore.syncSkip. Omit when 0 so
      // this stays byte-for-byte the original web-parity call in the
      // common (small-session) case.
      ...(skip > 0 ? { skip } : {}),
    });
  }

  /** LEGACY fallback: gate fetch action (unused by web; may not exist server-side). */
  envelopeFetch(token: string, writeSecret: string | null) {
    return this.invoke('veilSessionGate', { action: 'fetch', token, write_secret: writeSecret });
  }

  // ---------- encrypted media blobs (web's image flow, extracted Sept 19 2026) ----------

  /**
   * Private blob upload — the web SDK contract
   * S.integrations.Core.UploadPrivateFile({file}) → {file_uri}, i.e.
   *   POST /api/apps/{appId}/integration-endpoints/Core/UploadPrivateFile
   * with the ciphertext as a multipart "file" part named veil-media
   * (type application/octet-stream). Plaintext never leaves the device.
   */
  /** b70 (audit VAR-06): `chat` binds a media upload to its chat on the relay */
  async uploadPrivateFile(source: { uri?: string; bytes?: Uint8Array; name?: string; chat?: { sessionToken: string; writeSecret: string | null } }): Promise<string> {
    const fetchImpl = this.cfg.fetchImpl ?? fetch;
    assertUploadSize(source.bytes); // b77p (audit VAR-11)
    const token = await this.cfg.getToken();
    const name = source.name ?? 'veil-media';
    let cleanup: (() => void) | null = null;
    try {
      const form = new FormData();
      if (source.uri) {
        // RN path: the OS fetch understands {uri,name,type} file parts
        form.append('file', { uri: source.uri, name, type: 'application/octet-stream' } as unknown as Blob);
      } else if (source.bytes && this.cfg.bytesToTempFile) {
        // RN bytes path: route through a real file — Blob-from-bytes is broken on-device
        const tmp = await this.cfg.bytesToTempFile(source.bytes, name);
        cleanup = tmp.cleanup;
        form.append('file', { uri: tmp.uri, name, type: 'application/octet-stream' } as unknown as Blob);
      } else if (source.bytes) {
        // Node/test path: Blob(ArrayBufferView) works fine off-device
        form.append('file', new Blob([source.bytes as unknown as BlobPart], { type: 'application/octet-stream' }), name);
      } else {
        throw new Error('uploadPrivateFile: needs a uri or bytes');
      }
      if (source.chat) {
        form.append('session_token', source.chat.sessionToken);
        form.append('write_secret', source.chat.writeSecret ?? '');
      }
      const { res, data } = await this.fetchJson(fetchImpl, `${this.cfg.baseUrl}/api/apps/${this.cfg.appId}/integration-endpoints/Core/UploadPrivateFile`, {
        method: 'POST',
        // no Content-Type header — the FormData sets its own multipart boundary
        ...(token ? { headers: { Authorization: `Bearer ${token}` } } : {}),
        body: form as unknown as BodyInit,
      }, 'UploadPrivateFile', this.uploadTimeoutMs()); // b77p (audit VAR-11): bounded
      if (!res.ok) {
        throw relayErrorFor(res.status, data); // b77m (audit VAR-20): app-written text only
      }
      const d = data as { file_uri?: string; data?: { file_uri?: string } } | null;
      const uri = d?.file_uri ?? d?.data?.file_uri;
      if (!uri) throw new Error('upload returned no file_uri');
      return uri;
    } finally {
      cleanup?.();
    }
  }

  /**
   * Signed download URL for a stored blob — the web contract
   * C.functions.invoke('vaultFileSignedUrl', {file_uri, session_token,
   * write_secret}) → {signed_url} (accepts the .data-wrapped form too).
   */
  async vaultFileSignedUrl(fileUri: string, sessionToken: string, writeSecret: string | null): Promise<string> {
    const r = await this.invoke('vaultFileSignedUrl', {
      file_uri: fileUri,
      session_token: sessionToken,
      write_secret: writeSecret,
    });
    const d = r.data as { signed_url?: string; data?: { signed_url?: string } } | null;
    const url = d?.signed_url ?? d?.data?.signed_url;
    if (!url) throw new Error('Signed URL unavailable');
    return this.assertSignedUrl(url); // b74 (audit VAR-20)
  }

  /**
   * Vaults: web p.functions.invoke('vaultFileSignedUrl', {file_uri}) — no
   * session context (the vault unlock path). Same response shapes.
   */
  async vaultContainerSignedUrl(fileUri: string): Promise<string> {
    const r = await this.invoke('vaultFileSignedUrl', { file_uri: fileUri });
    const d = r.data as { signed_url?: string; data?: { signed_url?: string } } | null;
    const url = d?.signed_url ?? d?.data?.signed_url;
    if (!url) throw new Error('Signed URL unavailable');
    return this.assertSignedUrl(url); // b74 (audit VAR-20)
  }

  /** Fetch raw bytes from a (pre-signed, unauthenticated) URL. */
  /** b77p (audit VAR-11): bounded — the answer must start within `connectMs`, keep coming (no gap longer than
   *  `idleMs`), finish within `totalMs` (MEDIA_FETCH_LIMITS / cfg.mediaLimits), and be at most `maxBytes` (default
   *  the relay's 25 MiB file cap: a padded media blob or a vault container is never larger). A Content-Length over
   *  the cap is refused before the body is read; a body that runs past it is aborted mid-stream. */
  async fetchBytes(url: string, opts: { maxBytes?: number } = {}): Promise<Uint8Array> {
    const fetchImpl = this.cfg.fetchImpl ?? fetch;
    const t = { ...MEDIA_FETCH_LIMITS, ...(this.cfg.mediaLimits ?? {}) };
    // b77q (audit 3 DV-2): where fetch doesn't stream (React Native), XMLHttpRequest, which can abort past the cap
    const streams = this.cfg.fetchStreams ?? fetchStreams();
    const platformXhr = (globalThis as { XMLHttpRequest?: unknown }).XMLHttpRequest;
    const xhr = this.cfg.xhrImpl !== undefined ? this.cfg.xhrImpl
      : (!this.cfg.fetchImpl && typeof platformXhr === 'function' ? platformXhr as XhrCtor : null);
    if (xhr && !streams) return xhrBytesBounded(xhr, this.assertSignedUrl(url), { maxBytes: opts.maxBytes ?? RELAY_FILE_CAP_BYTES, totalMs: t.totalMs });
    return fetchBytesBounded(fetchImpl, this.assertSignedUrl(url), {}, { // b74 (audit VAR-20): this relay's file links only
      maxBytes: opts.maxBytes ?? RELAY_FILE_CAP_BYTES, connectMs: t.connectMs, idleMs: t.idleMs, totalMs: t.totalMs,
      streams: this.cfg.fetchStreams, // b77p round 2 (review M2): unset = detected
    });
  }

  // ---------- envelope submission (its own function, NOT a gate action) ----------

  /** b77: GROUP envelopes only. A 1:1 envelope goes through sealedSubmit; one without a group
   *  token is refused here, before anything leaves the phone. */
  async submitEnvelope(sub: EnvelopeSubmission): Promise<{ data: unknown; status: number }> {
    if (!sub.group_token) throw new Error('1:1 envelopes go through sealedSubmit (b77 sealed sender).');
    const payload = {
      session_token: sub.session_token,
      write_secret: sub.write_secret,
      ...(sub.sender_client_id ? { sender_client_id: sub.sender_client_id } : {}),
      ciphertext: sub.ciphertext,
      iv: sub.iv,
      header: sub.header,
      byte_length: sub.byte_length,
      expires_at: new Date(Date.now() + sub.ttl_seconds * 1000).toISOString(),
      ttl_seconds: sub.ttl_seconds,
      delivery_state: 'accepted',
      protocol_version: sub.protocolVersion ?? RATCHET_PROTOCOL,
      ...(sub.group_token ? { group_token: sub.group_token } : {}),
    };
    return this.invoke('submitEnvelope', payload);
  }

  // ---------- account: sign out other devices, change password (b77s owner decision) ----------

  /** b77s (owner decision): ends every other login of this account on the relay (this phone's stays).
   *  Authenticated `accountSignOutOthers` {} → {ok, signed_out}. Returns how many were signed out. */
  /** b77t (audit 5 L-6): the relay now needs a FRESH credential — `cred.password` (the account's password) or
   *  `cred.signer` with `cred.userId` (the primary identity signs "vardum-signout-others-v1" with a relay nonce) — and
   *  revokes every token, this phone's too, answering with a new one, which is stored (cfg.setToken) before this
   *  returns. Without a credential the relay refuses (403). */
  async signOutOtherDevices(cred: { password?: string; signer?: PrimarySigner; userId?: string } = {}): Promise<number> {
    const payload: Record<string, unknown> = {};
    if (cred.password) payload.password = cred.password;
    else if (cred.signer && cred.userId) {
      const nonce = await fetchProofNonce(this, 'vardum-signout-others-v1');
      if (!nonce) throw new Error('The server did not answer. Your other devices are still signed in. Try again.');
      const ts = Date.now();
      payload.proof = { veil_id: cred.signer.veilId, ts, nonce, sig: await cred.signer.sign(btoa(proofMessage('vardum-signout-others-v1', cred.userId, ts, nonce))) };
    }
    const r = await this.invoke('accountSignOutOthers', payload);
    const d = r.data as { ok?: unknown; signed_out?: unknown; access_token?: unknown } | null;
    if (!d || d.ok !== true) throw new Error('The server did not confirm that your other devices were signed out. Try again.');
    await this.adoptRotatedToken(d.access_token);
    const n = Number(d.signed_out);
    return Number.isFinite(n) && n > 0 ? Math.floor(n) : 0;
  }

  /** b77t (audit 5 L-6): the relay revoked this phone's token too and sent a new one: keep it. An older relay sends
   *  none (and kept the old token): nothing to do. */
  private async adoptRotatedToken(token: unknown): Promise<void> {
    if (token === undefined || token === null) return;
    if (typeof token !== 'string' || !token) throw new Error('The server sent no usable sign-in. Sign in again on this phone.');
    if (!this.cfg.setToken) throw new Error('This phone could not keep its new sign-in. Sign in again on this phone.');
    await this.cfg.setToken(token);
  }

  /** b77s (owner decision): changes an email account's password. Authenticated `accountChangePassword`
   *  {old_password, new_password} → {ok, signed_out} (the relay signs the account's other logins out).
   *  The relay's codes wrong_password (401), weak_password (400) and not_email_account (400) become
   *  plain sentences; the RelayError (status, code) is kept. Returns how many other logins were signed out. */
  async changePassword(oldPassword: string, newPassword: string): Promise<number> {
    if (typeof oldPassword !== 'string' || typeof newPassword !== 'string' || !oldPassword || !newPassword) {
      throw new Error('Enter your current password and a new one.');
    }
    let r: { data: unknown; status: number };
    try {
      r = await this.invoke('accountChangePassword', { old_password: oldPassword, new_password: newPassword });
    } catch (e) {
      const err = e as { status?: unknown; code?: unknown; data?: unknown; message?: unknown };
      const body = (err && typeof err === 'object' && err.data && typeof err.data === 'object' ? err.data : {}) as { code?: unknown; error?: unknown };
      const code = [err?.code, body.code, body.error].find((c) => c === 'wrong_password' || c === 'weak_password' || c === 'not_email_account');
      const text = code === 'wrong_password' ? 'Your current password is not right. Nothing was changed.'
        : code === 'weak_password' ? 'The server refused the new password as too weak. Choose a longer one. Nothing was changed.'
          : code === 'not_email_account' ? 'This account has no email password to change (it signs in with your 24 words). Nothing was changed.'
            : null;
      if (text && err && typeof err === 'object') {
        try { (err as { message: string }).message = text; } catch { /* frozen: rethrown as it is */ }
        try { if (!err.code) (err as { code?: string }).code = code as string; } catch { /* read-only */ }
      }
      throw e;
    }
    const d = r.data as { ok?: unknown; signed_out?: unknown; access_token?: unknown } | null;
    if (!d || d.ok !== true) throw new Error('The server did not confirm the password change. Your old password may still be in use.');
    await this.adoptRotatedToken(d.access_token); // b77t (audit 5 L-6): this phone's token was revoked too
    const n = Number(d.signed_out);
    return Number.isFinite(n) && n > 0 ? Math.floor(n) : 0;
  }
}

// ---------- b77t (audit 5 L-5, IH C-08): the pre-authorised duress purge ----------

/**
 * Mints the account's duress PURGE TOKEN (signed in, while the primary identity is in memory): the identity signs
 * "vardum-purge-token-v1:<userId>:<ts>:<nonce>" with a relay nonce, and the relay answers a 64-hex token it keeps only
 * as a hash. One per account: a new mint replaces the old token. The caller stores the token ON THE DEVICE where a
 * duress wipe can still read it when the identity is not in memory (e.g. under Nothing at Rest), and mints again
 * after each use or after the account's identity changes. Returns the token. Throws when the relay refuses or
 * doesn't issue nonces.
 */
export async function mintDuressPurgeToken(relay: VeilRelay, signer: PrimarySigner, userId: string): Promise<string> {
  const nonce = await fetchProofNonce(relay, 'vardum-purge-token-v1');
  if (!nonce) throw new Error('The relay did not set up the emergency wipe. Try again later.');
  const ts = Date.now();
  const sig = await signer.sign(btoa(proofMessage('vardum-purge-token-v1', userId, ts, nonce)));
  const r = await relay.invoke('veilPurgeToken', { action: 'mint', proof: { veil_id: signer.veilId, ts, nonce, sig } });
  const d = r.data as { purge_token?: unknown; data?: { purge_token?: unknown } } | null;
  const tok = d?.purge_token ?? d?.data?.purge_token;
  if (typeof tok !== 'string' || !/^[0-9a-f]{64}$/.test(tok)) throw new Error('The relay did not set up the emergency wipe. Try again later.');
  return tok;
}

/**
 * Revokes the account's duress purge token (signed in). Best effort is the caller's choice; this throws on refusal.
 * b77t2 (CL-3): the relay no longer revokes on the bearer token alone (a stolen token copy could silently disarm the
 * duress purge). The caller proves one of:
 *   - `purgeToken`: the stored purge token itself (the relay checks it is the account's current one; 403 otherwise);
 *   - `signer` + `userId`: the primary identity's nonce proof (label 'vardum-purge-token-v1', as mint).
 * The token is used when both are given. With neither it throws at once, sending nothing.
 *
 *   revokeDuressPurgeToken(relay: VeilRelay, cred?: { purgeToken?: string | null; signer?: PrimarySigner | null; userId?: string | null }): Promise<void>
 */
export async function revokeDuressPurgeToken(relay: VeilRelay, cred: { purgeToken?: string | null; signer?: PrimarySigner | null; userId?: string | null } = {}): Promise<void> {
  if (typeof cred.purgeToken === 'string' && /^[0-9a-f]{64}$/.test(cred.purgeToken)) {
    await relay.invoke('veilPurgeToken', { action: 'revoke', purge_token: cred.purgeToken });
    return;
  }
  if (cred.signer && cred.userId) {
    const nonce = await fetchProofNonce(relay, 'vardum-purge-token-v1');
    if (!nonce) throw new Error('The relay did not turn off the emergency wipe. Try again later.');
    const ts = Date.now();
    const sig = await cred.signer.sign(btoa(proofMessage('vardum-purge-token-v1', cred.userId, ts, nonce)));
    await relay.invoke('veilPurgeToken', { action: 'revoke', proof: { veil_id: cred.signer.veilId, ts, nonce, sig } });
    return;
  }
  throw new Error('Turning off the emergency wipe needs this phone’s purge token or its Vardum ID.');
}

/**
 * The duress purge with a stored purge token — NO login and NO identity needed (`veilDuressPurge {purge_token}`,
 * sent with no Authorization header). The relay checks the token, makes it unusable (single use), and deletes the
 * account's relay identity records, chats, group memberships and owned groups, transfer links, registration lock,
 * and every vault (with its file) and note. The account itself stays.
 *
 *   duressPurgeWithToken(relay: VeilRelay, purgeToken: string): Promise<{ ok: boolean; status: number; deleted: Record<string, unknown> | null }>
 *
 * Never throws: ok false on any failure (offline, an unknown or used token: 403, a malformed token: no request at
 * all). `deleted` holds the relay's counts (sessions, envelopes, identities, transfer_links, groups, reglock, vaults,
 * notes) when ok. The caller should delete its stored token afterwards whatever the result (a used token is dead).
 */
export async function duressPurgeWithToken(relay: VeilRelay, purgeToken: string): Promise<{ ok: boolean; status: number; deleted: Record<string, unknown> | null }> {
  if (typeof purgeToken !== 'string' || !/^[0-9a-f]{64}$/.test(purgeToken)) return { ok: false, status: 0, deleted: null };
  try {
    const r = await relay.invokeAnon('veilDuressPurge', { purge_token: purgeToken });
    const d = r.data as { ok?: unknown; deleted?: unknown; data?: { ok?: unknown; deleted?: unknown } } | null;
    const ok = (d?.ok ?? d?.data?.ok) === true;
    const del = (d?.deleted ?? d?.data?.deleted) as Record<string, unknown> | null | undefined;
    return { ok, status: r.status, deleted: ok && del && typeof del === 'object' ? del : null };
  } catch (e) {
    const st = Number((e as { status?: unknown })?.status);
    return { ok: false, status: Number.isFinite(st) ? st : 0, deleted: null };
  }
}
