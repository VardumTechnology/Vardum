/**
 * b77s (audit 4 A-01 / A-03): how a JSON answer from the relay is read.
 *
 * A-03: `res.json()` buffered and parsed whatever the relay sent, however large. Every relay call now has a byte
 * limit (RELAY_JSON_MAX_BYTES by default; a route that legitimately returns more names its own): a Content-Length
 * over it is refused before the body is read; a streamed body (res.body.getReader) is counted chunk by chunk and
 * cancelled the moment it passes the limit; where fetch can't stream (React Native: the answer arrives whole),
 * res.text() is read only after the Content-Length check and its UTF-8 size is counted before anything is parsed.
 * Oversized data is never parsed (RelayResponseTooLargeError).
 *
 * A-01: React Native's fetch (whatwg-fetch) defaults to credentials 'same-origin', which its XMLHttpRequest turns
 * into withCredentials = true, so the platform cookie jar rode along with relay calls. Every relay request is made
 * with credentials 'omit' (the relay authenticates with bearer tokens and capabilities, never cookies).
 */

/** b77s (audit 4 A-03): the default limit on one JSON answer from the relay (1 MiB) */
export const RELAY_JSON_MAX_BYTES = 1024 * 1024;

/** b77s (audit 4 A-03): routes that legitimately answer with more than the default. Worked out from the relay's
 *  own caps (relay/main.ts): an entity list page is up to 200 rows of at most 48 KB (VeilEnvelope pages: 200 x
 *  ~56 KB with the JSON around it, ~11 MiB); sealedFetch returns up to 100 envelopes of at most 56 KB (~5.5 MiB);
 *  veilSessionGate list has no row limit (rows of at most 24 KB); veilGroupGate rosters hold up to 100 members.
 *  b77s (audit 4 N-2): deviceLink `fetch` returns the whole encrypted move bundle inline ({"data":{"blob":"..."}}),
 *  and the relay deletes it before answering, so a refusal here loses the move. The bundle is an uploaded file of at
 *  most 25 MiB (the upload cap 26 MiB); 40 MiB covers it read as text and JSON-encoded (cap x 4/3 + overhead).
 *  veilSessionGate's unpaged list (the app does not page its own rows) covers 1500 group rows (the per-account
 *  cap) of up to 24 KB plus the naming page: 40 MiB as well. The other function routes answer with small,
 *  fixed-shape objects (tokens, keys, states, a 40 KB group key wrap at most) and keep the 1 MiB default. */
export const RELAY_JSON_ROUTE_MAX_BYTES: Readonly<Record<string, number>> = Object.freeze({
  entities: 16 * 1024 * 1024,
  sealedFetch: 8 * 1024 * 1024,
  veilSessionGate: 40 * 1024 * 1024,
  veilGroupGate: 4 * 1024 * 1024,
  deviceLink: 40 * 1024 * 1024,
});

/** b77s (audit 4 A-03): the limit for one route (a function name, or 'entities') */
export function relayJsonLimitFor(route: string): number {
  return Object.prototype.hasOwnProperty.call(RELAY_JSON_ROUTE_MAX_BYTES, route) ? RELAY_JSON_ROUTE_MAX_BYTES[route] : RELAY_JSON_MAX_BYTES;
}

/** b77s (audit 4 A-03): an answer from the relay over its byte limit — refused unparsed. status 0: transient
 *  (a sync pass ends with an error, a burn stays queued), like a timeout. */
export class RelayResponseTooLargeError extends Error {
  readonly status = 0;
  constructor(route: string, maxBytes: number) {
    super(`The relay's answer was larger than Vardum accepts (${route}, over ${Math.round(maxBytes / 1024)} KB) — refused.`);
    this.name = 'RelayResponseTooLargeError';
  }
}

/** UTF-8 size of a string (no TextEncoder needed: Hermes) */
export function utf8ByteLength(s: string): number {
  let n = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c < 0x80) n += 1;
    else if (c < 0x800) n += 2;
    else if (c >= 0xd800 && c <= 0xdbff && i + 1 < s.length && (s.charCodeAt(i + 1) & 0xfc00) === 0xdc00) { n += 4; i++; }
    else n += 3;
  }
  return n;
}

const parseOrNull = (t: string): unknown => { try { return JSON.parse(t); } catch { return null; } };

/**
 * b77s (audit 4 A-03): read a relay answer as JSON within `maxBytes`. Unparseable JSON gives null (as
 * `res.json().catch(() => null)` did); an answer over the limit throws RelayResponseTooLargeError and is never
 * parsed. `onTooLarge` aborts the request (the caller's AbortController).
 */
export async function readJsonBounded(res: Response, maxBytes: number, route: string, onTooLarge?: () => void): Promise<unknown> {
  const tooBig = (): never => { try { onTooLarge?.(); } catch { /* never throws */ } throw new RelayResponseTooLargeError(route, maxBytes); };
  const len = Number(res.headers?.get?.('content-length') ?? NaN);
  if (Number.isFinite(len) && len > maxBytes) {
    try { await (res.body as ReadableStream<Uint8Array> | null | undefined)?.cancel?.(); } catch { /* aborted already */ }
    tooBig();
  }
  const reader = (res.body as ReadableStream<Uint8Array> | null | undefined)?.getReader?.();
  if (reader && typeof TextDecoder === 'function') {
    const dec = new TextDecoder('utf-8');
    let total = 0;
    let text = '';
    for (;;) {
      const step = await reader.read();
      if (step.done) break;
      total += step.value.length;
      if (total > maxBytes) {
        try { await reader.cancel(); } catch { /* aborted already */ }
        tooBig();
      }
      text += dec.decode(step.value, { stream: true });
    }
    text += dec.decode();
    return parseOrNull(text);
  }
  if (typeof res.text === 'function') {
    // React Native: the body is already in (fetch answers only once it has all of it); counted before parsing
    const text = await res.text().catch(() => null);
    if (text === null) return null;
    if (text.length > maxBytes || utf8ByteLength(text) > maxBytes) tooBig();
    return parseOrNull(text);
  }
  // a test double with json() only (every real fetch Response has text())
  return typeof (res as { json?: unknown }).json === 'function' ? res.json().catch(() => null) : null;
}
