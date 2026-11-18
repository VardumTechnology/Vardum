/**
 * Call guard rails that need no native module, so the tests can run them
 * directly (CallManager itself imports react-native-webrtc and expo-av).
 *
 *  - relay-only peer connection config: no TURN relay servers, no call
 *  - outgoing SDP / trickle scrub: only relay candidates leave this phone,
 *    and no address of this phone rides along (raddr, c=, a=rtcp, o=)
 *  - offer freshness: an offer is rung only inside a short window around its
 *    authenticated send time
 *  - seen call ids: a bounded, persisted set so a replayed offer never rings
 *  - DTLS certificate fingerprint read from WebRTC stats
 */

/** Shown on the call card when no relay credentials could be had. */
export const CALL_RELAY_UNREACHABLE = "Couldn't reach the call relay — try again";
/** b77n2 (review INFO): shown on the caller's card when the other phone never approved the call before the
 *  ring window ended (offline, or a build that doesn't take calls this way — nothing tells the two apart, so
 *  the text claims neither) */
export const CALL_PEER_UNREACHABLE = "Couldn't reach the other phone";

export interface TurnServer { urls: string[]; username: string; credential: string }
export interface TurnIce { iceServers: TurnServer[] }

export interface RelayOnlyPcConfig {
  iceServers: TurnServer[];
  iceTransportPolicy: 'relay';
  iceCandidatePoolSize: number;
}

const TURN_URL = /^turns?:/i;

/** b75 (audit CA-1): the host of a turn:/turns: URL ("turn:host:port?..",
 *  "turn:[v6]:port"), lower-cased, or null when it can't be read */
export function turnHostOf(url: string): string | null {
  const m = /^turns?:(\[[0-9a-fA-F:.]+\]|[^:?/\s]+)(?::(\d{1,5}))?(?:\?.*)?$/i.exec(url.trim());
  if (!m) return null;
  return m[1].toLowerCase();
}

/**
 * b75 round 2 (audit D2): IP literals are read STRICTLY. The b75 filter matched only the
 * canonical spellings, while the platform resolver (inet_aton / getaddrinfo) also accepts
 * 127.1, 10.1, 0x7f.0.0.1, 0177.0.0.1 and IPv6 forms such as [0:0:0:0:0:0:0:1],
 * [::ffff:7f00:1], [::127.0.0.1] or NAT64 [64:ff9b::a00:1]: each passed as "public".
 * Now an IPv4 literal must be a plain dotted quad (decimal, no leading zeros), an IPv6
 * literal must be in its canonical RFC 5952 form, and anything else must be a real DNS
 * name (its last label is never all digits or hex). The address itself is then judged
 * by what it means (mapped, compatible, NAT64, 6to4 and Teredo forms included).
 */
function ipv4Parts(h: string): number[] | null {
  if (!/^(0|[1-9]\d{0,2})(\.(0|[1-9]\d{0,2})){3}$/.test(h)) return null;
  const p = h.split('.').map(Number);
  return p.every((x) => x <= 255) ? p : null;
}

/** an IPv6 literal (no brackets) as 8 groups of 16 bits, or null */
function ipv6Groups(h: string): number[] | null {
  if (!/^[0-9a-f:.]+$/.test(h) || !h.includes(':')) return null;
  let tail: number[] = [];
  let body = h;
  const lastColon = h.lastIndexOf(':');
  const lastPart = h.slice(lastColon + 1);
  if (lastPart.includes('.')) {
    const v4 = ipv4Parts(lastPart);
    if (!v4) return null;
    tail = [(v4[0] << 8) | v4[1], (v4[2] << 8) | v4[3]];
    body = h.slice(0, lastColon + 1); // ends with ':'
    if (!body.endsWith('::')) body = body.slice(0, -1);
  }
  const halves = body.split('::');
  if (halves.length > 2) return null;
  const parse = (s: string): number[] | null => {
    if (s === '') return [];
    const out: number[] = [];
    for (const g of s.split(':')) {
      if (!/^[0-9a-f]{1,4}$/.test(g)) return null;
      out.push(parseInt(g, 16));
    }
    return out;
  };
  const head = parse(halves[0]);
  const rest = halves.length === 2 ? parse(halves[1]) : [];
  if (!head || !rest) return null;
  const want = 8 - tail.length;
  let groups: number[];
  if (halves.length === 2) {
    const fill = want - head.length - rest.length;
    if (fill < 1) return null;
    groups = [...head, ...new Array<number>(fill).fill(0), ...rest];
  } else {
    if (head.length !== want) return null;
    groups = head;
  }
  return [...groups, ...tail];
}

/** RFC 5952 text of 8 groups (lower case, no leading zeros, the longest run of two or more
 *  zero groups shortened, the first one on a tie; IPv4-mapped written with a dotted quad) */
function canonicalIpv6(g: number[]): string {
  if (g.slice(0, 5).every((x) => x === 0) && g[5] === 0xffff) return `::ffff:${g[6] >> 8}.${g[6] & 255}.${g[7] >> 8}.${g[7] & 255}`;
  let best = -1;
  let bestLen = 0;
  for (let i = 0; i < 8;) {
    if (g[i] !== 0) { i++; continue; }
    let j = i;
    while (j < 8 && g[j] === 0) j++;
    if (j - i > bestLen && j - i >= 2) { best = i; bestLen = j - i; }
    i = j;
  }
  const hex = g.map((x) => x.toString(16));
  if (best < 0) return hex.join(':');
  return `${hex.slice(0, best).join(':')}::${hex.slice(best + bestLen).join(':')}`;
}

function publicV4(v4: number[]): boolean {
  const [a, b] = v4;
  if (a === 0 || a === 10 || a === 127 || a >= 224) return false; // this-net, private, loopback, multicast/reserved
  if (a === 169 && b === 254) return false; // link-local
  if (a === 172 && b >= 16 && b <= 31) return false; // private
  if (a === 192 && b === 168) return false; // private
  if (a === 100 && b >= 64 && b <= 127) return false; // carrier-grade NAT
  if (a === 192 && b === 0 && v4[2] === 0) return false; // IETF protocol assignments
  if (a === 198 && (b === 18 || b === 19)) return false; // benchmarking
  return true;
}

function publicV6(g: number[]): boolean {
  const zeros = (n: number) => g.slice(0, n).every((x) => x === 0);
  if (zeros(8)) return false; // ::
  if (zeros(7) && g[7] === 1) return false; // ::1
  if (zeros(5) && g[5] === 0xffff) return publicV4([g[6] >> 8, g[6] & 255, g[7] >> 8, g[7] & 255]); // IPv4-mapped
  if (zeros(6)) return false; // IPv4-compatible (deprecated): ::a.b.c.d
  if (zeros(4) && g[4] === 0xffff && g[5] === 0) return false; // SIIT ::ffff:0:a.b.c.d
  if (g[0] === 0x64 && g[1] === 0xff9b) return false; // NAT64 (64:ff9b::/96 and the local-use 64:ff9b:1::/48)
  if (g[0] === 0x2001 && g[1] === 0) return false; // Teredo
  if (g[0] === 0x2002) return publicV4([g[1] >> 8, g[1] & 255, g[2] >> 8, g[2] & 255]); // 6to4 carries an IPv4 address
  if (g[0] === 0x100 && g[1] === 0 && g[2] === 0 && g[3] === 0) return false; // discard-only 100::/64
  if ((g[0] & 0xfe00) === 0xfc00) return false; // unique local fc00::/7
  if ((g[0] & 0xffc0) === 0xfe80 || (g[0] & 0xffc0) === 0xfec0) return false; // link-local, old site-local
  if ((g[0] & 0xff00) === 0xff00) return false; // multicast
  return true;
}

/** b75 (audit CA-1): a TURN server must be a PUBLIC host. A relay that names a LAN,
 *  loopback, link-local, carrier-NAT or unique-local address (or a single-label /
 *  .local / .internal name) would make the phone send its TURN traffic, credentials
 *  and call timing into the local network. b75 round 2 (audit D2): in any spelling. */
export function isPublicTurnHost(host: string): boolean {
  let h = host.toLowerCase();
  const bracketed = h.startsWith('[') && h.endsWith(']');
  if (bracketed) h = h.slice(1, -1);
  if (h.includes(':')) {
    const g = ipv6Groups(h);
    if (!g || canonicalIpv6(g) !== h) return false; // only the canonical spelling is read
    return publicV6(g);
  }
  if (bracketed) return false;
  const v4 = ipv4Parts(h);
  if (v4) return publicV4(v4);
  // a DNS name: letters, digits, hyphens; at least two labels, none empty; and a last label
  // that is not numeric or hex (127.1, 0x7f.0.0.1, 0177.0.0.1 are addresses to the
  // resolver, never names)
  if (!/^[a-z0-9.-]+$/.test(h) || !h.includes('.') || h.endsWith('.')) return false; // single-label names resolve locally
  const labels = h.split('.');
  if (labels.some((l) => !l || l.length > 63 || l.startsWith('-') || l.endsWith('-'))) return false;
  const last = labels[labels.length - 1];
  if (!/[a-z]/.test(last) || /^0x[0-9a-f]*$/.test(last)) return false;
  if (labels.some((l) => /^0x[0-9a-f]+$/.test(l))) return false;
  if (/(^|\.)(localhost|local|internal|lan|home|intranet|corp|home\.arpa)$/.test(h)) return false;
  return true;
}

/** b75 round 2 (audit D2): the product's own TURN domains. A public DNS name can still
 *  resolve to a private address (localtest.me is 127.0.0.1), which a host check can't see
 *  without resolving; the app therefore accepts only TURN hosts under these suffixes. The
 *  relay's TURN_HOSTS are hostnames under them. */
export const PRODUCT_TURN_HOST_SUFFIXES: readonly string[] = ['tryveil.app', 'tryvardum.app'];

/** b75 (audit CA-1): optional pin of the TURN host names the app accepts (domain
 *  suffixes, e.g. "tryveil.app"). Empty = any public host. b75 round 2 (audit D2): the app
 *  pins PRODUCT_TURN_HOST_SUFFIXES at start (CallManager); `devLoopback` (development
 *  builds only) also accepts a TURN server on this machine (127.0.0.1, [::1], localhost). */
let turnHostSuffixes: string[] = [];
let turnDevLoopback = false;
export function setTurnHostAllowList(suffixes: readonly string[], opts: { devLoopback?: boolean } = {}): void {
  turnHostSuffixes = suffixes.map((x) => x.toLowerCase().replace(/^\./, '')).filter(Boolean);
  turnDevLoopback = opts.devLoopback === true;
}
function turnUrlAllowed(u: string): boolean {
  const h = turnHostOf(u);
  if (!h) return false;
  if (turnDevLoopback && (h === '127.0.0.1' || h === '[::1]' || h === 'localhost')) return true;
  if (!isPublicTurnHost(h)) return false;
  if (!turnHostSuffixes.length) return true;
  return turnHostSuffixes.some((sfx) => h === sfx || h.endsWith('.' + sfx));
}

/** The only peer connection config a call may use: TURN servers, relay-only.
 *  Null when there is no usable relay server; the caller must then end the
 *  call instead of building a connection that would gather host candidates.
 *  b75 (audit CA-1): only public TURN hosts (and, when pinned, only the pinned ones). */
export function relayOnlyPcConfig(ice: TurnIce | null | undefined): RelayOnlyPcConfig | null {
  if (!ice || !Array.isArray(ice.iceServers)) return null;
  const servers = ice.iceServers
    .map((s) => ({ ...s, urls: (s?.urls ?? []).filter((u) => typeof u === 'string' && TURN_URL.test(u) && turnUrlAllowed(u)) }))
    .filter((s) => s.urls.length > 0 && typeof s.username === 'string' && typeof s.credential === 'string');
  if (servers.length === 0) return null;
  return { iceServers: servers, iceTransportPolicy: 'relay', iceCandidatePoolSize: 1 };
}

// ---------------------------------------------------------------------------
// candidate scrub
// ---------------------------------------------------------------------------

/** Fields of an ICE candidate line (with or without the "a=" prefix). */
function candFields(line: string): string[] | null {
  const body = line.replace(/^a=/, '').replace(/^candidate:/, '');
  const f = body.trim().split(/\s+/);
  return f.length >= 8 && f[6] === 'typ' ? f : null;
}

/** True for a well-formed relay candidate (typ relay). */
export function isRelayCandidate(line: string): boolean {
  const f = candFields(line);
  return !!f && f[7] === 'relay';
}

/** A relay candidate with its related address (this phone's own public
 *  address as the TURN server saw it) zeroed. Null for any other type. */
export function scrubCandidate(line: string): string | null {
  if (!isRelayCandidate(line)) return null;
  return line.replace(/ raddr \S+ rport \S+/, ' raddr 0.0.0.0 rport 0');
}

/** Trickle form: the JSON CallManager sends for one candidate. Null = drop. */
export function scrubCandidateJson(json: string): string | null {
  try {
    const c = JSON.parse(json) as { candidate?: unknown };
    if (typeof c?.candidate !== 'string') return null;
    const clean = scrubCandidate(c.candidate);
    if (!clean) return null;
    return JSON.stringify({ ...c, candidate: clean });
  } catch { return null; }
}

/** The SDP this phone sends: non-relay candidate lines dropped, relay
 *  candidates' related address zeroed, and any connection / rtcp / origin
 *  address that is not a relay address replaced with a placeholder. The
 *  DTLS fingerprint and everything else is left untouched. */
export function scrubOutgoingSdp(sdp: string): string {
  if (typeof sdp !== 'string') return sdp;
  const eol = sdp.includes('\r\n') ? '\r\n' : '\n';
  const lines = sdp.split(/\r?\n/);
  const relayAddrs = new Set<string>();
  for (const l of lines) {
    if (l.startsWith('a=candidate:') && isRelayCandidate(l)) relayAddrs.add((candFields(l) as string[])[4]);
  }
  const safeAddr = (a: string) => a === '0.0.0.0' || a === '::' || a === '127.0.0.1' || relayAddrs.has(a);
  const out: string[] = [];
  for (const l of lines) {
    if (l.startsWith('a=candidate:')) {
      const clean = scrubCandidate(l);
      if (clean) out.push(clean);
      continue;
    }
    let m = /^c=IN (IP4|IP6) (\S+)(.*)$/.exec(l);
    if (m) { out.push(safeAddr(m[2]) ? l : 'c=IN IP4 0.0.0.0'); continue; }
    m = /^a=rtcp:(\d+) IN (IP4|IP6) (\S+)$/.exec(l);
    if (m) { out.push(safeAddr(m[3]) ? l : `a=rtcp:${m[1]} IN IP4 0.0.0.0`); continue; }
    m = /^(o=\S+ \S+ \S+ IN) (IP4|IP6) (\S+)$/.exec(l);
    if (m) { out.push(safeAddr(m[3]) ? l : `${m[1]} IP4 127.0.0.1`); continue; }
    out.push(l);
  }
  return out.join(eol);
}

// ---------------------------------------------------------------------------
// offer freshness
// ---------------------------------------------------------------------------

/** An offer older than this (by its authenticated send time) never rings. */
export const OFFER_MAX_AGE_MS = 60_000;
/** ...nor one claiming to be sent further than this in the future. */
export const OFFER_MAX_FUTURE_MS = 30_000;

export type OfferFreshness = 'fresh' | 'stale' | 'future' | 'untimed';

/** The authenticated send time of a call signal: the ratchet trailer time
 *  (sentAt, set by the sync layer from the decrypted frame) when present,
 *  else the send time the caller put inside the encrypted signal (ts). Both
 *  are covered by the ratchet's authentication; the relay can set neither. */
export function signalSentAt(sig: { sentAt?: unknown; ts?: unknown }): number | null {
  for (const v of [sig.sentAt, sig.ts]) {
    if (typeof v === 'number' && Number.isFinite(v) && v > 0) return v;
  }
  return null;
}

export function offerFreshness(sig: { sentAt?: unknown; ts?: unknown }, now = Date.now()): OfferFreshness {
  const t = signalSentAt(sig);
  if (t === null) return 'untimed';
  if (t - now > OFFER_MAX_FUTURE_MS) return 'future';
  if (now - t > OFFER_MAX_AGE_MS) return 'stale';
  return 'fresh';
}

// ---------------------------------------------------------------------------
// seen call ids
// ---------------------------------------------------------------------------

export interface CallKV {
  get(k: string): Promise<string | null>;
  set(k: string, v: string): Promise<unknown>;
}

export const SEEN_CALLS_KEY = 'veil_calls_seen';
/** Entries outlive the freshness window by a wide margin, then go: an offer
 *  older than OFFER_MAX_AGE_MS is refused on its time anyway, so keeping
 *  call ids longer would only leave a trace of past calls on the phone. */
export const SEEN_CALLS_TTL_MS = 10 * 60_000;
export const SEEN_CALLS_MAX = 256;

/** Call ids this phone has already rung (or refused). In memory always; in
 *  storage too when App provides it, so a replay after a restart is caught. */
export class SeenCallIds {
  private map = new Map<string, number>();
  private loaded = false;
  constructor(private readonly storage: () => CallKV | null | undefined, private readonly now: () => number = Date.now) {}

  private prune(): void {
    const cutoff = this.now() - SEEN_CALLS_TTL_MS;
    for (const [id, at] of this.map) if (at < cutoff) this.map.delete(id);
    while (this.map.size > SEEN_CALLS_MAX) this.map.delete(this.map.keys().next().value as string);
  }

  async load(): Promise<void> {
    if (this.loaded) return;
    const kv = this.storage();
    if (!kv) return; // retried on the next call until storage exists
    this.loaded = true;
    try {
      const raw = await kv.get(SEEN_CALLS_KEY);
      const arr = raw ? (JSON.parse(raw) as unknown) : [];
      if (Array.isArray(arr)) {
        for (const e of arr) {
          if (Array.isArray(e) && typeof e[0] === 'string' && typeof e[1] === 'number' && !this.map.has(e[0])) this.map.set(e[0], e[1]);
        }
      }
    } catch { /* unreadable list: start empty, the time check still holds */ }
    this.prune();
  }

  has(id: string): boolean {
    this.prune();
    return this.map.has(id);
  }

  /** b75 (audit DEV-L4): a wipe removed the stored list; the copy in memory goes too
   *  (it is reloaded from storage, now empty, on the next call) */
  forget(): void {
    this.map.clear();
    this.loaded = false;
  }

  async add(id: string): Promise<void> {
    this.map.delete(id);
    this.map.set(id, this.now());
    this.prune();
    const kv = this.storage();
    if (!kv) return;
    try { await kv.set(SEEN_CALLS_KEY, JSON.stringify([...this.map.entries()])); } catch { /* memory copy still guards this run */ }
  }

  /** Test/wipe helper. */
  clearMemory(): void { this.map.clear(); this.loaded = false; }
}

// ---------------------------------------------------------------------------
// DTLS certificate from stats
// ---------------------------------------------------------------------------

/** The remote DTLS certificate fingerprint WebRTC reports for the selected
 *  transport ("sha-256 AB:CD:..."), or null when the stats don't carry it
 *  (older react-native-webrtc builds). */
export function remoteCertFingerprint(stats: Iterable<Record<string, unknown>>): string | null {
  const all = Array.from(stats);
  const byId = new Map(all.map((r) => [String(r.id), r]));
  const transports = all.filter((r) => r.type === 'transport' && typeof r.remoteCertificateId === 'string');
  const tr = transports.find((r) => r.selectedCandidatePairId) ?? transports[0];
  if (!tr) return null;
  const cert = byId.get(String(tr.remoteCertificateId));
  if (!cert || typeof cert.fingerprint !== 'string' || typeof cert.fingerprintAlgorithm !== 'string') return null;
  return `${cert.fingerprintAlgorithm.toLowerCase()} ${cert.fingerprint.toUpperCase()}`;
}

/**
 * b77u (audit 6 U-M4 / R1 F-04): capture the microphone beside another set-up step (the TURN grant, a
 * prewarm). `Promise.all` handed the stream to the call only once BOTH succeeded, so a failed grant left
 * the acquired mic track running with no owner. Here the stream is handed over (`own`) the moment it
 * arrives, and if the other step fails it is stopped, whichever of the two settles first.
 */
export async function captureBeside<M extends { getTracks(): { stop(): void }[] }, T>(capture: Promise<M>, sibling: Promise<T>, own: (m: M) => void): Promise<M> {
  const owned = capture.then((m) => { own(m); return m; });
  try {
    const [m] = await Promise.all([owned, sibling]);
    return m;
  } catch (e) {
    const m = await owned.catch(() => null);
    if (m) for (const t of m.getTracks()) { try { t.stop(); } catch { /* already stopped */ } }
    throw e;
  }
}
