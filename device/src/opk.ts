/**
 * @veil/device — b76 (one-time prekeys): this phone's one-time prekey pairs.
 *
 * Each pair is one X25519 key and one ML-KEM-768 key under one id, signed together by the
 * identity key (crypto-core identity.ts, OPK_SIG_LABEL). The relay holds the public halves and
 * hands each pair out ONCE, to someone starting a contact chat; the request names the pair's
 * id (signed), and this phone uses the private halves for that one request and deletes them
 * before the chat is saved. So a later theft of this phone — identity key and signed prekeys
 * included — can't re-derive the first message keys of a chat that used a one-time pair.
 *
 * Storage: one secure-store entry per pair (`veil_opk_k_<id>`: private halves + public halves +
 * signing time), the used-id ledger (`veil_opk_used_v1`) and this phone's one-time-key tag
 * (`veil_opk_tag_v1`). All live under the `veil_` prefix and none is a kept record
 * (container-key.ts CK_KEPT_KEYS), so every wipe sweeps them and they are sealed under the
 * main container key: Nothing-at-Rest's close wipe (a destroy of that key, then the sweep) and
 * the keyvault's own memory-mode close (IdentityVault.onClose) remove them with the identity.
 *
 * They never move to another phone (transfer.ts carries chats only): the new phone makes its own
 * pairs, and its first upload — under a new tag — replaces the old phone's pool on the relay.
 */

import { generateOneTimePrekeys, OPK_ID_RE, PREKEY_SIG_MAX_AGE_MS, randomBytes, type OneTimePrekey, type VeilStorage } from '../../crypto-core/src/index';
import { PREKEY_SIG_MAX_FUTURE_MS } from '../../crypto-core/src/constants';
import { secureRemove, secureRemoveMany } from './secure-wipe';

/** one entry per pair: `veil_opk_k_<id>` */
export const OPK_KEY_PREFIX = 'veil_opk_k_';
/** ids of pairs this phone has used (bounded): a request naming one is refused */
export const OPK_USED_KEY = 'veil_opk_used_v1';
/** this phone's one-time-key tag (random); the relay's pool belongs to the last tag that uploaded */
export const OPK_TAG_KEY = 'veil_opk_tag_v1';
/** b76r1 (audit P-4): ms since 1970 when this phone first read `mine: false` (another phone with
 *  this Vardum ID has published the pool since); removed once the pool is this phone's again.
 *  Settings shows it, with the choice to take the pool back (replenishOneTimePrekeys `reclaim`). */
export const OPK_ELSEWHERE_KEY = 'veil_opk_elsewhere_v1';
/** pairs per top-up batch, and the relay count below which the phone tops up */
export const OPK_BATCH = 20;
export const OPK_LOW_WATER = 8;
/** never more than this many pairs stored here (failed uploads can't pile up) */
export const OPK_LOCAL_MAX = 100;
/** a pair's private halves are kept this long after it was made, then deleted unused. The relay
 *  serves a pair for at most 21 days (relay OPK_RELAY_TTL_MS), a client accepts its signature
 *  for 28 (PREKEY_SIG_MAX_AGE_MS), and a request made with it lives 24 h on the relay. */
export const OPK_LOCAL_KEEP_MS = PREKEY_SIG_MAX_AGE_MS + 2 * 24 * 3600 * 1000;
const OPK_USED_MAX = 1000;

/** b76r2 (audit DEV-R2-04): a pair counts as live only while it is at most OPK_LOCAL_KEEP_MS old
 *  AND not stamped more than PREKEY_SIG_MAX_FUTURE_MS (a day, the clock skew a client accepts on a
 *  prekey signature) in the future. A pair made while the phone's clock ran ahead, then corrected,
 *  used to pass `now - madeAt <= keep` for as long as the clock had been ahead (years), so its
 *  private halves were never purged; no client would accept its signature anyway. */
export function oneTimePrekeyLive(madeAt: number, now = Date.now()): boolean {
  const t = Number(madeAt);
  return Number.isFinite(t) && now - t <= OPK_LOCAL_KEEP_MS && t - now <= PREKEY_SIG_MAX_FUTURE_MS;
}

/** `seq`: b76r2 (audit DEV-R2-04) insertion order on this phone (1, 2, ...; absent on pairs stored
 *  before b76r2, which count as oldest). Room is made by evicting the lowest `seq` first, not the
 *  lowest `madeAt`: a future-dated pair used to sort last and outlive every honest one. */
export interface StoredOpk { id: string; xPubB64: string; xPrivB64: string; pqPubB64: string; pqPrivB64: string; sig: string; madeAt: number; seq?: number }

function parseStored(raw: string | null): StoredOpk | null {
  try {
    const v = raw ? JSON.parse(raw) as StoredOpk : null;
    return v && typeof v.id === 'string' && OPK_ID_RE.test(v.id) && typeof v.xPrivB64 === 'string' && typeof v.pqPrivB64 === 'string' ? v : null;
  } catch { return null; }
}

/** b76r1 (audit P-4): when this phone first read that another phone holds the relay's pool, or 0 */
export async function oneTimePrekeysElsewhereSince(storage: VeilStorage): Promise<number> {
  const v = Number(await storage.get(OPK_ELSEWHERE_KEY).catch(() => null));
  return Number.isFinite(v) && v > 0 ? v : 0;
}

/** the private one-time pair with this id, or null (unknown, expired or malformed id) */
export async function loadOneTimePrekey(storage: VeilStorage, id: string, now = Date.now()): Promise<StoredOpk | null> {
  if (typeof id !== 'string' || !OPK_ID_RE.test(id)) return null;
  const v = parseStored(await storage.get(OPK_KEY_PREFIX + id));
  if (!v || v.id !== id) return null;
  if (!oneTimePrekeyLive(v.madeAt, now)) return null; // b76r2 (audit DEV-R2-04): future-dated = expired
  return v;
}

export async function usedOneTimePrekeyIds(storage: VeilStorage): Promise<string[]> {
  try { const v = JSON.parse((await storage.get(OPK_USED_KEY)) || '[]'); return Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : []; } catch { return []; }
}

export async function oneTimePrekeyUsed(storage: VeilStorage, id: string): Promise<boolean> {
  return (await usedOneTimePrekeyIds(storage)).includes(id);
}

/** b76r1 (one-time prekeys, audit P-1 / D1): one-at-a-time chains, keyed. `pair:<id>` serialises
 *  every accept that names that pair (contact.ts acceptOneTapSession holds it from the used-ledger
 *  check through the load, the derive and the consume); `ledger` serialises the used ledger's
 *  read-modify-write. Accepts were serialised per request TOKEN only, so two requests naming the
 *  same pair (an A2 relay handing one pair to two initiators) both passed the "not used yet"
 *  check, both derived, and both consumed it: one one-time key opened two chats. */
const opkChains = new Map<string, Promise<unknown>>();
function serializeOpk<T>(key: string, run: () => Promise<T>): Promise<T> {
  const prev = opkChains.get(key) ?? Promise.resolve();
  const next = prev.then(() => undefined, () => undefined).then(run);
  opkChains.set(key, next);
  const trim = () => { if (opkChains.get(key) === next) opkChains.delete(key); };
  next.then(trim, trim);
  return next;
}

/** b76r1 (audit P-1 / D1): run `fn` while holding the lock for one-time pair `id` (see above).
 *  Never nest it for the same id (it would wait on itself). */
export function withOneTimePrekeyLock<T>(id: string, fn: () => Promise<T>): Promise<T> {
  return serializeOpk('pair:' + String(id), fn);
}

/** the refusal a request naming an already used pair gets (the accept's check and the consume) */
export const OPK_ALREADY_USED_MESSAGE = 'This request was made to a one-time key this phone has already used, so it was not accepted. Ask your contact to send a new one.';

/**
 * b76: the pair is spent. Its id goes into the used ledger (a refused write throws), then its
 * private halves are overwritten and deleted, and the delete is checked (still there: throws).
 * The responder calls this after deriving the root and BEFORE saving the chat, so a chat never
 * exists on this phone while the one-time key that opened it still does.
 * b76r1 (audit P-1 / D1): an id ALREADY in the ledger throws (it used to pass as "recorded,
 * deleted", so a second accept racing the first went through). The ledger's check-and-append
 * runs under one lock, so two consumes can't both find the id missing, and two consumes of
 * different ids can't drop each other's entry.
 */
export async function consumeOneTimePrekey(storage: VeilStorage, id: string): Promise<void> {
  if (!OPK_ID_RE.test(id)) throw new Error('Malformed one-time prekey id.');
  await serializeOpk('ledger', async () => {
    const used = await usedOneTimePrekeyIds(storage);
    if (used.includes(id)) throw new Error(OPK_ALREADY_USED_MESSAGE);
    const ok = await storage.set(OPK_USED_KEY, JSON.stringify([...used, id].slice(-OPK_USED_MAX)));
    if (ok === false) throw new Error('This phone could not record its one-time key as used, so the request was not accepted. Try again.');
  });
  await secureRemove(storage, OPK_KEY_PREFIX + id);
  const present = (storage as unknown as { present?: (k: string) => Promise<boolean> }).present;
  const still = typeof present === 'function' ? await present.call(storage, OPK_KEY_PREFIX + id) : (await storage.get(OPK_KEY_PREFIX + id)) !== null;
  if (still) throw new Error('This phone could not delete its used one-time key, so the request was not accepted. Try again.');
}

const seqOf = (o: StoredOpk) => (Number.isSafeInteger(o.seq) && Number(o.seq) > 0 ? Number(o.seq) : 0);

/** every stored pair, in the order this phone stored them (b76r2, audit DEV-R2-04: `seq`, then
 *  `madeAt` among pairs from before b76r2); malformed entries are removed */
async function listStored(storage: VeilStorage): Promise<StoredOpk[]> {
  const out: StoredOpk[] = [];
  for (const k of await storage.keys(OPK_KEY_PREFIX)) {
    const v = parseStored(await storage.get(k));
    if (!v || k !== OPK_KEY_PREFIX + v.id) { await secureRemove(storage, k); continue; }
    out.push(v);
  }
  return out.sort((a, b) => seqOf(a) - seqOf(b) || a.madeAt - b.madeAt);
}

/** b76: delete pairs past OPK_LOCAL_KEEP_MS; returns those still kept (in insertion order).
 *  b76r2 (audit DEV-R2-04): and pairs stamped in the future (oneTimePrekeyLive). */
export async function purgeExpiredOneTimePrekeys(storage: VeilStorage, now = Date.now()): Promise<StoredOpk[]> {
  const all = await listStored(storage);
  const dead = all.filter((o) => !oneTimePrekeyLive(o.madeAt, now));
  if (dead.length) await secureRemoveMany(storage, dead.map((o) => OPK_KEY_PREFIX + o.id));
  return all.filter((o) => !dead.includes(o));
}

/** the tag this phone's pool was confirmed under, or a new candidate (saved only once the relay
 *  took a replacing upload under it — a failed first upload must not leave a tag the relay
 *  never saw, or the phone would read "not mine" and stop for good) */
async function tagOf(storage: VeilStorage): Promise<{ tag: string; fresh: boolean }> {
  const cur = await storage.get(OPK_TAG_KEY).catch(() => null);
  if (cur && /^[0-9a-f]{32}$/.test(cur)) return { tag: cur, fresh: false };
  return { tag: [...randomBytes(16)].map((b) => b.toString(16).padStart(2, '0')).join(''), fresh: true };
}

/**
 * b76r2 (one-time prekeys, audit PK-01): Nothing-at-Rest's close destroys this phone's private
 * halves, so the pairs the relay still holds would only be handed out to new contacts' requests
 * that then fail here. The close asks the relay to drop them (opk_drop) BEFORE it destroys the
 * keys. Best effort, and never in the wipe's way: the request is started and given at most
 * `waitMs`; offline, refused or slow, the wipe goes on and the next restore's top-up replaces the
 * pool instead (its first upload, under a new tag, has `replace`). Never throws.
 */
export function dropRelayOneTimePrekeys(relay: { opkDrop(veilId: string): Promise<unknown> }, veilId: string | null | undefined, waitMs = 1500): Promise<boolean> {
  if (!veilId) return Promise.resolve(false);
  let sent: Promise<boolean>;
  try { sent = Promise.resolve(relay.opkDrop(veilId)).then(() => true, () => false); } catch { return Promise.resolve(false); }
  let timer: ReturnType<typeof setTimeout> | undefined;
  const late = new Promise<boolean>((res) => { timer = setTimeout(() => res(false), Math.max(0, waitMs)); });
  return Promise.race([sent, late]).finally(() => { if (timer) clearTimeout(timer); });
}

export interface OpkRelay {
  opkCount(veilId: string, device: string): Promise<{ data: unknown }>;
  opkUpload(veilId: string, device: string, opks: { id: string; x_pub: string; pq_pub: string; sig: string }[], replace?: boolean): Promise<{ data: unknown }>;
}

const dataOf = (r: { data: unknown }) => ((r?.data as { data?: Record<string, unknown> })?.data ?? r?.data ?? {}) as Record<string, unknown>;

/**
 * b76: keep the relay's pool of this phone's one-time pairs topped up. Asks the relay how many it
 * still holds (and whether they are this phone's); below OPK_LOW_WATER it makes enough new pairs
 * for OPK_BATCH, saves them here FIRST (a pair the relay could hand out but this phone doesn't
 * have would fail that request), then uploads the public halves. A phone with no tag yet (first
 * run, a restore, a new phone after a move) uploads with `replace`, which drops whatever the
 * relay held for this Vardum ID (pairs this phone can't open). A phone whose pool another phone
 * has since replaced (`mine: false`) stops topping up: the newer phone owns the pool now.
 * b76r1 (audit P-4): that stop is no longer silent and for good. The phone notes when it first
 * read `mine: false` (OPK_ELSEWHERE_KEY, shown in Settings) and asks again at every top-up (each
 * launch, each accept); `reclaim` (the user's choice in Settings) uploads a full batch with
 * `replace`, so this phone's pairs replace the other phone's. Never automatic: two phones holding
 * one identity would otherwise keep dropping each other's pools, failing requests on both.
 * Never throws for the caller's sake; returns what happened.
 */
export async function replenishOneTimePrekeys(
  deps: { relay: OpkRelay; storage: VeilStorage },
  identity: { veilId: string; ikSeedB64: string },
  opts: { now?: number; batch?: number; lowWater?: number; reclaim?: boolean } = {},
): Promise<{ count: number; uploaded: number; mine: boolean; error?: string }> {
  const now = opts.now ?? Date.now();
  const batch = opts.batch ?? OPK_BATCH, low = opts.lowWater ?? OPK_LOW_WATER;
  try {
    let kept = await purgeExpiredOneTimePrekeys(deps.storage, now);
    const { tag, fresh } = await tagOf(deps.storage);
    const replace = fresh || opts.reclaim === true;
    let count = 0, mine = true;
    if (!replace) {
      const d = dataOf(await deps.relay.opkCount(identity.veilId, tag));
      count = Math.max(0, Number(d.count) || 0);
      mine = d.mine !== false;
      if (!mine) {
        // b76r1 (audit P-4): remembered (first time only) for Settings
        if (!(await oneTimePrekeysElsewhereSince(deps.storage))) await deps.storage.set(OPK_ELSEWHERE_KEY, String(now));
        return { count, uploaded: 0, mine };
      }
      if (await deps.storage.get(OPK_ELSEWHERE_KEY).catch(() => null)) await deps.storage.remove(OPK_ELSEWHERE_KEY);
    }
    if (!replace && count >= low) return { count, uploaded: 0, mine };
    const need = Math.max(0, batch - count);
    if (!need) return { count, uploaded: 0, mine };
    // room here: the first stored pairs go first (most likely already handed out, or expired soon).
    // b76r2 (audit DEV-R2-04): by insertion order, whatever their signing time says
    const overflow = kept.length + need - OPK_LOCAL_MAX;
    if (overflow > 0) {
      await secureRemoveMany(deps.storage, kept.slice(0, overflow).map((o) => OPK_KEY_PREFIX + o.id));
      kept = kept.slice(overflow);
    }
    const made: OneTimePrekey[] = await generateOneTimePrekeys(identity.ikSeedB64, need, now);
    let seq = kept.reduce((m, o) => Math.max(m, seqOf(o)), 0);
    for (const o of made) {
      const rec: StoredOpk = { id: o.id, xPubB64: o.xPubB64, xPrivB64: o.xPrivB64, pqPubB64: o.pqPubB64, pqPrivB64: o.pqPrivB64, sig: o.sig, madeAt: o.madeAt, seq: ++seq };
      if ((await deps.storage.set(OPK_KEY_PREFIX + o.id, JSON.stringify(rec))) === false) throw new Error('could not save a one-time key');
    }
    const up = dataOf(await deps.relay.opkUpload(identity.veilId, tag, made.map((o) => ({ id: o.id, x_pub: o.xPubB64, pq_pub: o.pqPubB64, sig: o.sig })), replace));
    if (fresh && (await deps.storage.set(OPK_TAG_KEY, tag)) === false) throw new Error('could not save the one-time key tag');
    if (replace && (await deps.storage.get(OPK_ELSEWHERE_KEY).catch(() => null))) await deps.storage.remove(OPK_ELSEWHERE_KEY);
    return { count: Math.max(0, Number(up.count) || 0), uploaded: made.length, mine: true };
  } catch (e) {
    return { count: -1, uploaded: 0, mine: true, error: String((e as Error)?.message ?? e) };
  }
}
