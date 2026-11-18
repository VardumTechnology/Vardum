/**
 * b77t (audit 5 M-E / IH V-02, owner decision "a real throwaway account"): the decoy is a working, empty
 * Vardum on its own account.
 *
 * Before: the decoy session's relay and account were a Proxy that rejected every call, and the Vardum ID it
 * showed was a hash of the lock salt that no relay knew, so New chat failed and a lookup of the shown ID found
 * nothing. Now the decoy has a real, separate account and identity on the relay, made with the existing
 * 24-word path (provisionSilentAccount + restoreFromPhrase) from a random phrase generated on the phone. The
 * decoy's stores live under their own names, so nothing it does touches the real records, and its relay client
 * signs in with its own token only (never the real one).
 *
 * Where it is kept:
 *  - DECOY_AUX_KEY: one kept record (container-key.ts CK_KEPT_KEYS, sealed under the kept slot; Nothing at Rest
 *    keeps it, so the decoy works after a departure wipe and a restart) holding the decoy's phrase, its Vardum ID,
 *    its login and its identity keys. It exists whenever an app lock exists, decoy or not, and is always padded
 *    to DECOY_AUX_LEN, so neither its name nor its size says whether a decoy is set up (the app lock record, in
 *    the same sealed slot, already holds the decoy code's check).
 *  - everything else the decoy stores (its chats, contacts, settings): veil_dk_* records, sealed under the main
 *    key with blinded names like every chat record; every wipe removes them (Nothing at Rest: at each departure,
 *    as the real chats).
 *
 * What links the two accounts on the relay: nothing stored. Each has its own token, identity, client id and
 * records; the decoy never registers push (decoy-push.ts holds registration in decoy mode) and has no wake target.
 * Residual (spec): the relay sees both accounts used from the same network address, and the decoy's account and
 * identity are created close in time to activity on the real one (at decoy setup, from the real session).
 *
 * Pure module (no React Native): veil-app.ts builds the decoy VeilApp from it.
 */
import type { VeilStorage } from '../vendor/crypto-core/src/index';
import { createIdentity, restoreIdentity, ikSign } from '../vendor/crypto-core/src/index';
import type { SecureStore } from '../vendor/device/src/secure-store';
import { AUTH_SESSION_KEY, REGLOCK_DEVICE_STORAGE, type Base44Auth } from '../vendor/device/src/auth';
import { KEYVAULT_KEY, type IdentityVault, type KeyvaultIdentity } from '../vendor/device/src/keyvault';
import type { VeilRelay } from '../vendor/device/src/relay';
import { provisionSilentAccount, silentLogin } from '../vendor/device/src/silent-auth';
import { secureRandomUnit } from '../vendor/device/src/secure-random';
import { restoreFromPhrase } from '../vendor/device/src/restore';
import { currentWipeGeneration } from '../vendor/device/src/wipe-generation';

/** the kept record (CK_KEPT_KEYS) */
export const DECOY_AUX_KEY = 'veil_lock_aux_v1';
/** the decoy's other records */
export const DECOY_PREFIX = 'veil_dk_';
/** the aux record's fixed length (an identity with its ML-KEM keys and a login fit with room to spare) */
export const DECOY_AUX_LEN = 16384;
/** the decoy keys kept inside the aux record (so Nothing at Rest keeps them): its login, its identity, and the
 *  registration-lock device key that belongs to the login */
export const DECOY_AUX_FIELDS: ReadonlySet<string> = new Set([AUTH_SESSION_KEY, KEYVAULT_KEY, REGLOCK_DEVICE_STORAGE]);

export interface DecoyAuxData {
  /** the decoy account's 24 words (never shown; the account and identity are derived from them) */
  phrase: string;
  /** its Vardum ID (derived from the phrase, so it is known before the relay is reached) */
  veilId: string;
  /** the aux fields' values (DECOY_AUX_FIELDS) */
  f: Record<string, string>;
}
type AuxRecord = { v: 1; d: DecoyAuxData | null; p?: string };

type RealStore = Pick<VeilStorage, 'get' | 'set' | 'remove' | 'keys'>;

/** the aux record: read-modify-write under one lock, always written at DECOY_AUX_LEN */
export class DecoyAux {
  private chain: Promise<unknown> = Promise.resolve();
  /** the last value read or written, for the wipe generation it was read in (every relay call reads the login:
   *  this saves a keystore read of the whole record each time). A wipe moves the generation: read again. */
  private cache: { gen: number; d: DecoyAuxData | null } | null = null;
  constructor(private real: RealStore) {}

  private locked<T>(fn: () => Promise<T>): Promise<T> {
    const run = this.chain.catch(() => undefined).then(fn);
    this.chain = run.catch(() => undefined);
    return run;
  }

  private async readRaw(): Promise<AuxRecord | null> {
    const gen = currentWipeGeneration();
    if (this.cache && this.cache.gen === gen) return { v: 1, d: this.cache.d };
    const r = await this.readStored();
    if (r) this.cache = { gen, d: r.d };
    return r;
  }

  private async readStored(): Promise<AuxRecord | null> {
    const raw = await this.real.get(DECOY_AUX_KEY);
    if (raw === null || raw === undefined) return null;
    try {
      const v = JSON.parse(raw) as AuxRecord;
      if (v?.v !== 1) return { v: 1, d: null };
      const d = v.d;
      if (d && (typeof d.phrase !== 'string' || typeof d.veilId !== 'string' || typeof d.f !== 'object' || !d.f)) return { v: 1, d: null };
      return { v: 1, d: d ?? null };
    } catch { return { v: 1, d: null }; }
  }

  /** padded to DECOY_AUX_LEN; a write the store refuses throws */
  private async writeRaw(d: DecoyAuxData | null): Promise<void> {
    const body = JSON.stringify({ v: 1, d });
    const padLen = Math.max(0, DECOY_AUX_LEN - body.length - ',"p":""'.length);
    const out = JSON.stringify({ v: 1, d, p: '0'.repeat(padLen) });
    if (out.length > DECOY_AUX_LEN) console.warn('[veil-decoy] the decoy record is larger than its fixed size');
    const gen = currentWipeGeneration();
    this.cache = null;
    if ((await this.real.set(DECOY_AUX_KEY, out)) === false) throw new Error('The decoy record could not be stored.');
    if (currentWipeGeneration() === gen) this.cache = { gen, d };
  }

  /** the decoy's data, or null (no decoy set up, or no record) */
  read(): Promise<DecoyAuxData | null> {
    return this.locked(async () => (await this.readRaw())?.d ?? null);
  }

  update(fn: (d: DecoyAuxData | null) => DecoyAuxData | null): Promise<DecoyAuxData | null> {
    return this.locked(async () => {
      const cur = (await this.readRaw())?.d ?? null;
      const next = fn(cur ? { ...cur, f: { ...cur.f } } : null);
      if (cur === null && next === null) return null; // nothing to write (no record is made from here)
      await this.writeRaw(next);
      return next;
    });
  }

  /** an app lock exists: the record exists too (empty filler when there is no decoy), same size either way */
  ensurePresent(): Promise<void> {
    return this.locked(async () => {
      const cur = await this.readRaw().catch(() => undefined);
      if (cur === undefined) return; // unreadable: left as it is
      if (cur === null) await this.writeRaw(null);
    });
  }

  /** the decoy code was removed: the decoy's data goes, the (empty) record stays while a lock exists */
  async clearDecoy(alsoRecord = false): Promise<void> {
    await this.locked(async () => {
      this.cache = null;
      if (alsoRecord) await this.real.remove(DECOY_AUX_KEY);
      else await this.writeRaw(null);
    });
    await sweepDecoyRecords(this.real);
  }
}

/** the decoy's veil_dk_ name for one of its store keys */
export function decoyRecordName(k: string): string {
  // a key outside veil_ gets a '~' mark (never in a veil_ key name), so two keys can't share a record name
  return DECOY_PREFIX + (k.startsWith('veil_') ? k.slice(5) : `~${k}`);
}
function decoyKeyOf(name: string): string | null {
  if (!name.startsWith(DECOY_PREFIX)) return null;
  const rest = name.slice(DECOY_PREFIX.length);
  return rest.startsWith('~') ? rest.slice(1) : `veil_${rest}`;
}

async function sweepDecoyRecords(real: RealStore): Promise<void> {
  try {
    for (const k of await real.keys(DECOY_PREFIX)) await real.remove(k).catch(() => undefined);
  } catch { /* the next wipe sweeps them (veil_ keys) */ }
}

/**
 * The decoy's platform store: a SecureStore over the REAL store. Its keys map to veil_dk_* records, except the
 * aux fields (login, identity), which live in the kept aux record. With no decoy set up it stores nothing
 * (writes throw, reads are empty), so a decoy store can never write into the real records' names.
 */
export function decoySecureStore(real: RealStore, aux: DecoyAux): SecureStore {
  return {
    async get(k) {
      if (DECOY_AUX_FIELDS.has(k)) return (await aux.read())?.f[k] ?? null;
      return real.get(decoyRecordName(k));
    },
    async set(k, v) {
      if (DECOY_AUX_FIELDS.has(k)) {
        const next = await aux.update((d) => (d ? { ...d, f: { ...d.f, [k]: v } } : null));
        if (!next) throw new Error('No decoy is set up.');
        return;
      }
      if (!(await aux.read())) throw new Error('No decoy is set up.');
      if ((await real.set(decoyRecordName(k), v)) === false) throw new Error('The decoy record could not be stored.');
    },
    async delete(k) {
      if (DECOY_AUX_FIELDS.has(k)) { await aux.update((d) => { if (!d) return null; const f = { ...d.f }; delete f[k]; return { ...d, f }; }); return; }
      await real.remove(decoyRecordName(k));
    },
    async list() {
      const out: string[] = [];
      for (const n of await real.keys(DECOY_PREFIX)) { const k = decoyKeyOf(n); if (k) out.push(k); }
      const d = await aux.read();
      if (d) for (const k of Object.keys(d.f)) out.push(k);
      return out;
    },
  };
}

/** b77t (M-E): the decoy's phrase and Vardum ID, made on the phone (no network) when none exists yet */
export async function prepareDecoy(aux: DecoyAux, make: () => Promise<{ mnemonic: string[]; veilId: string }> = createIdentity): Promise<DecoyAuxData> {
  const cur = await aux.read();
  if (cur) return cur;
  const m = await make();
  const d = await aux.update((x) => x ?? { phrase: m.mnemonic.join(' '), veilId: m.veilId, f: {} });
  if (!d) throw new Error('The decoy could not be prepared.');
  return d;
}

export interface DecoyAccountDeps {
  aux: DecoyAux;
  /** the DECOY app's account, relay and vault (never the real ones) */
  auth: Pick<Base44Auth, 'currentSession' | 'login'>;
  relay: VeilRelay;
  vault: IdentityVault;
}

/**
 * b77t (M-E): register the decoy's account and identity on the relay (idempotent; resumes where it stopped).
 * 1. the phrase and ID (local, prepareDecoy); 2. the phrase-derived account (provisionSilentAccount: an account
 * that already exists from an earlier attempt signs in); 3. the identity (restoreFromPhrase: publishes prekeys,
 * binds the ID to the account, saves the keys in the aux record). Throws when the relay can't be reached; the
 * caller tries again later (at the next decoy unlock or launch).
 */
export async function ensureDecoyAccount(d: DecoyAccountDeps): Promise<{ veilId: string; identity: KeyvaultIdentity }> {
  const data = await prepareDecoy(d.aux);
  if (!(await d.auth.currentSession())) {
    await provisionSilentAccount({ auth: d.auth as Base44Auth, relay: d.relay }, data.phrase);
  }
  let id = await d.vault.load();
  if (!id || id.veilId !== data.veilId) id = await restoreFromPhrase({ relay: d.relay, vault: d.vault }, data.phrase, data.veilId);
  return { veilId: data.veilId, identity: id };
}

// ---------- b77t merge (owner decision 2 Nov): removing the decoy code deletes the decoy's relay account ----------

/**
 * The pending decoy-account deletes. Removing the decoy code (or the whole lock) used to drop only the decoy's
 * records on the phone; its account and identity stayed on the relay for good. Now the decoy's 24 words go into
 * this record first (sealed, kept: Nothing at Rest keeps it, every wipe removes it), its records on the phone go at
 * once as before, and after a random CSPRNG delay (DECOY_END_MIN_MS..DECOY_END_MAX_MS, while the app runs — never
 * in the same moment as the real account's activity that removed the code) the app signs in as the DECOY (its
 * phrase-derived login, a fresh client with an in-memory store: never the real token) and deletes its account
 * with the decoy identity's own proof (the normal account-delete path). Then the entry goes. A launch that finds
 * an entry left (the app closed first) waits a new random delay after the unlock.
 *
 * Shape: one record under this name on EVERY install (written at launch, with or without a lock or a decoy), always
 * padded to DECOY_END_LEN, so neither its presence nor its size says that a decoy existed (kept records' names are
 * not blinded: container-key.ts CK_KEPT_KEYS). At most DECOY_END_MAX_ENTRIES entries (the oldest go first).
 */
export const DECOY_END_KEY = 'veil_aux_pending_v1';
export const DECOY_END_LEN = 2048;
export const DECOY_END_MAX_ENTRIES = 4;
export const DECOY_END_MIN_MS = 60_000;
export const DECOY_END_MAX_MS = 30 * 60_000;

export interface DecoyEndEntry { phrase: string; veilId: string }

/** b77t2 (info): the CURRENT decoy as a delete entry (its phrase and ID from the aux record), or null. A wipe of the
 *  phone (wipe device, self-destruct, sign-out, the duress code) reads it before the erase and deletes the decoy's
 *  relay account from memory after a random delay, best effort, as it does for a removed decoy */
export async function currentDecoyEnd(real: RealStore): Promise<DecoyEndEntry | null> {
  try {
    const d = await new DecoyAux(real).read();
    return d && d.phrase && d.veilId ? { phrase: d.phrase, veilId: d.veilId } : null;
  } catch { return null; }
}
type EndRecord = { v: 1; q: DecoyEndEntry[]; p?: string };

/** a CSPRNG delay in [DECOY_END_MIN_MS, DECOY_END_MAX_MS) */
export function decoyEndDelayMs(rand: () => number = secureRandomUnit): number {
  const u = Math.min(Math.max(Number(rand()) || 0, 0), 0.999999999);
  return DECOY_END_MIN_MS + Math.floor(u * (DECOY_END_MAX_MS - DECOY_END_MIN_MS));
}

export class DecoyEnd {
  private chain: Promise<unknown> = Promise.resolve();
  constructor(private real: Pick<VeilStorage, 'get' | 'set'>) {}
  private locked<T>(fn: () => Promise<T>): Promise<T> {
    const run = this.chain.catch(() => undefined).then(fn);
    this.chain = run.catch(() => undefined);
    return run;
  }
  /** null = no record (a new install or after a wipe); [] = the record, nothing pending */
  private async readRaw(): Promise<DecoyEndEntry[] | null> {
    const raw = await this.real.get(DECOY_END_KEY);
    if (raw === null || raw === undefined) return null;
    try {
      const v = JSON.parse(raw) as EndRecord;
      if (v?.v !== 1 || !Array.isArray(v.q)) return [];
      return v.q.filter((e) => e && typeof e.phrase === 'string' && typeof e.veilId === 'string').slice(-DECOY_END_MAX_ENTRIES);
    } catch { return []; }
  }
  private async writeRaw(q: DecoyEndEntry[]): Promise<void> {
    const body = JSON.stringify({ v: 1, q });
    const padLen = Math.max(0, DECOY_END_LEN - body.length - ',"p":""'.length);
    const out = JSON.stringify({ v: 1, q, p: '0'.repeat(padLen) });
    if ((await this.real.set(DECOY_END_KEY, out)) === false) throw new Error('The pending record could not be stored.');
  }
  /** the pending entries ([] when none) */
  read(): Promise<DecoyEndEntry[]> { return this.locked(async () => (await this.readRaw()) ?? []); }
  /** every install has the record: written (empty) when missing. An unreadable store is left as it is. */
  ensurePresent(): Promise<void> {
    return this.locked(async () => {
      const cur = await this.readRaw().catch(() => undefined);
      if (cur === null) await this.writeRaw([]);
    });
  }
  /** adds an entry (a decoy whose code is being removed). Throws when the store refuses (the caller then keeps the
   *  decoy's records: they are its only way to delete the account later) */
  add(e: DecoyEndEntry): Promise<void> {
    return this.locked(async () => {
      const cur = ((await this.readRaw()) ?? []).filter((x) => x.veilId !== e.veilId);
      await this.writeRaw([...cur, { phrase: e.phrase, veilId: e.veilId }].slice(-DECOY_END_MAX_ENTRIES));
    });
  }
  /** an entry is done (deleted, or nothing left to delete) */
  done(veilId: string): Promise<void> {
    return this.locked(async () => {
      const cur = await this.readRaw();
      if (cur === null) return; // wiped meanwhile: nothing is written back
      await this.writeRaw(cur.filter((x) => x.veilId !== veilId));
    });
  }
}

/** the decoy code goes: its phrase is noted for the delayed account delete FIRST, then its records go (DecoyAux.clearDecoy) */
export async function endDecoy(aux: DecoyAux, end: DecoyEnd, alsoRecord = false): Promise<DecoyEndEntry | null> {
  const d = await aux.read().catch(() => null);
  let entry: DecoyEndEntry | null = null;
  if (d) {
    entry = { phrase: d.phrase, veilId: d.veilId };
    await end.add(entry); // throws: the decoy's records stay (they are needed to delete its account)
  }
  await aux.clearDecoy(alsoRecord);
  return entry;
}

export type DecoyDeleteResult = 'deleted' | 'gone' | 'retry';

/**
 * Deletes one decoy account on the relay with ITS OWN login and identity: a fresh client (`clients()` makes an auth
 * and a relay client over an in-memory store, never the real one), sign-in with the phrase-derived credentials, then
 * the normal account delete signed by the decoy identity. 'deleted' (200 / 410), 'gone' (its credentials no longer
 * sign in: there is nothing left to delete), 'retry' (offline, a timeout, a server error, a refusal to retry later).
 */
/** b77t2 (info): only a DEFINITE "no such account" answer to the decoy's sign-in drops its pending delete — the relay's
 *  401 (its only 401 at sign-in: "Invalid email or password", and the credentials come from the decoy's phrase, so
 *  the account is gone) or an explicit account_deleted / account_not_found. A 400, 403 or 404 (a proxy, an older
 *  relay, a malformed answer) is tried again later: dropping the entry on it left the decoy's account on the relay. */
export function decoyLoginSaysGone(err: unknown): boolean {
  const status = Number((err as { status?: unknown } | null)?.status);
  const code = (err as { code?: unknown } | null)?.code;
  return status === 401 || code === 'invalid_login' || code === 'account_deleted' || code === 'account_not_found';
}

export async function deleteDecoyAccount(e: DecoyEndEntry, clients: () => { auth: Pick<Base44Auth, 'login' | 'deleteAccount'>; relay: VeilRelay }): Promise<DecoyDeleteResult> {
  const { auth, relay } = clients();
  try {
    await silentLogin({ auth: auth as Base44Auth, relay }, e.phrase);
  } catch (err) {
    return decoyLoginSaysGone(err) ? 'gone' : 'retry';
  }
  let seed: string;
  try { seed = (await restoreIdentity(e.phrase, e.veilId)).ikSeedB64; } catch { return 'gone'; } // a phrase that no longer matches: nothing to sign with
  try {
    await auth.deleteAccount([e.veilId], { veilId: e.veilId, sign: (m) => ikSign(seed, m) });
    return 'deleted';
  } catch {
    return 'retry';
  }
}
