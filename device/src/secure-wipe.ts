/**
 * @veil/device — b93 P2 anti-forensics: overwrite-before-delete.
 *
 * The Sept 20 roadmap item: duress + sign-out wipes must OVERWRITE key
 * material, not just dereference it. A bare `remove()` is a logical delete —
 * on iOS the backing store (SQLite/MMKV/keychain-backed adapter) keeps the
 * plaintext bytes in its file until the region is reused, so a Cellebrite-
 * class logical extraction of the store file reads the "deleted" keyvault,
 * session keys and ratchet states verbatim.
 *
 * `secureRemove` first rewrites the key's value IN PLACE with a same-length
 * block of zeroes — forcing the storage engine to overwrite the stored
 * record with junk — and only then deletes the key. After the pass the
 * store file contains zeros where the key material lived, not the keys.
 * (Flash wear-leveling still applies below the file layer; this closes the
 * application-layer gap, which is what a logical forensic extraction sees.)
 *
 * Best-effort by design: a failed overwrite still proceeds to the delete,
 * and callers under duress must never be blocked by a storage hiccup.
 */

import type { VeilStorage } from '../../crypto-core/src/index';

/**
 * Batch G (round-5 review R5-3-04 / R4-4-31): keys whose READ is biometric-gated
 * in hardware mode. Reading one raises Face ID — under duress that is a tell —
 * so a wipe overwrites and deletes them blind and checks them by listing only.
 */
export const GATED_KEYS: readonly string[] = ['veil_keyvault_identity'];

/** b70 (audit PRIM-3): is the gated key biometric-gated RIGHT NOW (hardware
 *  mode)? Only then is it removed blind. In the other modes it is a plain
 *  entry and is overwritten like every other key. Unset = assume gated. */
let gatedNow: () => boolean = () => true;
export function setGatedKeysActive(fn: () => boolean): void {
  gatedNow = fn;
}

/**
 * b75 (audit DEV-L1): how many zeros overwrite a key. A sealing store answers with the
 * length of a value stored UNSEALED (left from before b75), 0 for a sealed one (its key
 * is destroyed by the wipe's shred). Reading through get() instead queued the store's
 * background migration of an unsealed value, which made a new container key after the
 * shred and re-sealed the value under it.
 */
async function zeroFillLength(storage: VeilStorage, key: string): Promise<number> {
  const plain = (storage as unknown as { plainLength?: (k: string) => Promise<number> }).plainLength;
  if (typeof plain === 'function') return plain.call(storage, key);
  const cur = await storage.get(key);
  return typeof cur === 'string' ? cur.length : 0;
}

/**
 * b75 round 3 (audit DV-2): the overwrite itself. A store that knows it is a wipe's zero-fill
 * (KeychainStorage.zeroFill: an explicit call, past the write freeze, overwriting only a value
 * stored unsealed) gets that; zero-fills used to be recognised by their VALUE, so any empty or
 * all-zero write skipped the freeze, the post-wipe barrier and the sealing. A plain storage
 * gets a same-length block of zeros.
 */
async function zeroFill(storage: VeilStorage, key: string, len: number): Promise<void> {
  const zf = (storage as unknown as { zeroFill?: (k: string, n: number) => Promise<void> }).zeroFill;
  if (typeof zf === 'function') { await zf.call(storage, key, len); return; }
  await storage.set(key, '0'.repeat(len));
}

/** Zero-fill a key in place, then delete it. */
export async function secureRemove(storage: VeilStorage, key: string): Promise<void> {
  if (GATED_KEYS.includes(key) && gatedNow()) {
    // Batch H (round-6 review R6-1-02): no overwrite. In Android hardware mode a
    // write of this key wraps it with the hardware key, which shows a biometric
    // prompt (a tell during a duress wipe). The stored value is a wrapped blob;
    // the app also resets the hardware wrap key at every wipe (crypto-shred), so
    // a surviving copy can never be unwrapped.
    try { await storage.remove(key); } catch { /* already gone */ }
    return;
  }
  let len = 0;
  try { len = await zeroFillLength(storage, key); } catch { /* unreadable — delete anyway */ }
  if (len > 0) {
    try { await zeroFill(storage, key, len); } catch { /* overwrite is best-effort */ }
  }
  try { await storage.remove(key); } catch { /* already gone */ }
}

/**
 * b71 (audit): overwrite and delete many keys with ONE index update at the end
 * (KeychainStorage.removeMany), instead of rewriting both index copies once per
 * key. The keys go in the order given, so the caller puts the most important
 * first. Falls back to secureRemove per key on a storage without removeMany.
 */
export async function secureRemoveMany(storage: VeilStorage, keys: string[]): Promise<void> {
  const many = (storage as unknown as { removeMany?: (k: string[]) => Promise<void> }).removeMany;
  if (typeof many !== 'function') {
    for (const k of keys) await secureRemove(storage, k);
    return;
  }
  for (const k of keys) {
    if (GATED_KEYS.includes(k) && gatedNow()) continue; // removed blind below (R6-1-02)
    let len = 0;
    try { len = await zeroFillLength(storage, k); } catch { /* unreadable */ }
    if (len > 0) { try { await zeroFill(storage, k, len); } catch { /* best-effort */ } }
  }
  try { await many.call(storage, keys); } catch { for (const k of keys) { try { await storage.remove(k); } catch { /* already gone */ } } }
}

/**
 * Batch E (Superagent round 3, F-5): wipe every key under a prefix (except the
 * kept ones), then VERIFY: every key that was there is read back, removed again
 * if it is still readable, and counted if it survives. Returns that count
 * (0 = clean). Never throws — callers under duress must not be blocked.
 * Batch I (local review V-04): -1 = UNKNOWN (the keys couldn't be listed), never
 * reported as clean.
 */
export const WIPE_UNKNOWN = -1;

/** b75 (audit AL-6): after the container key is shredded a sealed entry reads as
 *  missing, so the verify pass asks the store whether the entry is still there */
async function stillStored(storage: VeilStorage, k: string): Promise<boolean> {
  const present = (storage as unknown as { present?: (k: string) => Promise<boolean> }).present;
  if (typeof present === 'function') return present.call(storage, k);
  return (await storage.get(k)) !== null;
}
/** b77k2 (IP77-5): what the platform store holds under a prefix (KeychainStorage.diskKeys), so a
 *  wipe's sweep never touches the Nothing-at-Rest memory session (the flip's verify pass runs while
 *  it is live; every other wipe has already dropped it at its shred). Other storages: keys(). */
async function listStored(storage: VeilStorage, prefix: string): Promise<string[]> {
  const disk = (storage as unknown as { diskKeys?: (p: string) => Promise<string[]> }).diskKeys;
  if (typeof disk === 'function') return disk.call(storage, prefix);
  return storage.keys(prefix);
}
export async function wipeAndVerify(storage: VeilStorage, prefix: string, keep: string[] = []): Promise<number> {
  let doomed: string[] = [];
  try { doomed = (await listStored(storage, prefix)).filter((k) => !keep.includes(k)); } catch { return WIPE_UNKNOWN; }
  // b71 (review): one batch with one index update. Per key it took about four
  // keychain writes each, so a duress wipe ran long behind the lock screen.
  // The secrets go first.
  // b76 (one-time prekeys): the one-time prekey private keys (veil_opk_k_*) go with the secrets
  const first = (k: string) => (k === 'veil_keyvault_identity' ? 0 : /^veil_(rk_|gk_|msgcache_|notes_key|opk_k_)/.test(k) ? 1 : 2);
  await secureRemoveMany(storage, [...doomed].sort((a, b) => first(a) - first(b)));
  try { for (const k of await listStored(storage, prefix)) if (!keep.includes(k) && !doomed.includes(k)) doomed.push(k); } catch { /* listing failed: verify what we know */ }
  let stuck = 0;
  let listed: string[] | null = null;
  for (const k of doomed) {
    let still = false;
    if (GATED_KEYS.includes(k)) {
      // Batch G (R5-3-04): never read a gated key; it is "still there" if still listed
      try { listed = listed ?? await listStored(storage, prefix); still = listed.includes(k); } catch { still = false; }
    } else {
      try { still = await stillStored(storage, k); } catch { still = false; }
    }
    if (!still) continue;
    await secureRemove(storage, k);
    if (GATED_KEYS.includes(k)) { try { if ((await listStored(storage, prefix)).includes(k)) stuck += 1; } catch { /* listing failed */ } continue; }
    try { if (await stillStored(storage, k)) stuck += 1; } catch { /* unreadable counts as gone */ }
  }
  return stuck;
}

/** Zero-fill + delete every key under a prefix (rk, gk, msgcache, ...). */
export async function secureRemovePrefix(storage: VeilStorage, prefix: string): Promise<void> {
  let keys: string[] = [];
  try { keys = await storage.keys(prefix); } catch { return; }
  await secureRemoveMany(storage, keys); // b71 (audit): one index update, not one per key
}
