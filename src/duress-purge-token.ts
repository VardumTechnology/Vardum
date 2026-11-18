/**
 * b77t (audit 5 L-5 / IH C-08): the pre-authorised duress purge, app side.
 *
 * The relay purges an account's records only with the primary identity's signed proof (b74 VAR-12), made in
 * memory at the moment of the duress wipe. With no identity in memory (Nothing at Rest at the lock screen, a
 * cancelled Face ID in hardware mode) there was no proof and the purge was skipped. Now, while the identity IS
 * in memory and the app is unlocked, the app mints a purge token (relay.ts mintDuressPurgeToken: the identity
 * signs a relay nonce; one token per account, a new mint replaces the old one) and keeps it in a kept record
 * (DURESS_PURGE_TOKEN_KEY: Nothing at Rest keeps it, every wipe removes it). The duress wipe reads it in its
 * capture phase and, when it can't sign a proof, purges with it (relay.ts duressPurgeWithToken: no login, single
 * use), then deletes the stored copy whatever the answer.
 *
 * When the token is (re)minted: at an unlock with the real identity in memory, when the stored one is missing,
 * belongs to another account or identity (a sign-in elsewhere, an identity reset), or is over a day old (a
 * token used or replaced elsewhere is dead, and the relay offers no "is it still live" check: a daily re-mint
 * bounds how long a dead one is relied on).
 * When it is revoked: sign-out, wipe-device, account delete and self-destruct (the wipe's remote phase, while the
 * login is still held in memory: revokePurgeTokenRemote); the account delete also drops it on the relay.
 */
import { mintDuressPurgeToken, duressPurgeWithToken, revokeDuressPurgeToken, type PrimarySigner, type VeilRelay } from '../vendor/device/src/relay';

/** kept (container-key.ts CK_KEPT_KEYS): survives the Nothing-at-Rest departure wipe, removed by every wipe */
export const DURESS_PURGE_TOKEN_KEY = 'veil_duress_purge_v1';
/** a stored token older than this is minted again at the next unlock */
export const PURGE_TOKEN_REFRESH_MS = 24 * 60 * 60 * 1000;

type Store = { get(k: string): Promise<string | null>; set(k: string, v: string): Promise<unknown>; remove(k: string): Promise<unknown> };
type PurgeRelay = Pick<VeilRelay, 'invoke' | 'invokeAnon'>;

interface StoredToken { v: 2; token: string; at: number; bind: string }

/** which account and identity a token belongs to (a hash: the kept record names neither) */
async function bindingOf(userId: string, veilId: string): Promise<string> {
  const h = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(`vardum-purge-bind-v1:${userId}:${veilId}`) as unknown as BufferSource));
  return [...h.slice(0, 12)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

async function readStored(storage: Pick<Store, 'get'>): Promise<StoredToken | null> {
  try {
    const raw = await storage.get(DURESS_PURGE_TOKEN_KEY);
    if (!raw) return null;
    const v = JSON.parse(raw) as Partial<StoredToken>;
    if (v?.v !== 2 || typeof v.token !== 'string' || !/^[0-9a-f]{64}$/.test(v.token)) return null;
    return { v: 2, token: v.token, at: Number(v.at) || 0, bind: String(v.bind ?? '') };
  } catch {
    return null;
  }
}

/** whether a new token should be minted now (missing, another account/identity, or stale) */
export async function purgeTokenNeedsMint(storage: Pick<Store, 'get'>, userId: string, veilId: string, now = Date.now()): Promise<boolean> {
  const cur = await readStored(storage);
  if (!cur) return true;
  if (cur.bind !== (await bindingOf(userId, veilId))) return true;
  return !(cur.at > 0 && now - cur.at < PURGE_TOKEN_REFRESH_MS && cur.at <= now + 60_000);
}

/**
 * Mints and stores a token when one is needed (identity in memory: `signer` is the real primary identity).
 * Never throws; returns whether a new token is now stored. `force` mints whatever is stored.
 */
export async function refreshPurgeToken(d: {
  relay: PurgeRelay;
  storage: Store;
  userId: string | null;
  signer: PrimarySigner | null;
  force?: boolean;
}): Promise<boolean> {
  try {
    if (!d.userId || !d.signer) return false;
    if (!d.force && !(await purgeTokenNeedsMint(d.storage, d.userId, d.signer.veilId))) return false;
    const token = await mintDuressPurgeToken(d.relay as VeilRelay, d.signer, d.userId);
    const rec: StoredToken = { v: 2, token, at: Date.now(), bind: await bindingOf(d.userId, d.signer.veilId) };
    await d.storage.set(DURESS_PURGE_TOKEN_KEY, JSON.stringify(rec));
    return true;
  } catch {
    return false;
  }
}

/** the stored token, or null (a local read; the duress wipe's capture phase) */
export async function readPurgeToken(storage: Pick<Store, 'get'>): Promise<string | null> {
  return (await readStored(storage))?.token ?? null;
}

/**
 * The duress wipe's purge with the stored token (DuressRelay.purgeWithToken): the relay call (no login), then
 * the stored copy is deleted whatever the answer (used: dead; refused: useless; offline: this wipe is the last
 * chance anyway, and nothing may outlive a duress wipe). Never throws; resolves the relay's answer.
 */
export async function purgeWithStoredToken(relay: PurgeRelay, storage: Pick<Store, 'remove'>, token: string): Promise<{ ok: boolean; status: number }> {
  try {
    const r = await duressPurgeWithToken(relay as VeilRelay, token);
    return { ok: r.ok, status: r.status };
  } finally {
    await Promise.resolve().then(() => storage.remove(DURESS_PURGE_TOKEN_KEY)).catch(() => undefined);
  }
}

/** the account's token is revoked on the relay (signed in) and the stored copy goes. Never throws.
 *  b77t2 (CL-3): the relay wants the token itself (a bearer token alone can't revoke it): `purgeToken` when the
 *  caller read it before an erase, else the stored copy. */
export async function revokePurgeTokenRemote(relay: PurgeRelay, storage?: Partial<Pick<Store, 'get' | 'remove'>> | null, purgeToken?: string | null): Promise<boolean> {
  let ok = false;
  const token = purgeToken ?? (storage?.get ? await readPurgeToken(storage as Pick<Store, 'get'>).catch(() => null) : null);
  try { await revokeDuressPurgeToken(relay as VeilRelay, { purgeToken: token }); ok = true; } catch { /* offline, or no token: the relay keeps it until a new mint or the account delete */ }
  if (storage?.remove) await Promise.resolve().then(() => storage.remove?.(DURESS_PURGE_TOKEN_KEY)).catch(() => undefined);
  return ok;
}
