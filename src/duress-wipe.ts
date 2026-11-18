/**
 * Batch I (local security review 19 Oct 2026, V-01): the duress wipe.
 *
 * The duress branch used to await the relay (session purge, per-thread end,
 * vault and note deletes) BEFORE it erased anything on the phone, and the relay
 * client has no deadline. A stalled or malicious relay held the local erase
 * back, and killing the app in that window kept every local secret.
 *
 * Now, in three phases:
 *  1. capture (local reads only): the account id, each thread's write secret,
 *     the saved-photo ids and the push target, which the wipe would delete;
 *     b75 (audit AL-4): under ONE hard deadline (CAPTURE_MS) — a slow or stalled
 *     read can no longer hold the erase back; whatever was not read in time is
 *     simply not used (the signed purge already covers the account);
 *  2. local erase: b75 (audit AL-3 / AL-6 / AL-9): eraseLocal(), the one routine
 *     every wipe uses — the pending marker is already set; the container key is
 *     destroyed first (a crypto-shred: every sealed entry is unreadable from that
 *     moment), then the hardware wrap key and the hardware-gated identity entry,
 *     then every veil_* key (overwrite, delete, verify), then every file Vardum
 *     left. No network call can run before this phase ends. b70 (audit VAR-12):
 *     the account login goes too; the cleanup below uses a copy held only in
 *     memory, and the token is revoked on the server when it ends;
 *  3. remote cleanup, in the background and bounded: Photos (an OS dialog on
 *     some phones), the session purge, per-thread end, vault and note records,
 *     and the push registration, using only what phase 1 captured. Each call
 *     gets a deadline and the whole phase has one. If the app is killed here,
 *     the server copies stay: they are ciphertext the server can't read, and
 *     the phone no longer holds the keys. b75 (audit AL-7): a push registration
 *     that could not be dropped leaves a non-identifying marker outside the wipe;
 *     every launch then turns this phone's push delivery off locally again until
 *     a new registration is made (retryPushUnregister).
 *
 * b75 (audit AL-9): self-destruct, sign-out, wipe-device, delete-account and the
 * erase after N wrong passwords use this same routine (without the remote phase's
 * account cleanup), so none is weaker than the duress wipe.
 */

import type { VeilStorage } from '../vendor/crypto-core/src/index';
import { wipeAndVerify, secureRemove, GATED_KEYS } from '../vendor/device/src/secure-wipe';
import { readPendingMedia, stashPendingMedia, SAVED_MEDIA_PENDING_KEY, type MediaWipeResult } from './saved-media-pending';
import type { PurgeProof } from '../vendor/device/src/relay';
import type { ChatDelivery } from '../vendor/crypto-core/src/index';
import { CK_NAME_MAP_KEY, CK_KEPT_KEYS, CK_PRESENT_KEY } from '../vendor/device/src/container-key'; // b77u (U-M10); b77u2 (UC-L2)
import { NAR_KEEP_KEYS } from './nar-memory'; // b77u2 (UC-L2)
import { clearFailedBodyCache } from '../vendor/crypto-core/src/ratchet'; // b77s (audit 4 CR-1 / A-04)

export interface DuressRelay {
  /** b74 (audit VAR-12): the relay purges only with the primary identity's proof */
  sessionPurge(userId: string, proof: PurgeProof): Promise<unknown>;
  sessionList(userId: string, cursor: undefined): Promise<unknown>;
  sessionEnd(token: string, writeSecret: string | null, userId: string): Promise<unknown>;
  entityList(entity: string, params: Record<string, string | number>): Promise<unknown>;
  entityDelete(entity: string, id: string, opts?: { wipe?: boolean }): Promise<unknown>;
  /** b77 (sealed sender): end a 1:1 mailbox (my inbound with my read cap, the peer's with my
   *  send cap) — anonymous, no account */
  sealedEnd?(mbox: string, cap: string): Promise<unknown>;
  /** b77t (audit 5 L-5 / IH C-08): the account purge with a token minted earlier, while the identity was in
   *  memory (src/duress-purge-token.ts). Used only when no signed proof could be made now. */
  purgeWithToken?(userId: string, token: string): Promise<unknown>;
}

/** b75: what the local erase needs (every wipe, Nothing-at-Rest included) */
export interface EraseDeps {
  storage: VeilStorage;
  shredHardwareKey(): Promise<void>;
  /** the file sweep. b77u (audit 6 U-M13): may resolve to the number of entries it could not remove (-1 = a folder
   *  could not be listed; local-files sweepAllLocalFiles); void = not reported (counted as clean) */
  clearFileCache(): Promise<void | number>;
  /** b75 (audit AL-10): records kept outside the secure store (the launch flag, the
   *  lock's epoch mirror) */
  forgetOutsideRecords?(): Promise<void>;
}

export interface DuressDeps<T> extends EraseDeps {
  relay: DuressRelay;
  /** the signed-in account id, read from the stored login (no network) */
  userId(): Promise<string | null>;
  localTokens(): Promise<string[]>;
  writeSecretOf(token: string): Promise<string | null>;
  capturePushTarget(): Promise<T | null>;
  deleteSavedMedia(ids: string[]): Promise<void>;
  /** b75 (audit AL-7): resolves true once the relay row is gone (false/throw = not dropped) */
  dropPushRegistration(target: T | null): Promise<void | boolean>;
  /** b70 (VAR-12): read the stored login (no network) */
  captureLogin?(): Promise<unknown>;
  /** b70 (VAR-12): keep the captured login in memory only, for the cleanup */
  holdLogin?(login: unknown): void;
  /** b70 (VAR-12): revoke the login on the server and forget it */
  endLogin?(): Promise<void>;
  /** b75 (audit DEV-I1): false = a failed saved-media delete was NOT retried at later launches (the duress wipe).
   *  b77u (audit 6 R4 #23): IGNORED now — every wipe, the duress wipe included, keeps the pending list until the
   *  files are gone, and the next launch retries (finishPendingMedia, at most PENDING_MEDIA_MAX_TRIES launches):
   *  photos left in the gallery are a bigger tell than a delete prompt. Kept so older callers still compile. */
  retryMediaLater?: boolean;
  /** b74 (audit VAR-12): sign the relay purge's proof with the identity key, in memory,
   *  before the erase destroys that key (null: no identity at hand — the purge is skipped) */
  signPurgeProof?(userId: string): Promise<PurgeProof | null>;
  /** b77t (audit 5 L-5 / IH C-08): the pre-authorised purge token stored while the identity was in memory
   *  (a local read; null: none). The duress code at the lock screen with no identity in memory (Nothing at
   *  rest, a cancelled Face ID) used to skip the purge. */
  capturePurgeToken?(): Promise<string | null>;
  /** b77t (audit 5 L-5): revoke the account's purge token on the relay (signed in, on the login held in memory),
   *  run in the remote phase just before endLogin — the wipes that end the account's use of this phone (sign-out,
   *  wipe-device, account delete, self-destruct). b77u (audit 6 R4 #22): the duress wipe too, once its purge ran
   *  with the signed proof (the token, single-use, was not spent then and would outlive the purge); a purge made
   *  WITH the token spent it (nothing to revoke). `token` = the one captured before the erase (null: none read). */
  revokePurgeToken?(token?: string | null): Promise<unknown>;
  /** b77 (sealed sender): a 1:1 chat's delivery capabilities, read in the capture phase (local)
   *  so the remote phase can end its mailboxes after the erase (null: none / not a 1:1 chat) */
  deliveryOf?(token: string): Promise<ChatDelivery | null>;
  /** b77g (NaR-1): the chats' capabilities already in memory (SessionStore.cachedDeliveries, a
   *  snapshot taken before the wipe began) — ended whatever the keystore's speed; deliveryOf is
   *  asked only for the chats missing from it */
  cachedDeliveries?: Map<string, ChatDelivery>;
}

export interface DuressOptions {
  /** deadline for one remote step */
  callMs: number;
  /** deadline for the whole remote phase */
  totalMs: number;
  /** b75 (audit AL-4): deadline for the whole capture phase (local reads) */
  captureMs: number;
}

/** b77u (audit 6 U-M10 / U-M13): what the local erase could not finish */
export interface EraseReport {
  /** the container key could not be destroyed (after retries): its records were deleted directly instead */
  shredFailed: boolean;
  /** the file sweep: entries it could not remove (0 = clean, -1 = a folder could not be listed), after one retry */
  filesLeft: number;
  /** the wipe-pending marker was kept: the next launch runs the wipe again to finish it */
  pendingNextLaunch: boolean;
}

export interface DuressResult {
  /** keys the local erase could not remove (0 = clean) */
  leftAfterWipe: number;
  /** b77u (audit 6 U-M10 / U-M13): for the app to show. `files.filesLeft` != 0 means files Vardum wrote may still be
   *  on the phone; `pendingNextLaunch` that the next launch finishes the wipe (the marker was kept) */
  report: EraseReport;
  /** b71 (audit): the saved Photos / folder files — 'failed' (refused, no access,
   *  timed out) is not clean; the pending list then stays for the next launch */
  media: Promise<MediaWipeResult>;
  /** the bounded remote cleanup; callers don't wait for it */
  remote: Promise<void>;
}

/** b70 (audit VAR-12): nothing survives a duress wipe on the phone, the login
 *  included (the server cleanup runs on an in-memory copy) */
export const DURESS_KEEP: string[] = [];
/** the "a wipe is running" marker (set first; a launch finishes a killed wipe). b75: stored
 *  unsealed, so it still reads after the container key is gone */
export const WIPE_PENDING_KEY = 'veil_wipe_pending';
/** b75 (audit AL-7): "this phone's push registration may still be live on the relay".
 *  audit VAR-15 (b77m): NO LONGER WRITTEN. An unsealed marker outside the wipe that survived an iOS
 *  reinstall proved a Vardum wipe had happened (a new install never has it). Every launch with no
 *  identity now turns push off locally instead (retryPushUnregister), which a fresh install does
 *  too, so nothing tells the two apart. The name stays only so a launch removes a marker an older
 *  build left. */
export const PUSH_UNREG_PENDING_KEY = 'vardum_push_unreg_pending';
/** b75 (audit AL-4): the capture phase as a whole — local reads, so normally
 *  milliseconds; this bounds a store that stalls */
export const CAPTURE_MS = 1500;
const DEFAULTS: DuressOptions = { callMs: 4000, totalMs: 20000, captureMs: CAPTURE_MS };
/** b74 (audit VAR-12): the most the purge-proof signature may hold the erase back (it is a
 *  local Ed25519 signature — milliseconds; this only bounds a misbehaving signer) */
const PURGE_SIGN_MS = 1000;
/** b75 (AL-7): tries of the relay-side push drop inside the remote budget */
const PUSH_DROP_TRIES = 4;
/** b77u (audit 6 U-M10): tries of the crypto-shred before the records it protects are deleted directly */
export const SHRED_TRIES = 3;
/** b77u (audit 6 U-M11, R4 #18 / #21, IH W11): records outside the veil_ prefix a FULL wipe removes too, so a wiped
 *  phone's record names match a fresh install's: the UnifiedPush choice migration flag (unifiedpush.ts
 *  UP_CHOICE_MIGRATED_KEY, raw) and the decoy push hold (decoy-push.ts PUSH_HOLD_KEY, sealed: its key dies with the
 *  shred, but its NAME stayed). Nothing-at-Rest keeps both (its keep list). After a wipe the next launch writes the
 *  hold '0' again, as a fresh install's first launch does, and the flag at the first push registration (the
 *  migration then finds nothing a pre-b77m build saved, or clears a distributor that survived the wipe). */
export const ERASE_OUTSIDE_KEYS: readonly string[] = ['vardum_up_choice_v1', 'vardum_push_hold_v1'];

function within<T>(p: Promise<T>, ms: number): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const late = new Promise<never>((_, reject) => { timer = setTimeout(() => reject(new Error('duress: step timed out')), Math.max(0, ms)); });
  return Promise.race([p, late]).finally(() => clearTimeout(timer));
}

/**
 * b75 (audit AL-3 / AL-6 / AL-9 / AL-10): the ONE local erase. Order:
 *   1. crypto-shred: the container key (full wipe) — every sealed entry is
 *      unreadable from here on; then the hardware wrap key; then the
 *      hardware-gated identity entry (removed blind, no prompt). These go before
 *      any other key is touched (a wipe cut short anywhere after this point leaves
 *      nothing that opens). Nothing-at-Rest (`rotate`) keeps a few entries: b75 round 2
 *      (audit D1 / D8) they live under the store's kept slot, so it destroys only the
 *      main key (no new key is made, nothing is re-sealed before the destroy);
 *   2. every veil_* key except `keep`: overwrite, delete, verify;
 *   3. the file cache and the records kept outside the store.
 * Never throws; returns the keys that could not be removed (-1 = unknown).
 */
export async function eraseLocal(d: EraseDeps, opts: { keep?: string[]; rotate?: boolean; forgetOutside?: boolean; report?: EraseReport } = {}): Promise<number> {
  const report = opts.report ?? { shredFailed: false, filesLeft: 0, pendingNextLaunch: false };
  // b77s (audit 4 CR-1 / A-04): the ratchet's in-memory cache of tampered-copy message keys goes
  // first, synchronously, before any await (it held keys of never-opened messages past every wipe)
  try { clearFailedBodyCache(); } catch { /* best-effort */ }
  const keep = [...new Set([...(opts.keep ?? []), WIPE_PENDING_KEY])];
  const st = d.storage as unknown as { cryptoShred?: () => Promise<boolean>; rotateSealKey?: (k: string[]) => Promise<boolean> };
  // 1. crypto-shred, before anything else. b77u (audit 6 U-M10, R4 #17): a failed shred used to be swallowed and the
  // wipe went on as if every sealed record were unreadable. Now it is retried; if the key still can't be destroyed,
  // the records it seals are deleted directly (overwrite, delete, verify) BEFORE anything else continues, and a full
  // wipe keeps its pending marker so the next launch runs it again (and retries the shred).
  let destroyed = false;
  for (let i = 0; i < SHRED_TRIES && !destroyed; i++) {
    try {
      if (opts.rotate) await st.rotateSealKey?.(keep); // b75 round 2 (audit D1): Nothing-at-Rest destroys the main key only
      else await st.cryptoShred?.();
      destroyed = true;
    } catch { /* tried again */ }
  }
  let left = 0;
  let swept = false;
  if (!destroyed) {
    report.shredFailed = true;
    if (!opts.rotate) { try { await d.storage.set(WIPE_PENDING_KEY, '1'); } catch { /* the caller set it first */ } }
    try { left = await wipeAndVerify(d.storage, 'veil_', keep); swept = true; } catch { left = -1; }
    // the sealed list of blinded record names still opens under the live key: it goes too (the index copies then list nothing)
    try { await secureRemove(d.storage, CK_NAME_MAP_KEY); } catch { /* the sweep below retries */ }
  }
  try { await d.shredHardwareKey(); } catch { /* best-effort, silent */ }
  for (const g of GATED_KEYS) {
    if (!keep.includes(g)) { try { await secureRemove(d.storage, g); } catch { /* the sweep retries it */ } }
  }
  // 2. every other key
  if (!swept || left !== 0) { try { left = await wipeAndVerify(d.storage, 'veil_', keep); } catch { left = -1; } }
  // Batch I (V-04): -1 means the keys couldn't be listed, so nothing is known
  // to be gone. One more pass; the result stays "not clean" (left !== 0).
  if (left < 0) { try { left = await wipeAndVerify(d.storage, 'veil_', keep); } catch { /* still unknown */ } }
  // b77u (audit 6 U-M11): a full wipe leaves no record name a fresh install doesn't have
  if (!opts.rotate) {
    for (const k of ERASE_OUTSIDE_KEYS) {
      if (keep.includes(k)) continue;
      try { await secureRemove(d.storage, k); } catch { /* counted below */ }
      try { if ((await d.storage.get(k)) !== null || await stillPresent(d.storage, k)) { if (left >= 0) left += 1; } } catch { /* unreadable */ }
    }
  }
  // 3. files and outside records. b77u (audit 6 U-M13, R4 #20): the sweep's count is no longer dropped: what it could
  // not remove (or list) is swept once more, then reported; a full wipe keeps its pending marker for the next launch
  report.filesLeft = await sweepFiles(d);
  if (report.filesLeft !== 0) report.filesLeft = await sweepFiles(d);
  if (opts.forgetOutside !== false) { try { await d.forgetOutsideRecords?.(); } catch { /* best-effort */ } }
  // b77u merge (U-M13): stored keys left count too (the app's notice promises the next launch tries again)
  if (!opts.rotate && (report.shredFailed || report.filesLeft !== 0 || left !== 0)) {
    report.pendingNextLaunch = true;
    try { await d.storage.set(WIPE_PENDING_KEY, '1'); } catch { /* best-effort */ }
  }
  if (report.shredFailed && left >= 0) left += 1; // never reported clean
  return left;
}

/** b77u2 (UC-L2): set-up refused because the last wipe's key could still not be destroyed */
export class LeftoverWipeError extends Error {
  constructor() {
    super('The last wipe could not delete one of this phone’s storage keys, so a new identity can’t be set up safely yet. Close Vardum and open it again to retry. If this keeps happening, delete the Vardum app from this phone and install it again.');
    this.name = 'LeftoverWipeError';
  }
}

/** b77u2 (UC-L2): the records set-up keeps across the settle's shred (re-sealed under the new key) */
export const SETTLE_KEEP_KEYS: readonly string[] = Object.freeze([...new Set([...CK_KEPT_KEYS, ...NAR_KEEP_KEYS])]
  .filter((k) => k !== WIPE_PENDING_KEY && k !== CK_PRESENT_KEY && k !== 'vardum_ck_kept_v1'));

/**
 * b77u merge (U-M13): a new identity is being set up on this phone while a wipe's marker is still kept for its
 * leftovers. b77u2 (UC-L2): it used to sweep the files and drop the marker, also when the wipe had left stored keys
 * or could not destroy the container key: the new identity was then sealed under the very key the wipe was meant to
 * destroy, and no later launch retried. Now, before any identity is saved, the wipe is finished first:
 *  1. the records set-up may already have written (`keep`: the login, settings, the lock; never message keys) are
 *     read, in memory;
 *  2. the container key is destroyed again (cryptoShred, retried); if it still can't be, set-up is refused
 *     (LeftoverWipeError, the records read in 1 put back, the marker kept: the next launch and set-up try again);
 *  3. every veil_ record is overwritten, deleted and verified (wipeAndVerify), and the records read in 1 are
 *     written back, sealed under a fresh key; a record the wipe could not remove also refuses set-up;
 *  4. the files are swept again (twice if the first sweep left some); files left don't refuse set-up (they are
 *     not sealed under the container key), as before; then the marker goes.
 * Call it right after the fresh start's clearTombstones() and BEFORE startNarSession (the shred ends any memory
 * session). Returns false when no wipe was pending.
 */
export async function settleLeftoverWipe(storage: VeilStorage, sweep: () => Promise<number | void>, keep: readonly string[] = SETTLE_KEEP_KEYS): Promise<boolean> {
  if ((await storage.get(WIPE_PENDING_KEY).catch(() => null)) !== '1') return false;
  const held = new Map<string, string>();
  for (const k of keep) {
    if (k === WIPE_PENDING_KEY) continue;
    try { const v = await storage.get(k); if (v !== null && v !== undefined) held.set(k, v); } catch { /* unreadable: not kept */ }
  }
  const st = storage as unknown as { cryptoShred?: () => Promise<boolean>; endShred?: () => void };
  let destroyed = typeof st.cryptoShred !== 'function';
  for (let i = 0; i < SHRED_TRIES && !destroyed; i++) {
    try { await st.cryptoShred!(); destroyed = true; } catch { /* tried again */ }
  }
  const refuse = async (): Promise<never> => {
    try { await storage.set(WIPE_PENDING_KEY, '1'); } catch { /* still set */ }
    throw new LeftoverWipeError();
  };
  const putBack = async (): Promise<void> => {
    for (const [k, v] of held) { try { await storage.set(k, v); } catch { /* lost: set-up asks again (settings, lock) */ } }
  };
  // the old main key stands: set-up stops. A shred cut short may still have removed the kept slot, so what set-up
  // had saved is written back (the kept records only, under their own new slot); nothing else is touched
  if (!destroyed) { try { st.endShred?.(); } catch { /* best-effort */ } await putBack(); return refuse(); }
  let left = 0;
  try { left = await wipeAndVerify(storage, 'veil_', [WIPE_PENDING_KEY]); } catch { left = -1; }
  if (left < 0) { try { left = await wipeAndVerify(storage, 'veil_', [WIPE_PENDING_KEY]); } catch { left = -1; } }
  try { st.endShred?.(); } catch { /* the store makes a key at the next write anyway */ }
  await putBack(); // what set-up had saved goes back, sealed under a fresh key
  if (left !== 0) return refuse();
  let files: number | void = 0;
  try { files = await sweep(); } catch { files = -1; }
  if (typeof files === 'number' && files !== 0) { try { await sweep(); } catch { /* reported by the wipe already */ } }
  try { await storage.remove(WIPE_PENDING_KEY); } catch { /* the next launch wipes again: no identity is saved yet */ }
  return true;
}

/** b77u (U-M13): one file sweep: the entries left (0 when the sweep reports nothing, -1 when it threw) */
async function sweepFiles(d: EraseDeps): Promise<number> {
  try {
    const r = await d.clearFileCache();
    return typeof r === 'number' && Number.isFinite(r) ? r : 0;
  } catch { return -1; }
}

async function stillPresent(storage: VeilStorage, k: string): Promise<boolean> {
  const present = (storage as unknown as { present?: (k: string) => Promise<boolean> }).present;
  return typeof present === 'function' ? present.call(storage, k) : false;
}

/** b75 (audit AL-9): the saved-media list, copied outside the wiped keys before the erase.
 *  b75 round 2 (audit D9): `stash` false (the duress wipe, which never retries) only reads */
async function stashSavedMedia(storage: VeilStorage, stash = true): Promise<string[]> {
  let ids: string[] = [];
  try {
    const raw = await storage.get('veil_saved_media');
    const v = raw ? (JSON.parse(raw) as unknown) : [];
    if (Array.isArray(v)) ids = v.filter((x): x is string => typeof x === 'string');
  } catch { /* unreadable: nothing to delete */ }
  if (ids.length && stash) { try { await stashPendingMedia(storage as never, ids); } catch { /* the in-memory copy still drives this run */ } }
  // b71 (audit): plus what an earlier, cut-short wipe left in the pending list
  try { ids = [...new Set([...ids, ...(await readPendingMedia(storage as never))])]; } catch { /* none */ }
  return ids;
}

export async function runDuressWipe<T>(d: DuressDeps<T>, opts: Partial<DuressOptions> = {}): Promise<DuressResult> {
  const o = { ...DEFAULTS, ...opts };

  // ---- 0. the pending marker: a launch finishes a wipe killed from here on ----
  try { await within(Promise.resolve(d.storage.set(WIPE_PENDING_KEY, '1')), o.captureMs); } catch { /* the erase runs anyway */ }

  // ---- 1. capture: local reads only, under one hard deadline (b75, AL-4) ----
  const captureEnds = Date.now() + o.captureMs;
  const capLeft = () => Math.max(0, captureEnds - Date.now());
  let userId: string | null = null;
  let purgeProof: PurgeProof | null = null;
  let purgeToken: string | null = null; // b77t (audit 5 L-5)
  const secrets = new Map<string, string | null>();
  const deliveries: ChatDelivery[] = []; // b77 (sealed sender)
  // b77g (NaR-1): the cached capabilities first (no keystore read: a slow keystore that runs out
  // the capture deadline can't cost these chats their ends)
  const cachedCaps = d.cachedDeliveries ?? new Map<string, ChatDelivery>();
  for (const dv of cachedCaps.values()) deliveries.push(dv);
  let mediaIds: string[] = [];
  let pushTarget: T | null = null;
  let login: unknown = null;
  const capture = (async () => {
    // the cheap, important reads first: what the remote phase needs to act at all
    try { pushTarget = await d.capturePushTarget(); } catch { /* no target */ }
    try { login = (await d.captureLogin?.()) ?? null; } catch { /* no login */ }
    if (login) { try { d.holdLogin?.(login); } catch { /* cleanup just runs without it */ } }
    try { mediaIds = await stashSavedMedia(d.storage, true); } catch { /* none */ } // b77u (R4 #23): every wipe retries
    try { userId = await d.userId(); } catch { /* no login: nothing to clean remotely */ }
    // b74 (audit VAR-12): the relay purges only with the primary identity's signed proof,
    // signed in memory before the erase destroys the key (valid 10 minutes)
    if (userId && d.signPurgeProof) {
      const uid: string = userId;
      try { purgeProof = await within(d.signPurgeProof(uid), Math.min(PURGE_SIGN_MS, capLeft())); } catch { purgeProof = null; }
    }
    // b77t (audit 5 L-5 / IH C-08): no identity in memory: the token minted while it was.
    // b77u (audit 6 R4 #22): read in every case (a refused proof falls back to it; after a purge made with the proof
    // the token is revoked, so it doesn't outlive the purge)
    if (userId && d.capturePurgeToken) {
      try { purgeToken = await within(d.capturePurgeToken(), capLeft()); } catch { purgeToken = null; }
    }
    // per-thread write secrets last: one keystore read per chat, so the slowest part.
    // What is not read by the deadline is not used (the signed purge covers the account).
    try {
      for (const t of await d.localTokens()) {
        if (capLeft() <= 0) break;
        try { secrets.set(t, await within(d.writeSecretOf(t), capLeft())); } catch { secrets.set(t, null); }
        // b77 (sealed sender): the chat's mailbox capabilities, to end both mailboxes after the erase
        if (d.deliveryOf && !cachedCaps.has(t) && capLeft() > 0) { try { const dv = await within(d.deliveryOf(t), capLeft()); if (dv) deliveries.push(dv); } catch { /* not ended; the relay's sweeper retires it 30 days after this owner's last use (b77g) */ } }
      }
    } catch { /* no thread list: the relay's own list still drives the cleanup */ }
  })();
  try { await within(capture, o.captureMs); } catch { /* deadline: erase now with what was read */ }
  // b75 (AL-7) / audit VAR-15: no marker is written for a failed push drop. Every launch with no
  // identity turns push off locally (retryPushUnregister), so an offline wipe leaves no evidence.

  // ---- 2. local erase: no network before this is done ----
  // b71 (review): the pending marker stays until the hardware key and the file
  // cache are gone too. Deleted with the keys, a kill in between left those for good.
  const report: EraseReport = { shredFailed: false, filesLeft: 0, pendingNextLaunch: false };
  let leftAfterWipe = await eraseLocal(d, { keep: [...DURESS_KEEP], report });
  // b77u (audit 6 R4 #23): the pending-media list is kept by every wipe now (b75 round 2 D9 dropped it here for the
  // duress wipe, so a refused delete left the photos for good); the next launch retries until the files are gone
  // b77u (audit 6 U-M10 / U-M13): a wipe the erase could not finish keeps its marker (the next launch runs it again)
  if (!report.pendingNextLaunch) try {
    await d.storage.remove(WIPE_PENDING_KEY);
    const still = (d.storage as unknown as { present?: (k: string) => Promise<boolean> }).present;
    const there = typeof still === 'function' ? await still.call(d.storage, WIPE_PENDING_KEY) : (await d.storage.get(WIPE_PENDING_KEY)) !== null;
    if (there && leftAfterWipe >= 0) leftAfterWipe += 1;
  } catch { /* a marker left behind only re-runs the wipe at the next launch */ }

  // ---- 3. remote cleanup: background, every step bounded ----
  const stopAt = Date.now() + o.totalMs;
  const left = () => stopAt - Date.now();
  const step = async <R>(fn: () => Promise<R>): Promise<{ ok: true; value: R } | { ok: false }> => {
    const ms = Math.min(o.callMs, left());
    if (ms <= 0) return { ok: false };
    try { return { ok: true, value: await within(fn(), ms) }; } catch { return { ok: false }; }
  };
  const valueOf = <R>(s: { ok: true; value: R } | { ok: false }): R | undefined => (s.ok ? s.value : undefined);
  let resolveMedia!: (r: MediaWipeResult) => void;
  const media = new Promise<MediaWipeResult>((r) => { resolveMedia = r; });
  if (!mediaIds.length) resolveMedia('none');
  const capturedSecrets = secrets;
  const target = pushTarget as T | null;
  let purgedWithProof = false; // b77u (R4 #22)
  let tokenSpent = false;
  const remote = (async () => {
    // b63 review (I3-6): first, so the time budget can't skip it (a wiped
    // phone that keeps getting banners is a giveaway). b75 (AL-7): retried while the
    // budget lasts; the marker goes only once the relay row is known to be gone.
    if (target) {
      for (let i = 0; i < PUSH_DROP_TRIES && left() > 0; i++) {
        const r = await step(() => Promise.resolve(d.dropPushRegistration(target)));
        if (r.ok && r.value !== false) break;
        await new Promise((res) => setTimeout(res, Math.min(250 * 2 ** i, Math.max(0, left()))));
      }
    } else {
      await step(() => Promise.resolve(d.dropPushRegistration(target)));
    }
    // b77 (sealed sender): end every 1:1 chat — my inbound (read cap) and the peer's (send cap),
    // so the peers' next fetch runs their "chat ended" path. All at once, one step's deadline;
    // best effort (the relay's 30-day sweeper retires what this misses: b77g, only the owner's
    // own use keeps a mailbox alive, so the peer's sends can't hold it off)
    if (deliveries.length && d.relay.sealedEnd) {
      const end = d.relay.sealedEnd.bind(d.relay);
      await step(() => Promise.allSettled(deliveries.flatMap((dv) => [end(dv.inbound.mbox, dv.inbound.read), end(dv.outbound.mbox, dv.outbound.send)])));
    }
    if (mediaIds.length) {
      const ok = (await step(() => d.deleteSavedMedia(mediaIds))).ok;
      // b71 (audit): the pending list goes only once the files are gone (b75: and its key).
      // b77u (audit 6 R4 #23): every wipe (the duress wipe too) keeps it after a failure: the next launch retries
      if (ok) {
        await d.storage.remove(SAVED_MEDIA_PENDING_KEY).catch(() => undefined);
        await (d.storage as unknown as { shredMediaKey?: () => Promise<void> }).shredMediaKey?.().catch(() => undefined);
      }
      resolveMedia(ok ? 'clean' : 'failed');
    }
    if (userId) {
      const uid: string = userId;
      const proof = purgeProof as PurgeProof | null;
      // b77u (audit 6 R4 #22): the signed purge first; if it was refused (or there was no proof), the token
      if (proof) purgedWithProof = (await step(() => d.relay.sessionPurge(uid, proof))).ok;
      if (!purgedWithProof && purgeToken && d.relay.purgeWithToken) { const tok: string = purgeToken; tokenSpent = (await step(() => d.relay.purgeWithToken!(uid, tok))).ok; } // b77t (L-5)
      const r = valueOf(await step(() => d.relay.sessionList(uid, undefined)));
      const data = (r as { data?: unknown } | undefined)?.data;
      const list = (data as { data?: unknown[] })?.data ?? (data as { sessions?: unknown[] })?.sessions ?? data;
      for (const raw of Array.isArray(list) ? list : []) {
        if (left() <= 0) break;
        const rec = raw as Record<string, unknown>;
        const tok = String(rec.token ?? '');
        const rid = String(rec.id ?? '');
        if (!tok) continue;
        await step(() => d.relay.sessionEnd(tok, capturedSecrets.get(tok) ?? null, uid));
        if (rid) await step(() => d.relay.entityDelete('VeilSession', rid, { wipe: true })); // b77u2: the wipe bucket
      }
      for (const ent of ['VeilVault', 'VeilNote'] as const) {
        for (let guard = 0; guard < 50 && left() > 0; guard++) {
          const raw = valueOf(await step(() => d.relay.entityList(ent, { limit: 100, sort: '-created_date' })));
          const rec = raw as { data?: unknown } | undefined;
          const rows = (Array.isArray(rec?.data) ? rec!.data : (Array.isArray(raw) ? raw : [])) as { id?: string }[];
          if (!rows.length) break;
          let removed = 0;
          for (const row of rows) {
            const id = String(row?.id ?? '');
            if (!id) continue;
            if ((await step(() => d.relay.entityDelete(ent, id, { wipe: true }))).ok) removed++; // b77u2 (Info): not the 120/min bucket
          }
          if (removed === 0) break;
        }
      }
    }
  })().catch(() => undefined).finally(async () => {
    resolveMedia('failed'); // no-op once settled; covers a budget that ran out first
    // b77t (audit 5 L-5): before the login goes (the revoke needs it), with its own short deadline
    // b77u (audit 6 R4 #22): a purge wipe (the duress code) revokes the token once its purge ran with the proof (the
    // single-use token was not spent and would outlive the purge); one spent by the purge has nothing to revoke, and
    // after a purge that did not run at all the token is the account's only way to be purged later, so it stays
    const revokeNow = userId ? purgedWithProof && !tokenSpent && !!purgeToken : true;
    if (d.revokePurgeToken && revokeNow) { try { await within(d.revokePurgeToken(userId ? purgeToken : undefined), o.callMs); } catch { /* offline: a later mint or the account delete replaces it */ } }
    // b70 (VAR-12): always last, with its own short deadline, even when the
    // budget ran out: the token stops working on the server and leaves memory
    try { await within(d.endLogin?.() ?? Promise.resolve(), o.callMs); } catch { /* offline: the token is still gone from the phone */ }
  });

  return { leftAfterWipe, remote, media, report };
}

/**
 * b75 (audit AL-7): at launch, a phone whose push registration may still be live
 * on the relay (a wipe that could not reach it) turns its push delivery off again
 * locally — the UnifiedPush distributor registration and the OS push token — so no
 * "Vardum" banner arrives on a phone that looks freshly installed. The marker is
 * cleared by the next successful registration (a new identity wants push again).
 */
export async function retryPushUnregister(d: {
  storage: Pick<VeilStorage, 'get' | 'remove'>;
  /** true while this install has an identity that wants push (then nothing is done) */
  pushWanted: () => boolean;
  /** local, no network: the distributor registration and the OS push token */
  unregisterLocally: () => Promise<void>;
}): Promise<boolean> {
  // audit VAR-15 (b77m): no marker decides this any more — a launch with no identity always turns
  // push off locally (a fresh install does the same, so it proves nothing). A marker an older build
  // left is removed.
  try { if ((await d.storage.get(PUSH_UNREG_PENDING_KEY)) !== null) await d.storage.remove(PUSH_UNREG_PENDING_KEY); } catch { /* best-effort */ }
  if (d.pushWanted()) return false;
  try { await d.unregisterLocally(); } catch { /* tried again at the next launch */ }
  return true;
}
