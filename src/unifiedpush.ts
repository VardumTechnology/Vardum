/**
 * Google-free push for Android (GrapheneOS) via UnifiedPush.
 *
 * Native side: modules/vardum-unifiedpush. Loaded OPTIONALLY, so iOS and any
 * build without the module behave exactly as before (Expo push).
 *
 * The phone needs a UnifiedPush distributor app installed — ntfy (F-Droid,
 * io.heckel.ntfy). With one present, Android uses this path; without one it
 * falls back to Expo/FCM, which only works where Google Play Services exist.
 */
import { Platform } from 'react-native';

export type UpEndpoint = { url: string; pubKey: string; auth: string };

type NativeUp = {
  getDistributors(): string[];
  getSavedDistributor(): string | null;
  getAckDistributor(): string | null;
  saveDistributor(pkg: string): void;
  register(vapid: string | null): void;
  unregister(): void;
  getEndpoint(): UpEndpoint | null;
  getLastError(): string | null;
  /** b74 (VAR-03): absent on builds before b74 */
  setSilent?(on: boolean): void;
  /** b74 (audit VAR-13): the relay's push-verify code the push service kept (one-shot,
   *  10 minutes); absent on native builds before b74 */
  takePushVerifyCode?(): string | null;
  /** b77n2 (review INFO): the native silent flag can't be verified (Keystore trouble), so banners stay
   *  hidden; absent on native builds before b77n2 */
  getSilentUnverifiable?(): boolean;
};

/** ntfy is the recommended distributor (self-hostable — Vardum's own server later). */
export const NTFY_PACKAGE = 'io.heckel.ntfy';

/** Relay token prefix: lets the relay tell a UnifiedPush row from an Expo token. */
export const UP_TOKEN_PREFIX = 'up:';

let native: NativeUp | null | undefined;

function getNative(): NativeUp | null {
  if (native !== undefined) return native;
  native = null;
  if (Platform.OS !== 'android') return native;
  try {
    // same optional-load pattern as noble-subtle.ts / kdf.ts
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const emc = require('expo-modules-core') as { requireOptionalNativeModule?: <T>(name: string) => T | null };
    native = typeof emc?.requireOptionalNativeModule === 'function'
      ? emc.requireOptionalNativeModule<NativeUp>('VardumUnifiedPush')
      : null;
  } catch {
    native = null;
  }
  return native;
}

/** tests only: stand in for the native module (null = none) */
export function setUnifiedPushNativeForTests(n: NativeUp | null | undefined): void { native = n; userChoseThisRun = false; }

function distributors(): string[] {
  const n = getNative();
  if (!n) return [];
  try { return n.getDistributors() ?? []; } catch { return []; }
}

/** b74 (review VAR-03): silence (or restore) the native push banners — decoy mode must
 *  not show the real account's pings. No-op where the module is missing (iOS, older builds). */
export function setUnifiedPushSilent(on: boolean): void {
  try { getNative()?.setSilent?.(on); } catch { /* best-effort */ }
}

/** True when this phone can do Google-free push: module present AND a distributor installed. */
export function isUnifiedPushAvailable(): boolean {
  return distributors().length > 0;
}

/**
 * audit VAR-17 (b77m): the distributor is the one the USER chose (Settings → Push service), and only
 * while it is still installed. Any app can claim to be a distributor (no permission needed) and the
 * io.heckel.ntfy name can be squatted by a sideloaded app; it used to be picked silently (saved, else
 * ntfy, else the first app found). With none chosen, Vardum doesn't use UnifiedPush at all.
 */
export function chosenDistributor(installed: string[], saved: string | null): string | null {
  return saved && installed.includes(saved) ? saved : null;
}

function pickDistributor(n: NativeUp): string | null {
  let saved: string | null = null;
  try { saved = n.getSavedDistributor(); } catch { saved = null; }
  return chosenDistributor(distributors(), saved);
}

/**
 * b77m review (L7): the VAR-17 migration. Builds before b77m saved a distributor themselves (the silent
 * auto-pick: the saved one, else ntfy, else the first app found), and chosenDistributor treated any saved
 * distributor as the user's choice — so a squatting app picked silently before the update stayed in use.
 * Once per install (the flag below; stored unsealed and kept by Nothing-at-Rest), a distributor saved before
 * this build is dropped: its registration ends and the saved choice is overwritten with '' (never installed,
 * so chosenDistributor reads "none"). The user then picks in Settings → Push service. A choice made after the
 * flag is set (choosePushService) stands. Returns what it did.
 */
export const UP_CHOICE_MIGRATED_KEY = 'vardum_up_choice_v1';
/** b77m review (L7): the user picked in Settings during this run (before the migration ran): that choice stands */
let userChoseThisRun = false;
export async function migratePushChoice(store: { get(k: string): Promise<string | null>; set(k: string, v: string): Promise<unknown> }): Promise<'done-before' | 'cleared' | 'nothing-saved' | 'no-module'> {
  if ((await store.get(UP_CHOICE_MIGRATED_KEY).catch(() => null)) === '1') return 'done-before';
  const n = getNative();
  if (!n) return 'no-module';
  let saved: string | null = null;
  try { saved = n.getSavedDistributor(); } catch { saved = null; }
  let out: 'cleared' | 'nothing-saved' = 'nothing-saved';
  if (saved && !userChoseThisRun) {
    try { n.unregister(); } catch { /* none registered */ }
    try { n.saveDistributor(''); } catch { return 'no-module'; } // not marked done: tried again next time
    out = 'cleared';
    console.log('[veil-push] a push service saved before this update was dropped — choose one in Settings → Push service');
  }
  await store.set(UP_CHOICE_MIGRATED_KEY, '1');
  return out;
}

/** audit VAR-17: well-known distributors, named in the chooser. The package name is always shown
 *  too — a name here is not proof (any app can use a package name that isn't installed yet). */
export const KNOWN_DISTRIBUTORS: Record<string, string> = {
  [NTFY_PACKAGE]: 'ntfy',
  'org.unifiedpush.distributor.nextpush': 'NextPush',
  'org.unifiedpush.distributor.fcm': 'FCM distributor',
  'eu.siacs.conversations': 'Conversations',
  'im.molly.app': 'Molly',
};
export function distributorLabel(pkg: string): string {
  const known = KNOWN_DISTRIBUTORS[pkg];
  return known ? `${known} (${pkg})` : pkg;
}

/** audit VAR-17: what Settings shows — the installed distributors and the one chosen (if any) */
export function pushServiceChoice(): { installed: string[]; chosen: string | null; alertsHidden?: boolean } {
  const n = getNative();
  if (!n) return { installed: [], chosen: null };
  const installed = distributors();
  let saved: string | null = null;
  try { saved = n.getSavedDistributor(); } catch { saved = null; }
  return { installed, chosen: chosenDistributor(installed, saved), alertsHidden: unifiedPushAlertsHidden() };
}

/** b77n2 (review INFO): true when the native push service can't verify its silent flag (this phone's
 *  Keystore refused or lost its key). The service then fails SILENT — no banner for any push — whatever
 *  the app set; this lets Settings say so. False where the module (or this getter) is missing. */
export function unifiedPushAlertsHidden(): boolean {
  const n = getNative();
  if (!n || typeof n.getSilentUnverifiable !== 'function') return false;
  try { return n.getSilentUnverifiable() === true; } catch { return false; }
}

/** audit VAR-17: the user picked a distributor in Settings. Returns false if it isn't installed. */
export function choosePushService(pkg: string): boolean {
  const n = getNative();
  if (!n || !distributors().includes(pkg)) return false;
  try { n.unregister(); } catch { /* none registered yet */ }
  try { n.saveDistributor(pkg); userChoseThisRun = true; return true; } catch { return false; } // b77m review (L7)
}

/** audit VAR-17: true when a distributor the user chose is installed (UnifiedPush is used then) */
export function unifiedPushChosen(): boolean {
  const n = getNative();
  return !!n && pickDistributor(n) !== null;
}

/** The endpoint already stored on this device (no network, no registration). */
export function storedEndpoint(): UpEndpoint | null {
  const n = getNative();
  if (!n) return null;
  try {
    const ep = n.getEndpoint();
    return ep && ep.url ? ep : null;
  } catch { return null; }
}

/**
 * Register with the distributor and wait for its endpoint.
 * Re-registering is safe: the distributor answers with the same endpoint.
 */
export async function ensureEndpoint(timeoutMs = 12_000): Promise<UpEndpoint | null> {
  const n = getNative();
  if (!n) return null;
  const pkg = pickDistributor(n);
  if (!pkg) return null;
  const before = storedEndpoint();
  try {
    n.register(null);
  } catch (e) {
    console.log(`[veil-push] UnifiedPush register FAILED: ${(e as Error).message ?? e}`);
    return before;
  }
  if (before) return before;
  const until = Date.now() + timeoutMs;
  while (Date.now() < until) {
    await new Promise((r) => setTimeout(r, 300));
    const ep = storedEndpoint();
    if (ep) return ep;
  }
  let err: string | null = null;
  try { err = n.getLastError(); } catch { err = null; }
  console.log(`[veil-push] UnifiedPush: no endpoint from ${pkg} after ${timeoutMs}ms${err ? ` (${err})` : ''}`);
  return null;
}

/** Drop this device's registration with the distributor (wipe / Nothing-at-Rest). */
export function unregisterUnifiedPush(): void {
  const n = getNative();
  if (!n) return;
  try { n.unregister(); } catch { /* best-effort */ }
}

/** b74 (audit VAR-13): the push-verify code VardumPushService kept for this address, once */
export function takePushVerifyCode(): string | null {
  const n = getNative();
  if (!n || typeof n.takePushVerifyCode !== 'function') return null;
  try { return n.takePushVerifyCode() ?? null; } catch { return null; }
}

export function upTokenFor(ep: UpEndpoint): string {
  return UP_TOKEN_PREFIX + ep.url;
}
