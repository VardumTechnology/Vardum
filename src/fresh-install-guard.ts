/**
 * b170 (owner hardware finding, Oct 2, 2026).
 *
 * ROOT CAUSE of the live bug: owner deleted and reinstalled VEIL to test
 * onboarding "fresh", without first using in-app Sign out / Wipe VEIL data.
 * The new "create identity" flow attached its brand-new Veil keypair to the
 * PREVIOUS install's leftover account session — confirmed live by decoding
 * the stuck JWT's `sub` claim, which was the OLD pre-reinstall account
 * email, not a fresh silent account. Symptom: refreshSessions() found
 * session.user missing a usable id on every poll, so the newly-created
 * identity could never list or receive sessions — a message sent from web
 * never reached it.
 *
 * This is standard, documented Apple platform behavior, not a VEIL storage
 * bug on its own: iOS Keychain items are deliberately NOT removed when an
 * app is deleted (that's what lets normal apps restore a login after a
 * reinstall). VEIL's "Sign out" and "Wipe VEIL data from this device"
 * already correctly clear every veil_-prefixed Keychain entry including the
 * auth session (see handleSignOut / handleWipeDevice in App.tsx) — the gap
 * is only the path where a user deletes the app WITHOUT using either of
 * those first, which silently inherits the old install's entire Keychain.
 *
 * Fix: AsyncStorage (unlike Keychain) IS cleared when the app is deleted,
 * so its absence at boot is a reliable "this process is running on top of a
 * possibly-stale Keychain" signal. On that signal, sweep every veil_-
 * prefixed Keychain entry before a single byte of it is ever read — the
 * exact same sweep handleWipeDevice already uses, just run automatically at
 * boot instead of waiting on the user to notice something's broken.
 *
 * Known limitation (stated honestly, not swept under the rug): a full
 * device backup/restore (iCloud or iTunes/Finder) restores the sandbox
 * wholesale, AsyncStorage included — that is a deliberate user action to
 * recover their own device, not a "start fresh" signal, and this guard
 * correctly does nothing in that case.
 */
import AsyncStorage from '@react-native-async-storage/async-storage';
import type { VeilApp } from './veil-app';
import { containerKeyPresent, deleteSecureEnclaveKey } from './secure-store.rn';
import { resetLockMacKey } from '../vendor/device/src/applock';
import { LOCK_EPOCH_KEY } from './lock-epoch';
import { WIPE_PENDING_KEY } from './duress-wipe';

const LAUNCHED_BEFORE_KEY = 'veil_launched_before_v1';

/**
 * b75 (audit AL-10): a wipe removes the records Vardum keeps outside the secure
 * store — this launch flag and the lock's epoch mirror — so nothing but the listed
 * records survives it. Safe: the next launch then treats the phone as fresh only if
 * no container key exists either (b75, AL-6), and anything written after the wipe
 * (a new identity, a login) made a new container key.
 */
export async function forgetLaunchRecords(): Promise<void> {
  // b75 round 3 (audit DV-6): the lock's epoch notes now count as a trace of a lock (a
  // missing lock record next to them reads as a damaged lock), so their removal is checked
  // and tried once more
  for (let i = 0; i < 2; i++) {
    try {
      await AsyncStorage.multiRemove([LAUNCHED_BEFORE_KEY, LOCK_EPOCH_KEY]);
      if ((await AsyncStorage.getItem(LOCK_EPOCH_KEY)) === null) return;
    } catch { /* tried again */ }
  }
}

/** Returns true if a stale-Keychain sweep ran (useful for a one-line Metro log at boot). */
export async function purgeIfFreshInstall(app: VeilApp): Promise<boolean> {
  let launchedBefore: string | null = null;
  try {
    launchedBefore = await AsyncStorage.getItem(LAUNCHED_BEFORE_KEY);
  } catch (e) {
    // fail-safe: a storage read error must NEVER be treated as "fresh" —
    // that would wipe a real returning user's data on a flaky read.
    console.error('[veil-fresh-install] AsyncStorage read failed — treating as a normal launch, no sweep:', String((e as Error)?.message || e));
    return false;
  }
  if (launchedBefore) return false;
  // b75 (audit AL-6 / AL-10): a container key means this install wrote data after its
  // last wipe (a wipe removes the flag above): not a reinstall, nothing to sweep.
  // A reinstall on iOS has no container key (it went with the old app), so whatever
  // the Keychain kept can't be opened anyway; the sweep below removes it.
  if (await containerKeyPresent()) {
    try { await AsyncStorage.setItem(LAUNCHED_BEFORE_KEY, '1'); } catch { /* set again next launch */ }
    return false;
  }

  console.log('[veil-fresh-install] no launch sentinel found — sweeping Keychain in case this is a reinstall with leftover data from a previous install');
  try {
    for (const k of await app.storage.keys('veil_')) {
      // b75: a wipe cut short after it removed the launch flag still finishes at boot
      if (k === WIPE_PENDING_KEY) continue;
      await app.storage.remove(k).catch(() => undefined);
    }
    // b75 (audit AL-10): and the hardware keys an old install left in the Keychain /
    // Keystore (the security-chip wrap key, the lock's key pair)
    await deleteSecureEnclaveKey().catch(() => undefined);
    await resetLockMacKey().catch(() => undefined);
    // belt-and-braces: logout() also clears veil_auth_session even if the
    // index-based sweep above somehow missed it.
    await app.auth.logout().catch(() => undefined);
    // b70 (re-review 8): the crash marker sits outside the index; removed by name
    try {
      const KC = require('react-native-keychain') as { resetGenericPassword: (o: unknown) => Promise<boolean> };
      await KC.resetGenericPassword({ service: 'veil.veil_sess_crash' }).catch(() => undefined);
    } catch { /* keychain module unavailable */ }
  } catch (e) {
    console.error('[veil-fresh-install] sweep failed (non-fatal — boot continues; worst case is a stale session, same as before this fix):', String((e as Error)?.message || e));
  }
  try {
    await AsyncStorage.setItem(LAUNCHED_BEFORE_KEY, '1');
  } catch (e) {
    console.error('[veil-fresh-install] failed to set launch sentinel — this sweep will simply run again next launch, which is harmless:', String((e as Error)?.message || e));
  }
  return true;
}
