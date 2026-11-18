/**
 * b75 (audit AL-2): the app lock's epoch mirror, kept OUTSIDE the secure store.
 *
 * The lock's two attempt rows (veil_lockout, veil_lock_wrong_in_a_row) carry a
 * per-write epoch under their MAC, so no two writes are alike. The latest epoch of
 * each row is also noted here, in the app's own storage (AsyncStorage, a different
 * file from the Keychain / Keystore). An old copy of a row put back into the secure
 * store then shows: its epoch is behind the one noted here, and it counts as
 * tampering (the longest lockout). Someone who can roll back BOTH stores together
 * still can; closing that needs a hardware monotonic counter (spec §8.2).
 *
 * Holds only numbers and a short tag of the lock's salt: no code, no key.
 */
import AsyncStorage from '@react-native-async-storage/async-storage';
import type { LockEpochMirror } from '../vendor/device/src/applock';
import { currentWipeGeneration } from '../vendor/device/src/wipe-generation';

export const LOCK_EPOCH_KEY = 'vardum_lock_epoch_v1';

export function createLockEpochMirror(): LockEpochMirror {
  return {
    read: () => AsyncStorage.getItem(LOCK_EPOCH_KEY),
    write: (v) => AsyncStorage.setItem(LOCK_EPOCH_KEY, v),
    clear: () => AsyncStorage.removeItem(LOCK_EPOCH_KEY),
    // b75 round 3 (audit DV-3): a password check in flight when a wipe begins writes no note
    // after it (the wipe removes the notes; one written back would outlive the lock)
    generation: currentWipeGeneration,
  };
}
