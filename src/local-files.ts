/**
 * b70 (audit VAR-03): every plaintext file Vardum writes goes through here.
 *
 * - Temporary plaintext (decrypted voice/video notes, files handed to the share
 *   sheet, picked attachments and vault/stego sources) lives in one folder,
 *   `cache/veil-tmp/`, and is deleted when it is no longer needed and whenever
 *   the app locks.
 * - A wipe (duress, Nothing-at-Rest, sign-out, wipe device, delete account,
 *   self-destruct) empties the WHOLE cache directory — that also takes the
 *   system pickers' copies (DocumentPicker/, ImagePicker/), expo-av recordings
 *   (AV/) and anything else a library left there — plus Vardum's own exports.
 * The logic lives in local-files-core.ts (no native imports, so it is testable).
 */
import * as FileSystem from 'expo-file-system';
import { makeLocalFiles } from './local-files-core';

const lf = makeLocalFiles({
  cacheDirectory: () => FileSystem.cacheDirectory,
  documentDirectory: () => FileSystem.documentDirectory,
  makeDirectory: (uri) => FileSystem.makeDirectoryAsync(uri, { intermediates: true }),
  readDirectory: (uri) => FileSystem.readDirectoryAsync(uri),
  remove: (uri) => FileSystem.deleteAsync(uri, { idempotent: true }),
  exists: async (uri) => (await FileSystem.getInfoAsync(uri)).exists,
  copy: (from, to) => FileSystem.copyAsync({ from, to }),
});

export const { tmpPath, deleteQuietly, purgeTmp, sweepAllLocalFiles, adoptIntoTmp, dropPickerInbox /* b77u (U-M6) */, lastSweepReport /* b77u (U-M13) */ } = lf;

/** b70 (audit L-5): keep a file Vardum saves out of iCloud / device backups.
 *  iOS only (Android backups are off for the whole app). Best-effort. */
export async function excludeFromBackup(uri: string): Promise<void> {
  try {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const emc = require('expo-modules-core') as { requireNativeModule?: <T>(name: string) => T };
    const mod = emc.requireNativeModule?.<{ excludeFromBackup?: (path: string) => Promise<boolean> }>('VeilCrypto');
    await mod?.excludeFromBackup?.(uri);
  } catch { /* no native module (tests) or Android */ }
}
