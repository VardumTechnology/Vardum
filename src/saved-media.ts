/**
 * Saving media out of Vardum, and deleting what Vardum saved (b69).
 *
 * Android: no broad photo/video permission (Google Play's photo and video
 * permissions policy; a messenger doesn't qualify). "Save to…" opens the
 * system folder picker (Storage Access Framework). expo-file-system takes a
 * persistable grant on the chosen folder, so the duress wipe and
 * Nothing-at-Rest can still delete the files Vardum saved there, with no
 * prompt and no gallery permission. Saved files are tracked by their
 * content:// URI.
 *
 * iOS is unchanged: Photos via expo-media-library with full access (b92 F14),
 * tracked by asset id.
 */
import { Platform } from 'react-native';
import * as FileSystem from 'expo-file-system';
import * as MediaLibrary from 'expo-media-library';

const SAF = FileSystem.StorageAccessFramework;

/** True for an Android "Save to…" file (a SAF content:// URI), not a Photos asset id. */
export const isSafUri = (id: string): boolean => id.startsWith('content://');

/** Android only: "Save to…" uses the folder picker instead of gallery access. */
export const usesFolderPicker = (): boolean => Platform.OS === 'android';

/**
 * Android: ask the user for a folder, then write the file there.
 * Returns the saved file's content:// URI, or null if the user cancelled.
 */
export async function saveToChosenFolder(b64: string, fileName: string, mime: string): Promise<string | null> {
  const perm = await SAF.requestDirectoryPermissionsAsync();
  if (!perm.granted) return null;
  // createFileAsync adds the extension from the mime type itself
  const base = fileName.replace(/\.[^./]+$/, '');
  const uri = await SAF.createFileAsync(perm.directoryUri, base, mime);
  await SAF.writeAsStringAsync(uri, b64, { encoding: FileSystem.EncodingType.Base64 });
  return uri;
}

/**
 * Delete media Vardum saved (the veil_saved_media list). Android files are
 * removed through the folder grant; Photos assets only on iOS (on Android the
 * media permissions are not declared, and expo-media-library rejects without
 * them). Tries every item, then throws the first error so callers can count it.
 */
export async function deleteSavedMedia(ids: string[]): Promise<void> {
  let firstError: unknown = null;
  for (const uri of ids.filter(isSafUri)) {
    try { await FileSystem.deleteAsync(uri, { idempotent: true }); } catch (e) { firstError ??= e; }
  }
  const assets = ids.filter((id) => !isSafUri(id));
  if (assets.length && Platform.OS !== 'android') {
    // b71 (audit): no permission, or the user tapping "Don't Allow" on the iOS
    // prompt, is a failed delete (it used to count as done). iOS also keeps what
    // was deleted in Recently Deleted for 30 days; Vardum can't empty that.
    try {
      const perm = await MediaLibrary.getPermissionsAsync();
      if (!perm.granted) throw new Error('Photos access is off, so the saved images could not be deleted.');
      if ((await MediaLibrary.deleteAssetsAsync(assets)) === false) throw new Error('The saved images were not deleted (the request was refused).');
    } catch (e) { firstError ??= e; }
  }
  if (firstError) throw firstError;
}

/** b70 (re-review 4): remember a file this app saved to Photos (asset id) or a
 *  chosen folder (content:// URI), so every wipe deletes it with the rest */
// b70 (re-review 10): one update at a time (two saves finishing together used to drop one
// id), and a refused write (a wipe's write freeze) is retried, so no saved file falls off
// the list every wipe deletes
let trackQueue: Promise<unknown> = Promise.resolve();
export function trackSavedMedia(
  storage: { get(k: string): Promise<string | null>; set(k: string, v: string): Promise<unknown> } | null | undefined,
  id: string | null | undefined,
): Promise<void> {
  if (!storage || !id) return Promise.resolve();
  const run = trackQueue.catch(() => undefined).then(async () => {
    for (let attempt = 0; attempt < 6; attempt++) {
      try {
        const raw = await storage.get('veil_saved_media');
        const arr = raw ? (JSON.parse(raw) as unknown[]).filter((x): x is string => typeof x === 'string') : [];
        if (arr.includes(id)) return;
        arr.push(id);
        if ((await storage.set('veil_saved_media', JSON.stringify(arr))) !== false) return;
      } catch { /* retried */ }
      await new Promise((r) => setTimeout(r, 2000));
    }
  });
  trackQueue = run;
  return run.then(() => undefined);
}
