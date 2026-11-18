/**
 * b70 (audit VAR-03): the file rules behind local-files.ts, with the file
 * system passed in (so the wipe sweep is tested without a phone).
 */
export interface FileOps {
  cacheDirectory(): string | null;
  documentDirectory(): string | null;
  makeDirectory(uri: string): Promise<void>;
  readDirectory(uri: string): Promise<string[]>;
  remove(uri: string): Promise<void>;
  exists(uri: string): Promise<boolean>;
  copy(from: string, to: string): Promise<void>;
  /** b77u (audit 6 U-M6): the app's tmp folder (iOS NSTemporaryDirectory), when it is not derivable from the
   *  documents folder; null on Android */
  tmpDirectory?(): string | null;
}

/** b77u (U-M6): the iOS document picker's asCopy originals (tmp/<bundle id>-Inbox/) */
export const INBOX_SUFFIX = '-Inbox';
/** b77u (U-M6, W11, IH full L-11): library outputs inside the cache directory that hold plaintext: the pickers'
 *  copies and expo-image-manipulator's outputs (the stego cover). Emptied at every lock purge too */
export const LIBRARY_CACHE_DIRS = ['ImageManipulator/', 'ImagePicker/', 'DocumentPicker/'];
/** b77u (W11): react-native-view-shot's iOS tmpfile folder (the QR snapshot) */
export const VIEWSHOT_TMP_DIR = 'ReactNative/';

/** b77u (U-M13): what the last wipe sweep could not remove (paths) and which folders it could not list */
export type SweepReport = { left: string[]; unlistable: string[] };

export const TMP_DIR = 'veil-tmp/';

/** b77u merge (U-M13): the device half's name for the same report */
export type FileSweepReport = SweepReport;

/** Vardum's own files in the documents folder (encrypted stego extracts) */
export const isOwnDocument = (name: string): boolean => name.startsWith('veil-') && name.endsWith('.veilenc');

export function makeLocalFiles(fs: FileOps) {
  /** b77u (audit 6 U-M6): iOS tmp/ = <container>/tmp/, beside <container>/Documents/ (null on Android) */
  function tmpDir(): string | null {
    const t = fs.tmpDirectory?.();
    if (t) return t.endsWith('/') ? t : t + '/';
    const d = fs.documentDirectory();
    return d && /\/Documents\/$/.test(d) ? d.replace(/Documents\/$/, 'tmp/') : null;
  }

  /** b77u (audit 6 U-M6 / IH M2): delete the iOS picker's Inbox originals (the picked file under its own name,
   *  a hidden-volume source included). Called right after a picked copy is adopted, at every lock purge and in
   *  every wipe. Returns how many could not be removed. */
  async function dropPickerInbox(): Promise<number> {
    const t = tmpDir();
    if (!t) return 0;
    let names: string[];
    try { names = await fs.readDirectory(t); } catch { return 0; }
    let left = 0;
    for (const n of names) {
      if (!n.endsWith(INBOX_SUFFIX)) continue;
      await fs.remove(t + n + '/').catch(() => undefined);
      if (await fs.exists(t + n).catch(() => false)) left += 1;
    }
    return left;
  }

  /** a fresh path inside the temp folder (created if missing) */
  async function tmpPath(name: string): Promise<string> {
    const dir = fs.cacheDirectory();
    if (!dir) throw new Error('No cache folder on this device.');
    await fs.makeDirectory(dir + TMP_DIR).catch(() => undefined);
    // a received or picked file name never climbs out of the folder
    const safe = name.replace(/[\\/]/g, '_').replace(/^\.+/, '_').slice(0, 120) || 'file';
    return dir + TMP_DIR + safe;
  }

  async function deleteQuietly(uri: string | null | undefined): Promise<void> {
    if (!uri || !uri.startsWith('file:')) return;
    await fs.remove(uri).catch(() => undefined);
  }

  /** drop every temporary plaintext file (app lock, app start, chat close) */
  async function purgeTmp(): Promise<void> {
    const dir = fs.cacheDirectory();
    if (dir) {
      await fs.remove(dir + TMP_DIR).catch(() => undefined);
      // b77u (audit 6 U-M6, W11, IH full L-11): and the libraries' own plaintext copies (picker copies, the
      // image manipulator's outputs: the clean stego cover)
      for (const sub of LIBRARY_CACHE_DIRS) await fs.remove(dir + sub).catch(() => undefined);
    }
    await dropPickerInbox();
    const t = tmpDir();
    if (t) await fs.remove(t + VIEWSHOT_TMP_DIR).catch(() => undefined); // b77u (W11): the QR snapshot (iOS)
  }

  /**
   * The wipe sweep: everything in the cache directory (the pickers' and image manipulator's copies, AV/,
   * veil-tmp/), Vardum's own files in the documents directory and, on iOS, the whole tmp folder. Returns how
   * many entries could not be removed (-1 when a folder could not be listed).
   * b77u merge (U-M6, U-M12, U-M13): one sweep for both halves. The whole iOS tmp/ (the picker's -Inbox
   * originals, the QR snapshot under ReactNative/, anything else a library left there) is a root; a folder that
   * will not list is tried once more, and so is every entry that will not go. What still remains is kept in
   * lastSweepReport() and the count goes back to the wipe (eraseLocal), which keeps its pending marker so the
   * next launch finishes it.
   */
  let lastReport: SweepReport = { left: [], unlistable: [] };
  async function sweepAllLocalFiles(): Promise<number> {
    const report: SweepReport = { left: [], unlistable: [] };
    const roots: [string | null, (n: string) => boolean][] = [
      [fs.cacheDirectory(), () => true],
      [fs.documentDirectory(), isOwnDocument],
      [tmpDir(), () => true],
    ];
    for (const [dir, mine] of roots) {
      if (!dir) continue;
      let names: string[] | null = null;
      for (let i = 0; i < 2 && names === null; i++) { try { names = await fs.readDirectory(dir); } catch { names = null; } }
      if (names === null) { report.unlistable.push(dir); continue; }
      for (const n of names) {
        if (!mine(n)) continue;
        let still = true;
        for (let i = 0; i < 2 && still; i++) {
          await fs.remove(dir + n).catch(() => undefined);
          still = await fs.exists(dir + n).catch(() => false);
        }
        if (still) report.left.push(dir + n);
      }
    }
    lastReport = report;
    return report.unlistable.length ? -1 : report.left.length;
  }
  /** b77u (audit 6 U-M13): the last sweep's leftovers and unlistable folders (the wipe's report, the notice) */
  function lastSweepReport(): SweepReport {
    return { left: [...lastReport.left], unlistable: [...lastReport.unlistable] };
  }

  /**
   * Move a file a picker or recorder produced into the temp folder, so the lock
   * purge and the wipe find it. A file outside the cache directory (a photo
   * library asset) is copied, never deleted.
   */
  async function adoptIntoTmp(uri: string, name: string): Promise<string> {
    const cache = fs.cacheDirectory();
    if (!cache) return uri;
    // b77u (audit 6 U-M12 / R4 #19): an Android content:// pick is copied into the swept temp folder and used from
    // there, so nothing derived from it is made outside a swept path (the original is the user's: never deleted;
    // a picker's grant is temporary and ends with the activity). A failed copy reads the original in place
    if (uri.startsWith('content:')) {
      const target = await tmpPath(`${Date.now()}-${name}`);
      try { await fs.copy(uri, target); return target; } catch { await deleteQuietly(target); return uri; }
    }
    if (!uri.startsWith('file:')) return uri;
    if (uri.startsWith(cache + TMP_DIR)) { await dropPickerInbox(); return uri; }
    const target = await tmpPath(`${Date.now()}-${name}`);
    try {
      await fs.copy(uri, target);
    } catch {
      await dropPickerInbox(); // b77u (U-M6)
      return uri; // the original still works; the wipe sweep still covers the cache
    }
    if (uri.startsWith(cache)) await deleteQuietly(uri);
    await dropPickerInbox(); // b77u (U-M6 / IH M2): the iOS picker's Inbox original goes as soon as its copy is ours
    return target;
  }

  return { tmpPath, deleteQuietly, purgeTmp, sweepAllLocalFiles, adoptIntoTmp, dropPickerInbox, lastSweepReport };
}
