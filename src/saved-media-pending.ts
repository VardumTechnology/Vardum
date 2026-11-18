/**
 * b71 (audit): photos and files Vardum saved outside the app (Photos on iOS, a
 * chosen folder on Android) are deleted by every wipe, from the list kept in
 * veil_saved_media. That list is itself a veil_ key, so it was erased with the
 * rest; a wipe cut short (the app killed, or the delete refused) lost the list
 * and the files stayed for good.
 *
 * Now each wipe copies the list here first, under a key OUTSIDE the veil_
 * prefix every wipe sweeps, and removes it only once the delete succeeded. The
 * next launch finishes the job. A refused or failed delete counts as "not
 * clean". The list holds only Photos asset ids / file URIs, never content.
 *
 * Pure module (no React Native imports) so the wipes and the tests share it.
 */

export const SAVED_MEDIA_PENDING_KEY = 'vardum_media_pending';
/** launches that retry a refused delete before giving up (each retry may show an iOS prompt) */
export const PENDING_MEDIA_MAX_TRIES = 5;

export interface PendingStore {
  get(k: string): Promise<string | null>;
  set(k: string, v: string): Promise<unknown>;
  remove(k: string): Promise<void>;
}

interface Pending { ids: string[]; tries: number }

async function readRaw(st: PendingStore): Promise<Pending> {
  try {
    const raw = await st.get(SAVED_MEDIA_PENDING_KEY);
    const v = raw ? (JSON.parse(raw) as unknown) : null;
    if (v && typeof v === 'object' && Array.isArray((v as Pending).ids)) {
      return { ids: (v as Pending).ids.filter((x): x is string => typeof x === 'string'), tries: Number((v as Pending).tries) || 0 };
    }
  } catch { /* unreadable: nothing known */ }
  return { ids: [], tries: 0 };
}

export async function readPendingMedia(st: PendingStore): Promise<string[]> {
  return (await readRaw(st)).ids;
}

/** Add ids to the pending list (merged). Returns false when the write was refused. */
export async function stashPendingMedia(st: PendingStore, ids: string[]): Promise<boolean> {
  if (!ids.length) return true;
  const cur = await readRaw(st);
  const merged = [...new Set([...cur.ids, ...ids])];
  try {
    return (await st.set(SAVED_MEDIA_PENDING_KEY, JSON.stringify({ ids: merged, tries: cur.tries }))) !== false;
  } catch {
    return false;
  }
}

export type MediaWipeResult = 'none' | 'clean' | 'failed';

/**
 * Delete what the pending list names. The list is removed only when the delete
 * succeeded; a refusal keeps it for the next launch (up to PENDING_MEDIA_MAX_TRIES).
 */
export async function finishPendingMedia(st: PendingStore, del: (ids: string[]) => Promise<void>): Promise<MediaWipeResult> {
  const cur = await readRaw(st);
  if (!cur.ids.length) return 'none';
  try {
    await del(cur.ids);
  } catch {
    const tries = cur.tries + 1;
    if (tries >= PENDING_MEDIA_MAX_TRIES) {
      console.log(`[veil-wipe] saved media could not be deleted after ${tries} tries — giving up (${cur.ids.length} item(s) remain outside Vardum)`);
      await st.remove(SAVED_MEDIA_PENDING_KEY).catch(() => undefined);
      await shredMediaKey(st);
    } else {
      await Promise.resolve(st.set(SAVED_MEDIA_PENDING_KEY, JSON.stringify({ ids: cur.ids, tries }))).catch(() => undefined);
    }
    return 'failed';
  }
  await st.remove(SAVED_MEDIA_PENDING_KEY).catch(() => undefined);
  await shredMediaKey(st);
  return 'clean';
}

/** b75 (audit AL-6 / VS-1): the pending list is sealed under its own container-key
 *  slot (it must outlive the wipe's crypto-shred until the files are gone); once
 *  the list is done with, that key goes too */
async function shredMediaKey(st: PendingStore): Promise<void> {
  try { await (st as unknown as { shredMediaKey?: () => Promise<void> }).shredMediaKey?.(); } catch { /* best-effort */ }
}
