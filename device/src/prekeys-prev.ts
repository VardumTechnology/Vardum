/**
 * b70 (audit L-2 / re-review 7): the prekey set a rotation replaced, kept for
 * requests and group wraps already on their way to it — but only for a short
 * window, so a later seizure can't open everything made to it.
 */
import type { VeilStorage } from '../../crypto-core/src/index';
import { secureRemove } from './secure-wipe';

/** b70 (audit L-2): the prekeys replaced by the last rotation */
export const PREV_PREKEYS_KEY = 'veil_prekeys_prev_v1';
/** b70 (re-review 7): the replaced prekeys are kept this long after a rotation, then
 *  dropped (they used to last until the next rotation: ~60 days of exposure, not 30).
 *  b73 (audit V-03): 2 days (was 7). Long enough for what is already on its way to the
 *  old set: a contact request lives 24 h on the relay, and a group wrap made to the old
 *  PQ prekey that arrives later is re-requested from the creator (wrap_request). */
export const PREV_PREKEYS_KEEP_MS = 2 * 24 * 3600 * 1000;

/** the replaced prekey set, if still inside its grace window (else removed) */
export async function readPrevPrekeys(storage: VeilStorage): Promise<{ spkPubB64: string; spkPrivB64: string; pqPubB64: string; pqPrivB64: string } | null> {
  let v: Record<string, unknown> | null = null;
  try { v = JSON.parse((await storage.get(PREV_PREKEYS_KEY)) ?? 'null'); } catch { v = null; }
  if (!v || typeof v !== 'object') return null;
  const at = Number(v.retiredAt);
  if (!Number.isFinite(at) || at <= 0) {
    // kept by an older build without a date: its window starts now
    await storage.set(PREV_PREKEYS_KEY, JSON.stringify({ ...v, retiredAt: Date.now() })).catch(() => undefined);
  } else if (Date.now() - at > PREV_PREKEYS_KEEP_MS) { // b70: one window for every phone (no longer per-set)
    await secureRemove(storage, PREV_PREKEYS_KEY).catch(() => undefined);
    return null;
  }
  return v as { spkPubB64: string; spkPrivB64: string; pqPubB64: string; pqPrivB64: string };
}
