/**
 * @veil/device — device-local block list (Play UGC policy, 18 Oct 2026).
 *
 * A list of Vardum IDs kept on this phone only. Blocked senders' messages are
 * not shown and don't notify. Nothing is sent anywhere.
 * (b70: moved out of moderation.ts.)
 */

export const BLOCK_LIST_KEY = 'veil_blocked_ids_v1';

interface KV { get(k: string): Promise<string | null>; set(k: string, v: string): Promise<unknown>; remove?(k: string): Promise<unknown> }

/** Batch E (Superagent round 3, N3-4 / F-4): the block list could not be read.
 *  Callers keep what they had (and retry) — never an empty list. */
export class BlockListUnreadableError extends Error {
  constructor() { super('The block list could not be read on this phone. Try again in a moment.'); this.name = 'BlockListUnreadableError'; }
}

function parseBlockList(raw: string): Set<string> {
  const arr = JSON.parse(raw) as unknown;
  if (!Array.isArray(arr)) throw new Error('not a list');
  return new Set(arr.filter((x): x is string => typeof x === 'string' && !!x));
}

/** Batch E (N3-4): fails closed. A damaged list falls back to the backup copy
 *  written with every save; if neither reads, it throws instead of returning an
 *  empty list (which used to un-hide every blocked sender, and a later block
 *  then overwrote the whole list). */
export async function loadBlockList(storage: KV): Promise<Set<string>> {
  let main: string | null;
  try { main = await storage.get(BLOCK_LIST_KEY); } catch { throw new BlockListUnreadableError(); }
  if (main) { try { return parseBlockList(main); } catch { /* damaged: try the backup */ } }
  let bak: string | null = null;
  try { bak = await storage.get(BLOCK_LIST_KEY + '_bak'); } catch { /* fall through */ }
  if (bak) { try { return parseBlockList(bak); } catch { /* fall through */ } }
  if (!main && !bak) return new Set();
  throw new BlockListUnreadableError();
}

async function saveBlockList(storage: KV, ids: Set<string>): Promise<Set<string>> {
  // the phone's secure store answers false when it refuses a write
  // Batch F (R4-2-05): never drop a block silently past the limit
  if (ids.size > 2000) throw new Error('The block list is full (2,000 people). Unblock someone first.');
  const body = JSON.stringify([...ids]);
  if ((await storage.set(BLOCK_LIST_KEY, body)) === false) throw new Error('This phone’s secure storage refused the change. Try again.');
  await storage.set(BLOCK_LIST_KEY + '_bak', body); // Batch E (N3-4): the fallback copy
  return ids;
}

export async function blockVeilId(storage: KV, veilId: string): Promise<Set<string>> {
  const ids = await loadBlockList(storage);
  const v = veilId.trim();
  if (v) ids.add(v);
  return saveBlockList(storage, ids);
}

export async function unblockVeilId(storage: KV, veilId: string): Promise<Set<string>> {
  const ids = await loadBlockList(storage);
  ids.delete(veilId.trim());
  return saveBlockList(storage, ids);
}

/** A message is hidden when its sender's Vardum ID is blocked. My own messages never are. */
export function isFromBlocked(m: { mine?: boolean; senderVid?: string | null }, blocked: ReadonlySet<string>): boolean {
  return !m.mine && !!m.senderVid && blocked.has(m.senderVid);
}

export function withoutBlocked<T extends { mine?: boolean; senderVid?: string | null }>(messages: T[], blocked: ReadonlySet<string>): T[] {
  if (!blocked.size) return messages;
  return messages.filter((m) => !isFromBlocked(m, blocked));
}
