/**
 * @veil/device — b70: the public forum ("lounge", Founding Tester Forum) was
 * removed. On launch, quietly delete what an older build kept for it on this
 * phone, so nothing of it lingers: its group records (listener / forum-member,
 * or the founder's open-membership creator record), their local sessions and
 * message caches (`lounge_<group>` threads), the founder's report queue, and the
 * report-limit and banner markers. Private groups are never touched.
 *
 * Returns the relay session tokens whose local state went, plus the purged group
 * tokens, so the caller can hide their relay rows (with the record gone they
 * would otherwise come back as unnamed group rows). Safe to run every launch.
 */
import type { VeilStorage } from '../../crypto-core/src/storage-adapter';
import type { SessionStore } from './session-store';
import { loadGroupRecords, listGroupTokens, groupRecord, forgetGroup } from './groups';
import { secureRemove } from './secure-wipe';

/** what older builds stored for the forum (record fields no longer in GroupRecord) */
type LegacyForumRecord = {
  role?: string; openMembership?: boolean; postingSessionToken?: string;
  sessionToken?: string; seatToken?: string; seats?: Record<string, unknown>;
};

const OLD_THREAD_PREFIX = 'lounge_';
const OLD_REPORT_INDEX_PREFIX = 'veil_report_queue_';
const OLD_REPORT_ITEM_PREFIX = 'veil_report_q_';
const OLD_SINGLE_KEYS = ['veil_report_sends_v1', 'veil_forum_banner_dismissed'];

async function drop(storage: VeilStorage, key: string): Promise<void> {
  try { await secureRemove(storage, key); } catch { /* already gone */ }
}

/** b77m (audit VAR-26): the per-chat key kinds a pre-b77m SessionStore wrote under `veil_<kind>_<name>` */
const LEGACY_THREAD_KINDS = ['rk', 'rk_wrap', 'msgcache', 'procids', 'syncskip', 'backfill', 'unread', 'stray', 'straypending', 'missing',
  'missedcall', 'receipted', 'desyncpending', 'pendburn', 'displayed', 'mbox', 'outbox'];
async function dropLegacyThread(storage: VeilStorage, name: string): Promise<void> {
  for (const kind of LEGACY_THREAD_KINDS) await drop(storage, `veil_${kind}_${name}`);
  try {
    for (const k of await storage.keys(`veil_msgcache_${name}_p`)) if (/_p\d{1,3}$/.test(k)) await drop(storage, k);
  } catch { /* nothing listed */ }
}

export async function purgeForumLeftovers(
  deps: { storage: VeilStorage; sessions: Pick<SessionStore, 'remove'> },
): Promise<{ groupTokens: string[]; sessionTokens: string[] }> {
  const groupTokens: string[] = [];
  const sessionTokens = new Set<string>();
  await loadGroupRecords(deps.storage).catch(() => 0);
  for (const gt of listGroupTokens(deps.storage)) {
    const rec = groupRecord(deps.storage, gt) as unknown as LegacyForumRecord | null;
    if (!rec) continue;
    const forum = rec.role === 'listener' || rec.role === 'forum-member' || rec.openMembership === true;
    if (!forum) continue;
    groupTokens.push(gt);
    for (const t of [rec.postingSessionToken, rec.sessionToken, rec.seatToken, ...Object.keys(rec.seats ?? {})]) {
      if (!t || sessionTokens.has(t)) continue;
      sessionTokens.add(t);
      try { await deps.sessions.remove(t); } catch { /* no local state */ }
    }
    // b77m (audit VAR-26): "lounge_<group>" is not a token SessionStore takes any more (no "_" in a storage
    // token), so the old thread's keys are removed here directly — every per-chat key kind, and the cache parts
    await dropLegacyThread(deps.storage, OLD_THREAD_PREFIX + gt);
    // the founder's report queue: a small index plus one item per report
    try {
      const raw = await deps.storage.get(OLD_REPORT_INDEX_PREFIX + gt);
      const idx = raw ? (JSON.parse(raw) as unknown) : [];
      if (Array.isArray(idx)) for (const it of idx) if (it && typeof (it as { id?: unknown }).id === 'string') await drop(deps.storage, `${OLD_REPORT_ITEM_PREFIX}${gt}_${(it as { id: string }).id}`);
    } catch { /* unreadable index: removed below */ }
    await drop(deps.storage, OLD_REPORT_INDEX_PREFIX + gt);
    await forgetGroup(deps.storage, gt);
  }
  for (const k of OLD_SINGLE_KEYS) await drop(deps.storage, k);
  if (groupTokens.length) console.log(`[veil-group] removed ${groupTokens.length} leftover forum record(s) from this phone`);
  return { groupTokens, sessionTokens: [...sessionTokens] };
}
