/**
 * b77p (audit 2, VAR-03): where a chat row's burn countdown starts. A received row counts from when
 * it was first displayed; the sender's own copy counts from min(send time, read receipt), the same
 * clock the store purges it by (session-store purgeCacheUnlocked), so an unread own row shows its
 * countdown instead of vanishing without warning. No React Native imports (the tests load it).
 */
export function burnAnchor(item: { mine?: boolean; ts?: string | null; openedAt?: number }): number | undefined {
  if (!item.mine) return item.openedAt;
  const sent = item.ts ? Date.parse(item.ts) : NaN;
  if (Number.isFinite(sent)) return item.openedAt !== undefined ? Math.min(sent, item.openedAt) : sent;
  return item.openedAt;
}
