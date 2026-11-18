/**
 * Batch H (round-6 review R6-1-06): a ratchet save that must land — a send (before
 * it goes out), a join, an accept, a completion. The secure store answers a
 * refused write with false; here that is an error, never a silent continue.
 */
export async function saveOrThrow(sessions: { save(token: string, state: never): Promise<unknown>; isMoving?(token: string): boolean }, token: string, state: unknown): Promise<void> {
  // b70 (re-review P2/P3): a chat on its way to a new phone sends nothing from
  // this one (its save is refused on purpose, so say why)
  if (sessions.isMoving?.(token)) throw new Error('This chat is moving to your new phone. Send from there.');
  let ok: unknown;
  try { ok = await sessions.save(token, state as never); } catch { ok = false; }
  if (ok === false) throw new Error('Chat keys could not be saved on this device. Free up some space, then try again.');
}
