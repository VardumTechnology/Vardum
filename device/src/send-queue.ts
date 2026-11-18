/**
 * b147: per-token ratchet-write serialization.
 *
 * Live-forensics finding (Oct 1, builder relay audit): during a call setup the
 * native client emitted the SAME ratchet step seven times — same ratchet key,
 * same counter, seven different payloads. Every ratchet-encrypting send
 * (chat, receipt, media, cover, call signal) does
 *   load -> encrypt -> save -> submit
 * with nothing serializing the sequence. The call path fires its offer and
 * each ICE candidate fire-and-forget, so several sends overlap on one token:
 * all of them load the SAME pre-send state, all of them encrypt the SAME
 * step, and the receiver sees a rewind ("counter out of range").
 *
 * Root fix: every ratchet-writing send funnels through a per-token promise
 * chain, so a burst serializes into distinct steps exactly like it does when
 * the user sends messages one at a time. The queue lives at module scope and
 * self-trims when it is still the tail.
 */

const chains = new Map<string, Promise<unknown>>();

/** b77z2 (Z-1): true when no job is queued or running on this token's chain (a job enqueued now
 *  runs first, without waiting for a sync pass or a relay call) */
export function ratchetChainIdle(token: string): boolean {
  return !chains.has(token);
}

export function serializeRatchetSend<T>(token: string, run: () => Promise<T>): Promise<T> {
  const prev = chains.get(token) as Promise<void> | undefined;
  const runAfterPrev = (prev ?? Promise.resolve()).then(() => undefined, () => undefined).then(run);
  chains.set(token, runAfterPrev);
  // trim: if we are still the tail when we settle, drop the map entry
  const trim = () => { if (chains.get(token) === runAfterPrev) chains.delete(token); };
  runAfterPrev.then(trim, trim);
  return runAfterPrev;
}
