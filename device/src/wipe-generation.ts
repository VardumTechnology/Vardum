/**
 * b70 (re-review 2, D2-2): a wipe generation for background work.
 *
 * A wipe (duress, Nothing-at-Rest, sign-out, wipe device, self-destruct) bumps
 * the generation. A long-running job (a chat or group sync that waits on the
 * relay) pins the stores it uses when it starts; once a wipe has happened,
 * every later call through those pinned stores throws. So a sync that loaded a
 * chat before the wipe can never save its keys back after it, however late the
 * relay answers. The write freeze during the wipe still covers calls already
 * running when it starts.
 */

let generation = 0;

/** synchronous methods of SessionStore / KeychainStorage */
const SYNC_METHODS = new Set(['isMoving', 'freezeMoving', 'unfreezeMoving', 'freezeWrites', 'cachedDeliveries', 'forgetDeliveries', 'setDeliveryCacheEnabled' /* b77g (NaR-1) */, 'resumeDeliveries', 'deliveriesLatched' /* b77h (H-1) */, 'holdDeliveries' /* b77k (IP77-5) */, 'releaseHeldDeliveries', 'startMemorySession', 'memorySessionActive', 'memorySessionKeys', 'dropMemorySession' /* b77k2 (IP77-5) */]);

export class WipedDuringOperationError extends Error {
  constructor() {
    super('Could not reach the relay. Try again later.'); // never says "wiped" (an attacker may be watching after a duress code)
    this.name = 'WipedDuringOperationError';
  }
}

/** called at the start of every wipe */
export function bumpWipeGeneration(): void {
  generation++;
}

export function currentWipeGeneration(): number {
  return generation;
}

const PIN_TARGET = Symbol('veil.pinTarget');

/** the real object behind a pinned view (caches keyed by a store must use this) */
export function unwrapPinned<T extends object>(obj: T): T {
  // (re-review 12: all the way down — a flow pinned inside another pinned flow wraps twice)
  let cur = obj;
  for (let i = 0; i < 8; i++) {
    const inner = (cur as Record<symbol, unknown>)[PIN_TARGET] as T | undefined;
    if (!inner || inner === cur) break;
    cur = inner;
  }
  return cur;
}

/** A view of `obj` whose methods refuse to run once a wipe has happened since
 *  this call. Non-function properties read through unchanged. */
export function pinToWipe<T extends object>(obj: T): T {
  const pinned = generation;
  return new Proxy(obj, {
    get(target, prop) {
      if (prop === PIN_TARGET) return target;
      const v = Reflect.get(target, prop, target);
      if (typeof v !== 'function') return v;
      return (...args: unknown[]) => {
        if (generation !== pinned) {
          // the stores' methods are async (a rejection reaches .catch handlers);
          // the few synchronous ones throw
          if (typeof prop === 'string' && SYNC_METHODS.has(prop)) throw new WipedDuringOperationError();
          return Promise.reject(new WipedDuringOperationError());
        }
        return (v as (...a: unknown[]) => unknown).apply(target, args);
      };
    },
  });
}

/** b70 (re-review 9): pin the stores in a deps object (sessions, storage, pins, vault),
 *  so a flow that waits on the relay can't write after a wipe whoever called it */
export function pinDeps<T extends object>(deps: T): T {
  const d = { ...deps } as Record<string, unknown>;
  for (const k of ['sessions', 'storage', 'pins', 'vault']) {
    const v = d[k];
    if (v && typeof v === 'object') d[k] = pinToWipe(v as object);
  }
  return d as T;
}
