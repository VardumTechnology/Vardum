/**
 * b77t (audit 5, owner decision "iOS screen lock: fix pre-emptively"): iOS's "protected data will become
 * unavailable" signal (UIApplication.protectedDataWillBecomeUnavailableNotification: the phone is locking
 * and data-protection keys are about to be dropped). The native VeilCrypto module (b77t binary) forwards it
 * as an `onProtectedData` event; the app locks at once (app-guards.ts createDepartureLock).
 *
 * On Android, older binaries, web or Node the resolver finds no event and the watch is inert (null).
 */
interface NativeEvents {
  addListener?: (name: string, handler: (event: { available?: boolean }) => void) => { remove: () => void };
}

export function startProtectedDataWatch(onUnavailable: () => void, resolve?: () => NativeEvents | null): (() => void) | null {
  try {
    const mod = resolve ? resolve() : (() => {
      const emc = require('expo-modules-core') as { requireOptionalNativeModule?: <T = unknown>(name: string) => T | null };
      return emc?.requireOptionalNativeModule?.<NativeEvents>('VeilCrypto') ?? null;
    })();
    if (!mod || typeof mod.addListener !== 'function') return null;
    const sub = mod.addListener('onProtectedData', (event) => {
      try { if (event?.available === false) onUnavailable(); } catch { /* never crashes the app */ }
    });
    return () => { try { sub.remove(); } catch { /* ignore */ } };
  } catch {
    return null;
  }
}
