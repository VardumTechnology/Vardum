/**
 * b77s (audit 4 A-01, app half): every wipe asks the native module to drop the app's cookies
 * (Android: CookieManager.removeAllCookies + flush; iOS: HTTPCookieStorage.shared, every cookie).
 * React Native's networking keeps cookies a relay sets, so a malicious relay could otherwise link the
 * phone's requests from before a wipe with those after it. Best-effort and never throws: a build
 * without the native function (older native code, tests, web) simply skips it. The request-side
 * half (withCredentials=false / credentials:'omit') is in vendor/device/src/relay.ts.
 */
type CookieNative = { clearCookies?: () => Promise<boolean> };

function nativeCookies(): CookieNative | null {
  try {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const emc = require('expo-modules-core') as { requireOptionalNativeModule?: <T>(name: string) => T | null };
    return emc.requireOptionalNativeModule?.<CookieNative>('VeilCrypto') ?? null;
  } catch {
    return null;
  }
}

/** resolves true when the native store said it cleared, false otherwise (absent, failed); never rejects */
export async function clearAppCookies(native: CookieNative | null = nativeCookies()): Promise<boolean> {
  try {
    if (typeof native?.clearCookies !== 'function') return false;
    return (await native.clearCookies()) === true;
  } catch {
    return false;
  }
}
