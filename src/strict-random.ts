/**
 * b77t (audit 5 L-32 / IH I-11): crypto.getRandomValues that never falls back to Math.random.
 *
 * react-native-get-random-values fills the array from Math.random when it thinks it runs under
 * Chrome remote debugging (__DEV__ with no nativeCallSyncHook). Every key, nonce and padding byte
 * comes from this function, so a debug build could make guessable keys. This replacement asks the
 * platform CSPRNG only (Expo's ExpoCrypto, then the library's native module) and THROWS when
 * neither is there, in development builds too. A crypto operation then fails loudly instead of
 * running on weak randomness.
 *
 * Pure module: the platform pieces are passed in (installStrictRandom looks them up at run time).
 */

export interface StrictRandomSources {
  /** Expo SDK 48+: fills the array in place */
  expoGetRandomValues?: ((a: ArrayBufferView) => void) | null;
  /** react-native-get-random-values' native module: base64 of n random bytes */
  nativeRandomBase64?: ((n: number) => string) | null;
}

const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
function b64Into(s: string, out: Uint8Array): number {
  const clean = String(s).replace(/[^A-Za-z0-9+/]/g, '');
  let n = 0, bits = 0, acc = 0;
  for (const c of clean) {
    const v = B64.indexOf(c);
    acc = (acc << 6) | v; bits += 6;
    if (bits >= 8) { bits -= 8; if (n < out.length) out[n] = (acc >> bits) & 0xff; n++; }
  }
  return n;
}

export const STRICT_RANDOM_UNAVAILABLE = 'No secure random number source on this device (Vardum never uses a weak one).';

export function makeStrictGetRandomValues(src: StrictRandomSources) {
  return function getRandomValues<T extends ArrayBufferView | null>(array: T): T {
    const a = array as unknown as ArrayBufferView;
    if (!(a instanceof Int8Array || a instanceof Uint8Array || a instanceof Int16Array || a instanceof Uint16Array
      || a instanceof Int32Array || a instanceof Uint32Array || a instanceof Uint8ClampedArray)) {
      throw new TypeError('Expected an integer array');
    }
    if (a.byteLength > 65536) throw new RangeError('Can only request a maximum of 65536 bytes');
    if (a.byteLength === 0) return array;
    const bytes = new Uint8Array(a.buffer, a.byteOffset, a.byteLength);
    if (typeof src.expoGetRandomValues === 'function') {
      src.expoGetRandomValues(bytes);
      return array;
    }
    if (typeof src.nativeRandomBase64 === 'function') {
      const got = b64Into(src.nativeRandomBase64(bytes.length), bytes);
      if (got < bytes.length) throw new Error(STRICT_RANDOM_UNAVAILABLE);
      return array;
    }
    throw new Error(STRICT_RANDOM_UNAVAILABLE);
  };
}

/** Installs the strict function as globalThis.crypto.getRandomValues (replacing the library's). */
export function installStrictRandom(lookup?: () => StrictRandomSources): void {
  const g = globalThis as unknown as { crypto?: { getRandomValues?: unknown }; expo?: { modules?: { ExpoCrypto?: { getRandomValues?: (a: ArrayBufferView) => void } } } };
  const find = lookup ?? ((): StrictRandomSources => {
    const out: StrictRandomSources = {};
    const ec = g.expo?.modules?.ExpoCrypto;
    if (ec && typeof ec.getRandomValues === 'function') out.expoGetRandomValues = (a) => ec.getRandomValues!(a);
    try {
      // eslint-disable-next-line @typescript-eslint/no-var-requires
      const NM = (require('react-native') as { NativeModules?: Record<string, { getRandomBase64?: (n: number) => string }> }).NativeModules;
      const m = NM?.RNGetRandomValues;
      if (m && typeof m.getRandomBase64 === 'function') out.nativeRandomBase64 = (n) => m.getRandomBase64!(n);
    } catch { /* no React Native: only the Expo source counts */ }
    return out;
  });
  // the sources are looked up per call: Expo's module can appear after this file runs
  const strict = (array: ArrayBufferView) => makeStrictGetRandomValues(find())(array);
  if (typeof g.crypto !== 'object' || g.crypto === null) (g as { crypto?: object }).crypto = {};
  try {
    Object.defineProperty(g.crypto, 'getRandomValues', { value: strict, writable: true, configurable: true });
  } catch {
    (g.crypto as { getRandomValues?: unknown }).getRandomValues = strict;
  }
}
