/**
 * b77t (audit 5 L-28, R5 F-4): the CSPRNG [0, 1) source, in its own module so relay.ts can use it (sealed.ts
 * imports relay.ts; it re-exports this for its callers). b77m (audit VAR-40): 53 random bits from the
 * platform CSPRNG — every relay-observable delay or jitter uses this, never Math.random.
 */
export function secureRandomUnit(): number {
  const buf = new Uint32Array(2);
  crypto.getRandomValues(buf);
  return (buf[0] * 2 ** 21 + (buf[1] >>> 11)) / 2 ** 53;
}
