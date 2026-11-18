/**
 * b74 (audit VAR-13): the relay stores a UnifiedPush address only once this phone proves it
 * receives that address's pushes: it sends a "push-verify" Web Push, encrypted to the keys
 * the registration named. The native push service (VardumPushService) keeps the code it
 * carries, without a banner; the app picks it up here and re-registers with it.
 * (No React Native imports, so the wait can be tested in node.)
 */
export const PUSH_VERIFY_WAIT_MS = 60_000;
export const PUSH_VERIFY_POLL_MS = 1_500;

/** Poll `take` (the native module's one-shot read) until it yields a code or the time is up. */
export async function waitForPushVerifyCode(
  take: () => string | null,
  opts: { timeoutMs?: number; intervalMs?: number } = {},
): Promise<string | null> {
  const until = Date.now() + (opts.timeoutMs ?? PUSH_VERIFY_WAIT_MS);
  const every = opts.intervalMs ?? PUSH_VERIFY_POLL_MS;
  for (;;) {
    let code: string | null = null;
    try { code = take(); } catch { code = null; }
    if (code && /^[A-Za-z0-9_-]{8,64}$/.test(code)) return code;
    if (Date.now() + every > until) return null;
    await new Promise((r) => setTimeout(r, every));
  }
}
