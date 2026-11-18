/**
 * b77u (audit 6 R1 F-05): the keychain write behind secure-store.rn.ts set(), with the keychain passed in (so it is
 * tested without a phone). Pure module: no React Native imports.
 *
 * Before: the read-back that checks a write landed sat INSIDE the catch of the first write, so a normal write that
 * RESOLVED false (react-native-keychain's "not stored") skipped the check, and the false itself was ignored: the
 * caller took the record as saved. Now a false counts as a failed write (delete and rewrite once, as for a throw),
 * and the read-back runs after the whole write for every non-gated key. Gated (Secure Enclave / biometric) keys are
 * still never read back: reading them would show a prompt.
 */
export interface KeychainLike {
  setGenericPassword(username: string, password: string, options?: unknown): Promise<unknown>;
  resetGenericPassword(options: { service: string }): Promise<unknown>;
  getGenericPassword(options: { service: string }): Promise<unknown>;
}

const passwordOf = (rc: unknown): string | undefined => (rc && typeof rc === 'object' ? (rc as { password?: string }).password : undefined);

export async function writeKeychainVerified(
  kc: KeychainLike,
  key: string,
  value: string,
  options: { service: string } & Record<string, unknown>,
  gated: boolean,
  fail: (op: string, key: string, e: unknown) => never,
): Promise<void> {
  const service = options.service;
  const setOnce = async (): Promise<void> => {
    const r = await kc.setGenericPassword('veil', value, options);
    if (r === false) throw new Error('keychain write was not stored (resolved false)');
  };
  try {
    await setOnce();
  } catch {
    // AUDIT FIX (Sept 19): iOS can't change an existing item's accessControl in place — delete and retry once fresh
    try {
      await kc.resetGenericPassword({ service });
      await setOnce();
    } catch (e2) {
      fail('set', key, e2);
    }
  }
  // b196-r7: a write that claims success must VERIFY (a fresh-install keychain flake resolved without storing)
  if (gated) return;
  if (passwordOf(await kc.getGenericPassword({ service })) === value) return;
  console.error('[veil-secure] write did not persist (read-back mismatch) — retrying once:', key);
  try {
    await kc.resetGenericPassword({ service });
    await setOnce();
  } catch (e3) {
    fail('set', key, e3);
  }
  if (passwordOf(await kc.getGenericPassword({ service })) !== value) {
    fail('set', key, new Error('keychain write did not persist (verified read-back)'));
  }
}
