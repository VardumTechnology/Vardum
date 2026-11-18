/**
 * b77 rollout (5 Nov 2026, owner: "Restore keeps old ID"). Build 77 runs on a new relay (relay2.tryveil.app) that
 * started empty: a Vardum ID made on an older build has no account and no identity there, so the 24-word sign-in
 * fails and the restore used to fall through to the old email sign-in (TestFlight build 66, owner's iPhone).
 *
 * When the words are valid but no account signs in with them, the restore asks the relay (no login) whether this
 * Vardum ID is bound to any account. Only when it is NOT does it create the phrase-derived account here; the restore
 * then registers and binds the same ID as usual. Safe because a Vardum ID is the hash of its identity key: the relay
 * refuses a registration whose key doesn't derive the ID, and the bind needs a signature only the 24 words can make.
 * An ID that IS bound here (an email account made on this relay) keeps the email sign-in offer, as before. A lookup
 * that fails decides nothing: the email offer shows, and Restore can be tapped again.
 */
export type CarryVerdict = 'provisioned' | 'bound-here' | 'unknown';

export interface CarryDeps {
  /** the Vardum ID the 24 words derive (computed on the phone) */
  veilId: () => Promise<string>;
  /** relay key lookup with no login: { found: false } when the ID has no bound identity */
  lookupAnon: (veilId: string) => Promise<{ data: unknown }>;
  /** create the phrase-derived account on this relay and sign in */
  provision: () => Promise<unknown>;
}

export async function carryIdToThisRelay(d: CarryDeps): Promise<CarryVerdict> {
  let found: unknown;
  try {
    const r = await d.lookupAnon(await d.veilId());
    found = (r?.data as { found?: unknown; veil_id?: unknown } | null) ?? null;
  } catch {
    return 'unknown';
  }
  const rec = found as { found?: unknown; veil_id?: unknown } | null;
  if (!rec || typeof rec !== 'object') return 'unknown';
  if (rec.found === false) {
    await d.provision();
    return 'provisioned';
  }
  return typeof rec.veil_id === 'string' && rec.veil_id ? 'bound-here' : 'unknown';
}
