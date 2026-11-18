/**
 * b77t (audit 5 L-15, IH R-08): single-use proofs for the account's primary identity.
 *
 * The relay used to accept a primary-identity proof (`<label>:<userId>:<ts>`, signed with the identity key) for its
 * whole 10-minute window, as often as it was presented. It now hands out a nonce first (`veilProofNonce {label}` →
 * `{nonce}`: 32 hex, 10 minutes, for this account and label only), the identity signs `<label>:<userId>:<ts>:<nonce>`,
 * and the relay consumes the nonce with the request that uses it. Older relays have no such route: `fetchProofNonce`
 * then answers null and the caller signs the old form (which the relay accepts only during its transition window, and
 * only once).
 */
export type ProofLabel = 'vardum-delete-v1' | 'vardum-purge-v1' | 'vardum-reglock-off-v1' | 'vardum-signout-others-v1' | 'vardum-purge-token-v1' | /** b77u (audit 6 W2) */ 'vardum-reglock-set-v1';

/** the signed text: `<label>:<userId>:<ts>` plus `:<nonce>` when there is one */
export const proofMessage = (label: ProofLabel, userId: string, ts: number, nonce?: string | null): string =>
  nonce ? `${label}:${userId}:${ts}:${nonce}` : `${label}:${userId}:${ts}`;

const NONCE_RE = /^[0-9a-f]{32}$/;

/** a nonce for `label` from the relay (signed in: `relay.invoke`), or null when the relay doesn't issue them (an older
 *  relay: 404) or the call fails — the caller then signs the old form */
export async function fetchProofNonce(relay: { invoke(fn: string, payload: Record<string, unknown>): Promise<{ data: unknown; status: number }> }, label: ProofLabel): Promise<string | null> {
  try {
    const r = await relay.invoke('veilProofNonce', { label });
    const d = r.data as { nonce?: unknown; data?: { nonce?: unknown } } | null;
    const n = d?.nonce ?? d?.data?.nonce;
    return typeof n === 'string' && NONCE_RE.test(n) ? n : null;
  } catch {
    return null;
  }
}
