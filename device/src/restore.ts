/**
 * @veil/device — identity restore (phrase login).
 *
 * The web-verified flow (Sept 8, re-verified Sept 13), exact order:
 *   1. restoreIdentity(phrase) — keys re-derived locally, veil_id reproduced
 *   2. identityRegister — publish FRESH SPK/pq prekeys (public material only)
 *   3. identityChallenge — relay issues a nonce
 *   4. ikSign(nonce) — Ed25519 signature with the identity key
 *   5. identityBind — binds the veil_id to the logged-in account
 *   6. keyvault saved to the secure store
 *
 * The phrase and every private key stay on-device; the relay sees public keys
 * and a nonce signature only. A phrase belonging to a DIFFERENT identity than
 * expected is rejected before anything touches the network.
 */

import { restoreIdentity, ikSign, signPqPrekey, signSpk, parseSignedPrekeySig, prekeyTsNow, bindChallengeMessage, toB64, utf8, republishPrekeys, type VeilIdentityMaterial, type VeilStorage } from '../../crypto-core/src/index';
import { PREV_PREKEYS_KEY, readPrevPrekeys } from './prekeys-prev';
import type { VeilRelay, IdentityVault, KeyvaultIdentity } from './index';

export interface RestoreDeps {
  relay: VeilRelay;
  vault: IdentityVault;
}

/**
 * Provision any identity material (freshly created or phrase-restored):
 * publish fresh prekeys (public-only), challenge -> sign -> bind, keyvault save.
 * The phrase and every private key stay on-device.
 */
export async function provisionIdentity(
  deps: RestoreDeps,
  material: VeilIdentityMaterial,
  /** b77u (audit 6 R4 #28): when this account already has a primary identity ("Generate new Vardum ID"), that identity
   *  approves the bind of the new one (the relay refuses a second identity otherwise); `userId` is the signed-in account */
  /** b77u2 (UC-L4): `currentPassword` — on an account with no primary identity, the account's current password lets
   *  this bind record one (see VeilRelay.identityBind) */
  opts: { approver?: { veilId: string; ikSeedB64: string; userId: string } | null; currentPassword?: string } = {},
): Promise<KeyvaultIdentity> {
  // 1. publish fresh prekeys (public material only — never the phrase)
  await deps.relay.identityRegister({
    veil_id: material.veilId,
    IK_pub: material.ikPubB64,
    SPK_pub: material.spkPubB64,
    SPK_sig: material.spkSigB64,
    pq_pub: material.pq.pub,
    pq_sig: material.pqSigB64,
  });

  // 2. challenge -> sign the nonce with the identity key -> bind
  const nonce = await deps.relay.identityChallenge(material.veilId);
  // b54 (T-1): never sign relay-chosen bytes raw — domain-separated bind message
  const signature = await ikSign(material.ikSeedB64, toB64(bindChallengeMessage(nonce, material.veilId)));
  const ap = opts.approver && opts.approver.veilId !== material.veilId ? opts.approver : null;
  const addProof = ap ? { veilId: ap.veilId, sig: await ikSign(ap.ikSeedB64, toB64(utf8(`vardum-add-identity-v1:${ap.userId}:${material.veilId}:${nonce}`))) } : undefined;
  await deps.relay.identityBind(material.veilId, nonce, signature, addProof, opts.currentPassword);

  // 3. keyvault to secure storage
  const identity: KeyvaultIdentity = {
    veilId: material.veilId,
    ikSeedB64: material.ikSeedB64,
    ikPubB64: material.ikPubB64,
    spkPubB64: material.spkPubB64,
    spkPrivB64: material.spkPrivB64,
    spkSigB64: material.spkSigB64,
    pqPubB64: material.pq.pub,
    pqPrivB64: material.pq.priv,
    pqSigB64: material.pqSigB64,
    createdAt: new Date().toISOString(),
  };
  await deps.vault.save(identity);
  return identity;
}

export async function restoreFromPhrase(
  deps: RestoreDeps,
  phrase: string,
  expectedVeilId?: string,
): Promise<KeyvaultIdentity> {
  // keys re-derived locally; wrong-identity phrase rejected before network
  const material = await restoreIdentity(phrase, expectedVeilId, true);
  return provisionIdentity(deps, material);
}

/**
 * b54 (Batch A): a keyvault created before b54 has no pq_sig. Sign the
 * EXISTING prekeys with the identity key, republish them unchanged with the
 * signature, and save it to the keyvault. Idempotent; runs at every launch
 * until it has succeeded once. Peers on b54 refuse an unsigned PQ prekey.
 * b75 (audit 2 V9): likewise a keyvault whose prekey signatures are the older
 * undated form (peers on b75 refuse those). Both are re-signed in the dated form,
 * dated when the prekeys were made (their last rotation), never "now": a prekey
 * older than the age limit stays refused until its weekly rotation replaces it.
 */
export async function ensurePqPrekeySigned(deps: RestoreDeps, identity: KeyvaultIdentity): Promise<KeyvaultIdentity> {
  if (identity.pqSigB64 && parseSignedPrekeySig(identity.pqSigB64) && parseSignedPrekeySig(identity.spkSigB64)) return identity;
  const madeAt = Date.parse(identity.prekeysRotatedAt ?? identity.createdAt ?? '') || Date.now();
  const ts = prekeyTsNow(Math.min(madeAt, Date.now()));
  const spkSigB64 = await signSpk(identity.ikSeedB64, identity.spkPubB64, ts);
  const pqSigB64 = await signPqPrekey(identity.ikSeedB64, identity.pqPubB64, ts);
  await deps.relay.identityRegister({
    veil_id: identity.veilId,
    IK_pub: identity.ikPubB64,
    SPK_pub: identity.spkPubB64,
    SPK_sig: spkSigB64,
    pq_pub: identity.pqPubB64,
    pq_sig: pqSigB64,
  });
  const updated = { ...identity, spkSigB64, pqSigB64 };
  await deps.vault.save(updated);
  return updated;
}

/** b70 (audit L-2): how often the contact prekeys (SPK + post-quantum) rotate.
 *  b73 (audit V-03): weekly (was 30 days). Every group key is wrapped to the member's
 *  published PQ prekey, so whoever copies a member's phone once (its PQ prekey private
 *  key, plus the group record) can follow the group's later epochs from relay ciphertext
 *  alone until the member's prekey rotates and the creator's next group rotation wraps to
 *  the new one: up to about 8 days now (7, plus up to one 24 h epoch), about 31 before
 *  (the audit counted 37 with the old 7-day kept copy). A copy taken within
 *  PREV_PREKEYS_KEEP_MS (2 days) of a rotation also holds the previous key, which only
 *  opens wraps made before that rotation. A relay that keeps serving the old, validly
 *  signed prekey stretches the window, but only within the signature's 28-day limit
 *  (b75r3 comment fix: prekey signatures are dated since b75 (audit 2 V9), spec §2.5). A key change
 *  inside a group does NOT end the window on its own; this prekey rotation does. */
export const PREKEY_ROTATE_MS = 7 * 24 * 3600 * 1000;
/** b73 (audit V-03): Android security-chip ('hardware') mode kept the monthly rotation only
 *  because saving the identity there asks for a fingerprint and a weekly prompt was not
 *  wanted (a UX choice, not a security one — see d266f97). b74 (V-03): weekly there too, the
 *  same as every other mode, so those phones no longer keep a ~31-day window after a
 *  one-time key theft (now ~8 days, as above). The app still asks after an unlock, with a
 *  word first ("Once a week…"), because of the fingerprint prompt. */
export const PREKEY_ROTATE_HW_MS = PREKEY_ROTATE_MS;

/** b70 (re-review 8): is a prekey rotation due (or a publish pending)?
 *  b73 (audit V-03): intervalMs = PREKEY_ROTATE_HW_MS for Android security-chip mode */
export function prekeysRotationDue(identity: KeyvaultIdentity, now = Date.now(), intervalMs = PREKEY_ROTATE_MS): boolean {
  if (identity.prekeysPending) return true;
  const last = Date.parse(identity.prekeysRotatedAt ?? identity.createdAt ?? '') || 0;
  return !!last && now - last >= intervalMs;
}

/**
 * b70 (audit L-2): rotate the SPK and the ML-KEM prekey once they are a month
 * old (they used to change only on restore, so one long-lived PQ prekey covered
 * every contact request). b73 (audit V-03): a week old (PREKEY_ROTATE_MS; the caller
 * passes intervalMs = PREKEY_ROTATE_HW_MS in Android security-chip mode). The replaced set is kept (PREV_PREKEYS_KEY) so
 * requests and group wraps already made to it still open. The new set is saved
 * locally first and then published; a failed publish is retried next launch
 * (prekeysPending), and peers still on the old set match the kept copy.
 */
export async function rotatePrekeysIfDue(
  deps: { relay: Pick<RestoreDeps['relay'], 'identityRegister'>; vault: RestoreDeps['vault']; storage: VeilStorage },
  identity: KeyvaultIdentity,
  opts: { now?: number; skip?: boolean; /** b73 (audit V-03) */ intervalMs?: number } = {},
): Promise<KeyvaultIdentity> {
  const now = opts.now ?? Date.now();
  await readPrevPrekeys(deps.storage).catch(() => null); // b70 (re-review 7): drops an expired replaced set
  if (opts.skip) return identity;
  const publish = async (id: KeyvaultIdentity) => {
    await deps.relay.identityRegister({
      veil_id: id.veilId, IK_pub: id.ikPubB64, SPK_pub: id.spkPubB64, SPK_sig: id.spkSigB64, pq_pub: id.pqPubB64, pq_sig: id.pqSigB64 ?? '',
    });
    const done = { ...id, prekeysPending: false };
    await deps.vault.save(done);
    return done;
  };
  if (identity.prekeysPending) return publish(identity);
  const last = Date.parse(identity.prekeysRotatedAt ?? identity.createdAt ?? '') || 0;
  if (!last) {
    const stamped = { ...identity, prekeysRotatedAt: new Date(now).toISOString() };
    await deps.vault.save(stamped);
    return stamped;
  }
  if (now - last < (opts.intervalMs ?? PREKEY_ROTATE_MS)) return identity;
  const fresh = await republishPrekeys(identity.ikSeedB64);
  if (fresh.ikPubB64 !== identity.ikPubB64) throw new Error('Prekey rotation produced a different identity key.');
  await deps.storage.set(PREV_PREKEYS_KEY, JSON.stringify({
    spkPubB64: identity.spkPubB64, spkPrivB64: identity.spkPrivB64, pqPubB64: identity.pqPubB64, pqPrivB64: identity.pqPrivB64,
    retiredAt: now, // b70 (re-review 7): dropped PREV_PREKEYS_KEEP_MS later
  }));
  const next: KeyvaultIdentity = {
    ...identity,
    spkPubB64: fresh.spkPubB64, spkPrivB64: fresh.spkPrivB64, spkSigB64: fresh.spkSigB64,
    pqPubB64: fresh.pq.pub, pqPrivB64: fresh.pq.priv, pqSigB64: fresh.pqSigB64,
    prekeysRotatedAt: new Date(now).toISOString(),
    prekeysPending: true,
  };
  await deps.vault.save(next);
  return publish(next);
}
