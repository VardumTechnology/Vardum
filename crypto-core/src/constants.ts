/**
 * @veil/crypto-core — protocol constants. These MUST NOT drift: any change is
 * a protocol bump.
 */

/** b74: veil-ratchet-7 is the ONLY supported 1:1 protocol. Hard cut (owner decision:
 *  clean break) — older sessions (ratchet-3/-4: P-256, optional PQ; ratchet-5: no
 *  responder-IK term, shared signing key, dials outside the transcript; ratchet-6: header
 *  signature over rp + pq only, message receipts by relay id) are refused on load and
 *  ended by the app's one-time migration. */
/** b77: veil-ratchet-8 (encrypted ratchet header, spec §4.2) replaces veil-ratchet-7 the same
 *  way: clean break. A ratchet-7 state is refused on load and ended by the one-time migration;
 *  a ratchet-7 (cleartext JSON) header is refused by the relay and by the receiver. */
export const RATCHET_PROTOCOL_LATEST = 'veil-ratchet-8' as const;
export const RATCHET_VERSION = RATCHET_PROTOCOL_LATEST;
export const RATCHET_PROTOCOL_SUPPORTED = [RATCHET_PROTOCOL_LATEST] as const;

export const RATCHET_ENGINE_LABEL =
  'Double Ratchet — hybrid X25519 + ML-KEM-768 (FIPS 203), signed PQ prekey, PQ mandatory, per-step PQ re-key, header signatures keyed by the session root (they authenticate against the relay, not one peer against the other) · HKDF-SHA256 · AES-GCM-256 · padded buckets · cover traffic' as const;
// b71 (audit): cover traffic blurs, it does not hide: cover frames are sized like real
// messages, but only real messages trigger a push, which the relay can see.

/** Padded plaintext buckets (bytes). Anything larger throws in the web app. */
export const PADDED_BUCKETS: readonly number[] = [1024, 4096];
/** Padded frame header: 1 byte cover flag + 2 bytes big-endian length. */
export const PAD_FRAME_HEADER_BYTES = 3;

/** BIP39 (standard English wordlist, 2048 words). */
export const BIP39_SALT = 'mnemonic' as const;
export const BIP39_ITERATIONS = 2048;
export const BIP39_WORDS = 24;

/** HKDF info strings (extracted from bundle). */
export const HKDF_INFO_IDENTITY_ED25519 = 'veil-identity-ed25519' as const;

/** 64-byte root/chain derivation (KDF_RK): info = `vardum-ratchet-6/rk` -> {rk, ck}. */
export const ROOT_KEY_INFO = 'vardum-ratchet-6/rk' as const;
/** Handshake root: HKDF(shared, salt=`vardum-ratchet-6:<token>`, info=`rk0`, 32). */
export const RK0_SALT_PREFIX = 'vardum-ratchet-6:' as const;
export const RK0_INFO = 'rk0' as const;
/** Invite link secret (`k=` fragment, never sent to the relay):
 *  HKDF(k, salt=`vardum-pp-6:<token>`, info=`pp`, 32). */
export const PP_SALT_PREFIX = 'vardum-pp-6:' as const;
export const PP_INFO = 'pp' as const;
/** One-tap contact relay write credentials. */
export const CONTACT_WRITE_INFO = 'vardum-contact-write-6' as const;
/** Session fingerprint transcript label (see kdf.ts transcriptFingerprint). */
export const FINGERPRINT_LABEL = 'vardum-fp-6' as const;
/** Signed ML-KEM prekey (b54-b74): Ed25519(IK, utf8(PQ_PREKEY_SIG_LABEL) || pq_pub bytes).
 *  No longer accepted from b75 on (audit 2 V9: undated). */
export const PQ_PREKEY_SIG_LABEL = 'vardum-pq-prekey-v1:' as const;
/** b75 (audit 2 V9): dated, domain-labelled prekey signatures. Each published signature is
 *  `b64(Ed25519(IK, utf8(LABEL) || key bytes || utf8(':' + ts))) + '.' + ts`, ts = the
 *  signing time in whole seconds since 1970 (decimal), so the date travels with — and is
 *  covered by — its signature. */
export const SPK_SIG_LABEL_V2 = 'vardum-spk-v2:' as const;
export const PQ_PREKEY_SIG_LABEL_V2 = 'vardum-pq-prekey-v2:' as const;
/** b75 (audit 2 V9): a prekey signed longer ago than this is refused. Prekeys rotate weekly
 *  (device restore.ts PREKEY_ROTATE_MS, when the app runs); the 21-day grace covers a phone
 *  left unopened for three weeks. A relay can no longer serve an old prekey for longer. */
export const PREKEY_SIG_MAX_AGE_MS = (7 + 21) * 24 * 3600 * 1000;
/** b75 (V9): clock skew allowed for a signing time in the future */
export const PREKEY_SIG_MAX_FUTURE_MS = 24 * 3600 * 1000;
/** b76 (one-time prekeys): label of a one-time prekey pair's signature. One signature covers
 *  the pair's id, its X25519 key AND its ML-KEM-768 key, so a relay can't mix one pair's
 *  classical half with another's PQ half, or hand out a key under another id:
 *  `b64(Ed25519(IK, utf8(LABEL || id || ':') || x_pub || pq_pub || utf8(':' || ts))) + '.' + ts`.
 *  Dated like the signed prekeys and refused past PREKEY_SIG_MAX_AGE_MS. */
export const OPK_SIG_LABEL = 'vardum-opk-v1:' as const;
/** b76 (one-time prekeys): a one-time prekey id — 16 lowercase hex characters (8 random bytes) */
export const OPK_ID_RE = /^[0-9a-f]{16}$/;
/** ML-KEM-768 public key / ciphertext sizes (FIPS 203). */
export const MLKEM768_PUB_BYTES = 1184;
export const MLKEM768_CT_BYTES = 1088;

/** Session-scoped Ed25519 ratchet-key signatures (prior finding H-1). The
 *  signing keypair is derived from the session's handshake root with this
 *  info string, one pair per direction (Batch C, B9), and every header's
 *  ratchet pub + PQ step pub is signed. Always on. */
export const RATCHET_SIG_INFO = 'vardum-ratchet-sig-6' as const;
/** b74 (veil-ratchet-7, VAR-09): label of the whole-header signature (every field but sig). */
export const RATCHET_HEADER_SIG_LABEL = 'vardum-ratchet-7/header' as const;
/** b75 (audit RT-5): the header-signing ("epoch") keys follow the root key. The key that
 *  signs the headers of a chain is derived, with this info string, from the root key that
 *  chain's own derivation used as its salt — so it changes at every DH ratchet step and
 *  heals with the root after a state compromise. */
export const RATCHET_EPOCH_SIG_INFO = 'vardum-ratchet-7/epoch-sig' as const;
/** b75 (audit RT-5): label of the second header signature, made with the per-direction
 *  SESSION key derived once from the handshake root (RATCHET_SIG_INFO). It never heals; it
 *  only lets the receiver tell "an authentic header my keys no longer match" (out of sync)
 *  from relay junk. It never gates key work on its own. */
export const RATCHET_HEADER_SESSION_SIG_LABEL = 'vardum-ratchet-7/header-session' as const;

/** b77 (veil-ratchet-8, spec §4.2): header keys. Each sending chain's header key is
 *  HKDF(ikm = R, salt = utf8(RATCHET_HEADER_KEY_LABEL), info = RATCHET_HEADER_KEY_LABEL + '/' + dir, 32),
 *  R = the root that salted that chain's own KDF_RK (the same root as its epoch signing key). */
export const RATCHET_HEADER_KEY_LABEL = 'vardum-ratchet-8/hdr' as const;
/** b77 (spec §4.2, deviation from the B77 design): the per-direction SESSION header-tag key,
 *  derived once from rk0 like the session signing keys. It seals only the sender's epoch
 *  number, bound to the encrypted header, so a receiver that can open no header key can still
 *  tell "my contact, keys diverged" (out of sync) and "an old copy" from relay junk. */
export const RATCHET_HEADER_SESSION_KEY_LABEL = 'vardum-ratchet-8/hdr-session' as const;
/** b77: the inner (JSON) header is framed u16be(len) || utf8 || zeros to exactly this many bytes.
 *  3810 (the design said 3840): with the 32-byte session tag the sealed header is 3870 bytes, a
 *  multiple of 3, so the header string is 'h8.' + exactly 5160 base64 characters, no '=' (5163). */
export const HEADER_FRAME_BYTES = 3810;
/** b77: the envelope's header string starts with this; the rest is standard base64 */
export const HEADER_PREFIX = 'h8.' as const;
/** b77: hnonce(12) || hct(frame + 16) || snonce(12) || sct(4 + 16) = 3870 bytes */
export const HEADER_SEALED_BYTES = 12 + HEADER_FRAME_BYTES + 16 + 12 + 4 + 16;
/** b77: every 1:1 header string has exactly this length (5163 characters) */
export const HEADER_STRING_LENGTH = HEADER_PREFIX.length + 4 * Math.ceil(HEADER_SEALED_BYTES / 3);
/** b77: the shape rule for a 1:1 header string, shared with the relay (spec §4.10). It also admits the '=='
 *  form (3868 bytes) the relay accepts; openHeader then requires exactly HEADER_SEALED_BYTES = 3870. */
export const HEADER_STRING_RE = /^h8\.(?:[A-Za-z0-9+/]{5158}==|[A-Za-z0-9+/]{5160})$/;
/** b77: is this a well-formed veil-ratchet-8 header string (shape only; it opens nothing) */
export function isSealedHeaderString(h: unknown): h is string {
  return typeof h === 'string' && h.length === HEADER_STRING_LENGTH && HEADER_STRING_RE.test(h);
}
