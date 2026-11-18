/**
 * @veil/device — GROUP messaging protocol (veil-group-3). First ported from the
 * web bundle (Sept 19, 2026); the native code has moved on since, and this
 * header describes the native code (b71 (audit): it used to describe the old
 * web wire format — unsigned v1 rekeys, an AEAD over the full header, a 7-day
 * record TTL — none of which is true any more). docs/protocol-spec.md §11 is
 * the full specification.
 *
 * b74 (owner decision: CLEAN BREAK): the group protocol became 'veil-group-2'. b74 clients
 * sent and accepted only veil-group-2 envelopes; veil-group-1 rows (b73 and older) are
 * irrelevant to them (marked processed, never shown). Fields that were optional for
 * older builds are now required: every rekey carries its signed recipient set rc, every
 * member list carries its epoch (e) and the first-bound sequence of every name (fb), and
 * group names are only ever 'enc2:' (HKDF sub-key; 'enc1:' raw-GEK blobs are refused).
 * The rekey and member-list signature labels moved on too (-rekey-v3, -members-v2), so a
 * body signed for veil-group-1 never verifies here. A member leaves with a signed
 * "__veil_group_leave" control message (b74, VAR-05).
 *
 * b77m (CLEAN BREAK again): the protocol is now 'veil-group-3' (GROUP_PROTO). Two things changed, so a
 * veil-group-3 envelope can't be read by a veil-group-2 build and vice versa: every epoch key is delivered
 * in a HYBRID wrap (X25519 with the member's identity key + ML-KEM-768 to its signed PQ prekey, audit
 * VAR-10; a wrap without the X25519 half is refused), and the message key's HKDF label is v2 and names the
 * sender chain (audit VAR-38). A row under another 'veil-group-N' tag is never opened: the thread shows an
 * "update needed" note saying which side must update (groupProtoMismatchNote).
 *
 * Wire contract summary:
 *  - Envelope header (canonical order, anything else refused):
 *    {v:'veil-group-3', sid:<sender tag>, ge:<epoch>, n:<send counter>, ch:<sender chain id>, sv, sig}.
 *    The AEAD associated data is the CORE header (everything but sig); sig is the
 *    sender's Ed25519 over label ‖ core ‖ IV ‖ SHA-256(ct) (sv 2; sv 3 = a seat intro).
 *  - Message key: HKDF-SHA256(ikm=GEK, salt=SHA256('veil-group-bind:'+groupToken+':'+epoch+':'+pqPubB64),
 *    info='veil-group-msg-v2:'+sid+':'+ch+':'+n, 32) — AES-256-GCM, IV 12B random (b77m, audit VAR-38: the
 *    v2 label binds the sender chain id; a seat intro keeps 'veil-group-msg:'+sid+':'+n under its seat key).
 *    b73 (audit V-15): pqPubB64 is the epoch's "group PQ key": an ML-KEM-768 public key
 *    whose private half is thrown away when it is made. It protects nothing; it is a
 *    public per-epoch salt (and the link binding's input), kept only because the relay
 *    requires an ML-KEM-768-shaped value and older builds mix it in. What is
 *    post-quantum about a group is the DELIVERY of each epoch key (ML-KEM-768 wraps),
 *    not the epoch key itself (a 32-byte AES key).
 *  - Payload (b76: the smallest of [1024, 4096, 16384, 32768] that holds it, by length alone — posts capped at
 *    4096, membership controls at 32768; stripped strictly, cc/padding.ts, spec §8.3):
 *    [1 cover flag][2 BE length][utf8 text][sender trailer][zero pad]. b71 (audit F-12):
 *    the trailer is [0xA7][8 BE sent-at ms][4 BE per-sender sequence], as in 1:1
 *    (cc/padding.ts) — inside the encryption and covered by the signature, so the
 *    relay can no longer choose a post's shown time or drop posts unseen.
 *  - Sender tag (b71 (audit F-13)): 'g' + hex(first 6 bytes of HMAC-SHA256(tagKey, veilId)),
 *    tagKey = HKDF(GEK, salt=SHA256('vardum-group-sender-v2:'+groupToken+':'+epoch), 'sender-tag').
 *    Only holders of the epoch key can compute it, so the TAG doesn't name the author
 *    to someone who only has the roster. b73 (audit V-09): that is all it does — the
 *    relay CAN link every post to a member: each envelope is submitted with the
 *    sender's own seat session token and write credential (and the account behind
 *    them), and the relay bound that seat to the member's Vardum ID and IK when it
 *    attested. The old public form, SHA-256('veil-group-sender:'+groupToken+':'+epoch+
 *    ':'+veilId)[0:6] (senderTag), is still accepted from older builds (b77u, audit 6 R4 #13: until
 *    groupTagPolicy.publicPostsUntilMs; after it on seat intros only), used by a
 *    joiner that holds no key yet (its seat intro), and used for ONE post at a time
 *    when a relay not yet updated refuses the keyed tag (see submitGroupEnvelope).
 *  - Replay guard: per SIGNER (identity key; b77p, audit VAR-07 — it was per sender tag), keyed on the
 *    signed (ch, n): {last, skipped[]} per chain — n<=last must be in skipped (then consumed); n>last buffers
 *    the skipped counters (cap 64). b77p (audit VAR-10): up to 4 chains per signer stay open, in any order; a
 *    chain pushed out of that set is retired (refused for the rest of the epoch). b77u (audit 6 R4 #14): plus the
 *    signer's last GROUP_POSTS_SEEN signed (seq, sentAt) pairs, across epochs — a copy under a fresh chain is a replay.
 *  - Rekey (v2, signed): the creator wraps the new GEK for EACH trusted member in a hybrid wrap (b77m,
 *    audit VAR-10): wrap {to, ct, xe, wk, wi}, ct = ML-KEM-768 encapsulation to the member's signed PQ prekey,
 *    xe = a fresh creator X25519 pub (DH with the member's IK in Montgomery form),
 *    wk = AES-GCM(HKDF(ssX ‖ ssPQ, salt=SHA256(REKEY_WRAP_LABEL:group:epoch), info=REKEY_WRAP_LABEL:toVeilId),
 *    newGEK) with AAD = JSON[REKEY_WRAP_LABEL, group, epoch, to, ct, xe] (buildRekeyWrap / openRekeyWrap),
 *    and sends {"__veil_group_rekey":2, body, sig} with body = JSON{t, ge, pq, rid, kc,
 *    pi, pc, at, nm?, rc, ms, mh, rh, wraps}, sig = Ed25519(creator IK, 'vardum-group-rekey-v3:' ‖ body),
 *    ms/mh (b75, audit GR-5) = the number and membersHash of the member list it was made with,
 *    rh (b76r1, audit AUD-G2) = the rotation hash over the whole rotation (rotationHash; every part signs
 *    the same one, and a member applies a rotation only once it holds every part — finishRotation),
 *    then gate action 'rotate'. Receivers accept only the creator's signature, a
 *    forward epoch and a matching key commitment kc. b73 (audit V-07): rc = the sorted
 *    Vardum IDs the epoch key is meant for; an in-group rekey is refused if any wrap
 *    or rc entry names someone not on the creator-signed member list (or the creator).
 *    b74 (rc-omission bypass): rc is REQUIRED — a rekey without it is malformed and refused.
 *  - Epoch fingerprint: SHA-256('veil-group-epoch:'+token+':'+epoch+':'+GEK+':'+pqPub+':'+sorted member IKs
 *    +':rc='+sorted rc) — b74: always with the recipient set (a group's first epoch: rc = [])
 *    → hex, uppercased, grouped in 4s with dashes (see epochFingerprint).
 *  - Creator attest: Ed25519(ikSeed) over 'vardum-group-attest-v2:' ‖ JSON{group_token, veil_id, IK_pub, joined_epoch}
 *    (b75, audit GR-8: labelled; it was bare JSON).
 *  - Evict deny-sig: Ed25519(ikSeed) over 'vardum-group-deny-v2:' ‖ JSON{group_token, target_IK_pub, deny_epoch} (b75: labelled).
 *  - Intro: {"__veil_intro":1, p, s}, s = Ed25519(IK) over 'vardum-group-intro-v2:' ‖ p, p names the group (t) (b75: labelled).
 *  - Group name blob: 'enc2:'+b64(iv)+':'+b64(AES-GCM(nameKey, name)), nameKey = HKDF(GEK,
 *    SHA-256('vardum-group-name-key-v2:'), 'group-name', 32) (b73 (audit V-22): the raw GEK is
 *    no longer used as an AES key; b74: 'enc1:' blobs — AES-GCM under the raw GEK — are refused).
 *  - Member list: {"__veil_group_members":1, body, sig}, body = JSON{t, seq, e, m, nm?, fb, rm?},
 *    sig = Ed25519(creator IK, 'vardum-group-members-v2:' ‖ body). b74: e = the epoch it was
 *    published in (a member applies it only in that epoch); fb = IK_pub -> the sequence at
 *    which that member's current name was first bound (name clashes go to the lowest fb).
 *  - Leave (b74, VAR-05): {"__veil_group_leave":1, body, sig}, body = JSON{t, ik, id, e, at},
 *    sig = Ed25519(leaver IK, 'vardum-group-leave-v1:' ‖ body). The creator treats it as a removal.
 *  - Protocol version on submitEnvelope: 'veil-group-3' (GROUP_PROTO); group envelopes carry
 *    BOTH session_token and group_token.
 *  - Auto-rotation trigger (creator): 100 envelopes received or 24 h since
 *    epoch start. Members stop sending on an epoch older than 7 days
 *    (MEMBER_EPOCH_MAX_MS; b77q owner (1 Nov)) and stop showing posts past 9 days (b77u, R4 #16: were shown unverified).
 *  - Group record persistence: the JSON record in the OS secure store under
 *    'veil_gk_'+token, with the send counter (~send) and replay window (~recv) in
 *    their own small items. Native records have no TTL (keys are per device).
 */
import { sha256 as nobleSha256 } from '@noble/hashes/sha256'; // b77t2 (L-8): a hash with no wait
import { toB64, fromB64, utf8, fromUtf8, concat } from '../../crypto-core/src/bytes';
import { unwrapPinned } from './wipe-generation';
import { readPrevPrekeys } from './prekeys-prev';
import { hkdf, sha256, hmacSha256 } from '../../crypto-core/src/kdf';
import { ikSign, verifyWithIk, veilIdFromIkPub } from '../../crypto-core/src/identity';
import { mlkemEncap, mlkemDecap } from '../../crypto-core/src/mlkem';
import { x25519, edwardsToMontgomeryPub, edwardsToMontgomeryPriv } from '@noble/curves/ed25519'; // b77m (audit VAR-10)
import type { VeilStorage } from '../../crypto-core/src/storage-adapter';
import { MESSAGE_CLASSES, padMessageFrame, unpadMessageFrame, padBlob, unpadBlob, coverFillerText } from '../../crypto-core/src/padding';

/** b74 (owner decision: clean break): veil-group-2 only — veil-group-1 rows are never read.
 *  b77m review (INFO): veil-group-3 — the key wraps (hybrid, VAR-10) and the message-key label (bound to the
 *  chain id, VAR-38) changed, so a b77m group envelope is not readable by an earlier build and vice versa; the
 *  tag says so. A row under another veil-group-N tag is not opened: the thread says which side must update
 *  (groupProtoMismatchNote) instead of failing silently. */
export const GROUP_PROTO = 'veil-group-3';
/** b77m review (INFO): the number in a group envelope tag ('veil-group-N'), or null */
export function groupProtoVersion(v: unknown): number | null {
  const m = typeof v === 'string' ? /^veil-group-(\d{1,4})$/.exec(v) : null;
  return m ? Number(m[1]) : null;
}
/** b77n (pre-audit LOW-2): how far from our own veil-group-N a tag may be and still be noted (a real
 *  older or newer build is one or two versions away; anything further is noise or an injection) */
export const GROUP_PROTO_NOTE_WINDOW = 2;
/** b77n (pre-audit LOW-2): the thread note for a group envelope under another veil-group-N tag. The tag
 *  rides in the envelope header, which nothing authenticates (the relay, or any member, can set it), so the
 *  note says only what this phone saw and never tells the user to update. One note per group (the caller's
 *  id is per group, not per version); a tag outside our version ±GROUP_PROTO_NOTE_WINDOW gives no note.
 *  null: not a group tag at all, ours, or outside the window.
 *  (b77m review INFO said which side must update, once per version: forgeable "Update Vardum" lines.) */
export const GROUP_PROTO_MISMATCH_NOTE = 'The server delivered a message in a format this version can’t read.';
export function groupProtoMismatchNote(v: unknown): string | null {
  const n = groupProtoVersion(v);
  const mine = groupProtoVersion(GROUP_PROTO) as number;
  if (n === null || n === mine || Math.abs(n - mine) > GROUP_PROTO_NOTE_WINDOW) return null;
  return GROUP_PROTO_MISMATCH_NOTE;
}
export const GROUP_KEY_PREFIX = 'veil_gk_';
/** Batch H (round-6 review R6-2-01): the send counter lives in its own small item
 *  (`veil_gk_<token>~send`), so a group record too large for the phone's secure
 *  store no longer blocks sends. Same prefix, so every group-key wipe covers it. */
export const GROUP_SEND_SUFFIX = '~send';
/** b71 (review P-06): the receive replay window lives in its own small item too
 *  (`veil_gk_<token>~recv`), saved fail-closed: a message whose window did not land
 *  is not shown (it is retried), so a refused write can't roll the window back and
 *  re-open messages already shown. Same prefix, so every group-key wipe covers it. */
export const GROUP_RECV_SUFFIX = '~recv';
/** b77t (audit 5 M-C / IH C-1): the group's epoch floor (`veil_gk_<token>~floor`): the highest epoch whose key
 *  this phone has held (e) and the highest a creator-signed message showed it (s). It lives OUTSIDE the record, so
 *  forgetGroup leaves it and a phone that lost its record and re-joined can't be handed an older epoch (a hostile
 *  relay replaying its old key delivery rolled it back to an epoch a removed member holds). Same prefix, so every
 *  veil_gk_ wipe (a full wipe, a Nothing-at-Rest flip) clears it with the keys. Not a record: no groupToken. */
export const GROUP_FLOOR_SUFFIX = '~floor';
/** b76 (padding, spec §8.3): every group payload — post, receipt, intro, leave, member list,
 *  rekey part, cover — is padded to the smallest class of ONE ladder that holds it,
 *  [1024, 4096, 16384, 32768] (cc/padding.ts MESSAGE_CLASSES), chosen by length alone. Before
 *  b76 member lists and rekey parts used their own buckets (4096/16384/32768, never 1024)
 *  and everything else [1024, 4096], so a control message's bucket set marked it as one.
 *  What still differs by kind is only how LARGE a payload may be: a post (anything that is
 *  not a membership control) is capped at 4096, as before; a control at 32768, which stays
 *  under the relay's 48,000-character envelope cap (Deno KV 64 KB). */
export const GROUP_CLASSES: readonly number[] = MESSAGE_CLASSES;
const POST_MAX = 4096;
const CONTROL_MAX = GROUP_CLASSES[GROUP_CLASSES.length - 1];
/** b54: rekey parts carry up to REKEY_WRAPS_PER_PART ML-KEM wraps (~1.6 KB each) plus the
 *  new group PQ key. b76 (padding): the most a part may carry — rekeyWrapsPerPart picks
 *  fewer, so that parts land in the smallest class they can (4 KiB, the class of long posts
 *  and some cover posts, whenever one wrap fits it). */
export const REKEY_WRAPS_PER_PART = 16;
const PAYLOAD_HDR = 3; // 1 cover byte + 2 BE length bytes
const MAX_SKIPPED = 64;
/** b77p (audit VAR-10): chain windows one signer keeps open per epoch (a chain pushed out is retired) */
const GROUP_OPEN_CHAINS = 4;
/** b77u (audit 6 R4 #14): the signed (sequence, sent-at) pairs of a signer's last numbered posts kept to spot a
 *  copy of one under a fresh chain (kept across epochs; bounded, about 1 KB a signer) */
export const GROUP_POSTS_SEEN = 64;
/** b77u (audit 6 R4 #13): ordinary posts under the PUBLIC (unkeyed, roster-computable) sender tag are read only
 *  until this date — the transition for the relay-refusal fallback (F-13) and builds that still use it. After it
 *  the public tag is read only on seat intros (sv 3). A field (not a const) so tests can move it. */
export const groupTagPolicy = { publicPostsUntilMs: Date.UTC(2027, 1, 1) };
export function publicTagPostsAllowed(now: number = Date.now()): boolean {
  return now < groupTagPolicy.publicPostsUntilMs;
}
export const EPOCH_MAX_ENVELOPES = 100;
export const EPOCH_MAX_MS = 24 * 60 * 60 * 1000;
/** M-3 (b69 audit): slack on top of the 24 h rotation period before a member
 *  treats its epoch as overdue (creator's phone asleep, clock skew, a slow relay).
 *  b77q owner (1 Nov): 6 days, so the send limit is 7 days again (MEMBER_EPOCH_MAX_MS). */
export const MEMBER_EPOCH_SLACK_MS = 6 * 24 * 60 * 60 * 1000;
/** Batch D (D-06, RV-05) + M-3 (b69 audit): a member stops sending on a key older
 *  than this, and the group shows a "keys haven't been refreshed" notice. The
 *  creator rotates every EPOCH_MAX_MS, so a key this old means rotations are not
 *  arriving — or a relay is withholding them (the M-3 partition: the creator
 *  removed someone, rotated, and the relay hides the new epoch from this member).
 *  The removed member still holds this key. Was 7 days (owner decision 18 Oct);
 *  the b69 audit showed that gave a withholding relay a week of readable sends, and b71
 *  cut it to 48 h.
 *  b77q owner (1 Nov): 7 days again, as decided on 18 Oct — "so quiet groups whose creator
 *  is away for a few days keep working". The cost is accepted: a relay that withholds a
 *  rotation (after a removal) gets up to a week of sends the removed member can read. The
 *  rest of M-3 stays: the creator still rotates every 24 h, the stale notice, the read limit
 *  below, signed "behind" evidence (signedAheadEpoch) and a signed removal ahead
 *  (removalPendingEpoch) still stop sends at once. */
export const MEMBER_EPOCH_MAX_MS = EPOCH_MAX_MS + MEMBER_EPOCH_SLACK_MS;
/** M-3 (b69 audit): a member does not show posts as verified when they were sent
 *  under an epoch whose signed start ("at" in the creator's rekey; local apply
 *  time for older epochs without it) is older than this. Longer than the send
 *  limit on purpose: a member who was offline reads an epoch's backlog only when
 *  it gets back; past this the posts are still shown, but marked as sent under old
 *  keys and never as verified.
 *  b71 (review P-04): was 7 days. Now the send limit (the last honest post of
 *  an epoch) plus the longest message lifetime the app offers short of 30 days
 *  (48 h): every honest post of an epoch is gone from the relay by then. With the
 *  30-day setting, posts read more than that after their epoch began are shown
 *  marked "old keys" instead of verified (still shown).
 *  b77q owner (1 Nov): with the 7-day send limit this is 9 days (b71: 4).
 *  b77u (audit 6 R4 #16): past it a post is NOT SHOWN (pollGroupInbox; control messages are still read). Not
 *  shortened: the 7-day send limit is its floor, and the 48 h covers the longest short message lifetime. */
export const MEMBER_EPOCH_READ_MAX_MS = MEMBER_EPOCH_MAX_MS + 48 * 60 * 60 * 1000;
/** b71 (review P-01): a seat nobody used within this long is not admitted any more
 *  (and is dropped from the creator's record). The relay's own row expires sooner
 *  (its dials, 30 days at most). */
export const SEAT_MAX_AGE_MS = 30 * 24 * 60 * 60 * 1000;

/** b77k (IP77-2, iPhone battery): this group can't take a send yet, for a reason written for people
 *  (not admitted by the creator yet; a removal waiting for its key rotation). Shown as it is — the
 *  generic "Something went wrong" used to sit above the amber "Waiting for the group creator…" note. */
export class GroupSendBlockedError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'GroupSendBlockedError';
  }
}

/** M-3: a send refused because this member's group keys need refreshing. */
export class GroupKeysStaleError extends Error {
  /** b71 (audit F-04): 'removed' = the creator's signed member list says someone was
   *  removed at an epoch this phone doesn't have yet */
  readonly reason: 'stale' | 'behind' | 'removed';
  constructor(message: string, reason: 'stale' | 'behind' | 'removed') {
    super(message);
    this.name = 'GroupKeysStaleError';
    this.reason = reason;
  }
}

/** M-3: ms-epoch the current group epoch started (signed start, or local apply time), null if unknown */
export function epochStartMs(rec: { epochStartedAt?: string }): number | null {
  const t = rec.epochStartedAt ? Date.parse(rec.epochStartedAt) : NaN;
  return Number.isFinite(t) ? t : null;
}

/** M-3: how fresh this member's group keys are. `stale`: no rotation seen within
 *  the rotation period plus slack (sends stop, the group shows a notice).
 *  `behind`: the group creator has signed a newer epoch that hasn't reached this phone.
 *  The creator's own epoch is the group's, so it is never stale or behind here.
 *  b75 (audit GR-2): `behind` rests only on creator-signed evidence (signedAheadEpoch: a
 *  creator-signed rekey for a later epoch this phone read but couldn't apply). b70–b74 took it
 *  from the relay's unsigned roster epoch (seenEpoch), so the relay alone paused a member's sends
 *  for a day and made the app advise rejoining — and leaving gets an identity denied for good. */
export type GroupFreshnessInput = { role: string; epoch: number; epochStartedAt?: string; signedAheadEpoch?: number; removalPendingEpoch?: number; removedFromGroup?: number; ghostKeyEpoch?: number };
export function groupKeyFreshness(
  rec: GroupFreshnessInput, now = Date.now(),
): { stale: boolean; behind: boolean; removed: boolean; removedSelf: boolean; ghost: boolean; ageMs: number } {
  const started = epochStartMs(rec);
  const ageMs = started === null ? 0 : Math.max(0, now - started);
  if (rec.role !== 'member') return { stale: false, behind: false, removed: false, removedSelf: false, ghost: false, ageMs };
  return {
    // b77m review (L2): this epoch's key reached someone not on the creator-signed list (a gate delivery checked
    // once its list arrived) — signed evidence, cleared by the next key (a new epoch)
    ghost: rec.ghostKeyEpoch !== undefined && rec.ghostKeyEpoch === rec.epoch,
    stale: ageMs > MEMBER_EPOCH_MAX_MS,
    // b75 (audit GR-2): signed by the creator, so the relay can't raise it; no lapse is needed (a
    // post under the old key isn't read by members on the new one anyway). Cleared when the
    // epoch's key arrives (advanceEpoch).
    behind: (rec.signedAheadEpoch ?? 0) > rec.epoch,
    // b71 (audit F-04): the creator-signed member list announced a removal at an
    // epoch this phone doesn't hold — the current key is one the removed member
    // has, so nothing more is sent under it. Signed by the creator, so the relay
    // can't raise it; it clears when the new epoch's key arrives (advanceEpoch).
    // b75r1 (audit G-7): and when the list removed THIS phone (it will never get the next key)
    removed: (rec.removalPendingEpoch ?? 0) > rec.epoch || rec.removedFromGroup !== undefined,
    removedSelf: rec.removedFromGroup !== undefined,
    ageMs,
  };
}

/** M-3: throw the user-facing GroupKeysStaleError when a member must not send
 *  (also checked before a media upload, so nothing is uploaded only to be refused). */
export function assertGroupKeysFresh(rec: GroupFreshnessInput): void {
  const fresh = groupKeyFreshness(rec);
  if (fresh.removedSelf) {
    throw new GroupKeysStaleError('The group creator removed you from this group, so you can’t send here any more.', 'removed');
  }
  if (fresh.removed) {
    throw new GroupKeysStaleError('The group creator removed someone — waiting for new group keys. Sending resumes when they arrive.', 'removed');
  }
  if (fresh.ghost) {
    throw new GroupKeysStaleError('The group creator’s phone gave this group’s key to someone who isn’t on the member list, so sending is paused until the next key change.', 'removed');
  }
  if (fresh.stale) {
    throw new GroupKeysStaleError(`This group's keys haven't been refreshed for ${Math.floor(fresh.ageMs / 3600_000)} hours, so sending is paused. They refresh when the group creator opens the group — ask them to, or wait for it to sync.`, 'stale');
  }
  if (fresh.behind) {
    throw new GroupKeysStaleError('This group has new keys that haven\'t reached this phone yet. This phone has asked the group creator\'s phone for them; sending works again once they arrive.', 'behind');
  }
}
export const GROUP_MEMBER_CAP = 100; // b198 (was 8)

export interface GroupRecvState {
  last: number;
  skipped: number[];
  /** b196-r2: posting-session token the sender's counter `n` belongs to. A
   * re-minted posting session (end+rejoin, device restore) restarts
   * the sender chain at n=0 while the sender TAG stays identical — keying the
   * replay guard on (sid, n) alone rejected every message from the new chain
   * as a replay. */
  chain?: string;
  /** b54 (T-3): chains this sender already replaced — never accepted again */
  retired?: string[];
  /** b77p (audit VAR-10): this signer's older chains still open (newest first; chain/last/skipped above is
   *  the newest). At most GROUP_OPEN_CHAINS - 1; one pushed out goes to retired. */
  open?: Array<{ chain: string; last: number; skipped: number[] }>;
  /** b77u (audit 6 R4 #14): this signer's last numbered posts, `seq.sentAt@n.ch` (oldest first, at most
   *  GROUP_POSTS_SEEN; carried into the next epoch) — a post with a (seq, sentAt) seen here is a copy */
  posts?: string[];
}

export interface GroupRecord {
  groupToken: string;
  /** b198: this member's own group session token (background poll + push
   *  credential). Older records predate it — derive via findMainGroupSession. */
  sessionToken?: string;
  veilId: string;
  ikSeedB64: string;
  ikPubB64: string;
  role: 'creator' | 'member';
  /** b71 (review P-01): for a member still waiting for its key, the epoch the relay
   *  reported (only used to address the seat intro) */
  epoch: number;
  /** b71 (review P-01): '' for a member that has joined but not yet received the
   *  key from the creator (links no longer carry it) */
  gekB64: string;
  /** legacy: the first epoch's key, kept only to read the name (b70 re-review 5: no
   *  longer stored — the name itself is kept instead, and old records drop this on read) */
  nameGekB64?: string;
  pqPubB64: string;
  myTag: string;
  sendN: number;
  recv: Record<string, GroupRecvState>;
  envCount?: number;
  epochStartedAt?: string;
  /** b70 (audit GRP-5): the newest group epoch the relay's roster reported. b75 (audit GR-2): no
   *  longer written or read — the relay's unsigned word paused sends; see signedAheadEpoch. */
  seenEpoch?: number;
  /** b70 (re-review P5): when seenEpoch was recorded. b75: unused (see seenEpoch) */
  seenEpochAt?: number;
  /** b75 (audit GR-2): member — the newest epoch a creator-signed rekey this phone read (and
   *  verified) names but that this phone couldn't apply (no wrap for it in the part it read, or
   *  the member list the rekey was made with hasn't arrived, GR-5). While it is ahead of `epoch`
   *  nothing is sent under the old key, and the phone asks for the new one through the gate. */
  signedAheadEpoch?: number;
  /** roster: sender tag -> member IK_pub b64 (for per-sender signature checks) */
  senderKeys?: Record<string, string>;
  /** my own display nickname in this group (used for roster display) */
  myNick?: string;
  /** durable sender tag -> nickname map (intros are one-shot; this survives polls) */
  nicks?: Record<string, string>;
  /** b70 (re-review 13): the same names keyed by Vardum ID (tags change every epoch) */
  nicksById?: Record<string, string>;
  /** b92 F10: per-group envelope pagination cursor (full-page advance rule) */
  syncSkip?: number;
  /** b195: deletion-immune inbox cursor — server created_date of the last
   *  definitively-processed envelope (−1ms). Replaces the skip cursor for
   *  fetches: skip offsets SHIFT every time the relay purges expired rows,
   *  silently striding past unprocessed backlog at tester volume. */
  syncCursorAt?: string;
  /** the group's display name, kept locally once read from the relay blob */
  name?: string;
  /** b76r1 (audit AUD-G4): the name was read from a relay row's blob (opened under the group key), not from
   *  the creator's signed key delivery (nm) — a signed name replaces it */
  nameFromRow?: boolean;
  /** b92 F11: persistently-known envelope ids (marked only after definitive outcome), capped */
  knownEnvIds?: string[];
  /** b190: ms-epoch cooldown — auto-rotation stops re-attempting (identity
   *  lookups) until this time when a member has no published PQ prekey. */
  rotateBlockedUntil?: number;
  /** b190: the server-side session row is gone (deleted group) — the thread
   *  is fail-closed ended; roster polls stop, local history stays readable. */
  sessionEnded?: boolean;
  /** b54 (T-3): this device's current sender chain id (fresh at counter 0) */
  sendChain?: string;
  /** b54 (Batch A, N-1): the group creator's IK — the ONLY key whose signature
   *  can move this group to a new epoch. Creator: own IK. Member: from the
   *  invite link `c=` fragment. */
  creatorIkPubB64?: string;
  /** b54 (Batch A, H-3): creator-side LOCAL deny list (evicted IKs). A rekey
   *  never wraps to these, whatever the relay roster says. */
  evictedIks?: string[];
  /** Batch C (A1): creator — every seat this device minted: seat token ->
   *  { key: HKDF of the seat link's secret `k` (the relay never sees k),
   *    invitee: locked Vardum ID if any, usedBy: the ONE IK admitted through it }. */
  seats?: Record<string, GroupSeat>;
  /** Batch C (A1): creator — admitted members, IK_pub -> veil_id. Only these
   *  receive rekey wraps or count as senders (minus evictedIks). */
  admitted?: Record<string, string>;
  /** Batch E (round-3 review F-3): a pre-Batch-C creator record — the relay roster
   *  seen on its first poll (IK_pub -> veil_id), waiting for the creator to confirm.
   *  Nobody on it is trusted until confirmed. */
  legacyRoster?: Record<string, string>;
  /** Batch E (F-3): the signed member list must be (re)published on the next pass */
  memberListDirty?: boolean;
  /** Batch C (A1): member — the creator-signed member list (IK_pub -> veil_id).
   *  memberSeq undefined = a pre-Batch-C record (verified relay roster until the
   *  first signed list arrives); 0 = strict, trusts only the creator so far. */
  memberList?: Record<string, string>;
  memberSeq?: number;
  /** Batch C (A1): member — the seat I joined through and my proof for it (re-sent in my intro) */
  seatToken?: string;
  seatProof?: string;
  /** b70 (VAR-10): the seat proof bound to the creator key from the link */
  seatProof2?: string;
  /** ms-epoch of my last intro send (the re-send throttle) */
  introSentAt?: number;
  /** Batch C (A3): ms-epoch of my last missing-wrap request (the re-ask throttle) */
  wrapRequestedAt?: number;
  /** b77t (audit 5 M-C): the nonces of this membership's own keyless key requests ([nonce, ms-epoch], newest
   *  last). A creator's answer binds its rid to one (deliveryBindRid); a delivery for an epoch at or below
   *  this phone's epoch floor is taken only when so bound (an old delivery for a previous seat is not) */
  wrapReqNonces?: Array<[string, number]>;
  /** b77t (audit 5 L-8): creator — the number and member hash of the list numbered last (buildMemberList), set
   *  together, so a key delivery signs a consistent (ms, mh) pair even before that list's send is confirmed */
  numberedList?: [number, string];
  /** b77t (audit 5 L-7): ids of rows whose UNAUTHENTICATED header names a later epoch, held in their own bounded
   *  bucket ([id, header epoch]) — never mixed with the held rows above, never pushing them out */
  heldFutureIds?: Array<[string, number]>;
  /** Batch C (A3): a rotation persisted BEFORE anything was sent; a retry resends these exact parts */
  pendingRotation?: PendingRotation;
  /** Batch C (A3): an eviction is waiting for its rotation — normal sends are refused
   *  until a rotation that excludes every evicted IK completes. Value = epoch at eviction. */
  evictionPendingAt?: number;
  /** Batch C (A3): IKs the last completed rotation wrapped to (an eviction checks it excluded the evicted) */
  lastRotationRecipients?: string[];
  /** Batch D (D-06): Vardum IDs the last rotation skipped (no valid signed prekey);
   *  they recover the key through the missing-wrap request once their prekey is good */
  lastRotationSkipped?: string[];
  /** b71 (review P-02): the salt of the group identity — groupToken =
   *  groupIdFor(creator IK, groupSalt). Groups made before b71 have none (their
   *  token is random, so no link for them can bind the creator key). */
  groupSalt?: string;
  /** b71 (review P-01): creator — this group's invite links carry no group key.
   *  A record without it (made before b71) rotates once, so any older link's key
   *  stops opening anything. */
  linksV2?: boolean;
  /** b71 (review P-01): member — the seat key (from the link secret), kept until
   *  admission so the seat intro can be re-sent */
  seatKey?: string;
  /** b71 (review P-03): names learnt from a signed binding, IK_pub -> name, in
   *  list order (member: the creator-signed member list, each name self-signed by
   *  its member; creator: the members' own seat-proven intros). Shown as is unless
   *  an earlier entry shows the same name. Any other name carries an ID suffix. */
  boundNicks?: Record<string, string>;
  /** b71 (review P-03): creator — each member's self-signed name, IK_pub ->
   *  [name, signature], published in the member list */
  nameSigs?: Record<string, [string, string]>;
  /** b71 (review P-03): names seen only in loose intros (Vardum ID -> raw name) */
  introNicks?: Record<string, string>;
  /** b71 (review P-03): member — the epoch in which my name binding was last sent */
  nameIntroEpoch?: number;
  /** b71 (audit F-07): creator — seat claims waiting for the creator's tap, IK_pub ->
   *  claim. A plain link's claim is never admitted without one (admitGroupClaims). */
  pendingClaims?: Record<string, GroupSeatClaim>;
  /** b71 (audit F-02): creator — IK_pub -> the first epoch this member may receive. An
   *  admission sets it to the next epoch, so its first key is a fresh one and it never
   *  reads what was posted before it was let in. deliverGroupKey refuses before that. */
  joinEpochs?: Record<string, number>;
  /** b71 (audit F-01): creator — seats retired by an eviction or a decline (grow-only,
   *  capped), so a stale copy of the record can't bring one back */
  retiredSeats?: string[];
  /** b71 (audit F-04): creator — removals announced in the signed member list:
   *  [IK_pub, veil_id, the first epoch without them] (the newest 16) */
  removals?: Array<[string, string, number]>;
  /** b71 (audit F-04): member — the member list announced a removal at this epoch;
   *  while it is ahead of `epoch`, nothing is sent (the removed member holds the key) */
  removalPendingEpoch?: number;
  /** b71 (audit F-24): creator — the dials every seat of this group is minted with
   *  (set at creation; new seats no longer take the creator's current global settings) */
  dials?: { burnAfterOpen: boolean; expireAfterSeconds: number; keyRetentionHours: number; defaultTtlSeconds: number };
  /** b71 (audit F-12): my per-sender sequence (posts numbered in the signed trailer) */
  postSeq?: number;
  /** b71 (audit F-12): the highest sequence seen per sender, IK_pub -> seq */
  recvSeq?: Record<string, number>;
  /** b71 (audit F-13): the epoch in which the relay refused my keyed sender tag.
   *  b73 (audit V-09): no longer written or honoured — a refusal now sends only that one
   *  post under the public tag (records from b71/b72 drop it at their next send). */
  legacyTagEpoch?: number;
  /** b73 (audit V-01): envelope ids looked at but not processable YET (a future epoch
   *  within reach, a sender on the relay roster this phone doesn't trust yet). They end
   *  the inbox pager's descent like processed rows (so they can't hide newer rows) and
   *  are retried whenever fetched. The newest 300 (b77t (audit 5 L-7): older ones are dropped from the set,
   *  never marked processed). */
  heldEnvIds?: string[];
  /** b73 (audit V-01): the trust state (epoch : member-list seq : trusted count) the held
   *  rows were judged under — when it changes the next pass re-scans deeper */
  heldStateKey?: string;
  /** b73 (audit V-07): the current epoch's signed recipient set (sorted Vardum IDs, the
   *  rekey's rc) — part of the epoch fingerprint. b74: every rekey carries one; a creator's
   *  first epoch has []. (Absent only on a record from before b74, read as [].) */
  epochRecipients?: string[];
  /** b77q (audit 3 GR-2): member — the rotation id (rid) of the posted rotation this phone applied for the current
   *  epoch (unset when the epoch came by a gate delivery, whose rid is its own): a second rotation id for the same
   *  epoch read later is the creator's phone contradicting itself (collectRotationPart) */
  epochRid?: string;
  /** b73 (audit V-07): creator — the IKs on the last member list it published (a rotation
   *  that wraps to anyone else publishes a list naming them first) */
  listedIks?: string[];
  /** b73 (audit V-07): member — an in-group rekey for this epoch gave the key to someone
   *  not on the member list and was refused; a gate delivery of this epoch is refused too */
  rekeyRefusedEpoch?: number;
  /** b77m review (L2): member — gate deliveries taken with a NEWER signed list than this phone held (ms >
   *  memberSeq), whose recipient set (rc) could not be checked then. Checked when that list (or a later one)
   *  arrives (applyMembersPayload); at most 8 kept. */
  deliveryChecks?: Array<{ ge: number; ms: number; mh: string; rc: string[]; at?: number;
    /** b77q review (GR-1 residual): when this phone kept it, and how many inbox passes have found it still waiting
     *  (expireDeliveryChecks) */
    kept?: number; passes?: number;
    /** b77q owner (1 Nov, "Warn, keep sending"): already warned about (a later rekey numbered below it, or past the
     *  wait). Kept, not dropped: the list it names (or a later epoch's) can still prove a stray, which stops sends */
    warned?: true }>;
  /** b77q review (GR-1 residual): member — deliveries flagged outside a member-list apply (a later epoch's creator-signed
   *  rekey numbered below them, or still unsettled past the wait), for the inbox pass to say in the thread
   *  (takeDeliveryGhostNotes) */
  deliveryGhostNotes?: GroupDeliveryGhost[];
  /** b77m review (L2): member — that later check found the delivered key given to someone not on the list:
   *  nothing more is sent under this epoch's key (groupKeyFreshness.ghost) until the next key change */
  ghostKeyEpoch?: number;
  /** b77u (audit 6 IH full I-4): members (first 16 characters of the IK) whose "joined the group" line this phone
   *  has shown — a join is said once (at most 128 kept) */
  joinNoted?: string[];
  /** b73 (audit V-07): member — the removals the latest creator-signed list announced,
   *  [Vardum ID, the first epoch without them]: a rekey for an earlier epoch may still
   *  wrap to them (a rotation already partly sent when the removal began is finished) */
  listRemovals?: Array<[string, number]>;
  /** b74 (VAR-06): creator — the last first-bound sequence handed out (see nameFb) */
  nameSeq?: number;
  /** b74 (VAR-06): IK_pub -> [name, the sequence at which that name was first bound to this
   *  member]. Creator: assigned when a member's (or its own) name binding changes. Member:
   *  from the creator-signed member list (fb). A name clash is won by the LOWEST sequence —
   *  whoever held the name first — never by admission order, so a member admitted earlier
   *  can't rename itself to a later member's name and take it over. */
  nameFb?: Record<string, [string, number]>;
  /** b74 (VAR-05): creator — IK_pub -> ms-epoch a trusted member was first seen missing from
   *  the relay's roster (a member who left without the leave message). Only surfaced to the
   *  creator, never acted on alone: the relay can fake an absence. */
  missingSince?: Record<string, number>;
  /** b75 (audit GR-1): member — members whose own signed leave this phone read (directly or re-posted
   *  by another member), IK_pub -> {vid, at: min(the leave's signed time, when this phone first saw
   *  it), text: the signed leave, kept until a creator-signed list drops them (for the re-post)}.
   *  They are no longer trusted here (trustedMembers), and a later rekey made after `at` that still
   *  gives them the key is refused. Grow-only (merged), newest 64.
   *  b77q review (GR-6): `at` is when this phone first saw the leave (the leave's own signed time is the leaver's
   *  choice and is no longer used: a back-dated one made honest rekeys look made after it), and `ep` the epoch this
   *  phone was on then — the leaver held that epoch's key, so a rekey for it or an earlier one may still name them
   *  (older records without `ep` keep the `at` rule alone). */
  leftIks?: Record<string, { vid: string; at: number; text?: string; ep?: number }>;
  /** b75 (audit GR-5): member — membersHash of the latest creator-signed list applied (with memberSeq) */
  memberListHash?: string;
  /** b75 (audit GR-5): creator — membersHash of the last list it published (with listedIks) */
  listedHash?: string;
  /** b76r1 (rotation commitment): member — the creator-signed rekey parts of rotations to a later epoch, kept
   *  by rotation id until every part of that rotation is here (only then is it checked as a whole and applied),
   *  and kept further while the member list it was made with (ms) hasn't arrived (b75, audit GR-5). Compact:
   *  per part only its number, the digest of its wraps and who they are to; the whole text only of the part
   *  carrying this phone's wrap. Bounded by pc per rotation, HELD_ROTATIONS_MAX rotations and
   *  HELD_ROTATIONS_MAX_BYTES (b75 kept whole part texts, the newest 8 — b76 sends one part per member, so a
   *  held 10-member rotation lost its oldest parts: audit AUD-G3). */
  heldRotations?: HeldRotation[];
  /** b75 (audit GR-1): member — the leavers whose leave this phone has re-posted (once each) */
  leavesRelayed?: string[];
  /** b75 (audit GR-8): creator — wrap-request nonces it has answered, [nonce, the request's signed time] */
  wrapReqSeen?: Array<[string, number]>;
  /** b75 (audit GR-1): creator — leavers whose "left, can't read from now on" note is owed: it is
   *  shown only once the rotation that excludes them has completed. [IK_pub, shown name] */
  leaveNotesOwed?: Array<[string, string]>;
  /** b75r1 (audit G-1): names freed recently — [IK_pub of who held it, the name, until ms]. A name a member
   *  was bound to and no longer is (it was removed, left, or renamed) is held back for GROUP_NAME_HOLD_MS:
   *  anyone else using it meanwhile is shown with the ID suffix (shownGroupNames), so nobody silently takes
   *  over the name of someone who just went. Member: from consecutive creator-signed lists; creator: from
   *  its own removals and the renames it learns. b77p (audit VAR-13): the newest 4 per holder (512 in all). */
  heldNames?: Array<[string, string, number]>;
  /** b75r1 (audit G-1): the names this phone showed for the other members at the end of its last pass,
   *  IK_pub -> shown name — a shown name that changes without a rename note gets a note of its own */
  shownNames?: Record<string, string>;
  /** b75r1 (audit G-7): member — the creator-signed list removed THIS phone (its rm names this phone's key,
   *  or a list dropped it): the epoch of that list. The thread says so plainly ("removed you"). */
  removedFromGroup?: number;
  /** b75r1 (audit G-4): member — per leaver whose leave this phone re-posts, IK_pub -> {next: ms of the next
   *  re-post, n: re-posts so far}. Re-posted at random later times (never in the pass the leave was read)
   *  until a creator-signed list drops the leaver, at most LEAVE_REPOST_MAX times. */
  leaveReposts?: Record<string, { next: number; n: number }>;
}

/** b75r1 (audit G-1): how long a freed name is held back from everyone else (see GroupRecord.heldNames) */
export const GROUP_NAME_HOLD_MS = 30 * 24 * 60 * 60 * 1000;

/** b75r1 (audit G-1): record that `ik` no longer goes by `name` (removed, left or renamed) */
export function holdFreedName(rec: Pick<GroupRecord, 'heldNames'>, ik: string, name: string | undefined, now = Date.now()): void {
  if (!ik || !name) return;
  const keep = (rec.heldNames ?? []).filter((h) => Array.isArray(h) && h[2] > now && !(h[0] === ik && h[1] === name));
  // b77p (audit VAR-13): the cap is per holder. One list of the newest 32 let a member push a removed member's
  // held name out with 32 throwaway renames of its own, then take that name unsuffixed. Now a holder's new
  // hold evicts only that holder's own oldest (GROUP_HELD_NAMES_PER_IK each), and the overall cap
  // (GROUP_HELD_NAMES_MAX, above every member's share of a 100-member group) is a backstop.
  const mine = keep.filter((h) => h[0] === ik);
  const drop = new Set(mine.slice(0, Math.max(0, mine.length - (GROUP_HELD_NAMES_PER_IK - 1))));
  rec.heldNames = [...keep.filter((h) => !drop.has(h)), [ik, name, now + GROUP_NAME_HOLD_MS] as [string, string, number]].slice(-GROUP_HELD_NAMES_MAX);
}
/** b77p (audit VAR-13): held names kept per holder (its newest) */
export const GROUP_HELD_NAMES_PER_IK = 4;
/** b77p (audit VAR-13): held names kept in all (backstop; 100 members x 4 fit) */
export const GROUP_HELD_NAMES_MAX = 512;

/** b71 (audit F-07): a seat claim the creator has checked (seat proof, signatures)
 *  but not admitted. `nick`/`ns`: the claimant's own name and its self-signature. */
export interface GroupSeatClaim {
  veilId: string; seat: string; nick?: string; ns?: string; at: number;
  /** the seat is locked to this claimant's Vardum ID / key (a contact invite) */
  contact?: boolean;
}

/** b71 (review P-01): `at` = when the seat was minted (ms); older seats get it at first sight */
export interface GroupSeat { key: string; invitee?: string; usedBy?: string; at?: number;
  /** b71 (audit F-07): the invited contact's pinned identity key, when the app knew it */
  inviteeIk?: string }

export interface PendingRotation {
  epoch: number;
  gekB64: string;
  pqPubB64: string;
  rid: string;
  /** the signed rekey texts, part i of n */
  parts: string[];
  /** indices already accepted by the relay */
  sent: number[];
  /** b70 (re-review 3): parts whose submit was tried (maybe stored by the relay even on an error) */
  attempted?: number[];
  /** IKs that received a wrap */
  recipients: string[];
  /** b73 (audit V-07): the signed recipient set (sorted Vardum IDs of every member the key
   *  is meant for, skipped ones included) carried in every part as rc. b74: required. */
  rc: string[];
  /** Batch D (D-06): Vardum IDs skipped for a missing or badly signed prekey */
  skipped?: string[];
  /** b75 (audit GR-5): the member list this rotation was made with, when it had to be published first
   *  (it names someone the last published list didn't, or drops someone): its signed text — sent before
   *  the first part, the same text on every retry — its sequence (the parts' ms) and the IKs it lists */
  preList?: { seq: number; text: string; iks: string[]; hash: string; sent?: boolean };
}

export interface GroupEnvelopeHeader {
  v: string; sid: string; ge: number; n: number; sig?: string;
  /** b54 (pre-audit T-3): the sender's chain id, chosen by the SENDER at
   *  counter 0 and carried inside the AEAD-authenticated, signed header. The
   *  receiver's replay window keys on it, never on relay metadata. */
  ch?: string;
  /** b188: the sender's veil-id (part of the signed core when present). b70:
   *  no sender sets it any more; still parsed so the signed core matches. */
  vid?: string;
  /** Batch C (A2): sender-signature version. Only GROUP_SIG_VERSION is accepted. */
  sv?: number;
}

/** Batch C (A2): v2 sender signatures cover the ciphertext. */
export const GROUP_SIG_VERSION = 2;
const GROUP_SIG_LABEL = 'vardum-group-msg-v2:';
/** b71 (review P-01): a SEAT INTRO — the joiner's first envelope, encrypted under a
 *  key from its seat's link secret (it holds no group key yet) and read only by the
 *  creator. Same header and signature layout, its own version and label. */
export const GROUP_SEAT_SIG_VERSION = 3;
const GROUP_SEAT_SIG_LABEL = 'vardum-group-seat-intro-v1:';

/** Batch C (A2): bytes the sender signs — label ‖ core header ‖ IV ‖ SHA-256(ct).
 *  b71 (review P-01): a seat intro (sv 3) signs under its own label. */
export async function groupSigMessage(coreStr: string, iv: Uint8Array, ct: Uint8Array, sv: number = GROUP_SIG_VERSION): Promise<Uint8Array> {
  return concat(utf8(sv === GROUP_SEAT_SIG_VERSION ? GROUP_SEAT_SIG_LABEL : GROUP_SIG_LABEL), utf8(coreStr), iv, await sha256(ct));
}

/** Batch C (A2): true only if `senderIkB64` signed this exact envelope (header, IV and ciphertext). */
export async function verifyGroupEnvelopeSig(senderIkB64: string, headerStr: string, ciphertextB64: string, ivB64: string): Promise<boolean> {
  const parsed = parseSignedGroupHeader(headerStr);
  if (!parsed || !senderIkB64) return false;
  try {
    return await verifyWithIk(senderIkB64, toB64(await groupSigMessage(parsed.coreStr, fromB64(ivB64), fromB64(ciphertextB64), parsed.header.sv)), parsed.header.sig);
  } catch { return false; }
}

/** Batch C (A2 + A5): parse a group envelope header strictly. The only form
 *  accepted is the canonical v2 one — {v, sid, ge, n, ch, (vid), sv, sig}
 *  in exactly that order — so the core string the receiver re-derives is
 *  byte-identical to what the sender signed and bound as AEAD data. Headers
 *  without a sender chain id (the old relay-supplied fallback) are refused. */
export function parseSignedGroupHeader(headerStr: string): { header: Required<Pick<GroupEnvelopeHeader, 'v' | 'sid' | 'ge' | 'n' | 'ch' | 'sv' | 'sig'>> & { vid?: string }; coreStr: string } | null {
  let h: Record<string, unknown>;
  try { h = JSON.parse(headerStr); } catch { return null; }
  if (!h || typeof h !== 'object' || Array.isArray(h)) return null;
  const { v, sid, ge, n, ch, vid, sv, sig } = h as Record<string, unknown>;
  if (v !== GROUP_PROTO || (sv !== GROUP_SIG_VERSION && sv !== GROUP_SEAT_SIG_VERSION)) return null; // b71 (review P-01): or a seat intro
  // b54 (T-4): sender tags are exactly 'g' + 12 hex — '__proto__' etc. refused
  if (typeof sid !== 'string' || !/^g[0-9a-f]{12}$/.test(sid)) return null;
  if (!Number.isInteger(ge) || (ge as number) < 0 || !Number.isInteger(n) || (n as number) < 0) return null;
  if (typeof ch !== 'string' || !/^[0-9a-f]{16}$/.test(ch)) return null;
  if (vid !== undefined && (typeof vid !== 'string' || !vid)) return null;
  if (typeof sig !== 'string' || !sig) return null;
  const core = vid !== undefined ? { v, sid, ge, n, ch, vid, sv } : { v, sid, ge, n, ch, sv };
  const coreStr = JSON.stringify(core);
  if (JSON.stringify({ ...core, sig }) !== headerStr) return null; // no extra or reordered fields
  return {
    header: { v: v as string, sid: sid as string, ge: ge as number, n: n as number, ch: ch as string, sv: sv as number, sig: sig as string, ...(vid !== undefined ? { vid: vid as string } : {}) },
    coreStr,
  };
}

export interface GroupDecryptResult {
  /** Batch G (R5-2-03): the record could not be saved (kept in memory) */
  stateNotSaved?: boolean;
  cover: boolean;
  text: string;
  senderVerified: boolean;
  /** b71 (audit F-12): the sender's signed time and sequence (absent from older builds) */
  meta?: GroupPostMeta;
  /** M-3 (b69 audit): sent under an epoch that started more than
   *  MEMBER_EPOCH_READ_MAX_MS ago — a removed member may hold that key, so the
   *  post is never shown as verified (senderVerified is false) */
  staleKeys?: boolean;
  /** b77s (audit 4 GR-01): the identity key whose signature on this envelope was verified (its signer) */
  signerIk?: string;
}

// ---------- record store (web's nm Map + um persistence) ----------

/**
 * Per-device record caches, keyed by the storage INSTANCE. Two group sessions
 * on different stores (two devices simulated in one process, tests, a future
 * multi-profile build) never share or clobber each other's group state —
 * the send counter, replay window and epoch live with the store that owns them.
 */
const registries = new WeakMap<VeilStorage, Map<string, GroupRecord>>();
function registry(storeIn: VeilStorage): Map<string, GroupRecord> {
  const store = unwrapPinned(storeIn); // b70 (re-review 2): a pinned view shares the real store's records
  let m = registries.get(store);
  if (!m) { m = new Map(); registries.set(store, m); }
  return m;
}
/** b70 (re-review 8): every wipe drops the in-memory group records (with their keys
 *  and the identity seed they carry) — they used to outlive the wipe, list the real
 *  groups to whoever came next, and be written back by the next save */
export function clearGroupRegistry(store: VeilStorage): void {
  registries.delete(unwrapPinned(store));
  floorCaches.delete(unwrapPinned(store)); // b77t (audit 5 M-C): read again from the store (a wipe removed it)
  forgetTagKeys(); // b77q (audit 3 GR-3)
}
const sendLocks = new Map<string, Promise<void>>();

/** b77t (audit 5 M-C): the group's epoch floor (GROUP_FLOOR_SUFFIX). e = the highest epoch whose key this phone held,
 *  s = the highest epoch a creator-signed message showed (signedAheadEpoch). */
export type GroupEpochFloor = { e: number; s: number };
const floorCaches = new WeakMap<VeilStorage, Map<string, GroupEpochFloor>>();
function floorCache(storeIn: VeilStorage): Map<string, GroupEpochFloor> {
  const store = unwrapPinned(storeIn);
  let m = floorCaches.get(store);
  if (!m) { m = new Map(); floorCaches.set(store, m); }
  return m;
}
const floorInt = (v: unknown): number => (Number.isSafeInteger(v) && (v as number) > 0 ? v as number : 0);
/** b77t (audit 5 M-C): read the floor ({0, 0} when there is none). Throws when the store can't be read (the caller
 *  then refuses for now and retries: never "no floor" on a read error). */
export async function groupEpochFloor(store: VeilStorage, groupToken: string): Promise<GroupEpochFloor> {
  const cached = floorCache(store).get(groupToken);
  if (cached) return cached;
  const raw = await store.get(GROUP_KEY_PREFIX + groupToken + GROUP_FLOOR_SUFFIX);
  let f: GroupEpochFloor = { e: 0, s: 0 };
  if (raw) {
    try { const j = JSON.parse(raw) as { e?: unknown; s?: unknown }; f = { e: floorInt(j?.e), s: floorInt(j?.s) }; } catch { /* unparseable: none */ }
  }
  floorCache(store).set(groupToken, f);
  return f;
}
/** b77t (audit 5 M-C): raise the floor (never lowers it). Best effort: a refused write keeps the higher value in memory
 *  for this run and is tried again on the next save. */
async function raiseEpochFloor(store: VeilStorage, groupToken: string, e: number, s: number): Promise<void> {
  let cur: GroupEpochFloor;
  try { cur = await groupEpochFloor(store, groupToken); } catch { return; }
  const next = { e: Math.max(cur.e, floorInt(e)), s: Math.max(cur.s, floorInt(s)) };
  if (next.e === cur.e && next.s === cur.s) return;
  try {
    if ((await store.set(GROUP_KEY_PREFIX + groupToken + GROUP_FLOOR_SUFFIX, JSON.stringify(next))) === false) return;
    floorCache(store).set(groupToken, next);
  } catch { /* kept for the next save */ }
}

async function persist(store: VeilStorage, rec: GroupRecord): Promise<void> {
  try {
    // Batch F (round-4 review R4-2-06): the phone's secure store reports a refused
    // write by answering false, not by throwing — treat it as the failure it is
    if ((await store.set(GROUP_KEY_PREFIX + rec.groupToken, JSON.stringify(rec))) === false) throw new Error('refused write');
  } catch (e) {
    // Batch D (D-07, RV-06): fail closed — a caller that must not continue on an
    // unsaved state (the rotation's persist-before-send) has to see the failure
    console.error('[veil-group] key persistence failed:', e);
    throw new Error('Group keys could not be saved on this device. Try again in a moment.');
  }
  // b77t (audit 5 M-C): the epoch floor follows every saved record (a held key's epoch; a creator-signed later one)
  await raiseEpochFloor(store, rec.groupToken, rec.gekB64 ? rec.epoch : 0, rec.signedAheadEpoch ?? 0);
}

/**
 * Batch G (round-5 review R5-2-03, a Batch F regression): BOOKKEEPING writes —
 * the receive replay window and the envelope counter — must not block a group
 * when the phone's storage refuses the record (the iOS Keychain refuses large
 * items). The state stays in memory and the caller is told (false). Safety
 * writes (rotation, admission, eviction, member list, the send counter) keep
 * using persist(), which fails closed.
 */
async function persistBookkeeping(store: VeilStorage, rec: GroupRecord): Promise<boolean> {
  try {
    if ((await store.set(GROUP_KEY_PREFIX + rec.groupToken, JSON.stringify(rec))) === false) throw new Error('refused write');
    return true;
  } catch (e) {
    console.log('[veil-group] group state not saved (kept in memory):', String((e as Error)?.message ?? e), 'bytes', groupRecordBytes(rec));
    return false;
  }
}

/** Batch G (R5-2-03): the record's stored size, for the size log */
export function groupRecordBytes(rec: GroupRecord): number {
  try { return JSON.stringify(rec).length; } catch { return -1; }
}

/** Batch H (R6-2-01): the send counter, saved on its own and fail-closed (a
 *  counter that did not land would be reused). Small, so the phone's size limit
 *  for the big record never reaches it. */
async function persistSendState(store: VeilStorage, rec: GroupRecord): Promise<void> {
  const send = { epoch: rec.epoch, myTag: rec.myTag, sendN: rec.sendN, sendChain: rec.sendChain, postSeq: rec.postSeq ?? 0 }; // b71 (audit F-12): + postSeq
  try {
    if ((await store.set(GROUP_KEY_PREFIX + rec.groupToken + GROUP_SEND_SUFFIX, JSON.stringify(send))) === false) throw new Error('refused write');
  } catch (e) {
    console.error('[veil-group] send counter persistence failed:', e);
    throw new Error('Group keys could not be saved on this device. Try again in a moment.');
  }
}

/** b63 review (I3-5): records whose saved send counter couldn't be read */
const sendUnconfirmed = new WeakSet<GroupRecord>();

/** Batch H (R6-2-01): a saved counter ahead of the big record wins, but only for
 *  the same epoch and sender tag (a rotation resets the counter in the record). */
async function mergeSendState(store: VeilStorage, rec: GroupRecord): Promise<void> {
  let raw: string | null;
  try {
    raw = await store.get(GROUP_KEY_PREFIX + rec.groupToken + GROUP_SEND_SUFFIX);
  } catch (e) {
    // b63 review (I3-5): fail closed. The big record's counter may be behind,
    // so sending on it could reuse counters; encryptGroupMessage retries this.
    console.error('[veil-group] send counter unreadable — sends held until it reads:', e);
    sendUnconfirmed.add(rec);
    return;
  }
  sendUnconfirmed.delete(rec);
  try {
    if (!raw) return;
    const s = JSON.parse(raw) as { epoch?: number; myTag?: string; sendN?: number; sendChain?: string; postSeq?: number };
    // b71 (audit F-12): the post sequence runs across epochs — the higher one wins
    if (Number(s.postSeq) > Number(rec.postSeq ?? 0)) rec.postSeq = Number(s.postSeq);
    if (s.epoch === rec.epoch && s.myTag === rec.myTag && Number(s.sendN) > Number(rec.sendN ?? 0)) {
      rec.sendN = Number(s.sendN);
      if (s.sendChain) rec.sendChain = s.sendChain;
    }
  } catch { /* the big record's counter stands */ }
}

/** b71 (review P-06): the replay window, saved on its own and fail-closed. */
async function persistRecvState(store: VeilStorage, rec: GroupRecord): Promise<void> {
  const item = { epoch: rec.epoch, recv: rec.recv ?? {} };
  try {
    if ((await store.set(GROUP_KEY_PREFIX + rec.groupToken + GROUP_RECV_SUFFIX, JSON.stringify(item))) === false) throw new Error('refused write');
  } catch (e) {
    console.error('[veil-group] replay window persistence failed:', e);
    throw new Error('Group state could not be saved on this device, so this message waits. Free up space, then reopen the group.');
  }
}

/** b71 (review P-06): records whose saved replay window couldn't be read */
const recvUnconfirmed = new WeakSet<GroupRecord>();

/** b71 (review P-06): the window item is written before every message is shown, so
 *  for the record's epoch it is never older than the big record's copy. An item for
 *  another epoch is stale (the epoch change resets the window) and is ignored. */
async function mergeRecvState(store: VeilStorage, rec: GroupRecord): Promise<void> {
  let raw: string | null;
  try {
    raw = await store.get(GROUP_KEY_PREFIX + rec.groupToken + GROUP_RECV_SUFFIX);
  } catch (e) {
    // fail closed: the big record's window may be behind, so opening on it could re-open messages
    console.error('[veil-group] replay window unreadable — messages held until it reads:', e);
    recvUnconfirmed.add(rec);
    return;
  }
  recvUnconfirmed.delete(rec);
  try {
    if (!raw) return;
    const s = JSON.parse(raw) as { epoch?: number; recv?: Record<string, GroupRecvState> };
    if (s.epoch === rec.epoch && s.recv && typeof s.recv === 'object' && !Array.isArray(s.recv)) rec.recv = s.recv;
  } catch { /* the big record's window stands */ }
}

/** Batch D (D-07): the record as it is ON DISK (not the in-memory copy). */
export async function readPersistedGroupRecord(store: VeilStorage, groupToken: string): Promise<GroupRecord | null> {
  try {
    const raw = await store.get(GROUP_KEY_PREFIX + groupToken);
    return raw ? JSON.parse(raw) as GroupRecord : null;
  } catch {
    return null;
  }
}

/** web's dm(): normalize + memory map + persist */
export async function saveGroupRecord(store: VeilStorage, rec: GroupRecord): Promise<GroupRecord> {
  // b198 EPOCH MONOTONICITY (live-caught: One's record regressed 3 → 2 after a
  // rotation — a stale in-flight record save clobbered the advanceEpoch that
  // landed while the pass was running; the background group pass widened that
  // window). Group epochs only ever move FORWARD: a save carrying an OLDER
  // epoch has the newer epoch's key material preserved so the regression can
  // never stick. (Re-join flows re-attest at the CURRENT epoch, so forward is
  // always the right direction.)
  // Batch D (D-01): a record not yet loaded this run is still checked
  // Batch E (F-9): an unreadable stored record throws here instead of passing the guard
  const cur = registry(store).get(rec.groupToken) ?? (await loadGroupRecordStrict(store, rec.groupToken)) ?? undefined;
  // Batch C: saving the LIVE record keeps its identity — callers that hold it
  // (a poll pass, a rotation) keep seeing every later change, and nobody ends
  // up writing back a stale copy (which could regress replay windows).
  if (cur && cur === rec) {
    rec.recv = rec.recv ?? {};
    rec.envCount = rec.envCount ?? 0;
    rec.epochStartedAt = rec.epochStartedAt ?? new Date().toISOString();
    await persist(store, rec);
    return rec;
  }
  let r: GroupRecord = {
    ...rec,
    recv: rec.recv ?? {},
    envCount: rec.envCount ?? 0,
    epochStartedAt: rec.epochStartedAt ?? new Date().toISOString(),
  };
  if (cur && cur !== rec) {
    assertSameGroup(cur, r);
    r = mergeMembershipState(cur, r);
  }
  if (cur && Number(rec.epoch ?? 0) < Number(cur.epoch ?? 0)) {
    r = {
      ...r,
      epoch: cur.epoch,
      gekB64: cur.gekB64,
      pqPubB64: cur.pqPubB64,
      myTag: cur.myTag,
      sendN: cur.sendN,
      recv: cur.recv ?? r.recv,
      envCount: cur.envCount ?? r.envCount,
      epochStartedAt: cur.epochStartedAt ?? r.epochStartedAt,
    };
    console.log(`[veil-group] stale record save blocked — kept epoch ${cur.epoch} over ${rec.epoch} for ${rec.groupToken.slice(0, 8)}`);
  }
  registry(store).set(r.groupToken, r);
  try {
    await persist(store, r);
  } catch (e) {
    // b70 (re-review 12): a record that wasn't in memory and couldn't be saved (a wipe
    // refused it) doesn't stay in memory either — it used to come back after a wipe
    if (!cur) registry(store).delete(r.groupToken);
    throw e;
  }
  return r;
}

/** Batch D (D-01, RV-01/RV-03): thrown when a save would turn one group's record
 *  into another kind of group (a relay-named token colliding with a group this
 *  device already holds). */
export class GroupRecordConflictError extends Error {
  constructor() {
    super('This link points at another group already on this device, so it was not joined.');
    this.name = 'GroupRecordConflictError';
  }
}

/**
 * Batch D (D-01): a save that is not the live record may never change what group
 * a token belongs to: a creator never becomes a member (or back), and a known
 * creator key or own identity key is never replaced.
 */
function assertSameGroup(cur: GroupRecord, r: GroupRecord): void {
  const roleOk = cur.role === r.role;
  const creatorOf = (x: GroupRecord) => x.creatorIkPubB64 || (x.role === 'creator' ? x.ikPubB64 : undefined);
  const creatorOk = !creatorOf(cur) || !creatorOf(r) || creatorOf(cur) === creatorOf(r);
  const selfOk = !cur.ikPubB64 || cur.ikPubB64 === r.ikPubB64;
  if (!roleOk || !creatorOk || !selfOk) throw new GroupRecordConflictError();
}

/**
 * Batch C (V-28 + A1/A3): a stale write-back (a copy loaded before an eviction,
 * an admission or a rotation was recorded) must never undo it. Deny lists,
 * admissions and seat bindings only grow; the member list keeps the higher
 * sequence; a pending rotation / eviction survives until a save shows the
 * epoch it was waiting for.
 */
function mergeMembershipState(cur: GroupRecord, r: GroupRecord): GroupRecord {
  const out: GroupRecord = { ...r };
  if (cur.evictedIks?.length || r.evictedIks?.length) out.evictedIks = [...new Set([...(cur.evictedIks ?? []), ...(r.evictedIks ?? [])])];
  if (cur.admitted || r.admitted) out.admitted = { ...(cur.admitted ?? {}), ...(r.admitted ?? {}) };
  // b71 (audit F-01): retired seats stay retired whatever copy is saved
  const retired = [...new Set([...(cur.retiredSeats ?? []), ...(r.retiredSeats ?? [])])].slice(-512);
  if (retired.length) out.retiredSeats = retired;
  if (cur.seats || r.seats) {
    const seats: Record<string, GroupSeat> = { ...(cur.seats ?? {}) };
    for (const [t, s] of Object.entries(r.seats ?? {})) seats[t] = { ...s, usedBy: seats[t]?.usedBy ?? s.usedBy };
    for (const t of retired) delete seats[t];
    out.seats = seats;
  }
  if (cur.joinEpochs || r.joinEpochs) out.joinEpochs = { ...(cur.joinEpochs ?? {}), ...(r.joinEpochs ?? {}) };
  // b75 (audit GR-1): a leave once read stays read (a stale copy can't bring the leaver's trust back)
  if (cur.leftIks || r.leftIks) out.leftIks = { ...(r.leftIks ?? {}), ...(cur.leftIks ?? {}) };
  if (cur.leavesRelayed?.length || r.leavesRelayed?.length) out.leavesRelayed = [...new Set([...(cur.leavesRelayed ?? []), ...(r.leavesRelayed ?? [])])].slice(-64);
  if (cur.joinNoted?.length || r.joinNoted?.length) out.joinNoted = [...new Set([...(cur.joinNoted ?? []), ...(r.joinNoted ?? [])])].slice(-128); // b77u (audit 6 I-4)
  // b74 (VAR-06): a first-bound sequence is never handed out twice
  if ((cur.nameSeq ?? 0) > (r.nameSeq ?? 0)) out.nameSeq = cur.nameSeq;
  if ((cur.memberSeq ?? -1) > (r.memberSeq ?? -1)) { out.memberSeq = cur.memberSeq; out.memberList = cur.memberList; out.memberListHash = cur.memberListHash; }
  // b77m review (L2): a ghost-key flag only rises; a delivery still waiting for its list survives a stale copy
  if ((cur.ghostKeyEpoch ?? 0) > (r.ghostKeyEpoch ?? 0)) out.ghostKeyEpoch = cur.ghostKeyEpoch;
  if (!r.deliveryGhostNotes && cur.deliveryGhostNotes?.length) out.deliveryGhostNotes = cur.deliveryGhostNotes; // b77q review (GR-1 residual)
  if (!r.deliveryChecks && cur.deliveryChecks?.length) {
    // b77q (audit 3 GR-1): nor one a later epoch's list settled (its epoch is flagged: ghostKeyEpoch >= ge)
    const waiting = cur.deliveryChecks.filter((c) => c.ms > (out.memberSeq ?? 0) && (out.ghostKeyEpoch ?? 0) < c.ge);
    if (waiting.length) out.deliveryChecks = waiting;
  }
  if (!r.pendingRotation && cur.pendingRotation && cur.pendingRotation.epoch > Number(r.epoch ?? 0)) out.pendingRotation = cur.pendingRotation;
  if (r.evictionPendingAt === undefined && cur.evictionPendingAt !== undefined && Number(r.epoch ?? 0) <= cur.evictionPendingAt) out.evictionPendingAt = cur.evictionPendingAt;
  return out;
}

export function groupRecord(store: VeilStorage, groupToken: string): GroupRecord | null {
  return registry(store).get(groupToken) ?? null;
}

export function listGroupTokens(store: VeilStorage): string[] {
  return [...registry(store).keys()];
}

export async function forgetGroup(store: VeilStorage, groupToken: string): Promise<void> {
  registry(store).delete(groupToken);
  sendLocks.delete(groupToken);
  forgetTagKeys(groupToken); // b77q (audit 3 GR-3)
  try { await store.remove(GROUP_KEY_PREFIX + groupToken); } catch { /* already gone */ }
  try { await store.remove(GROUP_KEY_PREFIX + groupToken + GROUP_SEND_SUFFIX); } catch { /* already gone */ }
  try { await store.remove(GROUP_KEY_PREFIX + groupToken + GROUP_RECV_SUFFIX); } catch { /* already gone */ } // b71 (review P-06)
}

/** web's Am(): export all records (device transfer payload) */
export function exportGroupRecords(store: VeilStorage): GroupRecord[] {
  return [...registry(store).values()].map((r) => ({ ...r }));
}

/** web's jm(): restore records from a device transfer */
export async function importGroupRecords(store: VeilStorage, recs: GroupRecord[]): Promise<number> {
  let n = 0;
  for (const r of recs ?? []) {
    if (!r || !r.groupToken || registry(store).has(r.groupToken)) continue;
    await saveGroupRecord(store, { ...r, recv: r.recv ?? {}, envCount: r.envCount ?? 0, epochStartedAt: r.epochStartedAt ?? new Date().toISOString() });
    n += 1;
  }
  return n;
}

/**
 * Boot-time reload (web's hm() counterpart): the native SecureStore has no key
 * enumeration, so the App layer re-hydrates records from the session rows the
 * gate returns (group sessions carry group_token) plus this explicit loader
 * for tokens the caller knows about.
 */
/** Batch E (round-3 review F-9): a stored group record exists but can't be read. */
export class GroupRecordUnreadableError extends Error {
  constructor() { super('This group\'s keys could not be read on this device. Try again in a moment.'); this.name = 'GroupRecordUnreadableError'; }
}

/** Batch E (F-9): like loadGroupRecord, but "unreadable" is not "absent" — it
 *  throws, so joins and saves never overwrite a record they couldn't read. */
export async function loadGroupRecordStrict(store: VeilStorage, groupToken: string): Promise<GroupRecord | null> {
  if (registry(store).has(groupToken)) return registry(store).get(groupToken)!;
  let raw: string | null;
  try { raw = await store.get(GROUP_KEY_PREFIX + groupToken); } catch { throw new GroupRecordUnreadableError(); }
  if (!raw) return null;
  const rec = await loadGroupRecord(store, groupToken);
  if (!rec) throw new GroupRecordUnreadableError();
  return rec;
}

export async function loadGroupRecord(store: VeilStorage, groupToken: string): Promise<GroupRecord | null> {
  if (registry(store).has(groupToken)) return registry(store).get(groupToken)!;
  try {
    const raw = await store.get(GROUP_KEY_PREFIX + groupToken);
    if (!raw) return null;
    const rec = JSON.parse(raw) as GroupRecord;
    if (!rec?.groupToken) return null;
    rec.recv = rec.recv ?? {};
    rec.envCount = rec.envCount ?? 0;
    rec.epochStartedAt = rec.epochStartedAt ?? new Date().toISOString();
    await mergeSendState(store, rec); // Batch H (R6-2-01)
    await mergeRecvState(store, rec); // b71 (review P-06)
    registry(store).set(rec.groupToken, rec);
    return rec;
  } catch (e) {
    // Do not destroy key material on transient Keychain/read or parse errors.
    console.error('[veil-group] key restore failed — keeping the record for retry', e);
    return null;
  }
}

/**
 * Boot-time reload for ALL persisted groups (web hm() counterpart). The
 * native keychain index is enumerable, so every veil_gk_ record loads in one
 * sweep. Unlike the web's 7-day localStorage TTL, native records do not
 * expire — losing them means losing group access on this device.
 */
export async function loadGroupRecords(store: VeilStorage): Promise<number> {
  let n = 0;
  try {
    const keys = await store.keys(GROUP_KEY_PREFIX);
    for (const k of keys ?? []) {
      const token = k.slice(GROUP_KEY_PREFIX.length);
      if (!token || token.endsWith(GROUP_SEND_SUFFIX) || token.endsWith(GROUP_RECV_SUFFIX) || token.endsWith(GROUP_FLOOR_SUFFIX) || registry(store).has(token)) continue;
      const raw = await store.get(k);
      if (!raw) continue;
      try {
        const rec = JSON.parse(raw) as GroupRecord;
        if (!rec?.groupToken) continue;
        rec.recv = rec.recv ?? {};
        rec.envCount = rec.envCount ?? 0;
        rec.epochStartedAt = rec.epochStartedAt ?? new Date().toISOString();
        await mergeSendState(store, rec); // Batch H (R6-2-01)
        await mergeRecvState(store, rec); // b71 (review P-06)
        registry(store).set(rec.groupToken, rec);
        n += 1;
      } catch (e) {
        // Preserve unreadable key material so a later unlock/recovery can retry.
        console.error('[veil-group] key restore failed — keeping the record for retry', e);
      }
    }
  } catch (e) {
    console.error('[veil-group] boot restore failed:', e);
  }
  return n;
}

// ---------- primitives ----------

async function sha256HexPrefix(s: string, bytes: number): Promise<string> {
  const h = await sha256(utf8(s));
  return [...h.subarray(0, bytes)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

/** b77t (audit 5 M-C / IH C-1): the rid a creator puts on its answer to a KEYLESS member's key request (have_epoch 0),
 *  binding the delivery to that request's signed nonce, so to the membership that asked. A field every veil-group-3
 *  phone already carries and checks only for its shape (16-64 hex); a phone holding the key ignores a delivery's rid. */
export function deliveryBindRid(groupToken: string, epoch: number, nonce: string): Promise<string> {
  return sha256HexPrefix(`vardum-group-delivery-bind-v1:${JSON.stringify([groupToken, epoch, nonce])}`, 16);
}

/** web's lm(): the PUBLIC per-sender tag for an epoch. b71 (audit F-13): anyone with
 *  the roster (the relay) can compute it, so it is no longer what a key holder sends
 *  under (keyedSenderTag). Still used: by a joiner without a key (its seat intro), to
 *  read posts from older builds, and for a single post the relay refused under the
 *  keyed tag (b73 (audit V-09): never for the rest of an epoch any more). */
export async function senderTag(groupToken: string, epoch: number, veilId: string): Promise<string> {
  return `g${await sha256HexPrefix(`veil-group-sender:${groupToken}:${epoch}:${veilId}`, 6)}`;
}

/** b77q (audit 3 GR-3): keyed by token, epoch and a hash of the group key — the key itself (base64) used to be the
 *  map key, so past epochs' and forgotten groups' keys stayed reachable here until the map overflowed. Cleared by
 *  a wipe (clearGroupRegistry), forgetGroup, and for older epochs by advanceEpoch (forgetTagKeys) */
const tagKeyCache = new Map<string, Promise<CryptoKey>>();
/** b77q (audit 3 GR-3): drop the cached tag keys — all, a group's, or a group's epochs below `belowEpoch` */
export function forgetTagKeys(groupToken?: string, belowEpoch?: number): void {
  if (groupToken === undefined) { tagKeyCache.clear(); return; }
  for (const id of [...tagKeyCache.keys()]) {
    const [t, e] = id.split('|');
    if (t === groupToken && (belowEpoch === undefined || Number(e) < belowEpoch)) tagKeyCache.delete(id);
  }
}
/** b71 (audit F-13): the epoch's sender-tag key, from the epoch's group key */
async function senderTagKey(groupToken: string, epoch: number, gekB64: string): Promise<CryptoKey> {
  const id = `${groupToken}|${epoch}|${[...(await sha256(utf8('vardum-tag-key-cache:' + gekB64))).subarray(0, 16)].map((b) => b.toString(16).padStart(2, '0')).join('')}`;
  let k = tagKeyCache.get(id);
  if (!k) {
    k = (async () => {
      const raw = await hkdf(fromB64(gekB64), await sha256(utf8(`vardum-group-sender-v2:${groupToken}:${epoch}`)), 'sender-tag', 32);
      return crypto.subtle.importKey('raw', raw as unknown as BufferSource, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    })();
    if (tagKeyCache.size > 64) tagKeyCache.clear();
    tagKeyCache.set(id, k);
    k.catch(() => tagKeyCache.delete(id));
  }
  return k;
}

/** b71 (audit F-13): the sender tag key holders send under —
 *  'g' + hex(HMAC-SHA256(HKDF(GEK, salt = SHA-256("vardum-group-sender-v2:" ‖ token ‖ ":" ‖ epoch), "sender-tag"), veilId)[0:6]).
 *  Someone holding only the roster (a copy of the envelope table, another seat's
 *  fetch) can't compute it. b73 (audit V-09): this does NOT hide who posted from the
 *  relay — every envelope arrives with the sender's own seat session token and write
 *  credential, which the relay bound to the member's Vardum ID at attest; the relay
 *  can attribute every post. (Same shape as the public tag: 'g' + 12 hex.) */
export async function keyedSenderTag(groupToken: string, epoch: number, gekB64: string, veilId: string): Promise<string> {
  const mac = new Uint8Array(await crypto.subtle.sign('HMAC', await senderTagKey(groupToken, epoch, gekB64), utf8(veilId) as unknown as BufferSource));
  return 'g' + [...mac.subarray(0, 6)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

/** b71 (audit F-13): every tag a member may post under in the record's epoch — the
 *  keyed one (when this phone holds the key) first, then the public one */
export async function groupSenderTags(rec: Pick<GroupRecord, 'groupToken' | 'epoch' | 'gekB64'>, veilId: string, epoch: number = rec.epoch): Promise<string[]> {
  const pub = await senderTag(rec.groupToken, epoch, veilId);
  if (!rec.gekB64 || epoch !== rec.epoch) return [pub];
  return [await keyedSenderTag(rec.groupToken, epoch, rec.gekB64, veilId), pub];
}

/** b71 (audit F-13): the tag this phone sends under in the record's epoch.
 *  b73 (audit V-09): always the keyed tag once the key is here (legacyTagEpoch is
 *  ignored: a relay refusal no longer downgrades the rest of the epoch) */
export async function ownSenderTag(rec: Pick<GroupRecord, 'groupToken' | 'epoch' | 'gekB64' | 'veilId'>): Promise<string> {
  if (!rec.gekB64) return senderTag(rec.groupToken, rec.epoch, rec.veilId);
  return keyedSenderTag(rec.groupToken, rec.epoch, rec.gekB64, rec.veilId);
}

/**
 * Epoch fingerprint shown to users (web's bm() twin — MUST stay byte-exact
 * with the web app so cross-platform comparisons work).
 *
 * b136 (Sept 27, rotation test finding): the old input bound only
 * groupToken + sorted member veil IDs, so the fingerprint was IDENTICAL
 * across epochs — matching prints proved roster agreement, not KEY
 * agreement. A forked/malicious rekey (different GEKs or group PQ keys
 * delivered to different members) would still show identical
 * fingerprints, defeating the entire purpose of an "epoch" fingerprint.
 * The input now binds the full key-agreement state: epoch number, GEK,
 * and the epoch's group PQ public key. Two members display the same
 * fingerprint iff they hold the same keys for the same epoch AND count the
 * same member set. b71 (audit F-14): that set comes from each phone's own
 * signed state (its trusted list, itself and the creator always included),
 * never from whether the relay's roster happens to list a row, so a relay
 * can't make two phones holding the same keys show different fingerprints.
 * (SHA-256 of the GEK does not leak it — the fingerprint remains safe to
 * read aloud / compare out-of-band.) Web lockstep change requested from
 * the builder in the same cadence.
 *
 * b137 (builder reconciliation, Sept 27): the member element is the
 * sorted Ed25519 IK PUBS (b64), NOT veil IDs — the web's bm() has always
 * hashed IK pubs, so the native's pre-b136 "web's bm()" comment was wrong
 * and the two platforms were ALREADY fingerprint-divergent before b136.
 * Final cross-platform contract (byte-exact, both sides):
 *   veil-group-epoch:${groupToken}:${epoch}:${gekB64}:${pqPubB64}:${sortedIkPubsCommaJoined}
 * - groupToken: the 40-char hex group token, as-is
 * - epoch: DEVICE-LOCAL applied epoch, decimal, no padding ("2", "3") —
 *   NOT the relay-stamped group_epoch, for the same fork reason as GEK
 * - gekB64 / pqPubB64: device-LOCAL group state (identical to the relay
 *   row in normal operation; divergence under fork is the point)
 * - sortedIkPubs: member Ed25519 IK pub b64 strings, lexical sort, comma
 *   join, no spaces
 */
/** b77m (audit VAR-42): salt label of the fingerprint's key-derived input */
const EPOCH_FP_KEY_LABEL = 'vardum-group-fp-key-v1:';

export async function epochFingerprint(
  groupToken: string,
  epoch: number,
  gekB64: string,
  pqPubB64: string,
  ikPubs: string[],
  /** b73 (audit V-07): the epoch's signed recipient set (rec.epochRecipients): the
   *  fingerprint covers who the key was given to, not only the member list — ':rc=' +
   *  sorted Vardum IDs, comma-joined, is appended. b74: REQUIRED and always appended (a
   *  group's first epoch: []); before, an epoch whose rekey omitted rc kept the old input,
   *  so a creator that left rc out also kept every fingerprint matching. */
  recipients: string[],
): Promise<string> {
  if (!Array.isArray(recipients)) throw new Error('epochFingerprint: the recipient set is required');
  const sorted = [...(ikPubs ?? [])].sort();
  const rc = `:rc=${[...recipients].sort().join(',')}`;
  // b77m (audit VAR-42): the key's place in the input is taken by a value DERIVED from it (HKDF, own label),
  // never the raw group key itself
  const fpk = toB64(await hkdf(fromB64(gekB64), await sha256(utf8(EPOCH_FP_KEY_LABEL)), 'epoch-fingerprint', 32));
  const h = await sha256(utf8(`veil-group-epoch:${groupToken}:${epoch}:${fpk}:${pqPubB64}:${sorted.join(',')}${rc}`));
  return [...h].map((b) => b.toString(16).padStart(2, '0')).join('').toUpperCase().match(/.{1,4}/g)!.join('-');
}

/** web's xm(): per-message AES key.
 *  b77m (audit VAR-38): the sender chain id `ch` is in the HKDF info too (it was in the AAD only), so a
 *  counter that restarts within an epoch (a new chain) never derives a key used before — safety no longer
 *  rests on the random 96-bit IVs alone. Label v2: a key made the old way never opens here (clean break,
 *  b77, with the hybrid wraps). */
async function groupMsgKey(rec: GroupRecord, sid: string, ch: string, n: number): Promise<Uint8Array> {
  const salt = await sha256(utf8(`veil-group-bind:${rec.groupToken}:${rec.epoch}:${rec.pqPubB64}`));
  return hkdf(fromB64(rec.gekB64), salt, `veil-group-msg-v2:${sid}:${ch}:${n}`, 32);
}

/** b71 (review P-01): per-message key of a seat intro — from the seat key (HKDF of the
 *  link secret, which the relay never sees), bound to the group, epoch and seat. */
async function seatIntroMsgKey(seatKeyB64: string, groupToken: string, epoch: number, seatToken: string, sid: string, n: number): Promise<Uint8Array> {
  const salt = await sha256(utf8(`vardum-seat-intro-v1:${groupToken}:${epoch}:${seatToken}`));
  return hkdf(fromB64(seatKeyB64), salt, `veil-group-msg:${sid}:${n}`, 32);
}

/** b71 (review P-01): creator — open a seat intro with the key of the seat it names.
 *  Throws when the key is not that seat's. */
export async function decryptSeatIntro(
  seatKeyB64: string, groupToken: string, seatToken: string, headerStr: string, ciphertextB64: string, ivB64: string,
): Promise<{ cover: boolean; text: string }> {
  const parsed = parseSignedGroupHeader(headerStr);
  if (!parsed || parsed.header.sv !== GROUP_SEAT_SIG_VERSION) throw new Error('Not a seat intro.');
  const { header, coreStr } = parsed;
  const msgKey = await seatIntroMsgKey(seatKeyB64, groupToken, header.ge, seatToken, header.sid, header.n);
  const key = await crypto.subtle.importKey('raw', msgKey as unknown as BufferSource, { name: 'AES-GCM' }, false, ['decrypt']);
  const pt = new Uint8Array(await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: fromB64(ivB64) as unknown as BufferSource, additionalData: utf8(coreStr) as unknown as BufferSource },
    key, fromB64(ciphertextB64) as unknown as BufferSource,
  ));
  return parseGroupPayload(pt);
}

/** b71 (audit F-12): the sender trailer — the same bytes as the 1:1 one (cc/padding.ts):
 *  [0xA7][8 BE sent-at ms][4 BE sequence], right after the text, inside the encryption.
 *  Older builds read `length` bytes of text and never look at it. */

const TRAILER_BYTES = 13;
export interface GroupPostMeta { sentAt: number; seq: number }

/** b76 (padding): the largest payload a text may take — a post 4096, a membership control 32768.
 *  (Only the cap depends on the kind; the class is chosen by length alone.)
 *  b76r2 (audit R2-I3): the kind is the control flag the building code set (controlKindOf), never the text alone —
 *  b76 chose the 32 KiB cap from the text prefix, so a typed text that merely started like a rekey went out in the
 *  16/32 KiB classes. */
function payloadMaxFor(membership: boolean): number {
  return membership ? CONTROL_MAX : POST_MAX;
}

/** does this text, with the sender trailer, fit under its cap? */
function trailerFits(text: string, membership: boolean): boolean {
  return PAYLOAD_HDR + utf8(text).length + TRAILER_BYTES <= payloadMaxFor(membership);
}

/** web's sm(): pad payload into a fixed bucket so envelope sizes don't leak length.
 *  b76 (padding): the smallest class of the one group ladder that holds it (cc/padding.ts
 *  padMessageFrame — the same frame bytes as 1:1), whatever kind of message it is. */
function padGroupPayload(text: string, cover: boolean, meta: GroupPostMeta, membership: boolean): Uint8Array {
  const max = payloadMaxFor(membership);
  return padMessageFrame(text, cover, meta, GROUP_CLASSES.filter((c) => c <= max));
}

/** web's cm(): parse the padded payload (b71 (audit F-12): and the sender trailer, if any).
 *  b76 (padding): strictly (cc/padding.ts unpadMessageFrame) — the frame must be exactly the
 *  class its content needs, with zero padding; anything else is refused. Exported for tests.
 *  b76r2 (audit R2-I3): and as the send side makes it — every group payload carries the sender trailer (since
 *  b76r1), and only a membership control (a rekey part or member list) may be larger than the 4 KiB post cap. A
 *  frame without the trailer, or a 16/32 KiB frame holding anything else (a 10 KB text post from a modified app),
 *  is refused: receivers used to render it. */
export function parseGroupPayload(bytes: Uint8Array): { cover: boolean; text: string; meta?: GroupPostMeta } {
  const out = unpadMessageFrame(bytes, GROUP_CLASSES, 'group message');
  if (!out.meta) throw new Error('Corrupted group message payload');
  if (bytes.length > POST_MAX && (out.cover || !isMembershipControl(out.text))) throw new Error('Corrupted group message payload');
  return out;
}

/** b76 (padding): group cover filler — the same filler as 1:1 cover (cc/padding.ts
 *  coverFillerText: ~85 % in the 1 KiB class, the rest in the 4 KiB one). b75 group cover was
 *  16–48 hex characters, always the 1 KiB class, so a 4 KiB group envelope was never cover. */
export function groupCoverText(): string {
  return coverFillerText();
}

/** b71 (audit F-12): posts that carry a sequence number — what a member sees or what
 *  moves the group (messages, media, member lists, rekeys). Receipts, intros and cover
 *  are not numbered: a missing one is not worth a gap note. (This said they are "burned early by design";
 *  since b76r1 every kind is burned alike, audit AUD-G1.) */
export function isNumberedGroupPost(text: string, cover: boolean): boolean {
  return !cover && !text.startsWith('{"__veil_receipt":') && !text.startsWith('{"__veil_intro":');
}

/** b73 (audit V-22): the group-name key — HKDF(GEK, salt = SHA-256("vardum-group-name-key-v2:"),
 *  info = "group-name", 32). The GEK itself is otherwise only ever HKDF input (message keys,
 *  sender-tag key); enc1 blobs used it directly as an AES-GCM key. */
async function groupNameKey(gekB64: string): Promise<Uint8Array> {
  return hkdf(fromB64(gekB64), await sha256(utf8('vardum-group-name-key-v2:')), 'group-name', 32);
}

/** group name prefixes this build reads: enc2 only. b74 (VAR-22, clean break): enc1 (AES-GCM
 *  directly under the raw GEK, b72 and older) is no longer read — the GEK is only ever HKDF input */
export function isGroupNameBlob(blob: unknown): boolean {
  return typeof blob === 'string' && blob.startsWith('enc2:');
}

/** web's _m(): encrypted group name blob. b73 (audit V-22): 'enc2:' under the derived
 *  name key (see groupNameKey). Builds before b73 read only 'enc1:', so a b72 member
 *  joining through a b73 creator sees no group name until it updates. */
export async function encryptGroupText(gekB64: string, text: string): Promise<string> {
  const key = await crypto.subtle.importKey('raw', await groupNameKey(gekB64) as unknown as BufferSource, { name: 'AES-GCM' }, false, ['encrypt']);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  // b76 (padding): the name is framed and padded inside the encryption (cc/padding.ts padBlob,
  // floor GROUP_NAME_FLOOR), so every name blob on a relay row or in a key delivery is the same
  // 256-byte ciphertext — b75 blobs were name length + 16, telling the relay how long it was
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv as unknown as BufferSource }, key, padBlob(utf8(text), GROUP_NAME_FLOOR) as unknown as BufferSource));
  return `enc2:${toB64(iv)}:${toB64(ct)}`;
}

/** b76 (padding): a group name's ciphertext is at least this long (every name up to 234 UTF-8
 *  bytes; names are cut to 40 characters) — the smallest class of the size ladder */
export const GROUP_NAME_FLOOR = 256;

/** web's vm(): open a name blob. b73 (audit V-22): the
 *  prefix is the version marker — enc2 = derived key. b74 (VAR-22): an 'enc1:' blob (raw GEK
 *  as the AES key) is refused, never opened with the raw key.
 *  b76r1 (audit AUD-G4): anything that isn't a well-formed enc2 blob is refused too, and so is a call
 *  without a key. This used to RETURN THE RAW STRING ("falls back to the raw string"), so a relay row
 *  whose name was "enc2:<any text>" became a waiting joiner's group name. */
export async function decryptGroupText(gekB64: string, blob: string): Promise<string> {
  if (String(blob ?? '').startsWith('enc1:')) throw new Error('Group name from an older version (raw-key format) — not opened.');
  const m = /^enc2:([A-Za-z0-9+/]+={0,2}):([A-Za-z0-9+/]+={0,2})$/.exec(String(blob ?? ''));
  if (!m) throw new Error('Not an encrypted group name — not opened.');
  if (typeof gekB64 !== 'string' || !gekB64) throw new Error('No group key to open this group name with.');
  const [, ivB64, ctB64] = m;
  const raw = await groupNameKey(gekB64);
  const key = await crypto.subtle.importKey('raw', raw as unknown as BufferSource, { name: 'AES-GCM' }, false, ['decrypt']);
  const pt = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: fromB64(ivB64) as unknown as BufferSource }, key, fromB64(ctB64) as unknown as BufferSource));
  // b76 (padding): stripped strictly — an unpadded (b75) or mis-sized name frame is refused
  return fromUtf8(unpadBlob(pt, GROUP_NAME_FLOOR));
}

// ---------- encrypt / decrypt ----------

export interface GroupEnvelopeOut {
  ciphertext: string; iv: string; header: string; byteLength: number; senderTag: string;
  /** b71 (audit F-12): the post sequence this envelope carries (0 = unnumbered) */
  seq?: number;
  /** b77p (audit VAR-07): the message identity — sender chain, counter and signed time — so a re-send of
   *  THIS post (under the public tag) can carry the same one (encryptGroupMessage send.resend) */
  ch: string; n: number; sentAt: number;
}

/** b71 (audit F-12): a numbered post the relay refused never reached anyone — give its
 *  sequence number back (only if nothing was numbered since), so receivers don't see a
 *  gap for it. Best effort: a relay that stored it and still answered with an error
 *  shows up as a repeated number, which receivers ignore. */
export async function releaseGroupPostSeq(store: VeilStorage, groupToken: string, seq: number): Promise<void> {
  const rec = registry(store).get(groupToken);
  if (!rec || !seq || rec.postSeq !== seq) return;
  rec.postSeq = seq - 1;
  await persistSendState(store, rec).catch(() => undefined);
}

/** web's Sm(): send-path encrypt. Serialized under a per-group lock so the
 *  send counter never interleaves. */
export async function encryptGroupMessage(
  store: VeilStorage, groupToken: string, text: string, cover = false,
  /** b71 (review P-01): send as a seat intro, keyed by this seat */
  seat?: { keyB64: string; token: string },
  /** b73 (audit V-09): this one envelope under the PUBLIC sender tag (a relay not yet
   *  updated refused the keyed one); the record's own tag is left as it is.
   *  b75r3 (audit R3G-I2): control — set only by the code that BUILT a control message (see GroupControlKind) */
  send?: { publicTag?: boolean; control?: GroupControlKind;
    /** b77p (audit VAR-07): re-send of a post the relay refused under the keyed tag — the same chain, counter,
     *  sequence and time (receivers keep one replay window per signer, so if the relay had in fact kept the
     *  first copy, this one is a replay, never a second post). Only with publicTag. */
    resend?: { ch: string; n: number; seq: number; sentAt: number } },
): Promise<GroupEnvelopeOut> {
  let rec = registry(store).get(groupToken);
  if (!rec) throw new Error('Group keys are not established on this device.');
  const assertSendable = (r: GroupRecord): void => {
    // b71 (review P-01): a joiner holds no group key until the creator admits it and
    // delivers one; until then only its seat intro can go out
    if (!seat && !r.gekB64) {
      // b71 (audit F-07): the creator approves each link join with a tap
      throw new GroupSendBlockedError('Waiting for the group creator to approve you — you can send once they have.'); // b77k (IP77-2)
    }
    if (seat && !text.startsWith('{"__veil_intro":')) throw new Error('Only an intro travels on a seat key.');
    // b75r3 (audit R3G-I2): the exemptions below go by the control flag the building code set, never by the text
    // alone (a typed message that merely starts like a control message used to pass them: it went out while a
    // removal waited for its rotation, under the key the removed member holds). Flag and shape must agree.
    const ctl = controlKindOf(text, send?.control);
    // Batch C (A3): while an eviction waits for its rotation, only the rotation's
    // own control messages may go out under the old key
    if (r.evictionPendingAt !== undefined && ctl !== 'membership') {
      throw new GroupSendBlockedError('A member is being removed — waiting for the group keys to rotate. Try again in a moment.'); // b77k (IP77-2)
    }
    // Batch D (D-06, RV-05): members get no eviction signal, so they stop on a key
    // the creator should long since have replaced (intros still go out: they are
    // how a member asks to be let back in)
    // M-3 (b69 audit): the limit is the rotation period plus slack (48 h), not 7 days
    // b74 (VAR-05): a leave goes out whatever the key's age — it is how a leaver stops getting keys
    if (r.role === 'member' && ctl === null) {
      assertGroupKeysFresh(r);
    }
  };
  assertSendable(rec); // (fails fast, before queueing behind another send)
  const prev = sendLocks.get(groupToken) ?? Promise.resolve();
  let release!: () => void;
  sendLocks.set(groupToken, new Promise<void>((r) => (release = r)));
  await prev;
  try {
    if (sendUnconfirmed.has(rec)) {
      await mergeSendState(store, rec); // b63 review (I3-5): try the read again
      if (sendUnconfirmed.has(rec)) throw new Error('Group keys could not be read on this device. Try again in a moment.');
    }
    // b75r2 (audit R2G-01): the checks above ran BEFORE the wait for the send lock (another send, a rotation's
    // part, may hold it for as long as the relay takes). A Remove tap landing in that wait used to be missed —
    // the post went out under the key the removed member holds — and a save of a copy meanwhile left this
    // function encrypting with the copy's (older) epoch and key. So: the LIVE record, checked again, and the
    // epoch, key, tag and counter all taken from it in one step with no wait in between.
    const live = registry(store).get(groupToken);
    if (!live) throw new Error('Group keys are not established on this device.');
    if (live !== rec && sendUnconfirmed.has(live)) throw new Error('Group keys could not be read on this device. Try again in a moment.');
    rec = live;
    assertSendable(rec);
    // b76r2 (audit R2-I3): the cap is the control flag's, not the text prefix's; checked before the send counter moves
    // (a refused too-long post used to use up a counter value)
    const membership = controlKindOf(text, send?.control) === 'membership';
    if (!trailerFits(text, membership)) throw new Error('Message too long for the padded bucket sizes');
    const resend = send?.publicTag && !seat ? send.resend : undefined; // b77p (audit VAR-07)
    const n = resend ? resend.n : rec.sendN;
    if (!resend) {
      // b54 (T-3): a fresh sender chain id whenever the counter (re)starts
      if (n === 0 || !rec.sendChain) rec.sendChain = [...crypto.getRandomValues(new Uint8Array(8))].map((b) => b.toString(16).padStart(2, '0')).join('');
      rec.sendN += 1;
    }
    const ch = resend ? resend.ch : rec.sendChain as string;
    const epoch = rec.epoch;
    const keySnap = { groupToken, epoch, pqPubB64: rec.pqPubB64, gekB64: rec.gekB64 } as GroupRecord;
    const ownTag = rec.myTag, ownVid = rec.veilId, seedB64 = rec.ikSeedB64;
    // ---- (from here on only the values above are used for the envelope) ----
    // Batch C (A2; reviews P1 NF-3, P2 V-5): sender-signature v2 covers the
    // CIPHERTEXT. The AEAD associated data is the core header (everything but
    // sig); the signature, appended last, covers label ‖ core ‖ IV ‖ SHA-256(ct),
    // so a GEK holder can no longer swap content under another member's header.
    const sv = seat ? GROUP_SEAT_SIG_VERSION : GROUP_SIG_VERSION;
    const sid = send?.publicTag && !seat ? await senderTag(groupToken, epoch, ownVid) : ownTag; // b73 (audit V-09)
    const core: GroupEnvelopeHeader = { v: GROUP_PROTO, sid, ge: epoch, n, ch, sv };
    const coreStr = JSON.stringify(core);
    const msgKey = seat ? await seatIntroMsgKey(seat.keyB64, groupToken, epoch, seat.token, sid, n) : await groupMsgKey(keySnap, sid, ch, n);
    const key = await crypto.subtle.importKey('raw', msgKey as unknown as BufferSource, { name: 'AES-GCM' }, false, ['encrypt']);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    // b71 (audit F-12): the signed sender trailer — the sender's time, and a
    // sequence number on numbered posts (cross-epoch, per sender), so receivers spot
    // posts the relay drops and show the sender's time, not the relay's. (A text
    // too long to take the trailer goes without it, unnumbered.)
    // b76r1 (audit AUD-I4): EVERY group payload carries the trailer now — seat intros (unnumbered) and posts
    // at the 4 KiB edge too — so the size class is one function of the text's length (header + text + 13).
    // b76 left it off a post of 4081–4093 bytes (still 4 KiB) and off seat intros, while a control message of
    // the same length took it (and, at the edge, the next class): the class depended on the kind. A post too
    // long for its 4 KiB cap with the trailer is refused ("too long"), as a longer one always was.
    const seq = resend ? resend.seq : !seat && isNumberedGroupPost(text, cover) ? (rec.postSeq ?? 0) + 1 : 0;
    if (seq && !resend) rec.postSeq = seq;
    const meta: GroupPostMeta = { sentAt: resend ? resend.sentAt : Date.now(), seq };
    const payload = padGroupPayload(text, cover, meta, membership);
    const ct = new Uint8Array(await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: iv as unknown as BufferSource, additionalData: utf8(coreStr) as unknown as BufferSource },
      key, payload as unknown as BufferSource,
    ));
    if (!seedB64) throw new Error('Group identity key missing — cannot sign.');
    const sig = await ikSign(seedB64, toB64(await groupSigMessage(coreStr, iv, ct, sv)));
    const headerStr = JSON.stringify({ ...core, sig });
    // Batch H (R6-2-01): the counter is saved on its own (fail closed); the big
    // record is bookkeeping here, so its size can't stop a send or a removal post
    await persistSendState(store, rec);
    await persistBookkeeping(store, rec);
    return { ciphertext: toB64(ct), iv: toB64(iv), header: headerStr, byteLength: payload.length, senderTag: sid, ch, n, sentAt: meta.sentAt, ...(meta?.seq ? { seq: meta.seq } : {}) };
  } finally {
    release();
  }
}

/** web's Cm(): receive-path decrypt with replay guard + per-sender sig check. */
export async function decryptGroupMessage(
  store: VeilStorage, groupToken: string, headerStr: string, ciphertextB64: string, ivB64: string,
  relayChainId?: string,
): Promise<GroupDecryptResult> {
  const rec = registry(store).get(groupToken);
  if (!rec) throw new Error('Group keys are not established on this device.');
  void relayChainId; // Batch C (A5 / V-29): no longer used — the chain id comes ONLY from the signed header
  const parsed = parseSignedGroupHeader(headerStr);
  // an unsigned, pre-Batch-C or malformed envelope is a signature failure, not a transient one
  if (!parsed) throw new Error('veil-group-sig: unsigned, old-format or malformed envelope');
  // b71 (review P-01): a seat intro is never a group message (the poll hands it to the creator's admission)
  if (parsed.header.sv !== GROUP_SIG_VERSION) throw new Error('veil-group-sig: a seat intro is not a group message');
  if (!rec.gekB64) throw new Error('Group keys are not established on this device.');
  // b71 (review P-06): fail closed — with the saved window unread, an old copy could re-open messages
  if (recvUnconfirmed.has(rec)) {
    await mergeRecvState(store, rec);
    if (recvUnconfirmed.has(rec)) throw new Error('Group state could not be read on this device. Try again in a moment.');
  }
  const { header, coreStr } = parsed;
  const chainId = 'h:' + header.ch;
  const sid = header.sid;
  const n = header.n;
  const senderIk = rec.senderKeys && Object.prototype.hasOwnProperty.call(rec.senderKeys, sid) ? rec.senderKeys[sid] : undefined;

  // b54 (Batch A, N-2): private groups render ONLY messages signed by a
  // verified roster member. Thrown before any counter work, so a roster gap
  // just retries on the next poll.
  if (!senderIk) {
    throw new Error('veil-group-sig: sender not on the verified roster');
  }
  // Batch C (A2): verify the v2 signature (covers the ciphertext) BEFORE any
  // decryption or counter work.
  let senderVerified = false;
  if (senderIk) {
    const ok = await verifyWithIk(senderIk, toB64(await groupSigMessage(coreStr, fromB64(ivB64), fromB64(ciphertextB64))), header.sig)
      .catch(() => false);
    if (!ok) throw new Error('veil-group-sig: this envelope was not signed by the roster member it claims');
    senderVerified = true;
  }

  // b77p (audit VAR-07): the replay window belongs to the SIGNER (its identity key), not to the tag the post
  // came under. A member posts under its keyed tag or, when the relay refuses that, its public tag; with
  // a window per tag the relay could fake that refusal, keep the first copy and make the same post arrive
  // twice (the re-send went under a new tag and counter). The re-send now keeps its chain and counter and
  // the window is the signer's, so the second copy is a replay. A window stored under a tag (an older
  // build, this epoch) is taken over on first use.
  const wkey = 'ik:' + senderIk;
  const legacyKey = Object.prototype.hasOwnProperty.call(rec.recv, wkey) ? undefined
    : Object.prototype.hasOwnProperty.call(rec.recv, sid) ? sid : undefined;
  const hadSender = Object.prototype.hasOwnProperty.call(rec.recv, wkey) || legacyKey !== undefined;
  const prior = hadSender ? rec.recv[legacyKey ?? wkey] : undefined;
  // b54 (pre-audit T-3b): snapshot the STORED state before anything changes,
  // and work on a copy — a failed decrypt must never leave a reset window behind
  // (previously a garbage envelope with a new chain id reset the window for good).
  const copyState = (p0: GroupRecvState): GroupRecvState => ({
    last: p0.last, skipped: [...p0.skipped], chain: p0.chain, retired: [...(p0.retired ?? [])],
    ...(p0.open ? { open: p0.open.map((w) => ({ chain: w.chain, last: w.last, skipped: [...w.skipped] })) } : {}),
    ...(Array.isArray(p0.posts) ? { posts: [...p0.posts] } : {}), // b77u (audit 6 R4 #14)
  });
  const snapshot: GroupRecvState | undefined = prior ? copyState(prior) : undefined;
  const saved: GroupRecvState = snapshot ? copyState(snapshot) : { last: -1, skipped: [] };
  // b54 (T-3): never go BACK to a sender chain that was already replaced —
  // that is how an old chain's messages would be replayed after a restart
  if ((saved.retired ?? []).includes(chainId)) {
    throw new Error('Replayed or too-old group message.');
  }
  // b196-r2 chain switch: a DIFFERENT posting-session chain means this sender's counter restarted.
  // b77p (audit VAR-10): a new chain no longer retires the current one. Any chain id that differed from
  // the stored one was treated as newer and the old chain retired after one decrypt, so a relay that
  // delivered a member's new chain B first and then a withheld post of the old chain A retired B — and
  // every later post of that member was refused as a replay until the next rotation. Now each signer
  // keeps up to GROUP_OPEN_CHAINS chain windows (the newest in last/skipped/chain, the rest in open), each
  // judging its own counters; a chain is retired only when it falls out of that set (pushed out by newer
  // chains), so a post of an older chain that is still open is accepted in any order, and an old chain's
  // replays are still refused (by its own window while open, by retired after).
  const win = (): { last: number; skipped: number[] } => {
    if (saved.chain === chainId) return saved;
    const o = (saved.open ?? []).find((w) => w.chain === chainId);
    if (o) return o;
    // a chain this signer has not used before (this epoch): it opens as the newest window
    if (saved.chain !== undefined) {
      const open = [{ chain: saved.chain, last: saved.last, skipped: saved.skipped }, ...(saved.open ?? [])];
      const keep = open.slice(0, GROUP_OPEN_CHAINS - 1);
      const gone = open.slice(GROUP_OPEN_CHAINS - 1).map((w) => w.chain);
      saved.open = keep;
      if (gone.length) saved.retired = [...(saved.retired ?? []), ...gone].slice(-16);
    }
    saved.chain = chainId; saved.last = -1; saved.skipped = [];
    return saved;
  };
  try {
    const w = win();
    if (n <= w.last) {
      const idx = w.skipped.indexOf(n);
      if (idx === -1) throw new Error('Replayed or too-old group message.');
      w.skipped.splice(idx, 1);
    } else {
      // The counter is in unauthenticated JSON until AES-GCM succeeds. Bound
      // the gap before iterating to avoid a hostile huge-counter UI freeze.
      if (n - w.last > 1_000_000) throw new Error('Group message counter jump too large.');
      // Only the most recent MAX_SKIPPED positions are recoverable; do not
      // loop over the entire unauthenticated gap even when it is legitimate.
      for (let k = Math.max(w.last + 1, n - MAX_SKIPPED); k < n; k++) w.skipped.push(k);
      if (w.skipped.length > MAX_SKIPPED) w.skipped = w.skipped.slice(-64);
      w.last = n;
    }
    if (legacyKey !== undefined) delete rec.recv[legacyKey];
    rec.recv[wkey] = saved;

    const msgKey = await groupMsgKey(rec, sid, String(header.ch), n); // b77m (audit VAR-38)
    const key = await crypto.subtle.importKey('raw', msgKey as unknown as BufferSource, { name: 'AES-GCM' }, false, ['decrypt']);
    const pt = new Uint8Array(await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: fromB64(ivB64) as unknown as BufferSource, additionalData: utf8(coreStr) as unknown as BufferSource },
      key, fromB64(ciphertextB64) as unknown as BufferSource,
    ));
    // b196-r2 / b77p (VAR-10): the windows (and any chain pushed out of them) were changed on a copy; they
    // stand only because GCM authenticated (the catch puts the snapshot back otherwise)
    const out = parseGroupPayload(pt);
    // b77u (audit 6 R4 #14): the chain windows are per chain, so a member could re-send its own signed post under
    // a fresh chain id and counter 0 and have it shown twice (same text, time and sequence). A numbered post's
    // signed (seq, sentAt) names the post: one already seen from this signer is a copy (refused as a replay).
    // A re-used sequence number after a refused submit carries a new time, so it is not taken for a copy.
    const pseq = out.meta?.seq ?? 0;
    if (pseq > 0 && out.meta) {
      const pid = `${pseq}.${out.meta.sentAt}`;
      const seen = Array.isArray(saved.posts) ? saved.posts : [];
      if (seen.some((p) => p.split('@')[0] === pid)) throw new Error('Replayed or too-old group message.');
      saved.posts = [...seen, `${pid}@${n}.${String(header.ch).slice(0, 16)}`].slice(-GROUP_POSTS_SEEN);
    }
    // b71 (review P-06): the replay window is saved on its own BEFORE the message is
    // shown, and fail-closed: a refused write throws here, the window goes back to the
    // snapshot (catch below), and the message is retried on the next pass. (Batch G
    // kept it in memory only; a restart then rolled it back and re-opened messages.)
    await persistRecvState(store, rec);
    // Batch G (R5-2-03): the big record stays bookkeeping — a refused save keeps it in memory
    const wrote = await persistBookkeeping(store, rec);
    // M-3 (b69 audit): a relay can hide a rotation (and the member list that
    // removed someone) from this member and keep it on the old epoch, whose key
    // the removed member still holds. Past the read limit — measured from the
    // creator-signed epoch start, never a relay time — a post is not verified.
    // (The creator's epoch is the group's own; members only.)
    const started = epochStartMs(rec);
    const staleKeys = rec.role === 'member' && started !== null && Date.now() - started > MEMBER_EPOCH_READ_MAX_MS;
    const result: GroupDecryptResult = {
      ...out, senderVerified: senderVerified && !staleKeys,
      signerIk: senderIk, // b77s (audit 4 GR-01)
      ...(staleKeys ? { staleKeys: true } : {}),
      ...(wrote ? {} : { stateNotSaved: true }),
    };
    return result;
  } catch (e) {
    if (snapshot) rec.recv[legacyKey ?? wkey] = snapshot;
    else delete rec.recv[wkey];
    if (legacyKey !== undefined && snapshot) delete rec.recv[wkey];
    throw e;
  }
}

/** b77q review (J2-1): the post this header names opened, but the App could not keep it (its cache write was
 *  refused), so the poll holds the envelope for the next pass. Its counter is put back in the signer's window
 *  (as a skipped position) so that pass can open it again; nothing else changes (a chain pushed out stays out).
 *  false when the window could not be saved (the post is then lost on this phone, as before). */
export async function reopenGroupCounter(store: VeilStorage, groupToken: string, headerStr: string): Promise<boolean> {
  const rec = registry(store).get(groupToken);
  const parsed = parseSignedGroupHeader(headerStr);
  if (!rec || !parsed) return false;
  const { sid, ch, n, ge } = parsed.header;
  if (ge !== rec.epoch) return false; // the window was reset by a rotation since: nothing to put back
  const senderIk = rec.senderKeys && Object.prototype.hasOwnProperty.call(rec.senderKeys, sid) ? rec.senderKeys[sid] : undefined;
  const wkey = senderIk ? 'ik:' + senderIk : '';
  const st = wkey && Object.prototype.hasOwnProperty.call(rec.recv, wkey) ? rec.recv[wkey] : undefined;
  if (!st) return false;
  const chainId = 'h:' + ch;
  const w = st.chain === chainId ? st : (st.open ?? []).find((x) => x.chain === chainId);
  // b77u (audit 6 R4 #14): the post is read again, so its (seq, sentAt) mark goes too
  if (Array.isArray(st.posts)) { const suf = `@${n}.${String(ch).slice(0, 16)}`; st.posts = st.posts.filter((p) => !p.endsWith(suf)); }
  if (!w || n > w.last) return true; // never taken (nothing to undo)
  if (!w.skipped.includes(n)) {
    w.skipped.push(n);
    if (w.skipped.length > MAX_SKIPPED) w.skipped = w.skipped.filter((k) => k !== n).slice(-(MAX_SKIPPED - 1)).concat(n);
  }
  try { await persistRecvState(store, rec); } catch { return false; }
  await persistBookkeeping(store, rec);
  return true;
}

/** b123: read-only decrypt of MY OWN group envelope — the inbox poll's
 *  own-echo path uses it to learn which envelope id carries a locally-sent
 *  bubble, so group read receipts can tick that bubble (pairwise already
 *  had this via sendChatMessage's envId). Deliberately does NOT touch the
 *  per-sender recv bookkeeping or the sender-signature check — it only
 *  reads the payload back with the same GEK-derived message key. */
export async function decryptOwnGroupEnvelope(
  store: VeilStorage, groupToken: string, headerStr: string, ciphertextB64: string, ivB64: string,
): Promise<{ cover: boolean; text: string }> {
  const rec = registry(store).get(groupToken);
  if (!rec) throw new Error('Group keys are not established on this device.');
  const parsed = parseSignedGroupHeader(headerStr);
  if (!parsed) throw new Error('Malformed group message header.');
  const { header, coreStr } = parsed;
  const msgKey = await groupMsgKey(rec, header.sid, String(header.ch), header.n); // b77m (audit VAR-38)
  const key = await crypto.subtle.importKey('raw', msgKey as unknown as BufferSource, { name: 'AES-GCM' }, false, ['decrypt']);
  const pt = new Uint8Array(await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: fromB64(ivB64) as unknown as BufferSource, additionalData: utf8(coreStr) as unknown as BufferSource },
    key, fromB64(ciphertextB64) as unknown as BufferSource,
  ));
  return parseGroupPayload(pt);
}

/** web's fm(): bump the rotation counter (creator auto-rotate trigger) */
export async function bumpGroupEnvCount(store: VeilStorage, groupToken: string): Promise<number> {
  const rec = registry(store).get(groupToken);
  if (!rec) return 0;
  rec.envCount = (rec.envCount ?? 0) + 1;
  await persistBookkeeping(store, rec); // Batch G (R5-2-03)
  return rec.envCount;
}

// ---------- rekey / epoch rotation ----------

/** b77m (audit VAR-10): a hybrid wrap — `ct` the ML-KEM-768 ciphertext to the member's signed PQ prekey, `xe` the
 *  creator's one-time X25519 key (DH with the member's identity key), `wk`/`wi` the AES-GCM-wrapped group key
 *  and its IV. A wrap without `xe` (b76 and older: ML-KEM alone) is not read (clean break, see buildRekeyWrap). */
export interface GroupRekeyWrap { to: string; ct: string; xe: string; wk: string; wi: string }
/** b77m (audit VAR-10): what a wrap is bound to besides its recipient */
export interface RekeyWrapContext { groupToken: string; epoch: number }
/** b54: signed rekey (v2). `body` is the exact signed string; t/ge/pq/wraps are parsed from it.
 *  Batch C (A3): also rid (rotation id), kc (key commitment), pi/pc (part i of n). */
export interface GroupRekeyPayload {
  t: string; ge: number; pq: string; wraps: GroupRekeyWrap[]; body: string; sig: string;
  rid: string; kc: string; pi: number; pc: number;
  /** b70 (re-review 6): the creator's signed epoch start (ms); older builds omit it */
  at?: number;
  /** b71 (review P-01): the group name under the delivered key (key deliveries to joiners) */
  nm?: string;
  /** b73 (audit V-07): the signed recipient set — sorted Vardum IDs of every member this
   *  epoch's key is meant for (the same in every part and in later deliveries).
   *  b74 (rc-omission bypass): REQUIRED — a rekey without it is malformed. */
  rc: string[];
  /** b75 (audit GR-5): the sequence of the creator-signed member list this rekey was made with
   *  (REQUIRED). A member whose latest list is older knows a list is missing — it waits for it (or
   *  asks for the key through the gate) instead of blaming the creator for a stranger in rc. */
  ms: number;
  /** b75 (audit GR-5): membersHash of that list's entries (REQUIRED) — a list under the same number
   *  with other entries is a contradiction, refused */
  mh: string;
  /** b76r1 (audit AUD-G2): the rotation hash (REQUIRED) — every part of one rotation signs the same
   *  commitment to the WHOLE rotation (rotationHash: its fields, rc and the digest of every part's wraps),
   *  so a member that has all pc parts can tell that no part carries a wrap the others don't account for */
  rh: string;
}

/** b76r1 (audit AUD-G2/G3): one rotation a member is collecting (GroupRecord.heldRotations) */
export interface HeldRotation {
  rid: string; ge: number; pc: number; rh: string;
  /** the fields every part must agree on (they are in rh): pq, kc, at, rc, ms, mh */
  pq: string; kc: string; at?: number; rc: string[]; ms: number; mh: string;
  /** [pi, digest of the part's wraps (rekeyPartDigest), the Vardum IDs its wraps are to] */
  parts: Array<[number, string, string[]]>;
  /** the full signed text of the part carrying this phone's wrap, if one does */
  own?: string;
  /** when this phone saw the rotation's first part (ms) */
  first: number;
}

/** b76r1 (audit AUD-G3): bounds on GroupRecord.heldRotations */
export const HELD_ROTATIONS_MAX = 4;
export const HELD_ROTATIONS_MAX_BYTES = 96 * 1024;
/** b76r1 (audit AUD-G2): how long a member waits for the missing parts of a rotation before it treats the
 *  rotation as signed evidence that the group moved on (sends stop, the key is asked for through the gate) */
export const ROTATION_PARTS_WAIT_MS = 10 * 60_000;

/** b75 (audit GR-5): the bytes a rekey commits to for a member list — B64(SHA-256(utf8(
 *  "vardum-group-members-hash-v1:" ‖ JSON of the [IK_pub, veil_id] entries sorted by IK_pub))) */
export async function membersHash(members: Array<[string, string]>): Promise<string> {
  return membersHashSync(members);
}
/** b77t2 (L-8): the same hash with no wait (the member-list builder keeps it in the one write that numbers the list) */
export function membersHashSync(members: Array<[string, string]>): string {
  const sorted = [...members].map(([ik, vid]) => [String(ik), String(vid)] as [string, string]).sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
  return toB64(nobleSha256(utf8('vardum-group-members-hash-v1:' + JSON.stringify(sorted))));
}

/** b77u (audit 6 IH crypto F-2): the wrap labelled with this phone's ID does not open with this phone's keys (made to
 *  an older prekey, or to someone else's keys). Not applied; the thread says so and the key is asked for. */
export class GroupOwnWrapError extends Error {
  readonly ge: number;
  constructor(ge: number, why: string) { super('This phone could not open its copy of the new group key: ' + why); this.name = 'GroupOwnWrapError'; this.ge = ge; }
}

/** b77u (audit 6 IH crypto F-3): two different creator-signed member lists under one number */
export class GroupListConflictError extends Error {
  readonly seq: number;
  constructor(seq: number) { super(`Two different member lists signed under number ${seq} — the second was not taken.`); this.name = 'GroupListConflictError'; this.seq = seq; }
}

/** b75 (audit GR-5): a rekey part names someone not on this phone's list, and was made with a member list
 *  (ms) this phone hasn't received: not a refusal — the phone waits for that list (or the gate's key) */
export class GroupRekeyListMissingError extends Error {
  readonly ms: number;
  constructor(ms: number) { super(`This rekey was made with member list ${ms}, which hasn't reached this phone yet.`); this.name = 'GroupRekeyListMissingError'; this.ms = ms; }
}

/** b73 (audit V-07): a rekey that gives the key to someone it may not */
export class GroupRekeyRecipientsError extends Error {
  /** b75 (audit GR-1): the Vardum IDs among the stray recipients who had said they were leaving */
  readonly leavers: string[];
  /** b76r1 (audit AUD-G2): 'mismatch' = the parts of one rotation don't agree (fields, rh, or a part's wraps
   *  against the signed rotation hash) — the creator's phone contradicted itself about who gets the key */
  /** b76r2 (audit R2-G1): 'conflict' = two different rotations (rotation ids) for the same epoch — the creator's
   *  phone signed two different key changes for one step; 'already' = this epoch was refused earlier on this phone
   *  (the note was given then) */
  /** b77q (audit 3 GR-2): 'equivocation' = a creator-signed key change for the epoch this phone ALREADY applied
   *  contradicts it (another rotation id, another key, or the key given to someone the applied one wasn't): sends
   *  under that key stop (ghostKeyEpoch) until the next key change */
  /** b77u (audit 6 IH crypto F-2): 'duplicate' = two wraps for one recipient (one can be made to a ghost's keys) */
  readonly kind?: 'mismatch' | 'conflict' | 'already' | 'equivocation' | 'duplicate';
  constructor(message: string, leavers: string[] = [], kind?: 'mismatch' | 'conflict' | 'already' | 'equivocation' | 'duplicate') { super(message); this.name = 'GroupRekeyRecipientsError'; this.leavers = leavers; if (kind) this.kind = kind; }
}

/** Batch C (A3): commitment to a group key, bound to the group and epoch. Every
 *  part of one rotation carries the same value; a member checks its unwrapped key against it. */
export async function gekCommitment(groupToken: string, epoch: number, gekB64: string): Promise<string> {
  return toB64(await sha256(concat(utf8(`vardum-gek-commit-v1:${groupToken}:${epoch}:`), fromB64(gekB64))));
}

/** Batch C (A1/A3): control messages that may travel while an eviction is pending,
 *  and that use the larger rekey buckets. */
export function isMembershipControl(text: string): boolean {
  return text.startsWith('{"__veil_group_rekey":') || text.startsWith('{"__veil_group_members":');
}

/** b75r3 (audit R3G-I2): the control messages the send path treats differently, as the code that builds them flags
 *  them (submitGroupEnvelope's `control`): 'membership' — a rekey part or a creator-signed member list (may go out
 *  while a removal waits for its rotation); 'intro' — a seat intro or a name binding; 'leave' — a signed leave (both
 *  go out whatever the key's age). A message the user typed never carries a flag. */
export type GroupControlKind = 'membership' | 'intro' | 'leave';

/** b75r3 (audit R3G-I2): the control kind of an outgoing message — the flag, and only when the text has that shape
 *  (null = an ordinary post, whatever its text starts with) */
export function controlKindOf(text: string, flag: GroupControlKind | undefined): GroupControlKind | null {
  if (flag === 'membership') return isMembershipControl(text) ? 'membership' : null;
  if (flag === 'intro') return text.startsWith('{"__veil_intro":') ? 'intro' : null;
  if (flag === 'leave') return isLeaveControl(text) ? 'leave' : null;
  return null;
}

// ---------- Batch C (A1): seats and the creator-signed member list ----------

/** Seat key = HKDF(link secret k, salt "vardum-seat-v1:" ‖ seat token). k lives only in
 *  the link fragment, so the relay — which sees the seat token — cannot derive it. */
export async function deriveSeatKey(linkSecret: string, seatToken: string): Promise<string> {
  if (!/^[0-9a-f]{64}$/i.test(linkSecret)) throw new Error('This invite link is missing its secret.');
  return toB64(await hkdf(utf8(linkSecret.toLowerCase()), utf8(`vardum-seat-v1:${seatToken}`), 'seat', 32));
}

/** b70 (audit VAR-10 / GRP-1): the same proof, also covering the creator key
 *  the joiner was given (the link's c=). The real creator recomputes it with its
 *  own key, so a link whose c= was swapped by whoever forwarded it is refused. */
export async function seatProofForCreator(seatKeyB64: string, groupToken: string, seatToken: string, veilId: string, ikPubB64: string, creatorIkB64: string): Promise<string> {
  return toB64(await hmacSha256(fromB64(seatKeyB64), utf8(`vardum-seat-proof-v2:${groupToken}:${seatToken}:${veilId}:${ikPubB64}:${creatorIkB64}`)));
}

/** Proof that the holder of seat `seatToken` is admitting exactly (veilId, ik). */
export async function seatProof(seatKeyB64: string, groupToken: string, seatToken: string, veilId: string, ikPubB64: string): Promise<string> {
  return toB64(await hmacSha256(fromB64(seatKeyB64), utf8(`vardum-seat-proof-v1:${groupToken}:${seatToken}:${veilId}:${ikPubB64}`)));
}

// ---------- b71 (review P-02 / P-03): group identity and name bindings ----------

const GROUP_ID_LABEL = 'vardum-group-id-v1:';

/** b71 (review P-02): a group token commits to its creator's key —
 *  hex(SHA-256(utf8("vardum-group-id-v1:" ‖ creatorIK_b64 ‖ ":" ‖ salt_hex)))[0:32]
 *  (128 bits). The salt travels in the link (s=), so a joiner checks the link's c=
 *  against the token itself: whoever forwards a link can't name another creator
 *  without finding a second preimage, and the relay's roster labels play no part. */
export async function groupIdFor(creatorIkB64: string, saltHex: string): Promise<string> {
  if (!/^[0-9a-f]{32}$/.test(saltHex) || !creatorIkB64) throw new Error('This group invitation is incomplete — ask for a fresh link.');
  return sha256HexPrefix(`${GROUP_ID_LABEL}${creatorIkB64}:${saltHex}`, 16);
}

const GROUP_NAME_LABEL = 'vardum-group-name-v1:';

/** b71 (review P-03): the bytes a member signs to bind its name in one group */
function groupNameMessage(groupToken: string, ikPubB64: string, nick: string): string {
  return toB64(utf8(GROUP_NAME_LABEL + JSON.stringify([groupToken, ikPubB64, nick])));
}

/** b71 (review P-03): a member's own signature on its name in this group (Ed25519, IK) */
export function signGroupName(ikSeedB64: string, groupToken: string, ikPubB64: string, nick: string): Promise<string> {
  return ikSign(ikSeedB64, groupNameMessage(groupToken, ikPubB64, nick));
}

/** b71 (review P-03): true only if `ikPubB64` signed this name for this group */
export async function verifyGroupName(groupToken: string, ikPubB64: string, nick: string, sig: string): Promise<boolean> {
  if (typeof nick !== 'string' || !nick || nick.length > 40 || typeof sig !== 'string' || !sig) return false;
  try { return await verifyWithIk(ikPubB64, groupNameMessage(groupToken, ikPubB64, nick), sig); } catch { return false; }
}

/** b74 (clean break): v2 — the body now carries the epoch (e) and the first-bound name
 *  sequences (fb); a list signed for veil-group-1 never verifies here */
const MEMBERS_SIG_LABEL = 'vardum-group-members-v2:';
const IK_B64_RE = /^[A-Za-z0-9+/]{43}=$/;

export interface GroupMembersPayload { t: string; seq: number; members: Array<[string, string]>; body: string; sig: string;
  /** b74 (VAR-19 part): the epoch the creator published this list in. A member applies it
   *  only while it is on exactly that epoch (it arrived under that epoch's key), so an
   *  insider can't re-post an old list into a later epoch. */
  e: number;
  /** b71 (review P-03): IK_pub -> [name, the member's own signature on it] */
  names?: Record<string, [string, string]>;
  /** b74 (VAR-06): IK_pub -> the sequence at which that member's current name was first bound
   *  (required in veil-group-2; a name entry without one is not trusted) */
  fb: Record<string, number>;
  /** b71 (audit F-04): removals — [IK_pub, veil_id, the first epoch without them] */
  removed?: Array<[string, string, number]> }

/** Creator-signed member list: body = JSON{t, seq, e, m: [[IK_pub, veil_id], ...], nm?, fb, rm?}.
 *  b71 (review P-03): nm: {IK_pub: [name, self-signature]} — every member's name, so a
 *  newcomer knows them all and shows the same names as everyone else.
 *  b74: e = the epoch it is published in; fb = {IK_pub: first-bound sequence} for every
 *  name in nm (VAR-06: a name clash is won by the lowest — whoever bound the name first).
 *  If the list would not fit the largest control bucket, the longest names are left out
 *  (those members show with an ID suffix). */
export async function buildSignedMembersText(
  creatorIkSeedB64: string, groupToken: string, seq: number, epoch: number, members: Array<[string, string]>,
  opts: {
    names?: Record<string, [string, string]>;
    /** b74 (VAR-06): IK_pub -> first-bound sequence of that member's current name. A name
     *  without one is left out of the list. */
    fb?: Record<string, number>;
    /** b71 (audit F-04): rm — who was removed, and the first epoch without them. A member
     *  still on an older epoch stops sending when it reads this (the removed member holds
     *  that epoch's key). */
    removed?: Array<[string, string, number]>;
  } = {},
): Promise<string> {
  if (!Number.isInteger(epoch) || epoch < 1) throw new Error('A member list must name its epoch.');
  const nm: Record<string, [string, string]> = {};
  const fb: Record<string, number> = {};
  for (const [ik, v] of Object.entries(opts.names ?? {})) {
    const n = opts.fb && Object.prototype.hasOwnProperty.call(opts.fb, ik) ? opts.fb[ik] : undefined;
    if (Array.isArray(v) && typeof v[0] === 'string' && typeof v[1] === 'string' && Number.isInteger(n) && (n as number) >= 0) { nm[ik] = [v[0], v[1]]; fb[ik] = n as number; }
  }
  const rm = (opts.removed ?? []).filter((x) => Array.isArray(x) && typeof x[0] === 'string' && typeof x[1] === 'string' && Number.isInteger(x[2])).slice(-16);
  const bodyOf = () => JSON.stringify({ t: groupToken, seq, e: epoch, m: members, ...(Object.keys(nm).length ? { nm } : {}), fb, ...(rm.length ? { rm } : {}) });
  // b71 (audit F-12): room for the sender trailer too
  const fits = (body: string) => PAYLOAD_HDR + utf8(JSON.stringify({ __veil_group_members: 1, body, sig: 'x'.repeat(88) })).length + TRAILER_BYTES <= CONTROL_MAX;
  let body = bodyOf();
  while (!fits(body) && Object.keys(nm).length) {
    const longest = Object.entries(nm).sort((a, b) => utf8(b[1][0]).length - utf8(a[1][0]).length)[0][0];
    delete nm[longest];
    delete fb[longest];
    body = bodyOf();
  }
  const sig = await ikSign(creatorIkSeedB64, toB64(utf8(MEMBERS_SIG_LABEL + body)));
  return JSON.stringify({ __veil_group_members: 1, body, sig });
}

export function parseMembersPayload(text: string): GroupMembersPayload | 'invalid' | null {
  if (typeof text !== 'string' || !text.startsWith('{"__veil_group_members":')) return null;
  try {
    const t = JSON.parse(text) as Record<string, unknown>;
    if (t.__veil_group_members !== 1 || typeof t.body !== 'string' || typeof t.sig !== 'string') return 'invalid';
    const b = JSON.parse(t.body) as Record<string, unknown>;
    if (typeof b.t !== 'string' || !Number.isInteger(b.seq) || Number(b.seq) < 1 || !Array.isArray(b.m)) return 'invalid';
    // b74 (clean break): the epoch and the first-bound sequences are required
    if (!Number.isInteger(b.e) || Number(b.e) < 1) return 'invalid';
    if (!b.fb || typeof b.fb !== 'object' || Array.isArray(b.fb)) return 'invalid';
    const members = (b.m as unknown[]).filter((x): x is [string, string] => Array.isArray(x) && x.length === 2 && typeof x[0] === 'string' && typeof x[1] === 'string');
    if (members.length !== (b.m as unknown[]).length || members.length > GROUP_MEMBER_CAP) return 'invalid';
    const fb: Record<string, number> = {};
    for (const [ik, v] of Object.entries(b.fb as Record<string, unknown>)) {
      if (IK_B64_RE.test(ik) && Number.isInteger(v) && Number(v) >= 0) fb[ik] = Number(v);
    }
    // b71 (review P-03): names, if any (a malformed entry is skipped, never trusted).
    // b74 (VAR-06): a name without its first-bound sequence is skipped too
    const names: Record<string, [string, string]> = {};
    if (b.nm && typeof b.nm === 'object' && !Array.isArray(b.nm)) {
      for (const [ik, v] of Object.entries(b.nm as Record<string, unknown>)) {
        if (!IK_B64_RE.test(ik) || !Array.isArray(v) || v.length !== 2 || typeof v[0] !== 'string' || typeof v[1] !== 'string') continue;
        if (!Object.prototype.hasOwnProperty.call(fb, ik)) continue;
        names[ik] = [v[0], v[1]];
      }
    }
    // b71 (audit F-04): removal notices, if any (malformed entries skipped)
    const removed: Array<[string, string, number]> = [];
    if (Array.isArray(b.rm)) {
      for (const x of (b.rm as unknown[]).slice(0, 16)) {
        if (Array.isArray(x) && x.length === 3 && typeof x[0] === 'string' && typeof x[1] === 'string' && Number.isInteger(x[2]) && Number(x[2]) > 0) removed.push([x[0], x[1], Number(x[2])]);
      }
    }
    return { t: b.t, seq: Number(b.seq), e: Number(b.e), members, body: t.body, sig: t.sig, fb, ...(Object.keys(names).length ? { names } : {}), ...(removed.length ? { removed } : {}) };
  } catch { return 'invalid'; }
}

/** b74 (VAR-06): a name change the latest member list carries — [IK_pub, old name, new name] */
export type GroupRename = [string, string, string];

/** Member: accept a member list only if the group creator signed it, it names this
 *  group, it is newer than the one held, and every entry's ID is the hash of its key.
 *  b74 (VAR-19 part): and only in the epoch it was published in (payload.e === this
 *  phone's epoch — the epoch whose key opened it). b74 (VAR-06): each name's first-bound
 *  sequence is kept (clashes go to the lowest), and `out.renames` lists the members whose
 *  listed name changed, for a "X renamed to Y" note. */
export async function applyMembersPayload(store: VeilStorage, groupToken: string, payload: GroupMembersPayload, out?: { renames: GroupRename[]; ghosts?: GroupDeliveryGhost[] }): Promise<boolean> {
  const rec = registry(store).get(groupToken);
  if (!rec || !rec.creatorIkPubB64) return false;
  const ok = await verifyWithIk(rec.creatorIkPubB64, toB64(utf8(MEMBERS_SIG_LABEL + payload.body)), payload.sig).catch(() => false);
  if (!ok) throw new Error('veil-group-sig: member list not signed by the group creator');
  if (payload.t !== groupToken) throw new Error('Member list names a different group — refused.');
  if (payload.e !== rec.epoch) throw new Error(`Member list is for epoch ${payload.e}, this phone is on ${rec.epoch} — refused.`);
  // b77u (audit 6 IH crypto F-3): a DIFFERENT signed list under the number this phone already took is the creator's
  // phone contradicting itself (an honest one numbers each list once); a relay could show members different ones.
  // It was dropped silently; now it is said (the list taken stays — a warning, sends go on).
  if (payload.seq === (rec.memberSeq ?? 0) && rec.memberListHash && await membersHash(payload.members) !== rec.memberListHash) {
    throw new GroupListConflictError(payload.seq);
  }
  if (payload.seq <= (rec.memberSeq ?? 0)) return false;
  const list: Record<string, string> = {};
  for (const [ik, vid] of payload.members) {
    if ((await veilIdFromIkPub(ik).catch(() => '')) !== vid) continue;
    list[ik] = vid;
  }
  const wasListed = !!rec.memberList && Object.prototype.hasOwnProperty.call(rec.memberList, rec.ikPubB64);
  rec.memberList = list;
  rec.memberSeq = payload.seq;
  rec.memberListHash = await membersHash(payload.members); // b75 (audit GR-5): what a rekey's mh is checked against
  // b71 (review P-03): the names this list carries, each checked against its own
  // member's signature (the creator first). They replace the old set.
  const before = rec.boundNicks ?? {};
  const bound: Record<string, string> = {};
  const nameFb: Record<string, [string, number]> = {};
  for (const ik of [rec.creatorIkPubB64, ...Object.keys(list)]) {
    const e = payload.names && Object.prototype.hasOwnProperty.call(payload.names, ik) ? payload.names[ik] : undefined;
    if (e && !Object.prototype.hasOwnProperty.call(bound, ik) && await verifyGroupName(groupToken, ik, e[0], e[1])) {
      bound[ik] = e[0];
      nameFb[ik] = [e[0], payload.fb[ik]]; // (parseMembersPayload kept only names with an fb)
    }
  }
  if (out) {
    for (const [ik, n] of Object.entries(bound)) {
      const old = Object.prototype.hasOwnProperty.call(before, ik) ? before[ik] : undefined;
      if (old && old !== n) out.renames.push([ik, old, n]);
    }
  }
  // b75r1 (audit G-1): a name someone held and no longer holds (they were dropped, or renamed) is held back
  for (const [ik, old] of Object.entries(before)) if (typeof old === 'string' && old && bound[ik] !== old) holdFreedName(rec, ik, old);
  // b75r1 (audit G-7): this phone itself was removed — named in rm, or dropped by a list after one that named it
  if (rec.role === 'member' && rec.removedFromGroup === undefined
    && ((payload.removed ?? []).some(([ik]) => ik === rec.ikPubB64) || (wasListed && !Object.prototype.hasOwnProperty.call(list, rec.ikPubB64)))) {
    rec.removedFromGroup = payload.e;
  }
  rec.boundNicks = bound;
  rec.nameFb = nameFb;
  // b71 (audit F-04): a removal at an epoch this phone doesn't hold yet stops its
  // sends until that epoch's key arrives (groupKeyFreshness.removed)
  const ahead = Math.max(0, ...(payload.removed ?? []).map((x) => x[2]).filter((e) => e > rec.epoch));
  if (ahead > (rec.removalPendingEpoch ?? 0)) rec.removalPendingEpoch = ahead;
  // b73 (audit V-07): kept for the rekey recipient check (each entry's ID must be its key's)
  const removals: Array<[string, number]> = [];
  for (const [ik, vid, ep] of payload.removed ?? []) if ((await veilIdFromIkPub(ik).catch(() => '')) === vid) removals.push([vid, ep]);
  rec.listRemovals = removals.length ? removals : undefined;
  // b77m review (L2): gate deliveries that waited for this list are checked now
  const ghosts = await settleDeliveryChecks(rec, payload.e);
  if (out && ghosts.length) (out.ghosts ??= []).push(...ghosts);
  await saveGroupRecord(store, rec);
  return true;
}

/** b77q review (GR-6): the leavers (Vardum IDs) a rekey for epoch `ge` signed at `at` may still name: it was made
 *  before this phone first saw the leave, or it is for the epoch this phone read the leave in (or an earlier one —
 *  the leaver held that key when it left, so naming it there gives nothing away) */
function leaversStillKeyed(rec: GroupRecord, ge: number, at: number | undefined): string[] {
  const out: string[] = [];
  for (const l of Object.values(rec.leftIks ?? {})) {
    if (!l || typeof l.vid !== 'string') continue;
    if ((at !== undefined && at < Number(l.at)) || (Number.isInteger(l.ep) && ge <= (l.ep as number))) out.push(l.vid);
  }
  return out;
}

/** b77m review (L2): a gate delivery whose signed recipient set, checked once its member list arrived, named
 *  someone not on it (or was made with a different list under the same number) */
export type GroupDeliveryGhost = { ge: number; stray: string[]; mismatch: boolean;
  /** b77q owner (1 Nov, "Warn, keep sending"): only said in the thread — sends under that epoch's key go on (an
   *  inflated list number with no stray, a delivery whose list never arrived). Unset: sends stop (ghostKeyEpoch). */
  warnOnly?: true };

/** b77m review (L2): check the kept gate deliveries (deliveryChecks) whose list number this phone now holds,
 *  with the same rules as a posted rotation (checkRekeyRecipients): the trusted set, a removal that applies
 *  only from a later epoch, a leave learnt after the delivery was signed. A stray sets ghostKeyEpoch (when
 *  that epoch's key is the one held, sends under it stop) and is returned for the notice. Deliveries for a
 *  list this phone still doesn't hold stay kept.
 *  b77q (audit 3 GR-1): `listEpoch` = the epoch the list just applied was published in. A delivery for epoch ge
 *  signed with list number ms is settled by the first list of a LATER epoch too, whatever its number: an honest
 *  creator signs a delivery for ge only while on ge, with its latest list number, and numbers only go up, so every
 *  list it publishes in a later epoch has seq > ms. A later-epoch list with seq < ms proves ms was inflated (a
 *  creator's phone that signed ms = 10^9 used to defer this check for ever): flagged like a list mismatch
 *  (ghostKeyEpoch and the notice). Lists of the same epoch ge may honestly be older than the delivery: they don't
 *  settle it. */
async function settleDeliveryChecks(rec: GroupRecord, listEpoch?: number): Promise<GroupDeliveryGhost[]> {
  const pending = rec.deliveryChecks ?? [];
  if (!pending.length || rec.role !== 'member' || rec.memberSeq === undefined) return [];
  const seq = rec.memberSeq as number;
  const settles = (c: { ge: number; ms: number }) => c.ms <= seq || (listEpoch !== undefined && listEpoch > c.ge);
  const due = pending.filter(settles);
  if (!due.length) return [];
  rec.deliveryChecks = pending.filter((c) => !settles(c));
  if (!rec.deliveryChecks.length) delete rec.deliveryChecks;
  const trusted = await trustedMembers(rec);
  if (!trusted) return [];
  const out: GroupDeliveryGhost[] = [];
  for (const c of due) {
    const allowed = new Set(Object.values(trusted));
    for (const [vid, firstWithout] of rec.listRemovals ?? []) if (firstWithout > c.ge) allowed.add(vid);
    for (const vid of leaversStillKeyed(rec, c.ge, c.at)) allowed.add(vid); // b77q review (GR-6)
    // b77q (audit 3 GR-1): settled by a later epoch's list numbered below the delivery's ms — ms was inflated
    const inflated = c.ms > seq;
    const sameNumber = c.ms === rec.memberSeq && !!rec.memberListHash && c.mh !== rec.memberListHash;
    const mismatch = inflated || sameNumber;
    const stray = c.rc.filter((t) => !allowed.has(t));
    if (!stray.length && !mismatch) continue;
    // b77q owner (1 Nov, "Warn, keep sending"): sends stop only on proof — a stray recipient (the key given to someone
    // not on the list this phone holds) or two signed lists under one number (equivocation). An inflated number
    // alone proves the creator's phone misnumbered, not that anyone else got the key: warned, sends go on
    if (!stray.length && !sameNumber) { if (!c.warned) out.push({ ge: c.ge, stray, mismatch, warnOnly: true }); continue; }
    out.push({ ge: c.ge, stray, mismatch });
    if (c.ge >= (rec.ghostKeyEpoch ?? 0)) rec.ghostKeyEpoch = c.ge;
  }
  return out;
}

/** b77q review (GR-1 residual): how long a delivery made with a newer list than this phone holds may wait for that list
 *  (or any later epoch's) before it is flagged — both bounds must pass. Generous: an honest creator publishes a list
 *  after every rotation (posted under the delivered key), but the post may be late, or lost and only replaced by the
 *  next rotation's list. b77q owner (1 Nov, "Warn, keep sending"): such a flag is a warning only (sends go on). */
export const DELIVERY_CHECK_MAX_WAIT_MS = 72 * 3600_000;
export const DELIVERY_CHECK_MAX_PASSES = 30;

/** b77q owner (1 Nov, "Warn, keep sending"): both callers flag what is not proof that anyone else holds the key (a
 *  number that went down, a list that never came), so the flag is a warning in the thread; sends are not stopped */
function flagDelivery(rec: GroupRecord, c: { ge: number }, out: GroupDeliveryGhost[]): void {
  const g: GroupDeliveryGhost = { ge: c.ge, stray: [], mismatch: true, warnOnly: true };
  out.push(g);
  rec.deliveryGhostNotes = [...(rec.deliveryGhostNotes ?? []).filter((x) => x.ge !== c.ge), g].slice(-8);
}

/** b77q review (GR-1 residual): a creator-signed rekey (a rotation part or a gate delivery, signature checked) for
 *  epoch `ge` with list number `ms`. A kept delivery for an EARLIER epoch with a higher list number is proven
 *  inflated: an honest creator's numbers only go up, and it signs a later epoch's rekey with its latest number. Before,
 *  only a later epoch's member list settled it — a compromised creator that never published one in a later epoch left
 *  it waiting for ever. Flagged with the "different member list" notice (b77q owner (1 Nov): a warning only — sends
 *  go on). Returns the flags (also kept in deliveryGhostNotes); the caller saves the record. */
export function settleDeliveryChecksByRekey(rec: GroupRecord, ge: number, ms: number): GroupDeliveryGhost[] {
  const pending = rec.deliveryChecks ?? [];
  if (!pending.length || rec.role !== 'member' || !Number.isSafeInteger(ms)) return [];
  const inflated = (c: { ge: number; ms: number; warned?: true }) => !c.warned && ge > c.ge && ms < c.ms;
  const due = pending.filter(inflated);
  if (!due.length) return [];
  // b77q owner (1 Nov): warned and KEPT (a later list can still check its rc and prove a stray)
  rec.deliveryChecks = pending.map((c) => (inflated(c) ? { ...c, warned: true as const } : c));
  const out: GroupDeliveryGhost[] = [];
  for (const c of due) flagDelivery(rec, c, out);
  return out;
}

/** b77q review (GR-1 residual): once per inbox pass (member) — a kept delivery still waiting for its list after
 *  DELIVERY_CHECK_MAX_WAIT_MS and DELIVERY_CHECK_MAX_PASSES passes is flagged: the "different member list" notice is
 *  said. b77q owner (1 Nov, "Warn, keep sending"): sends are NOT stopped (the review had them fail closed; a lost list
 *  post would have frozen an honest group). true = the record changed (the caller saves it). */
export function expireDeliveryChecks(rec: GroupRecord, now = Date.now()): boolean {
  const pending = rec.deliveryChecks ?? [];
  if (!pending.length || rec.role !== 'member') return false;
  const keep: NonNullable<GroupRecord['deliveryChecks']> = [];
  const out: GroupDeliveryGhost[] = [];
  for (const c0 of pending) {
    const c = { ...c0, kept: Number.isSafeInteger(c0.kept) ? c0.kept as number : now, passes: (Number.isSafeInteger(c0.passes) ? c0.passes as number : 0) + 1 };
    // b77q owner (1 Nov): warned once and kept (its list may still arrive and prove a stray)
    if (!c.warned && c.passes >= DELIVERY_CHECK_MAX_PASSES && now - c.kept >= DELIVERY_CHECK_MAX_WAIT_MS) { flagDelivery(rec, c, out); keep.push({ ...c, warned: true }); }
    else keep.push(c);
  }
  rec.deliveryChecks = keep;
  if (!keep.length) delete rec.deliveryChecks;
  return true;
}

/** b77q review (GR-1 residual): the flags waiting to be said in the thread — taken out (the caller saves the record) */
export function takeDeliveryGhostNotes(rec: GroupRecord): GroupDeliveryGhost[] {
  const notes = rec.deliveryGhostNotes ?? [];
  delete rec.deliveryGhostNotes;
  return notes;
}

/** b74 (VAR-06): creator — record that `ik` now goes by `name`. A name that differs from the
 *  one held gets the next first-bound sequence (so a rename never inherits an earlier claim);
 *  the same name keeps its sequence. Returns true if anything changed. */
export function noteNameBinding(rec: GroupRecord, ik: string, name: string): boolean {
  if (!name) return false;
  const cur = rec.nameFb && Object.prototype.hasOwnProperty.call(rec.nameFb, ik) ? rec.nameFb[ik] : undefined;
  if (cur && cur[0] === name) return false;
  const seq = (rec.nameSeq ?? 0) + 1;
  rec.nameSeq = seq;
  rec.nameFb = { ...(rec.nameFb ?? {}), [ik]: [name, seq] };
  return true;
}

// ---------- b74 (VAR-05): leaving a group ----------

const LEAVE_SIG_LABEL = 'vardum-group-leave-v1:';

export interface GroupLeavePayload { t: string; ik: string; id: string; e: number; at: number; body: string; sig: string }

/** b74 (VAR-05): a member's signed "I am leaving" — {"__veil_group_leave":1, body, sig},
 *  body = JSON{t, ik, id, e, at}, sig = Ed25519(the leaver's IK, label ‖ body). Sent in
 *  the group stream before the member ends its seat; the creator treats it as a removal. */
export async function buildSignedLeaveText(ikSeedB64: string, groupToken: string, ikPubB64: string, veilId: string, epoch: number): Promise<string> {
  const body = JSON.stringify({ t: groupToken, ik: ikPubB64, id: veilId, e: epoch, at: Date.now() });
  const sig = await ikSign(ikSeedB64, toB64(utf8(LEAVE_SIG_LABEL + body)));
  return JSON.stringify({ __veil_group_leave: 1, body, sig });
}

export function isLeaveControl(text: string): boolean {
  return typeof text === 'string' && text.startsWith('{"__veil_group_leave":');
}

/** b74 (VAR-05): parse a leave strictly. null = not a leave; 'invalid' = leave-shaped but malformed. */
export function parseLeavePayload(text: string): GroupLeavePayload | 'invalid' | null {
  if (!isLeaveControl(text)) return null;
  try {
    const t = JSON.parse(text) as Record<string, unknown>;
    if (t.__veil_group_leave !== 1 || typeof t.body !== 'string' || typeof t.sig !== 'string') return 'invalid';
    const b = JSON.parse(t.body) as Record<string, unknown>;
    if (typeof b.t !== 'string' || typeof b.ik !== 'string' || !IK_B64_RE.test(b.ik) || typeof b.id !== 'string' || !b.id
      || !Number.isInteger(b.e) || Number(b.e) < 1 || !Number.isInteger(b.at) || Number(b.at) < 0) return 'invalid';
    return { t: b.t, ik: b.ik, id: b.id, e: Number(b.e), at: Number(b.at), body: t.body, sig: t.sig };
  } catch { return 'invalid'; }
}

/** b74 (VAR-05): true only if the leave names this group and is signed by the key it names,
 *  whose Vardum ID it carries */
export async function verifyLeavePayload(groupToken: string, p: GroupLeavePayload): Promise<boolean> {
  if (p.t !== groupToken) return false;
  try {
    if ((await veilIdFromIkPub(p.ik)) !== p.id) return false;
    return await verifyWithIk(p.ik, toB64(utf8(LEAVE_SIG_LABEL + p.body)), p.sig);
  } catch { return false; }
}

/**
 * Batch C (A1): the senders this device trusts, IK_pub -> veil_id.
 *  creator: itself + admitted, minus the local deny list
 *  member (strict): the creator + the creator-signed list, minus the deny list
 *  member (pre-Batch-C record, no signed list yet): null -> caller falls back to the verified roster
 *  The creator's veil_id is derived from its key, never taken from the relay.
 */
export async function trustedMembers(rec: GroupRecord): Promise<Record<string, string> | null> {
  const denied = new Set(rec.evictedIks ?? []);
  const out: Record<string, string> = {};
  if (rec.role === 'creator') {
    out[rec.ikPubB64] = rec.veilId;
    for (const [ik, vid] of Object.entries(rec.admitted ?? {})) if (!denied.has(ik)) out[ik] = vid;
    return out;
  }
  if (rec.role !== 'member' || rec.memberSeq === undefined) return null;
  if (rec.creatorIkPubB64) out[rec.creatorIkPubB64] = await veilIdFromIkPub(rec.creatorIkPubB64);
  // b75 (audit GR-1): a member whose own signed leave this phone read is no longer trusted here,
  // even while the creator's list (which may not know yet) still names it
  const left = rec.leftIks ?? {};
  for (const [ik, vid] of Object.entries(rec.memberList ?? {})) if (!denied.has(ik) && !Object.prototype.hasOwnProperty.call(left, ik)) out[ik] = vid;
  out[rec.ikPubB64] = rec.veilId;
  return out;
}

/** b77m (audit VAR-10): the hybrid wrap's KDF / AAD label */
export const REKEY_WRAP_LABEL = 'vardum-group-rekey-wrap-v2';

function x25519PubOf(b64: string, what: string): Uint8Array {
  let b: Uint8Array;
  try { b = fromB64(b64); } catch { throw new Error(`Malformed ${what}.`); }
  if (b.length !== 32) throw new Error(`Malformed ${what}.`);
  return b;
}

/** b77m (audit VAR-10): X25519 with the all-zero (low-order) result refused, as the 1:1 ratchet's dh() */
function wrapDh(priv: Uint8Array, pub: Uint8Array): Uint8Array {
  const out = x25519.getSharedSecret(priv, pub);
  if (out.every((x) => x === 0)) throw new Error('Invalid X25519 shared secret.');
  return out;
}

/** b77m (audit VAR-10): the wrap key and AAD — both secrets through the one KDF (the 1:1 protocol's
 *  combine-then-HKDF), bound to the group, the epoch, the recipient, the KEM ciphertext and the ephemeral key */
async function rekeyWrapKey(ssX: Uint8Array, ssPq: Uint8Array, ctx: RekeyWrapContext, to: string, ct: string, xe: string): Promise<{ key: CryptoKey; aad: Uint8Array }> {
  if (typeof ctx?.groupToken !== 'string' || !ctx.groupToken || !Number.isInteger(ctx.epoch) || ctx.epoch < 1) throw new Error('A group key wrap needs its group and epoch.');
  const ikm = concat(ssX, ssPq);
  try {
    const salt = await sha256(utf8(`${REKEY_WRAP_LABEL}:${ctx.groupToken}:${ctx.epoch}`));
    const raw = await hkdf(ikm, salt, `${REKEY_WRAP_LABEL}:${to}`, 32);
    const key = await crypto.subtle.importKey('raw', raw as unknown as BufferSource, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
    raw.fill(0);
    return { key, aad: utf8(JSON.stringify([REKEY_WRAP_LABEL, ctx.groupToken, ctx.epoch, to, ct, xe])) };
  } finally { ikm.fill(0); }
}

/**
 * web's wm(): wrap the new GEK for one member.
 * b77m (audit VAR-10): HYBRID, like the 1:1 handshake — ML-KEM-768 to the member's signed PQ prekey AND X25519
 * between a fresh creator key and the member's identity key (Ed25519 IK in Montgomery form, as X3DH's DH(EK, IK)).
 * The wrap used to be ML-KEM alone, so a break of ML-KEM (or of this pure-JS implementation) let whoever kept the
 * relay's copies of the wraps open every relay-delivered group key; now it also takes the member's identity key.
 * The key is HKDF(X25519 secret || ML-KEM secret, salt = H(label:group:epoch), info = label:recipient) and the
 * AES-GCM AAD binds group, epoch, recipient, ciphertext and ephemeral key.
 * Clean break (b77, as group-2 at b74): a wrap without `xe` is refused by parseRekeyPayload / openRekeyWrap.
 */
export async function buildRekeyWrap(memberPqPubB64: string, toVeilId: string, newGekB64: string, ctx: RekeyWrapContext & { memberIkPubB64: string }): Promise<GroupRekeyWrap> {
  const ikX = edwardsToMontgomeryPub(x25519PubOf(ctx?.memberIkPubB64, 'identity key'));
  const { ct, secret } = await mlkemEncap(memberPqPubB64);
  const ePriv = x25519.utils.randomPrivateKey();
  const xe = toB64(x25519.getPublicKey(ePriv));
  const ssX = wrapDh(ePriv, ikX);
  ePriv.fill(0);
  const { key, aad } = await rekeyWrapKey(ssX, secret, ctx, toVeilId, ct, xe);
  ssX.fill(0); secret.fill(0);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const wk = new Uint8Array(await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: iv as unknown as BufferSource, additionalData: aad as unknown as BufferSource }, key, fromB64(newGekB64) as unknown as BufferSource,
  ));
  return { to: toVeilId, ct, xe, wk: toB64(wk), wi: toB64(iv) };
}

/** web's Tm(): unwrap a new GEK with my PQ private key and my identity key (b77m, audit VAR-10: hybrid only) */
export async function openRekeyWrap(myPqPrivB64: string, wrap: GroupRekeyWrap, ctx: RekeyWrapContext & { ikSeedB64: string; myVeilId?: string }): Promise<string> {
  // b77u (audit 6 IH crypto F-2): the opener binds its OWN ID into the wrap key and AAD (for an honest wrap the
  // same value as its label), never the label alone
  if (ctx?.myVeilId !== undefined && wrap?.to !== ctx.myVeilId) throw new Error('This group key wrap is labelled for someone else — refused.');
  if (!wrap || typeof wrap.xe !== 'string' || !wrap.xe) throw new Error('This group key was wrapped the old way (post-quantum only) — refused.');
  const seed = fromB64(ctx?.ikSeedB64 ?? '');
  if (seed.length !== 32) throw new Error('Group key unwrap: no identity key.');
  const ikXPriv = edwardsToMontgomeryPriv(seed);
  seed.fill(0);
  const ssX = wrapDh(ikXPriv, x25519PubOf(wrap.xe, 'wrap key'));
  ikXPriv.fill(0);
  const secret = await mlkemDecap(myPqPrivB64, wrap.ct);
  const { key, aad } = await rekeyWrapKey(ssX, secret, ctx, ctx?.myVeilId ?? wrap.to, wrap.ct, wrap.xe);
  ssX.fill(0); secret.fill(0);
  const pt = new Uint8Array(await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: fromB64(wrap.wi) as unknown as BufferSource, additionalData: aad as unknown as BufferSource }, key, fromB64(wrap.wk) as unknown as BufferSource,
  ));
  return toB64(pt);
}

/** b54 (Batch A, N-1): domain label for the creator's rekey signature.
 *  b74 (clean break): v3 — a body signed for veil-group-1 (rc optional) never verifies here. */
const REKEY_SIG_LABEL = 'vardum-group-rekey-v3:';

/**
 * b54: build the signed rekey message (creator only). The signed bytes are the
 * exact `body` string carried in the message, so no JSON canonicalisation is
 * needed: sig = Ed25519(creator IK, utf8(label || body)), where body =
 * JSON{t: group token, ge: new epoch, pq: new group PQ pub, wraps}.
 */
export async function buildSignedRekeyText(
  creatorIkSeedB64: string, groupToken: string, ge: number, pq: string, wraps: GroupRekeyWrap[],
  /** b76r1 (audit AUD-G2): rh = the rotation hash every part signs. A one-part rekey (a key delivery, a
   *  rotation of one part) may leave it out: it is then worked out from this part alone. A part of a
   *  rotation of several parts must carry it (buildSignedRekeyParts works it out over all of them). */
  meta: { rid: string; kc: string; pi: number; pc: number; at?: number; nm?: string; rc: string[]; ms: number; mh: string; rh?: string },
): Promise<string> {
  // b70 (re-review 6): "at" = when the creator started this epoch, signed with the
  // rest — a member's epoch-age limits (48 h to send, 96 h to show as verified; b71
  // (audit): this said they ran for a week) run from it, not from when a (possibly stale) copy arrived
  // b71 (review P-01): "nm" = the group's name encrypted under the delivered key, for
  // a joiner (links no longer carry a key that could read the relay's name blob)
  // b73 (audit V-07): "rc" = who the key is meant for (sorted Vardum IDs). b74: required —
  // every wrap must name someone in it (refused here too, so this phone never signs a ghost wrap)
  if (!Array.isArray(meta.rc)) throw new Error('A rekey must name its recipients (rc).');
  const rc = [...new Set(meta.rc)].sort();
  if (wraps.some((w) => !rc.includes(w.to))) throw new Error('A rekey wraps the key to someone outside its recipient list.');
  // b75 (audit GR-5): ms/mh = the member list it was made with (required)
  if (!Number.isInteger(meta.ms) || meta.ms < 0 || typeof meta.mh !== 'string' || !IK_B64_RE.test(meta.mh)) throw new Error('A rekey must name the member list it was made with (ms, mh).');
  // b76r1 (audit AUD-G2): the commitment to the whole rotation
  let rh = meta.rh;
  if (rh === undefined) {
    if (meta.pc !== 1) throw new Error('A part of a rekey sent in several parts must carry its rotation hash (rh).');
    rh = await rotationHash(groupToken, ge, pq, { ...meta, rc }, [await rekeyPartDigest(wraps)]);
  }
  if (typeof rh !== 'string' || !IK_B64_RE.test(rh)) throw new Error('A rekey must carry its rotation hash (rh).');
  const body = rekeyBodyString(groupToken, ge, pq, wraps, { ...meta, rc, rh });
  const sig = await ikSign(creatorIkSeedB64, toB64(utf8(REKEY_SIG_LABEL + body)));
  return JSON.stringify({ __veil_group_rekey: 2, body, sig });
}

/**
 * b76r1 (audit AUD-G2): the signed parts of one rotation — `chunks[i]` are the wraps of part i. Every part
 * carries the same rotation hash rh over all of them (rotationHash). b76 packed one wrap a part for groups
 * up to ~21 members, and a member stopped opening parts once it had its own wrap, so a ghost wrap in the
 * LAST part (with an rc naming the ghost in that part only) went unseen by everyone (the V-07 check only
 * looked at the parts a phone opened). Now a member applies a rotation only once it holds every part, and
 * refuses it unless every part signs the same rh and rh matches all the parts' wraps.
 */
export async function buildSignedRekeyParts(
  creatorIkSeedB64: string, groupToken: string, ge: number, pq: string, chunks: GroupRekeyWrap[][],
  meta: { rid: string; kc: string; at?: number; rc: string[]; ms: number; mh: string },
): Promise<string[]> {
  const parts = chunks.length ? chunks : [[]];
  const rc = [...new Set(meta.rc)].sort();
  const pc = parts.length;
  const rh = await rotationHash(groupToken, ge, pq, { ...meta, rc, pc }, await Promise.all(parts.map((w) => rekeyPartDigest(w))));
  const out: string[] = [];
  for (let i = 0; i < pc; i++) out.push(await buildSignedRekeyText(creatorIkSeedB64, groupToken, ge, pq, parts[i], { ...meta, rc, pi: i, pc, rh }));
  return out;
}

/** b76r1 (audit AUD-G2): digest of one part's wraps — B64(SHA-256(utf8(JSON of [to, ct, wk, wi] per wrap, in order))) */
export async function rekeyPartDigest(wraps: GroupRekeyWrap[]): Promise<string> {
  return toB64(await sha256(utf8(JSON.stringify(wraps.map((w) => [String(w.to), String(w.ct), String(w.xe), String(w.wk), String(w.wi)]))))); // b77m: + xe
}

/** b76r1 (audit AUD-G2): label for the rotation hash */
const ROTATION_HASH_LABEL = 'vardum-group-rotation-v1:';

/**
 * b76r1 (audit AUD-G2): the rotation hash — B64(SHA-256(utf8("vardum-group-rotation-v1:" ‖ JSON{t, ge, pq,
 * rid, kc, pc, at (0 if none), rc (sorted, unique), ms, mh, d}))), d = rekeyPartDigest of every part's
 * wraps, in part order. Signed into every part (rh), so the parts of one rotation all commit to the same
 * recipients and the same wraps.
 */
export async function rotationHash(
  groupToken: string, ge: number, pq: string,
  meta: { rid: string; kc: string; pc: number; at?: number; rc: string[]; ms: number; mh: string },
  digests: string[],
): Promise<string> {
  const rc = [...new Set(meta.rc)].sort();
  return toB64(await sha256(utf8(ROTATION_HASH_LABEL + JSON.stringify({
    t: groupToken, ge, pq, rid: meta.rid, kc: meta.kc, pc: meta.pc, at: meta.at ? Math.floor(meta.at) : 0, rc, ms: meta.ms, mh: meta.mh, d: digests,
  }))));
}

type RekeyMeta = { rid: string; kc: string; pi: number; pc: number; at?: number; nm?: string; rc: string[]; ms: number; mh: string; rh?: string };
function rekeyBodyString(groupToken: string, ge: number, pq: string, wraps: GroupRekeyWrap[], meta: RekeyMeta): string {
  return JSON.stringify({ t: groupToken, ge, pq, rid: meta.rid, kc: meta.kc, pi: meta.pi, pc: meta.pc, ...(meta.at ? { at: Math.floor(meta.at) } : {}), ...(meta.nm ? { nm: meta.nm } : {}), rc: meta.rc, ms: meta.ms, mh: meta.mh, rh: meta.rh, wraps });
}

/** b76 (padding): the padded payload one rekey part would need (frame header, text with an
 *  88-character signature, sender trailer) — measured, not signed. b76r1: with a rotation hash of its
 *  fixed length (44 characters) when the meta has none yet. */
export function rekeyPartNeed(groupToken: string, ge: number, pq: string, wraps: GroupRekeyWrap[], meta: RekeyMeta): number {
  const rc = [...new Set(meta.rc)].sort();
  const body = rekeyBodyString(groupToken, ge, pq, wraps, { ...meta, rc, rh: meta.rh ?? 'A'.repeat(43) + '=' });
  return PAYLOAD_HDR + utf8(JSON.stringify({ __veil_group_rekey: 2, body, sig: 'x'.repeat(88) })).length + TRAILER_BYTES;
}

/** b76r1 (audit AUD-I1): the sizes a key delivery (gate wrap_deliver payload) is padded to — the relay
 *  takes at most 40,000 bytes. b76r2 (audit R2-I4): 16 KiB at least — with 4 KiB as the smallest class a
 *  delivery's class told whether the group had more than 2 members; a 16 KiB delivery holds a full 100-member rc
 *  and the longest name blob, so every delivery is now 16 KiB (a few KB more, once per admission or missed key) */
export const KEY_DELIVERY_CLASSES: readonly number[] = [16384, 32768];

/**
 * b76r1 (audit AUD-I1): pad a key delivery to the smallest of KEY_DELIVERY_CLASSES. A delivery is handed to
 * the relay's gate as clear JSON (only the wrap inside it is encrypted, to the member's prekey), and b76 sent
 * it unpadded, so its exact length — which grows with the recipient set rc and the name blob — was visible.
 * The padding is an unsigned "pad" field of zeros after the signature; parseRekeyPayload ignores it, and the
 * text still starts with '{"__veil_group_rekey":' (the relay checks that). What the relay can still read in
 * a delivery (t, ge, pq, rid, kc, at, rc, ms, mh, the wrap's `to`) is listed in spec §8.3.
 */
export function padKeyDelivery(text: string): string {
  if (!text.endsWith('}')) throw new Error('Not a key delivery.');
  const extra = ',"pad":""'.length;
  const len = utf8(text).length;
  const cls = KEY_DELIVERY_CLASSES.find((c) => c >= len + extra);
  if (!cls) throw new Error('A key delivery does not fit the largest size class.');
  return text.slice(0, -1) + ',"pad":"' + '0'.repeat(cls - len - extra) + '"}';
}

/**
 * b76 (padding, spec §8.2 item 45): how many wraps each rekey part carries. Parts are packed
 * to land in the SMALLEST class they can: if a part with one wrap fits 4 KiB — the class of
 * long posts and of some cover posts — every part carries as many wraps as still fit 4 KiB
 * (in practice one, for groups up to about 20 members); otherwise as many as fit 16 KiB, else
 * 32 KiB (never more than REKEY_WRAPS_PER_PART). b54–b75 always packed 16, so every rotation
 * of a group with more than one member went out in the 16 or 32 KiB class, which posts
 * never use. The price is more, smaller parts (for up to 20 members, one 4 KiB part per member
 * instead of one 32 KiB part: at most 2.5 times the bytes, once a rotation).
 * `measure(k)` is the padded need of a part carrying k wraps (rekeyPartNeed).
 */
export function rekeyWrapsPerPart(wrapCount: number, measure: (k: number) => number): number {
  if (wrapCount <= 0) return 0;
  const most = Math.min(REKEY_WRAPS_PER_PART, wrapCount);
  for (const cls of GROUP_CLASSES) {
    let k = 0;
    while (k < most && measure(k + 1) <= cls) k++;
    if (k > 0) return k;
  }
  throw new Error('A rekey part with one wrap does not fit the largest bucket.');
}

/**
 * Parse decrypted group text. null = not a rekey message at all;
 * 'invalid' = a rekey-shaped message that must be dropped (old unsigned v1
 * format or malformed) — never rendered as text, never applied.
 */
/** b76r2 (audit R2-I1): the fields a signed rekey body may carry (rekeyBodyString writes no others) */
const REKEY_BODY_FIELDS = new Set(['t', 'ge', 'pq', 'rid', 'kc', 'pi', 'pc', 'at', 'nm', 'rc', 'ms', 'mh', 'rh', 'wraps']);
/** b76r2 (audit R2-I1): a wrap entry is exactly {to, ct, wk, wi}, each a non-empty string */
function isExactRekeyWrap(w: unknown): boolean {
  if (!w || typeof w !== 'object' || Array.isArray(w)) return false;
  const keys = Object.keys(w);
  // b77m (audit VAR-10, clean break): exactly {to, ct, xe, wk, wi} — a b76 wrap (no xe: ML-KEM alone) is malformed here
  return keys.length === 5 && ['to', 'ct', 'xe', 'wk', 'wi'].every((k) => typeof (w as Record<string, unknown>)[k] === 'string' && !!(w as Record<string, unknown>)[k]);
}

export function parseRekeyPayload(text: string): GroupRekeyPayload | 'invalid' | null {
  if (typeof text !== 'string' || !text.startsWith('{"__veil_group_rekey":')) return null;
  try {
    const t = JSON.parse(text) as Record<string, unknown>;
    if (t.__veil_group_rekey !== 2 || typeof t.body !== 'string' || typeof t.sig !== 'string') return 'invalid';
    const b = JSON.parse(t.body) as Record<string, unknown>;
    if (typeof b.t !== 'string' || !Number.isInteger(b.ge) || Number(b.ge) < 1 || typeof b.pq !== 'string' || !Array.isArray(b.wraps)) return 'invalid';
    // Batch C (A3): rotation id, key commitment and part i of n are mandatory
    if (typeof b.rid !== 'string' || !/^[0-9a-f]{16,64}$/.test(b.rid) || typeof b.kc !== 'string' || !b.kc
      || !Number.isInteger(b.pi) || !Number.isInteger(b.pc) || Number(b.pc) < 1 || Number(b.pi) < 0 || Number(b.pi) >= Number(b.pc)) return 'invalid';
    // b73 (audit V-07): a recipient set must be well formed. b74 (rc-omission bypass, clean
    // break): and present — a rekey without rc is malformed, never "an older creator"
    if (!Array.isArray(b.rc) || b.rc.length > GROUP_MEMBER_CAP || b.rc.some((x) => typeof x !== 'string' || !x)) return 'invalid';
    // b75 (audit GR-5): the member list it was made with is required
    if (!Number.isInteger(b.ms) || Number(b.ms) < 0 || typeof b.mh !== 'string' || !IK_B64_RE.test(b.mh)) return 'invalid';
    // b76r1 (audit AUD-G2): and the rotation hash
    if (typeof b.rh !== 'string' || !IK_B64_RE.test(b.rh)) return 'invalid';
    // b76r2 (audit R2-I1): the signed body holds exactly the fields this phone reads, and every wrap is exactly
    // {to, ct, wk, wi} (strings). A field nobody reads (a wrap under "x", say) or a wrap entry the old filter
    // dropped (to: an array) was signed, ignored by every member and outside rh and the part digest; now the
    // part is refused, so what the digest and rh cover (rekeyPartDigest over [to, ct, wk, wi] of every wrap) is
    // the whole wraps array as signed, and a present at/nm that isn't well formed is refused too, not skipped.
    if (Object.keys(b).some((k) => !REKEY_BODY_FIELDS.has(k))) return 'invalid';
    if (!(b.wraps as unknown[]).every(isExactRekeyWrap)) return 'invalid';
    if (b.at !== undefined && !(Number.isInteger(b.at) && Number(b.at) > 0)) return 'invalid';
    if (b.nm !== undefined && !(isGroupNameBlob(b.nm) && String(b.nm).length <= 4096)) return 'invalid';
    return {
      t: b.t,
      ge: Number(b.ge),
      pq: b.pq,
      rid: b.rid,
      kc: b.kc,
      pi: Number(b.pi),
      pc: Number(b.pc),
      ...(Number.isInteger(b.at) && Number(b.at) > 0 ? { at: Number(b.at) } : {}),
      ...(isGroupNameBlob(b.nm) && String(b.nm).length <= 4096 ? { nm: String(b.nm) } : {}), // b71 (review P-01); b73 (audit V-22): enc1 or enc2
      rc: [...new Set(b.rc as string[])].sort(), // b73 (audit V-07); b74: required
      ms: Number(b.ms), mh: String(b.mh), // b75 (audit GR-5)
      rh: String(b.rh), // b76r1 (audit AUD-G2)
      wraps: (b.wraps as GroupRekeyWrap[]).filter((w) => w && typeof w.to === 'string' && typeof w.ct === 'string' && typeof w.xe === 'string' && typeof w.wk === 'string' && typeof w.wi === 'string'),
      body: t.body,
      sig: t.sig,
    };
  } catch { return 'invalid'; }
}

/**
 * Apply a rekey to my group record. b54 (Batch A, N-1): accepted ONLY when
 * (1) it is signed by the group creator's IK held in my record, (2) it names
 * this group, and (3) it moves the epoch FORWARD. Anyone else holding the
 * current GEK (a member, a leaked link) can no longer fork or roll back the
 * group's epoch.
 */
export async function applyRekeyPayload(
  store: VeilStorage, groupToken: string, payload: GroupRekeyPayload, myPqPrivB64: string,
  /** b73 (audit V-07): delivered: a key delivery fetched from the gate for this phone alone
   *  (one wrap, to this phone), not a rekey part posted in the group */
  how: {
    delivered?: boolean;
    /** b76r1 (audit AUD-G2): this part is applied as one of a whole rotation (finishRotation has checked that
     *  every part is here, agrees and matches the signed rotation hash); tos = who ALL its wraps are to */
    rotation?: { tos: string[] };
  } = {},
): Promise<boolean> {
  const rec = registry(store).get(groupToken);
  if (!rec) return false;
  if (!rec.creatorIkPubB64) throw new Error('Group creator key unknown on this device — rekey refused.');
  const okSig = await verifyWithIk(rec.creatorIkPubB64, toB64(utf8(REKEY_SIG_LABEL + payload.body)), payload.sig).catch(() => false);
  if (!okSig) throw new Error('Rekey not signed by the group creator — refused.');
  if (payload.t !== groupToken) throw new Error('Rekey names a different group — refused.');
  // b77q review (GR-1 residual): as collectRotationPart — a later epoch's signed rekey (a delivery too) numbered below
  if (settleDeliveryChecksByRekey(rec, payload.ge, payload.ms).length) await saveGroupRecord(store, rec).catch(() => undefined);
  // b76r2 (audit R2-G1): an epoch refused on this phone is never applied, by any path (a rotation part, a one-part
  // rekey; a gate delivery is refused in checkRekeyRecipients); applyRekeyPayload used to check it only for deliveries
  if (!how.delivered && rec.rekeyRefusedEpoch !== undefined && payload.ge === rec.rekeyRefusedEpoch) {
    throw new GroupRekeyRecipientsError('This epoch’s group key was already refused on this phone — refused.', [], 'already');
  }
  // b76r1 (audit AUD-G2): a one-part rekey (a key delivery, a one-part rotation) is checked against its rotation
  // hash here; a part of a rotation of several parts only as a whole, once every part is here (finishRotation)
  if (!how.rotation) {
    if (payload.pc !== 1) throw new Error('A part of a rekey sent in several parts is applied only with all its parts — refused.');
    if (payload.rh !== await rotationHash(groupToken, payload.ge, payload.pq, payload, [await rekeyPartDigest(payload.wraps)])) {
      throw new Error('Rekey does not match its signed rotation hash — refused.');
    }
  }
  await checkRekeyRecipients(store, rec, payload, !!how.delivered, how.rotation?.tos);
  // b71 (review P-01): a joiner waiting for its key takes the creator's key delivery
  // for whatever epoch it names (its own epoch is only the relay's word so far). The
  // signature, the wrap to this phone's prekey and the key commitment are checked as
  // for any rekey.
  const keyless = rec.role === 'member' && !rec.gekB64;
  if (keyless) {
    // b77t (audit 5 M-C / IH C-1): "whatever epoch it names" let a hostile relay replay a member's OLD delivery
    // after it lost its record and re-joined (reinstall, "forget group"): the phone went back to an epoch a member
    // removed since holds, and its posts were readable by them. The floor kept outside the record says what this
    // phone held before: an epoch below it (or below a creator-signed later one) is refused, and one at or below the
    // highest it held is taken only from the creator's answer to THIS membership's own key request (rid bound to the
    // request's nonce). An admission always rotates past every epoch in use, so a fresh member's first key is above.
    // Refused quietly (false): the caller then files a new request.
    const floor = await groupEpochFloor(store, groupToken);
    if (payload.ge < Math.max(floor.e, floor.s)) {
      console.warn('[veil-group] key delivery for an epoch older than this phone already had — refused', { groupToken: groupToken.slice(0, 6), epoch: payload.ge, floor: floor.e });
      return false;
    }
    if (payload.ge <= floor.e) {
      const nonces = (rec.wrapReqNonces ?? []).map(([n]) => n);
      let bound = false;
      if (how.delivered) for (const n of nonces) if (await deliveryBindRid(groupToken, payload.ge, n) === payload.rid) { bound = true; break; }
      if (!bound) {
        console.warn('[veil-group] key delivery for an epoch this phone held before, not made for this membership — refused', { groupToken: groupToken.slice(0, 6), epoch: payload.ge });
        return false;
      }
    }
    const w = (payload.wraps || []).find((x) => x && x.to === rec.veilId);
    if (!w) return false;
    const wctx = { groupToken, epoch: payload.ge, ikSeedB64: rec.ikSeedB64, myVeilId: rec.veilId }; // b77m (audit VAR-10); b77u (F-2): + my ID
    const gek = await openRekeyWrap(myPqPrivB64, w, wctx).catch(async (e) => {
      let prev = '';
      try { prev = String((await readPrevPrekeys(store))?.pqPrivB64 ?? ''); } catch { prev = ''; }
      if (!prev || prev === myPqPrivB64) throw e;
      return openRekeyWrap(prev, w, wctx);
    });
    if (payload.kc !== await gekCommitment(groupToken, payload.ge, gek)) throw new Error('Rekey key does not match its signed commitment — refused.');
    await advanceEpoch(store, groupToken, payload.ge, gek, String(payload.pq || rec.pqPubB64), payload.at ? Math.min(payload.at, Date.now()) : undefined, payload.rc);
    delete rec.wrapReqNonces; // b77t (audit 5 M-C): the key is here (saved with the next save)
    // b76r1 (audit AUD-G4): the creator's signed name replaces a name read from a relay row (nameFromRow)
    if ((!rec.name || rec.nameFromRow) && payload.nm) {
      const name = await decryptGroupText(gek, payload.nm).catch(() => '');
      if (name) { rec.name = name; delete rec.nameFromRow; await saveGroupRecord(store, rec); }
    }
    return true;
  }
  // a later part of the rekey we already applied: nothing to do (never re-key
  // within an epoch); anything OLDER is a rollback attempt
  if (payload.ge === rec.epoch) {
    // Batch C (A3): same epoch — it must be the SAME key, or the group has split.
    // b77q (audit 3 GR-2): that used to be only logged. A creator-signed key change for this epoch that commits to
    // another key, or gives it to someone the applied one didn't, is now refused out loud and stops sends under
    // the key (equivocation)
    const why = await appliedEpochContradiction(groupToken, rec, payload, how.delivered ? 'delivery' : 'rotation');
    if (why) await flagAppliedEpoch(store, rec, why);
    return false;
  }
  if (payload.ge < rec.epoch) throw new Error('Rekey does not move the epoch forward — refused.');
  const wrap = (payload.wraps || []).find((w) => w && w.to === rec.veilId);
  if (!wrap) return false;
  // b70 (audit L-2): a wrap made to the previous PQ prekey just before a prekey rotation
  // opens with the kept previous key (b73 (audit V-03): prekeys rotate weekly, monthly on
  // Android security-chip phones, and the previous set is kept 2 days — see restore.ts)
  let newGekB64: string;
  const wctx = { groupToken, epoch: payload.ge, ikSeedB64: rec.ikSeedB64, myVeilId: rec.veilId }; // b77m (audit VAR-10); b77u (F-2): + my ID
  try {
    try {
      newGekB64 = await openRekeyWrap(myPqPrivB64, wrap, wctx);
    } catch (e) {
      let prev = '';
      try { prev = String((await readPrevPrekeys(store))?.pqPrivB64 ?? ''); } catch { prev = ''; } // b70 (re-review 7): within its window only
      if (!prev || prev === myPqPrivB64) throw e;
      newGekB64 = await openRekeyWrap(prev, wrap, wctx);
    }
  } catch (e) {
    // b77u (audit 6 IH crypto F-2): the wrap labelled with this phone's ID doesn't open with its keys — made to an
    // older key of this phone, or to someone else's (a ghost given this member's place). Said in the thread.
    throw new GroupOwnWrapError(payload.ge, String((e as Error)?.message ?? e));
  }
  if (payload.kc !== await gekCommitment(groupToken, payload.ge, newGekB64)) {
    throw new Error('Rekey key does not match its signed commitment — refused.');
  }
  // b70 (re-review 6): the epoch's age is the creator's signed start time (never later
  // than now); a stale copy still opens old messages, but its send window has passed
  const startedAt = payload.at ? Math.min(payload.at, Date.now()) : undefined;
  return advanceEpoch(store, groupToken, payload.ge, newGekB64, String(payload.pq || rec.pqPubB64), startedAt, payload.rc, how.delivered ? undefined : payload.rid);
}

/**
 * b73 (audit V-07): who a rekey gives the key to. Before, only this phone's own wrap was
 * looked at, so a creator-signed rekey with an extra wrap to someone not on the member
 * list (a "ghost") was applied, nobody was told, and every fingerprint still matched.
 *  - Every wrap must be to someone in the rekey's own signed recipient set rc. b74: every
 *    rekey carries rc (parseRekeyPayload refuses one without it).
 *  - A part posted in the group: rc and every wrap
 *    must name only people on this phone's creator-signed member list (or the creator, or
 *    this phone). Refused otherwise, and the epoch is remembered (rekeyRefusedEpoch): a
 *    gate delivery of that same epoch's key is refused too, so the phone stays on its
 *    old key (sends pause after 48 h, as for any missed rotation) until the next key
 *    change. A b73 creator publishes a list naming any newcomer BEFORE the rotation
 *    (rotateOnce), so an honest admission never trips this.
 *  - b74 (rc-omission bypass, FEEDBACK-RESPONSE §3): there is no "older creator" path any
 *    more. b73 only logged an unlisted wrap in a rekey WITHOUT rc and applied it — and the
 *    creator device (the V-07 attacker) chooses whether rc is there, so a ghost wrap just
 *    left rc out. With the clean break to veil-group-2 every rekey must carry rc, and an
 *    unlisted wrap or rc entry is always refused.
 *  - A gate delivery (how.delivered) carries one wrap, to this phone; rc is not checked
 *    against the list (a joiner receives its first key before any list), but it is kept
 *    and goes into the epoch fingerprint, so a different rc shows as a different
 *    fingerprint.
 *  - A member record from before Batch C (no signed list yet) can't check against a list.
 *  - Someone the signed list's removal notice (rm) excludes only from a LATER epoch than the
 *    rekey's is allowed: a rotation already partly sent when a removal began is finished
 *    (it may be out already) and rotated past (evictGroupMember / rotateGroup).
 *  - b75 (audit GR-1): a member whose own signed leave this phone read (leftIks) is not on the
 *    allowed list. A rekey whose creator-signed start `at` is before the moment this phone learnt
 *    of the leave may still name them (the creator's phone may not have seen it yet); one made
 *    after that is refused, and the error names them (GroupRekeyRecipientsError.leavers) so the
 *    thread can say what contradicts what. (A relay that shows the leave to members and hides it
 *    from the creator used to leave the leaver with every new key while members believed it gone.)
 *  - b76r1 (audit AUD-G2): a rotation in several parts is checked as a WHOLE. b76 packs one wrap a part
 *    for groups up to ~21 members, and up to b76 a member applied the part carrying its own wrap at once;
 *    the parts after it were sent under the key it had just replaced and never opened, so a ghost wrap in
 *    the last part (with an rc naming the ghost in that part only) passed every member. Now a member keeps
 *    the old key until it holds every part of the rotation (collectRotationPart / finishRotation): every
 *    part must sign the same fields, rc and rotation hash rh, and rh must match the digests of all the
 *    parts' wraps; then every wrap of every part (tos) is checked here. (This text used to say only "a
 *    rotation of more than 16 members" had several parts.)
 */
async function checkRekeyRecipients(store: VeilStorage, rec: GroupRecord, payload: Pick<GroupRekeyPayload, 'wraps' | 'rc' | 'ge' | 'at' | 'ms' | 'mh'>, delivered: boolean, tosOverride?: string[]): Promise<void> {
  const tos = tosOverride ?? (payload.wraps ?? []).map((w) => w.to);
  let why = '';
  let leavers: string[] = [];
  // b74: rc is required (a payload without it never gets here; checked again, fail closed)
  if (!Array.isArray(payload.rc)) throw new GroupRekeyRecipientsError('This rekey does not name its recipients — refused.');
  const rcSet = new Set(payload.rc);
  if (tos.some((t) => !rcSet.has(t))) why = 'This rekey gives the group key to someone outside its own signed recipient list — refused.';
  // b77u (audit 6 IH crypto F-2): a wrap's `to` is only a label — nobody but the member it names can tell which
  // keys it was made to. A second wrap labelled with a member (made to a ghost's keys) passed every check, and the
  // member opened the first one. One wrap per recipient: two for one name are refused by every member.
  const dup = new Set(tos).size !== tos.length;
  if (!why && dup) why = 'This rekey carries two copies of the new group key for one member — refused.';
  if (delivered) {
    if (why) throw new GroupRekeyRecipientsError(why, [], dup ? 'duplicate' : undefined);
    if (tos.some((t) => t !== rec.veilId)) throw new GroupRekeyRecipientsError('A key delivery for this phone carries keys for others — refused.');
    if (rec.rekeyRefusedEpoch !== undefined && payload.ge === rec.rekeyRefusedEpoch) {
      throw new GroupRekeyRecipientsError('This epoch’s group key was also given to someone not on the member list — refused.');
    }
    // b77m (audit VAR-36): a member that already holds the creator-signed list checks a delivery's signed
    // recipient set (rc) against it too, as it does a rotation posted in the group. Only "to me and inside
    // rc" was checked, so a creator's phone (with the relay) could give the key to a ghost through the gate,
    // after the 10-minute part timeout, without any member seeing the "not on the member list" notice. Not
    // checked (nothing to check against): a joiner's first key (no key, no list yet), and a delivery made with a
    // NEWER list than this phone holds — that list is posted under the very key being delivered, so waiting for
    // it would leave a member that missed a rotation locked out for good.
    // b77m review (L2): that newer list is checked when it arrives. The delivery's signed rc, ms and mh are kept
    // (deliveryChecks) and applyMembersPayload checks rc against the list numbered ms (or a later one) — a
    // stray is then flagged (the notice, ghostKeyEpoch: sends stop under that key). Skipping it for good let a
    // creator's phone sign a higher ms to bypass this check.
    if (rec.role === 'member' && rec.memberSeq !== undefined && rec.gekB64 && payload.ms > rec.memberSeq) {
      const keep = (rec.deliveryChecks ?? []).filter((c) => !(c.ge === payload.ge && c.ms === payload.ms));
      keep.push({ ge: payload.ge, ms: payload.ms, mh: payload.mh, rc: [...payload.rc], ...(payload.at !== undefined ? { at: payload.at } : {}), kept: Date.now(), passes: 0 });
      rec.deliveryChecks = keep.slice(-8);
      await saveGroupRecord(store, rec).catch(() => undefined);
      return;
    }
    if (rec.role !== 'member' || rec.memberSeq === undefined || !rec.gekB64) return;
  }
  if (rec.role !== 'member') return;
  if (!why) {
    const trusted = await trustedMembers(rec);
    if (!trusted) return;
    const allowed = new Set(Object.values(trusted));
    // a member the signed list says is removed only from a LATER epoch may still be in this one
    for (const [vid, firstWithout] of rec.listRemovals ?? []) if (firstWithout > payload.ge) allowed.add(vid);
    // b75 (audit GR-1): a leaver may still be in a rekey made before this phone learnt of the leave
    // b77q review (GR-6): or in one for the epoch this phone read the leave in (or earlier)
    const leftAt = new Map<string, number>();
    for (const l of Object.values(rec.leftIks ?? {})) if (l && typeof l.vid === 'string') leftAt.set(l.vid, Number(l.at));
    for (const vid of leaversStillKeyed(rec, payload.ge, payload.at)) allowed.add(vid);
    // b75 (audit GR-5): the same list number with other entries is the creator contradicting itself
    if (payload.ms === (rec.memberSeq ?? 0) && rec.memberListHash && payload.mh !== rec.memberListHash) {
      why = 'This rekey was made with a different member list under the same number — refused.';
    }
    const stray = why ? [] : [...new Set([...tos, ...payload.rc])].filter((t) => !allowed.has(t));
    if (!why && !stray.length) return;
    // b75 (audit GR-5): someone not on this phone's list, but the rekey was made with a NEWER list than this
    // phone holds: that list (which may name them) hasn't arrived — the relay may be holding it back. Not
    // the creator's fault and not refused: the caller keeps the part for when the list arrives, stops
    // sending on the old key, and asks for the new one through the gate. (b73/b74 refused it and told the
    // member the creator had given the key to a stranger.)
    if (!why && payload.ms > (rec.memberSeq ?? 0)) throw new GroupRekeyListMissingError(payload.ms);
    leavers = stray.filter((v) => leftAt.has(v));
    if (!why) {
      why = leavers.length
        ? 'The group creator’s phone gave the new group key to someone who said they are leaving — refused.'
        : "The group creator’s phone gave the new group key to someone who isn’t on the member list — refused.";
    }
  }
  if (payload.ge > rec.epoch && (rec.rekeyRefusedEpoch ?? 0) < payload.ge) {
    rec.rekeyRefusedEpoch = payload.ge;
    await saveGroupRecord(store, rec).catch(() => undefined);
  }
  // b77q (audit 3 GR-2): a key change for the epoch this phone already holds (a gate delivery) that gives the key to
  // someone not on the list: refusing it changed nothing — this phone kept sending under a key the stray may hold.
  // Sends under it now stop (ghostKeyEpoch) until the next key change
  if (payload.ge === rec.epoch && rec.gekB64) {
    if ((rec.ghostKeyEpoch ?? 0) <= rec.epoch) rec.ghostKeyEpoch = rec.epoch;
    await saveGroupRecord(store, rec).catch(() => undefined);
    throw new GroupRekeyRecipientsError(why, leavers, 'equivocation');
  }
  throw new GroupRekeyRecipientsError(why, leavers, dup ? 'duplicate' : undefined);
}

/** b76r1 (audit AUD-G2/G3): what collectRotationPart did with a part */
export type RotationPartResult =
  /** the rotation's epoch is already this phone's (or older): nothing to do */
  | { state: 'stale' }
  /** kept; saved = the record (with the part) is on disk */
  | { state: 'waiting' | 'complete'; rid: string; ge: number; saved: boolean };

/** b76r1 (audit AUD-G2): the parts of one rotation contradict each other — refused like a ghost wrap (the
 *  epoch is remembered, so a gate delivery of it is refused too), and the rotation is dropped */
async function refuseRotation(store: VeilStorage, rec: GroupRecord, rid: string, ge: number, why: string): Promise<never> {
  rec.heldRotations = (rec.heldRotations ?? []).filter((h) => h.rid !== rid);
  if (!rec.heldRotations.length) delete rec.heldRotations;
  if (ge > rec.epoch && (rec.rekeyRefusedEpoch ?? 0) < ge) rec.rekeyRefusedEpoch = ge;
  await saveGroupRecord(store, rec).catch(() => undefined);
  throw new GroupRekeyRecipientsError(why, [], 'mismatch');
}

/** b76r2 (audit R2-G1): two rotations (rotation ids) for one epoch — the epoch is refused (remembered, so a gate
 *  delivery of it is refused too) and EVERY kept rotation of it is dropped, whichever came first */
async function refuseRotationEpoch(store: VeilStorage, rec: GroupRecord, ge: number, why: string): Promise<never> {
  rec.heldRotations = (rec.heldRotations ?? []).filter((h) => h.ge !== ge);
  if (!rec.heldRotations.length) delete rec.heldRotations;
  if (ge > rec.epoch && (rec.rekeyRefusedEpoch ?? 0) < ge) rec.rekeyRefusedEpoch = ge;
  await saveGroupRecord(store, rec).catch(() => undefined);
  throw new GroupRekeyRecipientsError(why, [], 'conflict');
}

/** b76r2 (audit R2-G1): member — refuse an epoch for which this pass saw parts of more than one rotation id (the
 *  poll checks this before it applies a round's rotations; collectRotationPart catches the case while both are
 *  kept, this one also when one of them was not kept). Throws GroupRekeyRecipientsError (kind 'conflict'). */
export async function refuseConflictingRotations(store: VeilStorage, groupToken: string, ge: number): Promise<never> {
  const rec = registry(store).get(groupToken);
  if (!rec) throw new Error('Group keys are not established on this device.');
  return refuseRotationEpoch(store, rec, ge, 'Two different key changes for the same epoch — refused.');
}

/** b76r1 (audit AUD-G3): drop rotations already reached, then keep at most HELD_ROTATIONS_MAX (newest
 *  epoch first) within HELD_ROTATIONS_MAX_BYTES — never dropping the one just added to (`keep`) */
function boundHeldRotations(rec: GroupRecord, keep?: string): void {
  const list = (rec.heldRotations ?? []).filter((h) => h.ge > rec.epoch);
  list.sort((a, b) => (b.ge - a.ge) || (b.first - a.first));
  const tooBig = () => list.length > HELD_ROTATIONS_MAX || (list.length > 1 && utf8(JSON.stringify(list)).length > HELD_ROTATIONS_MAX_BYTES);
  while (tooBig()) {
    let at = list.length - 1;
    while (at >= 0 && list[at].rid === keep) at--;
    if (at < 0) break;
    list.splice(at, 1);
  }
  if (list.length) rec.heldRotations = list; else delete rec.heldRotations;
}

/**
 * b77q (audit 3 GR-2): member — does a creator-signed key change for the epoch this phone already applied contradict
 * the applied one? Returns why, or '' when it agrees. Compared: the key (kc against the held key); for a posted
 * rotation, its rotation id when the epoch was applied from a posted rotation (epochRid; a gate delivery has its
 * own rid, so a phone that took the epoch by delivery can't compare rids) and its recipient set, which must be the
 * applied one (same rid) or within it (the applied epoch came by delivery: rc = the rotation's rc plus this
 * phone); for a gate delivery, its recipient set within the applied one plus this phone (deliverGroupKey adds the
 * recipient to the epoch's rc).
 */
async function appliedEpochContradiction(groupToken: string, rec: GroupRecord, payload: Pick<GroupRekeyPayload, 'kc' | 'rid' | 'rc'>, how: 'rotation' | 'delivery'): Promise<string> {
  if (!rec.gekB64 || rec.role !== 'member') return '';
  if (payload.kc !== await gekCommitment(groupToken, rec.epoch, rec.gekB64)) return 'A key change for this step commits to a different key than the one this phone took — refused.';
  const applied = new Set(rec.epochRecipients ?? []);
  const rc = Array.isArray(payload.rc) ? payload.rc : [];
  if (how === 'rotation' && rec.epochRid) {
    if (payload.rid !== rec.epochRid) return 'A second key change for a step this phone already took — refused.';
    if (JSON.stringify([...rc].sort()) !== JSON.stringify([...applied].sort())) return 'A key change for this step names other recipients than the one this phone took — refused.';
    return '';
  }
  if (how === 'delivery') applied.add(rec.veilId);
  if (rc.some((v) => !applied.has(v))) return 'A key change for this step gives the key to someone the one this phone took did not — refused.';
  return '';
}

/** b77q (audit 3 GR-2): the creator's phone contradicted the applied epoch — sends under its key stop
 *  (ghostKeyEpoch: groupKeyFreshness.ghost) until the next key change, and the caller says so */
async function flagAppliedEpoch(store: VeilStorage, rec: GroupRecord, why: string): Promise<never> {
  console.error('[veil-group] creator equivocation about the current epoch', { groupToken: rec.groupToken.slice(0, 6), epoch: rec.epoch, why });
  if ((rec.ghostKeyEpoch ?? 0) <= rec.epoch) rec.ghostKeyEpoch = rec.epoch;
  await saveGroupRecord(store, rec).catch(() => undefined);
  throw new GroupRekeyRecipientsError(why, [], 'equivocation');
}

/**
 * b76r1 (audit AUD-G2/G3): member — keep one creator-signed part of a rotation to a later epoch. The part's
 * signature and group are checked here; it must agree with the parts of the same rotation (rid) already
 * kept on every signed field (ge, pc, rh, pq, kc, at, rc, ms, mh), and a part number seen before must carry
 * the same wraps — otherwise the rotation is refused (GroupRekeyRecipientsError, kind 'mismatch'). Kept per
 * part: its number, the digest of its wraps and who they are to; the whole text only of the part carrying
 * this phone's wrap. 'complete' = every part (0..pc-1) is here: finishRotation checks and applies it.
 */
export async function collectRotationPart(store: VeilStorage, groupToken: string, payload: GroupRekeyPayload, text: string): Promise<RotationPartResult> {
  const rec = registry(store).get(groupToken);
  if (!rec) throw new Error('Group keys are not established on this device.');
  if (!rec.creatorIkPubB64) throw new Error('Group creator key unknown on this device — rekey refused.');
  if (!(await verifyWithIk(rec.creatorIkPubB64, toB64(utf8(REKEY_SIG_LABEL + payload.body)), payload.sig).catch(() => false))) throw new Error('Rekey not signed by the group creator — refused.');
  if (payload.t !== groupToken) throw new Error('Rekey names a different group — refused.');
  // b77q review (GR-1 residual): a creator-signed rotation for a later epoch settles a kept delivery it proves inflated
  if (settleDeliveryChecksByRekey(rec, payload.ge, payload.ms).length) await saveGroupRecord(store, rec).catch(() => undefined);
  // b77q (audit 3 GR-2): a part for the epoch this phone already applied is compared with it first (it was 'stale'
  // unread, so a second rotation of that epoch — naming a ghost, say — posted a pass later left no trace)
  if (payload.ge === rec.epoch && rec.gekB64) {
    const why = await appliedEpochContradiction(groupToken, rec, payload, 'rotation');
    if (why) await flagAppliedEpoch(store, rec, why);
    return { state: 'stale' };
  }
  if (payload.ge <= rec.epoch) return { state: 'stale' };
  if (rec.rekeyRefusedEpoch === payload.ge) throw new GroupRekeyRecipientsError('This epoch’s group key was already refused on this phone — refused.', [], 'already');
  const digest = await rekeyPartDigest(payload.wraps);
  const tos = payload.wraps.map((w) => w.to);
  const list = [...(rec.heldRotations ?? [])];
  let h = list.find((x) => x.rid === payload.rid);
  // b76r2 (audit R2-G1): a SECOND rotation id for an epoch this phone already holds a rotation of refuses that
  // epoch. Only parts within one rid used to be compared, so a self-consistent second rotation (its own rh) for
  // the same epoch, wrapping the same new key to a ghost, was either applied silently (posted after the honest
  // one) or refused while the honest one of the same epoch — the same key the ghost holds — was applied anyway.
  // An honest creator never signs two rotations for one epoch (a rotation is saved before its first part is
  // tried and every retry resends the same parts, rotateOnce), so two rids for one epoch are the creator's phone
  // contradicting itself about who gets that epoch's key.
  if (!h && list.some((x) => x.ge === payload.ge)) {
    return refuseRotationEpoch(store, rec, payload.ge, 'Two different key changes for the same epoch — refused.');
  }
  if (h) {
    const same = h.ge === payload.ge && h.pc === payload.pc && h.rh === payload.rh && h.pq === payload.pq && h.kc === payload.kc
      && (h.at ?? 0) === (payload.at ?? 0) && h.ms === payload.ms && h.mh === payload.mh && JSON.stringify(h.rc) === JSON.stringify(payload.rc);
    if (!same) return refuseRotation(store, rec, payload.rid, Math.max(h.ge, payload.ge), 'The parts of this rekey don’t agree on the new key or who gets it — refused.');
    const prev = h.parts.find((p) => p[0] === payload.pi);
    if (prev && prev[1] !== digest) return refuseRotation(store, rec, payload.rid, h.ge, 'Two copies of one part of this rekey carry different keys — refused.');
    if (prev) return { state: h.parts.length === h.pc ? 'complete' : 'waiting', rid: h.rid, ge: h.ge, saved: true }; // a copy seen before
  } else {
    h = { rid: payload.rid, ge: payload.ge, pc: payload.pc, rh: payload.rh, pq: payload.pq, kc: payload.kc, ...(payload.at ? { at: payload.at } : {}), rc: [...payload.rc], ms: payload.ms, mh: payload.mh, parts: [], first: Date.now() };
    list.push(h);
  }
  h.parts = [...h.parts, [payload.pi, digest, tos] as [number, string, string[]]].sort((a, b) => a[0] - b[0]);
  if (tos.includes(rec.veilId)) h.own = text;
  rec.heldRotations = list;
  boundHeldRotations(rec, h.rid);
  const saved = await saveGroupRecord(store, rec).then(() => true, () => false);
  return { state: h.parts.length === h.pc ? 'complete' : 'waiting', rid: h.rid, ge: h.ge, saved };
}

/**
 * b76r1 (audit AUD-G2): member — check and apply a rotation whose every part is here. rh is worked out
 * again from the kept fields and the digests of parts 0..pc-1 and must be the rh every part signed; then
 * every wrap of every part is checked against rc and this phone's member list (checkRekeyRecipients), and
 * this phone's own wrap, if any, is opened. true = applied. Throws GroupRekeyListMissingError (the
 * rotation stays kept until that list arrives) or GroupRekeyRecipientsError (refused, dropped). false with
 * no throw = no wrap for this phone (it asks through the gate) or nothing to do.
 */
export async function finishRotation(store: VeilStorage, groupToken: string, rid: string, myPqPrivB64: string): Promise<boolean> {
  const rec = registry(store).get(groupToken);
  if (!rec) return false;
  const h = (rec.heldRotations ?? []).find((x) => x.rid === rid);
  if (!h) return false;
  const drop = async () => {
    const live = registry(store).get(groupToken) ?? rec;
    live.heldRotations = (live.heldRotations ?? []).filter((x) => x.rid !== rid);
    if (!live.heldRotations.length) delete live.heldRotations;
    await saveGroupRecord(store, live).catch(() => undefined);
  };
  if (h.ge <= rec.epoch) { await drop(); return false; }
  // b76r2 (audit R2-G1): an epoch refused on this phone (another rotation of it contradicted this one, say) is
  // never applied — finishRotation used to ignore rekeyRefusedEpoch
  if (rec.rekeyRefusedEpoch === h.ge) { await drop(); throw new GroupRekeyRecipientsError('This epoch’s group key was already refused on this phone — refused.', [], 'already'); }
  if (h.parts.length !== h.pc || h.parts.some((p, i) => p[0] !== i)) return false; // not complete yet
  const rh = await rotationHash(groupToken, h.ge, h.pq, h, h.parts.map((p) => p[1]));
  if (rh !== h.rh) return refuseRotation(store, rec, rid, h.ge, 'This rekey’s parts don’t match the rotation they sign — refused.');
  const tos = h.parts.flatMap((p) => p[2]);
  let applied = false;
  try {
    const own = h.own ? parseRekeyPayload(h.own) : null;
    if (own && own !== 'invalid' && own.rid === rid && own.rh === h.rh) {
      applied = await applyRekeyPayload(store, groupToken, own, myPqPrivB64, { rotation: { tos } });
    } else {
      await checkRekeyRecipients(store, rec, { wraps: [], rc: h.rc, ge: h.ge, ...(h.at ? { at: h.at } : {}), ms: h.ms, mh: h.mh }, false, tos);
    }
  } catch (e) {
    if (!(e instanceof GroupRekeyListMissingError)) await drop();
    throw e;
  }
  await drop();
  return applied;
}

const verifiedAttestations = new Set<string>();

/**
 * b54 (Batch A, H-3): keep only roster rows whose attestation verifies:
 * veil_id = f(IK_pub), Ed25519(IK, 'vardum-group-attest-v2:' ‖ {group_token, veil_id, IK_pub, joined_epoch})
 * checks out, a 'creator' row carries the creator IK this device holds, and
 * the IK is not on this device's local deny list. Never trusts the relay's
 * word for who is in the group.
 */
export async function verifiedRosterRows<T extends { veil_id?: unknown; IK_pub?: unknown; joined_epoch?: unknown; attestation_sig?: unknown; role?: unknown }>(
  rec: Pick<GroupRecord, 'groupToken' | 'creatorIkPubB64' | 'evictedIks'>, rows: T[],
): Promise<T[]> {
  const out: T[] = [];
  const denied = new Set(rec.evictedIks ?? []);
  // verified attestations are immutable facts: check each one once per process
  // (a 100-member group polled every few seconds must not re-verify 100 sigs)
  for (const m of rows) {
    const veilId = String(m.veil_id ?? '');
    const ik = String(m.IK_pub ?? '');
    const sig = String(m.attestation_sig ?? '');
    const joinedEpoch = Number(m.joined_epoch ?? NaN);
    if (!veilId || !ik || !sig || !Number.isInteger(joinedEpoch)) continue;
    if (denied.has(ik)) continue;
    if (String(m.role ?? '') === 'creator' && ik !== rec.creatorIkPubB64) continue;
    const cacheKey = `${rec.groupToken}|${veilId}|${ik}|${joinedEpoch}|${sig}`;
    if (!verifiedAttestations.has(cacheKey)) {
      try {
        if ((await veilIdFromIkPub(ik)) !== veilId) continue;
        if (!(await verifyWithIk(ik, attestMessage(rec.groupToken, veilId, ik, joinedEpoch), sig))) continue; // b75 (audit GR-8): labelled
      } catch { continue; }
      verifiedAttestations.add(cacheKey);
    }
    out.push(m);
  }
  return out;
}

/** web's Dm(): move to a new epoch (sendN/recv reset, new sender tag) */
export async function advanceEpoch(
  store: VeilStorage, groupToken: string, epoch: number, gekB64: string, pqPubB64: string, startedAtMs: number | undefined,
  /** b73 (audit V-07): the epoch's signed recipient set (the rekey's rc). b74: required */
  recipients: string[],
  /** b77q (audit 3 GR-2): the rotation id, when a posted rotation is applied (rec.epochRid) */
  rid?: string,
): Promise<boolean> {
  const rec = registry(store).get(groupToken);
  if (!rec) throw new Error('Group keys are not established on this device.');
  if (!Array.isArray(recipients)) throw new Error('A new group epoch must name its recipients.');
  // b77t (audit 5 M-C / IH C-1): the epoch never goes back — below the one whose key this record holds, or below
  // the highest this phone ever held (the floor, kept outside the record). It used to be set unconditionally. A
  // keyless record's epoch is only the relay's word, so only the floor binds it.
  if (rec.gekB64 && epoch < rec.epoch) throw new Error('A group key change can only move the epoch forward — refused.');
  if (epoch < (await groupEpochFloor(store, groupToken)).e) throw new Error('This phone already held a later group key — refused.');
  rec.epoch = epoch;
  rec.gekB64 = gekB64;
  rec.pqPubB64 = pqPubB64;
  rec.epochRecipients = [...recipients].sort(); // b73 (audit V-07); b74: always set
  if (rid) rec.epochRid = rid; else delete rec.epochRid; // b77q (audit 3 GR-2)
  forgetTagKeys(groupToken, epoch); // b77q (audit 3 GR-3): older epochs' tag keys
  rec.seenEpoch = undefined; // b70 (re-review P5): the new key is here
  rec.seenEpochAt = undefined;
  if ((rec.signedAheadEpoch ?? 0) <= epoch) rec.signedAheadEpoch = undefined; // b75 (audit GR-2)
  rec.legacyTagEpoch = undefined; // b71 (audit F-13): each epoch tries the keyed tag again
  rec.myTag = await ownSenderTag(rec);
  if ((rec.removalPendingEpoch ?? 0) <= epoch) rec.removalPendingEpoch = undefined; // b71 (audit F-04)
  rec.sendN = 0;
  // b77u (audit 6 R4 #14): the chain windows start again, but each signer's seen posts carry over (sequence
  // numbers run across epochs, so a post from the last epoch re-sent under this one is still a copy)
  const carried: Record<string, GroupRecvState> = {};
  for (const [k, s] of Object.entries(rec.recv ?? {})) {
    if (k.startsWith('ik:') && s && Array.isArray(s.posts) && s.posts.length) carried[k] = { last: -1, skipped: [], posts: s.posts.slice(-GROUP_POSTS_SEEN) };
  }
  rec.recv = carried;
  rec.envCount = 0;
  rec.epochStartedAt = new Date(startedAtMs ?? Date.now()).toISOString();
  await saveGroupRecord(store, rec);
  await persistSendState(store, rec).catch(() => undefined); // Batch H: an old-epoch counter is ignored anyway
  await persistRecvState(store, rec).catch(() => undefined); // b71 (review P-06): likewise an old-epoch window
  return true;
}

/** creator: does this group need an auto-rotation? (100 envelopes / 24 h) */
export function groupNeedsRotation(rec: GroupRecord): boolean {
  const byCount = (rec.envCount ?? 0) >= EPOCH_MAX_ENVELOPES;
  const started = rec.epochStartedAt ? Date.parse(rec.epochStartedAt) : Date.now();
  const byAge = Date.now() - started >= EPOCH_MAX_MS;
  return byCount || byAge;
}

// ---------- signatures ----------

/** b75 (audit GR-8): every identity-key signature in a group carries its own domain label (§2.8). The
 *  attestation, the deny entry and the intro used to sign bare JSON, so a signature made for one could be
 *  offered as another wherever the JSON shapes allow. */
export const ATTEST_SIG_LABEL = 'vardum-group-attest-v2:';
export const DENY_SIG_LABEL = 'vardum-group-deny-v2:';
export const INTRO_SIG_LABEL = 'vardum-group-intro-v2:';

function attestMessage(groupToken: string, veilId: string, ikPubB64: string, joinedEpoch: number): string {
  return toB64(utf8(ATTEST_SIG_LABEL + JSON.stringify({ group_token: groupToken, veil_id: veilId, IK_pub: ikPubB64, joined_epoch: joinedEpoch })));
}

/** web's Om(): creator/member attestation signature. b75 (audit GR-8): over
 *  'vardum-group-attest-v2:' ‖ JSON{group_token, veil_id, IK_pub, joined_epoch} */
export function attestSignature(ikSeedB64: string, groupToken: string, veilId: string, ikPubB64: string, joinedEpoch: number): Promise<string> {
  return ikSign(ikSeedB64, attestMessage(groupToken, veilId, ikPubB64, joinedEpoch));
}

/** web's km(): deny-list eviction signature. b75 (audit GR-8): over
 *  'vardum-group-deny-v2:' ‖ JSON{group_token, target_IK_pub, deny_epoch} */
export function denySignature(ikSeedB64: string, groupToken: string, targetIkPubB64: string, denyEpoch: number): Promise<string> {
  return ikSign(ikSeedB64, toB64(utf8(DENY_SIG_LABEL + JSON.stringify({ group_token: groupToken, target_IK_pub: targetIkPubB64, deny_epoch: denyEpoch }))));
}

// ---------- intro (web's Kp/Im) ----------

/** Batch C (A1): v2 intros also carry the seat token and its proof (seat, sp). */
export interface GroupIntro { veilId: string; ikPub: string; nick: string; seat?: string; sp?: string; /** b70 (VAR-10): proof bound to the creator key */ sp2?: string;
  /** b71 (review P-03): the member's own signature on its name in this group */ ns?: string }

export function parseGroupIntro(text: string): { p: string; s: string } | null {
  if (typeof text !== 'string' || !text.startsWith('{"__veil_intro":')) return null;
  try {
    const t = JSON.parse(text) as Record<string, unknown>;
    if (t.__veil_intro !== 1 || typeof t.p !== 'string' || typeof t.s !== 'string') return null;
    const inner = JSON.parse(t.p) as Record<string, unknown>;
    if ((inner.v !== 1 && inner.v !== 2) || typeof inner.id !== 'string' || typeof inner.ik !== 'string') return null;
    return { p: t.p, s: t.s };
  } catch { return null; }
}

/** b75 (audit GR-8): an intro's signature is over 'vardum-group-intro-v2:' ‖ p, and p names its group (t).
 *  With `groupToken`, an intro for another group (or one without t) is refused. */
export async function verifyGroupIntro(intro: { p: string; s: string }, groupToken?: string): Promise<GroupIntro | null> {
  try {
    const inner = JSON.parse(intro.p) as { v?: number; id?: string; ik?: string; nick?: string; seat?: unknown; sp?: unknown; sp2?: unknown; ns?: unknown; t?: unknown };
    const okSig = await verifyWithIk(String(inner.ik), toB64(utf8(INTRO_SIG_LABEL + intro.p)), intro.s);
    if (!okSig) return null;
    if (groupToken !== undefined && inner.t !== groupToken) return null;
    const derived = await veilIdFromIkPub(String(inner.ik));
    if (derived !== String(inner.id)) return null;
    const seat = inner.v === 2 && typeof inner.seat === 'string' && typeof inner.sp === 'string' ? { seat: inner.seat, sp: inner.sp, ...(typeof inner.sp2 === 'string' ? { sp2: inner.sp2 } : {}) } : {};
    return { veilId: String(inner.id), ikPub: String(inner.ik), nick: typeof inner.nick === 'string' ? inner.nick.slice(0, 40) : '', ...seat, ...(typeof inner.ns === 'string' ? { ns: inner.ns } : {}) };
  } catch { return null; }
}
