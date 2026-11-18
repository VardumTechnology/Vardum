/**
 * @veil/device — GROUP session orchestration (create / join / inbox / send /
 * rotate / evict), ported from the live web bundle (Sept 19, 2026).
 *
 * All cryptography lives in groups.ts (veil-group-2 since b74 — clean break, see its header).
 * This module owns the relay/gate/entity flows:
 *
 *  CREATE (creator):
 *    groupToken = groupIdFor(creator IK, salt) (b71, review P-02: the token commits
 *      to the creator key), GEK = 32 random bytes, group PQ pub = ML-KEM keypair
 *      (b73 (audit V-15): only its public half is kept — a per-epoch salt, not a key
 *      that protects anything; the epoch key's DELIVERY is what is ML-KEM protected)
 *    main session: invite-style createSession bound to the group
 *      (VeilSession group_token + encrypted group_name blob), state ACTIVE —
 *      it is the creator's broadcast channel; nobody ever joins it 1:1.
 *    N invite sessions: plain invite sessions; links carry #w=&k=&d= plus
 *      &e=&c=<creator IK>&t=<token>&s=<salt>&ph=&ph2= — and NO group key (b71,
 *      review P-01: links used to carry &g=<GEK>, opening the whole epoch).
 *    veilGroupGate rotate {new_epoch:1, group_pq_pub} → stamps group_epoch on
 *    the group's sessions; veilGroupGate attest (creator sig over 'vardum-group-attest-v2:' ‖
 *      {group_token, veil_id, IK_pub, joined_epoch} — b75 (audit GR-8): labelled); local group record
 *      (role creator); signed intro broadcast into the group channel.
 *
 *  JOIN (member):
 *    parse link → #w= write secret, &k= link secret, c=/t=/s= (b71: the token
 *    must equal groupIdFor(c, s)).
 *    normal invite join (peek → ratchet join → gate join); the gate's session
 *    record carries group_token / group_epoch / group_pq_pub.
 *    veilGroupGate attest (member sig); local record (role member, NO key yet);
 *    seat intro (keyed by the seat's link secret, read only by the creator).
 *    b71 (review P-01): the creator checks the seat proof and delivers the key as a
 *    creator-signed wrap to the joiner's signed PQ prekey through the gate
 *    (wrap_deliver / wrap_fetch); the joiner reads nothing before that.
 *    b71 (audit F-07 / F-02): a plain link's claim waits for the creator's tap
 *    (pendingClaims → admitGroupClaims / declineGroupClaim); a contact seat claimed
 *    by its invitee's own key is admitted without one. Every admission rotates the
 *    group first, so the newcomer only ever gets the key of an epoch that began
 *    after it was let in.
 *
 *  INBOX (pollGroupInbox, per open group thread; b75: this used to describe the old
 *  ascending 200-row fetch, gone since b70):
 *    Roster first, through the gate (veilGroupGate 'roster'): attestation-verified rows
 *    (verifiedRosterRows) give the IK <-> Vardum ID bindings; who is TRUSTED comes from this
 *    phone's own state (creator: its admitted list; member: the creator-signed member list,
 *    minus its deny list and, b75, minus members whose own leave it read), never from the
 *    roster, and neither do the labels shown (b75: the creator key held locally).
 *    Envelopes: VeilEnvelope {group_token} paged NEWEST-first, 50 a page, at most 10 pages,
 *    down to the first page whose oldest row is already dealt with, resuming at a row anchor
 *    (dev/backfill.ts pageBacklog); rows are then handled oldest-first and each ends as
 *    processed, rejected (both ledgered in knownEnvIds) or held (heldEnvIds, retried) — see
 *    the comment above the pager. Per row: own posts (signature checked), seat intros
 *    (creator), past/future epochs, untrusted senders, then decrypt (sender signature first)
 *    and apply: rekeys, member lists, leaves, receipts, intros, media/text.
 *    After the rows: kept rekeys (b75, GR-5), gap notes, the creator's admissions, leaver
 *    removals and wrap-request service, the member's key recovery; "behind" only on a
 *    creator-signed rekey it couldn't take (b75, GR-2). The result's epoch and fingerprint are
 *    the record's at the END of the pass (b75).
 *
 *  SEND: Sm-encrypt via groups.ts, submitEnvelope with BOTH session_token and
 *    group_token, sender_client_id = group sender tag, protocol_version
 *    'veil-group-2' (b74). b73 (audit V-09): the session token and write credential name
 *    the sender's own seat, which the relay bound to the member's Vardum ID at attest:
 *    the relay can attribute every post to a member, whatever the sender tag.
 */
import { toB64, fromB64, utf8, randomBytes } from '../../crypto-core/src/bytes';
import { ikSign, verifyWithIk, verifyPqPrekeySig, veilIdFromIkPub } from '../../crypto-core/src/identity';
import { mlkemKeypair } from '../../crypto-core/src/mlkem';
import { createSession, serializeRatchetState, type RatchetStateSerialized } from '../../crypto-core/src/ratchet';
import type { VeilStorage } from '../../crypto-core/src/storage-adapter';
import type { SessionStore } from './session-store';
import type { VeilRelay } from './relay';
import {
  createInviteSession, groupInviteLink, groupLinkBinding, groupLinkBinding2, parseInviteLink, joinInviteSession, writeHashHex,
} from './invite';
import { encryptMedia } from './chat';
import { relayTimestampToIso } from './time';
import { pinToWipe, pinDeps } from './wipe-generation';
import { pageBacklog, parseAnchor, type BackfillAnchor } from './backfill';
import {
  GROUP_PROTO, groupProtoMismatchNote, encryptGroupMessage, decryptGroupMessage, saveGroupRecord, loadGroupRecord, loadGroupRecordStrict, readPersistedGroupRecord,
  loadGroupRecords, groupRecord, bumpGroupEnvCount, groupRecordBytes, senderTag, epochFingerprint,
  buildRekeyWrap, parseRekeyPayload, applyRekeyPayload, attestSignature, denySignature,
  buildSignedRekeyText, verifiedRosterRows, rekeyWrapsPerPart, rekeyPartNeed, verifyGroupEnvelopeSig,
  encryptGroupText, decryptGroupText, groupNeedsRotation, exportGroupRecords,
  importGroupRecords, forgetGroup, decryptOwnGroupEnvelope, type GroupRecord, type GroupRekeyPayload, type GroupRekeyWrap,
  parseGroupIntro, verifyGroupIntro, advanceEpoch, INTRO_SIG_LABEL,
  trustedMembers, parseMembersPayload, applyMembersPayload, buildSignedMembersText, gekCommitment,
  seatProof, seatProofForCreator, deriveSeatKey, type PendingRotation, type GroupSeat,
  groupKeyFreshness, GroupKeysStaleError, assertGroupKeysFresh, MEMBER_EPOCH_MAX_MS, MEMBER_EPOCH_READ_MAX_MS,
  GROUP_SEAT_SIG_VERSION, decryptSeatIntro, groupIdFor, signGroupName, verifyGroupName, SEAT_MAX_AGE_MS,
  keyedSenderTag, groupSenderTags, ownSenderTag, releaseGroupPostSeq, type GroupSeatClaim, type GroupPostMeta,
  GroupRekeyRecipientsError, isGroupNameBlob, GroupRekeyListMissingError, membersHash, membersHashSync /* b77t2 (L-8) */,
  GroupOwnWrapError, GroupListConflictError, publicTagPostsAllowed, epochStartMs, /* b77u (audit 6) */
  noteNameBinding, buildSignedLeaveText, parseLeavePayload, verifyLeavePayload, type GroupRename, type GroupDeliveryGhost, holdFreedName,
  type GroupControlKind, collectRotationPart, finishRotation, buildSignedRekeyParts, ROTATION_PARTS_WAIT_MS, padKeyDelivery,
  refuseConflictingRotations, reopenGroupCounter, expireDeliveryChecks, takeDeliveryGhostNotes, deliveryBindRid,
} from './groups';
import { shownTime } from './chat';
import { secureRandomUnit } from './secure-random'; // b77u (audit 6)
import { cleanRelayText, relayErrorText } from './relay-errors'; // b77m (audit VAR-20)
import { nameSkeleton, displayGroupName, nameRisk, noteName, UNVERIFIED_ID_CHARS } from './names';
// b185: parseGroupIntro/verifyGroupIntro/advanceEpoch moved to this STATIC import.
// The previous dynamic `await import('./groups')` resolved to a SECOND module
// instance under any loader that separates static and dynamic module graphs
// (node:test/tsx demonstrated it live; some bundler configurations do too) —
// the WeakMap group-key registry silently split in two and a rotation could
// throw "Group keys are not established" while the record sat intact in the
// other instance. One module, one registry, no loader-dependent behavior.

/** b70 (re-review 9): normalised so look-alikes (case, spacing, compatibility forms) collide.
 *  b71 (audit): invisible / format characters are removed first, and the look-alike
 *  fold is the wider Latin / Cyrillic / Greek skeleton in names.ts (e.g. U+04CF). */
export function nickKey(n: string): string {
  return nameSkeleton(n);
}
/** a member's display name, made distinct from every other member's */
export function uniqueGroupNick(nickIn: string, tag: string, tagToNick: Record<string, string>, veilId: string, otherVeilIds: Iterable<string> = []): string {
  // b70 (re-review 12): the " · ID" suffix is the app's own mark — a member can't type it
  // (a name "Alice · 85vG" used to look exactly like the app's label for a second Alice)
  // b70 (re-review 14): normalised first (U+0387 and U+FF65 used to pass the list
  // unchanged and look exactly like the app's mark), and every middle-dot look-alike
  // b71 (audit): no invisible or bidi-control characters in a shown name either
  // b75 (audit GR-4): every dot, bullet, word separator and full stop Unicode names (U+A78F,
  // U+10101 and U+0701 got through the b70 hand list of 22), see displayGroupName
  const nick = displayGroupName(nickIn);
  const k = nickKey(nick);
  // b70 (re-review 13): a member with no name shows as the first 8 characters of their
  // ID, so a name equal to another member's ID prefix clashes too; the suffix was 8
  // characters (4 could be matched by grinding a look-alike ID). b77s (audit 4 GR-02): 12 now
  const others = [...otherVeilIds].filter((v) => !!v && v !== veilId).map((v) => v.slice(0, 8));
  // b75 (audit GR-4): a name that mixes scripts, uses a script outside the common set, claims a
  // role word ("Matt (creator)") or carries another member's ID prefix anywhere is never plain
  const clash = !!nameRisk(nick, others) || Object.entries(tagToNick).some(([t, n]) => t !== tag && nickKey(n) === k)
    || others.some((v) => nickKey(v) === k);
  // b77s (audit 4 GR-02): the suffix is UNVERIFIED_ID_CHARS (12) characters — 8 (~47 bits) could be ground
  return clash ? `${nick} · ${veilId.slice(0, UNVERIFIED_ID_CHARS) || tag.slice(0, UNVERIFIED_ID_CHARS)}` : nick;
}

/**
 * b71 (review P-03): the names this phone shows, IK_pub -> name, for `people`
 * ([IK_pub, Vardum ID]). Names from a signed binding (rec.boundNicks: the creator-
 * signed member list, each name self-signed; on the creator's phone, the members'
 * seat-proven intros; and the creator's own name) are shown as is, in list order —
 * the creator first, then by admission — unless an earlier entry already shows the
 * same name (then with the ID suffix). Every phone holds the same list, so every
 * phone picks the same names. A name seen only in a loose intro is never trusted to
 * be unique here and always carries the suffix.
 * b74 (VAR-06): the order is the FIRST-BOUND sequence of each name (rec.nameFb: from the
 * creator-signed list, or the creator's own bookkeeping), lowest first — whoever held a
 * name first keeps it plain. (Before, it was admission order, and a member admitted
 * earlier could rename itself to a later member's name and take it over.) A name with no
 * sequence for exactly that name comes after every sequenced one, in the old order.
 */
export function shownGroupNames(
  rec: Pick<GroupRecord, 'role' | 'ikPubB64' | 'creatorIkPubB64' | 'myNick' | 'boundNicks' | 'introNicks' | 'nameFb'> & Partial<Pick<GroupRecord, 'heldNames'>>, people: Array<[string, string]>,
  now = Date.now(),
): Record<string, string> {
  const vidOf: Record<string, string> = Object.create(null);
  for (const [ik, vid] of people) if (ik && vid) vidOf[ik] = vid;
  const allVids = Object.values(vidOf);
  const bound: Record<string, string> = Object.create(null);
  if (rec.role === 'creator' && rec.myNick) bound[rec.ikPubB64] = rec.myNick;
  for (const [ik, n] of Object.entries(rec.boundNicks ?? {})) if (!(ik in bound) && typeof n === 'string' && n) bound[ik] = n;
  const creatorIk = rec.creatorIkPubB64 ?? (rec.role === 'creator' ? rec.ikPubB64 : '');
  const listOrder = [...(creatorIk && creatorIk in bound ? [creatorIk] : []), ...Object.keys(bound).filter((ik) => ik !== creatorIk)];
  const fbOf = (ik: string): number => {
    const e = rec.nameFb && Object.prototype.hasOwnProperty.call(rec.nameFb, ik) ? rec.nameFb[ik] : undefined;
    return e && e[0] === bound[ik] && Number.isInteger(e[1]) ? e[1] : Number.POSITIVE_INFINITY;
  };
  const order = listOrder.map((ik, i) => [ik, i] as const).sort((a, b) => (fbOf(a[0]) - fbOf(b[0])) || (a[1] - b[1])).map(([ik]) => ik);
  const out: Record<string, string> = Object.create(null);
  const taken: Record<string, string> = {};
  // b75r1 (audit G-1): a name freed recently by someone else (removed, left, renamed) is held back
  const held = (rec.heldNames ?? []).filter((h) => Array.isArray(h) && typeof h[0] === 'string' && typeof h[1] === 'string' && h[2] > now);
  for (const ik of order) {
    if (!vidOf[ik]) continue;
    out[ik] = uniqueGroupNick(bound[ik], ik, taken, vidOf[ik], allVids);
    if (!out[ik].includes(' · ') && held.some(([hik, hn]) => hik !== ik && nickKey(hn) === nickKey(bound[ik]))) out[ik] = `${out[ik]} · ${vidOf[ik].slice(0, UNVERIFIED_ID_CHARS)}`; // b77s (audit 4 GR-02): 12
    taken[ik] = out[ik];
  }
  for (const [ik, vid] of Object.entries(vidOf)) {
    if (out[ik]) continue;
    if (ik === rec.ikPubB64 && rec.myNick) { out[ik] = rec.myNick; continue; } // my own name, on my own phone
    const loose = rec.introNicks && Object.prototype.hasOwnProperty.call(rec.introNicks, vid) ? rec.introNicks[vid] : '';
    if (loose) out[ik] = `${displayGroupName(loose)} · ${vid.slice(0, UNVERIFIED_ID_CHARS)}`; // b77s (audit 4 GR-02): 12
  }
  return out;
}

export interface GroupIdentity {
  veilId: string;
  ikSeedB64: string;
  ikPubB64: string;
  /** the member's OWN ML-KEM private key — only used to unwrap rekey GEKs */
  pqPrivB64: string;
}

export interface GroupSessionDeps {
  relay: VeilRelay;
  sessions: SessionStore;
  storage: VeilStorage;
  webBaseUrl: string;
}

export interface InviteDialsInput {
  burnAfterOpen: boolean;
  expireAfterSeconds: number;
  keyRetentionHours: number;
  defaultTtlSeconds: number;
}

export interface CreatedGroup {
  groupToken: string;
  groupName: string;
  mainToken: string;
  inviteLinks: string[];
  /** b199: one seat per invited contact, locked to their Veil ID — the app
   *  delivers each link privately inside the encrypted 1:1 chat. */
  contactInvites: { veilId: string; link: string }[];
}

export interface JoinedGroup {
  token: string;
  groupToken: string;
  epoch: number;
}

function hexRand(n: number): string {
  return Array.from(randomBytes(n)).map((b) => b.toString(16).padStart(2, '0')).join('');
}

/** web's Nm()/Ep(): the signed intro payload broadcast into a group.
 *  b75 (audit GR-8): p names the group (t) and the signature is over 'vardum-group-intro-v2:' ‖ p */
export async function buildIntroPayload(id: GroupIdentity, nickname: string, seat?: { token: string; proof: string; proof2?: string }, groupToken?: string): Promise<string> {
  const nick = (nickname || '').trim().slice(0, 40);
  // b71 (review P-03): ns = my own signature on my name in this group; the creator
  // puts it in the signed member list, so every member learns every name
  const ns = groupToken && nick ? await signGroupName(id.ikSeedB64, groupToken, id.ikPubB64, nick) : undefined;
  // Batch C (A1): v2 intros carry the seat token and its proof (link-secret HMAC);
  // b70 (VAR-10): plus sp2, the proof bound to the creator key this phone holds
  const t = groupToken ? { t: groupToken } : {};
  const p = seat
    ? JSON.stringify({ v: 2, ...t, id: id.veilId, ik: id.ikPubB64, nick, seat: seat.token, sp: seat.proof, ...(seat.proof2 ? { sp2: seat.proof2 } : {}), ...(ns ? { ns } : {}) })
    : JSON.stringify({ v: 1, ...t, id: id.veilId, ik: id.ikPubB64, nick, ...(ns ? { ns } : {}) });
  const s = await ikSign(id.ikSeedB64, toB64(utf8(INTRO_SIG_LABEL + p)));
  return JSON.stringify({ __veil_intro: 1, p, s });
}

/** b135: the pairwise submit path got assertSubmitOk in b127 after an
 *  HTTP-200-wrapped {error} silently ate a receipt — the GROUP path never
 *  did. Owner repro (Sept 27 group test): a harness `say` returned
 *  {ok:true} but its envelope never appeared on the relay (verified by full
 *  ascending page scan of VeilEnvelope rows for the group — every other row
 *  present, that one absent). A 200-wrapped reject must throw here so the
 *  caller can surface it; silence turns a dropped message into a "delivered"
 *  lie. */
function assertGroupSubmitOk(r: { data: unknown; status: number }, what: string): void {
  const d = r.data as { error?: unknown } | null;
  if (r.status >= 400 || (d && typeof d.error === 'string')) {
    // b77m (audit VAR-20): the relay's words go to the log, never into the thrown (displayable) message
    console.log(`[veil-group] ${what} rejected by relay (${r.status}): ${cleanRelayText(d?.error) || 'no detail'}`);
    throw Object.assign(new Error(`${what} was refused by the server — ${relayErrorText(r.status >= 400 ? r.status : 400, d).message}`), { status: r.status, relayMessage: cleanRelayText(d?.error) });
  }
}

async function submitGroupEnvelope(
  deps: GroupSessionDeps, opts: {
    groupToken: string; sessionToken: string; clientId: string; text: string; cover?: boolean;
    /** b71 (review P-01): a seat intro, keyed by this seat */
    seat?: { keyB64: string; token: string };
    /** b75r3 (audit R3G-I2): set by the code that built a control message (never for a typed one) */
    control?: GroupControlKind;
  },
): Promise<{ senderTag: string; byteLength: number }> {
  const sealed = await deps.sessions.load(opts.sessionToken);
  if (!sealed) throw new Error('No session state for this group on this device.');
  // b73 (audit V-09): a b71/b72 record may still carry the per-epoch downgrade to the public
  // tag — it is dropped here, so this post (and every later one) tries the keyed tag
  if (!opts.seat) {
    const r0 = groupRecord(deps.storage, opts.groupToken);
    if (r0 && r0.legacyTagEpoch !== undefined) {
      r0.legacyTagEpoch = undefined;
      if (r0.gekB64) r0.myTag = await ownSenderTag(r0);
      await saveGroupRecord(deps.storage, r0).catch(() => undefined);
    }
  }
  let env = await encryptGroupMessage(deps.storage, opts.groupToken, opts.text, opts.cover ?? false, opts.seat, { control: opts.control });
  const submitOnce = () => deps.relay.submitEnvelope({
    session_token: opts.sessionToken,
    group_token: opts.groupToken,
    client_id: opts.clientId,
    write_secret: (sealed as RatchetStateSerialized & { writeSecret?: string }).writeSecret ?? null,
    sender_client_id: env.senderTag,
    ciphertext: env.ciphertext,
    iv: env.iv,
    header: env.header,
    byte_length: env.byteLength,
    // b91: group envelopes (messages + receipts) use the session's expire
    // dial, not a hardcoded 1h — same uniform-expiry rule as pairwise
    ttl_seconds: Number((sealed as { expireAfterSeconds?: number }).expireAfterSeconds) || 86400,
    protocolVersion: GROUP_PROTO,
  });
  try {
    try {
      assertGroupSubmitOk(await submitOnce(), 'group submit'); // b135: no more silent 200-wrapped rejects
    } catch (e) {
      // b71 (audit F-13): a relay not yet updated recomputes every sender tag from the
      // public roster and refuses the keyed one. Receivers accept both forms. (A seat
      // intro already uses the public tag.)
      // b73 (audit V-09): THIS post goes again under the public tag, and nothing else
      // changes — the next post tries the keyed tag first again (b71/b72 stayed on the
      // public tag for the rest of the epoch after one refusal, which any relay could
      // trigger). Logged every time. What the public tag gives away is no more than the
      // relay already has: it sees which seat (and so which member) submitted every post.
      const rec = groupRecord(deps.storage, opts.groupToken);
      if (opts.seat || !rec || !rec.gekB64 || !/Sender is not a member of this group epoch/i.test(String((e as Error)?.message ?? e))) throw e;
      // b77u (audit 6 R4 #13): past the transition date receivers read the public tag on seat intros only, so the
      // fallback would only be dropped: the refusal is shown instead
      if (!publicTagPostsAllowed()) throw new Error('The relay refused this post under your group sender tag. Try again after the group’s next key change.');
      // b77p (audit VAR-07): the refusal is the relay's word — it may have stored the first copy. The re-send
      // keeps the post's identity (chain, counter, sequence, time), so receivers (one replay window per
      // signer, groups.ts) take whichever copy comes first and drop the other as a replay. The sequence number
      // is no longer given back here (the re-send carries it).
      console.warn('[veil-group] the relay refused the keyed sender tag (relay not updated?) — this post is re-sent under the public tag with the same identity; the next post tries the keyed tag again', { groupToken: opts.groupToken.slice(0, 6) });
      env = await encryptGroupMessage(deps.storage, opts.groupToken, opts.text, opts.cover ?? false, undefined, { publicTag: true, control: opts.control, resend: { ch: env.ch, n: env.n, seq: env.seq ?? 0, sentAt: env.sentAt } });
      assertGroupSubmitOk(await submitOnce(), 'group submit');
    }
  } catch (e) {
    // b71 (audit F-12): a refused post gives its sequence number back (no false gap)
    if (env.seq) await releaseGroupPostSeq(deps.storage, opts.groupToken, env.seq).catch(() => undefined);
    throw e;
  }
  // b198 GROUP PUSH: group sends pinged the other members through the relay's group notify action (b77p, audit
  // VAR-08: cover posts too, through one scheduler, so the call told no cover from real).
  // b77p round 2 (owner decision 1): NO GROUP NOTIFY AT ALL. The relay's group push went to each member ACCOUNT's push
  // rows (account-level push, now gone), and a per-seat wake would still name accounts (the group gate is signed in
  // and every seat maps to an account-tagged member row). Members see a post on their next poll or wake. With no call
  // after any post, cover and real posts can't be told apart by one either (VAR-08).
  return { senderTag: env.senderTag, byteLength: env.byteLength };
}

/** b71 (audit F-07): the pinned key the app gave for an invitee, if any (a contact
 *  seat then admits exactly that key; see checkSeatClaim) */
function pinnedKeyFor(keys: Record<string, string> | undefined, veilId: string): string | undefined {
  const k = keys && Object.prototype.hasOwnProperty.call(keys, veilId) ? keys[veilId] : undefined;
  return typeof k === 'string' && k ? k : undefined;
}

// ---------- create ----------

export async function createGroup(
  deps: GroupSessionDeps,
  opts: { identity: GroupIdentity; groupName: string; inviteCount: number; clientId: string; dials: InviteDialsInput; nickname?: string;
          /** b199: pinned contacts to invite directly (one locked seat each) */
          invitees?: string[];
          /** b71 (audit F-07): each invitee's pinned identity key (Vardum ID -> IK_pub), so
           *  their seat admits exactly that key without a tap */
          inviteeKeys?: Record<string, string> },
): Promise<CreatedGroup> {
  deps = pinDeps(deps); // b70 (re-review 9): a wipe while this waits on the relay stops its writes
  // b71 (review P-02): the token commits to the creator key (the salt rides in every link)
  const groupSalt = hexRand(16);
  const groupToken = await groupIdFor(opts.identity.ikPubB64, groupSalt);
  const pq = await mlkemKeypair();
  const gek = toB64(randomBytes(32));
  const nameBlob = await encryptGroupText(gek, opts.groupName);
  // Batch D (D-03): every link names its group and binds the group's PQ key
  const bind = await groupLinkBinding(groupToken, pq.pub);
  const bind2 = await groupLinkBinding2(groupToken, pq.pub, opts.identity.ikPubB64); // b70 (VAR-10)

  // creator's MAIN group session — active immediately, bound to the group
  const main = await createInviteSession(deps, {
    clientId: opts.clientId,
    dials: opts.dials,
    group: { groupToken, groupNameBlob: nameBlob, activate: true, epoch: 1, pqPubB64: pq.pub },
  });

  // member invite sessions (plain invite links + group fragments)
  // Batch C (A1): every seat is recorded with a key derived from its link
  // secret, so the creator can later admit exactly one identity per seat
  const seats: Record<string, GroupSeat> = {};
  const recordSeat = async (inv: { token: string; link: string }, invitee?: string) => {
    const inviteeIk = invitee ? pinnedKeyFor(opts.inviteeKeys, invitee) : undefined;
    seats[inv.token] = { key: await deriveSeatKey(parseInviteLink(inv.link).linkSecret ?? '', inv.token), ...(invitee ? { invitee } : {}), ...(inviteeIk ? { inviteeIk } : {}), at: Date.now() };
  };
  // b71 (review P-01): no group key in any link
  const invites: string[] = [];
  for (let i = 0; i < opts.inviteCount; i++) {
    const inv = await createInviteSession(deps, { clientId: opts.clientId, dials: opts.dials, group: { groupToken, groupNameBlob: nameBlob, epoch: 1, pqPubB64: pq.pub } });
    await recordSeat(inv);
    invites.push(groupInviteLink(inv.link, 1, opts.identity.ikPubB64, groupToken, groupSalt, bind, bind2));
  }
  // b199: contact seats — same invite mechanism, locked to the invitee
  const contactInvites: { veilId: string; link: string }[] = [];
  for (const veilId of [...new Set(opts.invitees ?? [])]) {
    const inv = await createInviteSession(deps, { clientId: opts.clientId, dials: opts.dials, group: { groupToken, groupNameBlob: nameBlob, epoch: 1, pqPubB64: pq.pub, inviteeVeilId: veilId } });
    await recordSeat(inv, veilId);
    contactInvites.push({ veilId, link: groupInviteLink(inv.link, 1, opts.identity.ikPubB64, groupToken, groupSalt, bind, bind2) });
  }

  await deps.relay.invoke('veilGroupGate', {
    action: 'rotate',
    group_token: groupToken,
    session_token: main.token,
    write_secret: (await deps.sessions.load(main.token) as RatchetStateSerialized & { writeSecret?: string })?.writeSecret ?? null,
    new_epoch: 1,
    group_pq_pub: pq.pub,
  });

  const sig = await attestSignature(opts.identity.ikSeedB64, groupToken, opts.identity.veilId, opts.identity.ikPubB64, 1);
  await deps.relay.invoke('veilGroupGate', {
    action: 'attest',
    group_token: groupToken,
    session_token: main.token,
    write_secret: (await deps.sessions.load(main.token) as RatchetStateSerialized & { writeSecret?: string })?.writeSecret ?? null,
    veil_id: opts.identity.veilId,
    IK_pub: opts.identity.ikPubB64,
    joined_epoch: 1,
    sig,
  });

  const creatorNick = (opts.nickname ?? '').trim().slice(0, 40);
  await saveGroupRecord(deps.storage, {
    groupToken,
    sessionToken: main.token, // b198: the member's own group session (background poll + push credential)
    veilId: opts.identity.veilId,
    ikSeedB64: opts.identity.ikSeedB64,
    ikPubB64: opts.identity.ikPubB64,
    role: 'creator',
    // b74 (rc required): the first epoch's key went to nobody else
    epochRecipients: [],
    // b74 (VAR-06): the creator's own name is the group's first binding
    ...(creatorNick ? { nameSeq: 1, nameFb: { [opts.identity.ikPubB64]: [creatorNick, 1] as [string, number] } } : {}),
    creatorIkPubB64: opts.identity.ikPubB64,
    groupSalt, // b71 (review P-02)
    linksV2: true, // b71 (review P-01)
    dials: { ...opts.dials }, // b71 (audit F-24): every later seat uses these
    evictedIks: [],
    seats,
    admitted: {},
    memberSeq: 0,
    epoch: 1,
    gekB64: gek, // (b70 re-review 5: no nameGekB64 — the plain name below is kept instead)
    pqPubB64: pq.pub,
    // b199: the creator keeps the plain name so "Add people" can mint seats later
    name: opts.groupName,
    myNick: (opts.nickname ?? '').trim().slice(0, 40) || undefined,
    myTag: await keyedSenderTag(groupToken, 1, gek, opts.identity.veilId), // b71 (audit F-13)
    sendN: 0,
    recv: {},
    envCount: 0,
  });

  try {
    await submitGroupEnvelope(deps, {
      groupToken,
      sessionToken: main.token,
      clientId: opts.clientId,
      text: await buildIntroPayload(opts.identity, opts.nickname ?? '', undefined, groupToken),
      control: 'intro',
    });
  } catch (e) {
    console.error('group-create:auto-intro-failed', e);
  }

  return { groupToken, groupName: opts.groupName, mainToken: main.token, inviteLinks: invites, contactInvites };
}

/**
 * b199 "Add people" (creator only): mint new seats for an existing group at its
 * CURRENT epoch. Locked seats when inviteeVeilId is given; plain link seats otherwise.
 * b71 (review P-01): the link carries no group key; the joiner receives the key
 * that is current when it is admitted (so a rotation in between no longer makes
 * the link stale). b71 (review P-02): groups made before b71 can't add people.
 */
export async function createGroupSeats(
  deps: GroupSessionDeps,
  opts: { groupToken: string; clientId: string; dials: InviteDialsInput; invitees?: string[]; linkCount?: number;
          /** b71 (audit F-07): each invitee's pinned identity key (see createGroup) */
          inviteeKeys?: Record<string, string> },
): Promise<{ groupName: string; contactInvites: { veilId: string; link: string }[]; inviteLinks: string[] }> {
  deps = pinDeps(deps); // b70 (re-review 9): a wipe while this waits on the relay stops its writes
  const rec = (await loadGroupRecord(deps.storage, opts.groupToken)) ?? groupRecord(deps.storage, opts.groupToken);
  if (!rec) throw new Error('This group is not on this device.');
  if (rec.role !== 'creator') throw new Error('Only the person who created this group can add people.');
  // b71 (review P-02): a link binds its creator key through the group token. A group
  // made before b71 has a random token, so no link for it can be checked by a joiner
  // (b71 joiners refuse links without s=): it can't take new people.
  if (!rec.groupSalt || await groupIdFor(rec.creatorIkPubB64 ?? rec.ikPubB64, rec.groupSalt) !== rec.groupToken) {
    throw new Error('This group was made with an older version of Vardum, so new people can\'t be added to it safely. Start a new group to add them.');
  }
  const name = rec.name || 'Group';
  // b71 (audit F-24): every seat of a group rides the group's own dials (kept since
  // creation), not whatever the creator's global settings are today. A group made
  // before b71 keeps the dials of its first "Add people" from then on.
  if (!rec.dials) { rec.dials = { ...opts.dials }; await saveGroupRecord(deps.storage, rec); }
  const dials = rec.dials;
  const seat = async (inviteeVeilId?: string) => {
    // b75r2 (audit R2G-01): the epoch, its key and its PQ public key are read together, from the live record, for
    // each seat — b75r1 encrypted the name once, before every seat's wait on the relay, and read the epoch and the
    // PQ key at different moments across those waits (a rotation landing in between put a past epoch's name blob
    // on a new seat row, readable by a member removed since, and gave the link a binding for the wrong epoch)
    const cur = groupRecord(deps.storage, opts.groupToken) ?? rec;
    const ep = cur.epoch, gek = cur.gekB64, pq = cur.pqPubB64;
    const nameBlob = await encryptGroupText(gek, name);
    const inv = await createInviteSession(deps, {
      clientId: opts.clientId, dials,
      group: { groupToken: rec.groupToken, groupNameBlob: nameBlob, epoch: ep, pqPubB64: pq, inviteeVeilId },
    });
    // Batch C (A1): record the seat before its link leaves this device
    const key = await deriveSeatKey(parseInviteLink(inv.link).linkSecret ?? '', inv.token);
    const inviteeIk = inviteeVeilId ? pinnedKeyFor(opts.inviteeKeys, inviteeVeilId) : undefined;
    rec.seats = { ...(rec.seats ?? {}), [inv.token]: { key, ...(inviteeVeilId ? { invitee: inviteeVeilId } : {}), ...(inviteeIk ? { inviteeIk } : {}), at: Date.now() } };
    await saveGroupRecord(deps.storage, rec);
    const creatorIk = rec.creatorIkPubB64 ?? rec.ikPubB64;
    // b71 (review P-01): no group key in the link. b71 (audit F-02/F-07): the joiner
    // gets a key only after the creator approves it (a contact seat: its own pinned key),
    // and only the key of a NEW epoch started at admission — so it never reads what was
    // posted before it was let in (this comment used to claim that for the link alone)
    return groupInviteLink(inv.link, ep, creatorIk, rec.groupToken, rec.groupSalt!, await groupLinkBinding(rec.groupToken, pq), await groupLinkBinding2(rec.groupToken, pq, creatorIk));
  };
  const contactInvites: { veilId: string; link: string }[] = [];
  for (const veilId of [...new Set(opts.invitees ?? [])]) contactInvites.push({ veilId, link: await seat(veilId) });
  const inviteLinks: string[] = [];
  for (let i = 0; i < Math.max(0, opts.linkCount ?? 0); i++) inviteLinks.push(await seat());
  return { groupName: name, contactInvites, inviteLinks };
}

// ---------- join ----------

export async function joinGroup(
  deps: GroupSessionDeps,
  opts: { link: string; clientId: string; displayName?: string; identity: GroupIdentity; nickname?: string },
): Promise<JoinedGroup> {
  deps = pinDeps(deps); // b70 (re-review 9): a wipe while this waits on the relay stops its writes
  const parsed = parseInviteLink(opts.link);
  // b54 (N-1): the creator IK travels in the link fragment — it is the only key
  // allowed to move this group to a new epoch.
  // b71 (review P-01): links no longer carry the group key (g=); one that does is
  // read like any other, and its key is never used.
  let creatorIkOk = false;
  try { creatorIkOk = !!parsed.creatorIk && fromB64(parsed.creatorIk).length === 32; } catch { creatorIkOk = false; }
  if (!creatorIkOk) throw new Error('This group invitation is from an older version of Vardum — ask for a fresh link.');
  // Batch D (D-03, RV-03): the link names its group; the relay doesn't get to.
  // Links made before b56 carry no group token and are refused (hard cut, D5).
  // b71 (review P-02): and the token must commit to the link's creator key through
  // the salt s= (links made before b71 have none and are refused, hard cut). This,
  // not the relay's roster, is what makes c= the group's real creator: whoever
  // forwards a link can swap c= and recompute every hash in it, but not find a
  // second (key, salt) for the same token.
  if (!parsed.groupToken || !parsed.groupBind || !parsed.groupSalt) throw new Error('This group invitation is from an older version of Vardum — ask for a fresh link.');
  if (await groupIdFor(String(parsed.creatorIk), parsed.groupSalt) !== parsed.groupToken) {
    throw new Error('This group invitation was changed on its way to you (it names a different creator), so it was not joined. Ask the group creator for a link directly.');
  }
  const linkEpoch = parsed.epoch ?? 1;
  // Batch E (F-9): an unreadable record is not "not a member"
  if (await loadGroupRecordStrict(deps.storage, parsed.groupToken)) throw new Error('You are already in this group on this device.');

  // normal invite join (peek → ratchet → gate join, with all its validations)
  await joinInviteSession(deps, { link: opts.link, clientId: opts.clientId, displayName: opts.displayName });

  // fetch the joined record to read the group binding
  // Batch C (V-16): after the join the stored credential may no longer be the link's w
  const seatWrite = (await deps.sessions.load(parsed.token) as RatchetStateSerialized & { writeSecret?: string } | null)?.writeSecret ?? parsed.writeSecret;
  const pk = await deps.relay.invoke('veilSessionGate', { action: 'peek', token: parsed.token, write_secret: seatWrite });
  const pd = pk.data as { data?: { session?: Record<string, unknown> }; session?: Record<string, unknown> };
  const rec = pd?.data?.session ?? pd?.session;
  if (!rec) throw new Error('Invitation not found or expired.');
  const groupToken = String(rec.group_token ?? '');
  if (!groupToken || Number(rec.group_epoch ?? 0) < 1) throw new Error('This group invitation is incomplete — ask for a fresh link.');
  // b71 (review P-01): the relay's epoch only addresses the seat intro — the key, the
  // epoch and the group PQ key this phone uses come from the creator's signed
  // delivery. A link made before a rotation still joins (it used to be refused).
  const epoch = Number(rec.group_epoch) || linkEpoch;
  // Batch D (D-03): the relay's answer must be the group the link names
  if (groupToken !== parsed.groupToken) {
    throw new Error('This invitation does not match the group it was made for, so it was not joined. Ask for a fresh link.');
  }
  // Batch D (D-03) / b70 (audit VAR-10 / GRP-1): the group PQ key the link was made
  // with, and the creator key it binds. (After a rotation the relay serves the new
  // PQ key; the creator's signed delivery carries it then.)
  if (epoch === linkEpoch) {
    if (await groupLinkBinding(groupToken, String(rec.group_pq_pub ?? '')) !== parsed.groupBind) {
      throw new Error('This invitation does not match the group it was made for, so it was not joined. Ask for a fresh link.');
    }
    if (parsed.groupBind2 && await groupLinkBinding2(groupToken, String(rec.group_pq_pub ?? ''), String(parsed.creatorIk)) !== parsed.groupBind2) {
      throw new Error('This invitation was changed after it was made, so it was not joined. Ask the group creator for a fresh link.');
    }
  }

  // Batch C (A1): prove this seat to the creator with the link secret
  const seatKey = await deriveSeatKey(parsed.linkSecret ?? '', parsed.token);
  const proof = await seatProof(seatKey, groupToken, parsed.token, opts.identity.veilId, opts.identity.ikPubB64);
  // b70 (VAR-10): the creator admits this seat only if c= is really its key
  const proof2 = await seatProofForCreator(seatKey, groupToken, parsed.token, opts.identity.veilId, opts.identity.ikPubB64, String(parsed.creatorIk));

  const sig = await attestSignature(opts.identity.ikSeedB64, groupToken, opts.identity.veilId, opts.identity.ikPubB64, epoch);
  await deps.relay.invoke('veilGroupGate', {
    action: 'attest',
    group_token: groupToken,
    session_token: parsed.token,
    write_secret: seatWrite,
    veil_id: opts.identity.veilId,
    IK_pub: opts.identity.ikPubB64,
    joined_epoch: epoch,
    sig,
  });

  // b71 (review P-02): the relay-roster check that stood here (b70 re-review P4 / F1)
  // is gone. It trusted the relay's unsigned 'creator' label: a relay that relabelled
  // the real creator let a forwarded link with a swapped c= through. The token check
  // above binds c= instead, and nothing here depends on the relay's roles.

  await saveGroupRecord(deps.storage, {
    groupToken,
    sessionToken: parsed.token, // b198: the member's own group session (background poll + push credential)
    veilId: opts.identity.veilId,
    ikSeedB64: opts.identity.ikSeedB64,
    ikPubB64: opts.identity.ikPubB64,
    role: 'member',
    creatorIkPubB64: parsed.creatorIk,
    groupSalt: parsed.groupSalt, // b71 (review P-02)
    // Batch C (A1): strict from the start — trusts the creator only until its signed member list arrives
    memberSeq: 0,
    memberList: {},
    seatToken: parsed.token,
    seatProof: proof,
    seatProof2: proof2,
    seatKey, // b71 (review P-01): the seat intro is re-sent under it until admission
    introSentAt: Date.now(),
    epoch,
    // b71 (review P-01): no key until the creator admits this seat and delivers one
    gekB64: '',
    // (b71: the name arrives with the key — the relay's blob is under a key this phone doesn't hold)
    pqPubB64: String(rec.group_pq_pub ?? ''),
    myNick: (opts.nickname ?? '').trim().slice(0, 40) || undefined,
    myTag: await senderTag(groupToken, epoch, opts.identity.veilId),
    sendN: 0,
    recv: {},
    envCount: 0,
  });

  try {
    await sendSeatIntro(deps, { groupToken, sessionToken: parsed.token, clientId: opts.clientId, identity: opts.identity, nick: opts.nickname ?? '', seatToken: parsed.token, seatKey, proof, proof2 });
  } catch (e) {
    console.error('group-join:auto-intro-failed', e);
  }

  return { token: parsed.token, groupToken, epoch };
}

/** b71 (review P-01): the joiner's seat-proven intro, encrypted under its seat key
 *  (only the creator, who minted the seat, can open it) and carrying the member's
 *  self-signed name for the member list (P-03). */
async function sendSeatIntro(
  deps: GroupSessionDeps,
  o: { groupToken: string; sessionToken: string; clientId: string; identity: GroupIdentity; nick: string; seatToken: string; seatKey: string; proof: string; proof2?: string },
): Promise<void> {
  await submitGroupEnvelope(deps, {
    groupToken: o.groupToken, sessionToken: o.sessionToken, clientId: o.clientId,
    text: await buildIntroPayload(o.identity, o.nick, { token: o.seatToken, proof: o.proof, proof2: o.proof2 }, o.groupToken),
    seat: { keyB64: o.seatKey, token: o.seatToken },
    control: 'intro',
  });
}

// ---------- inbox ----------

/** incoming group media (parsed from the __veil_media JSON body) */
export interface GroupIncomingMedia {
  uri: string; k: string; iv: string; mime: string; name: string; size: number; dl?: boolean;
}

export interface GroupMemberRow {
  veilId: string;
  /** display nickname (source of truth when set; '' -> UI falls back to veil id) */
  nick: string;
  ikPub: string;
  role: string;
  joinedEpoch: number;
  tag: string;
  /** Batch C (A1): on the relay roster but not admitted by the creator (creator view only) */
  pending?: boolean;
  /** b70 (audit VAR-11 / GRP-2): trusted (gets every new key) but the relay's
   *  roster doesn't list them — shown, counted in the fingerprint, evictable */
  notOnRelay?: boolean;
  /** b74 (VAR-05): creator view — missing from the relay's roster for longer than
   *  GROUP_ABSENT_GRACE_MS (since this ms-epoch): they may have left without saying so.
   *  Surfaced with a one-tap Remove; never removed on the relay's word alone. */
  goneSince?: number;
  /** b75 (audit GR-1): member view — this member's own signed leave reached this phone, but no
   *  creator-signed list has dropped them yet: shown as "says they are leaving", no longer trusted
   *  here, and they still get new keys until the creator removes them */
  leaving?: boolean;
}

/** b74 (VAR-05): how long a trusted member may be missing from the relay's roster before the
 *  creator is told they may have left (a seat ended without the signed leave message) */
export const GROUP_ABSENT_GRACE_MS = 24 * 60 * 60 * 1000;

/** b75r1 (audit G-9): why a group message was discarded (onSenderVerifyFailed) — the app words each one for
 *  what it is (b75 called every one of them a signature that "did not match the roster"):
 *  - 'signature': not signed by the member its sender tag belongs to (or it used this phone's own tag);
 *  - 'list': a member list that failed a check (not the creator's signature, another group, another epoch);
 *  - 'leave': a leave message that didn't match its sender or wasn't signed by the key it names. */
export type GroupDiscardReason = 'signature' | 'list' | 'leave';

/** b75r1 (audit G-9): the thread's note for a discarded group message */
export function groupDiscardNote(reason?: GroupDiscardReason): string {
  if (reason === 'list') return 'A member-list update was discarded — it did not pass this phone’s checks (the group creator’s signature, this group, the current keys).';
  if (reason === 'leave') return 'A “leaving the group” message was discarded — it did not match the member it came from.';
  return 'A message was discarded — it was not signed by the member it claimed to come from.';
}

/** b77q review (J2-1): the thread's note when the App could not keep a post (held, opened again on the next pass) —
 *  the 1:1 chat's storage note (App.tsx `storage_<token>`) */
/** b77m review (L2) / b77q review (GR-1 residual): a delivered key whose member list never matched the one published */
export const GHOST_KEY_MISMATCH_NOTE = 'The group creator’s phone sent this phone a group key made with a different member list than the one it published, so this phone has stopped sending with that key. New messages wait until the next key change.';
/** b77q owner (1 Nov, "Warn, keep sending"): the same warning where nothing proves anyone else got the key — sends go on */
export const GHOST_KEY_MISMATCH_WARN_NOTE = 'The group creator’s phone sent this phone a group key with a member list that doesn’t match the ones it published (or that never arrived). Nothing shows that anyone else got the key, so this phone keeps sending — but if this keeps happening, ask the group creator, or start a new group.';
export const GROUP_CACHE_REFUSED_NOTE = 'This phone’s storage refused to save part of this chat. Messages still open, but free up some space soon so nothing is lost.';

export interface GroupInboxEvents {
  /** a normal chat message (text may be '' for media/intro-only envelopes).
   *  b77q review (J2-1): awaited. `false` (or a promise of it) = the App could not keep it (its cache write was
   *  refused): the envelope is then held — not marked known, not burned, its counter put back — and opened again
   *  on the next pass. Anything else = kept. (The peek path ignores the answer: it never consumes.) */
  onMessage: (info: { envelopeId: string; text: string; senderTag: string; senderVeilId: string | null; senderNick: string | null; senderVerified: boolean; sentAt: string; media?: GroupIncomingMedia; expiresAt: string | null;
    /** b77m (audit VAR-54): when this phone received it (epoch ms) — the app caches it as ChatMessage.rcvAt */
    rcvAt?: number;
    /** M-3 (b69 audit): sent under group keys older than MEMBER_EPOCH_READ_MAX_MS — not verified; the App marks it */
    staleKeys?: boolean;
    /** b75 (audit GR-4): the post is signed by the group creator's key as this phone holds it (the
     *  link's c=, or its own key on the creator's phone) — the App's "Creator" badge comes from
     *  this, never from a name or the relay's roster */
    senderIsCreator?: boolean }) => void | boolean | Promise<void | boolean>;
  /** system line (X joined the group / keys rotated) */
  onSystem: (info: { envelopeId: string; note: string; sentAt: string }) => void;
  /** my envelopes confirmed read by peers */
  onRead: (readIds: string[]) => void;
  /** the group moved to a new key epoch (b73 (audit V-15): not a "post-quantum epoch" —
   *  the new key is delivered in ML-KEM wraps, the epoch key itself is a 32-byte AES key) */
  onRotated: (newEpoch: number) => void;
  /** a sender-signature failure — envelope discarded (possible impersonation) */
  onSenderVerifyFailed: (envelopeId: string, reason?: GroupDiscardReason) => void;
  /** b191 parity (shell Oct 12): this device is BEHIND the group's key epoch —
   *  it can't open members' envelopes of the new epoch until the key arrives (it has asked the
   *  creator for it through the gate). b75 (audit GR-2): fired only on creator-signed evidence (a
   *  verified rekey for a later epoch this phone couldn't take), never on the relay's roster
   *  epoch; the App never advises leaving or rejoining (a leaver is denied for good, §11.12).
   *  At most once per poll; the App layer dedupes. */
  onEpochBehind?: (info: { groupToken: string; behindEpoch: number; localEpoch: number }) => void;
  /** b191 parity: a real (non-replay) key/counter failure opening a group
   *  envelope (the row is held and retried). The App layer shows a one-per-group notice
   *  that it couldn't be opened (b75 (audit GR-2): no "rejoin" advice). */
  onDecryptFailed?: (info: { groupToken: string; err: string }) => void;
  /** b123: own-envelope echo — my just-sent bubble's text back with its
   *  envelope id, so the App layer can attach envId to the local bubble and
   *  group read receipts can tick it. Cover envelopes echo too (harmless:
   *  no local bubble matches their filler text). */
  onOwnEcho?: (envelopeId: string, text: string) => void;
}

export interface GroupInboxResult {
  tagToVeilId: Record<string, string>;
  /** sender tag -> display nickname (source of truth when set) */
  tagToNick: Record<string, string>;
  members: GroupMemberRow[];
  /** the epoch fingerprint of the record at the END of the pass (b75: after any rotation in it) */
  fingerprint: string | null;
  /** b75 (lead's emulator finding): the record's epoch at the end of the pass */
  epoch: number;
  needsRotation: boolean;
  /** Batch E (F-3): creator of a pre-Batch-C group — the old roster to confirm (asked once) */
  legacyRosterToConfirm?: { veilId: string; ikPub: string }[];
  /** M-3 (b69 audit): member — the group's keys are overdue for a refresh (no
   *  rotation within the rotation period plus slack: sends are paused, and a
   *  removed member may still hold the current key), or newer keys exist that
   *  haven't reached this phone. The App shows a plain notice in the group. */
  keyNotice?: { kind: 'stale' | 'behind' | 'removed'; epoch: number; ageHours: number;
    /** b75r1 (audit G-7): 'removed' — it is THIS phone the creator removed (not someone else) */
    self?: boolean };
  /** b71 (audit F-07): creator — people who used an invite link and wait for the creator
   *  to approve (admitGroupClaims) or decline (declineGroupClaim) them */
  pendingClaims?: GroupClaimRow[];
  /** b71 (review P-01): member — joined, but the creator has not admitted this phone
   *  and delivered the group key yet (nothing can be read or sent until then) */
  awaitingKey?: boolean;
  /** b74 (VAR-05): creator — trusted members missing from the relay's roster past the grace
   *  period (they still get every new key until the creator removes them) */
  goneFromRelay?: Array<{ ikPub: string; veilId: string; label: string; sinceMs: number }>;
  /** b74 (VAR-05): creator — members whose signed leave this pass processed (removed, keys rotated) */
  left?: Array<{ ikPub: string; veilId: string }>;
}

/** b75r1 (audit G-4): when a member re-posts a leave it read (see the end of pollGroupInbox). Exported as a
 *  test knob, like wrapServiceTiming. */
export const leaveRepostTiming = { firstMinMs: 2 * 60_000, firstMaxMs: 20 * 60_000, againMinMs: 30 * 60_000, againMaxMs: 3 * 3600_000, max: 6 };

/** a uniformly random whole number of ms in [lo, hi] (crypto randomness: the relay must not predict it) */
function randomBetween(lo: number, hi: number): number {
  const b = randomBytes(4);
  const u = ((b[0] << 24) >>> 0) + (b[1] << 16) + (b[2] << 8) + b[3];
  return Math.floor(lo + (u / 0x1_0000_0000) * Math.max(0, hi - lo));
}

/** b71 (audit F-07): a seat claim as the app shows it */
export interface GroupClaimRow {
  ikPub: string;
  veilId: string;
  /** the name the claimant gave itself, always with the ID suffix (unverified) */
  label: string;
  /** 'link' = a plain invite link (needs the creator's tap); 'contact' = a contact seat */
  via: 'link' | 'contact';
  at: number;
  /** b75r1 (audit G-8): set by the app — whether the claimant is one of this phone's contacts and whether
   *  the key matches the one saved for them (claimContactLine) */
  contactLine?: string;
}

/** b75r1 (audit G-8): the claimant against this phone's contacts — not one, one whose saved key matches the
 *  claiming key, or one whose saved key is DIFFERENT (a stale or wrong pin: shown as a warning, never hidden) */
export type ClaimContact = 'none' | 'match' | 'different';
export function claimContactStatus(pin: { ikPubB64?: string } | null | undefined, ikPub: string): ClaimContact {
  if (!pin || !pin.ikPubB64) return 'none';
  return pin.ikPubB64 === ikPub ? 'match' : 'different';
}
/** b75r1 (audit G-8): the join-request card's line about who is asking (b75 showed only the self-chosen name and ID) */
export function claimContactLine(status: ClaimContact, contactName?: string | null): string {
  if (status === 'match') return `In your contacts${contactName ? ` as ${noteName(contactName)}` : ''}, and their key matches the one you saved.`;
  if (status === 'different') return `⚠ In your contacts${contactName ? ` as ${noteName(contactName)}` : ''}, but this key is DIFFERENT from the one you saved for them. Check with them outside Vardum before approving.`;
  return 'Not in your contacts. The name is the one they chose.';
}

/** b71 (audit F-07): the record's claims, oldest first */
export function groupClaimRows(rec: Pick<GroupRecord, 'pendingClaims'>): GroupClaimRow[] {
  return Object.entries(rec.pendingClaims ?? {})
    .map(([ikPub, c]) => ({ ikPub, veilId: c.veilId, label: claimLabel(c), via: (c.contact ? 'contact' : 'link') as 'link' | 'contact', at: c.at }))
    .sort((a, b) => a.at - b.at);
}

function claimLabel(c: Pick<GroupSeatClaim, 'nick' | 'veilId'>): string {
  const nick = c.nick ? displayGroupName(c.nick) : '';
  // b75r3 (audit R3G-I3): 12 ID characters, as every other unverified name (RT-7) — 8 (~47 bits) can be ground
  const id = c.veilId.slice(0, UNVERIFIED_ID_CHARS);
  return nick ? `${nick} · ${id}` : id;
}

/** b73 (audit V-01): at most this many held envelope ids per group (see pollGroupInbox) */
const HELD_CAP = 300;
/** b77t (audit 5 L-7): at most this many rows held on an unauthenticated "next epoch" header alone (their own bucket,
 *  newest dropped first; past it only a row signed by a known member is kept), and at most this many keys tried */
const FUTURE_HELD_CAP = 300;
const FUTURE_SIGNER_CHECK_MAX = 128;
/** b77t (audit 5 L-7): at most this many such signature checks in one inbox pass (only a flood fills the bucket) */
const FUTURE_VERIFY_BUDGET = 2048;
/** b77t (audit 5 I-18): pending seat claims kept per seat, and in all */
export const PENDING_CLAIMS_PER_SEAT = 4;
export const PENDING_CLAIMS_MAX = 64;

function asEnvelopeRow(raw: unknown): Record<string, unknown> {
  return (raw ?? {}) as Record<string, unknown>;
}

// b138: the direct VeilGroupMember entityList is dead — the roster-fence fix
// (published) made the entity admin-only, so a non-admin read silently
// returned 0 rows, wiping senderKeys/fingerprint and breaking group
// decryption on native. The ONLY client-facing roster read is now the
// veilGroupGate 'roster' action: it clears session + write-credential
// checks, then fences membership (403 membership_gone / session-group
// binding), and its projection drops account_hash and session_token.
async function gateRoster(
  deps: GroupSessionDeps,
  opts: { groupToken: string; sessionToken: string; writeSecret?: string },
): Promise<{ members: Record<string, unknown>[]; epoch: number }> {
  // (a join passes its seat credential: the seat's state is not saved yet then)
  const ws = opts.writeSecret ?? (await deps.sessions.load(opts.sessionToken) as RatchetStateSerialized & { writeSecret?: string })?.writeSecret ?? null;
  const res = await deps.relay.invoke('veilGroupGate', {
    action: 'roster',
    group_token: opts.groupToken,
    session_token: opts.sessionToken,
    write_secret: ws,
  }) as { data?: { data?: { members?: Record<string, unknown>[]; epoch?: number }; members?: Record<string, unknown>[]; epoch?: number } };
  // b198 (live-caught, first on-device group test post-flip): the relay returns
  // the BASE44 double-wrapped shape { data: { members, epoch } } and invoke
  // hands back the RAW body — so the roster lived at res.data.data.members,
  // one level deeper than this read. A perfectly good roster read as undefined
  // → "Group roster was rejected by the relay" → and since the poll runs the
  // roster BEFORE the envelope fetch, the whole pass aborted and group
  // messages never arrived (Two's 'hey' never seen on One; rotate looked
  // broken too). Accept both shapes; single source of truth for the parse.
  const body = (res?.data ?? {}) as { data?: { members?: Record<string, unknown>[]; epoch?: number }; members?: Record<string, unknown>[]; epoch?: number };
  const members = Array.isArray(body?.data?.members) ? body.data!.members : (Array.isArray(body?.members) ? body.members : undefined);
  if (!Array.isArray(members)) throw new Error('Group roster was rejected by the relay.');
  // b191 parity: the roster is the only place a device with NO pending
  // foreign-epoch envelope can learn the group has moved on without it.
  const epochRaw = body?.data?.epoch ?? body?.epoch;
  return { members: members as Record<string, unknown>[], epoch: Number(epochRaw ?? 0) };
}

/**
 * The epoch fingerprint this phone shows (§11.14): its epoch, key, group PQ key, the member set
 * from its own state — its trusted list when it has one (b71 (audit F-14): never whether the
 * relay's roster happens to list a row), and always itself and the creator — and the epoch's
 * signed recipient set. `fallbackIks`: the verified roster members, for a member record from
 * before Batch C (no signed list). null for a member still waiting for its key.
 */
async function groupFingerprintOf(rec: GroupRecord, fallbackIks: string[] = []): Promise<string | null> {
  if (rec.role === 'member' && !rec.gekB64) return null;
  const trusted = await trustedMembers(rec);
  if (!trusted && !fallbackIks.length) return null;
  const fpIks = new Set<string>(trusted ? Object.keys(trusted) : fallbackIks);
  // b75 (audit GR-1): a member that said it is leaving is still on the creator's list (and gets its
  // keys) until the creator removes it — it counts, so this phone's fingerprint still matches the others'
  for (const ik of Object.keys(rec.leftIks ?? {})) if ((rec.memberList ?? {})[ik] && !(rec.evictedIks ?? []).includes(ik)) fpIks.add(ik);
  fpIks.add(rec.ikPubB64);
  if (rec.creatorIkPubB64) fpIks.add(rec.creatorIkPubB64);
  return epochFingerprint(rec.groupToken, rec.epoch, String(rec.gekB64 ?? ''), String(rec.pqPubB64 ?? ''), [...fpIks], rec.epochRecipients ?? []); // b73 (audit V-07): + who got the key (b74: always)
}

/** b75 (lead's emulator finding): the fingerprint of the group's CURRENT epoch on this phone, for
 *  the App to refresh the members panel right after a rotation it ran (rotate, remove, approve) */
export async function currentGroupFingerprint(store: VeilStorage, groupToken: string): Promise<string | null> {
  const rec = (await loadGroupRecord(store, groupToken)) ?? groupRecord(store, groupToken);
  return rec ? groupFingerprintOf(rec) : null;
}

/** b77u (audit 6 R4 #15): map sender tag `t` to `ik` unless another key already holds it in this epoch. A tag two
 *  keys claim is dropped for both and remembered (`clashed`), so neither key's posts under it are read as the other's.
 *  The tag stays 48 bits: the relay checks `g` + 12 hex digits and b77t phones derive 6 bytes, so a wider tag would
 *  be refused by the relay and unreadable to un-updated members of the same group (veil-group-3). false = refused. */
export function bindSenderTag(map: Record<string, string>, names: Record<string, string>, clashed: Set<string>, t: string, ik: string, vid: string): boolean {
  if (clashed.has(t)) return false;
  const cur = Object.prototype.hasOwnProperty.call(map, t) ? map[t] : undefined;
  if (cur !== undefined && cur !== ik) {
    delete map[t]; delete names[t]; clashed.add(t);
    console.warn('[veil-group] two members map to one sender tag in this epoch — refused for both');
    return false;
  }
  map[t] = ik; names[t] = vid;
  return true;
}

/**
 * One pass over the group's envelopes + roster. The App layer calls this on
 * its poll cycle and keeps a known-id set so processed envelopes are skipped.
 */
export async function pollGroupInbox(
  depsIn: GroupSessionDeps,
  opts: { groupToken: string; identity: GroupIdentity; knownIds: Set<string>; events: GroupInboxEvents; sessionToken?: string; burnAfterOpen?: boolean;
          /** b54 (device test Oct 18): BACKGROUND PEEK for a closed thread —
           *  read-only. Reports new real messages via onMessage (text empty)
           *  so the app can notify, but consumes NOTHING: no recv/replay
           *  state, no known-ledger entry, no burn, no rekey, no cursor move.
           *  The open thread's normal pass processes and renders them later.
           *  (Before: the background pass consumed + burned the messages and
           *  they never rendered — "notification, nothing in the chat".) */
          peekOnly?: boolean;
          /** Batch C (A1): lets the creator publish the signed member list from the pass */
          clientId?: string;
          /** b77u (audit 6 RH-L2): checked after the envelope fetch, before any decrypt: true ends the pass with
           *  nothing processed, no cursor moved (the phone locked under "Hold until unlock", an account switch) */
          shouldAbort?: () => boolean },
): Promise<GroupInboxResult | null> {
  // b70 (re-review 2, D2-2): a wipe during this poll stops all its later reads and writes
  const deps: GroupSessionDeps = { ...depsIn, sessions: pinToWipe(depsIn.sessions), storage: pinToWipe(depsIn.storage) };
  const rec = (await loadGroupRecord(deps.storage, opts.groupToken)) ?? groupRecord(deps.storage, opts.groupToken);
  if (!rec) return null;
  // Batch D (D-08, RV-19): private groups only. b70: a leftover record of the removed
  // forum (purged at launch) would render its unknown senders unverified here.
  if (rec.role !== 'creator' && rec.role !== 'member') {
    console.warn('[veil-group] pollGroupInbox refused a non-private record', { role: rec.role, groupToken: rec.groupToken.slice(0, 6) });
    return null;
  }
  // b71 (review P-01): a joiner holds no group key until the creator admits its seat
  // and delivers one through the gate — collect it first (before any tag or name is
  // worked out for this pass, since the delivery may move the epoch)
  if (rec.role === 'member' && !rec.gekB64 && !opts.peekOnly && opts.sessionToken) {
    const got = await collectKeyDelivery(deps, rec, opts.sessionToken, opts.identity).catch((e) => {
      console.log('[veil-group] key delivery not collected yet:', String((e as Error)?.message ?? e));
      return false;
    });
    if (got) opts.events.onRotated(rec.epoch);
  }
  const keyless = rec.role === 'member' && !rec.gekB64;

  // b132: relay-side burn-after-open for groups. The veilSessionGate 'burn'
  // action authorises any envelope in this group against the CALLER's OWN
  // session credential (session.group_token === env.group_token clause —
  // builder-verified), so a receiving member can burn envelopes it has
  // definitively processed: the group twin of the pairwise burn-on-decrypt
  // in chat.ts. Without this, group envelopes sat at the full 24h submit
  // TTL no matter how many members opened them (owner repro: 5-min burn,
  // every relay row still +24h after both members opened everything).
  // b76r1 (audit AUD-G1): every envelope this phone has finished with is burned, WHATEVER ITS KIND, and all
  // at the same moment (the end of the envelope pass: burnQueue). Up to b76 rekey parts, member lists and
  // leaves were never burned while posts, receipts, intros and cover were burned by every reader, so the
  // relay told control messages from posts by who burned what — defeating the equal-size padding (a leave
  // was pinned exactly). Control messages are kept and applied on the phone, so the relay copy isn't needed
  // once this phone has read it; members who haven't read it yet are covered by the relay's group quorum
  // (spec §12.9: a group envelope's burn window starts only once EVERY admitted member other than its sender
  // has opened it — until then it keeps its normal expiry). Not burned, whatever the kind: own echoes (the
  // sender's copy serves the others), past-epoch rows (no key to read them), rows held or rejected (never
  // read), a rotation part this phone couldn't save (read again from the relay), seat intros (from a seat the relay
  // knows isn't admitted yet: nothing to hide, and the quorum doesn't count their sender), and anything during a peek.
  const burnCred = opts.burnAfterOpen && opts.sessionToken
    ? { token: opts.sessionToken, ws: (await deps.sessions.load(opts.sessionToken))?.writeSecret ?? null }
    : null;
  const burnEnvelope = async (id: string, what: string): Promise<void> => {
    if (!burnCred) return;
    try {
      // b134 (owner Metro log, Sept 27): every burn call — including ones
      // the builder confirmed DID shorten the relay row's TTL — logged
      // "no-op (unknown reason)". relay.invoke() (what sessionBurn calls)
      // returns the WRAPPER shape { data, status }, not the bare response
      // body — burned/reason live at res.data.burned / res.data.reason, one
      // level deeper than this was reading. res.burned was always
      // undefined, so this branch always fell through regardless of the
      // real outcome. Pure logging bug — the burn call itself was fine.
      const wrapped = (await deps.relay.sessionBurn(burnCred.token, burnCred.ws, id)) as { data?: { burned?: boolean; reason?: string } };
      const res = wrapped?.data ?? {};
      console.log(`[veil-group] burn ${what} ${id.slice(0, 8)}: ${res?.burned ? 'burned' : `no-op (${res?.reason ?? 'unknown reason'})`}`);
    } catch (e) {
      // Best-effort by design (same as web); a missed burn leaves the row
      // at its submit TTL. Logged with the id so Metro shows exactly which.
      console.log(`[veil-group] burn FAILED for ${id.slice(0, 8)} (${what}): ${(e as Error).message ?? e}`);
    }
  };
  /** b76r1 (audit AUD-G1): burns wait for the end of the envelope pass, so every kind goes out at the same moment */
  const burnQueue = new Map<string, string>();
  const queueBurn = (id: string, what: string): void => { if (burnCred && !opts.peekOnly) burnQueue.set(id, what); };

  // ---- roster (web's f()): members + senderKeys + tag->veilId names
  // b138: routed through veilGroupGate 'roster' (entity is admin-only now).
  if (!opts.sessionToken) throw new Error("Group roster requires this member's session.");
  const roster = await gateRoster(deps, { groupToken: opts.groupToken, sessionToken: opts.sessionToken });
  // b54 (Batch A, H-3): only attestation-verified, non-denied rows count —
  // they alone feed senderKeys (signature checks), names and the fingerprint.
  const memberRows = await verifiedRosterRows(rec, roster.members.map(asEnvelopeRow));
  if (memberRows.length < roster.members.length) {
    console.warn('[veil-group] roster rows failed verification and were ignored', { groupToken: opts.groupToken.slice(0, 6), dropped: roster.members.length - memberRows.length });
  }
  // b191 parity: the roster read is the only place a device with no pending
  // foreign-epoch envelope learns the group moved on without it — same
  // onEpochBehind as the envelope-path mismatch above.
  // b54 (device test Oct 18): RECORDED here, raised only after the envelope
  // pass — the rekey that catches this device up is usually in this very
  // page, and warning first showed a false "rejoin required" banner.
  // b71 (review P-01): a joiner still waiting for its key follows the relay's epoch
  // only to address its seat intro (it reads and sends nothing else), and re-sends
  // the intro at once when the epoch moved (the one it sent is now a past epoch)
  if (keyless && !opts.peekOnly && roster.epoch > rec.epoch) {
    rec.epoch = roster.epoch;
    rec.myTag = await senderTag(opts.groupToken, rec.epoch, rec.veilId);
    rec.sendN = 0;
    rec.introSentAt = 0;
    await saveGroupRecord(deps.storage, rec).catch((e) => console.log('[veil-group] epoch hint not saved:', String((e as Error)?.message ?? e)));
  }
  // b75 (audit GR-2): the roster's epoch is the relay's unsigned word. It only makes this phone
  // ask the creator for a key (harmless: the creator answers admitted members that are behind,
  // and a delivery is creator-signed). It no longer raises "behind", pauses sends or puts any
  // notice in the thread — those rest on a creator-signed rekey for a later epoch (signedAhead).
  const rosterAhead = !keyless && roster.epoch > rec.epoch ? roster.epoch : 0;
  /** b75 (audit GR-2): the newest epoch a creator-signed rekey read in this pass names but that
   *  this phone could not apply (applyRekeyPayload checks the signature before it returns false) */
  let signedAhead = 0;
  const members: GroupMemberRow[] = [];
  const tagToVeilId: Record<string, string> = {};
  // b71 (review P-03): names are worked out from signed bindings by refreshNames below
  const tagToNick: Record<string, string> = {};
  if (rec.myNick) tagToNick[rec.myTag] = rec.myNick;
  const senderKeys: Record<string, string> = {};
  /** b77u (audit 6 R4 #15): tags two different keys claimed in this epoch — 48 bits can be ground (a public tag is
   *  roster-computable ahead of an epoch), so a tag already mapped to another key is refused for both, never
   *  overwritten (the later mapping used to win silently) */
  const clashedTags = new Set<string>();
  /** b77u (audit 6 R4 #13): trusted members' public tags past the transition date — their posts are refused */
  const retiredPublicTags = new Set<string>();
  /** a trusted member's tags in one epoch: [keyed, public] (groupSenderTags); the public one only while allowed */
  const bindTrustedTags = (tags: string[], ik: string, vid: string): void => {
    const pubOk = publicTagPostsAllowed();
    tags.forEach((t, i) => {
      if (i > 0 && !pubOk) { retiredPublicTags.add(t); return; }
      bindSenderTag(senderKeys, tagToVeilId, clashedTags, t, ik, vid);
    });
  };
  /** b75 (audit GR-3): a member row's label comes from this phone's own state — the creator key it
   *  holds (the link's c=, or its own key on the creator's phone) and, on the creator's phone, its
   *  admitted list ('pending' rows below) — never from the relay's unsigned roster `role` (which the
   *  attestation doesn't cover: the relay could strip the real creator's label or show an admitted,
   *  key-holding member as "no group keys yet") */
  const creatorIkLocal = rec.creatorIkPubB64 ?? (rec.role === 'creator' ? rec.ikPubB64 : '');
  const localRole = (ik: string): 'creator' | 'member' => (ik && ik === creatorIkLocal ? 'creator' : 'member');
  // Batch C (A1): who counts as a member is decided by the CREATOR, never by
  // the relay roster. Creator: its admitted list (one IK per seat it minted,
  // proven with the seat's link secret). Member: the creator-signed list.
  // Batch E (round-3 review F-3): a pre-Batch-C creator record used to adopt the
  // relay roster on its first poll, so a relay that injected itself at that moment
  // got every later key. Now the roster is held aside and nobody on it is trusted
  // until the creator confirms (confirmLegacyRoster); meanwhile they show as pending.
  let membersChanged = !!rec.memberListDirty;
  if (rec.role === 'creator' && rec.admitted === undefined) {
    rec.admitted = {};
    const held: Record<string, string> = {};
    for (const m of memberRows) {
      const ik = String(m.IK_pub ?? ''), vid = String(m.veil_id ?? '');
      if (ik && vid && ik !== rec.ikPubB64) held[ik] = vid;
    }
    if (Object.keys(held).length) rec.legacyRoster = held;
    console.log('[veil-group] pre-Batch-C group: roster held for the creator to confirm', { groupToken: opts.groupToken.slice(0, 6), members: Object.keys(held).length });
  }
  const trusted = await trustedMembers(rec);
  /** creator only: roster-verified identities that are not admitted yet — their
   *  envelopes are read ONLY to find a seat-proven intro (see the loop) */
  const pendingKeys: Record<string, string> = {};
  const rosterIks = new Set<string>();
  /** b71 (audit F-13): a trusted member's tags in the record's epoch — the keyed one
   *  (what b71 senders use) and the public one (older builds; the relay fallback) */
  const trust = async (ik: string, vid: string): Promise<string> => {
    const tags = await groupSenderTags(rec, vid);
    bindTrustedTags(tags, ik, vid);
    return tags[0];
  };
  for (const m of memberRows) {
    const veilId = String(m.veil_id ?? '');
    const ikPub = String(m.IK_pub ?? '');
    if (!veilId || !ikPub) continue;
    rosterIks.add(ikPub);
    if (trusted && !trusted[ikPub]) {
      if (rec.role === 'creator' && !(rec.evictedIks ?? []).includes(ikPub)) {
        // (a joiner holds no key: its seat intro carries the public tag)
        const tag = await senderTag(opts.groupToken, rec.epoch, veilId);
        pendingKeys[tag] = ikPub;
        tagToVeilId[tag] = veilId;
        members.push({ veilId, nick: '', ikPub, role: 'pending', joinedEpoch: Number(m.joined_epoch ?? 0), tag, pending: true });
      }
      continue;
    }
    const tag = await trust(ikPub, veilId);
    members.push({ veilId, nick: '', ikPub, role: localRole(ikPub), joinedEpoch: Number(m.joined_epoch ?? 0), tag });
  }
  // trusted members the relay roster no longer lists still count (the relay
  // can't remove someone the creator admitted). b70 (audit VAR-11 / GRP-2): they
  // are SHOWN too, and counted in the fingerprint, because they receive every
  // new key: a relay that hides someone from the roster can't hide them from
  // the member list or from the creator's evict list.
  // b74 (VAR-05): creator — how long each trusted member has been missing from the roster
  const nowMs = Date.now();
  const missingBefore = JSON.stringify(rec.missingSince ?? {});
  if (rec.role === 'creator' && !opts.peekOnly) {
    const ms: Record<string, number> = {};
    for (const [ik, t0] of Object.entries(rec.missingSince ?? {})) if (trusted?.[ik] && !rosterIks.has(ik) && Number.isFinite(t0)) ms[ik] = t0;
    rec.missingSince = ms;
  }
  for (const [ik, vid] of Object.entries(trusted ?? {})) {
    if (rosterIks.has(ik)) continue;
    const tag = await trust(ik, vid);
    if (ik === rec.ikPubB64) continue;
    let goneSince: number | undefined;
    if (rec.role === 'creator' && !opts.peekOnly) {
      const since = rec.missingSince![ik] ?? (rec.missingSince![ik] = nowMs);
      if (nowMs - since >= GROUP_ABSENT_GRACE_MS) goneSince = since;
    }
    members.push({ veilId: vid, nick: '', ikPub: ik, role: localRole(ik), joinedEpoch: 0, tag, notOnRelay: true, ...(goneSince !== undefined ? { goneSince } : {}) });
  }
  if (rec.role === 'creator' && !opts.peekOnly && JSON.stringify(rec.missingSince ?? {}) !== missingBefore) {
    await saveGroupRecord(deps.storage, rec).catch((e) => console.log('[veil-group] roster absence not saved:', String((e as Error)?.message ?? e)));
  }
  // b75 (audit GR-1): members whose own signed leave this phone has read. They are not trusted here
  // (trustedMembers leaves them out, so they are not in senderKeys); their tags are kept so their
  // later posts are refused outright, and while the creator's list still names them they are shown
  // as leaving (they still get every new key until the creator removes them).
  const leavingKeys: Record<string, string> = {};
  if (rec.role === 'member') {
    for (const [ik, l] of Object.entries(rec.leftIks ?? {})) {
      if (!l || typeof l.vid !== 'string' || !l.vid) continue;
      const tags = await groupSenderTags(rec, l.vid);
      for (const t of tags) { leavingKeys[t] = ik; tagToVeilId[t] = l.vid; }
      if ((rec.memberList ?? {})[ik] && !(rec.evictedIks ?? []).includes(ik) && !members.some((m) => m.ikPub === ik)) {
        members.push({ veilId: l.vid, nick: '', ikPub: ik, role: localRole(ik), joinedEpoch: 0, tag: tags[0], leaving: true, ...(rosterIks.has(ik) ? {} : { notOnRelay: true }) });
      }
    }
  }
  /** b71 (audit F-13): every tag this phone may have posted under in this epoch */
  let ownTags = new Set<string>([rec.myTag, ...(rec.gekB64 ? await groupSenderTags(rec, rec.veilId) : [])]);
  rec.senderKeys = senderKeys;
  // b71 (review P-03): every shown name is recomputed from the record's bindings
  // (by key and Vardum ID, so tags from an older epoch don't matter): a listed name
  // (creator-signed list, self-signed entry) as is unless an earlier entry shows it;
  // a name seen only in a loose intro always with the ID suffix. Run again whenever
  // the bindings or the tags change in this pass.
  const refreshNames = (): void => {
    const people: Array<[string, string]> = [];
    for (const [t, ik] of [...Object.entries(senderKeys), ...Object.entries(pendingKeys), ...Object.entries(leavingKeys)]) if (tagToVeilId[t]) people.push([ik, tagToVeilId[t]]);
    people.push([rec.ikPubB64, rec.veilId]);
    const shown = shownGroupNames(rec, people);
    for (const k of Object.keys(tagToNick)) delete tagToNick[k];
    for (const [t, ik] of [...Object.entries(senderKeys), ...Object.entries(pendingKeys), ...Object.entries(leavingKeys)]) if (shown[ik]) tagToNick[t] = shown[ik];
    if (rec.myNick) tagToNick[rec.myTag] = rec.myNick;
  };
  // b71 (review P-01): creator — a seat minted before b71 gets its age now; an unused
  // seat past SEAT_MAX_AGE_MS is dropped (never admitted, and the record stays small)
  if (rec.role === 'creator' && !opts.peekOnly && rec.seats) {
    const now = Date.now();
    for (const [t, s] of Object.entries(rec.seats)) {
      if (!s || typeof s !== 'object') continue;
      if (s.at === undefined) rec.seats[t] = { ...s, at: now };
      else if (!s.usedBy && now - s.at > SEAT_MAX_AGE_MS) delete rec.seats[t];
    }
  }
  refreshNames();
  // (b75: the epoch fingerprint is worked out at the END of the pass, from the record as it is
  // then — a rekey, a key delivery, an admission or a removal in this pass changes it)

  // ---- envelopes (web's g()): oldest-first, skip known
  // b92 F10 (b91 audit): the group twin of the b87 pairwise stall — this
  // fetch had NO pagination cursor, so a group past 200 total envelopes
  // (cover traffic accumulates them fast) re-read the same oldest 200
  // forever and NEW group messages silently stopped arriving. Same rule
  // as syncChat: advance the per-group cursor ONLY on a full 200-row
  // page, by (page - margin); a partial page IS the live tail and must
  // stay re-scannable for freshness.
  // b70 (re-review 9): the saved numeric offset is gone. Once older rows left the relay
  // (expiry, burns, the sweeper) every later row shifted down and the offset skipped
  // rows that were never fetched, for good. Groups now page like the 1:1 chats:
  // newest-first down to the processed boundary, resuming at a row anchor.
  const GROUP_PAGE = 50;
  const GROUP_FETCH_PAGES = 10;
  const knownAtStart = new Set<string>(rec.knownEnvIds ?? []);
  const anchorRec = rec as GroupRecord & { backfillAnchor?: BackfillAnchor | null };
  /**
   * b73 (audit V-01): every row this pass looks at ends in one of three states.
   *  - PROCESSED (markKnown): shown, applied, or irrelevant for good (own, past epoch,
   *    malformed, foreign protocol).
   *  - REJECTED (reject = markKnown, never shown): can never become readable here —
   *    a sender tag that belongs to nobody on the relay's verified roster or this
   *    phone's trusted set, a seat intro or claim that doesn't check out, an epoch more
   *    than one past both this phone's and the relay's, a replay. Before b73 these stayed "retryable" for ever and were never marked,
   *    so about 500 of them on top of the thread (any seat holder could post them) made
   *    every pass hit the pager's cap and return nothing: the group went silent with no
   *    error.
   *  - HELD (hold): looked at, not readable YET, and may become readable — an epoch at most
   *    one past the newest this phone or the relay knows (its rekey or key delivery hasn't
   *    arrived), or a sender on the relay's verified roster this phone doesn't trust yet
   *    (its admission list hasn't arrived; the creator's pending claimants go through the
   *    claim check instead), or a post under a trusted member's tag whose signature or AEAD
   *    fails (it could be a damaged copy of a real post). Held ids (newest HELD_CAP = 300, rec.heldEnvIds; older ones are
   *    given up and marked processed) end the pager's descent
   *    like processed ones, so they can't hide newer rows, and are retried whenever
   *    fetched; after the trust state changes (epoch, list seq, trusted count) the next pass
   *    re-scans at least 5 pages so held rows below the first page are retried too.
   *  Only local failures (this phone's group state unreadable / unsaved) leave a row
   *  untouched, as before. Rejected and held rows are never shown, never burned, and never
   *  counted as messages.
   */
  const held = new Set<string>(rec.heldEnvIds ?? []);
  // b77t (audit 5 L-7 / IH C-2): rows held only on their unauthenticated header's "next epoch" go in their own
  // bucket (id -> header epoch), so a flood of them can't push a real held post out (see holdFuture)
  const heldFuture = new Map<string, number>((rec.heldFutureIds ?? [])
    .filter((h) => Array.isArray(h) && typeof h[0] === 'string' && Number.isSafeInteger(h[1]))
    .map((h) => [h[0], h[1]] as [string, number]));
  const heldKey = `${rec.epoch}:${rec.memberSeq ?? '-'}:${new Set(Object.values(senderKeys)).size}`;
  const rescan = !opts.peekOnly && !keyless && (held.size + heldFuture.size) > 0 && rec.heldStateKey !== heldKey;
  const backlog = await pageBacklog({
    fetchPage: async (skip, limit) => {
      const envRaw = await deps.relay.entityList('VeilEnvelope', { group_token: opts.groupToken, sort: '-created_date', limit, skip });
      const ed = envRaw as unknown[] | { data?: unknown[] };
      return (Array.isArray(ed) ? ed : ed.data ?? []).map((r) => (r ?? {}) as Record<string, unknown>);
    },
    isKnown: (id) => knownAtStart.has(id) || opts.knownIds.has(id),
    isHeld: (id) => held.has(id) || heldFuture.has(id), // b73 (audit V-01); b77t (audit 5 L-7)
    // b77t (audit 5 L-7): deep enough to reach every held row when there are many (pageBacklog keeps it below the cap)
    minPages: rescan ? Math.max(Math.ceil(GROUP_FETCH_PAGES / 2), Math.ceil((held.size + heldFuture.size) / GROUP_PAGE) + 1) : 0,
    pageSize: GROUP_PAGE,
    maxPages: GROUP_FETCH_PAGES,
    anchor: parseAnchor(anchorRec.backfillAnchor),
  });
  if (opts.shouldAbort?.()) return null; // b77u (audit 6 RH-L2): nothing decrypted, cached or announced
  // b71 (review P-01): a joiner without its key reads nothing yet — no cursor move,
  // nothing consumed; the backlog is read once the key is here
  if (!opts.peekOnly && !keyless) {
    if (backlog.anchor) anchorRec.backfillAnchor = backlog.anchor;
    else delete anchorRec.backfillAnchor;
  }
  const envelopes = keyless ? [] : backlog.rows.map(asEnvelopeRow); // oldest-first, unprocessed only

  // b71 (review P-01): a creator record from before b71 rotates once — its unused
  // invite links carry the current key (g=), which the rotation retires
  // b71 (audit F-02): and while an admitted member waits for the fresh epoch it is owed
  let needsRotation = rec.role === 'creator' && (groupNeedsRotation(rec) || !rec.linksV2 || Object.values(rec.joinEpochs ?? {}).some((e) => e > rec.epoch));
  /**
   * b71 (audit F-07): creator — a pending identity's seat intro checked out (seat proof,
   * signatures, seat lock and age; both intro kinds). It is NOT admitted here: the claim
   * is kept for the creator to approve or decline (admitGroupClaims / declineGroupClaim),
   * except a contact seat claimed by exactly the invited contact's key, which is admitted
   * after this pass (see admitClaimsNow). true = the claim is held (the envelope is done).
   * b73 (audit V-01): 'bad' = the claim doesn't check out (the envelope is rejected; a real
   * joiner re-sends its intro every 10 minutes while it waits); false = it checked out but
   * couldn't be saved (retried).
   */
  const takeClaim = async (ik: string, vid: string, e: { headerStr: string; ciphertextB64: string; ivB64: string; sessionToken?: string }): Promise<boolean | 'bad'> => {
    if (rec.pendingClaims && Object.prototype.hasOwnProperty.call(rec.pendingClaims, ik)) return true; // a re-send while it waits
    const claim = await checkSeatClaim(deps.storage, rec, { ik, veilId: vid, ...e })
      .catch((err) => { console.warn('[veil-group] seat claim not accepted', String((err as Error)?.message ?? err)); return null; });
    if (!claim) return 'bad';
    // b75r2 (audit R2G-01): checked again against the record as it is AFTER the claim check's waits — a claimant
    // removed, or a seat retired by a removal, meanwhile is not taken (approval would refuse it anyway)
    if (!claimStillValid(groupRecord(deps.storage, opts.groupToken) ?? rec, ik, claim)) return 'bad';
    // b77t (audit 5 I-18): pending claims are capped — per seat (one link held by someone minting identities, with
    // the relay, grew the record without bound) and in all. The first claims stay; later ones are refused.
    const pend = Object.values(rec.pendingClaims ?? {});
    if (pend.filter((c) => c.seat === claim.seat).length >= PENDING_CLAIMS_PER_SEAT || pend.length >= PENDING_CLAIMS_MAX) {
      console.warn('[veil-group] too many pending claims — refused', { groupToken: opts.groupToken.slice(0, 6) });
      return 'bad';
    }
    rec.pendingClaims = { ...(rec.pendingClaims ?? {}), [ik]: claim };
    try { await saveGroupRecord(deps.storage, rec); } catch (err) {
      delete rec.pendingClaims[ik];
      console.warn('[veil-group] seat claim not saved — retried next pass', String((err as Error)?.message ?? err));
      return false;
    }
    console.log('[veil-group] seat claim waiting for the creator', { groupToken: opts.groupToken.slice(0, 6), contact: !!claim.contact });
    return true;
  };

  // b92 F11 (b91 audit): mark known ONLY after a definitive outcome —
  // successful decrypt, or a permanently-irrelevant row (own envelope,
  // foreign protocol, malformed header, PAST epoch whose keys are gone by
  // design). Previously EVERY row was marked known up-front, so an
  // epoch-transition race (rekey payload landing later in the same fetch)
  // or a transient decrypt failure permanently swallowed a REAL message —
  // the exact bug class the Sept 19 audit fix removed from the pairwise
  // path. Future-epoch rows and failed decrypts stay RETRYABLE; the F10
  // cursor eventually retires them from the fetch window.
  const persistedKnown = new Set<string>(rec.knownEnvIds ?? []);
  let storageNoted = false; // Batch G (R5-2-03)
  /** b77q review (J2-1): opened this pass but the App could not keep them — held, not tried again this pass */
  const cacheRefused = new Set<string>();
  let staleNoted = false; // M-3 (b69 audit)
  /** b77u (audit 6 IH full I-4): record that this phone said "X joined"; false when it already had */
  const noteJoined = (ik: string): boolean => {
    const live = groupRecord(deps.storage, opts.groupToken) ?? rec;
    const k = ik.slice(0, 16), seen = live.joinNoted ?? [];
    if (seen.includes(k)) return false;
    live.joinNoted = [...seen, k].slice(-128);
    if (live !== rec) rec.joinNoted = live.joinNoted;
    return true;
  };
  const markKnown = (id: string): void => {
    opts.knownIds.add(id);
    persistedKnown.add(id);
    held.delete(id); // b73 (audit V-01)
    heldFuture.delete(id); // b77t (audit 5 L-7)
  };
  // b73 (audit V-01): see the three states above the pager
  const rejectedWhy: Record<string, number> = {};
  const reject = (id: string, why: string): void => {
    markKnown(id);
    rejectedWhy[why] = (rejectedWhy[why] ?? 0) + 1;
  };
  const hold = (id: string): void => { if (!opts.peekOnly) { held.add(id); heldFuture.delete(id); } };
  /** b77t (audit 5 L-7 / IH C-2): a row held only because its UNAUTHENTICATED header names the next epoch. Such rows
   *  used to share the held set, before any sender or signature check, and past HELD_CAP the OLDEST held ids — a real
   *  post waiting for its key among them — were marked known and never retried: 301 junk rows from any admitted
   *  member (or the relay) made a member lose it. Now they have their own bucket of FUTURE_HELD_CAP that drops its
   *  NEWEST first: once it is full a further row is kept only if its envelope signature checks out under the key of
   *  someone this phone trusts or the verified roster lists (then it is held with the real rows), and otherwise
   *  rejected. */
  let futureSigners: string[] | null = null;
  let futureChecks = 0;
  const holdFuture = async (id: string, ge: number, headerStr: string, ct: string, iv: string): Promise<void> => {
    if (opts.peekOnly || held.has(id)) return;
    if (heldFuture.has(id) || heldFuture.size < FUTURE_HELD_CAP) { heldFuture.set(id, ge); return; }
    if (!futureSigners) {
      const live = groupRecord(deps.storage, opts.groupToken) ?? rec;
      futureSigners = [...new Set([live.creatorIkPubB64 ?? '', ...Object.values(senderKeys), ...memberRows.map((m) => String(m.IK_pub ?? ''))]
        .filter((ik) => ik && ik !== live.ikPubB64))].slice(0, FUTURE_SIGNER_CHECK_MAX);
    }
    for (const [i, ik] of futureSigners.entries()) {
      // a flood can't buy unbounded signature work in one pass (the creator's key, first, is always tried: one
      // check a row, and the pager reads at most 500 rows a pass)
      if (i > 0 && futureChecks >= FUTURE_VERIFY_BUDGET) break;
      if (i > 0) futureChecks += 1;
      if (await verifyGroupEnvelopeSig(ik, headerStr, ct, iv).catch(() => false)) { held.add(id); return; }
    }
    reject(id, 'unverified next-epoch row past the cap');
  };
  /** b73 (audit V-01): the tags (keyed and public, this epoch) of every identity on the relay's
   *  verified roster or in the trusted set — an untrusted sender under one of them may yet be
   *  admitted (held); under none of them it is nobody this phone could ever trust (rejected) */
  const rosterTags = new Set<string>();
  let rosterTagsEpoch = -1;
  const isRosterTag = async (sid: string): Promise<boolean> => {
    const live = groupRecord(deps.storage, opts.groupToken) ?? rec;
    if (rosterTagsEpoch !== live.epoch) {
      rosterTags.clear();
      const vids = new Set<string>([...memberRows.map((m) => String(m.veil_id ?? '')), ...Object.values(trusted ?? {})].filter(Boolean));
      for (const vid of vids) for (const t of await groupSenderTags(live, vid)) rosterTags.add(t);
      rosterTagsEpoch = live.epoch;
    }
    return rosterTags.has(sid);
  };
  /** b73 (audit V-07): rotations (by rid) one of whose parts was refused in this pass */
  const refusedRids = new Set<string>();
  /** b75 (audit GR-5): a rotation made with a member list this phone hasn't received is kept (retried once
   *  that list arrives, below) — signed evidence the group moved on (signedAhead), never a refusal */
  const listWaitNoted = new Set<number>();
  /** b77q (audit 3 GR-2): the creator's phone contradicted the epoch this phone already took — sends stopped */
  const equivocationNote = (ge: number, sentAt: string) => ({ envelopeId: `rekey_equivocation_${opts.groupToken}_${ge}`, note: 'The group creator’s phone sent a key change that contradicts the one this phone already took for this step (another key, or the key given to someone else), so this phone has stopped sending with that key. New messages in this group wait until the next key change.', sentAt });
  /** b73 (audit V-07) / b75 (audit GR-1) / b76r1 (audit AUD-G2): say why a rotation was refused */
  const noteRefused = (e: GroupRekeyRecipientsError, ge: number, sentAt: string): void => {
    console.error('[veil-group] rekey refused', { epoch: ge, why: e.message });
    // b76r2 (audit R2-G1): an epoch refused earlier on this phone — the note was given when it was refused
    if (e.kind === 'already') return;
    if (e.kind === 'equivocation') { opts.events.onSystem(equivocationNote(ge, sentAt)); return; } // b77q (audit 3 GR-2)
    if (e.kind === 'conflict') {
      opts.events.onSystem({ envelopeId: `rekey_refused_${opts.groupToken}_${ge}`, note: 'The group creator’s phone sent two different key changes for the same step, so this phone didn’t take either. New messages in this group wait until the next key change.', sentAt });
      return;
    }
    if (e.kind === 'duplicate') { // b77u (audit 6 IH crypto F-2)
      opts.events.onSystem({ envelopeId: `rekey_refused_${opts.groupToken}_${ge}`, note: 'The group creator’s phone sent a key change with two copies of the new key for one member (the second copy could be made for someone else), so this phone didn’t take it. New messages in this group wait until the next key change.', sentAt });
      return;
    }
    if (e.kind === 'mismatch') {
      opts.events.onSystem({ envelopeId: `rekey_refused_${opts.groupToken}_${ge}`, note: 'The group creator\u2019s phone sent a key change whose parts don\u2019t agree on who gets the new key, so this phone didn\u2019t take it. New messages in this group wait until the next key change.', sentAt });
      return;
    }
    if (e.leavers.length) {
      // b75 (audit GR-1): the contradiction, said plainly — they said they are leaving, and the
      // creator's phone (after this phone learnt of it) still gave them the new key
      const nameOf = (vid: string) => { const t = Object.keys(leavingKeys).find((x) => tagToVeilId[x] === vid); return (t && tagToNick[t]) || vid.slice(0, 8); };
      const who = e.leavers.map((v) => noteName(nameOf(v))).join(', '); // b75r1 (audit G-2)
      opts.events.onSystem({ envelopeId: `rekey_refused_${opts.groupToken}_${ge}`, note: `The group creator’s phone sent the new group key to ${who}, who said they are leaving, so this phone didn’t take it. The creator’s phone may not have received the leave message. New messages in this group wait until the next key change.`, sentAt });
      return;
    }
    opts.events.onSystem({ envelopeId: `rekey_refused_${opts.groupToken}_${ge}`, note: 'The group creator\u2019s phone sent the new group key to someone who isn\u2019t on the member list, so this phone didn\u2019t take it. New messages in this group wait until the next key change.', sentAt });
  };
  /** a rotation was applied: sender tags (and names) move to the new epoch for the rest of this pass */
  const onRotationApplied = async (ge: number, envelopeId: string, sentAt: string): Promise<void> => {
    // Batch C: sender tags are per epoch — re-derive them so messages in
    // the new epoch later in this same page verify without waiting a pass
    // b70 (re-review 13): names move to the new tags too (b71: refreshNames below)
    const byKey = [...new Map(Object.entries(senderKeys).map(([tag, ik]) => [ik, tagToVeilId[tag]] as const)).entries()];
    const pendingByKey = Object.entries(pendingKeys).map(([tag, ik]) => [ik, tagToVeilId[tag]] as const);
    for (const k of Object.keys(senderKeys)) delete senderKeys[k];
    for (const k of Object.keys(pendingKeys)) delete pendingKeys[k];
    clashedTags.clear(); retiredPublicTags.clear(); // b77u (audit 6 R4 #13, #15): tags are per epoch
    // b71 (audit F-13): the new epoch's tags come from its key (the live record has it now)
    const liveRec = groupRecord(deps.storage, opts.groupToken) ?? rec;
    for (const [ik, vid] of byKey) {
      if (!vid) continue;
      const tags = await groupSenderTags(liveRec, vid, ge);
      bindTrustedTags(tags, ik, vid); // b77u (audit 6 R4 #13, #15)
      const m = members.find((x) => x.ikPub === ik); if (m) m.tag = tags[0];
    }
    ownTags = new Set<string>([liveRec.myTag, ...await groupSenderTags(liveRec, liveRec.veilId, ge)]);
    for (const [ik, vid] of pendingByKey) {
      if (!vid) continue;
      const t = await senderTag(opts.groupToken, ge, vid);
      pendingKeys[t] = ik; tagToVeilId[t] = vid;
      const m = members.find((x) => x.ikPub === ik); if (m) m.tag = t;
    }
    // b75 (audit GR-1): leavers' tags move to the new epoch too (their posts stay refused)
    const leavingByKey = [...new Map(Object.entries(leavingKeys).map(([tag, ik]) => [ik, tagToVeilId[tag]] as const)).entries()];
    for (const k of Object.keys(leavingKeys)) delete leavingKeys[k];
    for (const [ik, vid] of leavingByKey) {
      if (!vid) continue;
      for (const t of await groupSenderTags(liveRec, vid, ge)) { leavingKeys[t] = ik; tagToVeilId[t] = vid; }
    }
    rec.senderKeys = senderKeys;
    refreshNames();
    opts.events.onRotated(ge);
    // b73 (audit V-15): was "Group keys rotated — new post-quantum epoch." The new key is
    // delivered in ML-KEM-768 wraps, but the epoch key itself is not a post-quantum key
    opts.events.onSystem({ envelopeId, note: 'Group keys changed.', sentAt });
  };
  /**
   * b76r1 (audit AUD-G2): a rotation every part of which this phone holds — checked as a whole and applied
   * (finishRotation). Made with a member list this phone hasn't got (b75, audit GR-5): kept for when it
   * arrives, and meanwhile signed evidence the group moved on. Refused: said in the thread. No wrap for this
   * phone in any part: signed evidence the group moved on (the key is asked for through the gate).
   */
  /** b77u (audit 6 IH crypto F-2): this phone's own wrap doesn't open with its keys — only a console line before.
   *  Said in the thread; the key is asked for through the gate (signed evidence the group moved on). */
  const noteOwnWrap = (e: GroupOwnWrapError, ge: number, sentAt: string): void => {
    console.error('[veil-group] own rekey wrap did not open', { epoch: ge, why: e.message });
    signedAhead = Math.max(signedAhead, ge);
    opts.events.onSystem({ envelopeId: `own_wrap_${opts.groupToken}_${ge}`, note: 'This phone could not open its copy of the new group key. It may have been made for an older key of this phone, or for someone else’s key in your place. This phone asks the group creator for the key again.', sentAt });
  };
  const finishHeld = async (rid: string, ge: number, envelopeId: string, sentAt: string): Promise<boolean> => {
    let applied = false;
    try {
      applied = await finishRotation(deps.storage, opts.groupToken, rid, opts.identity.pqPrivB64);
    } catch (e) {
      if (e instanceof GroupRekeyListMissingError) {
        signedAhead = Math.max(signedAhead, ge);
        if (!listWaitNoted.has(ge)) {
          listWaitNoted.add(ge);
          console.log('[veil-group] rekey made with a member list this phone has not received — kept, waiting for the list', { groupToken: opts.groupToken.slice(0, 6), epoch: ge });
        }
        return false;
      }
      if (e instanceof GroupRekeyRecipientsError) { refusedRids.add(rid); noteRefused(e, ge, sentAt); return false; }
      if (e instanceof GroupOwnWrapError) { noteOwnWrap(e, ge, sentAt); return false; } // b77u (audit 6 IH crypto F-2)
      console.error('[veil-group] rekey apply failed', e);
      return false;
    }
    if (applied) { await onRotationApplied(ge, envelopeId, sentAt); return true; }
    const live = groupRecord(deps.storage, opts.groupToken) ?? rec;
    if (ge > live.epoch && live.rekeyRefusedEpoch !== ge) signedAhead = Math.max(signedAhead, ge);
    return false;
  };
  /** b76r1 (audit AUD-G2): rotations completed in this round of the pass — applied only after the round has read
   *  every row of the page under the OLD key, so another part of the same rotation further down the page (a
   *  second copy of a part number carrying other wraps, say) is seen before the key changes. Rows of the new
   *  epoch the round held are read in the next round, under the new key. */
  const readyRotations: Array<{ rid: string; ge: number; id: string; sentAt: string }> = [];
  /** b76r2 (audit R2-G1): the rotation ids of every creator-signed part kept in this pass, by epoch — an epoch with
   *  more than one is refused before any rotation of it is applied */
  const ridsByEpoch = new Map<number, Set<string>>();
  /** b74 (VAR-05): creator — members whose signed leave arrived in this pass (removed after it) */
  const leavers: Array<{ ikPub: string; veilId: string }> = [];
  /** b75r1 (audit G-1): members whose name change this pass already said out loud (a rename, a removal) */
  const renameNoted = new Set<string>();
  /** b71 (audit F-12): per sender (by key — tags change every epoch), posts numbered
   *  but missing in this pass; a late one fills a gap counted earlier */
  const seqGaps: Record<string, number> = {};
  const noteSeq = (sid: string, meta?: GroupPostMeta): void => {
    const ik = senderKeys[sid];
    if (!ik || !meta || !(meta.seq > 0)) return;
    const seen = rec.recvSeq ?? (rec.recvSeq = {});
    const prev = Object.prototype.hasOwnProperty.call(seen, ik) ? seen[ik] : undefined;
    if (prev === undefined) { seen[ik] = meta.seq; return; } // first post seen from them: the baseline
    if (meta.seq > prev) {
      if (meta.seq > prev + 1) seqGaps[ik] = (seqGaps[ik] ?? 0) + meta.seq - prev - 1;
      seen[ik] = meta.seq;
    } else if ((seqGaps[ik] ?? 0) > 0) seqGaps[ik] -= 1;
  };
  // b76r1 (audit AUD-G2): the page is read in rounds (at most 4) — a round that completes a rotation applies it at
  // its end and the next round reads what the new key opens (the inner loop is not re-indented, to keep the diff small)
  for (let round = 0; round < 4; round++) {
  for (const env of envelopes) {
    const id = String(env.id ?? '');
    if (!id || opts.knownIds.has(id) || persistedKnown.has(id) || cacheRefused.has(id)) continue;
    const expiresAt = env.expires_at ? String(env.expires_at) : null;
    if (expiresAt && new Date(expiresAt).getTime() < Date.now()) continue;
    const headerStr = String(env.header ?? '');
    let header: { v?: string; sid?: string; ge?: number; sv?: number };
    if (!headerStr) { markKnown(id); queueBurn(id, 'malformed'); continue; } // malformed — never improves
    try { header = JSON.parse(headerStr); } catch { markKnown(id); queueBurn(id, 'malformed'); continue; }
    if (header.v !== GROUP_PROTO) {
      // b77m review (INFO): another veil-group-N version is said in the thread, not dropped silently.
      // b77n (pre-audit LOW-2): the tag is unauthenticated, so at most ONE note per group (one id, whatever
      // the version), only for a version within ours +-2, worded as unverified (groupProtoMismatchNote)
      const note = groupProtoMismatchNote(header.v);
      if (note && !opts.peekOnly) opts.events.onSystem({ envelopeId: `proto_${opts.groupToken}`, note, sentAt: relayTimestampToIso(env.created_date as string | undefined) });
      markKnown(id); queueBurn(id, 'foreign-proto'); continue; // permanently irrelevant to this build
    }
    // b77q (audit 3 GR-5): the sender tag is checked before it indexes anything — '__proto__' or 'constructor' found
    // an inherited value in senderKeys, passed the trusted-sender gate, and was held and reported as a forgery
    if (typeof header.sid !== 'string' || !/^g[0-9a-f]{12}$/.test(header.sid)) { markKnown(id); queueBurn(id, 'malformed'); continue; }
    const ge = Number(header.ge);
    // b71 (review P-01): a SEAT INTRO (keyed by its seat's link secret, not the group
    // key). Only the creator can open it, to admit; for everyone else it is
    // permanently irrelevant. Handled for any epoch: a joiner may have sent it just
    // before a rotation.
    if (Number(header.sv) === GROUP_SEAT_SIG_VERSION) {
      if (opts.peekOnly) continue;
      if (rec.role !== 'creator') { markKnown(id); continue; }
      const sid = String(header.sid ?? '');
      if (ownTags.has(sid) || senderKeys[sid]) { markKnown(id); continue; } // a re-send from someone already in
      // the pending identity this tag belongs to (tags are per epoch)
      let pend: [string, string] | null = null;
      for (const [t, ik] of Object.entries(pendingKeys)) {
        const vid = tagToVeilId[t] ?? '';
        if (vid && (t === sid || await senderTag(opts.groupToken, ge, vid) === sid)) { pend = [t, ik]; break; }
      }
      // nobody pending under this tag: an admitted member's re-send from an older epoch, or
      // someone the relay's verified roster doesn't list as waiting. b73 (audit V-01): rejected
      // (it used to stay "for a later pass" for ever; a real joiner re-sends every 10 minutes)
      if (!pend) { reject(id, 'seat intro from nobody waiting'); continue; }
      const [pendTag, pendIk] = pend;
      const pendVid = tagToVeilId[pendTag] ?? '';
      // b71 (audit F-07): a checked claim waits for the creator. b73 (audit V-01): one that
      // doesn't check out is rejected (it used to stay retryable for ever)
      const claimed = await takeClaim(pendIk, pendVid, { headerStr, sessionToken: String(env.session_token ?? ''), ciphertextB64: String(env.ciphertext ?? ''), ivB64: String(env.iv ?? '') });
      if (claimed === true) markKnown(id);
      else if (claimed === 'bad') reject(id, 'seat claim that does not check out');
      continue;
    }
    // b123: my OWN envelope — read the payload back (own GEK, no recv
    // bookkeeping) and emit the id so the App layer can bind envId to the
    // locally-sent bubble; group read receipts then work like pairwise.
    if (ownTags.has(String(header.sid ?? ''))) { // b71 (audit F-13): either of my tags
      // b70 (audit GRP-6): an envelope under MY tag must carry MY signature.
      // Another member posting under my tag used to be hidden here as my own
      // echo, while everyone else saw a signature failure "from me".
      // (current epoch only: older envelopes are past their keys and only marked known)
      if (ge === rec.epoch && !(await verifyGroupEnvelopeSig(rec.ikPubB64, headerStr, String(env.ciphertext ?? ''), String(env.iv ?? '')))) {
        console.warn('[veil-group] an envelope used my sender tag without my signature — discarded', { groupToken: opts.groupToken.slice(0, 6) });
        markKnown(id);
        opts.events.onSenderVerifyFailed(id, 'signature');
        continue;
      }
      if (opts.events.onOwnEcho && ge === rec.epoch) {
        try {
          const own = await decryptOwnGroupEnvelope(deps.storage, opts.groupToken, headerStr, String(env.ciphertext ?? ''), String(env.iv ?? ''));
          if (!own.cover && own.text && !own.text.startsWith('{"__veil_intro"')) opts.events.onOwnEcho(id, own.text);
        } catch { /* cover / malformed own envelope — nothing to bind */ }
      }
      markKnown(id); continue;
    }
    if (ge !== rec.epoch) {
      // b191 parity: shell Oct 12 — a foreign epoch used to vanish with NO
      // trace. Trace both sides + deviceBehind; a NEWER epoch means this
      // device missed a rekey and is blind in both directions, so surface it
      // (onEpochBehind) instead of dropping silently forever.
      if (ge < rec.epoch) { markKnown(id); continue; } // past epoch — keys gone by design
      // b73 (audit V-01): the header's epoch is unauthenticated. More than one past both this
      // phone's epoch and the relay's can't be a real post (the creator moves one epoch at a
      // time, after the relay): rejected. Otherwise held until its rekey or key delivery lands.
      if (ge > Math.max(rec.epoch, roster.epoch) + 1) { reject(id, 'epoch out of reach'); continue; }
      console.log('[veil-group] epoch mismatch', { groupToken: opts.groupToken.slice(0, 8), envelopeId: id, senderEpoch: ge, localEpoch: rec.epoch, deviceBehind: true });
      // b73 (audit V-01): only an epoch the relay also reports raises "behind" (a forged
      // header one past it no longer shows the rejoin notice or files key requests)
      // b75 (audit GR-2): the header's epoch is unauthenticated, and so is the roster's: neither
      // raises "behind" any more (b73 raised it when the two agreed). The row is held until its
      // rekey or key delivery lands; a creator-signed rekey is what raises "behind".
      await holdFuture(id, ge, headerStr, String(env.ciphertext ?? ''), String(env.iv ?? '')); // b77t (audit 5 L-7)
      continue; // future epoch — RETRYABLE until the rekey envelope lands (b73 (audit V-01): held)
    }

    // Batch C (A1): a sender the creator has not admitted. Nothing is rendered
    // and nothing is consumed (retryable: it renders once the member is on the
    // creator-signed list). The creator reads such an envelope read-only, and
    // only to find a seat-proven intro to admit.
    {
      const sid = String(header.sid ?? '');
      if ((rec.role === 'creator' || rec.role === 'member') && !senderKeys[sid]) {
        // b77u (audit 6 R4 #13): past the transition date a trusted member's PUBLIC tag is read on seat intros only;
        // R4 #15: a tag two keys claim belongs to neither. Both are refused (not held for a later pass).
        if (retiredPublicTags.has(sid)) { if (!opts.peekOnly) reject(id, 'post under a public sender tag'); continue; }
        if (clashedTags.has(sid)) { if (!opts.peekOnly) reject(id, 'sender tag two members claim'); continue; }
        // b75 (audit GR-1): a member who said it is leaving is not trusted here any more — its posts
        // are refused (never shown as a member's), whatever the creator's list still says
        if (leavingKeys[sid]) { if (!opts.peekOnly) reject(id, 'post from a member who said they are leaving'); continue; }
        if (!opts.peekOnly && rec.role === 'creator' && pendingKeys[sid]) {
          // Batch D (D-08): one malformed intro can never stall the pass
          // (b71: this path is the intro of a joiner from an older build — it holds the key
          // from a pre-b71 link and sent its intro under it. b71 (audit F-07): a claim too.)
          // b73 (audit V-01): anything else a waiting claimant posts is rejected
          const claimed = await takeClaim(pendingKeys[sid], tagToVeilId[sid] ?? '', { headerStr, ciphertextB64: String(env.ciphertext ?? ''), ivB64: String(env.iv ?? '') });
          if (claimed === true) markKnown(id);
          else if (claimed === 'bad') reject(id, 'post from a claimant not let in');
        } else if (!opts.peekOnly) {
          // b73 (audit V-01): someone on the relay's verified roster may still be admitted (held);
          // a tag that belongs to nobody known can never be trusted (rejected)
          if (await isRosterTag(sid)) hold(id);
          else reject(id, 'sender tag of nobody known');
        }
        continue;
      }
    }

    if (opts.peekOnly) {
      // b54: read-only — notify for real messages from verified members only;
      // everything stays unconsumed for the open thread's pass.
      const sid = String(header.sid ?? '');
      // Batch C (A2): the peek checks the full v2 signature (it covers the ciphertext)
      const signedByMember = !!senderKeys[sid]
        && await verifyGroupEnvelopeSig(senderKeys[sid], headerStr, String(env.ciphertext ?? ''), String(env.iv ?? ''));
      if ((rec.role === 'creator' || rec.role === 'member') && !signedByMember) continue;
      // b77u (audit 6 R4 #16): a post past the read limit is not shown, so it doesn't notify either
      { const st = epochStartMs(rec); if (rec.role === 'member' && st !== null && Date.now() - st > MEMBER_EPOCH_READ_MAX_MS) continue; }
      try {
        const peek = await decryptOwnGroupEnvelope(deps.storage, opts.groupToken, headerStr, String(env.ciphertext ?? ''), String(env.iv ?? ''));
        const control = /^\{"__veil_(receipt|intro|group_rekey|remove|report|group_members|group_leave)":/.test(peek.text); // Batch E (F-11); b74: + leave
        if (!peek.cover && peek.text && !control) {
          opts.events.onMessage({
            envelopeId: id, text: '', senderTag: sid, senderVeilId: tagToVeilId[sid] ?? null, senderNick: tagToNick[sid] ?? null,
            senderVerified: signedByMember, sentAt: relayTimestampToIso(env.created_date as string | undefined), expiresAt,
          });
        }
      } catch { /* not decryptable yet — the open thread's pass will retry */ }
      continue;
    }

    let out;
    try {
      out = await decryptGroupMessage(deps.storage, opts.groupToken, headerStr, String(env.ciphertext ?? ''), String(env.iv ?? ''), String(env.session_token ?? '') || undefined);
    } catch (e) {
      // b92 F11: NOT marked known — a transient failure (rekey race,
      // momentary roster gap behind a sender-signature check) must stay
      // retryable, exactly like the pairwise path post Sept 19.
      // b73 (audit V-01): both of those are handled before this point now (a future epoch
      // is held above; an untrusted sender never reaches the decrypt). A replayed or
      // out-of-window counter is final (rejected). A bad signature or a ciphertext that
      // doesn't open under a trusted member's tag is HELD, not rejected: the sender is
      // trusted, and a relay serving a damaged copy of a real post must not make this phone
      // give the post up for good — held rows end the pager's descent all the same, so they
      // can't pile up and hide newer rows (past HELD_CAP they are given up). Only a failure of
      // this phone's own group state is left untouched, as before.
      const failMsg = String((e as Error)?.message ?? e);
      if (/replayed or too-old|counter jump too large/i.test(failMsg)) reject(id, 'replay');
      else if (!/not established|could not be read|could not be saved/i.test(failMsg)) hold(id);
      if (/veil-group-sig/i.test((e as Error).message ?? '')) {
        console.error('Group sender signature failed — envelope discarded', { envelopeId: id });
        opts.events.onSenderVerifyFailed(id, 'signature');
      } else {
        const dmsg = String((e as Error).message ?? 'unknown');
        // b191 parity: replay rejections stay SILENT (normal re-scan result —
        // the poll re-reads the live tail every pass, so a pre-rotation row
        // correctly refuses forever and must not spam the log); a REAL
        // key/counter failure is traced + surfaced instead of silently missing messages
        // (b75 (audit GR-2): the App no longer advises rejoining). b198: the
        // console.error moved INSIDE the guard — it was logging replays too.
        if (!/replayed or too-old/i.test(dmsg)) {
          console.error('[veil-group] envelope decrypt failed', { envelopeId: id, msg: dmsg });
          opts.events.onDecryptFailed?.({ groupToken: opts.groupToken, err: dmsg });
        }
      }
      continue;
    }

    markKnown(id); // b92 F11: definitive outcome — safe to record now
    queueBurn(id, 'opened'); // b76r1 (audit AUD-G1): every kind alike (a rotation part this phone couldn't save is taken back below)
    // Batch G (R5-2-03): tell the thread once when the phone refused to save the group state
    if (out.stateNotSaved && !storageNoted) {
      storageNoted = true;
      opts.events.onSystem({ envelopeId: `storage_${opts.groupToken}`, note: 'This phone’s storage refused to save this group’s state. Messages still open, but some of it is only kept until the app closes. Free up space, then reopen the group.', sentAt: new Date().toISOString() });
    }
    // Batch E (N3-5): the rotation counter is a heuristic; a storage error must not abort the pass
    await bumpGroupEnvCount(deps.storage, opts.groupToken).catch((e) => console.log('[veil-group] envelope counter not saved:', String((e as Error)?.message ?? e)));
    if (out.cover) continue; // cover traffic — never rendered (burned like everything else: queueBurn above)
    // b71 (audit F-12): the sender's signed sequence — a jump means posts that never
    // reached this phone (the relay may be holding them back); counted before any
    // control message is applied (rekeys and member lists are numbered too)
    noteSeq(String(header.sid), out.meta);

    // rekey? (b76r1, audit AUD-G1: burned like any other envelope once this phone has kept it — the
    // relay's group quorum keeps it for members who haven't read it yet)
    const rekey = parseRekeyPayload(out.text);
    if (rekey === 'invalid') {
      console.error('[veil-group] unsigned or malformed rekey dropped', { envelopeId: id });
      continue;
    }
    if (rekey) {
      // b77s (audit 4 GR-01): only the creator posts key changes into the group. Any other member holds the
      // current key and could re-post a creator-signed text it was given (its own gate delivery, say, which
      // carries the epoch's key under another rotation id): read here, it looked like the creator contradicting
      // itself about the applied epoch and stopped every member's sends. A rekey text is acted on only when
      // the envelope's verified signer is the creator; anyone else's is dropped unread (burned like any post).
      const creatorIk = (groupRecord(deps.storage, opts.groupToken) ?? rec).creatorIkPubB64;
      if (!creatorIk || out.signerIk !== creatorIk) {
        console.warn('[veil-group] a key change posted by someone other than the group creator — ignored', { envelopeId: id });
        continue;
      }
      // b73 (audit V-07): one refused part taints its whole rotation
      if (refusedRids.has(rekey.rid)) { console.warn('[veil-group] another part of a refused rotation — ignored', { envelopeId: id }); continue; }
      const sentAt = relayTimestampToIso(env.created_date as string | undefined);
      // b76r1 (audit AUD-G2): every part of a rotation is kept (by rid) and the rotation is checked and
      // applied only once ALL its parts are here — the old key stays until then. b76 applied the part with
      // this phone's wrap at once and never opened the parts after it (sent under the key it had just
      // replaced), so a ghost wrap in the last part passed every member.
      let got;
      try {
        got = await collectRotationPart(deps.storage, opts.groupToken, rekey, out.text);
      } catch (e) {
        if (e instanceof GroupRekeyRecipientsError) {
          refusedRids.add(rekey.rid);
          // b76r2 (audit R2-G1): two rotations of one epoch — every rotation of that epoch is refused
          if (e.kind === 'conflict') for (const r of ridsByEpoch.get(rekey.ge) ?? []) refusedRids.add(r);
          noteRefused(e, rekey.ge, sentAt);
        }
        else console.error('[veil-group] rekey part refused', { envelopeId: id, why: String((e as Error)?.message ?? e) });
        continue;
      }
      if (got.state === 'stale') continue;
      { const s = ridsByEpoch.get(got.ge) ?? new Set<string>(); s.add(got.rid); ridsByEpoch.set(got.ge, s); } // b76r2 (audit R2-G1)
      if (!got.saved) {
        burnQueue.delete(id); // kept in memory only: the relay copy stays for a later pass
        // b77t (audit 5 L-9 / IH C-3): its counter was already saved (the small ~recv item), so after a restart the
        // relay copy was refused as a replay and the rotation could never complete from its parts. Put it back.
        if (!(await reopenGroupCounter(deps.storage, opts.groupToken, headerStr))) console.error('[veil-group] an unsaved rotation part could not be put back for a later pass', { envelopeId: id });
      }
      if (got.state === 'complete' && !readyRotations.some((r) => r.rid === got.rid)) readyRotations.push({ rid: got.rid, ge: got.ge, id, sentAt });
      continue;
    }

    // Batch C (A1): the creator-signed member list
    const memberMsg = parseMembersPayload(out.text);
    if (memberMsg === 'invalid') { console.error('[veil-group] malformed member list dropped', { envelopeId: id }); continue; }
    if (memberMsg) {
      if (rec.role === 'member') {
        try {
          const listedBefore = rec.memberSeq ? new Set(Object.keys(rec.memberList ?? {})) : null;
          const listBefore: Record<string, string> = { ...(rec.memberList ?? {}) };
          const removedBefore = rec.removedFromGroup; // b75r1 (audit G-7)
          const renamed: { renames: GroupRename[]; ghosts?: GroupDeliveryGhost[] } = { renames: [] };
          /** b74 (VAR-06): the names shown before this list, by key (for "X renamed to Y") */
          const shownBefore: Record<string, string> = {};
          for (const [t, ik] of [...Object.entries(senderKeys), ...Object.entries(leavingKeys)]) if (tagToNick[t] && !shownBefore[ik]) shownBefore[ik] = tagToNick[t];
          if (await applyMembersPayload(deps.storage, opts.groupToken, memberMsg, renamed)) {
            console.log('[veil-group] creator-signed member list applied', { groupToken: opts.groupToken.slice(0, 6), seq: memberMsg.seq, members: memberMsg.members.length });
            // trust the listed members for the rest of this pass too (their
            // messages later in this page render now, not on the next pass)
            for (const [ik, vid] of Object.entries(groupRecord(deps.storage, opts.groupToken)?.memberList ?? {})) {
              if ((rec.evictedIks ?? []).includes(ik)) continue;
              if (Object.prototype.hasOwnProperty.call(rec.leftIks ?? {}, ik)) continue; // b75 (audit GR-1)
              const tags = await groupSenderTags(rec, vid); // b71 (audit F-13): keyed + public
              if (senderKeys[tags[0]]) continue;
              bindTrustedTags(tags, ik, vid); // b77u (audit 6 R4 #13, #15)
              const row = members.find((m) => m.ikPub === ik);
              if (!row) members.push({ veilId: vid, nick: '', ikPub: ik, role: localRole(ik), joinedEpoch: rec.epoch, tag: tags[0] });
            }
            // b73 (audit V-08): and stop trusting anyone the new list dropped, for the rest of
            // this pass too (a removed member's post later in this same page used to render as
            // verified; one pass later it was refused)
            const nowTrusted = await trustedMembers(groupRecord(deps.storage, opts.groupToken) ?? rec);
            if (nowTrusted) {
              for (const [t, ik] of Object.entries(senderKeys)) if (!nowTrusted[ik]) delete senderKeys[t];
              const listedNow = groupRecord(deps.storage, opts.groupToken)?.memberList ?? {};
              for (let i = members.length - 1; i >= 0; i--) if (!members[i].pending && !nowTrusted[members[i].ikPub] && !(members[i].leaving && listedNow[members[i].ikPub])) members.splice(i, 1);
            }
            rec.senderKeys = senderKeys;
            refreshNames(); // b71 (review P-03): the names the list carries
            // b77m review (L2): a gate delivery taken before this list, now checked against it
            for (const g of renamed.ghosts ?? []) {
              console.error('[veil-group] a delivered group key was given to someone not on the member list', { epoch: g.ge, stray: g.stray.length, mismatch: g.mismatch });
              opts.events.onSystem({ envelopeId: `ghost_key_${opts.groupToken}_${g.ge}`, note: g.warnOnly ? GHOST_KEY_MISMATCH_WARN_NOTE : g.mismatch // b77q owner (1 Nov)
                ? GHOST_KEY_MISMATCH_NOTE
                : 'The group creator’s phone gave the group key it sent this phone to someone who isn’t on the member list, so this phone has stopped sending with that key. New messages wait until the next key change.', sentAt: relayTimestampToIso(env.created_date as string | undefined) });
            }
            // b74 (VAR-06): every rename is said out loud, with the names as shown
            for (const [ik, oldName, newName] of renamed.renames) {
              if (ik === rec.ikPubB64) continue;
              const t = Object.keys(senderKeys).find((x) => senderKeys[x] === ik);
              const was = shownBefore[ik] || oldName;
              const now = (t && tagToNick[t]) || newName;
              renameNoted.add(ik); // b75r1 (audit G-1)
              // b75r1 (audit G-2): names in a notice are quoted and isolated (noteName)
              opts.events.onSystem({ envelopeId: `${id}_rn_${ik.slice(0, 8)}`, note: `${noteName(was)} renamed to ${noteName(now)}`, sentAt: relayTimestampToIso(env.created_date as string | undefined) });
            }
            // b75r1 (audit G-1): a member the creator REMOVED (dropped by the list, no leave of theirs read here)
            // is said out loud — b75 said nothing on members' phones, so whoever had parked on that member's name
            // silently became the only one shown with it (the name is also held back: holdFreedName)
            if (listedBefore) {
              const listedNow = rec.memberList ?? {};
              for (const ik of listedBefore) {
                if (listedNow[ik] || ik === rec.ikPubB64 || Object.prototype.hasOwnProperty.call(rec.leftIks ?? {}, ik)) continue;
                renameNoted.add(ik);
                opts.events.onSystem({ envelopeId: `${id}_rm_${ik.slice(0, 8)}`, note: `${noteName(shownBefore[ik] || String(listBefore[ik] ?? '').slice(0, 8))} was removed from the group by the group creator.`, sentAt: relayTimestampToIso(env.created_date as string | undefined) });
              }
            }
            // b75r1 (audit G-7): this phone's own removal, said plainly (b75 said "the group creator removed someone")
            if (removedBefore === undefined && (groupRecord(deps.storage, opts.groupToken) ?? rec).removedFromGroup !== undefined) {
              opts.events.onSystem({ envelopeId: `removed_me_${opts.groupToken}`, note: 'The group creator removed you from this group. You won’t get its new keys, so you can’t read or send new messages here.', sentAt: relayTimestampToIso(env.created_date as string | undefined) });
            }
            // b75 (audit GR-1): a member who said it was leaving has LEFT once a creator-signed list drops
            // it (until then this phone said only "says they are leaving"); its kept leave text goes
            if (listedBefore) {
              const listedNow = rec.memberList ?? {};
              for (const ik of listedBefore) {
                const l = rec.leftIks && Object.prototype.hasOwnProperty.call(rec.leftIks, ik) ? rec.leftIks[ik] : undefined;
                if (!l || listedNow[ik]) continue;
                const t = Object.keys(leavingKeys).find((x) => leavingKeys[x] === ik);
                opts.events.onSystem({ envelopeId: `${id}_lf_${ik.slice(0, 8)}`, note: `${noteName(shownBefore[ik] || (t && tagToNick[t]) || l.vid.slice(0, 8))} left the group.`, sentAt: relayTimestampToIso(env.created_date as string | undefined) });
                rec.leftIks![ik] = { vid: l.vid, at: l.at, ...(l.ep !== undefined ? { ep: l.ep } : {}) }; // b77q review (GR-6): keeps ep
                const row = members.findIndex((m) => m.ikPub === ik); if (row >= 0) members.splice(row, 1);
              }
            }
            // b71 (review P-01): seat intros are the creator's alone now, so members learn
            // of a newcomer from the list (not on this phone's first list: that is everyone)
            if (listedBefore) {
              for (const [ik, vid] of Object.entries(rec.memberList ?? {})) {
                if (listedBefore.has(ik) || ik === rec.ikPubB64) continue;
                // b71 (audit F-12): a newcomer numbers its posts from 1 — a missing first post counts
                if (rec.recvSeq?.[ik] === undefined) rec.recvSeq = { ...(rec.recvSeq ?? {}), [ik]: 0 };
                const t = Object.keys(senderKeys).find((x) => senderKeys[x] === ik);
                opts.events.onSystem({ envelopeId: `${id}_${ik.slice(0, 8)}`, note: `${noteName((t && tagToNick[t]) || vid.slice(0, 8))} joined the group`, sentAt: relayTimestampToIso(env.created_date as string | undefined) });
                noteJoined(ik); // b77u (audit 6 I-4)
              }
            }
          }
        } catch (e) {
          // b77u (audit 6 IH crypto F-3): two signed lists under one number — said once in the thread
          if (e instanceof GroupListConflictError) {
            console.error('[veil-group] two different member lists under one number', { envelopeId: id, seq: e.seq });
            opts.events.onSystem({ envelopeId: `list_conflict_${opts.groupToken}_${e.seq}`, note: 'The group creator’s phone sent two different member lists under the same number. This phone kept the first one it got; other members may have been shown the other. Compare the group’s epoch fingerprint with the other members.', sentAt: relayTimestampToIso(env.created_date as string | undefined) });
            continue;
          }
          const msg = String((e as Error)?.message ?? e);
          if (/could not be saved/i.test(msg)) {
            // b77t (audit 5 L-9): this phone couldn't save it — not a refusal. Held and read again (its counter goes
            // back in the window; it had been saved on its own), instead of being lost until the next list
            console.warn('[veil-group] member list not saved — read again next pass', { envelopeId: id });
            opts.knownIds.delete(id); persistedKnown.delete(id); burnQueue.delete(id); hold(id);
            await reopenGroupCounter(deps.storage, opts.groupToken, headerStr);
          } else {
            console.error('[veil-group] member list refused', { envelopeId: id, msg });
            opts.events.onSenderVerifyFailed(id, 'list');
          }
        }
      }
      continue;
    }

    // b74 (VAR-05): a member's signed leave. It must be signed by the key its sender tag is
    // trusted under (and name that key). The creator removes the leaver exactly as on a
    // Remove tap — deny entry, removal notice in the signed member list, key rotation —
    // once this pass is done; everyone else shows a note. b76r1 (audit AUD-G1): burned like any envelope once
    // read (b74-b76 never burned it, which pinned every leave for the relay); the relay's quorum keeps it until
    // every member — the creator included — has read it.
    const leave = parseLeavePayload(out.text);
    if (leave === 'invalid') { console.error('[veil-group] malformed leave dropped', { envelopeId: id }); continue; }
    if (leave) {
      const sidKey = String(header.sid);
      // b75 (audit GR-1): a leave may come from the leaver itself, or be RE-POSTED by another trusted
      // member (members re-post every leave they read, so the creator gets it even if the relay held
      // the leaver's own post back from it). Either way it must be signed by the key it names, for
      // this group; from the leaver itself it must also be the key and ID its tag is trusted under.
      if (leave.ik === rec.ikPubB64) continue; // someone re-posted my own leave: nothing to do
      const own = leave.ik === senderKeys[sidKey];
      const okLeave = (!own || leave.id === tagToVeilId[sidKey]) && leave.ik !== creatorIkLocal && await verifyLeavePayload(opts.groupToken, leave);
      if (!okLeave) {
        console.error('[veil-group] leave does not match its sender — dropped', { envelopeId: id });
        opts.events.onSenderVerifyFailed(id, 'leave');
        continue;
      }
      // who it is, as this phone counts members (someone already removed or never let in: nothing to do)
      const isMember = rec.role === 'creator'
        ? rec.admitted?.[leave.ik] === leave.id && !(rec.evictedIks ?? []).includes(leave.ik)
        : (rec.memberList ?? {})[leave.ik] === leave.id && !(rec.evictedIks ?? []).includes(leave.ik);
      if (!isMember) continue;
      const leaverTag = Object.keys(senderKeys).find((t) => senderKeys[t] === leave.ik) ?? Object.keys(leavingKeys).find((t) => leavingKeys[t] === leave.ik);
      const who = (leaverTag && tagToNick[leaverTag]) || leave.id.slice(0, 8);
      if (rec.role === 'creator') {
        if (!leavers.some((l) => l.ikPub === leave.ik)) {
          leavers.push({ ikPub: leave.ik, veilId: leave.id });
          // b75 (audit GR-1): "they can't read what is sent from now on" is said only once the rotation
          // that leaves them out has completed (end of the pass, or a later one) — not before it ran
          if (!(rec.leaveNotesOwed ?? []).some((x) => x[0] === leave.ik)) rec.leaveNotesOwed = [...(rec.leaveNotesOwed ?? []), [leave.ik, who] as [string, string]].slice(-16);
          opts.events.onSystem({ envelopeId: `${id}_leaving`, note: `${noteName(who)} says they are leaving. Removing them and changing the group keys…`, sentAt: relayTimestampToIso(env.created_date as string | undefined) });
        }
      } else if (leave.e > rec.epoch) {
        // b77q review (GR-6): a leave signed for an epoch this phone isn't on, read under this epoch's key, is no
        // honest leave (the leaver signs its own epoch; a re-post carries an older one)
        console.error('[veil-group] leave signed for a later epoch — dropped', { envelopeId: id });
        opts.events.onSenderVerifyFailed(id, 'leave');
      } else if (!Object.prototype.hasOwnProperty.call(rec.leftIks ?? {}, leave.ik)) {
        // b75 (audit GR-1): a member can't see whether the creator acts on it, so it says what it
        // knows — they SAY they are leaving — and stops trusting them here at once. "Left" is said when
        // a creator-signed list drops them; a rekey that still gives them the key is refused.
        // b77q review (GR-6): when this phone first saw it, and the epoch it was on — never the leave's own `at`, which
        // the leaver picks (back-dated, it made the creator's honest rekeys look made after the leave: GR-2 then
        // stopped sends and blamed the creator)
        const left = { ...(rec.leftIks ?? {}), [leave.ik]: { vid: leave.id, at: Date.now(), ep: rec.epoch, text: out.text } };
        const keys = Object.keys(left);
        for (const k of keys.slice(0, Math.max(0, keys.length - 64))) if (!(rec.memberList ?? {})[k]) delete left[k];
        rec.leftIks = left;
        for (const [t, ik] of Object.entries(senderKeys)) if (ik === leave.ik) { delete senderKeys[t]; leavingKeys[t] = ik; }
        rec.senderKeys = senderKeys;
        const row = members.find((m) => m.ikPub === leave.ik); if (row) row.leaving = true;
        refreshNames();
        await saveGroupRecord(deps.storage, rec).catch(async (e) => {
          console.log('[veil-group] leave not saved — read again next pass:', String((e as Error)?.message ?? e));
          // b77t (audit 5 L-9): read again — its counter goes back in the window (it was saved on its own)
          burnQueue.delete(id);
          await reopenGroupCounter(deps.storage, opts.groupToken, headerStr);
        });
        opts.events.onSystem({ envelopeId: `${id}_leaving`, note: `${noteName(who)} says they are leaving the group. Until the group creator removes them, they can still read what is sent here.`, sentAt: relayTimestampToIso(env.created_date as string | undefined) });
      }
      continue;
    }

    // read receipts?
    if (out.text.startsWith('{"__veil_receipt":')) {
      try {
        const t = JSON.parse(out.text) as { __veil_receipt?: number; ids?: string[] };
        if (t.__veil_receipt === 1 && Array.isArray(t.ids)) opts.events.onRead(t.ids.slice(0, 20));
      } catch { /* ignore */ }
      continue;
    }

    // intro?
    if (out.text.startsWith('{"__veil_intro":')) {
      const parsed = parseGroupIntro(out.text);
      const intro = parsed ? await verifyGroupIntro(parsed, opts.groupToken) : null; // b75 (audit GR-8): for this group
      // Batch C (B6): the intro's key and ID must be the ones this sender tag
      // is trusted under — no claiming another member's nickname or identity
      const sidKey = String(header.sid);
      if (intro && (intro.ikPub !== senderKeys[sidKey] || intro.veilId !== tagToVeilId[sidKey])) {
        console.error('[veil-group] intro does not match its sender — dropped', { envelopeId: id });
      } else if (intro) {
        // b71 (review P-03): a loose intro no longer names anyone on its own. The
        // creator takes a name the member signed for this group (ns) into the signed
        // member list; everywhere else the name is only a fallback for a member with
        // no listed name, and is always shown with the ID suffix (this phone may not
        // know the other names, so it can't tell a copy). A name re-send (v1) is not
        // a join and gets no "joined" line; a v2 intro is an older build's join.
        const nick = intro.nick ? intro.nick.trim().slice(0, 40) : '';
        if (nick && rec.role === 'creator' && intro.ns && await verifyGroupName(opts.groupToken, intro.ikPub, nick, intro.ns)) {
          if (rec.boundNicks?.[intro.ikPub] !== nick) {
            const prevName = rec.boundNicks?.[intro.ikPub];
            const prevShown = tagToNick[sidKey] || prevName || '';
            rec.boundNicks = { ...(rec.boundNicks ?? {}), [intro.ikPub]: nick };
            rec.nameSigs = { ...(rec.nameSigs ?? {}), [intro.ikPub]: [nick, intro.ns] };
            // b74 (VAR-06): a new name gets a new first-bound sequence — a rename never
            // inherits a claim on a name someone else already holds
            noteNameBinding(rec, intro.ikPub, nick);
            membersChanged = true;
            if (prevName) {
              holdFreedName(rec, intro.ikPub, prevName); // b75r1 (audit G-1): the old name is held back from the others
              refreshNames();
              renameNoted.add(intro.ikPub);
              opts.events.onSystem({ envelopeId: `${id}_rn`, note: `${noteName(prevShown)} renamed to ${noteName(tagToNick[sidKey] || nick)}`, sentAt: relayTimestampToIso(env.created_date as string | undefined) });
            }
          }
        } else if (nick) {
          rec.introNicks = { ...(rec.introNicks ?? {}), [intro.veilId]: nick };
        }
        refreshNames();
        // b77u (audit 6 IH full I-4): any member could post a v2-shaped intro (any seat value) again and again and
        // every phone said "X joined" each time. Said once per member, and never for one already on this phone's
        // list (members) or admitted (creator) before this intro.
        const alreadyIn = !!(rec.memberList ?? {})[intro.ikPub] || !!(rec.admitted ?? {})[intro.ikPub];
        if (intro.seat && !alreadyIn && noteJoined(intro.ikPub)) {
          opts.events.onSystem({
            envelopeId: id,
            // b70 (re-review 13): the distinct name, never the raw one
            note: `${noteName(tagToNick[String(header.sid)] || intro.veilId.slice(0, 8))} joined the group`, // b75r1 (audit G-2)
            sentAt: relayTimestampToIso(env.created_date as string | undefined),
          });
        }
      }
      continue;
    }

    // b70: report / removal posts belonged to the removed forum; in a private group
    // they were never shown, and still aren't
    if (out.text.startsWith('{"__veil_report":') || out.text.startsWith('{"__veil_remove":')) continue;

    // normal message (text or media — media rides as __veil_media JSON, same
    // shape as the 1:1 flow; the receiver loads/decrypts the blob by uri)
    let media: { uri: string; k: string; iv: string; mime: string; name: string; size: number; dl?: boolean } | undefined;
    let text = out.text;
    if (out.text.startsWith('{"__veil_media":')) {
      try {
        const t = JSON.parse(out.text) as Record<string, unknown>;
        if (t.__veil_media === 1 && typeof t.uri === 'string' && typeof t.k === 'string' && typeof t.iv === 'string') {
          media = {
            uri: String(t.uri), k: String(t.k), iv: String(t.iv),
            mime: String(t.mime ?? 'application/octet-stream'), name: String(t.name ?? 'media'),
            size: Number(t.size ?? 0), dl: t.dl === 1 ? true : undefined,
          };
          text = '';
        }
      } catch { /* not media after all — render as text */ }
    }
    // M-3 (b69 audit): once per epoch, say why posts are missing.
    // b77u (audit 6 R4 #16): a relay can keep this phone on an old epoch (hiding the rotation and the list that
    // removed someone) for the whole read limit; past it a post was still shown, marked "old keys". It is no longer
    // shown at all (control messages above are still read — a rekey is how this phone gets back on current keys).
    if (out.staleKeys) {
      if (!staleNoted) {
        staleNoted = true;
        opts.events.onSystem({ envelopeId: `stalekeys_${opts.groupToken}_${rec.epoch}`, note: `Some messages were not shown: they were sent under group keys more than ${Math.round(MEMBER_EPOCH_READ_MAX_MS / 86400_000)} days old. Their senders can't be confirmed as current members — someone removed from the group may still hold those keys.`, sentAt: relayTimestampToIso(env.created_date as string | undefined) });
      }
      continue; // known and burned like any read post (above)
    }
    const rcvNow = Date.now();
    // b77u (audit 6 IH full I-3): the sender's signed time is shown only if it is no earlier than the epoch the post
    // is under began (less an hour for clocks); an older one (a member back-dating a post weeks, to before it was even
    // let in) shows the relay's time instead. shownTime alone allowed 30 days.
    const epochFrom = epochStartMs(groupRecord(deps.storage, opts.groupToken) ?? rec);
    const timeFloorAge = epochFrom !== null ? Math.max(60_000, rcvNow - (epochFrom - 60 * 60_000)) : undefined;
    // b77q review (J2-1): awaited — a post is known and burned only once the App has kept it. The relay copy was
    // burned and the id saved as known whatever the App's cache write did, so a refused write lost the post for good
    const kept = await opts.events.onMessage({
      envelopeId: id,
      text,
      senderTag: String(header.sid),
      senderVeilId: tagToVeilId[String(header.sid)] ?? null,
      senderNick: tagToNick[String(header.sid)] ?? null,
      senderVerified: out.senderVerified,
      ...(out.senderVerified && senderKeys[String(header.sid)] === (rec.creatorIkPubB64 ?? (rec.role === 'creator' ? rec.ikPubB64 : '')) ? { senderIsCreator: true } : {}), // b75 (audit GR-4)
      // b71 (audit F-12): the sender's signed time when plausible (not the relay's)
      // b77m (audit VAR-55): never later than this phone received it
      sentAt: shownTime({ meta: out.meta }, env.created_date, { rcvAt: rcvNow, ...(timeFloorAge !== undefined ? { maxAgeMs: timeFloorAge } : {}) }) ?? relayTimestampToIso(env.created_date as string | undefined),
      rcvAt: rcvNow, // b77m (audit VAR-54)
      media,
      expiresAt,
      ...(out.staleKeys ? { staleKeys: true } : {}),
    });
    if (kept === false) {
      // b77q review (J2-1): not kept — held for the next pass (not known, not burned; its counter goes back in the
      // window so it opens again). Said once in the thread, in the words of the 1:1 chat's storage note.
      opts.knownIds.delete(id);
      persistedKnown.delete(id);
      burnQueue.delete(id);
      hold(id);
      cacheRefused.add(id);
      if (!(await reopenGroupCounter(deps.storage, opts.groupToken, headerStr))) console.error('[veil-group] a post the app could not keep could not be put back either — it is lost on this phone', { envelopeId: id });
      if (!storageNoted) {
        storageNoted = true;
        opts.events.onSystem({ envelopeId: `storage_${opts.groupToken}`, note: GROUP_CACHE_REFUSED_NOTE, sentAt: new Date().toISOString() });
      }
    }
  }
  // b76r1 (audit AUD-G2): the round is over — apply the rotations it completed, then read again what the new key opens
  if (!readyRotations.length) break;
  // b76r2 (audit R2-G1): before any rotation of this round is applied, an epoch this pass saw more than one rotation
  // id for is refused (all of them), and an epoch refused on this phone is never applied
  for (const ge of new Set(readyRotations.map((r) => r.ge))) {
    const rids = ridsByEpoch.get(ge) ?? new Set<string>();
    if (rids.size < 2) continue;
    for (const r of rids) refusedRids.add(r);
    try { await refuseConflictingRotations(deps.storage, opts.groupToken, ge); } catch (e) {
      if (e instanceof GroupRekeyRecipientsError) noteRefused(e, ge, readyRotations.find((r) => r.ge === ge)!.sentAt);
      else console.error('[veil-group] rekey refusal not saved', e);
    }
  }
  let moved = false;
  for (const r of readyRotations.splice(0)) {
    if (refusedRids.has(r.rid) || groupRecord(deps.storage, opts.groupToken)?.rekeyRefusedEpoch === r.ge) continue;
    if (await finishHeld(r.rid, r.ge, r.id, r.sentAt)) moved = true;
  }
  if (!moved) break;
  }

  // b75 (audit GR-5) / b76r1 (audit AUD-G2/G3): kept rotations — dropped once their epoch is reached; a complete
  // one waiting for the member list it was made with is tried again once that list has arrived (then checked like
  // any rotation: applied, or refused with the usual note); one still missing parts after ROTATION_PARTS_WAIT_MS
  // is signed evidence the group moved on (sends stop, the key is asked for through the gate)
  if (rec.role === 'member' && !opts.peekOnly && (groupRecord(deps.storage, opts.groupToken)?.heldRotations ?? []).length) {
    const live = groupRecord(deps.storage, opts.groupToken)!;
    for (const h of [...(live.heldRotations ?? [])]) {
      const cur = groupRecord(deps.storage, opts.groupToken) ?? live;
      if (h.ge <= cur.epoch || refusedRids.has(h.rid) || h.ge === cur.rekeyRefusedEpoch) { // b76r2 (audit R2-G1): or its epoch was refused
        cur.heldRotations = (cur.heldRotations ?? []).filter((x) => x.rid !== h.rid);
        if (!cur.heldRotations.length) delete cur.heldRotations;
        await saveGroupRecord(deps.storage, cur).catch(() => undefined);
        continue;
      }
      if (h.parts.length === h.pc) {
        if (h.ms > (cur.memberSeq ?? 0)) { signedAhead = Math.max(signedAhead, h.ge); continue; }
        await finishHeld(h.rid, h.ge, `rotation_${h.rid}`, new Date().toISOString());
      } else if (Date.now() - h.first >= ROTATION_PARTS_WAIT_MS) {
        signedAhead = Math.max(signedAhead, h.ge);
      }
    }
  }
  // b76r1 (audit AUD-G1): every envelope this pass finished with is burned now, whatever its kind
  for (const [id, what] of burnQueue) await burnEnvelope(id, what);
  // b71 (audit F-12): say so when a sender's numbered posts never arrived
  for (const [ik, n] of Object.entries(seqGaps)) {
    if (!(n > 0)) continue;
    const t = Object.keys(senderKeys).find((x) => senderKeys[x] === ik);
    const who = (t && (tagToNick[t] || tagToVeilId[t]?.slice(0, 8))) || 'A member';
    opts.events.onSystem({
      envelopeId: `gap_${opts.groupToken}_${ik.slice(0, 8)}_${rec.recvSeq?.[ik] ?? 0}`,
      note: `${n} message${n === 1 ? '' : 's'} from ${who === 'A member' ? who.toLowerCase() : noteName(who)} didn't reach this phone. ${n === 1 ? 'It' : 'They'} may have expired or been deleted — or the relay held ${n === 1 ? 'it' : 'them'} back.`,
      sentAt: new Date().toISOString(),
    });
  }

  // b92 F10/F11: persist the per-group cursor + known ledger (survives
  // restarts; capped like every other ledger).
  // (b70 re-review 9: no offset cursor any more — see the pager above)
  if (!opts.peekOnly) delete (rec as { syncSkip?: number }).syncSkip;
  // Batch G (R5-2-03): the known ids are a fast path (replays are refused anyway);
  // 300 keeps the record well under the Keychain's size cliff
  // b73 (audit V-01): held rows (the newest HELD_CAP) and the trust state they were judged
  // under. Held rows past the cap are marked processed instead, so they still end the pager's
  // descent (a pile of held rows must not hide newer rows either). An honest epoch is ~100
  // envelopes (the creator rotates at 100), so the cap only bites on a flood.
  if (!opts.peekOnly && !keyless) {
    const all = Array.from(held);
    const over = all.length - HELD_CAP;
    if (over > 0) {
      // b77t (audit 5 L-7 / IH C-2): dropped from the held set, never marked known — a row given up here used to be
      // lost for good; now it is read again whenever a pass fetches it (a re-scan after a trust change does)
      console.warn('[veil-group] too many held rows — the oldest are no longer held', { groupToken: opts.groupToken.slice(0, 6), count: over });
    }
    // b77t (audit 5 L-7): the future bucket keeps only rows for an epoch this phone hasn't passed (one for an older
    // epoch is marked known when fetched; one never fetched again has left the relay)
    const epochEnd = (groupRecord(deps.storage, opts.groupToken) ?? rec).epoch;
    const future = [...heldFuture.entries()].filter(([, e]) => e >= epochEnd).slice(-FUTURE_HELD_CAP);
    if (future.length) rec.heldFutureIds = future; else delete rec.heldFutureIds;
    if (all.length) rec.heldEnvIds = all.slice(-HELD_CAP); else delete rec.heldEnvIds;
    if (all.length || future.length) rec.heldStateKey = heldKey; else delete rec.heldStateKey;
  }
  rec.knownEnvIds = Array.from(persistedKnown).slice(-300);
  if (Object.keys(rejectedWhy).length) console.warn('[veil-group] rows rejected (never shown)', { groupToken: opts.groupToken.slice(0, 6), ...rejectedWhy });
  if (groupRecordBytes(rec) > 40_000) console.log('[veil-group] large group record', { group: opts.groupToken.slice(0, 6), bytes: groupRecordBytes(rec) });
  for (const m of members) m.nick = tagToNick[m.tag] ?? '';
  // b75r1 (audit G-1): every change of the name this phone SHOWS for another member is said out loud. b75 said
  // only a member's own rename: when the member whose name another had parked on (shown "m0 · <ID>") was
  // removed or renamed, the parker silently became plain "m0" on every phone. Freed names are held back now
  // (holdFreedName), and a shown name that still changes — the hold ran out, a clash resolved — gets a note
  // naming the name before and after. Compared by key against the last pass (rec.shownNames).
  if (!opts.peekOnly && !keyless) {
    const nowShown: Record<string, string> = {};
    for (const [t, ik] of [...Object.entries(senderKeys), ...Object.entries(leavingKeys)]) if (ik !== rec.ikPubB64 && tagToNick[t] && !nowShown[ik]) nowShown[ik] = tagToNick[t];
    const prevShown = rec.shownNames;
    if (prevShown) {
      for (const [ik, was] of Object.entries(prevShown)) {
        const now = Object.prototype.hasOwnProperty.call(nowShown, ik) ? nowShown[ik] : undefined;
        if (!now || now === was || renameNoted.has(ik)) continue;
        opts.events.onSystem({ envelopeId: `shown_${opts.groupToken}_${ik.slice(0, 12)}_${nameSkeleton(now).slice(0, 40)}`, note: `${noteName(was)} is now shown as ${noteName(now)}.`, sentAt: new Date().toISOString() });
      }
    }
    rec.shownNames = nowShown;
  }
  // b77q review (GR-1 residual): a kept gate delivery still waiting for its list past the bound is flagged, and every
  // flag raised outside a list apply (a later epoch's signed rekey numbered below a delivery) is said in the thread
  if (rec.role === 'member' && !opts.peekOnly && !keyless) {
    const liveG = groupRecord(deps.storage, opts.groupToken) ?? rec;
    const changed = expireDeliveryChecks(liveG);
    const flagged = takeDeliveryGhostNotes(liveG);
    if (liveG !== rec) {
      rec.deliveryChecks = liveG.deliveryChecks; rec.ghostKeyEpoch = liveG.ghostKeyEpoch; delete rec.deliveryGhostNotes;
      if (changed || flagged.length) await saveGroupRecord(deps.storage, liveG).catch(() => undefined);
    }
    for (const g of flagged) {
      console.error('[veil-group] a delivered group key was flagged (its member list never matched)', { epoch: g.ge });
      opts.events.onSystem({ envelopeId: `ghost_key_${opts.groupToken}_${g.ge}`, note: g.warnOnly ? GHOST_KEY_MISMATCH_WARN_NOTE : GHOST_KEY_MISMATCH_NOTE, sentAt: new Date().toISOString() }); // b77q owner (1 Nov)
    }
  }
  // (b71 review P-03: names are recomputed every pass from boundNicks / introNicks;
  // nicks is kept for older readers, nicksById is no longer written)
  rec.nicks = { ...tagToNick };
  try { await saveGroupRecord(deps.storage, rec); } catch { /* nickname persistence best-effort */ }
  // b74 (VAR-05): a member who said it is leaving is removed like on a Remove tap: deny entry
  // (local and relay), a removal notice in the signed member list, and a key rotation that
  // leaves it out. The local part is recorded first (evictGroupMember), so if the relay or
  // the rotation fails, the next pass still owes the rotation (evictionPendingAt).
  // b75r2 (audit R2G-01): BEFORE this pass publishes a member list or admits anyone. b75r1 removed leavers last,
  // after a contact admission's rotation had already wrapped the new epoch's key to a member whose leave it had
  // just read (members who read the leave refuse that rekey too: it still names the leaver).
  const leftDone: Array<{ ikPub: string; veilId: string }> = [];
  if (rec.role === 'creator' && !opts.peekOnly) {
    const epochBefore = (groupRecord(deps.storage, opts.groupToken) ?? rec).epoch;
    for (const l of leavers) {
      if ((rec.evictedIks ?? []).includes(l.ikPub)) continue;
      try {
        await evictGroupMember(deps, { groupToken: opts.groupToken, sessionToken: opts.sessionToken, target: { veilId: l.veilId, ikPub: l.ikPub }, clientId: opts.clientId, left: true });
      } catch (e) {
        console.error('[veil-group] removal after a leave not finished — the next pass finishes the key change', String((e as Error)?.message ?? e));
      }
      if ((groupRecord(deps.storage, opts.groupToken) ?? rec).evictedIks?.includes(l.ikPub)) leftDone.push(l);
    }
    // b75 (lead's emulator finding): a removal's rotation is a rotation too
    const now = (groupRecord(deps.storage, opts.groupToken) ?? rec).epoch;
    if (now > epochBefore) opts.events.onRotated(now);
  }
  // Batch C (A1): the creator publishes the signed member list after any admission
  if (membersChanged && rec.role === 'creator' && opts.clientId && !opts.peekOnly) {
    await publishMemberList(deps, { groupToken: opts.groupToken, sessionToken: opts.sessionToken, clientId: opts.clientId })
      .then(async () => { if (rec.memberListDirty) { rec.memberListDirty = undefined; await saveGroupRecord(deps.storage, rec); } })
      .catch((e) => console.error('[veil-group] member list publish failed — retried on the next admission or rotation', String((e as Error)?.message ?? e)));
  }
  // b71 (audit F-07): a contact seat claimed by exactly the invited contact's key is
  // admitted without a tap (checkSeatClaim says why that is safe); like every
  // admission it rotates first and the newcomer gets only the new epoch's key
  // (admitClaimsNow). Every other claim waits for the creator (pendingClaims below).
  if (rec.role === 'creator' && !opts.peekOnly && opts.clientId) {
    const auto = Object.entries(rec.pendingClaims ?? {}).filter(([, c]) => c.contact).map(([ik]) => ik);
    if (auto.length) {
      const epochBefore = (groupRecord(deps.storage, opts.groupToken) ?? rec).epoch;
      const done = await admitClaimsNow(deps, rec, { groupToken: opts.groupToken, sessionToken: opts.sessionToken, clientId: opts.clientId, iks: auto })
        .catch((e) => { console.error('[veil-group] contact admission not finished — retried next pass', String((e as Error)?.message ?? e)); return null; });
      // b75 (lead's emulator finding): the admission rotated the group — say so, like every other
      // rotation path (the open chat kept showing the old epoch, and its old fingerprint)
      { const now = (groupRecord(deps.storage, opts.groupToken) ?? rec).epoch; if (now > epochBefore) opts.events.onRotated(now); }
      for (const a of done?.admitted ?? []) {
        opts.events.onSystem({ envelopeId: `join_${a.ikPub.slice(0, 12)}_${done!.epoch}`, note: `${noteName(a.label)} joined the group`, sentAt: new Date().toISOString() }); // b75r1 (audit G-2)
        noteJoined(a.ikPub); // b77u (audit 6 I-4)
      }
      if (done) needsRotation = needsRotation && Object.values(rec.joinEpochs ?? {}).some((e) => e > rec.epoch);
    }
  }
  // Batch C (A1): a member the creator hasn't admitted yet re-sends its
  // seat-proven intro (at most every 10 minutes) in case the first one was lost
  // b71 (review P-01): under its seat key (a joiner without a key isn't on any list yet)
  if (rec.role === 'member' && rec.seatToken && rec.seatProof && opts.clientId && !opts.peekOnly
      && (keyless || !(rec.memberList ?? {})[rec.ikPubB64]) && Date.now() - Number(rec.introSentAt ?? 0) > 10 * 60_000) {
    rec.introSentAt = Date.now();
    // Batch H (round-6 review R6-2-07): a refused save must not end the poll pass here
    await saveGroupRecord(deps.storage, rec).catch((e) => console.log('[veil-group] intro time not saved:', String((e as Error)?.message ?? e)));
    const resend = rec.seatKey
      ? sendSeatIntro(deps, { groupToken: opts.groupToken, sessionToken: opts.sessionToken, clientId: opts.clientId, identity: opts.identity, nick: rec.myNick ?? '', seatToken: rec.seatToken, seatKey: rec.seatKey, proof: rec.seatProof, proof2: rec.seatProof2 })
      : submitGroupEnvelope(deps, { // a joiner from before b71 (it holds the key from its link)
        groupToken: opts.groupToken, sessionToken: opts.sessionToken, clientId: opts.clientId,
        text: await buildIntroPayload(opts.identity, rec.myNick ?? '', { token: rec.seatToken, proof: rec.seatProof, proof2: rec.seatProof2 }, opts.groupToken),
        control: 'intro',
      });
    await resend.catch((e) => console.error('[veil-group] intro re-send failed', String((e as Error)?.message ?? e)));
  }
  // b71 (review P-03): a listed member whose name isn't in the creator's list yet
  // (joined before b71, or the name changed) sends a signed name binding once per
  // epoch; the creator puts it in the next member list
  if (rec.role === 'member' && !keyless && rec.myNick && opts.clientId && !opts.peekOnly
      && (rec.memberList ?? {})[rec.ikPubB64] && rec.boundNicks?.[rec.ikPubB64] !== rec.myNick && rec.nameIntroEpoch !== rec.epoch) {
    rec.nameIntroEpoch = rec.epoch;
    await saveGroupRecord(deps.storage, rec).catch(() => undefined);
    await submitGroupEnvelope(deps, {
      groupToken: opts.groupToken, sessionToken: opts.sessionToken, clientId: opts.clientId,
      text: await buildIntroPayload(opts.identity, rec.myNick, undefined, opts.groupToken),
      control: 'intro',
    }).catch((e) => console.error('[veil-group] name binding not sent', String((e as Error)?.message ?? e)));
  }
  // b75 (audit GR-1): creator — the "can't read from now on" note for each leaver, once the rotation that
  // leaves them out has really completed (b74 said it as soon as the leave was read, before any rotation)
  if (rec.role === 'creator' && !opts.peekOnly && (rec.leaveNotesOwed ?? []).length) {
    const live = groupRecord(deps.storage, opts.groupToken) ?? rec;
    const owed: Array<[string, string]> = [];
    for (const [ik, who] of live.leaveNotesOwed ?? []) {
      const done = (live.evictedIks ?? []).includes(ik) && live.evictionPendingAt === undefined && !live.pendingRotation && !(live.lastRotationRecipients ?? []).includes(ik);
      if (done) opts.events.onSystem({ envelopeId: `left_${opts.groupToken}_${ik.slice(0, 12)}`, note: `${noteName(who)} left the group. They were removed and the group keys changed, so they can't read what is sent from now on.`, sentAt: new Date().toISOString() });
      else owed.push([ik, who]);
    }
    live.leaveNotesOwed = owed.length ? owed : undefined;
    await saveGroupRecord(deps.storage, live).catch(() => undefined);
  }
  // b75 (audit GR-1): member — re-post every leave read here while the creator's list still names the leaver,
  // so the relay can't keep the leave from the creator without holding back what this member sends.
  // b75r1 (audit G-4): NOT in the pass the leave was read, and not just once. b75 re-posted it at once, as the
  // first thing this member submitted after the relay served it the leave row — so the relay could hide just
  // that one post per member from the creator (by timing alone) and let everything else through. Now the first
  // re-post waits a random time (leaveRepostTiming: 2–20 min; the app's own cover posts go out meanwhile), and
  // it is posted again at random times (30 min – 3 h apart, at most `max` times) until a creator-signed list
  // drops the leaver — the creator's removal is the acknowledgement.
  if (rec.role === 'member' && !keyless && opts.clientId && !opts.peekOnly) {
    const now = Date.now();
    const plan: Record<string, { next: number; n: number }> = { ...(rec.leaveReposts ?? {}) };
    let changed = false;
    for (const ik of Object.keys(plan)) {
      const l = rec.leftIks && Object.prototype.hasOwnProperty.call(rec.leftIks, ik) ? rec.leftIks[ik] : undefined;
      if (!l?.text || !(rec.memberList ?? {})[ik]) { delete plan[ik]; changed = true; } // acknowledged (dropped by the list)
    }
    for (const [ik, l] of Object.entries(rec.leftIks ?? {})) {
      if (!l?.text || !(rec.memberList ?? {})[ik]) continue;
      const cur = Object.prototype.hasOwnProperty.call(plan, ik) ? plan[ik] : undefined;
      if (!cur) { plan[ik] = { next: now + randomBetween(leaveRepostTiming.firstMinMs, leaveRepostTiming.firstMaxMs), n: 0 }; changed = true; continue; }
      if (cur.n >= leaveRepostTiming.max || now < cur.next) continue;
      try {
        await submitGroupEnvelope(deps, { groupToken: opts.groupToken, sessionToken: opts.sessionToken, clientId: opts.clientId, text: l.text, control: 'leave' });
        plan[ik] = { next: now + randomBetween(leaveRepostTiming.againMinMs, leaveRepostTiming.againMaxMs), n: cur.n + 1 };
        changed = true;
      } catch (e) {
        console.warn('[veil-group] leave re-post failed — retried next pass', String((e as Error)?.message ?? e));
      }
    }
    if (changed) {
      rec.leaveReposts = Object.keys(plan).length ? plan : undefined;
      await saveGroupRecord(deps.storage, rec).catch(() => undefined);
    }
  }
  // Batch C (A3): an unfinished rotation or eviction is finished on the next opportunity
  if (rec.role === 'creator' && (rec.pendingRotation || rec.evictionPendingAt !== undefined)) needsRotation = true;
  // Batch C (A3): the creator answers missing-wrap requests (at most once a minute per group)
  if (rec.role === 'creator' && !opts.peekOnly) {
    await serviceWrapRequests(deps, rec, opts.sessionToken).catch((e) => console.error('[veil-group] wrap requests not served', String((e as Error)?.message ?? e)));
  }
  // b54: still behind AFTER every rekey in this pass was applied → genuinely
  // missed a rotation. Batch C (A3): first collect a wrap the creator delivered
  // through the gate, otherwise ask for one; surface "behind" only if still behind.
  let epochNow = groupRecord(deps.storage, opts.groupToken)?.epoch ?? rec.epoch;
  // b75 (audit GR-2): a creator-signed later epoch this phone still doesn't hold after the pass is
  // remembered (it stops sends under the old key: groupKeyFreshness.behind)
  if (rec.role === 'member' && !opts.peekOnly && signedAhead > epochNow) {
    const cur = groupRecord(deps.storage, opts.groupToken) ?? rec;
    if ((cur.signedAheadEpoch ?? 0) < signedAhead) {
      cur.signedAheadEpoch = signedAhead;
      await saveGroupRecord(deps.storage, cur).catch((e) => console.log('[veil-group] signed epoch hint not saved:', String((e as Error)?.message ?? e)));
    }
  }
  const signedBehind = (): number => {
    const cur = groupRecord(deps.storage, opts.groupToken) ?? rec;
    return (cur.signedAheadEpoch ?? 0) > cur.epoch ? cur.signedAheadEpoch! : 0;
  };
  // b71 (review P-01): a joiner still without its key asks too (have_epoch 0), so a
  // delivery that failed at admission is served by the creator's next request pass
  // b71 (audit F-04): and a member whose signed member list announced a removal at an
  // epoch it doesn't hold asks for that epoch's key at once
  // b75 (audit GR-2): the roster's word still makes it ASK (a request is harmless), nothing more
  // b76r1 (audit AUD-G2): while this phone is still collecting the parts of a rotation to the relay's epoch (for less
  // than ROTATION_PARTS_WAIT_MS), the relay's word alone doesn't make it ask the gate — the parts are what it checks
  // the rotation by, and a gate delivery would skip that check
  const collecting = (e: number): boolean => (groupRecord(deps.storage, opts.groupToken)?.heldRotations ?? [])
    .some((h) => h.ge === e && h.parts.length < h.pc && Date.now() - h.first < ROTATION_PARTS_WAIT_MS);
  const rosterAsk = rosterAhead > epochNow && !(rosterAhead === epochNow + 1 && collecting(rosterAhead));
  if ((rosterAsk || signedBehind() > epochNow || keyless || (rec.removalPendingEpoch ?? 0) > epochNow) && rec.role === 'member' && !opts.peekOnly) {
    const applied = await recoverMissingWrap(deps, rec, opts.sessionToken, opts.identity).catch((e) => {
      console.error('[veil-group] missing-wrap recovery failed', String((e as Error)?.message ?? e));
      // b77m (audit VAR-36): a delivery refused for its recipients is said, like a refused rotation
      if (e instanceof GroupRekeyRecipientsError && e.kind === 'equivocation') {
        opts.events.onSystem(equivocationNote(groupRecord(deps.storage, opts.groupToken)?.epoch ?? 0, new Date().toISOString())); // b77q (audit 3 GR-2)
      } else if (e instanceof GroupRekeyRecipientsError && e.kind !== 'already') {
        const ge = groupRecord(deps.storage, opts.groupToken)?.rekeyRefusedEpoch ?? 0;
        opts.events.onSystem({ envelopeId: `rekey_refused_${opts.groupToken}_${ge}`, note: 'The group creator’s phone sent the new group key to someone who isn’t on the member list, so this phone didn’t take it. New messages in this group wait until the next key change.', sentAt: new Date().toISOString() });
      }
      return false;
    });
    if (applied) {
      epochNow = groupRecord(deps.storage, opts.groupToken)?.epoch ?? epochNow;
      opts.events.onRotated(epochNow);
    }
  }
  // b75 (audit GR-2): "behind" only on creator-signed evidence still standing after the recovery
  // attempt (b70–b74: on the relay roster's epoch, and the app then advised rejoining). The b70
  // roster-epoch send hold (seenEpoch) is gone for the same reason: the relay alone set it.
  { const sb = signedBehind(); if (sb > epochNow) opts.events.onEpochBehind?.({ groupToken: opts.groupToken, behindEpoch: sb, localEpoch: epochNow }); }
  const legacyRosterToConfirm = rec.role === 'creator' && rec.legacyRoster
    ? Object.entries(rec.legacyRoster).filter(([ik]) => !(rec.evictedIks ?? []).includes(ik)).map(([ikPub, veilId]) => ({ veilId, ikPub }))
    : [];
  // M-3 (b69 audit): the member's visible signal that rotations aren't arriving
  // (a relay withholding them looks exactly like this from here)
  let keyNotice: GroupInboxResult['keyNotice'];
  {
    const cur = groupRecord(deps.storage, opts.groupToken) ?? rec;
    const fresh = groupKeyFreshness(cur);
    // b71 (audit F-04): 'removed' first — it says why sending stopped
    if (cur.gekB64 && (fresh.removed || fresh.stale || fresh.behind)) keyNotice = { kind: fresh.removed ? 'removed' : fresh.stale ? 'stale' : 'behind', epoch: cur.epoch, ageHours: Math.floor(fresh.ageMs / 3600_000), ...(fresh.removedSelf ? { self: true } : {}) }; // b75r1 (audit G-7)
  }
  const awaitingKey = rec.role === 'member' && !(groupRecord(deps.storage, opts.groupToken) ?? rec).gekB64;
  // b71 (audit F-07): the claims waiting for the creator's tap
  const pendingClaims = rec.role === 'creator' ? groupClaimRows(groupRecord(deps.storage, opts.groupToken) ?? rec) : [];
  // b74 (VAR-05): trusted members gone from the relay's roster past the grace period — the
  // creator is told once per absence (with a one-tap Remove in the member list); nothing is
  // done on the relay's word alone (it could fake an absence to make the creator drop someone)
  const goneFromRelay: NonNullable<GroupInboxResult['goneFromRelay']> = [];
  if (rec.role === 'creator' && !opts.peekOnly) {
    const denied = new Set(groupRecord(deps.storage, opts.groupToken)?.evictedIks ?? rec.evictedIks ?? []);
    for (const m of members) {
      if (m.goneSince === undefined || denied.has(m.ikPub)) continue;
      const label = m.nick || m.veilId.slice(0, 8);
      goneFromRelay.push({ ikPub: m.ikPub, veilId: m.veilId, label, sinceMs: m.goneSince });
      const days = Math.max(1, Math.floor((Date.now() - m.goneSince) / 86400_000));
      opts.events.onSystem({ envelopeId: `gone_${opts.groupToken}_${m.ikPub.slice(0, 12)}_${m.goneSince}`, note: `${noteName(label)} hasn't been on this group's server list for ${days === 1 ? 'a day' : `${days} days`} — they may have left without saying so. They still get every new group key until you remove them: open Group members and tap Remove.`, sentAt: new Date().toISOString() });
    }
  }
  const membersOut = leftDone.length ? members.filter((m) => !leftDone.some((l) => l.ikPub === m.ikPub)) : members;
  // b75 (lead's emulator finding): the fingerprint and epoch of the record as it is NOW (b74 worked
  // the fingerprint out before the pass applied a rekey, a key delivery, an admission's rotation or a
  // removal's, so the members panel showed the previous epoch's until the next pass)
  const liveEnd = groupRecord(deps.storage, opts.groupToken) ?? rec;
  const confirmed = membersOut.filter((m) => !m.pending);
  const fingerprint = await groupFingerprintOf(liveEnd, confirmed.map((m) => m.ikPub));
  return { tagToVeilId, tagToNick, members: membersOut, fingerprint, epoch: liveEnd.epoch, needsRotation, ...(legacyRosterToConfirm.length ? { legacyRosterToConfirm } : {}), ...(keyNotice ? { keyNotice } : {}), ...(awaitingKey ? { awaitingKey: true } : {}), ...(pendingClaims.length ? { pendingClaims } : {}), ...(goneFromRelay.length ? { goneFromRelay } : {}), ...(leftDone.length ? { left: leftDone } : {}) };
}

// ---------- send / receipts ----------

export async function sendGroupMessage(
  deps: GroupSessionDeps,
  opts: { groupToken: string; sessionToken: string; clientId: string; text: string; cover?: boolean },
): Promise<{ senderTag: string }> {
  // b75r3 (audit R3G-I2): exactly these fields — a typed message never carries a control flag or a seat
  const r = await submitGroupEnvelope(deps, { groupToken: opts.groupToken, sessionToken: opts.sessionToken, clientId: opts.clientId, text: opts.text, cover: opts.cover });
  return { senderTag: r.senderTag };
}

/** web parity: group read receipts are {__veil_receipt:1, ids, read?} through
 *  the encrypted group channel. */
export async function sendGroupReceipt(
  deps: GroupSessionDeps,
  opts: { groupToken: string; sessionToken: string; clientId: string; ids: string[]; read: boolean },
): Promise<void> {
  if (!opts.ids.length) return;
  const body = opts.read
    ? JSON.stringify({ __veil_receipt: 1, ids: opts.ids.slice(0, 20), read: true })
    : JSON.stringify({ __veil_receipt: 1, ids: opts.ids.slice(0, 20) });
  await submitGroupEnvelope(deps, { ...opts, text: body, cover: false });
}

/**
 * b74 (VAR-05): a member leaving says so first — a signed leave in the group stream, read by
 * the creator, which removes this member like on a Remove tap (deny entry, removal notice in
 * the signed member list, a key rotation without it). Before b74 leaving only ended the seat:
 * the creator kept wrapping every new key to the leaver and members kept trusting its
 * signature. The App calls this before ending the seat. false = nothing was sent (no group
 * key yet, or this phone is the creator); a throw = the relay refused it (the creator's
 * "missing from the relay" notice is the fallback then).
 */
export async function sendGroupLeave(
  deps: GroupSessionDeps,
  opts: { groupToken: string; sessionToken: string; clientId: string },
): Promise<boolean> {
  const rec = (await loadGroupRecord(deps.storage, opts.groupToken)) ?? groupRecord(deps.storage, opts.groupToken);
  if (!rec || rec.role !== 'member' || !rec.gekB64 || !rec.ikSeedB64) return false;
  const text = await buildSignedLeaveText(rec.ikSeedB64, opts.groupToken, rec.ikPubB64, rec.veilId, rec.epoch);
  await submitGroupEnvelope(deps, { groupToken: opts.groupToken, sessionToken: opts.sessionToken, clientId: opts.clientId, text, control: 'leave' });
  return true;
}

// ---------- media (web parity: __veil_media JSON through the group channel) ----------

export async function sendGroupMediaMessage(
  deps: GroupSessionDeps,
  opts: {
    groupToken: string; sessionToken: string; clientId: string;
    media: { bytes: Uint8Array; name?: string; mime?: string; size?: number; dl?: boolean };
    localUri?: string;
    uploadCiphertext?: (ciphertext: Uint8Array) => Promise<string>;
  },
): Promise<{ id: string; media: { uri: string; k: string; iv: string; mime: string; name: string; size: number; dl: boolean; localUri?: string } }> {
  const size = opts.media.size ?? opts.media.bytes.byteLength;
  const { ciphertext, keyB64, ivB64 } = await encryptMedia(opts.media.bytes);
  const fileUri = opts.uploadCiphertext
    ? await opts.uploadCiphertext(ciphertext)
    : await deps.relay.uploadPrivateFile({ bytes: ciphertext, name: 'veil-media', chat: { sessionToken: opts.sessionToken, writeSecret: await mainWriteSecret(deps, opts.sessionToken) } }); // b77u (audit 6 U-M9): bound to the group
  const f: Record<string, unknown> = { name: opts.media.name || 'media', mime: opts.media.mime || 'application/octet-stream', size };
  if (opts.media.dl) f.dl = 1;
  const body = JSON.stringify({ __veil_media: 1, uri: fileUri, k: keyB64, iv: ivB64, ...f });
  await submitGroupEnvelope(deps, {
    groupToken: opts.groupToken, sessionToken: opts.sessionToken,
    clientId: opts.clientId, text: body, cover: false,
  });
  // b76r1 (audit AUD-I3): the file id rides only inside the encrypted body (no media_uri on the envelope;
  // this comment used to say the receiver read it from the relay's row — it never did)
  return {
    id: `local_${Date.now()}_${Math.floor(secureRandomUnit() * 1e6)}`, // b77u (audit 6): the CSPRNG, never Math.random
    media: { uri: fileUri, k: keyB64, iv: ivB64, mime: String(f.mime), name: String(f.name), size, dl: !!opts.media.dl, localUri: opts.localUri },
  };
}

// ---------- rotate / evict (creator) ----------

/** Batch C (A3): one rotation at a time per group, in this process. */
const rotationLocks = new Map<string, Promise<unknown>>();
function withRotationLock<T>(groupToken: string, fn: () => Promise<T>): Promise<T> {
  const prev = rotationLocks.get(groupToken) ?? Promise.resolve();
  const run = prev.catch(() => undefined).then(fn);
  rotationLocks.set(groupToken, run.catch(() => undefined));
  return run;
}

/** Batch C (A3): test hook — throw after the named step to prove a retry converges. */
export const rotationCrashHook: { at: string | null } = { at: null };
function crashPoint(step: string): void {
  if (rotationCrashHook.at === step) { rotationCrashHook.at = null; throw new Error(`[test] crash after ${step}`); }
}

async function mainWriteSecret(deps: GroupSessionDeps, sessionToken: string): Promise<string | null> {
  return (await deps.sessions.load(sessionToken) as RatchetStateSerialized & { writeSecret?: string })?.writeSecret ?? null;
}

/** Batch C (A3): build a rotation; the caller persists it BEFORE anything is sent. */
async function prepareRotation(deps: GroupSessionDeps, rec: GroupRecord, sessionToken: string): Promise<PendingRotation> {
  // Batch C (A1): wrap ONLY to members the creator admitted (one IK per seat it
  // minted), minus the local deny list — the relay roster is not consulted.
  let trusted = await trustedMembers(rec);
  if (!trusted) {
    trusted = {};
    const roster = (await gateRoster(deps, { groupToken: rec.groupToken, sessionToken })).members;
    for (const m of await verifiedRosterRows(rec, roster.map((r) => (r ?? {}) as Record<string, unknown>))) trusted[String(m.IK_pub)] = String(m.veil_id);
  }
  const targets = Object.entries(trusted).filter(([ik]) => ik !== rec.ikPubB64);
  // b75r1 (audit G-6): the member list this key is made with (ms, mh, and whether it must be published
  // first) is worked out from the SAME snapshot as the recipients, before the prekey lookups below wait on
  // the relay (b75 read the record again after them, so a removal or admission landing meanwhile signed a
  // list that didn't match the wraps). A rotation whose membership changed while it was being made is
  // thrown away by rotateOnce (rotationUnfit) before anything of it is sent.
  const listMembers = targets as Array<[string, string]>;
  const listed = new Set(rec.listedIks ?? []);
  const needList = !rec.listedIks || listed.size !== listMembers.length || listMembers.some(([ik]) => !listed.has(ik));
  const seqSnap = rec.memberSeq ?? 0;
  const hashSnap = rec.listedHash;
  const newGek = toB64(randomBytes(32));
  const epoch = rec.epoch + 1; // b77m (audit VAR-10): every wrap is bound to the epoch it is for
  const wraps: GroupRekeyWrap[] = [];
  const recipients: string[] = [];
  const skipped: string[] = [];
  for (const [ik, veilId] of targets) {
    let pqPub = '';
    let pqSig = '';
    let lookupIk = '';
    try {
      const d = (await deps.relay.invoke('veilIdentityGate', { action: 'lookup', veil_id: veilId })).data as { IK_pub?: string; pq_pub?: string; pq_sig?: string };
      pqPub = String(d?.pq_pub ?? '');
      pqSig = String(d?.pq_sig ?? '');
      lookupIk = String(d?.IK_pub ?? '');
    } catch { /* lookup failure handled below */ }
    // b54 (Batch A, H-1): the PQ prekey must be signed by the SAME IK the
    // creator admitted — a substituted key would hand the relay the wrap.
    // Batch D (D-06, RV-05): a member without one is SKIPPED, not a veto — a relay
    // serving one bad prekey could otherwise stall every rotation (and with it an
    // eviction) for ever. They stay trusted and recover the key through the
    // missing-wrap request once their prekey checks out.
    if (!pqPub || lookupIk !== ik || !(await verifyPqPrekeySig(ik, pqPub, pqSig).catch(() => false))) {
      console.warn('[veil-group] rotation skips a member without a valid signed prekey', { veilId });
      skipped.push(veilId);
      continue;
    }
    wraps.push(await buildRekeyWrap(pqPub, veilId, newGek, { groupToken: rec.groupToken, epoch, memberIkPubB64: ik })); // b77m (audit VAR-10): hybrid
    recipients.push(ik);
  }
  // b73 (audit V-15): only the public half is ever used (a per-epoch salt); the private half is dropped here
  const pq = await mlkemKeypair();
  const rid = hexRand(16);
  const kc = await gekCommitment(rec.groupToken, epoch, newGek);
  // b73 (audit V-07): who this key is for — every trusted member (skipped ones included: they
  // get it later through the gate), signed into every part as rc
  const rc = targets.map(([, veilId]) => veilId).sort();
  // b75 (audit GR-5): the member list this key is made with is signed into every part (ms = its number,
  // mh = membersHash of its entries). When the last published list doesn't name exactly these members (a
  // newcomer, or someone removed), that list is built — and numbered — now, and goes out before the first
  // part (rotateOnce), the same text on every retry. A member whose latest list is older than ms then
  // knows a list is missing and waits for it (or the gate's key) instead of raising a ghost-key alarm.
  // (b75r1, audit G-6: listMembers / needList / seqSnap / hashSnap are the snapshot taken with `targets`)
  let preList: PendingRotation['preList'];
  let ms = seqSnap;
  let mh = hashSnap ?? await membersHash(listMembers);
  if (needList) {
    const l = await buildMemberList(deps, rec, rec.groupToken, listMembers);
    preList = { seq: l.seq, text: l.text, iks: l.iks, hash: l.hash };
    ms = l.seq; mh = l.hash;
  }
  const parts: string[] = [];
  const at = Date.now(); // b70 (re-review 6): the epoch's signed start time
  // b54: sent in parts, each signed on its own. Batch C (A3): every part names the rotation, its
  // key commitment and i of n. b76 (padding, spec §8.2 item 45): as many wraps per part as keep
  // each part in the smallest size class it can reach (rekeyWrapsPerPart), measured with the
  // largest part number the rotation could have (so a part never outgrows its class)
  const per = rekeyWrapsPerPart(wraps.length, (k) => rekeyPartNeed(rec.groupToken, epoch, pq.pub, wraps.slice(0, k), { rid, kc, pi: wraps.length, pc: wraps.length, at, rc, ms, mh }));
  const chunks = wraps.length
    ? Array.from({ length: Math.ceil(wraps.length / per) }, (_, i) => wraps.slice(i * per, (i + 1) * per))
    : [[]];
  // b76r1 (audit AUD-G2): every part signs the same rotation hash over all the parts' wraps (rh), and members
  // apply the rotation only once they hold every part (collectRotationPart / finishRotation)
  parts.push(...await buildSignedRekeyParts(rec.ikSeedB64, rec.groupToken, epoch, pq.pub, chunks, { rid, kc, at, rc, ms, mh }));
  return { epoch, gekB64: newGek, pqPubB64: pq.pub, rid, parts, sent: [], recipients, skipped, rc, ...(preList ? { preList } : {}) };
}

/**
 * Batch D (D-05, RV-04): a rotation prepared before an eviction may wrap the new
 * key to the member being removed. If none of its parts went out, it is thrown
 * away and a fresh one is prepared. (If some did, the key may already be with
 * them: it is finished, and rotateGroup runs one more rotation past it while
 * the creator's sends stay blocked.)
 */
function dropTaintedRotation(rec: GroupRecord): void {
  const p = rec.pendingRotation;
  // b70 (re-review 3): a part whose submit was TRIED counts as possibly out (the
  // relay may have stored it and still answered with an error); only a rotation
  // nothing of which was ever tried may be thrown away and replaced
  if (!p || p.sent.length > 0 || (p.attempted ?? []).length > 0) return;
  const denied = new Set(rec.evictedIks ?? []);
  if (p.recipients.some((ik) => denied.has(ik))) {
    console.log('[veil-group] discarded an unsent rotation that wrapped to a removed member', { groupToken: rec.groupToken.slice(0, 6), epoch: p.epoch });
    rec.pendingRotation = undefined;
  }
}

/**
 * b75r1 (audit G-6): why a rotation nothing of which has been tried no longer fits the record as it is
 * NOW, or null. Synchronous on purpose (rotateOnce acts on the answer with no wait in between):
 *  - it wraps to, or names in its rc, someone on the deny list (a removal landed while it was made);
 *  - a trusted member it must cover (join epoch at or below its epoch) is neither a recipient nor in its rc
 *    (an admission landed while it was made — b74 VAR-02: the newcomer's first epoch must not be one made
 *    without it).
 */
/** the Vardum IDs of everyone on the record's deny list (from its admissions and its removal notices) */
function deniedVidsOf(rec: GroupRecord): Set<string> {
  const denied = new Set(rec.evictedIks ?? []);
  const deniedVids = new Set<string>();
  for (const ik of denied) { const v = rec.admitted && Object.prototype.hasOwnProperty.call(rec.admitted, ik) ? rec.admitted[ik] : ''; if (v) deniedVids.add(v); }
  for (const [ik, vid] of rec.removals ?? []) if (denied.has(ik) && vid) deniedVids.add(vid);
  return deniedVids;
}

/** b75r2 (audit R2G-01): does the record's CURRENT epoch reach anyone on its deny list — as a recipient of the
 *  rotation that made it, or named in its signed recipient set (a member skipped for a bad prekey is named, and
 *  could be handed the key later)? An eviction is complete only once this is false. */
function epochReachesDenied(rec: GroupRecord): boolean {
  const denied = new Set(rec.evictedIks ?? []);
  if (!denied.size) return false;
  if ((rec.lastRotationRecipients ?? []).some((ik) => denied.has(ik))) return true;
  const deniedVids = deniedVidsOf(rec);
  return (rec.epochRecipients ?? []).some((v) => deniedVids.has(v));
}

/** b75r2 (audit R2G-01): rotationUnfit against the record a rotation holds AND the live one (a save of a copy
 *  replaces the live record, and a Remove tap then lands on the new one) */
function rotationUnfitNow(store: VeilStorage, rec: GroupRecord, p: PendingRotation): string | null {
  const live = groupRecord(store, rec.groupToken);
  return rotationUnfit(rec, p) ?? (live && live !== rec ? rotationUnfit(live, p) : null);
}

function rotationUnfit(rec: GroupRecord, p: PendingRotation): string | null {
  const denied = new Set(rec.evictedIks ?? []);
  if (p.recipients.some((ik) => denied.has(ik))) return 'wraps to a removed member';
  const deniedVids = deniedVidsOf(rec);
  if ((p.rc ?? []).some((v) => deniedVids.has(v))) return 'names a removed member';
  if (rec.role === 'creator') {
    const covered = new Set([...p.recipients, ...(p.rc ?? [])]);
    for (const [ik, vid] of Object.entries(rec.admitted ?? {})) {
      if (ik === rec.ikPubB64 || denied.has(ik) || Number(rec.joinEpochs?.[ik] ?? 0) > p.epoch) continue;
      if (!covered.has(ik) && !covered.has(vid)) return 'leaves out a member';
    }
  }
  return null;
}

/** b75r1 (audit G-6): drop a rotation nothing of which was tried if it no longer fits (rotationUnfit) */
function discardIfUnfit(store: VeilStorage, rec: GroupRecord, p: PendingRotation): boolean {
  if (p.sent.length || (p.attempted ?? []).length) return false;
  const why = rotationUnfitNow(store, rec, p); // b75r2 (audit R2G-01): the live record too
  if (!why) return false;
  console.log('[veil-group] discarded an unsent rotation: the membership changed while it was being made', { groupToken: rec.groupToken.slice(0, 6), epoch: p.epoch, why });
  for (const r of new Set([rec, groupRecord(store, rec.groupToken) ?? rec])) if (!r.pendingRotation || r.pendingRotation.rid === p.rid) r.pendingRotation = undefined;
  return true;
}

/**
 * b74 (VAR-02, belt and braces): a pending rotation prepared BEFORE an admission doesn't wrap to
 * the newcomer — and must never become the newcomer's first epoch (members may already be
 * posting under it: it is pre-admission history). Every trusted member whose join epoch is at
 * or below the pending epoch must be among its recipients (or its signed rc, for a member
 * skipped for a bad prekey). If one isn't, the rotation is stale:
 *  - nothing of it was ever tried: thrown away (a fresh one, prepared now, covers them);
 *  - parts may be out: it is finished (the group must not split), but every uncovered member's
 *    join epoch moves past it, so deliverGroupKey never hands them that epoch's key and the
 *    creator owes one more rotation (rotationOwed).
 */
async function dropStaleRotation(rec: GroupRecord): Promise<void> {
  const p = rec.pendingRotation;
  if (!p || p.epoch !== rec.epoch + 1) return;
  const trusted = (await trustedMembers(rec)) ?? {};
  const covered = new Set([...p.recipients, ...(p.rc ?? [])]);
  const uncovered = Object.entries(trusted).filter(([ik, vid]) => ik !== rec.ikPubB64
    && Number(rec.joinEpochs?.[ik] ?? 0) <= p.epoch && !covered.has(ik) && !covered.has(vid)).map(([ik]) => ik);
  if (!uncovered.length) return;
  if (!p.sent.length && !(p.attempted ?? []).length) {
    console.log('[veil-group] discarded an unsent rotation prepared before an admission', { groupToken: rec.groupToken.slice(0, 6), epoch: p.epoch });
    rec.pendingRotation = undefined;
    return;
  }
  const je = { ...(rec.joinEpochs ?? {}) };
  for (const ik of uncovered) je[ik] = Math.max(Number(je[ik] ?? 0), p.epoch + 1);
  rec.joinEpochs = je;
  console.log('[veil-group] finishing a rotation already partly sent; members admitted after it was made get the next one', { groupToken: rec.groupToken.slice(0, 6), epoch: p.epoch, owed: uncovered.length });
}

/**
 * Batch C (A3): durable rotation. The new key, epoch and signed parts are saved
 * BEFORE the first send; a retry (after a crash, a network error, or a relay
 * refusal) resends the SAME parts, so a group can never split into two keys for
 * one epoch. Parts already accepted are not resent. Serialised per group.
 * If an eviction is pending and the finished rotation still wrapped to an
 * evicted IK (it was prepared before the eviction), one more rotation runs.
 */
/** b71 (device test): a creator record still owes a rotation (the reasons pollGroupInbox reports) */
function rotationOwed(rec: GroupRecord): boolean {
  return rec.role === 'creator' && (groupNeedsRotation(rec) || !rec.linksV2 || !!rec.pendingRotation || rec.evictionPendingAt !== undefined
    || Object.values(rec.joinEpochs ?? {}).some((e) => e > rec.epoch));
}

export async function rotateGroup(
  deps: GroupSessionDeps,
  opts: { groupToken: string; sessionToken: string; clientId: string;
    /** b71 (device test): an automatic rotation (the poll asked for one) runs only if,
     *  once its turn comes, one is still owed — polls every few seconds used to queue
     *  rotation after rotation while one was in flight, and the epoch climbed without end */
    onlyIfNeeded?: boolean;
    /** b74 (VAR-02): an admission's rotation — runs (never as a reuse of a rotation prepared
     *  before the admission: see dropStaleRotation) unless, once its turn comes, the group is
     *  already at this epoch or past it (a rotation prepared after the admission got there) */
    untilEpoch?: number },
): Promise<number> {
  deps = pinDeps(deps); // b70 (re-review 12): a wipe while this waits on the relay stops its writes
  return withRotationLock(opts.groupToken, async () => {
    if (opts.onlyIfNeeded) {
      const cur = groupRecord(deps.storage, opts.groupToken);
      if (cur && !rotationOwed(cur)) return cur.epoch;
    }
    if (opts.untilEpoch !== undefined) {
      const cur = groupRecord(deps.storage, opts.groupToken);
      if (cur && cur.epoch >= opts.untilEpoch) return cur.epoch;
    }
    let epoch = await rotateOnce(deps, opts);
    const rec = groupRecord(deps.storage, opts.groupToken);
    if (rec && rec.evictionPendingAt !== undefined) {
      // b75r2 (audit R2G-01): judged on the deny list as it is AFTER each rotation (b75r1 kept the one read
      // before the second rotation, so a Remove tapped while that rotation was out could be marked done — and
      // the creator's sends unblocked — while the current epoch still reached the removed member), and on the
      // epoch's signed recipient set as well as its wraps (a member skipped for a bad prekey is named in it)
      if (epochReachesDenied(rec)) epoch = await rotateOnce(deps, opts);
      const after = groupRecord(deps.storage, opts.groupToken)!;
      if (!epochReachesDenied(after)) {
        after.evictionPendingAt = undefined;
        await saveGroupRecord(deps.storage, after);
      }
    }
    return epoch;
  });
}

async function rotateOnce(
  deps: GroupSessionDeps,
  opts: { groupToken: string; sessionToken: string; clientId: string },
): Promise<number> {
  let rec = groupRecord(deps.storage, opts.groupToken);
  if (!rec) throw new Error('Group keys are not on this device.');
  if (rec.role !== 'creator') throw new Error('Only the group creator can rotate the keys.');

  // b75r1 (audit G-6): a rotation is made, saved and (part by part) sent across several waits on the relay,
  // and a Remove tap (evictGroupMember) or an admission doesn't wait for it. Before anything of a rotation is
  // tried, it is checked against the record AS IT IS NOW (rotationUnfit: no denied recipient, nobody denied in
  // its rc, every trusted member it must cover covered). One that no longer fits is thrown away and a fresh
  // one is made — at most three times; then this attempt fails and the next one starts over (a pending
  // removal keeps the creator's sends blocked meanwhile). In b75 a removal landing while the prekey lookups
  // were out (the relay can hold them as long as it likes) left the next epoch's key wrapped to the removed
  // member: evictGroupMember's dropTaintedRotation ran before the rotation was recorded, so it saw nothing.
  // Every check and the step after it run with no wait in between, so nothing can slip in.
  let pending: PendingRotation | undefined;
  for (let round = 0; !pending; round++) {
    // b75r2 (audit R2G-01): each round starts from the live record (a save of a copy may have replaced it)
    rec = groupRecord(deps.storage, opts.groupToken) ?? rec;
    dropTaintedRotation(rec);
    await dropStaleRotation(rec);
    let p: PendingRotation;
    if (rec.pendingRotation && rec.pendingRotation.epoch === rec.epoch + 1) {
      p = rec.pendingRotation;
    } else {
      p = await prepareRotation(deps, rec, opts.sessionToken);
      const why = rotationUnfitNow(deps.storage, rec, p);
      if (why) {
        console.log('[veil-group] the membership changed while new keys were being made — made again', { groupToken: rec.groupToken.slice(0, 6), why });
        if (round >= 2) throw new Error('The group’s members changed while new keys were being made, so nothing was sent. Try again in a moment.');
        continue;
      }
      rec.pendingRotation = p;
    }
    // Batch D (D-07, RV-06): persist-before-send is checked, not assumed — the
    // save throws on a storage error, and the copy ON DISK must hold this rotation
    await saveGroupRecord(deps.storage, rec);
    if ((await readPersistedGroupRecord(deps.storage, opts.groupToken))?.pendingRotation?.rid !== p.rid) {
      throw new Error('The new group keys could not be saved on this device, so nothing was sent. Try again in a moment.');
    }
    crashPoint('persist');

    // b73 (audit V-07): members refuse a rekey (with rc) that gives the key to anyone not on
    // their signed list. A rotation that admits someone wraps to them before any list names
    // them, so a list naming them goes out first, under the current key (they can't read it:
    // they hold no key of this epoch). Only before the first part is tried.
    // b75 (audit GR-5): that list was built (and numbered) with the rotation and is signed into its parts
    // (ms, mh); it is sent here, the same text on every retry. A failure stops the rotation before anything
    // of it is sent (retried).
    if (p.preList && !p.preList.sent && !p.sent.length && !(p.attempted ?? []).length) {
      if (discardIfUnfit(deps.storage, rec, p)) { if (round >= 2) throw new Error('The group’s members changed while new keys were being made, so nothing was sent. Try again in a moment.'); await saveGroupRecord(deps.storage, rec); continue; }
      await submitGroupEnvelope(deps, { groupToken: opts.groupToken, sessionToken: opts.sessionToken, clientId: opts.clientId, text: p.preList.text, control: 'membership' });
      p.preList = { ...p.preList, sent: true };
      // b75r2 (audit R2G-01): unless a later list was numbered while this one was on its way (members keep the
      // later one, so "who they trust" stays at it; a rotation to anyone else then publishes again)
      if ((groupRecord(deps.storage, opts.groupToken) ?? rec).memberSeq === p.preList.seq) {
        rec.listedIks = p.preList.iks;
        rec.listedHash = p.preList.hash;
      }
      if (rec.pendingRotation?.rid === p.rid || !rec.pendingRotation) rec.pendingRotation = p;
      await saveGroupRecord(deps.storage, rec);
    }
    // b75r1 (audit G-6): the last check — right before the first part is recorded as tried (no wait between)
    if (!p.sent.length && !(p.attempted ?? []).length && discardIfUnfit(deps.storage, rec, p)) {
      if (round >= 2) throw new Error('The group’s members changed while new keys were being made, so nothing was sent. Try again in a moment.');
      await saveGroupRecord(deps.storage, rec);
      continue;
    }
    pending = p;
  }

  for (let i = 0; i < pending.parts.length; i++) {
    if (pending.sent.includes(i)) continue;
    if (!(pending.attempted ?? []).includes(i)) {
      pending.attempted = [...(pending.attempted ?? []), i]; // b70 (re-review 3): recorded BEFORE the submit
      rec.pendingRotation = pending;
      await saveGroupRecord(deps.storage, rec);
    }
    await submitGroupEnvelope(deps, { groupToken: opts.groupToken, sessionToken: opts.sessionToken, clientId: opts.clientId, text: pending.parts[i], control: 'membership' });
    pending.sent = [...pending.sent, i];
    rec.pendingRotation = pending;
    await saveGroupRecord(deps.storage, rec);
    crashPoint(`part-${i}`);
  }

  let refusal: string | null = null;
  try {
    const res = await deps.relay.invoke('veilGroupGate', {
      action: 'rotate',
      group_token: opts.groupToken,
      session_token: opts.sessionToken,
      write_secret: await mainWriteSecret(deps, opts.sessionToken),
      new_epoch: pending.epoch,
      group_pq_pub: pending.pqPubB64,
    }) as { status?: number; data?: { error?: string } };
    if ((res?.status ?? 200) >= 400 || res?.data?.error) refusal = String(res?.data?.error ?? res?.status);
  } catch (e) { refusal = String((e as Error)?.message ?? e); }
  if (refusal !== null) {
    // a retry after the relay already moved (crash after the relay step): its epoch tells us
    const roster = await gateRoster(deps, { groupToken: opts.groupToken, sessionToken: opts.sessionToken }).catch(() => null);
    if (roster?.epoch !== pending.epoch) throw new Error(`Rotation refused by the relay: ${refusal}`);
  }
  crashPoint('relay');

  await advanceEpoch(deps.storage, opts.groupToken, pending.epoch, pending.gekB64, pending.pqPubB64, undefined, pending.rc, pending.rid); // b73 (audit V-07); b77s (audit 4 GR-01): + the rotation's rid (deliveries carry it)
  const done = groupRecord(deps.storage, opts.groupToken)!;
  done.lastRotationRecipients = pending.recipients;
  done.lastRotationSkipped = pending.skipped ?? [];
  done.pendingRotation = undefined;
  done.linksV2 = true; // b71 (review P-01): any older link's key (g=) is a past epoch now
  await saveGroupRecord(deps.storage, done);
  // Batch C (A1): a fresh signed member list in the new epoch
  await publishMemberList(deps, opts).catch((e) => console.error('[veil-group] member list publish after rotation failed', String((e as Error)?.message ?? e)));
  return pending.epoch;
}

// ---------- Batch C (A3): missing-wrap requests through the gate ----------

/** b75 (audit GR-8): v2 — the signed request carries its time (at, ms) and a random nonce; the creator
 *  answers only a fresh one (WRAP_REQUEST_MAX_AGE_MS either way) and each nonce once. v1 had neither,
 *  so a relay could replay a member's old request to make the creator deliver again whenever it liked. */
const WRAP_REQUEST_LABEL = 'vardum-wrap-request-v2';
export const WRAP_REQUEST_MAX_AGE_MS = 30 * 60_000;
function wrapRequestMessage(groupToken: string, veilId: string, ikPub: string, have: number, at: number, nonce: string): string {
  return JSON.stringify({ v: WRAP_REQUEST_LABEL, group_token: groupToken, veil_id: veilId, IK_pub: ikPub, have_epoch: have, at, nonce });
}
const wrapServiceAt = new Map<string, number>();
/** test knob: how often the creator checks for wrap requests */
export const wrapServiceTiming = { intervalMs: 60_000 };

function gateBody(r: unknown): Record<string, unknown> {
  const d = ((r as { data?: unknown })?.data ?? {}) as Record<string, unknown>;
  return ((d.data && typeof d.data === 'object') ? d.data : d) as Record<string, unknown>;
}

/**
 * Member: collect a creator-signed key delivery the gate holds for this device
 * (a missed rotation's wrap, or b71 (review P-01): a joiner's first key). A
 * delivered wrap is a normal creator-signed rekey: applyRekeyPayload checks the
 * creator signature, the group, forward-only epoch (any epoch for a joiner without
 * a key) and the key commitment, exactly as in-group.
 */
async function collectKeyDelivery(deps: GroupSessionDeps, rec: GroupRecord, sessionToken: string, identity: GroupIdentity): Promise<boolean> {
  const ws = await mainWriteSecret(deps, sessionToken);
  const fetched = gateBody(await deps.relay.invoke('veilGroupGate', { action: 'wrap_fetch', group_token: rec.groupToken, session_token: sessionToken, write_secret: ws, IK_pub: rec.ikPubB64 }));
  if (typeof fetched.payload === 'string' && fetched.payload) {
    const p = parseRekeyPayload(fetched.payload);
    if (p && p !== 'invalid' && await applyRekeyPayload(deps.storage, rec.groupToken, p, identity.pqPrivB64, { delivered: true })) { // b73 (audit V-07)
      console.log('[veil-group] group key received through the gate', { groupToken: rec.groupToken.slice(0, 6), epoch: p.ge });
      return true;
    }
  }
  return false;
}

/**
 * Member: this device missed a rotation (the relay refuses envelopes off the
 * current epoch, so it cannot ask in the group), or (b71) has joined and holds no
 * key yet. Collect a delivery; otherwise file a request signed with this device's
 * IK (at most every 10 minutes). have_epoch 0 = no key at all.
 */
async function recoverMissingWrap(deps: GroupSessionDeps, rec: GroupRecord, sessionToken: string, identity: GroupIdentity): Promise<boolean> {
  if (await collectKeyDelivery(deps, rec, sessionToken, identity)) return true;
  const ws = await mainWriteSecret(deps, sessionToken);
  const live = groupRecord(deps.storage, rec.groupToken) ?? rec;
  if (Date.now() - Number(live.wrapRequestedAt ?? 0) < 10 * 60_000) return false;
  const have = live.gekB64 ? live.epoch : 0; // b71 (review P-01)
  const at = Date.now(); // b75 (audit GR-8): freshness
  const nonce = hexRand(16);
  // b77t (audit 5 M-C): a keyless request's nonce is kept (before it goes out): the creator binds its answer to it
  if (have === 0) live.wrapReqNonces = [...(live.wrapReqNonces ?? []), [nonce, at] as [string, number]].slice(-8);
  const msg = wrapRequestMessage(rec.groupToken, rec.veilId, rec.ikPubB64, have, at, nonce);
  await deps.relay.invoke('veilGroupGate', {
    action: 'wrap_request', group_token: rec.groupToken, session_token: sessionToken, write_secret: ws,
    veil_id: rec.veilId, IK_pub: rec.ikPubB64, have_epoch: have, at, nonce, sig: await ikSign(rec.ikSeedB64, toB64(utf8(msg))),
  });
  live.wrapRequestedAt = Date.now();
  await saveGroupRecord(deps.storage, live);
  console.log('[veil-group] asked the creator for a missing wrap', { groupToken: rec.groupToken.slice(0, 6), haveEpoch: have });
  return false;
}

/**
 * b75r2 (audit R2G-01): creator — may this identity be handed the key of the record's CURRENT epoch, right now?
 * Admitted under exactly this Vardum ID, not on the deny list, not the creator itself, and its join epoch reached
 * (b71 audit F-02: a newcomer is owed only an epoch that started after it was let in). Synchronous on purpose:
 * every caller acts on the answer with no wait in between. Pass the LIVE record (groupRecord), never a copy read
 * before a wait on the relay — a Remove tap, an admission or a rotation may have landed during that wait.
 */
function creatorMayDeliver(rec: GroupRecord | null | undefined, ik: string, vid: string): rec is GroupRecord {
  if (!rec || rec.role !== 'creator' || !rec.gekB64 || !ik || !vid || ik === rec.ikPubB64) return false;
  if ((rec.evictedIks ?? []).includes(ik)) return false;
  const adm = rec.admitted && Object.prototype.hasOwnProperty.call(rec.admitted, ik) ? rec.admitted[ik] : undefined;
  if (adm !== vid) return false;
  if (rec.joinEpochs && Object.prototype.hasOwnProperty.call(rec.joinEpochs, ik)) {
    const owed = Number(rec.joinEpochs[ik]);
    if (!Number.isFinite(owed) || owed > rec.epoch) return false;
  }
  return true;
}

/** b75r2 (audit R2G-01): creator — the members it trusts right now (admitted minus denied, minus itself), read
 *  synchronously from the record it is given (trustedMembers' creator branch, without the wait) */
function creatorMembersNow(rec: GroupRecord): Array<[string, string]> {
  const denied = new Set(rec.evictedIks ?? []);
  return Object.entries(rec.admitted ?? {}).filter(([ik]) => ik !== rec.ikPubB64 && !denied.has(ik));
}

/**
 * Creator: deliver the CURRENT key to one member through the gate — a creator-
 * signed rekey for the current epoch carrying one wrap to the member's published
 * PQ prekey, which must be signed by the same IK the creator admitted. b71 (review
 * P-01): this is also how a newly admitted joiner gets its first key (links carry
 * none), with the group's name under that key (nm). false = no valid prekey, or
 * (b75r2) the member may not be given this epoch's key (any more).
 *
 * b75r2 (audit R2G-01): the delivery waits on the relay (the prekey lookup, the write secret, building the wrap
 * and signing it), and a Remove tap, an admission or a rotation doesn't wait for it. b75r1 checked the member
 * only BEFORE the lookup and then wrapped whatever key the record held when the lookup came back — so a relay
 * that held the lookup while the creator removed the member got the POST-removal epoch's key wrapped to the
 * removed member (from its own signed wrap request, or the admission of a newcomer removed meanwhile). Now:
 *  - after the last wait before the wrap is made, the LIVE record is read again and the member checked again
 *    (creatorMayDeliver: still admitted, not denied, join epoch reached); the epoch, key and list it uses are
 *    taken from that same read, with no wait in between;
 *  - right before the delivery is sent (no wait between the check and the send) the live record is checked once
 *    more: a member removed while the wrap was being made gets nothing, and a delivery made for an epoch the
 *    group has since left is made again for the new one (at most three times).
 * What can still happen: a removal tapped while the delivery is already on the network. That delivery carries
 * the epoch that was current before the removal — one the member was entitled to — and the removal's own
 * rotation moves the group past it.
 */
async function deliverGroupKey(deps: GroupSessionDeps, rec: GroupRecord, sessionToken: string, ik: string, vid: string,
  /** b77t (audit 5 M-C): the signed nonce of the keyless request this answers (its rid is bound to it) */
  bindNonce?: string): Promise<boolean> {
  const gt = rec.groupToken;
  for (let round = 0; round < 3; round++) {
    if (!creatorMayDeliver(groupRecord(deps.storage, gt), ik, vid)) return false;
    const d = gateBody(await deps.relay.invoke('veilIdentityGate', { action: 'lookup', veil_id: vid }).catch(() => null));
    const pqPub = String(d.pq_pub ?? ''), pqSig = String(d.pq_sig ?? '');
    if (String(d.IK_pub ?? '') !== ik || !pqPub || !(await verifyPqPrekeySig(ik, pqPub, pqSig).catch(() => false))) return false;
    const ws = await mainWriteSecret(deps, sessionToken);
    // b75r2 (audit R2G-01): everything the delivery is made of comes from ONE read of the live record, taken
    // after the waits above and checked first — nothing read before a wait is used after it
    const live = groupRecord(deps.storage, gt);
    if (!creatorMayDeliver(live, ik, vid)) return false;
    const epoch = live.epoch, gek = live.gekB64, pq = live.pqPubB64, name = live.name, seed = live.ikSeedB64;
    // b73 (audit V-07): the epoch's recipient set, as in the rotation's parts (a member trusted only
    // after the rotation, e.g. a confirmed legacy roster entry, is added for its own delivery).
    // b74: always present
    const rc = [...new Set([...(live.epochRecipients ?? []), vid])].sort();
    const at = Date.parse(String(live.epochStartedAt ?? '')) || undefined; // b70 (re-review 6): the epoch's real start
    // b75 (audit GR-5): the creator's latest published list (a delivery's recipient check doesn't use it)
    const ms = live.memberSeq ?? 0;
    // b77t (audit 5 L-8 / IH V-07): the hash of the list NUMBERED ms (recorded with the number), not listedHash —
    // memberSeq moves when a list is numbered, listedHash only once its send is confirmed, so one failed submit
    // signed (new number, old hash) and the member raised a false equivocation alarm (and stopped sending)
    const listedHash = live.numberedList && live.numberedList[0] === ms ? live.numberedList[1] : live.listedHash;
    const membersNow = creatorMembersNow(live);
    const wrap = await buildRekeyWrap(pqPub, vid, gek, { groupToken: gt, epoch, memberIkPubB64: ik }); // b77m (audit VAR-10): hybrid
    const text = await buildSignedRekeyText(seed, gt, epoch, pq, [wrap], {
      // b77s (audit 4 GR-01): a delivery carries the rid of the rotation that made this epoch (when this phone
      // made one), so a copy of it read anywhere names the same rotation as the posted parts (a new random rid
      // read as a second key change for the epoch)
      // b77t (audit 5 M-C): an answer to a keyless request carries a rid bound to its nonce instead (a keyless phone
      // holds no epochRid to compare it with; it takes a delivery for an epoch it held before only when so bound)
      rid: bindNonce ? await deliveryBindRid(gt, epoch, bindNonce) : live.epochRid && /^[0-9a-f]{16,64}$/.test(live.epochRid) ? live.epochRid : hexRand(16), kc: await gekCommitment(gt, epoch, gek), pi: 0, pc: 1, at,
      ...(name ? { nm: await encryptGroupText(gek, name) } : {}),
      rc, ms, mh: listedHash ?? await membersHash(membersNow),
    });
    // b75r2 (audit R2G-01): the last check — no wait between it and the send
    const now = groupRecord(deps.storage, gt);
    if (!creatorMayDeliver(now, ik, vid)) {
      console.log('[veil-group] key delivery dropped: the member was removed while it was being made', { groupToken: gt.slice(0, 6) });
      return false;
    }
    if (now.epoch !== epoch || now.gekB64 !== gek) continue; // the group moved on meanwhile: made again for the new epoch
    const res = await deps.relay.invoke('veilGroupGate', { action: 'wrap_deliver', group_token: gt, session_token: sessionToken, write_secret: ws, target_IK_pub: ik, payload: padKeyDelivery(text) }) as { status?: number; data?: { error?: string } }; // b76r1 (audit AUD-I1): padded to a size class
    if ((res?.status ?? 200) >= 400 || res?.data?.error) throw new Error(`wrap delivery refused: ${res?.data?.error ?? res?.status}`);
    return true;
  }
  return false;
}

/**
 * Creator: answer missing-wrap requests. Only for identities this creator
 * admitted (and has not evicted), whose request is signed by that IK, who are
 * behind (or, b71, hold no key yet: have_epoch 0), and whose published PQ prekey
 * is signed by the same IK.
 * b75r2 (audit R2G-01): who is trusted, and the epoch a request must be behind, are read from the LIVE record
 * for every request (b75r1 worked the trusted set out once, before the loop, so a member removed while an
 * earlier request was being served still passed); deliverGroupKey checks again after each of its own waits.
 */
async function serviceWrapRequests(deps: GroupSessionDeps, rec: GroupRecord, sessionToken: string): Promise<number> {
  if (Date.now() - (wrapServiceAt.get(rec.groupToken) ?? 0) < wrapServiceTiming.intervalMs) return 0;
  wrapServiceAt.set(rec.groupToken, Date.now());
  const ws = await mainWriteSecret(deps, sessionToken);
  const listed = gateBody(await deps.relay.invoke('veilGroupGate', { action: 'wrap_requests', group_token: rec.groupToken, session_token: sessionToken, write_secret: ws }));
  const requests = Array.isArray(listed.requests) ? listed.requests as Record<string, unknown>[] : [];
  let served = 0;
  const now = Date.now();
  // b75 (audit GR-8): nonces already answered (within the freshness window; older ones are refused anyway)
  const seen = ((groupRecord(deps.storage, rec.groupToken) ?? rec).wrapReqSeen ?? []).filter(([, t]) => now - t <= 2 * WRAP_REQUEST_MAX_AGE_MS);
  for (const r of requests) {
    const ik = String(r.IK_pub ?? ''), vid = String(r.veil_id ?? ''), have = Number(r.have_epoch), sig = String(r.sig ?? '');
    const at = Number(r.at), nonce = String(r.nonce ?? '');
    const cur = groupRecord(deps.storage, rec.groupToken); // b75r2 (audit R2G-01): per request, never before the loop
    if (!cur) break; // the group was forgotten (or the phone wiped) meanwhile
    if (!creatorMayDeliver(cur, ik, vid) || !Number.isInteger(have) || have >= cur.epoch) continue;
    // b75 (audit GR-8): signed time within the window (either way: a phone's clock may run ahead) and an unused nonce
    if (!Number.isInteger(at) || Math.abs(now - at) > WRAP_REQUEST_MAX_AGE_MS || !/^[0-9a-f]{32}$/.test(nonce) || seen.some(([n]) => n === nonce)) continue;
    const msg = wrapRequestMessage(rec.groupToken, vid, ik, have, at, nonce);
    if (!(await verifyWithIk(ik, toB64(utf8(msg)), sig).catch(() => false))) continue;
    // b77t (audit 5 M-C): a keyless member's request gets an answer bound to its nonce (deliveryBindRid)
    if (await deliverGroupKey(deps, rec, sessionToken, ik, vid, have === 0 ? nonce : undefined).catch(() => false)) {
      served += 1;
      seen.push([nonce, at]);
    }
  }
  const live = groupRecord(deps.storage, rec.groupToken);
  if (!live) return served;
  // (merged with what the live record holds now, so a nonce answered elsewhere meanwhile stays answered)
  const merged = [...(live.wrapReqSeen ?? []).filter(([n]) => !seen.some(([m]) => m === n)), ...seen].filter(([, t]) => now - t <= 2 * WRAP_REQUEST_MAX_AGE_MS);
  const nextSeen = merged.length ? merged.slice(-256) : undefined;
  if (JSON.stringify(nextSeen ?? null) !== JSON.stringify(live.wrapReqSeen ?? null)) {
    live.wrapReqSeen = nextSeen;
    await saveGroupRecord(deps.storage, live).catch(() => undefined);
  }
  if (served) console.log('[veil-group] delivered missing wraps', { groupToken: rec.groupToken.slice(0, 6), served });
  return served;
}

/**
 * Batch E (round-3 review F-3): the creator's answer about a pre-Batch-C group's
 * old roster. The listed identity keys are admitted; everyone else stays pending
 * (they can still come in through a seat). Asked once either way; the signed
 * member list goes out on the next pass.
 */
export async function confirmLegacyRoster(store: VeilStorage, groupToken: string, confirmIks: string[]): Promise<number> {
  const rec = await loadGroupRecordStrict(store, groupToken);
  if (!rec || rec.role !== 'creator' || !rec.legacyRoster) return 0;
  const held = rec.legacyRoster;
  let n = 0;
  rec.admitted = { ...(rec.admitted ?? {}) };
  for (const ik of confirmIks) {
    if (held[ik] && !(rec.evictedIks ?? []).includes(ik)) { rec.admitted[ik] = held[ik]; n += 1; }
  }
  rec.legacyRoster = undefined;
  rec.memberListDirty = true;
  await saveGroupRecord(store, rec);
  return n;
}

/**
 * Creator: build (and number) the signed member list — admitted minus denied — without sending it.
 * b75 (audit GR-5): split out of publishMemberList so a rotation can sign, in its rekey parts, the list
 * it will publish before them (seq = the parts' ms, hash = their mh).
 * b75r2 (audit R2G-01): the members, the removal notices, the epoch and the number are all taken in ONE step
 * with no wait in between, from the LIVE record (b75r1 read the members, waited, and only then numbered the
 * list — so a Remove tap landing in that wait could get the LOWER number, and the stale list naming the removed
 * member, numbered after it, was the one members kept). Whatever lands after that step gets a later number.
 */
async function buildMemberList(deps: GroupSessionDeps, rec: GroupRecord, groupToken: string, snapshot?: Array<[string, string]>): Promise<{ seq: number; text: string; iks: string[]; hash: string }> {
  // b71 (review P-03): the creator's own self-signed name (signed before the step below: it is the only wait)
  const myNick = (rec.myNick ?? '').trim().slice(0, 40);
  const mySig = myNick ? await signGroupName(rec.ikSeedB64, groupToken, rec.ikPubB64, myNick) : '';
  // ---- from here to the save: no wait ----
  const live = groupRecord(deps.storage, groupToken) ?? rec;
  // b75r1 (audit G-6): a rotation passes the members it wraps to, so its list and its wraps can't differ
  // (a rotation whose membership changed meanwhile is thrown away before its list is sent: rotationUnfit)
  const members = snapshot ? snapshot.filter(([ik]) => ik !== live.ikPubB64) : creatorMembersNow(live);
  const seq = Math.max(live.memberSeq ?? 0, rec.memberSeq ?? 0) + 1;
  // b70 (re-review 7): the number is used up BEFORE the send — a list the relay stored
  // and then answered with an error must never be followed by a different list
  // under the same number (members keep the first and ignore the second)
  live.memberSeq = seq;
  if (rec !== live) rec.memberSeq = seq; // (a copy the caller holds and saves later carries it too)
  const epoch = live.epoch;
  const removed = live.removals ? live.removals.map((x) => [...x] as [string, string, number]) : undefined;
  // b71 (review P-03): every listed member's self-signed name, and the creator's own
  // b74 (VAR-06): each with its first-bound sequence (fb) — the order every phone resolves
  // clashes in (lowest first: whoever bound the name first keeps it plain)
  const names: Record<string, [string, string]> = {};
  if (myNick && (live.myNick ?? '').trim().slice(0, 40) === myNick) names[live.ikPubB64] = [myNick, mySig];
  for (const [ik] of members) {
    const e = live.nameSigs && Object.prototype.hasOwnProperty.call(live.nameSigs, ik) ? live.nameSigs[ik] : undefined;
    if (e) names[ik] = e;
  }
  const fb: Record<string, number> = {};
  for (const [ik, [name]] of Object.entries(names)) {
    noteNameBinding(live, ik, name); // (a name not seen before — a creator rename, an older record — gets its sequence now)
    fb[ik] = live.nameFb![ik][1];
  }
  // b77t (audit 5 L-8): the hash of the list numbered seq, kept with that number (a key delivery signs the pair).
  // b77t2 (L-8): computed with no wait and saved in the SAME write as the number (a crash between two writes left
  // memberSeq ahead of numberedList)
  const hash = membersHashSync(members);
  live.numberedList = [seq, hash];
  if (rec !== live) rec.numberedList = [seq, hash];
  await saveGroupRecord(deps.storage, live);
  // b71 (audit F-04): with the recent removals, so a member still on an older epoch stops sending
  // b74 (VAR-19 part): bound to the epoch it is sent in (members apply it only in that epoch)
  const text = await buildSignedMembersText(live.ikSeedB64, groupToken, seq, epoch, members, { names, fb, removed });
  return { seq, text, iks: members.map(([ik]) => ik), hash };
}

/** Batch C (A1): creator — send the signed member list (admitted minus denied). */
export async function publishMemberList(
  deps: GroupSessionDeps,
  opts: { groupToken: string; sessionToken: string; clientId: string },
): Promise<number> {
  deps = pinDeps(deps); // b70 (re-review 12): a wipe while this waits on the relay stops its writes
  const rec = groupRecord(deps.storage, opts.groupToken);
  if (!rec || rec.role !== 'creator') throw new Error('Only the group creator can publish the member list.');
  const list = await buildMemberList(deps, rec, opts.groupToken);
  await submitGroupEnvelope(deps, { groupToken: opts.groupToken, sessionToken: opts.sessionToken, clientId: opts.clientId, text: list.text, control: 'membership' });
  // b73 (audit V-07): who the members now trust (a rotation to anyone else publishes first)
  // b75r2 (audit R2G-01): on the live record, and only if no later list was numbered while this one was on its
  // way (members keep the later one)
  const live = groupRecord(deps.storage, opts.groupToken);
  if (live && live.memberSeq === list.seq) {
    live.listedIks = list.iks;
    live.listedHash = list.hash; // b75 (audit GR-5)
    await saveGroupRecord(deps.storage, live).catch(() => undefined);
  }
  return list.seq;
}

/**
 * Batch C (A1): creator — check a roster identity's seat claim: its signed intro
 * must prove possession of a seat this device minted (HMAC with the seat key, which
 * derives from the link secret the relay never sees). One IK per seat; a locked
 * seat admits only its invitee. Read-only: nothing on the record changes here.
 *
 * b71 (audit F-07): this used to ADMIT on the spot, inside the poll, with nobody
 * asked — anyone holding an unused link was let in (and, after a removal, the
 * removed person under a new identity). Now it returns the checked claim; the
 * creator approves or declines it (admitGroupClaims / declineGroupClaim). A claim
 * on a CONTACT seat by exactly the invited contact's key is marked `contact` and
 * admitted without a tap. Why that is safe: the creator chose that one person when
 * inviting; the link travelled only inside the encrypted 1:1 chat with them; the
 * seat admits nobody but the identity key whose hash is that contact's Vardum ID
 * (and, when the app passed it, exactly the key pinned for the contact) — a forwarded
 * or stolen copy of the link is useless to anyone else, since the intro must be
 * signed by that key. A tap would add nothing the creator didn't already decide.
 * A plain link is a bearer credential that may have travelled anywhere, so it always
 * needs the tap. Returns null when the claim does not check out.
 */
async function checkSeatClaim(
  store: VeilStorage, rec: GroupRecord,
  e: { ik: string; veilId: string; headerStr: string; ciphertextB64: string; ivB64: string; sessionToken?: string },
): Promise<GroupSeatClaim | null> {
  if (!e.veilId || (rec.evictedIks ?? []).includes(e.ik)) return null;
  if (!(await verifyGroupEnvelopeSig(e.ik, e.headerStr, e.ciphertextB64, e.ivB64))) return null;
  let text = '';
  /** b71 (review P-01): the seat whose key opened a seat intro */
  let openedBy = '';
  let sv = 0;
  try { sv = Number((JSON.parse(e.headerStr) as { sv?: unknown }).sv); } catch { return null; }
  if (sv === GROUP_SEAT_SIG_VERSION) {
    // b71 (review P-01): a seat intro opens only with its own seat's key. The row's
    // session token (the seat the relay says it came through) is tried first; it is
    // only a hint — every unused seat is tried if it fails.
    const seatsNow = rec.seats ?? {};
    const own = (t: string) => Object.prototype.hasOwnProperty.call(seatsNow, t);
    const candidates = [...(e.sessionToken && own(e.sessionToken) ? [e.sessionToken] : []), ...Object.keys(seatsNow).filter((t) => t !== e.sessionToken && (!seatsNow[t]?.usedBy || seatsNow[t]?.usedBy === e.ik))];
    for (const t of candidates.slice(0, 256)) {
      const s = seatsNow[t];
      if (!s || typeof s.key !== 'string' || !s.key) continue;
      try { text = (await decryptSeatIntro(s.key, rec.groupToken, t, e.headerStr, e.ciphertextB64, e.ivB64)).text; openedBy = t; break; } catch { /* not this seat */ }
    }
    if (!openedBy) return null;
  } else {
    // an older build's join intro, under the group key it took from its pre-b71 link
    try { text = (await decryptOwnGroupEnvelope(store, rec.groupToken, e.headerStr, e.ciphertextB64, e.ivB64)).text; } catch { return null; }
  }
  const parsed = parseGroupIntro(text);
  const intro = parsed ? await verifyGroupIntro(parsed, rec.groupToken) : null; // b75 (audit GR-8): for this group
  if (!intro || intro.ikPub !== e.ik || intro.veilId !== e.veilId || !intro.seat || !intro.sp) return null;
  if (openedBy && intro.seat !== openedBy) return null; // b71: the seat it names is the seat whose key opened it
  // Batch D (D-08, RV-32): own properties only ("__proto__" is not a seat)
  if (!rec.seats || !Object.prototype.hasOwnProperty.call(rec.seats, intro.seat)) return null;
  if ((rec.retiredSeats ?? []).includes(intro.seat)) return null; // b71 (audit F-01)
  const seat = rec.seats[intro.seat];
  if (!seat || typeof seat.key !== 'string' || !seat.key) return null;
  if (seat.invitee && seat.invitee !== e.veilId) return null;
  // b71 (audit F-07): a contact seat whose pinned key is known admits exactly that key
  if (seat.inviteeIk && seat.inviteeIk !== e.ik) return null;
  if (seat.usedBy && seat.usedBy !== e.ik) return null;
  // b71 (review P-01): an unused seat expires (its link may have travelled far)
  if (!seat.usedBy && seat.at !== undefined && Date.now() - seat.at > SEAT_MAX_AGE_MS) return null;
  const expected = await seatProof(seat.key, rec.groupToken, intro.seat, e.veilId, e.ik);
  if (!ctEqStr(expected, intro.sp)) return null;
  // b70 (audit VAR-10 / GRP-1): a joiner on b70+ also proves which creator key
  // its link named. If that isn't this creator's key, someone swapped c= on the
  // way: the seat is NOT admitted (the joiner would trust the wrong "creator").
  if (intro.sp2 !== undefined) {
    const expected2 = await seatProofForCreator(seat.key, rec.groupToken, intro.seat, e.veilId, e.ik, rec.creatorIkPubB64 ?? rec.ikPubB64);
    if (!ctEqStr(expected2, intro.sp2)) return null;
  }
  const nick = intro.nick ? intro.nick.trim().slice(0, 40) : '';
  const ns = nick && intro.ns && await verifyGroupName(rec.groupToken, e.ik, nick, intro.ns) ? intro.ns : undefined;
  // (verifyGroupIntro checked that the Vardum ID is the hash of this key)
  const contact = !!seat.invitee && seat.invitee === e.veilId;
  return { veilId: e.veilId, seat: intro.seat, ...(nick ? { nick } : {}), ...(ns ? { ns } : {}), at: Date.now(), ...(contact ? { contact: true } : {}) };
}

/** b71 (audit F-07): still a valid claim on the creator's record right now? */
function claimStillValid(rec: GroupRecord, ik: string, c: GroupSeatClaim): boolean {
  if ((rec.evictedIks ?? []).includes(ik) || (rec.retiredSeats ?? []).includes(c.seat)) return false;
  const seat = rec.seats && Object.prototype.hasOwnProperty.call(rec.seats, c.seat) ? rec.seats[c.seat] : undefined;
  if (!seat || (seat.usedBy && seat.usedBy !== ik)) return false;
  if (seat.invitee && seat.invitee !== c.veilId) return false;
  if (seat.inviteeIk && seat.inviteeIk !== ik) return false;
  if (!seat.usedBy && seat.at !== undefined && Date.now() - seat.at > SEAT_MAX_AGE_MS) return false;
  return true;
}

/**
 * b71 (audit F-07 / F-02): creator — admit these claims in ONE batch: mark the seats
 * used and the members admitted and owed a fresh epoch (joinEpochs = epoch + 1);
 * rotate once for all of them; then deliver the NEW epoch's key to each. A newcomer
 * therefore never holds the key of an epoch that started before it was let in, and
 * reads nothing posted before. If the rotation fails the admissions stand but no key
 * goes out (deliverGroupKey refuses before joinEpochs); the next pass reports
 * needsRotation, and the newcomers' own key requests are answered once it has run.
 */
async function admitClaimsNow(
  deps: GroupSessionDeps, rec: GroupRecord,
  opts: { groupToken: string; sessionToken: string; clientId: string; iks: string[] },
): Promise<{ admitted: Array<{ ikPub: string; veilId: string; label: string }>; epoch: number }> {
  const admitted: Array<{ ikPub: string; veilId: string; label: string }> = [];
  // b74 (VAR-02): the newcomers' first epoch starts after EVERY epoch that may already be in use:
  // this record's, a rotation prepared but not finished here (its parts and the relay's step
  // may already be out — members then post under it), and the relay's. (b73 used this record's
  // epoch + 1, which was exactly the half-finished rotation's epoch: the newcomer was handed a
  // key members had been using before it was let in.)
  const relayEpochRaw = await gateRoster(deps, { groupToken: opts.groupToken, sessionToken: opts.sessionToken }).then((r) => Number(r.epoch) || 0).catch(() => 0);
  // b75r2 (audit R2G-01): the record as it is AFTER that wait (a removal, a decline or a rotation may have landed
  // meanwhile, and a save of a copy may have replaced the live record): the claims are checked against it, and
  // the join epoch worked out from it
  rec = groupRecord(deps.storage, opts.groupToken) ?? rec;
  if (rec.role !== 'creator') return { admitted, epoch: rec.epoch };
  // b75r1 (audit G-5): the relay's epoch is its unsigned word, and only the creator moves it — one step at a
  // time, after saving the rotation (rotateOnce). So it can honestly be at most one past this record (a crash
  // after the relay's step, before the local one). b75 took it as it came: a relay over-reporting by 1000 at
  // an admission left the newcomer without a key for good, and the creator owing a rotation on every pass.
  const relayEpoch = Math.min(Number.isInteger(relayEpochRaw) && relayEpochRaw > 0 ? relayEpochRaw : 0, rec.epoch + 1);
  if (relayEpochRaw > rec.epoch + 1) console.warn('[veil-group] the relay reported an epoch more than one past this phone’s — ignored', { groupToken: opts.groupToken.slice(0, 6), relay: relayEpochRaw, local: rec.epoch });
  const joinEpoch = Math.max(rec.epoch, rec.pendingRotation?.epoch ?? 0, relayEpoch) + 1;
  for (const ik of [...new Set(opts.iks)]) {
    const c = rec.pendingClaims && Object.prototype.hasOwnProperty.call(rec.pendingClaims, ik) ? rec.pendingClaims[ik] : undefined;
    if (!c) continue;
    if (!claimStillValid(rec, ik, c)) { delete rec.pendingClaims![ik]; continue; }
    rec.seats = { ...(rec.seats ?? {}), [c.seat]: { ...rec.seats![c.seat], usedBy: ik } };
    rec.admitted = { ...(rec.admitted ?? {}), [ik]: c.veilId };
    rec.joinEpochs = { ...(rec.joinEpochs ?? {}), [ik]: joinEpoch };
    // b71 (audit F-12): a newcomer's posts are numbered from 1 — a missing first post counts
    rec.recvSeq = { ...(rec.recvSeq ?? {}), [ik]: 0 };
    if (c.nick) {
      // b71 (review P-03): the member's own seat-proven name is a binding on this phone;
      // with its self-signature it also goes into the signed member list for everyone
      rec.boundNicks = { ...(rec.boundNicks ?? {}), [ik]: c.nick };
      if (c.ns) rec.nameSigs = { ...(rec.nameSigs ?? {}), [ik]: [c.nick, c.ns] };
      noteNameBinding(rec, ik, c.nick); // b74 (VAR-06): bound now — after every name already held
    }
    delete rec.pendingClaims![ik];
    // another claim on the same seat can't be admitted any more
    for (const [other, oc] of Object.entries(rec.pendingClaims ?? {})) if (oc.seat === c.seat) delete rec.pendingClaims![other];
    admitted.push({ ikPub: ik, veilId: c.veilId, label: claimLabel(c) });
  }
  await saveGroupRecord(deps.storage, rec);
  if (!admitted.length) return { admitted, epoch: rec.epoch };
  console.log('[veil-group] admitting', { groupToken: opts.groupToken.slice(0, 6), count: admitted.length });
  // the rotation also publishes the new member list, in the new epoch
  // b74 (VAR-02): an unfinished rotation is finished FIRST (it was made before the admission and
  // doesn't wrap to the newcomers), then a FRESH rotation always runs — never onlyIfNeeded, never
  // a reuse — so the newcomers' first key is for an epoch that starts after they were let in.
  // (If either fails the admissions stand but no key goes out: deliverGroupKey refuses before
  // joinEpochs, and the next pass reports needsRotation.)
  // joinEpoch is past every epoch that could have been in use when they were let in, so
  // reaching it (here, or by an automatic rotation queued meanwhile) means a post-admission key.
  let epoch = rec.epoch;
  for (let i = 0; i < 3 && epoch < joinEpoch; i++) {
    epoch = await rotateGroup(deps, { groupToken: opts.groupToken, sessionToken: opts.sessionToken, clientId: opts.clientId, untilEpoch: joinEpoch });
  }
  // b75r2 (audit R2G-01): each delivery re-reads the live record after every one of its waits (a newcomer
  // removed while the rotation or an earlier delivery was out gets nothing)
  for (const a of admitted) {
    await deliverGroupKey(deps, rec, opts.sessionToken, a.ikPub, a.veilId)
      .then((ok) => { if (!ok) console.warn('[veil-group] key not delivered to a new member (no valid signed prekey yet — it will ask again — or no longer a member)', { veilId: a.veilId }); })
      .catch((e) => console.error('[veil-group] key delivery failed — the new member will ask again', String((e as Error)?.message ?? e)));
  }
  return { admitted, epoch };
}

/**
 * b71 (audit F-07): creator — approve people who asked to join (the app calls this
 * when the creator taps Approve). All approved claims are admitted in one batch with
 * one key rotation (admitClaimsNow). Returns who was admitted and the new epoch.
 */
export async function admitGroupClaims(
  deps: GroupSessionDeps,
  opts: { groupToken: string; sessionToken: string; clientId: string; iks: string[] },
): Promise<{ admitted: Array<{ ikPub: string; veilId: string; label: string }>; epoch: number }> {
  deps = pinDeps(deps); // a wipe while this waits on the relay stops its writes
  const rec = await loadGroupRecordStrict(deps.storage, opts.groupToken);
  if (!rec) throw new Error('This group is not on this device.');
  if (rec.role !== 'creator') throw new Error('Only the person who created this group can let people in.');
  return admitClaimsNow(deps, rec, opts);
}

/**
 * b71 (audit F-07): creator — decline a claim. The seat it came through is retired as
 * well (that link may be in the wrong hands, so nobody can use it again); to invite
 * the intended person, make a new link. true if there was such a claim.
 * b73 (audit V-01 / V-10): with the relay deps and the creator's main session token, the
 * relay is told too, with its creator-only `decline` action: it deletes the claimant's
 * roster row, any wrap request, every envelope it posted and its seat session (the link
 * is dead). Unlike a removal it adds no deny entry, so the same person can be invited
 * again with a new link. 404 (no row left) counts as done; 409 means the claimant was
 * already admitted (remove them instead). Best effort: a refusal is logged; the local
 * decline stands.
 * (Before, a declined claimant kept its relay seat: it could keep posting, and the relay
 * counted it in burn-after-open quorums.)
 */
export async function declineGroupClaim(
  deps: Pick<GroupSessionDeps, 'storage'> & Partial<Pick<GroupSessionDeps, 'relay' | 'sessions'>>,
  opts: { groupToken: string; ik: string; sessionToken?: string },
): Promise<boolean> {
  const rec = await loadGroupRecordStrict(deps.storage, opts.groupToken);
  if (!rec || rec.role !== 'creator') return false;
  const c = rec.pendingClaims && Object.prototype.hasOwnProperty.call(rec.pendingClaims, opts.ik) ? rec.pendingClaims[opts.ik] : undefined;
  if (!c) return false;
  delete rec.pendingClaims![opts.ik];
  const seat = rec.seats && Object.prototype.hasOwnProperty.call(rec.seats, c.seat) ? rec.seats[c.seat] : undefined;
  if (seat && !seat.usedBy) retireSeats(rec, [c.seat]);
  await saveGroupRecord(deps.storage, rec);
  if (deps.relay && deps.sessions && opts.sessionToken) {
    try {
      const res = await deps.relay.invoke('veilGroupGate', {
        action: 'decline',
        group_token: opts.groupToken,
        session_token: opts.sessionToken,
        write_secret: (await deps.sessions.load(opts.sessionToken) as RatchetStateSerialized & { writeSecret?: string })?.writeSecret ?? null,
        target_IK_pub: opts.ik,
      }) as { status?: number; data?: { error?: string } };
      const st = res?.status ?? 200;
      if (st !== 404 && (st >= 400 || res?.data?.error)) console.warn('[veil-group] relay did not drop the declined claimant:', String(res?.data?.error ?? st));
    } catch (e) {
      console.warn('[veil-group] relay did not drop the declined claimant:', String((e as Error)?.message ?? e));
    }
  }
  return true;
}

/** b71 (audit F-01): drop seats for good (and any claim on them) */
function retireSeats(rec: GroupRecord, tokens: string[]): void {
  if (!tokens.length) return;
  rec.retiredSeats = [...new Set([...(rec.retiredSeats ?? []), ...tokens])].slice(-512);
  const seats = { ...(rec.seats ?? {}) };
  for (const t of tokens) delete seats[t];
  rec.seats = seats;
  for (const [ik, c] of Object.entries(rec.pendingClaims ?? {})) if (tokens.includes(c.seat)) delete rec.pendingClaims![ik];
}

/** b75r3 (audit R3G-I1): ends retired seats on the relay (creator only; the relay keeps a seat holding an admitted
 *  membership, and skips seats it doesn't have). At most 64 per call. Never throws: a refusal is logged. */
async function retireSeatsOnRelay(deps: GroupSessionDeps, groupToken: string, sessionToken: string, tokens: string[]): Promise<void> {
  for (let i = 0; i < tokens.length; i += 64) {
    try {
      const res = await deps.relay.invoke('veilGroupGate', {
        action: 'retire_seats',
        group_token: groupToken,
        session_token: sessionToken,
        write_secret: await mainWriteSecret(deps, sessionToken),
        seat_tokens: tokens.slice(i, i + 64),
      }) as { status?: number; data?: { error?: string } };
      const st = res?.status ?? 200;
      if (st >= 400 || res?.data?.error) console.warn('[veil-group] relay did not end the retired invite links:', String(res?.data?.error ?? st));
    } catch (e) {
      console.warn('[veil-group] relay did not end the retired invite links:', String((e as Error)?.message ?? e));
    }
  }
}

function ctEqStr(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}

/**
 * Remove a member. Batch C (A3): eviction and rotation are ONE operation —
 * the IK goes on the local deny list, the CREATOR's normal sends are blocked
 * (evictionPendingAt), the relay deny entry is written, then the rotation
 * runs. If the rotation fails, the creator's sends stay blocked and the next
 * poll (or a manual rotate) finishes it. Other members get no signal from
 * this device: until the rotation reaches them they keep sending on the old
 * key, which the removed member holds. Batch D (D-06) bounds that: a member
 * with a valid prekey can't veto the rotation, and members stop sending on a
 * key older than MEMBER_EPOCH_MAX_MS (M-3, b69 audit; b77q owner (1 Nov): 7 days — the
 * rotation period plus slack — and they see a notice; posts under an epoch older than
 * MEMBER_EPOCH_READ_MAX_MS are no longer shown as verified).
 *
 * b71 (audit F-01): every unused plain seat (and every seat with a claim not yet
 * approved) is retired here — the removed person may have seen a spare link and
 * would otherwise come back under a new identity and read the new epoch.
 * Contact seats nobody used yet stay (they admit only their invitee's key).
 * b71 (audit F-04): before rotating, a signed member list goes out under the CURRENT
 * key, naming the removal and the epoch that excludes them. A member that reads it
 * while it still sits on the old epoch stops sending at once ("the group creator
 * removed someone — waiting for new keys") instead of after 48 h. (A relay can still
 * withhold that list too; then the 48 h bound is what remains.)
 */
export async function evictGroupMember(
  deps: GroupSessionDeps,
  opts: { groupToken: string; sessionToken: string; target: { veilId: string; ikPub: string }; clientId?: string;
    /** b74 (VAR-05): the member left (its signed leave arrived) — removed the same way, but the
     *  group's unused invite links are kept (a leaver who used one can't come back without the
     *  creator's tap, and its own identity is denied from now on) */
    left?: boolean },
): Promise<number | null> {
  deps = pinDeps(deps); // b70 (re-review 12): a wipe while this waits on the relay stops its writes
  const rec = groupRecord(deps.storage, opts.groupToken);
  if (!rec) throw new Error('Group keys are not on this device.');
  if (rec.role !== 'creator') throw new Error('Only the group creator can remove members.');
  // b54 (Batch A, H-3): record the eviction LOCALLY first — later rekeys never
  // wrap to this IK even if the relay re-inserts it into the roster.
  rec.evictedIks = [...new Set([...(rec.evictedIks ?? []), opts.target.ikPub])];
  rec.evictionPendingAt = rec.evictionPendingAt ?? rec.epoch;
  // b75r1 (audit G-1): the removed member's name is held back from everyone else for a while
  holdFreedName(rec, opts.target.ikPub, rec.boundNicks?.[opts.target.ikPub]);
  dropTaintedRotation(rec); // Batch D (D-05)
  // b71 (audit F-01): spare plain links and unapproved claims die with the removal
  const spare = opts.left ? [] : Object.entries(rec.seats ?? {}).filter(([, st]) => st && !st.usedBy && !st.invitee).map(([t]) => t);
  const claimed = opts.left ? [] : Object.values(rec.pendingClaims ?? {}).map((c) => c.seat).filter((t) => !rec.seats?.[t]?.usedBy);
  retireSeats(rec, [...new Set([...spare, ...claimed])]);
  if (spare.length || claimed.length) console.log('[veil-group] removal retired unused invite links', { groupToken: opts.groupToken.slice(0, 6), links: new Set([...spare, ...claimed]).size });
  // b71 (audit F-04): the removal notice for the signed member list
  // (a rotation already partly sent that wraps to them is finished first, then one more runs)
  const firstWithout = rec.epoch + (rec.pendingRotation?.recipients.includes(opts.target.ikPub) ? 2 : 1);
  rec.removals = [...(rec.removals ?? []).filter((x) => x[0] !== opts.target.ikPub), [opts.target.ikPub, opts.target.veilId || '', firstWithout] as [string, string, number]].slice(-16);
  await saveGroupRecord(deps.storage, rec);
  const deny_sig = await denySignature(rec.ikSeedB64, opts.groupToken, opts.target.ikPub, rec.epoch);
  const evict = deps.relay.invoke('veilGroupGate', {
    action: 'evict',
    group_token: opts.groupToken,
    session_token: opts.sessionToken,
    write_secret: await mainWriteSecret(deps, opts.sessionToken),
    remover_IK_pub: rec.ikPubB64,
    target_IK_pub: opts.target.ikPub,
    target_veil_id: opts.target.veilId || '',
    deny_sig,
  });
  // b70 (audit VAR-11 / GRP-2): a member the relay hides from its roster may be
  // refused by the relay's evict. The key change below is what removes them,
  // so it runs anyway (the local deny list above already excludes them).
  if (opts.clientId) await evict.catch((e) => console.warn('[veil-group] relay evict refused; rotating anyway:', String((e as Error)?.message ?? e)));
  else await evict;
  // b75r3 (audit R3G-I1): the seats retired above end on the relay too (they used to be retired only on this phone,
  // so whoever held a spare link could still join and post its "let me in" note through it). Best effort: the
  // seat is already dead here (its claims are refused, it never gets a key); the relay copy is what this ends.
  await retireSeatsOnRelay(deps, opts.groupToken, opts.sessionToken, [...new Set([...spare, ...claimed])]);
  if (!opts.clientId) return null; // caller rotates (older call sites)
  // b71 (audit F-04): tell members under the current key first (best effort — the
  // rotation below is what actually removes them)
  await publishMemberList(deps, { groupToken: opts.groupToken, sessionToken: opts.sessionToken, clientId: opts.clientId })
    .catch((e) => console.warn('[veil-group] removal notice not sent before the rotation:', String((e as Error)?.message ?? e)));
  return rotateGroup(deps, { groupToken: opts.groupToken, sessionToken: opts.sessionToken, clientId: opts.clientId });
}

// ---------- exports for the App layer ----------

export {
  loadGroupRecords, loadGroupRecord, groupRecord, forgetGroup,
  exportGroupRecords, importGroupRecords,
  decryptGroupText, encryptGroupText, epochFingerprint, senderTag,
  groupNeedsRotation, type GroupRecord, type GroupRekeyPayload,
  GroupKeysStaleError, groupKeyFreshness, assertGroupKeysFresh, MEMBER_EPOCH_MAX_MS,
};

/** creator's main group session finder (web: initiator_client_id === me &&
 *  state active && !responder_client_id). */
export async function findMainGroupSession(
  deps: GroupSessionDeps, groupToken: string, clientId: string,
): Promise<string | null> {
  const raw = await deps.relay.sessionList(clientId);
  const d = raw.data as { data?: Record<string, unknown>[]; sessions?: Record<string, unknown>[] };
  const list = d?.data ?? d?.sessions ?? (raw.data as Record<string, unknown>[] ?? []);
  for (const r of list) {
    if (String(r.group_token ?? '') === groupToken
      && String(r.initiator_client_id ?? '') === clientId
      && String(r.state ?? '') === 'active'
      && !String(r.responder_client_id ?? '')) {
      return String(r.token ?? '');
    }
  }
  return null;
}

/** decrypt a group session row's name blob for display */
export async function groupRowLabel(
  deps: GroupSessionDeps, groupToken: string, nameBlob: string,
): Promise<string | null> {
  const rec = (await loadGroupRecord(deps.storage, groupToken)) ?? groupRecord(deps.storage, groupToken);
  if (!rec) return null;
  // b70 (re-review 2, F5): every name this app sets is encrypted (enc1:/enc2:). A plain
  // name on the row came from the relay, which must not rename a private group.
  // b70 (re-review 5): the kept name first; an old record reads it once with its
  // first-epoch key, keeps the name, and drops that key for good
  if (rec.name) {
    if (rec.nameGekB64) { delete rec.nameGekB64; await saveGroupRecord(deps.storage, rec).catch(() => undefined); }
    return rec.name;
  }
  if (!isGroupNameBlob(String(nameBlob ?? ''))) return null; // b73 (audit V-22): enc1 or enc2
  // b76r1 (audit AUD-G4): only a name actually opened under a key this phone holds is shown or kept
  // (decryptGroupText refuses anything else — it used to hand back the raw row text, so a joiner still
  // waiting for its key took a relay-chosen "enc2:<any text>" as the group's name, for good). A kept row
  // name is marked, so the creator's signed name (nm in the key delivery) replaces it.
  const key = rec.nameGekB64 || rec.gekB64;
  if (!key) return null;
  try {
    const name = await decryptGroupText(key, nameBlob);
    if (name) { rec.name = name; rec.nameFromRow = true; }
    if (rec.nameGekB64 || name) { delete rec.nameGekB64; await saveGroupRecord(deps.storage, rec).catch(() => undefined); }
    return name || null;
  } catch {
    return null;
  }
}

// re-export writeHashHex (used by callers composing group session records)
export { writeHashHex };

/** unused import guard: createSession/serialize kept for parity with the
 *  main-session ratchet the web stores (harmless, keeps sessions.load working) */
export async function ensureMainSessionRatchet(deps: GroupSessionDeps, token: string, writeSecret: string): Promise<void> {
  const existing = await deps.sessions.load(token);
  if (existing) return;
  const { state } = await createSession(token, toB64(randomBytes(32)), {}); // never joined: the link secret and dials are unused
  state.writeSecret = writeSecret;
  await deps.sessions.save(token, await serializeRatchetState(state));
}
