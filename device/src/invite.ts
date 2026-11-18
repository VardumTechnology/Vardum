/**
 * @veil/device — Strict invite sessions (web parity, build 40).
 *
 * Web contract extracted from the live bundle (createSession qe / joinSession
 * tt / veilSessionGate create-peek-join):
 *
 * INITIATOR ("Create an invite link")
 *   token = xu(24)  (hex of 24 random bytes)
 *   myWrite = xu(32) (hex) — stored on-device as the ratchet state's writeSecret
 *   peerWrite = xu(32) — travels ONLY in the link fragment #w=
 *   linkSecret k = xu(32) — mixed into the session root; travels only in the fragment
 *   createSession(token, k, dials) → pending initiator ratchet (X25519 + ML-KEM pub)
 *   VeilSession.create {token, state:'pending', initiator_client_id, ...,
 *     initiator_pub_jwk, initiator_pq_pub, initiator_write_hash=sha256hex(myWrite),
 *     responder_write_hash=sha256hex(peerWrite), expires 24h,
 *     default_ttl_seconds, key_retention_hours, burn_after_open (BOOL, dial>0),
 *     expire_after_seconds}
 *   link = {origin}/?join={token}#w={encodeURIComponent(peerWrite)}&k={linkSecret}&d={dials}
 *   — the initiator's existing pending loop (App advanceHandshake) completes
 *     the handshake when the responder joins: state active + responder fields.
 *
 * RESPONDER ("Join with an invite link")
 *   parse → { token, #w=, &k=, &d= } (a link without k is refused as from an older version)
 *   peek {action:'peek', token, write_secret:w} → session record
 *   validations: ended / active-and-not-mine / expired / missing initiator key
 *   joinSession(token, k, initiator_pub_jwk, initiator_pq_pub, dials) → READY state
 *     + responder fields + fingerprint (writeSecret = w, the #w fragment)
 *   join {action:'join', token, write_secret:w, client_id,
 *     responder_pub_jwk, responder_ratchet_pub_jwk, responder_pq_ct, fingerprint}
 *   clobber check: record's responder fields must echo ours (VEIL-JOIN-CLOBBERED)
 */
import { pinDeps } from './wipe-generation';
import {
  randomBytes, utf8,
  createSession, joinSession, serializeRatchetState, clampDials, canonicalDials,
  deliveryForRole,
} from '../../crypto-core/src/index';
import { scheduleInboundOpen, prepareOpenBlind, adoptJoinOpenSig, isOpenKeyRefusal, noteOpenKeyRefused } from './sealed';
import type { DialsInput } from '../../crypto-core/src/ratchet';
import { sha256 } from '../../crypto-core/src/kdf';
import { isChatToken, type SessionStore } from './session-store'; // b77m (audit VAR-26): isChatToken
import { saveOrThrow } from './save-strict';
import type { VeilRelay } from './relay';

export interface InviteDeps {
  sessions: SessionStore;
  relay: VeilRelay;
  /** web origin — the invite link opens the web app; VEIL native can paste it too */
  webBaseUrl: string;
}

export interface InviteDials {
  burnAfterOpen: boolean;
  expireAfterSeconds: number;
  keyRetentionHours: number;
  defaultTtlSeconds: number;
}

export interface CreatedInvite {
  token: string;
  link: string;
}

export interface JoinedInvite {
  token: string;
  fingerprint: string;
  alreadyJoined: boolean;
}

/** web xu(n): hex string of n random bytes */
function hexRand(nBytes: number): string {
  return Array.from(randomBytes(nBytes)).map((b) => b.toString(16).padStart(2, '0')).join('');
}

/** web td(s): SHA-256 hex of the utf8 secret — the write_hash fields */
export async function writeHashHex(secret: string): Promise<string> {
  const d = await crypto.subtle.digest('SHA-256', utf8(secret) as unknown as BufferSource);
  return Array.from(new Uint8Array(d)).map((b) => b.toString(16).padStart(2, '0')).join('');
}

/** Initiator: create the pending session, publish the record, return the link. */
export async function createInviteSession(
  deps: InviteDeps,
  opts: { clientId: string; dials: InviteDials; displayName?: string;
          /** group mode: bind the session to a group + encrypted name blob.
           *  activate=true creates the creator's MAIN group session (immediately
           *  active, no responder ever joins it) — web parity. */
          group?: { groupToken: string; groupNameBlob: string; activate?: boolean; epoch?: number; pqPubB64?: string;
                    /** b199: lock this seat to one person — the relay only lets
                     *  the account that owns this Veil ID peek or join it, so a
                     *  forwarded invite is useless to anyone else. */
                    inviteeVeilId?: string } },
): Promise<CreatedInvite> {
  deps = pinDeps(deps); // b70 (re-review 9): a wipe while this waits on the relay stops its writes
  const token = hexRand(24);
  const myWrite = hexRand(32);
  const peerWrite = hexRand(32);

  // b54 (Batch A): the link secret k travels ONLY in the link fragment and is
  // mixed into the handshake root — a relay without the link cannot sit in
  // the middle of this session at all (the fingerprint stays the second line).
  const linkSecret = hexRand(32);
  // Batch C (V-12): clamped dials — the SAME values go on the row, into the
  // sealed state, and into the fingerprint (the joiner binds the row's copy).
  const dials = clampDials(opts.dials);
  const { state, initiatorPub, initiatorPqPub } = await createSession(token, linkSecret, dials);
  state.writeSecret = myWrite;
  // b188-r5: KeychainStorage.set swallows write errors and returns false, and
  // the old code IGNORED that — a silent keychain failure left a record
  // pointing at a session that never persisted. Fail HONESTLY instead.
  // b193: the CREATE path must persist the dials too — the join path always
  // has (7200/86400 fallbacks there); without them every send off a
  // created session falls back to ttl 86400.
  const saved = await deps.sessions.save(token, {
    ...(await serializeRatchetState(state)),
    burnAfterOpen: dials.burnAfterOpen,
    defaultTtlSeconds: dials.defaultTtlSeconds,
    expireAfterSeconds: dials.expireAfterSeconds,
  } as never);
  if (!saved) throw new Error('Secure storage refused this session — join aborted, nothing half-saved. Try again.');

  await deps.relay.entityCreate('VeilSession', {
    token,
    state: 'pending',
    // b77 (sealed sender): a 1:1 row carries no account id (the relay never stored the body's copy)
    ...(opts.group ? { initiator_client_id: opts.clientId } : {}),
    responder_client_id: '',
    // b71 (review R-1): no display names on the row (the relay drops them; opts.displayName is unused)
    passphrase_required: false,
    session_fingerprint: '',
    initiator_pub_jwk: initiatorPub,
    initiator_pq_pub: initiatorPqPub,
    initiator_write_hash: await writeHashHex(myWrite),
    responder_write_hash: await writeHashHex(peerWrite),
    initiator_verified: false,
    responder_verified: false,
    // b192: session lifetime comes from the DIALS, not a hard-coded 24h — the
    // relay stores the declared expiry (hard 30-day ceiling). Regular invites
    // dial expireAfterSeconds 86400 so behavior is unchanged there.
    expires_at: new Date(Date.now() + (dials.expireAfterSeconds || 86400) * 1000).toISOString(),
    default_ttl_seconds: dials.defaultTtlSeconds,
    key_retention_hours: dials.keyRetentionHours,
    burn_after_open: dials.burnAfterOpen,
    // b197-r8l (TWO-DIAL SYNCHRONIZED MODEL): expire_after_seconds is the
    // founder-programmable unopened-message deletion horizon (12/24/36/48 h).
    expire_after_seconds: dials.expireAfterSeconds,
    last_activity: new Date().toISOString(),
    ...(opts.group
      ? {
          group_token: opts.group.groupToken,
          group_name: opts.group.groupNameBlob,
          // (creator / member rows never pre-stamp group_epoch: the gate's rotate
          // action requires new_epoch == current + 1)
          ...(opts.group.inviteeVeilId ? { invitee_veil_id: opts.group.inviteeVeilId } : {}),
        }
      : {}),
  });

  // web parity: the group MAIN session is activated THROUGH the gate (the
  // web client never writes state:'active' on the entity row itself).
  if (opts.group?.activate) {
    await deps.relay.sessionActivate(token, myWrite);
  }

  const base = deps.webBaseUrl.replace(/\/$/, '');
  // Batch F (round-4 reviews R4-1-01 / R4-4-05): the creator's dials ride in the
  // fragment next to k, so the joiner never has to take the relay's copy
  return { token, link: `${base}/?join=${token}#w=${encodeURIComponent(peerWrite)}&k=${linkSecret}&d=${linkDials(dials)}` };
}

/** Parse an invite link (web URL or pasted text). b54 links carry
 *  #w=<write secret>&k=<link secret>; group invites additionally carry
 *  &g=<group GEK b64>&e=<epoch>&c=<creator IK b64>; from b56 (Batch D, D-03)
 *  also &t=<group token>&ph=<groupLinkBinding hex>.
 *  b71 (review P-01 / P-02): from b71 g= is only the marker "v2", never a key (the
 *  key comes from the creator after admission; an older link's g= key is parsed but
 *  never used), and s=<32 hex salt>:
 *  the group token must equal groupIdFor(c, s). */
/** Batch F (R4-1-01): the dials as they travel in a link: ttl.expire.retention.burn */
export function linkDials(d: Partial<DialsInput>): string {
  const c = clampDials(d);
  return `${c.defaultTtlSeconds}.${c.expireAfterSeconds}.${c.keyRetentionHours}.${c.burnAfterOpen ? 1 : 0}`;
}

/** Batch F (R4-1-01): the longest burn window the app offers (24 h). A session
 *  whose dials came from the relay (an older link without d=) is never purged
 *  locally faster than this, so the relay can only lengthen its burn window. */
export const PEEK_DIALS_BURN_FLOOR_SECONDS = 86400;

export function parseInviteLink(link: string): { token: string; writeSecret: string; linkSecret?: string; creatorIk?: string; gek?: string; epoch?: number; groupToken?: string; groupBind?: string; groupBind2?: string; groupSalt?: string; dials?: DialsInput } {
  const t = link.match(/[?&]join=([^&#\s]+)/i);
  const w = link.match(/[#&?]w=([^&#\s]+)/i);
  // b54: k = invite link secret (64 hex, fragment only); c = group creator IK
  const k = link.match(/[#&]k=([0-9a-f]{64})(?=[&#\s]|$)/i);
  const c = link.match(/[#&]c=([^&#\s]+)/i);
  if (!t || !w) throw new Error('That is not a Vardum invite link — ask your peer for a fresh one.');
  // b77m (audit VAR-26): the token becomes this chat's storage keys (and a seat's relay id) — 48 lowercase hex
  // only; a link with `<another chat's token>_p0` used to read and then retire that chat's history
  let tokenIn = '';
  try { tokenIn = decodeURIComponent(t[1]); } catch { tokenIn = ''; }
  if (!isChatToken(tokenIn)) throw new Error('That is not a Vardum invite link — ask your peer for a fresh one.');
  const g = link.match(/[?&]g=([^&#\s]+)/i);
  const e = link.match(/[?&]e=(\d+)/i);
  const gt = link.match(/[#&]t=([0-9a-f]{16,64})(?=[&#\s]|$)/i);
  const ph = link.match(/[#&]ph=([0-9a-f]{64})(?=[&#\s]|$)/i);
  const ph2 = link.match(/[#&]ph2=([0-9a-f]{64})(?=[&#\s]|$)/i); // b70 (VAR-10)
  const gs = link.match(/[#&]s=([0-9a-f]{32})(?=[&#\s]|$)/i); // b71 (review P-02)
  const d = link.match(/[#&]d=(\d+)\.(\d+)\.(\d+)\.([01])(?=[&#\s]|$)/);
  return {
    token: tokenIn,
    writeSecret: decodeURIComponent(w[1]),
    linkSecret: k ? k[1].toLowerCase() : undefined,
    creatorIk: c ? decodeURIComponent(c[1]) : undefined,
    gek: g ? decodeURIComponent(g[1]) : undefined,
    epoch: e ? Number(e[1]) : undefined,
    groupToken: gt ? gt[1].toLowerCase() : undefined,
    groupBind: ph ? ph[1].toLowerCase() : undefined,
    groupBind2: ph2 ? ph2[1].toLowerCase() : undefined,
    groupSalt: gs ? gs[1].toLowerCase() : undefined,
    dials: d ? clampDials({ defaultTtlSeconds: Number(d[1]), expireAfterSeconds: Number(d[2]), keyRetentionHours: Number(d[3]), burnAfterOpen: d[4] === '1' }) : undefined,
  };
}

/** b77q (audit 3 DV-3): what an invite link is, by the documented marker alone: `g=` = a group seat, anything else
 *  1:1. A link that carries group-only fields (t, c, s, ph, ph2, e) without `g=` is neither — it throws, so the
 *  app's router and joinInviteSession can't disagree about it (the app should route with this too). */
export function inviteLinkKind(link: string | ReturnType<typeof parseInviteLink>): '1:1' | 'group' {
  const p = typeof link === 'string' ? parseInviteLink(link) : link;
  if (p.gek) return 'group';
  if (p.groupToken || p.creatorIk || p.groupSalt || p.groupBind || p.groupBind2 || p.epoch !== undefined) {
    throw new Error('This invite link is damaged (it mixes a chat link with group details), so it was not opened. Ask for a fresh link.');
  }
  return '1:1';
}

/** Responder: join a session from an invite link. READY on return. */
export async function joinInviteSession(
  deps: InviteDeps,
  opts: { link: string; clientId: string; displayName?: string },
): Promise<JoinedInvite> {
  deps = pinDeps(deps); // b70 (re-review 9): a wipe while this waits on the relay stops its writes
  const parsedLink = parseInviteLink(opts.link);
  const { token, writeSecret, linkSecret, dials: linkDialsIn } = parsedLink;
  if (!linkSecret) throw new Error('This invite link is from an older version of Vardum. Ask for a fresh link.');
  // b77q (audit 3 DV-3): group or 1:1 by the documented marker (g=) alone, the app's rule too; a link carrying group
  // fields without it is refused before anything is sent (inviteLinkKind throws)
  const linkKind = inviteLinkKind(parsedLink);

  const existing = await deps.sessions.load(token);
  if (existing?.ready && existing.fingerprint) {
    return { token, fingerprint: existing.fingerprint, alreadyJoined: true };
  }
  // AUDIT FIX (Sept 19): a ready-but-fingerprint-less local state is a GHOST —
  // a previous attempt saved the ratchet before the relay join confirmed (and
  // the join failed). The relay record has no responder fields, so a fresh
  // join is exactly right. Drop the ghost and fall through.
  if (existing?.ready) {
    console.log('[veil-invite] dropping half-joined ghost state for ' + token.slice(0, 4));
    await deps.sessions.remove(token);
  } else if (existing) {
    // b75 (audit RT-4): any other local state for this token — above all the creator's own
    // pending initiator state, when someone sends you your own link back — is never
    // overwritten by a join (that lost the handshake keys and locked the real invitee out)
    throw new Error('This invitation was made on this phone, so it can\'t be joined here. Send the link to the person you want to chat with.');
  }

  // b77 (sealed sender): a 1:1 link is peeked without login (the write secret is the proof)
  // b77q (audit 3 DV-3): it was gek OR groupToken, so a 1:1 link with `&t=<hex>` appended (the app routes it here:
  // no g=) peeked and joined on the logged-in routes with this phone's account client id next to the rendezvous
  const linkIsGroup = linkKind === 'group';
  const pk = !linkIsGroup && typeof (deps.relay as Partial<VeilRelay>).sessionPeekAnon === 'function'
    ? await deps.relay.sessionPeekAnon(token, writeSecret)
    : await deps.relay.sessionPeek(token, writeSecret);
  const pd = pk.data as { data?: { session?: Record<string, string> }; session?: Record<string, string> };
  const rec = pd?.data?.session ?? pd?.session ?? (pk.data as Record<string, string>);
  if (!rec) throw new Error('Invitation not found or expired.');
  if (rec.state === 'ended') throw new Error('This session has ended.');
  if (rec.state === 'active' && rec.responder_client_id && rec.responder_client_id !== opts.clientId) {
    throw new Error('This session is already in use.');
  }
  if (rec.state === 'pending' && new Date(rec.expires_at).getTime() < Date.now()) {
    throw new Error('This invitation has expired.');
  }
  if (!rec.initiator_pub_jwk) {
    throw new Error('This session was created by an older client and cannot be joined.');
  }
  // b77r1 (audit A-3): group or 1:1 is decided by the LINK alone. A 1:1 link whose peek answer
  // claims a group (group_token) is refused: a relay must not turn an anonymous 1:1 join into a
  // logged-in one carrying this phone's account id (and no mailbox tickets)
  if (!linkIsGroup && (rec as { group_token?: unknown }).group_token) {
    throw new Error('This invitation does not match what the server sent, so it was not opened. Ask for a fresh link.');
  }

  // Batch C (V-12): the row's dials, clamped, are bound into the fingerprint —
  // if the relay rewrote them, the two phones show different fingerprints.
  const peekDials = clampDials({
    defaultTtlSeconds: rec.default_ttl_seconds as unknown as number,
    expireAfterSeconds: rec.expire_after_seconds as unknown as number,
    keyRetentionHours: rec.key_retention_hours as unknown as number,
    burnAfterOpen: (rec.burn_after_open as unknown) === true,
  });
  // Batch F (round-4 reviews R4-1-01 / R4-4-05): a link made from b60 on carries
  // the creator's dials. They win, and a relay copy that differs is refused (group
  // seats have no fingerprint ceremony, so this is their only check). An older
  // link has none: the relay's copy is used (it is in the fingerprint), and the
  // session is marked so the local burn window is floored (burnWindow).
  if (linkDialsIn && canonicalDials(linkDialsIn) !== canonicalDials(peekDials)) {
    throw new Error('This invitation\'s settings were changed on the server, so it was not opened. Ask for a fresh link.');
  }
  const dials = linkDialsIn ?? peekDials;
  const dialsSource: 'link' | 'peek' = linkDialsIn ? 'link' : 'peek';
  const { state, responderPub, responderRatchetPub, responderPqCt, fingerprint, delivery: caps } =
    await joinSession(token, linkSecret, rec.initiator_pub_jwk, rec.initiator_pq_pub || null, dials);
  // b77 (sealed sender): a 1:1 invite chat gets delivery capabilities (from rk0); a group seat
  // stays on the group protocol (its session ratchet only carries the relay credential)
  const isGroupSeat = linkIsGroup; // b77r1 (audit A-3): never from the relay's answer
  const delivery = isGroupSeat ? null : await deliveryForRole(caps, 'responder');
  // b77p (audit 2 VAR-01): my blinded mailbox-open token rides the join (it replaced the two ticket hashes the
  // relay could match to the later opens)
  const openPrep = isGroupSeat ? null : await prepareOpenBlind(deps.relay, deps.sessions); // b77q (audit 3 CR-1): the pinned issuer key
  // Batch C (V-16, client half): retire the link's w at join — a fresh
  // responder credential replaces it, so anyone else holding the link can no
  // longer act as this member. Kept only if the relay confirms the new hash.
  const freshWrite = hexRand(32);
  const freshHash = await writeHashHex(freshWrite);
  state.writeSecret = writeSecret;

  // b77 (sealed sender): a 1:1 join is anonymous (no login, no client id) and carries my blinded
  // open token (b77p); a group seat joins as before
  const j = await deps.relay.sessionJoin({
    token,
    write_secret: writeSecret,
    client_id: isGroupSeat ? opts.clientId : '', // b71 (review R-1): no display_name (opts.displayName is unused)
    responder_pub_jwk: responderPub,
    responder_ratchet_pub_jwk: responderRatchetPub,
    responder_pq_ct: responderPqCt,
    fingerprint,
    new_responder_write_hash: freshHash,
    ...(openPrep ? { open_blind: openPrep.open_blind, open_kid: openPrep.open_kid } : {}),
  }, { anon: !isGroupSeat }).catch(async (e) => {
    // b77q (audit 3 CR-1): the relay refused the issuer key: noted on the pin (a retried join may fetch again)
    if (openPrep && isOpenKeyRefusal(e)) await noteOpenKeyRefused(deps.sessions, openPrep.open_kid).catch(() => undefined);
    throw e;
  });
  const jd = j.data as { data?: { session?: Record<string, string> }; session?: Record<string, string> };
  const joined = jd?.data?.session ?? jd?.session;
  if (!joined) throw new Error('Could not join the session.');
  if (
    joined.responder_pub_jwk !== responderPub ||
    joined.responder_ratchet_pub_jwk !== responderRatchetPub
  ) {
    throw new Error('The session was joined again while you were joining — its keys no longer match. Ask your peer for a fresh invitation.');
  }
  if (joined.responder_write_hash === freshHash) state.writeSecret = freshWrite;

  // AUDIT FIX (Sept 19): persist the ratchet ONLY after the relay join confirmed
  // (and the clobber check passed) — never before.
  // Batch H (round-6 review R6-1-06): a refused save is an error, not a ghost chat
  await saveOrThrow(deps.sessions, token, {
    ...(await serializeRatchetState(state)),
    burnAfterOpen: dials.burnAfterOpen,
    defaultTtlSeconds: dials.defaultTtlSeconds,
    expireAfterSeconds: dials.expireAfterSeconds,
    dialsSource, // Batch F (R4-1-01)
    ...(delivery ? { delivery } : {}), // b77 (sealed sender)
  } as never);
  // b77: open my own inbound after the random 5–120 s delay
  if (delivery) await scheduleInboundOpen(deps.sessions, token);
  // b77p: keep the unblinded open token (or the blind, so gate `issue` can recover a lost signature)
  if (delivery && openPrep) await adoptJoinOpenSig(deps.relay, deps.sessions, token, openPrep.blind, j);

  return { token, fingerprint, alreadyJoined: false };
}


/** Group invite links append the group fragments to the invite link:
 *  ?join=<token>#w=…&k=…&d=…&g=v2&e=<epoch>&c=<creator IK>&t=<group token>&s=<salt>&ph=…&ph2=…
 *  b71 (review P-01): NO group key — links used to carry &g=<GEK>, so anyone holding
 *  one (admitted or not) could read every message of the epoch. The joiner gets the
 *  key from the creator after its seat proof checks out. g= stays as a marker
 *  ("v2", never a key): the app and the chat-invite card tell group links by it, and
 *  without it an older build would open the seat as a 1:1 chat.
 *  b71 (review P-02): s= is the salt the group token commits to with the creator key. */
export const GROUP_LINK_MARK = 'v2';
export function groupInviteLink(baseLink: string, epoch: number, creatorIkB64: string, groupToken: string, groupSaltHex: string, groupBindHex: string, groupBind2Hex?: string): string {
  // b70 (audit VAR-10): ph2 also binds the creator key; ph stays for older joiners
  return `${baseLink}&g=${GROUP_LINK_MARK}&e=${epoch}&c=${encodeURIComponent(creatorIkB64)}&t=${groupToken}&s=${groupSaltHex}&ph=${groupBindHex}${groupBind2Hex ? `&ph2=${groupBind2Hex}` : ''}`;
}

/** b70 (audit VAR-10 / GRP-1): binds a group link to its group AND its creator key */
export async function groupLinkBinding2(groupToken: string, groupPqPubB64: string, creatorIkB64: string): Promise<string> {
  const h = await sha256(utf8(`vardum-group-link-v2:${groupToken}:${groupPqPubB64}:${creatorIkB64}`));
  return Array.from(h).map((b) => b.toString(16).padStart(2, '0')).join('');
}

/** Batch D (D-03, RV-03): binds a group link to its group. The relay supplies the
 *  group token and the group's ML-KEM public key at join time; a joiner refuses a
 *  peek whose token or key doesn't hash to the value the inviter put in the link. */
export async function groupLinkBinding(groupToken: string, groupPqPubB64: string): Promise<string> {
  const h = await sha256(utf8(`vardum-group-link-v1:${groupToken}:${groupPqPubB64}`));
  return Array.from(h).map((b) => b.toString(16).padStart(2, '0')).join('');
}
