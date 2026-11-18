/**
 * @veil/crypto-core — b77 sealed sender: 1:1 delivery capabilities (spec §1.7, §3.4).
 *
 * Once a 1:1 handshake is done, both phones derive the same delivery capabilities from the
 * root they already share (contact chats: the root contactWriteSecrets uses; invite chats:
 * rk0). For each direction d in {i2r, r2i}:
 *
 *   mbox_d   = hex(HKDF(root, salt = utf8('vardum-ratchet-8/mbox'),   info = 'vardum-ratchet-8/mbox/'   + d, 32))  address
 *   send_d   = hex(HKDF(root, salt = utf8('vardum-ratchet-8/send'),   info = 'vardum-ratchet-8/send/'   + d, 32))  write capability
 *   read_d   = hex(HKDF(root, salt = utf8('vardum-ratchet-8/read'),   info = 'vardum-ratchet-8/read/'   + d, 32))  read / burn / end
 *   ticket_d = hex(HKDF(root, salt = utf8('vardum-ratchet-8/ticket'), info = 'vardum-ratchet-8/ticket/' + d, 32))  (b77p: unused — opens use blind tokens, open-token.ts)
 *   wake_d   = hex(HKDF(root, salt = utf8('vardum-ratchet-8/wake'),   info = 'vardum-ratchet-8/wake/'   + d, 32))  b77p: seals the recipient's wake box (wake.ts)
 *
 * The initiator's inbound mailbox is r2i and its outbound is i2r; the responder's are the
 * reverse. A phone keeps only what its role needs: {inbound:{mbox, read, ticket, sendHash},
 * outbound:{mbox, send}}. The relay is given only capHash(send), capHash(read) and
 * capHash(ticket); it sees a capability itself only when one is presented.
 */
import { hkdf, sha256 } from './kdf';
import { utf8, randomBytes } from './bytes';

export const DELIVERY_LABEL = 'vardum-ratchet-8';
export type DeliveryDir = 'i2r' | 'r2i';
export type DeliveryRole = 'initiator' | 'responder';
export const DELIVERY_KINDS = ['mbox', 'send', 'read', 'ticket', 'wake'] as const;
export type DeliveryKind = (typeof DELIVERY_KINDS)[number];

export interface DeliveryDirCaps { mbox: string; send: string; read: string; ticket: string; /** b77p */ wake: string }
export interface DeliveryCaps { i2r: DeliveryDirCaps; r2i: DeliveryDirCaps }

/** what one phone stores for a chat (its sealed record's `delivery` field) */
export interface ChatDelivery {
  v: 1;
  /** my own mailbox: its address, read cap, one-time ticket, and the HASH of the peer's send cap
   *  (mailboxOpen registers it; this phone never holds the cap that writes to itself) */
  inbound: { mbox: string; read: string; ticket: string; sendHash: string; /** b77p: seals my own wake box (absent on a chat set up before b77p) */ wake?: string;
    /** b77u (audit 6 W4): the OWNER cap — 32 random bytes (hex) made on this phone, never derived from the shared root, so
     *  the peer can't compute it. Its hash is registered at mailboxOpen (own_hash); the owner-only operations (verify,
     *  wake box, TURN grant/approve/redeem) present it. Absent on a chat set up before b77u (the read cap is used). */
    own?: string };
  /** the peer's inbound: its address and the send cap (b77p: and its wake cap, sent with every submit) */
  outbound: { mbox: string; send: string; wake?: string };
}

const HEX64 = /^[0-9a-f]{64}$/;
const hex = (b: Uint8Array): string => [...b].map((x) => x.toString(16).padStart(2, '0')).join('');

async function capOf(root: Uint8Array, kind: DeliveryKind, dir: DeliveryDir): Promise<string> {
  const out = await hkdf(root, utf8(`${DELIVERY_LABEL}/${kind}`), `${DELIVERY_LABEL}/${kind}/${dir}`, 32);
  try { return hex(out); } finally { out.fill(0); }
}

/** Both directions' capabilities from the shared delivery root (32 bytes). */
export async function deriveDelivery(root: Uint8Array): Promise<DeliveryCaps> {
  if (!(root instanceof Uint8Array) || root.length !== 32) throw new Error('Delivery root must be 32 bytes.');
  const dirCaps = async (dir: DeliveryDir): Promise<DeliveryDirCaps> => ({
    mbox: await capOf(root, 'mbox', dir),
    send: await capOf(root, 'send', dir),
    read: await capOf(root, 'read', dir),
    ticket: await capOf(root, 'ticket', dir),
    wake: await capOf(root, 'wake', dir),
  });
  return { i2r: await dirCaps('i2r'), r2i: await dirCaps('r2i') };
}

/** the direction a role RECEIVES on (initiator: r2i, responder: i2r) */
export function inboundDir(role: DeliveryRole): DeliveryDir { return role === 'initiator' ? 'r2i' : 'i2r'; }
/** the direction a role SENDS on (initiator: i2r, responder: r2i) */
export function outboundDir(role: DeliveryRole): DeliveryDir { return role === 'initiator' ? 'i2r' : 'r2i'; }

/** The relay-side hash of a capability: lowercase hex SHA-256 of the capability's UTF-8 hex
 *  string (the same convention as the write-secret hashes, spec §3.3). */
export async function capHash(cap: string): Promise<string> {
  return hex(await sha256(utf8(cap)));
}

/** What a phone in `role` keeps: its own inbound's address, read cap, ticket and the hash of its
 *  send cap, and the peer inbound's address and send cap. Nothing else (no read cap for the
 *  peer's mailbox, no send cap for its own). */
export async function deliveryForRole(caps: DeliveryCaps, role: DeliveryRole): Promise<ChatDelivery> {
  const i = caps[inboundDir(role)], o = caps[outboundDir(role)];
  const own = hex(randomBytes(32)); // b77u (audit 6 W4): random, this phone's alone
  return { v: 1, inbound: { mbox: i.mbox, read: i.read, ticket: i.ticket, sendHash: await capHash(i.send), wake: i.wake, own }, outbound: { mbox: o.mbox, send: o.send, wake: o.wake } };
}

/** The joiner's mbox_ticket_hashes for gate join: [H(ticket_i2r), H(ticket_r2i)]. */
export async function ticketHashes(caps: DeliveryCaps): Promise<[string, string]> {
  return [await capHash(caps.i2r.ticket), await capHash(caps.r2i.ticket)];
}

/** A stored `delivery` field, checked; null when absent or malformed (a pre-b77 chat). */
export function parseChatDelivery(v: unknown): ChatDelivery | null {
  const d = v as { v?: unknown; inbound?: Record<string, unknown>; outbound?: Record<string, unknown> } | null;
  if (!d || typeof d !== 'object' || d.v !== 1 || !d.inbound || !d.outbound) return null;
  const ok = (x: unknown): x is string => typeof x === 'string' && HEX64.test(x);
  const { mbox: im, read, ticket, sendHash, wake: iw, own: io } = d.inbound, { mbox: om, send, wake: ow } = d.outbound;
  if (!ok(im) || !ok(read) || !ok(ticket) || !ok(sendHash) || !ok(om) || !ok(send) || im === om) return null;
  // b77p: the wake caps are optional (a chat set up before b77p has none: no wakes), but never malformed
  if ((iw !== undefined && !ok(iw)) || (ow !== undefined && !ok(ow))) return null;
  if (io !== undefined && !ok(io)) return null; // b77u (audit 6 W4): optional, never malformed
  return { v: 1, inbound: { mbox: im, read, ticket, sendHash, ...(ok(iw) ? { wake: iw } : {}), ...(ok(io) ? { own: io } : {}) }, outbound: { mbox: om, send, ...(ok(ow) ? { wake: ow } : {}) } };
}
