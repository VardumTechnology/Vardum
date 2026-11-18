/**
 * @veil/crypto-core — b77p (audit 2 VAR-01): sealed wake boxes (spec §12.19.1).
 *
 * b77 bound each inbound mailbox to a random push_ref that the recipient's ACCOUNT push row also
 * listed, so the relay database joined mailbox -> push row -> account. Now the recipient seals its
 * own push target into its own inbound under a key derived from the chat's `wake` capability, which
 * the relay is shown only when the peer submits (sealedSubmit wake_cap) and never stores:
 *
 *   K   = HKDF-SHA256(ikm = utf8(wake), salt = utf8('vardum-wake-box/v1'), info = 'vardum-wake-box/v1/' || mbox, 32)
 *   pt  = utf8(JSON {v: 1, t, p?, a?}) right-padded with spaces to 1024 bytes
 *   box = 'w1.' || B64(iv(12) || AES-256-GCM(K, iv, pt, aad = utf8('vardum-wake-box/v1/' || mbox)))   (1407 characters)
 */
import { hkdf, sha256 } from './kdf';
import { utf8, fromUtf8, toB64, fromB64, concat } from './bytes';

export const WAKE_BOX_LABEL = 'vardum-wake-box/v1';
export const WAKE_BOX_PT_BYTES = 1024;
/** 'w1.' + base64 of 12 + 1024 + 16 bytes */
export const WAKE_BOX_LENGTH = 3 + 4 * Math.ceil((12 + WAKE_BOX_PT_BYTES + 16) / 3);
const HEX64 = /^[0-9a-f]{64}$/;

/** where a wake goes: an Expo token or 'up:' + UnifiedPush endpoint, and for UnifiedPush its Web Push keys */
/** b77u (audit 6 W6): `k` — this phone's wake key (64 hex, the same in every box it seals). The relay keys its per-address
 *  wake ceiling on (address, k), so a stranger who knows only the push address can't spend this phone's wakes. */
export interface WakeTarget { t: string; p?: string; a?: string; k?: string }

export function isWakeTarget(v: unknown): v is WakeTarget {
  const w = v as WakeTarget | null;
  if (!w || typeof w !== 'object' || typeof w.t !== 'string' || !w.t || w.t.length > 512) return false;
  if (w.p !== undefined && (typeof w.p !== 'string' || w.p.length > 200)) return false;
  if (w.a !== undefined && (typeof w.a !== 'string' || w.a.length > 64)) return false;
  if (w.k !== undefined && (typeof w.k !== 'string' || !HEX64.test(w.k))) return false; // b77u (audit 6 W6)
  return true;
}

async function wakeKey(wake: string, mbox: string): Promise<CryptoKey> {
  if (!HEX64.test(wake) || !HEX64.test(mbox)) throw new Error('Bad wake capability or mailbox');
  const raw = await hkdf(utf8(wake), utf8(WAKE_BOX_LABEL), `${WAKE_BOX_LABEL}/${mbox}`, 32);
  try { return await crypto.subtle.importKey('raw', raw as BufferSource, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']); } finally { raw.fill(0); }
}

function targetJson(t: WakeTarget): string {
  return JSON.stringify({ v: 1, t: t.t, ...(t.p ? { p: t.p } : {}), ...(t.a ? { a: t.a } : {}), ...(t.k ? { k: t.k } : {}) });
}

/** Seal `target` into the box for inbound mailbox `mbox` under its `wake` capability. */
export async function sealWakeBox(wake: string, mbox: string, target: WakeTarget): Promise<string> {
  if (!isWakeTarget(target)) throw new Error('Bad wake target');
  const body = utf8(targetJson(target));
  if (body.length > WAKE_BOX_PT_BYTES) throw new Error('Wake target too long');
  const pt = new Uint8Array(WAKE_BOX_PT_BYTES).fill(0x20);
  pt.set(body, 0);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await wakeKey(wake, mbox);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv as BufferSource, additionalData: utf8(`${WAKE_BOX_LABEL}/${mbox}`) as BufferSource }, key, pt as BufferSource));
  return 'w1.' + toB64(concat(iv, ct));
}

/** Open a box (tests and the relay's mirror); null when it doesn't open. */
export async function openWakeBox(wake: string, mbox: string, box: string): Promise<WakeTarget | null> {
  try {
    if (typeof box !== 'string' || box.length !== WAKE_BOX_LENGTH || !box.startsWith('w1.')) return null;
    const raw = fromB64(box.slice(3));
    const key = await wakeKey(wake, mbox);
    const pt = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: raw.subarray(0, 12) as BufferSource, additionalData: utf8(`${WAKE_BOX_LABEL}/${mbox}`) as BufferSource }, key, raw.subarray(12) as BufferSource));
    const o = JSON.parse(fromUtf8(pt).trimEnd()) as { v?: unknown } & WakeTarget;
    if (o.v !== 1 || !isWakeTarget(o)) return null;
    return { t: o.t, ...(o.p ? { p: o.p } : {}), ...(o.a ? { a: o.a } : {}), ...(o.k ? { k: o.k } : {}) };
  } catch { return null; }
}

/** what MboxState.wakeFp records: the first 16 hex of SHA-256 over the target's JSON */
export async function wakeFingerprint(target: WakeTarget): Promise<string> {
  return [...(await sha256(utf8(targetJson(target))))].slice(0, 8).map((b) => b.toString(16).padStart(2, '0')).join('');
}
