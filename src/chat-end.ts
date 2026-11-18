/**
 * b77m merge (audit VAR-07, app half of the device fix): how the app ends a 1:1 chat and reads a
 * sync pass's end / unavailable outcome. No React Native imports (the repro tests load this file).
 *
 *  - "End this chat" goes through the library's endChat: the END control envelope first (so the
 *    peer's phone says "ended by the other side"), then the mailboxes. Calling endSealedChat
 *    directly retired the peer's inbound before it could carry the END, so the peer only ever saw
 *    410s and marked the chat unavailable.
 *  - A chat the RELAY reports gone (syncChat `unavailable`) is not ended: it stays listed and
 *    readable, read-only, with a banner and a Delete button; nothing is sent for it again.
 *  - Only `ended` (endedBy 'peer', the authenticated END) closes the thread as "ended by the other side".
 */
import { endChat, isChatUnavailable } from '../vendor/device/src/chat';
import { chatDelivery } from '../vendor/device/src/sealed';
import type { VeilRelay } from '../vendor/device/src/relay';
import type { SessionStore } from '../vendor/device/src/session-store';

/** the banner on a chat the relay reports gone */
export const CHAT_UNAVAILABLE_TEXT = 'The server reports this chat no longer exists';
/** the chat-list subtitle note for such a chat */
export const CHAT_UNAVAILABLE_NOTE = 'the server reports this chat no longer exists';
/** b77m review (L9): the banner on a chat the peer ended with messages arriving alongside the END (kept read-only) */
// b77u (audit 6 U-M8): the END removes this phone's copy of the chat too
export const CHAT_ENDED_BY_PEER_TEXT = 'The other person ended this chat. Its messages were removed from this phone.';

/** b77m review (L9): the peer's END ended this chat but it was kept read-only for the messages sent before it */
export async function chatEndedByPeer(sessions: Pick<SessionStore, 'mboxState'>, token: string): Promise<boolean> {
  try { return !!(await sessions.mboxState(token))?.peerEnded; } catch { return false; }
}

export type SyncOutcome = 'ended' | 'unavailable' | 'gonePending' | 'ok';
/** what a syncChat result means for the thread. The peer's END wins over everything; then the
 *  relay's word (unavailable, kept read-only); then a not-yet-confirmed gone (back off). */
export function syncOutcome(res: { ended?: boolean; unavailable?: boolean; gonePending?: boolean } | null | undefined): SyncOutcome {
  if (!res) return 'ok';
  if (res.ended) return 'ended';
  if (res.unavailable) return 'unavailable';
  if (res.gonePending) return 'gonePending';
  return 'ok';
}

/** a locally held 1:1 chat's list status: unavailable chats show with the ended ones (read-only), never as active */
export function localChatStatus(o: { preSealed: boolean; ready: boolean; unavailable: boolean }): 'active' | 'pending' | 'ended' {
  if (o.preSealed || o.unavailable) return 'ended';
  return o.ready ? 'active' : 'pending';
}

export type ChatEndResult =
  | { route: 'local' }
  | { route: 'sealed'; notice: boolean; inbound: boolean; outbound: boolean }
  | { route: 'legacy' };

/**
 * The relay side of "End this chat" / "Delete" for a 1:1 chat. Never removes the local state (the
 * caller does, afterwards, as before).
 *  - ended by the peer's END (kept read-only): nothing is sent — 'local';
 *  - unavailable (the relay reported it gone): b77n — the mailboxes are no longer retired on the
 *    relay's word alone, so a Delete still tries the END (best effort) so the peer is told if the
 *    relay lied; a refusal falls back to 'local';
 *  - a chat with delivery capabilities: endChat (END envelope, then the mailboxes) — 'sealed';
 *  - otherwise (a chat that never finished its handshake): `legacyEnd` (the rendezvous row's end);
 *    its errors propagate to the caller's fallbacks — 'legacy'.
 */
export async function endChatOnRelay(
  relay: VeilRelay, sessions: SessionStore, token: string, legacyEnd: () => Promise<unknown>,
): Promise<ChatEndResult> {
  if (await chatEndedByPeer(sessions, token)) return { route: 'local' };
  const unavailable = await isChatUnavailable(sessions, token);
  const sealed = await sessions.load(token).catch(() => null);
  if (unavailable) {
    if (!chatDelivery(sealed)) return { route: 'local' };
    try { const r = await endChat(relay, sessions, token); return { route: 'sealed', ...r }; } catch { return { route: 'local' }; }
  }
  if (chatDelivery(sealed)) {
    const r = await endChat(relay, sessions, token);
    return { route: 'sealed', ...r };
  }
  await legacyEnd();
  return { route: 'legacy' };
}

/** a chat-list subtitle for an unavailable chat: its #TAG, then the note (the rest no longer applies) */
export function unavailableSubtitle(subtitle: string): string {
  const tag = String(subtitle ?? '').split(' · ')[0];
  return tag && tag.startsWith('#') ? `${tag} · ${CHAT_UNAVAILABLE_NOTE}` : CHAT_UNAVAILABLE_NOTE;
}
