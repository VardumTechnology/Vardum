import { burnAnchor } from '../burn-anchor'; // b77p (audit 2, VAR-03)
import React, { memo, useEffect, useRef, useState } from 'react';
import { titleInitials } from '../../vendor/device/src/names'; // b77k2: initials without the isolate marks
import { burnCountdownText } from '../burn';
import { isolateName } from '../../vendor/device/src/names';
import { mediaDisplayName } from '../media-name'; // b77q (audit 3 AQ-2)
import { parseCapturePayload, captureNoticeText } from '../../vendor/device/src/capture-notice';
import { ScrollView, View, Text, TextInput, TouchableOpacity, Pressable, FlatList, StyleSheet, Platform, Image, ActivityIndicator, Keyboard } from 'react-native';
import { SecureOverlay } from '../components/SecureOverlay'; // audit VAR-02
/** audit VAR-42 (1f51): the save toggle is a request the recipient's Vardum honours, not a lock */
export const SAVE_TOGGLE_NOTE = 'Off hides Save in their Vardum app. It can’t stop a modified app or a photo of the screen.';
/** b77t (audit 5 M-F / IH C-01): the confirmed-panel text. The gate is one-sided: it says what this phone knows */
/**
 * b77u (audit 6 U-M15 / R4 #29): a 1:1 chat that isn't with a contact whose key this phone pinned (an invite-link
 * chat, a request from a stranger). An invite link isn't tied to one person and the joiner takes the inviter's keys
 * from the server, so the safety-code comparison is the only thing that would catch a server swapping them. Shown in
 * the safety-code panel and over the locked composer (sending stays locked on this phone until the code is confirmed).
 */
export const UNPINNED_KEYS_NOTE = 'This chat’s keys came to this phone through the server, and they aren’t a contact’s key you saved. For a chat started from an invite link, comparing this safety code with the other person is the only check that the server didn’t swap them. That is why sending stays locked on this phone until you confirm it.';
export const CONFIRMED_PANEL_TEXT = 'You confirmed the safety code on this phone ✓\nSending from this phone is unlocked. Vardum can’t tell whether the other person has confirmed it on their phone: until they do, their sending stays locked.';
import { useKbPadding } from '../hooks/useKbPadding';
import { Video, ResizeMode } from 'expo-av';
import { Ionicons } from '@expo/vector-icons';
import { copySensitive } from '../clipboard-guard';
import { useThemedChooser } from './ThemedSheets';
import { useThemedPrompt } from './ThemedPrompt';
import { privateComposerProps } from '../secret-entry'; // b77m (audit VAR-14)
import { CHAT_UNAVAILABLE_TEXT, CHAT_ENDED_BY_PEER_TEXT } from '../chat-end'; // b77m merge (audit VAR-07); b77m review (L9)

// b69: Android saves through the system folder picker (no gallery permission)
const SAVE_MEDIA_LABEL = Platform.OS === 'android' ? 'Save to…' : 'Save to Photos';

/** b199: media error marker for a file the relay no longer has (404). */
export const MEDIA_GONE = 'gone';

/** b140: above this size the pick preview shows a soft warning (send still allowed). */
const MEDIA_SOFT_WARN_BYTES = 26214400; // 25 MB — matches chat.ts MEDIA_SOFT_WARN_BYTES

export interface ChatMediaUI {
  name: string;
  mime: string;
  size: number;
  dl: boolean;
  /** render source: resolved decrypted data: URI, or the sender's local pick */
  src: string | null;
  loading: boolean;
  error: string | null;
}

export interface ChatMessageUI {
  id: string;
  text: string;
  mine: boolean;
  ts: string | null;
  media?: ChatMediaUI;
  read?: boolean;
  /** b62 groups: short sender label above the bubble (web parity) */
  sender?: string;
  /** b62 groups: per-sender Ed25519 signature verified against the roster */
  senderVerified?: boolean;
  /** b75 (audit GR-4): signed by the group creator's key as this phone holds it — the badge is
   *  drawn by the app, apart from the name, so a member's chosen name can't copy it */
  senderCreator?: boolean;
  /** b62 groups: centered system line (member joined / keys rotated / sig discard) */
  systemNote?: string;
  /** b72: epoch ms this message was first displayed here — burn-countdown anchor */
  openedAt?: number;
  /** b199: group invitation card (Join / Decline) */
  groupInvite?: { name: string; link: string; from?: string };
  /** b199: reactions — one per side */
  reactions?: { mine?: string; peer?: string };
  /** b77r1 (audit A-5): mine, encrypted, still waiting for the peer's phone to finish setting up */
  queued?: boolean;
}

/** b199 (owner request, Oct 17): the quick reactions on a held message */
const REACTIONS = ['👍', '👎', '❤️', '🙏', '😂', '😮'];

/** b62 groups: admin + roster context for group threads */
export interface ChatGroupInfoUI {
  isCreator: boolean;
  epoch: number;
  fingerprint: string | null;
  members: { veilId: string; nick?: string; ikPub: string; role: string; joinedEpoch: number; tag: string;
    /** b75 (audit GR-1): member view — said they are leaving; the creator hasn't removed them yet */
    leaving?: boolean;
    /** b74 (VAR-05): creator view — gone from the relay's roster since (ms); may have left */
    goneSince?: number }[];
  busy: boolean;
  onRotate: () => Promise<void>;
  onEvict: (member: { veilId: string; ikPub: string }) => Promise<void>;
  /** b71 (audit F-07): creator — people who opened an invite link and wait for approval */
  pendingRequests?: { ikPub: string; veilId: string; label: string; via: 'link' | 'contact'; contactLine?: string }[];
  onApproveRequest?: (ikPub: string) => Promise<void>;
  onDeclineRequest?: (ikPub: string) => Promise<void>;
}

export interface PendingPick {
  uri: string;
  name: string;
  mime: string;
  size: number;
  /** b62: set when this pick is a recorded voice note (drives the preview UI) */
  voiceSeconds?: number;
}

export interface ChatScreenProps {
  /** b70 (audit L-6): no autocorrect, suggestions or keyboard learning */
  privateKeyboard?: boolean;
  title: string;
  subtitle: string;
  status: 'pending' | 'active' | 'ended';
  busy: boolean;
  error: string | null;
  /** b172: honest notice when history is not being saved on this device. */
  historyNotice?: string | null;
  messages: ChatMessageUI[];
  /** b179: thread session token — re-arms memoized rows on thread switches. */
  threadKey: string;
  /** b180: dismiss the transient error banner (App-level error state). */
  onDismissError: () => void;
  draft: string;
  onDraftChange: (t: string) => void;
  onSend: () => void;
  /** b199: hold a message to react (pairwise threads); omitted = off */
  onReactMessage?: (id: string, emoji: string) => void;
  /** Play UGC: long-press menu on someone else's group message */
  onBlockSender?: (id: string) => Promise<void>;
  /** Play UGC: block this 1:1 contact (⋯ sheet; ends the chat) */
  onBlockContact?: () => void;
  onBack: () => void;
  /** b144 W3: start an encrypted call on this thread (1:1, ready threads only) */
  onStartCall?: () => void;
  onEndSession: () => void;
  /** audit VAR-24: the group creator's explicit "End group for everyone" (absent for members and 1:1) */
  onEndGroupForAll?: () => void;
  onAttach: () => void;
  pendingPick: PendingPick | null;
  onSendMedia: () => void;
  onCancelPick: () => void;
  allowDl: boolean;
  onAllowDlChange: (v: boolean) => void;
  onMediaRetry: (id: string) => void;
  onMediaSave: (id: string) => void;
  mediaSaving: Record<string, 'saving' | 'saved' | 'error'>;
  /** b199 group invitations: joined/declined state kept on this phone */
  inviteState?: Record<string, 'joined' | 'declined'>;
  onJoinGroupInvite?: (msgId: string, link: string) => Promise<void>;
  onDeclineGroupInvite?: (msgId: string) => Promise<void>;
  /** b62 voice notes */
  voiceRec: { active: boolean; seconds: number };
  onVoiceRecord: () => void;
  onVoiceCancel: () => void;
  onVoiceSend: () => void;
  /** web parity: true when the peer of THIS thread is a pinned contact —
   *  enables the 'New chat thread with the same person' header button */
  canNewThread: boolean;
  onNewThread: () => void;
  /** b155 decision A: contact (pinned) session — badge shows 'Pinned contact',
   *  no ceremony, no 'waiting for peer'. Trust comes from the pin. */
  contact?: boolean;
  /** per-session verify ceremony state (web parity: 'Verified for this session') */
  myVerified: boolean;
  /** b161 (parity handoff): resolves true only when the RELAY confirms our slot's
   *  verified flag — the panel stays open and shows an INLINE retry on false. */
  /** the safety code the user compared (what this screen shows) */
  onVerifySession: (shownFingerprint: string) => Promise<boolean>;
  /** b126: session fingerprint — viewable in the panel pre AND post verification */
  sessionFingerprint?: string | null;
  /** b126: peer veil id (pairwise only) — gates the "Pin as contact" affordance */
  peerVeilId?: string | null;
  /** b126: peer already pinned — flips the panel button to "Pinned" */
  peerPinned?: boolean;
  /** b126: promote the session peer into the permanent contacts (pins table) */
  onPinContact?: () => void;
  /** b62 groups: present only on group threads */
  group?: ChatGroupInfoUI;
  /** b72 web parity: "burn N hours after open" countdown — set only when the
   *  session's burn-after-open dial is on; burnSeconds is the window. */
  burnAfterOpen?: boolean;
  burnSeconds?: number;
  /** b95 (owner-approved Sept 21): one-time dismissible "verify fingerprints"
   *  card on first open of an unverified pairwise thread. Non-blocking — the
   *  ceremony stays Signal-style; the card just surfaces it loudly once. */
  showVerifyCard?: boolean;
  onVerifyCardDismiss?: () => void;
  /** b123: rename this thread locally (chat sheet) — shown only when the
   *  peer veil-id is known. Name is device-local, never transmitted. */
  canRename?: boolean;
  threadNickname?: string | null;
  onRenameThread?: (name: string) => void;
  /** b71 (audit): a contact request from a Vardum ID that isn't pinned — nothing
   *  happens until the user taps Accept (or Decline) */
  request?: boolean;
  onAcceptRequest?: () => Promise<boolean>;
  /** b76r2 (ZTE battery, ZTE-5): this phone's keys for the thread are gone (Nothing-at-Rest, a wipe)
   *  and the handshake failed closed — it can never work here; say so and offer the way out */
  unrecoverable?: boolean;
  /** b77r1 (audit A-5): this 1:1 chat couldn't finish setting up (the relay kept refusing this
   *  phone's mailbox ticket, or messages waited past the other phone's last chance) — say so
   *  and offer End, as for an unrecoverable chat */
  setupFailed?: boolean;
  /** b77m merge (audit VAR-07): the relay reports this 1:1 chat no longer exists (nothing from the peer said
   *  so) — read-only with its history; the banner offers Delete (onEndSession, which sends nothing for it) */
  unavailable?: boolean;
  /** b77m review (L9): the chat is read-only because the other person ended it (messages arrived with the end) */
  endedByPeer?: boolean;
  /** b77n (pre-audit INFO-5): "Check again" on the unavailable banner (relay's word only; absent after the peer's END) */
  onCheckAgain?: () => void;
  onDeclineRequest?: () => void;
}

function mediaCaption(m: ChatMediaUI): string {
  const mb = (m.size / 1048576).toFixed(1);
  return `${mediaDisplayName(m.name) || 'media'} · ${mb} MB${m.dl ? ' · saving allowed' : ''}`;
}

function fmtSecs(n: number): string {
  const m = Math.floor(n / 60), s = n % 60;
  return `${m}:${String(s).padStart(2, '0')}`;
}

/**
 * b176: leaf burn-after-open countdown. Owns its own 1s interval so the
 * per-second re-render is confined to this Text node instead of re-rendering
 * every bubble in the FlatList (see b176 note above). Unmounted automatically
 * when burn-after-open is off or the row disappears.
 */
const BurnCountdown = memo(function BurnCountdown({ openedAt, burnSeconds }: { openedAt?: number; burnSeconds: number }) {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const iv = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(iv);
  }, []);
  return <Text> · {burnCountdownText(openedAt, burnSeconds, now)}</Text>;
});

/**
 * b179 (owner report Oct 2: "the txt is still shaking" — even after the
 * b176 countdown memo). ROOT CAUSE: App re-renders on EVERY keystroke
 * (draft lives in App state) and every sync/presence/unread poll, and the
 * uiMessages map built per render hands FlatList brand-new object
 * identities — so EVERY message row re-rendered on EVERY keystroke and
 * EVERY poll tick. On iOS that wholesale row re-render is visible as the
 * text jittering ("shaking"). Fix: the row is now its own memo component
 * with a VALUE comparator — it re-renders only when its own content
 * (text/timestamp/read-tick/media state) actually changes. Callbacks are
 * deliberately NOT compared: they're invoked on press, and presses always
 * re-render the row first via the state they flip. `threadKey` guards
 * against a stale closure surviving a thread switch (ChatScreen's instance
 * is reused across threads, so rows must re-arm when the token changes).
 */
interface MessageRowProps {
  item: ChatMessageUI;
  group?: ChatGroupInfoUI;
  burnAfterOpen?: boolean;
  burnSeconds?: number;
  threadKey: string;
  playing: boolean;
  avErrMsg: string | null;
  saveState?: 'saving' | 'saved' | 'error';
  onMediaRetry: (id: string) => void;
  onMediaSave: (id: string) => void;
  onToggleAudio: (id: string, src: string, mime: string) => void;
  onOpenLightbox: (src: string, name: string) => void;
  onOpenVideo: (src: string, name: string) => void;
  /** b199 group invite card state + actions */
  inviteStatus?: 'joined' | 'declined' | 'joining' | 'error';
  onJoinInvite?: (id: string, link: string) => void;
  onDeclineInvite?: (id: string) => void;
  /** b199 reactions: undefined = reactions off for this thread */
  onReactOpen?: (id: string) => void;
  reactOpen?: boolean;
  onReact?: (id: string, emoji: string) => void;
  /** Play UGC: long-press menu (block); undefined = off */
  onMenu?: (id: string) => void;
}

const MessageRow = memo(function MessageRow({
  item, group, burnAfterOpen, burnSeconds, threadKey,
  playing, avErrMsg, saveState,
  onMediaRetry, onMediaSave, onToggleAudio, onOpenLightbox, onOpenVideo,
  inviteStatus, onJoinInvite, onDeclineInvite,
  onReactOpen, reactOpen, onReact, onMenu,
}: MessageRowProps) {
  const renderMedia = () => {
    const media = item.media!;
    if (media.loading && !media.src) {
      return (
        <View style={styles.mediaStub}>
          <ActivityIndicator color="#FFFFFF" size="small" />
          <Text style={styles.mediaStubTxt}>Decrypting media…</Text>
        </View>
      );
    }
    if (media.error && !media.src) {
      // b199 (ZTE device run): the relay answered 404 — the file was deleted
      // (burn window or expiry). Retrying can never bring it back.
      if (media.error === MEDIA_GONE) {
        return (
          <View style={styles.mediaStub}>
            <Text style={styles.mediaErrTxt}>Deleted — this media has burned</Text>
          </View>
        );
      }
      return (
        <TouchableOpacity style={styles.mediaStub} onPress={() => onMediaRetry(item.id)}>
          <Text style={styles.mediaErrTxt}>Couldn't load media — tap to retry</Text>
        </TouchableOpacity>
      );
    }
    if (media.src) {
      const isVideo = media.mime.startsWith('video/');
      const isAudio = media.mime.startsWith('audio/');
      // Audio (voice note): compact play row — no bubble image
      if (isAudio) {
        return (
          <View style={styles.audioRow}>
            <TouchableOpacity style={styles.audioBtn} onPress={() => onToggleAudio(item.id, media.src!, media.mime)}>
              <Text style={styles.audioBtnTxt}>{playing ? '⏸' : '▶'}</Text>
            </TouchableOpacity>
            <Text style={[styles.audioLbl, avErrMsg ? styles.mediaErrTxt : null]}>
              {avErrMsg ?? (playing ? 'Playing…' : 'Voice note')}
            </Text>
          </View>
        );
      }
      // Video: poster-style inline player
      if (isVideo) {
        return (
          <View>
            <TouchableOpacity activeOpacity={0.9} style={styles.videoBox} onPress={() => onOpenVideo(media.src!, media.name)}>
              <Text style={styles.videoIcon}>▶</Text>
              <Text style={styles.videoLbl}>Video — tap to play full screen</Text>
            </TouchableOpacity>
            {media.dl ? (
              <TouchableOpacity
                style={styles.saveBtn}
                onPress={() => onMediaSave(item.id)}
                disabled={saveState === 'saving' || saveState === 'saved'}
              >
                <Text style={styles.saveBtnTxt}>
                  {saveState === 'saving' ? 'Saving…' : saveState === 'saved' ? 'Saved ✓' : saveState === 'error' ? 'Save failed — tap to retry' : SAVE_MEDIA_LABEL}
                </Text>
              </TouchableOpacity>
            ) : null}
          </View>
        );
      }
      // Image (original path)
      return (
        <View>
          <TouchableOpacity activeOpacity={0.9} onPress={() => onOpenLightbox(media.src!, media.name)}>
            <Image source={{ uri: media.src }} style={styles.mediaImg} resizeMode="cover" />
          </TouchableOpacity>
          {media.dl ? (
            <TouchableOpacity
              style={styles.saveBtn}
              onPress={() => onMediaSave(item.id)}
              disabled={saveState === 'saving' || saveState === 'saved'}
            >
              <Text style={styles.saveBtnTxt}>
                {saveState === 'saving' ? 'Saving…' : saveState === 'saved' ? 'Saved ✓' : saveState === 'error' ? 'Save failed — tap to retry' : SAVE_MEDIA_LABEL}
              </Text>
            </TouchableOpacity>
          ) : null}
        </View>
      );
    }
    // b75: peer media that this device hasn't cached — a stub, never silence
    return (
      <TouchableOpacity style={styles.mediaStub} onPress={() => onMediaRetry(item.id)}>
        <Text style={styles.mediaStubTxt}>Tap to load media</Text>
      </TouchableOpacity>
    );
  };

  if (item.systemNote) {
    // b62 groups: centered system line (member joined / keys rotated /
    // signature discard) — same visual family as the capture notice
    return <Text style={styles.captureNotice}>{item.systemNote}</Text>;
  }
  // b75r2 (audit P-1): a capture notice (screenshot/recording) is a typed payload, never
  // inferred from the text (b61 drew any text starting with a warning sign as an
  // unattributed system line, so a peer could type one). The words are written here and
  // name who it was.
  const capture = parseCapturePayload(item.text);
  if (capture) {
    return <Text style={styles.captureNotice}>{captureNoticeText(capture, item.mine, item.sender)}</Text>;
  }
  if (item.groupInvite) {
    // b199: group invitation sent privately inside this encrypted chat
    const inv = item.groupInvite;
    return (
      <View style={[styles.bubbleRow, item.mine ? styles.mineRow : styles.peerRow]}>
        <View style={styles.inviteCard}>
          <Text style={styles.inviteKicker}>Group invitation</Text>
          <Text style={styles.inviteName} numberOfLines={2}>{isolateName(inv.name) || 'Group' /* audit VAR-58: peer-chosen, cleaned and isolated */}</Text>
          {item.mine ? (
            <Text style={styles.inviteSub}>{/* b71 (audit): links carry no group key since b71 (review P-01) — the old text said they did */}You invited them. Only their phone can take this seat, and they get the group’s keys once they join.</Text>
          ) : inviteStatus === 'joined' ? (
            <Text style={styles.inviteDone}>✓ Joined — find it in Conversations</Text>
          ) : inviteStatus === 'declined' ? (
            <Text style={styles.inviteSub}>Declined</Text>
          ) : (
            <>
              <Text style={styles.inviteSub}>You've been invited to join this group.{/* b77q (audit 3 AQ-4): "This seat is for you" went: nothing checked it against the link */}</Text>
              {inviteStatus === 'error' ? <Text style={styles.inviteErr}>Couldn't join — the invite may have expired. Ask for a new one.</Text> : null}
              <View style={styles.inviteActions}>
                <TouchableOpacity style={styles.inviteJoin} onPress={() => onJoinInvite?.(item.id, inv.link)} disabled={inviteStatus === 'joining'}>
                  <Text style={styles.inviteJoinTxt}>{inviteStatus === 'joining' ? 'Joining…' : 'Join'}</Text>
                </TouchableOpacity>
                <TouchableOpacity style={styles.inviteDecline} onPress={() => onDeclineInvite?.(item.id)} disabled={inviteStatus === 'joining'}>
                  <Text style={styles.inviteDeclineTxt}>Decline</Text>
                </TouchableOpacity>
              </View>
            </>
          )}
          {item.ts ? (
            <Text style={item.mine ? [styles.mineTs, styles.mineTsOnDark] : styles.peerTs}>
              {new Date(item.ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
            </Text>
          ) : null}
        </View>
      </View>
    );
  }
  const canReact = !!onReact && !item.systemNote && (!item.mine || !!item.id);
  const reacts = [item.reactions?.peer, item.reactions?.mine].filter(Boolean) as string[];
  return (
    <View style={[styles.bubbleRow, item.mine ? styles.mineRow : styles.peerRow]}>
      <View style={[styles.bubbleCol, item.mine ? styles.bubbleColMine : styles.bubbleColPeer]}>
      {reactOpen && canReact ? (
        <View style={[styles.reactBar, item.mine ? styles.reactBarMine : styles.reactBarPeer]}>
          {REACTIONS.map((e) => (
            <TouchableOpacity
              key={e}
              style={[styles.reactBtn, item.reactions?.mine === e ? styles.reactBtnOn : null]}
              onPress={() => onReact?.(item.id, e)}
              accessibilityLabel={item.reactions?.mine === e ? `Remove ${e} reaction` : `React ${e}`}
            >
              <Text style={styles.reactEmoji}>{e}</Text>
            </TouchableOpacity>
          ))}
          {/* b54 (owner, device test Oct 18): copy a text message — needed to
              pass invite links between phones from inside a chat */}
          {!item.media && item.text ? (
            <TouchableOpacity
              style={styles.reactBtn}
              onPress={() => { copySensitive(item.text).catch(() => undefined); onReactOpen?.(item.id); }} /* b70 (L-6): cleared after 60 s */
              accessibilityLabel="Copy message text"
            >
              <Ionicons name="copy-outline" size={20} color="#FFFFFF" />
            </TouchableOpacity>
          ) : null}
        </View>
      ) : null}
      <Pressable
        onLongPress={canReact ? () => onReactOpen?.(item.id) : (onMenu && !item.mine && !item.systemNote ? () => onMenu(item.id) : undefined)}
        delayLongPress={350}
        style={[styles.bubble, styles.bubbleInCol, item.mine ? styles.mineBubble : styles.peerBubble, item.media ? styles.mediaBubble : null]}
      >
        {group && !item.mine && item.sender ? (
          <Text style={styles.senderLbl}>
            {isolateName(item.sender) /* b71 (audit): no hidden characters, can't reorder the text around it */}{item.senderVerified ? ' ✓' : ''}
            {item.senderCreator ? <Text style={styles.creatorBadge}>{'  CREATOR'}</Text> : null}
          </Text>
        ) : null}
        {item.media ? (
          <>
            {renderMedia()}
            <Text style={styles.mediaCaption} numberOfLines={1}>{mediaCaption(item.media)}</Text>
          </>
        ) : (
          <Text style={item.mine ? styles.mineText : styles.peerText}>{item.text}</Text>
        )}
        {item.ts ? (
          <Text style={item.mine ? [styles.mineTs, item.media ? styles.mineTsOnDark : null] : styles.peerTs}>
            {new Date(item.ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
            {/* b123: read-receipt tick — teal ✓ read, replacing the washed-out
                plain " · read" text (owner live-test ask, Sept 24). */}
            {item.mine && item.read ? <Text style={styles.readTick}>  ✓ read</Text> : null}
            {/* b77r1 (audit A-5): never shown as sent while it only waits in the outbox */}
            {item.mine && item.queued && !item.read ? <Text style={styles.queuedTick}>  · Spacing out this new chat so it's harder to link to you (usually under a minute)</Text> : null}
            {/* b77p (audit 2, VAR-03): the sender's copy burns from the send time (receipts or not),
                so its countdown runs from min(send time, receipt) and shows on unread own rows too */}
            {burnAfterOpen && !item.systemNote ? <BurnCountdown openedAt={burnAnchor(item)} burnSeconds={burnSeconds ?? 86400} /> : null}
          </Text>
        ) : null}
      </Pressable>
      {reacts.length ? (
        <View style={[styles.reactBadge, item.mine ? styles.reactBadgeMine : styles.reactBadgePeer]}>
          <Text style={styles.reactBadgeTxt}>{reacts.join(' ')}</Text>
        </View>
      ) : null}
      </View>
    </View>
  );
}, (a, b) => {
  // VALUE compare — new object identities from the per-render map must NOT
  // re-render the row (that's the shake). Callbacks excluded by design.
  const ai = a.item, bi = b.item;
  if (ai.id !== bi.id || ai.text !== bi.text || ai.mine !== bi.mine || ai.ts !== bi.ts
    || ai.read !== bi.read || ai.sender !== bi.sender || ai.senderVerified !== bi.senderVerified || ai.senderCreator !== bi.senderCreator
    || ai.systemNote !== bi.systemNote || ai.openedAt !== bi.openedAt || !!ai.queued !== !!bi.queued) return false;
  if ((ai.reactions?.mine ?? '') !== (bi.reactions?.mine ?? '') || (ai.reactions?.peer ?? '') !== (bi.reactions?.peer ?? '')
    || a.reactOpen !== b.reactOpen || !!a.onReact !== !!b.onReact || !!a.onMenu !== !!b.onMenu) return false;
  if ((ai.groupInvite?.link ?? '') !== (bi.groupInvite?.link ?? '') || a.inviteStatus !== b.inviteStatus) return false;
  const am = ai.media, bm = bi.media;
  if (!!am !== !!bm) return false;
  if (am && bm && (am.name !== bm.name || am.mime !== bm.mime || am.size !== bm.size
    || am.dl !== bm.dl || am.src !== bm.src || am.loading !== bm.loading || am.error !== bm.error)) return false;
  if (a.group !== b.group || a.burnAfterOpen !== b.burnAfterOpen || a.burnSeconds !== b.burnSeconds
    || a.threadKey !== b.threadKey || a.playing !== b.playing || a.avErrMsg !== b.avErrMsg
    || a.saveState !== b.saveState) return false;
  return true;
});

export function ChatScreen({ title, subtitle, status, busy, error, historyNotice, messages, threadKey, onDismissError, draft, onDraftChange, onSend, onBack, onStartCall, onEndSession, onEndGroupForAll, canNewThread, onNewThread, contact, myVerified, onVerifySession, onAttach, pendingPick, onSendMedia, onCancelPick, allowDl, onAllowDlChange, onMediaRetry, onMediaSave, mediaSaving, voiceRec, onVoiceRecord, onVoiceCancel, onVoiceSend, group, burnAfterOpen, burnSeconds, showVerifyCard, onVerifyCardDismiss, canRename, threadNickname, onRenameThread, sessionFingerprint, peerVeilId, peerPinned,
  onPinContact, inviteState, onJoinGroupInvite, onDeclineGroupInvite, onReactMessage,
  onBlockSender, onBlockContact, privateKeyboard, request, onAcceptRequest, onDeclineRequest, unrecoverable, setupFailed, unavailable, endedByPeer, onCheckAgain }: ChatScreenProps) {
  // Play UGC (18 Oct 2026): long-press someone else's group message -> block
  // its sender. Rows get one stable callback; the live props ride a ref.
  const { node: chooserNode, choose } = useThemedChooser();
  const { node: promptNode, ask } = useThemedPrompt();
  const menuRef = useRef({ onBlockSender, messages });
  menuRef.current = { onBlockSender, messages };
  const hasMessageMenu = !!onBlockSender;
  const onMessageMenu = React.useCallback(async (id: string) => {
    const { onBlockSender: block, messages: list } = menuRef.current;
    const item = list.find((m) => m.id === id);
    if (!item || item.mine || item.systemNote) return;
    const who = item.sender || 'this sender';
    const actions: { label: string; sub?: string; run: () => Promise<void> }[] = [];
    if (block) actions.push({ label: `Block ${who}`, sub: 'Hide their posts and messages on this phone', run: async () => {
      const ok = await ask({ title: `Block ${who}?`, message: 'You won’t see their posts or messages on this phone, and they won’t notify you. They aren’t told. You can unblock them in Settings.', confirm: true, danger: true, submitLabel: 'Block' });
      if (ok === true) await block(id);
    } });
    if (!actions.length) return;
    const i = await choose({ title: 'This message', options: actions.map(({ label, sub }) => ({ label, sub })) });
    if (i === null) return;
    try {
      await actions[i].run();
    } catch (e) {
      console.log('[veil-ugc] message action failed:', String((e as Error)?.message ?? e));
      await ask({ title: 'That didn’t work', message: String((e as Error)?.message || 'Please try again in a moment.'), info: true });
    }
  }, [choose, ask]);
  const confirmBlockContact = React.useCallback(async () => {
    if (!onBlockContact) return;
    const ok = await ask({ title: `Block ${title}?`, message: 'This ends the chat on both sides and hides them on this phone: no messages, no notifications, no new chat requests from them. They aren’t told why. You can unblock them in Settings.', confirm: true, danger: true, submitLabel: 'Block' });
    if (ok === true) onBlockContact();
  }, [ask, onBlockContact, title]);
  // b199 reactions: which message's bar is open. Rows get stable callbacks
  // (their memo compare skips callbacks), routed through a ref.
  const [reactOpenId, setReactOpenId] = React.useState<string | null>(null);
  const onReactRef = useRef(onReactMessage);
  onReactRef.current = onReactMessage;
  const openReact = React.useCallback((id: string) => setReactOpenId((cur) => (cur === id ? null : id)), []);
  const pickReact = React.useCallback((id: string, emoji: string) => { setReactOpenId(null); onReactRef.current?.(id, emoji); }, []);
  useEffect(() => { setReactOpenId(null); }, [threadKey]);
  // b199 group invitations: in-flight / failed joins (persisted outcome lives in inviteState)
  const [inviteBusy, setInviteBusy] = React.useState<Record<string, 'joining' | 'error'>>({});
  const joinInvite = React.useCallback((id: string, link: string) => {
    if (!onJoinGroupInvite) return;
    setInviteBusy((s) => ({ ...s, [id]: 'joining' }));
    onJoinGroupInvite(id, link)
      .then(() => setInviteBusy((s) => { const n = { ...s }; delete n[id]; return n; }))
      .catch((e) => { console.log('[veil-group-invite] join failed:', String((e as Error)?.message ?? e)); setInviteBusy((s) => ({ ...s, [id]: 'error' })); });
  }, [onJoinGroupInvite]);
  const declineInvite = React.useCallback((id: string) => { void onDeclineGroupInvite?.(id); }, [onDeclineGroupInvite]);
  // b62 groups: Members overlay + evict two-tap arming
  const [groupPanel, setGroupPanel] = React.useState(false);
  // the members panel needs the whole screen — drop the message keyboard when it opens
  React.useEffect(() => { if (groupPanel) Keyboard.dismiss(); }, [groupPanel]);
  const [evictArmed, setEvictArmed] = React.useState<string | null>(null);
  const [groupErr, setGroupErr] = React.useState<string | null>(null);
  React.useEffect(() => { if (!group) { setGroupPanel(false); setEvictArmed(null); setGroupErr(null); } }, [group]);

  // b111 (owner report: keyboard covers what you're typing): RN's
  // KeyboardAvoidingView "padding" mode proved unreliable on device — replaced
  // with deterministic keyboard-height padding: the composer grows by exactly
  // the keyboard height, the message list shrinks, and the input always sits
  // directly above the keys. Raw height comes from iOS's keyboardWillShow /
  // WillHide / WillChangeFrame (floating keyboard included).
  const kbH = useKbPadding();
  // follow the keyboard: once it's up, bring the newest message (and what
  // you're typing) into view — a small delay lets the shrunken list lay out.
  useEffect(() => {
    if (kbH > 0) { const t = setTimeout(() => listRef.current?.scrollToEnd?.({ animated: false }), 60); return () => clearTimeout(t); }
  }, [kbH]);
  // b180 (owner report: the "server is briefly busy" banner never goes away
  // unless you exit the thread): chat errors are TRANSIENT by design — the
  // banner says "wait a few seconds and try again", so it must hold itself
  // to that promise. Self-dismiss after 6s; a new error resets the clock,
  // a successful send clears it instantly (App: b180 success-path clear).
  useEffect(() => {
    if (!error) return;
    const t = setTimeout(() => onDismissError(), 6000);
    return () => clearTimeout(t);
  }, [error, onDismissError]);
  // b62: media playback (voice notes + video). One shared AV player: playing a
  // new item stops the previous. data: URIs work with expo-av via source={{ uri }}.
  const [audioPlayingId, setAudioPlayingId] = useState<string | null>(null);
  const soundRef = useRef<{ unloadAsync: () => Promise<unknown> } | null>(null);
  // b198 watchdog: expo-av's status callback proved unreliable as an end-of-
  // playback signal on real voice notes (owner: row stuck "Playing…" until a
  // manual pause — persisted across the didJustFinish + isPlaying callback
  // fixes). Poll the player DIRECTLY once a second: any loaded player that is
  // not playing past the start, or reports didJustFinish, is done. Cleared on
  // every stop, so it never outlives the playback.
  const audioWatchRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const stopAudio = async () => {
    if (audioWatchRef.current) { clearInterval(audioWatchRef.current); audioWatchRef.current = null; }
    const s = soundRef.current as ({ unloadAsync: () => Promise<unknown>; setOnPlaybackStatusUpdate?: (cb: null) => void } | null);
    soundRef.current = null;
    if (s) {
      // b199 (seen on the first expo-av 15 device run: ~150 "ended" resets
      // after one voice note): an unloaded player keeps emitting isLoaded:false
      // status updates, and each one re-ran this stop. Detach the listener
      // before unloading.
      try { s.setOnPlaybackStatusUpdate?.(null); } catch { /* older player */ }
      try { await s.unloadAsync(); } catch { /* already gone */ }
    }
    setAudioPlayingId(null);
  };
  const [audioErr, setAudioErr] = useState<{ id: string; msg: string } | null>(null);
  const toggleAudio = async (id: string, src: string, mime: string) => {
    if (audioPlayingId === id) { await stopAudio(); return; }
    await stopAudio();
    setAudioErr(null);
    console.log(`[veil-av] play tapped (${mime || 'no mime'}, ${src.slice(0, 5) === 'data:' ? 'data uri' : 'file'})`);
    try {
      // b73 (owner report: receive-side voice notes viewable but silently
      // dead on tap): a prior recording session on this device leaves iOS's
      // audio session in .playAndRecord — reset it to plain playback first,
      // best-effort, so a stale record-mode session can't mute playback.
      const { Audio } = require('expo-av');
      try { await Audio.setAudioModeAsync({ allowsRecordingIOS: false, playsInSilentModeIOS: true, staysActiveInBackground: false }); } catch { /* best-effort */ }
      // b199: this playback ends exactly once, however many status updates
      // follow — and only once it has really started: expo-av 15 can report
      // isLoaded:false BEFORE createAsync resolves, which used to end the
      // playback before it began (row stuck on "Playing").
      let ended = false;
      let live: unknown = null;
      const end = (why: string) => { if (ended || !live) return; ended = true; console.log(`[veil-av] ${why} — resetting row`); void stopAudio(); };
      // b199 (Android device run): a player that never finishes loading used
      // to leave the row silent with no log and no error. Give it 10 s.
      const created = Audio.Sound.createAsync(
        { uri: src },
        { shouldPlay: true },
        (st: { isLoaded?: boolean; didJustFinish?: boolean; isPlaying?: boolean; positionMillis?: number }) => {
          if (ended || !live || soundRef.current !== live) return;
          if (!st.isLoaded || st.didJustFinish) { end('status ended the playback'); return; }
          if (st.isPlaying === false && (st.positionMillis ?? 0) > 0) end('status stopped-without-finish');
        },
      );
      const { sound } = await Promise.race([
        created,
        new Promise<never>((_, rej) => setTimeout(() => rej(new Error('player did not load within 10 s')), 10000)),
      ]);
      console.log('[veil-av] player loaded — playing');
      soundRef.current = sound as unknown as { unloadAsync: () => Promise<unknown> };
      live = sound; // b199: from here on, status updates and the watchdog count
      setAudioPlayingId(id);
      let ticks = 0;
      const watchdog = setInterval(async () => {
        try {
          const s = await (sound as unknown as { getStatusAsync: () => Promise<{ isLoaded?: boolean; didJustFinish?: boolean; isPlaying?: boolean; positionMillis?: number; durationMillis?: number; isBuffering?: boolean; volume?: number; isMuted?: boolean }> }).getStatusAsync();
          if (ticks++ < 3) console.log(`[veil-av] tick ${ticks}: playing=${!!s.isPlaying} pos=${s.positionMillis ?? '?'} dur=${s.durationMillis ?? '?'} buffering=${!!s.isBuffering} vol=${s.volume ?? '?'} muted=${!!s.isMuted}`);
          // b199 (ZTE device run): Android can load a note and never start it
          // (shouldPlay ignored — the row sat on "Playing" at 0:00 in silence).
          // Nudge it once at 2 s; if it still hasn't moved by 5 s, say so.
          if (s.isLoaded && !s.isPlaying && (s.positionMillis ?? 0) === 0 && !s.isBuffering) {
            if (ticks === 2) { console.log('[veil-av] not started — nudging play'); void (sound as unknown as { playAsync: () => Promise<unknown> }).playAsync().catch(() => undefined); }
            if (ticks >= 5) { ended = true; console.log('[veil-av] never started — giving up'); void stopAudio(); setAudioErr({ id, msg: 'Could not play — tap to retry' }); }
          }
          if (!s.isLoaded || s.didJustFinish || (s.isPlaying === false && (s.positionMillis ?? 0) > 0)) {
            end(`watchdog: playback ended (loaded=${!!s.isLoaded} finish=${!!s.didJustFinish} playing=${!!s.isPlaying} pos=${s.positionMillis ?? 0})`);
          }
        } catch { end('watchdog: status read failed'); }
      }, 1000);
      audioWatchRef.current = watchdog;
    } catch (e) {
      // b73: was silently swallowed — a dead ▶ with no feedback is exactly
      // the owner-reported symptom. Now visible + logged for Metro triage.
      console.log('[veil-av] playback failed:', String(e));
      // b74 (owner report: voice note SENT FROM WEB taps to "error"): the web
      // app records voice notes as audio/webm;codecs=opus (Chrome/Firefox
      // MediaRecorder) — iOS's AVPlayer CANNOT decode webm/opus at all, so
      // the tap fails no matter how clean the decrypt/cache was. Native-to-
      // native notes (.m4a) play fine. Real fix is web-side (WAV transcode
      // work order to builder); until it lands, say WHY instead of a generic
      // retry that can never succeed.
      const m = (mime || '').toLowerCase();
      if (m.includes('webm') || m.includes('ogg')) {
        setAudioErr({ id, msg: 'Web app voice notes use a codec iOS can\'t play — web fix in progress' });
      } else {
        setAudioErr({ id, msg: 'Could not play — tap to retry' });
      }
    }
  };
  useEffect(() => { return () => { void stopAudio(); }; }, []);
  const listRef = useRef<FlatList<ChatMessageUI>>(null);
  const [lightbox, setLightbox] = useState<{ src: string; name: string } | null>(null);
  // b140: full-screen video player — a video bubble taps straight into a
  // native-controls player covering the screen (voice notes keep the inline row).
  const [videoFS, setVideoFS] = useState<{ src: string; name: string } | null>(null);
  useEffect(() => {
    if (messages.length) listRef.current?.scrollToEnd?.({ animated: false });
  }, [messages.length]);

  // b163: sending requires the fingerprint ceremony on EVERY pairwise path — pinned contact
  // threads no longer send on keys alone. Groups are exempt: their trust anchor is the
  // group signature scheme, not a pairwise ceremony.
  // b71 (audit): the gate is the confirmation sealed on THIS phone.
  // b77t (audit 5 M-F / IH C-01, owner decision "until you confirm"): the gate is one-sided. Each phone
  // locks its own sending until ITS user confirms; nothing tells this phone whether the other person
  // has confirmed (the old server flag is gone), and no text here says otherwise.
  const verifyGate = !group && !myVerified;
  const composerLocked = status !== 'active' || busy || verifyGate;

  // (b66) the ✕ sheet is now VEIL-styled instead of the plain system action
  // sheet: End renders as a true RED destructive button (the system sheet showed
  // plain text on device), and a stray tap still can't end the session — End
  // requires a deliberate press on the red row.
  const [sheet, setSheet] = useState(false);
  // b126: verification panel replaces the system Alert — the fingerprint is
  // shown BEFORE "Mark verified" unlocks (two-step comparison gate), and the
  // same panel stays viewable any time AFTER verification via the badge.
  const [verifyPanel, setVerifyPanel] = useState<'ceremony' | 'view' | null>(null);
  /** b161: panel-LOCAL verify failure — never the app-wide error state (suppression rule). */
  const [verifyFail, setVerifyFail] = useState(false);
  /** b71 (audit): the Accept tap on a contact request is running */
  const [reqBusy, setReqBusy] = useState(false);
  const [compareArmed, setCompareArmed] = useState(false);
  // b123: local thread rename (device-local nickname against the peer veil-id)
  const [renameOpen, setRenameOpen] = useState(false);
  const [renameInput, setRenameInput] = useState('');
  // b176 (owner report Oct 2, live on-device: bubbles visibly "shaking"
  // side-to-side during rapid-fire bursts on a burn-after-open thread): the
  // b72 design ticked ONE parent-level clock state every second, which
  // re-rendered the ENTIRE message list 1×/s — stacked with per-message
  // renders from the burst it read as a continuous wobble. The tick now
  // lives inside <BurnCountdown> below, so a per-second update touches
  // only that one countdown Text node, and the FlatList renders only
  // when messages actually change.

  // b179: renderMedia moved into memoized MessageRow (shake fix) — see above.

  return (
    <View style={styles.fill}>
    <View style={styles.fill}>
      {/* header */}
      {/* b199 UI redesign (owner, Oct 16): one clean bar — back, avatar, name +
          status, call, ⋯. "＋ New" lived here AND in the ✕ sheet; it is now
          only in the ⋯ sheet, and ⋯ replaces ✕ (✕ read as "close"). */}
      <View style={styles.header}>
        <TouchableOpacity onPress={onBack} style={styles.backBtn} hitSlop={{ top: 10, bottom: 10, left: 10, right: 6 }} accessibilityLabel="Back">
          <Ionicons name="chevron-back" size={26} color="#FFFFFF" />
        </TouchableOpacity>
        <View style={[styles.hAvatar, group && styles.hAvatarGroup]}>
          <Text style={styles.hAvatarTxt}>{group ? '#' : titleInitials(title).toUpperCase()}</Text>
        </View>
        <View style={styles.headerMid}>
          <Text style={styles.title} numberOfLines={1}>{isolateName(title)}</Text>
          {status === 'pending' || status === 'ended' ? (
            <Text style={styles.subtitle} numberOfLines={1}>{status === 'pending' ? (request ? 'Wants to chat · not in your contacts' : 'Waiting for your contact to accept…') : unavailable ? 'No longer available' : 'Session ended'}</Text>
          ) : null}
          {group ? (
            <TouchableOpacity style={styles.vBadge} onPress={() => setGroupPanel(true)} hitSlop={{ top: 10, bottom: 10 }}>
              <Text style={styles.vBadgeTxtGroup}>Members · epoch {group.epoch} ›</Text>
            </TouchableOpacity>
          ) : status !== 'ended' && !request ? (
            /* b163 (web P1.2 parity): pinned contact threads show the SAME
             * ceremony state as invite threads — the 'Pinned contact' trust
             * chip is gone; sending from this phone unlocks once you confirm (b77t M-F: one-sided).
             * The pin still anchors identity (panel shows the pinned state);
             * the ceremony is the human comparison on top of it. */
            <TouchableOpacity
              style={[styles.vBadge, myVerified ? styles.vBadgeOk : styles.vBadgeNone]}
              onPress={() => { setCompareArmed(false); setVerifyPanel(myVerified ? 'view' : 'ceremony'); }}
            >
              <Text style={[styles.vBadgeTxt, myVerified ? styles.vBadgeTxtOk : styles.vBadgeTxtNone]}>
                {myVerified ? '✓ Safety code confirmed' : 'Safety code not confirmed'}
              </Text>
            </TouchableOpacity>
          ) : null}
        </View>
        {onStartCall && status !== 'ended' && status !== 'pending' ? (
          <TouchableOpacity onPress={onStartCall} style={styles.callBtn} hitSlop={{ top: 10, bottom: 10, left: 6, right: 6 }} accessibilityLabel="Call">
            {/* b198 (owner): a proper phone icon replaces the two-ring glyph */}
            <Ionicons name="call-outline" size={22} color="#FFFFFF" />
          </TouchableOpacity>
        ) : null}
        {status !== 'ended' ? (
          <TouchableOpacity onPress={() => setSheet(true)} disabled={busy} style={styles.menuBtn} hitSlop={{ top: 12, bottom: 12, left: 8, right: 12 }} accessibilityLabel="Chat options">
            <Ionicons name="ellipsis-horizontal" size={22} color="#8E9696" />
          </TouchableOpacity>
        ) : null}
      </View>

      {/* b62 groups: Members overlay — roster, epoch fingerprint, creator admin */}
      {group && groupPanel ? (
        <View style={styles.groupOverlay}>
          <View style={styles.groupPanel}>
            <View style={styles.groupPanelHead}>
              <Text style={styles.groupPanelTitle}>Group members</Text>
              <TouchableOpacity onPress={() => { setGroupPanel(false); setEvictArmed(null); setGroupErr(null); }} hitSlop={{ top: 10, bottom: 10 }}>
                <Text style={styles.groupCloseTxt}>✕</Text>
              </TouchableOpacity>
            </View>
            <Text style={styles.groupFp}>
              Epoch {group.epoch} fingerprint{'\n'}
              {group.fingerprint || 'Not available yet — opens with the group'}
            </Text>
            <ScrollView style={styles.groupMemberList}>
              {group.members.length === 0 ? (
                <Text style={styles.groupEmpty}>The roster opens with the group.</Text>
              ) : group.members.map((m) => (
                <View key={m.veilId} style={styles.groupMemberRow}>
                  <View style={{ flex: 1 }}>
                    <Text style={styles.groupMemberName}>{m.nick ? isolateName(m.nick) : m.veilId.slice(0, 10) + '…'}</Text>
                    {!!m.nick && <Text style={styles.groupMemberMeta}>{m.veilId.slice(0, 10)}…</Text>}
                    <Text style={styles.groupMemberMeta}>{/* b75 (audit GR-3): roles come from this phone's own state (the creator key it holds; on the creator's phone, who it admitted) */}
                      {m.role === 'creator' ? 'Creator' : m.role === 'pending' ? 'Waiting for your approval — no group keys yet' : m.leaving ? 'Says they are leaving — still gets new group keys until the group creator removes them' : 'Member'} · joined epoch {m.joinedEpoch}</Text>
                    {group.isCreator && m.goneSince !== undefined ? (
                      <Text style={styles.groupMemberMeta}>Not on the group's server list since {new Date(m.goneSince).toLocaleDateString()} — they may have left. They still get new keys until you remove them.</Text>
                    ) : null}
                  </View>
                  {group.isCreator ? (
                    <TouchableOpacity
                      style={[styles.evictBtn, evictArmed === m.veilId ? styles.evictBtnArmed : null]}
                      disabled={group.busy || m.role === 'creator'}
                      onPress={async () => {
                        if (evictArmed !== m.veilId) { setEvictArmed(m.veilId); setTimeout(() => setEvictArmed((cur) => (cur === m.veilId ? null : cur)), 6000); return; }
                        setEvictArmed(null); setGroupErr(null);
                        try { await group.onEvict({ veilId: m.veilId, ikPub: m.ikPub }); } catch (e) { setGroupErr('That did not work — please try again.'); console.log('[veil-error] group-evict:', String((e as Error).message ?? e)); }
                      }}
                    >
                      <Text style={styles.evictBtnTxt}>{evictArmed === m.veilId ? 'Remove?' : 'Remove'}</Text>
                    </TouchableOpacity>
                  ) : null}
                </View>
              ))}
            </ScrollView>
            {group.isCreator ? (
              <TouchableOpacity
                style={styles.rotateBtn}
                disabled={group.busy}
                onPress={async () => {
                  setGroupErr(null);
                  try { await group.onRotate(); } catch (e) { setGroupErr('That did not work — please try again.'); console.log('[veil-error] group-evict:', String((e as Error).message ?? e)); }
                }}
              >
                <Text style={styles.rotateBtnTxt}>{group.busy ? 'Working…' : 'Rotate keys now'}</Text>
              </TouchableOpacity>
            ) : null}
            {groupErr ? <Text style={styles.groupErr}>{groupErr}</Text> : null}
          </View>
        </View>
      ) : null}

      {error ? <Text style={styles.error}>{error}</Text> : null}

      {historyNotice ? <Text style={styles.notice}>{historyNotice}</Text> : null}

      {/* b76r2 (ZTE-5): a dead thread used to say "wait for the safety code" forever while the peer kept sending into it */}
      {unrecoverable ? (
        <View style={styles.claimRow}>
          <View style={styles.inviteCard}>
            <Text style={styles.inviteKicker}>This chat can't continue here</Text>
            <Text style={styles.inviteSub}>This phone no longer has the keys for this chat (Nothing at rest or a wipe removed them), so nothing in it can be sent or read here. End it and start a new chat with the same person; ending it tells their phone too.</Text>
            <View style={styles.inviteActions}>
              <TouchableOpacity style={styles.inviteJoin} onPress={onEndSession}>
                <Text style={styles.inviteJoinTxt}>End this chat</Text>
              </TouchableOpacity>
            </View>
          </View>
        </View>
      ) : null}

      {/* b77m merge (audit VAR-07): the relay's word alone no longer ends a chat or deletes its history */}
      {unavailable && !unrecoverable ? (
        <View style={styles.claimRow}>
          <View style={styles.inviteCard}>
            <Text style={styles.inviteKicker}>{endedByPeer ? CHAT_ENDED_BY_PEER_TEXT : CHAT_UNAVAILABLE_TEXT}</Text>
            <Text style={styles.inviteSub}>Nothing more can be sent or received in this chat. Its messages stay on this phone until you delete it. Start a new chat to keep talking to this person.</Text>
            <View style={styles.inviteActions}>
              {/* b77n (pre-audit INFO-5): the relay's word alone can be wrong — ask it again (never after the peer's END) */}
              {onCheckAgain && !endedByPeer ? (
                <TouchableOpacity style={styles.inviteJoin} accessibilityLabel="Check again" onPress={onCheckAgain}>
                  <Text style={styles.inviteJoinTxt}>Check again</Text>
                </TouchableOpacity>
              ) : null}
              <TouchableOpacity
                style={styles.inviteJoin}
                accessibilityLabel="Delete this chat"
                onPress={() => { void (async () => {
                  const ok = await ask({ title: 'Delete this chat?', message: 'Its messages are removed from this phone. This can’t be undone.', confirm: true, danger: true, submitLabel: 'Delete' });
                  if (ok === true) onEndSession();
                })(); }}
              >
                <Text style={styles.inviteJoinTxt}>Delete this chat</Text>
              </TouchableOpacity>
            </View>
          </View>
        </View>
      ) : null}

      {/* b77r1 (audit A-5): a chat whose mailbox never finished opening used to wait (and queue) for ever */}
      {setupFailed && !unrecoverable ? (
        <View style={styles.claimRow}>
          <View style={styles.inviteCard}>
            <Text style={styles.inviteKicker}>This chat couldn't finish setting up</Text>
            <Text style={styles.inviteSub}>The two phones never finished connecting this chat, so messages in it can't be delivered. Start a new chat with the same person and end this one.</Text>
            <View style={styles.inviteActions}>
              <TouchableOpacity style={styles.inviteJoin} onPress={onEndSession}>
                <Text style={styles.inviteJoinTxt}>End this chat</Text>
              </TouchableOpacity>
            </View>
          </View>
        </View>
      ) : null}

      {/* b71 (audit F-07): join requests — nobody gets into the group without the creator's tap */}
      {group?.isCreator && group.pendingRequests?.length ? group.pendingRequests.map((r) => (
        <View key={r.ikPub} style={styles.claimRow}>
          <View style={styles.inviteCard}>
            <Text style={styles.inviteKicker}>Wants to join</Text>
            <Text style={styles.inviteName} numberOfLines={2}>{isolateName(r.label)}</Text>
            <Text style={styles.inviteSub}>Vardum ID {r.veilId}</Text>
            {r.contactLine ? <Text style={styles.inviteSub}>{r.contactLine}</Text> : null}
            <Text style={styles.inviteSub}>They opened one of this group's invite links. Approve only someone you meant to invite. The keys rotate first, so they won't see earlier messages.</Text>
            <View style={styles.inviteActions}>
              <TouchableOpacity style={styles.inviteJoin} disabled={group.busy} onPress={async () => {
                setGroupErr(null);
                try { await group.onApproveRequest?.(r.ikPub); } catch (e) { setGroupErr('That did not work — please try again.'); console.log('[veil-error] group-approve:', String((e as Error).message ?? e)); }
              }}>
                <Text style={styles.inviteJoinTxt}>{group.busy ? 'Working…' : 'Approve'}</Text>
              </TouchableOpacity>
              <TouchableOpacity style={styles.inviteDecline} disabled={group.busy} onPress={() => { void group.onDeclineRequest?.(r.ikPub).catch(() => undefined); }}>
                <Text style={styles.inviteDeclineTxt}>Decline</Text>
              </TouchableOpacity>
            </View>
          </View>
        </View>
      )) : null}

      {showVerifyCard && !myVerified && !unrecoverable ? (
        <View style={styles.vCard}>
          <View style={styles.vCardBody}>
            <Text style={styles.vCardTitle}>Check the safety code</Text>
            <Text style={styles.vCardTxt}>Sending unlocks once you compare the safety code with the other person outside Vardum (call them or meet) and confirm it on this phone. It is the check that nobody is intercepting this chat.</Text>
            <View style={styles.vCardRow}>
              <TouchableOpacity style={styles.vCardBtn} onPress={() => { setCompareArmed(false); setVerifyFail(false); setVerifyPanel('ceremony'); }} accessibilityLabel="Verify fingerprints now">
                <Text style={styles.vCardBtnTxt}>Verify fingerprints</Text>
              </TouchableOpacity>
              <TouchableOpacity style={styles.vCardSkip} onPress={onVerifyCardDismiss} accessibilityLabel="Dismiss verification reminder">
                <Text style={styles.vCardSkipTxt}>Not now</Text>
              </TouchableOpacity>
            </View>
          </View>
        </View>
      ) : null}

      {/* messages */}
      <FlatList
        ref={listRef}
        style={styles.list}
        keyboardShouldPersistTaps="handled"
        // b199: the keyboard goes down when the person scrolls the chat (or
        // taps an empty part of it — "handled" above), not when they send
        keyboardDismissMode="on-drag"
        onScrollBeginDrag={() => setReactOpenId(null)}
        data={messages}
        keyExtractor={(m) => m.id}
        renderItem={({ item }) => (
          <MessageRow
            item={item}
            group={group}
            burnAfterOpen={burnAfterOpen}
            burnSeconds={burnSeconds}
            threadKey={threadKey}
            playing={audioPlayingId === item.id}
            avErrMsg={audioErr?.id === item.id ? audioErr.msg : null}
            saveState={mediaSaving[item.id]}
            onMediaRetry={onMediaRetry}
            onMediaSave={onMediaSave}
            onToggleAudio={toggleAudio}
            onOpenLightbox={(s, n) => setLightbox({ src: s, name: n })}
            onOpenVideo={(s, n) => { stopAudio(); setVideoFS({ src: s, name: n }); }}
            inviteStatus={inviteState?.[item.id] ?? inviteBusy[item.id]}
            onJoinInvite={joinInvite}
            onDeclineInvite={declineInvite}
            onReactOpen={onReactMessage ? openReact : undefined}
            reactOpen={reactOpenId === item.id}
            onReact={onReactMessage ? pickReact : undefined}
            onMenu={hasMessageMenu ? onMessageMenu : undefined}
          />
        )}
        ListEmptyComponent={
          <View style={styles.empty}>
            <Text style={styles.emptyTxt}>{status === 'pending' && request ? 'Someone who isn\u2019t in your contacts wants to chat. The name they chose is not shown; check who it is before you accept.' : status === 'pending' ? 'Your contact hasn\u2019t accepted yet — messages will flow once they do.' : 'No messages yet. Say hi.'}</Text>
          </View>
        }
      />

      {/* b71 (audit): a request from a Vardum ID that isn't pinned is answered here —
          nothing is accepted, pinned or named until the user decides */}
      {request && status === 'pending' ? (
        <View style={styles.reqCard}>
          <Text style={styles.reqTitle}>Accept this chat request?</Text>
          <Text style={styles.reqTxt}>It comes from {isolateName(title)}, a Vardum ID that isn’t in your contacts. Accepting opens the chat; it doesn’t add them as a contact. You can check the safety code and pin them afterwards.</Text>
          <View style={styles.reqRow}>
            <TouchableOpacity style={styles.reqDecline} disabled={reqBusy} onPress={() => onDeclineRequest?.()} accessibilityLabel="Decline the chat request">
              <Text style={styles.reqDeclineTxt}>Decline</Text>
            </TouchableOpacity>
            <TouchableOpacity
              style={styles.reqAccept}
              disabled={reqBusy}
              onPress={() => { setReqBusy(true); void (onAcceptRequest?.() ?? Promise.resolve(false)).finally(() => setReqBusy(false)); }}
              accessibilityLabel="Accept the chat request"
            >
              <Text style={styles.reqAcceptTxt}>{reqBusy ? 'Accepting…' : 'Accept'}</Text>
            </TouchableOpacity>
          </View>
        </View>
      ) : null}

      {/* composer */}
      <View style={[styles.composer, kbH > 0 && { paddingBottom: kbH + 12 }]}>
        {verifyGate && status === 'active' && !busy && !unrecoverable ? (
          /* b163 (web P1.2 parity): blocked-send state explains itself and the
           * ceremony stays reachable from the composer — no dead-end lock. */
          <View style={styles.verifyNotice}>
            <Text style={styles.verifyNoticeTxt}>🔒 Sending unlocks once you compare the safety code with the other person and confirm it on this phone.{!contact ? ' For a chat from an invite link, this is the only check that the server didn’t swap the keys.' /* b77u (audit 6 U-M15) */ : ''}</Text>
            <TouchableOpacity
              style={styles.verifyNowBtn}
              onPress={() => { setCompareArmed(false); setVerifyFail(false); setVerifyPanel(myVerified ? 'view' : 'ceremony'); }}
              accessibilityLabel="Verify now"
            >
              <Text style={styles.verifyNowBtnTxt}>Verify now</Text>
            </TouchableOpacity>
          </View>
        ) : null}
        {/* b199 UI redesign (owner, Oct 16): attach · message · mic/send. The
            mic becomes a send arrow as soon as there is text; while recording,
            the bar becomes cancel · timer · send. */}
        {voiceRec.active ? (
          <>
            <TouchableOpacity style={[styles.roundBtn, styles.roundBtnGhost]} onPress={onVoiceCancel} accessibilityLabel="Cancel voice note">
              <Ionicons name="close" size={20} color="#8E9696" />
            </TouchableOpacity>
            <View style={styles.recBar}>
              <View style={styles.recDot} />
              <Text style={styles.recTxt}>Recording {fmtSecs(voiceRec.seconds)}</Text>
            </View>
            <TouchableOpacity style={[styles.roundBtn, styles.roundBtnSend]} onPress={onVoiceSend} accessibilityLabel="Send voice note">
              <Ionicons name="arrow-up" size={20} color="#0B0B0F" />
            </TouchableOpacity>
          </>
        ) : (
          <>
            <TouchableOpacity
              style={[styles.roundBtn, styles.roundBtnGhost, composerLocked && styles.roundBtnOff]}
              disabled={composerLocked}
              onPress={onAttach}
              accessibilityLabel="Attach a photo or video"
            >
              <Ionicons name="add" size={24} color="#FFFFFF" />
            </TouchableOpacity>
            <TextInput
              style={[styles.input, composerLocked && styles.inputLocked]}
              placeholder={unrecoverable ? 'This chat has ended on this phone' : unavailable ? 'This chat is no longer available' : status === 'pending' ? (request ? 'Accept the request to chat' : 'Locked until your contact accepts') : verifyGate ? 'Locked until you confirm the safety code' : 'Message'}
              placeholderTextColor="#5E6464"
              value={draft}
              onChangeText={onDraftChange}
              // b199 (owner request): the keyboard stays up after Send. The box
              // used to go non-editable while a send was in flight (busy), and
              // iOS drops the keyboard when the focused input is disabled.
              // Busy still blocks a second send via the button.
              editable={status === 'active' && !verifyGate}
              multiline
              // b70 (audit L-6): the Private keyboard setting. audit VAR-14: plus no content type / smart
              // insert on iOS; what it can't stop is said in Settings (src/secret-entry.ts)
              {...privateComposerProps(!!privateKeyboard)}
            />
            {draft.trim() ? (
              <TouchableOpacity
                style={[styles.roundBtn, (!composerLocked && draft.trim()) ? styles.roundBtnSend : [styles.roundBtnGhost, styles.roundBtnOff]]}
                disabled={composerLocked || !draft.trim()}
                onPress={onSend}
                accessibilityLabel="Send"
              >
                <Ionicons name="arrow-up" size={20} color={(!composerLocked && draft.trim()) ? '#0B0B0F' : '#8E9696'} />
              </TouchableOpacity>
            ) : (
              /* b62 voice notes: mic in the composer; recording UI replaces the bar */
              <TouchableOpacity
                style={[styles.roundBtn, styles.roundBtnGhost, composerLocked && styles.roundBtnOff]}
                disabled={composerLocked}
                onPress={onVoiceRecord}
                accessibilityLabel="Record a voice note"
              >
                <Ionicons name="mic-outline" size={21} color="#FFFFFF" />
              </TouchableOpacity>
            )}
          </>
        )}
      </View>
    </View>

      {/* attach confirm — web parity: preview + Cancel/Send before anything is encrypted.
          Rendered as a plain in-screen overlay, NOT React Native's <Modal>. The photo
          picker (ImagePicker.launchImageLibraryAsync) itself presents a native iOS modal
          (PHPickerViewController); opening a SECOND native modal (RN's <Modal>) the instant
          it resolves collides with iOS's dismiss animation and freezes the whole screen
          (build 25 bug — looked like a total hang, no scroll/back). A plain absolutely
          positioned View has no native presentation of its own, so there's nothing to
          collide with. Kept OUTSIDE the KeyboardAvoidingView (build 26 bug: 'padding'
          behavior pads the AvoidingView's own box when the keyboard is up, which pushes
          this absolutely-positioned overlay's bottom edge off-screen behind the keyboard,
          clipping Cancel/Send — being outside means it's always anchored to the real
          screen bounds regardless of keyboard state; handleAttach also dismisses the
          keyboard proactively as a belt-and-suspenders fix). */}
      {pendingPick ? (
        <View style={styles.pickOverlay} pointerEvents="auto">
          <View style={styles.pickSheet}>
            {pendingPick.voiceSeconds ? (
              <>
                <Text style={styles.pickTitle}>Send this voice note?</Text>
                <View style={styles.pickAudioPreview}>
                  <Text style={styles.pickAudioIcon}>🎤</Text>
                  <Text style={styles.pickAudioMeta}>{fmtSecs(pendingPick.voiceSeconds)} · encrypted end-to-end before upload</Text>
                </View>
              </>
            ) : pendingPick.mime.startsWith('video/') ? (
              <>
                <Text style={styles.pickTitle}>Send this video?</Text>
                <View style={styles.pickAudioPreview}>
                  <Text style={styles.pickAudioIcon}>▶</Text>
                  <Text style={styles.pickAudioMeta}>{pendingPick.name || 'video'}</Text>
                </View>
                <Text style={styles.pickMeta}>{(pendingPick.size / 1048576).toFixed(1)} MB · encrypted on this phone before it is uploaded</Text>
                {pendingPick.size > MEDIA_SOFT_WARN_BYTES ? <Text style={styles.pickWarn}>Large file — encrypting and sending may take a few minutes. Keep Vardum open until it sends.</Text> : null}
              </>
            ) : (
              <>
                <Text style={styles.pickTitle}>Send this image?</Text>
                <Image source={{ uri: pendingPick.uri }} style={styles.pickPreview} resizeMode="contain" />
                <Text style={styles.pickMeta}>{pendingPick.name || 'media'}</Text>
                <Text style={styles.pickMeta}>{(pendingPick.size / 1048576).toFixed(1)} MB · encrypted on this phone before it is uploaded</Text>
                {pendingPick.size > MEDIA_SOFT_WARN_BYTES ? <Text style={styles.pickWarn}>Large file — encrypting and sending may take a few minutes. Keep Vardum open until it sends.</Text> : null}
              </>
            )}
            <TouchableOpacity style={styles.dlToggle} onPress={() => onAllowDlChange(!allowDl)} activeOpacity={0.7}>
              <View style={[styles.dlBox, allowDl && styles.dlBoxOn]}>
                {allowDl ? <Text style={styles.dlBoxTxt}>✓</Text> : null}
              </View>
              <Text style={styles.dlToggleTxt}>Allow recipient to save this {pendingPick.voiceSeconds ? 'voice note' : pendingPick.mime.startsWith('video/') ? 'video' : 'image'}</Text>
            </TouchableOpacity>
            {/* audit VAR-42 (1f51): the recipient's own app enforces this — say so */}
            <Text style={styles.pickMeta}>{SAVE_TOGGLE_NOTE}</Text>
            <View style={styles.pickBtns}>
              <TouchableOpacity style={styles.pickCancel} onPress={onCancelPick}>
                <Text style={styles.pickCancelTxt}>Cancel</Text>
              </TouchableOpacity>
              <TouchableOpacity style={styles.pickSend} onPress={onSendMedia} disabled={busy}>
                <Text style={styles.pickSendTxt}>{busy ? 'Sending…' : 'Send'}</Text>
              </TouchableOpacity>
            </View>
          </View>
        </View>
      ) : null}

      {/* lightbox — full-screen media view */}
      {/* (b66) VEIL-styled ✕ sheet — End is a real red destructive button */}
      <SecureOverlay visible={sheet} onRequestClose={() => setSheet(false)}>
        <TouchableOpacity style={styles.sheetBackdrop} activeOpacity={1} onPress={() => setSheet(false)}>
          <TouchableOpacity style={styles.sheetPanel} activeOpacity={1} onPress={() => undefined}>
            {canRename && onRenameThread ? (
              <TouchableOpacity style={styles.sheetRow} onPress={() => { setSheet(false); setRenameInput(threadNickname ?? ''); setRenameOpen(true); }}>
                <Text style={styles.sheetRowTxt}>Rename this thread</Text>
                <Text style={styles.sheetRowSub}>Device-local only — never transmitted, never synced</Text>
              </TouchableOpacity>
            ) : null}
            {canNewThread ? (
              <TouchableOpacity style={styles.sheetRow} onPress={() => { setSheet(false); onNewThread(); }}>
                <Text style={styles.sheetRowTxt}>New chat thread with the same person</Text>
                <Text style={styles.sheetRowSub}>All-new keys — no new invitation needed</Text>
              </TouchableOpacity>
            ) : null}
            {onBlockContact ? (
              <TouchableOpacity style={styles.sheetRowDanger} onPress={() => { setSheet(false); void confirmBlockContact(); }}>
                <Text style={styles.sheetRowDangerTxt}>Block this contact</Text>
                <Text style={styles.sheetRowDangerSub}>Ends this chat and hides them on this phone</Text>
              </TouchableOpacity>
            ) : null}
            <TouchableOpacity style={styles.sheetRowDanger} onPress={() => { setSheet(false); onEndSession(); }}>
              {group ? (
                /* audit VAR-24: the words match what happens (groupDeletePlan in App.tsx) */
                group.isCreator ? (
                  <>
                    <Text style={styles.sheetRowDangerTxt}>Delete this group thread</Text>
                    <Text style={styles.sheetRowDangerSub}>From this phone only — the group goes on for the others</Text>
                  </>
                ) : (
                  <>
                    <Text style={styles.sheetRowDangerTxt}>Leave this group</Text>
                    <Text style={styles.sheetRowDangerSub}>Tells the group you left and deletes the thread from this phone</Text>
                  </>
                )
              ) : (
                <>
                  <Text style={styles.sheetRowDangerTxt}>End this session</Text>
                  <Text style={styles.sheetRowDangerSub}>Ends it on both sides — permanently</Text>
                </>
              )}
            </TouchableOpacity>
            {group && onEndGroupForAll ? (
              <TouchableOpacity style={styles.sheetRowDanger} onPress={async () => {
                setSheet(false);
                const ok = await ask({ title: 'End this group for everyone?', message: 'The group closes on every member’s phone and can’t be reopened. Their copies of earlier messages stay on their phones.', confirm: true, danger: true, submitLabel: 'End for everyone' });
                if (ok) onEndGroupForAll();
              }}>
                <Text style={styles.sheetRowDangerTxt}>End group for everyone</Text>
                <Text style={styles.sheetRowDangerSub}>Closes the group on every member’s phone — permanently</Text>
              </TouchableOpacity>
            ) : null}
            <TouchableOpacity style={styles.sheetRowCancel} onPress={() => setSheet(false)}>
              <Text style={styles.sheetCancelTxt}>Cancel</Text>
            </TouchableOpacity>
          </TouchableOpacity>
        </TouchableOpacity>
      </SecureOverlay>
      {/* b126 verification panel — fingerprint viewable pre AND post verification;
          "Mark verified" only unlocks after an explicit out-of-band comparison
          confirmation. Vardum palette (#15151B card, white primary). */}
      <SecureOverlay visible={!!verifyPanel} onRequestClose={() => setVerifyPanel(null)}>
        <TouchableOpacity style={styles.rnBackdrop} activeOpacity={1} onPress={() => setVerifyPanel(null)}>
          <TouchableOpacity style={styles.rnCard} activeOpacity={1} onPress={() => undefined}>
            {verifyPanel === 'ceremony' ? (
              <>
                <Text style={styles.rnTitle}>Verify this session</Text>
                <Text style={styles.fpBox} selectable>
                  {sessionFingerprint ?? (unrecoverable ? 'There is no safety code: this phone no longer has the keys for this chat. End it and start a new one.' : 'No safety code yet. It appears here once the other phone has opened Vardum and joined this chat. Keep Vardum open on both phones and wait a few seconds; starting another new chat resets this.')}
                </Text>
                <Text style={styles.rnBody}>Compare it with your peer out-of-band — read it to them on a call, or side by side in person. Only continue if every group of characters matches exactly.</Text>
                {!group && !contact ? <Text style={styles.rnBody}>{UNPINNED_KEYS_NOTE /* b77u (audit 6 U-M15) */}</Text> : null}
                <TouchableOpacity
                  style={[styles.fpStepBtn, compareArmed && styles.fpStepBtnOn]}
                  onPress={() => setCompareArmed(true)}
                  disabled={compareArmed || !sessionFingerprint} // Batch G (NF-1)
                >
                  <Text style={[styles.fpStepBtnTxt, compareArmed && styles.fpStepBtnTxtOn]}>
                    {compareArmed ? '✓ Compared — they match' : 'I compared them — they match'}
                  </Text>
                </TouchableOpacity>
                {verifyPanel === 'ceremony' && verifyFail ? (
                  <Text style={styles.fpFailTxt}>Verification failed to save — tap to retry.</Text>
                ) : null}
                <View style={styles.rnActions}>
                  <TouchableOpacity style={styles.rnBtnGhost} onPress={() => setVerifyPanel(null)}>
                    <Text style={styles.rnBtnGhostTxt}>Cancel</Text>
                  </TouchableOpacity>
                  <TouchableOpacity
                    style={[styles.rnBtnTeal, (!compareArmed || !sessionFingerprint) && styles.fpBtnDisabled]}
                    disabled={!compareArmed || !sessionFingerprint}
                    onPress={() => {
                      setVerifyFail(false);
                      void onVerifySession(sessionFingerprint ?? '').then((ok) => { if (!ok) setVerifyFail(true); else setVerifyPanel(null); });
                    }}
                  >
                    <Text style={styles.rnBtnTealTxt}>{verifyFail ? 'Retry' : 'Mark verified'}</Text>
                  </TouchableOpacity>
                </View>
              </>
            ) : verifyPanel === 'view' ? (
              <>
                <Text style={styles.rnTitle}>Session fingerprint</Text>
                <Text style={styles.fpBox} selectable>
                  {sessionFingerprint ?? '(fingerprint unavailable on this device)'}
                </Text>
                <Text style={styles.fpStatus}>
                  {/* b77t (audit 5 M-F): one-sided; this phone can't know whether the other person has checked */}
                  {CONFIRMED_PANEL_TEXT}
                </Text>
                {peerVeilId ? (
                  peerPinned ? (
                    <Text style={styles.fpPinned}>✓ Pinned in contacts</Text>
                  ) : (
                    <TouchableOpacity style={styles.rnBtnTeal} onPress={() => onPinContact?.()}>
                      <Text style={styles.rnBtnTealTxt}>Pin as contact</Text>
                    </TouchableOpacity>
                  )
                ) : null}
                <View style={styles.rnActions}>
                  <TouchableOpacity style={styles.rnBtnGhost} onPress={() => setVerifyPanel(null)}>
                    <Text style={styles.rnBtnGhostTxt}>Close</Text>
                  </TouchableOpacity>
                </View>
              </>
            ) : null}
          </TouchableOpacity>
        </TouchableOpacity>
      </SecureOverlay>
      {/* b123: rename modal — same VEIL modal pattern as the Contacts nickname */}
      <SecureOverlay visible={renameOpen} onRequestClose={() => setRenameOpen(false)}>
        <TouchableOpacity style={styles.rnBackdrop} activeOpacity={1} onPress={() => setRenameOpen(false)}>
          <TouchableOpacity style={styles.rnCard} activeOpacity={1} onPress={() => undefined}>
            <Text style={styles.rnTitle}>Rename this thread</Text>
            <Text style={styles.rnBody}>Stored on this device only. Never transmitted, never synced, never on the server.</Text>
            <TextInput
              style={styles.rnInput}
              placeholder="e.g. Book club"
              placeholderTextColor="#5E6464"
              value={renameInput}
              onChangeText={setRenameInput}
              maxLength={40}
            />
            <View style={styles.rnActions}>
              <TouchableOpacity style={styles.rnBtnGhost} onPress={() => setRenameOpen(false)}>
                <Text style={styles.rnBtnGhostTxt}>Cancel</Text>
              </TouchableOpacity>
              <TouchableOpacity
                style={styles.rnBtnTeal}
                onPress={() => { setRenameOpen(false); onRenameThread?.(renameInput.trim()); }}
              >
                <Text style={styles.rnBtnTealTxt}>Save</Text>
              </TouchableOpacity>
            </View>
          </TouchableOpacity>
        </TouchableOpacity>
      </SecureOverlay>
      <SecureOverlay visible={!!videoFS} transparent={false} onRequestClose={() => setVideoFS(null)}>
        {videoFS ? (
          <View style={styles.videoFSBg}>
            <Video
              source={{ uri: videoFS.src }}
              style={styles.videoFSPlayer}
              useNativeControls
              shouldPlay
              resizeMode={ResizeMode.CONTAIN}
              onError={() => setVideoFS(null)}
            />
            <TouchableOpacity style={styles.videoFSClose} onPress={() => setVideoFS(null)}>
              <Text style={styles.videoFSCloseTxt}>✕</Text>
            </TouchableOpacity>
            <Text style={styles.videoFSHint}>{videoFS.name} — decrypted on this phone</Text>
          </View>
        ) : null}
      </SecureOverlay>
      <SecureOverlay visible={!!lightbox} onRequestClose={() => setLightbox(null)}>
        <TouchableOpacity style={styles.lightbox} activeOpacity={1} onPress={() => setLightbox(null)}>
          {lightbox ? <Image source={{ uri: lightbox.src }} style={styles.lightboxImg} resizeMode="contain" /> : null}
          <Text style={styles.lightboxHint} numberOfLines={1}>{mediaDisplayName(lightbox?.name)} — tap anywhere to close</Text>{/* b77q (audit 3 AQ-2) */}
        </TouchableOpacity>
      </SecureOverlay>
      {chooserNode}
      {promptNode}
    </View>
  );
}

const styles = StyleSheet.create({
  reqCard: { marginHorizontal: 12, marginBottom: 8, padding: 14, borderRadius: 12, borderWidth: 1, borderColor: '#3A3A44', backgroundColor: '#15151B' },
  reqTitle: { color: '#FFFFFF', fontSize: 15, fontWeight: '700', marginBottom: 6 },
  reqTxt: { color: '#C9CFCE', fontSize: 13, lineHeight: 18, marginBottom: 12 },
  reqRow: { flexDirection: 'row', justifyContent: 'flex-end' },
  reqDecline: { paddingVertical: 10, paddingHorizontal: 18, borderRadius: 10, borderWidth: 1, borderColor: '#24242D', marginRight: 10 },
  reqDeclineTxt: { color: '#C9CFCE', fontSize: 14, fontWeight: '600' },
  reqAccept: { paddingVertical: 10, paddingHorizontal: 22, borderRadius: 10, backgroundColor: '#FFFFFF' },
  reqAcceptTxt: { color: '#0B0B0F', fontSize: 14, fontWeight: '800' },
  fpFailTxt: { color: '#e8896b', fontSize: 13, lineHeight: 18, marginBottom: 10 },
  fill: { flex: 1, backgroundColor: '#0B0B0F' },
  header: { flexDirection: 'row', alignItems: 'center', paddingHorizontal: 8, paddingBottom: 10, paddingTop: 48, borderBottomWidth: 1, borderBottomColor: '#24242D', backgroundColor: '#0B0B0F' },
  backBtn: { paddingVertical: 4, paddingRight: 2 },
  hAvatar: { width: 36, height: 36, borderRadius: 18, backgroundColor: '#24242D', alignItems: 'center', justifyContent: 'center', marginLeft: 2 },
  hAvatarGroup: { borderRadius: 11, backgroundColor: '#24242D' },
  hAvatarTxt: { color: '#FFFFFF', fontSize: 13, fontWeight: '700' },
  callBtn: { paddingVertical: 6, paddingHorizontal: 8 },
  callGlyph: { color: '#FFFFFF', fontSize: 20, lineHeight: 24 },
  // b62 groups
  senderLbl: { color: '#FFFFFF', fontSize: 11, marginBottom: 2 },
  creatorBadge: { color: '#FFD479', fontSize: 9, fontWeight: '700', letterSpacing: 0.5 }, // b75 (audit GR-4)
  groupOverlay: { ...StyleSheet.absoluteFillObject, backgroundColor: 'rgba(11,11,15,0.86)', justifyContent: 'center', padding: 18, zIndex: 40 },
  groupPanel: { backgroundColor: '#0B0B0F', borderColor: '#24242D', borderWidth: 1, borderRadius: 14, padding: 16, maxHeight: '72%' },
  groupPanelHead: { flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 },
  groupPanelTitle: { color: '#FFFFFF', fontSize: 16, fontWeight: '700' },
  groupCloseTxt: { color: '#8E9696', fontSize: 18, paddingHorizontal: 6 },
  groupFp: { color: '#8a6d3b', fontSize: 11, marginBottom: 10 },
  groupMemberList: { flexGrow: 0 },
  groupEmpty: { color: '#8E9696', fontSize: 13, paddingVertical: 8 },
  groupMemberRow: { flexDirection: 'row', alignItems: 'center', paddingVertical: 8, borderBottomWidth: StyleSheet.hairlineWidth, borderBottomColor: '#24242D' },
  groupMemberName: { color: '#FFFFFF', fontSize: 13 },
  groupMemberMeta: { color: '#8E9696', fontSize: 11, marginTop: 1 },
  evictBtn: { borderColor: '#7c3a3a', borderWidth: 1, borderRadius: 8, paddingHorizontal: 10, paddingVertical: 5 },
  evictBtnArmed: { backgroundColor: '#7c3a3a' },
  evictBtnTxt: { color: '#f0b8b8', fontSize: 11 },
  rotateBtn: { backgroundColor: '#24242D', borderColor: '#3A3A44', borderWidth: 1, borderRadius: 10, paddingVertical: 10, alignItems: 'center', marginTop: 12 },
  rotateBtnTxt: { color: '#FFFFFF', fontSize: 13, fontWeight: '600' },
  groupErr: { color: '#f0b8b8', fontSize: 12, marginTop: 8 },
  backTxt: { color: '#FFFFFF', fontSize: 14 },
  headerMid: { flex: 1, minWidth: 0, marginHorizontal: 10 },
  title: { color: '#FFFFFF', fontSize: 16, fontWeight: '700' },
  subtitle: { color: '#8E9696', fontSize: 12, marginTop: 2 },
  vBadge: { alignSelf: 'flex-start', marginTop: 3, borderWidth: 1, borderColor: 'transparent', borderRadius: 999, paddingHorizontal: 7, paddingVertical: 1 },
  vBadgeTxtGroup: { color: '#FFFFFF', fontSize: 12, fontWeight: '600' },
  vBadgeOk: { borderColor: '#3A3A44', backgroundColor: 'rgba(255,255,255,0.10)' },
  vBadgeHalf: { borderColor: '#5c4526', backgroundColor: 'rgba(214,154,92,0.10)' },
  vBadgeNone: { borderColor: '#3A3A44', backgroundColor: 'transparent' },
  vBadgeTxt: { fontSize: 11, fontWeight: '600' },
  vBadgeTxtOk: { color: '#20D9C2' }, // b199 (owner, Oct 17): the logo's teal "V"
  vBadgeTxtHalf: { color: '#d69a5c' },
  vBadgeTxtNone: { color: '#8E9696' },
  newThreadBtn: { borderWidth: 1, borderColor: '#3A3A44', borderRadius: 8, paddingHorizontal: 10, height: 34, minWidth: 56, alignItems: 'center', justifyContent: 'center' },
  newThreadTxt: { color: '#FFFFFF', fontSize: 13, fontWeight: '600' },
  menuBtn: { paddingHorizontal: 8, paddingVertical: 6 },
  menuTxt: { color: '#8E9696', fontSize: 22, fontWeight: '700' },
  // (b66) ✕ sheet
  sheetBackdrop: { flex: 1, backgroundColor: 'rgba(11,11,15,0.8)', justifyContent: 'flex-end' },
  sheetPanel: { backgroundColor: '#15151B', borderTopLeftRadius: 18, borderTopRightRadius: 18, borderWidth: 1, borderColor: '#24242D', paddingHorizontal: 14, paddingBottom: 34, paddingTop: 6 },
  sheetRow: { paddingVertical: 16, borderBottomWidth: 1, borderBottomColor: '#24242D' },
  sheetRowTxt: { color: '#FFFFFF', fontSize: 15, fontWeight: '700', textAlign: 'center' },
  sheetRowSub: { color: '#8E9696', fontSize: 12, marginTop: 3, textAlign: 'center' },
  sheetRowDanger: { paddingVertical: 16, borderBottomWidth: 1, borderBottomColor: '#24242D' },
  sheetRowDangerTxt: { color: '#ff5a4e', fontSize: 15, fontWeight: '800', textAlign: 'center' },
  sheetRowDangerSub: { color: '#8a5450', fontSize: 12, marginTop: 3, textAlign: 'center' },
  sheetRowCancel: { paddingVertical: 16 },
  // b123: read-receipt tick appended to my read bubbles' timestamps
  // Vardum: inherits the timestamp colour so it reads on the white sent bubble and on dark media bubbles
  readTick: { fontWeight: '700' },
  queuedTick: { fontStyle: 'italic' },
  // b123: rename-thread modal (Vardum palette: #15151B card, white primary)
  rnBackdrop: { flex: 1, backgroundColor: 'rgba(11,11,15,0.8)', justifyContent: 'center', alignItems: 'center', padding: 28 },
  rnCard: { width: '100%', backgroundColor: '#15151B', borderRadius: 16, borderWidth: 1, borderColor: '#24242D', padding: 18 },
  rnTitle: { color: '#FFFFFF', fontSize: 17, fontWeight: '800', textAlign: 'center' },
  rnBody: { color: '#8E9696', fontSize: 12, textAlign: 'center', marginTop: 6, marginBottom: 14 },
  rnInput: { backgroundColor: '#15151B', borderWidth: 1, borderColor: '#3A3A44', borderRadius: 10, color: '#FFFFFF', paddingHorizontal: 12, paddingVertical: 10, fontSize: 15 },
  rnActions: { flexDirection: 'row', marginTop: 14 },
  rnBtnGhost: { flex: 1, alignItems: 'center', paddingVertical: 12, borderRadius: 10, borderWidth: 1, borderColor: '#24242D', marginRight: 8 },
  rnBtnGhostTxt: { color: '#8E9696', fontSize: 14, fontWeight: '700' },
  rnBtnTeal: { flex: 1, alignItems: 'center', paddingVertical: 12, borderRadius: 10, backgroundColor: '#FFFFFF' },
  rnBtnTealTxt: { color: '#0B0B0F', fontSize: 14, fontWeight: '800' },
  sheetCancelTxt: { color: '#8E9696', fontSize: 15, fontWeight: '700', textAlign: 'center' },
  endBtn: { padding: 6 },
  endTxt: { color: '#8a4b55', fontSize: 13 },
  error: { color: '#d98b8b', fontSize: 12, paddingHorizontal: 16, paddingTop: 8 },
  notice: { color: '#e0a458', fontSize: 12, paddingHorizontal: 16, paddingTop: 4 },
  list: { flex: 1, paddingHorizontal: 12 },
  bubbleRow: { flexDirection: 'row', marginVertical: 3 },
  // b199 reactions: bar above, bubble, badge below, all on the bubble's side
  bubbleCol: { maxWidth: '78%' },
  bubbleColMine: { alignItems: 'flex-end' },
  bubbleColPeer: { alignItems: 'flex-start' },
  bubbleInCol: { maxWidth: '100%' },
  reactBar: { flexDirection: 'row', backgroundColor: '#15151B', borderWidth: 1, borderColor: '#24242D', borderRadius: 22, paddingHorizontal: 4, paddingVertical: 3, marginBottom: 4 },
  reactBarMine: { alignSelf: 'flex-end' },
  reactBarPeer: { alignSelf: 'flex-start' },
  reactBtn: { width: 38, height: 38, borderRadius: 19, alignItems: 'center', justifyContent: 'center' },
  reactBtnOn: { backgroundColor: '#3A3A44' },
  reactEmoji: { fontSize: 22 },
  reactBadge: { marginTop: -6, backgroundColor: '#15151B', borderWidth: 1, borderColor: '#24242D', borderRadius: 12, paddingHorizontal: 6, paddingVertical: 1 },
  reactBadgeMine: { marginRight: 6 },
  reactBadgePeer: { marginLeft: 6 },
  reactBadgeTxt: { fontSize: 14 },
  mineRow: { justifyContent: 'flex-end' },
  peerRow: { justifyContent: 'flex-start' },
  // b199 group invitation card
  inviteCard: { maxWidth: '86%', borderWidth: 1, borderColor: '#3A3A44', backgroundColor: '#15151B', borderRadius: 14, padding: 14 },
  inviteKicker: { color: '#FFFFFF', fontSize: 10, fontWeight: '800', letterSpacing: 0.8, textTransform: 'uppercase' },
  inviteName: { color: '#FFFFFF', fontSize: 17, fontWeight: '700', marginTop: 4 },
  inviteSub: { color: '#8E9696', fontSize: 12, lineHeight: 17, marginTop: 6 },
  inviteDone: { color: '#FFFFFF', fontSize: 13, fontWeight: '600', marginTop: 8 },
  inviteErr: { color: '#e8836f', fontSize: 12, marginTop: 6 },
  inviteActions: { flexDirection: 'row', gap: 8, marginTop: 12 },
  inviteJoin: { backgroundColor: '#FFFFFF', borderRadius: 10, paddingVertical: 9, paddingHorizontal: 22 },
  inviteJoinTxt: { color: '#0B0B0F', fontWeight: '800', fontSize: 14 },
  inviteDecline: { borderWidth: 1, borderColor: '#24242D', borderRadius: 10, paddingVertical: 9, paddingHorizontal: 16 },
  inviteDeclineTxt: { color: '#8E9696', fontWeight: '600', fontSize: 14 },
  claimRow: { paddingHorizontal: 12, paddingTop: 8, alignItems: 'center' }, // b71 (audit F-07): join request card
  bubble: { maxWidth: '78%', borderRadius: 16, paddingHorizontal: 12, paddingVertical: 8 },
  // Vardum: media bubbles stay dark (white sent bubble would hide the white audio/play controls)
  mediaBubble: { padding: 6, backgroundColor: '#24242D' },
  mineBubble: { backgroundColor: '#FFFFFF' },
  peerBubble: { backgroundColor: '#15151B' },
  mineText: { color: '#0B0B0F', fontSize: 14 },
  peerText: { color: '#FFFFFF', fontSize: 14 },
  mineTs: { color: '#5E6464', fontSize: 9, marginTop: 3, textAlign: 'right' },
  mineTsOnDark: { color: '#8E9696' },
  peerTs: { color: '#5E6464', fontSize: 9, marginTop: 3 },
  mediaImg: { width: 220, height: 220, borderRadius: 12, backgroundColor: '#0B0B0F' },
  mediaStub: { width: 220, height: 120, borderRadius: 12, backgroundColor: '#0B0B0F', alignItems: 'center', justifyContent: 'center' },
  mediaStubTxt: { color: '#5E6464', fontSize: 12, marginTop: 8 },
  mediaErrTxt: { color: '#d98b8b', fontSize: 12 },
  mediaCaption: { color: '#8E9696', fontSize: 10, marginTop: 4, maxWidth: 220 },
  micBtnRec: { backgroundColor: 'rgba(214,160,84,0.15)', borderWidth: 1, borderColor: '#8a6d3b', borderRadius: 8, paddingHorizontal: 10, paddingVertical: 9, marginLeft: 4 },
  micBtnTxt: { color: '#d6a054', fontSize: 12, fontWeight: '600' },
  audioRow: { flexDirection: 'row', alignItems: 'center', paddingVertical: 2 },
  audioBtn: { width: 34, height: 34, borderRadius: 17, backgroundColor: 'rgba(255,255,255,0.12)', borderWidth: 1, borderColor: '#3A3A44', alignItems: 'center', justifyContent: 'center' },
  audioBtnTxt: { color: '#FFFFFF', fontSize: 14 },
  audioLbl: { color: '#C9CFCE', fontSize: 12, marginLeft: 8 },
  videoBox: { width: 220, height: 120, borderRadius: 8, backgroundColor: '#15151B', borderWidth: 1, borderColor: '#24242D', alignItems: 'center', justifyContent: 'center' },
  videoIcon: { color: '#FFFFFF', fontSize: 22 },
  videoLbl: { color: '#8E9696', fontSize: 10, marginTop: 4 },
  pickAudioPreview: { alignItems: 'center', paddingVertical: 14 },
  pickAudioIcon: { fontSize: 34 },
  pickAudioMeta: { color: '#C9CFCE', fontSize: 12, marginTop: 6 },
  empty: { padding: 40, alignItems: 'center' },
  captureNotice: {
    color: '#d6a054', textAlign: 'center', fontSize: 11, lineHeight: 15,
    paddingHorizontal: 24, paddingVertical: 6, marginVertical: 4,
  },
  emptyTxt: { color: '#4A4A54', fontSize: 13, textAlign: 'center', lineHeight: 20 },
  vCard: { marginHorizontal: 12, marginTop: 8, borderRadius: 12, borderWidth: 1, borderColor: '#3A3A44', backgroundColor: '#15151B' },
  vCardBody: { padding: 14 },
  vCardTitle: { color: '#FFFFFF', fontSize: 13, fontWeight: '700', marginBottom: 4 },
  vCardTxt: { color: '#8E9696', fontSize: 12, lineHeight: 17 },
  vCardRow: { flexDirection: 'row', alignItems: 'center', marginTop: 10 },
  vCardBtn: { borderRadius: 8, backgroundColor: '#FFFFFF', paddingHorizontal: 12, paddingVertical: 8 },
  vCardBtnTxt: { color: '#0B0B0F', fontSize: 12, fontWeight: '700' },
  vCardSkip: { marginLeft: 10, padding: 6 },
  vCardSkipTxt: { color: '#5E6464', fontSize: 12 },
  // b126 verification panel
  fpBox: { backgroundColor: '#15151B', borderWidth: 1, borderColor: '#3A3A44', borderRadius: 10, paddingHorizontal: 12, paddingVertical: 12, color: '#FFFFFF', fontSize: 13, lineHeight: 19, marginTop: 12 },
  fpStepBtn: { alignItems: 'center', paddingVertical: 11, borderRadius: 10, borderWidth: 1, borderColor: '#24242D', marginTop: 12 },
  fpStepBtnOn: { borderColor: '#FFFFFF', backgroundColor: 'rgba(255,255,255,0.08)' },
  fpStepBtnTxt: { color: '#8E9696', fontSize: 13, fontWeight: '700' },
  fpStepBtnTxtOn: { color: '#FFFFFF' },
  fpBtnDisabled: { opacity: 0.35 },
  fpStatus: { color: '#8E9696', fontSize: 12, textAlign: 'center', marginTop: 12, lineHeight: 17 },
  fpPinned: { color: '#FFFFFF', fontSize: 13, fontWeight: '700', textAlign: 'center', marginTop: 12 },
  composer: { flexDirection: 'row', flexWrap: 'wrap', alignItems: 'flex-end', paddingHorizontal: 10, paddingTop: 10, paddingBottom: 12, borderTopWidth: 1, borderTopColor: '#24242D', backgroundColor: '#0B0B0F', gap: 8 },
  input: { flex: 1, minWidth: 120, minHeight: 40, maxHeight: 120, borderRadius: 20, borderWidth: 1, borderColor: '#24242D', color: '#FFFFFF', paddingHorizontal: 15, paddingTop: 10, paddingBottom: 10, fontSize: 15, backgroundColor: '#15151B' },
  roundBtn: { width: 40, height: 40, borderRadius: 20, alignItems: 'center', justifyContent: 'center' },
  roundBtnGhost: { backgroundColor: '#15151B', borderWidth: 1, borderColor: '#24242D' },
  roundBtnSend: { backgroundColor: '#FFFFFF' },
  roundBtnOff: { opacity: 0.4 },
  recBar: { flex: 1, minHeight: 40, flexDirection: 'row', alignItems: 'center', borderRadius: 20, borderWidth: 1, borderColor: '#5c4526', backgroundColor: 'rgba(214,154,92,0.10)', paddingHorizontal: 15 },
  recDot: { width: 9, height: 9, borderRadius: 5, backgroundColor: '#e8836f', marginRight: 8 },
  recTxt: { color: '#d69a5c', fontSize: 14, fontWeight: '600' },
  inputLocked: { opacity: 0.5 },
  // b163: composer-level ceremony-gate notice (web P1.2 parity)
  verifyNotice: { flexBasis: '100%', width: '100%', flexDirection: 'row', alignItems: 'center', gap: 8, marginBottom: 2, paddingLeft: 6, paddingRight: 2 },
  verifyNoticeTxt: { flex: 1, color: '#d69a5c', fontSize: 12, lineHeight: 16 },
  verifyNowBtn: { borderColor: '#FFFFFF', borderWidth: 1, borderRadius: 8, paddingHorizontal: 10, paddingVertical: 6 },
  verifyNowBtnTxt: { color: '#FFFFFF', fontSize: 12, fontWeight: '700' },
  attachBtn: { marginLeft: 8, height: 42, width: 42, borderRadius: 21, alignItems: 'center', justifyContent: 'center' },
  attachBtnOn: { backgroundColor: '#15151B' },
  attachBtnOff: { backgroundColor: '#0B0B0F', opacity: 0.5 },
  attachTxt: { fontSize: 20, color: '#FFFFFF' },
  attachTxtOff: { color: '#5E6464' },
  sendBtn: { marginLeft: 8, borderRadius: 20, paddingHorizontal: 18, paddingVertical: 12 },
  sendBtnOn: { backgroundColor: '#FFFFFF' },
  sendBtnOff: { backgroundColor: '#15151B' },
  sendTxt: { fontSize: 13, fontWeight: '700', color: '#5E6464' },
  sendTxtOn: { color: '#0B0B0F' },
  pickOverlay: { position: 'absolute', top: 0, left: 0, right: 0, bottom: 0, backgroundColor: 'rgba(11,11,15,0.75)', alignItems: 'center', justifyContent: 'center', padding: 16, zIndex: 50, elevation: 50 },
  pickSheet: { width: '100%', maxWidth: 340, borderRadius: 20, backgroundColor: '#15151B', borderWidth: 1, borderColor: '#24242D', padding: 18, alignItems: 'center' },
  pickTitle: { color: '#FFFFFF', fontSize: 15, fontWeight: '700', marginBottom: 12 },
  pickPreview: { width: '100%', height: 240, borderRadius: 12, backgroundColor: '#0B0B0F' },
  pickMeta: { color: '#8E9696', fontSize: 11, marginTop: 8 },
  pickBtns: { flexDirection: 'row', marginTop: 16 },
  dlToggle: { flexDirection: 'row', alignItems: 'center', marginTop: 14, alignSelf: 'flex-start' },
  dlBox: { width: 18, height: 18, borderRadius: 5, borderWidth: 1.5, borderColor: '#3A3A44', marginRight: 8, alignItems: 'center', justifyContent: 'center' },
  dlBoxOn: { backgroundColor: '#24242D', borderColor: '#FFFFFF' },
  dlBoxTxt: { color: '#FFFFFF', fontSize: 12, fontWeight: '700' },
  dlToggleTxt: { color: '#8E9696', fontSize: 12 },
  saveBtn: { marginTop: 6, alignSelf: 'flex-end', paddingVertical: 4, paddingHorizontal: 10, borderRadius: 8, backgroundColor: '#15151B', borderWidth: 1, borderColor: '#24242D' },
  saveBtnTxt: { color: '#FFFFFF', fontSize: 11 },
  pickCancel: { flex: 1, borderRadius: 14, backgroundColor: '#15151B', paddingVertical: 12, alignItems: 'center', marginRight: 8 },
  pickCancelTxt: { color: '#8E9696', fontSize: 14, fontWeight: '600' },
  pickSend: { flex: 1, borderRadius: 14, backgroundColor: '#FFFFFF', paddingVertical: 12, alignItems: 'center' },
  pickSendTxt: { color: '#0B0B0F', fontSize: 14, fontWeight: '700' },
  lightbox: { flex: 1, backgroundColor: 'rgba(11,11,15,0.94)', alignItems: 'center', justifyContent: 'center', padding: 16 },
  lightboxImg: { width: '100%', height: '82%' },
  lightboxHint: { color: '#8E9696', fontSize: 11, marginTop: 14 },
  // b140: soft large-file warning in the pick preview (send still allowed)
  pickWarn: { color: '#e8a33d', fontSize: 11, marginTop: 6, marginHorizontal: 18, textAlign: 'center' },
  // b140: full-screen video player
  videoFSBg: { flex: 1, backgroundColor: '#0B0B0F' },
  videoFSPlayer: { flex: 1 },
  videoFSClose: { position: 'absolute', top: 54, right: 20, width: 40, height: 40, borderRadius: 20, backgroundColor: 'rgba(11,11,15,0.55)', alignItems: 'center', justifyContent: 'center' },
  videoFSCloseTxt: { color: '#FFFFFF', fontSize: 20, lineHeight: 22 },
  videoFSHint: { color: '#8E9696', fontSize: 11, textAlign: 'center', paddingVertical: 10 },
});
