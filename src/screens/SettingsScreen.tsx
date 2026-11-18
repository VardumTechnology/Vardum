/**
 * Native Settings — NATIVE-PARITY-HANDOFF §2 exact structure:
 * Device protection / Messages / Private storage / Emergency access /
 * Security details / Support / Device transfer / Identity / Appearance /
 * Own VEIL / Account / About / Delete account. (Founder operations — Mission
 * Control — is admin-only and intentionally absent: for everyone else this
 * route is indistinguishable from a page that does not exist.)
 * One mode. Nothing pre-set — every control explained and yours to set.
 */
import React, { useCallback, useState } from 'react';
import Constants from 'expo-constants';
import { View, Text, TextInput, TouchableOpacity, ScrollView, StyleSheet, Alert, Linking, ActivityIndicator, Image } from 'react-native';
import { useThemedPrompt } from './ThemedPrompt';
import { PASSWORD_MIN, PASSWORD_MAX, passwordProblem, SOFT_LOCK_NOTE, WIPE_AFTER_FAILS_SETUP, DECOY_LOCKOUT_NOTE /* b77s (audit 4 DV-1) */, DECOY_SETUP_NOTE /* b77t (M-E) */, EMAIL_PASSWORD_MIN, EMAIL_PASSWORD_MAX, emailPasswordProblem /* b77s (owner) */ } from '../password';
import { lockHardwareKeyAvailable } from '../../vendor/device/src/applock';
import { copySensitive, sensitiveCopySupported, clearPhraseFromClipboard } from '../clipboard-guard';
import { PRIVATE_KEYBOARD_NOTE } from '../secret-entry'; // b77m (audit VAR-14)
import { distributorLabel } from '../unifiedpush'; // b77m (audit VAR-17)
/** b77n2 (review INFO): the push service can't verify its silent flag (Keystore trouble) and fails silent */
/** b77p round 2 (owner decisions 1 and 2, 31 Oct): what the "Notifications" row says. Only chats wake the phone (no
 *  contact-request or group pushes any more); a call rings, with the same text. */
export const NOTIFICATIONS_EXPLAIN = 'Vardum only ever shows one constant alert, "Vardum / Notification": never message content, senders or badges. New messages in your chats wake your phone with it. A call rings with the call sound, still showing only "Vardum / Notification" (Apple, Google or Expo can tell a ringing call from a message, as they always could from its repeated alerts). Contact requests and group messages don’t alert you on their own: they appear when you next open Vardum or a chat message wakes it.';
export const PUSH_ALERTS_HIDDEN_NOTE = 'Alerts are hidden: this phone’s secure key store refused Vardum’s key, so new-message alerts can’t show. Restarting the phone may help.';
import { QrCode } from './VeilQr';
import { QrScanner } from './QrScanner';
import { qrMatrix } from '../qr';
import { parseMoveCode } from '../../vendor/device/src/transfer';
import { groupNameProblem } from '../../vendor/device/src/names';
import { useThemedShare } from './ThemedSheets';
import {
  type VeilSettings, BURN_OPTIONS, EXPIRY_OPTIONS, QUIET_OPTIONS,
  SELF_DESTRUCT_HOURS, SELF_DESTRUCT_WARN_HOURS, SELF_DESTRUCT_DAYS, selfDestructLeftLabel,
} from '../../vendor/device/src/settings';
import { isSilentAccountEmail } from '../../vendor/device/src/silent-auth';
import { regLockPinProblem, regLockNotOwnerText, REGLOCK_PIN_MAX, REGLOCK_LAPSE_DAYS, type RegLockStatus } from '../../vendor/device/src/reglock';
import { SECURE_CHIP, BIOMETRIC, BIOMETRIC_SHORT, BETA_SOURCE, IS_ANDROID, SCREEN_PROTECTION_INFO } from '../platformText';
import { VEIL_RELAY_IS_STAGING } from '../veil-app';
import { PROTOCOL_WIRE_TAG } from '../about-tags'; // b77k (IP77-1)
import { SELF_DESTRUCT_CLOCK_NOTE, selfDestructArmNow } from '../relay-clock'; // b77t (audit 5 L-4); b77t2 (info)

/** b75 (audit XF-1): the old phone's side of a move, after it read the new phone's code */
export interface MoveOffer {
  /** the 6-digit check code; the new phone must show the same */
  sas: string;
  sessionCount: number;
  groupsKept: number;
  /** the user said the codes match: send */
  confirm: () => Promise<void>;
  /** the user backed out, or the codes differ: nothing is sent */
  cancel: () => Promise<void>;
}
/** b75 (audit XF-1): the new phone's side of a move */
export interface ReceiveFlow {
  /** the move code to show (QR or text): public keys only */
  code: string;
  /** resolves with the check code once the old phone answered */
  offer: () => Promise<{ sas: string }>;
  /** resolves once the chats are imported */
  finish: () => Promise<{ importedCount: number; skippedExisting: number; incomplete?: boolean; ackHeld?: string; conflicts?: number }>;
  cancel: () => Promise<void>;
}

/** b76 (registration lock): what it does, in the app's words (spec §12.17, §8.2) */
export const REGLOCK_EXPLAIN = 'With the registration lock on, restoring this account with your 24 words on another phone also needs a PIN you choose now. It helps if someone gets your 24 words while this phone is still yours. This phone doesn’t need the PIN while it holds the lock. If the PIN is entered on another phone, that phone holds the lock instead, and Settings here says so.\n\n'
  + `If you lose this phone and forget the PIN, the lock lapses once none of your phones has been online for ${REGLOCK_LAPSE_DAYS} days, and your 24 words alone work again. Moving to a new phone? It asks for the PIN when you restore your 24 words on it.\n\n`
  + 'Vardum’s server checks the PIN and limits wrong tries (10 in all). It never receives the PIN itself, but someone who has your 24 words and a copy of the server’s data could test guesses at it, so choose more than a short number.';

/** b75 (audit XF-1): shown from "Last move" and the "Moved" alert.
 *  b75r1 (audit PX-01): only a phone holding the identity key can collect a move now, so
 *  "not me" means someone else knows the 24 words or has a copy of the keys. */
export function moveNotMeText(sas?: string): string {
  return `The chats this phone moved were collected by ${sas ? `the phone that showed code ${sas}` : 'another phone'}. Only a phone holding your Vardum ID\u2019s keys (restored from your 24 words) can collect a move. If that wasn\u2019t your new phone, someone else has your 24 words or a copy of your keys: they can read and send in those chats, and act as you.\n\nWarn your contacts another way. To start fresh, choose Settings \u2192 Generate new Vardum ID: you get new 24 words, and your contacts need to add your new ID.`;
}

export interface SettingsScreenProps {
  /** audit VAR-17: Android — the UnifiedPush distributors installed and the one chosen (none: not shown) */
  pushService?: { installed: string[]; chosen: string | null; alertsHidden?: boolean } | null;
  /** audit VAR-17: the user chose a distributor */
  onChoosePushService?: (pkg: string) => Promise<void>;
  /** b199: open the full-screen VEIL QR */
  onShowQr?: () => void;
  settings: VeilSettings;
  onChange: (s: VeilSettings) => void;
  veilId: string | null;
  email?: string | null;
  /** open the privacy checkup wizard (web parity: /checkup from Settings) */
  onRunCheckup: () => void;
  /** app lock (passcode + Decoy + Duress) configured on this device */
  appLockEnabled: boolean;
  /** b70 (VAR-01/VAR-17): `current` is the real password when a lock is already set */
  onSetAppLock: (current: string | null, pass: string, decoy?: string | null, duress?: string | null) => Promise<void>;
  onRemoveAppLock: (pass: string) => Promise<boolean>;
  /** b70 (VAR-01/02/17): check the app-lock password before an account or key
   *  action. 'wiped' = it was the duress code and the phone has been erased. */
  onCheckPassword?: (code: string) => Promise<'ok' | 'wrong' | 'wiped'>;
  /** Account category */
  onSignOut: () => void;
  onLockNow: () => void;
  /** b77t2 (decoy gaps): a decoy session — Nothing at rest (key storage), self-destruct and erase-after-10 act on
   *  the whole phone, so they are shown at a fresh install's values and can't be changed here (src/decoy-settings.ts) */
  lockOptionsFixed?: boolean;
  onWipeDevice: () => Promise<void>;
  onDeleteAccount: () => Promise<void>;
  onViewIntro: () => void;
  onOpenTools: () => void;
  /** b141: re-open the Getting Started screen (carry-over after "Don't show
   * again") */
  onOpenWelcome: () => void;
  /** Settings > Identity "Pinned contacts" cross-link (jumps to the Contacts tab) */
  onOpenContacts?: () => void;
  /** Play UGC: the device-local block list (Vardum IDs) and its unblock action */
  blockedIds?: string[];
  onUnblock?: (veilId: string) => Promise<void>;
  /** web app base for purchase + legal links */
  webBaseUrl: string;
  /** b75 (audit XF-1): OLD phone — read the new phone's move code, return the check code */
  onCreateTransfer: (code: string) => Promise<MoveOffer>;
  /** b75 (audit XF-1): NEW phone — show a move code (public keys only) and wait */
  onReceiveTransfer: () => Promise<ReceiveFlow>;
  /** b75 (audit XF-1): when the last move was collected, and the code that phone showed */
  getLastMove?: () => Promise<{ at: number; count: number; sas?: string } | null>;
  /** Identity (web parity): local-only 24-word phrase check against the current Veil ID */
  onVerifyPhrase: (phrase: string) => Promise<boolean>;
  /** b199 Account: move a made-up-email account's sign-in to the 24-word phrase */
  onSwitchToPhraseSignIn?: (phrase: string) => Promise<'ok' | 'wrong-phrase'>;
  /** Identity (web parity "Remove from this device"): drop this device's keyvault copy only */
  onRemoveIdentity: () => Promise<void>;
  /** "Generate new Veil ID" (landing headline feature): remove current identity then run the create flow */
  onGenerateNewVeilId: () => Promise<void>;
  /** open the identity create/restore flow (shown when this device has no identity) */
  onCreateIdentity: () => void;
  /** b76 (registration lock): its state (null = not known yet; undefined = not offered, e.g. decoy mode) */
  regLock?: RegLockStatus | null;
  /** b76 (registration lock): read it again (and check in) */
  onRegLockRefresh?: () => Promise<void>;
  /** b76 (registration lock): turn on, or change the PIN */
  onRegLockSet?: (pin: string) => Promise<void>;
  onRegLockOff?: () => Promise<void>;
  /** b76r1 (audit P-4): since when another phone holds this Vardum ID's one-time keys (0 / undefined: not shown) */
  opkElsewhereSince?: number;
  /** b76r1 (audit P-4): publish this phone's one-time keys in their place */
  onOpkReclaim?: () => Promise<void>;
  /** b77s (owner decision): end every other login of this account (returns how many); refused in decoy mode */
  onSignOutOtherDevices?: () => Promise<number>;
  /** b77s (owner decision): change an email account's password (returns how many other logins were
   *  signed out); refused in decoy mode and for 24-word (silent) accounts */
  onChangeAccountPassword?: (oldPassword: string, newPassword: string) => Promise<number>;
}

// Real facts about THIS build, shown in Settings > About — never copied from
// the web app's own About card (which tracks a separate governance process:
// Security patch / Claims Register). PROTOCOL_VERSION must match VeilRelay's
// wire contract. b103: BUILD_NUMBER now derives from the NATIVE build number
// embedded in the binary (expo-constants) — a hardcoded constant here drifted
// from b99 through b103 and made the owner believe a fresh build was stale.
const APP_VERSION = '1.0.92';
const BUILD_NUMBER = (IS_ANDROID ? Constants.expoConfig?.android?.versionCode : Constants.expoConfig?.ios?.buildNumber) ?? Constants.nativeBuildVersion ?? '?';
const BUILD_DATE = '2026-10-12';
// b122: the native build number is frozen into the EAS binary and never
// changes across staged Metro patches — the owner cannot tell which staged
// source the device is actually running (b109-09-24 read identically for
// b118..b121). SOURCE_TAG is bumped with every staged zip so Settings > About
// always identifies the live JS tree.
// b77k (IP77-1): b77 (the package.json build suffix; b122 keeps the two in step)
const SOURCE_TAG = 'b77';
// b185+: the engine is a SPEC-CONFORMANT Signal Double Ratchet with the single
// custom extension retained — per-step ML-KEM-768 post-quantum re-keying
// (PQ-hybrid). 'veil-ratchet-4' is retired; this string is user-facing and
// must match the audited protocol story, not the legacy engine.
// b188: keep the WIRE TAG first (the fail-closed version marker every header carries)
// and append the audited engine description.
// b77k (IP77-1): the wire tag comes from the protocol constant the engine stamps
// (about-tags.ts), never a literal (it still said veil-ratchet-4 on veil-ratchet-8).
const PROTOCOL_VERSION = 'Signal DR + ML-KEM-768';

interface Chip { label: string; value: number }

const BURN_CHIPS: Chip[] = BURN_OPTIONS;
const EXPIRE_CHIPS: Chip[] = EXPIRY_OPTIONS;
const RETENTION_CHIPS: Chip[] = QUIET_OPTIONS;
/** b77u (audit 6 W8): what "End quiet chats after" does, exactly */
export const QUIET_SETTING_TEXT = 'When a one-to-one chat has had no messages, sent or received, for this long, this phone ends it, as if you had tapped End chat. Each chat also keeps the quiet time that was set when it started (by whoever started it); the shorter of the two applies. Groups are not ended this way. Off = only the chat’s own quiet time applies; a chat started with Off too is never ended for being quiet by this phone (the other phone still may, and Vardum’s server closes a chat’s mailboxes after 30 days without use).'; // b77u merge (W8): Off on this phone leaves the chat's own time (quietWindowMs)

/**
 * OptionSheet — b199 Settings redesign (owner request, Oct 16 2026).
 *
 * A themed "pick one" overlay for the Settings timers: the row on the main
 * screen shows only the current value; tapping it opens this sheet with the
 * explanation, the "Defends against" line and the options. Same overlay
 * pattern as ThemedPrompt (absolute overlay, NOT RN Modal — the
 * modal/native-picker collision freeze from b25 stays avoided).
 *
 *   const { node, pick } = useOptionSheet();
 *   const v = await pick({ title, message, defends, options, value });  // null = cancelled
 */

export interface OptionSheetSpec<T extends number | string> {
  title: string;
  message?: string;
  defends?: string;
  options: { label: string; value: T }[];
  value: T;
}

interface Active {
  spec: OptionSheetSpec<number | string>;
  resolve: (v: number | string | null) => void;
}

export function useOptionSheet(): {
  node: React.ReactNode;
  pick: <T extends number | string>(spec: OptionSheetSpec<T>) => Promise<T | null>;
} {
  const [active, setActive] = useState<Active | null>(null);

  const pick = useCallback(<T extends number | string>(spec: OptionSheetSpec<T>) => (
    new Promise<T | null>((resolve) => {
      setActive({ spec: spec as OptionSheetSpec<number | string>, resolve: resolve as (v: number | string | null) => void });
    })
  ), []);

  const settle = useCallback((v: number | string | null) => {
    setActive((cur) => { cur?.resolve(v); return null; });
  }, []);

  const node = active ? (
    <View style={sheetStyles.backdrop}>
      <TouchableOpacity style={StyleSheet.absoluteFill} activeOpacity={1} onPress={() => settle(null)} />
      <View style={sheetStyles.card}>
        <Text style={sheetStyles.title}>{active.spec.title}</Text>
        {active.spec.message ? <Text style={sheetStyles.message}>{active.spec.message}</Text> : null}
        {active.spec.defends ? <Text style={sheetStyles.defends}>{active.spec.defends}</Text> : null}
        <ScrollView style={sheetStyles.list} bounces={false}>
          {active.spec.options.map((o) => {
            const on = o.value === active.spec.value;
            return (
              <TouchableOpacity key={String(o.value)} style={[sheetStyles.opt, on && sheetStyles.optOn]} onPress={() => settle(o.value)}>
                <Text style={[sheetStyles.optTxt, on && sheetStyles.optTxtOn]}>{o.label}</Text>
                {on ? <Text style={sheetStyles.tick}>✓</Text> : null}
              </TouchableOpacity>
            );
          })}
        </ScrollView>
        <TouchableOpacity style={sheetStyles.cancel} onPress={() => settle(null)}>
          <Text style={sheetStyles.cancelTxt}>Cancel</Text>
        </TouchableOpacity>
      </View>
    </View>
  ) : null;

  return { node, pick };
}

const sheetStyles = StyleSheet.create({
  backdrop: { ...StyleSheet.absoluteFillObject, backgroundColor: 'rgba(11,11,15,0.86)', justifyContent: 'center', alignItems: 'center', padding: 22, zIndex: 90 },
  card: { width: '100%', maxWidth: 420, maxHeight: '86%', backgroundColor: '#15151B', borderRadius: 14, borderWidth: 1, borderColor: '#24242D', padding: 18 },
  title: { color: '#FFFFFF', fontSize: 16, fontWeight: '800', marginBottom: 6 },
  message: { color: '#d69a5c', fontSize: 12, lineHeight: 17, marginBottom: 6 },
  defends: { color: '#8E9696', fontSize: 11, fontStyle: 'italic', lineHeight: 16, marginBottom: 12 },
  list: { flexGrow: 0 },
  opt: { flexDirection: 'row', alignItems: 'center', borderWidth: 1, borderColor: '#24242D', borderRadius: 10, paddingVertical: 12, paddingHorizontal: 14, marginBottom: 8 },
  optOn: { borderColor: '#FFFFFF', backgroundColor: 'rgba(255,255,255,0.08)' },
  optTxt: { color: '#C9CFCE', fontSize: 14, flex: 1 },
  optTxtOn: { color: '#FFFFFF', fontWeight: '700' },
  tick: { color: '#FFFFFF', fontSize: 14, fontWeight: '800' },
  cancel: { borderWidth: 1, borderColor: '#24242D', borderRadius: 10, paddingVertical: 10, alignItems: 'center', marginTop: 4 },
  cancelTxt: { color: '#8E9696', fontSize: 13, fontWeight: '600' },
});

// b199 Settings redesign (owner request, Oct 16 2026): one line per setting,
// the current value on the right, explanations one tap away (OptionSheet /
// themed info sheets) instead of paragraphs on the main screen.

const EXPIRE_CHIPS_SHORT: Chip[] = [
  { label: '12 hours', value: 43200 }, { label: '24 hours', value: 86400 }, { label: '36 hours', value: 129600 },
  { label: '48 hours', value: 172800 }, { label: '30 days', value: 2592000 },
];

function labelFor(chips: Chip[], value: number): string {
  return chips.find((c) => c.value === value)?.label ?? EXPIRE_CHIPS.find((c) => c.value === value)?.label ?? '—';
}

/** A titled group of rows (iOS-style inset list). */
function Group({ title, children, note }: { title: string; children: React.ReactNode; note?: string }) {
  return (
    <View style={styles.groupWrap}>
      <Text style={styles.groupTitle}>{title}</Text>
      <View style={styles.group}>{children}</View>
      {note ? <Text style={styles.groupNote}>{note}</Text> : null}
    </View>
  );
}

/** A tappable row: label on the left, value / chevron on the right. */
function Row({ label, value, onPress, danger, accent, chevron = true, sub, disabled, last }: {
  label: string; value?: string; onPress?: () => void; danger?: boolean; accent?: boolean;
  chevron?: boolean; sub?: string; disabled?: boolean; last?: boolean;
}) {
  return (
    <TouchableOpacity style={[styles.row, last && styles.rowLast]} onPress={onPress} disabled={disabled || !onPress} activeOpacity={0.7}>
      <View style={styles.rowMid}>
        <Text style={[styles.rowLabel, danger && styles.dangerTxt, accent && styles.accentTxt]}>{label}</Text>
        {sub ? <Text style={styles.rowSub}>{sub}</Text> : null}
      </View>
      {value ? <Text style={styles.rowValue} numberOfLines={1}>{value}</Text> : null}
      {chevron && onPress ? <Text style={styles.rowChevron}>›</Text> : null}
    </TouchableOpacity>
  );
}

/** A row with a real on/off switch. */
function SwitchRow({ label, on, onFlip, danger, sub, disabled, last }: {
  label: string; on: boolean; onFlip: () => void; danger?: boolean; sub?: string; disabled?: boolean; last?: boolean;
}) {
  return (
    <TouchableOpacity
      style={[styles.row, last && styles.rowLast]} onPress={onFlip} disabled={disabled} activeOpacity={0.7}
      accessibilityRole="switch" accessibilityState={{ checked: on, disabled: !!disabled }} // b71: on/off was only drawn, never announced
    >
      <View style={styles.rowMid}>
        <Text style={[styles.rowLabel, disabled && styles.rowLabelOff]}>{label}</Text>
        {sub ? <Text style={styles.rowSub}>{sub}</Text> : null}
      </View>
      <View style={[styles.switchTrack, on && (danger ? styles.switchTrackDanger : styles.switchTrackOn), disabled && styles.switchOff]}>
        <View style={[styles.switchKnob, on && styles.switchKnobOn]} />
      </View>
    </TouchableOpacity>
  );
}

/**
 * b199 (owner, Oct 16): the identity card — top of Settings AND top of
 * Conversations (it replaced the thin Veil ID strip that sat on every tab).
 * The nickname gets the same weight as the ID. Never renders the account
 * email (b107/b118); the sign-in type line was dropped too (owner, Oct 16).
 */
export function IdentityCard({ veilId, nickname, onShare, onShowQr, onCreateIdentity }: {
  veilId: string | null;
  nickname: string;
  onShare: () => void;
  /** b199: open the full-screen VEIL QR */
  onShowQr?: () => void;
  onCreateIdentity?: () => void;
}) {
  if (!veilId) {
    return (
      <View style={styles.idCard}>
        <Text style={styles.idCardKicker}>No identity on this phone</Text>
        <Text style={styles.idCardLine}>Create an identity with no phone number or email, or restore one with your 24 words.</Text>
        {onCreateIdentity ? (
          <TouchableOpacity style={styles.primaryBtn} onPress={onCreateIdentity}>
            <Text style={styles.primaryBtnTxt}>Create or restore identity</Text>
          </TouchableOpacity>
        ) : null}
      </View>
    );
  }
  return (
    <View style={styles.idCard}>
      <View style={styles.idCardHead}>
        <Image source={require('../../assets/logo.png')} style={styles.idCardLogo} />
        <View style={{ flex: 1 }}>
          <Text style={styles.idCardKicker}>Your Vardum ID</Text>
          <Text style={styles.idCardId} numberOfLines={1} adjustsFontSizeToFit>{veilId}</Text>
        </View>
        {onShowQr ? (
          <TouchableOpacity onPress={onShowQr} style={styles.idCardQr} accessibilityLabel="Show my Vardum QR">
            <Text style={styles.idCardQrTxt}>QR</Text>
          </TouchableOpacity>
        ) : null}
        <TouchableOpacity onPress={onShare}>
          <Text style={styles.idCardCopy}>Share</Text>
        </TouchableOpacity>
      </View>
      <View style={styles.idCardDivider} />
      <Text style={styles.idCardKicker}>Nickname</Text>
      <Text style={[styles.idCardNick, !nickname && styles.idCardNickOff]} numberOfLines={1}>{nickname || 'Not set'}</Text>
    </View>
  );
}

/** b77t2 (decoy gaps): what a phone-wide lock option says when it can't be changed (a decoy session). True, and
 *  the same words for every such option; it neither changes nor shows the phone's real lock settings */
export const LOCK_OPTION_FIXED_NOTE = 'This setting can’t be changed right now. Nothing was changed.';

export function SettingsScreen({
  settings, onChange, veilId, email, onRunCheckup, appLockEnabled, onSetAppLock, onRemoveAppLock,
  onSignOut, onLockNow, onWipeDevice, onDeleteAccount, onViewIntro, onOpenWelcome, onOpenContacts, webBaseUrl,
  onCreateTransfer, onReceiveTransfer, getLastMove, onVerifyPhrase, onSwitchToPhraseSignIn, onRemoveIdentity, onGenerateNewVeilId, onCreateIdentity, onShowQr,
  blockedIds, onUnblock, onCheckPassword,
  regLock, onRegLockRefresh, onRegLockSet, onRegLockOff, opkElsewhereSince, onOpkReclaim,
  pushService, onChoosePushService,
  onSignOutOtherDevices, onChangeAccountPassword, lockOptionsFixed,
}: SettingsScreenProps) {
  const phraseSignIn = isSilentAccountEmail(email);
  // b75 (audit XF-1): the receiver-bound move. OLD phone: scan the new phone's code,
  // compare the check code, send. NEW phone: show a code, compare, receive.
  const [xferBusy, setXferBusy] = useState(false);
  const [moveUi, setMoveUi] = useState<null | { step: 'scan' } | { step: 'check'; offer: MoveOffer } | { step: 'sent'; count: number }>(null);
  const [recvUi, setRecvUi] = useState<null | { step: 'code'; flow: ReceiveFlow } | { step: 'check'; flow: ReceiveFlow; sas: string }>(null);
  const recvFlowRef = React.useRef<ReceiveFlow | null>(null);
  const moveOfferRef = React.useRef<MoveOffer | null>(null);
  // the move code as a QR (it always fits: about 140 characters)
  const recvQrOk = React.useMemo(() => { if (!recvUi) return false; try { qrMatrix(recvUi.flow.code); return true; } catch { return false; } }, [recvUi]);
  /** b71 (audit): scan the code with the camera instead of pasting it */
  const [xferScan, setXferScan] = useState(false);
  const [recvInput, setRecvInput] = useState('');
  const [recvBusy, setRecvBusy] = useState(false);
  const [recvMsg, setRecvMsg] = useState<string | null>(null);
  const [lastMove, setLastMove] = useState<{ at: number; count: number; sas?: string } | null>(null);
  React.useEffect(() => { getLastMove?.().then(setLastMove).catch(() => undefined); }, [getLastMove, moveUi]);
  // leaving Settings ends a move that wasn't sent yet: the receive keys are dropped, an unconfirmed offer is withdrawn
  React.useEffect(() => () => {
    void recvFlowRef.current?.cancel().catch(() => undefined);
    void moveOfferRef.current?.cancel().catch(() => undefined);
  }, []);
  const [identityArmed, setIdentityArmed] = useState(false);
  const [phraseBusy, setPhraseBusy] = useState(false);
  // (b57) themed replacement for every system Alert.prompt/confirm — the OS
  // alerts are unthemeable white iPhone boxes (owner request).
  const { node: promptNode, ask } = useThemedPrompt();
  // b105: VEIL-branded Veil ID share card (owner request Sept 22 — was the
  // stock Apple share sheet). Copy is the primary action; the system sheet
  // only opens on explicit "Share…".
  const { node: shareNode, share: openShare } = useThemedShare();
  const shareVeilId = () => { if (veilId) openShare({ value: veilId, kicker: 'People use it to look you up and start verified conversations.' }); };

  /** b70 (audit VAR-01/02/17): with an app lock set, every account, identity
   *  and key action asks for the password first. The decoy code fails here
   *  the same way a wrong password does. Returns the password typed ('' when
   *  no lock is set), or null to stop. */
  const passwordGate = async (why: string): Promise<string | null> => {
    if (!appLockEnabled || !onCheckPassword) return '';
    const code = (await ask({ title: 'Enter your password', message: why, input: 'code', existing: true, maxLength: PASSWORD_MAX, submitLabel: 'Continue' })) as string | null;
    if (!code) return null;
    let r: 'ok' | 'wrong' | 'wiped';
    try { r = await onCheckPassword(code); } catch (e) {
      await ask({ title: 'Not now', message: String((e as Error)?.message ?? 'Could not check the password.'), info: true });
      return null;
    }
    if (r === 'ok') return code;
    if (r === 'wrong') await ask({ title: 'Incorrect password', message: 'Nothing was changed.', info: true });
    return null;
  };
  const passwordOk = async (why: string): Promise<boolean> => (await passwordGate(why)) !== null;
  /** b77t2 (decoy gaps): true (after saying so) when a phone-wide lock option can't be changed in this session */
  const lockOptionRefused = async (): Promise<boolean> => {
    if (!lockOptionsFixed) return false;
    await ask({ title: 'Not changed', message: LOCK_OPTION_FIXED_NOTE, info: true });
    return true;
  };

  /** b77s (owner decision): "Sign out all other devices" — behind the app password, then a plain confirm */
  const [accountBusy, setAccountBusy] = useState(false);
  const doSignOutOthers = async () => {
    if (!onSignOutOtherDevices) return;
    if (!(await passwordOk('Required to sign out your other devices.'))) return;
    const go = (await ask({
      title: 'Sign out all other devices?',
      message: 'Every other phone or browser signed in to this account is signed out. This phone stays signed in. A device that has your 24 words can sign in again.',
      confirm: true, submitLabel: 'Sign out others',
    })) as boolean;
    if (!go) return;
    setAccountBusy(true);
    try {
      const n = await onSignOutOtherDevices();
      await ask({ title: 'Done', message: n > 0 ? `${n} other ${n === 1 ? 'device was' : 'devices were'} signed out.` : 'No other devices were signed in.', info: true });
    } catch (e) {
      await ask({ title: 'Could not sign out other devices', message: String((e as Error)?.message || e), info: true });
    } finally { setAccountBusy(false); }
  };
  /** b77s (owner decision): "Change password" — email accounts only; behind the app password; the new
   *  password follows the email-account minimum (EMAIL_PASSWORD_MIN) */
  const doChangeAccountPassword = async () => {
    if (!onChangeAccountPassword || phraseSignIn || !email) return;
    if (!(await passwordOk('Required to change your account password.'))) return;
    const oldPw = (await ask({ title: 'Current account password', message: 'The password you use to sign in with your email (not the app lock password).', input: 'code', existing: true, maxLength: EMAIL_PASSWORD_MAX, submitLabel: 'Next' })) as string | null;
    if (!oldPw) return;
    const newPw = (await ask({ title: 'New account password', message: `At least ${EMAIL_PASSWORD_MIN} characters. It can’t be reset by email, so keep it safe.`, input: 'code', maxLength: EMAIL_PASSWORD_MAX, submitLabel: 'Next' })) as string | null;
    if (!newPw) return;
    const problem = emailPasswordProblem(newPw);
    if (problem) { await ask({ title: 'Password too short', message: `${problem} Nothing was changed.`, info: true }); return; }
    const again = (await ask({ title: 'Type it again', message: 'To make sure there’s no typo.', input: 'code', maxLength: EMAIL_PASSWORD_MAX, submitLabel: 'Change' })) as string | null;
    if (again === null) return;
    if (again !== newPw) { await ask({ title: 'Those didn’t match', message: 'Nothing was changed. Try again.', info: true }); return; }
    setAccountBusy(true);
    try {
      const n = await onChangeAccountPassword(oldPw, newPw);
      await ask({ title: 'Password changed', message: 'Use the new password next time you sign in with your email.' + (n > 0 ? ` ${n} other ${n === 1 ? 'device was' : 'devices were'} signed out.` : ''), info: true });
    } catch (e) {
      await ask({ title: 'Could not change the password', message: String((e as Error)?.message || e), info: true });
    } finally { setAccountBusy(false); }
  };

  /** web parity: "Verify recovery phrase" — local-only check, phrase never leaves the device */
  const doVerifyPhrase = async () => {
    if (!(await passwordOk('Required to check your recovery phrase.'))) return;
    const t = (await ask({
      title: 'Verify recovery phrase',
      message: 'Paste your 24-word recovery phrase. It is checked on this device against your Vardum ID — the phrase itself never leaves this device.',
      input: 'phrase', // audit VAR-08
      submitLabel: 'Verify',
    })) as string | null;
    const phrase = (t || '').trim().toLowerCase();
    if (!phrase) return;
    void clearPhraseFromClipboard(phrase); // audit VAR-08
    setPhraseBusy(true);
    try {
      const ok = await onVerifyPhrase(phrase);
      await ask({
        title: ok ? 'Phrase verified' : 'Not this identity',
        message: ok
          ? 'Phrase verified — it matches the identity key published to the relay.'
          : 'This recovery phrase belongs to a different Vardum identity.',
        info: true,
      });
    } catch {
      await ask({ title: 'Not this identity', message: 'This recovery phrase belongs to a different Vardum identity.', info: true });
    } finally {
      setPhraseBusy(false);
    }
  };

  /** b199: move a made-up-email account's sign-in to the 24-word phrase */
  const doSwitchToPhraseSignIn = async () => {
    if (!onSwitchToPhraseSignIn) return;
    if (!(await passwordOk('Required to change how this account signs in.'))) return;
    const go = (await ask({
      title: 'Sign in with your 24 words',
      message: 'Your account will sign in with your 24-word recovery phrase instead of an email and password. Your current email and password stop working, and nothing personal stays on the relay. The phrase is checked on this device; only a one-way code made from it is sent. Keep your 24 words safe — they become the only way back into this account.',
      confirm: true,
    })) as boolean;
    if (!go) return;
    const t = (await ask({
      title: 'Enter your recovery phrase',
      message: 'Type or paste your 24 words, in order, separated by spaces.',
      input: 'phrase', // audit VAR-08
      submitLabel: 'Switch',
    })) as string | null;
    const phrase = (t || '').trim().toLowerCase();
    if (!phrase) return;
    void clearPhraseFromClipboard(phrase); // audit VAR-08
    setPhraseBusy(true);
    try {
      const r = await onSwitchToPhraseSignIn(phrase);
      await ask({
        title: r === 'ok' ? 'Done — 24-word sign-in is on' : 'Not this identity',
        message: r === 'ok'
          ? 'This account now signs in with your 24 words only. Your old email and password no longer work.'
          : 'This recovery phrase belongs to a different Vardum identity. Nothing was changed.',
        info: true,
      });
    } catch (e) {
      await ask({ title: 'Could not switch sign-in', message: String((e as Error).message || e) + ' Nothing was changed.', info: true });
    } finally {
      setPhraseBusy(false);
    }
  };

  /** "Generate new Veil ID": fresh keys and a fresh ID. b75 (audit DEV-M1): the server account
   *  stays the same, so the server can link the two IDs; the copy says so */
  const doGenerateNewVeilId = async () => {
    if (!(await passwordOk('Required to replace your Vardum ID.'))) return;
    const ok = (await ask({
      title: 'Generate new Vardum ID',
      message: 'Creates a new identity: new keys, new 24 words and a new Vardum ID. Your account on Vardum’s server stays the same, so the server (and anyone who gets its data) can link your old and new IDs. For a clean break, wipe Vardum from this phone and create a new account instead.\n\nYour current identity is removed from this device first; it stays recoverable only with its 24-word recovery phrase. Contacts, pins and existing conversation keys are kept; new chats use the new identity.',
      confirm: true,
      danger: true,
    })) as boolean;
    if (!ok) return;
    setIdentityArmed(false);
    try {
      await onGenerateNewVeilId();
    } catch (e) {
      await ask({ title: 'Could not generate a new identity', message: String((e as Error).message || e), info: true });
    }
  };

  // ---- b76 (registration lock) ----
  // Read its state when Settings opens (that is also a check-in that keeps it from lapsing).
  React.useEffect(() => { if (veilId) void onRegLockRefresh?.(); }, [veilId, onRegLockRefresh]);
  const [regLockBusy, setRegLockBusy] = useState(false);
  /** a new PIN, typed twice (null = the user stopped, or it was refused and they were told) */
  const askNewRegLockPin = async (): Promise<string | null> => {
    const pin = (await ask({
      title: 'Choose a registration lock PIN',
      message: 'Asked when your 24 words are used to restore this account on another phone. Use at least 6 characters; a few words you will remember is best. A short number is easy to guess for someone who has your 24 words AND a copy of the server’s data. Vardum can’t recover it for you.',
      input: 'secure', maxLength: REGLOCK_PIN_MAX, submitLabel: 'Next',
    })) as string | null;
    if (!pin) return null;
    const problem = regLockPinProblem(pin);
    if (problem) { await ask({ title: 'Choose another PIN', message: `${problem} Nothing was changed.`, info: true }); return null; }
    const again = (await ask({ title: 'Type it again', message: 'To make sure there’s no typo.', input: 'secure', maxLength: REGLOCK_PIN_MAX, submitLabel: 'Save' })) as string | null;
    if (again === null) return null;
    if (again !== pin) { await ask({ title: 'Those didn’t match', message: 'Nothing was changed. Try again.', info: true }); return null; }
    return pin;
  };
  /** turning it on, changing the PIN and turning it off all sit behind the app password */
  const regLockNeedsAppLock = async (): Promise<boolean> => {
    if (appLockEnabled) return true;
    await ask({ title: 'Set an app lock first', message: 'The registration lock is turned on, changed and turned off with your app password. Set one under Lock and emergency → App lock, then come back.', info: true });
    return false;
  };
  const doRegLockOn = async (change: boolean) => {
    if (!onRegLockSet || regLockBusy) return;
    if (!(await regLockNeedsAppLock())) return;
    if (!change) {
      const go = (await ask({ title: 'Registration lock', message: REGLOCK_EXPLAIN, confirm: true, submitLabel: 'Turn on' })) as boolean;
      if (!go) return;
    }
    if (!(await passwordOk(change ? 'Required to change the registration lock PIN.' : 'Required to turn on the registration lock.'))) return;
    const pin = await askNewRegLockPin();
    if (!pin) return;
    setRegLockBusy(true);
    try {
      await onRegLockSet(pin);
      await ask({
        title: change ? 'PIN changed' : 'Registration lock is on',
        message: change ? 'Use the new PIN from now on. The old one no longer works.' : 'Restoring this account with your 24 words on another phone now also needs this PIN. This phone doesn’t.',
        info: true,
      });
    } catch (e) {
      // b76r1 (audit I5): "Nothing was changed" only when that is true
      const changed = (e as { regLockChanged?: boolean } | null)?.regLockChanged === true;
      await ask({ title: 'Could not save the registration lock', message: `${String((e as Error).message || e)}${changed ? '' : ' Nothing was changed.'}`, info: true });
    } finally { setRegLockBusy(false); }
  };
  const doRegLockOff = async () => {
    if (!onRegLockOff || regLockBusy) return;
    if (!(await regLockNeedsAppLock())) return;
    const go = (await ask({ title: 'Turn off the registration lock?', message: 'Your 24 words alone will restore this account on any phone again.', confirm: true, danger: true, submitLabel: 'Turn off' })) as boolean;
    if (!go) return;
    if (!(await passwordOk('Required to turn off the registration lock.'))) return;
    setRegLockBusy(true);
    try { await onRegLockOff(); } catch (e) {
      await ask({ title: 'Could not turn it off', message: `${String((e as Error).message || e)} The lock is still on.`, info: true });
    } finally { setRegLockBusy(false); }
  };

  // ---- b76r1 (one-time prekeys, audit P-4) ----
  // Another phone with this Vardum ID published the one-time keys new contacts use to reach it, so
  // this phone stopped publishing its own. Shown here (it used to stop silently, for good), with
  // the choice to publish this phone's keys in their place.
  const [opkBusy, setOpkBusy] = useState(false);
  const doOpkReclaim = async () => {
    if (!onOpkReclaim || opkBusy) return;
    const go = (await ask({
      title: 'One-time keys',
      message: 'Another phone with your Vardum ID publishes the one-time keys that new contacts use to reach you, so contact requests made with them can be accepted only on that phone. If you don’t recognise that phone, someone may have your 24 words.\n\nUse this phone’s keys instead? New requests can then be accepted here, and no longer on the other phone.',
      confirm: true, submitLabel: 'Use this phone',
    })) as boolean;
    if (!go) return;
    setOpkBusy(true);
    try {
      await onOpkReclaim();
      await ask({ title: 'One-time keys', message: 'This phone’s one-time keys are published now.', info: true });
    } catch (e) {
      await ask({ title: 'Could not publish the keys', message: String((e as Error).message || e), info: true });
    } finally { setOpkBusy(false); }
  };

  /** web parity: "Remove from this device" — two-tap armed, drops the keyvault copy only */
  const doRemoveIdentity = async () => {
    if (identityArmed) {
      setIdentityArmed(false);
      if (!(await passwordOk('Required to remove your identity from this phone.'))) return;
      onRemoveIdentity().catch((e) =>
        ask({ title: 'Could not remove the identity', message: String((e as Error).message || e), info: true }));
    } else {
      setIdentityArmed(true);
    }
  };

  /** OLD phone, step 1: open the scan/paste box (password first) */
  const openMove = async () => {
    if (!(await passwordOk('Required to move your chats to another phone.'))) return;
    setRecvInput(''); setMoveUi({ step: 'scan' });
  };
  /** OLD phone, step 2: read the new phone's code and get the check code */
  const doCreateTransfer = async (code: string) => {
    setXferBusy(true);
    try {
      const offer = await onCreateTransfer(code.trim());
      moveOfferRef.current = offer;
      setMoveUi({ step: 'check', offer });
    } catch (e) {
      void ask({ title: 'Couldn\u2019t start the move', message: String((e as Error).message || e), info: true });
    } finally { setXferBusy(false); setRecvInput(''); }
  };
  /** OLD phone, step 3: the user compared the codes */
  const answerCheck = async (match: boolean) => {
    if (!moveUi || moveUi.step !== 'check') return;
    const { offer } = moveUi;
    moveOfferRef.current = null;
    if (!match) {
      await offer.cancel().catch(() => undefined);
      setMoveUi(null);
      void ask({ title: 'Nothing was sent', message: 'The codes didn\u2019t match, so your chats stay on this phone. Make sure you scanned the code on your own new phone, then start again.', info: true });
      return;
    }
    setXferBusy(true);
    try {
      await offer.confirm();
      setMoveUi({ step: 'sent', count: offer.sessionCount });
    } catch (e) {
      setMoveUi(null);
      void ask({ title: 'The move didn\u2019t finish', message: String((e as Error).message || e), info: true });
    } finally { setXferBusy(false); }
  };

  /** NEW phone: show a move code, then the check code, then import */
  const doReceiveTransfer = async () => {
    if (!(await passwordOk('Required to bring chats onto this phone.'))) return;
    setRecvBusy(true); setRecvMsg(null);
    let flow: ReceiveFlow | null = null;
    try {
      flow = await onReceiveTransfer();
      recvFlowRef.current = flow;
      setRecvUi({ step: 'code', flow });
      const { sas } = await flow.offer();
      setRecvUi({ step: 'check', flow, sas });
      const r = await flow.finish();
      recvFlowRef.current = null;
      setRecvUi(null);
      setRecvMsg(
        `Imported ${r.importedCount} chat${r.importedCount === 1 ? '' : 's'}`
        + (r.skippedExisting ? ` (${r.skippedExisting} not imported: already here, or not matching a key you pinned)` : '')
        + '.',
      );
    } catch (e) {
      const cancelled = !!flow && !recvFlowRef.current;
      recvFlowRef.current = null;
      setRecvUi(null);
      if (flow) void flow.cancel().catch(() => undefined);
      if (!cancelled) void ask({ title: 'Nothing was imported', message: String((e as Error).message || e), info: true });
    } finally { setRecvBusy(false); }
  };
  const cancelReceive = () => {
    const f = recvFlowRef.current;
    recvFlowRef.current = null;
    setRecvUi(null);
    if (f) void f.cancel().catch(() => undefined);
  };
  const set = (patch: Partial<VeilSettings>) => onChange({ ...settings, ...patch });

  /**
   * b105 two-tap key storage change (owner request Sept 22): tap 1 shows what
   * the switch will actually do; tap 2 (Confirm) executes it. The hardware
   * flip's own Face ID demand then fires as part of the switch, as in b104.
   */
  const confirmKeyMode = async (mode: 'device' | 'hardware' | 'memory') => {
    if (settings.storageMode === mode) return;
    if (await lockOptionRefused()) return; // b77t2 (decoy gaps)
    const warnings: Record<'device' | 'hardware' | 'memory', string> = {
      device: 'Your identity keys will move into encrypted on-device storage. They persist across restarts and nothing is demanded at boot. Weaker against a seized device — the stored keys exist in a full device image. Conversations keep working unchanged.',
      // b70 (audit VAR-15): only the identity key is sealed in the chip; say so
      hardware: `Your identity key will be re-sealed inside ${SECURE_CHIP}. The phone itself will demand ${BIOMETRIC_SHORT} at boot and at this switch — if biometry is off, broken or re-enrolled, the key becomes unreachable and the app falls back to restoring from your 24-word phrase. This protects your identity key from extraction from a seized phone. Conversation keys and saved history are stored the same way as in Sealed mode.`,
      memory: 'The moment Vardum leaves the foreground or the screen locks, ALL local data is wiped: chats, notes, vaults and your identity keys (identity first). Saved stego images are deleted too (best effort; iOS asks first and keeps them in Recently Deleted for 30 days). Local history is forced off. While Vardum is open, your identity and chat keys are held in memory only, never written to the phone’s storage, so a forced restart or a crash leaves none behind. This holds for the chats you have when you turn it on and for chats started or restored while it is on. Wiped chat threads can NEVER be reopened. Your 24-word phrase restores identity and notes; vaults reopen with their passphrases. Your login, settings, app lock and pinned contacts survive, with your notes’ version numbers, a record of contact requests already answered (fingerprints only), the self-destruct clock, this phone’s app ID and, with a decoy code, the decoy’s separate account; with the kept login, someone holding the phone could ask Vardum’s server which Vardum IDs you have chats with (not what was said).',
    };
    const labels: Record<'device' | 'hardware' | 'memory', string> = {
      device: 'Switch to Sealed-at-rest',
      hardware: 'Switch to security chip',
      memory: 'Switch to Nothing-at-Rest',
    };
    const ok = await ask({ title: 'Change key storage?', message: warnings[mode], confirm: true, submitLabel: labels[mode] });
    if (ok !== true) return;
    if (!(await passwordOk('Required to change where your keys are kept.'))) return;
    if (mode === 'memory') set({ storageMode: mode, localHistory: false });
    else set({ storageMode: mode });
  };
  const [wipeArmed, setWipeArmed] = useState(0);

  const armWipe = () => {
    const id = Date.now();
    setWipeArmed(id);
    setTimeout(() => setWipeArmed((a) => (a === id ? 0 : a)), 6000);
  };

  const setLockCodes = async () => {
    // b70 (audit VAR-01/VAR-17): changing an existing lock needs the current
    // real password. In decoy mode the decoy code fails here like a wrong one.
    const current = await passwordGate('Required to change the app lock.');
    if (current === null) return;
    // b199 (owner, Oct 16): a password — any characters, 4 to 50
    const pass = (await ask({
      title: 'Set your password',
      message: `${PASSWORD_MIN} to ${PASSWORD_MAX} characters: letters, numbers, symbols or spaces. Use it to unlock Vardum.`,
      input: 'code',
      maxLength: PASSWORD_MAX,
      submitLabel: 'Next',
    })) as string | null;
    if (!pass) return;
    const problem = passwordProblem(pass);
    if (problem) { await ask({ title: 'Password too short', message: problem, info: true }); return; }
    const again = (await ask({ title: 'Type it again', message: 'To make sure there’s no typo.', input: 'code', maxLength: PASSWORD_MAX, submitLabel: 'Next' })) as string | null;
    if (again === null) return;
    if (again !== pass) { await ask({ title: 'Those didn’t match', message: 'Nothing was saved. Try again.', info: true }); return; }
    const decoy = (await ask({
      title: 'Decoy code (optional)',
      message: `Cancel to skip. ${DECOY_SETUP_NOTE}${DECOY_LOCKOUT_NOTE} Any characters, ${PASSWORD_MIN} to ${PASSWORD_MAX}.` + (lockHardwareKeyAvailable() ? '' : SOFT_LOCK_NOTE),
      input: 'code',
      maxLength: PASSWORD_MAX,
      submitLabel: 'Next',
    })) as string | null;
    const duress = (await ask({
      title: 'Duress code (optional)',
      message: `Cancel to skip. Entered at the lock screen (or any password prompt), it erases Vardum from this phone (best effort), signs out and shows the start screen. It can’t undo a copy of the phone’s storage taken earlier. Any characters, ${PASSWORD_MIN} to ${PASSWORD_MAX}.` + (lockHardwareKeyAvailable() ? '' : SOFT_LOCK_NOTE),
      input: 'code',
      maxLength: PASSWORD_MAX,
      submitLabel: 'Save',
    })) as string | null;
    for (const [label, code] of [['Decoy code', decoy], ['Duress code', duress]] as const) {
      const p = code ? passwordProblem(code) : null;
      if (p) { await ask({ title: `${label} too short`, message: `${p} Nothing was saved.`, info: true }); return; }
    }
    try {
      await onSetAppLock(current || null, pass, decoy || null, duress || null);
    } catch (e) {
      await ask({ title: 'Could not save', message: String((e as Error).message || e), info: true });
      return;
    }
    // audit VAR-18: the erase-after-10 choice is put to the user at password setup (off unless turned on)
    if (!settings.wipeAfterFails) {
      const wipe = (await ask({ title: 'Erase after 10 wrong passwords?', message: WIPE_AFTER_FAILS_SETUP, confirm: true, submitLabel: 'Turn on' })) as boolean;
      if (wipe) set({ wipeAfterFails: true });
    }
  };

  // self-destruct countdown state
  const sdArmedAt = settings.selfDestructArmedAt || 0;
  const sdElapsedH = sdArmedAt ? (Date.now() - sdArmedAt) / 3600000 : 0;
  const sdWarn = settings.selfDestruct && sdElapsedH >= SELF_DESTRUCT_WARN_HOURS;

  const selfDestructRow = settings.selfDestruct ? (
    <View style={styles.sdBox}>
      <Text style={styles.sdTxt}>
        {sdWarn
          ? `Self-destruct in under ${selfDestructLeftLabel(SELF_DESTRUCT_HOURS - sdElapsedH)}. After that, Vardum wipes what it keeps on this phone the next time it opens, or straight away if it is running — extend if you are still using it.`
          : `Self-destruct armed. Once ${selfDestructLeftLabel(SELF_DESTRUCT_HOURS - sdElapsedH)} have passed, Vardum wipes what it keeps on this phone, your login included, the next time it opens, or straight away if it is running. A phone that stays switched off isn’t wiped until Vardum next opens. Messaging does not reset the clock. ${SELF_DESTRUCT_CLOCK_NOTE}`}
      </Text>
      <TouchableOpacity style={styles.sdExtendBtn} onPress={async () => { if (await passwordOk('Required to extend the self-destruct countdown.')) set({ selfDestructArmedAt: selfDestructArmNow() }); }} /* b70 (re-review 7); b77t2: relay time when known */>
        <Text style={styles.sdExtendTxt}>Extend by another {SELF_DESTRUCT_DAYS} days</Text>
      </TouchableOpacity>
    </View>
  ) : null;

  // b199 redesign: themed "pick one" sheet for the timers
  const { node: sheetNode, pick } = useOptionSheet();

  const pickBurn = async () => {
    const v = await pick({
      title: 'Burn after opening',
      message: 'Messages delete themselves this long after the other person reads them. Off = messages are not burned after opening; they last their full unopened window.',
      defends: 'Defends against: someone later opening a phone and re-reading conversations.',
      options: BURN_CHIPS, value: settings.burnTtlSeconds,
    });
    if (v !== null) set({ burnTtlSeconds: v });
  };
  const pickExpire = async () => {
    const v = await pick({
      title: 'Unopened messages expire',
      message: 'If nobody opens a message, Vardum’s server deletes it this long after it was sent. Opened messages follow the burn timer instead.',
      defends: 'Defends against: unread messages piling up on the server.',
      options: EXPIRE_CHIPS_SHORT, value: settings.expireAfterSeconds,
    });
    if (v !== null) set({ expireAfterSeconds: v });
  };
  const pickQuiet = async () => {
    const v = await pick({
      title: 'End quiet chats after',
      // b77u (audit 6 W8 / website C-1): the phone ends quiet chats now (App.tsx, src/quiet-chats.ts); the text says exactly how
      message: QUIET_SETTING_TEXT,
      defends: 'Defends against: old one-to-one chats lingering on this phone and on Vardum’s server.',
      options: RETENTION_CHIPS, value: settings.retentionHours,
    });
    if (v !== null) set({ retentionHours: v });
  };
  const info = (title: string, message: string) => { void ask({ title, message, info: true }); };

  const keyModeShort = settings.storageMode === 'hardware'
    ? `Your identity key is sealed in your phone’s security chip; ${BIOMETRIC} is needed to open it. Conversation keys are stored as in Sealed mode.`
    : settings.storageMode === 'memory'
      ? 'Each time you leave Vardum, your identity, chats, notes, vaults and keys are wiped from this phone. Kept: your login, settings, app lock and pinned contacts (their Vardum IDs and verified marks), your notes’ version numbers, a record of contact requests already answered (fingerprints only), the self-destruct clock, this phone’s app ID and, with a decoy code, the decoy’s separate account. While Vardum is open, your identity, chats and keys are held in memory only, never written to the phone’s storage; the kept items above are stored sealed, as in Sealed mode. Your 24 words bring your identity back.' // b75 (audit AL-8): what stays. b77s (audit 4 DV-6): memory-only while open since audit VAR-12 (1f51) — a session that begins with a restore or a new identity runs in a memory session too (nar-memory.ts startNarSession), as does the dial flip (carryIntoMemory); the b71 "not memory-only while open" note predates both
      : 'Keys stored encrypted on this phone. Convenient, but the most exposed if the phone is seized.';

  return (
    <View style={styles.fill}>
    <ScrollView style={styles.fill} contentContainerStyle={styles.content}>
      <Text style={styles.headline}>Settings</Text>

      {/* ---- Identity ---- */}
      <IdentityCard veilId={veilId} nickname={settings.nickname} onShare={shareVeilId} onShowQr={onShowQr} onCreateIdentity={onCreateIdentity} />

      {/* ---- Messages ---- */}
      <Group title="Messages" note="New chats use these timers. Turning history off means read in the moment: messages vanish from this phone when you leave the chat, including ones you sent. Deleted messages leave Vardum’s live server on time, but leftovers in the server’s storage and its backups can keep an encrypted copy (which the server can’t read) for up to about 15 days.">
        <Row label="Burn after opening" value={labelFor(BURN_CHIPS, settings.burnTtlSeconds)} onPress={pickBurn} />
        <Row label="Unopened messages expire" value={labelFor(EXPIRE_CHIPS_SHORT, settings.expireAfterSeconds)} onPress={pickExpire} />
        <Row label="End quiet chats after" value={labelFor(RETENTION_CHIPS, settings.retentionHours)} onPress={pickQuiet} />
        <SwitchRow
          label="Keep history on this phone"
          on={settings.localHistory}
          onFlip={async () => {
            if (settings.localHistory) {
              // audit VAR-01: turning it off erases the history already on this phone (App.tsx), so ask first
              const ok = await ask({ title: 'Turn history off?', message: 'Every message already saved on this phone is erased now, in every chat. From now on messages show only while their chat is open. Your contacts keep their own copies.', confirm: true, danger: true, submitLabel: 'Erase and turn off' });
              if (ok) set({ localHistory: false });
              return;
            }
            if (await passwordOk('Required to keep history on this phone.')) set({ localHistory: true }); /* b70 (re-review 7): turning it ON asks */
          }}
          disabled={settings.storageMode === 'memory'}
          sub={settings.storageMode === 'memory' ? 'Off while Nothing at rest is on' : undefined}
        />
        <SwitchRow label="Read receipts" on={settings.readReceipts} onFlip={() => set({ readReceipts: !settings.readReceipts })} />
        <SwitchRow label="Private keyboard" on={settings.privateKeyboard} onFlip={() => set({ privateKeyboard: !settings.privateKeyboard })} sub={PRIVATE_KEYBOARD_NOTE /* audit VAR-14: says what it really does */} last />
      </Group>

      {/* ---- audit VAR-17: the UnifiedPush distributor is the user's choice, and shown ---- */}
      {pushService && pushService.installed.length > 0 && onChoosePushService ? (
        <Group title="Push service" note="The app that wakes Vardum for new messages (UnifiedPush). It sees when alerts arrive, never what they say. Pick one you installed yourself; any app can offer itself here.">
          <Row
            label="Push service"
            value={pushService.chosen ? distributorLabel(pushService.chosen) : 'Not chosen'}
            sub={pushService.alertsHidden ? PUSH_ALERTS_HIDDEN_NOTE : pushService.chosen ? undefined : 'Until you choose one, Vardum doesn’t use UnifiedPush'}
            onPress={async () => {
              const v = await pick({
                title: 'Push service',
                message: 'These apps on this phone say they can deliver UnifiedPush alerts. Choose the one you installed for this (for example ntfy). The package name is shown so you can check it.',
                options: pushService.installed.map((p) => ({ label: distributorLabel(p), value: p })),
                value: pushService.chosen ?? '',
              });
              if (v) await onChoosePushService(v);
            }}
            last
          />
        </Group>
      ) : null}

      {/* ---- Play UGC (18 Oct 2026): blocked people, kept only on this phone ---- */}
      {onUnblock ? (
        <Group title="Blocked" note="Kept only on this phone. Blocked people's messages are hidden and don't notify you; they aren't told.">
          {(blockedIds ?? []).length === 0 ? (
            <Row label="Nobody is blocked" sub="Hold a message to block its sender, or use ⋯ in a chat" last />
          ) : (blockedIds ?? []).map((vid, i, all) => (
            <Row
              key={vid}
              label={vid}
              value="Unblock"
              onPress={async () => {
                const ok = await ask({ title: 'Unblock this Vardum ID?', message: `${vid}\n\nTheir messages show again on this phone. Ended chats stay ended.`, confirm: true, submitLabel: 'Unblock' });
                if (ok === true) await onUnblock(vid);
              }}
              last={i === all.length - 1}
            />
          ))}
        </Group>
      ) : null}

      {/* ---- Lock and emergency ---- */}
      <Group title="Lock and emergency" note="The app lock stops someone using Vardum on your phone. It does not encrypt your messages with your password: someone who extracts the phone’s storage with forensic tools may be able to read saved chats and keys. For that threat use Nothing at rest (chats and keys are wiped whenever you leave Vardum) or turn history off. Decoy code: opens a separate, empty Vardum with its own Vardum ID and its own account on Vardum’s server, and it works like a new one: you can add contacts, chat and use groups (it starts with none). Your real data stays on the phone, hidden, and nothing done in the decoy reaches it. Nothing stored on the server links the two accounts, but the server can see that both are used from the same network. Someone who knows the app, or watches it closely, may be able to tell. Opening the decoy resets the wrong-password count, so someone who knows the decoy code isn’t slowed down by the lockout when guessing the real one. Duress code: erases Vardum’s data and keys on this phone (best effort), signs out and shows the start screen. Then, in the background for about 20 seconds, it tries to delete your server copies (chats, vaults and notes): that needs the phone to be online, and whatever it can’t reach in that time stays on the server, encrypted, where the server can’t read it. Images Vardum saved to Photos (from a chat or from Stego), and files it saved to a folder you chose, are deleted too (in Photos iOS asks first, only once: if you refuse, they stay; it keeps them in Recently Deleted for 30 days). This is why, on iPhone, Vardum asks for full Photos access when you first save an image: with add-only access it could not delete what it saved. Deleting the app deletes the key that seals what Vardum stored, so the stored values can’t be opened; on iPhone the sealed entries and their names stay in the Keychain until Vardum is installed again.">
        <Row label="App lock" value={appLockEnabled ? 'Password, decoy, duress' : 'Off'} onPress={setLockCodes} />
        <SwitchRow
          label="Erase after 10 wrong passwords"
          on={!!settings.wipeAfterFails}
          onFlip={async () => { if (await lockOptionRefused()) return; /* b77t2 (decoy gaps) */ if (!settings.wipeAfterFails || (await passwordOk('Required to turn off erase-after-10-wrong-passwords.'))) set({ wipeAfterFails: !settings.wipeAfterFails }); }} /* b73 (audit V-14); turning it OFF asks */
          sub="10 wrong app-lock passwords in a row erase Vardum from this phone, like the duress code. Anyone holding your phone can trigger it."
        />
        <SwitchRow
          label="Hold messages while locked"
          on={settings.holdUntilUnlock}
          onFlip={async () => { if (!settings.holdUntilUnlock || (await passwordOk('Required to receive messages while locked.'))) set({ holdUntilUnlock: !settings.holdUntilUnlock }); }} /* b70 (re-review 7): turning it OFF asks */
          sub="A locked phone receives no message data, and calls don’t ring until you unlock"
        />
        <SwitchRow
          label="Self-destruct countdown"
          on={settings.selfDestruct}
          onFlip={async () => { if (await lockOptionRefused()) return; /* b77t2 (decoy gaps) */ if (!settings.selfDestruct || (await passwordOk('Required to turn off the self-destruct countdown.'))) set({ selfDestruct: !settings.selfDestruct, selfDestructArmedAt: !settings.selfDestruct ? selfDestructArmNow() /* b77t2 */ : 0 }); }} /* b70 (re-review 7): turning it OFF asks */
          sub={`After ${SELF_DESTRUCT_DAYS} days, wipes Vardum from this phone and signs it out, the next time it opens (or while it runs)`} /* b77u (audit 6 APP-04 claim): the login goes too */
          danger
        />
        <Row label="Lock now" onPress={onLockNow} accent chevron={false} last={!appLockEnabled} />
        {appLockEnabled ? (
          <Row
            label="Remove app lock"
            danger
            chevron={false}
            last
            onPress={async () => {
              const pass = (await ask({ title: 'Enter your current password', message: 'Required to remove the app lock.', input: 'code', existing: true, maxLength: PASSWORD_MAX, submitLabel: 'Remove' })) as string | null;
              if (!pass) return;
              // Batch D (D-11): the shared wrong-attempt lockout applies here too
              let ok = false;
              try { ok = await onRemoveAppLock(pass); } catch (e) {
                await ask({ title: 'Not now', message: String((e as Error)?.message ?? 'Could not check the password.'), info: true });
                return;
              }
              if (!ok) await ask({ title: 'Incorrect password', message: 'The app lock was not changed.', info: true });
            }}
          />
        ) : null}
      </Group>
      {selfDestructRow}

      {/* ---- Key storage (b105 two-tap change kept: confirmKeyMode) ---- */}
      <Group title="Key storage">
        <View style={styles.segWrap}>
          <View style={styles.seg}>
            {([['device', 'Sealed'], ['hardware', 'Security chip'], ['memory', 'Nothing at rest']] as const).map(([mode, label]) => (
              <TouchableOpacity
                key={mode}
                style={[styles.segItem, settings.storageMode === mode && styles.segItemOn]}
                onPress={() => { void confirmKeyMode(mode); }}
                accessibilityRole="radio" accessibilityState={{ selected: settings.storageMode === mode }} // b71: the choice was only drawn
              >
                <Text style={[styles.segTxt, settings.storageMode === mode && styles.segTxtOn]} numberOfLines={1} adjustsFontSizeToFit>{label}</Text>
              </TouchableOpacity>
            ))}
          </View>
          <Text style={styles.keyModeDesc}>{keyModeShort}</Text>
        </View>
        <Row
          label="If your phone could be seized"
          last
          onPress={() => info('If your phone could be seized',
            `Phone-extraction tools work best on a phone that has been unlocked since it was switched on. Sealed keys can sometimes be extracted from such a phone${IS_ANDROID ? ' (on Android, the key that opens them works only while the phone is unlocked, where the phone supports that; Vardum keeps it in memory while it runs, even when the screen locks)' : ''}; in Security chip mode your identity key also needs ${BIOMETRIC}, while conversation keys are stored as in Sealed mode; Nothing at rest holds your identity and conversation keys in memory only and never writes them to the phone’s storage, so a forced restart or a crash leaves none behind (your login, settings, app lock and contact pins are stored, sealed; a voice or video note you play is a temporary file while its chat is open, and one left by a crash is deleted the next time Vardum opens). Saved history reveals more than keys, so turn it off if this risk applies to you. Switching the phone off before it leaves your hands puts it in its hardest-to-extract state.`)}
        />
      </Group>

      {/* ---- Always on ---- */}
      <Group title="Always on">
        <Row
          label="Screen protection"
          value="Always on"
          onPress={() => info('Block recording & hide app-switcher preview',
            SCREEN_PROTECTION_INFO)}
        />
        <Row
          label="Notifications"
          value="Contentless"
          onPress={() => info('Notifications', NOTIFICATIONS_EXPLAIN)}
        />
        <Row
          label="Your IP address"
          value="Kept as a daily code"
          onPress={() => info('Your IP address',
            // b77q (audit 3 AQ-1): it said "but not your messages, name or contacts" while every key check named each
            // pinned contact under the account; the checks now go without the login, and the text says what is left
            'Like any internet service, Vardum’s server sees the network address your phone connects from, but not your messages or name. When you add a contact, the request and the first fetch of their keys go with your login. After that, your phone checks your contacts’ security keys every few hours, and when you open a chat with one of them, without signing in, so the server no longer gets your contact list with your account. It could still guess at it from your network address and the timing. It doesn’t keep the address itself: it’s turned into a one-way code that changes daily. The key for that code is held only in the server’s memory (never written to disk) and replaced daily. If hiding your address matters to you, connect through a trusted VPN or Tor (for example Orbot) before opening Vardum.')}
        />
        <Row label="Auto-lock" value="After 1 minute" last />
      </Group>

      {/* ---- Recovery and devices ---- */}
      <Group title="Recovery and devices" note="Your 24 words restore your identity on a new phone. Then your chats can move: open Receive from old phone on the new phone, and Move to a new phone on this one.">
        {veilId ? <Row label={phraseBusy ? 'Verifying…' : 'Verify recovery phrase'} onPress={doVerifyPhrase} disabled={phraseBusy} /> : null}
        {!phraseSignIn && veilId && onSwitchToPhraseSignIn ? (
          <Row label={phraseBusy ? 'Working…' : 'Sign in with my 24 words instead'} sub="Drops your email and password" onPress={() => { void doSwitchToPhraseSignIn(); }} disabled={phraseBusy} />
        ) : null}
        {/* b76 (registration lock): on / change / off, each behind the app password */}
        {veilId && regLock !== undefined && onRegLockSet ? (
          <Row
            label={regLockBusy ? 'Working…' : 'Registration lock'}
            value={regLock === null ? undefined : regLock.enabled ? 'On' : 'Off'}
            sub={regLock?.enabled
              ? (regLockNotOwnerText(regLock) /* b76r1 (audit D3): a correct PIN elsewhere took the lock over */
                ?? (regLock.failedAttempts > 0
                  // b76r1 (audit D3): the count resets when the PIN is set AND when it is entered correctly
                  ? `${regLock.failedAttempts} wrong PIN ${regLock.failedAttempts === 1 ? 'try' : 'tries'} on another phone since the PIN was last set or entered correctly. Someone may have your 24 words.`
                  : 'Restoring this account on another phone needs your PIN'))
              : 'Ask for a PIN when your 24 words are used on another phone'}
            onPress={() => { if (regLock?.enabled) info('Registration lock', REGLOCK_EXPLAIN); else void doRegLockOn(false); }}
            disabled={regLockBusy}
          />
        ) : null}
        {veilId && regLock?.enabled && onRegLockSet ? <Row label="Change registration lock PIN" onPress={() => { void doRegLockOn(true); }} disabled={regLockBusy} /> : null}
        {veilId && regLock?.enabled && onRegLockOff ? <Row label="Turn off registration lock" onPress={() => { void doRegLockOff(); }} disabled={regLockBusy} /> : null}
        {/* b76r1 (audit P-4): another phone publishes this Vardum ID's one-time keys */}
        {veilId && opkElsewhereSince && onOpkReclaim ? (
          <Row
            label={opkBusy ? 'Working…' : 'One-time keys'}
            value="Another phone"
            sub={`Since ${new Date(opkElsewhereSince).toLocaleDateString(undefined, { day: 'numeric', month: 'short', year: 'numeric' })}. New contact requests may work only on that phone.`}
            onPress={() => { void doOpkReclaim(); }}
            disabled={opkBusy}
          />
        ) : null}
        {veilId ? <Row label="Move to a new phone" sub="Scan the code your new phone shows" onPress={() => { void openMove(); }} disabled={xferBusy || !!moveUi} /> : null}
        {veilId ? <Row label={recvBusy ? 'Receiving…' : 'Receive from old phone'} sub="Shows a code for your old phone to scan" onPress={() => { void doReceiveTransfer(); }} disabled={recvBusy} /> : null}
        {lastMove ? (
          <Row
            label="Last move"
            value={new Date(lastMove.at).toLocaleString()}
            sub={`${lastMove.count} chat${lastMove.count === 1 ? '' : 's'}, collected by the phone that showed ${lastMove.sas ?? 'the check code'}. Not you? Tap here.`}
            onPress={() => info('If this wasn\u2019t you', moveNotMeText(lastMove.sas))}
          />
        ) : null}
        {veilId ? (
          <Row
            label={settings.nickname ? 'Change nickname' : 'Set a nickname'}
            value={settings.nickname || undefined}
            onPress={async () => {
              const t = (await ask({
                title: 'Nickname',
                // b77k (IP77-3): shown in 1:1 chats too now
                message: 'The name members of your groups see next to your messages. It is signed and sent inside the group’s encryption, so Vardum’s server can’t read it. Anyone you have a one-to-one chat with sees it too, including someone who starts a chat through your invite link, next to your Vardum ID, sent inside that chat’s encryption. Leave it empty to appear as your Vardum ID.',
                input: 'text', defaultValue: settings.nickname ?? '', submitLabel: 'Save',
              })) as string | null;
              if (t === null) return;
              // b75r1 (audit G-2): the name members see in groups — one that reads like a notice from the app is refused
              const problem = groupNameProblem(t);
              if (problem) { info('Choose another nickname', problem); return; }
              set({ nickname: t.trim() });
            }}
          />
        ) : null}
        <Row label="Generate new Vardum ID" sub="New keys and new 24 words; same server account" onPress={doGenerateNewVeilId} last />
      </Group>
      {/* b75 (audit XF-1): OLD phone — scan the new phone's code, compare, send */}
      {moveUi?.step === 'scan' ? (
        <View style={styles.xferBox}>
          <Text style={styles.xferCount}>On your new phone: restore your 24 words{regLock?.enabled ? ' (it asks for your registration lock PIN too)' : ''}, then open Settings → Receive from old phone. Scan the code it shows.</Text>
          <TouchableOpacity style={styles.primaryBtn} disabled={xferBusy} onPress={() => setXferScan(true)}>
            <Text style={styles.primaryBtnTxt}>Scan the code</Text>
          </TouchableOpacity>
          <TextInput
            style={[styles.recvInput, { marginTop: 10 }]}
            autoCapitalize="none"
            autoCorrect={false}
            placeholder="…or paste the code"
            placeholderTextColor="#5E6464"
            value={recvInput}
            editable={!xferBusy}
            onChangeText={setRecvInput}
          />
          <TouchableOpacity
            style={[styles.primaryBtn, recvInput.length < 20 && styles.btnXferOff]}
            disabled={xferBusy || recvInput.length < 20}
            onPress={() => { void doCreateTransfer(recvInput); }}
          >
            {xferBusy ? <ActivityIndicator color="#FFFFFF" size="small" /> : <Text style={styles.primaryBtnTxt}>Continue</Text>}
          </TouchableOpacity>
          <TouchableOpacity onPress={() => setMoveUi(null)} disabled={xferBusy}>
            <Text style={styles.dismissTxt}>Cancel</Text>
          </TouchableOpacity>
        </View>
      ) : null}
      {moveUi?.step === 'check' ? (
        <View style={styles.xferBox}>
          <Text style={styles.xferCount}>Check the code</Text>
          <Text style={styles.sasTxt}>{moveUi.offer.sas}</Text>
          <Text style={styles.xferCount}>
            Your new phone should show the same 6 digits. Only send if they match.
            {' '}This moves {moveUi.offer.sessionCount} one-to-one chat{moveUi.offer.sessionCount === 1 ? '' : 's'}
            {moveUi.offer.groupsKept ? '; groups stay on this phone' : ''}. Your Vardum ID{'\u2019'}s private keys never leave this phone.
          </Text>
          <TouchableOpacity style={styles.primaryBtn} disabled={xferBusy} onPress={() => { void answerCheck(true); }}>
            {xferBusy ? <ActivityIndicator color="#FFFFFF" size="small" /> : <Text style={styles.primaryBtnTxt}>They match. Send</Text>}
          </TouchableOpacity>
          <TouchableOpacity onPress={() => { void answerCheck(false); }} disabled={xferBusy}>
            <Text style={styles.dismissTxt}>They don{'\u2019'}t match</Text>
          </TouchableOpacity>
        </View>
      ) : null}
      {moveUi?.step === 'sent' ? (
        <View style={styles.xferBox}>
          <Text style={styles.xferCount}>
            Sent. Waiting for your new phone to confirm it imported {moveUi.count === 1 ? 'the chat' : 'them'}. Until then
            {' '}{moveUi.count === 1 ? 'this chat is' : `these ${moveUi.count} chats are`} paused on this phone. If no confirmation arrives within about half an hour, Vardum asks you what to do.
          </Text>
          <TouchableOpacity onPress={() => setMoveUi(null)}>
            <Text style={styles.dismissTxt}>Close</Text>
          </TouchableOpacity>
        </View>
      ) : null}
      {/* b75 (audit XF-1 / XF-2): NEW phone — a code holding public keys only; there is no
          paste-a-bundle path any more */}
      {recvUi ? (
        <View style={styles.xferBox}>
          {recvUi.step === 'code' ? (
            <>
              <Text style={styles.xferCount}>On your old phone: Settings → Move to a new phone, then scan this code. It holds only public keys, so a photo of it can{'\u2019'}t take your chats.</Text>
              {recvQrOk ? (
                <View style={styles.xferQr}>
                  <QrCode text={recvUi.flow.code} size={220} />
                </View>
              ) : null}
              <TouchableOpacity onPress={() => { copySensitive(recvUi.flow.code).then(() => ask({ title: 'Code copied', message: 'Paste it on your old phone under Move to a new phone.', info: true })).catch(() => {}); }}>
                <Text style={styles.dismissTxt}>Copy the code instead</Text>
              </TouchableOpacity>
              <View style={styles.xferQr}><ActivityIndicator color="#FFFFFF" size="small" /><Text style={styles.xferQrTxt}>Waiting for your old phone…</Text></View>
            </>
          ) : (
            <>
              <Text style={styles.xferCount}>Check the code</Text>
              <Text style={styles.sasTxt}>{recvUi.sas}</Text>
              <Text style={styles.xferCount}>Your old phone should show the same 6 digits. If it does, confirm there. If it doesn{'\u2019'}t, cancel on both phones.</Text>
              <View style={styles.xferQr}><ActivityIndicator color="#FFFFFF" size="small" /><Text style={styles.xferQrTxt}>Waiting for your chats…</Text></View>
            </>
          )}
          <TouchableOpacity onPress={cancelReceive}>
            <Text style={styles.dismissTxt}>Cancel</Text>
          </TouchableOpacity>
        </View>
      ) : null}
      {recvMsg ? <View style={styles.xferBox}><Text style={styles.recvOk}>{recvMsg}</Text></View> : null}

      {/* ---- b71 (audit): usage counts are opt-in ---- */}
      <Group title="Usage counts" note="Off by default. When on, Vardum gets a few one-time milestones (account created, first chat opened, still using it after 7 and 30 days) with your account's sign-in, never content or contacts. They are deleted after 30 days.">
        <SwitchRow label="Share usage counts" on={!!settings.usageStats} onFlip={() => set({ usageStats: !settings.usageStats })} last />
      </Group>

      {/* ---- Help ---- */}
      <Group title="Help">
        <Row label="Run the privacy checkup" onPress={onRunCheckup} />
        <Row label="View the introduction" onPress={onViewIntro} />
        <Row label="Getting started" onPress={onOpenWelcome} />
        <Row label="Security Centre" value="Web" onPress={() => Linking.openURL(webBaseUrl + '/who-can-see-what/')} />
        <Row label="Report a problem" sub="support@tryveil.app — add your Vardum ID only if you want a reply" onPress={() => Linking.openURL('mailto:support@tryveil.app')} last />
      </Group>

      {/* ---- About ---- */}
      <Group title="About" note={`Free during the beta (${BETA_SOURCE}). At launch, Vardum is a one-off payment of A$14.99.`}>
        <View style={styles.infoRow}>
          <Text style={styles.rowLabel}>Version</Text>
          <Text style={styles.infoRowValue}>{APP_VERSION}</Text>
        </View>
        <View style={styles.infoRow}>
          <Text style={styles.rowLabel}>Build</Text>
          <View style={styles.infoRowValueWrap}><Text style={styles.infoRowValue}>{SOURCE_TAG} · native b{BUILD_NUMBER}{VEIL_RELAY_IS_STAGING ? ' · STAGING relay' : ''}</Text><Text style={styles.infoRowSub}>{BUILD_DATE}</Text></View>
        </View>
        <View style={styles.infoRow}>
          <Text style={styles.rowLabel}>Protocol</Text>
          <View style={styles.infoRowValueWrap}>
            <Text style={styles.infoRowValue}>{PROTOCOL_VERSION}</Text>
            <Text style={styles.infoRowSub}>{PROTOCOL_WIRE_TAG}</Text>
          </View>
        </View>
        <Row label="Privacy policy" onPress={() => Linking.openURL(webBaseUrl + '/privacy')} />
        <Row label="Terms of use" onPress={() => Linking.openURL(webBaseUrl + '/terms')} last />
      </Group>

      {/* ---- Danger zone ---- */}
      {/* ---- b77s (owner decision): account ---- */}
      {/* sign-out-others shows whenever offered (in decoy mode too, where it fails like the decoy's offline relay); change password only for an email account */}
      {onSignOutOtherDevices || (email && onChangeAccountPassword && !phraseSignIn) ? (
        <Group title="Account" note="With an app lock set, each of these asks for your app password first.">
          {onSignOutOtherDevices ? <Row label={accountBusy ? 'Working…' : 'Sign out all other devices'} sub="This phone stays signed in" onPress={() => { void doSignOutOthers(); }} disabled={accountBusy} last={!(email && onChangeAccountPassword && !phraseSignIn)} /> : null}
          {email && onChangeAccountPassword && !phraseSignIn ? <Row label="Change password" sub="Your email sign-in password" onPress={() => { void doChangeAccountPassword(); }} disabled={accountBusy} last /> : null}
        </Group>
      ) : null}

      <Group title="Danger zone" note="Each of these asks you to confirm first.">
        <Row label="Sign out" onPress={async () => { if (await passwordOk('Required to sign out and wipe this phone.')) onSignOut(); }} chevron={false} />
        {veilId ? (
          <Row
            label={identityArmed ? 'Tap again to remove the identity' : 'Remove identity from this phone'}
            sub="Removes your ID keys and notes key; chats and history stay. Only your 24 words restore it"
            danger
            chevron={false}
            onPress={doRemoveIdentity}
          />
        ) : null}
        <Row
          label={wipeArmed ? 'Tap again within 6 seconds to wipe' : 'Wipe Vardum from this phone'}
          sub="No recovery from this phone"
          danger
          chevron={false}
          onPress={async () => {
            if (!wipeArmed) { armWipe(); return; }
            setWipeArmed(0);
            if (!(await passwordOk('Required to wipe Vardum from this phone.'))) return;
            onWipeDevice();
          }}
        />
        <Row
          label="Delete account"
          danger
          chevron={false}
          last
          onPress={async () => {
            const t = (await ask({
              title: 'Type DELETE to confirm',
              message: 'Permanently deletes everything this account owns on Vardum’s server (chats and their messages, vaults, notes, contacts, transfer links, group memberships and published identities) plus the keys on this phone. Encrypted files you uploaded may remain on the server as unreadable data, and the server’s storage and backups can keep encrypted copies for up to about 15 days. This can’t be undone, and nothing is deleted until you confirm.',
              input: 'text',
              submitLabel: 'Delete everything',
            })) as string | null;
            if (t === null) return;
            if (t.trim() !== 'DELETE') { await ask({ title: 'Nothing was deleted', message: 'Type DELETE to confirm.', info: true }); return; }
            if (!(await passwordOk('Required to delete your account.'))) return;
            onDeleteAccount();
          }}
        />
      </Group>

      <View style={styles.footer}>
        <Text style={styles.footerTitle}>Vardum — private messaging, under your control.</Text>
      </View>
    </ScrollView>
    {sheetNode}
    {promptNode}
    {xferScan ? (
      <QrScanner
        title="Scan your new phone's code"
        hint="On your new phone: Settings → Receive from old phone. Point this camera at the code it shows."
        rejectNote="That isn’t a Vardum move code. Scan the one on your new phone."
        accept={(raw) => { try { parseMoveCode(raw); return raw.trim(); } catch { return null; } }}
        onFound={(code) => { setXferScan(false); void doCreateTransfer(code); }}
        onClose={() => setXferScan(false)}
      />
    ) : null}
    {shareNode}
    </View>
  );
}

const styles = StyleSheet.create({
  fill: { flex: 1, backgroundColor: '#0B0B0F' },
  content: { padding: 16, paddingBottom: 60 },
  headline: { color: '#FFFFFF', fontSize: 22, fontWeight: '700', letterSpacing: 1, marginBottom: 12, marginLeft: 4 },
  // grouped list (b199): one inset card per group, hairline row dividers
  groupWrap: { marginTop: 18 },
  groupTitle: { color: '#FFFFFF', fontSize: 11, fontWeight: '800', letterSpacing: 0.8, textTransform: 'uppercase', marginBottom: 6, marginLeft: 6 },
  group: { backgroundColor: '#15151B', borderWidth: 1, borderColor: '#24242D', borderRadius: 12, overflow: 'hidden' },
  groupNote: { color: '#8E9696', fontSize: 11, lineHeight: 16, marginTop: 6, marginHorizontal: 6 },
  row: { flexDirection: 'row', alignItems: 'center', paddingVertical: 13, paddingHorizontal: 14, borderBottomWidth: 1, borderBottomColor: '#24242D', minHeight: 48 },
  rowLast: { borderBottomWidth: 0 },
  rowMid: { flex: 1, paddingRight: 10 },
  rowLabel: { color: '#FFFFFF', fontSize: 14, fontWeight: '500' },
  rowLabelOff: { color: '#5E6464' },
  rowSub: { color: '#8E9696', fontSize: 11, lineHeight: 15, marginTop: 2 },
  rowValue: { color: '#8E9696', fontSize: 13, maxWidth: '50%', textAlign: 'right' },
  rowChevron: { color: '#4A4A54', fontSize: 20, marginLeft: 8, marginTop: -2 },
  accentTxt: { color: '#FFFFFF' },
  dangerTxt: { color: '#e8836f' },
  switchTrack: { width: 46, height: 28, borderRadius: 14, backgroundColor: '#24242D', padding: 3, justifyContent: 'center' },
  switchTrackOn: { backgroundColor: '#FFFFFF' },
  switchTrackDanger: { backgroundColor: '#e8836f' },
  switchOff: { opacity: 0.4 },
  switchKnob: { width: 22, height: 22, borderRadius: 11, backgroundColor: '#5E6464' },
  switchKnobOn: { backgroundColor: '#0B0B0F', alignSelf: 'flex-end' },
  // key storage segmented control (owner: descriptions in light orange)
  segWrap: { padding: 12, borderBottomWidth: 1, borderBottomColor: '#24242D' },
  seg: { flexDirection: 'row', borderWidth: 1, borderColor: '#3A3A44', borderRadius: 9, overflow: 'hidden' },
  segItem: { flex: 1, paddingVertical: 9, paddingHorizontal: 4, alignItems: 'center' },
  segItemOn: { backgroundColor: 'rgba(255,255,255,0.14)' },
  segTxt: { color: '#8E9696', fontSize: 12, fontWeight: '600' },
  segTxtOn: { color: '#FFFFFF', fontWeight: '800' },
  keyModeDesc: { color: '#d69a5c', fontSize: 12, lineHeight: 17, marginTop: 10 },
  sdBox: { borderWidth: 1, borderColor: '#e8836f', borderRadius: 10, padding: 12, marginTop: 8 },
  sdTxt: { color: '#e8836f', fontSize: 12, lineHeight: 16 },
  sdExtendBtn: { marginTop: 8, alignSelf: 'flex-start' },
  sdExtendTxt: { color: '#FFFFFF', fontSize: 12, fontWeight: '700' },
  primaryBtn: { borderWidth: 1, borderColor: '#FFFFFF', borderRadius: 10, padding: 12, alignItems: 'center', marginTop: 10 },
  primaryBtnTxt: { color: '#FFFFFF', fontSize: 13, fontWeight: '700' },
  dismissTxt: { color: '#FFFFFF', fontSize: 12, textAlign: 'center', paddingTop: 10 },
  xferBox: { borderWidth: 1, borderColor: '#3A3A44', borderRadius: 12, padding: 12, marginTop: 8, backgroundColor: 'rgba(255,255,255,0.05)' },
  xferQr: { alignItems: 'center', marginVertical: 10 },
  xferQrTxt: { color: '#C9CFCE', fontSize: 12, lineHeight: 17, textAlign: 'center', marginTop: 8 },
  xferCount: { color: '#C9CFCE', fontSize: 12, lineHeight: 17 },
  recvInput: { color: '#FFFFFF', backgroundColor: '#0B0B0F', borderWidth: 1, borderColor: '#24242D', borderRadius: 10, paddingHorizontal: 12, paddingVertical: 10, fontSize: 12 },
  recvOk: { color: '#FFFFFF', fontSize: 12, lineHeight: 17, marginTop: 8 },
  sasTxt: { color: '#FFFFFF', fontSize: 34, fontWeight: '700', letterSpacing: 4, textAlign: 'center', marginVertical: 12 },
  btnXferOff: { opacity: 0.35 },
  infoRow: { flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center', paddingVertical: 12, paddingHorizontal: 14, borderBottomWidth: 1, borderBottomColor: '#24242D' },
  infoRowValue: { color: '#8E9696', fontSize: 12, fontFamily: 'monospace', flexShrink: 1, textAlign: 'right' },
  infoRowValueWrap: { flex: 1, alignItems: 'flex-end', marginLeft: 12 },
  infoRowSub: { color: '#5E6464', fontSize: 10, fontFamily: 'monospace', marginTop: 2, textAlign: 'right' },
  footer: { marginTop: 28, alignItems: 'center' },
  footerTitle: { color: '#5E6464', fontSize: 11, textAlign: 'center' },
  idCard: { borderWidth: 1, borderColor: '#3A3A44', borderRadius: 14, padding: 14, backgroundColor: '#15151B' },
  idCardHead: { flexDirection: 'row', alignItems: 'center', gap: 10 },
  idCardLogo: { width: 40, height: 40, borderRadius: 10 },
  idCardKicker: { color: '#5E6464', fontSize: 10, letterSpacing: 1.5, textTransform: 'uppercase', marginBottom: 3 },
  idCardId: { color: '#FFFFFF', fontSize: 17, fontWeight: '800', letterSpacing: 0.5 },
  idCardCopy: { color: '#FFFFFF', fontSize: 13, fontWeight: '800', paddingHorizontal: 8, paddingVertical: 6 },
  idCardLine: { color: '#8E9696', fontSize: 12, marginTop: 10 },
  idCardQr: { borderWidth: 1, borderColor: '#3A3A44', borderRadius: 8, paddingHorizontal: 9, paddingVertical: 5, marginRight: 2 },
  idCardQrTxt: { color: '#FFFFFF', fontSize: 12, fontWeight: '800', letterSpacing: 0.5 },
  idCardDivider: { height: 1, backgroundColor: '#24242D', marginVertical: 12 },
  idCardNick: { color: '#FFFFFF', fontSize: 17, fontWeight: '800', letterSpacing: 0.3 },
  idCardNickOff: { color: '#5E6464', fontWeight: '600' },
});
