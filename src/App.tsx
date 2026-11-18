import { secureRemove, secureRemoveMany, setGatedKeysActive, wipeAndVerify } from '../vendor/device/src/secure-wipe';
import { CallManager } from './calls/CallManager';
import { CallOverlay } from './components/CallOverlay';
import { PrivacyCover } from './PrivacyCover'; // b71 (audit F-22)
import { adoptNotesIdentityKey, NOTES_KEY_STORAGE, noteMetaOf } from '../vendor/device/src/notes';
import { secureEnclaveAvailable, keyvaultHardwareProtected, keyvaultProtectionState /* b77t2 (CL-5) */, resetSecureEnclaveKey, deleteSecureEnclaveKey, rebindContainerKey } from './secure-store.rn';
import React, { useEffect, useRef, useState, useCallback, useMemo } from 'react';
import { Alert, AppState, ActivityIndicator, Linking, View, Text, StyleSheet, Image, Keyboard, SafeAreaView, Platform } from 'react-native';
import { SafeAreaProvider, useSafeAreaInsets } from 'react-native-safe-area-context';
import * as LocalAuthentication from 'expo-local-authentication';
import * as ScreenCapture from 'expo-screen-capture';
import { Audio } from 'expo-av';
import { startScreenWatch } from './screen-watch';
import { createVeilApp, createDecoyApp, createDecoyEndClients, VEIL_LINK_URL, VEIL_SITE_URL, DECOY_RELAY_REFUSAL, VEIL_BASE_URL, type VeilApp } from './veil-app';
import { relayHomeCheck, RELAY_MOVED_TITLE, RELAY_MOVED_TEXT } from './relay-home'; // b77 rollout: an older build's login on the new relay
import { carryIdToThisRelay } from './relay-move-restore'; // b77 rollout: Restore keeps an old Vardum ID
import { setUnifiedPushSilent } from './unifiedpush'; // b74 (review VAR-03)
import { purgeIfFreshInstall, forgetLaunchRecords } from './fresh-install-guard';

import { prepareMove, confirmMove, cancelMove, startReceive, waitForOffer, receiveMove, cancelReceive, finishTransferMove, loadPendingTransfers, keepMovedChatsHere, removeMovedChatsHere, markTransferAsked, loadLastMove, MOVE_PAUSE_CAP_MS, type PendingTransfer, type PreparedMove } from '../vendor/device/src/transfer';
import { moveNotMeText } from './screens/SettingsScreen';
import { decoySettingsView } from './decoy-settings'; // b77t2 (decoy gaps)
import { useThemedPrompt, type PromptSpec } from './screens/ThemedPrompt'; // b77t (audit 5 L-20)
import { AccountPromptGate, type AskForOptions, type PromptGateState } from './prompt-gate'; // b77t2 (CM-2)
import { relayClockNow, setRelayClockUptime } from './relay-clock'; // b77t (audit 5 L-4)
import { startProtectedDataWatch } from './protected-data'; // b77t (audit 5, iOS screen lock)
import { refreshPurgeToken, readPurgeToken, purgeWithStoredToken, revokePurgeTokenRemote, DURESS_PURGE_TOKEN_KEY /* b77u merge (W1) */ } from './duress-purge-token'; // b77t (audit 5 L-5)
import { relayErrorCode } from '../vendor/device/src/relay-errors'; // b77u merge (relay U-M14: current_password_required)
import { DECOY_PREFIX /* b77u (U-M5) */, DecoyAux, prepareDecoy, ensureDecoyAccount, DecoyEnd, endDecoy, deleteDecoyAccount, decoyEndDelayMs, currentDecoyEnd /* b77t2 (info) */, type DecoyEndEntry } from './decoy-account'; // b77t (audit 5 M-E); merge: decoy account delete
/** b77t (audit 5 M-E): the decoy session's account: its app (its own stores, login and relay client), its
 *  identity once registered, and its Vardum ID (known before the relay is reached; null if the decoy store
 *  refused, and the old placeholder ID shows) */
type DecoyAccount = { app: VeilApp; identity: KeyvaultIdentity | null; veilId: string | null; /** the wipe generation it was opened in */ gen: number };
import { createInviteSession, joinInviteSession } from '../vendor/device/src/invite';import * as ImagePicker from 'expo-image-picker';
import * as FileSystem from 'expo-file-system';
import { tmpPath, purgeTmp, deleteQuietly, sweepAllLocalFiles, adoptIntoTmp } from './local-files';
import { wipeLeftoverNotice, WIPE_LEFTOVER_TITLE } from './wipe-leftovers'; // b77u (audit 6 U-M13)
import * as MediaLibrary from 'expo-media-library';
import { LoginScreen } from './screens/LoginScreen';
import { OtpScreen } from './screens/OtpScreen';
import { MainScreen } from './screens/MainScreen';
import { IdentityScreen } from './screens/IdentityScreen';
import { ChatScreen, MEDIA_GONE, type ChatMessageUI, type PendingPick } from './screens/ChatScreen';
import { LockScreen } from './screens/LockScreen';
import { wipeStarted, wipeBusy, onWipeBusy, waitWipeIdle } from './wipe-busy'; // b77k (IP77-6)
import { mediaSaveType, neutralSaveName /* b77s (audit 4 DV-5) */ } from './media-save-type'; // audit VAR-39 (1f51)
import { flipCapture, carryIntoMemory, leaveMemoryMode, retryLeaveMemoryMode, startNarSession, startDecoyNarSession /* b77u (U-M5) */, dropDecoyNarSession /* b77u2 (UC-M1) */ } from './nar-memory';
import { TempMediaTracker } from './nar-temp-media'; // b77k2 (review L-4) // b77k2 (IP77-5)
import { createNickIntroScheduler, createPeerNickRefreshLimiter, nickIntroAllowed } from './nick-intro-schedule'; // b77k2 (review L2); audit VAR-21
import type { ChatDelivery } from '../vendor/crypto-core/src/index';
import { clearFailedBodyCache } from '../vendor/crypto-core/src/ratchet'; // b77s (audit 4 CR-1 / A-04)
import { imageReencodePlan, reencodedName, IMAGE_STRIP_FAILED, stripPngMetadata, neutralSendName, motionStripPlan, stripGifMetadata, neutralizeVideoMetadata, VIDEO_META_WARNING /* b77u (W10) */, hasTimedMetadataTrack /* b77u2 (UC info) */ } from './media-strip'; // b77s (audit 4 DV-4); b77t (L-19)
import { clearAppCookies } from './cookie-clear'; // b77s (audit 4 A-01)

/** b199: photos are shrunk to this long edge (px) before encrypting + sending */
const MEDIA_PHOTO_MAX_EDGE = 2048;
/** b77t (audit 5 L-18, IH V-11): the open chat loads the newest this many media messages by itself; older ones on a tap */
const MEDIA_AUTO_LOAD = 12;

/** auto-lock §0: shared module-level last-interaction clock. The root view's
 *  touch responder lives outside <VeilApp/>'s scope, so the inactivity clock
 *  must be module state, not a ref inside the component. */
let VEIL_LAST_ACTIVITY = Date.now();

/**
 * b111 (owner directive: "no errors like that coming up at all"): every error
 * path that reaches the SCREEN must speak human. The raw exception (message +
 * stack) still flows to the Metro console for diagnosis, but the UI never shows
 * internal strings — the build-35 lesson was a mate staring at
 * "Media picker returned nothing (canceled=true…)" like it was a hex dump.
 */
function friendlyError(e: unknown, what: string): string {
  const err = e as Error;
  const raw = String(err?.message ?? e);
  console.log(`[veil-error] ${what}:`, raw, err?.stack ?? '');
  // b77r1 (audit A-5): the sealed-delivery errors are already written for people
  if (err?.name === 'OutboxFullError' || err?.name === 'MailboxNotOpenError' || err?.name === 'MailboxRetiredError') return raw;
  // b77k (IP77-2): so are a group's "can't send yet" reasons (not admitted yet, keys to refresh)
  if (err?.name === 'GroupSendBlockedError' || err?.name === 'GroupKeysStaleError') return raw;
  // b77g (G-2 / G-3): the restore's flag-save refusal and the uncertain account delete say what happened
  if (raw === RESTORE_FLAG_SAVE_FAILED || err?.name === 'DeleteUncertainError') return raw;
  // b77p (audit 2, VAR-28 / VAR-11): already written for people (not the 25 MB file message)
  if (err?.name === 'MessageTooLongError' || err?.name === 'MediaTooLargeError') return raw;
  const s = raw.toLowerCase();
  if (s.includes('network') || s.includes('timeout') || s.includes('fetch') || s.includes('request failed'))
    return 'Connection problem — check your internet and try again.';
  if (s.includes('permission') || s.includes('not authorized') || s.includes('denied'))
    return PERMISSION_DECLINED;
  // b77m merge (audit VAR-31): the PNG decoder's dimension / data cap is not the 25 MB media limit
  if (s.includes('unsupported png: the image is too large'))
    return 'This image is too large to open — Vardum reads images up to 40 megapixels (20,000 pixels a side). Pick a smaller image.';
  if (s.includes('100 mb') || s.includes('25 mb') || s.includes('too large') || s.includes('size'))
    return 'That file is too large — the limit is 25 MB per message.';
  if (s.includes('session not found') || s.includes('no longer') || s.includes('gone'))
    return 'That session is no longer available.';
  if (s.includes('credentials') || s.includes('password') || s.includes('email'))
    return 'Those sign-in details did not work — check them and try again.';
  if (s.includes('biometr') || s.includes('face id') || s.includes('keychain'))
    return `${BIOMETRIC_SHORT} / secure storage could not complete — try again.`;
  if (s.includes('rate limit'))
    // b175 (owner Metro repro, Oct 2: burst send surfaced a raw-feeling
    // "Something went wrong" during a transient relay throttle): the relay's
    // anti-abuse limiter is a few-second self-healing cooldown, not a real
    // failure — say so plainly instead of falling through to the scary
    // generic bucket. The composer keeps the drafted text either way.
    return 'The server is briefly busy — wait a few seconds and try again.';
  return 'Something went wrong — please try again.';
}

const veilActivityPing = () => { VEIL_LAST_ACTIVITY = Date.now(); };
import { OnboardingScreen } from './screens/OnboardingScreen';
import { autoLockHeld, releaseAllHolds, setHoldEndedHook, withSystemSheet, systemSheetExpected, expectSystemSheet, SYSTEM_SHEET_MS, setSystemSheetPolicy, systemSheetLeftMs } from './lock-hold';
import { deleteSavedMedia, saveToChosenFolder, usesFolderPicker, trackSavedMedia } from './saved-media';
import { stashPendingMedia, readPendingMedia, finishPendingMedia } from './saved-media-pending';
import { clearSensitiveNow } from './clipboard-guard';
import { WelcomeScreen } from './screens/WelcomeScreen';
import { APPLOCK_KEY, type AppLockRecord, type LockoutState, MAX_ATTEMPTS, AppLockWrongCodeError, AppLockErasedError, resetLockMacKey, uptimeMs } from '../vendor/device/src/applock';
import { bumpWipeGeneration, currentWipeGeneration, pinToWipe, unwrapPinned /* b77t2 (CL-8) */ } from '../vendor/device/src/wipe-generation';
import { relayTimestampToIso } from '../vendor/device/src/time';
import { relaySessionLiveness } from '../vendor/device/src/session-liveness';
import { burnWindow, userText, locallyVerified, markLocallyVerified, clearLocalVerification, sessionDials /* b77u (W8) */ } from '../vendor/device/src/chat';
import { QuietLedger, quietWindowMs, QUIET_CHECK_MS, endQuietChats } from './quiet-chats'; // b77u (audit 6 W8); b77u2 (UC-L1)
import { KEYVAULT_KEY, readNarMarker, writeNarMarker } from '../vendor/device/src/keyvault'; // b77m review (M1): + the Nothing-at-Rest marker
import { buildCapturePayload } from '../vendor/device/src/capture-notice'; // b75r2 (audit P-1)
import { contactRequestCheck, isVardumIdShape, requestDisplayBinding, acceptFailureMessage } from '../vendor/device/src/contact'; // b75r2 (audit P-2); b75r3 (PR3-01)
import { chatGoneAnswers, confirmSessionGone, confirmGoneLater } from '../vendor/device/src/session-liveness'; // b75r2 (audit P-4)
import { unverifiedTitle, peerNickTitle, peerNickNote /* b77k (IP77-3) */ } from '../vendor/device/src/names';
import { sealedPeer, sealedPeerMatches, pickContactSession } from '../vendor/device/src/contact';
// b77 (sealed sender): 1:1 chats live on anonymous mailboxes; the chat list comes from this phone's records
import { isPreSealedChat, chatDelivery, endSealedChat, wipeDeliveries, startWipeEnds /* b77g (NaR-1): the wipes' ends from the in-memory capabilities */, NAR_CAPTURE_FALLBACK_MS /* b77h (H-2) */, scheduleDelayedSealedEnds /* b77f (A-7) */, SUPERSEDE_INBOUND_MIN_MS, SUPERSEDE_INBOUND_MAX_MS /* b77f2 (F-4) */, syncInboundVerified, setWakeTargetProvider /* b77p (audit 2 VAR-01) */, withWakeKey /* b77u (audit 6 W6) */, readHandshakeStatus, secureRandomUnit /* b77n (INFO-3) */ } from '../vendor/device/src/sealed';
import { currentWakeTarget, dismissDeliveredNotifications /* b77u (W11) */ } from './notifications';
import { registerPushToken, unregisterCachedPushToken, unregisterPushLocally, releaseOsPushToken, capturePushTarget, type PushTarget, notifyNewMessage, notifyNewInvite, setLocalNotifySuppressed } from './notifications';
import { createDecoyPushGate, PUSH_HOLD_KEY, holdRecord, holdState } from './decoy-push'; // b75 (audit DEV-L3); b75 round 2 (audit D3): the hold survives a restart
import { runDuressWipe, eraseLocal, retryPushUnregister, WIPE_PENDING_KEY, PUSH_UNREG_PENDING_KEY, settleLeftoverWipe /* b77u merge (U-M13) */, type DuressRelay, type EraseReport } from './duress-wipe'; // Batch I (V-01); b70 (re-review 14): the marker set while a wipe runs, finished at launch

/** b75 (audit DEV-L3): the app's push registration (set by the component while an
 *  identity is loaded), run through the decoy gate below */
let registerPushHook: (() => Promise<unknown>) | null = null;
/** b75 (audit DEV-L3): decoy mode releases the OS push token on the phone (no network,
 *  no relay change) so the real account's banners stop; the real unlock registers again */
/** b75 round 2 (audit D3): the real app's store, where the decoy push hold is kept (set at launch) */
let pushHoldStore: { set(k: string, v: string): Promise<unknown>; remove(k: string): Promise<unknown> } | null = null;
const decoyPush = createDecoyPushGate({
  setUnifiedPushSilent,
  releaseOsToken: releaseOsPushToken,
  register: async () => (registerPushHook ? registerPushHook() : false),
  setLocalSuppressed: setLocalNotifySuppressed, // b75 round 2 (D3): in-app banners stay off while held
  // b77t (audit 5 L-3): the record stays, '1' or '0' (same shape on every install); only a wipe removes it
  saveHold: async (on) => { if (pushHoldStore) await pushHoldStore.set(PUSH_HOLD_KEY, holdRecord(on)); },
  dropHold: async () => { if (pushHoldStore) await pushHoldStore.remove(PUSH_HOLD_KEY); },
  log: (m) => console.log(m),
  generation: currentWipeGeneration, // b75 round 3 (audit DV-3): a step asked before a wipe does nothing after it
});
/** b73 (audit V-14): the opt-in erase-after-N-wrong-passwords limit. b74 (review VAR-04):
 *  counted inside AppLockStore.verify, so every password check counts. */
const WIPE_AFTER_FAILS = 10;
/** b77k (IP77-6): the longest an unlock attempt waits for a running wipe to end */
const WIPE_IDLE_WAIT_MS = 20_000;
/** b77m review (M1): a boot that found the key storage unreadable with the app on screen checks again this soon */
const NAR_BOOT_RECHECK_MS = 3_000;

/** Batch G (round-5 review R5-1-04): names the user gave invite chats, per chat */
const THREAD_NAMES_KEY = 'veil_thread_names_v1';
/** Call quality (20 Oct 2026): poll cadence while a call is ringing or connecting */
const CALL_SETUP_POLL_MS = 750;
async function loadThreadNames(storage: { get(k: string): Promise<string | null> }): Promise<Record<string, string>> {
  // b75r3 (audit I-5): a null-prototype map of strings — looked up by relay tokens, so a token
  // like "constructor" must find nothing, never an inherited function
  const out: Record<string, string> = Object.create(null);
  try {
    const raw = await storage.get(THREAD_NAMES_KEY); const v = raw ? JSON.parse(raw) as unknown : {};
    if (v && typeof v === 'object' && !Array.isArray(v)) for (const [k, n] of Object.entries(v)) if (typeof n === 'string') out[k] = n;
  } catch { /* unreadable: no names */ }
  return out;
}

/** Batch F (round-4 review R4-4-17): every wipe drops this phone's push
 *  registration on the relay (while still signed in), so a wiped phone gets no
 *  more banners. It used to happen only on a Nothing-at-Rest lock.
 *  Batch H (round-6 reviews R6-1-01 / R6-3-10): a wipe reads the target BEFORE
 *  wiping (the wipe deletes the cached token) and unregisters AFTER the local wipe
 *  has started, passing the target it read. */
async function dropPushRegistration(a: { relay: { invoke(fn: string, p: Record<string, unknown>): Promise<unknown>; entityCreate(e: string, r: Record<string, unknown>): Promise<unknown>; entityList(e: string, p: Record<string, string | number>): Promise<unknown>; entityDelete(e: string, id: string): Promise<unknown> }; storage: { get(k: string): Promise<string | null>; set(k: string, v: string): Promise<unknown> } } | null | undefined, target?: PushTarget | null): Promise<boolean> {
  if (!a) return false;
  // Batch G (R5-3-04): the cached token only (no OS prompt), and never more than 3 s
  // b75 (audit AL-7): resolves true only once the relay rows are gone (the wipe keeps
  // its unregister-pending marker otherwise)
  try {
    return await Promise.race([
      unregisterCachedPushToken({
        invoke: (fn, p) => a.relay.invoke(fn, p), // Batch H (R6-3-09)
        entityCreate: (e, r) => a.relay.entityCreate(e, r),
        entityList: (e, pr) => a.relay.entityList(e, pr),
        entityDelete: (e, id) => a.relay.entityDelete(e, id),
        getCached: (k) => a.storage.get(k),
        setCached: (k, v) => a.storage.set(k, v) as never,
      }, target),
      new Promise<boolean>((resolve) => setTimeout(() => resolve(false), 3000)),
    ]);
  } catch { return false; /* never block a wipe on the network */ }
}

/** Batch H (R6-1-01): read the push target before a wipe deletes the cached token */
/** Batch I (local review V-03): save a key-change revocation, retrying a
 *  refused save (2, 4, 8, 16, 32 s). The in-memory revocation set keeps the
 *  send gate closed meanwhile; a save that never lands is logged, not hidden. */
function persistRevocation(sessions: Parameters<typeof clearLocalVerification>[0], token: string, attempt = 0, after?: () => void): void {
  // b77 (sealed sender): once the revocation is saved, `after` clears the inbound's verified flag too
  clearLocalVerification(sessions, token).then(() => after?.()).catch((e: Error) => {
    if (attempt >= 4) { console.log(`[veil] revocation for ${token.slice(0, 6)}… not saved after retries: ${e.message}`); return; }
    setTimeout(() => persistRevocation(sessions, token, attempt + 1, after), 2000 * 2 ** attempt);
  });
}

async function capturePushTargetOf(a: { storage: { get(k: string): Promise<string | null> } } | null | undefined): Promise<PushTarget | null> {
  return a ? capturePushTarget((k) => a.storage.get(k)) : null;
}

/** Batch H (round-6 review R6-1-02): crypto-shred the hardware-mode identity at a
 *  wipe. The gated key is deleted without a write (a write showed a biometric
 *  prompt on Android); resetting the hardware wrap key makes any surviving copy
 *  of the wrapped blob useless. Key generation needs no biometric, so no prompt. */
async function shredHardwareKey(opts: { keepLock?: boolean } = {}): Promise<void> {
  // b75 (audit AL-10): deleted, not reset — a reset made a fresh key at once, so a wiped
  // phone still held a Vardum hardware key (the next hardware-mode seal makes a new one)
  try { await deleteSecureEnclaveKey(); } catch { /* best-effort, silent */ }
  // b70 (VAR-07): the app-lock hardware key goes too — but only where the lock
  // record goes with it (re-review: Nothing-at-Rest keeps the lock, and a reset
  // key made its codes, duress included, unmatchable forever)
  if (!opts.keepLock) await resetLockMacKey();
}

/**
 * b70 (re-review): a wipe freezes key writes for its duration, so a background
 * sync that loaded a chat before the wipe can't save its keys back after it.
 * The returned function ends the wipe: three seconds later (in-flight syncs
 * settled) one more pass removes anything that slipped in, then writes resume.
 */
function beginWipe(a: VeilApp, keep: string[] = [], opts: { clearClipboard?: boolean; ended?: Map<string, ChatDelivery> } = {}): () => void {
  bumpWipeGeneration(); // b70 (re-review 2, D2-2): syncs that started before this can't write after it
  try { dismissDeliveredNotifications(); } catch { /* best-effort */ } // b77u (audit 6 W11): the delivered banners and the badge go with every wipe
  clearGroupRegistry(a.storage); // b70 (re-review 8): no group record survives in memory
  // b70 (re-review 11): a live call ends with the wipe (its overlay, with the real
  // contact's name, used to stay up over the post-wipe screens)
  try { CallManager.hangup(); } catch { /* no call */ }
  // b70 (re-review 8): the crash marker lives outside the wipe index (written straight to
  // the keychain by the fatal-error handler), so it is removed by name
  try {
    const KC = require('react-native-keychain') as { resetGenericPassword: (o: unknown) => Promise<boolean> };
    void KC.resetGenericPassword({ service: 'veil.veil_sess_crash' }).catch(() => undefined);
  } catch { /* keychain module unavailable */ }
  // b70 (re-review 4): what Vardum copied (a transfer link, chat text) goes with
  // it — except at Nothing-at-Rest's every-departure wipe, where it would break copy-and-paste
  if (opts.clearClipboard !== false) void clearSensitiveNow();
  // b75 (audit DEV-L4): what lives only in memory goes too: the notes key (its stored copy
  // is wiped; the object kept opening notes for the rest of the run), the cached TURN
  // credentials and the seen-call ids
  try { a.notes.forget(); } catch { /* best-effort */ }
  // b77k2 (re-review L1 / review L-1): a login kept only in memory goes too (set aside for this wipe's
  // cleanup to revoke) — not at Nothing-at-Rest, which keeps the login
  try { if (!keep.includes('veil_auth_session')) a.auth.forgetUnsaved(); } catch { /* best-effort */ }
  // b77g (NaR-1): the chats' capabilities held in memory. b77h (audit77g H-1): this also latches the
  // cache shut (the wipe's own reads can't fill it again) until a deliberate fresh start
  let deliveriesEpoch: number | undefined;
  // b77k2 (L1): `ended` = the capabilities this wipe took to end; only those leave the held set.
  // b77k2 (re-review L4): a full wipe (nothing kept) drops every held one
  try { deliveriesEpoch = a.sessions.forgetDeliveries(undefined, keep.length ? opts.ended : 'all'); } catch { /* best-effort */ }
  try { CallManager.forgetAfterWipe(); } catch { /* best-effort */ }
  try { void decoyPush.forget(); } catch { /* best-effort */ } // b75 (audit DEV-L3): a wipe ends decoy mode without registering push again
  // (b75 round 2, audit D6: a registration waiting for its push-verify code ended here — b77p round 2: there is no
  // push-verify any more, the account push row is gone)
  const st = a.storage as unknown as { freezeWrites?: (on: boolean, keep?: string[]) => void };
  // b75 round 2 (audit D5): when the freeze ends, only the kept records may be written
  // again until a deliberate fresh start (create / restore an identity, sign in)
  st.freezeWrites?.(true, keep);
  // b77s (audit 4 CR-1 / A-04): the ratchet's cached tampered-copy message keys go with every wipe (sign-out, delete
  // account, self-destruct, wipe device, duress, Nothing-at-Rest); beginWipe is synchronous, so this runs before the
  // wipe's first asynchronous step. A-01: and the app's cookies (native, best-effort; absent in older native builds)
  try { clearFailedBodyCache(); } catch { /* best-effort */ }
  try { void clearAppCookies(); } catch { /* best-effort */ }
  return () => {
    setTimeout(() => {
      void wipeAndVerify(a.storage, 'veil_', keep).catch(() => -1).finally(() => {
        // b77h (H-1): and emptied again after the verify pass (unless a fresh start came in between)
        try { if (deliveriesEpoch !== undefined) a.sessions.forgetDeliveries(deliveriesEpoch); } catch { /* best-effort */ }
        st.freezeWrites?.(false);
      });
    }, 3000);
  };
}


/** Batch H (round-6 review R6-1-08): the self-destruct clock has run out */
function selfDestructDue(st: VeilSettings): boolean {
  if (!(st.selfDestruct && st.selfDestructArmedAt)) return false;
  // b74 (review VAR-11; owner decision): a clock set back while the countdown is armed
  // is tampering, and fires the self-destruct at once — only a set-back seen during THIS
  // arming counts (re-audit N3A: one from before arming wiped the phone the moment the
  // countdown was turned on)
  if (selfDestructClockTamperedFor === st.selfDestructArmedAt) return true;
  // b70 (re-review 7): the latest time this phone has ever shown counts, so setting
  // the clock back can't hold the countdown off
  const now = Math.max(Date.now(), selfDestructSeenMax);
  // b77t (audit 5 L-4 / IH DEV-2): and the elapsed-time floor (the relay's clock when online; the stored
  // high-water mark moved on by the boot clock, across restarts too), so a restart plus a clock set back
  // no longer holds the countdown off once the phone is online, and offline it keeps counting
  return Math.max(now, selfDestructFloorNow(st.selfDestructArmedAt)) - st.selfDestructArmedAt >= SELF_DESTRUCT_HOURS * 3600000;
}

/** b77t (audit 5 L-4): the relay's time now, or null (relay-clock.ts relayClockNow; set by the app) */
let selfDestructRelayNow: () => number | null = () => null;
/** b77t (L-4): "the real time was at least `at` when the boot clock read `up`", for the arming `armed`. Kept
 *  in SELF_DESTRUCT_SEEN_KEY (fl / flUp). A restart since (boot clock lower than `up`) still counts: the time
 *  since boot passed after the record was written, so the floor is at + boot clock. Never moves backwards. */
let selfDestructFloor: { armed: number; at: number; up: number | null } = { armed: 0, at: 0, up: null };
function selfDestructFloorNow(armed: number): number {
  let t = 0;
  if (armed && selfDestructFloor.armed === armed) {
    t = selfDestructFloor.at;
    const up = uptimeMs();
    if (selfDestructFloor.up !== null && up !== null && up >= selfDestructFloor.up) t += up - selfDestructFloor.up;
  }
  let r: number | null = null;
  try { r = selfDestructRelayNow(); } catch { r = null; }
  return r !== null && Number.isFinite(r) ? Math.max(t, r) : t;
}

/** b70 (re-review 7): highest wall-clock time seen (kept across runs in SELF_DESTRUCT_SEEN_KEY).
 *  b74 (review VAR-11): saved with the boot clock at that moment, on every move to the
 *  background as well as at start and each minute (it used to miss all the time the app
 *  was closed, so setting the clock back before reopening held the countdown off). */
let selfDestructSeenMax = 0;
/** b74 (VAR-11): the arming (selfDestructArmedAt) during which the wall clock went
 *  backwards, or 0 */
let selfDestructClockTamperedFor = 0;
const SELF_DESTRUCT_SEEN_KEY = 'veil_selfdestruct_seen';
/** b75 (audit DEV-I2): the most the launch waits for the first sealing pass */
const SEAL_AT_LAUNCH_MS = 1500;
/** a clock may be corrected by this much (network time sync) without counting as tampering */
const SELF_DESTRUCT_CLOCK_SLACK_MS = 10 * 60_000;
/** `armedAt` = the countdown's selfDestructArmedAt, or 0 when it is off. The saved
 *  times belong to one arming: while the countdown is off, or once it is (re)armed or
 *  extended, the clock is re-baselined, so a clock fixed while it was off never counts
 *  (re-audit N3A). Tampering is judged only against times saved during this arming. */
async function noteSelfDestructClock(storage: VeilApp['storage'], armedAt: number): Promise<void> {
  const now = Date.now();
  const up = uptimeMs();
  let saved: { wall: number; up: number | null; armed: number; fl?: number; flUp?: number | null } = { wall: 0, up: null, armed: -1 };
  try {
    const raw = await storage.get(SELF_DESTRUCT_SEEN_KEY);
    if (raw) {
      const v = JSON.parse(raw) as unknown;
      if (typeof v === 'number') saved = { wall: v, up: null, armed: -1 }; // a b73 value: wall clock only, no arming
      else if (v && typeof v === 'object') {
        const o = v as { wall?: unknown; up?: unknown; armed?: unknown; fl?: unknown; flUp?: unknown };
        saved = { wall: Number(o.wall) || 0, up: o.up !== null && Number.isFinite(Number(o.up)) ? Number(o.up) : null, armed: Number.isFinite(Number(o.armed)) ? Number(o.armed) : -1,
          fl: Number(o.fl) || 0, flUp: o.flUp !== null && o.flUp !== undefined && Number.isFinite(Number(o.flUp)) ? Number(o.flUp) : null }; // b77t (L-4)
      }
    }
  } catch { /* unreadable: re-baselined below */ }
  if (!armedAt || saved.armed !== armedAt) {
    // off, or a new arming: start this arming's clock record from now
    selfDestructSeenMax = now;
    if (selfDestructClockTamperedFor !== armedAt) selfDestructClockTamperedFor = 0;
    // b75 (audit AL-10): with the countdown off nothing is kept (a wiped phone used to
    // get this record back within a minute, from the clock check below)
    if (!armedAt) selfDestructFloor = { armed: 0, at: 0, up: null }; // b77t (L-4)
    if (!armedAt) { if (saved.wall || saved.armed !== -1) await storage.remove(SELF_DESTRUCT_SEEN_KEY).catch(() => undefined); return; }
    // b77t (L-4): a new arming's floor starts now (the relay's time, if known and later)
    const fl0 = Math.max(now, (() => { try { return selfDestructRelayNow() ?? 0; } catch { return 0; } })());
    selfDestructFloor = { armed: armedAt, at: fl0, up };
    await storage.set(SELF_DESTRUCT_SEEN_KEY, JSON.stringify({ wall: now, up, armed: armedAt, fl: fl0, flUp: up })).catch(() => undefined);
    return;
  }
  // b77t (audit 5 L-4 / IH DEV-2): the floor carried over from the record: moved on by the boot clock since it
  // was written (same boot), or by the whole boot clock (a restart since: that time passed after the write)
  let carried = saved.wall;
  if (saved.fl) {
    let c = saved.fl;
    if (saved.flUp !== null && saved.flUp !== undefined && up !== null) c += up >= saved.flUp ? up - saved.flUp : up;
    carried = Math.max(carried, c);
  }
  if (selfDestructFloor.armed === armedAt) carried = Math.max(carried, selfDestructFloorNow(armedAt));
  const floorNow = Math.max(now, carried, selfDestructFloorNow(0));
  selfDestructFloor = { armed: armedAt, at: floorNow, up };
  selfDestructSeenMax = Math.max(selfDestructSeenMax, saved.wall);
  // the wall clock is behind a time this phone already showed during this arming ...
  if (now + SELF_DESTRUCT_CLOCK_SLACK_MS < selfDestructSeenMax) selfDestructClockTamperedFor = armedAt;
  // ... or, without a restart since, moved less than the boot clock did
  if (saved.up !== null && up !== null && up >= saved.up && now + SELF_DESTRUCT_CLOCK_SLACK_MS < saved.wall + (up - saved.up)) selfDestructClockTamperedFor = armedAt;
  if (now > selfDestructSeenMax) selfDestructSeenMax = now;
  await storage.set(SELF_DESTRUCT_SEEN_KEY, JSON.stringify({ wall: selfDestructSeenMax, up: now >= selfDestructSeenMax ? up : null, armed: armedAt, fl: floorNow, flUp: up })).catch(() => undefined);
}

/** the countdown's arming time, or 0 when it is off */
function selfDestructArming(st: VeilSettings): number {
  return st.selfDestruct && st.selfDestructArmedAt ? st.selfDestructArmedAt : 0;
}

/** b75 (audit AL-9): wipes that are not duress run no account cleanup on the relay
 *  (the server copies stay: ciphertext the relay can't read); this is never called */
const NO_ACCOUNT_CLEANUP: DuressRelay = {
  sessionPurge: async () => undefined, sessionList: async () => undefined, sessionEnd: async () => undefined,
  entityList: async () => undefined, entityDelete: async () => undefined,
};

/**
 * b75 (audit AL-9): self-destruct, sign-out, wipe-device and delete-account all run the
 * duress wipe's routine: the pending marker; the reads it needs (push target, login,
 * saved-media list) under a deadline; then the crypto-shred (container key, hardware
 * key, gated identity) BEFORE anything else; then every key with a verify pass; then
 * the files. Photos (an iOS prompt), the push drop and the logout run after, in the
 * background — nothing waits on a prompt before the erase. They used to remove keys
 * one at a time in index order, without a marker, after a Photos prompt.
 */
/** b75 (audit AL-9): set by the app. While a wipe's cleanup still holds the old login in
 *  memory, no new identity may be made or restored (it would join the old account);
 *  the self-destruct paths, which run outside the component, use this. */
let wipeHoldHook: ((on: boolean) => void) | null = null;

/**
 * b77t merge (owner decision 2 Nov: removing the decoy code deletes the decoy's relay account): each pending decoy
 * delete (decoy-account.ts DecoyEnd) runs once, after its own random CSPRNG delay, while the app runs. `onDone` (the
 * stored entry goes) after a delete or "nothing left to delete"; 'retry' leaves it for a later run. `gate` false at
 * the moment it fires (locked): skipped, scheduled again at the next unlock. A wipe schedules what it read in memory
 * only (its record is gone with the erase): deleting a removed decoy's account is then a bonus.
 */
const decoyEndTimers = new Map<string, ReturnType<typeof setTimeout>>();
function scheduleDecoyDeletes(entries: DecoyEndEntry[], onDone?: (veilId: string) => Promise<unknown>, gate?: () => boolean): void {
  for (const e of entries) {
    if (decoyEndTimers.has(e.veilId)) continue;
    decoyEndTimers.set(e.veilId, setTimeout(() => {
      decoyEndTimers.delete(e.veilId);
      if (gate && !gate()) return;
      void deleteDecoyAccount(e, createDecoyEndClients).then(async (r) => {
        console.log(`[veil-decoy] removed decoy's account: ${r}`);
        if (r !== 'retry' && onDone) await onDone(e.veilId);
      }).catch(() => undefined);
    }, decoyEndDelayMs()));
  }
}
/** b77t merge: the pending decoy deletes, read before a wipe erases them (bounded: the erase never waits long).
 *  b77t2 (info): plus the CURRENT decoy's account (currentDecoyEnd), deleted from memory the same way */
async function readDecoyEndsQuick(storage: VeilApp['storage']): Promise<DecoyEndEntry[]> {
  let t: ReturnType<typeof setTimeout> | undefined;
  try {
    const read = async (): Promise<DecoyEndEntry[]> => {
      const [q, cur] = await Promise.all([new DecoyEnd(storage).read().catch(() => [] as DecoyEndEntry[]), currentDecoyEnd(storage)]);
      return cur && !q.some((e) => e.veilId === cur.veilId) ? [...q, cur] : q;
    };
    return await Promise.race([read(), new Promise<DecoyEndEntry[]>((r) => { t = setTimeout(() => r([]), 300); })]);
  } catch { return []; } finally { if (t !== undefined) clearTimeout(t); }
}

// b77u merge (U-M13): the wipe's outcome: the stored keys left (0 clean, -1 unknown) and the device's erase report
// (files left 0/n/-1, a failed shred, whether the marker was kept so the next launch finishes the wipe)
type WipeOutcome = { left: number; report: EraseReport | null };
async function wipeDeviceNow(a: VeilApp, hooks: { hold?: (on: boolean) => void; /** b77 rollout: the relay-move reset leaves the photos and files the owner saved */ keepSavedMedia?: boolean } = {}): Promise<WipeOutcome> {
  const hold = hooks.hold ?? wipeHoldHook ?? undefined;
  // b70 (re-review 14): the marker first (a launch finishes a wipe the app was killed in);
  // b71 (audit): the saved-media list copied outside the wiped keys before anything goes
  await a.storage.set(WIPE_PENDING_KEY, '1').catch(() => undefined);
  if (!hooks.keepSavedMedia) await stashPendingMedia(a.storage, await readTrackedSavedMedia(a.storage));
  const decoyEnds = await readDecoyEndsQuick(a.storage); // b77t merge: a removed decoy's account is still deleted
  const purgeToken = await readPurgeToken(a.storage).catch(() => null); // b77t2 (CL-3): read before the erase; the revoke needs it
  const endWipe = beginWipe(a); // b70 (re-review): nothing writes back meanwhile
  let left = -1;
  let report: EraseReport | null = null;
  try {
    const r = await runDuressWipe<PushTarget>({
      storage: a.storage,
      relay: NO_ACCOUNT_CLEANUP,
      userId: async () => null, // no account cleanup (only the duress code purges the relay)
      localTokens: async () => [],
      writeSecretOf: async () => null,
      capturePushTarget: () => capturePushTargetOf(a),
      shredHardwareKey,
      clearFileCache: () => sweepAllLocalFiles(), // b70 (VAR-03); b77u (audit 6 U-M13): its count goes back to the erase
      forgetOutsideRecords: forgetLaunchRecords, // b75 (audit AL-10)
      deleteSavedMedia: (ids) => (hooks.keepSavedMedia ? Promise.resolve(true as never) : deleteSavedMedia(ids)),
      dropPushRegistration: (t) => dropPushRegistration(a, t), // Batch F (R4-4-17); b75: retried, marker kept if it fails
      // b70 (re-review 6): the login goes too; the logout (server revoke) uses a copy in memory
      captureLogin: async () => a.auth.takeOrphan() ?? a.auth.currentSession(), // b77k2 (review L-1): + a login only in memory
      holdLogin: (l) => { hold?.(true); a.auth.holdInMemory(l as Awaited<ReturnType<typeof a.auth.currentSession>>); },
      endLogin: () => a.auth.logout().finally(() => hold?.(false)),
      // b77t (audit 5 L-5): the account's duress purge token is revoked on the relay before the logout (the
      // stored copy went with the erase)
      revokePurgeToken: () => revokePurgeTokenRemote(a.relay, null, purgeToken),
    });
    left = r.leftAfterWipe;
    report = r.report; // b77u merge (U-M13): the one source of truth for what the wipe left
    scheduleDecoyDeletes(decoyEnds); // b77t merge: in memory only (the record went with the erase)
    void r.media.then((m) => { if (m === 'failed') console.log('[veil] wipe verify: saved photos/files were NOT all deleted — retried at the next launch'); });
  } finally {
    endWipe();
  }
  if (left > 0) console.log(`[veil] wipe verify: ${left} item(s) could not be removed`);
  return { left, report };
}

/** b77u (audit 6 U-M13): after a wipe the owner asked for, say what could not be deleted (never after duress,
 *  a Nothing-at-Rest departure or the self-destruct: those don't call this). b77u merge: from the device's erase
 *  report (files 0/n/-1, the kept marker), not a second count of its own */
function noteWipeLeftovers(w: WipeOutcome): void {
  const text = wipeLeftoverNotice(w.left, w.report ?? { shredFailed: false, filesLeft: -1, pendingNextLaunch: false });
  if (text) setTimeout(() => Alert.alert(WIPE_LEFTOVER_TITLE, text), 800);
}

/** Batch H (R6-1-08): the self-destruct wipe. It never reads the identity, so it
 *  also runs when the hardware-mode identity can't be read (a cancelled Face ID). */
async function selfDestructWipe(a: VeilApp): Promise<void> {
  await wipeDeviceNow(a);
}
// b77t (audit 5 L-4): the countdown also counts the relay's clock (relay-clock.ts), moved on by the boot clock
setRelayClockUptime(uptimeMs);
selfDestructRelayNow = relayClockNow;

/** b70 (re-review 13): the veil_saved_media list, or [] */
async function readTrackedSavedMedia(storage: VeilApp['storage']): Promise<string[]> {
  try {
    const raw = await storage.get('veil_saved_media');
    const ids = raw ? (JSON.parse(raw) as unknown[]) : [];
    return Array.isArray(ids) ? ids.filter((x): x is string => typeof x === 'string') : [];
  } catch { return []; }
}

/** b70 (VAR-03 / L-7): delete the images Vardum saved to Photos / the chosen
 *  folder, from the list kept in veil_saved_media. Call before the keys go. */
async function deleteTrackedSavedMedia(storage: VeilApp['storage']): Promise<void> {
  const ids = await readTrackedSavedMedia(storage);
  if (ids.length) await deleteSavedMedia(ids).catch(() => undefined);
}
import * as Notifications from 'expo-notifications';
import { createIdentity, restoreIdentity, type VeilIdentityMaterial } from '../vendor/crypto-core/src/index';
import { provisionIdentity, restoreFromPhrase, ensurePqPrekeySigned, rotatePrekeysIfDue, replenishOneTimePrekeys /* b76 (one-time prekeys) */, oneTimePrekeysElsewhereSince /* b76r1 (audit P-4) */, dropRelayOneTimePrekeys /* b76r2 (audit PK-01) */, prekeysRotationDue, runProtocolUpgrade, createOneTapSession, acceptOneTapSession, needsExplicitAccept, syncChat, sendChatMessage, sendChatControl /* b77m review (L1) */, sendCoverEnvelope, jitteredPollMs, coverSendDelayMs /* b77t (audit 5 M-G) */, sendReadReceipt, sendReaction, sendNicknameIntro, nickIntroDue, peerNickOf /* b77k (IP77-3) */, completeContactHandshake, sendMediaMessage, loadMediaFile, mediaBlobKey /* b77t (audit 5 L-18) */, markEnvelopesDisplayed, MEDIA_LIMIT_BYTES,
  createGroup, createGroupSeats, buildGroupInvitePayload, joinGroup, pollGroupInbox, confirmLegacyRoster, sendGroupMessage, sendGroupReceipt, sendGroupLeave, sendGroupMediaMessage, rotateGroup, evictGroupMember, groupRowLabel, loadGroupRecord, loadGroupRecords, saveGroupRecord, groupRecord, findMainGroupSession, forgetGroup, GROUP_MEMBER_CAP, assertGroupKeysFresh, listGroupTokens, exportGroupRecords, clearGroupRegistry, type GroupMemberRow,
  groupCoverText, // b76 (padding)
  admitGroupClaims, declineGroupClaim, type GroupClaimRow, // b71 (audit F-07): group admission
  currentGroupFingerprint, // b75 (lead's emulator finding)
  groupDiscardNote, claimContactLine, claimContactStatus, noteGoneAnswer, clearGoneAnswers, type GoneAnswers, // b75r1 (audit G-9, G-8, G-10)
  PREKEY_ROTATE_HW_MS, // b73 (audit V-03); b74: weekly in Android security-chip mode too (asked after an unlock)
  loadBlockList, blockVeilId, unblockVeilId, withoutBlocked, isFromBlocked, purgeForumLeftovers } from '../vendor/device/src/index';
import { type VeilSettings, normalizeSettings, SettingsStore, protectiveSettings, AUTO_LOCK_MINUTES, SELF_DESTRUCT_HOURS, SELF_DESTRUCT_WARN_HOURS, SELF_DESTRUCT_DAYS } from '../vendor/device/src/settings';
import type { KeyvaultIdentity, ChatMessage } from '../vendor/device/src/index';
import { silentLogin, provisionSilentAccount, rebindSilentAccount, handoverPrimaryIdentity, isSilentAccountEmail, deriveSilentCredentials, canonicalPhrase, SilentAccountUnavailableError } from '../vendor/device/src/silent-auth';
import { regLockInfo, regLockPinAuth, regLockStatus, regLockSet, regLockOff, type RegLockInfo, type RegLockStatus } from '../vendor/device/src/reglock';
import {
  noteSessionStart, noteAppOpen, noteVeilIdCreated, noteEmailVerified, setFunnelConsent,
  noteFirstSession,
} from '../vendor/device/src/funnel';
import { identityFingerprint, toB64, fromB64, ikSign, base58 } from '../vendor/crypto-core/src/index';
import { purgeProofMessage } from '../vendor/device/src/relay'; // b74 (audit VAR-12)
import { parseVeilAddLink, trustedAppLink, oneToOneInviteLink, GROUP_JOIN_NOTE, LINK_FROM_OUTSIDE_NOTE, APP_LINK_IN_TEXT_RE /* b77s (owner) */ } from './qr'; // b77q (audit 3 DV-3 / AQ-4 / AP-4)
import { createKeyChangeSweep, KEY_UNVERIFIABLE_NOTE /* b77u (R4 #30) */, type KeyCheck } from './key-change-sweep'; // b77m (audit VAR-11)
import { askPasswordUpgradeAfter, PASSWORD_UPGRADE_NOTE, passwordReminderDue, PASSWORD_REMINDED_KEY, emailPasswordProblem /* b77s (owner) */ } from './password'; // b77m (audit VAR-18); b77q owner (1 Nov): weekly
import { isRateLimitedError, isSessionGoneError } from './relay-error-kind'; // b77m merge (audit VAR-20): status / code, not message text
import { endChatOnRelay, syncOutcome, localChatStatus, unavailableSubtitle, chatEndedByPeer } from './chat-end'; // b77m merge (audit VAR-07, app half)
import { isChatUnavailable, checkChatAgain /* b77n (pre-audit INFO-5) */ } from '../vendor/device/src/chat';
import { historyTurnedOff, chatOnScreen, supersedeTokens, bootLocks, deviceAuthFailureUnlocks, departureSteps, createDepartureLock /* b77t */, groupDisplayBatch, groupMessageRow, groupDeletePlan, holdWhileLocked, narColdBootWipe, narMarkerRepair, pollBackoffMs, crashScreenText, crashId, gonePendingReplacement } from './app-guards'; // b77m (external audit acaef32)
import { bootOnboardingRoute, restoreWithPasswordFlag /* b77f2 (audit F-1) */, RESTORE_FLAG_SAVE_FAILED /* b77g (G-2) */, restoreRetryingSignIn /* b77k2 (L4) */ } from './restore-password'; // b77f (audit ZTE77-4)
import { deleteMayHaveCommitted, DeleteUncertainError /* b77g (G-3) */ } from '../vendor/device/src/auth'; // b77f2 (audit F-3)
import type { SessionRow } from './screens/SessionsScreen';
import { collapseGroupRows } from './session-list';
import { UnlockGate, nextActiveEvent } from './unlock-gate'; // b77u (audit 6 U-M2); b77u2 (UC-M2)
import { ThreadView, mergeById } from './thread-view'; // b77u (audit 6 U-M3)
import { MediaWork } from './media-work'; // b77u (audit 6 U-M1)
import type { ContactRow, LookupResult, GroupInviteResult, ContactChatChoice } from './screens/ContactsScreen';
import { PERMISSION_DECLINED, BIOMETRIC, BIOMETRIC_SHORT, SECURE_CHIP } from './platformText';

type Screen = 'boot' | 'login' | 'otp' | 'identity' | 'onboard' | 'main' | 'chat' | 'welcome';

/**
 * iOS invalidates ALL Keychain items written with
 * ACCESS_CONTROL.BIOMETRY_CURRENT_SET the moment the enrolled biometry
 * changes (Face ID/Touch ID re-enrolled or reset) — SecItemCopyMatching then
 * returns errSecAuthFailed (-25293), rendered as "The user name or
 * passphrase you entered is not correct." That is an OS security feature,
 * not an app bug — but the identity is fully recoverable from the 24-word
 * phrase, so boot must treat it as "no identity on this device" (clear the
 * dead entry, route to the restore flow) instead of dead-ending on the fatal
 * "VEIL could not start" screen.
 */
/** b70 (audit PRIM-8): cover-traffic decisions come from the CSPRNG, so the
 *  relay can't predict which envelopes are cover from a guessable PRNG */
function secureRandom(): number {
  const b = new Uint32Array(1);
  crypto.getRandomValues(b);
  return b[0] / 0x100000000;
}

/** b70 (re-review): what decoy mode answers when asked to act as the real
 *  identity — the same words a phone without a relay connection shows */
const DECOY_REFUSAL = 'Could not reach the relay. Try again later.';

function isKeychainAuthDead(e: unknown): boolean {
  const m = String((e as Error)?.message || e);
  if (!m.includes('veil_keyvault_identity')) return false;
  return (
    m.includes('user name or passphrase you entered is not correct') ||
    m.includes('-25293') ||
    m.toLowerCase().includes('authfailed') ||
    // b104 FIX (owner hardware crash, Sept 21): "VEIL could not start" —
    // Keychain get('veil_keyvault_identity') failed — original: Biometry is
    // not available for this app. This is a DIFFERENT OS error class than
    // the -25293 re-enrollment case above (LAError.biometryNotAvailable,
    // not errSecAuthFailed) but the same recovery answer applies: the
    // gated entry cannot be read on this device right now, and the identity
    // is fully recoverable from the 24-word phrase — a boot-time read
    // failure must NEVER hard-crash to the fatal screen when a safe
    // fallback (clear + route to restore) exists. Previously this string
    // matched none of the checks above and fell through to `throw e`,
    // taking down the whole app at boot with no recovery UI at all.
    m.toLowerCase().includes('biometry is not available') ||
    m.toLowerCase().includes('biometry is not enrolled')
  );
}

function VeilApp() {
  // b77t (audit 5 L-20 / IH DEV-4): dialogs that show a nickname, a Vardum ID or the move code are drawn in
  // the app's own window (FLAG_SECURE, the iOS cover), never as a system Alert, which escapes both
  // b77t2 (CM-2): ...and each one belongs to an account. They go through the prompt gate (src/prompt-gate.ts),
  // tagged with the VeilApp they act for: never shown while locked or to another account, withdrawn (answered
  // null) at every lock and account switch, and the layer draws nothing while locked
  const { node: appPromptNode, ask: appAskRaw, dismiss: appPromptDismiss } = useThemedPrompt();
  // b77u2 phone test: declared before the prompt gate, whose visible() reads it during the first render (it was
  // declared ~900 lines below, so the first render threw "Cannot read property 'current' of undefined")
  const lockedRef = useRef(false);
  const promptStateRef = useRef<PromptGateState<VeilApp>>({ account: null, locked: false });
  const promptGateRef = useRef<AccountPromptGate<VeilApp, PromptSpec> | null>(null);
  if (!promptGateRef.current) {
    promptGateRef.current = new AccountPromptGate<VeilApp, PromptSpec>(
      // lockedRef as well: most lock paths set it before the state change renders
      () => ({ account: promptStateRef.current.account, locked: promptStateRef.current.locked || lockedRef.current }),
      appAskRaw, appPromptDismiss);
  }
  const promptGate = promptGateRef.current;
  /** b77t2 (CM-2): an in-window prompt for `owner`'s account (null when it can't be, or stops being, shown to it) */
  const askFor = useCallback((owner: VeilApp | null | undefined, spec: PromptSpec, opts?: AskForOptions) => promptGate.askFor(owner, spec, opts), [promptGate]);
  /** b77t (audit 5 M-E): the REAL app (the phone's own account). `app` below is the account in use: the decoy's
   *  in a decoy session. Wipes, the lock, push and the boot use the real one by name. */
  const [realApp, setApp] = useState<VeilApp | null>(null);
  const [screen, setScreen] = useState<Screen>('boot');
  /** entry mode for the identity screen — 'confirm-create' when arriving from Generate new Veil ID */
  const [identityEntry, setIdentityEntry] = useState<'choose' | 'confirm-create'>('choose');
  const [realIdentity, setIdentity] = useState<KeyvaultIdentity | null>(null);
  // b77 rollout: "Vardum has moved" on the first screen after an update off the older relay; gone once an identity is here
  const [relayMovedNotice, setRelayMovedNotice] = useState(false);
  useEffect(() => { if (realIdentity) setRelayMovedNotice(false); }, [realIdentity]);
  // b77t (audit 5 M-E / IH V-02, owner decision "a real throwaway account"): a decoy session runs on the decoy's
  // own account (src/decoy-account.ts). While it lasts, `app` and `identity` ARE the decoy's — every screen,
  // handler and chat effect then reads and writes only the decoy's records with the decoy's token — and the real
  // account's background work is gated off (decoyModeRef). The real app stays reachable only as realApp, for the
  // wipes, the lock and push.
  const [decoyMode, setDecoyMode] = useState(false);
  const [decoyAcct, setDecoyAcct] = useState<DecoyAccount | null>(null);
  const app = decoyMode ? (decoyAcct?.app ?? null) : realApp;
  const identity = decoyMode ? (decoyAcct?.identity ?? null) : realIdentity;
  const realAppRef = useRef<VeilApp | null>(null);
  realAppRef.current = realApp;
  /** b77t (audit 5 M-E): the account in use (the decoy's in a decoy session), for passes that must stop on a switch */
  const activeAppRef = useRef<VeilApp | null>(null);
  activeAppRef.current = app;
  /** b77t (audit 5 M-E): the identity in use (the decoy's in a decoy session); identityRef (below) is the REAL one */
  const activeIdentityRef = useRef<KeyvaultIdentity | null>(null);
  activeIdentityRef.current = identity;
  // b77t (audit 5 V-09): declared up here so the launch-time relay work below can wait for the unlock
  const [locked, setLockedState] = useState(false);
  /** b77u (audit 6 U-M2 / R1 F-02): every lock voids an unlock attempt still in flight (src/unlock-gate.ts) */
  const unlockGateRef = useRef(new UnlockGate(currentWipeGeneration, () => AppState.currentState === 'active'));
  const setLocked = useCallback((v: boolean) => { if (v) unlockGateRef.current.invalidate(); setLockedState(v); }, []);
  /** b77t (audit 5 V-09): the boot has read the settings and the lock record. Until then (setApp runs before
   *  both) the launch-time relay work below can't tell whether "Hold until unlock" holds it, so it waits */
  const [bootSettled, setBootSettled] = useState(false);
  /** b77t (audit 5 V-09): "Hold until unlock" fetches nothing while locked — the launch-time relay work (old
   *  forum rows, prekey signing and rotation, one-time prekeys, the protocol upgrade) waits for the unlock too */
  const launchWorkHeld = (): boolean => !bootSettled || holdWhileLocked(locked, settingsRef.current.holdUntilUnlock);
  // b77t2 (CM-2): what the prompt gate checks — set during render, so the check below sees this render's values
  promptStateRef.current = { account: app, locked };
  useEffect(() => { promptGate.check(); }, [promptGate, locked, app]);
  /** b77t2 (CM-2): the app-level prompt layer as drawn — nothing while locked or for another account */
  const appPromptShown = !locked && promptGate.visible() ? appPromptNode : null;

  // b62 groups: reload keychain group records at boot (records never expire —
  // losing them means losing group access on this device)
  useEffect(() => {
    if (!app) return;
    loadGroupRecords(app.storage).then((n) => { if (n > 0) console.log(`[veil-group] restored ${n} group record(s)`); }).catch(() => undefined);
  }, [app]);
  const forumSweptRef = useRef(false);
  useEffect(() => {
    if (!app || forumSweptRef.current || launchWorkHeld() || decoyModeRef.current || app !== realAppRef.current) return; // b77t (audit 5 V-09): it lists the account's rows; (M-E) real account only
    forumSweptRef.current = true;
    // b70: the forum is gone — quietly delete what an older build kept for it, and
    // hide its relay rows (with the record gone they would show as unnamed groups)
    (async () => {
      const gone = await purgeForumLeftovers({ storage: app.storage, sessions: app.sessions });
      if (!gone.groupTokens.length) return;
      const hide = new Set(gone.sessionTokens);
      try {
        const uid = (await app.auth.currentSession())?.user.id;
        if (uid) {
          const lr = await app.relay.sessionList(uid);
          const list = (lr.data as { data?: unknown[] })?.data ?? (lr.data as unknown as { sessions?: unknown[] })?.sessions ?? (lr.data as unknown[]);
          for (const raw of Array.isArray(list) ? list : []) {
            const rec = raw as Record<string, unknown>;
            if (rec.group_token && gone.groupTokens.includes(String(rec.group_token)) && rec.token) hide.add(String(rec.token));
          }
        }
      } catch { /* list failure → only the rows this phone knew are hidden */ }
      const raw = await app.storage.get('veil_dismissed_sessions');
      const hidden: string[] = raw ? (JSON.parse(raw) as string[]) : [];
      for (const t of hide) if (!hidden.includes(t)) hidden.push(t);
      await app.storage.set('veil_dismissed_sessions', JSON.stringify(hidden));
    })().catch((e) => console.log('[veil-group] forum leftovers not removed yet:', String((e as Error)?.message ?? e)));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [app, locked, bootSettled]);
  // b54 (Batch A) / Batch C: protocol upgrade (now veil-ratchet-6). (1) Sign +
  // republish the ML-KEM prekey (peers refuse an unsigned one); (2) one-time hard
  // cut per protocol bump: end older 1:1 chats on the relay, retire pre-b54
  // private-group member records. Retries on the next launch if the relay is unreachable.
  const b54UpgradeRef = useRef(false);
  // b76 (one-time prekeys): top up the relay's pool of this phone's one-time prekeys (opk.ts). At
  // launch and after an accept that spent one; never in decoy mode; a wipe while it runs stops its
  // writes (pinToWipe). Failures only log: chats still start from the signed prekeys.
  const opkBusyRef = useRef(false);
  /** b76r1 (audit I3): the wipe generation of the last top-up this run (-1: none yet) */
  const opkGenRef = useRef(-1);
  /** b76r1 (audit P-4): since when another phone holds this Vardum ID's one-time keys (0: it doesn't) */
  const [opkElsewhereSince, setOpkElsewhereSince] = useState(0);
  const topUpOneTimePrekeys = useCallback(async (id?: KeyvaultIdentity | null, opts: { reclaim?: boolean } = {}): Promise<void> => {
    const who = id ?? identityRef.current ?? identity;
    if (!app || !who || opkBusyRef.current || decoyModeRef.current) return;
    opkBusyRef.current = true;
    const opkGen = currentWipeGeneration();
    try {
      const r = await replenishOneTimePrekeys({ relay: app.relay, storage: pinToWipe(app.storage) }, who, { reclaim: opts.reclaim });
      if (r.error) console.warn('[veil-opk] one-time keys not topped up yet:', r.error);
      else if (r.uploaded) console.log(`[veil-opk] published ${r.uploaded} one-time keys (relay holds ${r.count})`);
      else if (!r.mine) console.log('[veil-opk] another phone publishes the one-time keys for this Vardum ID now');
      if (opts.reclaim && r.error) throw new Error('This phone could not publish its one-time keys right now. Try again later.');
      opkGenRef.current = opkGen;
      if (currentWipeGeneration() === opkGen) setOpkElsewhereSince(await oneTimePrekeysElsewhereSince(app.storage).catch(() => 0));
    } finally { opkBusyRef.current = false; }
  }, [app, identity]);
  // b76r1 (audit I3): after a wipe that took the one-time keys (Nothing-at-Rest's close, every
  // departure), the relay still hands out the old pairs, and requests made with them fail here.
  // The identity's return (a restore) tops up again at once: the wipe took the tag too, so that
  // upload REPLACES the relay's stale pool. (The launch top-up below covers the first identity.)
  useEffect(() => {
    if (!app || !identity || opkGenRef.current === -1 || opkGenRef.current === currentWipeGeneration()) return;
    if (launchWorkHeld() || decoyModeRef.current || app !== realAppRef.current) return; // b77t (audit 5 V-09); (M-E) real account only
    void topUpOneTimePrekeys(identity);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [app, identity, topUpOneTimePrekeys, locked, bootSettled]);
  /** b76r1 (audit P-4): Settings — the user takes the one-time keys back to this phone */
  const handleOpkReclaim = useCallback(async () => {
    if (!app || !identityRef.current || decoyModeRef.current) return;
    if (opkBusyRef.current) throw new Error('This phone is already publishing its one-time keys. Try again in a moment.');
    await topUpOneTimePrekeys(identityRef.current, { reclaim: true });
  }, [app, topUpOneTimePrekeys]);
  useEffect(() => {
    if (!app || !identity || b54UpgradeRef.current || decoyModeRef.current || app !== realAppRef.current) return; // b77t (M-E): never for the decoy
    if (launchWorkHeld()) return; // b77t (audit 5 V-09): prekey publishing and the upgrade wait for the unlock
    b54UpgradeRef.current = true;
    // b70 (re-review 3): a wipe while this runs ends it (no identity is put back)
    const gen = currentWipeGeneration();
    const wiped = () => currentWipeGeneration() !== gen;
    (async () => {
      try {
        const signedId = await ensurePqPrekeySigned({ relay: app.relay, vault: pinToWipe(app.vault) }, identity);
        if (wiped()) return;
        if (signedId !== identity && app === realAppRef.current) { console.log('[veil-b54] PQ prekey signed and republished'); setIdentity(signedId); }
        // b70 (audit L-2): SPK + PQ prekey rotation (b73 (audit V-03): weekly). Android
        // security-chip mode rotates after an unlock instead (saving there asks for a
        // fingerprint; see the effect below).
        const rotated = await rotatePrekeysIfDue({ relay: app.relay, vault: pinToWipe(app.vault), storage: pinToWipe(app.storage) }, signedId, {
          skip: Platform.OS === 'android' && settingsRef.current.storageMode === 'hardware',
        }).catch((e) => { console.warn('[veil-prekeys] rotation deferred:', String((e as Error)?.message ?? e)); return signedId; });
        if (wiped()) return;
        if (rotated !== signedId && app === realAppRef.current) setIdentity(rotated);
        // b76 (one-time prekeys): keep this phone's one-time prekeys on the relay topped up
        await topUpOneTimePrekeys(rotated);
        if (wiped()) return;
      } catch (e) {
        console.warn('[veil-b54] PQ prekey signature not published yet — retrying next launch:', String((e as Error)?.message ?? e));
      }
      if (wiped()) return;
      try {
        const sess = await app.auth.currentSession();
        if (!sess) return;
        const res = await runProtocolUpgrade({ relay: app.relay, sessions: app.sessions, storage: app.storage }, sess.user.id, identity.veilId);
        if (!res.alreadyDone) console.log('[veil-b54] protocol upgrade done', res);
      } catch (e) {
        console.warn('[veil-b54] protocol upgrade incomplete — retrying next launch:', String((e as Error)?.message ?? e));
      }
    })();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [app, identity, locked, bootSettled]);
  const [pendingMaterial, setPendingMaterial] = useState<VeilIdentityMaterial | null>(null);
  // b112: phrase awaiting a classic email sign-in (pre-b112 accounts) — the
  // restore resumes automatically the moment that sign-in succeeds
  const [pendingRestorePhrase, setPendingRestorePhrase] = useState<string | null>(null);
  // b76 (registration lock): a restore the relay held for the lock's PIN — the phrase it is for,
  // how the account signs in, and what the relay said (lapse time, tries left). An email account's
  // password is held in a ref (memory only) until the PIN is in or the user goes back.
  const [regLockPrompt, setRegLockPrompt] = useState<{ phrase: string; kind: 'silent' | 'email'; email?: string; info: RegLockInfo } | null>(null);
  const regLockPromptRef = useRef<typeof regLockPrompt>(null);
  useEffect(() => { regLockPromptRef.current = regLockPrompt; }, [regLockPrompt]);
  const regLockPasswordRef = useRef('');
  // b76 (registration lock): the lock's state for Settings (null = not known yet)
  const [regLock, setRegLock] = useState<RegLockStatus | null>(null);
  const regLockRef = useRef<RegLockStatus | null>(null);
  useEffect(() => { regLockRef.current = regLock; }, [regLock]);
  const [email, setEmail] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  // b172: the message cache refused a write for this token — surfaced as the
  // honest "couldn't save history" notice instead of silent thread amnesia.
  const [cacheSaveFailed, setCacheSaveFailed] = useState<string | null>(null);
  const [bootError, setBootError] = useState<string | null>(null);
  const [info, setInfo] = useState<string | null>(null);
  const [tab, setTab] = useState<'sessions' | 'contacts' | 'vaults' | 'stego' | 'notes' | 'settings'>('sessions');
  // b95: owner-approved one-time verify card (see openChat for the gate)
  const [verifyCard, setVerifyCard] = useState(false);
  const [chat, setChatState] = useState<{ token: string; title: string; subtitle: string; status: 'pending' | 'active' | 'ended'; peerVeilId: string | null; canNewThread: boolean; myVerified: boolean; groupToken?: string; /** b77m merge (VAR-07): the relay reports this 1:1 chat gone — read-only, Delete offered */ unavailable?: boolean; /** b77m review (L9): it was the peer's END (kept for the messages sent before it) */ endedByPeer?: boolean; burnAfterOpen?: boolean; burnSeconds?: number; fingerprint?: string | null; peerPinned?: boolean; contact?: boolean; request?: boolean } | null>(null);
  /** b77u (audit 6 U-M3 / R1 F-03): the thread on screen, known at once (chatRef only catches up at the next render) */
  const threadViewRef = useRef(new ThreadView(currentWipeGeneration, () => activeAppRef.current));
  const setChat = useCallback((v: React.SetStateAction<typeof chat>) => {
    if (typeof v !== 'function') threadViewRef.current.show(v?.token ?? null);
    setChatState(v);
  }, []);
  /** b77u (U-M3, RH-M1): a pass's guard — it writes to the thread's view only while it is still on screen,
   *  for the same account, with no wipe since the pass began */
  const threadGuard = (token: string, a: VeilApp) => {
    const tv = threadViewRef.current;
    const tk = tv.ticket(token, a);
    const onThread = (): boolean => tv.shows(tk);
    const setThreadMessages: typeof setChatMessages = (u) => { if (tv.shows(tk)) setChatMessages(u); };
    return { tk, onThread, live: (): boolean => tv.live(tk), setThreadMessages };
  };
  const [groupInfo, setGroupInfo] = useState<{ /** b77u (RH-M1): whose panel this is */ groupToken?: string; isCreator: boolean; epoch: number; fingerprint: string | null; members: GroupMemberRow[] } | null>(null);
  /** b71 (audit F-07): creator — people who asked to join the open group (Approve / Decline) */
  const [groupClaims, setGroupClaims] = useState<{ groupToken: string; rows: GroupClaimRow[] } | null>(null);
  /** b123: device-local nickname of the OPEN thread's peer (rename modal prefill) */
  const [chatLocalNick, setChatLocalNick] = useState<string | null>(null);
  const [groupBusy, setGroupBusy] = useState(false);
  const [threadReady, setThreadReady] = useState(false);
  const chatRef = useRef<{ token: string; peerVeilId?: string | null; groupToken?: string } | null>(null); // b123: peerVeilId added for the local rename handler; b198: groupToken for the sync routers
  // b84: when openChat last opened a thread — the banner gate below needs it,
  // because right after an unlock-resume AppState.currentState can still read
  // 'inactive'/'background' for a moment, and the FIRST decrypt of the thread
  // you just opened would slip past the gate and banner you with the message
  // you are visibly reading (owner repro: banner fired right after entering
  // the chat from the lock screen).
  const chatOpenedAtRef = useRef(0);
  // guards against overlapping poll calls (interval tick + foreground + push
  // firing close together) decrypting the SAME envelope twice before either
  // call's advanced ratchet state is persisted — the exact cause of the
  // "everything arrives twice" bug (two concurrent syncChat calls both load
  // the not-yet-saved state and each independently decrypts the new envelope).
  const syncInFlightRef = useRef<Record<string, boolean>>({});
  // b196: adaptive background backoff — per-token next-poll timestamps and
  // quiet-streak counters. A thread that produces nothing new polls half as
  // often each pass (10s → 20s → 40s → 60s cap + jitter); any new content
  // resets it. The foreground open-thread poll is untouched, so open
  // threads stay real-time. Cuts per-account request pressure at tester
  // scale, where quiet threads dominate (owner Metro log Oct 12).
  const pollBackoffRef = useRef<Record<string, number>>({});
  const zeroStreakRef = useRef<Record<string, number>>({});
  // b91: the end-session desync recommendation fires once per thread per
  // app run, not on every poll that sees a key-mismatch/stacking failure
  const desyncPromptedRef = useRef<Record<string, boolean>>({});
  // b70 (audit L-4): consecutive sync passes that looked like a desync, per thread
  const desyncStreakRef = useRef<Record<string, number>>({});
  // b75 (audit RT-2): envelope ids already counted towards a streak, per thread — a relay
  // re-serving the same failing envelope every poll must not build the streak by itself
  const desyncSeenRef = useRef<Record<string, Set<string>>>({});
  /** b75 (audit RT-2): one sync pass counts towards "out of sync" only when it brought a
   *  decrypt failure on an authenticated envelope this app run has not counted yet; a pass
   *  that opens a message resets the streak. Shared by the open-chat and background paths. */
  /** b75r3 (audit PR3-03): keyed on the peer's SIGNED header (desyncKeys: ratchet key + counter),
   *  not the relay's envelope id — one withheld envelope re-served corrupted under new ids
   *  counted as a new failure every pass and raised the prompt with nothing visible lost. And
   *  any envelope that opens (a cover or receipt too, authOpened) resets the streak, not only a
   *  displayed message. So the prompt needs three passes in a row, each failing on a signed
   *  header not counted before, with nothing at all opening in between. */
  const countDesyncPass = useCallback((token: string, res: { desync?: boolean; desyncIds?: string[]; desyncKeys?: string[]; authOpened?: number; messages: unknown[] }): boolean => {
    const seen = (desyncSeenRef.current[token] ??= new Set<string>());
    if ((res.authOpened ?? 0) > 0 || res.messages.length) desyncStreakRef.current[token] = 0;
    const fresh = (res.desyncKeys ?? res.desyncIds ?? []).filter((id) => !seen.has(id));
    fresh.forEach((id) => seen.add(id));
    const counted = !!res.desync && fresh.length > 0 && !((res.authOpened ?? 0) > 0 || res.messages.length);
    if (counted) desyncStreakRef.current[token] = (desyncStreakRef.current[token] ?? 0) + 1;
    return counted;
  }, []);
  const syncTokenRef = useRef<(t: string) => void>(() => {});
  // b175 (owner Metro repro, Oct 2: rapid-fire burst tripped the relay's
  // anti-abuse rate limiter — burn/heartbeat/list all 500'd "Rate limit
  // exceeded" — but the 1.5s poll loop kept hammering at full speed with no
  // backoff, which is the exact abuse signature behind the historical K-4
  // 10-minute lockout). Per-token cooldown + doubling backoff, reset on the
  // next clean pass.
  const rateLimitCooldownUntilRef = useRef<Record<string, number>>({});
  const rateLimitBackoffMsRef = useRef<Record<string, number>>({});
  const RATE_LIMIT_BACKOFF_BASE_MS = 5000;
  const RATE_LIMIT_BACKOFF_CAP_MS = 60000;
  // b196-r8 fail-close set: a handshake the relay says is already joined must stop retrying —
  // the pre-r8 loops spammed 'Session already joined' every 3s forever on restored threads
  // whose local state is gone. (b77: the 1:1 presence heartbeat and its limiter/dead sets are gone.)
  // b77 (sealed sender): 1:1 chats sealed before b77 (no delivery capabilities) — the clean break
  const legacyChatsRef = useRef<Set<string>>(new Set());
  // b77m merge (audit VAR-07): 1:1 chats the relay reported gone (syncChat `unavailable`, isChatUnavailable):
  // kept with their history, read-only; never synced again (no relay call), never "ended by the other side"
  const unavailableChatsRef = useRef<Set<string>>(new Set());
  // b197-r6: sessionActivate runs at most once per token per app run — repeat
  // opens/supersede auto-switches skipped the redundant relay round trip.
  const activatedOnceRef = useRef<Set<string>>(new Set());
  const hsFailClosedRef = useRef<Set<string>>(new Set());
  // b76r2 (ZTE-5): re-render when a thread fails closed, so the open chat can say it is dead
  const [, setFailClosedTick] = useState(0);
  // b77r1 (audit A-5): 1:1 chats that couldn't finish setting up (my inbound's ticket kept being
  // refused, or my envelopes waited past the peer's last chance to open) — the chat says so and
  // offers End
  const setupFailedRef = useRef<Set<string>>(new Set());
  const backgroundSyncAllSessionsRef = useRef<() => void>(() => {});
  // b199 reactions: set after applyPeerReactions is defined (the sync paths are declared earlier)
  const applyPeerReactionsRef = useRef<(token: string, list?: { target: string; emoji: string | null }[]) => Promise<void>>(async () => {});
  const [chatMessages, setChatMessages] = useState<(ChatMessage & { sender?: string; senderVerified?: boolean; senderCreator?: boolean; systemNote?: string })[]>([]);
  /** b77q review (J2-2): the open thread's rows as last rendered — the receipt sweep acknowledges only these */
  const chatMessagesRef = useRef(chatMessages);
  chatMessagesRef.current = chatMessages;
  /** b77r1 (audit A-5): what a 1:1 sync pass said about setting up and the outbox — the
   *  "couldn't finish setting up" notice, and "Waiting to deliver" bubbles that have gone out */
  const applySealedPass = (token: string, res: { setupFailed?: boolean; queuedIds?: string[]; delivered?: { id: string; envId?: string }[] }): void => {
    if (res.setupFailed && !setupFailedRef.current.has(token)) { setupFailedRef.current.add(token); setFailClosedTick((n) => n + 1); }
    if (!res.queuedIds || chatRef.current?.token !== token) return;
    const still = new Set(res.queuedIds);
    const envIds = new Map((res.delivered ?? []).map((d) => [d.id, d.envId]));
    setChatMessages((prev) => (prev.some((m) => m.queued && !still.has(m.id))
      ? prev.map((m) => {
        if (!m.queued || still.has(m.id)) return m;
        const { queued: _q, ...rest } = m;
        const envId = envIds.get(m.id);
        return envId ? { ...rest, envId } : rest;
      })
      : prev));
  };
  // b77k (IP77-3, owner decision): the peer's own nickname changed — the list (and with it the open
  // chat's title) follows; and my nickname goes into a ready 1:1 chat once, and again whenever it
  // changes (inside the chat's encryption: chat.ts sendNicknameIntro). Never from decoy mode.
  // b77k2 (review L2): each chat's intro waits its own random 3–30 s (src/nick-intro-schedule.ts), so a
  // nickname change (or several chats becoming ready) never sends the intros in one burst; the send
  // re-checks then (the nickname current at that moment, still due, not decoy mode)
  const nickAppRef = useRef(app);
  nickAppRef.current = app;
  const nickIntroRef = useRef<ReturnType<typeof createNickIntroScheduler> | null>(null);
  if (!nickIntroRef.current) {
    nickIntroRef.current = createNickIntroScheduler(async (token) => {
      const a = nickAppRef.current;
      if (!a || decoyModeRef.current) return;
      const nick = chatSettingsRef.current.nickname || '';
      // audit VAR-21 (1f51): re-checked at fire time — still confirmed on this phone (a key change clears it)
      const sealedNow = await a.sessions.load(token).catch(() => null);
      if (!nickIntroAllowed(sealedNow, nick, { due: nickIntroDue, verified: locallyVerified, revoked: revokedTokensRef.current.has(token) })) return;
      await sendNicknameIntro(a.relay, a.sessions, token, nick)
        .then((sent) => { if (sent) console.log(`[veil] #${token.slice(0, 4)}: nickname sent inside the chat`); })
        .catch((e) => { console.log(`[veil] #${token.slice(0, 4)}: nickname not sent yet (${String((e as Error)?.message ?? e)}) — tried again in a few minutes`); throw e; }); // b77k2 (review I-2): the scheduler backs off
    }, { epoch: currentWipeGeneration, random: secureRandomUnit }); // b77k2 (re-review, info): none fires after a wipe; b77n (INFO-3): CSPRNG delays
  }
  // b77k2 (review, optional): a peer's changed intro refreshes the list at most once per 30 s per chat
  const peerNickRefreshRef = useRef<ReturnType<typeof createPeerNickRefreshLimiter> | null>(null);
  if (!peerNickRefreshRef.current) peerNickRefreshRef.current = createPeerNickRefreshLimiter(() => { void refreshSessionsRef.current?.(true); });
  const applyNickPass = (token: string, res: { peerNick?: string; state?: unknown }): void => {
    if (res.peerNick !== undefined) peerNickRefreshRef.current?.changed(token);
    if (!app || decoyModeRef.current) return;
    const nick = chatSettingsRef.current.nickname || '';
    // audit VAR-21 (1f51): only into a chat whose safety code this phone confirmed, like every other automatic 1:1 send
    if (!nickIntroAllowed(res.state, nick, { due: nickIntroDue, verified: locallyVerified, revoked: revokedTokensRef.current.has(token) })) return;
    nickIntroRef.current?.schedule(token);
  };
  // b75r3 (audit PR3-02): whether the app is on screen — a row counts as displayed (its burn
  // clock starts) only while the chat is open, the app is in front and the phone is unlocked
  const [appActive, setAppActive] = useState(AppState.currentState === 'active');
  // b62 groups: per-thread known-envelope guard (separate from chatKnown because
  // group processing must not race the 1:1 path's set semantics)
  const groupKnownRef = useRef<Set<string>>(new Set());
  // b54: background group peeks notify each envelope once (peek re-reads rows)
  const groupPeekNotifiedRef = useRef<Set<string>>(new Set());
  // session-token -> group-token map, filled at openChat/join time (survives a
  // stale sessionRows snapshot until the next refresh)
  const groupKnownTokensRef = useRef<Record<string, string>>({});
  // b134: sticky winner-token memory for collapseGroupRows — see
  // session-list.ts for why this exists (message-cache-vanishes-on-reopen
  // fix). Keyed by groupToken -> the token last chosen to represent it.
  const groupWinnerRef = useRef<Record<string, string>>({});
  const [chatKnown, setChatKnown] = useState<Set<string>>(new Set());
  // Play UGC (18 Oct 2026): device-local block list (Vardum IDs). Blocked
  // senders' messages aren't shown and don't notify; nothing leaves the phone.
  const [blockedIds, setBlockedIds] = useState<Set<string>>(new Set());
  const blockedRef = useRef<Set<string>>(new Set());
  blockedRef.current = blockedIds;
  // Batch G (round-5 review R5-2-05): until the list has loaded, other people's
  // group posts are not shown and don't notify (an unread list used to mean "nobody blocked")
  const [blockListLoaded, setBlockListLoaded] = useState(false);
  const blockListLoadedRef = useRef(false);
  blockListLoadedRef.current = blockListLoaded;
  useEffect(() => {
    if (!app) return;
    // Batch E (N3-4): a failed read keeps the current list and retries (it used
    // to be swallowed, leaving blocked senders visible)
    let stop = false;
    const loadBlockListRetry = (attempt: number) => {
      loadBlockList(app.storage).then((s) => { if (!stop) { setBlockedIds(s); setBlockListLoaded(true); } }).catch((e) => {
        console.log('[veil] block list unreadable (BlockListUnreadableError) — retrying', attempt, String((e as Error)?.message ?? e));
        // Batch F (R4-2-05): keep trying (5 s, backing off to once a minute) — it used to stop after ~1 minute
        if (!stop) setTimeout(() => loadBlockListRetry(attempt + 1), Math.min(60_000, 5_000 * attempt));
      });
    };
    loadBlockListRetry(1);
    return () => { stop = true; };
    // b70 (re-review 5): reloaded whenever the identity changes — a wipe clears the
    // identity, so the old list no longer survives it in memory
  }, [app, identity?.veilId]);
  const [draft, setDraft] = useState('');
  // media: the picked-but-unsent image (confirm dialog), and the per-message
  // decrypt cache (data: URIs in MEMORY — web parity: decrypted blobs never
  // touch disk; on restart they re-fetch + re-decrypt from the relay)
  const [pendingPick, setPendingPick] = useState<PendingPick | null>(null);
  const [allowDl, setAllowDl] = useState(false);

  /**
   * b96 (owner directive: "key phrase should restore everything"): the notes
   * key is DERIVED from the identity's ik seed (itself phrase-derived), so a
   * Nothing-at-Rest wipe + 24-word phrase restore brings every relay-side
   * note back. Existing notes encrypted under the old device-local random
   * key are re-encrypted once, transparently. Best-effort — a failure must
   * never block the app — and safe to call repeatedly (idempotent).
   */
  // b77t2 (decoy gaps): `acct` = the account (default: the one in use) — the decoy session's own notes get their key
  // the same way, on the decoy's NotesStore and records
  const ensureNotesKey = useCallback(async (id: KeyvaultIdentity, acct: VeilApp | null = activeAppRef.current) => {
    const app = acct;
    if (!app) return;
    const notesGen = app.notes.generation(); // b77t (audit 5 M-B): a wipe meanwhile stops the adoption and the backfill
    try {
      await adoptNotesIdentityKey(app.notes, id.ikSeedB64, {
        get: (k) => app.storage.get(k),
        set: (k, v) => app.storage.set(k, v),
        listRows: async () => {
          const data = (await app.relay.entityList('VeilNote', { sort: '-updated_date', limit: 100 })) as unknown;
          const rows = (Array.isArray(data) ? data : ((data as { data?: unknown[] })?.data ?? [])) as Array<{ id: string; payload_ciphertext: string; payload_iv: string; note_nid?: unknown; note_v?: unknown }>;
          return rows; // b74 (VAR-10): with note_nid / note_v, so bound rows stay bound
        },
        updateRow: (rid, rec) => app.relay.entityUpdate('VeilNote', rid, rec),
        // b75 round 2 (audit D4): the marks manifest (rollback marks that survive a restore)
        createRow: (rec) => app.relay.entityCreate('VeilNote', { ...rec, owner_veil_id: id.veilId }),
      });
      // b101 owner backfill: the ghost filter (visibleUnderIdentity) can only
      // classify TAGGED rows, and every note created before this build is
      // untagged. Since the notes key is identity-derived (b96), a row that
      // DECRYPTS under this identity's key provably belongs to it — tag it
      // with owner_veil_id once, so a future identity reset hides it instead
      // of resurrecting it as a "(encrypted on this note key)" ghost forever.
      // Rows that don't decrypt (other identity, web device key, corrupted)
      // stay untagged and visible until deleted. Idempotent; zero crypto work
      // once every row is tagged.
      const data = (await app.relay.entityList('VeilNote', { sort: '-updated_date', limit: 100 })) as unknown;
      const rows = (Array.isArray(data) ? data : ((data as { data?: unknown[] })?.data ?? [])) as Array<{
        id: string; owner_veil_id?: string; payload_ciphertext?: string; payload_iv?: string; note_nid?: string; note_v?: number;
      }>;
      for (const r of rows) {
        if (app.notes.generation() !== notesGen) break;
        if (!r.id || r.owner_veil_id || !r.payload_ciphertext || !r.payload_iv) continue;
        try {
          await app.notes.decryptNote(r.payload_ciphertext, r.payload_iv, noteMetaOf(r)); // proof of ownership
          if (app.notes.generation() !== notesGen) break;
          await app.relay.entityUpdate('VeilNote', r.id, { owner_veil_id: id.veilId });
        } catch { /* not this identity's key — leave untagged */ }
      }
    } catch (e) {
      console.warn('[veil] notes key adoption failed:', String((e as Error)?.message || e));
    }
  }, [app]);
  const ensureNotesKeyRef = useRef(ensureNotesKey);
  useEffect(() => { ensureNotesKeyRef.current = ensureNotesKey; }, [ensureNotesKey]);

  /** b77k (IP77-5): the dial flip's chat capabilities, for the flip wipe to hold (see naRWipeStorage) */
  const naRFlipCapsRef = useRef<ReturnType<NonNullable<typeof app>['sessions']['cachedDeliveries']> | null>(null);
  /** b77k2 (review M-B): the wipe generation when the dial flip began (before its first await) */
  const naRFlipGenRef = useRef<number | null>(null);
  /**
   * NOTHING-AT-REST v2 (b95, owner spec from hardware verify Sept 21: lock the
   * phone → unlock → "absolutely nothing wiped: no note, no chat, no stego,
   * no vault, no ID"). The old implementation only ever wiped conversation
   * keys + the plaintext cache, and ONLY on a real 'background' event — iOS
   * never delivers one for a screen lock, so locking fired NOTHING, and
   * notes/vaults/stego media were never covered at all.
   * v2: one wipe covering the ENTIRE Veil surface, fired from THREE sites —
   * (1) the moment the dial flips to 'memory', (2) any departure from the
   * foreground ('inactive' = screen lock, 'background' = app switch), and
   * (3) every cold boot while the mode is on (catches a process kill that
   * never delivered an event). Storage only — RAM state is reset by the
   * caller when the user can see it.
   */
  const naRWipeStorage = useCallback(async (opts: { coldBoot?: boolean } = {}): Promise<void> => {
    // b77s (audit 4 CR-1 / A-04): Nothing-at-Rest's close (leaving the app) and flip drop the cached
    // tampered-copy message keys at once, before any await (beginWipe and eraseLocal repeat it)
    try { clearFailedBodyCache(); } catch { /* best-effort */ }
    const app = realApp; // b77t (audit 5 M-E): the real records, in a decoy session too
    // b77k (IP77-5): the dial flip's capabilities, handed over by handleSettingsChange in the same
    // synchronous step as this call (null = not the flip: a departure or cold-boot wipe)
    const flipCaps = naRFlipCapsRef.current;
    naRFlipCapsRef.current = null;
    const flipGen = naRFlipGenRef.current; // b77k2 (review M-B)
    naRFlipGenRef.current = null;
    if (!app) return;
    // b77k (IP77-6): held from the first step (the pre-shred reads come before beginWipe; from there
    // its write freeze holds it too, until the end pass); lets go by itself if this throws half-way
    const naRBusy = wipeStarted(); // b77u (audit 6 R4 #24): released at the erase's end below; the cap is only a safety net
    // b76r2 (one-time prekeys, audit PK-01): the relay drops this identity's one-time pairs, asked
    // BEFORE the keys go (their private halves die with the main key below). Started, not awaited:
    // the crypto-shred never waits on the network (the kept login still signs the request).
    // Offline, or a cold-boot wipe with no identity loaded: the next restore's top-up replaces the
    // pool instead. Never from decoy mode (it would send the real Vardum ID from the decoy login).
    const opkVeilId = decoyModeRef.current ? null : identityRef.current?.veilId;
    const opkDropped = dropRelayOneTimePrekeys(app.relay, opkVeilId, 10_000);
    // b77 (sealed sender): every 1:1 chat ends with this wipe (its keys die with the main key):
    // both mailboxes of each chat are ended in the background — started, never awaited, so the
    // crypto-shred never waits on it. Never from decoy mode (the decoy holds no real chats).
    // b77f2 (audit F-2, owner decision): at once again, as before b77f. The b77f random 3–30 s
    // delay (A-7) is not used here: iOS suspends an app that leaves the screen within seconds, so
    // a later timer may never run. Accepted: these ends go out next to the signed-in one-time-key
    // drop above (the A-7 timing link, for Nothing-at-Rest only).
    // b77g (NaR-1, found live on a ZTE Blade A3 Plus): the capabilities came from a keystore read
    // per chat raced against 1 s; a slow keystore lost the race and NO mailbox was ended (the
    // peer kept writing to an inbox nobody could read, and the restored phone couldn't end it).
    // Now the cached chats (SessionStore.cachedDeliveries, kept by every load / save) are ended
    // at once with no keystore read; only chats missing from the cache are read, bounded at
    // WIPE_CAPTURE_FALLBACK_MS (3 s), and ended when that read resolves — the shred never waits.
    // (At the dial flip, vault.setMode('memory') has already deleted the sealed records before
    // this runs, so only the cache still holds their capabilities.)
    // b77h (audit77g H-2): the cache is still taken here, synchronously; the fallback read for the
    // chats missing from it waits until this wipe's own pre-shred reads (saved media, push target)
    // have been issued, reads one chat at a time (Android's keychain is one native queue: N reads
    // at once sat ahead of those reads and the shred) and is bounded at NAR_CAPTURE_FALLBACK_MS
    // (1.5 s). The cold-boot wipe has no fallback at all (the shred never waits; its fresh process
    // has nothing cached either).
    // b77k (IP77-5, iPhone battery): the dial flip ends NO mailbox (the user is still in the app).
    // b77k2 (IP77-5, owner decision): it shreds the stored data as before and carries the chats into
    // memory (src/nar-memory.ts), so they keep working until the departure wipe ends them.
    // b77k2 (L1): `endCaps` (this wipe's snapshot) is what beginWipe drops from the held set; a wipe
    // that ends nothing (decoy mode, the flip) keeps every held capability for a later wipe.
    let releaseFallback: () => void = () => undefined;
    const fallbackAfter = new Promise<void>((r) => { releaseFallback = r; });
    let endCaps: ReturnType<typeof app.sessions.cachedDeliveries> | undefined;
    if (!decoyModeRef.current && !flipCaps) {
      endCaps = app.sessions.cachedDeliveries();
      void startWipeEnds(app.relay, app.sessions, { budgetMs: 8_000, captureMs: NAR_CAPTURE_FALLBACK_MS, fallback: !opts.coldBoot, after: fallbackAfter, cached: endCaps }).done;
    }
    // b75 (audit DEV-L2): reads only, then the write freeze and the crypto-shred FIRST
    // (the per-key deletes and the file sweep used to run before them; iOS gives an app
    // leaving the screen a few seconds). eraseLocal's first writes: hardware key, identity
    // entry, container-key rotation; then the per-key deletes and the file sweep.
    // stego images this app saved (Photos on iOS, the chosen folder on
    // Android) — tracked in veil_saved_media at save time; delete silently
    // (same purge the duress wipe uses).
    // b70 (re-review 13): read now, deleted after the keys (an iOS Photos prompt must not
    // hold the wipe off)
    const mediaIds = await readTrackedSavedMedia(app.storage);
    // b71 (audit): the list is also kept outside the wiped keys until the files are gone
    // b75 round 3: the keep list below also has the sealed presence list (audit DV-6:
    // 'veil_ck_present_v1' = CK_PRESENT_KEY, kept with the protected records it lists) and the
    // decoy push hold (audit DV-3: the post-wipe barrier covers vardum_ keys now)
    // b75 round 2 (audit D8): a refused stash (locking Android phone) deletes from memory
    const mediaStashed = mediaIds.length ? await stashPendingMedia(app.storage, mediaIds).catch(() => false) : true;
    // every veil_ record except the minimum needed to keep the app itself
    // usable: the login session, the mode flag, the privacy dials, the
    // app-lock gate, pinned contacts, and the device's client id. Notes key,
    // vault keys, message caches, ratchet states, identity — all gone.
    // b70 (audit info): the push device id no longer survives. The registration
    // is dropped below (target read first), and a kept id would let the relay
    // link this phone's push rows before and after the wipe.
    // b75 round 2 (audit D1 / D8): kept records live under the kept slot (CK_KEPT_KEYS)
    // b77m review: + the Nothing-at-Rest marker (M1) and the UnifiedPush choice migration flag (L7), both stored unsealed
    // audit VAR-12 (1f51): nar-memory.ts NAR_KEEP_KEYS must equal this list (the fresh-start memory session keeps the same records; b77p_app test)
    const keep = new Set(['veil_nar_marker', 'vardum_up_choice_v1', 'veil_auth_session', 'veil_storage_mode', 'veil_settings_v1', 'veil_app_lock', 'veil_pins_v1', 'veil_client_id', 'veil_app_lock_key', 'veil_contact_seen_v1' /* b70 (L-2): replay ledger, hashes only */, 'veil_lockout' /* b70 (re-review 2): a relaunch must not reset wrong-password lockouts */, 'veil_lock_wrong_in_a_row' /* b75 (audit AL-1): the wrong-in-a-row row; a missing one is tampering now */, 'veil_selfdestruct_seen' /* b70 (re-review 7) */, WIPE_PENDING_KEY /* b70 (re-review 14) */, 'veil_notes_versions', 'veil_notes_bound_only' /* b75 round 2 (audit D4): the notes' rollback marks */, 'veil_ck_present_v1', PUSH_HOLD_KEY, 'veil_reglock_device', 'veil_lock_aux_v1' /* b77t (audit 5 M-E): the decoy account */, 'veil_duress_purge_v1' /* b77t (audit 5 L-5) */, 'veil_aux_pending_v1' /* b77t merge: pending decoy-account deletes */]);
    // Batch H (R6-1-01): read before the erase deletes its cached token
    const pushTarget = await capturePushTargetOf(app);
    releaseFallback(); // b77h (H-2): the pre-shred reads are issued
    const endWipe = beginWipe(app, [...keep], { clearClipboard: false, ended: endCaps }); // b70 (re-review)
    if (flipCaps) { try { app.sessions.holdDeliveries(flipCaps); } catch { /* best-effort */ } }
    naRBusy(); // b77k (IP77-6)
    const flip = flipCaps ? await flipCapture(app.storage, currentWipeGeneration, flipGen) : null;
    // b75 (audit AL-6 / AL-9): the one erase routine; the main key goes first (`rotate`),
    // then overwrite + delete + verify. The launch flag stays.
    await eraseLocal({
      storage: app.storage,
      shredHardwareKey: () => shredHardwareKey({ keepLock: true }), // Batch H (R6-1-02); b70: the kept lock keeps its key
      // encrypted vault-container cache + stray temp files (outside the keychain)
      clearFileCache: async () => (FileSystem.cacheDirectory ? sweepAllLocalFiles() : 0), // b70 (VAR-03): the whole cache, not three prefixes; b77u (U-M13): the count goes back
    }, { keep: [...keep], rotate: true, forgetOutside: false });
    // b77k2 (IP77-5): the flip — the chats go on from memory
    if (flip) await carryIntoMemory(app, flip.captured, [...keep], { identity: identityRef.current, at: flip.at, isCurrent: flip.isCurrent, reloadGroups: () => loadGroupRecords(app.storage) });
    endWipe();
    if (mediaIds.length) { if (mediaStashed) void finishPendingMedia(app.storage, deleteSavedMedia); else void deleteSavedMedia(mediaIds).catch(() => undefined); } // b70 (re-review 13): not awaited; b71: the list stays until the files are gone
    // b95 NaR v2: the device goes silent too (best-effort; an offline flip retries at boot)
    await dropPushRegistration(app, pushTarget);
    void app.auth.revokeOrphan().catch(() => undefined); // b77k2 (review L-1): a login only in memory is revoked, not left valid
    void opkDropped.then((ok) => { if (opkVeilId) console.log(ok ? '[veil-opk] relay dropped the one-time keys' : '[veil-opk] one-time keys not dropped on the relay (the next restore replaces them)'); });
  }, [realApp]);
  const naRWipeRef = useRef(naRWipeStorage);
  useEffect(() => { naRWipeRef.current = naRWipeStorage; }, [naRWipeStorage]);
  /** b77m review (M1): the cold-boot Nothing-at-Rest check deferred because the key storage was unreadable */
  const narBootRecheckRef = useRef<(() => void) | null>(null);

  const handleSettingsChange = useCallback(async (sIn: VeilSettings) => {
    // b70 (audit VAR-16): decoy mode edits its own throwaway copy only
    // b77t2 (decoy gaps): minus the phone-wide lock options (decoySettingsView), which the decoy can't change
    if (decoyModeRef.current) sIn = decoySettingsView(sIn);
    if (decoyModeRef.current) void decoyAcctRef.current?.app.settings.save(sIn).catch(() => undefined); // b77t (audit 5 M-E): kept by the decoy account
    if (decoyModeRef.current) { setDecoySettings(sIn); return; }
    // b70 (re-review 8): weakening a protection needs the password (entered within the
    // last 2 minutes) whichever screen asks — the privacy checkup used to skip it.
    // Without it, the protective values are kept and everything else applies.
    let s = sIn;
    {
      const cur = settingsRef.current;
      const rank = (m: string) => (m === 'memory' ? 2 : m === 'hardware' ? 1 : 0);
      const weakerSd = cur.selfDestruct && (!s.selfDestruct || s.selfDestructArmedAt !== cur.selfDestructArmedAt);
      const weakerHist = !cur.localHistory && s.localHistory;
      const weakerHold = cur.holdUntilUnlock && !s.holdUntilUnlock;
      const weakerMode = rank(s.storageMode) < rank(cur.storageMode);
      if ((weakerSd || weakerHist || weakerHold || weakerMode) && appLockRef.current && Date.now() > sensitiveOkUntilRef.current) {
        s = {
          ...s,
          ...(weakerSd ? { selfDestruct: cur.selfDestruct, selfDestructArmedAt: cur.selfDestructArmedAt } : {}),
          ...(weakerHist ? { localHistory: cur.localHistory } : {}),
          ...(weakerHold ? { holdUntilUnlock: cur.holdUntilUnlock } : {}),
          ...(weakerMode ? { storageMode: cur.storageMode } : {}),
        };
        Alert.alert('Password needed', 'Turning a protection down needs your password. Change it in Settings, which asks for it.');
      }
    }
    const prevMode = settingsRef.current.storageMode;
    const prevHistory = settingsRef.current.localHistory; // audit VAR-01
    // b77k2 (review M-B): the flip carries the chats only if no wipe ran between here and its own wipe
    const genAtStart = currentWipeGeneration();
    setSettings(s); // instant UI feedback
    settingsRef.current = s; // synchronous — the hardware-gate getter below and the reprotect check need this NOW, not after the next render
    if (app) {
      await app.settings.save(s).catch((e) => console.error('[veil] settings save failed:', e));
      // sync the real key-storage engine (IdentityVault) to the dial: this is what
      // actually wipes veil_rk_*/veil_gk_* at flip under Nothing-at-Rest — the
      // settings field alone only drives the UI unless this call happens.
      // b77k (IP77-5): flipping to Nothing-at-Rest — the chats' capabilities are taken from the cache
      // NOW, before setMode deletes the sealed records (a load in between would drop them from it);
      // the flip wipe holds them for the departure wipe instead of ending every chat at once
      let flipCaps: ReturnType<typeof app.sessions.cachedDeliveries> | null = null;
      const flipping = s.storageMode === 'memory' && prevMode !== 'memory';
      if (flipping) {
        try { flipCaps = app.sessions.cachedDeliveries(); } catch { flipCaps = new Map(); }
      }
      // b77k2 (IP77-5 / re-review L3): at the flip the records stay until the flip wipe has read them
      // under its own write freeze (no sync or send can save a newer state after that read), then it
      // erases them and carries the chats into memory (src/nar-memory.ts)
      await app.vault.setMode(s.storageMode, { wipeLater: flipping }).catch((e) => console.error('[veil] vault mode sync failed:', e));
      // b77k2 (IP77-5): turned down from Nothing-at-Rest — the chats the flip carried into memory are
      // stored again (as a Nothing-at-Rest session's stored chats simply stay), never ended
      // audit VAR-01: "Keep history" turned off erases what was already stored (Settings confirmed it);
      // the store's read gate keeps it off screen from the moment the setting was saved
      if (historyTurnedOff(prevHistory, s.localHistory)) {
        const left = await app.sessions.dropStoredHistory().catch(() => -1);
        if (left !== 0) console.log(`[veil] history off: ${left < 0 ? 'the stored history could not be listed' : `${left} record(s) not erased yet`}`);
      }
      if (prevMode === 'memory' && s.storageMode !== 'memory') {
        const left = await leaveMemoryMode(app).catch(() => -1);
        if (left !== 0) console.log(`[veil] leaving Nothing-at-Rest: ${left < 0 ? 'the chats stay in memory' : `${left} record(s) not stored`}`);
      }
      // b95 NaR v2: the invariant must hold the instant the dial flips —
      // nothing Veil-stored (notes, vaults, stego, chats, identity material)
      // remains on this device from this moment on. RAM keeps running so the
      // user isn't yanked out of Settings mid-tap; the first lock/close wipes it.
      if (s.storageMode === 'memory' && prevMode !== 'memory') {
        naRFlipCapsRef.current = flipCaps ?? new Map(); // b77k (IP77-5): taken by the call below before its first await
        naRFlipGenRef.current = genAtStart; // b77k2 (review M-B): likewise
        await naRWipeStorage().catch(() => undefined); // (no mailbox ends at the flip)
      }
      // entering or leaving "hardware" mode needs the identity keyvault re-written
      // once so the biometric gate is actually added/removed on that entry
      // (secure-store.rn.ts reads the mode live at write-time, not at boot).
      if (s.storageMode !== prevMode && (s.storageMode === 'hardware' || prevMode === 'hardware')) {
        try {
          // b98 FIX: this used to re-read the identity from the Keychain
          // (app.vault.load()) purely to immediately write it straight back
          // out with new attributes — a completely unnecessary fresh GET on
          // the one entry most prone to the -25293 ACL-mismatch class of bug
          // (owner hit it live on b97, even with an explicit authentication
          // Prompt on the read: the boot-time load already succeeded and is
          // sitting in memory, RIGHT ON SCREEN, the whole time). There is no
          // reason to re-read what we already have — use the in-memory copy
          // and go straight to the WRITE, which already self-heals the same
          // ACL-mismatch class via delete+retry (secure-store.rn.ts set()).
          const id = identityRef.current;
          // b104 FIX (owner Sept 21: flipped to hardware on b103, "absolutely
          // nothing" happened — no prompt, no error, flip silently completed).
          // Two compounding causes: (1) iOS's biometric GRACE WINDOW — the
          // verification read at the bottom of this block relies on the SE
          // key's kSecAccessControlBiometryCurrentSet ACL to raise system UI,
          // but iOS skips that prompt when a biometric unlock happened
          // recently (the user had just unlocked the phone to open the app),
          // so a flip done right after unlocking legitimately shows nothing;
          // (2) that verification read is `.catch(() => undefined)` — its
          // result is discarded, so a failed/cancelled/no-prompt read was
          // indistinguishable from success. Fix: demand biometrics EXPLICITLY
          // at the top of the flip, via expo-local-authentication's
          // authenticateAsync — this always presents the Face ID sheet (no
          // grace-window shortcut) and its outcome is enforced: cancel/fail
          // aborts the flip and reverts the dial. disableDeviceFallback keeps
          // the semantics identical to the SE gate itself (biometry only, no
          // passcode fallback — the SE key's ACL has none either).
          if (s.storageMode === 'hardware') {
            // b77t: a system prompt Vardum opened (no inactive-lock timer while it is up)
            const bio = await withSystemSheet(() => LocalAuthentication.authenticateAsync({
              promptMessage: `Confirm ${BIOMETRIC} to switch key storage to hardware`,
              cancelLabel: 'Cancel',
              disableDeviceFallback: true,
            }));
            if (!bio.success) {
              throw new Error(`biometric confirmation failed or was cancelled (${bio.warning || bio.error || 'cancelled'})`);
            }
          }
          // b102 FIX: devices that first touched hardware mode before b100
          // carry a persisted SE key created WITHOUT a biometry constraint —
          // loadOrCreateSeKey() reuses it forever, so the seal succeeds and
          // unwrap never prompts Face ID (owner Sept 21: "does not engage
          // Face ID or anything else"). Regenerate the key with today's
          // biometryCurrentSet ACL before sealing; safe because the identity
          // is in memory (identityRef) and is re-sealed under the fresh key
          // by the save below, inside the same try block.
          if (s.storageMode === 'hardware' && id && secureEnclaveAvailable()) {
            await resetSecureEnclaveKey();
          }
          if (id) await app.vault.save(id);
          // b96: PROVE the gate at the flip — read the entry back through the
          // gated path so Face ID is demanded immediately (owner finding:
          // "none of the modes asks me for biometrics" — the gate previously
          // only engaged on a cold boot, so flipping modes mid-session never
          // visibly did anything). A cancelled prompt is fine: the seal is
          // in place and the next boot demands it again.
          if (s.storageMode === 'hardware' && id) {
            // b77t (audit 5 M-A): affirmative — 'missing' (or an unsealed entry) is a failure too
            if (!(await keyvaultHardwareProtected())) {
              throw new Error(`${SECURE_CHIP} did not accept the seal`);
            }
            // b104: stop swallowing this read — its failure was invisible
            // ("absolutely nothing" on b103). A failure here after a
            // successful explicit biometric prompt is a REAL problem worth a
            // Metro line, not a silent pass.
            await app.vault.load().catch((e) => console.warn('[veil] gated verification read after flip failed:', e?.message ?? e));
          }
        } catch (e) {
          console.error('[veil] keyvault re-protect failed:', e);
          // AUDIT FIX (Sept 19): this used to fail silently in the console
          // only — the user saw the toggle "succeed" while the keychain
          // entry was left broken. Now it's surfaced and the dial reverts.
          const reverted = { ...s, storageMode: prevMode };
          setSettings(reverted);
          settingsRef.current = reverted;
          // b97 FIX: the revert above only touched React state — the NEW
          // mode had already been persisted to disk by app.settings.save(s)
          // a few lines above, before this re-protect attempt even ran. A
          // failed flip was leaving settings.json and the actual (unchanged)
          // keychain entry permanently out of sync — every later boot would
          // read back the stale "hardware" mode and try to reconcile a
          // keyvault entry that was never actually re-gated, risking the
          // exact repeated failure this block exists to recover from. Now
          // the revert is persisted too, so a failed flip is fully undone.
          await app.settings.save(reverted).catch(() => undefined);
          // b102: if the failure struck AFTER the SE key was regenerated,
          // any sealed entry is now unreadable (its wrapping key is gone).
          // settingsRef.current is already reverted, so re-writing the vault
          // from the in-memory identity stores it under the reverted mode —
          // the next boot can never hit a sealed blob whose key no longer
          // exists. Best-effort; identity is still in RAM either way.
          if (identityRef.current) await app.vault.save(identityRef.current).catch(() => undefined);
          // (b67) fix: this used to call the app-wide setError(), which
          // ChatScreen also renders — the stale message was bleeding into
          // unrelated chat threads opened afterwards. A native alert is
          // scoped to this action only.
          const authIssue = /auth|passphrase|user name|biometr|cancel/i.test(String((e as Error)?.message || e));
          Alert.alert(
            'Could not switch key storage mode',
            authIssue
              ? `${BIOMETRIC_SHORT} / passcode confirmation failed or was cancelled. Reverted — try again and complete the prompt when it appears.`
              : 'Reverted — try again.',
          );
        }
      }
    }
  }, [app]);
  const [settings, setSettings] = useState<VeilSettings>(DEFAULTS);
  useEffect(() => { settingsRef.current = settings; }, [settings]);
  const receiptSentRef = useRef<Set<string>>(new Set());
  const [mediaSaving, setMediaSaving] = useState<Record<string, 'saving' | 'saved' | 'error'>>({});
  /** b62 voice notes: live recorder state for the chat composer */
  const [voiceRec, setVoiceRec] = useState<{ active: boolean; seconds: number }>({ active: false, seconds: 0 });
  const voiceRecRef = useRef<Audio.Recording | null>(null);
  const handleVoiceCancelRef = useRef<(() => void) | null>(null); // b70 (re-review 5)
  const voiceTickRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const voiceRecStateSecondsRef = useRef(0);
  const [mediaLoad, setMediaLoad] = useState<Record<string, { loading: boolean; uri?: string; fileUri?: string; error?: string }>>({});
  // b70 (VAR-03): sender-side previews that still exist in the temp folder
  const liveLocalUris = useRef(new Set<string>());
  const mediaLoadRef = useRef(mediaLoad);
  useEffect(() => { mediaLoadRef.current = mediaLoad; }, [mediaLoad]);
  // b70 (VAR-03): temporary plaintext goes when the app locks, a chat closes, or at start
  /** b77u (audit 6 U-M1 / R1 F-01): every cleanup voids the media loads in flight (src/media-work.ts) */
  const mediaWorkRef = useRef(new MediaWork());
  const purgeTempFiles = useCallback(() => {
    mediaWorkRef.current.bump(); // b77u (U-M1): a load still running writes no plaintext file after this
    mediaInFlight.current = {};
    liveLocalUris.current.clear();
    setMediaLoad({});
    void purgeTmp();
  }, []);
  const mediaInFlight = useRef<Record<string, boolean>>({});
  /** b77t (audit 5 L-18, IH V-11): one media blob reused by many messages is loaded once: the message whose
   *  load is running or done, by chat + blob (its mediaLoad entry's strings are shared, never copied) */
  const mediaBlobOwner = useRef(new Map<string, string>());
  /** b88: consecutive session-list misses per open thread — see the
   *  dead-thread close effect near the b73 title patch. */
  const goneMissRef = useRef<Record<string, number>>({});
  // b164 FIX (owner Metro log Oct 2: the supersede-switch fired 4x for the
  // SAME dead session, flooding veilIdentityGate/veilSessionGate until the
  // relay 500'd with "Rate limit exceeded" and briefly broke the handshake).
  // Root cause: `chat` stays the OLD token until the async switch's
  // setChat() lands, but sessionRows keeps updating in that window (10s
  // poll, 3s sync tick) and re-fires the effect against the same stale
  // chat.token, re-matching the same replacement and re-calling openChat
  // (identity + pin + nickname lookups) each time. This guard blocks a
  // second switch for a token already mid-switch.
  const supersedeInFlightRef = useRef<Set<string>>(new Set());
  // b198 FRESHNESS GATE (the Native-One '+ thread loses its keys' root cause,
  // diagnosed from metro-live.log Oct 15): the b164 gone-detection effect acts
  // on sessionRows — but sessionRows is REACT STATE, updated only when a
  // refreshSessions pass lands. A brand-new '+' thread is NOT in the list yet
  // when its openChat runs, so the effect saw stillListed=false, matched an
  // OLDER same-peer row as the 'replacement', auto-switched, and
  // app.sessions.remove()d the JUST-CREATED thread's local keys — relay row
  // alive, credential gone, verify/heartbeat 403 'Invalid session credential'
  // forever (log evidence: the #48ca↔#0732 and #5fd9↔#d3c0 ping-pong pairs,
  // each bounce deleting one side's keys). The old guard only handled the
  // EMPTY-list case. These two stamps close the stale-list hole for real:
  // chatOpenedAtRef is stamped by openChat; listRefreshedAtRef is stamped by
  // refreshSessions with the time its relay list FETCH STARTED (a fetch that
  // began before the chat opened can never see the new row, so its completion
  // must not count as fresh). The effect refuses to act until a list fetched
  // AFTER the current chat opened has landed.
  const listRefreshedAtRef = useRef(0);
  // b167: identity-gate rate-limit lock window (ms epoch) — see handleMessage.
  const identityLockUntilRef = useRef<number>(0);
  /** b74: last-known relay dials per session token (from refreshSessions) */
  const sessionDialsRef = useRef<Record<string, { burn: boolean; burnSecs: number }>>({});
  // b155 decision A: relay record's contact_session flag per token —
  // contact (pinned) threads show 'Pinned contact', never ceremony state.
  const sessionContactRef = useRef<Record<string, boolean>>({});
  /** Batch E (N3-1): the safety code is confirmed, per 1:1 session (from the list).
   *  b71 (audit): this phone's own sealed confirmation only — never the relay's peer flag */
  const sessionVerifiedRef = useRef<Record<string, boolean>>({});
  /** b71 (audit): contact requests the user explicitly accepted this run (by token) */
  const acceptedRequestsRef = useRef<Set<string>>(new Set());
  /** b75r3 (audit PR3-01): what each request row showed (requestDisplayBinding), and what the
   *  user's Accept was given for — the accept runs only on that same row */
  const requestShownRef = useRef<Record<string, string>>(Object.create(null));
  const acceptedBindingRef = useRef<Record<string, string>>(Object.create(null));
  /** b75r2 (audit P-2): why the last handshake pass for a token failed — the Accept tap shows it */
  const hsLastErrorRef = useRef<Record<string, string>>({});
  /** Batch G (R5-1-05): chats whose contact key changed since the pin — stay unverified */
  const revokedTokensRef = useRef<Set<string>>(new Set());
  // b75 (audit RT-8): chats whose reported key change was already shown this app run
  const keyChangeAlertedRef = useRef<Set<string>>(new Set());
  /** b77t2 (CM-2): key-change warnings withdrawn before an answer, by chat token, to ask again after the unlock */
  const keyChangeRetryRef = useRef<Map<string, () => void>>(new Map());
  const pwUpgradeAskedRef = useRef(false); // audit VAR-18
  // audit VAR-11: the contacts' security-key check runs on its own schedule over EVERY pinned contact
  // (src/key-change-sweep.ts); opening a chat reads its answer. b77q owner (1 Nov): and makes one anonymous,
  // throttled lookup of its own (keySweep.checkOnOpen, not awaited)
  const keySweepRef = useRef(createKeyChangeSweep());
  /** b77q owner (1 Nov): the sweep's anonymous check of one contact, for the chat-open check ('unknown' until set up) */
  const keyCheckRef = useRef<(veilId: string) => Promise<KeyCheck>>(async () => 'unknown');
  useEffect(() => {
    keySweepRef.current.reset(); // a new identity (or none) starts with no answers
    keyCheckRef.current = async () => 'unknown';
    if (!app || !identity) return;
    // b77t2 (decoy gaps, owner "fix the cheap ones now"): the sweep runs for the account in use — the decoy's own
    // contacts in a decoy session, as in a fresh real account — and stops the moment that account isn't in use
    const wanted = () => activeAppRef.current === app && activeIdentityRef.current === identity && !lockedRef.current && AppState.currentState === 'active';
    // b77q (audit 3 AQ-1): the sweep's lookups go WITHOUT the account token (identityLookupAnon), spread out, with
    // decoy IDs (random, in the Vardum ID format: base58 of 32 random bytes, first 16, as veilIdFromIkPub) mixed in
    const check = async (veilId: string): Promise<KeyCheck> => {
      const lr = await app.relay.identityLookupAnon(veilId);
      const pub = ((lr.data as { data?: Record<string, string> })?.data ?? (lr.data as Record<string, string>)) || null;
      if (!pub || typeof pub !== 'object' || !Object.keys(pub).length) return 'unknown'; // no bundle at all
      // b77u (audit 6 R4 #30): a bundle that is there but malformed is its own visible answer, never 'unknown'
      if (!(pub.IK_pub && pub.SPK_pub && pub.SPK_sig)) return 'unverifiable';
      // b54: the check also requires the IK-signed PQ prekey — pass it
      const trust = await app.pins.verifyPeerPrekeys(veilId, { IK_pub: pub.IK_pub, SPK_pub: pub.SPK_pub, SPK_sig: pub.SPK_sig, pq_pub: pub.pq_pub, pq_sig: pub.pq_sig });
      if (trust.trusted) return 'ok';
      if (trust.reason === 'identity-key-changed') return 'changed';
      console.log(`[veil] a contact's published keys did not check out (${trust.reason}) — shown in their chat`);
      return 'unverifiable'; // b77u (audit 6 R4 #30)
    };
    keyCheckRef.current = check; // b77q owner (1 Nov)
    const iv = setInterval(() => {
      if (!wanted() || !keySweepRef.current.due()) return;
      void keySweepRef.current.run({
        listPinned: async () => (await app.pins.listPins()).map((p) => p.veilId),
        check,
        stillWanted: wanted,
        decoyId: () => base58(crypto.getRandomValues(new Uint8Array(32))).slice(0, 16),
        lookupDecoy: (veilId) => app.relay.identityLookupAnon(veilId),
      });
    }, 60_000);
    return () => clearInterval(iv);
  }, [app, identity]);
  /** Batch G (R5-3-06): chats whose relay "verified" flag was re-sent this run */
  /** Batch G (round-5 review R5-1-08): call offers and answers only on a chat whose
   *  safety code THIS phone confirmed (b71 (audit): the peer's confirmation is a
   *  relay hint only and is not checked here; starting a call was already gated) */
  const callSignalsAllowed = (token: string): boolean => {
    // b70 (audit VAR-16): the real account's calls never ring in decoy mode
    if (decoyModeRef.current) return false;
    const ok = !!sessionVerifiedRef.current[token];
    if (!ok) console.log(`[veil-call] #${token.slice(0, 4)}: call signals ignored — safety codes not confirmed`);
    return ok;
  };
  // b155: live view of session rows for the presence heartbeat loop
  const hbRowsRef = useRef<SessionRow[]>([]);

  // b71: a call ringing or live under the lock (phase only — no name or chat shown)
  const [lockCall, setLockCall] = useState<{ phase: string; callId: string; incoming: boolean } | null>(null);
  useEffect(() => CallManager.subscribe(() => setLockCall(CallManager.lockScreenCall())), []);
  // b71 (device test): an incoming call shown on the lock screen IS a ring the person can
  // see, so the caller gets "ringing" (it used to give up while the phone sat locked)
  useEffect(() => {
    if (locked && lockCall?.incoming && AppState.currentState === 'active') CallManager.ringShown(lockCall.callId);
  }, [locked, lockCall]);
  /** b77t (audit 5 M-G): this 1:1 chat is on screen (open, app in front, phone unlocked): its cover entries
   *  then burn when a displayed message's would */
  const chatOnScreenNow = (token: string): boolean =>
    chatRef.current?.token === token && !chatRef.current?.groupToken && !lockedRef.current && AppState.currentState === 'active';
  /** b71: the background sync took in messages for the open chat while locked */
  const lockedOpenSyncedRef = useRef(false);
  /** live mirrors so the mount-once AppState/inactivity watchers never read stale state */
  // b164: live mirrors so the mount-once AppState resume handler can call
  // the CURRENT refresh closures (same pattern as the watchers above).
  const refreshSessionsRef = useRef<((force?: boolean) => Promise<void>) | null>(null);
  // b191 parity (shell Oct 12): one-per-group notices for epoch-behind and
  // un-openable envelopes — a stale device must be TOLD, never left guessing.
  const groupBehindNoticeRef = useRef<Set<string>>(new Set());
  /** b75r1 (audit G-10): "Session not found" answers per group, counted until a good poll (noteGoneAnswer) */
  const groupGoneRef = useRef<GoneAnswers>(new Map());
  /** b71 (device test): groups with an automatic key rotation on the network right now */
  const autoRotatingRef = useRef<Set<string>>(new Set());
  const refreshContactsRef = useRef<(() => Promise<void>) | null>(null);
  const identityRef = useRef<KeyvaultIdentity | null>(null);
  /** b70 (re-review R2): the identity being replaced by "Generate new Vardum ID", in memory only, until it has signed the sign-in move */
  const duressCleanupRef = useRef(false); // b70 (re-review 2)
  /** b77h (G-3 retry): the last account delete whose result was uncertain, in this session */
  // b75 (audit AL-9): the self-destruct wipe holds the old login for its cleanup too
  useEffect(() => { wipeHoldHook = (on) => { duressCleanupRef.current = on; }; return () => { wipeHoldHook = null; }; }, []);
  /** b70 (re-review 9): every wipe also drops secrets held in memory (the outgoing
   *  identity seed, a typed restore phrase, an unfinished new identity) */
  const clearHeldSecretsRef = useRef<() => void>(() => undefined);
  /** b70 (re-review 7): transfer outcomes are never shown in decoy mode, over the lock or during a duress cleanup */
  const transferQuiet = () => decoyModeRef.current || lockedRef.current || duressCleanupRef.current;
  const retiringIdentityRef = useRef<{ veilId: string; ikSeedB64: string } | null>(null);
  clearHeldSecretsRef.current = () => {
    retiringIdentityRef.current = null; setPendingRestorePhrase(null); setPendingMaterial(null); // b70 (re-review 9)
    // b77q review (J2-4): the sign-in password and the restore phrase a registration-lock prompt holds, and the prompt
    regLockPasswordRef.current = ''; regLockPromptRef.current = null; setRegLockPrompt(null);
  };
  // b77t (audit 5 M-E): the REAL identity, in a decoy session too (activeIdentityRef is the one in use)
  useEffect(() => { identityRef.current = realIdentity; }, [realIdentity]);
  const [lockHint, setLockHint] = useState<string | null>(null);
  const backgrounded = useRef(false);
  const autoLockBgAtRef = useRef<number | null>(null);
  const settingsRef = useRef<VeilSettings>(DEFAULTS);
  /** true only while Settings → "Generate new Vardum ID" runs the create flow:
   *  that path returns an existing user straight to the app (no onboarding) */
  const regeneratingIdRef = useRef(false);
  const [sessionRows, setSessionRows] = useState<SessionRow[]>([]);
  /** b178: session tokens seen by the LAST refreshSessions pass — null until
   *  the first pass seeds it (silent seed, no invite banners on login). */
  const knownSessionTokensRef = useRef<Set<string> | null>(null);
  const [appLock, setAppLock] = useState<AppLockRecord | null>(null);
  const appLockRef = useRef<AppLockRecord | null>(null);
  useEffect(() => { appLockRef.current = appLock; }, [appLock]);
  /** b123: progressive passcode lockout (5 attempts -> 5/10/20/40/60 min) */
  const [lockout, setLockout] = useState<LockoutState | null>(null);
  const [onboardingMode, setOnboardingMode] = useState<'full' | 'introOnly' | 'checkupOnly' | 'idOnly' | 'passwordOnly'>('full');
  const [securePrompt, setSecurePrompt] = useState(false);

  /** b74 (review VAR-03): "Remove app lock" done with the decoy code — hidden from the
   *  decoy's Settings only; the real lock stays and applies again at the next lock */
  const [decoyLockHidden, setDecoyLockHidden] = useState(false);
  useEffect(() => { if (!decoyMode) setDecoyLockHidden(false); }, [decoyMode]);
  /** b74 (VAR-03): a placeholder Vardum ID for decoy mode — an unused Vardum shows an
   *  ID, so a blank one gave the decoy away. Stable per lock setup (from the lock
   *  record's salt), never the real ID, and never published anywhere. */
  const [decoyVeilId, setDecoyVeilId] = useState<string | null>(null);
  /** b61: live mirrors for the screen-capture watcher — avoids re-subscribing
   *  the native event on every render/state change. */
  const decoyModeRef = useRef(decoyMode);
  decoyModeRef.current = decoyMode; // b77t (audit 5 M-E): set during render, so effects of the switch commit already see it
  // b77t (audit 5 L-5 / IH C-08): while the real identity is in memory and the app is unlocked, mint the
  // pre-authorised duress purge token, so the duress code at the lock screen with no identity in memory still
  // purges the account (src/duress-purge-token.ts). At every unlock a local check; a mint (relay.ts
  // mintDuressPurgeToken, signed by the real identity) only when the stored token is missing, belongs to another
  // account or identity, or is a day old. Real account only (never the decoy's), never during a duress cleanup.
  const purgeTokenBusyRef = useRef(false);
  useEffect(() => {
    if (decoyMode || locked || !realApp || !realIdentity || app !== realApp || purgeTokenBusyRef.current || duressCleanupRef.current) return;
    purgeTokenBusyRef.current = true;
    const a = realApp;
    const id = realIdentity;
    void (async () => {
      const uid = (await a.auth.currentSession().catch(() => null))?.user?.id ?? null;
      const ok = await refreshPurgeToken({
        relay: a.relay, storage: pinToWipe(a.storage), userId: uid,
        signer: { veilId: id.veilId, sign: (m) => ikSign(id.ikSeedB64, m) },
      });
      if (ok) console.log('[veil-duress] pre-authorised purge token stored');
    })().finally(() => { purgeTokenBusyRef.current = false; });
  }, [app, realApp, realIdentity, locked, decoyMode]);
  // b77g (NaR-1): the in-memory capability cache is off (and empty) for as long as decoy mode lasts
  useEffect(() => { try { app?.sessions.setDeliveryCacheEnabled(!decoyMode); } catch { /* best-effort */ } }, [app, decoyMode]);
  // b70 (audit VAR-16): no message banners from the real account in decoy mode
  // b75 (audit DEV-L3): and the OS push token is released while decoy mode is up (iOS and
  // Google push showed the real account's banners in the background); the real unlock
  // registers again
  // b74 (VAR-03): native UnifiedPush banners too. b75 round 2 (audit D3): the gate owns the
  // silent flag and the in-app suppression, and keeps them (and the OS push token released)
  // across restarts until the REAL code is entered (handleCode calls setDecoy(false)); this
  // effect no longer writes decoyMode=false into them at every launch
  useEffect(() => { if (decoyMode) { setLocalNotifySuppressed(decoyMode); void decoyPush.setDecoy(true); } }, [decoyMode]);
  // b74 (VAR-03): the decoy's placeholder Vardum ID (see decoyVeilId)
  useEffect(() => {
    if (!decoyMode) { setDecoyVeilId(null); return; }
    // b77t (audit 5 M-E): the decoy account's own, registered Vardum ID (it resolves when looked up)
    if (decoyAcct?.veilId) { setDecoyVeilId(decoyAcct.veilId); return; }
    if (!appLock?.salt) { setDecoyVeilId(null); return; }
    let live = true;
    void (async () => {
      const h = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(`vardum-decoy-id-v1:${appLock.salt}`) as unknown as BufferSource));
      if (live) setDecoyVeilId(base58(h).slice(0, 16));
    })();
    return () => { live = false; };
  }, [decoyMode, appLock, decoyAcct]);
  // b70 (audit VAR-16): decoy mode shows and edits a throwaway copy of the
  // settings; the real ones are never read or changed there
  const [decoySettings, setDecoySettings] = useState<VeilSettings>(DEFAULTS);
  /** b77t (audit 5 M-E): the settings a chat action uses — the decoy's own in a decoy session. The real nickname
   *  and dials must never ride a decoy session row, invite or receipt (they would link the two accounts); the
   *  real `settings` / settingsRef still drive the lock, the storage mode and Hold until unlock */
  const chatSettings = decoyMode ? decoySettings : settings;
  const chatSettingsRef = useRef<VeilSettings>(chatSettings);
  /** b77u (audit 6 W8): the last-message times per 1:1 chat of the account in use (src/quiet-chats.ts), pinned to the
   *  wipe generation (a new ledger after a wipe or an account switch) */
  const quietLedgerRef = useRef<{ app: VeilApp; gen: number; ledger: QuietLedger } | null>(null);
  const quietLedgerFor = (a: VeilApp): QuietLedger => {
    const cur = quietLedgerRef.current;
    if (cur && cur.app === a && cur.gen === currentWipeGeneration()) return cur.ledger;
    const ledger = new QuietLedger(pinToWipe(a.storage));
    quietLedgerRef.current = { app: a, gen: currentWipeGeneration(), ledger };
    return ledger;
  };
  chatSettingsRef.current = chatSettings;
  /** b77t2 (decoy gaps, owner "fix the cheap ones now"): the decoy's own "Hold messages while locked" holds the
   *  decoy session's fetches while locked, as in a fresh account (the real setting still holds everything; the
   *  decoy's never changes or reveals it) */
  const decoyHoldNow = (): boolean => lockedRef.current && decoyModeRef.current && !!chatSettingsRef.current.holdUntilUnlock;
  const decoyAcctRef = useRef<DecoyAccount | null>(null);
  decoyAcctRef.current = decoyAcct;
  // b77t (audit 5 M-E): a decoy session that ends (a wipe, the real code) drops the decoy account from memory,
  // its in-memory group records with it
  useEffect(() => {
    if (decoyMode) return;
    const a = decoyAcctRef.current;
    if (!a) return;
    try { clearGroupRegistry(a.app.storage); } catch { /* best-effort */ }
    setDecoyAcct(null);
  }, [decoyMode]);
  /** b77t (audit 5 M-E): the account in use changes (decoy in or out): what was on screen for the other one
   *  goes at once (the next list refresh fills it from the account now in use; refreshSessions drops a pass
   *  that began under the other account) */
  const resetAccountView = (): void => {
    threadViewRef.current.bump(); // b77u (U-M3): passes of the account left write nothing to the view
    mediaWorkRef.current.bump(); // b77u (U-M1): nor media loads
    mediaInFlight.current = {}; // b77u2 (UC info): as at a chat leave
    setChat(null); setChatMessages([]); setDraft('');
    knownSessionTokensRef.current = null; hbRowsRef.current = [];
    setSessionRows([]); setContactRows([]); setContactsError(null);
  };
  // b77t (audit 5 M-E): the decoy's own account (its aux record over the real store; src/decoy-account.ts)
  const decoyAuxRef = useRef<{ store: unknown; aux: DecoyAux } | null>(null);
  const decoyAuxOf = (a: VeilApp): DecoyAux => {
    if (!decoyAuxRef.current || decoyAuxRef.current.store !== a.storage) decoyAuxRef.current = { store: a.storage, aux: new DecoyAux(a.storage) };
    return decoyAuxRef.current.aux;
  };
  /** b77t merge: the pending decoy deletes (the real store; writes pinned to this wipe generation) */
  const decoyEndOf = (a: VeilApp): DecoyEnd => new DecoyEnd(pinToWipe(a.storage));
  const scheduleDecoyEndsFor = (a: VeilApp, entries: DecoyEndEntry[]): void => {
    const end = decoyEndOf(a);
    scheduleDecoyDeletes(entries, (vid) => end.done(vid), () => !lockedRef.current);
  };
  /** b77t (M-E): register the decoy's account and identity (idempotent, resumes); the session's identity follows */
  const decoyRegisteringRef = useRef(false);
  const registerDecoy = (real: VeilApp, acct?: DecoyAccount | null): void => {
    if (decoyRegisteringRef.current || lockedRef.current) return; // b77t2 (CL-9): nothing goes out while locked
    decoyRegisteringRef.current = true;
    const aux = decoyAuxOf(real);
    const dApp = acct?.app ?? createDecoyApp(real, aux);
    void ensureDecoyAccount({ aux, auth: dApp.auth, relay: dApp.relay, vault: dApp.vault })
      .then(({ identity: did, veilId }) => {
        setDecoyAcct((cur) => (cur && cur.app === dApp ? { ...cur, identity: did, veilId } : cur));
        console.log('[veil-decoy] the decoy account is registered');
      })
      .catch((e) => console.log('[veil-decoy] decoy account not registered yet (tried again later):', String((e as Error)?.message ?? e)))
      .finally(() => { decoyRegisteringRef.current = false; });
  };
  /** b77t (M-E): the account for a decoy session: its app, its Vardum ID (made on the phone at once if new) and
   *  its identity once registered. Never throws (a store that refuses leaves the old placeholder ID) */
  const openDecoyAccount = async (real: VeilApp): Promise<DecoyAccount> => {
    const aux = decoyAuxOf(real);
    // b77u (audit 6 U-M5 / IH M1): under Nothing-at-Rest the decoy's records live in a memory session of their own
    // (src/nar-memory.ts startDecoyNarSession); the post-wipe barrier refused every decoy save after a departure
    startDecoyNarSession(real.storage, settingsRef.current.storageMode, DECOY_PREFIX);
    const dApp = createDecoyApp(real, aux);
    let veilId: string | null = null;
    try { veilId = (await prepareDecoy(aux)).veilId; } catch (e) { console.log('[veil-decoy] decoy not prepared:', String((e as Error)?.message ?? e)); }
    const did = veilId ? await dApp.vault.load().catch(() => null) : null;
    return { app: dApp, identity: did && did.veilId === veilId ? did : null, veilId, gen: currentWipeGeneration() };
  };
  // b77t merge: pending decoy deletes left by an earlier run (the app closed before the delay ran out) are scheduled
  // again, with a new random delay, once the app is unlocked
  useEffect(() => {
    if (!realApp || locked) return;
    const a = realApp;
    void decoyEndOf(a).read().then((q) => { if (q.length) scheduleDecoyEndsFor(a, q); }).catch(() => undefined);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [realApp, locked]);
  // b77t (M-E): a decoy session whose account isn't registered yet keeps trying (once a minute while it lasts)
  // b77t2 (CL-9): never while the app is locked (the lock fetches and sends nothing then, and "Hold until unlock"
  // promises it) — the retry stops at the lock and starts again at the next unlock
  useEffect(() => {
    if (!decoyMode || locked || !decoyAcct || decoyAcct.identity || !decoyAcct.veilId || !realApp) return;
    registerDecoy(realApp, decoyAcct);
    const t = setInterval(() => { if (!lockedRef.current) registerDecoy(realApp, decoyAcct); }, 60_000);
    return () => clearInterval(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [decoyMode, decoyAcct, realApp, locked]);
  // b77t2 (decoy gaps, owner "fix the cheap ones now"): the decoy session's notes work as in a fresh account — its
  // notes key is derived from the DECOY identity, on the decoy's own NotesStore and records (once per decoy
  // identity per run; nothing of the real account's is read or written)
  const decoyNotesKeyedRef = useRef<string | null>(null);
  useEffect(() => {
    const did = decoyAcct?.identity;
    if (!decoyMode || locked || !decoyAcct || !did || decoyNotesKeyedRef.current === did.veilId) return;
    decoyNotesKeyedRef.current = did.veilId;
    void ensureNotesKey(did, decoyAcct.app).catch(() => { decoyNotesKeyedRef.current = null; });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [decoyMode, decoyAcct, locked]);
  // b70 (audit VAR-01/02/17): account and key actions need the real password,
  // checked in the last two minutes, and never run in decoy mode
  const sensitiveOkUntilRef = useRef(0);
  const requireSensitive = (strict = true) => {
    // b74 (review VAR-03): in decoy mode the decoy code passes the password prompt (as
    // it unlocked the app), and the action then fails the way the decoy's relay does —
    // never "Incorrect password." for the code that just opened the app
    if (decoyModeRef.current) throw new Error(DECOY_RELAY_REFUSAL);
    if (strict && appLockRef.current && Date.now() > sensitiveOkUntilRef.current) throw new Error('Enter your password first.');
  };
  useEffect(() => { voiceRecStateSecondsRef.current = voiceRec.seconds; }, [voiceRec]);
  const chatOpenRef = useRef<string | null>(null);
  /** b74: groupToken of the currently open chat (null = 1:1) */
  const chatOpenGroupRef = useRef<string | null>(null); // session token while a conversation is open
  /** (b64) background as STATE: drives the capture-shield effect below */
  const [bgState, setBackgrounded] = useState(false);
  /**
   * (b70) Screenshot shield — CORRECTED after owner device evidence.
   * Metro proved `preventScreenCaptureAsync()` resolves "confirmed" every
   * time yet a screenshot still came out clean. Root cause (confirmed
   * against Expo's own docs, Sept 20): on iOS, preventScreenCaptureAsync
   * ONLY blocks screen *recording* — Apple gives NO app the power to block
   * a screenshot, full stop, and the promise resolving successfully never
   * meant screenshots were blocked. The b64 log line "-> PREVENT ...
   * confirmed" was true but misleading about WHAT it prevented.
   * Fix: split the two real iOS capabilities apart and stop overclaiming:
   *   - preventScreenCaptureAsync/allowScreenCaptureAsync: blocks screen
   *     RECORDING while the dial is on. Real, verifiable, kept.
   *   - the app-switcher preview: b71 (audit F-22) covered by <PrivacyCover />
   *     on iOS (expo-screen-capture 7.0.1 has no app-switcher API; the call
   *     that used to be here did nothing); Android: FLAG_SECURE blanks it.
   *   - Screenshots themselves: UNBLOCKABLE on iOS by design (no exception).
   *     The only honest mitigation is detection + peer notice, already wired
   *     in screen-watch.ts/startScreenWatch below. Settings copy corrected
   *     to say this outright instead of implying screenshots get redacted.
   */
  useEffect(() => {
    // b197-r8 (owner product decision, claims test #1): recording block is
    // ALWAYS ON. The dial existed so users could self-record, but the
    // protection's purpose is the OTHER party's privacy — leaving it in the
    // recorder's hands means the person being captured never consented.
    // Same reasoning that made screenshot alerts always-on (K-18). The
    // settings key is retained for storage compatibility but is no longer read.
    const wantRecordingBlock = true;
    console.log(`[veil-shield] recording-block ALWAYS-ON -> PREVENT (screen recording only — iOS cannot block screenshots)`);
    const call = wantRecordingBlock ? ScreenCapture.preventScreenCaptureAsync() : ScreenCapture.allowScreenCaptureAsync();
    call.then(
      () => { console.log(`[veil-shield] ${wantRecordingBlock ? 'prevent' : 'allow'} confirmed (recording only)`); },
      (e: unknown) => { console.error('[veil-shield] FAILED:', String((e as Error)?.message || e)); },
    );
  }, [settings.screenshotShield]);
  // b71 (audit F-22): the app-switcher cover is <PrivacyCover /> (iOS); Android relies on FLAG_SECURE above
  const [codeError, setCodeError] = useState<string | null>(null);
  const [codeVerifying, setCodeVerifying] = useState(false);
  // b77k (IP77-6): a wipe is still running — the lock screen shows "Verifying…" (b77k2, review M-A) and waits
  const [wipeFinishing, setWipeFinishing] = useState(wipeBusy());
  // b77k2 (review L-3): a memory session left live after Nothing-at-Rest was turned down is stored as soon as it can be
  useEffect(() => (app ? retryLeaveMemoryMode(app, () => settingsRef.current.storageMode !== 'memory') : undefined), [app]);
  useEffect(() => { setWipeFinishing(wipeBusy()); return onWipeBusy(setWipeFinishing); }, []);
  // every wipe's write freeze (beginWipe → its end pass) holds it too: an attempt row can't be
  // written while it is on (KeychainStorage.onFreezeChange)
  useEffect(() => {
    const st = app?.storage as unknown as { onFreezeChange?: (fn: (frozen: boolean) => void) => () => void } | undefined;
    let release: (() => void) | null = null;
    const off = st?.onFreezeChange?.((frozen) => {
      if (frozen && !release) release = wipeStarted(); // b77u (audit 6 R4 #24): until the freeze really ends
      else if (!frozen && release) { release(); release = null; }
    });
    return () => { off?.(); release?.(); };
  }, [app]);
  const [codeResetKey, setCodeResetKey] = useState(0);
  const [contactRows, setContactRows] = useState<ContactRow[]>([]);
  const [contactsError, setContactsError] = useState<string | null>(null);

  useEffect(() => {
    (async () => {
     try {
      const a = await createVeilApp({ isHardwareGated: () => settingsRef.current.storageMode === 'hardware' });
      // b70 (audit PRIM-3): outside hardware mode the identity entry is overwritten before delete too
      setGatedKeysActive(() => settingsRef.current.storageMode === 'hardware');
      // b75 (audit AL-5): in Nothing-at-Rest no departure is "expected" — a picker or
      // share sheet open when Vardum leaves the screen wipes and locks like any other exit
      setSystemSheetPolicy(() => settingsRef.current.storageMode !== 'memory');
      setFunnelConsent(() => settingsRef.current.usageStats === true && !decoyModeRef.current); // b71 (audit): usage counts are opt-in
      // b172 (owner hardware finding Oct 2: threads "deleted" their history
      // on close): the iOS Keychain can refuse large cache writes — surface
      // it in the open thread instead of failing invisibly.
      a.sessions.onCacheWriteFailure = (token) => setCacheSaveFailed(token);
      // b170: MUST run before anything below reads the Keychain-stored auth
      // session or identity — a reinstall-with-leftover-Keychain-data sweep
      // happening after that point would be too late (see fresh-install-guard.ts).
      await purgeIfFreshInstall(a).catch((e) => console.error('[veil-fresh-install] guard threw (non-fatal):', String((e as Error)?.message || e)));
      // b75 (audit DEV-I2 / DEV-L1): entries left unsealed from before the container key
      // are sealed FIRST, before the launch reads anything (a store that still held them
      // kept them readable after the app was deleted, and a wipe had to deal with them).
      // Bounded so a slow store can't hold the launch; the rest finishes in the background
      // (below). Once a pass finds nothing left it leaves a marker, so this is one read.
      await Promise.race([
        a.storage.sealOlderEntries(0).catch(() => 0),
        new Promise((r) => setTimeout(r, SEAL_AT_LAUNCH_MS)),
      ]);
      // b75 round 3 (audit DV-11): Android, once the phone has a screen lock, the key files are
      // bound to an unlocked phone (a phone without one when Vardum first ran kept a key that
      // works while locked, for good). In the background: the launch never waits on it.
      if (Platform.OS === 'android') void rebindContainerKey();
      // b75 round 2 (audit D3): a decoy push hold from an earlier run applies again BEFORE any
      // registration (the identity loads behind the lock screen and asks for one): push stays
      // released and silenced until the real code is entered
      pushHoldStore = a.storage;
      // b75 round 3 (audit DV-7): the hold fails closed: a record that can't be read (altered,
      // planted unsealed, or deleted while the store's list says it is there) keeps it
      // b77t (audit 5 L-3): '0' = not held; no record yet = not held, and '0' is written (every install has one)
      void decoyPush.restore(await a.storage.get(PUSH_HOLD_KEY).then(holdState, () => true));
      // b77t merge: every install has the pending-decoy-delete record (same name and size, decoy or not)
      void new DecoyEnd(a.storage).ensurePresent().catch(() => undefined);
      // b199 (owner hardware finding, Oct 16): setApp used to run BEFORE the
      // sweep above, so every [app] effect raced it — the group-record loader
      // read the previous install's group into memory mid-sweep and polled it
      // with dead credentials (403 "Invalid session credential" every few
      // seconds until the next restart). The app is published to React only
      // once the Keychain is known-clean.
      setApp(a);
      // b104: capture the REAL persisted settings in a local and sync the ref
      // NOW — the dead-entry catch below must act on the actual storageMode,
      // and settingsRef would otherwise still hold DEFAULTS at that point
      // (the [settings] effect hasn't fired yet mid-boot).
      // b75 round 2 (audit D10): the protective settings fail CLOSED. An altered record (it
      // fails its seal check: a fail-closed key now) or one that can't be parsed reads as every
      // protection on; so does a MISSING record on a phone that still holds an identity or an
      // app lock (a new install or a wiped phone holds neither). They used to read as the
      // defaults (self-destruct off, erase-after-10 off, history on) and were saved over the
      // record with no warning unless the Android keystore had reported it unreadable.
      const bootRead = await a.settings.loadChecked();
      let bootSettings = bootRead.settings;
      let settingsTampered = bootRead.state === 'unreadable';
      if (bootRead.state === 'missing') {
        const held = await a.storage.keys('veil_').catch(() => [] as string[]);
        settingsTampered = held.includes(KEYVAULT_KEY) || held.includes(APPLOCK_KEY);
      }
      if (settingsTampered) {
        bootSettings = protectiveSettings({ ...bootSettings, storageMode: await a.vault.mode().catch(() => bootSettings.storageMode) });
        console.log(`[veil] settings record ${bootRead.state} — every protection turned on`);
        Alert.alert('Settings could not be read', `Your Vardum settings on this phone could not be read, so every protection is now on: self-destruct in ${SELF_DESTRUCT_DAYS} days, erase after ${WIPE_AFTER_FAILS} wrong passwords, history off, and messages held until you unlock. Check Settings → Lock and emergency.`);
        await a.settings.save(bootSettings).catch((e) => console.error('[veil] protective settings save failed:', e));
      } else if (bootRead.state === 'missing') {
        // b199: a fresh install (no saved settings yet) persists the defaults
        // at once — so the history-OFF default is what the message store's
        // write gate actually sees from the very first message. Installs that
        // already saved settings keep their own choice untouched.
        await a.settings.save(bootSettings).catch((e) => console.error('[veil] default settings save failed:', e));
      }
      settingsRef.current = bootSettings;
      setSettings(bootSettings);
      // Batch D (D-11): an unreadable lock record means LOCKED, never "no lock" —
      // the lock screen shows, and verify reports the read error until it clears
      let lockRec: AppLockRecord | null;
      try {
        lockRec = await a.appLock.load();
      } catch (e) {
        console.error('[veil-lock] lock record unreadable — staying locked', String((e as Error)?.message ?? e));
        lockRec = { method: 'passcode', kdf: '', salt: '', v: 2, mac: 'hw', tags: [] } as AppLockRecord;
      }
      setAppLock(lockRec);
      // b70 (re-review 6): locked from the moment a lock is known, BEFORE the identity
      // loads (effects keyed on the identity used to run in the gap, over the lock screen)
      if (lockRec) { lockedRef.current = true; setLocked(true); }
      // b77t (audit 5 M-E): with a lock, the decoy aux record exists whether or not a decoy is set up
      if (lockRec) void decoyAuxOf(a).ensurePresent().catch(() => undefined);
      setLockout(await a.appLock.lockout()); // b123: a surviving lockout window carries across restarts
      let session = await a.auth.currentSession(); // b77 rollout: cleared below when it belongs to the older relay
      // b139 quality gate: one session_start row per cold start; drains the
      // fatal-interceptor crash flag from the previous run. app_opened /
      // retention markers fire only once an account session exists (a fresh
      // install emits them right after the silent account provisions).
      // b70 (re-review 7): in the background — a stalled relay used to hold the
      // self-destruct check (below) back for as long as it stalled
      void (async () => {
        try {
          await noteSessionStart(a.relay, a.storage);
          if (session) {
            await noteAppOpen(a.relay, a.storage);
          }
        } catch { /* instrumentation must never break boot */ }
      })();
      await noteSelfDestructClock(a.storage, selfDestructArming(bootSettings)); // b70 (re-review 7)
      // b104 FIX (owner screenshot, Sept 21): Settings > About showed
      // "Signed in as —" on a live, logged-in session. Root cause: `email`
      // state is only ever set from the login-form's local `em` argument on
      // the SIGNUP/OTP-required paths — a normal successful login (see fix
      // #2 below) and every cold-boot session restore (HERE) left it at its
      // initial '' forever. The session we just fetched carries the real
      // account email — populate it now so Settings is correct from the
      // very first render after a restore, not only after a fresh login.
      if (session?.user?.email) setEmail(session.user.email);
      // b95 NaR v2: under Nothing-at-Rest a cold boot finds NOTHING — wipe
      // before anything loads. This also catches a process kill that never
      // delivered an AppState event (jetsam, crash): at most the foreground
      // window's data was on disk; it is gone by the time the app renders.
      // audit VAR-63: fail closed. Either record saying Nothing-at-Rest wipes; an unreadable mode record
      // wipes too unless the settings record was read cleanly and says otherwise (narColdBootWipe)
      // b77m review (M1): when BOTH sealed records are unreadable (one keystore error does that: an iOS
      // background launch, an Android keystore stall) the unsealed one-bit marker decides: on = wipe, off =
      // keep, none / unreadable = no wipe now, checked again once the app is active (narBootRecheck)
      const narBootRead = async (settingsRead: { settings: { storageMode?: string }; state: 'ok' | 'missing' | 'unreadable' }) => {
        // b77n (pre-audit LOW-1): the raw record (modeChecked), never mode()'s 'device' default for a missing one
        const modeRec = await a.vault.modeChecked();
        const modeRead = modeRec.state === 'ok' ? modeRec.mode : modeRec.state;
        const marker = await readNarMarker(a.storage);
        // a fresh install holds no identity and no app lock (a keys() error is not a fresh install)
        const held = await a.storage.keys('veil_').catch(() => null);
        const freshInstall = held !== null && !held.includes(KEYVAULT_KEY) && !held.includes(APPLOCK_KEY);
        const decision = narColdBootWipe({ mode: modeRead, settingsMode: settingsRead.settings.storageMode, settingsState: settingsRead.state, marker, freshInstall });
        // a clean, PRESENT mode record repairs a missing or stale marker (installs from before it; a flip cut
        // short); a missing or unreadable one never writes it (narMarkerRepair)
        const repair = narMarkerRepair(modeRec, marker);
        if (repair) await writeNarMarker(a.storage, repair);
        return { decision, modeRead, marker };
      };
      let narBootPending = false;
      const narBootRecheck = async (): Promise<void> => {
        if (!narBootPending) return;
        const again = await narBootRead(await a.settings.loadChecked().catch(() => ({ settings: {}, state: 'unreadable' as const })));
        if (again.decision === 'retry') { console.log('[veil] key storage still unreadable — the Nothing-at-Rest check waits for the next open'); return; }
        narBootPending = false;
        if (again.decision !== 'wipe') { console.log('[veil] key storage readable again — not Nothing-at-Rest, nothing wiped'); return; }
        console.log('[veil] key storage readable again — Nothing-at-Rest: wiping now');
        try { await naRWipeRef.current?.({ coldBoot: true }); } catch (e) { console.log('[veil] Nothing-at-Rest wipe failed:', String((e as Error)?.message ?? e)); }
        setIdentity(null); setChat(null); setChatMessages([]); clearHeldSecretsRef.current(); knownSessionTokensRef.current = null; setSessionRows([]); setContactRows([]);
        setDecoyMode(false); setScreen('identity');
      };
      narBootRecheckRef.current = () => { void narBootRecheck(); };
      {
        const { decision, modeRead, marker } = await narBootRead(bootRead);
        if (decision === 'wipe') {
          try { await naRWipeRef.current?.({ coldBoot: true }); } catch (e) { console.log('[veil] Nothing-at-Rest boot wipe failed:', String((e as Error)?.message ?? e)); } // b77h (H-2): no fallback read
        } else if (decision === 'retry') {
          narBootPending = true;
          console.log(`[veil] key storage unreadable at boot (Nothing-at-Rest marker ${marker}) — no boot wipe; checked again when the app is active`);
          if (AppState.currentState === 'active') setTimeout(() => { void narBootRecheck(); }, NAR_BOOT_RECHECK_MS);
        } else if (modeRead === 'unreadable' || modeRead === 'missing') console.log(`[veil] key-storage mode ${modeRead}; the settings, the marker or a fresh install say it is not Nothing-at-Rest — no boot wipe`);
      }
      // Batch H (round-6 review R6-1-08): the cold-boot self-destruct runs from the
      // boot settings BEFORE the identity is read. In hardware mode that read is
      // Face ID: a seizer who cancels it used to skip the wipe entirely.
      // b70 (re-review 14): or a wipe was cut short (the app killed part-way)
      const selfDestructed = selfDestructDue(bootSettings) || (await a.storage.get(WIPE_PENDING_KEY).catch(() => null)) === '1';
      // b71 (audit): saved photos/files a cut-short or refused wipe left behind
      if (!selfDestructed && (await readPendingMedia(a.storage)).length) void finishPendingMedia(a.storage, deleteSavedMedia).then((m) => { if (m === 'failed') console.log('[veil] saved photos/files from an earlier wipe still not deleted'); });
      if (selfDestructed) {
        await selfDestructWipe(a);
        setAppLock(null); setIdentity(null); setSettings(DEFAULTS); setChat(null); setChatMessages([]); /* b70 (re-review 13): the open thread goes too */
        clearHeldSecretsRef.current(); knownSessionTokensRef.current = null; setSessionRows([]); /* b178 re-seed */ setContactRows([]); setLocked(false); setScreen('identity');
      }
      // b77 rollout (5 Nov, owner): a phone updated from a build on the older relay holds that relay's login; this relay
      // answers it 401 forever and the app showed nothing (TestFlight build 65). Checked once (src/relay-home.ts): a moved
      // login gets the local reset (saved photos and files kept) and the owner is told to restore or start again
      let relayMoved = false;
      if (session && !selfDestructed) {
        const s0 = session;
        const verdict = await relayHomeCheck({
          get: (k) => a.storage.get(k), set: (k, v) => a.storage.set(k, v), base: VEIL_BASE_URL,
          probe: () => a.relay.sessionList(String(s0.user?.id ?? '')),
        }).catch(() => 'unknown' as const);
        if (verdict === 'moved') {
          console.log('[veil] the stored login belongs to the older relay - local reset, then restore or create');
          relayMoved = true;
          try { await wipeDeviceNow(a, { keepSavedMedia: true }); } catch (e) { console.log('[veil] relay-move reset:', String((e as Error)?.message ?? e)); }
          session = null; lockRec = null; // the reset removed the app lock too
          setAppLock(null); setIdentity(null); setSettings(DEFAULTS); setChat(null); setChatMessages([]);
          clearHeldSecretsRef.current(); knownSessionTokensRef.current = null; setSessionRows([]); /* b178 re-seed */ setContactRows([]); setLocked(false);
        }
      }
      if (relayMoved) setRelayMovedNotice(true); // b77 rollout: a card on the first screen (an Alert here was dropped on the iPhone)
      let bootHasIdentity = false; // b75 (audit AL-7)
      if (session && !selfDestructed) {
        let id: KeyvaultIdentity | null = null;
        try {
          id = await a.vault.load();
        } catch (e) {
          if (isKeychainAuthDead(e)) {
            // The hardware-gated keychain entry was invalidated by the OS
            // (biometric re-enrollment etc.). The identity itself is safe —
            // it is fully recoverable from the 24-word phrase — so clear the
            // dead entry and continue as if no identity existed on this
            // device. The identity screen offers "Restore a Veil identity".
            // b70 (audit L-2): the entry is NOT deleted here. The same error
            // comes back from a failed or locked-out Face ID / Touch ID, and
            // deleting on that would destroy a working identity. A restore (or
            // a new identity) overwrites the entry; until then it stays.
            // b104 CRASH-LOOP PREVENTION (owner device, Sept 21: "Biometry
            // is not available for this app"): when the OS reports biometry
            // is UNAVAILABLE/not enrolled (not merely re-enrolled), a
            // hardware-mode seal can NEVER be read on this device. If we
            // leave storageMode stuck on 'hardware', the phrase-restore the
            // crash screen routes to re-seals the identity right back into
            // the same unreadable state and the app dead-ends forever.
            // Revert key storage to device mode so the app stays usable;
            // the owner can flip back to hardware from Settings once
            // biometry works again (the b104 flip demands it explicitly).
            const msg = String((e as Error)?.message || e).toLowerCase();
            if ((msg.includes('biometry is not available') || msg.includes('biometry is not enrolled'))
                && bootSettings.storageMode === 'hardware') {
              const stDev = { ...bootSettings, storageMode: 'device' as const };
              settingsRef.current = stDev;
              setSettings(stDev);
              await a.settings.save(stDev).catch(() => undefined);
              console.warn('[veil] biometry unavailable for this app — key storage reverted to device mode to avoid an unreadable hardware seal');
            }
          } else {
            throw e; // anything else keeps the existing fatal-error path
          }
        }
        setIdentity(id);
        bootHasIdentity = !!id;
        if (id) {
          const st = await a.settings.load();
          // audit VAR-01: history off — anything stored before the switch (an older build, or an erase
          // the app was closed during) is erased now; the store never shows it either way
          if (st.localHistory === false) void a.sessions.dropStoredHistory().catch(() => undefined);
          settingsRef.current = st; // sync NOW — the hardware-gate getter and the reconcile below need this before the next render
          // b96: phrase-derived notes key (the phrase restores everything)
          await ensureNotesKeyRef.current?.(id).catch(() => undefined);
          // b96 hardware reconcile: if the keyvault entry failed to seal
          // (crash mid-flip, module unavailable then), re-seal now so the
          // Face ID demand engages — a silently unsealed entry was the
          // owner's "none of the modes asks me for biometrics" finding.
          // b77t (audit 5 M-A): affirmative. 'missing' counted as fine, which hid an identity stored under a
          // blinded name with no protection at all; now anything but a confirmed protected entry is re-saved
          // (right after the launch's own unlock of it, like the b75 DEV-I2 re-save below) and checked again.
          if (st.storageMode === 'hardware') {
            try {
              // b77t2 (CL-5): only a CONFIRMED unprotected entry (plain, or confirmed absent) is re-sealed. A check
              // that failed ('unknown': a transient Keychain error) changes nothing — resetting the Secure Enclave
              // key under an entry that is in fact sealed would make it unopenable, and a failed re-save then
              // loses the identity. On a confirmed plain/absent entry no stored blob depends on the old SE key,
              // so the reset can't lose anything (the plain entry stays readable if the save below fails).
              const prot = await keyvaultProtectionState();
              if (prot === 'unknown') console.log('[veil] hardware protection check failed this launch — nothing changed (checked again next launch)');
              else if (prot === 'unprotected') {
                // b102: regenerate the SE key (legacy ungated-key devices)
                // before re-sealing — see secure-store.rn.ts resetSecureEnclaveKey
                if (secureEnclaveAvailable()) await resetSecureEnclaveKey();
                await a.vault.save(id);
                const after = await keyvaultProtectionState();
                if (after === 'unprotected') throw new Error('the identity entry is still not protected');
                if (after === 'unknown') console.log('[veil] re-seal written; its check failed this launch (checked again next launch)');
              }
            } catch (e) {
              // Batch F (round-4 review R4-4-19): say so — Settings would otherwise
              // read "hardware" while the key entry stays unsealed
              console.log('[veil] boot re-seal failed:', String((e as Error)?.message ?? e));
              Alert.alert('Hardware key protection is off', 'Vardum could not turn hardware key protection back on for this phone. Open Settings → Key storage and choose it again.');
            }
          }
          // b75 (audit DEV-I2): in security-chip mode an identity entry stored before the
          // container key is never re-written in the background (that would ask for a
          // fingerprint at a random moment). It is re-saved once here, right after the
          // launch's own unlock of it, so it no longer outlives the app readable.
          if (st.storageMode === 'hardware' && a.storage.needsSeal(KEYVAULT_KEY)) {
            await a.vault.save(id).catch((e) => console.log('[veil] sealing the identity entry deferred:', String((e as Error)?.message ?? e)));
          }
          // b92 F-S3 (settings sweep): the 48h self-destruct clock was only
          // enforced on background→foreground transitions — a COLD START
          // (the exact seizure scenario the feature exists for) skipped the
          // check. Run the identical rule here, before anything renders.
          if (selfDestructDue(st)) {
            await selfDestructWipe(a); // Batch H: one wipe, push dropped after it
            setAppLock(null); setIdentity(null); setSettings(DEFAULTS); setChat(null); setChatMessages([]); /* b70 (re-review 13): the open thread goes too */
            clearHeldSecretsRef.current(); knownSessionTokensRef.current = null; setSessionRows([]); /* b178 re-seed */ setContactRows([]); setLocked(false); setScreen('identity');
          } else if (st.selfDestruct && st.selfDestructArmedAt && !lockRec /* b70 (re-review 3): never to whoever holds a locked phone */
            && Date.now() - st.selfDestructArmedAt >= SELF_DESTRUCT_WARN_HOURS * 3600000) {
            // b92 F-S4 (settings sweep): the 12-hours-left warning only
            // existed inside the Settings screen — surface it in the app
            // itself, where the onboarding promise says it appears.
            const left = Math.max(0, SELF_DESTRUCT_HOURS - Math.floor((Date.now() - st.selfDestructArmedAt) / 3600000));
            Alert.alert(
              'Self-destruct countdown',
              `Your self-destruct clock has ${left} hour${left === 1 ? '' : 's'} left. Messaging never resets it. Extend it by another ${SELF_DESTRUCT_DAYS} days from Settings → Lock and emergency, or let it wipe this device's Vardum data when it reaches zero.`,
            );
          }
          setSettings(st);
          // handoff §1(4): returning users go straight into the app; the
          // checkup + app lock wait behind the dismissible "Secure your VEIL"
          // prompt. b199: a NEW sign-up that closed the app mid-onboarding
          // resumes the required onboarding instead (from the first slide).
          // b77f (audit ZTE77-4): a phrase restore that left no app lock and was closed before
          // its "Set your password" step finished resumes at that step, never the app. A lock
          // that exists by now (set elsewhere, or a record that can't be read) drops the flag.
          // b77t (audit 5 V-09): the lock engages BEFORE the screen leaves 'boot' (the list poll starts with
          // the main screen and would fetch once over a lock that wasn't set yet); the same rule as below
          if (bootLocks(!!lockRec, !!id)) { lockedRef.current = true; setLocked(true); }
          const obRoute = bootOnboardingRoute(st, !!lockRec);
          if (st.onboardingPending) { setOnboardingMode('full'); setScreen('onboard'); }
          else if (obRoute === 'passwordOnly') { setOnboardingMode('passwordOnly'); setScreen('onboard'); }
          else setScreen('main');
          if (obRoute === 'clear') {
            const stc = { ...st, restorePasswordPending: false };
            settingsRef.current = stc;
            setSettings(stc);
            await a.settings.save(stc).catch((e) => console.error('[veil] restore-password flag clear failed:', e));
          }
          // b139 funnel fix: the "Secure your VEIL" prompt waits until after
          // the user's first real session — never before.
          setSecurePrompt(!st.setupDone && st.firstSessionDone);
          // the app lock engages on every open. audit VAR-06: with no app password too — the phone's own
          // authentication is the lock then, and a cold start used to skip it (swipe away, reopen)
          if (bootLocks(!!lockRec, !!id)) { lockedRef.current = true; setLocked(true); }
        } else setScreen('identity');
      } else {
        // b112: new users go straight to identity creation — the account is
        // derived silently from the phrase. Existing (email) accounts reach
        // the classic sign-in from the identity screen's account link.
        setScreen('identity');
      }
      // b75 (audit AL-7): a wipe that could not reach the relay left its push row live;
      // until a new registration, every launch turns this phone's push off locally again
      void retryPushUnregister({ storage: a.storage, pushWanted: () => bootHasIdentity, unregisterLocally: unregisterPushLocally });
      // b77u merge (U-M13): no separate launch file sweep. A wipe that left keys or files keeps veil_wipe_pending
      // (duress-wipe.ts eraseLocal), and the check above runs the whole wipe again at this launch (silently)
      // b75 (audit AL-6): entries from before the container key are sealed in the background
      // (each one is also sealed the first time it is read)
      // b75 (DEV-I2): in every mode (Nothing-at-Rest keeps its login and settings too)
      void a.storage.sealOlderEntries().then((n) => { if (n) console.log(`[veil-secure] sealed ${n} older entries`); }).catch(() => undefined);
      // b70 (re-review): the lock engages at every cold start whenever a lock
      // is set, identity loaded or not (after "Remove identity" or an
      // unreadable hardware entry the app used to open unlocked)
      if (lockRec) setLocked(true);
      setBootSettled(true); // b77t (audit 5 V-09): settings, lock and identity known — held launch work may decide now
      // (b64) the shield itself is now applied by the React effect on
      // [settings.screenshotShield, bgState] near the top of the component —
      // driven by state, awaited, and logged to Metro instead of the old
      // fire-and-forget ref callback that failed silently on device.
      let sheetAwayAt = 0; // b199: when Vardum went to the background for its own picker/prompt
      // b75 (audit AL-5): the picker grace is backed by a timer. When it runs out with
      // Vardum still away, the lock (and in Nothing-at-Rest the wipe) happens THEN — it
      // used to wait for a return to the foreground that might never come.
      // b77q (audit 3 AP-3): only while JS still runs. Android pauses JS timers with the
      // activity (and iOS suspends the app), so behind a picker this timer usually fires only
      // on the way back; the 'active' handler then locks FIRST, before any keychain I/O, so
      // the last unlocked screen is not shown while the self-destruct clock is read.
      let sheetTimer: ReturnType<typeof setTimeout> | null = null;
      const sheetGraceOver = async () => {
        sheetTimer = null;
        if (AppState.currentState === 'active') return;
        sheetAwayAt = 0;
        backgrounded.current = true;
        setBackgrounded(true);
        autoLockBgAtRef.current = Date.now();
        if ((identityRef.current || appLockRef.current) && !lockedRef.current) { console.log('[veil-lock] picker grace over while away — locking'); setLocked(true); }
        if (settingsRef.current.storageMode === 'memory') {
          await naRWipeRef.current?.().catch(() => undefined);
          setIdentity(null); setChat(null); setChatMessages([]); clearHeldSecretsRef.current(); knownSessionTokensRef.current = null; setSessionRows([]); setContactRows([]);
          setDecoyMode(false); setScreen('identity');
        }
      };
      // b77t (audit 5, owner decision "iOS screen lock: fix pre-emptively"): a sustained 'inactive' and
      // iOS's protected-data-unavailable signal lock too (app-guards.ts createDepartureLock)
      const departureLock = createDepartureLock({
        lock: () => { console.log('[veil-lock] inactive past the limit, or the phone is locking — locking'); lockedRef.current = true; setLocked(true); },
        guarded: () => !!(identityRef.current || appLockRef.current),
        locked: () => lockedRef.current,
        currentState: () => AppState.currentState,
        setTimer: (fn, ms) => setTimeout(fn, ms),
        clearTimer: (h) => clearTimeout(h as ReturnType<typeof setTimeout>),
      });
      if (Platform.OS === 'ios') startProtectedDataWatch(() => departureLock.onProtectedDataUnavailable());
      const sub = AppState.addEventListener('change', async (s) => {
        try {
          departureLock.onState(s, s !== 'active' && systemSheetExpected()); // b77t: synchronously, first
          // audit VAR-19: the lock and the Nothing-at-Rest wipe start HERE, synchronously, before any
          // keychain I/O (the self-destruct clock below is a secure-store read and write; Android's
          // keystore can take seconds, and iOS may suspend the app before it returns)
          const sheetOpen = s !== 'active' && systemSheetExpected();
          // b77q (audit 3 AP-3): a picker left open past its grace locks at once on return (the
          // grace timer could not fire while Vardum was paused); the wipe and the log follow below
          if (s === 'active' && sheetAwayAt && Date.now() - sheetAwayAt > SYSTEM_SHEET_MS && (identityRef.current || appLockRef.current)) { lockedRef.current = true; setLocked(true); }
          const steps = departureSteps(s, { sheetOpen, guarded: !!(identityRef.current || appLockRef.current), locked: lockedRef.current, memoryMode: settingsRef.current.storageMode === 'memory' });
          // b77u (audit 6 U-M2): a real departure voids an unlock attempt in flight (also when already locked)
          if ((s === 'background' && !sheetOpen) || steps.lockNow || steps.wipeNow) unlockGateRef.current.depart();
          if (steps.lockNow) { lockedRef.current = true; setLocked(true); }
          if (s === 'background' && !sheetOpen) releaseAllHolds(); // audit VAR-16: a job's hold never outlives a departure
          const narWipe = steps.wipeNow ? (naRWipeRef.current?.() ?? Promise.resolve()).catch(() => undefined) : null;
          await noteSelfDestructClock(a.storage, selfDestructArming(settingsRef.current)).catch(() => undefined); // b74 (review VAR-11): saved on the way out, checked on the way back
          // b95 NaR v2 (owner hardware verify: locking the phone fired NOTHING
          // — iOS delivers 'inactive' for a screen lock, never 'background'):
          // ANY departure from the foreground wipes the full Veil surface —
          // chats, notes, vaults, stego, identity. RAM resets too, so on unlock
          // the user lands on the identity screen (24-word phrase restores it).
          // b199 (ZTE device run): a picker/prompt Vardum itself opened is not a
          // departure — Android runs those as separate screens. Only while one
          // is open (withSystemSheet); any other exit still locks/wipes at once.
          if (sheetOpen) console.log(`[veil-lock] ${s} while a system picker/prompt is open — not locking`);
          if (sheetOpen && s === 'background') {
            sheetAwayAt = Date.now();
            if (sheetTimer) clearTimeout(sheetTimer);
            sheetTimer = setTimeout(() => { void sheetGraceOver(); }, systemSheetLeftMs());
          }
          if (s === 'active' && sheetTimer) { clearTimeout(sheetTimer); sheetTimer = null; }
          if (s === 'active') narBootRecheckRef.current?.(); // b77m review (M1): a deferred cold-boot Nothing-at-Rest check
          if (s === 'active' && sheetAwayAt) {
            // a picker left open for over 2 min (Home pressed from inside it,
            // phone set down) is treated as a real departure after all
            const away = Date.now() - sheetAwayAt; sheetAwayAt = 0;
            if (away > SYSTEM_SHEET_MS && (identityRef.current || appLockRef.current) && !lockedRef.current) { console.log(`[veil-lock] picker open ${Math.round(away / 1000)}s — locking`); setLocked(true); }
            // b70 (re-review 4): and in Nothing-at-Rest that departure wipes too (it used to be skipped for good)
            if (away > SYSTEM_SHEET_MS && settingsRef.current.storageMode === 'memory') {
              await naRWipeRef.current?.().catch(() => undefined);
              setIdentity(null); setChat(null); setChatMessages([]); clearHeldSecretsRef.current(); knownSessionTokensRef.current = null; setSessionRows([]); setContactRows([]);
              setDecoyMode(false); setScreen('identity');
            }
          }
          if (narWipe) {
            await narWipe; // started above, before the clock's keychain I/O (audit VAR-19)
            setIdentity(null); setChat(null); setChatMessages([]); clearHeldSecretsRef.current(); knownSessionTokensRef.current = null; setSessionRows([]); /* b178 re-seed */ setContactRows([]);
            setDecoyMode(false); setScreen('identity');
          }
          if (s === 'background' && !sheetOpen) {
            backgrounded.current = true;
            setBackgrounded(true); // (b64) drives the capture-shield effect (app-switcher redaction)
            autoLockBgAtRef.current = Date.now();
            // auto-lock §0: leaving the app (or locking the phone) engages the
            // passcode gate immediately — never wait out the inactivity timer.
            if ((identityRef.current || appLockRef.current) && !lockedRef.current) setLocked(true);
            // b71 (audit F-22): the app-switcher snapshot is covered by <PrivacyCover />
          } else if (s === 'active' && backgrounded.current) {
            backgrounded.current = false;
            setBackgrounded(false); // (b64) shield effect re-applies (iOS drops it in background)
            // back in the foreground: the inactivity clock starts fresh (the
            // immediate lock on background already covered any absence)
            veilActivityPing();
            // b164: resume = instant session/contact refresh instead of
            // waiting up to 10s for the next poll tick (ceremony flags,
            // new threads, presence all feel immediate on return).
            refreshSessionsRef.current?.();
            refreshContactsRef.current?.();
            // self-destruct countdown: fixed 14-day clock (b199; was 48h), messaging never resets it
            const st = settingsRef.current;
            if (selfDestructDue(st)) {
              await selfDestructWipe(a); // Batch H: one wipe, push dropped after it
              setAppLock(null); setIdentity(null); setSettings(DEFAULTS); setChat(null); setChatMessages([]); /* b70 (re-review 13): the open thread goes too */
              clearHeldSecretsRef.current(); knownSessionTokensRef.current = null; setSessionRows([]); /* b178 re-seed */ setContactRows([]); setLocked(false); setScreen('identity');
            }
          }
        } catch { /* listener must never be a crash source */ }
      });
      } catch (e) {
        const err = e as Error;
        // audit VAR-64: release builds show fixed text and an opaque id, never the raw error or stack
        const cid = crashId();
        console.log(`[veil-crash] ${cid}: ${String(err?.message || e)}`);
        setBootError(crashScreenText(e, __DEV__, cid));
      }
     })();
  }, []);

  /** b112: credential-shaped login failure = "this phrase has no silent
   * account here" (pre-b112 identity) — resume via classic email sign-in.
   * Network/lockout failures are NOT this and surface as errors. */
  const isCredentialFailure = (msg: string): boolean =>
    /credential|password|email|invalid|no account|user not found|unauthor/i.test(msg);

  /** b112: the tail of phrase restore, shared by the silent path (session
   * present) and the resumed path (after classic email sign-in). */
  const completeRestore = useCallback(async (phrase: string) => {
    if (decoyModeRef.current) throw new Error(DECOY_REFUSAL); // b70 (re-review 2, D2-3): never touches the real identity or account
    if (duressCleanupRef.current) throw new Error(DECOY_REFUSAL); // b70 (re-review 2): the real login is still held for the cleanup
    try { app?.sessions.resumeDeliveries(); } catch { /* best-effort */ } // b77h (audit77g H-1): the new identity's chats fill the capability cache again
    (app?.storage as unknown as { clearTombstones?: () => void } | undefined)?.clearTombstones?.(); // b70 (re-review 3): a deliberate fresh start
    startNarSession(app?.storage, settingsRef.current.storageMode); // audit VAR-12
    // b77u merge (U-M13): a wipe that left something kept its marker for the next launch; a new identity on the phone
    // ends that, so the next launch does not wipe the new identity. b77u2 (UC-L2): the wipe is finished first (the key
    // shred retried, every record verified gone); if the old key still can't be destroyed, set-up stops here with a
    // clear message (LeftoverWipeError) and the marker stays. The settle's shred ends the memory session: it starts again
    if (app) { await settleLeftoverWipe(app.storage, () => sweepAllLocalFiles()); startNarSession(app.storage, settingsRef.current.storageMode); }
    if (!app) return;
    // b77f (audit ZTE77-4): a restore that leaves this phone with no app lock (after a duress
    // wipe, or on a fresh install) must not open the app: the lock screen would fall back to the
    // device's own authentication, which is no lock at all on a phone without a screen lock.
    // The onboarding's "Set your password" step runs first. A lock that survived the restore
    // (Nothing-at-Rest keeps veil_app_lock) is not asked for again; an unreadable lock record
    // counts as a lock (the boot treats it as locked too).
    // b77f2 (audit F-1): the lock is checked and restorePasswordPending is on disk BEFORE
    // restoreFromPhrase writes the identity (its last step, after the relay round trips), so a
    // kill anywhere after the identity lands (the notes adoption below makes more round trips)
    // resumes the password step at the next launch, never the app. A failed flag write stops the
    // restore (nothing restored, the error shown); a restore that fails before its identity write
    // drops the flag again.
    const { needsPassword, settings: stFlag } = await restoreWithPasswordFlag({
      hasLock: async () => !!appLockRef.current || !!(await app.appLock.load()),
      loadSettings: () => app.settings.load(),
      saveSettings: (s1) => app.settings.save(s1),
      restore: () => restoreFromPhrase({ relay: app.relay, vault: app.vault }, phrase),
      identityOnDisk: async () => !!(await app.vault.load()),
    });
    const rid = await app.vault.load();
    setIdentity(rid);
    if (needsPassword) {
      // the app shows the password step from here on, even if the notes adoption below fails
      settingsRef.current = stFlag;
      setSettings(stFlag);
      setSecurePrompt(false);
      setOnboardingMode('passwordOnly');
    }
    if (rid) await ensureNotesKey(rid);
    setIdentityEntry('choose');
    if (needsPassword) {
      setScreen('onboard');
      return;
    }
    const st = await app.settings.load();
    setSettings(st);
    setScreen('main');
    setSecurePrompt(!st.setupDone && st.firstSessionDone);
  }, [app]);

  /** b112: after ANY successful sign-in, resume an identity flow that paused
   * for the classic email login (silent accounts unavailable on the relay,
   * or a pre-b112 email account). Returns true when a flow was resumed. */
  const resumeIdentityFlow = useCallback(async (): Promise<boolean> => {
    if (!app) return false;
    if (pendingMaterial) {
      try {
        finishStepRef.current = 'publishing the identity and saving its keys';
    // b77u merge (relay R4 #28): an account that already has a primary takes this new identity only with the primary's
    // add-identity proof. A fresh account's first bind (onboarding) needs none; the identity this phone is retiring, if
    // any, signs the proof, as in finishCreateInner
    const resumeUid = (await app.auth.currentSession().catch(() => null))?.user?.id;
    const resumeApprover = retiringIdentityRef.current && resumeUid ? { ...retiringIdentityRef.current, userId: String(resumeUid) } : null;
    // b77u2 merge (UC-L4): an account with no primary identity (late identity after the classic email sign-in) records
    // one only with the account's current password: a 403 current_password_required asks for it in Vardum's own window
    let id!: KeyvaultIdentity;
    const provisionResume = async (currentPassword?: string) => { id = await provisionIdentity({ relay: app.relay, vault: app.vault }, pendingMaterial, { approver: resumeApprover, currentPassword }); };
    { const wcp = withCurrentPasswordRef.current; if (wcp) await wcp(app, false, provisionResume); else await provisionResume(); }
    finishStepRef.current = 'finishing set-up';
        setIdentity(id); setPendingMaterial(null); setIdentityEntry('choose');
        await app.notes.setBoundOnly().catch(() => undefined); // b75 round 2 (audit D4): a new identity
        await ensureNotesKey(id);
        try { await noteVeilIdCreated(app.relay, app.storage); } catch { /* never a blocker */ }
        // b77g (G-5): a new identity made through the classic email sign-in gets the full
        // onboarding, as finishCreateInner does (it went straight to the app): the pending flag
        // is saved first, so closing the app midway resumes the onboarding at the next launch
        const regenerating = regeneratingIdRef.current;
        regeneratingIdRef.current = false;
        if (!regenerating) {
          const st0 = await app.settings.load();
          const st1 = { ...st0, onboardingPending: true };
          await app.settings.save(st1).catch((e) => console.error('[veil] onboarding flag save failed:', e));
          setSettings(st1);
          settingsRef.current = st1;
          setSecurePrompt(false);
          setOnboardingMode('full');
          setScreen('onboard');
          return true;
        }
        setScreen('main');
        setSecurePrompt(false);
      } catch (e) { setError(friendlyError(e, 'identity')); }
      return true;
    }
    if (pendingRestorePhrase) {
      const ph = pendingRestorePhrase;
      setPendingRestorePhrase(null);
      try { await completeRestore(ph); } catch (e) { setError(friendlyError(e, 'identity')); }
      return true;
    }
    return false;
  }, [app, pendingMaterial, pendingRestorePhrase, completeRestore]);

  /** b77f2 (audit F-6): where a sign-in that finds an identity already on this phone lands — the
   *  launch's own onboarding gate (bootOnboardingRoute): an unfinished new sign-up's onboarding,
   *  or the password step for an identity with no app lock that never finished one, comes before
   *  the app (a lock record that can't be read counts as a lock, as at launch). */
  const routeAfterSignIn = useCallback(async (id: unknown) => {
    if (!app || !id) { setScreen(id ? 'main' : 'identity'); return; }
    let hasLock = !!appLockRef.current;
    if (!hasLock) { try { hasLock = !!(await app.appLock.load()); } catch { hasLock = true; } }
    const st = await app.settings.load();
    const route = bootOnboardingRoute(st, hasLock);
    if (route === 'full' || route === 'passwordOnly') {
      settingsRef.current = st;
      setSettings(st);
      setSecurePrompt(false);
      setOnboardingMode(route);
      setScreen('onboard');
      return;
    }
    if (route === 'clear') {
      const stc = { ...st, restorePasswordPending: false };
      settingsRef.current = stc;
      setSettings(stc);
      await app.settings.save(stc).catch((e) => console.error('[veil] restore-password flag clear failed:', e));
    }
    setScreen('main');
  }, [app]);

  const handleSignup = useCallback(async (em: string, pw: string) => {
    if (!app) return;
    setBusy(true); setError(null); setInfo(null);
    try {
      // b198 ANONYMOUS SIGNUP: one step — register returns the session directly.
      // The OTP screen is retired (the email is a self-declared label: real or
      // invented, never verified, never contacted; the 24-word phrase is the
      // only recovery path). Routing mirrors handleLogin's success path
      // (b104 setEmail + b112 identity-flow resume included).
      try { app.sessions.resumeDeliveries(); } catch { /* best-effort */ } // b77h (audit77g H-1): the new identity's chats fill the capability cache again
      (app.storage as unknown as { clearTombstones?: () => void }).clearTombstones?.(); // b75 round 2 (audit D5): a deliberate sign-in is a fresh start
      await app.auth.signup(em, pw);
      setEmail(em);
      if (await resumeIdentityFlow()) { setBusy(false); return; }
      const id = await app.vault.load();
      setIdentity(id);
      if (id) await ensureNotesKey(id);
      await routeAfterSignIn(id); // b77f2 (audit F-6): the launch's onboarding gate, not straight to main
    } catch (e) {
      setError(friendlyError(e, 'action'));
    } finally { setBusy(false); }
  }, [app, resumeIdentityFlow, routeAfterSignIn]);

  const handleLogin = useCallback(async (em: string, pw: string) => {
    if (!app) return;
    setBusy(true); setError(null); setInfo(null);
    try {
      try { app.sessions.resumeDeliveries(); } catch { /* best-effort */ } // b77h (audit77g H-1): the new identity's chats fill the capability cache again
      (app.storage as unknown as { clearTombstones?: () => void }).clearTombstones?.(); // b75 round 2 (audit D5): a deliberate sign-in is a fresh start
      await app.auth.login(em, pw);
      // b104 FIX: the success path never called setEmail — only the
      // OTP-required error path below did. Every login that didn't need an
      // OTP step left `email` state at '' for the rest of the session
      // (Settings showed "Signed in as —" the whole time despite a valid,
      // active login).
      setEmail(em);
      // b112: an identity flow (create or phrase restore) may be waiting on
      // this classic sign-in — resume it instead of the normal routing.
      if (await resumeIdentityFlow()) { setBusy(false); return; }
      const id = await app.vault.load();
      setIdentity(id);
      if (id) await ensureNotesKey(id);
      await routeAfterSignIn(id); // b77f2 (audit F-6): the launch's onboarding gate, not straight to main
    } catch (e) {
      const msg = String((e as Error).message || e);
      // b76 (registration lock): the account is locked to its own phone. With a restore waiting on
      // this sign-in, the restore screen asks for the PIN (the proof is made from the 24 words);
      // without one there is no identity seed to make it from, so say how to get in
      const rl = regLockInfo(e);
      if (rl) {
        if (pendingRestorePhrase) {
          regLockPasswordRef.current = pw;
          setRegLockPrompt({ phrase: pendingRestorePhrase, kind: 'email', email: em, info: rl });
          setScreen('identity');
        } else {
          setError('This account has a registration lock. To sign in on this phone, choose "Restore with recovery phrase", enter your 24 words, then the lock’s PIN.');
        }
        return;
      }
      if (/otp|code|verif/i.test(msg)) { setEmail(em); setScreen('otp'); }
      else setError(friendlyError(e, 'login'));
    } finally { setBusy(false); }
  }, [app, resumeIdentityFlow, pendingRestorePhrase, routeAfterSignIn]);

  const handleVerify = useCallback(async (code: string) => {
    if (!app) return;
    setBusy(true); setError(null); setInfo(null);
    try {
      try { app.sessions.resumeDeliveries(); } catch { /* best-effort */ } // b77h (audit77g H-1): the new identity's chats fill the capability cache again
      (app.storage as unknown as { clearTombstones?: () => void }).clearTombstones?.(); // b75 round 2 (audit D5): a deliberate sign-in is a fresh start
      await app.auth.verifyOtp(email, code);
      try { await noteEmailVerified(app.relay, app.storage); } catch { /* never a blocker */ }
      // b112: resume a pending identity flow that fell back to email sign-up
      if (await resumeIdentityFlow()) { setBusy(false); return; }
      const id = await app.vault.load();
      setIdentity(id);
      if (id) await ensureNotesKey(id);
      await routeAfterSignIn(id); // b77f2 (audit F-6): the launch's onboarding gate, not straight to main
    } catch (e) {
      setError(friendlyError(e, 'action'));
    } finally { setBusy(false); }
  }, [app, email, resumeIdentityFlow, routeAfterSignIn]);

  const handleResend = useCallback(async () => {
    if (!app) return;
    setBusy(true); setError(null);
    try {
      await app.auth.resendOtp(email);
      setInfo('New code sent.');
    } catch (e) {
      setError(friendlyError(e, 'action'));
    } finally { setBusy(false); }
  }, [app, email]);

  const handleForgot = useCallback(async (em: string) => {
    if (!app) return;
    setBusy(true); setError(null); setInfo(null);
    try {
      await app.auth.requestPasswordReset(em);
      setInfo('If that account exists, a reset link is on its way.');
    } catch (e) {
      setError(friendlyError(e, 'action'));
    } finally { setBusy(false); }
  }, [app]);

  /** Duress: NOTHING survives except the account login (until the server
   *  cleanup ends). b70 (VAR-16): shared by the lock screen, the Notes gate and
   *  every password prompt, so the duress code works wherever a password is asked. */
  const runDuressNow = useCallback(async () => {
    const app = realApp; // b77t (audit 5 M-E): the duress code erases the REAL records, in a decoy session too
    if (!app) return;
    await app.storage.set(WIPE_PENDING_KEY, '1').catch(() => undefined); // b70 (re-review 14): a killed wipe is finished at launch
    // b75 round 2 (audit D9): the duress wipe keeps NO pending-media list (it never retries a
    // refused Photos delete): the list it read drives this run's delete from memory only, so a
    // wipe killed in its remote phase leaves no list and no media key for a later launch
    const decoyEnds = await readDecoyEndsQuick(app.storage); // b77t merge: read before the erase (at most 300 ms)
    // b77g (NaR-1): the chats' capabilities from memory, taken before beginWipe empties the cache
    const cachedCaps = app.sessions.cachedDeliveries();
    const endWipe = beginWipe(app, [], { ended: cachedCaps }); // b70 (re-review): nothing survives, nothing writes back; b77k2 (L1)
    const { leftAfterWipe, media } = await runDuressWipe({
      storage: app.storage,
      // b77t (audit 5 L-5): + the pre-authorised purge (relay.ts duressPurgeWithToken: no login); the stored token
      // is deleted after the call whatever the answer (purgeWithStoredToken)
      relay: Object.assign(Object.create(app.relay) as typeof app.relay, { purgeWithToken: (_uid: string, tok: string) => purgeWithStoredToken(app.relay, app.storage, tok) }),
      capturePurgeToken: () => readPurgeToken(app.storage),
      userId: async () => (await app.auth.currentSession())?.user?.id ?? null,
      localTokens: () => app.sessions.listTokens(),
      writeSecretOf: async (t) => (await app.sessions.load(t))?.writeSecret ?? null,
      // b77 (sealed sender): read before the erase; the remote phase ends both mailboxes of every 1:1 chat
      deliveryOf: async (t) => chatDelivery(await app.sessions.load(t).catch(() => null)),
      cachedDeliveries: cachedCaps, // b77g (NaR-1): ended whatever the keystore's speed; deliveryOf only for the rest
      capturePushTarget: () => capturePushTargetOf(app),
      shredHardwareKey, // Batch H (R6-1-02): no prompt; the wrapped identity can never be opened again
      clearFileCache: async () => {
        // (b64) 5. encrypted vault-container file cache + stray temp files
        const cacheDir = FileSystem.cacheDirectory;
        if (!cacheDir) return 0;
        return await sweepAllLocalFiles(); // b70 (VAR-03): the whole cache, not three prefixes; b77u (U-M13): the count goes back
      },
      // (b64) 4. stego images this app saved (Photos on iOS, the chosen
      // folder on Android, b69); never asks for permission
      deleteSavedMedia: (ids) => deleteSavedMedia(ids),
      // b77u (audit 6 R4 #23): a refused or failed Photos delete is retried at the next launch (DEV-I1's no-retry is gone)
      // b77u (audit 6 R4 #22): after a purge made with the signed proof, the unspent purge token is revoked too
      revokePurgeToken: (tok) => revokePurgeTokenRemote(app.relay, null, tok ?? null),
      forgetOutsideRecords: forgetLaunchRecords, // b75 (audit AL-10): the launch flag and the lock's epoch mirror
      dropPushRegistration: (target) => dropPushRegistration(app, target), // Batch F (R4-4-17); b75 (AL-7): retried
      // b70 (audit VAR-12): the login leaves the phone with everything else
      captureLogin: async () => app.auth.takeOrphan() ?? app.auth.currentSession(), // b77k2 (review L-1): + a login only in memory
      // b70 (re-review 2): while the server cleanup still holds the real login,
      // no new identity may be made or restored (it would join the real account)
      holdLogin: (l) => { duressCleanupRef.current = true; app.auth.holdInMemory(l as Awaited<ReturnType<typeof app.auth.currentSession>>); },
      endLogin: () => app.auth.logout().finally(() => { duressCleanupRef.current = false; }),
      // b74 (audit VAR-12): the relay's purge needs the identity's signature; signed here, in
      // memory, before the erase destroys the key (no identity in memory: no purge)
      signPurgeProof: async (uid) => {
        const id = identityRef.current;
        if (!id) return null;
        const ts = Date.now();
        return { veil_id: id.veilId, ts, sig: await ikSign(id.ikSeedB64, btoa(purgeProofMessage(uid, ts))) };
      },
    });
    endWipe(); // b70 (re-review): the post-pass, then writes resume
    // b77t merge: a removed decoy's pending account delete runs from memory after its random delay (a bonus: the
    // phone is already wiped; nothing about it is stored)
    scheduleDecoyDeletes(decoyEnds);
    if (leftAfterWipe > 0) console.log(`[veil] wipe verify: ${leftAfterWipe} item(s) could not be removed`);
    else if (leftAfterWipe < 0) console.log('[veil] wipe verify: unknown — the stored keys could not be listed'); // Batch I (V-04)
    // b71 (audit): a refused or failed delete of saved photos/files is not a clean wipe
    void media.then((m) => { if (m === 'failed') console.log('[veil] wipe verify: saved photos/files were NOT all deleted — retried at the next launch'); }); // b77u (R4 #23)
    setAppLock(null); setIdentity(null); setSettings(DEFAULTS); setChat(null); setChatMessages([]); /* b70 (re-review 13): the open thread goes too */
    clearHeldSecretsRef.current(); knownSessionTokensRef.current = null; setSessionRows([]); /* b178 re-seed */ setContactRows([]); setDecoyMode(false); setDecoyAcct(null);
    setLocked(false); setScreen('identity');
  }, [realApp]);

  // b74 (review VAR-04): the opt-in erase limit lives in the lock store, so the Notes
  // gate, Settings prompts and lock changes count wrong passwords too
  useEffect(() => {
    if (!app) return;
    app.appLock.setWipeAfter(settings.wipeAfterFails ? { limit: WIPE_AFTER_FAILS, erase: runDuressNow } : null);
  }, [app, settings.wipeAfterFails, runDuressNow]);

  /** b77q owner (1 Nov): the "make your password longer" reminder after an unlock with a short code — once per app
   *  run at most (askPasswordUpgradeAfter), and only when the last one was shown a week or more ago
   *  (PASSWORD_REMINDED_KEY, a veil_ record every wipe removes). Called identically after a real and a decoy unlock:
   *  the record and the prompt depend on the code's length and the time only (b77q AP-1). */
  const remindPasswordUpgrade = (kind: string, code: string): void => {
    const app = realApp; // b77t (M-E): the real store, whichever account is in use (b77q AP-1: identical writes)
    if (!app || !askPasswordUpgradeAfter(kind, code, pwUpgradeAskedRef.current)) return;
    pwUpgradeAskedRef.current = true;
    void (async () => {
      const now = Date.now();
      if (!passwordReminderDue(await app.storage.get(PASSWORD_REMINDED_KEY).catch(() => null), now)) return;
      await Promise.resolve(app.storage.set(PASSWORD_REMINDED_KEY, String(now))).catch(() => undefined);
      setTimeout(() => Alert.alert('Make your password longer', PASSWORD_UPGRADE_NOTE), 600);
    })();
  };

  /** web parity: passcode / Decoy / Duress classification (PBKDF2 on-device) */
  const handleCode = useCallback(async (code: string) => {
    const app = realApp; // b77t (audit 5 M-E): the lock is the real app's (also when a decoy session locked)
    if (!app) return;
    // b123: a running lockout window refuses every code — the countdown
    // survives app restarts (persisted), so killing the app can't skip it.
    // b70 (re-review 3): verify() enforces it, and still accepts the DURESS code
    // (with its own small budget) — a captor who burned the attempts must not
    // be able to stop the phone from being erased
    setLockout(await app.appLock.lockout().catch(() => null));
    const t0 = Date.now();
    console.log("[veil-lock] unlock attempt"); // b199: no length — it is a password now
    setCodeVerifying(true); setCodeError(null);
    // b77u (audit 6 U-M2 / R1 F-02): this attempt's ticket. A lock, a departure, a wipe or a newer attempt
    // while the check runs voids it: the result then unlocks nothing (the duress code still erases)
    const ticket = unlockGateRef.current.begin();
    const stale = (): boolean => {
      if (unlockGateRef.current.accept(ticket)) return false;
      console.log('[veil-lock] unlock result arrived after a lock, a departure or a newer attempt — ignored');
      return true;
    };
    // b77k (IP77-6): a wipe still running (a Nothing-at-Rest departure / cold boot) refuses every
    // write, so the attempt could not be recorded and failed closed; wait for it first (bounded —
    // the fail-closed rule stays: an attempt the store refuses is still never checked)
    if (wipeBusy()) await waitWipeIdle(WIPE_IDLE_WAIT_MS);
    try {
    let kind: Awaited<ReturnType<typeof app.appLock.verify>>;
    try {
      kind = await app.appLock.verify(code);
    } catch (e) {
      if (e instanceof AppLockErasedError) return; // b74 (VAR-04): the erase already ran
      // Batch D (D-11): verify refuses during a lockout, and an unreadable lock
      // record stays locked; both say so instead of failing silently
      setLockout(await app.appLock.lockout().catch(() => null));
      setCodeError(String((e as Error)?.message ?? 'Could not check the password. Try again.'));
      setCodeResetKey(Date.now());
      return;
    }
    console.log(`[veil-lock] verify complete in ${Date.now() - t0} ms`); // b70 (re-review 8): never which kind of code
    if (kind === 'real') {
      await app.appLock.clearLockout(); setLockout(null); // b123: fresh 5-attempt budget on a good unlock
      if (stale()) return; // b77u (U-M2): a newer lock stands
      app.sessions.setDeliveryCacheEnabled(true); // b77g (NaR-1): the real chats fill it again
      // b77t (audit 5 M-E): out of a decoy session, nothing of the decoy account stays on screen
      // b77u2 (UC-M1): the decoy's veil_dk_-only memory session ends with the decoy session (a later restore or
      // new identity must start the full Nothing-at-Rest session; startNarSession also drops it)
      dropDecoyNarSession(app.storage);
      if (decoyModeRef.current) { resetAccountView(); const da = decoyAcctRef.current; if (da) { try { clearGroupRegistry(da.app.storage); } catch { /* best-effort */ } } }
      setCodeError(null); setDecoyMode(false); setDecoyAcct(null); setLocked(false); veilActivityPing();
      void decoyPush.setDecoy(false); // b75 round 2 (audit D3): only the real code ends a decoy push hold
      // audit VAR-18: a password from before the 8-character minimum still unlocks; its owner is asked
      // to make it longer (once per app run). b77m review (L3): the decoy code gets the identical prompt
      // (askPasswordUpgradeAfter) — asking only here told an observer which code was the real one
      // b77q owner (1 Nov): at most once a week (remindPasswordUpgrade, the same call in both branches)
      remindPasswordUpgrade(kind, code);
    } else if (kind === 'decoy') {
      // Decoy: harmless empty environment — real data untouched, real code still unlocks.
      // b77q (audit 3 AP-1): the decoy code resets the wrong-attempt budget exactly as the
      // real one does (verify() and this second clear, the same writes as the real branch):
      // Batch C (V-23) kept the budget running, so "N attempts remaining" after the next
      // wrong try told a captor the code handed over was the decoy. Trade-off in applock.ts.
      await app.appLock.clearLockout(); setLockout(null);
      if (stale()) return; // b77u (U-M2): a newer lock stands
      // b70 (re-review 4): whatever real chat was open when the phone locked is closed first
      // b70 (re-review 11): and a live call with a real contact ends (its overlay showed over the decoy)
      try { CallManager.hangup(); } catch { /* no call */ }
      // b77t (audit 5 M-E): the decoy's own account (its ID at once, registered in the background if new)
      const prev = decoyAcctRef.current;
      const acct = decoyModeRef.current && prev && prev.gen === currentWipeGeneration() ? prev : await openDecoyAccount(app);
      const decoySt = decoySettingsView(await acct.app.settings.load().catch(() => DEFAULTS)); // the decoy's own settings (its nickname, dials); b77t2: phone-wide lock options fixed
      if (stale()) return; // b77u (U-M2): checked again after the decoy account's awaits
      resetAccountView();
      setChat(null); setChatMessages([]); setDraft(""); setScreen("main");
      app.sessions.setDeliveryCacheEnabled(false); // b77g (NaR-1): none kept in decoy mode
      setDecoyAcct(acct);
      decoyModeRef.current = true; // b77t (M-E): before any effect of this commit runs
      setDecoySettings(decoySt); setCodeError(null); setDecoyMode(true); setLocked(false); setTab('sessions'); veilActivityPing();
      // b77m review (L3): the same "make your password longer" prompt as a real unlock with a short code
      remindPasswordUpgrade(kind, code); // b77q owner (1 Nov): weekly, as the real branch
    } else if (kind === 'duress') {
      // Duress: NOTHING survives except the account login. Batch I (local
      // security review V-01): the phone is erased FIRST (every veil_* key,
      // the hardware wrap key, the vault/stego file cache); the server cleanup
      // (purge, per-thread end, vaults, notes, Photos, push) runs afterwards
      // in the background, bounded, from values read before the wipe. A
      // stalled relay can no longer hold the local erase back.
      await runDuressNow();
    } else {
      // b123: 5 wrong attempts arm the progressive lockout. Batch D (D-11):
      // verify already counted this miss; read the state back. b74 (review VAR-04): the
      // opt-in erase after WIPE_AFTER_FAILS wrong passwords runs inside verify() now.
      const st = await app.appLock.lockout();
      setLockout(st);
      if (st.lockedUntil > Date.now()) {
        setCodeError(`Too many incorrect attempts — locked out. Try again later.`);
      } else {
        const left = MAX_ATTEMPTS - st.fails;
        setCodeError(left > 1 ? `Incorrect password. ${left} attempts remaining.` : left === 1 ? 'Incorrect password. 1 attempt remaining.' : 'Incorrect password.');
      }
      setCodeResetKey(Date.now());
    }
    } finally { setCodeVerifying(false); }
  }, [realApp, runDuressNow]);
  // b77u2 phone test (5 Nov): repeated taps on Unlock ran three checks at once on the ZTE; with a wrong code each
  // would count. One check at a time: a tap while one runs is ignored.
  const codeBusyRef = useRef(false);
  const handleCodeOnce = useCallback(async (code: string) => {
    if (codeBusyRef.current) return;
    codeBusyRef.current = true;
    try { await handleCode(code); } finally { codeBusyRef.current = false; }
  }, [handleCode]);

  /** b70 (audit VAR-01/VAR-17): a lock that is already set changes only with
   *  the current real password (AppLockStore.change checks it, and counts the
   *  attempt). The duress code typed there erases the phone. */
  const handleSetAppLock = useCallback(async (current: string | null, pass: string, decoy?: string | null, duress?: string | null) => {
    const app = realApp; // b77t (M-E)
    if (!app) return;
    if (decoyModeRef.current) {
      // b74 (review VAR-03): the decoy code is "the password" here; the real lock is
      // never touched and the change appears to fail like any decoy network action
      const kind = current === null ? null : await app.appLock.verify(current, { decoy: true }); // re-audit N2
      if (kind === 'duress') { await runDuressNow(); return; }
      throw new Error(kind === 'decoy' ? DECOY_RELAY_REFUSAL : 'Incorrect password.');
    }
    let rec: AppLockRecord;
    try {
      rec = current === null ? await app.appLock.save(pass, decoy, duress) : await app.appLock.change(current, pass, decoy, duress); // throws web-copy errors on rule violations
    } catch (e) {
      if (e instanceof AppLockWrongCodeError && e.kind === 'duress') { await runDuressNow(); return; }
      throw e;
    }
    setAppLock(rec);
    // b77t (audit 5 M-E / IH V-02, owner decision "a real throwaway account"): with a decoy code, the decoy gets
    // its own account and identity now (a random 24-word phrase made on this phone; registered in the background,
    // retried at the next decoy unlock if the relay can't be reached). Without one, its records go. The aux
    // record exists either way while a lock exists (same name, same size).
    const aux = decoyAuxOf(app);
    if (decoy) {
      void prepareDecoy(aux).then(() => registerDecoy(app)).catch((e) => console.log('[veil-decoy] decoy not prepared:', String((e as Error)?.message ?? e)));
    } else {
      // b77t merge (owner decision 2 Nov): the decoy's phrase is noted first, its records go, and its relay account
      // is deleted after a random delay with its own login (decoy-account.ts endDecoy / deleteDecoyAccount)
      void endDecoy(aux, decoyEndOf(app)).then((e) => { if (e) scheduleDecoyEndsFor(app, [e]); }).catch(() => undefined);
    }
  }, [realApp, runDuressNow]);

  /** b70 (audit VAR-01/02/17): the password prompt in front of account and key
   *  actions. Only the real code passes, and never in decoy mode. */
  const handleCheckPassword = useCallback(async (code: string): Promise<'ok' | 'wrong' | 'wiped'> => {
    const app = realApp; // b77t (M-E)
    if (!app) return 'wrong';
    let kind: Awaited<ReturnType<typeof app.appLock.verify>>;
    try { kind = await app.appLock.verify(code, { decoy: decoyModeRef.current }); } // lockout errors reach the prompt; re-audit N2
    catch (e) { if (e instanceof AppLockErasedError) return 'wiped'; throw e; }
    if (kind === 'duress') { await runDuressNow(); return 'wiped'; }
    // b74 (review VAR-03): in decoy mode the DECOY code passes (the action behind the
    // prompt then fails like the decoy's offline relay), and the real code is answered
    // exactly like a wrong one
    // b77q (audit 3 AP-1): the decoy code passing here clears the lockout as the real one does below
    if (decoyModeRef.current) { if (kind !== 'decoy') return 'wrong'; await app.appLock.clearLockout(); setLockout(null); return 'ok'; }
    if (kind === 'real') {
      await app.appLock.clearLockout();
      setLockout(null);
      sensitiveOkUntilRef.current = Date.now() + 120_000;
      return 'ok';
    }
    return 'wrong';
  }, [realApp, runDuressNow]);

  const handleRemoveAppLock = useCallback(async (pass: string): Promise<boolean> => {
    const app = realApp; // b77t (M-E)
    if (!app) return false;
    // b70 (re-review 5): the check runs in decoy mode too — attempts count and the
    // duress code erases exactly as in real mode (refusing before it gave decoy
    // mode away, and made the duress code do nothing here)
    let kind: Awaited<ReturnType<typeof app.appLock.verify>>;
    try { kind = await app.appLock.verify(pass, { decoy: decoyModeRef.current }); } catch (e) { if (e instanceof AppLockErasedError) return true; throw e; } // re-audit N2
    if (kind === 'duress') { await runDuressNow(); return true; }
    if (decoyModeRef.current) {
      // b74 (review VAR-03): the decoy code removes the lock as far as the decoy can
      // see; the real lock stays and applies again at the next lock
      if (kind !== 'decoy') return false;
      setDecoyLockHidden(true);
      return true;
    }
    if (kind !== 'real') return false;
    await app.appLock.clear();
    setAppLock(null);
    // b77t (audit 5 M-E): no lock, no decoy: the decoy's records and its aux record go. b77t merge: its relay
    // account is deleted after a random delay (the pending record, on every install, keeps its phrase until then)
    await endDecoy(decoyAuxOf(app), decoyEndOf(app), true).then((e) => { if (e) scheduleDecoyEndsFor(app, [e]); }).catch(() => undefined);
    return true;
  }, [realApp, runDuressNow]);

  const handleCreateIdentity = useCallback(async () => {
    if (decoyModeRef.current) throw new Error(DECOY_REFUSAL); // b70 (re-review 2, D2-3): never touches the real identity or account
    if (duressCleanupRef.current) throw new Error(DECOY_REFUSAL); // b70 (re-review 2): the real login is still held for the cleanup
    // local generation only — nothing touches the network until the phrase is confirmed written down
    const material = await createIdentity();
    setPendingMaterial(material);
    return { phrase: material.mnemonic, veilId: material.veilId };
  }, []);

  // b71 (device test): the step the identity set-up is on, so a stall says where it stopped
  const finishStepRef = useRef('start');
  /** b77u2 (UC info): withCurrentPassword (declared below) for the "Generate new ID" rebind */
  const withCurrentPasswordRef = useRef<((owner: VeilApp, silent: boolean, run: (currentPassword?: string) => Promise<void>) => Promise<void>) | null>(null);
  const finishCreateInner = useCallback(async () => {
    if (decoyModeRef.current) throw new Error(DECOY_REFUSAL); // b70 (re-review 2, D2-3): never touches the real identity or account
    if (duressCleanupRef.current) throw new Error(DECOY_REFUSAL); // b70 (re-review 2): the real login is still held for the cleanup
    try { app?.sessions.resumeDeliveries(); } catch { /* best-effort */ } // b77h (audit77g H-1): the new identity's chats fill the capability cache again
    (app?.storage as unknown as { clearTombstones?: () => void } | undefined)?.clearTombstones?.(); // b70 (re-review 3): a deliberate fresh start
    startNarSession(app?.storage, settingsRef.current.storageMode); // audit VAR-12
    // b77u merge (U-M13): a wipe that left something kept its marker for the next launch; a new identity on the phone
    // ends that, so the next launch does not wipe the new identity. b77u2 (UC-L2): the wipe is finished first (the key
    // shred retried, every record verified gone); if the old key still can't be destroyed, set-up stops here with a
    // clear message (LeftoverWipeError) and the marker stays. The settle's shred ends the memory session: it starts again
    if (app) { await settleLeftoverWipe(app.storage, () => sweepAllLocalFiles()); startNarSession(app.storage, settingsRef.current.storageMode); }
    // b71 (device test): this used to return silently, leaving the screen's spinner up forever
    if (!app) throw new Error('Vardum is still starting up — wait a moment and tap Continue again.');
    if (!pendingMaterial) throw new Error('The new identity was lost — go back and create it again.');
    finishStepRef.current = 'reading the sign-in';
    // b171 (builder confirmation, Oct 2 2026): the platform cannot create
    // pre-verified accounts — every signup requires a human-read OTP email,
    // and the `veilSilentAccount` function the b112 design assumed never
    // existed server-side and cannot be built as designed. The classic
    // email+OTP flow IS the permanent fresh-install path (it was the silent
    // fallback before). Native therefore no longer fires a guaranteed-404
    // custom-function call on every fresh install; it goes straight to
    // sign-in, and the identity finishes automatically right after.
    // b199: the self-hosted relay DOES provision phrase-derived accounts
    // (veilSilentAccount), so a fresh install signs in with the 24 words
    // alone — no email, no password, nothing personal. Only a relay without
    // that function falls back to the classic sign-in step.
    const phrase = pendingMaterial.mnemonic.join(' ');
    const priorSession = await app.auth.currentSession();
    if (!priorSession) {
      finishStepRef.current = 'creating the account on the server';
      try {
        const s = await provisionSilentAccount({ auth: app.auth, relay: app.relay }, phrase);
        setEmail(String(s.user?.email ?? ''));
      } catch (e) {
        // b71 (device test): thrown, so the identity screen shows it and stops spinning (it used to
        // set an app-level error the identity screen never shows, and return with the spinner up)
        if (!(e instanceof SilentAccountUnavailableError)) throw e;
        setInfo('One extra step: sign in with (or create) your Vardum account. Your new identity finishes automatically right after.');
        setScreen('login');
        return;
      }
    }
    // b77u (audit 6 R4 #28): on an account that already has an identity ("Generate new Vardum ID") the previous ID
    // approves the bind of the new one (the relay refuses a second identity otherwise)
    const approverId = retiringIdentityRef.current;
    const approverUid = priorSession?.user?.id ? String(priorSession.user.id) : '';
    // b77u2 merge (UC-L4): as in resumeIdentityFlow, a relay that wants the account's current password for this bind
    // (an account with no primary identity) gets it typed in Vardum's own window
    let id!: KeyvaultIdentity;
    const provisionNew = async (currentPassword?: string) => { id = await provisionIdentity({ relay: app.relay, vault: app.vault }, pendingMaterial, { approver: approverId && approverUid ? { ...approverId, userId: approverUid } : null, currentPassword }); };
    { const wcp = withCurrentPasswordRef.current; if (wcp) await wcp(app, isSilentAccountEmail(priorSession?.user?.email), provisionNew); else await provisionNew(); }
    // b199: "Generate new Veil ID" on a 24-word account — the sign-in follows
    // the NEW phrase (the old one is retired with the old identity), so a
    // later restore with the new 24 words still finds this account.
    let rebound = false;
    if (priorSession && isSilentAccountEmail(priorSession.user?.email)) {
      try {
        const signer = retiringIdentityRef.current;
        if (!signer) throw new Error('The previous Vardum ID is no longer on this phone to approve the change.');
        // b77u2 (UC info): as Settings does, a relay that wants the account's current sign-in (403 current_password_required)
        // gets it typed in Vardum's own window (withCurrentPassword), instead of the move failing
        const wcp = withCurrentPasswordRef.current;
        const rebind = (currentPassword?: string) => rebindSilentAccount({ auth: app.auth, relay: app.relay }, phrase, signer, id.veilId, { currentPassword }); // b70 (re-review 3): the new ID becomes primary
        if (wcp) await wcp(app, true, rebind); else await rebind();
        retiringIdentityRef.current = null;
        rebound = true; // b77u merge (W1): the rebind revoked the purge token; minted again for the new ID below
        setEmail((await deriveSilentCredentials(phrase)).email);
      } catch (e) {
        // b70 (re-review 3): at least hand the account's primary role to the new
        // ID, so "Sign in with my 24 words" can finish the move later
        const old = retiringIdentityRef.current;
        if (old) await handoverPrimaryIdentity({ auth: app.auth, relay: app.relay }, old, id.veilId).catch(() => undefined);
        retiringIdentityRef.current = null;
        console.log('[veil-error] rebind after regenerate:', String((e as Error)?.message ?? e));
        Alert.alert(
          'Sign-in not moved to your new words',
          'Your new Vardum ID is ready, but this account still signs in with your PREVIOUS 24 words. Keep them until you can retry from Settings → Account → "Sign in with my 24 words".',
        );
      }
    } else if (priorSession && retiringIdentityRef.current) {
      // b70 (re-review 3): an email-login account has no sign-in to move, but the
      // account's primary identity still passes to the new ID
      const old = retiringIdentityRef.current;
      retiringIdentityRef.current = null;
      await handoverPrimaryIdentity({ auth: app.auth, relay: app.relay }, old, id.veilId).catch((e) => console.log('[veil-error] primary handover:', String((e as Error)?.message ?? e)));
    }
    // b76 (registration lock): the lock's PIN proof was made from the previous Vardum ID's seed, so
    // moving the primary role to the new ID ended it on the relay. Say so, rather than let the
    // user believe a restore still needs the PIN.
    if (priorSession && regLockRef.current?.enabled) {
      const now = await regLockStatus(app.relay).catch(() => null);
      if (now && !now.enabled) {
        await app.auth.forgetRegLockDevice().catch(() => undefined);
        setRegLock(now);
        Alert.alert('Registration lock is off', 'Your registration lock PIN belonged to your previous Vardum ID, so the lock ended when you made the new one. Turn it on again in Settings → Recovery and devices → Registration lock.');
      }
    }
    // b77u merge (W1): the stored purge token was revoked by the rebind (and names the old ID): dropped now; the unlock
    // effect mints a fresh one for the new ID as soon as it is in memory
    if (rebound) await app.storage.remove(DURESS_PURGE_TOKEN_KEY).catch(() => undefined);
    setIdentity(id); setPendingMaterial(null); setIdentityEntry('choose');
    // b75 round 2 (audit D4): a new identity has no unbound notes: bound-only from the start
    // (the marks manifest carries it to every restore)
    await app.notes.setBoundOnly().catch(() => undefined);
    await ensureNotesKey(id);
    try { await noteVeilIdCreated(app.relay, app.storage); } catch { /* never a blocker */ }
    // b199 ONBOARDING ORDER (owner decision, Oct 16 2026 — replaces the b139
    // "land in the app, checkup later" funnel for NEW sign-ups): phrase →
    // intro slides → privacy checkup → Veil ID + passcode → app. Required,
    // no skip. The pending flag is persisted FIRST so closing the app midway
    // resumes the onboarding at the next launch instead of opening the app.
    // Owner report (Oct 18): the onboarding was skipped whenever the phone was
    // still signed in (after "Remove identity", or a reinstall that kept the
    // sign-in). Every new ID made from the start screen now gets it; only
    // Settings → "Generate new Vardum ID" returns straight to the app.
    // Phrase restores never come through here (b77f, ZTE77-4: one that leaves no app lock gets
    // the password step alone — completeRestore, onboarding mode 'passwordOnly').
    const regenerating = regeneratingIdRef.current;
    regeneratingIdRef.current = false;
    if (!regenerating) {
      const st0 = await app.settings.load();
      const st1 = { ...st0, onboardingPending: true };
      await app.settings.save(st1).catch((e) => console.error('[veil] onboarding flag save failed:', e));
      setSettings(st1);
      settingsRef.current = st1;
      setSecurePrompt(false);
      setOnboardingMode('full');
      setScreen('onboard');
      return;
    }
    setScreen('main');
    setSecurePrompt(false);
  }, [app, pendingMaterial]);

  /** b71 (device test): a stall shows an error naming the step instead of spinning forever */
  const handleFinishCreate = useCallback(async () => {
    finishStepRef.current = 'start';
    let timer: ReturnType<typeof setTimeout> | undefined;
    const watchdog = new Promise<never>((_, reject) => {
      timer = setTimeout(() => reject(new Error(`Setting up your identity is taking too long (stopped at: ${finishStepRef.current}). Check your connection, then tap Continue again.`)), 60_000);
    });
    try { await Promise.race([finishCreateInner(), watchdog]); } finally { if (timer) clearTimeout(timer); }
  }, [finishCreateInner]);

  /** Settings > Identity (web parity): local-only phrase check — the phrase never leaves the device */
  const handleVerifyPhrase = useCallback(async (phrase: string): Promise<boolean> => {
    requireSensitive(); // b70 (audit VAR-01/02/16)
    if (!app || !identity) return false;
    try {
      // derive the veil_id from the phrase locally; a phrase from another identity throws
      await restoreIdentity(phrase, identity.veilId, false);
      return true;
    } catch {
      return false;
    }
  }, [app, identity]);

  /** b77u merge (relay U-M14): a rebind the relay answers 403 current_password_required is tried again once the owner
   *  has typed the account's CURRENT password in Vardum's own window (the account's prompt; for an account that signs in
   *  with 24 words: those current words, whose derived secret is the password). Up to three tries. */
  const withCurrentPassword = useCallback(async (owner: VeilApp, silent: boolean, run: (currentPassword?: string) => Promise<void>): Promise<void> => {
    try { await run(); return; } catch (e) { if (relayErrorCode(e) !== 'current_password_required') throw e; }
    for (let tries = 0; tries < 3; tries++) {
      const a = await askFor(owner, silent
        ? { title: 'Confirm with your current 24 words', message: `${tries ? 'Those words were not accepted. ' : ''}This account was set up in a way that needs its current sign-in to change it. Enter the 24 words this account signs in with now.`, input: 'phrase', submitLabel: 'Continue' }
        : { title: 'Enter your current password', message: `${tries ? 'That password was not accepted. ' : ''}To change how this account signs in, enter the password it signs in with now.`, input: 'secure', submitLabel: 'Continue' });
      if (typeof a !== 'string' || !a.trim()) throw new Error('Nothing was changed: the current password was not entered.');
      const cur = silent ? (await deriveSilentCredentials(canonicalPhrase(a))).password : a;
      try { await run(cur); return; } catch (e) {
        const c = relayErrorCode(e);
        if (c !== 'wrong_password' && c !== 'current_password_required') throw e;
      }
    }
    throw new Error('Nothing was changed: the current password was not accepted.');
  }, [askFor]);
  withCurrentPasswordRef.current = withCurrentPassword; // b77u2 (UC info)

  /** b77u merge (W1): sign-out-others, a password change and a rebind revoke the account's duress purge token on the
   *  relay. The phone that made the change drops its stored copy and mints a fresh one at once (real account only). */
  const renewPurgeTokenNow = useCallback(async (a: VeilApp | null): Promise<void> => {
    const id = identityRef.current;
    if (!a || a !== realAppRef.current || decoyModeRef.current || duressCleanupRef.current || !id) return;
    await a.storage.remove(DURESS_PURGE_TOKEN_KEY).catch(() => undefined);
    const uid = (await a.auth.currentSession().catch(() => null))?.user?.id ?? null;
    await refreshPurgeToken({ relay: a.relay, storage: pinToWipe(a.storage), userId: uid, signer: { veilId: id.veilId, sign: (m) => ikSign(id.ikSeedB64, m) }, force: true });
  }, []);

  /** b199 Settings > Account "Sign in with my 24 words": a made-up-email
   *  account moves its sign-in to the phrase. The phrase is checked against
   *  THIS identity on-device first; only the derived label + password reach
   *  the relay. The old email + password stop working. */
  const handleSwitchToPhraseSignIn = useCallback(async (phrase: string): Promise<'ok' | 'wrong-phrase'> => {
    requireSensitive(); // b70 (audit VAR-01/02/16)
    if (!app || !identity) return 'wrong-phrase';
    const norm = canonicalPhrase(phrase);
    try { await restoreIdentity(norm, identity.veilId, false); } catch { return 'wrong-phrase'; }
    // b77u merge (relay U-M14): the relay may want the account's current password too (403 current_password_required)
    const silentNow = isSilentAccountEmail((await app.auth.currentSession().catch(() => null))?.user?.email);
    await withCurrentPassword(app, silentNow, (currentPassword) => rebindSilentAccount({ auth: app.auth, relay: app.relay }, norm, { veilId: identity.veilId, ikSeedB64: identity.ikSeedB64 }, '', { currentPassword })); // b70 (re-review R2)
    setEmail((await deriveSilentCredentials(norm)).email);
    void renewPurgeTokenNow(app); // b77u merge (W1): the rebind revoked the purge token on the relay
    return 'ok';
  }, [app, identity, withCurrentPassword, renewPurgeTokenNow]);

  /** b77s (owner decision): Settings > Account "Sign out all other devices" — every other login of this
   *  account ends on the relay (this phone's stays). Behind the real app password (requireSensitive);
   *  in decoy mode it fails like the decoy's offline relay, before anything is sent. */
  const handleSignOutOtherDevices = useCallback(async (): Promise<number> => {
    requireSensitive();
    if (!app) throw new Error('Vardum is still starting up. Try again in a moment.');
    // b77t (audit 5 L-6): the relay needs a fresh credential — this phone's Vardum ID signs (a relay nonce); the relay
    // then revokes every login, this phone's too, and the new one is stored (relay cfg setToken)
    const id = identityRef.current;
    const userId = (await app.auth.currentSession())?.user?.id ?? '';
    const n = await app.relay.signOutOtherDevices(id && userId ? { signer: { veilId: id.veilId, sign: (m) => ikSign(id.ikSeedB64, m) }, userId } : {});
    void renewPurgeTokenNow(app); // b77u merge (W1): the sign-out revoked the purge token on the relay
    return n;
  }, [app, renewPurgeTokenNow]);

  /** b77s (owner decision): Settings > Account "Change password" — email accounts only (a 24-word account's
   *  password is derived from the phrase: isSilentAccountEmail). The new password follows the email-account
   *  minimum (EMAIL_PASSWORD_MIN, as at sign-up). Refused in decoy mode (requireSensitive). */
  const handleChangeAccountPassword = useCallback(async (oldPassword: string, newPassword: string): Promise<number> => {
    requireSensitive();
    if (!app) throw new Error('Vardum is still starting up. Try again in a moment.');
    if (!email || isSilentAccountEmail(email)) throw new Error('This account signs in with your 24 words, so it has no email password to change.');
    const problem = emailPasswordProblem(newPassword);
    if (problem) throw new Error(`${problem} Nothing was changed.`);
    const n = await app.relay.changePassword(oldPassword, newPassword);
    void renewPurgeTokenNow(app); // b77u merge (W1): the change revoked the purge token on the relay
    return n;
  }, [app, email, renewPurgeTokenNow]);

  /** Settings > Identity (web parity "Remove from this device"): drop this device's keyvault copy.
   *  b75 (audit DEV-I5): and the notes key derived from it (stored and in memory); the
   *  phrase restores both. Chats, history, pins and settings stay, and the Settings row
   *  says so ("Wipe Vardum from this phone" removes everything). */
  const handleRemoveIdentity = useCallback(async () => {
    requireSensitive(); // b70 (audit VAR-01/02/16)
    if (!app) return;
    await app.vault.clear();
    try { app.notes.forget(); } catch { /* best-effort */ }
    await secureRemove(app.storage, NOTES_KEY_STORAGE).catch(() => undefined);
    setIdentity(null);
    regeneratingIdRef.current = false;
  }, [app]);

  /** "Generate new Veil ID": the old identity's keyvault copy is removed first, then the
   *  create flow runs — fresh keys, a fresh ID and new 24 words. b75 (audit DEV-M1): the
   *  relay account stays the same (and the old identity signs the move to the new one), so
   *  the server can link the two IDs; Settings says so and points to a wipe and a new
   *  account for a clean break. The 24-word reveal step is mandatory before anything is
   *  published. */
  const handleGenerateNewVeilId = useCallback(async () => {
    requireSensitive(); // b70 (audit VAR-01/02/16)
    if (!app) return;
    // b70 (re-review R2): the outgoing identity signs the sign-in move to the
    // new words, so it is held in memory (only) until the new one is provisioned
    retiringIdentityRef.current = identityRef.current ? { veilId: identityRef.current.veilId, ikSeedB64: identityRef.current.ikSeedB64 } : null;
    await app.vault.clear();
    setIdentity(null);
    regeneratingIdRef.current = true;
    setIdentityEntry('confirm-create');
    setScreen('identity');
  }, [app]);

  /** Settings > Identity when no identity is on this device — open the create/restore flow */
  const handleOpenIdentityFlow = useCallback(() => {
    if (decoyModeRef.current) { Alert.alert('Vardum', DECOY_REFUSAL); return; } // b70 (re-review 2, D2-3)
    regeneratingIdRef.current = false;
    setIdentityEntry('choose');
    setScreen('identity');
  }, []);

  const handleRestore = useCallback(async (rawPhrase: string) => {
    if (decoyModeRef.current) throw new Error(DECOY_REFUSAL); // b70 (re-review 2, D2-3): never touches the real identity or account
    if (duressCleanupRef.current) throw new Error(DECOY_REFUSAL); // b70 (re-review 2): the real login is still held for the cleanup
    if (!app) return;
    // b199: one canonical phrase for every step (sign-in derivation, identity
    // re-derivation, the pending-restore resume) — IdentityScreen already
    // validated it; this keeps any other caller on the same form.
    const phrase = canonicalPhrase(rawPhrase);
    // b112: the phrase now recovers the ACCOUNT too. No session on this
    // device → sign in with the phrase-derived credentials first.
    // b77k (IP77-4): "no session" = no usable token (a stale session without one, seen after a
    // duress wipe, skipped the sign-in and the identity register went out unauthenticated: 401)
    // b77k2 (review L4): the phrase sign-in, as a step: true = signed in; false = it handled the
    // outcome itself (the registration-lock PIN prompt, the email sign-in offer, an error shown)
    const signInWithPhrase = async (): Promise<boolean> => {
      try {
        const s = await silentLogin({ auth: app.auth, relay: app.relay }, phrase);
        setEmail(String(s.user?.email ?? ''));
        // b77k2 (IP77-4): never register the identity without a token (401): say so, and let them retry
        if (!(await app.auth.getToken().catch(() => null))) {
          setError('Signed in, but this phone could not keep the sign-in yet. Wait a few seconds and tap Restore again.');
          return false;
        }
        return true;
      } catch (e) {
        // b76 (registration lock): the words were right but the account is locked to its own phone
        // — the restore screen asks for the lock's PIN (handleRegLockPin) and says when it lapses
        const rl = regLockInfo(e);
        if (rl) { setRegLockPrompt({ phrase, kind: 'silent', info: rl }); return false; }
        if (isCredentialFailure(String((e as Error).message ?? e))) {
          // b77 rollout (owner: "Restore keeps old ID"): an ID from a build on the older relay has no account on this
          // one. Not bound here at all = create the phrase-derived account, and the restore re-registers the same ID
          // (src/relay-move-restore.ts). Bound here, or the lookup failed = the email sign-in offer below, as before.
          let carried: 'provisioned' | 'bound-here' | 'unknown' = 'unknown';
          try {
            carried = await carryIdToThisRelay({
              veilId: async () => (await restoreIdentity(phrase, undefined, false)).veilId,
              lookupAnon: (id) => app.relay.identityLookupAnon(id),
              provision: async () => {
                const s = await provisionSilentAccount({ auth: app.auth, relay: app.relay }, phrase);
                setEmail(String(s.user?.email ?? ''));
              },
            });
          } catch (pe) {
            setError(friendlyError(pe, 'restore'));
            return false;
          }
          if (carried === 'provisioned') {
            console.log('[veil-restore] no account on this relay for these words - created it; the restore re-registers the same ID');
            if (!(await app.auth.getToken().catch(() => null))) {
              setError('Signed in, but this phone could not keep the sign-in yet. Wait a few seconds and tap Restore again.');
              return false;
            }
            return true;
          }
          // pre-b112 email account — classic sign-in, then the restore
          // resumes automatically (resumeIdentityFlow)
          setPendingRestorePhrase(phrase);
          // b199: say WHY this screen appeared — the words are valid (checked
          // on-device), but no 24-word account exists for them on the relay
          console.log('[veil-restore] valid phrase, no 24-word account on the relay — offering the email sign-in');
          setInfo('Your 24 words are valid, but no account signs in with them yet. If this identity was set up with an email address, sign in with it below and your identity restores right after.');
          setScreen('login');
          return false;
        }
        setError(friendlyError(e, 'restore'));
        return false;
      }
    };
    // b77k2 (IP77-4, iPhone: duress wipe, then Restore — the first tap failed with a 401, the second
    // worked): the duress wipe's post-wipe barrier refused every veil_ write until a fresh start, which
    // only came inside completeRestore, AFTER the sign-in — so the sign-in's stored login was refused
    // (persist ignored that) and the register went out without a token. Now: a running wipe is waited
    // for (bounded; still running = no restore yet), a refused login write is kept in memory for this
    // run (auth.ts persist), and the fresh start comes once the sign-in has succeeded (re-review L2:
    // not before it, nor while a wipe still runs), so the login is stored before the register.
    if (wipeBusy() && !(await waitWipeIdle(WIPE_IDLE_WAIT_MS))) {
      setError('A wipe is still finishing on this phone. Wait a few seconds and tap Restore again.');
      return;
    }
    let signedIn = false;
    if (!(await app.auth.getToken().catch(() => null))) {
      if (!(await signInWithPhrase())) return;
      signedIn = true;
    }
    try { app.sessions.resumeDeliveries(); } catch { /* best-effort */ } // b77h (audit77g H-1): the new identity's chats fill the capability cache again
    (app.storage as unknown as { clearTombstones?: () => void }).clearTombstones?.(); // b77k2 (IP77-4 / L2): the fresh start, after a successful sign-in
    startNarSession(app.storage, settingsRef.current.storageMode); // audit VAR-12
    await settleLeftoverWipe(app.storage, () => sweepAllLocalFiles()); // b77u merge (U-M13); b77u2 (UC-L2): refuses (throws) while the old key stands
    startNarSession(app.storage, settingsRef.current.storageMode); // b77u2 (UC-L2): again if the settle's shred ended it
    await app.auth.getToken().catch(() => null); // b77k2 (IP77-4): a login kept in memory is stored now
    // b77k2 (review L4): a stored token can be expired or revoked: a 401 from the restore signs in
    // with the phrase once and retries once (restore-password.ts restoreRetryingSignIn)
    await restoreRetryingSignIn(() => completeRestore(phrase), signInWithPhrase, { signedInAlready: signedIn });
  }, [app, completeRestore]);

  /** b76 (registration lock): the PIN for a restore the relay held. The proof is made on this phone
   *  from the 24 words being restored (their identity seed) and the PIN; neither leaves the phone.
   *  A wrong PIN or a wait only updates what the restore screen shows. */
  const handleRegLockPin = useCallback(async (pin: string) => {
    if (decoyModeRef.current || duressCleanupRef.current) throw new Error(DECOY_REFUSAL);
    const p = regLockPromptRef.current;
    if (!app || !p) return;
    const material = await restoreIdentity(p.phrase, undefined, false);
    const pinAuth = await regLockPinAuth(material.ikSeedB64, pin);
    try {
      if (p.kind === 'silent') {
        const s = await silentLogin({ auth: app.auth, relay: app.relay }, p.phrase, { regLockPin: pinAuth });
        setEmail(String(s.user?.email ?? ''));
      } else {
        await app.auth.login(String(p.email ?? ''), regLockPasswordRef.current, { regLockPin: pinAuth });
        setEmail(String(p.email ?? ''));
        setPendingRestorePhrase(null);
      }
    } catch (e) {
      const rl = regLockInfo(e);
      if (rl) { setRegLockPrompt({ ...p, info: rl }); return; }
      throw e;
    }
    regLockPasswordRef.current = '';
    setRegLockPrompt(null);
    await completeRestore(p.phrase);
  }, [app, completeRestore]);

  /** b76 (registration lock): back out of the PIN step (nothing was restored) */
  const handleRegLockCancel = useCallback(() => {
    regLockPasswordRef.current = '';
    setRegLockPrompt(null);
    setPendingRestorePhrase(null);
    setIdentityEntry('choose');
  }, []);

  /** b76 (registration lock): Settings — read the lock's state (and check in) */
  const refreshRegLock = useCallback(async () => {
    if (!app || decoyModeRef.current || !identityRef.current) return;
    try {
      // b76r1 (audit D3): this phone's device key rides along, so the answer says whether this is
      // still the owning phone (and when the PIN last restored the account elsewhere)
      const session = await app.auth.currentSession().catch(() => null);
      const dev = session?.user?.email ? await app.auth.regLockDevice(String(session.user.email)) : null;
      setRegLock(await regLockStatus(app.relay, dev));
    } catch { /* offline: keep what we knew */ }
  }, [app]);

  /** b76 (registration lock): turn the lock on, or change its PIN (Settings asked for the app password) */
  const handleRegLockSet = useCallback(async (pin: string) => {
    requireSensitive();
    const id = identityRef.current;
    const session = app ? await app.auth.currentSession() : null;
    if (!app || !id || !session?.user?.id) throw new Error('Set up your Vardum ID on this phone first.');
    // b76r1 (audit I5): the state is read back whether or not the set worked (a key this phone
    // couldn't save turns the lock off again; Settings must show what is true)
    try {
      await regLockSet({ relay: app.relay, auth: app.auth }, { veilId: id.veilId, ikSeedB64: id.ikSeedB64 }, pin, { userId: String(session.user.id), email: String(session.user.email ?? '') });
    } finally { await refreshRegLock(); }
  }, [app, refreshRegLock]);

  /** b76 (registration lock): turn it off (Settings asked for the app password) */
  const handleRegLockOff = useCallback(async () => {
    requireSensitive();
    const id = identityRef.current;
    const session = app ? await app.auth.currentSession() : null;
    if (!app || !id || !session?.user?.id) throw new Error('Set up your Vardum ID on this phone first.');
    await regLockOff({ relay: app.relay, auth: app.auth }, { veilId: id.veilId, ikSeedB64: id.ikSeedB64 }, String(session.user.id));
    setRegLock({ enabled: false, failedAttempts: 0, lapseAt: 0 });
  }, [app]);

    useEffect(() => { lockedRef.current = locked; }, [locked]);
    // b77t2 (CM-2): a key-change warning withdrawn by the lock (or a switch) is asked again at the next unlock of its
    // account if its chat is still open (otherwise at that chat's next open) — never silently revoked
    useEffect(() => {
      if (locked) return;
      for (const [tok, again] of [...keyChangeRetryRef.current]) {
        if (chatRef.current?.token !== tok) continue;
        keyChangeRetryRef.current.delete(tok);
        again();
      }
    }, [locked, app]);
    // b71 (device test): messages the background sync took in for the open chat while the
    // phone was locked join the open thread at unlock (its own poll was paused)
    useEffect(() => {
      if (locked || !lockedOpenSyncedRef.current || !app || !chatRef.current) return;
      lockedOpenSyncedRef.current = false;
      const t = chatRef.current.token;
      const { onThread, setThreadMessages } = threadGuard(t, app); // b77u (audit 6 U-M3)
      app.sessions.cachedMessages(t).then((rows) => {
        if (!onThread()) return;
        setThreadMessages((prev) => {
          const ids = new Set(prev.map((m) => m.id));
          const add = rows.filter((m) => !ids.has(m.id));
          return add.length ? [...prev, ...add] : prev;
        });
      }).catch(() => undefined);
    }, [locked, app]);

  /** handoff §2 Account: "Lock now" */
  const handleLockNow = useCallback(() => setLocked(true), []);
  // b70 (VAR-03): temporary plaintext never outlives an unlock or an open chat
  // b70 (re-review 8): Android security-chip mode — the weekly (b74) key refresh runs after a
  // normal unlock, with a word first, because saving the identity there asks for a
  // fingerprint (it used to be skipped, so those keys never changed)
  const prekeyAskedRef = useRef(false);
  useEffect(() => {
    if (!app || !identity || locked || decoyMode || prekeyAskedRef.current) return;
    if (!(Platform.OS === 'android' && settings.storageMode === 'hardware')) return;
    if (!prekeysRotationDue(identity, Date.now(), PREKEY_ROTATE_HW_MS)) return; // b74 (V-03): weekly here too (asked, for the fingerprint prompt)
    prekeyAskedRef.current = true; // once per app run; "Later" asks again next time
    // b77t2 (CM-2): in-window and tagged with the real account — a system Alert stayed up over the lock and the
    // decoy session, and "Continue" rotated the real keys. Withdrawn by a lock or switch: asked again next unlock
    const owner = app;
    void askFor(owner, {
      title: 'Refreshing your security keys',
      message: 'Once a week Vardum replaces the keys new chats and groups start from, so a lost or seized phone exposes less. Confirm with your fingerprint.', // b74 (V-03): weekly here too
      confirm: true, submitLabel: 'Continue', cancelLabel: 'Later',
    }, { onWithheld: () => { prekeyAskedRef.current = false; } }).then((go) => {
      if (go !== true || activeAppRef.current !== owner) return;
      void rotatePrekeysIfDue({ relay: owner.relay, vault: pinToWipe(owner.vault), storage: pinToWipe(owner.storage) }, identityRef.current ?? identity, { intervalMs: PREKEY_ROTATE_HW_MS }) // b73 (audit V-03)
        .then((rotated) => { if (!decoyModeRef.current) setIdentity(rotated); })
        .catch((e) => console.warn('[veil-prekeys] rotation deferred:', String((e as Error)?.message ?? e)));
    });
  }, [app, identity, locked, decoyMode, settings.storageMode]);

  // b70 (re-review 7): the self-destruct clock is also checked every minute while the
  // app stays in the foreground (it used to run only at a cold start or a return
  // from the background, so a phone kept on the lock screen never wiped)
  useEffect(() => {
    const app = realApp; // b77t (audit 5 M-E): the real clock and the real records, in a decoy session too
    if (!app) return;
    let busyWipe = false;
    const t = setInterval(() => {
      if (busyWipe) return;
      void (async () => {
        await noteSelfDestructClock(app.storage, selfDestructArming(settingsRef.current));
        if (!selfDestructDue(settingsRef.current)) return;
        busyWipe = true;
        try {
          await selfDestructWipe(app);
          setAppLock(null); setIdentity(null); setSettings(DEFAULTS); setChat(null); setChatMessages([]); /* b70 (re-review 13): the open thread goes too */
          clearHeldSecretsRef.current(); knownSessionTokensRef.current = null; setSessionRows([]); /* b178 re-seed */ setContactRows([]); setDecoyMode(false); setLocked(false); setScreen('identity');
        } finally { busyWipe = false; }
      })();
    }, 60_000);
    return () => clearInterval(t);
  }, [realApp]);
  // b70 (re-review 5): a recording still running when the phone locks is cancelled (its file deleted)
  useEffect(() => { if (locked) { if (voiceRecRef.current) handleVoiceCancelRef.current?.(); purgeTempFiles(); } }, [locked, purgeTempFiles]);
  const wasInChatRef = useRef(false);
  useEffect(() => {
    if (wasInChatRef.current && screen !== 'chat') purgeTempFiles();
    // audit VAR-02: leaving the chat screen by ANY route closes the chat (onBack always did; the
    // add-contact link and other jumps to the main screen didn't)
    if (wasInChatRef.current && screen !== 'chat') { setChat(null); setChatMessages([]); }
    wasInChatRef.current = screen === 'chat';
  }, [screen, purgeTempFiles]);
  useEffect(() => { void purgeTmp(); }, []);

  /** b62/b139: join an invite or group link */
  const handleJoinInvite = useCallback(async (link: string) => {
    // b77t (audit 5 M-E): joins on the decoy's own account in a decoy session (`app`, `identity` are the decoy's)
    if (!app || !identity) throw new Error('Create your Vardum identity first — Settings → Identity.');
    const who = await clientId();
    if (!who) throw new Error('Sign in first.');
    if (/[?&]g=/.test(link)) {
      const j = await joinGroup(
        { sessions: pinToWipe(app.sessions), relay: app.relay, storage: pinToWipe(app.storage), webBaseUrl: VEIL_LINK_URL }, // b70 (re-review 9): a wipe while this waits on the relay stops its writes
        {
          link, clientId: who,
          identity: { veilId: identity.veilId, ikSeedB64: identity.ikSeedB64, ikPubB64: identity.ikPubB64, pqPrivB64: identity.pqPrivB64 },
          nickname: chatSettings.nickname || '', // b71: the name members see (signed, sent only inside the group)
        },
      );
      groupKnownTokensRef.current[j.token] = j.groupToken;
    } else {
      await joinInviteSession(
        { sessions: pinToWipe(app.sessions), relay: app.relay, webBaseUrl: VEIL_LINK_URL }, // b70 (re-review 9): a wipe while this waits on the relay stops its writes
        { link: oneToOneInviteLink(link), clientId: who, displayName: chatSettings.nickname || '' }, // b77q (audit 3 DV-3): never a signed-in seat join
      );
    }
    // b199 (owner hardware test Oct 16: "Joined" then a long wait before the
    // group showed): opening the invite card unlocks burns, and pending burns
    // hold ambient relay traffic — which silently skipped this refresh. A join
    // the user just tapped is not ambient: force it so the row appears now.
    await refreshSessions(true);
  }, [app, identity, chatSettings.nickname]);

  /**
   * b184 deep links: invites arrive via universal links (audit VAR-40: the veil:// scheme is gone)
   * (applinks:tryveil.app). The web marketing page's invite handoff opens this
   * app with the original tryveil.app/?join=...#w=... link (or the token/key
   * in its own query); normalize whatever shape arrives back into the full
   * https link and feed it through the existing handleJoinInvite flow once the
   * user is signed in and unlocked. Survives lock: consumed when unlocked.
   */
  const pendingInviteRef = useRef<string | null>(null);
  // Batch G (round-5 review R5-3-07 / R4-3-10): bumped when a link arrives, so the
  // confirmation below runs at once even while the app is already unlocked
  const [inviteTick, setInviteTick] = useState(0);
  const normalizeInviteUrl = useCallback((raw: string): string | null => {
    if (!raw) return null;
    const full = raw.match(APP_LINK_IN_TEXT_RE); // b77s (owner): tryveil.app or tryvardum.app
    if (full) return full[0];
    const jm = raw.match(/[?&]join=([A-Za-z0-9]+)/);
    if (!jm) return null;
    // b54: keep the WHOLE fragment — it carries w= plus the link secret k=
    // (and g=/e=/c= for groups); dropping any of it makes the join fail.
    const frag = raw.match(/#(w=[^\s"']+)/);
    return 'https://tryveil.app/?join=' + jm[1] + (frag ? '#' + frag[1] : '');
  }, []);

  // b199 Veil QR: add links (https://tryveil.app/?add=<Veil ID>) are checked
  // FIRST — normalizeInviteUrl accepts any tryveil.app/?… link and would feed
  // an add link into the invite-join path. State (not a ref) so a link opened
  // while the app is already unlocked acts at once.
  const [pendingAdd, setPendingAdd] = useState<string | null>(null);
  const [prefillAdd, setPrefillAdd] = useState<{ veilId: string; nonce: number } | null>(null);
  useEffect(() => {
    // Batch G (R5-3-07): subscribe here (not inside the async block) so the effect's
    // cleanup really removes the listener
    const sub = Linking.addEventListener('url', ({ url: raw }) => {
      const url = trustedAppLink(raw); // audit VAR-40 (1f51): https://tryveil.app links only — no custom scheme
      if (!url) return;
      const add = parseVeilAddLink(url);
      if (add) { setPendingAdd(add); return; }
      const n = normalizeInviteUrl(url);
      if (n) { pendingInviteRef.current = n; setInviteTick((t) => t + 1); }
    });
    (async () => {
      try {
        const init = trustedAppLink(await Linking.getInitialURL()); // audit VAR-40 (1f51)
        const add = init ? parseVeilAddLink(init) : null;
        const n = init && !add ? normalizeInviteUrl(init) : null;
        if (add) setPendingAdd(add);
        else if (n) { pendingInviteRef.current = n; setInviteTick((t) => t + 1); }
      } catch { /* best-effort */ }
    })();
    return () => { sub.remove(); };
  }, [normalizeInviteUrl]);

  useEffect(() => {
    if (!pendingAdd || !app || !identity || locked) return;
    if (screen !== 'main' && screen !== 'chat') return; // never skip onboarding / setup — waits until the app proper
    const id = pendingAdd;
    setPendingAdd(null);
    // b70 (re-review 4): in decoy mode every ID is treated alike (the "own QR" answer confirmed the real ID)
    if (id === identity.veilId && !decoyMode) { Alert.alert('That’s your own QR', 'Send it to someone else so they can add you.'); return; }
    setScreen('main');
    setTab('contacts');
    setPrefillAdd({ veilId: id, nonce: Date.now() });
  }, [pendingAdd, app, identity, locked, screen, decoyMode]);

  useEffect(() => {
    const link = pendingInviteRef.current;
    if (!link || !app || !identity || locked) return;
    if (screen !== 'main' && screen !== 'chat') return; // never pops over onboarding / setup
    pendingInviteRef.current = null;
    // Batch E (round-3 review R3-04): a link opened from outside the app used to
    // join at once, handing the link's maker this phone's Vardum ID, identity key
    // and nickname with no tap. Ask first.
    const isGroup = /[?&]g=/.test(link); // Batch F (R4-4-18): the same test the join uses
    Alert.alert(
      isGroup ? 'Join this group?' : 'Join this chat?',
      // b77q (audit 3 AP-4 / AQ-4): any app can open such a link, so the prompt says where it came from
      (isGroup ? GROUP_JOIN_NOTE : 'Joining starts a chat, on your account, with whoever made this link. Until you compare safety codes you can’t be sure who that is. Only join links you trust.') + '\n\n' + LINK_FROM_OUTSIDE_NOTE,
      [
        { text: 'Cancel', style: 'cancel' },
        { text: 'Join', onPress: () => {
          handleJoinInvite(link).catch((e: Error) =>
            Alert.alert('Invite', 'Could not open that invite link: ' + (e?.message || 'unknown error'))
          );
        } },
      ],
    );
  }, [app, identity, locked, screen, inviteTick]);

  // b75 (audit XF-1 / XF-3 / XF-4): settling a move on the OLD phone. The moved chats stay
  // paused until the new phone's ack proof arrives (they are then retired here), or until
  // the user decides, which Vardum asks once the pause reaches MOVE_PAUSE_CAP_MS (the
  // move code's 10 minutes plus a margin). What the relay says never retires or resumes
  // them on its own: a relay can't forge the proof, and its "expired" / "fetched" can't
  // be checked, so it is only quoted to the user as unverified.
  /** b70 (re-review 7): never over the lock, in decoy mode or during a duress cleanup — it waits */
  const untilShowable = async () => { while (transferQuiet()) await new Promise((r) => setTimeout(r, 5000)); };
  /** b77t2 (CM-2): ask `owner` (the real account) once it can be shown — a lock or switch that withdraws the prompt
   *  waits and asks again; null once the account is gone (a wipe) */
  const askRealWhenShowable = async (owner: VeilApp, spec: PromptSpec): Promise<{ answer: string | boolean | null } | null> => {
    for (;;) {
      await untilShowable();
      if (realAppRef.current !== owner) return null;
      let withheld = false;
      const answer = await askFor(owner, spec, { onWithheld: () => { withheld = true; } });
      if (!withheld) return { answer };
      await new Promise((r) => setTimeout(r, 1000));
    }
  };
  const showMoved = useCallback(async (owner: VeilApp, n: number, at: number | undefined, sas: string | undefined) => {
    await untilShowable();
    const when = at ? new Date(at).toLocaleTimeString() : 'just now';
    // b77t (audit 5 L-20): in-window (it shows the move code). b77t2 (CM-2): the real account's own prompt
    const r = await askRealWhenShowable(owner, {
      title: 'Moved to your new phone',
      message: `${n === 1 ? 'Your chat was' : `Your ${n} chats were`} collected at ${when} by ${sas ? `the phone that showed code ${sas}` : 'your new phone'}, and removed from this one.`,
      confirm: true, submitLabel: 'This wasn\u2019t me', cancelLabel: 'OK',
    });
    if (r?.answer === true) await askRealWhenShowable(owner, { title: 'If this wasn\u2019t you', message: moveNotMeText(sas), info: true });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [askFor]);
  const askKeepOrRemove = useCallback(async (pending: PendingTransfer, hint?: 'not-collected' | 'collected') => {
    if (!app) return;
    await untilShowable();
    const n = pending.sessionTokens.length;
    const said = hint === 'not-collected' ? ' Vardum\u2019s server says nothing was collected, but this phone can\u2019t check that.'
      : hint === 'collected' ? ' Vardum\u2019s server says the chats were collected, but this phone can\u2019t check that.' : '';
    // b77t2 (CM-2): in-window and tagged with this (real) account — a system Alert stayed up over the lock and the
    // decoy session, and its answer kept or removed the real chats. A tap outside the card answers "Not now"
    const r = await askRealWhenShowable(app, {
      title: 'Did your new phone get your chats?',
      message: `This phone sent ${n === 1 ? '1 chat' : `${n} chats`} to a new phone but has no proof that it imported them. Only the new phone can give that proof.${said}\n\nIf your new phone shows ${n === 1 ? 'the chat' : 'these chats'}, remove ${n === 1 ? 'it' : 'them'} here. If it doesn\u2019t, keep using ${n === 1 ? 'it' : 'them'} here, and don\u2019t use ${n === 1 ? 'it' : 'them'} on the new phone too: a chat used on two phones stops working.`,
      choices: [
        { label: 'Not now', value: 'later' },
        { label: 'Keep using here', value: 'keep' },
        { label: 'Remove from this phone', value: 'remove', danger: true },
      ],
    });
    const choice = r?.answer === 'keep' || r?.answer === 'remove' ? r.answer : 'later';
    if (choice === 'keep') {
      await keepMovedChatsHere({ relay: app.relay, storage: app.storage }, pending);
      app.sessions.unfreezeMoving(pending.sessionTokens);
    } else if (choice === 'remove') {
      await removeMovedChatsHere({ sessions: app.sessions, storage: app.storage }, pending);
      app.sessions.unfreezeMoving(pending.sessionTokens);
      refreshSessionsRef.current?.();
    } else {
      await markTransferAsked(app.storage, pending.token).catch(() => undefined); // asked again the next time Vardum starts
    }
  }, [app]);
  /** Settings' "Last move" row */
  const getLastMove = useCallback(async () => (app ? loadLastMove(app.storage) : null), [app]);
  const settleMove = useCallback(async (pending: PendingTransfer) => {
    if (!app) return;
    app.sessions.freezeMoving(pending.sessionTokens); // b70 (re-review P3): still on its way
    const res = await finishTransferMove({ relay: app.relay, sessions: app.sessions, storage: app.storage }, pending);
    if (res.state === 'used') {
      app.sessions.unfreezeMoving(pending.sessionTokens);
      refreshSessionsRef.current?.();
      await showMoved(app, res.retired, res.at, pending.sas);
    } else if (res.state === 'unconfirmed') {
      await askKeepOrRemove(pending, res.hint);
    }
  }, [app, showMoved, askKeepOrRemove]);

  // Batch E (F-3): a move whose proof this phone never saw (the app was closed or
  // killed) is settled after the next real unlock — every pending move, newest first.
  const pendingTransferCheckedRef = useRef(false);
  useEffect(() => {
    // b70 (re-review 3): never in decoy mode (it would show, or delete, the real chats); it runs after a real unlock
    if (!app || !identity || locked || decoyMode || pendingTransferCheckedRef.current) return;
    pendingTransferCheckedRef.current = true;
    (async () => {
      const all = (await loadPendingTransfers(app.storage)).sort((x, y) => y.createdAt - x.createdAt);
      for (const pending of all) app.sessions.freezeMoving(pending.sessionTokens);
      // each waits for its proof in the background until its pause ends (MOVE_PAUSE_CAP_MS), then asks
      for (const pending of all) void settleMove(pending).catch(() => undefined);
    })().catch(() => undefined);
  }, [app, identity, locked, decoyMode]);

  /** b139 welcome thread: "Don't show again" */
  const handleHideWelcome = useCallback(async () => {
    if (!app || decoyModeRef.current) return; // b70 (re-review 9): never the real settings from decoy mode
    try {
      const st = { ...(await app.settings.load()), welcomeDismissed: true };
      await app.settings.save(st);
      setSettings(st);
    } catch { /* best-effort */ }
    setScreen('main');
  }, [app]);

  /** auto-lock §0: fixed 1-minute INACTIVITY rule, always on — checks every 5s
   *  while the app is foregrounded; any touch resets the clock via the root
   *  responder. Locking the phone / leaving the app is instant (AppState). */
  useEffect(() => {
    const tick = () => {
      if (AppState.currentState !== 'active') return;
      if (lockedRef.current) return;
      if (!identityRef.current && !appLockRef.current) return;
      // b199: a vault transfer in progress holds the no-touch timer;
      // backgrounding still locks
      // b70 (audit L-8): a running job only pauses the check. It no longer counts
      // as activity, so a phone left alone during a long job locks the moment
      // the job ends instead of a minute later.
      if (autoLockHeld()) return;
      if (Date.now() - VEIL_LAST_ACTIVITY >= AUTO_LOCK_MINUTES * 60000) { lockedRef.current = true; setLocked(true); }
    };
    const iv = setInterval(tick, 5000);
    // audit VAR-16: and the moment the last job's hold ends (not up to 5 s later), so an untouched
    // phone locks before the job's result (a decrypted vault listing) is on screen
    setHoldEndedHook(tick);
    return () => { clearInterval(iv); setHoldEndedHook(null); };
  }, []);

  /** handoff §2 Account: "Wipe VEIL data from this device" (two-tap armed in UI) —
   *  wipes identity keyvault, session keys, cached messages and local settings, then signs out */
  const handleWipeDevice = useCallback(async () => {
    requireSensitive(); // b70 (audit VAR-01/02/16)
    if (!app) return;
    setBusy(true);
    try {
      // b75 (audit AL-9): the one wipe routine — marker, crypto-shred, verify, files; the
      // push drop, Photos and the logout follow in the background (no prompt before the erase)
      noteWipeLeftovers(await wipeDeviceNow(app, { hold: (on) => { duressCleanupRef.current = on; } }));
    } finally {
      setIdentity(null); setAppLock(null); setSettings(DEFAULTS); setChat(null); setChatMessages([]); /* b70 (re-review 13): the open thread goes too */
      clearHeldSecretsRef.current(); knownSessionTokensRef.current = null; setSessionRows([]); /* b178 re-seed */ setContactRows([]); setLocked(false); setBusy(false);
      setScreen('identity'); // b199: back to the 24-word welcome, never the email screen
    }
  }, [app]);

  /** handoff §2(14): Delete account — veilAccountDelete (web parity) then device wipe + sign out */
  const handleDeleteAccount = useCallback(async () => {
    requireSensitive(); // b70 (audit VAR-01/02/16)
    if (!app) return;
    setBusy(true);
    try {
      await dropPushRegistration(app); // Batch F (R4-4-17): no banners after a wipe
      // b77 (sealed sender): end every 1:1 chat (both mailboxes) when the account and keys go.
      // b77f (A-7, owner decision): the capabilities are held in memory; each mailbox's end fires
      // on its own after a random 3–30 s wait (never in the delete's burst, never awaited,
      // untouched by the erase and the screen change below).
      // b77f2 (audit F-3): scheduled whenever the delete MAY have committed — on success, and on a
      // failure that isn't a definite refusal (a transport failure or timeout, where the relay may
      // have deleted the account and only the answer was lost; a 500 / 504). A definite 4xx
      // refusal, a 502 / 503 (b77g, G-3: the proxy or relay is down, nothing reached it) and a
      // failure before the request was sent schedule nothing. Chosen over "schedule before the
      // delete": that would end the chats of an account the relay definitely kept. A killed
      // process still loses the timers (spec, b77f2).
      // b77g (NaR-1): the capabilities come from the in-memory cache (no keystore read); the
      // chats missing from it are read alongside the delete call, bounded at 3 s (it was one
      // keystore read per chat raced against 1 s, which a slow keystore lost).
      const endWip = wipeDeliveries(app.sessions);
      let delFailure: { e: unknown } | null = null;
      try {
        await app.auth.deleteAccount(identity ? [identity.veilId] : [], identity ? { veilId: identity.veilId, sign: (m) => ikSign(identity.ikSeedB64, m) } : undefined); // b70 (re-review 5)
      } catch (e) {
        delFailure = { e };
      }
      // b77i (I-1): only the relay's 200, or its 410 "account deleted" (deleteAccount returns for both,
      // deleteAnswerDone), means deleted; a retry after an uncertain delete gets one of them (the relay
      // finishes an interrupted cascade). A 401 or any other refusal is a refusal, never "deleted".
      if (delFailure && !deleteMayHaveCommitted(delFailure.e)) throw delFailure.e;
      const endCaps = [...endWip.cached, ...(await endWip.rest)];
      if (endCaps.length) scheduleDelayedSealedEnds(app.relay, endCaps);
      // b77g (G-3): a failure that may have committed never says "nothing was deleted": the
      // result is uncertain, and the chats are being ended
      if (delFailure) throw new DeleteUncertainError(endCaps.length > 0);
    } catch (e) {
      setBusy(false);
      setError(friendlyError(e, 'action'));
      return;
    }
    try {
      noteWipeLeftovers(await wipeDeviceNow(app, { hold: (on) => { duressCleanupRef.current = on; } })); // b75 (audit AL-9): the one wipe routine
    } finally {
      setIdentity(null); setAppLock(null); setSettings(DEFAULTS); setChat(null); setChatMessages([]); /* b70 (re-review 13): the open thread goes too */
      clearHeldSecretsRef.current(); knownSessionTokensRef.current = null; setSessionRows([]); /* b178 re-seed */ setContactRows([]); setBusy(false); setScreen('identity'); // b199: 24-word welcome
    }
  }, [app, identity]);

  const handleSignOut = useCallback(async () => {
    requireSensitive(false); // b70 (audit VAR-01/02/16)
    if (!app) return;
    // b94 verify finding: sign-out is a FULL device wipe (the privacy claim),
    // but the button fired it on a single tap with no warning — the identity
    // goes with it and only the 24-word recovery phrase brings it back.
    const confirmed = await new Promise<boolean>((resolve) => {
      Alert.alert(
        'Sign out and wipe this device?',
        'Signing out removes your identity, conversation keys and all local Vardum data from this device — only your 24-word recovery phrase can restore the identity here. Make sure you have it before continuing.',
        [
          { text: 'Cancel', style: 'cancel', onPress: () => resolve(false) },
          { text: 'Sign out & wipe', style: 'destructive', onPress: () => resolve(true) },
        ],
        { cancelable: true, onDismiss: () => resolve(false) },
      );
    });
    if (!confirmed) return;
    setBusy(true);
    try {
      // AUDIT FIX (Sept 19, website claim "Device wipe at sign-out"):
      // signing out used to leave the identity keyvault, every session key
      // and cached message on this device (and iOS keychain survives app
      // uninstall). Sign-out now wipes everything VEIL stored — the login
      // session itself is the last thing to go, inside auth.logout().
      // b75 (audit AL-9): the one wipe routine — marker, crypto-shred (container key,
      // hardware key), every key verified, the file cache (b64: nothing recoverable
      // stays); the push drop, Photos and the server logout run after it, in the background
      noteWipeLeftovers(await wipeDeviceNow(app, { hold: (on) => { duressCleanupRef.current = on; } }));
    } catch { /* wipe is best-effort; the state below resets regardless */ }
    try { /* the logout (server revoke) runs inside the wipe's cleanup, on the in-memory login */ } finally {
      // b70 (re-review): everything the wipe removed from disk leaves memory too
      // (a kept appLock left the next lock screen unable to accept any code)
      setAppLock(null); setSettings(DEFAULTS); setDecoyMode(false); setLocked(false);
      clearHeldSecretsRef.current(); knownSessionTokensRef.current = null; setSessionRows([]); setContactRows([]);
      setIdentity(null); setChat(null); setChatMessages([]); /* b70 (re-review 13) */ setScreen('identity'); setBusy(false); // b199: 24-word welcome
    }
  }, [app]);


  const refreshSessions = useCallback(async (force = false) => {
    if (lockedRef.current && settingsRef.current.holdUntilUnlock) return; // hold delivery while locked
    if (decoyHoldNow()) return; // b77t2 (decoy gaps): the decoy session's own "Hold messages while locked"
    if (!app) return;
    const acctAtStart = decoyModeRef.current; // b77t (audit 5 M-E): a pass that outlives an account switch shows nothing
    const refreshGen = currentWipeGeneration(); // b70 (re-review 14): a pass that outlives a wipe shows nothing
    // b190: veilSessionGate(list) is gate traffic — skip while the relay's
    // shared rate-limit quiet window is hot (see relay.ts) instead of
    // burning the budget and re-locking the limiter every 10s.
    // b198 EXCEPTION: deletion-triggered refreshes (cover-send/sync/heartbeat
    // observers of a superseded session) pass force=true — the quiet window
    // must not starve the ONE request that terminates the dead-thread loop
    // (the loop itself burns budget every pass; the refresh is what ends it).
    // Same priority logic as burn-priority mode: ambient traffic yields to
    // the privacy-critical operation, never the reverse.
    if (!force && app.relay.gateHot()) return;
    const session = await app.auth.currentSession();
    if (!session) return;
    // b169 (owner hardware test Oct 2: fresh onboarding, no action taken,
    // "Cannot read property 'id' of undefined" leaked onto the CONTACTS tab
    // — and web->native messages never arrived at all). ROOT CAUSE: this
    // whole function used to run in ONE try/catch around the entire list;
    // a single throw (session.user missing, or one malformed row) aborted
    // EVERY row after it, forever, every 10s poll — so a freshly-onboarded
    // identity could never discover ANY pending session, including one a
    // peer just created from web. Guard the auth shape explicitly first so
    // a transient/incomplete session degrades loudly in Metro, never as a
    // crash, and never paints onto an unrelated tab (contactsError belongs
    // to refreshContacts, not here — see the catch block below).
    if (!session.user?.id) {
      console.error('[veil-sessions] refreshSessions: session.user.id missing — session object:', JSON.stringify(session).slice(0, 200));
      return;
    }
    try {
      // b65: threads the user ended but the relay would not delete (peer-created
      // rows RLS blocks) stay hidden instead of resurrecting on every poll.
      let dismissed: string[] = [];
      try {
        const raw = await app.storage.get('veil_dismissed_sessions');
        dismissed = raw ? (JSON.parse(raw) as string[]) : [];
      } catch { dismissed = []; }
      const threadNames = await loadThreadNames(app.storage); // Batch G (R5-1-04)
      // b198 FRESHNESS GATE: record when the fetch STARTS, commit the stamp
      // only on success (below). A pass whose fetch began before the current
      // chat opened cannot have seen that chat's row — its result must never
      // satisfy the gone-detection effect's freshness requirement.
      const listFetchStartedAt = Date.now();
      const r = await app.relay.sessionList(session.user.id, identity?.veilId);
      const list = (r.data as { data?: unknown[] })?.data ?? (r.data as unknown as { sessions?: unknown[] })?.sessions ?? (r.data as unknown[]);
      const rows: SessionRow[] = [];
      // b77k2 (re-review M2): rows titled with a pinned peer's own nickname, checked against every other
      // contact once the list is built (peerNickTitle: ID-shaped refused; a clash or a risky name keeps the ID mark)
      const nickTitled: { row: SessionRow; nick: string; veilId: string }[] = [];
      for (const raw of Array.isArray(list) ? list : []) {
        // b169: per-row isolation — ONE malformed/null row (e.g. a sparse
        // array entry, or an unexpected relay payload shape) must not abort
        // every row after it. Each iteration is now self-contained; a bad
        // row is logged and skipped, the rest of the real list still loads.
        try {
        const rec = raw as Record<string, unknown>;
        if (!rec || typeof rec !== 'object') { console.error('[veil-sessions] skipping a malformed session row'); /* b70 (re-review 9): no row contents (a token) in logs */ continue; }
        const token = String(rec.token ?? '');
        if (!token) continue;
        // b77r1 (audit A-9): a ready local 1:1 chat (sealed with delivery capabilities) is never
        // described by a relay row — not its dials, contact flag or listing; the local pass lists it
        const local0 = await app.sessions.load(token).catch(() => null) as { ready?: unknown } | null;
        if (local0?.ready === true && chatDelivery(local0)) continue;
        // b74: keep the relay record's dials per token — openChat's burn
        // countdown needs them when the sealed state lacks the extras
        // (web-created threads joined via accept never had burn_after_open
        // in the pending record, so the flag never reached the sealed state).
        sessionDialsRef.current[token] = {
          burn: !!rec.burn_after_open,
          burnSecs: Number(rec.default_ttl_seconds) || 0,
        };
        sessionContactRef.current[token] = !!rec.contact_session;
        if (dismissed.includes(token)) continue; // b65: locally-ended ghost thread
        const groupToken = rec.group_token ? String(rec.group_token) : '';
        const groupEpoch = Number(rec.group_epoch ?? 0) || 0;
        // b75r3 (audit I-4): a row is a group row only by this phone's own records. The relay
        // could fold a 1:1 chat into a group (or hide it as an "orphan group row", below) by
        // writing a group_token on its row. A token the local group record names is the group's;
        // a token this phone holds as an established 1:1 chat (joined, with a safety code, or
        // sealed as being with a contact) never is.
        const groupLabelled = !!groupToken && groupEpoch >= 1;
        const groupRec0 = groupLabelled ? await loadGroupRecord(app.storage, groupToken) : null;
        const sealed0 = groupLabelled ? await app.sessions.load(token).catch(() => null) as Record<string, unknown> | null : null;
        const established1to1 = !!sealed0 && (!!sealedPeer(sealed0) || (sealed0.ready === true && !!sealed0.fingerprint));
        const namedByGroup = !!groupRec0 && (groupRec0.sessionToken === token || groupRec0.seatToken === token || !!(groupRec0.seats && Object.prototype.hasOwnProperty.call(groupRec0.seats, token)));
        const isGroup = groupLabelled && !!groupRec0 && (namedByGroup || !established1to1);
        if (groupLabelled && !isGroup && groupRec0) console.log(`[veil-sessions] #${token.slice(0, 4)}: the server labels a 1:1 chat as a group row — shown as the 1:1 chat it is`);
        // b198 ORPHAN GROUP ROWS (live-caught: the old test group banner-stormed
        // after its local record was gone): a group row without a LOCAL group
        // record must never render as a 1:1-style thread — the pairwise sync
        // fetches GROUP envelopes and decrypts them with a pairwise ratchet
        // (protocol-version mismatch → 12-failure desync banner). In-memory
        // view filter, deliberately NOT the b65 persisted list: re-joining the
        // group via a link restores the record and the row reappears.
        // b75r3 (audit I-4): never an established 1:1 chat (above) — the label alone hid one
        if (groupLabelled && !groupRec0 && !established1to1) continue;
        const peerId = String(rec.responder_veil_id || rec.initiator_veil_id || '');
        const mine = rec.initiator_client_id === session.user.id;
        // b99 GHOST-SESSION FIX (owner hardware finding, Sept 21): the relay
        // lists sessions by ACCOUNT id — NaR (or any identity reset) wipes the
        // local identity keyvault and creates a NEW Veil ID but never logs the
        // account out, so rows whose OWN side was the previous (now-extinct)
        // identity keep reappearing forever as unopenable ghosts: the ratchet
        // keys for them died with the old identity, so they can never decrypt
        // anything again. If the row's own-side veil id is known and does NOT
        // match the CURRENT identity, the row belongs to an extinct identity
        // — filter it out here, in memory only. Deliberately NOT persisted to
        // the b65 dismissed list: if the user later phrase-restores the OLD
        // identity, its sessions must come back — this is a view filter, not
        // a deletion. Rows with an EMPTY own-side veil id (not-yet-joined
        // invite links, pre-accept one-taps) can't be classified and are kept.
        if (identity?.veilId) {
          const ownSideVeilId = String((mine ? rec.initiator_veil_id : rec.responder_veil_id) || '');
          if (ownSideVeilId && ownSideVeilId !== identity.veilId) continue;
        }
        // role-aware PEER id: the OTHER party, whichever side we are
        const rowPeerVeilId = String((mine ? rec.responder_veil_id : rec.initiator_veil_id) || peerId || '');
        // Batch F (round-4 review R4-4-01, High): who a 1:1 chat is with comes from
        // this phone's SEALED state (contact chats seal it at the handshake), not
        // the relay row. A chat without a sealed peer (invite chats, chats from
        // before b60) never wears the user's own nickname for a contact, and a
        // row that disagrees with the sealed peer is flagged.
        const sealedRow = await app.sessions.load(token).catch(() => null);
        const sp = isGroup ? null : sealedPeer(sealedRow);
        // b75 (audit RT-1): request versus chat is decided from LOCAL state only. A token this
        // phone holds any session state for is never a "request", whatever the row's
        // contact_session / initiator_veil_id say (a relay that set them on a joined invite
        // chat used to make it wear a pinned contact's nickname and tick, here and on the
        // incoming-call screen). A half-joined ghost (ready, no safety code) is not a chat.
        const hasLocalState = !isGroup && !!sealedRow && !((sealedRow as { ready?: unknown }).ready === true && !(sealedRow as { fingerprint?: unknown }).fingerprint);
        // b77 (sealed sender): a 1:1 chat this phone holds state for is listed from that state
        // (the local pass below), never from the relay row — the list is for pending requests
        // and groups only. (After the join the relay clears the row's IDs and the initiator ends
        // the rendezvous row, so a ready chat has no row to come from anyway.)
        if (!isGroup && hasLocalState) continue;
        // b75 (audit RT-1): local state without a sealed peer is an invite chat — it gets the
        // invite title, never a pin, nickname or "pinned contact" label, and no peer ID from
        // the row (honest invite rows carry none; a relabelled one would name someone else)
        const inviteChat = !isGroup && hasLocalState && !sp;
        const peerLabelMismatch = !!(sp && rowPeerVeilId && rowPeerVeilId !== sp.veilId);
        if (peerLabelMismatch) console.log(`[veil-sessions] #${token.slice(0, 4)}: the server's peer label differs from this phone's record — using this phone's`);
        // b75r3 (audit PR3-01): a row's ID is shown only if it has a Vardum ID's shape (free text is not an ID)
        const peerVeilId = sp ? sp.veilId : inviteChat ? '' : isVardumIdShape(rowPeerVeilId) ? rowPeerVeilId : '';
        if (!isGroup) sessionContactRef.current[token] = !!sp && (sealedRow as { contact?: unknown } | null)?.contact === true;
        // b123 FIX (owner live-test screenshot, Sept 24): the TITLE lookup
        // used responder-OR-initiator WITHOUT checking which side we are —
        // so a session the user JOINED (responder side, e.g. an invite
        // link) titled itself with the user's OWN veil-id,
        // because responder_veil_id is US on those rows. The title's peer
        // is always the OTHER party, exactly like peerVeilId: nickname
        // lookup and the raw-ID fallback both use the role-aware id.
        // b71 (audit): a contact request addressed to me (not joined yet, so no sealed peer)
        const contactRequest = !isGroup && !hasLocalState && !mine && !!rec.contact_session && !!rowPeerVeilId;
        const nick = (sp || isGroup || contactRequest) && peerVeilId ? await app.pins.getNickname(peerVeilId) : null; // Batch F (R4-4-01): own nickname only for a sealed peer (b71: or a request's sender ID)
        // b68: the PEER's own self-chosen nickname (they set it on their side).
        // A name I gave them locally always wins; theirs is the fallback
        // before the raw Veil ID.
        // web parity: verify ceremony is PER-SIDE — badge goes green only when BOTH sides did it
        // Batch F (round-4 review R4-1-03): MY confirmation is the one sealed on
        // this phone (bound to the fingerprint), never the relay row's flag. The
        // peer's flag stays a relay hint for the badge.
        const myVerified = !revokedTokensRef.current.has(token) && locallyVerified(sealedRow);
        // b77t (audit 5 M-F / IH C-01): the relay row's "the other side checked" flag is no longer read
        // or shown anywhere (it was only the server's word, and ready 1:1 chats have no row)
        sessionVerifiedRef.current[token] = myVerified; // Batch E (N3-1); b71: the local seal alone
        // (b77: the R5-3-06 verify re-send and the b162 presence fields are gone — a ready 1:1 chat
        // has no row; its inbound mirrors this phone's confirmation, see sealed.ts ensureInboundOpen)
        // Batch G (round-5 review R5-1-04): a chat this phone didn't seal as being with a
        // contact never wears a contact's name; it is an invite chat, named per chat
        // b71 (audit): a contact request (or a chat accepted from one) from a Vardum ID
        // this phone hasn't pinned never wears the sender's self-chosen name — it is
        // titled with their ID and "(unverified)" until the user names it
        const pinnedPeer = !isGroup && peerVeilId ? await app.pins.getPin(peerVeilId).catch(() => null) : null;
        // b75r2 (audit P-2): a request naming a pinned contact wears their name only when its
        // signature verifies under the pinned key (offline, memoised). The relay can make a
        // request row up; one that isn't signed is titled unverified and must be accepted by hand.
        // b75r3 (audit PR3-01): and every request, pinned or not — the nickname the user gave an ID
        // shows only on a request that ID really signed (an unpinned ID's key comes from a lookup,
        // as accept's own does; it must hash to the ID either way)
        const requestCheck = contactRequest && !!peerVeilId && !!identity ? await contactRequestCheck({ relay: app.relay, pins: app.pins }, rec as never, identity.veilId) : 'unsigned';
        const requestSigned = contactRequest && requestCheck === 'signed';
        const requestUnsigned = contactRequest && !!pinnedPeer && !requestSigned;
        const requestForged = contactRequest && !pinnedPeer && requestCheck === 'unsigned' && !!peerVeilId;
        if (contactRequest && rec.state !== 'ended' && !rec.responder_pub_jwk) requestShownRef.current[token] = requestDisplayBinding(rec);
        const peerTrusted = !!pinnedPeer && !inviteChat && (!sp || sp.ikPub === pinnedPeer.ikPubB64) && !requestUnsigned; // b75 (RT-1); b75r2 (P-2)
        const needsAccept = contactRequest && rec.state !== 'ended' && !rec.responder_pub_jwk && !peerTrusted;
        let gTitle = inviteChat
          ? (threadNames[token] || `Invite chat · #${token.slice(0, 4).toUpperCase()}`) /* b75 (audit RT-1): sealed state, no sealed peer */
          : (!isGroup && (sp || contactRequest) && !peerTrusted)
          ? (((contactRequest ? requestSigned : true) ? nick : null) || unverifiedTitle(peerVeilId)) /* b75r2 (P-2); b75r3 (PR3-01): no nickname on a request its ID didn't sign */
          : (!isGroup && !sp && !contactRequest)
          ? (threadNames[token] || `Invite chat · #${token.slice(0, 4).toUpperCase()}`) /* b71: never the relay row's display name */
          // b71 (crypto review F2): a 1:1 title never uses the name the relay row carries
          : (nick || peerVeilId || 'Unnamed session') /* b71 (review): relay rows carry no nicknames now */;
        let gSub = `#${token.slice(0, 4).toUpperCase()} · ${peerLabelMismatch ? '⚠ server label differs' : requestUnsigned ? 'request · not signed by your contact' : requestForged ? 'request · not signed by the ID it names' : needsAccept ? 'request · not in your contacts' : (contactRequest && peerTrusted && !rec.responder_pub_jwk) ? 'request from a contact · open to start' : (sp || contactRequest) && !peerTrusted ? 'not in your contacts' : sessionContactRef.current[token] ? 'pinned contact' : 'invite session'}`; // Batch F (R4-4-01)
        if (isGroup) {
          try {
            gTitle = (await groupRowLabel(
              { relay: app.relay, sessions: app.sessions, storage: app.storage, webBaseUrl: VEIL_LINK_URL },
              groupToken, String(rec.group_name ?? ''),
            )) || 'Vardum group';
          } catch { gTitle = 'Vardum group'; }
          gSub = `Vardum group · epoch ${groupEpoch}`;
        }
        // b71 (owner report "groups show up twice"): one group = MANY rows here —
        // the creator's MAIN session + one invite row per link, all sharing the
        // same group_token, ALL participant-scoped into this list. collapseGroupRows()
        // (src/session-list.ts) keeps exactly ONE per group, preferring the MAIN
        // session, then any joined row, then anything this device has state for.
        rows.push({
          token,
          contact: !!rec.contact_session,
          mine,
          recId: String(rec.id ?? ''),
          title: gTitle,
          subtitle: gSub,
          status: rec.state === 'active' ? 'active' : rec.state === 'ended' ? 'ended' : 'pending',
          verified: myVerified, // b71 (audit): the tick is this phone's own sealed confirmation
          unread: 0,
          peerVeilId,
          myVerified,
          ...(needsAccept ? { request: true } : {}),
          // b71 (device test): a pinned contact's incoming request needs no Accept, but it is
          // still a request — it used to sit under "Waiting to join" labelled "invite session"
          ...(!needsAccept && contactRequest && peerTrusted && rec.state !== 'ended' && !rec.responder_pub_jwk ? { incoming: true } : {}),
          ...(isGroup ? { groupToken, mainGroupRow: mine && !peerVeilId } : {}),
        });
        } catch (rowErr) {
          // b169: this row is unreadable — skip it, keep the rest of the list.
          console.error(`[veil-sessions] skipping session row ${String((raw as Record<string, unknown>)?.token ?? '?')}: ${String((rowErr as Error).message || rowErr)}`);
        }
      }
      // b77 (sealed sender): READY (and pending) 1:1 chats come from this phone's own records —
      // the relay can no longer list them (it doesn't know which account a mailbox belongs to).
      // Group-owned tokens (the local group records) and dismissed ones are skipped; a pending
      // initiator chat shows as waiting; a ready chat sealed before b77 shows the clean break.
      {
        const listed = new Set(rows.map((r) => r.token));
        const groupOwned = new Set<string>();
        try {
          await loadGroupRecords(app.storage);
          for (const g of exportGroupRecords(app.storage)) {
            if (g.sessionToken) groupOwned.add(g.sessionToken);
            if (g.seatToken) groupOwned.add(g.seatToken);
            for (const t of Object.keys(g.seats ?? {})) groupOwned.add(t);
          }
        } catch { /* no group records: nothing to skip */ }
        for (const token of await app.sessions.listTokens().catch(() => [] as string[])) {
          try {
            if (listed.has(token) || groupOwned.has(token) || dismissed.includes(token)) continue;
            const sealedL = await app.sessions.load(token).catch(() => null) as (Record<string, unknown> & { ready?: unknown; fingerprint?: unknown; contact?: unknown; role?: unknown }) | null;
            if (!sealedL) continue;
            const ready = sealedL.ready === true;
            if (ready && !sealedL.fingerprint) continue; // a half-joined ghost is not a chat
            const sp = sealedPeer(sealedL);
            const preSealed = isPreSealedChat(sealedL);
            if (preSealed) legacyChatsRef.current.add(token);
            // b77r2 (audit R2-A-2): a `retired` flag an older build stored from one 410 is not a
            // fact (SessionStore drops it on load) — the chat lists as active and keeps syncing, so
            // the P-4 rule can see the end confirmed or not
            // b77m merge (audit VAR-07): a chat the relay reported gone lists with the ended ones (read-only, history kept)
            const unavailableL = !preSealed && await isChatUnavailable(app.sessions, token);
            if (unavailableL) unavailableChatsRef.current.add(token); else unavailableChatsRef.current.delete(token);
            const status: SessionRow['status'] = localChatStatus({ preSealed, ready, unavailable: unavailableL });
            const pinnedPeer = sp ? await app.pins.getPin(sp.veilId).catch(() => null) : null;
            const peerTrusted = !!sp && !!pinnedPeer && sp.ikPub === pinnedPeer.ikPubB64;
            const nick = sp ? await app.pins.getNickname(sp.veilId) : null;
            sessionContactRef.current[token] = !!sp && sealedL.contact === true;
            const w = burnWindow(sealedL);
            sessionDialsRef.current[token] = { burn: w.burn, burnSecs: w.secs };
            const myVerified = !revokedTokensRef.current.has(token) && locallyVerified(sealedL);
            sessionVerifiedRef.current[token] = myVerified;
            const tag = `#${token.slice(0, 4).toUpperCase()}`;
            // b77k (IP77-3): the peer's own nickname (sent inside the chat). A name I gave them wins;
            // a pinned contact's is the title (b77k2: the nickname only; the full ID in the subtitle); anyone else's
            // only quoted in the subtitle (b71: such a chat never wears a self-chosen name)
            const peerNick = peerNickOf(sealedL);
            const nickInTitle = !!sp && peerTrusted && !nick && !!peerNick;
            const nickNote = peerNick && !nickInTitle && !nick ? ` · ${peerNickNote(peerNick)}` : '';
            if (nickInTitle && sp) nickTitled.push({ row: null as unknown as SessionRow, nick: peerNick, veilId: sp.veilId });
            rows.push({
              token,
              contact: sealedL.contact === true,
              mine: sealedL.role === 'initiator',
              recId: '',
              title: !sp ? (threadNames[token] || `Invite chat · ${tag}`) : peerTrusted ? (nick || (nickInTitle ? peerNickTitle(peerNick, { veilId: sp.veilId }) : '') || sp.veilId) : (nick || unverifiedTitle(sp.veilId)),
              // b77k2 (IP77-3, owner decision): a title that is only the nickname keeps the full Vardum ID here
              // b77m merge (VAR-07): an unavailable chat says so after its tag (unavailableSubtitle)
              subtitle: ((sub: string) => (unavailableL ? unavailableSubtitle(sub) : sub))(`${tag} · ${preSealed ? 'older protocol · start a new chat' : sp && !peerTrusted ? 'not in your contacts' : sessionContactRef.current[token] ? 'pinned contact' : 'invite session'}${nickInTitle && sp ? ` · ${sp.veilId}` : ''}${nickNote}`),
              status,
              verified: myVerified,
              unread: 0,
              peerVeilId: sp?.veilId ?? '',
              myVerified,
              local: true, // b77q review (J2-3): listed from this phone's own sealed state
            });
            if (nickInTitle && sp) nickTitled[nickTitled.length - 1].row = rows[rows.length - 1]; // b77k2 (M2)
          } catch (rowErr) {
            console.error(`[veil-sessions] skipping a local chat: ${String((rowErr as Error).message || rowErr)}`);
          }
        }
      }
      // b77k2 (re-review M2): a nickname title must not pass for another contact: checked against every
      // other contact's ID and the name I gave them, and every other row's title and nickname
      if (nickTitled.length) {
        const pinsAll = await app.pins.listPins().catch(() => [] as { veilId: string }[]);
        const named = await Promise.all(pinsAll.map(async (p) => ({ veilId: p.veilId, name: (await app.pins.getNickname(p.veilId).catch(() => null)) ?? '' })));
        for (const c of nickTitled) {
          if (!c.row) continue;
          const others = [
            ...named.filter((p) => p.veilId !== c.veilId).flatMap((p) => [p.veilId, p.name]),
            ...rows.filter((r) => r !== c.row && r.peerVeilId !== c.veilId).map((r) => r.title),
            ...nickTitled.filter((o) => o !== c && o.veilId !== c.veilId).map((o) => o.nick),
          ];
          const t = peerNickTitle(c.nick, { veilId: c.veilId, others });
          if (t) { c.row.title = t; continue; }
          // ID-shaped: the Vardum ID stays the title, the nickname only quoted (as for a stranger)
          c.row.title = c.veilId;
          c.row.subtitle = c.row.subtitle.replace(` · ${c.veilId}`, ` · ${peerNickNote(c.nick)}`);
        }
      }
      // b89: a burn window that elapses while its thread is CLOSED must not
      // leave plaintext sitting in that session's msgcache either — sweep
      // every active burn session's cache on each list refresh (cheap: a
      // no-op purge is one storage read). Open threads purge themselves on
      // their own 1s tick above.
      for (const r of rows) {
        // Batch E (R1-01): the session's own dials, not the relay row's
        // Batch F (R4-4-14): no readable sealed session, no purge (never the row's dials)
        // b77u (audit 6 IH full L-10): every row whose sealed record can be read, ended chats included (a chat the
        // peer ended or the relay reports gone keeps its history read-only, and its expired burn messages stayed)
        const sealedB = await app.sessions.load(r.token).catch(() => null);
        const d = sealedB ? burnWindow(sealedB, sessionDialsRef.current[r.token]) : null;
        if (d?.burn && d.secs > 0) {
          // b90: burned rows can no longer be "waiting to read" — the badge decays by the same
          // count so it never points at an empty thread. b77h (audit77g H-3): inside the purge job,
          // once per job (two refreshes joining one queued purge used to decay it twice)
          app.sessions.purgeBurnedMessages(r.token, d.secs, { decayUnread: true }).catch(() => undefined);
        }
        // b90: badge = persisted per-session unread counter
        r.unread = await app.sessions.getUnread(r.token);
      }
      const collapsed = await collapseGroupRows(
        rows,
        async (t) => !!(await app.sessions.load(t)),
        (gt) => groupWinnerRef.current[gt],
      );
      // b134: remember this round's winner per group so the next refresh
      // (e.g. right after reopening the thread) can't silently pick a
      // different token and read a different — likely empty — msgcache.
      for (const r of collapsed) if (r.groupToken) groupWinnerRef.current[r.groupToken] = r.token;
      // Play UGC: chats and chat requests from a blocked Vardum ID stay hidden
      if (blockedRef.current.size) {
        const keep = collapsed.filter((r) => r.groupToken || !r.peerVeilId || !blockedRef.current.has(r.peerVeilId));
        collapsed.length = 0;
        collapsed.push(...keep);
      }
      if (decoyModeRef.current !== acctAtStart) return; // b77t (audit 5 M-E): the other account's rows never show
      if (currentWipeGeneration() !== refreshGen) return; // b70 (re-review 14): a wipe ran meanwhile
      setSessionRows(collapsed);
      listRefreshedAtRef.current = listFetchStartedAt; // b198 freshness gate: a successful, post-open fetch
      // b178 (owner report Oct 2: "you don't get push notifications for new
      // chat invites — new contact or pinned contact"). refreshSessions
      // DISCOVERS new invite rows on its 10s poll but never told the user:
      // a pending session just silently appeared in the list. Detection:
      // the FIRST pass after login seeds the known-token set silently (a
      // wipe+restore would otherwise banner-spam every existing thread);
      // every later pass banners rows that (a) newly appeared, (b) this
      // account did NOT initiate (mine), and (c) are not group rows the
      // user just joined via link (those open a thread immediately). The
      // banner body is generic — no sender, no session identity — per the
      // contentless threat model. NOTE the server side: the APNs wake-ping
      // only fires on VeilEnvelope inserts and a fresh invite carries NO
      // envelope, so a fully-backgrounded phone still needs the server
      // trigger (builder work order) — this banner covers the
      // foreground/app-open window.
      try {
        const tokens = collapsed.map((r) => r.token);
        const seenBefore = knownSessionTokensRef.current;
        if (seenBefore === null) {
          knownSessionTokensRef.current = new Set(tokens); // seed silently
        } else {
          const freshInvites = collapsed.filter((r) =>
            !seenBefore.has(r.token) && !r.mine && !r.groupToken && r.status !== 'ended');
          if (freshInvites.length) {
            for (const r of collapsed) seenBefore.add(r.token);
            console.log(`[veil-notify] ${freshInvites.length} new invite session(s) appeared — banner`);
            notifyNewInvite();
          } else {
            for (const r of collapsed) seenBefore.add(r.token);
          }
        }
      } catch { /* banner best-effort */ }
      // b164 (owner hardware test Oct 2: "after the ceremonies it doesn't
      // load — you have to click out and back in for it to become fully
      // verified"): only openChat ever read the per-side ceremony flags,
      // so the open thread's badge went stale the moment either side
      // confirmed. Patch the OPEN chat's flags from the fresh rows so the
      // badge auto-loads within one 10s list refresh — no reopen needed.
      const openTok = chatOpenRef.current;
      if (openTok) {
        const r = collapsed.find((x) => x.token === openTok);
        if (r && r.myVerified) {
          setChat((c) => (c && c.token === openTok && c.myVerified !== !!r.myVerified
            ? { ...c, myVerified: !!r.myVerified } : c));
        }
      }
    } catch (e) {
      // b169: this used to call setContactsError — refreshSessions is a
      // background 10s poll with no relation to the Contacts tab, so a
      // transient relay hiccup here painted a raw, permanent red error
      // onto an unrelated screen (owner hardware report, Oct 2). Every
      // other background poller in this file (backgroundSyncAllSessions,
      // syncGroupToken) fails silently to Metro only — match that
      // convention. A real outage still shows up: no sessions load, which
      // is visible in the UI on its own merits, without a scary raw string.
      console.error('[veil-sessions] refreshSessions failed:', String((e as Error).message || e));
    }
  }, [app, identity]);

  // b164: keep the AppState-resume mirrors pointed at the current closures.
  useEffect(() => {
    refreshSessionsRef.current = refreshSessions;
  }, [refreshSessions]);

  const refreshContacts = useCallback(async () => {
    if (!app) return;
    const acctAtStart = decoyModeRef.current; // b77t (audit 5 M-E)
    try {
      const pinned = await app.pins.listPins();
      const rows: ContactRow[] = [];
      for (const p of pinned) {
        const nick = await app.pins.getNickname(p.veilId);
        rows.push({ veilId: p.veilId, nickname: nick, verified: p.verified, fingerprint: await identityFingerprint(p.ikPubB64) });
      }
      if (decoyModeRef.current !== acctAtStart) return; // b77t (M-E): the other account's contacts never show
      setContactRows(rows);
      setContactsError(null);
    } catch (e) {
      setContactsError(String((e as Error).message || e));
    }
  }, [app]);

  // b164: contacts mirror for the resume handler.
  useEffect(() => {
    refreshContactsRef.current = refreshContacts;
  }, [refreshContacts]);

  // main screen entered: load both lists once, then keep them LIVE — b72 fix
  // (owner report: a nickname set in Settings took ~10s and a screen-hop to
  // appear). The list previously refreshed ONLY on entry; now it re-polls
  // every 10s while the main screen is visible and the app is foregrounded,
  // so title/subtitle/status changes propagate without navigation.
  // b73 (owner report: nickname only updates if you leave the chat and come
  // back): the poll was gated to screen==='main' only, so sessionRows never
  // refreshed while a chat was open — the open thread's title had nothing
  // fresh to read even on re-render. Now also polls while screen==='chat',
  // and a second effect below patches the open chat's title/subtitle live.
  useEffect(() => {
    if (screen !== 'main' && screen !== 'chat') return;
    refreshSessions(); refreshContacts();
    // b77 FIX: this poll used to only refresh list METADATA (title/subtitle/
    // status) — it never decrypted message content, so sitting on the
    // Conversations list (foreground, no thread open) produced zero
    // notifications no matter how many messages arrived elsewhere.
    // backgroundSyncAllSessions actually decrypts+caches+notifies for every
    // non-open session on the same cadence.
    backgroundSyncAllSessionsRef.current();
    const iv = setInterval(() => {
      if (AppState.currentState !== 'active') return; // backgrounded: skip
      refreshSessions(); refreshContacts();
      backgroundSyncAllSessionsRef.current();
    }, 10000);
    return () => clearInterval(iv);
  }, [screen, refreshSessions, refreshContacts]);

  // Pixel test Oct 20: the pass above runs before the first refreshSessions
  // lands, so it sees zero rows; the list then showed nothing new for up to
  // 10s after unlock (a pushed message only appeared once the thread was
  // opened). Run one pass as soon as the rows first arrive.
  const rowsLoaded = sessionRows.length > 0;
  useEffect(() => {
    if (!rowsLoaded || (screen !== 'main' && screen !== 'chat')) return;
    backgroundSyncAllSessionsRef.current();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [rowsLoaded]);

  // b77 (sealed sender): the b155 1:1 PRESENCE HEARTBEAT is gone. It was a logged-in call every
  // 7 s naming each chat's session token, so the relay could pair the two sides of every chat and
  // see who was online with whom. There is no presence any more (and no "online" dot).
  useEffect(() => { hbRowsRef.current = sessionRows; }, [sessionRows]);

  // b73: once sessionRows refreshes (every 10s above), patch the OPEN chat's
  // title/subtitle from the matching row so a nickname change is visible
  // live, without leaving the chat screen. Group titles/verify flags already
  // update via their own effects — this only touches title/subtitle to avoid
  // clobbering in-flight state (myVerified etc.) set elsewhere.
  useEffect(() => {
    if (screen !== 'chat' || !chat) return;
    const row = sessionRows.find((r) => r.token === chat.token);
    if (!row) return;
    // (b77: no presence suffix — the b162 presence display is gone with the heartbeat)
    const sub = row.subtitle;
    if (row.title === chat.title && sub === chat.subtitle) return;
    setChat((c) => c && c.token === chat.token ? { ...c, title: row.title, subtitle: sub } : c);
  }, [screen, chat, sessionRows]);

  // b88: DEAD-THREAD DETECTION while a chat is open. The 10s session-list
  // poll above already refreshes sessionRows while a chat is open — but
  // when the open thread's session row disappears server-side (peer ended
  // it, duress purge, relay cleanup, or the peer starting a NEW thread),
  // the list simply stopped containing the token and NOTHING acted on it:
  // the open chat kept polling envelopes (envelope rows outlive the
  // session) and looked perfectly "live". b80's gone-detection only fired
  // on a burn 404, which needs a NEW envelope to decrypt — a dead-but-
  // quiet thread never tripped it. Owner repro (Sept 21 ~02:55 Bris): web
  // tapped "+" to start a new chat; the phone sat in the old, deleted
  // thread "live" until manually exiting, only then seeing the new thread.
  // Now: when two CONSECUTIVE successful list refreshes (>=10s apart, and
  // only when the list is non-empty — never trust a pre-refresh/empty
  // state) do not contain the open token, the thread is closed with the
  // same b80-style local residue cleanup, landing on the conversations
  // list — which is already fresh, so what came next (the new thread) is
  // sitting right there. Group threads are excluded: their rows collapse
  // per group (b71) and their lifecycle is owned by the group flow.
  useEffect(() => {
    if (screen !== 'chat' || !chat) return;
    if (chat.groupToken) return; // group lifecycle: separate flow
    // b198: the old `sessionRows.length === 0 → return` guard is GONE — the
    // freshness gate below SUBSUMES it. The empty guard's purpose was to not
    // trust a pre-refresh empty list, but a list FETCHED AFTER the chat opened
    // is authoritative even when EMPTY — and an empty fresh list is exactly
    // what the ✕-end of the user's LAST thread produces (live-verified Oct 15:
    // Two sat in the deleted thread forever because the empty guard refused
    // to act on the legitimately-empty refresh). No signal before a post-open
    // fetch; full authority after one — including the empty verdict.
    // b198 FRESHNESS GATE: sessionRows must have been fetched AFTER this chat
    // opened. A list fetched before the thread existed (the normal state for
    // the first seconds of a '+' thread, and for any in-flight poll that
    // completes after openChat) proves nothing about this token's existence —
    // acting on it is how the auto-switch deleted the brand-new thread's
    // keys. Wait for the next refresh instead of counting a bogus miss.
    if (listRefreshedAtRef.current < chatOpenedAtRef.current) return;
    const stillListed = sessionRows.some((r) => r.token === chat.token);
    if (stillListed) { goneMissRef.current[chat.token] = 0; return; }
    if (supersedeInFlightRef.current.has(chat.token)) return; // b164: switch already running for this token
    // b164 (owner hardware test Oct 2: web's '+' supersession is seamless —
    // native kept sitting in the dead thread until the user pressed back).
    // When a SAME-PEER replacement thread is already in the fresh list, the
    // loss is corroborated: switch straight INTO the replacement after a
    // single miss instead of dropping to the list. Web parity — the new
    // thread just appears under your thumb, nothing to press.
    // b77q review (J2-3): only a row backed by this phone's sealed state or a signed, trusted request (as the 410 path)
    const replacement = gonePendingReplacement(sessionRows, chat.token, chat.peerVeilId);
    const misses = (goneMissRef.current[chat.token] ?? 0) + 1;
    goneMissRef.current[chat.token] = misses;
    if (replacement) {
      console.log(`[veil] session #${chat.token.slice(0, 4)} superseded — auto-switching to new thread #${replacement.token.slice(0, 4)} with the same peer`);
      goneMissRef.current[chat.token] = 0;
      const deadToken = chat.token;
      supersedeInFlightRef.current.add(deadToken);
      (async () => {
        try {
          // Batch E (round-3 review R3-02): the list is capped and other accounts
          // can add rows to it, so a missing row is not proof. Ask the relay about
          // THIS session; anything but a definite "not found" keeps the keys.
          if (!app) return;
          const sealedDead = await app.sessions.load(deadToken).catch(() => null);
          // b77r2 (audit R2-A-4): no legacy liveness check for a sealed chat (or one already gone
          // from this phone) — it is a logged-in heartbeat naming the rendezvous token (linking the
          // account to an anonymously joined chat) and fed the P-4 counter. A sealed chat's end
          // comes only from its mailboxes (syncChat); the view still moves to the new thread.
          if (sealedDead && !chatDelivery(sealedDead)) {
            const ws = (sealedDead as { writeSecret?: string | null }).writeSecret ?? null;
            // b75r2 (audit P-4): one "gone" answer moves the view to the new thread, but the old
            // chat's keys and history go only once its end is confirmed over minutes (G-10 rule)
            const gone = await confirmSessionGone(chatGoneAnswers, app.relay, deadToken, ws);
            if (gone.live !== 'gone') { console.log(`[veil] session #${deadToken.slice(0, 4)} is off the list but still on the relay — keeping it`); return; }
            if (gone.confirmed) { try { await app.sessions.remove(deadToken); } catch { /* residue already gone */ } }
            else confirmGoneLater({ seen: chatGoneAnswers, relay: app.relay, load: (t) => app.sessions.load(t), remove: (t) => app.sessions.remove(t), token: deadToken });
          }
          setError(null);
          await openChatRef.current?.(replacement.token, replacement.title, replacement.subtitle, replacement.status, replacement.peerVeilId ?? null, !!replacement.myVerified, undefined);
        } finally {
          supersedeInFlightRef.current.delete(deadToken);
        }
      })();
      return;
    }
    if (misses < 2) return; // two consecutive misses = genuinely gone
    console.log(`[veil] session #${chat.token.slice(0, 4)} no longer exists server-side (absent from ${misses} consecutive list refreshes) — closing thread, clearing local state`);
    goneMissRef.current[chat.token] = 0;
    const goneToken = chat.token;
    (async () => {
      // Batch E (R3-02): confirm with the relay before deleting any keys
      if (!app) return;
      const sealedGone = await app.sessions.load(goneToken).catch(() => null);
      // b77r2 (audit R2-A-4): never the logged-in legacy heartbeat for a sealed chat (it names the
      // rendezvous token and fed the P-4 counter) — its end comes from its mailboxes only
      if (chatDelivery(sealedGone)) return;
      if (!sealedGone) { setChat(null); setScreen('main'); refreshSessions(); return; } // nothing left here to check or remove
      const ws = (sealedGone as { writeSecret?: string | null }).writeSecret ?? null;
      // b75r2 (audit P-4): repeated "gone" answers over minutes, not one (G-10 rule)
      const gone = await confirmSessionGone(chatGoneAnswers, app.relay, goneToken, ws);
      if (!gone.confirmed) { console.log(`[veil] session #${goneToken.slice(0, 4)} is off the list — ${gone.live === 'gone' ? 'the relay says it ended; kept until that repeats' : 'but still on the relay, keeping it'}`); return; }
      try { await app.sessions.remove(goneToken); } catch { /* residue already gone */ }
      setChat(null);
      setScreen('main');
      refreshSessions();
    })();
  }, [screen, chat, sessionRows, app, refreshSessions]);

  // b89 (owner burn test Sept 21 ~03:32 Bris: "5 minute burn test and it hit
  // 0 but still on both"): the per-bubble burn countdown (b72) was DISPLAY-
  // ONLY — when a message's window elapsed, the "0m 00s" label sat there
  // while the plaintext stayed on screen and in the msgcache indefinitely,
  // on a product whose core promise is that burned content is gone. This
  // effect makes burn-after-open actually BURN: while a burn thread is
  // open, every second (matching the countdown tick, so messages vanish at
  // the exact moment their label hits 0) expired rows are dropped from the
  // visible thread AND deleted from the local cache via the same rule as
  // SessionStore.purgeBurnedMessages (openedAt + burnSeconds elapsed;
  // system notes and never-displayed rows are kept). The purge is a no-op
  // (no state churn, no storage write) while nothing has expired.
  useEffect(() => {
    if (screen !== 'chat' || !chat?.burnAfterOpen || !chat.burnSeconds) return;
    const token = chat.token;
    const secs = chat.burnSeconds;
    const iv = setInterval(() => {
      const now = Date.now();
      setChatMessages((prev) => {
        const keep = prev.filter((m) => m.systemNote || !m.openedAt || m.openedAt + secs * 1000 > now);
        if (keep.length === prev.length) return prev;
        // b70 (VAR-03): a burned voice/video note's decrypted file goes with it
        for (const m of prev) if (!keep.includes(m)) void deleteQuietly(mediaLoadRef.current[m.id]?.fileUri);
        // b77t2 (media dedupe): another message sharing a burned file (the same blob) loads its own copy again
        const goneFiles = new Set(prev.filter((m) => !keep.includes(m)).map((m) => mediaLoadRef.current[m.id]?.fileUri).filter((u): u is string => !!u));
        if (goneFiles.size) setMediaLoad((ml) => { const next = { ...ml }; for (const [id, st] of Object.entries(ml)) if (st.fileUri && goneFiles.has(st.fileUri)) delete next[id]; return next; });
        console.log(`[veil] burn window elapsed for #${token.slice(0, 4)} — removing ${prev.length - keep.length} burned message(s) from view and cache`);
        app?.sessions.purgeBurnedMessages(token, secs).catch(() => undefined);
        return keep;
      });
    }, 1000);
    return () => clearInterval(iv);
  }, [screen, chat, app]);

  // b75r3 (audit PR3-02): THE display marker for a 1:1 chat. A peer row gets its burn clock,
  // and its relay burn is unlocked, when it is actually on screen: the chat open, the app in
  // front, the phone unlocked. Rows a sync added while the app was in the background or the
  // phone was locked wait (no clock) until then. This used to happen at decrypt time, and the
  // closed-thread purge then took the "opened" rows for displayed ones and burned them unseen.
  useEffect(() => {
    if (!app || screen !== 'chat' || !chat || chat.groupToken || locked || !appActive) return;
    const unseen = chatMessages.filter((m) => !m.mine && !m.openedAt && !m.systemNote);
    if (!unseen.length) return;
    const token = chat.token;
    const now = Date.now();
    const ids = new Set(unseen.map((m) => m.id));
    setChatMessages((prev) => prev.map((m) => (ids.has(m.id) && !m.openedAt ? { ...m, openedAt: now } : m)));
    void markEnvelopesDisplayed(app.relay, app.sessions, token, unseen.map((m) => m.envId ?? m.id)).catch((e) =>
      console.log(`[veil] display mark skipped: ${(e as Error).message ?? e}`));
  }, [app, screen, chat, locked, appActive, chatMessages]);

  // audit VAR-21: the same display marker for a GROUP chat. A post gets its burn clock, and its READ
  // receipt goes out (when read receipts are on), only while it is really on screen: the group open,
  // the app in front, the phone unlocked. Both used to happen at decrypt, for posts nobody saw (the app
  // inactive, or the stale open-chat ref of VAR-02) and for blocked senders' hidden posts.
  useEffect(() => {
    if (!app || screen !== 'chat' || !chat || !chat.groupToken || locked || !appActive || !blockListLoaded) return;
    const { stampIds, receiptIds } = groupDisplayBatch(chatMessages as { id: string; mine?: boolean; openedAt?: number; systemNote?: boolean; senderVid?: string | null; envId?: string }[], { blocked: blockedIds, readReceipts: chatSettings.readReceipts });
    if (!stampIds.length) return;
    const token = chat.token;
    const groupToken = chat.groupToken;
    const now = Date.now();
    const ids = new Set(stampIds);
    setChatMessages((prev) => prev.map((m) => (ids.has(m.id) && !m.openedAt ? { ...m, openedAt: now } : m)));
    void app.sessions.markShown(token, stampIds).catch(() => undefined);
    if (receiptIds.length) {
      void (async () => {
        const who = await clientId();
        if (!who) return;
        await sendGroupReceipt(
          { relay: app.relay, sessions: app.sessions, storage: app.storage, webBaseUrl: VEIL_LINK_URL },
          { groupToken, sessionToken: token, clientId: who, ids: receiptIds, read: true },
        );
      })().catch(() => undefined);
    }
  }, [app, screen, chat, locked, appActive, chatMessages, blockedIds, blockListLoaded, chatSettings.readReceipts]);

  const decoyBlocked =() => setContactsError('Could not reach the relay. Try again later.');

  const handleLookup = useCallback(async (veilId: string): Promise<LookupResult | null> => {
    // b77t (audit 5 M-E): works in a decoy session too — `app` is the decoy's own account there
    if (!app) return null;
    const r = await app.relay.identityLookup(veilId);
    const rec = (r.data as { data?: Record<string, string> })?.data ?? (r.data as Record<string, string>);
    if (!rec?.IK_pub) return null;
    return { veilId, fingerprint: await identityFingerprint(rec.IK_pub), ikPubB64: rec.IK_pub };
  }, [app]);

  const handlePin = useCallback(async (lookup: LookupResult) => {
    // b77t (audit 5 M-E): works in a decoy session too — `app` is the decoy's own account there
    if (!app) return;
    await app.pins.pin(lookup.veilId, lookup.ikPubB64);
    await refreshContacts();
  }, [app, refreshContacts]);

  const handleUnpin = useCallback(async (veilId: string) => {
    // b77t (audit 5 M-E): works in a decoy session too — `app` is the decoy's own account there
    if (!app) return;
    await app.pins.unpin(veilId);
    await refreshContacts();
  }, [app, refreshContacts]);

  const handleVerifyPin = useCallback(async (veilId: string) => {
    // b77t (audit 5 M-E): works in a decoy session too — `app` is the decoy's own account there
    if (!app) return;
    await app.pins.markVerified(veilId);
    await refreshContacts();
  }, [app, refreshContacts]);

  const handleNickname = useCallback(async (veilId: string, nickname: string) => {
    // b77t (audit 5 M-E): works in a decoy session too — `app` is the decoy's own account there
    if (!app) return;
    await app.pins.setNickname(veilId, nickname || '');
    await refreshContacts();
  }, [app, refreshContacts]);

  /** b123: rename the OPEN thread locally — a device-only nickname stored
   *  against the peer's veil-id, feeding the role-aware chat-list title fix
   *  (rows stop rendering raw IDs once named). Never transmitted,
   *  never synced, same store the Contacts nicknames use. */
  const handleRenameThread = useCallback(async (name: string) => {
    // b77t (audit 5 M-E): works in a decoy session too — `app` is the decoy's own account there
    if (!app) return;
    const cur = chatRef.current;
    if (!cur?.token) return;
    // Batch G (round-5 review R5-1-04): only a chat sealed as being with a contact
    // renames that contact; an invite chat is renamed per chat (THREAD_NAMES_KEY)
    const sp = sealedPeer(await app.sessions.load(cur.token).catch(() => null));
    if (sp) await app.pins.setNickname(sp.veilId, name || '');
    else {
      const names = await loadThreadNames(app.storage);
      if (name) names[cur.token] = name; else delete names[cur.token];
      await app.storage.set(THREAD_NAMES_KEY, JSON.stringify(names));
    }
    setChatLocalNick(name || null);
    // optimistic patch: the 10s list poll re-syncs the title from the rows
    setSessionRows((prev) => prev.map((r) => (r.token === cur.token ? { ...r, title: name || r.title } : r)));
    setChat((c) => (c && c.token === cur.token && name ? { ...c, title: name } : c));
    refreshSessions().catch(() => undefined);
  }, [app, decoyMode, decoyBlocked, refreshSessions]);

  // b164: openChat is declared below (App.tsx order); callbacks/effects that
  // fire before that point in the file read it through this mirror instead.
  const openChatRef = useRef<((token: string, title: string, subtitle: string, status: 'pending' | 'active' | 'ended', peerVeilId: string | null, myVerified?: boolean, groupToken?: string) => Promise<void>) | null>(null);

  const handleMessage = useCallback(async (veilId: string) => {
    // b167 (owner hardware test Oct 2: "native's + button doesn't do
    // anything"): every failure below used to set ONLY contactsError —
    // which renders on the Contacts TAB, not in the open chat where the
    // "＋ New" button lives. A failed new-thread start (prekey trust
    // mismatch, missing prekeys, rate limit, pin lookup) was therefore
    // INVISIBLE in-chat: the button appeared to do nothing at all. All
    // failure paths now also set the global error, which ChatScreen
    // renders directly, so the reason shows exactly where the tap
    // happened, and log loudly for Metro.
    // b77t (audit 5 M-E): works in a decoy session too — `app` is the decoy's own account there (New chat)
    if (!app || !identity) {
      setContactsError('Create or restore your identity first.');
      setError('Create or restore your identity first.');
      return;
    }
    // Play UGC: a blocked contact's threads are hidden, so don't start one
    if (blockedRef.current.has(veilId)) {
      const m = 'You blocked this person. Unblock them in Settings first.';
      setContactsError(m);
      setError(m);
      return;
    }
    // b167: the identity gate's rate-limit lock (HTTP 429, retry_minutes)
    // blocks new-thread creation for its whole window — and each extra tap
    // while locked can re-trip it. Remember the window client-side so we
    // fail fast with a clear message instead of hammering the relay.
    if (Date.now() < identityLockUntilRef.current) {
      const waitMin = Math.max(1, Math.ceil((identityLockUntilRef.current - Date.now()) / 60000));
      const m = `Relay rate limit — new threads unlock in about ${waitMin} minute${waitMin === 1 ? '' : 's'}. Existing chats keep working.`;
      setError(m);
      return;
    }
    setBusy(true); setContactsError(null);
    try {
      const session = await app.auth.currentSession();
      if (!session) throw new Error('Not signed in.');
      const { token } = await createOneTapSession(
        { relay: app.relay, pins: pinToWipe(app.pins), sessions: pinToWipe(app.sessions) }, identity, veilId, session.user.id, // b70 (re-review 9): a wipe while this waits on the relay stops its writes
        // the Settings dials ride the new session record (web parity)
        {
          // b69 FIX: this callback's deps are [app, identity, refreshSessions] —
          // it does NOT re-close over `settings` when the user changes it in
          // Settings, so a nickname set after app boot silently never rode a
          // new one-tap session (owner report: "nicknames still do not
          // work"). settingsRef.current is the always-fresh mirror kept in
          // sync by the effect near the top of this component — read from
          // there in every callback that isn't recreated on settings change.
          default_ttl_seconds: chatSettingsRef.current.burnTtlSeconds,
          expire_after_seconds: chatSettingsRef.current.expireAfterSeconds,
          key_retention_hours: chatSettingsRef.current.retentionHours,
          burn_after_open: chatSettingsRef.current.burnTtlSeconds > 0,
        },
        // b68: my self-chosen nickname rides the session row — the peer sees
        // it in this thread's title unless they named me locally themselves.
        chatSettingsRef.current.nickname || undefined,
      );
      // b197-r5 (K-17 fix — zombie sessions): creating a new thread with a
      // pinned peer used to leave ALL the peer's previous sessions alive
      // server-side. Those zombies bannered as desynced after any key-state
      // reset (reinstall/wipe), lingered in BOTH users' lists, and made the
      // b164 peer-side auto-switch never fire (the old session never vanished
      // from the server list — no "gone" signal). Now the prior sessions are
      // superseded — server-side (write secret + recId hard-delete fallback)
      // then locally. The peer's EXISTING b164 machinery (old thread vanishes
      // from the list + same-peer replacement present → auto-switch) then
      // completes the wipe on their device with zero new peer-side code.
      // b197-r6 (lag fix, owner report "5-10s lag on everything"): the r5
      // version blocked the new thread's open on N SEQUENTIAL relay round
      // trips, and the inline hammering re-tripped the account limiter (its
      // gateHot window then slowed EVERY action). The supersede now runs in
      // the BACKGROUND, in parallel, AFTER the new thread is opened — the
      // open is instant, the cleanup lands seconds later, and the peer's
      // auto-switch fires on their next refresh exactly as before.
      // b198 (FOUNDER SPEC, supersedes the b197-r6 guard): pressing + must close
      // the old thread on BOTH sides — including the thread the user is standing
      // in. The r6 exclusion (never supersede the open thread) is what kept the
      // old thread alive as a second conversation. The r6 race it guarded
      // (stale hbRowsRef snapshot killing keys of a row that stayed listed) is
      // fixed at the ROOT instead: the supersede list is built from a FRESH
      // relay list right here — never from a stale UI snapshot — and the order
      // is server-delete FIRST, local keys SECOND, open-new LAST, so no listed
      // row ever exists without keys.
      // b77 (sealed sender): the old chats come from this phone's OWN records (the relay can't list a
      // ready 1:1 chat any more). Ended with sealedEnd on both mailboxes, so the peer's next fetch
      // gets 410 and its "chat ended" path (and the b164 same-peer switch) runs. Only READY chats
      // are superseded — a brand-new thread is never one of them, so two phones pressing + at once
      // can't end each other's new threads (the b198 "last writer wins" rule needed the relay's
      // row timestamps, which no longer exist for 1:1 chats).
      let staleTokens: { token: string; recId: string }[] = [];
      try {
        // audit VAR-02: the chat the user is standing in counts only while the chat screen shows it,
        // and only when its sealed peer IS this contact (supersedeTokens); a chat with anyone else is
        // never ended here
        const shown = chatRef.current;
        const pressedIn0 = shown && !shown.groupToken ? shown.token : null;
        const cands: { token: string; sealed: unknown }[] = [];
        for (const t of await app.sessions.listTokens()) {
          if (t === token) continue;
          // b77m merge (VAR-07): a chat the relay reported gone is read-only history, deleted only by the user
          if (unavailableChatsRef.current.has(t) || await isChatUnavailable(app.sessions, t)) continue;
          cands.push({ token: t, sealed: await app.sessions.load(t).catch(() => null) });
        }
        staleTokens = supersedeTokens(cands, token, veilId, pressedIn0).map((t) => ({ token: t, recId: '' }));
      } catch { /* a read failure → no supersede rather than block the open */ }

      for (const stale of staleTokens) {
        try {
          const staleSealed = await app.sessions.load(stale.token).catch(() => null);
          const ws = staleSealed?.writeSecret ?? null;
          // b77: both mailboxes, best effort. b77f (A-7, owner decision): never in the same burst as
          // the signed-in contact request above — each mailbox's end fires on its own after a random
          // wait, from the capabilities read here (held in memory; the local remove below can't
          // take them). b77f2 (audit F-4): MY inbound ends after 0–3 s, so the peer's sends to the
          // old chat get 410 (its "chat ended" path) quickly; the outbound end keeps 3–30 s.
          const staleDlv = chatDelivery(staleSealed);
          if (staleDlv) scheduleDelayedSealedEnds(app.relay, [staleDlv], { inboundWindowMs: [SUPERSEDE_INBOUND_MIN_MS, SUPERSEDE_INBOUND_MAX_MS] });
          else { try { await app.relay.sessionEnd(stale.token, ws, session.user.id); } catch { /* best-effort: entityDelete below owns it */ } }
          if (stale.recId) { try { await app.relay.entityDelete('VeilSession', stale.recId); } catch { /* already gone */ } }
          try { await app.sessions.remove(stale.token); } catch { /* residue already gone */ }
          console.log(`[veil-new-thread] superseded prior session #${stale.token.slice(0, 4)} for peer ${veilId.slice(0, 8)}…`);
        } catch { /* never break the app on supersede failures */ }
      }
      const nick = await app.pins.getNickname(veilId);
      await openChatRef.current?.(token, nick || veilId, 'pinned contact · PQ session', 'pending', veilId);
      refreshSessions();
    } catch (e) {
      const reason = String((e as Error).message || e);
      console.error(`[veil-new-thread] failed for peer ${veilId.slice(0, 8)}…: ${reason}`);
      // b167: capture the 429 lock window so repeat taps back off locally
      const lockMatch = /locked, try again in about (\d+) minutes?/.exec(reason);
      if (lockMatch) identityLockUntilRef.current = Date.now() + Number(lockMatch[1]) * 60000;
      setContactsError(reason);
      setError(`Couldn't start a new thread: ${reason}`);
    } finally { setBusy(false); }
  }, [app, identity, refreshSessions]);


  /**
   * WEB PARITY — 'New chat thread with the same person' (chat header, next to
   * End): a FRESH one-tap session with the same pinned peer — all-new keys,
   * no new invitation (web title: 'New chat thread with the same person —
   * all-new keys, no new invitation'). Only shown when the peer is pinned.
   */
  const handleNewThread = useCallback(() => {
    // b167: this used to be a SILENT no-op when peerVeilId was missing —
    // another "button does nothing" path. If the button is somehow visible
    // without a peer id, say so instead of swallowing the tap.
    if (chat?.peerVeilId) { handleMessage(chat.peerVeilId); return; }
    console.error('[veil-new-thread] tapped but chat.peerVeilId is empty — thread not pinned-contact based');
    setError('New threads need a pinned contact — open this thread from your Contacts list.');
  }, [chat, handleMessage]);

  /** b95: dismiss the one-time verify card — persisted per token so it never
   *  nags again for this thread. Verifying via the card/badge hides it too
   *  (render condition is !myVerified). */
  const handleDismissVerifyCard = useCallback(() => {
    setVerifyCard(false);
    const token = chat?.token;
    if (!app || !token) return;
    (async () => {
      try {
        const raw = await app.storage.get('veil_vcard_dismissed');
        const dis = raw ? (JSON.parse(raw) as string[]) : [];
        if (!dis.includes(token)) await app.storage.set('veil_vcard_dismissed', JSON.stringify([...dis, token]));
      } catch { /* cosmetic card — never crash */ }
    })();
  }, [app, chat]);

  /**
   * WEB PARITY — per-session verify ceremony ('Verified for this session'):
   * marks MY side only (gate flips the caller's *_verified field). Badge goes
   * fully green only when BOTH sides completed it.
   */
  /**
   * b126: the system Alert is GONE — the ChatScreen verification panel now
   * owns the ceremony UX (fingerprint shown BEFORE "Mark verified" unlocks,
   * and viewable any time post-verification). This handler is only invoked
   * after the user confirmed the out-of-band comparison in that panel.
   */
  const handleVerifySession = useCallback(async (token: string, shownFp?: string) => {
    if (!app) return;
    try {
      const sealedV = await app.sessions.load(token);
      const ws = sealedV?.writeSecret ?? null;
      // b198 DIAGNOSTIC (verify-NULL hunt): did the state load, and did it carry
      // a credential? Booleans + lengths only — never the secret itself.
      console.log(`[veil-verify-diag] token=${token.slice(0, 6)}… stateLoaded=${!!sealedV} ready=${!!(sealedV as { ready?: boolean } | null)?.ready} ws=${ws ? "present(len " + ws.length + ")" : "NULL"}`);
      // b154 (builder relay audit, Oct 1): sessionPeek is responder-only (the
      // initiator side 403s) and its payload omits the *_verified flags, so
      // the b147 read-back could NEVER confirm the initiator's write — every
      // inviter-side ceremony errored. The gate's verify action returns the
      // updated session record in its own response; native now confirms OUR
      // slot's flag on that response and never peeks.
      // Batch G (NF-1): nothing to compare on this phone — don't tell the relay it was verified
      if (!(sealedV as { fingerprint?: string | null } | null)?.fingerprint) { console.log('[veil-verify] no safety code on this phone — not verifying'); return false; }
      // b71 (review): only the code the user compared is confirmed. If the stored one
      // changed since the screen drew it, nothing is marked and the panel shows the new one
      if (shownFp !== undefined && shownFp !== (sealedV as { fingerprint?: string | null }).fingerprint) {
        console.log('[veil-verify] the safety code changed since it was shown — not verifying');
        await refreshSessions();
        return false;
      }
      // b71 (audit): the confirmation is sealed on this phone FIRST — it is the gate and
      // the tick. The relay echo below only tells the other phone (an advisory hint
      // there); a failed echo is re-sent by the list refresh (R5-3-06), it never undoes this.
      await markLocallyVerified(app.sessions, token); // Batch F (R4-1-03): the gate's own record
      setChat((c) => c && c.token === token ? { ...c, myVerified: true } : c);
      // b77 (sealed sender): the relay is told only on this phone's own inbound (mailboxVerify —
      // call rings and TURN need it); there is no session row to flag. An inbound not open yet
      // gets it when it opens (sealed.ts ensureInboundOpen re-checks on every pass).
      if (!(await syncInboundVerified(app.relay, app.sessions, token))) console.log('[veil-verify] the inbound is not open yet — its verified flag follows when it opens');
      void ws;
      await refreshSessions();
      return true;
    } catch (e) {
      // b161 (parity handoff §verify-2): failures render INLINE in the
      // ChatScreen verify panel — never the app-wide error state (the
      // toast-suppression rule made this failure invisible for weeks).
      // b197-r6: the catch was SILENT — "verification failed to save" with
      // zero diagnostics. Log the actual relay error (status/lock/gate state)
      // so the retry loop is diagnosable.
      console.error(`[veil-verify] save failed: ${(e as Error)?.message ?? String(e)} | relay gateHot=${app.relay.gateHot()}`);
      return false;
    }
  }, [app, refreshSessions]);

  /**
   * b126 "Pin as contact" (owner-approved Sept 26): promote a chat's peer into the
   * permanent pins table. b71: only from a chat with a sealed peer (the identity key
   * the contact request was checked against); invite chats are refused, and a pin is
   * never marked verified from the chat. Device-local, like every pin.
   */
  const handlePinFromSession = useCallback(async (token: string, veilId: string) => {
    // b77t (audit 5 M-E): works in a decoy session too — `app` is the decoy's own account there
    if (!app) return;
    try {
      // b71 (audit): a chat accepted from a contact request is sealed with the key the
      // request was checked against (ID = hash of key, plus its signature) — pin that
      // key, not whatever the relay serves now
      const sealedP = sealedPeer(await app.sessions.load(token).catch(() => null));
      // b71 (crypto review F1): an invite chat binds no identity — its peer ID comes from
      // the relay row — so it is never a source for a pin (a matching safety code proved
      // the session, not who the relay says is on the other end)
      if (!sealedP || sealedP.veilId !== veilId) {
        setError('An invite chat doesn’t prove who the other person is. To add them as a contact, use their Vardum QR or ID in Contacts and compare the identity fingerprint.');
        return;
      }
      const lk = { ikPubB64: sealedP.ikPub };
      if (!lk) { setError('Could not find that identity on the relay.'); return; }
      await app.pins.pin(veilId, lk.ikPubB64);
      // Batch F (round-4 review R4-4-02, High): an invite chat never binds the
      // other person's identity key, and the peer ID here comes from the relay row,
      // so this pin is trust-on-first-use. It is never marked verified from the
      // session's (relay-held) flags; the ✓ comes only from the contact
      // safety-code check, which is bound to the pinned key.
      setChat((c) => c && c.token === token ? { ...c, peerPinned: true } : c);
      await refreshContacts();
      Alert.alert('Added as a contact — not verified yet', 'To verify them, open the contact and compare its safety code with theirs, in person or on a call.');
    } catch (e) {
      setError('Could not pin that contact — please try again.');
    }
  }, [app, chat, handleLookup, refreshContacts]);

  /** b71 (audit): the user's explicit Accept on a contact request from a Vardum ID
   *  that isn't pinned. Nothing pins; the thread keeps the ID-based title. */
  const handleAcceptRequest = useCallback(async (token: string): Promise<boolean> => {
    // b77t (audit 5 M-E): works in a decoy session too — `app` is the decoy's own account there
    if (!app) return false;
    acceptedRequestsRef.current.add(token);
    acceptedBindingRef.current[token] = requestShownRef.current[token] ?? ''; // b75r3 (PR3-01)
    setChat((c) => (c && c.token === token ? { ...c, request: false } : c));
    const who = await clientId();
    if (!who) return false;
    delete hsLastErrorRef.current[token];
    const ready = await advanceHandshakeRef.current(token, who).catch(() => false);
    // b75r2 (audit P-2): a failed accept used to leave the thread as it was, with nothing shown
    const failed = hsLastErrorRef.current[token];
    if (!ready && failed) {
      acceptedRequestsRef.current.delete(token);
      setChat((c) => (c && c.token === token ? { ...c, request: true } : c));
      setError(acceptFailureMessage(failed));
    }
    setThreadReady(ready);
    await refreshSessionsRef.current?.(true);
    return ready;
  }, [app]);

  const handleUnlock = useCallback(async () => {
    setLockHint('Authenticating…');
    try {
      // b77u (audit 6 U-M2): the OS-auth continuation takes a ticket too — a lock, a wipe or a newer attempt
      // during the prompt voids it, and it never unlocks while Vardum is in the background
      const ticket = unlockGateRef.current.begin();
      // b77u2 (UC-M2): Android 10 and earlier resolve the PIN screen's success while AppState still reads
      // 'background' (onActivityResult before onResume): a current success waits for the next 'active' event
      // (bounded) instead of reading the state at resolve time; a real departure meanwhile still voids it
      const okNow = (): Promise<boolean> => unlockGateRef.current.acceptOsAuth(ticket, {
        state: () => AppState.currentState,
        nextActive: (ms) => nextActiveEvent((fn) => AppState.addEventListener('change', fn), ms),
      });
      // b77u2 (UC-M2): the OS credential screen is a prompt Vardum opened (withSystemSheet): under Nothing-at-Rest
      // its 'background' used to count as a departure and wipe the phone
      const bio = await withSystemSheet(() => LocalAuthentication.authenticateAsync({ promptMessage: 'Unlock Vardum' }));
      if (bio.success) { if (!(await okNow())) { setLockHint(null); return; } setLocked(false); setLockHint(null); veilActivityPing(); }
      else if (deviceAuthFailureUnlocks(await LocalAuthentication.getEnrolledLevelAsync().catch(() => -1))) {
        if (!(await okNow())) { setLockHint(null); return; }
        // b71 (device test): a phone with no screen lock and nothing enrolled — the OS check can never
        // pass there, and the app used to stay locked for good (such a phone is open to whoever holds it).
        // audit VAR-06: ONLY then. A cancelled prompt on a phone with a PIN (with or without biometric
        // hardware) used to open Vardum here (the old test was "no biometric hardware" or an error code)
        setLocked(false); setLockHint(null); veilActivityPing();
      } else {
        setLockHint('Authentication failed — try again.');
      }
    } catch {
      // b94: a crashing biometric module must never BECOME the unlock. The
      // not_available / no-hardware branches above already cover the legit
      // no-biometrics case; an unexpected exception keeps the gate shut.
      setLockHint('Unlock failed — try again.');
    }
  }, []);

  // b144 W3: call transport — closures over the live app context so the
  // call glue never outlives a sign-out (transport returns nulls after wipe)
  useEffect(() => {
    CallManager.configure({
      relay: () => app?.relay ?? null,
      sessions: () => app?.sessions ?? null,
      clientId: () => clientId(),
      storage: () => app?.storage ?? null, // b71: the seen-call list survives restarts
    });
  }, [app]);

  // b157: a call this device never answered (typically the offer was held
  // while the app was locked — hold-until-unlock deliberately keeps a locked
  // phone holding no message data, and call offers are ratcheted exactly
  // like chat so they cannot bypass it) is persisted per-thread and drained
  // into a "Missed call" system notice when the thread next opens.
  useEffect(() => {
    if (!app) return;
    CallManager.onMissedCall = (threadToken: string, peerLabel: string, outgoing?: boolean) => {
      // b158 live-note + b198: the missed-call trace. b71 (audit): CallManager reports
      // missed INCOMING calls only, so the outgoing branch and its "📞 Call unanswered"
      // notice below are not used today.
      const noteText = outgoing
        ? `📞 Outgoing call — no answer.`
        : `📞 Missed call from ${peerLabel} — the call came in while this device was locked or away.`;
      if (threadViewRef.current.current() === threadToken) { // b77u (audit 6 U-M3): the thread on screen now, not at the last render
        const note: (ChatMessage & { systemNote?: string }) = {
          id: `missedcall_live_${Date.now()}`,
          text: '',
          mine: false,
          ts: new Date().toISOString(),
          systemNote: noteText,
        };
        setChatMessages((prev) => (prev.some((m) => m.id === note.id) ? prev : [...prev, note]));
      } else {
        void app.sessions.bumpMissedCalls(threadToken, peerLabel).catch(() => undefined);
      }
      if (outgoing) {
        // the peer's thread needs the trace too — a real notice message rides
        // the sync and pings them (the offer itself expires after 5 minutes).
        // b75r1 (audit PX-02): like every other automatic send, only on a chat whose safety
        // code THIS phone confirmed (and never in decoy mode) — callSignalsAllowed is the
        // same gate the call offer itself passed
        if (!callSignalsAllowed(threadToken)) return;
        void (async () => {
          try {
            const who = await clientId();
            if (!who) return;
            await sendChatMessage(app.relay, app.sessions, threadToken, who, '📞 Call unanswered — no response.');
          } catch (e) { console.log('[veil-calls] missed-call notice send failed (best-effort):', (e as Error).message ?? e); }
        })();
      }
    };
    return () => { CallManager.onMissedCall = null; };
  }, [app]);

  const clientId = async (): Promise<string | null> => {
    if (!app) return null;
    const session = await app.auth.currentSession();
    return session?.user.id ?? null;
  };

  /**
   * Advance the handshake on whichever side we're on, then sync. Role is
   * decided from the session record's veil-ids, never guessed from UI state
   * (VEIL-P0 fix, Sept 18: the responder side previously had no accept path
   * at all — completeContactHandshake is initiator-only and threw forever).
   */
  /**
   * SPEC §3 handshake driver — returns true only when OUR ratchet is ready.
   * PENDING-INITIATOR LOOP: poll the participant-scoped session listing
   * (veilSessionGate {action:'list', client_id}) — the same record the web
   * client polls. Accepted exactly when state === 'active' AND both
   * responder_pub_jwk and responder_ratchet_pub_jwk are non-empty; then the
   * initiator completes the handshake EXACTLY ONCE from the stored
   * request-time state. Web's automatic intro envelope is already waiting on
   * the relay at that point (its header rp = responder_ratchet_pub_jwk) and
   * decrypts with the recv chain the completion derives.
   */
  const advanceHandshake = useCallback(async (token: string, who: string): Promise<boolean> => {
    if (!app || !identity) return false;
    if (hsFailClosedRef.current.has(token)) return false; // b196-r8: relay says already joined; retrying every 3s is noise
    const sealed = await app.sessions.load(token);
    if (sealed?.ready) return true; // joined/active — fast path, no network
    // b198: hoisted OUTSIDE the try so the fail-close below knows whether this
    // device has even ACCEPTED the thread yet (a pending row addressed to us
    // legitimately has no local keys — the accept creates them)
    let recState = 'unknown';
    let joinedHere = true;
    // Pixel test Oct 20 (and the "verify only works after re-entering the
    // thread" report): the safety code lands in the sealed state only when the
    // handshake completes, but openChat read it once on entry. A chat opened
    // before the peer accepted kept a null code, so the ceremony stayed
    // disabled until the thread was reopened. Hand the code to the open chat.
    const shareFingerprint = async (): Promise<void> => {
      const fp = ((await app.sessions.load(token)) as { fingerprint?: string | null } | null)?.fingerprint ?? null;
      if (fp) setChat((c) => (c && c.token === token && c.fingerprint !== fp ? { ...c, fingerprint: fp } : c));
    };
    try {
      // b77 (sealed sender): a pending chat this phone STARTED (contact request or invite link) reads
      // the responder's fields with the no-login gate `status` for this one token — never the
      // account-wide list (after the join the relay clears the row's IDs, so it isn't listed).
      // The completion derives the delivery capabilities; the inbound opens after its random delay
      // and the rendezvous row is then gate-ended (sealed.ts ensureInboundOpen).
      const sealedRole = (sealed as { role?: unknown } | null)?.role;
      const joinPending0 = !!(sealed as { joinPendingResponderPub?: unknown } | null)?.joinPendingResponderPub;
      if (sealed && sealedRole === 'initiator') {
        const st = await readHandshakeStatus(app.relay, token, (sealed as { writeSecret?: string | null }).writeSecret ?? null);
        recState = String(st?.state ?? 'unknown');
        if (!st || st.state !== 'active' || !st.responder_pub_jwk || !st.responder_ratchet_pub_jwk) return false;
        await completeContactHandshake(app.relay, app.sessions, token, st);
        await shareFingerprint();
        return !!(await app.sessions.load(token))?.ready;
      }
      // b77: an accept whose join answer was lost — the row no longer names this phone after the
      // join, so `status` (with this phone's responder write secret) says whether it landed
      let rec: Record<string, unknown> | undefined;
      if (sealed && joinPending0) {
        const st = await readHandshakeStatus(app.relay, token, (sealed as { writeSecret?: string | null }).writeSecret ?? null).catch(() => null);
        if (st) rec = { ...st, token, responder_veil_id: identity.veilId };
      }
      if (!rec) {
        const r = await app.relay.sessionList(who, identity.veilId);
        const list = (r.data as { data?: unknown[] })?.data ?? (r.data as { sessions?: unknown[] })?.sessions ?? (r.data as unknown as unknown[]);
        rec = (Array.isArray(list) ? list : []).map((x) => x as Record<string, unknown>)
          .find((x) => String(x.token ?? '') === token);
      }
      if (!rec) return false;
      recState = String(rec.state ?? '');
      // responder: joined iff their join is stamped on the row; initiator: keys exist from creation
      joinedHere = rec.responder_veil_id === identity.veilId ? !!rec.responder_pub_jwk : true;
      const iAmInitiator = rec.initiator_veil_id === identity.veilId;
      const iAmResponder = rec.responder_veil_id === identity.veilId;
      // Batch G (round-5 review R5-1-06): a chat this phone already holds is never
      // re-accepted because the row now names me as the responder
      // b75 (audit RT-6): except an accept whose relay join is not confirmed yet (saved not
      // ready, marked joinPendingResponderPub): acceptOneTapSession finishes or re-sends it
      const joinPending = !!(sealed as { joinPendingResponderPub?: unknown } | null)?.joinPendingResponderPub;
      if (sealed && iAmResponder && !iAmInitiator && !joinPending) { console.log(`[veil] #${token.slice(0, 4)}: the server's row names this phone as the responder of a chat it already holds — ignored`); return false; }
      // Batch H (round-6 review R6-1-09): a request from a blocked Vardum ID is never
      // accepted or pinned automatically (none at all until the block list has loaded)
      if (iAmResponder && !iAmInitiator && (!blockListLoadedRef.current || blockedRef.current.has(String(rec.initiator_veil_id ?? '')))) return false;
      // b71 (audit): a request from a Vardum ID that isn't pinned waits for the user's
      // explicit Accept — opening the thread, a background pass or the server marking
      // the row active never accepts it. Pinned contacts re-messaging keep the one-tap flow.
      if (iAmResponder && !iAmInitiator && await needsExplicitAccept(app.pins, String(rec.initiator_veil_id ?? ''), acceptedRequestsRef.current.has(token) || joinPending /* b75 (RT-6): accepted before */)) return false;
      // b75r3 (audit PR3-01): a request accepted by hand is accepted only as it was shown. If the
      // row now names someone else or carries another signature, the accept is refused.
      if (iAmResponder && !iAmInitiator && !joinPending && acceptedRequestsRef.current.has(token)
        && await needsExplicitAccept(app.pins, String(rec.initiator_veil_id ?? ''), false)
        && acceptedBindingRef.current[token] !== requestDisplayBinding(rec)) {
        acceptedRequestsRef.current.delete(token);
        throw new Error('This request changed after it was shown, so it was not accepted. Look at it again before accepting.');
      }
      if (iAmResponder && !iAmInitiator) {
        // responder side: accept + join (derives ready chains immediately)
        // b69 FIX: same stale-closure bug as handleMessage above — advanceHandshake's
        // deps are [app, identity] only, so a nickname set after boot never rode the accept.
        await acceptOneTapSession({ relay: app.relay, pins: pinToWipe(app.pins), sessions: pinToWipe(app.sessions), storage: pinToWipe(app.storage) } /* b70 (re-review 5): a wipe during the accept stops its writes */, activeIdentityRef.current ?? identity, /* b70 (re-review): the latest prekeys, not a stale copy */ rec as never, who, chatSettingsRef.current.nickname || undefined);
        // b76 (one-time prekeys): a request that used one of this phone's one-time keys spent it —
        // top the relay's pool up again (in the background; failures retry at the next launch)
        if ((rec as { responder_opk_id?: string }).responder_opk_id) void topUpOneTimePrekeys();
        await shareFingerprint();
        return !!(await app.sessions.load(token))?.ready;
      }
      if (iAmInitiator) {
        // SPEC gate: complete exactly once, only when accepted
        if (rec.state === 'active' && rec.responder_pub_jwk && rec.responder_ratchet_pub_jwk) {
          await completeContactHandshake(app.relay, app.sessions, token, rec);
          await shareFingerprint();
          return true;
        }
        return false;
      }
      // invite-link sessions carry no veil-ids — legacy initiator path.
      // b125 FIX: `rec` was already fetched via sessionList a few lines up
      // (it's how we got here at all — the `if (!rec) return false;` guard
      // above already proved it exists, complete with responder_pub_jwk /
      // responder_ratchet_pub_jwk once the peer has joined). Discarding it
      // and calling completeContactHandshake with no prefetched record forced
      // its peek() fallback, and the relay's peek gate rejects the SESSION
      // CREATOR outright ("Only the invited side can view this session" —
      // peek is scoped to the joining side, not the creator). Every invite-
      // link initiator was silently stuck at initiator_verified regardless of
      // ceremony state; reusing `rec` here skips peek entirely and completes
      // straight from data we already hold.
      await completeContactHandshake(app.relay, app.sessions, token, rec as never).catch(() => undefined);
      await shareFingerprint();
      return !!(await app.sessions.load(token))?.ready;
    } catch (e) {
      hsLastErrorRef.current[token] = (e as Error)?.message ?? String(e); // b75r2 (audit P-2)
      // b80 (owner report: message "just slipped into conversations, no
      // accept window" but never actually decrypts — even on b79) — this
      // catch used to be completely bare. b79 fixed ONE specific throw
      // inside acceptOneTapSession (the state!=='pending' guard), but ANY
      // other failure in the accept chain (signature check, missing
      // prekeys, relay join rejection, etc.) was — and still would be —
      // swallowed here with zero visibility. Logging instead of guessing.
      const m = (e as Error)?.message ?? String(e);
      // b196-r8: a restored thread whose relay state moved past us ("Session
      // already joined") can never complete its local handshake from here.
      // Fail-close it: log ONCE, stop the 3s retry loop. The thread stays
      // unready locally; ending it (✕) cleans the residue.
      if (/already joined/i.test(m)) {
        hsFailClosedRef.current.add(token); setFailClosedTick((n) => n + 1);
        console.error(`[veil-handshake] #${token.slice(0, 4)} already joined on relay but not completable locally — fail-close, ending retries`);
        return false;
      }
      // b197-r6: 'No ratchet state for this session on this device' on the
      // advance path means the LOCAL KEYS are gone (rapid-tap supersede race,
      // keychain flake, wipe) while the relay row still says active. Retrying
      // every 3s can NEVER succeed — keys don't come back — and it burns
      // relay budget forever. Fail-close: log once, direct the user to the
      // list ✕ end affordance (K-16/K-17 give every dead thread an exit).
      if (/no ratchet state/i.test(m)) {
        // b198 (live battery catch): a PENDING row this device has NOT accepted
        // yet legitimately has no local keys — the accept creates them. The old
        // guard failed-closed on exactly this and blacklisted brand-new threads
        // the moment an auto-switch surfaced them (the receiver-side "nothing
        // happens / verification failed" loop). Fail-close ONLY when this device
        // was supposed to have keys (joined/active) and they're gone.
        if (recState === 'pending' || !joinedHere) {
          console.log(`[veil-handshake] #${token.slice(0, 4)} pending/not-yet-accepted — no local keys yet is NORMAL; accepting on the next tick`);
          return false;
        }
        hsFailClosedRef.current.add(token); setFailClosedTick((n) => n + 1);
        console.error(`[veil-handshake] #${token.slice(0, 4)} local keys are GONE (relay row still active) — thread is unrecoverable, fail-close. End it from the conversation list (✕).`);
        return false;
      }
      console.error(`[veil-handshake] advanceHandshake failed for #${token.slice(0, 4)}: ${m}`);
      return false; // pending loop retries on the next 3s tick
    }
  }, [app, identity]);
  /** b76 FIX: the capture effect (deps [app]) runs ONCE at connect, while
   * identity is still null — it captured the identity=null advanceHandshake
   * and returned false FOREVER: every 1:1 screenshot notice silently logged
   * "handshake not ready (pending thread)" on fully-active threads (owner
   * report, repro'd in Metro twice). Route through a live ref instead. */
  const advanceHandshakeRef = useRef(advanceHandshake);
  useEffect(() => { advanceHandshakeRef.current = advanceHandshake; }, [advanceHandshake]);

  /** b77m merge (audit VAR-07): syncChat says the RELAY reports this chat gone (nothing from the peer said
   *  so). Not removed, not "ended by the other side": shown read-only with its history and a banner, Delete
   *  offered (handleEndSession → endChatOnRelay 'local'); its poll and backoff stop here. */
  const markChatUnavailable = useCallback((token: string, byPeer = false) => {
    const first = !unavailableChatsRef.current.has(token);
    unavailableChatsRef.current.add(token);
    delete rateLimitBackoffMsRef.current[token]; delete rateLimitCooldownUntilRef.current[token];
    delete pollBackoffRef.current[token]; delete zeroStreakRef.current[token];
    if (first) console.log(byPeer ? `[veil] #${token.slice(0, 4)}: ended by the other side — kept read-only for the messages sent before the end` : `[veil] #${token.slice(0, 4)}: the server reports this chat no longer exists — kept read-only with its history`);
    setChat((c) => (c && c.token === token && !c.unavailable ? { ...c, status: 'ended', unavailable: true, ...(byPeer ? { endedByPeer: true } : {}) } : c));
    setSessionRows((prev) => prev.map((r) => (r.token === token && r.status !== 'ended' ? { ...r, status: 'ended' as const, subtitle: unavailableSubtitle(r.subtitle) } : r)));
  }, []);

  /** b77u (audit 6 U-M8): the peer's authenticated END deleted this phone's copy of the chat (syncChat `purged`):
   *  the open thread empties and its decrypted media files go (the chat banner then says the messages were removed) */
  const dropPurgedThread = useCallback((token: string, onThread?: () => boolean) => {
    if (chatRef.current?.token !== token) return; // a closed chat's temp files went when it was left
    if (onThread && !onThread()) return; // b77u merge (U-M8 x RH-M1): only this pass's own thread and account
    setChatMessages([]);
    setMediaLoad({});
    void purgeTmp();
  }, []);

  const syncToken = useCallback(async (token: string) => {
    if (lockedRef.current && settingsRef.current.holdUntilUnlock) return; // delivery held while locked
    if (decoyHoldNow()) return; // b77t2 (decoy gaps): the decoy session's own "Hold messages while locked"
    if (!app) return;
    // b77u (audit 6 U-M3 / R1 F-03, RH-I1): this pass writes only to its own thread, for its own account
    const { onThread, live, setThreadMessages } = threadGuard(token, app);
    // b77u (RH-L2): a lock under "Hold until unlock" (or an account switch, a wipe) while the fetch waits: nothing is processed
    const passHeld = (): boolean => holdWhileLocked(lockedRef.current, settingsRef.current.holdUntilUnlock) || decoyHoldNow() || !live();
    if (unavailableChatsRef.current.has(token)) return; // b77m merge (VAR-07): read-only, nothing to sync
    if (syncInFlightRef.current[token]) return; // a sync for this token is already running
    // b175: relay said "slow down" on a recent pass — skip this tick
    // entirely rather than retrying at full 1.5s cadence into the same
    // limiter. Silent: the next eligible tick resumes normally.
    const cooldownUntil = rateLimitCooldownUntilRef.current[token] ?? 0;
    if (Date.now() < cooldownUntil) return;
    syncInFlightRef.current[token] = true;
    try {
      const who = await clientId();
      if (!who) return;
      const ready = await advanceHandshake(token, who);
      if (onThread()) setThreadReady(ready); // b77u (RH-I1)
      // b87: resume from this session's persisted pagination cursor — see
      // SessionStore.syncSkip / chat.ts's syncChat for why a plain skip=0
      // fetch permanently stalls once a session passes 200 total envelopes.
      const startSkip = ready ? await app.sessions.syncSkip(token) : 0;
      const res = ready
        ? await syncChat(app.relay, app.sessions, token, who, chatKnown, false, startSkip, sessionDialsRef.current[token]?.burnSecs || 0, { onScreen: () => chatOnScreenNow(token), shouldAbort: () => passHeld() }) // b77t (M-G)
        : { messages: [] as never[], processedIds: [] as string[], nextSkip: startSkip };
      if ((res as { aborted?: boolean }).aborted) return; // b77u (RH-L2)
      if (ready && !(res as { ended?: boolean }).ended && !(res as { unavailable?: boolean }).unavailable) {
        await app.sessions.saveSyncSkip(token, (res as { nextSkip: number }).nextSkip);
      }
      // b77m (audit VAR-07): `ended` now means the peer's END envelope (endedBy 'peer'), decrypted and
      // authenticated in this chat. syncChat already removed the local state: the existing "ended"
      // path closes the thread and refreshes the list. The relay's 410s alone give `unavailable`.
      const outcome = syncOutcome(res as { ended?: boolean; unavailable?: boolean; gonePending?: boolean });
      if (outcome === 'ended') {
        console.log(`[veil] #${token.slice(0, 4)}: chat ended by the other side — closing the thread`);
        if (onThread()) { setChat(null); setScreen('main'); }
        refreshSessionsRef.current?.(true);
        return;
      }
      if (outcome === 'unavailable') {
        if ((res as { purged?: boolean }).purged) dropPurgedThread(token, onThread); // b77u (audit 6 U-M8): the peer's END removed this chat's messages; b77u merge: the pass's own thread only
        // b77m review (L9): the peer's END arrived with messages sent before it — they are shown, then the chat is read-only
        const lastWords = (res as { messages?: ChatMessage[] }).messages ?? [];
        if (lastWords.length) {
          if (onThread()) setThreadMessages((prev) => [...prev, ...lastWords.filter((m) => !prev.some((p) => p.id === m.id))]);
          else notifyNewMessage();
        }
        markChatUnavailable(token, (res as { endedBy?: string }).endedBy === 'peer');
        return;
      } // b77m merge (VAR-07): read-only; b77u (U-M8): a peer's END purged the history (the relay's word alone keeps it)
      if (outcome === 'gonePending') {
        // b76r2 (ZTE battery) backoff, as the session-gone branch below: the first answer is
        // acted on at once, repeats slow to one a minute while the end is confirmed
        const prev = rateLimitBackoffMsRef.current[token] ?? RATE_LIMIT_BACKOFF_BASE_MS / 2;
        const next = Math.min(prev * 2, RATE_LIMIT_BACKOFF_CAP_MS);
        rateLimitBackoffMsRef.current[token] = next;
        rateLimitCooldownUntilRef.current[token] = Date.now() + next;
        // b164: a same-peer replacement thread is already listed → move the view there now
        // (the old chat's keys go once its end is confirmed, by the background pass)
        const cur = chatRef.current;
        // b77q review (J2-3): the 410 is the relay's unauthenticated word, so the view moves only to a row this phone
        // can stand behind — one listed from its own sealed state, or a request signed under the pinned key (src/app-guards.ts
        // gonePendingReplacement); never an unsigned or forged request row whose peer ID came from the relay
        const replacement = cur?.token === token ? gonePendingReplacement(hbRowsRef.current, token, cur.peerVeilId) : undefined;
        if (replacement) {
          console.log(`[veil] session #${token.slice(0, 4)} ended by the peer — switching to #${replacement.token.slice(0, 4)} with the same peer`);
          void openChatRef.current?.(replacement.token, replacement.title, replacement.subtitle, replacement.status, replacement.peerVeilId ?? null, !!replacement.myVerified, undefined);
        } else console.log(`[veil] sync #${token.slice(0, 4)}: the relay says this chat was ended — confirming (next try in ${next}ms)`);
        return;
      }
      if (ready) applySealedPass(token, res as never); // b77r1 (audit A-5)
      if (ready) applyNickPass(token, res as never); // b77k (IP77-3)
      // b144 W3: call signals (offer/answer/ice/end) were decrypted and
      // filtered from the chat list inside syncChat — hand them to the call
      // manager so the overlay can ring/connect. Fire-and-forget on purpose:
      // a call setup must never block the message pipeline.
      const callSigs = (res as { callSignals?: { __veil_call: 1; op: 'invite' | 'offer' | 'answer' | 'ice' | 'end' | 'ringing'; call_id: string; sdp?: string; k?: string; cand?: string; reason?: string; seq?: number }[] }).callSignals;
      if (ready && callSigs?.length) {
        if (callSignalsAllowed(token)) void CallManager.handleSignals(token, callSigs).catch((e) => console.log(`[veil-call] signal dispatch error: ${(e as Error).message}`));
      }
      // knownIds must include EVERY envelope decrypted this pass (visible
      // chat text + filtered cover/intro/receipt control payloads) or the
      // filtered ones get re-fetched and re-decrypted every poll — a
      // consumed ratchet message key can't be re-derived, so that only
      // spams decrypt-failed logs without ever surfacing anything.
      if ((res as { processedIds?: string[] }).processedIds?.length) {
        if (onThread()) setChatKnown((prev) => new Set([...prev, ...(res as { processedIds: string[] }).processedIds]));
      }
      if (res.messages.length) {
        void quietLedgerFor(app).touch(token).catch(() => undefined); // b77u (audit 6 W8): a message arrived
        setThreadMessages((prev) => mergeById(prev, res.messages)); // b77u (U-M3): once each
        // local banner only when the user is NOT looking at this thread
        // (the APNs ping itself stays silent — see notifications.ts)
        // b84: the thread-open grace window covers the unlock-resume race —
        // AppState can lag reality for a second or two after foregrounding.
        const inOpenThread = onThread();
        const justOpened = Date.now() - chatOpenedAtRef.current < 4000;
        if ((AppState.currentState !== 'active' && !justOpened) || !inOpenThread) {
          notifyNewMessage();
        }
      }
      // READ-RECEIPT PARITY (web): the user is looking at this thread and
      // these peer messages just rendered — batch-ack them through the
      // encrypted channel. read:true only when the local read-receipts dial
      // is on; ids still flow as delivery state when it's off.
      // b127: receipts must also cover messages that arrived via a
      // BACKGROUND pass while this thread was closed — they render from
      // CACHE on thread-open, never appear in res.messages again, so the
      // old code never acknowledged them no matter how long the user
      // read them (and the old "deferred retry" could never re-send:
      // the lost batch never reappears). Sweep un-receipted cached peer
      // rows every pass while the thread is open, backed by a persistent
      // per-token receipted ledger (SessionStore b127) so restarts don't
      // re-acknowledge the whole thread.
      // b129 FIX (live-found, Sept 26): the b127 sweep was nested inside
      // `if (res.messages.length)` — it only ran on passes that brought
      // NEW messages, so cached rows that arrived while the thread was
      // closed were never receipted on reopen (owner repro: sweep-test
      // A/B on session ae17 got zero receipts across 4+ min open).
      // Hoisted out of the gate: the sweep now runs on EVERY pass while
      // this thread is open (freshIds is simply empty on a cache-only
      // pass), so reopening a thread acks its cached backlog.
      // b70 (re-review 11): "open" means someone is looking — never while the phone is locked
      if (onThread() && !lockedRef.current) {
          // b74 (VAR-07): receipts name each message's header-derived mid, never a relay id
          const freshIds = (res as { messages: { mid?: string }[] }).messages.map((m) => m.mid).filter((x): x is string => !!x);
          const cachedRows = await app.sessions.cachedMessages(token).catch(() => [] as ChatMessage[]);
          const receipted = await app.sessions.receiptedIds(token).catch(() => new Set<string>());
          const cachedIds = cachedRows
            .filter((m) => !m.mine && !!m.mid && !(m.id ?? '').startsWith('stray_'))
            .map((m) => m.mid as string)
            .filter((id) => !receipted.has(id));
          // b77q review (J2-2): only rows the thread shows (rendered, or appended by this pass). A background pass
          // that was running when the chat opened cached rows the thread never showed, and READ went out for them
          const shownMids = new Set<string>([...freshIds, ...chatMessagesRef.current.map((m) => m.mid).filter((x): x is string => !!x)]);
          const seen = [...new Set([...freshIds, ...cachedIds])]
            .filter((id) => !receiptSentRef.current.has(id) && shownMids.has(id));
          // b74 (VAR-08): with read receipts off, viewing sends NOTHING (the old
          // read:false receipt still told the peer exactly what was viewed, and when)
          if (seen.length && chatSettings.readReceipts) {
            for (const id of seen) receiptSentRef.current.add(id);
            console.log(`[veil-receipt] sending ${seen.length} receipt id(s)`);
            sendReadReceipt(app.relay, app.sessions, token, who, seen, true).then(async () => {
              await app.sessions.markReceiptedIds(token, seen).catch(() => undefined);
            }).catch((e) => {
              // Expected + self-healing: iOS suspends background networking while
              // locked, so a receipt send here fails transiently and retries on the
              // next sync — and b127 makes the retry REAL: the ids stay
              // un-ledgered and resurface from the cache sweep next pass.
              console.warn('[veil] receipt send deferred (will retry):', (e as Error).message ?? e);
              for (const id of seen) receiptSentRef.current.delete(id);
            });
          }
        }
      // b91 (web stray-classifier parity): envelopes that failed to decrypt
      // BUT were followed by a successful newer decrypt in the same pass are
      // strays, not a desync — a soft in-thread notice, never the destructive
      // prompt. Ledgered in SessionStore so each stray notices exactly once.
      const strays = (res as { strayIds?: string[] }).strayIds ?? [];
      for (const sid of strays) {
        const notice: (ChatMessage & { systemNote?: string }) = {
          id: `stray_${sid}`,
          text: '',
          mine: false,
          ts: new Date().toISOString(),
          systemNote: strays.length === 1
            ? 'One message could not be opened on this device; the rest of the conversation is unaffected.'
            : `${strays.length} messages could not be opened on this device; the rest of the conversation is unaffected.`,
        };
        setThreadMessages((prev) => (prev.some((m) => m.id === notice.id) ? prev : [...prev, notice]));
      }
      // b70 (audit L-1): the peer numbered messages that never reached this phone
      const missing = (res as { missingFromPeer?: number }).missingFromPeer && onThread()
        ? await app.sessions.takePendingMissing(token) : 0; // b70 (re-review P1): drained once seen
      if (missing > 0) {
        const gapNote: (ChatMessage & { systemNote?: string }) = {
          id: `gap_${token}_${Date.now()}`,
          text: '',
          mine: false,
          ts: new Date().toISOString(),
          systemNote: missing === 1
            ? 'One message your contact sent has not arrived. It may still come; if not, the server did not deliver it.'
            : `${missing} messages your contact sent have not arrived. They may still come; if not, the server did not deliver them.`,
        };
        setThreadMessages((prev) => [...prev, gapNote]);
      }
      // b91: genuine desync signatures (header-key mismatch = epoch
      // divergence, or stacking failures with no newer success) keep the
      // web's end-session recommendation — once per thread per app run.
      // b70 (audit L-4): unauthenticated junk can look like a desync, so the
      // "end this session" advice needs three such passes in a row with no
      // message opening in between, not one
      // b75 (audit RT-2): junk, replays and old copies never set desync any more, and a
      // pass counts only with a failing envelope not counted before (countDesyncPass)
      const desyncNow = countDesyncPass(token, res as { desync?: boolean; desyncIds?: string[]; messages: unknown[] });
      // (b70 re-review 12: never over the lock — "End this thread" needs no password)
      if (desyncNow && (desyncStreakRef.current[token] ?? 0) >= 3 && onThread() && !lockedRef.current && !desyncPromptedRef.current[token]) {
        desyncPromptedRef.current[token] = true;
        // b197-r3 (K-16 fix): this banner previously had NO buttons — it told
        // the user to "end this session" while providing no way to do it, and
        // the server-side end silently fails for peer-created sessions (RLS),
        // leaving undeletable dead threads after a reinstall (fresh-install
        // sweep wipes the keys; server rows survive). Wire the close flow the
        // supersede path already uses: best-effort server end (with the local
        // write secret), local state removal, back to main, list refresh.
        // b77t2 (CM-2): in-window, tagged with this chat's account — a system Alert stayed up over the lock and the
        // decoy session, and its "End this thread" ended the real chat. A lock or switch withdraws it (asked again)
        const owner = app;
        let withheld = false;
        void askFor(owner, {
          title: 'Session out of sync',
          message: 'New messages in this thread can no longer be decrypted on this device. End this session and start a new chat thread with the same contact to keep messaging securely.',
          confirm: true, danger: true, submitLabel: 'End this thread', cancelLabel: 'Later',
        }, { onWithheld: () => { withheld = true; desyncPromptedRef.current[token] = false; } }).then((endIt) => {
          if (endIt !== true || withheld) return;
          void (async () => {
            if (!app) return;
            let ws: string | null = null;
            let sealedE: unknown = null;
            try { sealedE = await app.sessions.load(token); ws = (sealedE as { writeSecret?: string | null } | null)?.writeSecret ?? null; } catch { /* no sealed record */ }
            try {
              // b77 (sealed sender): a mailbox chat ends both mailboxes (best effort); a pending
              // chat still ends its rendezvous row
              if (chatDelivery(sealedE)) await endSealedChat(app.relay, sealedE);
              else {
                const sess = await app.auth.currentSession();
                if (sess) await app.relay.sessionEnd(token, ws, sess.user.id);
              }
            } catch { /* peer-created or pending: local close still proceeds */ }
            try { await app.sessions.remove(token); } catch { /* residue already gone */ }
            if (onThread()) { setChat(null); setScreen('main'); }
            refreshSessions();
          })();
        });
      }
      // COVER-TRAFFIC PARITY (web): each poll cycle, 15% chance to submit a
      // ratchet-encrypted filler envelope through the same channel as real
      // chat, sized like real messages. It blurs chatting with idling; it does
      // not hide it (only real messages trigger a push). b71 (audit). Failures
      // are non-fatal — the next poll simply rolls again.
      // b77t (audit 5 M-G): sent after a CSPRNG-random delay, not right after the poll (checked again then)
      if (ready && onThread() && secureRandom() < 0.15) setTimeout(() => { // b70 (audit PRIM-8)
        if (lockedRef.current || !onThread()) return;
        sendCoverEnvelope(app.relay, app.sessions, token, who).catch((e) => {
          const m = (e as Error).message ?? String(e);
          console.log('[veil] cover send skipped:', m);
          // b198 (live retest Oct 15): the cover send is the observer that
          // actually REACHES the relay on the open thread every poll cycle.
          // On a superseded/deleted session it is the FIRST component to see
          // "Session not found" (the sync cleanly fetches 0 envelopes; the
          // heartbeat loop may legitimately skip the row if its listed status
          // is stale). Summon the list refresh the b164 auto-switch needs.
          if (isSessionGoneError(e, { superseded: true })) refreshSessionsRef.current?.(true);
        });
      }, coverSendDelayMs());
      // peer receipts confirm MY messages read — mark the bubbles
      const readIds = (res as { readIds?: string[] }).readIds ?? [];
      if (readIds.length) {
        console.log(`[veil-receipt] peer read ${readIds.length} of my message(s) — marking`);
        const set = new Set(readIds);
        setThreadMessages((prev) => prev.map((m) =>
          m.mine && !!m.mid && set.has(m.mid) ? { ...m, read: true, openedAt: Date.now() } : m)); // b198: burn clock anchors at receipt; b74 (VAR-07): by mid only
        // b69: receipts survive close/reopen (cache previously never updated)
        app.sessions.markCachedRead(token, readIds, 'mid').catch(() => undefined);
      }
      // b199: the peer's reactions
      void applyPeerReactionsRef.current(token, (res as { reactions?: { target: string; emoji: string | null }[] }).reactions);
      // Batch E (Superagent round 3, F-1): the relay keeps refusing a burn — say so
      // once in the thread instead of giving up silently
      if ((res as { burnStuck?: number }).burnStuck && onThread()) {
        const note: (ChatMessage & { systemNote?: string }) = {
          id: `burnstuck_${token}`, text: '', mine: false, ts: new Date().toISOString(),
          systemNote: 'The server has not confirmed deleting a burned message yet. Vardum keeps asking. The server copy expires on its own when the message’s expiry is reached (at most 30 days).',
        };
        setThreadMessages((prev) => (prev.some((m) => m.id === note.id) ? prev : [...prev, note]));
      }
      // Batch H (round-6 review R6-1-06 / R5-1-09): the phone's storage refused this
      // chat's state or its burn queue — say so once in the thread (reading still works)
      if (((res as { stateNotSaved?: boolean }).stateNotSaved || (res as { burnQueueTrouble?: boolean }).burnQueueTrouble) && onThread()) {
        const note: (ChatMessage & { systemNote?: string }) = {
          id: `storage_${token}`, text: '', mine: false, ts: new Date().toISOString(),
          systemNote: 'This phone’s storage refused to save part of this chat. Messages still open, but free up some space soon so nothing is lost.',
        };
        setThreadMessages((prev) => (prev.some((m) => m.id === note.id) ? prev : [...prev, note]));
      }
      // b175: a clean pass resets this token's backoff — the limiter only
      // matters while it's actively firing, not as a lingering penalty.
      if (!(res as { rateLimited?: boolean }).rateLimited) {
        delete rateLimitBackoffMsRef.current[token];
        delete rateLimitCooldownUntilRef.current[token];
      }
      if (ready) {
        setChat((c) => c && c.token === token ? { ...c, status: 'active' } : c);
        // b198 (live retest Oct 15): acceptance previously flipped only the
        // CHAT state to 'active' — the session ROW kept its stale 'pending'
        // until the next list refresh. The presence heartbeat skips non-active
        // rows, so the freshly-accepted open thread was invisible to the beat
        // loop (instrumented evidence: "beat pass: no beatable rows") — which
        // also blinded the not-found → refresh trigger. Patch the row so the
        // listed status matches reality the moment acceptance completes.
        setSessionRows((prev) => prev.map((r) => (r.token === token ? { ...r, status: 'active' as const } : r)));
      }
      if ((res as { rateLimited?: boolean }).rateLimited) {
        const prev = rateLimitBackoffMsRef.current[token] ?? RATE_LIMIT_BACKOFF_BASE_MS / 2;
        const next = Math.min(prev * 2, RATE_LIMIT_BACKOFF_CAP_MS);
        rateLimitBackoffMsRef.current[token] = next;
        rateLimitCooldownUntilRef.current[token] = Date.now() + next;
        console.log(`[veil] sync #${token.slice(0, 4)}: relay rate-limited this pass — backing off ${next}ms before next attempt`);
      }
    } catch (e) {
      const msg = (e as Error).message ?? String(e);
      // b88 (owner repro Sept 21 ~03:15 Bris: "Console Error [veil] sync
      // failed: Network request failed" popped up while a thread was
      // simply open on patchy connectivity): a transient fetch failure is
      // EXACTLY the case b83 already decided should self-heal quietly (the
      // next poll retries 1.5-3s later) — but this foreground catch still
      // used console.error unconditionally, so every ordinary network
      // hiccup while a chat was open painted a full red LogBox screen,
      // unlike backgroundSyncAllSessions's matching catch (console.log)
      // for the identical failure. Only this known-transient RN fetch
      // error message drops to info level; a genuinely unexpected sync
      // failure (bad decrypt, malformed response, etc.) still logs loud.
      if (isRateLimitedError(e)) {
        // b175: the FETCH itself got throttled (owner Metro repro Oct 2:
        // envelopeList 500'd "Rate limit exceeded" alongside burn/heartbeat
        // during the burst). syncChat throws before it can return the
        // rateLimited flag, so without this branch the poll loop would keep
        // its full 1.5s cadence straight through the limiter window.
        const prev = rateLimitBackoffMsRef.current[token] ?? RATE_LIMIT_BACKOFF_BASE_MS / 2;
        const next = Math.min(prev * 2, RATE_LIMIT_BACKOFF_CAP_MS);
        rateLimitBackoffMsRef.current[token] = next;
        rateLimitCooldownUntilRef.current[token] = Date.now() + next;
        console.log(`[veil] sync #${token.slice(0, 4)}: relay rate-limited the fetch itself — backing off ${next}ms`);
      } else if (/network request failed/i.test(msg)) {
        console.log(`[veil] sync skipped for #${token.slice(0, 4)} — network hiccup, next poll retries: ${msg}`);
      } else if ((e as Error)?.name === 'LegacySessionError' || /older security protocol/i.test(msg)) {
        // b77 (sealed sender): a 1:1 chat sealed before b77 has no delivery capabilities — the
        // existing clean-break notice ("start a new chat"), once; the thread shows as ended
        legacyChatsRef.current.add(token);
        if (onThread()) {
          const note: (ChatMessage & { systemNote?: string }) = { id: `legacy_${token}`, text: '', mine: false, ts: new Date().toISOString(), systemNote: msg };
          setThreadMessages((prev) => (prev.some((m) => m.id === note.id) ? prev : [...prev, note]));
          setChat((c) => (c && c.token === token && c.status !== 'ended' ? { ...c, status: 'ended' } : c));
        }
        setSessionRows((prev) => prev.map((r) => (r.token === token && r.status !== 'ended' ? { ...r, status: 'ended' as const } : r)));
      } else if (isSessionGoneError(e, { superseded: true })) {
        // b198 handoff (live find, Oct 15): the receiver sitting INSIDE a
        // deleted thread kept syncing it ("Session not found" ×123) and NEVER
        // refreshed the session list — the b164 auto-switch only fires on a
        // LIST REFRESH, which does not run while a chat is open. Trigger the
        // refresh here so the (freshness-gated) auto-switch can complete the
        // same-peer handoff instead of looping on a dead token.
        refreshSessionsRef.current?.(true);
        // b76r2 (ZTE battery): the forced refresh bypasses the quiet window, so at the 1.5s poll
        // cadence it ran ~40 lists a minute, locked the relay's list limiter (30/min) and kept it
        // locked — the refresh that ends the loop never got through. Same doubling backoff as the
        // rate-limit branch: the first refresh goes at once, repeats slow to one a minute.
        const prev = rateLimitBackoffMsRef.current[token] ?? RATE_LIMIT_BACKOFF_BASE_MS / 2;
        const next = Math.min(prev * 2, RATE_LIMIT_BACKOFF_CAP_MS);
        rateLimitBackoffMsRef.current[token] = next;
        rateLimitCooldownUntilRef.current[token] = Date.now() + next;
        console.log(`[veil] sync #${token.slice(0, 4)}: session gone server-side — refreshed the list so the auto-switch can run (next try in ${next}ms)`);
      } else {
        // next poll retries — but never silently
        console.error('[veil] sync failed:', msg);
      }
    } finally {
      syncInFlightRef.current[token] = false;
    }
  }, [app, chatKnown, advanceHandshake, settings, markChatUnavailable]);

  // b77n (pre-audit INFO-5): "Check again" on a chat marked unavailable on the relay's word alone (never one the
  // peer's END ended): the mark is cleared (checkChatAgain) and the chat syncs once; the P-4 rule applies afresh
  const handleCheckChatAgain = useCallback(async (token: string) => {
    if (!app || !(await checkChatAgain(app.sessions, token))) return;
    unavailableChatsRef.current.delete(token);
    setChat((c) => (c && c.token === token && c.unavailable && !c.endedByPeer ? { ...c, status: 'active', unavailable: false } : c));
    await syncToken(token).catch(() => undefined);
    void refreshSessionsRef.current?.(true);
  }, [app, syncToken]);

  // b77 FIX (owner report: "no notifications at all, even in the app"):
  // syncToken() above only ever ran for the CURRENTLY OPEN thread's token —
  // the push-received listener and the 10s main-screen poll both gated on
  // chatRef.current, so a message arriving on any OTHER session (or while
  // the user sits on the Conversations list, or while backgrounded) was
  // never decrypted at all until that thread was opened by hand, and
  // notifyNewMessage() never got a chance to fire. This is syncToken's
  // decrypt+cache+notify core WITHOUT the open-thread UI side effects
  // (chatMessages append, cover traffic, receipt send/mark, threadReady) —
  // those stay scoped to the foreground poll so background calls can never
  // corrupt the currently-open thread's state. Safe to call for every
  // session token on every wake.
  // b77u2 (UC-L1): resolves true only when the pass fetched and processed to the end (the quiet-chat check syncs first)
  const backgroundSyncToken = useCallback(async (token: string, peerLabel?: string, opts?: { quietCheck?: boolean }): Promise<boolean | undefined> => {
    if (lockedRef.current && settingsRef.current.holdUntilUnlock) return;
    if (decoyHoldNow()) return; // b77t2 (decoy gaps): the decoy session's own "Hold messages while locked"
    if (!app) return;
    // b77u (audit 6 U-M3, RH-L1, RH-L2): own thread and account only; its writes stop at a wipe (pinned store)
    const { onThread, live, setThreadMessages } = threadGuard(token, app);
    const ss = pinToWipe(app.sessions);
    const passHeld = (): boolean => holdWhileLocked(lockedRef.current, settingsRef.current.holdUntilUnlock) || decoyHoldNow() || !live();
    // foreground poll already covers the open chat — except while locked: that poll pauses
    // then, and skipping here too left the open chat with no sync at all (its calls never
    // rang and its messages waited for unlock). b71 (device test)
    if (!opts?.quietCheck) { if (onThread() && !lockedRef.current) return; } // b77u2 (UC-L1): the quiet check syncs the open chat too
    if (unavailableChatsRef.current.has(token)) return; // b77m merge (VAR-07): read-only, nothing to sync
    if (syncInFlightRef.current[token]) return;
    syncInFlightRef.current[token] = true;
    try {
      const who = await clientId();
      if (!who) return;
      const ready = await advanceHandshake(token, who);
      if (!ready) return opts?.quietCheck ? true : undefined; // b77u2 (UC-L1): no handshake yet, so no message to fetch first
      // b78 CRITICAL FIX: pass a FRESH knownIds set — the app-level chatKnown
      // belongs to whichever thread is/was OPEN. Using it here re-served other
      // sessions' already-consumed envelopes and re-decrypted them; every
      // envelope header carries a PQ rekey, so each re-decrypt rotated both
      // chains and reset the counters — the "Message counter out of range"
      // desync, occurring exactly when the phone was locked (background sync
      // is the only path that runs then). Dedupe is now authoritative in the
      // per-token processed-id ledger inside syncChat (SessionStore).
      // b87: same pagination cursor as the foreground poll — background
      // sync hits the identical 200-row stale-head stall otherwise.
      const startSkip = await app.sessions.syncSkip(token);
      const res = await syncChat(app.relay, app.sessions, token, who, new Set(), false, startSkip, sessionDialsRef.current[token]?.burnSecs || 0, { onScreen: () => chatOnScreenNow(token), shouldAbort: () => passHeld() }); // b77t (M-G)
      // b77m (audit VAR-07): the peer's END (endedBy 'peer') ended the chat — the local state is gone;
      // the list refresh drops the row (and closes it if it was open). The relay's word alone
      // (`unavailable`) keeps the chat, read-only, with its history.
      if (res.aborted) return; // b77u (RH-L2)
      const bgOutcome = syncOutcome(res);
      if (bgOutcome === 'ended') {
        if (onThread()) { setChat(null); setScreen('main'); }
        refreshSessionsRef.current?.(true);
        return;
      }
      if (bgOutcome === 'unavailable') {
        if (res.purged) dropPurgedThread(token, onThread); // b77u (audit 6 U-M8); b77u merge: the pass's own thread only
        if (res.messages?.length) notifyNewMessage(); // b77m review (L9): the peer's last messages (cached / held for the chat's open)
        markChatUnavailable(token, res.endedBy === 'peer');
        return;
      }
      applySealedPass(token, res); // b77r1 (audit A-5)
      applyNickPass(token, res); // b77k (IP77-3)
      // b77q review (J2-2): a pass already running when the user opened this chat — its messages are merged into the
      // open thread (deduped by id: openChat may have read them from the cache already). They were cached only, and
      // never shown until the chat was opened again
      // b77u (audit 6 W8): a message arrived. b77u2 (UC-L1): awaited, so the quiet check re-reads it after this pass
      if (res.messages?.length) await quietLedgerFor(app).touch(token).catch(() => undefined);
      const intoOpenThread = onThread() && !lockedRef.current;
      if (intoOpenThread && res.messages?.length) {
        const fresh = res.messages;
        setThreadMessages((prev) => {
          const have = new Set(prev.map((m) => m.id));
          const add = fresh.filter((m) => !have.has(m.id));
          return add.length ? [...prev, ...add] : prev;
        });
      }
      // b71: what arrived for the open chat while locked is shown when it unlocks
      if (onThread() && lockedRef.current && res.messages?.length) lockedOpenSyncedRef.current = true;
      if (!res.ended) await ss.saveSyncSkip(token, res.nextSkip);
      // b196: adaptive backoff bookkeeping (see pollBackoffRef)
      const nothingNew = !res.processedIds?.length && !(res as { callSignals?: unknown[] }).callSignals?.length;
      if (nothingNew) {
        const streak = (zeroStreakRef.current[token] ?? 0) + 1;
        zeroStreakRef.current[token] = streak;
        // b71 (device test): capped at 20 s, inside the 60 s ring window. At 60 s a phone
        // without push (or locked, or a dev build) saw an incoming call only after it rang out
        pollBackoffRef.current[token] = Date.now() + pollBackoffMs(streak); // b77n (pre-audit INFO-3): CSPRNG jitter
      } else {
        zeroStreakRef.current[token] = 0;
        pollBackoffRef.current[token] = Date.now() + pollBackoffMs(0);
      }
      // b152 CRITICAL (owner repro Oct 1: "unless you're in a chat thread,
      // the phone does nothing at all" when a call comes in): syncChat had
      // ALREADY decrypted and classified call signals for background threads —
      // this loop just dropped them on the floor, so an offer on any
      // non-open session never rang. Forward them to CallManager exactly like
      // the foreground path does (fire-and-forget, never blocks message
      // handling). b149 mounted the overlay on every screen; THIS was the
      // missing half of "calls ring anywhere".
      const bgCallSigs = (res as { callSignals?: { __veil_call: 1; op: 'invite' | 'offer' | 'answer' | 'ice' | 'end' | 'ringing'; call_id: string; sdp?: string; k?: string; cand?: string; reason?: string; seq?: number }[] }).callSignals;
      if (bgCallSigs?.length) {
        if (callSignalsAllowed(token)) void CallManager.handleSignals(token, bgCallSigs, peerLabel).catch((e) =>
          console.log(`[veil-call] background signal dispatch error: ${(e as Error).message}`));
      }
      // b92 F1 (b91 audit): a stray or genuine desync classified while this
      // thread was CLOSED must not vanish — the foreground notice renders in
      // React state that is gone by the time the thread opens. Persist the
      // counts; openChat drains them into the same soft-notice bubbles /
      // one-time desync Alert the live path shows.
      const bgRes = res as { strayIds?: string[]; desync?: boolean; desyncIds?: string[]; messages: unknown[] };
      if (bgRes.strayIds?.length) await ss.bumpPendingStrays(token, bgRes.strayIds.length);
      // b75 (audit RT-2): the closed-thread path used to raise the "out of sync" prompt on
      // ONE such pass; it now needs the same three-pass streak as the open thread
      if (countDesyncPass(token, bgRes) && (desyncStreakRef.current[token] ?? 0) >= 3) await ss.setPendingDesync(token);
      // b127 CRITICAL (owner repro Sept 25: native has NEVER shown a ✓ read
      // tick on any build): receipts are usually processed by THIS background
      // pass — the thread is closed when they arrive, or this loop simply wins
      // the fetch race (both loops share the per-token dedupe ledger, so the
      // loser never sees the envelope again). The foreground path was the only
      // one that applied readIds, so most peer read-confirmations were
      // decrypted, extracted, and thrown away here. Persist to the cache
      // (thread-closed case: the tick is there on next open) and update the
      // live thread state if it happens to be open.
      const bgRead = (res as { readIds?: string[] }).readIds ?? [];
      if (bgRead.length) {
        console.log(`[veil-receipt] background: peer read ${bgRead.length} of my message(s) — marking`);
        await ss.markCachedRead(token, bgRead, 'mid').catch(() => undefined);
        if (onThread()) {
          const rset = new Set(bgRead);
          setThreadMessages((prev) => prev.map((m) =>
            (m.mine && !!m.mid && rset.has(m.mid) ? { ...m, read: true, openedAt: Date.now() } : m))); // b198: burn clock anchors at receipt; b74 (VAR-07): by mid only
        }
      }
      // b199: the peer's reactions (cache always; live thread if open)
      await applyPeerReactionsRef.current(token, (res as { reactions?: { target: string; emoji: string | null }[] }).reactions);
      // b92 F9 (b91 audit, traffic-analysis parity): web idles keep emitting
      // cover envelopes while the app is open on any screen; native previously
      // sent cover ONLY while a thread was foregrounded, letting a relay
      // observer tell "native user idle" from "web user idle" by cadence.
      // Same 15% roll as the foreground poll, only while the app is active
      // (a suspended iOS app cannot emit anything, and that's honest too).
      if (ready && AppState.currentState === 'active' && secureRandom() < 0.15) setTimeout(() => { // b70 (audit PRIM-8); b77t (M-G): random delay
        if (lockedRef.current || AppState.currentState !== 'active') return;
        sendCoverEnvelope(app.relay, app.sessions, token, who).catch((e) => {
          const m = (e as Error).message ?? String(e);
          console.log('[veil] background cover send skipped:', m);
          // b198: same receiver-side deletion signal as the foreground catch.
          if (isSessionGoneError(e, { superseded: true })) refreshSessionsRef.current?.(true);
        });
      }, coverSendDelayMs());
      if (res.messages.length) {
        console.log(`[veil-notify] background: ${res.messages.length} new message(s) on #${token.slice(0, 4)} — notifying`);
        // b90: badge the thread. Only messages from the OTHER side count —
        // this path never runs for the open thread, so everything here is
        // unseen by definition. b77q review (J2-2): except a pass the user opened the chat during (merged above):
        // no badge then, and a banner only while the app is not in front
        const fresh = res.messages.filter((m) => !m.mine).length;
        const seenNow = intoOpenThread && AppState.currentState === 'active';
        if (fresh > 0 && !seenNow) {
          const next = await app.sessions.bumpUnread(token, fresh);
          setSessionRows((prev) => prev.map((r) => (r.token === token ? { ...r, unread: next } : r)));
        }
        if (!seenNow) notifyNewMessage();
      }
      return true; // b77u2 (UC-L1): the whole pass ran
    } catch (e) {
      const msg = (e as Error).message ?? String(e);
      console.log(`[veil-notify] background sync failed for #${token.slice(0, 4)}:`, msg);
      // b198 handoff (live find): same receiver-side dead-thread loop as the
      // foreground catch — a background pass discovering the session is gone
      // must also trigger the list refresh that lets b164 auto-switch run.
      if (isSessionGoneError(e, { superseded: true })) refreshSessionsRef.current?.(true);
      // b83 (owner repro + device log: "Keychain get('veil_rk_...') failed —
      // User interaction is not allowed"): the ratchet/session key is, and
      // stays, gated to WHEN_UNLOCKED — that key IS the message-decryption
      // material, unlike the b81 login-token fix, and it should NOT be
      // loosened. The honest consequence: real content decrypt is
      // architecturally impossible while the screen is actually locked, even
      // during a granted background wake window. Rather than staying
      // completely silent in exactly the case the owner cares about most,
      // fire the SAME zero-content generic banner this already uses for a
      // real decrypt — it reveals nothing new (no sender, no text, no
      // session, matching the existing threat model) and turns "silently
      // failed" into "you were notified something is waiting, open the app
      // to read it." Tradeoff disclosed: this can fire on a cycle that turns
      // out to be nothing but cover traffic once actually decrypted —
      // accepted, because false-silence is worse than an occasional
      // false-positive nudge.
      if (/User interaction is not allowed/i.test(msg)) {
        console.log(`[veil-notify] locked-device decrypt blocked for #${token.slice(0, 4)} — firing generic banner anyway (content stays undecrypted until unlock)`);
        notifyNewMessage();
      }
    } finally {
      syncInFlightRef.current[token] = false;
    }
  }, [app, advanceHandshake, markChatUnavailable]);

  // b78: background sync ACTIVE non-group sessions only. Pending sessions
  // must never be auto-accepted by a background poll — acceptance is the
  // explicit openChat UX (ceremony, nickname). Ended ones have no ratchet.
  // Group inbox has its own poll (syncGroupToken).
  const backgroundSyncAllSessions = useCallback(() => {
    // b196: during an active call, background sync of OTHER threads waits —
    // call signaling (offers/ICE/answers) shares the per-account rate budget
    // with polls, and the owner's Oct 12 log shows 429s eating 4 of 9 ICE
    // sends mid-call while other sessions kept polling. The in-call session
    // is foregrounded by its own paths, so nothing of its own is starved.
    const snap = CallManager.snapshot();
    if (snap && (snap.phase === 'calling' || snap.phase === 'ringing' || snap.phase === 'connecting' || snap.phase === 'active')) return;
    const now = Date.now();
    for (const row of sessionRows) {
      // b77 (sealed sender): plus chats THIS phone started that wait for the other side (their
      // completion reads the no-login `status`; nothing is ever accepted here) — the relay no
      // longer flips a listed row to active, and the initiator must complete and open its
      // inbound without the thread being open, or the peer's first messages wait (425)
      const pendingMine = row.status === 'pending' && row.mine && !row.request && !row.incoming;
      if ((row.status !== 'active' && !pendingMine) || row.groupToken) continue;
      if (legacyChatsRef.current.has(row.token)) continue; // b77: a pre-b77 chat has nothing to sync
      if (now < (pollBackoffRef.current[row.token] ?? 0)) continue; // b196 backoff
      backgroundSyncToken(row.token, row.title).catch(() => undefined);
    }
    // b198 BACKGROUND GROUP DELIVERY: group polls previously ran ONLY while the
    // group thread was open — a group message never arrived unless the
    // recipient was sitting inside the thread (and group sends fired no push,
    // fixed relay-side). This pass polls every known group record NOT
    // currently open (the open thread's own poll covers it), gateHot-respecting
    // and in-flight-guarded, on the same background cadence as pairwise sync.
    void (async () => {
      if (!app || !identity || app.relay.gateHot()) return;
      if (holdWhileLocked(lockedRef.current, settingsRef.current.holdUntilUnlock)) return; // audit VAR-59: as the 1:1 paths
      if (decoyHoldNow()) return; // b77t2 (decoy gaps): the decoy session's own "Hold messages while locked"
      try {
        await loadGroupRecords(app.storage); // hydrate the registry (returns a count)
        const recs = exportGroupRecords(app.storage);
        const who = await clientId();
        for (const rec of recs) {
          if (rec.sessionEnded) continue;
          let tok = rec.sessionToken ?? '';
          if (!tok && who) {
            // records created before b198 predate the stored token — derive from
            // the relay list (either side: the creator's main row or the member's
            // joined invite row)
            const lst = await app.relay.sessionList(who, identity.veilId);
            const body = (lst.data ?? {}) as { data?: unknown[]; sessions?: unknown[] };
            const list = (Array.isArray(body.data) ? body.data : (body.sessions ?? [])) as Record<string, unknown>[];
            const mine = list.find((r) => String(r.group_token ?? '') === rec.groupToken
              && String(r.state ?? '') === 'active'
              && (String(r.initiator_client_id ?? '') === who || String(r.responder_client_id ?? '') === who));
            if (mine) tok = String(mine.token ?? '');
            // b77q review (Info): written back, so the relay list is not asked (and trusted) for it every pass. Set on
            // the live record and saved as it is (b75r2 R2G-01: a saved copy would replace a newer live record)
            const live = tok ? await loadGroupRecord(app.storage, rec.groupToken).catch(() => null) : null;
            if (live && !live.sessionToken) { live.sessionToken = tok; await saveGroupRecord(app.storage, live).catch(() => undefined); }
          }
          if (!tok || chatRef.current?.token === tok) continue; // open thread: its own poll covers it
          if (syncInFlightRef.current[tok]) continue;
          syncInFlightRef.current[tok] = true;
          void pollGroupInbox(
            { relay: app.relay, sessions: app.sessions, storage: app.storage, webBaseUrl: VEIL_LINK_URL },
            {
              groupToken: rec.groupToken,
              sessionToken: tok,
              burnAfterOpen: !!sessionDialsRef.current[tok]?.burn,
              identity: { veilId: identity.veilId, ikSeedB64: identity.ikSeedB64, ikPubB64: identity.ikPubB64, pqPrivB64: identity.pqPrivB64 },
              knownIds: groupKnownRef.current,
              // b54 (device test Oct 18): PEEK, never consume — the old
              // background pass marked + burned messages it only notified
              // about, so they never rendered when the thread was opened.
              peekOnly: true,
              events: {
                // background arrival: contentless banner + unread badge — the
                // message body renders when the user opens the thread. Peek
                // re-reads the same rows every pass, so notify each id ONCE.
                onMessage: (m) => {
                  if (groupPeekNotifiedRef.current.has(m.envelopeId)) return;
                  // Batch H (round-6 review R6-2-05): no banner until the block list has loaded
                  if (!blockListLoadedRef.current) return;
                  groupPeekNotifiedRef.current.add(m.envelopeId);
                  if (isFromBlocked({ senderVid: m.senderVeilId }, blockedRef.current)) return; // Play UGC
                  void notifyNewMessage();
                },
                onSystem: () => undefined,
                onRead: () => undefined,
                onRotated: () => undefined,
                onSenderVerifyFailed: () => undefined,
              },
            },
          ).then(() => clearGoneAnswers(groupGoneRef.current, rec.groupToken)).catch(async (e) => {
            const m = (e as Error).message ?? String(e);
            // b198: the background pass is also the group's gone-detector while
            // the thread is closed — mark ended (stops polling) + refresh so
            // the deleted group's row leaves the list without user action.
            // b75r1 (audit G-10): only on repeated answers, then confirmed by asking the relay about this one session
            if (isSessionGoneError(e)) {
              if (!noteGoneAnswer(groupGoneRef.current, rec.groupToken)) { console.log(`[veil-group] background pass: "session not found" for #${rec.groupToken.slice(0, 6)} — not marked ended on one answer`); return; }
              const wsG = ((await app.sessions.load(tok)) as { writeSecret?: string | null } | null)?.writeSecret ?? null;
              if ((await relaySessionLiveness(app.relay, tok, wsG)) !== 'gone') { console.log(`[veil-group] background pass: #${rec.groupToken.slice(0, 6)} still on the relay — kept`); return; }
              const dead = await loadGroupRecord(app.storage, rec.groupToken);
              if (dead && !dead.sessionEnded) {
                // b75r2 (audit R2G-01): set on the live record and saved as it is (a saved copy would replace the
                // live record under a rotation, removal or key delivery still holding it)
                dead.sessionEnded = true;
                await saveGroupRecord(app.storage, dead);
                console.log(`[veil-group] background pass: group #${rec.groupToken.slice(0, 6)} ended server-side — marked ended`);
                refreshSessions();
              }
            } else {
              console.log(`[veil-group] background poll failed for #${rec.groupToken.slice(0, 6)}: ${m}`);
            }
          })
            .finally(() => { syncInFlightRef.current[tok] = false; });
        }
      } catch { /* background group pass is best-effort */ }
    })();
  }, [sessionRows, backgroundSyncToken, app, identity]);

  // audit VAR-22: my contacts' Vardum IDs and the names I gave them, for the group sender-name clash
  // check; read at most once a minute while a group is open
  const groupNamesCacheRef = useRef<{ at: number; list: { veilId: string; name: string | null }[] }>({ at: 0, list: [] });
  const groupContactNames = useCallback(async (): Promise<{ veilId: string; name: string | null }[]> => {
    const c = groupNamesCacheRef.current;
    if (!app || Date.now() - c.at < 60_000) return c.list;
    try {
      const pins = await app.pins.listPins();
      const list = await Promise.all(pins.map(async (p) => ({ veilId: p.veilId, name: (await app.pins.getNickname(p.veilId).catch(() => null)) ?? null })));
      groupNamesCacheRef.current = { at: Date.now(), list };
      return list;
    } catch { return c.list; }
  }, [app]);

  // b62 groups: live poll for an open group thread (veil-group-1 inbox)
  const syncGroupToken = useCallback(async (token: string) => {
    if (!app || !identity) return;
    if (holdWhileLocked(lockedRef.current, settingsRef.current.holdUntilUnlock)) return; // audit VAR-59: as the 1:1 paths
    if (decoyHoldNow()) return; // b77t2 (decoy gaps): the decoy session's own "Hold messages while locked"
    const row = sessionRows.find((r) => r.token === token);
    const groupToken = row?.groupToken ?? (groupKnownTokensRef.current[token] ?? undefined);
    if (!groupToken) return;
    // b77u (audit 6 RH-M1): every write to the screen (messages, the members panel, the own-echo binding) is for
    // this group's thread only, for this account, with no wipe since the pass began. RH-L1: its store writes stop at a wipe
    const { onThread, live, setThreadMessages } = threadGuard(token, app);
    const ss = pinToWipe(app.sessions);
    const setThreadGroupInfo: typeof setGroupInfo = (u) => {
      if (!onThread()) return;
      setGroupInfo((gi) => (gi && gi.groupToken === groupToken ? (typeof u === 'function' ? u(gi) : u) : gi));
    };
    // b190: roster polls are gate traffic — during the shared rate-limit
    // quiet window the poll would only burn the budget and re-lock the
    // limiter.
    if (app.relay.gateHot()) return;
    // b190: a record marked sessionEnded (server-side session gone) never
    // polls again — local history stays readable, the relay is left alone.
    const endedRec = await loadGroupRecord(app.storage, groupToken);
    if (endedRec?.sessionEnded) return;
    if (syncInFlightRef.current[token]) return;
    syncInFlightRef.current[token] = true;
    try {
      const who = await clientId();
      if (!who) return;
      const contactNames = await groupContactNames(); // audit VAR-22
      const res = await pollGroupInbox(
        { relay: app.relay, sessions: app.sessions, storage: app.storage, webBaseUrl: VEIL_LINK_URL },
        {
          groupToken,
          // b132: relay-side group burn — this member's own session credential
          // (gate group clause authorises it) so opened envelopes don't sit
          // on the relay at the 24h submit TTL forever.
          sessionToken: token,
          burnAfterOpen: !!sessionDialsRef.current[token]?.burn,
          identity: { veilId: identity.veilId, ikSeedB64: identity.ikSeedB64, ikPubB64: identity.ikPubB64, pqPrivB64: identity.pqPrivB64 },
          knownIds: groupKnownRef.current,
          // Batch C (A1): lets the creator publish the signed member list and a
          // not-yet-admitted member re-send its seat-proven intro
          clientId: who,
          shouldAbort: () => holdWhileLocked(lockedRef.current, settingsRef.current.holdUntilUnlock) || decoyHoldNow() || !live(), // b77u (RH-L2)
          events: {
            onMessage: async (info) => {
              // audit VAR-21/22, GR-4, M-3 and (device fix VAR-54) rcvAt: the row as cached — src/app-guards.ts groupMessageRow
              const msg = groupMessageRow(info, contactNames);
              // b62: group history survives reopen. b77q review (J2-1): cached FIRST and awaited, as the 1:1 path —
              // a refused write answers false, and the library holds the envelope (not known, not burned) for the
              // next pass and says so in the thread; nothing is shown or notified until it is kept
              if ((await ss.cacheMessages(token, [msg]).catch(() => false)) === false) return false;
              setThreadMessages((prev) => (prev.some((m) => m.id === msg.id) ? prev : [...prev, msg]));
              // Play UGC: a blocked sender's message is kept (unblock shows it) but never notifies
              if ((AppState.currentState !== 'active' || lockedRef.current || !onThread()) && blockListLoadedRef.current && !isFromBlocked(msg, blockedRef.current)) { // (b70 re-review 11: locked counts as not looking)
                notifyNewMessage();
                // b90: group messages landing on a closed thread badge it too
                ss.bumpUnread(token, 1).then((next) => {
                  setSessionRows((prev) => prev.map((r) => (r.token === token ? { ...r, unread: next } : r)));
                }).catch(() => undefined);
              }
              // read receipts: sent by the group display marker (audit VAR-21), never at decrypt
            },
            // b123: own-envelope echo — bind the relay envelope id to the
            // locally-sent bubble so group read receipts can tick it (the
            // pairwise path has had envId from submit since day one; group
            // submits never learn it, the poll hands it back here).
            onOwnEcho: (envelopeId, text) => {
              setThreadMessages((prev) => {
                const idx = prev.findIndex((m) => m.mine && !m.envId && !m.systemNote && m.text === text);
                if (idx === -1) return prev;
                const next = [...prev];
                next[idx] = { ...next[idx], envId: envelopeId };
                const localId = next[idx].id;
                setTimeout(() => { ss.setCachedEnvId(token, localId, envelopeId).catch(() => undefined); }, 0);
                return next;
              });
            },
            onSystem: (info) => {
              const msg: (ChatMessage & { systemNote?: string }) = {
                id: `sys_${info.envelopeId}`,
                text: '', mine: false, ts: info.sentAt,
                systemNote: info.note,
              };
              setThreadMessages((prev) => (prev.some((m) => m.id === msg.id) ? prev : [...prev, msg]));
            },
            onRead: (readIds) => {
              if (!readIds.length) return;
              setThreadMessages((prev) => prev.map((m) => {
                if (!m.mine || !m.envId || !readIds.includes(m.envId)) return m;
                return { ...m, read: true, openedAt: Date.now() }; // b198: burn clock anchors at receipt
              }));
              // b69: group read ticks persist across close/reopen too
              ss.markCachedRead(token, readIds).catch(() => undefined);
            },
            onRotated: (newEpoch) => {
              setThreadGroupInfo((gi) => (gi ? { ...gi, epoch: newEpoch } : gi));
              // b75 (lead's emulator finding): the panel's fingerprint follows the epoch at once
              currentGroupFingerprint(app.storage, groupToken).then((fp) => setThreadGroupInfo((gi) => (gi && gi.epoch === newEpoch ? { ...gi, fingerprint: fp } : gi))).catch(() => undefined);
            },
            onSenderVerifyFailed: (envelopeId, reason) => {
              const msg: (ChatMessage & { systemNote?: string }) = {
                id: `sig_${envelopeId}`, text: '', mine: false, ts: new Date().toISOString(),
                systemNote: groupDiscardNote(reason), // b75r1 (audit G-9): worded for what was discarded
              };
              setThreadMessages((prev) => (prev.some((m) => m.id === msg.id) ? prev : [...prev, msg]));
            },
            onEpochBehind: ({ groupToken: gt, behindEpoch, localEpoch }) => {
              // b75 (audit GR-2): raised only on a creator-signed rekey this phone couldn't take, and the
              // note never advises leaving or rejoining (leaving gets this identity denied for good: §11.12)
              console.log('[veil-group] device behind group epoch — asked the creator for the key', { group: gt.slice(0, 8), localEpoch, behindEpoch });
              if (groupBehindNoticeRef.current.has(`ep_${gt}`)) return;
              groupBehindNoticeRef.current.add(`ep_${gt}`);
              const msg: (ChatMessage & { systemNote?: string }) = {
                id: `epoch_${gt}_${behindEpoch}`, text: '', mine: false, ts: new Date().toISOString(),
                systemNote: 'The group creator changed the group keys, and the new key hasn’t reached this phone yet. This phone has asked for it; messages sent since then appear once it arrives, and sending waits until then.',
              };
              setThreadMessages((prev) => (prev.some((m) => m.id === msg.id) ? prev : [...prev, msg]));
            },
            onDecryptFailed: ({ groupToken: gt, err }) => {
              if (groupBehindNoticeRef.current.has(`dec_${gt}`)) return;
              groupBehindNoticeRef.current.add(`dec_${gt}`);
              const msg: (ChatMessage & { systemNote?: string }) = {
                id: `dec_${gt}_${Date.now()}`, text: '', mine: false, ts: new Date().toISOString(),
                systemNote: 'A group message could not be opened on this phone. It may have been damaged on the way; the phone tries it again on the next check.', // b75 (audit GR-2): no rejoin advice
              };
              setThreadMessages((prev) => (prev.some((m) => m.id === msg.id) ? prev : [...prev, msg]));
            },
          },
        },
      );
      clearGoneAnswers(groupGoneRef.current, groupToken); // b75r1 (audit G-10): a good poll
      if (res) {
        setThreadGroupInfo((gi) => gi ? { ...gi, members: res.members, fingerprint: res.fingerprint, epoch: res.epoch ?? gi.epoch } : gi); // b75: epoch and fingerprint from the end of the pass
        // b71 (audit F-07); b75r1 (audit G-8): each request says whether the claimant is a contact and whether the key matches
        const claimRows = await Promise.all((res.pendingClaims ?? []).map(async (r) => {
          const pin = await app.pins.getPin(r.veilId).catch(() => null);
          const nick = pin ? await app.pins.getNickname(r.veilId).catch(() => null) : null;
          return { ...r, contactLine: claimContactLine(claimContactStatus(pin, r.ikPub), nick) };
        }));
        setGroupClaims({ groupToken, rows: claimRows });
        // M-3 (b69 audit): rotations aren't arriving (or are being withheld) — say so
        // plainly in the group, once per epoch per run
        const kn = res.keyNotice;
        if (kn && !groupBehindNoticeRef.current.has(`keys_${groupToken}_${kn.kind}_${kn.epoch}`)) {
          groupBehindNoticeRef.current.add(`keys_${groupToken}_${kn.kind}_${kn.epoch}`);
          const note = kn.kind === 'stale'
            ? `Group keys haven't been refreshed for ${kn.ageHours} hours. Until they are, someone recently removed from the group may still be able to read new messages here, so sending is paused. Keys refresh when the group creator opens the group.`
            : kn.kind === 'removed' && kn.self // b75r1 (audit G-7): it is this phone that was removed
              ? 'The group creator removed you from this group. You won\u2019t get its new keys, so you can\u2019t read or send new messages here.'
            : kn.kind === 'removed' // b71 (audit F-04): the creator's signed list announced a removal
              ? 'The group creator removed someone — waiting for new group keys. Sending is paused until they arrive, so the removed person can\'t read what you send.'
              : 'This group has newer keys that haven\'t reached this phone yet. Sending waits until they arrive.';
          const msg: (ChatMessage & { systemNote?: string }) = { id: `keys_${groupToken}_${kn.kind}_${kn.epoch}`, text: '', mine: false, ts: new Date().toISOString(), systemNote: note };
          setThreadMessages((prev) => (prev.some((m) => m.id === msg.id) ? prev : [...prev, msg]));
        }
        // b71 (review P-01): a joiner gets the group key only once the creator lets it in
        // b71 (audit F-07): the creator approves each link join with a tap, so the notice says that
        if (!res.awaitingKey) setThreadMessages((prev) => (prev.some((m) => m.id === `await_${groupToken}`) ? prev.filter((m) => m.id !== `await_${groupToken}`) : prev));
        if (res.awaitingKey && !groupBehindNoticeRef.current.has(`await_${groupToken}`)) {
          groupBehindNoticeRef.current.add(`await_${groupToken}`);
          const msg: (ChatMessage & { systemNote?: string }) = { id: `await_${groupToken}`, text: '', mine: false, ts: new Date().toISOString(), systemNote: 'Waiting for the group creator to approve you… Messages appear, and you can send, once they have.' };
          setThreadMessages((prev) => (prev.some((m) => m.id === msg.id) ? prev : [...prev, msg]));
        }
        // Batch E (round-3 review F-3): a group made before Batch C — its creator
        // confirms the old member list once instead of trusting the server's copy
        const legacy = res.legacyRosterToConfirm ?? [];
        // Batch F (round-4 reviews R4-4-08 / R4-2-03): one decision per member, with
        // the name the user gave them and whether they are a contact whose key
        // matches; leaving someone out is the default. "Not now" waits until the
        // next app launch (the notice key stays set for this run).
        if (legacy.length && onThread() && !lockedRef.current && !groupBehindNoticeRef.current.has(`legacy_${groupToken}`)) { // (b70 re-review 12: not over the lock)
          groupBehindNoticeRef.current.add(`legacy_${groupToken}`);
          // b77t (audit 5 L-20): in-window (it shows members' nicknames and Vardum IDs). buttons[0] is the
          // cancel (safe) answer, buttons[1] the confirm one; a tap outside the card answers cancel
          // b77t2 (CM-2): asked for THIS account only. A lock or account switch withdraws the dialog: the whole
          // review stops (nothing partial is saved) and is asked again on a later pass
          const owner = app;
          const noticeKey = `legacy_${groupToken}`;
          const WITHHELD = new Error('withheld');
          const ask = async (title: string, message: string, buttons: { text: string; style?: 'cancel' | 'destructive' | 'default'; value: boolean }[]) => {
            let withheld = false;
            const a = await askFor(owner, { title, message, confirm: true, cancelLabel: buttons[0].text, submitLabel: buttons[1].text }, { onWithheld: () => { withheld = true; } });
            if (withheld) throw WITHHELD;
            return a === true ? buttons[1].value : buttons[0].value;
          };
          void (async () => {
            const review = await ask(
              'Check who is in this group',
              `This group was made with an older version of Vardum. The server lists ${legacy.length} member(s). Only the people you confirm will get the group's keys, including the current key, so they can read what is still stored for this group.`,
              [{ text: 'Not now', style: 'cancel', value: false }, { text: 'Review members', value: true }],
            );
            if (!review) return;
            const chosen: string[] = [];
            for (const m of legacy) {
              const nick = await app.pins.getNickname(m.veilId).catch(() => null);
              const pin = await app.pins.getPin(m.veilId).catch(() => null);
              const status = !pin ? 'Not in your contacts.' : pin.ikPubB64 === m.ikPub ? 'In your contacts, and their key matches.' : '⚠ In your contacts, but their key is DIFFERENT from the one you saved.';
              const yes = await ask(
                nick ? `${nick}` : 'Is this someone you invited?',
                `Vardum ID ${m.veilId}\n${status}\n\nOnly confirm people you know you invited.`,
                [{ text: 'Leave out', style: 'cancel', value: false }, { text: 'Confirm', value: true }],
              );
              if (yes) chosen.push(m.ikPub);
            }
            // Batch G (round-5 review R5-2-06): a failed save is reported, not hidden
            const savedOk = await confirmLegacyRoster(app.storage, groupToken, chosen).then(() => true).catch(() => false);
            // Batch H (round-6 review R6-2-07): the choices may still take effect in this run
            if (!savedOk) { void askFor(owner, { title: 'May not have been saved', message: 'Your choices may not have been saved on this phone. If they were not, you will be asked again next time.', info: true }); return; }
            void askFor(owner, { info: true, title: 'Members confirmed', message: chosen.length === legacy.length
              ? 'Everyone on the list is confirmed.'
              : `${chosen.length} confirmed, ${legacy.length - chosen.length} left out. To bring someone back: they delete the group on their phone, then you send them a new invite with Add people.` });
          })().catch((e) => { if (e === WITHHELD) groupBehindNoticeRef.current.delete(noticeKey); });
        }
        // creator auto-rotation: 100 envelopes / 24 h per epoch (web parity)
        // b190 (owner Metro log Oct 11: auto-rotate re-fired every 3s poll
        // against a member with no published PQ prekey, each attempt doing
        // identity lookups that kept the relay limiter LOCKED — retry_minutes
        // 6→2 over an hour while nobody even wrote). Two guards: (1) never
        // rotate while the shared rate-limit quiet window is hot; (2) cache
        // the prekey miss on the group record for 15 min so a member who
        // hasn't published a PQ prekey stops triggering lookups entirely.
        const rotRec = await loadGroupRecord(app.storage, groupToken);
        const rotBlockedUntil = Number(rotRec?.rotateBlockedUntil ?? 0);
        // b71 (device test): one automatic rotation at a time per group (a poll every few
        // seconds used to start another while one was still on the network)
        if (res.needsRotation && onThread() && !autoRotatingRef.current.has(groupToken)
            && !app.relay.gateHot() && Date.now() >= rotBlockedUntil) {
          const main = await findMainGroupSession({ relay: app.relay, sessions: app.sessions, storage: app.storage, webBaseUrl: VEIL_LINK_URL }, groupToken, who);
          if (main) {
            autoRotatingRef.current.add(groupToken);
            rotateGroup({ relay: app.relay, sessions: app.sessions, storage: app.storage, webBaseUrl: VEIL_LINK_URL },
              { groupToken, sessionToken: main, clientId: who, onlyIfNeeded: true })
              .finally(() => autoRotatingRef.current.delete(groupToken))
              .then((newEpoch) => {
                setThreadGroupInfo((gi) => (gi ? { ...gi, epoch: newEpoch } : gi));
                currentGroupFingerprint(app.storage, groupToken).then((fp) => setThreadGroupInfo((gi) => (gi && gi.epoch === newEpoch ? { ...gi, fingerprint: fp } : gi))).catch(() => undefined); // b75
                setThreadMessages((prev) => [...prev, { id: `sys_rot_${newEpoch}`, text: '', mine: false, ts: new Date().toISOString(), systemNote: 'Group keys changed.' }]); // b73 (audit V-15): the epoch key isn't a post-quantum key (its delivery is ML-KEM wrapped)
              })
              .catch(async (e) => {
                const rmsg = String((e as Error)?.message ?? e);
                if (/no (published|signed) PQ prekey/i.test(rmsg)) {
                  // persist the 15-min cooldown ONLY onto a real record —
                  // never fabricate one (a missing record is its own problem)
                  const rec2 = await loadGroupRecord(app.storage, groupToken);
                  if (rec2) {
                    rec2.rotateBlockedUntil = Date.now() + 15 * 60_000; // b75r2 (audit R2G-01): on the live record, not a copy
                    await saveGroupRecord(app.storage, rec2);
                  }
                  console.log('[veil-group] auto-rotate: member has no published PQ prekey — rotation cool-down 15 min (member must republish)');
                } else {
                  console.error('[veil-group] auto-rotate failed', e);
                }
              });
          }
        }
      }
      // web parity: ~15% of poll cycles emit a cover envelope (padded to the
      // same buckets, cover flag set — undecryptable filler that masks activity)
      // b190: never while the shared rate-limit quiet window is hot.
      // b197 (audit L-2): VARIABLE-LENGTH cover text (16–48 chars) — a fixed
      // 24-char filler at a fixed probability is trivially fingerprintable by
      // size/periodicity; length jitter makes the cover population blend with
      // real short messages (all still inside the same padded buckets).
      // b76 (padding): the 1:1 cover filler (groupCoverText) — about 15 % of cover now lands in
      // the 4 KiB class too, the class of long posts and of most rekey parts (16–48 characters
      // always fell in the 1 KiB class, so a 4 KiB group envelope was never cover)
      if (!app.relay.gateHot() && secureRandom() < 0.15) { // b70 (audit PRIM-8)
        sendGroupMessage(
          { relay: app.relay, sessions: app.sessions, storage: app.storage, webBaseUrl: VEIL_LINK_URL },
          { groupToken, sessionToken: token, clientId: who, text: groupCoverText(), cover: true },
        ).catch(() => undefined);
      }
    } catch (e) {
      // b190 (owner Metro log Oct 11: veilGroupGate(roster) 404 "Session not
      // found" every poll cycle for a group whose server-side session row is
      // gone — e.g. a deleted group). Fail-closed like
      // the b186 DM case: mark the record ended once, stop hammering the
      // relay, and say so once instead of spamming errors every 3s.
      // b75r1 (audit G-10): not on one answer — repeated answers (noteGoneAnswer), then confirmed by asking the
      // relay about this one session (relaySessionLiveness); until then the thread stays open and keeps polling
      let goneForSure = false;
      if (isSessionGoneError(e) && noteGoneAnswer(groupGoneRef.current, groupToken)) {
        const wsG = ((await app.sessions.load(token)) as { writeSecret?: string | null } | null)?.writeSecret ?? null;
        goneForSure = (await relaySessionLiveness(app.relay, token, wsG)) === 'gone';
      }
      if (isSessionGoneError(e) && !goneForSure) {
        console.log('[veil-group] "session not found" — not treated as the end of the group until it repeats and the relay confirms it');
      } else if (goneForSure) {
        const deadRec = await loadGroupRecord(app.storage, groupToken);
        if (deadRec && !deadRec.sessionEnded) {
          deadRec.sessionEnded = true; // b75r2 (audit R2G-01): on the live record, not a copy that would replace it
          await saveGroupRecord(app.storage, deadRec);
          console.log('[veil-group] server-side session is gone — thread marked ended, roster polls stopped (local history kept)');
        }
        // b198 (group ✕ peer-close, founder report: same as the pairwise bug —
        // the member sitting INSIDE the group never saw it close): the pairwise
        // gone-detection effect deliberately excludes groups, so the open
        // thread must be closed HERE, the moment the poll proves the group's
        // server rows are gone. Local history stays readable (b190 semantics).
        if (onThread()) {
          setChat(null);
          setScreen('main');
          refreshSessions();
          console.log('[veil-group] open thread closed — the group was ended server-side');
        }
      } else {
        console.error('[veil-group] inbox poll failed', e);
      }
    } finally {
      syncInFlightRef.current[token] = false;
    }
  }, [app, identity, sessionRows, groupContactNames]);

  // b160 K-4 fix (live-found, Oct 1): re-arm the receipt ledger. A peer
  // message acked as delivery-only (read-receipts dial off, or by the
  // pre-b129 sweep that never reached cached rows) is permanently blocked
  // from ever upgrading to a read receipt — the ledger marks it done and
  // the sweep never re-sends it. Re-arm in two cases:
  //   1. every app launch, per token, once (covers the whole b127-b159 era
  //      where cached backlogs were acked delivery-only or not at all);
  //   2. every read-receipts dial flip OFF->ON (messages read while the
  //      dial was off must be re-acknowledged as read).
  // Cost per re-arm: one bounded receipt burst per thread on next open
  // (<=20 ids per envelope, cached rows only). Ledger rebuilt immediately.
  const receiptRearmedRef = useRef<Set<string>>(new Set());
  const readDialPrevRef = useRef<boolean>(chatSettings.readReceipts);
  useEffect(() => {
    if (!app) return;
    if (chatSettings.readReceipts !== readDialPrevRef.current) {
      // dial flipped: full re-arm (incl. threads re-armed earlier this launch)
      readDialPrevRef.current = chatSettings.readReceipts;
      if (chatSettings.readReceipts) {
        receiptSentRef.current = new Set();
        receiptRearmedRef.current = new Set();
        console.log('[veil-receipt] read-receipts dial switched ON — receipt ledgers re-armed');
      }
    }
    for (const row of sessionRows) {
      const t = row.token;
      if (!t || receiptRearmedRef.current.has(t)) continue;
      receiptRearmedRef.current.add(t);
      void app.sessions.clearReceiptedIds(t).catch(() => undefined);
    }
  }, [app, chatSettings.readReceipts, sessionRows]);

  const openChat = useCallback(async (token: string, title: string, subtitle: string, status: 'pending' | 'active' | 'ended', peerVeilId: string | null = null, myVerified = false, groupToken?: string) => {
    if (!app) return;
    const acctAtStart = decoyModeRef.current; // b77t (audit 5 M-E): an open that outlives an account switch opens nothing
    const openSeq = threadViewRef.current.beginOpen(); // b77u (audit 6 RH-I2): a later open supersedes this one
    // b139 funnel fix: the FIRST REAL relay session opened — emits the
    // first_session_started + activation events once, and unlocks the
    // dismissible "Secure your VEIL" prompt (checkup + app lock) which now
    // never appears before this point.
    if (!decoyModeRef.current) try { // b77t (M-E): the decoy's chats never touch the real settings or counts
      const st = await app.settings.load();
      if (!st.firstSessionDone) {
        const st1 = { ...st, firstSessionDone: true };
        await app.settings.save(st1);
        setSettings(st1);
        if (!st1.setupDone) setSecurePrompt(true);
      }
      await noteFirstSession(app.relay, app.storage);
    } catch { /* instrumentation must never break opening a chat */ }
    // (b67) defense-in-depth: clear any stale global error before showing a
    // chat thread — ChatScreen renders the same shared `error` state other
    // screens use, so a leftover Settings/Contacts error could otherwise
    // appear inside an unrelated conversation.
    setError(null);
    // b72: cached rows opened for the first time NOW get their burn clock
    // stamped here (web-parity "burn N hours after open" countdown)
    // b90: opening a thread clears its unread badge (persisted + row state)
    // b75r3 (audit PR3-04): with history off, unread messages wait in memory only; what the
    // badge counted beyond them was lost when Vardum closed (said once, below)
    const unreadAtOpen = groupToken ? 0 : await app.sessions.getUnread(token).catch(() => 0);
    const waitingAtOpen = groupToken ? 0 : app.sessions.unshownCount(token);
    const historyOff = !groupToken && await app.sessions.historyPersistBlocked().catch(() => true);
    await app.sessions.clearUnread(token);
    setSessionRows((prev) => prev.map((r) => (r.token === token ? { ...r, unread: 0 } : r)));
    const history = await app.sessions.ensureOpenedAt(token);
    if (decoyModeRef.current !== acctAtStart || !threadViewRef.current.openCurrent(openSeq)) return; // b77t (M-E): switched accounts meanwhile; b77u (RH-I2): or a newer open
    threadViewRef.current.show(token); // b77u (U-M3): the message list is this thread's from here (setChat follows later)
    setChatMessages(history);
    // b198 CACHE-RENDER LOOPHOLE: this open IS the human-open moment for every
    // cached peer row still awaiting display. Flip their relay burns (media
    // blobs ride along) and re-anchor their view-burn clocks here — background
    // decrypt had stamped machine time, so cache-rendered messages could
    // vanish "on their own" while the relay copy survived (live-caught with
    // the first post-flip voice message). Idempotent; no-ops on non-burn
    // threads (no pending entries) and on reopens (already-displayed).
    // decrypt-cached rows key the envelope id in `id` (live rows carry `envId`);
    // pendingBurn entries use the envelope id either way, so take both.
    const cacheEnvIds = history.filter((m) => !m.mine).map((m) => (m as { envId?: string }).envId ?? m.id);
    // b75r3 (audit PR3-02): awaited — the purge below must see the burns this open unlocked
    // b77z2 (Z-1): local storage only now (display marks + the cache's burn clocks); it no
    // longer waits on the chat's sync chain, so a pass in flight (or a hung relay call) can't
    // hold the chat from opening
    if (cacheEnvIds.length) {
      await markEnvelopesDisplayed(app.relay, app.sessions, token, cacheEnvIds).catch((e) =>
        console.log(`[veil] cache display-mark skipped: ${(e as Error).message ?? e}`));
    }
    const sealedInfo = (await app.sessions.load(token)) as { burnAfterOpen?: boolean; defaultTtlSeconds?: number; expireAfterSeconds?: number; fingerprint?: string | null } | null;
    // b92 F1 (b91 audit): drain strays/desync recorded while this thread was
    // closed — the user sees the same soft notice / one-time Alert the live
    // path would have shown, instead of a silently missing message.
    const pendingStrays = await app.sessions.takePendingStrays(token);
    const pendingDesync = await app.sessions.takePendingDesync(token);
    const pendingMissing = await app.sessions.takePendingMissing(token); // b70 (re-review P1)
    // b89 (owner burn test: window hit 0, messages stayed): purge rows whose
    // burn clock ran out while the thread was closed — they must not render
    // again on reopen, and must not survive in the plaintext cache.
    // b92 F8 (b91 audit): the expireAfterSeconds tail is GONE from both burn
    // chains — the 24h UNOPENED dial must never masquerade as a burn window;
    // defaultTtlSeconds is captured on every create/join path (7200
    // fallback) so the dial-derived value is the honest one.
    // Batch E (R1-01): the session's own dials win; the row only for a legacy thread
    const win0 = sealedInfo ? burnWindow(sealedInfo, sessionDialsRef.current[token]) : { burn: false, secs: 0 }; // Batch G (R5-1-02)
    const burnSecs0 = win0.secs;
    let history0 = history;
    if (win0.burn && burnSecs0 > 0) {
      // b75r3 (PR3-04): filter what this open loaded (messages that waited in memory are in
      // `history` only — re-reading the cache would drop them)
      // b77z2 (Z-1): the cache part only — the queue edit for unopened rows past their horizon
      // runs on the chat's sync chain in the background (opening never waits on a pass)
      const purged0 = await app.sessions.purgeBurnedMessages(token, burnSecs0, { queue: 'background' });
      history0 = history.filter((m) => !purged0.includes(m.id));
    }
    const lostAtOpen = historyOff ? Math.max(0, unreadAtOpen - waitingAtOpen) : 0;
    if (lostAtOpen > 0) {
      history0 = [...history0, {
        id: `notkept_bg_${Date.now()}`, text: '', mine: false, ts: new Date().toISOString(),
        systemNote: lostAtOpen === 1
          ? 'One message arrived while this chat was closed, but Vardum was closed before you opened it. With history off it was not kept.'
          : `${lostAtOpen} messages arrived while this chat was closed, but Vardum was closed before you opened them. With history off they were not kept.`,
      } as ChatMessage & { systemNote?: string }];
    }
    if (pendingStrays > 0) {
      const bgNotice: (ChatMessage & { systemNote?: string }) = {
        id: `stray_bg_${Date.now()}`,
        text: '',
        mine: false,
        ts: new Date().toISOString(),
        systemNote: pendingStrays === 1
          ? 'One message could not be opened on this device; the rest of the conversation is unaffected.'
          : `${pendingStrays} messages could not be opened on this device; the rest of the conversation is unaffected.`,
      };
      history0 = [...history0, bgNotice];
    }
    if (pendingMissing > 0) {
      history0 = [...history0, {
        id: `gap_bg_${Date.now()}`, text: '', mine: false, ts: new Date().toISOString(),
        systemNote: pendingMissing === 1
          ? 'One message your contact sent has not arrived. It may still come; if not, the server did not deliver it.'
          : `${pendingMissing} messages your contact sent have not arrived. They may still come; if not, the server did not deliver them.`,
      } as ChatMessage & { systemNote?: string }];
    }
    // b157: drain calls missed while this device was locked (offer held by
    // hold-until-unlock) — same soft-notice pattern as the strays above.
    const missedCalls = await app.sessions.takeMissedCalls(token);
    if (missedCalls && missedCalls.n > 0) {
      const mcNotice: (ChatMessage & { systemNote?: string }) = {
        id: `missedcall_bg_${Date.now()}`,
        text: '',
        mine: false,
        ts: new Date().toISOString(),
        systemNote: missedCalls.n === 1
          ? `Missed call from ${missedCalls.peer} — the call came in while this device was locked or away.`
          : `${missedCalls.n} missed calls from ${missedCalls.peer} — the calls came in while this device was locked or away.`,
      };
      history0 = [...history0, mcNotice];
    }
    if (pendingDesync) {
      desyncPromptedRef.current[token] = true; // one-time, matching the live path
      // b77t2 (CM-2): in-window, for this chat's account only
      void askFor(app, {
        title: 'Session out of sync',
        message: 'New messages in this thread can no longer be decrypted on this device. End this session and start a new chat thread with the same contact to keep messaging securely.',
        info: true,
      }, { onWithheld: () => { desyncPromptedRef.current[token] = false; } });
    }
    if (decoyModeRef.current !== acctAtStart || !threadViewRef.current.openCurrent(openSeq)) return; // b77t (M-E); b77u (RH-I2)
    groupKnownRef.current = new Set(history0.map((m) => m.id));
    setChatMessages(history0);
    setChatKnown(new Set(history0.map((m) => m.id)));
    // b123: prefill the rename modal with the peer's device-local nickname
    const localNick = peerVeilId ? await app.pins.getNickname(peerVeilId) : null;
    if (decoyModeRef.current !== acctAtStart || !threadViewRef.current.openCurrent(openSeq)) return; // b77t (M-E); b77u (RH-I2)
    setChatLocalNick(localNick);
    setDraft('');
    setThreadReady(!!(await app.sessions.load(token))?.ready);
    // web parity: 'New chat thread with the same person' only for PINNED peers
    // Batch G (round-5 review R5-1-04): "+" and the contact badge only when this phone
    // sealed the chat as being with that contact under the pinned key
    const pinForChat = peerVeilId ? await app.pins.getPin(peerVeilId) : null;
    const canNewThread = !!(peerVeilId && pinForChat && sealedPeerMatches(sealedInfo, peerVeilId, pinForChat.ikPubB64));
    // b74 BURN-COUNTDOWN FIX (owner report: countdown never renders on
    // native while web shows it): TWO bugs. (1) The window used the WRONG
    // dial — expireAfterSeconds is the "unopened messages expire" dial; the
    // burn-after-open window is defaultTtlSeconds (web's "Burn Nh after
    // opens"). (2) The flag came ONLY from the sealed state — a thread
    // created on the WEB side never wrote burn_after_open through the
    // native join path, so sealedInfo.burnAfterOpen was false/undefined and
    // the countdown silently never rendered. Now: sealed extras first, then
    // the relay record's dials (stashed by refreshSessions).
    const win = sealedInfo ? burnWindow(sealedInfo, sessionDialsRef.current[token]) : { burn: false, secs: 0 }; // Batch E (R1-01); Batch G (R5-1-02)
    const burnOn = win.burn;
    const burnSecs = win.secs;
    // b163 (web P1.2 parity): key change revokes prior confirmation — if the
    // peer's CURRENT published identity key no longer matches the pinned one,
    // this thread's ceremony flags are treated as revoked and the gate
    // re-engages. Lookup failures never brick the thread (skip the check).
    let myV = myVerified;
    if ((sessionContactRef.current[token] ?? false) && peerVeilId) {
      try {
        const pin = await app.pins.getPin(peerVeilId);
        if (pin) {
          // audit VAR-11: no signed-in lookup naming this contact at chat open. The check reads the last
          // background pass over ALL pinned contacts (keySweep, src/key-change-sweep.ts), which runs on its
          // own jittered schedule. b77q owner (1 Nov): plus one ANONYMOUS lookup of this contact now (below),
          // at most once per contact per 10 minutes and never awaited, so a key change shows at once (b64 did
          // this, signed in); the relay can line that lookup up with the chat open again (spec §8.2 #59)
          {
            // b75 (audit RT-8): the lookup is only what the relay says, and this chat's keys come
            // from the handshake, not from the lookup. A reported key change is shown to the
            // user, who decides; the relay's word alone no longer clears the chat's check.
            // (Bad or expired prekey signatures are the relay's problem, not a key change: logged.)
            const showKeyChange = (): void => {
              if (keyChangeAlertedRef.current.has(token)) return;
              keyChangeAlertedRef.current.add(token);
              const revoke = () => {
                revokedTokensRef.current.add(token); // Batch G (R5-1-05): sticks across list refreshes
                persistRevocation(app.sessions, token, 0, () => { void syncInboundVerified(app.relay, app.sessions, token); }); // Batch H (R6-1-05): and across restarts; Batch I (V-03): checked + retried; b77: and the inbound's flag
                sessionVerifiedRef.current[token] = false;
                setChat((c) => (c && c.token === token ? { ...c, myVerified: false } : c));
                console.log(`[veil] pin identity mismatch on ${token.slice(0, 6)}… — ceremony confirmation removed by the user`); // b70 (re-review 9): never the full token
              };
              // b77t (audit 5 M-F / IH C-01): the safe answer is the default — anything but an explicit
              // "Keep as checked" (a tap outside the card, Back) marks the chat not checked.
              // (L-20 / DEV-4): in-window, as it names the contact
              // b77t2 (CM-2): tagged with this chat's account. A lock or account switch before the answer withdraws
              // it: nothing is revoked on a dialog the user never saw (it is asked again at this chat's next open,
              // which is after the next unlock of this same account); only an answer other than "Keep" revokes
              let withheld = false;
              void askFor(app, {
                title: 'Security key changed?',
                message: `The server says ${title} now has a different security key. This chat still uses the keys you checked, so nothing in it has changed. If they reinstalled Vardum or got a new phone, start a new chat with them and compare safety codes again. The server could also be wrong.`,
                confirm: true, submitLabel: 'Keep as checked', cancelLabel: 'Mark not checked',
              }, { onWithheld: () => { withheld = true; keyChangeAlertedRef.current.delete(token); keyChangeRetryRef.current.set(token, showKeyChange); } }).then((keep) => { if (keep !== true && !withheld) revoke(); });
            };
            // b77u (audit 6 R4 #30): a bundle that did not check out is shown in the chat (once per open), never silent
            const { onThread: keyOnThread, setThreadMessages: keyNote } = threadGuard(token, app);
            const showUnverifiable = (): void => {
              if (!keyOnThread() || lockedRef.current) return;
              const id = `keyunverifiable_${token}`;
              keyNote((prev) => (prev.some((m) => m.id === id) ? prev : [...prev, { id, text: '', mine: false, ts: new Date().toISOString(), systemNote: KEY_UNVERIFIABLE_NOTE }]));
            };
            if (keySweepRef.current.changed(peerVeilId)) showKeyChange();
            else if (keySweepRef.current.unverifiable(peerVeilId)) showUnverifiable();
            // b77q owner (1 Nov): the fresh check — only a definite 'changed' warns ('unknown' / an error / throttled
            // never does), and only while this chat is still the one open, unlocked, outside decoy mode
            const openedPeer = peerVeilId;
            void keySweepRef.current.checkOnOpen(openedPeer, keyCheckRef.current).then((r) => {
              if (r === 'changed' && keyOnThread() && !lockedRef.current && activeAppRef.current === app) showKeyChange(); // b77t2 (decoy gaps): the decoy's own contacts too — only this chat's account counts
              else if (r === 'unverifiable') showUnverifiable();
            }).catch(() => undefined);
          }
        }
      } catch { /* store hiccup: keep existing flags */ }
    }
    // b95/b163 (owner decisions Sept 21 + Oct 2): show the verify card ONCE
    // per unverified pairwise thread — contact threads included now that the
    // ceremony is the gate. Groups surface epoch fingerprints in their sheet.
    let vcard = false;
    if (!myV && !groupToken && status === 'active') {
      try {
        const raw = await app.storage.get('veil_vcard_dismissed');
        const dis = raw ? (JSON.parse(raw) as string[]) : [];
        vcard = !dis.includes(token);
      } catch { vcard = true; }
    }
    setVerifyCard(vcard);
    // b126: fingerprint + pin state travel with the open chat so the
    // verification panel can show them (fingerprint now viewable post-verify).
    const peerPinned = !!(peerVeilId && pinForChat && sealedPeerMatches(sealedInfo, peerVeilId, pinForChat.ikPubB64));
    const unavailableO = !groupToken && unavailableChatsRef.current.has(token); // b77m merge (VAR-07): read-only
    const endedByPeerO = unavailableO && await chatEndedByPeer(app.sessions, token); // b77m review (L9)
    if (decoyModeRef.current !== acctAtStart || !threadViewRef.current.openCurrent(openSeq)) return; // b77t (M-E); b77u (RH-I2)
    setChat({ token, title, subtitle, status: unavailableO ? 'ended' : status, peerVeilId, canNewThread, myVerified: myV, fingerprint: sealedInfo?.fingerprint ?? null, peerPinned, contact: sessionContactRef.current[token] ?? false, request: !!hbRowsRef.current.find((r) => r.token === token)?.request && !acceptedRequestsRef.current.has(token), // b71 (audit)
      ...(unavailableO ? { unavailable: true } : {}),
      ...(endedByPeerO ? { endedByPeer: true } : {}),
      ...(groupToken ? { groupToken } : {}),
      ...(burnOn ? { burnAfterOpen: true, burnSeconds: burnSecs || 86400 } : {}) });
    setScreen('chat');
    if (groupToken) {
      groupKnownTokensRef.current[token] = groupToken;
      const rec = groupRecord(app.storage, groupToken);
      setGroupInfo(rec ? { groupToken, isCreator: rec.role === 'creator', epoch: rec.epoch, fingerprint: null, members: [] } : null);
      syncGroupToken(token);
    } else {
      setGroupInfo(null);
      syncToken(token);
    }
    const who = await clientId();
    // b197-r6 (lag fix): activate used to fire on EVERY openChat — including
    // repeat opens of the same thread and the supersede auto-switch — each a
    // relay round trip that mostly returned 404/role rejections (owner log:
    // continuous activate spam while the limiter was hot). Once per token per
    // run is enough: activation is idempotent server-side.
    // b77 (sealed sender): 1:1 chats never name their token to the relay again — groups only
    if (who && groupToken && status === 'active' && !activatedOnceRef.current.has(token)) {
      activatedOnceRef.current.add(token);
      await app.relay.sessionActivate(token, (await app.sessions.load(token))?.writeSecret ?? null).catch(() => undefined);
    }
  }, [app, syncToken, syncGroupToken]);

  // b164: mirror so earlier-in-file callbacks (handleMessage, the b88
  // supersession switch) always run the CURRENT openChat closure.
  useEffect(() => { openChatRef.current = openChat; }, [openChat]);

  const handleOpenSession = useCallback(async (token: string) => {
    if (!app) return;
    const row = sessionRows.find((r) => r.token === token);
    await openChat(token, row?.title ?? 'Session', row?.subtitle ?? '', row?.status ?? 'pending', row?.peerVeilId ?? null, !!row?.myVerified, row?.groupToken);
  }, [app, sessionRows, openChat]);

  // live poll: sync the open pane every 3s until ended/back
  useEffect(() => {
    // b77t (audit 5 M-E): the REAL account's push only. A decoy session never re-runs this (the hook stays the
    // real one, held by the decoy gate until the real unlock), so the phone's push address never reaches the
    // decoy account
    const app = realApp;
    const identity = realIdentity;
    if (!identity || !app) return;
    // contentless pings — b77p round 2 (owner decision 1): the push address is kept on this phone only (its wake boxes
    // carry it); no account push row is made, and one an earlier build made is retired
    // b75 (audit DEV-L3): through the decoy gate, which holds it while decoy mode is up and
    // runs it again at the real unlock (only while an identity is still loaded)
    registerPushHook = async () => {
      if (!identityRef.current) return false;
      if (decoyModeRef.current) return false; // b77t (audit 5 M-E): never in a decoy session
      // b75 round 2 (audit D6): bound to the wipe generation. After a wipe no step of this
      // registration reaches the relay or the store, a row it created meanwhile is dropped
      // again, and the unregister-pending marker stays (it is removed only when no wipe
      // happened since the registration started)
      const gen = currentWipeGeneration();
      const live = () => currentWipeGeneration() === gen;
      const guard = <T,>(fn: () => Promise<T>): Promise<T> => (live() ? fn() : Promise.reject(new Error('push registration overtaken by a wipe')));
      try {
        const reg = Promise.resolve(registerPushToken({
          invoke: (fn, pl) => guard(() => app.relay.invoke(fn, pl)), // Batch H (R6-3-09): retire this phone’s older rows
          entityList: (e, p) => guard(() => app.relay.entityList(e, p)),
          entityDelete: (e, id) => guard(() => app.relay.entityDelete(e, id)), // b77p round 2: an earlier build's account row goes
          getCached: (k) => guard(() => app.storage.get(k)),
          setCached: (k, v) => guard(() => app.storage.set(k, v)),
          stillValid: live,
        }));
        void reg.then((ok) => { if (ok && live()) void app.storage.remove(PUSH_UNREG_PENDING_KEY); }).catch(() => undefined); // b75 (AL-7): push wanted again
        return await reg;
      } catch { return false; /* push registration must never crash the app */ }
    };
    void decoyPush.register();
    // b77p (audit 2 VAR-01): each open inbound seals this phone's push target into its own wake box (the device
    // library re-seals when the target changes). No account row lists mailboxes any more (b77's push_refs joined
    // every inbound mailbox to this account). b77t2 (CL-8): decided by WHOSE store the pass binds, not by the mode
    // at the moment it asks — only the real account's own SessionStore gets the target; any other store (a decoy
    // pass, even one in flight across the switch) gets 'off', which clears a binding it may already carry.
    const realSessionsId = unwrapPinned(app.sessions as object);
    // b77u (audit 6 W6): with this phone's wake key, so a stranger who knows the push token can't use up its wakes
    setWakeTargetProvider(async (store) => (store === realSessionsId ? await withWakeKey(await currentWakeTarget((k) => app.storage.get(k)), pinToWipe(app.storage) /* b77u merge (W6): a pass in flight across a wipe writes no key after it */) : 'off'));
    return () => { registerPushHook = null; setWakeTargetProvider(null); };
  }, [realIdentity, realApp]);

  // keep refs for the foreground/push re-poll hooks
  // b84: stamp the moment a thread is (re)opened so the syncToken banner gate
  // can suppress the banner during the unlock-resume race window.
  // audit VAR-02: the ref names the chat ON SCREEN only (the chat screen showing). A chat left by any
  // route (the add-contact link went to Contacts without closing it) used to stay in this ref, and
  // handleMessage then ended and deleted it as "the thread the user pressed in"
  const chatShown = chatOnScreen(screen, chat);
  if (chatShown?.token && chatRef.current?.token !== chatShown.token) {
    chatOpenedAtRef.current = Date.now();
  }
  chatRef.current = chatShown;
  syncTokenRef.current = syncToken;
  backgroundSyncAllSessionsRef.current = backgroundSyncAllSessions;
  // b199 CALL SIGNAL POLL (owner report: when one side hangs up the other
  // stays on the call, shows "Minor interference detected", sometimes
  // forever). backgroundSyncAllSessions pauses EVERY session during a call
  // (b196 rate budget) on the assumption the call's own thread is open and
  // its 1.5s foreground poll carries the signals. A callee who answers from
  // the list or another thread has no such poll: the caller's ICE and END
  // signals sit on the relay unread. This polls the call's own session at the
  // thread cadence for as long as the call lives; backgroundSyncToken skips
  // itself when that thread is open, so it never doubles the foreground poll.
  const backgroundSyncTokenRef = useRef(backgroundSyncToken);
  backgroundSyncTokenRef.current = backgroundSyncToken;
  // Call quality (20 Oct 2026, owner test: ~5 s from Accept to audio): while a
  // call is being set up (offer, answer, candidates) the poll runs at
  // CALL_SETUP_POLL_MS, then drops back to the thread cadence once 'active'.
  useEffect(() => {
    let iv: ReturnType<typeof setInterval> | null = null;
    let current: string | null = null;
    const unsub = CallManager.subscribe((s) => {
      const live = s && s.phase !== 'ended' ? s.token : null;
      const ms = s?.phase === 'active' ? 1500 : CALL_SETUP_POLL_MS;
      const key = live ? `${live}:${ms}` : null;
      if (key === current) return;
      if (iv) { clearInterval(iv); iv = null; }
      current = key;
      if (!live) return;
      const label = s?.peerLabel;
      console.log(`[veil-call] call poll on for ${live.slice(0, 6)}… (phase ${s?.phase}, every ${ms} ms)`);
      iv = setInterval(() => { backgroundSyncTokenRef.current(live, label).catch(() => undefined); }, ms);
    });
    return () => { unsub(); if (iv) clearInterval(iv); };
  }, []);
  // Pixel test Oct 20: with the phone-wide microphone switch off, Android
  // puts up its own "Unblock microphone?" screen the moment a call's mic
  // starts. That backgrounds Vardum and the app locked mid-call. The screen
  // only appears right after a call changes phase, so a short window then is
  // treated like any other system prompt Vardum opened (see withSystemSheet).
  useEffect(() => {
    if (Platform.OS !== 'android') return;
    let last: string | null = null;
    return CallManager.subscribe((s) => {
      const p = s?.phase ?? null;
      // b70 (re-review 12): never under Nothing-at-Rest (every departure must wipe there),
      // and only 8 s otherwise (the window let a quick power-button press skip the lock)
      if (p !== last && (p === 'calling' || p === 'connecting' || p === 'active') && settingsRef.current.storageMode !== 'memory') expectSystemSheet(8_000);
      last = p;
    });
  }, []);
  // b198: the routers (push + foreground-resume) need the GROUP-aware sync —
  // running the pairwise syncChat against a group session fetched its group
  // envelopes and decrypt-failed them into a false desync banner.
  const syncRouterRef = useRef<(token: string) => void>((t) => { syncTokenRef.current(t); });
  syncRouterRef.current = (token: string) => {
    if (chatRef.current?.groupToken) syncGroupToken(chatRef.current.token);
    else syncTokenRef.current(token);
  };

  // ONE poll loop per open thread — covers BOTH jobs (accept detection via
  // advanceHandshake and envelope fetch via syncChat; syncToken already
  // branches on readiness internally). Previously this was two separate
  // intervals (3s + 1.5s) calling the identical logic; since 3000 is a
  // multiple of 1500 they routinely fired together and BOTH decrypted the
  // same new envelope before either call's ratchet-state save landed —
  // that double-decrypt is exactly the "everything arrives twice" bug. The
  // syncInFlightRef mutex above is the backstop against any remaining
  // overlap (foreground/push triggers can still coincide with a tick).
  useEffect(() => {
    if (screen !== 'chat' || !chat) return;
    // b70 (re-review 11): the open thread pauses while the phone is locked (it kept
    // decrypting and sending READ receipts with nobody looking); it resumes on unlock
    if (chat.groupToken) {
      // b77t (audit 5 M-G): jittered like the 1:1 tick
      let gt: ReturnType<typeof setTimeout> | undefined;
      let gStopped = false;
      const gTick = () => { gt = setTimeout(() => { if (gStopped) return; if (!lockedRef.current) syncGroupToken(chat.token); gTick(); }, jitteredPollMs(3000)); };
      gTick();
      return () => { gStopped = true; if (gt !== undefined) clearTimeout(gt); };
    }
    // b77t (audit 5 M-G): a CSPRNG-jittered tick (it was a fixed 1500 / 3000 ms)
    let t: ReturnType<typeof setTimeout> | undefined;
    let stopped = false;
    const tick = () => { t = setTimeout(() => { if (stopped) return; if (!lockedRef.current) syncToken(chat.token); tick(); }, jitteredPollMs(threadReady ? 1500 : 3000)); };
    tick();
    return () => { stopped = true; if (t !== undefined) clearTimeout(t); };
  }, [screen, chat, threadReady, syncToken, syncGroupToken]);

  // re-poll on app foreground (returning to the thread pulls immediately)
  useEffect(() => {
    const sub = AppState.addEventListener('change', (st) => {
      setAppActive(st === 'active'); // b75r3 (PR3-02)
      // b198: route through the group-aware sync router (a group thread must
      // never be pairwise-synced — see syncRouterRef).
      if (st === 'active' && chatRef.current) syncRouterRef.current(chatRef.current.token);
    });
    return () => sub.remove();
  }, []);

  // re-poll on contentless push (the ping carries no content by design)
  // b77 FIX: previously only re-synced the currently open thread — a push
  // caused by a message on ANY OTHER session did nothing but refresh
  // metadata, so it was never decrypted and never triggered a local banner.
  // Now every non-open session gets checked too.
  useEffect(() => {
    const sub = Notifications.addNotificationReceivedListener(() => {
      // b199 (owner report: an incoming call showed a burst of "Incoming call"
      // banners inside the open app and only rang ~7s later): the b196 idle
      // backoff (up to 60s) also gated push-triggered syncs, so the ping that
      // says "something new is waiting" was ignored until the backoff ran out.
      // A push is exactly the evidence the backoff waits for — clear it.
      pollBackoffRef.current = {};
      // b198: group-aware router (pairwise-syncing the group session here caused the false desync banner).
      // b77p round 2 (owner decision 1): only 1:1 mailbox wakes push now (no contact-request or group-post pushes) —
      // so this one wake is also when contact requests (refreshSessions) and group posts (the full background sync)
      // are found, besides the foreground poll.
      if (chatRef.current) syncRouterRef.current(chatRef.current.token);
      refreshSessions();
      backgroundSyncAllSessionsRef.current();
    });
    return () => sub.remove();
  }, [refreshSessions]);

  /**
   * Media receive path (web loader parity): vaultFileSignedUrl → fetch →
   * AES-GCM decrypt with the payload's key/iv → in-memory data: URI for the
   * RN Image. Resolved once per message per open; never written to disk.
   */
  const resolveMedia = useCallback(async (token: string, msgId: string, media: NonNullable<ChatMessage['media']>, mine?: boolean) => {
    if (mediaInFlight.current[msgId]) return;
    const already = mediaLoad[msgId];
    // b73 FIX (owner report "voice notes viewable but not playable on
    // receive"): audio/video NEED the cache file to play (expo-av refuses
    // data: URIs on iOS — silently, no error, no crash, just a dead ▶). The
    // old guard treated the dataUri fallback as "resolved" forever, so a
    // single cache-write hiccup on the receive path left the note stuck in
    // an unplayable state with no retry. Now: images are done once `uri` is
    // set; audio/video are only done once the actual playable `fileUri` is set.
    const isAv = (media.mime || '').startsWith('audio/') || (media.mime || '').startsWith('video/');
    if (isAv ? already?.fileUri : already?.uri) return;
    if (!app) return;
    // b77u (audit 6 U-M1 / R1 F-01): this load's ticket — the media generation (the lock, leaving the chat, the
    // Nothing-at-Rest drop), plus the thread, the account and the wipe generation. Checked after every await;
    // a load that outlived a cleanup shows nothing and leaves no file
    const work = mediaWorkRef.current.begin();
    const { onThread } = threadGuard(token, app);
    const live = (): boolean => mediaWorkRef.current.current(work, onThread);
    // b77t (audit 5 L-18): the same blob in another message: share its result, or wait while it loads
    const blob = `${token}|${mediaBlobKey(media)}`;
    const ownerId = mediaBlobOwner.current.get(blob);
    if (ownerId && ownerId !== msgId) {
      const owner = mediaLoad[ownerId];
      if (mediaInFlight.current[ownerId]) return; // the effect comes back when it is done
      if (owner && (isAv ? owner.fileUri : owner.uri)) {
        // b77t2 (media dedupe): only while the owner's decrypted file is still there — a burn or a Nothing-at-rest
        // wipe deletes it, and this message then loads its own copy instead of keeping a dead file
        const fileOk = !owner.fileUri || await FileSystem.getInfoAsync(owner.fileUri).then((i) => i.exists).catch(() => false);
        if (!live()) return; // b77u (U-M1)
        if (fileOk) {
          setMediaLoad((prev) => ({ ...prev, [msgId]: { loading: false, uri: owner.uri, fileUri: owner.fileUri } }));
          return;
        }
      }
      if (owner?.error === MEDIA_GONE) { setMediaLoad((prev) => ({ ...prev, [msgId]: { loading: false, error: MEDIA_GONE } })); return; }
    }
    mediaBlobOwner.current.set(blob, msgId);
    mediaInFlight.current[msgId] = true;
    setMediaLoad((prev) => ({ ...prev, [msgId]: { loading: true } }));
    try {
      // b77u (audit 6 U-M9 / IH W7): a group seat's file goes through the group path (it has no 1:1 mailboxes)
      const isGroupSeat = chatRef.current?.token === token && !!chatRef.current?.groupToken;
      const bytes = await loadMediaFile(app.relay, app.sessions, token, media, mine, { group: isGroupSeat }); // b77f (ZTE77-2): the known direction picks the one mailbox (no 403 probe of the other)
      if (!live()) return; // b77u (U-M1): a cleanup ran during the download: nothing shown, nothing written
      const mime = media.mime || 'application/octet-stream';
      const dataUri = `data:${mime};base64,${toB64(bytes)}`;
      // b62: expo-av can't play data: URIs — video/voice notes also get a
      // decrypted cache file (deleted with the app's cache, never synced).
      // b73: retry the write once (transient FS errors) and surface a real
      // error state (with retry) instead of silently degrading to the
      // unplayable data: URI when it still fails.
      let fileUri: string | null = null;
      if (isAv) {
        const ext = mime === 'audio/mp4' ? 'm4a' : (mime.split('/')[1]?.split(';')[0] || 'bin');
        const target = await tmpPath(`veil-av-${msgId}.${ext}`); // b70 (VAR-03): temp folder, purged on lock
        if (!live()) return; // b77u (U-M1)
        const b64 = toB64(bytes);
        const removeTarget = () => FileSystem.deleteAsync(target, { idempotent: true });
        for (let attempt = 0; attempt < 2 && !fileUri; attempt++) {
          try {
            // b77u (U-M1): written only while the ticket holds, and deleted again if a cleanup came during the write
            const wrote = await mediaWorkRef.current.writeIfCurrent(work, () => FileSystem.writeAsStringAsync(target, b64, { encoding: FileSystem.EncodingType.Base64 }), removeTarget, onThread);
            if (!wrote) return;
            const info = await FileSystem.getInfoAsync(target);
            if (!live()) { await removeTarget().catch(() => undefined); return; } // b77u (U-M1)
            if (info.exists && info.size > 0) fileUri = target;
            else throw new Error('cache file wrote empty/missing');
            if (settingsRef.current.storageMode === 'memory') narTempMediaRef.current.note(target, msgId); // b77k2 (review L-4)
          } catch (e) {
            console.log(`[veil-av] cache file write attempt ${attempt + 1}/2 failed:`, String(e));
          }
        }
        if (!live()) { await removeTarget().catch(() => undefined); return; } // b77u (U-M1)
        if (!fileUri) {
          setMediaLoad((prev) => ({ ...prev, [msgId]: { loading: false, error: 'Voice/video note failed to cache for playback — tap to retry' } }));
          return;
        }
      }
      setMediaLoad((prev) => ({ ...prev, [msgId]: { loading: false, uri: dataUri, fileUri: fileUri ?? undefined } }));
    } catch (e) {
      if (!live()) return; // b77u (U-M1): a void load reports nothing either
      const why = String((e as Error).message || e);
      // b199: a 404 means the relay deleted the file (burned/expired) — final, no retry
      const gone = /(404)/.test(why);
      if (gone) console.log(`[veil] media ${msgId} is gone from the relay (burned/expired)`);
      else console.error(`[veil] media ${msgId} failed to load: ${why}`);
      setMediaLoad((prev) => ({ ...prev, [msgId]: { loading: false, error: gone ? MEDIA_GONE : why } }));
    } finally {
      if (mediaWorkRef.current.current(work)) mediaInFlight.current[msgId] = false; // b77u (U-M1): a cleanup already reset the map
    }
  }, [app, mediaLoad]);

  // b77k2 (review L-4): under Nothing-at-Rest a decrypted voice/video file goes as soon as its chat is left
  const narTempMediaRef = useRef(new TempMediaTracker());
  useEffect(() => {
    if (screen !== 'chat' || !chat) return;
    return () => {
      mediaWorkRef.current.bump(); // b77u (audit 6 U-M1): leaving the chat voids its loads in flight
      mediaInFlight.current = {}; // b77u2 (UC info): a voided load never clears its own flag (A→B left it stuck for A)
      const tr = narTempMediaRef.current;
      if (!tr.size()) return;
      void tr.dropAll((uri) => FileSystem.deleteAsync(uri, { idempotent: true })).then((ids) => {
        if (ids.length) setMediaLoad((prev) => { const next = { ...prev }; for (const id of ids) delete next[id]; return next; });
      });
    };
  }, [screen, chat?.token]); // eslint-disable-line react-hooks/exhaustive-deps

  // auto-resolve media messages in the open thread
  // b77t (audit 5 L-18): lazily: only the newest MEDIA_AUTO_LOAD; older ones show "Tap to load media"
  useEffect(() => {
    if (screen !== 'chat' || !chat) return;
    const withMedia = chatMessages.filter((m) => m.media);
    for (const m of withMedia.slice(-MEDIA_AUTO_LOAD)) {
      if (!m.media) continue;
      if (m.media.localUri && m.mine && liveLocalUris.current.has(m.media.localUri)) continue; // sender has the plaintext already (b70: until the temp folder is purged)
      const st = mediaLoad[m.id];
      const isAv = (m.media.mime || '').startsWith('audio/') || (m.media.mime || '').startsWith('video/');
      const resolved = isAv ? st?.fileUri : st?.uri;
      if (resolved || st?.loading || st?.error) continue; // b73: error state waits for an explicit retry tap
      resolveMedia(chat.token, m.id, m.media, m.mine);
    }
  }, [screen, chat, chatMessages, mediaLoad, resolveMedia]);

  /**
   * b62 voice notes (site parity): tap the mic to record an encrypted voice
   * note — m4a (AAC) straight into the same E2EE media pipeline as photos.
   */
  // b77u2 phone test (5 Nov): taps while the recorder was starting each started another recording; the failures
  // reset the screen while the first 1-second timer kept running, so the next recording ran two timers (the counter
  // went twice as fast and the note's length came out too long). One start at a time, and any old timer is stopped.
  const voiceStartingRef = useRef(false);
  const handleVoiceRecord = useCallback(async () => {
    if (voiceRec.active || voiceStartingRef.current) return;
    voiceStartingRef.current = true;
    try {
      Keyboard.dismiss();
      if (voiceRecRef.current) { try { voiceRecRef.current.stopAndUnloadAsync(); } catch { /* stale */ } voiceRecRef.current = null; }
      const perm = await withSystemSheet(() => Audio.requestPermissionsAsync());
      if (!perm.granted) throw new Error('Microphone permission was not granted.');
      try { await Audio.setAudioModeAsync({ allowsRecordingIOS: true, playsInSilentModeIOS: true }); } catch { /* mode best-effort */ }
      let rec = new Audio.Recording();
      try {
        await rec.prepareToRecordAsync(Audio.RecordingOptionsPresets.HIGH_QUALITY);
      } catch (prepErr) {
        // b199 (owner hardware test Oct 16): the first mic use shows iOS's
        // permission prompt, which backgrounds the app for a moment — prepare
        // then fails "currently in the background". Wait until the app is
        // active again and try once more instead of showing an error.
        if (!/in the background/i.test(String(prepErr))) throw prepErr;
        for (let i = 0; i < 20 && AppState.currentState !== 'active'; i++) await new Promise((r) => setTimeout(r, 100));
        await new Promise((r) => setTimeout(r, 300));
        try { await rec.stopAndUnloadAsync(); } catch { /* never prepared */ }
        rec = new Audio.Recording();
        await rec.prepareToRecordAsync(Audio.RecordingOptionsPresets.HIGH_QUALITY);
      }
      if (Platform.OS === 'android' && settingsRef.current.storageMode !== 'memory') expectSystemSheet(8_000); // the same mic-unblock screen (see the call effect); b70 (re-review 12): not under Nothing-at-Rest
      await rec.startAsync();
      voiceRecRef.current = rec;
      if (voiceTickRef.current) clearInterval(voiceTickRef.current);
      // b77u2 phone test (5 Nov): the shown time is the real time since the start, not a count of ticks: a busy JS
      // thread (a large media decrypt on the ZTE took 23 s) held the ticks back and then ran them all at once
      const voiceStartedAt = Date.now();
      voiceTickRef.current = setInterval(() => setVoiceRec((r) => ({ ...r, seconds: Math.floor((Date.now() - voiceStartedAt) / 1000) })), 1000);
      setVoiceRec({ active: true, seconds: 0 });
      console.log('[veil-voice] recording started');
    } catch (e) {
      console.log('[veil-voice] record start failed:', String(e));
      setError(friendlyError(e, 'voice-start'));
      if (voiceTickRef.current) { clearInterval(voiceTickRef.current); voiceTickRef.current = null; }
      setVoiceRec({ active: false, seconds: 0 });
    } finally { voiceStartingRef.current = false; }
  }, [voiceRec.active]);

  const handleVoiceCancel = useCallback(() => {
    const rec = voiceRecRef.current;
    voiceRecRef.current = null;
    // b70 (re-review 5): the recording file goes too (it sat in the cache as plain audio)
    let recUri: string | null = null;
    try { recUri = rec?.getURI() ?? null; } catch { recUri = null; }
    void (async () => {
      try { await rec?.stopAndUnloadAsync(); } catch { /* already stopped */ }
      if (recUri) await FileSystem.deleteAsync(recUri, { idempotent: true }).catch(() => undefined);
    })();
    if (voiceTickRef.current) { clearInterval(voiceTickRef.current); voiceTickRef.current = null; }
    setVoiceRec({ active: false, seconds: 0 });
  }, []);
  handleVoiceCancelRef.current = handleVoiceCancel;

  const handleVoiceSend = useCallback(async () => {
    if (!voiceRec.active) return;
    let uri: string | null = null;
    let durationMs = 0;
    try {
      const rec = voiceRecRef.current;
      if (!rec) throw new Error('Recorder is not running.');
      // capture duration BEFORE stopping (status is invalid after unload)
      const status = await rec.getStatusAsync().catch(() => null);
      durationMs = (status as { durationMillis?: number } | null)?.durationMillis ?? 0;
      await rec.stopAndUnloadAsync();
      uri = rec.getURI() ?? null;
      voiceRecRef.current = null;
      if (voiceTickRef.current) { clearInterval(voiceTickRef.current); voiceTickRef.current = null; }
      setVoiceRec({ active: false, seconds: 0 });
      if (!uri) throw new Error('Recording produced no file — please try again.');
      const secs = Math.max(1, Math.round(durationMs / 1000), voiceRecStateSecondsRef.current);
      const name = `voice-note-${new Date().toISOString().slice(11, 19).replace(/:/g, '')}.m4a`;
      // file size checked at send time against the 25 MB cap (voice is far under)
      setPendingPick({ uri: await adoptIntoTmp(uri, name), name, mime: 'audio/mp4', size: 0, voiceSeconds: secs }); // b70 (VAR-03)
    } catch (e) {
      console.log('[veil-voice] send failed:', String(e));
      setError(friendlyError(e, 'voice-send'));
      if (uri) await FileSystem.deleteAsync(uri, { idempotent: true }).catch(() => undefined); // b70 (re-review 5)
      handleVoiceCancel();
    }
  }, [voiceRec.active]);

  const handleAttach = useCallback(async () => {
    // dismiss the composer keyboard before doing anything else — otherwise the
    // preview overlay (or the native picker itself) can render underneath/behind
    // it, cutting off the Cancel/Send buttons (build 26 bug: box stayed up and
    // obstructed the send button after typing then tapping attach).
    Keyboard.dismiss();
    try {
      // DIAGNOSTICS (build 25 hot-patch): log everything so Metro shows exactly
      // what the picker returns on this device; surface empty results on screen
      // instead of silently returning to chat.
      let perm: ImagePicker.PermissionResponse | undefined;
      try {
        perm = await ImagePicker.getMediaLibraryPermissionsAsync();
        console.log('[veil-media] photo permission:', JSON.stringify(perm));
      } catch { /* permission check is informational only */ }
      const res = await withSystemSheet(() => ImagePicker.launchImageLibraryAsync({
        // b62: images AND videos (site claims video; the send pipeline is
        // mime-generic E2EE bytes, so video needed only picker + render work)
        mediaTypes: ['images', 'videos'] as ImagePicker.MediaType[],
        quality: 0.8,
        allowsMultipleSelection: false,
        selectionLimit: 1,
        exif: false,
      }));
      const safe: unknown = JSON.parse(JSON.stringify(res, (k, v) => (k === 'base64' ? '[omitted]' : v)));
      console.log('[veil-media] picker result:', JSON.stringify(safe));
      if (res.canceled || !res.assets?.length) {
        // b110: keep raw diagnostics in the console log above (Metro-only);
        // the on-screen banner must never show internal state to the user.
        console.log('[veil-media] empty pick:', JSON.stringify({ canceled: res.canceled, assets: res.assets?.length ?? 0, permission: perm?.status ?? 'unknown' }));
        // b199 (owner hardware test Oct 16): closing the picker on purpose is
        // not an error — only a pick that came back empty gets the banner.
        if (!res.canceled) setError('No photo or video was selected — tap the attach button to try again.');
        return;
      }
      const a = res.assets[0];
      if (!a?.uri) {
        setError('The picker returned media with no file path — please try a different file.');
        return;
      }
      console.log('[veil-media] asset ok:', JSON.stringify({ uri: a.uri, name: a.fileName, mime: a.mimeType, size: a.fileSize }));
      Keyboard.dismiss();
      // b77t (audit 5 L-19 / IH DEV-3): a neutral name from the start (image.jpg, video.mp4); the picked
      // name (capture time, device, the app in a screenshot) is never kept or sent
      let pick: PendingPick = { uri: a.uri, name: neutralSendName(a.mimeType ?? 'image/jpeg', a.fileName), mime: a.mimeType ?? 'image/jpeg', size: a.fileSize ?? 0 };
      // b199 (owner hardware test Oct 16: photos "still lag a little"): a
      // 12 MP camera photo is ~2.5 MB that then gets read, encrypted,
      // uploaded, downloaded and decrypted. Shrink photos to a 2048 px long
      // edge first (plenty for a phone screen) — about 4-6x less to move.
      // b77s (audit 4 DV-4): and EVERY still image is re-encoded, whatever its size (JPEG/HEIC as
      // JPEG, PNG/WebP as PNG so transparency stays), which drops the camera metadata the picker
      // copies in (make, model, original time, image id). It used to run only for JPEG/HEIC over
      // 2048 px and was kept only when smaller. A failed re-encode is refused, never sent with its
      // metadata. GIFs and videos: see b77u W10 below (src/media-strip.ts).
      const plan = imageReencodePlan({ type: a.type, mime: pick.mime, width: a.width, height: a.height }, MEDIA_PHOTO_MAX_EDGE);
      if (plan) {
        // b77s (confirmation review): the output of a failed re-encode / strip is deleted too
        let outUri: string | null = null;
        try {
          const t0 = Date.now();
          if (plan.format === 'png-strip') {
            // b77s (confirmation review, stego regression): a PNG is never decoded or resized — its metadata chunks
            // are removed losslessly, the image data byte for byte, so a hidden (stego) message survives
            const stripped = stripPngMetadata(fromB64(await FileSystem.readAsStringAsync(a.uri, { encoding: FileSystem.EncodingType.Base64 })));
            outUri = await tmpPath(`${Date.now()}-strip.png`);
            await FileSystem.writeAsStringAsync(outUri, toB64(stripped), { encoding: FileSystem.EncodingType.Base64 });
            pick = { uri: outUri, name: reencodedName(pick.name, plan.ext), mime: plan.mime, size: stripped.length };
            console.log(`[veil-media] PNG metadata stripped losslessly ${a.fileSize ?? '?'}B -> ${stripped.length}B in ${Date.now() - t0} ms`);
          } else {
            // eslint-disable-next-line @typescript-eslint/no-var-requires
            const IM = require('expo-image-manipulator') as typeof import('expo-image-manipulator');
            const out = await IM.manipulateAsync(
              a.uri,
              plan.resize ? [{ resize: plan.resize }] : [],
              plan.format === 'png' ? { format: IM.SaveFormat.PNG, compress: 1 } : { format: IM.SaveFormat.JPEG, compress: 0.8 },
            );
            outUri = out.uri;
            const info = await FileSystem.getInfoAsync(out.uri);
            const size = info.exists ? (info as { size?: number }).size ?? 0 : 0;
            if (!(size > 0)) throw new Error('empty re-encode');
            pick = { uri: out.uri, name: reencodedName(pick.name, plan.ext), mime: plan.mime, size };
            console.log(`[veil-media] image re-encoded (metadata stripped) ${a.width}x${a.height} ${a.fileSize ?? '?'}B -> ${out.width}x${out.height} ${size}B in ${Date.now() - t0} ms`);
          }
        } catch (e) {
          console.log('[veil-media] re-encode failed, not sending:', String(e));
          if (outUri && outUri !== a.uri) await deleteQuietly(outUri);
          await deleteQuietly(a.uri);
          setError(IMAGE_STRIP_FAILED);
          return;
        }
      }
      // b77u (audit 6 W10 / IH full L-9): videos and GIFs lose their metadata too (src/media-strip.ts): GIF blocks
      // removed losslessly, MP4/MOV/3GP metadata boxes blanked in place and their times zeroed. A video that can't be
      // cleaned (another format, or a file this phone can't parse) is sent only after a plain warning
      const motion = plan ? null : motionStripPlan(pick.mime, a.type);
      if (motion) {
        let outUri: string | null = null;
        let warn = motion === 'video-warn';
        if (!warn) {
          try {
            const raw = fromB64(await FileSystem.readAsStringAsync(a.uri, { encoding: FileSystem.EncodingType.Base64 }));
            const clean = motion === 'gif-strip' ? stripGifMetadata(raw) : neutralizeVideoMetadata(raw);
            outUri = await tmpPath(`${Date.now()}-strip.${motion === 'gif-strip' ? 'gif' : (pick.name.split('.').pop() || 'mp4')}`);
            await FileSystem.writeAsStringAsync(outUri, toB64(clean), { encoding: FileSystem.EncodingType.Base64 });
            pick = { ...pick, uri: outUri, size: clean.length };
            console.log(`[veil-media] ${motion === 'gif-strip' ? 'GIF' : 'video'} metadata removed (${raw.length}B -> ${clean.length}B)`);
            // b77u2 (UC info): a timed-metadata track (GoPro GPS, camera motion, Apple mebx) keeps its samples in the media
            // data, which the strip never changes: the cleaned copy is sent only after the same warning
            if (motion === 'video-strip' && hasTimedMetadataTrack(clean)) { console.log('[veil-media] video has a timed-metadata track — asking first'); warn = true; }
          } catch (e) {
            console.log('[veil-media] metadata strip failed:', String(e));
            if (outUri) await deleteQuietly(outUri);
            if (motion === 'gif-strip') { await deleteQuietly(a.uri); setError(IMAGE_STRIP_FAILED); return; }
            warn = true;
          }
        }
        if (warn) {
          const ok = await askFor(activeAppRef.current, { title: 'Video details', message: VIDEO_META_WARNING, confirm: true, cancelLabel: 'Don’t send', submitLabel: 'Send anyway' });
          if (ok !== true) { await deleteQuietly(a.uri); return; }
        }
      }
      if (pick.uri !== a.uri) await deleteQuietly(a.uri); // b70 (VAR-03): the full-size picker copy
      setPendingPick({ ...pick, uri: await adoptIntoTmp(pick.uri, pick.name) }); // b70 (VAR-03)
      console.log('[veil-media] pendingPick SET — preview modal should now be visible');
    } catch (e) {
      const msg = `${(e as Error).message ?? e}`;
      console.log('[veil-media] picker error:', msg);
      setError(friendlyError(e, 'photo-picker'));
    }
  }, []);

  const handleCancelPick = useCallback(() => { setPendingPick((p) => { if (p) void deleteQuietly(p.uri); return null; }); }, []);

  /**
   * Save-to-Photos (web download parity, gated on the sender's dl flag):
   * the already-decrypted in-memory bytes go to a temp cache file, then
   * MediaLibrary adds it to Photos (full access, b92 F14: so a wipe can delete it); the temp copy
   * is deleted immediately after. Plaintext never persists in-app.
   */
  const handleMediaSave = useCallback(async (msgId: string) => {
    const entry = mediaLoad[msgId];
    const orig = chatMessages.find((m) => m.id === msgId);
    const dataUri = entry?.uri;
    if (!dataUri?.startsWith('data:') || !orig?.media) return;
    setMediaSaving((prev) => ({ ...prev, [msgId]: 'saving' }));
    let tmp: string | null = null;
    try {
      // audit VAR-39 (1f51): the sender's MIME type never picks the saved file's type — image, video
      // and audio types only, each with its own fixed extension; anything else is not saved
      const saveAs = mediaSaveType(orig.media.mime || 'image/jpeg');
      if (!saveAs) throw new Error('This file type can’t be saved.');
      const { mime, ext } = saveAs;
      const b64 = dataUri.slice(dataUri.indexOf(',') + 1);
      if (usesFolderPicker()) {
        // b69 Android: "Save to…" through the system folder picker; no
        // gallery permission. Cancelling the picker leaves the button as it was.
        const saved = await withSystemSheet(() => saveToChosenFolder(b64, neutralSaveName(mime, ext), mime) /* b77s (audit 4 DV-5): a camera-style name */);
        await trackSavedMedia(app?.storage, saved); // b70 (re-review 4): every wipe deletes it too
        setMediaSaving((prev) => {
          if (saved) return { ...prev, [msgId]: 'saved' };
          const next = { ...prev }; delete next[msgId]; return next;
        });
        return;
      }
      // b92 F14 (b91 audit): full Photos access (NOT write-only) so the
      // duress purge can delete what the app saves — write-only saves
      // survived a duress wipe.
      // b77t (audit 5 L-21 / IH V-13, owner decision 2 Nov "keep full access"): kept; the full-access prompt
      // (app.json photosPermission) now says why it is asked: so a wipe can delete the images Vardum saved
      const perm = await withSystemSheet(() => MediaLibrary.requestPermissionsAsync(false));
      if (!perm.granted) throw new Error('Photos permission was not granted.');
      tmp = `${FileSystem.cacheDirectory}${neutralSaveName(mime, ext)}`; // b77s (audit 4 DV-5): Photos keeps this name
      await FileSystem.writeAsStringAsync(tmp, b64, { encoding: FileSystem.EncodingType.Base64 });
      const asset = await MediaLibrary.createAssetAsync(tmp);
      await trackSavedMedia(app?.storage, asset?.id); // b70 (re-review 4): every wipe deletes it too
      setMediaSaving((prev) => ({ ...prev, [msgId]: 'saved' }));
    } catch (e) {
      console.error('[veil-media] save failed:', (e as Error).message ?? e);
      setMediaSaving((prev) => ({ ...prev, [msgId]: 'error' }));
    } finally {
      if (tmp) FileSystem.deleteAsync(tmp, { idempotent: true }).catch(() => undefined);
    }
  }, [mediaLoad, chatMessages, app]);

  const handleSendMedia = useCallback(async () => {
    if (!app || !chat || !pendingPick) return;
    // b77u (audit 6 U-M3): what this action adds to the view goes to its own thread only (a switch meanwhile drops it; the store has it)
    const { onThread, setThreadMessages } = threadGuard(chat.token, app);
    // b163: pairwise media sends are behind the ceremony gate too (text parity).
    if (!chat.groupToken && !chat.myVerified) return; // b71 (audit): the local seal, not the relay peer flag
    const who = await clientId();
    if (!who) return;
    setBusy(true); setError(null);
    try {
      if (chat.groupToken) {
        // M-3 (b69 audit): refuse before uploading anything when the group's keys need refreshing
        const keyRec = groupRecord(app.storage, chat.groupToken);
        if (keyRec) {
          try { assertGroupKeysFresh(keyRec); } catch (ge) { setError((ge as Error).message); return; }
        }
        const b64g = await FileSystem.readAsStringAsync(pendingPick.uri, { encoding: FileSystem.EncodingType.Base64 });
        const bytesG = fromB64(b64g);
        const sizeG = pendingPick.size || bytesG.byteLength;
        if (sizeG > MEDIA_LIMIT_BYTES) throw new Error('Media is limited to 25 MB per message.');
        const r = await sendGroupMediaMessage(
          { relay: app.relay, sessions: app.sessions, storage: app.storage, webBaseUrl: VEIL_LINK_URL },
          {
            groupToken: chat.groupToken, sessionToken: chat.token, clientId: who,
            media: { bytes: bytesG, name: pendingPick.name, mime: pendingPick.mime, size: sizeG, dl: allowDl },
            localUri: pendingPick.uri,
            uploadCiphertext: async (ct) => {
              const ctFile = `${FileSystem.cacheDirectory}veil-media-${Date.now()}.bin`;
              await FileSystem.writeAsStringAsync(ctFile, toB64(ct), { encoding: FileSystem.EncodingType.Base64 });
              try {
                // b77u (audit 6 U-M9): bound to the group on the relay (the seat token + write secret), so only the
                // group's members (and this account) can sign or delete it
                const seatWs = (await app.sessions.load(chat.token) as { writeSecret?: string | null } | null)?.writeSecret ?? null;
                return await app.relay.uploadPrivateFile({ uri: ctFile, name: 'veil-media', ...(seatWs ? { chat: { sessionToken: chat.token, writeSecret: seatWs } } : {}) });
              } finally {
                FileSystem.deleteAsync(ctFile, { idempotent: true }).catch(() => undefined);
              }
            },
          },
        );
        setThreadMessages((prev) => [...prev, { id: r.id, text: '', mine: true, ts: new Date().toISOString(), sender: 'You', media: { ...r.media, localUri: pendingPick.uri } }]); // b198: no send-time burn clock on own media — anchors at receipt
        liveLocalUris.current.add(pendingPick.uri); // b70 (VAR-03)
        setPendingPick(null);
        setError(null); // b180: success clears the banner
        syncGroupToken(chat.token);
        return;
      }
      const ready = await advanceHandshake(chat.token, who);
      if (!ready) throw new Error('Waiting for your contact to accept — messaging unlocks the moment they join.');
      const b64 = await FileSystem.readAsStringAsync(pendingPick.uri, { encoding: FileSystem.EncodingType.Base64 });
      const bytes = fromB64(b64);
      const size = pendingPick.size || bytes.byteLength;
      if (size > MEDIA_LIMIT_BYTES) throw new Error('Media is limited to 25 MB per message.');
      // RN networking: upload the CIPHERTEXT as a cache-file FormData part (the
      // guaranteed file:// path) — encryption happens inside sendMediaMessage
      const msg = await sendMediaMessage(
        app.relay, app.sessions, chat.token, who,
        { bytes, name: pendingPick.name, mime: pendingPick.mime, size, dl: allowDl },
        pendingPick.uri, // instant local preview, never transmitted
        undefined, // web contract: per-envelope TTL 3600 (live bundle send path)
        async (ct, target) => {
          const ctFile = `${FileSystem.cacheDirectory}veil-media-${Date.now()}.bin`;
          await FileSystem.writeAsStringAsync(ctFile, toB64(ct), { encoding: FileSystem.EncodingType.Base64 });
          try {
            // b77 (sealed sender): to the peer's inbound with the send cap — no owner, no account
            return await app.relay.sealedUpload({ uri: ctFile, name: 'veil-media', mbox: target.mbox, sendCap: target.sendCap });
          } finally {
            FileSystem.deleteAsync(ctFile, { idempotent: true }).catch(() => undefined);
          }
        },
      );
      void quietLedgerFor(app).touch(chat.token).catch(() => undefined); // b77u (audit 6 W8): a message sent
      setThreadMessages((prev) => [...prev, msg]);
      if (onThread()) setChatKnown((prev) => new Set([...prev, msg.id]));
      liveLocalUris.current.add(pendingPick.uri); // b70 (VAR-03)
      setPendingPick(null);
      setError(null); // b180: success clears the banner
      syncToken(chat.token);
    } catch (e) {
      setError(friendlyError(e, 'action'));
    } finally { setBusy(false); }
  }, [app, chat, pendingPick, syncToken, advanceHandshake, allowDl]);

  useEffect(() => {
    chatOpenRef.current = screen === 'chat' && chat ? chat.token : null;
    // b74: group threads need their own capture-notice path — the 1:1
    // advanceHandshake misreads group session rows (they never carry the
    // responder_* fields it looks for) and returns "not ready" even while
    // the group chat is actively exchanging messages.
    chatOpenGroupRef.current = screen === 'chat' && chat ? chat.groupToken ?? null : null;
  }, [screen, chat]);

  /**
   * b61→b70: screenshot / screen-recording watch. iOS cannot block a
   * screenshot — the ONLY real mitigation on the platform — so this fires the
   * instant one happens; if a conversation is open, VEIL sends the other party
   * an E2EE notice (the honest deterrent), regardless of dial state.
   */
  useEffect(() => {
    if (!app) return;
    let lastNoticeAt = 0;
    const stop = startScreenWatch((ev) => {
      const isShot = ev.kind === 'screenshot';
      if (!isShot && !(ev.kind === 'recording' && ev.captured === true)) return;
      const token = chatOpenRef.current;
      if (!token) { console.log('[veil-capture] event fired but no chat open — nothing to notify'); return; }
      if (lockedRef.current) { console.log('[veil-capture] skipped: app locked'); return; }
      // b77t2 (decoy gaps, owner "fix the cheap ones now"): the decoy session's own chats get the notice too, as in a
      // fresh account — `app` here is the account in use; only a stale subscription (another account) stays silent
      if (activeAppRef.current !== app) { return; }
      const now = Date.now();
      if (now - lastNoticeAt < 5000) return; // OS can burst-fire; one notice per 5 s
      lastNoticeAt = now;
      // b75r2 (audit P-1): a typed payload; each phone writes the words (ChatScreen), naming
      // who it was. Plain text starting with a warning sign is never drawn as a notice now.
      const text = buildCapturePayload(isShot ? 'screenshot' : 'recording');
      // b77u2 (UC-L6): the guard is taken now, before any send: the notice is drawn only in this chat, if still open
      const { onThread: capOnThread, setThreadMessages: setCapThread } = threadGuard(token, app);
      void (async () => {
        try {
          const who = await clientId();
          if (!who) { console.log('[veil-capture] notice skipped: no clientId'); return; }
          // b74 FIX (owner report: screenshot on a WORKING chat logged
          // "handshake not ready"): the old path only knew 1:1 sessions —
          // on a GROUP thread, advanceHandshake's slow path looks for
          // responder_* fields that group rows never carry, so it returned
          // false and silently skipped the notice on an actively-working
          // chat. Groups now go through the group send path (same dispatch
          // as handleSend); readiness rides the group ratchet itself.
          const groupToken = chatOpenGroupRef.current;
          if (groupToken) {
            await sendGroupMessage(
              { relay: app.relay, sessions: app.sessions, storage: app.storage, webBaseUrl: VEIL_LINK_URL },
              { groupToken, sessionToken: token, clientId: who, text },
            );
            const capMsg: (ChatMessage & { sender?: string; systemNote?: string }) = { id: `local_capture_${Date.now()}`, text, mine: true, ts: new Date().toISOString(), sender: 'You', openedAt: Date.now(), systemNote: undefined }; // b131: burn clock on capture notices
            setCapThread((prev) => [...prev, capMsg]); // b77u2 (UC-L6)
            app.sessions.cacheMessages(token, [capMsg]).catch(() => undefined); // b123: survives reopen
            console.log('[veil-capture] group notice sent (group', groupToken.slice(0, 8) + '…)');
            return;
          }
          const ready = await advanceHandshakeRef.current(token, who);
          if (!ready) { console.log('[veil-capture] notice skipped: handshake not ready (pending thread)'); return; }
          if (!sessionVerifiedRef.current[token]) { console.log('[veil-capture] notice skipped: safety codes not confirmed'); return; } // Batch G (R5-1-08)
          const msg = await sendChatControl(app.relay, app.sessions, token, who, text); // b77m review (L1): a control payload, sent as one
          setCapThread((prev) => [...prev, msg]); // b77u2 (UC-L6)
          if (capOnThread()) setChatKnown((prev) => new Set([...prev, msg.id]));
          console.log('[veil-capture] notice sent, envId:', msg.envId ?? '(none)');
        } catch (e) {
          // b73 (owner report: screenshot detected in Metro logs but the
          // peer notice never appeared): this catch used to be silent —
          // "best effort" hid the real failure. A desynced ratchet on this
          // thread throws right here on encrypt/send, same class as the
          // known "Message counter out of range" bug — now logged instead
          // of swallowed so the next repro tells us which it is.
          console.log('[veil-capture] notice FAILED to send:', String((e as Error).message ?? e));
        }
      })();
    });
    return () => { stop?.(); };
  }, [app]);

  // b199 REACTIONS (owner request, Oct 17): hold a message, tap an emoji.
  // Pairwise threads only for now (groups have no per-message ids the
  // other members share in this form). Tapping your current reaction
  // removes it. Optimistic: the bubble updates at once, the cache persists
  // it, and the encrypted reaction goes out; on failure the bubble reverts.
  const handleReact = useCallback(async (msgId: string, emoji: string) => {
    if (!app || !chat || chat.groupToken) return;
    // b77u (audit 6 U-M3): what this action adds to the view goes to its own thread only (a switch meanwhile drops it; the store has it)
    const { onThread, setThreadMessages } = threadGuard(chat.token, app);
    if (!chat.myVerified) return; // Batch F (R4-4-16): the safety-code gate
    const msg = chatMessages.find((m) => m.id === msgId);
    if (!msg) return;
    const target = msg.mid; // b74 (VAR-07): reactions name the header-derived message id
    if (!target) { console.log('[veil-react] skipped: this message has no message id'); return; }
    const prev = msg.reactions?.mine ?? null;
    const next = prev === emoji ? null : emoji;
    const token = chat.token;
    const apply = (e: string | null) => setThreadMessages((list) => list.map((m) => {
      if (m.id !== msgId) return m;
      const reactions = { ...(m.reactions ?? {}) };
      if (e) reactions.mine = e; else delete reactions.mine;
      return { ...m, reactions };
    }));
    apply(next);
    try {
      const who = await clientId();
      if (!who) throw new Error('not signed in');
      await sendReaction(app.relay, app.sessions, token, who, target, next);
      await app.sessions.setCachedReaction(token, msgId, 'mine', next).catch(() => undefined);
      console.log(`[veil-react] sent ${next ?? '(removed)'} on ${target.slice(0, 8)}…`);
    } catch (e) {
      console.log(`[veil-react] send failed: ${(e as Error)?.message ?? e}`);
      apply(prev);
    }
  }, [app, chat, chatMessages]);

  /** b199: apply the peer's reactions from a sync pass — live thread + cache */
  const applyPeerReactions = useCallback(async (token: string, list: { target: string; emoji: string | null }[] | undefined) => {
    if (!app || !list?.length) return;
    console.log(`[veil-react] peer reaction update(s): ${list.length}`);
    // b77u (audit 6 RH-L1, U-M3): pinned to this wipe generation; the view only if this thread is still on screen
    const { onThread, setThreadMessages } = threadGuard(token, app);
    const ss = pinToWipe(app.sessions);
    for (const r of list) await ss.setCachedReaction(token, r.target, 'peer', r.emoji, 'mid').catch(() => undefined);
    if (!onThread()) return;
    setThreadMessages((msgs) => msgs.map((m) => {
      const hits = list.filter((r) => !!m.mid && r.target === m.mid); // b74 (VAR-07)
      if (!hits.length) return m;
      const e = hits[hits.length - 1].emoji;
      const reactions = { ...(m.reactions ?? {}) };
      if (e) reactions.peer = e; else delete reactions.peer;
      return { ...m, reactions };
    }));
  }, [app]);
  applyPeerReactionsRef.current = applyPeerReactions;

  const handleSend = useCallback(async () => {
    if (!app || !chat || !draft.trim()) return;
    // b77u (audit 6 U-M3): what this action adds to the view goes to its own thread only (a switch meanwhile drops it; the store has it)
    const { onThread, setThreadMessages } = threadGuard(chat.token, app);
    // b77t (audit 5 M-E): in a decoy session the open chat is the decoy's and sends on its own account (`app`);
    // a real chat is never open there (the switch closes it; openChat drops one that began under the other account)
    // b163 (web P1.2 parity): the composer lock is UX — this is the enforced
    // gate on every pairwise user-content send path. Groups are exempt.
    if (!chat.groupToken && !chat.myVerified) return;
    const who = await clientId();
    if (!who) return;
    setBusy(true);
    // b180 (owner report: "server is briefly busy" banner never clears
    // until you exit the thread): clear any stale error from a previous
    // failed send BEFORE the new attempt — a banner that outlives its
    // cause is a lie on screen.
    setError(null);
    try {
      if (chat.groupToken) {
        try {
          await sendGroupMessage(
            { relay: app.relay, sessions: app.sessions, storage: app.storage, webBaseUrl: VEIL_LINK_URL },
            { groupToken: chat.groupToken, sessionToken: chat.token, clientId: who, text: userText(draft.trim()) }, // Batch E (F-14)
          );
        } catch (ge) {
          // M-3 (b69 audit): the group's keys need refreshing — say so (draft kept), not "Something went wrong"
          // b77k (IP77-2): and not admitted yet / a removal waiting for its rotation, the same way
          if ((ge as Error)?.name === 'GroupKeysStaleError' || (ge as Error)?.name === 'GroupSendBlockedError') { setError((ge as Error).message); return; }
          throw ge;
        }
        const now = new Date().toISOString();
        const mineMsg: (ChatMessage & { sender?: string }) = { id: `local_${Date.now()}`, text: draft.trim(), mine: true, ts: now, sender: 'You' }; // b198: own group sends get no send-time burn clock — anchors at receipt
        setThreadMessages((prev) => [...prev, mineMsg]);
        // b123: my own group sends now land in the history cache too (b62
        // gap — reopen previously dropped MY side of group threads) and the
        // own-echo path above binds envId onto this cached copy.
        app.sessions.cacheMessages(chat.token, [mineMsg]).catch(() => undefined);
        setDraft('');
        setError(null); // b180: success clears the banner, not just back-nav
        syncGroupToken(chat.token);
        return;
      }
      const ready = await advanceHandshake(chat.token, who);
      if (!ready) throw new Error('Waiting for your contact to accept — messaging unlocks the moment they join.');
      const msg = await sendChatMessage(app.relay, app.sessions, chat.token, who, userText(draft.trim())); // Batch E (F-14)
      void quietLedgerFor(app).touch(chat.token).catch(() => undefined); // b77u (audit 6 W8): a message sent
      setThreadMessages((prev) => [...prev, msg]);
      if (onThread()) setChatKnown((prev) => new Set([...prev, msg.id]));
      setDraft('');
      setError(null); // b180: success clears the banner
      syncToken(chat.token);
    } catch (e) {
      setChat((c) => c); // keep pane; error surfaces below composer
      setError(friendlyError(e, 'action'));
    } finally { setBusy(false); }
  }, [app, chat, draft, syncToken, syncGroupToken, advanceHandshake]);

  // b62 groups: create + admin (creator-only rotate / evict)
  /**
   * b199 (owner request, Oct 16 2026): deliver a private payload into the
   * encrypted 1:1 chat with a pinned contact. Reuses the live chat with them
   * when one exists — starting a fresh one-tap session would supersede it
   * (K-17) — otherwise starts one quietly without opening it here.
   */
  const sendToContact = useCallback(async (veilId: string, text: string): Promise<'sent' | 'queued'> => {
    if (!app || !identity) throw new Error('Create your Vardum identity first.');
    const session = await app.auth.currentSession();
    if (!session) throw new Error('Not signed in.');
    const who = await clientId();
    if (!who) throw new Error('Sign in first.');
    let token: string | null = null;
    // Batch F (round-4 review R4-1-04, High): this chat carries the group key. The
    // relay list only supplies CANDIDATES (newest first); the chat is chosen from
    // this phone's sealed state: a contact chat whose sealed peer is this contact
    // under its pinned key. The relay can't relabel another chat into the choice.
    const pin = await app.pins.getPin(veilId);
    try {
      // b77 (sealed sender): the candidates are this phone's own 1:1 chats (the relay can't list a
      // ready chat any more), live ones first; the sealed-peer check below still decides
      const candidates = sessionRows.filter((r) => !r.groupToken && r.status !== 'ended').sort((a, b) => (a.status === 'active' ? 0 : 1) - (b.status === 'active' ? 0 : 1)).map((r) => r.token);
      if (pin) token = await pickContactSession(app.sessions, candidates, veilId, pin.ikPubB64);
    } catch { /* read failure → start a fresh chat below */ }
    if (!token) {
      const created = await createOneTapSession(
        { relay: app.relay, pins: pinToWipe(app.pins), sessions: pinToWipe(app.sessions) }, identity, veilId, session.user.id, // b70 (re-review 9): a wipe while this waits on the relay stops its writes
        {
          default_ttl_seconds: chatSettingsRef.current.burnTtlSeconds,
          expire_after_seconds: chatSettingsRef.current.expireAfterSeconds,
          key_retention_hours: chatSettingsRef.current.retentionHours,
          burn_after_open: chatSettingsRef.current.burnTtlSeconds > 0,
        },
        chatSettingsRef.current.nickname || undefined,
      );
      token = created.token;
    }
    // b199 (owner hardware repro, Oct 16): a freshly started contact chat is
    // not usable until the other phone accepts it ("Session keys not
    // established") — the invite used to be lost there. Queue it on this
    // chat instead; flushPendingInvites sends it the moment the chat is ready.
    const st = await app.sessions.load(token) as { ready?: boolean } | null;
    // Batch E (Superagent round 3, N3-1): a group invite carries the group key, so it
    // waits for the same gate as typed messages — this phone's own safety-code seal
    if (!st?.ready || !sessionVerifiedRef.current[token]) {
      await enqueueInvite({ veilId, token, text, at: Date.now() });
      return 'queued';
    }
    await sendChatControl(app.relay, app.sessions, token, who, text); // b77m review (L1)
    return 'sent';
  }, [app, identity, sessionRows]);

  /** b199: invites waiting for a contact to accept the chat that carries them.
   *  Persisted (Keychain) so a restart never loses one; flushed every few seconds. */
  const PENDING_INVITES_KEY = 'veil_pending_group_invites_v1';
  type PendingInvite = { veilId: string; token: string; text: string; at: number };
  const readPendingInvites = async (): Promise<PendingInvite[]> => {
    try { const raw = await app?.storage.get(PENDING_INVITES_KEY); return raw ? (JSON.parse(raw) as PendingInvite[]) : []; } catch { return []; }
  };
  const writePendingInvites = async (list: PendingInvite[]) => {
    try { await app?.storage.set(PENDING_INVITES_KEY, JSON.stringify(list)); } catch { /* retried next pass */ }
  };
  const enqueueInvite = async (p: PendingInvite) => {
    const list = (await readPendingInvites()).filter((x) => !(x.token === p.token && x.text === p.text));
    list.push(p);
    await writePendingInvites(list);
    console.log(`[veil-group-invite] queued for ${p.veilId.slice(0, 8)}… until they accept the chat`);
  };
  const flushingInvitesRef = useRef(false);
  useEffect(() => {
    if (!app || !identity) return;
    const WEEK = 7 * 86400_000;
    // b77t (audit 5 open question, IH): the flush had no lock, hold or decoy gate, so a queued invite went out
    // over the lock screen and through the real account during a decoy session. It waits for the unlock now,
    // never runs during a duress cleanup, and a pass stops sending the moment one begins.
    // b77t (audit 5 M-E, decoy groups "empty but working"): each account flushes only its OWN queue (`app` here:
    // its store, relay and token); a pass stops the moment the account in use is no longer the one it began on
    const passApp = app;
    const flushHeld = () => lockedRef.current || duressCleanupRef.current || activeAppRef.current !== passApp;
    const iv = setInterval(() => {
      if (flushingInvitesRef.current || flushHeld()) return;
      flushingInvitesRef.current = true;
      // b75 round 2 (audit D5): a pass that a wipe overtook writes nothing back
      const wipeGen = currentWipeGeneration();
      (async () => {
        const list = await readPendingInvites();
        if (!list.length) return;
        const who = await clientId();
        if (!who) return;
        const keep: PendingInvite[] = [];
        for (const p of list) {
          if (Date.now() - p.at > WEEK) { console.log(`[veil-group-invite] dropped stale invite for ${p.veilId.slice(0, 8)}… (not accepted within 7 days)`); continue; }
          const st = await app.sessions.load(p.token).catch(() => null) as { ready?: boolean } | null;
          if (!st) { console.log(`[veil-group-invite] chat for ${p.veilId.slice(0, 8)}… is gone — invite dropped; add them again`); continue; }
          // Batch F (R4-1-04): the queued chat must still be a contact chat with this
          // contact under its pinned key (sealed state), or the invite is dropped
          const flushPin = await app.pins.getPin(p.veilId);
          if (!flushPin || !sealedPeerMatches(st, p.veilId, flushPin.ikPubB64)) { console.log(`[veil-group-invite] chat for ${p.veilId.slice(0, 8)}… no longer matches the contact — invite dropped; add them again`); continue; }
          if (!st.ready || !sessionVerifiedRef.current[p.token]) { keep.push(p); continue; } // Batch E (N3-1): safety codes first
          if (flushHeld()) { keep.push(p); continue; } // b77t: locked / decoy / duress since the pass began
          try {
            await sendChatControl(app.relay, app.sessions, p.token, who, p.text); // b77m review (L1)
            console.log(`[veil-group-invite] delivered queued invite to ${p.veilId.slice(0, 8)}…`);
          } catch (e) {
            console.log(`[veil-group-invite] queued send retry later: ${String((e as Error)?.message ?? e)}`);
            keep.push(p);
          }
        }
        if (currentWipeGeneration() !== wipeGen) return;
        await writePendingInvites(keep);
      })().catch(() => undefined).finally(() => { flushingInvitesRef.current = false; });
    }, 5000);
    return () => clearInterval(iv);
  }, [app, identity]);

  /** b199: the group dials every new seat rides (b92 F-S6: never a hard-coded burn) */
  const groupDials = useCallback(() => ({
    burnAfterOpen: chatSettingsRef.current.burnTtlSeconds > 0,
    expireAfterSeconds: chatSettingsRef.current.expireAfterSeconds,
    keyRetentionHours: chatSettingsRef.current.retentionHours,
    defaultTtlSeconds: chatSettingsRef.current.burnTtlSeconds,
  }), []);

  /** b71 (audit F-07): the pinned identity key of each invited contact (Vardum ID -> IK),
   *  so the creator's phone admits exactly that key through their seat without a tap */
  const pinnedGroupInviteeKeys = useCallback(async (veilIds: string[]): Promise<Record<string, string>> => {
    const out: Record<string, string> = {};
    for (const v of veilIds) {
      const ik = app ? (await app.pins.getPin(v).catch(() => null))?.ikPubB64 : undefined;
      if (ik) out[v] = ik;
    }
    return out;
  }, [app]);

  /** b199: send each contact their locked seat, privately, inside your 1:1 chat */
  const deliverGroupInvites = useCallback(async (groupName: string, invites: { veilId: string; link: string }[]) => {
    const invited: string[] = []; const queued: string[] = []; const failed: string[] = [];
    for (const inv of invites) {
      try {
        const r = await sendToContact(inv.veilId, buildGroupInvitePayload({ name: groupName, link: inv.link, from: identity?.veilId }));
        (r === 'sent' ? invited : queued).push(inv.veilId);
      } catch (e) {
        console.log(`[veil-group-invite] delivery to ${inv.veilId.slice(0, 8)}… failed: ${String((e as Error)?.message ?? e)}`);
        failed.push(inv.veilId);
      }
    }
    return { invited, queued, failed };
  }, [sendToContact, identity]);

  const handleCreateGroup = useCallback(async (groupName: string, invitees: string[], linkCount: number): Promise<GroupInviteResult> => {
    // b77t (audit 5 M-E, owner decision "empty but working"): groups work in a decoy session, on the decoy's own
    // account (`app`, `identity` are the decoy's there: its records, relay client and token, never the real ones)
    if (!app || !identity) throw new Error('Create your Vardum identity first — Settings → Identity.');
    const who = await clientId();
    if (!who) throw new Error('Sign in first.');
    const name = groupName.trim().slice(0, 40);
    if (!name) throw new Error('Give the group a name.');
    const people = [...new Set(invitees)].slice(0, GROUP_MEMBER_CAP - 1);
    const links = Math.max(0, Math.min(linkCount, GROUP_MEMBER_CAP - 1 - people.length));
    if (people.length + links === 0) throw new Error('Choose at least one person, or add an invite link.');
    const created = await createGroup(
      { relay: app.relay, sessions: pinToWipe(app.sessions), storage: pinToWipe(app.storage), webBaseUrl: VEIL_LINK_URL }, // b70 (re-review 9): a wipe while this waits on the relay stops its writes
      {
        identity: { veilId: identity.veilId, ikSeedB64: identity.ikSeedB64, ikPubB64: identity.ikPubB64, pqPrivB64: identity.pqPrivB64 },
        groupName: name,
        nickname: chatSettings.nickname || '', // b71: the name members see (signed, sent only inside the group)
        inviteCount: links,
        invitees: people,
        inviteeKeys: await pinnedGroupInviteeKeys(people), // b71 (audit F-07): a contact seat admits exactly their pinned key
        clientId: who,
        dials: groupDials(),
      },
    );
    const { invited, queued, failed } = await deliverGroupInvites(created.groupName, created.contactInvites);
    await refreshSessions(true); // b199: user action, not ambient — never skipped by the burn hold
    refreshMyGroups();
    return { groupName: created.groupName, inviteLinks: created.inviteLinks, invited, queued, failed };
  }, [app, identity, groupDials, deliverGroupInvites, refreshSessions, chatSettings.nickname, pinnedGroupInviteeKeys]);

  /** b199 "Add people" — creator only, seats minted at the group's current epoch */
  const handleAddGroupPeople = useCallback(async (groupToken: string, invitees: string[], linkCount: number): Promise<GroupInviteResult> => {
    // b77t (audit 5 M-E, owner decision "empty but working"): groups work in a decoy session, on the decoy's own
    // account (`app`, `identity` are the decoy's there: its records, relay client and token, never the real ones)
    if (!app || !identity) throw new Error('Create your Vardum identity first.');
    const who = await clientId();
    if (!who) throw new Error('Sign in first.');
    if (invitees.length + linkCount === 0) throw new Error('Choose at least one person, or add an invite link.');
    const seats = await createGroupSeats(
      { relay: app.relay, sessions: pinToWipe(app.sessions), storage: pinToWipe(app.storage), webBaseUrl: VEIL_LINK_URL }, // b70 (re-review 9): a wipe while this waits on the relay stops its writes
      { groupToken, clientId: who, dials: groupDials(), invitees, linkCount, inviteeKeys: await pinnedGroupInviteeKeys(invitees) }, // b71 (audit F-07 / F-24: the group's own dials win in createGroupSeats)
    );
    const { invited, queued, failed } = await deliverGroupInvites(seats.groupName, seats.contactInvites);
    return { groupName: seats.groupName, inviteLinks: seats.inviteLinks, invited, queued, failed };
  }, [app, identity, groupDials, deliverGroupInvites, pinnedGroupInviteeKeys]);

  /** b199: groups this device created — the only ones it can add people to */
  const [myGroups, setMyGroups] = useState<{ groupToken: string; name: string }[]>([]);
  const refreshMyGroups = useCallback(() => {
    if (!app) return;
    (async () => {
      const out: { groupToken: string; name: string }[] = [];
      for (const gt of listGroupTokens(app.storage)) {
        const rec = await loadGroupRecord(app.storage, gt).catch(() => null);
        if (rec && rec.role === 'creator') out.push({ groupToken: gt, name: rec.name || 'Unnamed group' });
      }
      setMyGroups(out);
    })().catch(() => undefined);
  }, [app]);
  useEffect(() => { setMyGroups([]); }, [app]); // b77t (audit 5 M-E): the other account's groups never show while the list reloads
  useEffect(() => { refreshMyGroups(); }, [refreshMyGroups, sessionRows.length]);

  /**
   * b199 (owner decision, Oct 16 2026): Contacts NEVER starts a chat silently.
   * Tapping a contact opens your existing contact chat with them. When there
   * is none, this returns the choices instead — your anonymous (invite-link)
   * chats, which carry no Veil ID and so can't be matched to a contact — and
   * the screen asks: open one of those, or start a new chat. A new chat is
   * started only on that explicit choice (`choice.start`).
   */
  const handleOpenContact = useCallback(async (
    veilId: string,
    choice?: { open?: string; start?: boolean },
  ): Promise<ContactChatChoice[] | null> => {
    // b77t (audit 5 M-E): works in a decoy session too — `app` is the decoy's own account there
    const openRow = async (r: SessionRow) => {
      await openChat(r.token, r.title, r.subtitle, r.status, r.peerVeilId ?? null, !!r.myVerified);
    };
    if (choice?.open) {
      const r = sessionRows.find((x) => x.token === choice.open);
      if (r) await openRow(r);
      return null;
    }
    if (choice?.start) { await handleMessage(veilId); return null; }
    // Batch F (R4-4-01): open a chat with this contact only if this phone sealed
    // it as being with them under their pinned key; the row's label never decides
    const pinC = app ? await app.pins.getPin(veilId) : null;
    const withThem = pinC && app
      ? await pickContactSession(app.sessions, sessionRows.filter((r) => !r.groupToken && r.status !== 'ended').map((r) => r.token), veilId, pinC.ikPubB64)
      : null;
    const mineWithThem = withThem ? sessionRows.find((r) => r.token === withThem) : undefined;
    if (mineWithThem) { await openRow(mineWithThem); return null; }
    return sessionRows
      .filter((r) => !r.groupToken && r.status !== 'ended' && !r.peerVeilId)
      .map((r) => ({ token: r.token, title: r.title, subtitle: r.subtitle }));
  }, [app, sessionRows, openChat, handleMessage]);

  /** b199: Join / Decline on a group invite card (state kept on this phone) */
  const INVITE_STATE_KEY = 'veil_group_invite_state_v1';
  const [inviteState, setInviteState] = useState<Record<string, 'joined' | 'declined'>>({});
  useEffect(() => {
    if (!app) return;
    app.storage.get(INVITE_STATE_KEY).then((raw) => { try { setInviteState(raw ? JSON.parse(raw) : {}); } catch { /* fresh */ } }).catch(() => undefined);
  }, [app]);
  const markInvite = useCallback(async (msgId: string, s: 'joined' | 'declined') => {
    setInviteState((cur) => {
      const next = { ...cur, [msgId]: s };
      app?.storage.set(INVITE_STATE_KEY, JSON.stringify(next)).catch(() => undefined);
      return next;
    });
  }, [app]);
  const handleJoinGroupInvite = useCallback(async (msgId: string, link: string) => {
    // b77t (audit 5 M-E, owner decision "empty but working"): groups work in a decoy session, on the decoy's own
    // account (`app`, `identity` are the decoy's there: its records, relay client and token, never the real ones)
    // b77q (audit 3 AQ-4): the same disclosure as the same link opened from outside (any chat
    // peer can send this card); Cancel leaves the card as it was
    const go = await new Promise<boolean>((res) => Alert.alert('Join this group?', GROUP_JOIN_NOTE, [
      { text: 'Cancel', style: 'cancel', onPress: () => res(false) },
      { text: 'Join', onPress: () => res(true) },
    ], { cancelable: true, onDismiss: () => res(false) }));
    if (!go) return;
    await handleJoinInvite(link);
    await markInvite(msgId, 'joined');
  }, [handleJoinInvite, markInvite]);
  const handleDeclineGroupInvite = useCallback(async (msgId: string) => { await markInvite(msgId, 'declined'); }, [markInvite]);

  const groupMainSession = useCallback(async (): Promise<string> => {
    if (!app || !chat?.groupToken) throw new Error('No group open.');
    const who = await clientId();
    if (!who) throw new Error('Sign in first.');
    const main = await findMainGroupSession(
      { relay: app.relay, sessions: app.sessions, storage: app.storage, webBaseUrl: VEIL_LINK_URL },
      chat.groupToken, who,
    );
    if (!main) throw new Error('This device cannot administer the group (creator session missing).');
    return main;
  }, [app, chat]);

  const handleRotateGroup = useCallback(async (): Promise<void> => {
    if (!app) return;
    // b77u (audit 6 U-M3): what this action adds to the view goes to its own thread only (a switch meanwhile drops it; the store has it)
    const { onThread, setThreadMessages } = threadGuard(chat?.token ?? '', app);
    const gt = chat?.groupToken;
    setGroupBusy(true);
    try {
      const main = await groupMainSession();
      const who = await clientId();
      if (!who) return;
      const newEpoch = await rotateGroup(
        { relay: app.relay, sessions: app.sessions, storage: app.storage, webBaseUrl: VEIL_LINK_URL },
        { groupToken: chat!.groupToken!, sessionToken: main, clientId: who },
      );
      const fp = await currentGroupFingerprint(app.storage, chat!.groupToken!).catch(() => null); // b75 (lead's emulator finding)
      setGroupInfo((gi) => (gi && gi.groupToken === gt && onThread() ? { ...gi, epoch: newEpoch, fingerprint: fp } : gi));
      setThreadMessages((prev) => [...prev, { id: `sys_rot_${newEpoch}`, text: '', mine: false, ts: new Date().toISOString(), systemNote: 'Group keys changed.' }]); // b73 (audit V-15): the epoch key isn't a post-quantum key (its delivery is ML-KEM wrapped)
    } catch (e) {
      setError(friendlyError(e, 'action'));
      throw e;
    } finally { setGroupBusy(false); }
  }, [app, chat, groupMainSession]);

  const handleEvictMember = useCallback(async (member: { veilId: string; ikPub: string }): Promise<void> => {
    if (!app || !chat?.groupToken) return;
    // b77u (audit 6 U-M3): what this action adds to the view goes to its own thread only (a switch meanwhile drops it; the store has it)
    const { onThread, setThreadMessages } = threadGuard(chat.token, app);
    const gt = chat.groupToken;
    setGroupBusy(true);
    try {
      const main = await groupMainSession();
      const who = await clientId();
      if (!who) return;
      // Batch C (A3): eviction + rotation are one operation; if the rotation
      // fails, normal sends stay blocked and the next poll finishes it
      const newEpoch = await evictGroupMember(
        { relay: app.relay, sessions: app.sessions, storage: app.storage, webBaseUrl: VEIL_LINK_URL },
        { groupToken: chat.groupToken, sessionToken: main, target: member, clientId: who },
      );
      if (newEpoch !== null) {
        const fp = await currentGroupFingerprint(app.storage, chat.groupToken).catch(() => null); // b75 (lead's emulator finding)
        setGroupInfo((gi) => (gi && gi.groupToken === gt && onThread() ? { ...gi, epoch: newEpoch, fingerprint: fp } : gi));
      }
      setThreadMessages((prev) => [...prev, { id: `sys_evict_${Date.now()}`, text: '', mine: false, ts: new Date().toISOString(), systemNote: 'A member was removed and the group keys rotated.' }]);
    } catch (e) {
      setError(friendlyError(e, 'action'));
      throw e;
    } finally { setGroupBusy(false); }
  }, [app, chat, groupMainSession]);

  // ---- b71 (audit F-07): the creator approves or declines a join request ----
  const handleApproveGroupClaim = useCallback(async (ikPub: string): Promise<void> => {
    if (!app || !chat?.groupToken) return;
    // b77u (audit 6 U-M3): what this action adds to the view goes to its own thread only (a switch meanwhile drops it; the store has it)
    const { onThread, setThreadMessages } = threadGuard(chat.token, app);
    const gt = chat.groupToken;
    setGroupBusy(true);
    try {
      const main = await groupMainSession();
      const who = await clientId();
      if (!who) return;
      // admits, rotates the keys once, then sends the newcomer only the new epoch's key
      const r = await admitGroupClaims(
        { relay: app.relay, sessions: app.sessions, storage: app.storage, webBaseUrl: VEIL_LINK_URL },
        { groupToken: chat.groupToken, sessionToken: main, clientId: who, iks: [ikPub] },
      );
      setGroupClaims((gc) => (gc ? { ...gc, rows: gc.rows.filter((x) => x.ikPub !== ikPub) } : gc));
      const fp = await currentGroupFingerprint(app.storage, chat.groupToken).catch(() => null); // b75 (lead's emulator finding)
      setGroupInfo((gi) => (gi && gi.groupToken === gt && onThread() ? { ...gi, epoch: r.epoch, fingerprint: fp } : gi));
      for (const a of r.admitted) {
        setThreadMessages((prev) => [...prev, { id: `sys_join_${a.ikPub.slice(0, 12)}_${r.epoch}`, text: '', mine: false, ts: new Date().toISOString(), systemNote: `${a.label} joined the group. The keys rotated first, so they can't read earlier messages.` }]);
      }
    } catch (e) {
      setError(friendlyError(e, 'action'));
      throw e;
    } finally { setGroupBusy(false); }
  }, [app, chat, groupMainSession]);

  const handleDeclineGroupClaim = useCallback(async (ikPub: string): Promise<void> => {
    if (!app || !chat?.groupToken) return;
    // b73 (audit V-01 / V-10): with the relay and the creator's main session, so the relay drops the claimant's seat
    const main = await groupMainSession().catch(() => undefined);
    await declineGroupClaim({ storage: app.storage, relay: app.relay, sessions: app.sessions }, { groupToken: chat.groupToken, ik: ikPub, sessionToken: main || undefined });
    setGroupClaims((gc) => (gc ? { ...gc, rows: gc.rows.filter((x) => x.ikPub !== ikPub) } : gc));
  }, [app, chat, groupMainSession]);

  const handleEndSession = useCallback(async (opts: { forEveryone?: boolean } = {}) => {
    if (!app || !chat) return;
    if (chat.groupToken) {
      // (b67) owner request: ✕ must delete group threads too. Groups have no
      // relay "end" — deleting the local group record removes the thread from
      // the list; the underlying main session is ended best-effort server-side.
      setBusy(true);
      try {
        const who = (await clientId()) ?? undefined;
        // b132 (owner repro: a group needed TWO ✕ before it left the thread
        // list): one group = MANY relay rows (main session + one invite row
        // per link, all sharing the group_token). The old code ended only
        // the OPEN thread's row and then forgot the local group record —
        // the surviving invite rows still carried the group tag and
        // resurrected the thread on the very next refresh. End EVERY row
        // tied to the group, then hide any survivor (peer-owned rows a
        // credential can't reach, b65 class) so nothing resurrects.
        const groupTokens = new Set<string>([chat.token]);
        // Batch F (round-4 review R4-4-07): the server's group tag only NOMINATES a
        // row. A row is ended and wiped only if the local group record knows its
        // token (my seat or seats I made), or this phone holds no keys for it, so a
        // 1:1 chat the server tagged with this group is never swept up.
        const gRec = await loadGroupRecord(app.storage, chat.groupToken).catch(() => null);
        // b74 (VAR-05): a member says it is leaving (signed, in the group) BEFORE its seat ends, so
        // the creator removes it and rotates the keys. Best effort: if it doesn't go out, the
        // creator is told the member has gone from the relay's list and can remove it with a tap.
        // audit VAR-24: what this delete does is decided by groupDeletePlan (below): the creator's "Delete
        // this group thread" is this phone only; ending the group for everyone is its own, explicit action
        const leaving = gRec?.role === 'member';
        if (leaving && gRec?.gekB64 && who) {
          await sendGroupLeave({ relay: app.relay, sessions: app.sessions, storage: app.storage, webBaseUrl: VEIL_LINK_URL }, { groupToken: chat.groupToken, sessionToken: gRec.sessionToken ?? gRec.seatToken ?? chat.token, clientId: who })
            .catch((e) => console.warn('[veil-group] leave not sent:', String((e as Error)?.message ?? e)));
        }
        const groupOwnTokens = new Set<string>([chat.token, ...(gRec?.seatToken ? [gRec.seatToken] : []), ...Object.keys(gRec?.seats ?? {})]);
        const hideOnly: string[] = [];
        // b77q review (Info): a row the relay tagged with this group is never hidden when this phone holds it for
        // something else — a chat's sealed state, or another group's record — so the tag can't make the delete hide it
        const otherGroupTokens = new Set<string>();
        try {
          for (const g of exportGroupRecords(app.storage)) {
            if (g.groupToken === chat.groupToken) continue;
            for (const t of [g.sessionToken, g.seatToken, ...Object.keys(g.seats ?? {})]) if (t) otherGroupTokens.add(t);
          }
        } catch { /* no other group records */ }
        const tokenHeldElsewhere = async (t: string): Promise<boolean> =>
          otherGroupTokens.has(t) || !!(await app.sessions.load(t).catch(() => ({}) as unknown));
        try {
          const r = await app.relay.sessionList(who ?? '');
          const list = (r.data as { data?: unknown[] })?.data ?? (r.data as unknown as { sessions?: unknown[] })?.sessions ?? (r.data as unknown[]);
          for (const raw of Array.isArray(list) ? list : []) {
            const rec = raw as Record<string, unknown>;
            if (rec.group_token && String(rec.group_token) === chat.groupToken) {
              const t = String(rec.token ?? '');
              // Batch G (round-5 review R5-2-07): only the group's own tokens are ended and
              // wiped. Other rows the server tagged with this group are only hidden here,
              // and a read error never counts as "no keys".
              if (t && groupOwnTokens.has(t)) groupTokens.add(t);
              else if (t && !(await tokenHeldElsewhere(t))) hideOnly.push(t);
            }
          }
        } catch { /* list failure → end just the open token, as before */ }
        const plan = groupDeletePlan(gRec?.role ?? null, !!opts.forEveryone, [...groupTokens], hideOnly);
        const survivors: string[] = [...plan.hide];
        for (const t of plan.end) {
          let ended = true;
          try { await app.relay.sessionEnd(t, (await app.sessions.load(t))?.writeSecret ?? null, who); }
          catch { ended = false; /* peer-created rows RLS-block the end (b65 class) */ }
          if (!ended) survivors.push(t);
        }
        if (survivors.length) {
          // b65 ghost-thread guard: hide any row we couldn't end server-side
          // so it cannot resurrect the thread after the group is forgotten.
          try {
            const raw = await app.storage.get('veil_dismissed_sessions');
            const list: string[] = raw ? (JSON.parse(raw) as string[]) : [];
            for (const t of survivors) if (!list.includes(t)) list.push(t);
            await app.storage.set('veil_dismissed_sessions', JSON.stringify(list));
          } catch { /* hide is best-effort */ }
        }
        for (const t of plan.removeLocal) { try { await app.sessions.remove(t); } catch { /* no local state for this row */ } }
        await forgetGroup(app.storage, chat.groupToken);
        setChat(null); setScreen('main'); refreshSessions();
      } catch (e) {
        setError(friendlyError(e, 'action'));
      } finally { setBusy(false); }
      return;
    }
    setBusy(true);
    try {
      const sealedEnd0 = await app.sessions.load(chat.token).catch(() => null);
      const ws = sealedEnd0?.writeSecret ?? null; // the legacy rendezvous end's write secret
      const who = await clientId();
      try {
        // b77m merge (audit VAR-07): "End this chat" goes through the library's endChat (src/chat-end.ts):
        // the END control envelope first, inside the chat's encryption, so the peer's phone says "ended
        // by the other side"; then MY inbound (read cap); the peer's inbound (send cap) only when the END
        // didn't get there (retiring it would destroy the END — the peer's phone retires it once read).
        // Calling endSealedChat here left the peer seeing only 410s ("unavailable"). A chat the relay
        // already reported gone sends nothing (Delete); a chat that never finished its handshake still
        // ends its rendezvous row. All best effort, bounded; no account, no session token.
        // b65: client_id = participation proof; until the gate update deploys the
        // server may still refuse (403) — the fallbacks below own that case.
        const r = await endChatOnRelay(app.relay, app.sessions, chat.token, () => app.relay.sessionEnd(chat.token, ws, who ?? undefined));
        // b77r2 (audit R2-A-1): a missed mailbox end is not left to the 30-day sweeper alone: the peer's
        // sends to my retired inbound get 410 and its P-4 rule marks the chat unavailable there
        if (r.route === 'sealed' && (!r.inbound || (!r.notice && !r.outbound))) console.log(`[veil-end] mailbox end incomplete (end message ${r.notice}, inbound ${r.inbound}, peer ${r.outbound}) — the peer's phone marks the chat unavailable when its sends keep getting 410`);
      } catch (e) {
        // 403s happen on sessions whose write secret we never stored (pending /
        // peer-created / restored device). Fall back to deleting the thread
        // record outright; if even that is denied, end locally anyway — the
        // user is never trapped in a thread they cannot leave.
        const recId = sessionRows.find((r) => r.token === chat.token)?.recId;
        let cleared = false;
        if (recId) { try { await app.relay.entityDelete('VeilSession', recId); cleared = true; } catch { /* RLS */ } }
        if (!cleared) {
          // b65: relay keeps the row (RLS-owned by the peer) — hide it locally so
          // the ghost thread cannot resurrect on the next poll. The gate-side
          // participation-proof fix deletes it for real once deployed.
          try {
            const raw = await app.storage.get('veil_dismissed_sessions');
            const list: string[] = raw ? (JSON.parse(raw) as string[]) : [];
            if (!list.includes(chat.token)) {
              list.push(chat.token);
              await app.storage.set('veil_dismissed_sessions', JSON.stringify(list));
            }
          } catch { /* hide is best-effort */ }
        }
        console.warn('[veil-end] relay end rejected, fallback:', String((e as Error).message || e), cleared ? '(record deleted)' : '(hidden locally)');
      }
      await app.sessions.remove(chat.token);
      unavailableChatsRef.current.delete(chat.token); // b77m merge (VAR-07): a deleted unavailable chat
      // b70 (re-review 9): the name the user gave this chat goes with it
      try { const names = await loadThreadNames(app.storage); if (names[chat.token] !== undefined) { delete names[chat.token]; await app.storage.set(THREAD_NAMES_KEY, JSON.stringify(names)); } } catch { /* best-effort */ }
      setChat(null); setScreen('main'); refreshSessions();
    } catch (e) {
      setError(friendlyError(e, 'action'));
    } finally { setBusy(false); }
  }, [app, chat, refreshSessions]);

  // b77u (audit 6 W8 / website C-1): "End quiet chats after" — this phone ends a 1:1 chat quiet for longer than the
  // shorter of its own dial and this phone's setting (src/quiet-chats.ts), the way "End chat" does: the END inside
  // the chat, then the mailboxes (endChatOnRelay), then the local state. Only while unlocked and in front, for the
  // account in use; a wipe or an account switch stops a pass (pinned store, account check before each end).
  const quietBusyRef = useRef(false);
  useEffect(() => {
    if (!app || !identity) return;
    const a = app;
    const pass = async (): Promise<void> => {
      if (quietBusyRef.current || lockedRef.current || AppState.currentState !== 'active' || activeAppRef.current !== a) return;
      quietBusyRef.current = true;
      try {
        const gen = currentWipeGeneration();
        const stillOn = () => currentWipeGeneration() === gen && activeAppRef.current === a && !lockedRef.current;
        const myHours = chatSettingsRef.current.retentionHours;
        const chats: { token: string; windowMs: number }[] = [];
        for (const r of hbRowsRef.current) {
          if (r.groupToken || r.status !== 'active') continue;
          const sealed = await a.sessions.load(r.token).catch(() => null);
          if (!sealed) continue;
          chats.push({ token: r.token, windowMs: quietWindowMs(sessionDials(sealed)?.keyRetentionHours, myHours) });
        }
        if (!stillOn()) return;
        const ledger = quietLedgerFor(a);
        const dueTokens = new Set(await ledger.due(chats));
        const due = chats.filter((c) => dueTokens.has(c.token));
        // b77u2 (UC-L1): each due chat is synced first (a normal pass, never while held) and ended only if it is
        // still quiet after it; a failed or held fetch leaves it for a later round (src/quiet-chats.ts endQuietChats)
        const ended = await endQuietChats(due, {
          ledger, stillOn,
          held: () => holdWhileLocked(lockedRef.current, settingsRef.current.holdUntilUnlock) || decoyHoldNow(),
          syncFirst: (token) => backgroundSyncTokenRef.current(token, undefined, { quietCheck: true }),
          end: async (token) => {
          if (!stillOn()) return;
          console.log(`[veil-end] #${token.slice(0, 4)}: quiet past "End quiet chats after" — ending it`);
          const ws = (await a.sessions.load(token).catch(() => null))?.writeSecret ?? null;
          const who = await clientId();
          try { await endChatOnRelay(a.relay, a.sessions, token, () => a.relay.sessionEnd(token, ws, who ?? undefined)); }
          catch (e) { console.log('[veil-end] quiet end: relay step failed (the peer marks it unavailable):', String((e as Error)?.message ?? e)); }
          if (!stillOn()) return;
          await a.sessions.remove(token).catch(() => undefined);
          unavailableChatsRef.current.delete(token);
          try { const names = await loadThreadNames(a.storage); if (names[token] !== undefined) { delete names[token]; await a.storage.set(THREAD_NAMES_KEY, JSON.stringify(names)); } } catch { /* best-effort */ }
          await ledger.forget(token);
          if (threadViewRef.current.current() === token) { setChat(null); setScreen('main'); }
          },
        });
        if (ended.length) refreshSessionsRef.current?.(true);
      } finally { quietBusyRef.current = false; }
    };
    const first = setTimeout(() => { void pass(); }, 30_000);
    const iv = setInterval(() => { void pass(); }, QUIET_CHECK_MS);
    return () => { clearTimeout(first); clearInterval(iv); };
  }, [app, identity]); // eslint-disable-line react-hooks/exhaustive-deps

  // ---------- Play UGC (18 Oct 2026): block (device-local) ----------

  /** block the sender of a group message (device-local) */
  const handleBlockSender = useCallback(async (msgId: string) => {
    if (!app) return;
    const vid = chatMessages.find((m) => m.id === msgId)?.senderVid;
    if (!vid) throw new Error('This message doesn’t carry its sender’s Vardum ID (it arrived before blocking existed). Block them from a newer message.');
    setBlockedIds(await blockVeilId(app.storage, vid));
    console.log('[veil-ugc] sender blocked on this device');
  }, [app, chatMessages]);

  /** 1:1: block this contact — ends the chat on both sides (so they can't keep
   *  sending or pinging), hides their threads and requests on this phone */
  const handleBlockContact = useCallback(async () => {
    if (!app || !chat || chat.groupToken) return;
    // Batch G (round-5 review R5-1-04): block the identity this phone sealed for the
    // chat; an invite chat only ends (its label came from the server)
    const sp = sealedPeer(await app.sessions.load(chat.token).catch(() => null));
    if (sp) setBlockedIds(await blockVeilId(app.storage, sp.veilId));
    else Alert.alert('Chat ended', 'This chat isn’t linked to a saved contact, so it was ended without blocking a Vardum ID.');
    await handleEndSession();
  }, [app, chat, handleEndSession]);

  const handleUnblock = useCallback(async (veilId: string) => {
    if (!app) return;
    setBlockedIds(await unblockVeilId(app.storage, veilId));
    refreshSessions();
  }, [app, refreshSessions]);

  if (locked && (identity || appLock)) {
    return (
      <LockScreen
        onUnlock={handleUnlock}
        hint={lockHint}
        onCode={handleCodeOnce}
        verifying={codeVerifying || wipeFinishing /* b77k (IP77-6): inert while a wipe finishes */}
        wipeFinishing={wipeFinishing}
        resetKey={codeResetKey}
        hasAppLock={!!appLock}
        codeError={codeError}
        lockoutUntil={lockout?.lockedUntil ?? 0}
        callLive={!!lockCall}
        callIncoming={!!lockCall?.incoming}
        onEndCall={() => CallManager.endFromLock()}
      />
    );
  }

  if (bootError) {
    return (
      <View style={styles.boot}>
        <Text style={styles.errTitle}>Vardum could not start</Text>
        <Text style={styles.errText}>{bootError}</Text>
        {/* b104: every fatal-screen screenshot must self-identify the JS
            build it ran on — the owner's crash screenshot was visually
            identical on old and new code, so we couldn't tell whether the
            patch had even been applied (it hadn't: the xcopy ran from a
            fresh cmd prompt in the wrong folder). This tag settles it in
            one glance from now on. */}
        <Text style={styles.errText}>build b154-2026-10-01</Text>
      </View>
    );
  }

  if (screen === 'boot' || !app) {
    return (
      <View style={styles.boot}>
        <ActivityIndicator color="#FFFFFF" />
        <Text style={styles.bootText}>Sealing the device…</Text>
      </View>
    );
  }

  if (screen === 'onboard') {
    return (
      <>
      <OnboardingScreen
        settings={decoyMode ? decoySettings : settings} /* b70 (re-review 5): never the real ID or nickname in decoy mode */
        onApply={handleSettingsChange}
        onDone={() => {
          // the "Secure your VEIL" prompt only clears once the checkup itself ran
          if (onboardingMode === 'full' || onboardingMode === 'checkupOnly') setSecurePrompt(false);
          else if (onboardingMode === 'passwordOnly') setSecurePrompt(!settingsRef.current.setupDone && settingsRef.current.firstSessionDone); // b77f (ZTE77-4): as a restore
          else setSecurePrompt(true);
          setScreen('main');
        }}
        veilId={decoyMode ? decoyVeilId : identity?.veilId ?? null}
        mode={onboardingMode}
        onCancel={() => setScreen('main')}
        appLockEnabled={!!appLock && !(decoyMode && decoyLockHidden)}
        onSetAppLock={(p, d, du) => (decoyModeRef.current ? Promise.reject(new Error(DECOY_REFUSAL)) : handleSetAppLock(null, p, d, du))} /* first-time set only: save() refuses an existing lock */
      />
      {appPromptShown}<CallOverlay /><PrivacyCover />
      </>
    );
  }

  if (screen === 'login') {
    return (
      <>
      <LoginScreen busy={busy} error={error} info={info} onLogin={handleLogin} onForgotPassword={handleForgot} onSignup={handleSignup} onSwitchToIdentity={() => setScreen('identity')} />
      {appPromptShown}<CallOverlay /><PrivacyCover />
      </>
    );
  }

  if (screen === 'otp') {
    return (
      <>
      <OtpScreen
        email={email} busy={busy} error={error} info={info}
        onVerify={handleVerify} onResend={handleResend}
        onBack={() => setScreen('login')}
      />
      {appPromptShown}<CallOverlay /><PrivacyCover />
      </>
    );
  }

  if (screen === 'identity') {
    return (
      <>
      <IdentityScreen
        onCreate={handleCreateIdentity}
        onRestore={handleRestore}
        regLock={regLockPrompt ? regLockPrompt.info : null}
        onRegLockPin={handleRegLockPin}
        onRegLockCancel={handleRegLockCancel}
        onFinishCreate={handleFinishCreate}
        onSignOut={handleSignOut}
        /* b199 (owner, Oct 16): no email sign-in link on the first screen. Older
           email-based identities still get in: restoring with their 24 words
           falls back to the email sign-in automatically (handleRestore). */
        initialMode={identityEntry}
        notice={relayMovedNotice ? { title: RELAY_MOVED_TITLE, text: RELAY_MOVED_TEXT } : null}
      />
      {appPromptShown}<CallOverlay /><PrivacyCover />
      </>
    );
  }

  // b70 (re-review 4): never a real thread in decoy mode. b77t (audit 5 M-E): the decoy's own chats open there
  // (the switch closes any real one, and openChat drops one that began under the other account)
  if (screen === 'chat' && chat) {
    // combine the device messages with the media decrypt cache for the UI
    // Play UGC: blocked senders' rows are never rendered (they stay cached, so unblocking shows them again)
    const uiMessages: ChatMessageUI[] = (blockListLoaded || !chat.groupToken ? withoutBlocked(chatMessages, blockedIds) : chatMessages.filter((m) => m.mine || !!(m as { systemNote?: string }).systemNote)).map((m) => {
      if (!m.media) return { id: m.id, text: m.text, mine: m.mine, ts: m.ts, sender: m.sender, senderVerified: m.senderVerified, senderCreator: m.senderCreator, systemNote: m.systemNote, openedAt: m.openedAt, read: m.read, groupInvite: m.groupInvite, reactions: m.reactions, queued: m.queued };
      const st = mediaLoad[m.id];
      const mime = m.media.mime ?? 'application/octet-stream';
      const isAv = mime.startsWith('audio/') || mime.startsWith('video/');
      // b62: av playback needs the cache file (data: URIs don't play in expo-av);
      // images keep the data URI for the lightbox.
      const own = m.mine && m.media.localUri && liveLocalUris.current.has(m.media.localUri) ? m.media.localUri : null; // b70 (VAR-03)
      let src = st?.uri ?? own;
      if (isAv) src = st?.fileUri ?? st?.uri ?? own;
      return {
        id: m.id, text: m.text, mine: m.mine, ts: m.ts, sender: m.sender, senderVerified: m.senderVerified, senderCreator: m.senderCreator, systemNote: m.systemNote, openedAt: m.openedAt, read: m.read, reactions: m.reactions, queued: m.queued,
        media: {
          name: m.media.name ?? 'media',
          mime,
          size: m.media.size ?? 0,
          dl: !!m.media.dl,
          src,
          loading: !!st?.loading,
          error: st?.error ?? null,
        },
      };
    });
    return (
      <>
      <ChatScreen
        privateKeyboard={settings.privateKeyboard}
        threadKey={chat.token}
        onDismissError={() => setError(null)}
        title={chat.title}
        historyNotice={
          (settings.storageMode === 'memory' || settings.localHistory === false)
            ? 'History isn\u2019t saved on this device \u2014 messages vanish when you leave this thread.'
            : (cacheSaveFailed === chat.token
              ? 'Couldn\u2019t save history on this device \u2014 messages may vanish when you leave this thread.'
              : null)
        }
        subtitle={chat.subtitle}
        status={chat.status}
        burnAfterOpen={chat.burnAfterOpen}
        burnSeconds={chat.burnSeconds}
        busy={busy}
        error={error}
        messages={uiMessages}
        draft={draft}
        onDraftChange={setDraft}
        onSend={handleSend}
        onReactMessage={!chat.groupToken ? handleReact : undefined}
        onBlockSender={chat.groupToken ? handleBlockSender : undefined}
        onBlockContact={!chat.groupToken && chat.peerVeilId ? handleBlockContact : undefined}
        onBack={() => { setChat(null); setError(null); refreshSessions(); setScreen('main'); }}
        onStartCall={chat.status !== 'ended' && chat.status !== 'pending' && !chat.groupToken && chat.myVerified ? () => { // Batch F (R4-4-16): safety-code gate
          // b144 W3: 1:1 ready threads only — group calls are post-W4
          CallManager.start(chat.token, chat.title).catch((e) => console.log(`[veil-call] start failed: ${(e as Error).message}`));
        } : undefined}
        onEndSession={() => { void handleEndSession(); }}
        onEndGroupForAll={chat.groupToken && groupInfo?.isCreator ? () => { void handleEndSession({ forEveryone: true }); } : undefined}
        unrecoverable={!chat.groupToken && hsFailClosedRef.current.has(chat.token)}
        unavailable={!chat.groupToken && !!chat.unavailable}
        endedByPeer={!chat.groupToken && !!chat.endedByPeer}
        onCheckAgain={!chat.groupToken && chat.unavailable && !chat.endedByPeer ? () => { void handleCheckChatAgain(chat.token); } : undefined}
        setupFailed={!chat.groupToken && !hsFailClosedRef.current.has(chat.token) && setupFailedRef.current.has(chat.token)}
        canNewThread={!!(chat?.canNewThread && chat.status !== 'ended')}
        onNewThread={handleNewThread}
        contact={!!chat?.contact}
        myVerified={!!chat?.myVerified}
        request={!!chat?.request}
        onAcceptRequest={() => (chat ? handleAcceptRequest(chat.token) : Promise.resolve(false))}
        onDeclineRequest={() => Alert.alert('Decline this request?', 'The chat request is removed from this phone and ended on the server where it can be.', [
          { text: 'Cancel', style: 'cancel' },
          { text: 'Decline', style: 'destructive', onPress: () => { void handleEndSession(); } },
        ])}
        sessionFingerprint={chat?.fingerprint ?? null}
        peerVeilId={chat?.peerVeilId ?? null}
        peerPinned={!!chat?.peerPinned}
        onPinContact={() => chat?.token && chat?.peerVeilId && handlePinFromSession(chat.token, chat.peerVeilId)}
        onVerifySession={async (shownFp) => { const ok = chat ? await handleVerifySession(chat.token, shownFp) : false; return !!ok; }}
        showVerifyCard={verifyCard && !chat?.groupToken && !chat?.contact && chat?.status === 'active'}
        onVerifyCardDismiss={handleDismissVerifyCard}
        canRename={!!(chat?.peerVeilId && !chat.groupToken)}
        threadNickname={chatLocalNick}
        onRenameThread={handleRenameThread}
        onAttach={handleAttach}
        pendingPick={pendingPick}
        allowDl={allowDl}
        onAllowDlChange={setAllowDl}
        onMediaSave={handleMediaSave}
        mediaSaving={mediaSaving}
        inviteState={inviteState}
        onJoinGroupInvite={handleJoinGroupInvite}
        onDeclineGroupInvite={handleDeclineGroupInvite}
        onSendMedia={handleSendMedia}
        onCancelPick={handleCancelPick}
        onMediaRetry={(id) => {
          const orig = chatMessages.find((x) => x.id === id);
          if (orig?.media && chat) resolveMedia(chat.token, id, orig.media, orig.mine);
        }}
        voiceRec={voiceRec}
        onVoiceRecord={handleVoiceRecord}
        onVoiceCancel={handleVoiceCancel}
        onVoiceSend={handleVoiceSend}
        group={chat.groupToken && groupInfo ? {
          isCreator: groupInfo.isCreator,
          epoch: groupInfo.epoch,
          fingerprint: groupInfo.fingerprint,
          members: groupInfo.members,
          busy: groupBusy,
          onRotate: handleRotateGroup,
          onEvict: handleEvictMember,
          // b71 (audit F-07): join requests for the creator to approve or decline
          pendingRequests: groupInfo.isCreator && groupClaims?.groupToken === chat.groupToken ? groupClaims.rows : [],
          onApproveRequest: handleApproveGroupClaim,
          onDeclineRequest: handleDeclineGroupClaim,
        } : undefined}
      />
      {/* b148: chat is an early-return branch — the overlay must mount here too,
          else the call rings "behind" the thread and only shows after backing out. */}
      {appPromptShown}<CallOverlay /><PrivacyCover />
      </>
    );
  }

  if (screen === 'welcome') {
    return (
      <>
      <WelcomeScreen
        veilId={decoyMode ? decoyVeilId : (identity ? identity.veilId : null)}
        onRunCheckup={() => { setOnboardingMode('checkupOnly'); setScreen('onboard'); }}
        onViewIntro={() => { setOnboardingMode('introOnly'); setScreen('onboard'); }}
        onHide={handleHideWelcome}
        onBack={() => setScreen('main')}
      />
      {appPromptShown}<CallOverlay /><PrivacyCover />
      </>
    );
  }

  return (
    <>
    <MainScreen
      welcomeVisible={!decoyMode && !!identity && !settings.welcomeDismissed}
      onOpenWelcome={() => setScreen('welcome')}
      app={app} /* b77t (audit 5 M-E): in a decoy session, the decoy's own account (b70 re-review 5: never the real stores) */
      decoyMode={decoyMode}
      veilId={decoyMode ? decoyVeilId : (identity ? identity.veilId : null)}
      email={decoyMode ? null : (email || null)}
      busy={busy}
      /* b70 (re-review 5): with an app lock set (or in decoy mode) the header button
         opens Settings, where signing out asks for the password like everywhere else */
      onHeaderSignOut={() => { if (appLockRef.current || decoyModeRef.current) setTab('settings'); else void handleSignOut().catch((e) => setError(friendlyError(e, 'sign-out'))); }}
      onSignOut={handleSignOut} /* the Settings row: it has already asked for the password (re-review 6: the header handler here made it do nothing) */
      sessions={sessionRows} /* b77t (M-E): the account in use (the switch empties it; a late pass from the other account is dropped) */
      onRefreshSessions={refreshSessions}
      onOpenSession={handleOpenSession}
      onNewSession={() => setTab('contacts')}
      onCreateInvite={async () => {
        // b77t (audit 5 M-E): on the decoy's own account in a decoy session
        if (!app || !identity) throw new Error('Create your Vardum identity first — Settings → Identity.');
        const who = await clientId();
        if (!who) throw new Error('Sign in first.');
        const link = (await createInviteSession(
          { sessions: pinToWipe(app.sessions), relay: app.relay, webBaseUrl: VEIL_LINK_URL }, // b70 (re-review 9): a wipe while this waits on the relay stops its writes
          {
            clientId: who,
            dials: {
              burnAfterOpen: chatSettings.burnTtlSeconds > 0,
              expireAfterSeconds: chatSettings.expireAfterSeconds,
              keyRetentionHours: chatSettings.retentionHours,
              // b92 F-S6 (settings sweep, live-confirmed on relay rows created
          // 20:55 Sept 20): was hardcoded 3600 — the burn dial silently
          // became a 1-hour burn window on every invite-link + group thread.
          defaultTtlSeconds: chatSettings.burnTtlSeconds,
            },
            displayName: chatSettings.nickname || '',
          },
        )).link;
        await refreshSessions();
        return link;
      }}
      onJoinInvite={handleJoinInvite}
      contacts={contactRows} /* b77t (M-E): the account in use */
      contactsError={contactsError}
      onLookup={handleLookup}
      onPin={handlePin}
      onUnpin={handleUnpin}
      onMessage={handleMessage}
      onVerify={handleVerifyPin}
      onSetNickname={handleNickname}
      onCreateGroup={handleCreateGroup}
      onOpenContact={handleOpenContact}
      myGroups={myGroups} /* b77t (audit 5 M-E): the account in use's groups (refreshMyGroups reads `app`: the decoy's own in a decoy session) */
      onAddGroupPeople={handleAddGroupPeople}
      prefillAdd={prefillAdd}
      blockedIds={decoyMode ? [] : [...blockedIds]}
      onUnblock={handleUnblock}
      tab={tab}
      onTab={setTab}
      settings={decoyMode ? decoySettings : settings}
      onSettingsChange={handleSettingsChange}
      onRunCheckup={() => { setOnboardingMode('checkupOnly'); setScreen('onboard'); }}
      onCreateTransfer={async (code: string) => {
        if (!app) throw new Error('App is not ready yet — try again in a moment.');
        requireSensitive(); // b70 (audit VAR-02): never from decoy mode, always after the real password
        // b70 (re-review P3): freeze before the bundle copies the chats, so none
        // can move on between the copy and the send
        const allTokens = await app.sessions.listTokens();
        app.sessions.freezeMoving(allTokens);
        const deps = { sessions: app.sessions, vault: app.vault, relay: app.relay, storage: app.storage };
        let p: PreparedMove;
        try {
          p = await prepareMove(deps, code);
        } catch (e) {
          app.sessions.unfreezeMoving(allTokens);
          throw e;
        }
        app.sessions.unfreezeMoving(allTokens.filter((x) => !p.sessionTokens.includes(x)));
        let done = false;
        return {
          sas: p.sas, sessionCount: p.sessionCount, groupsKept: p.groupsKept,
          // b75 (audit XF-1): sent only after the user saw the same code on both phones
          confirm: async () => {
            if (done) return;
            done = true;
            try {
              await confirmMove(deps, p);
            } catch (e) {
              // b75 (audit XF-4): once the move is recorded the relay may hold the bundle,
              // so the chats stay paused and the move is settled like any other
              const rec = (await loadPendingTransfers(app.storage)).find((x) => x.token === p.token);
              if (!rec) { app.sessions.unfreezeMoving(p.sessionTokens); throw e; }
              void settleMove(rec).catch(() => undefined);
              throw new Error(`Vardum couldn\u2019t confirm that the chats were sent (${String((e as Error).message || e)}). They stay paused on this phone until your new phone confirms, or until you choose to keep them here (Vardum asks within about ${Math.round(MOVE_PAUSE_CAP_MS / 60_000)} minutes).`);
            }
            const rec = (await loadPendingTransfers(app.storage)).find((x) => x.token === p.token);
            if (rec) void settleMove(rec).catch(() => undefined);
          },
          cancel: async () => {
            if (done) return;
            done = true;
            await cancelMove(deps, p);
            app.sessions.unfreezeMoving(p.sessionTokens);
          },
        };
      }}
      onReceiveTransfer={async () => {
        if (!app) throw new Error('App is not ready yet — try again in a moment.');
        requireSensitive(); // b70 (audit VAR-05/16)
        const deps = { sessions: app.sessions, vault: app.vault, relay: app.relay, storage: app.storage };
        // b75 (audit XF-1 / XF-2): fresh keys for this screen only; only a bundle encrypted
        // to them, from a phone holding this Vardum ID's identity key, is accepted
        const s = await startReceive(deps);
        return {
          code: s.code,
          offer: () => waitForOffer(deps, s),
          finish: async () => {
            const r = await receiveMove(deps, s, {
              // b70 (audit VAR-05): moved chats must agree with this phone's pinned keys
              pinnedIk: async (veilId: string) => (await app.pins.getPin(veilId))?.ikPubB64 ?? null,
            });
            if (transferQuiet()) return r; // b70 (re-review 11): nothing shown or loaded after a wipe / in decoy / over the lock
            refreshSessions();
            if (r.conflicts) Alert.alert('Some chats were not moved', r.conflicts === 1 ? 'One chat in the transfer did not match the safety key you pinned for that contact, so it was left out.' : `${r.conflicts} chats in the transfer did not match the safety keys you pinned for those contacts, so they were left out.`);
            // Batch G (R5-3-03): something wasn't saved — no ack went out, so the old phone keeps its chats
            if (r.incomplete) Alert.alert('Not everything was saved', 'This phone could not save everything from the transfer, so your old phone keeps its chats. Free up space here, then start the move again on both phones.');
            // Batch H (round-6 review R6-1-04): imported, but the old phone keeps its copy
            else if (r.ackHeld === 'already-here') Alert.alert('Your old phone keeps its chats', 'Some of these chats were already on this phone (or didn\u2019t match a key you pinned), so your old phone keeps its copy. On the old phone, Vardum asks what to do with them within about half an hour.');
            return r;
          },
          cancel: () => cancelReceive(deps, s),
        };
      }}
      getLastMove={decoyMode ? undefined : getLastMove} /* b70 (re-review 5): never the real move record in decoy mode */
      appLockEnabled={!!appLock && !(decoyMode && decoyLockHidden)}
      onSetAppLock={handleSetAppLock}
      onRemoveAppLock={handleRemoveAppLock}
      onCheckPassword={handleCheckPassword}
      onDuress={runDuressNow}
      onLockNow={handleLockNow}
      onWipeDevice={handleWipeDevice}
      onDeleteAccount={handleDeleteAccount}
      onViewIntro={() => { setOnboardingMode('introOnly'); setScreen('onboard'); }}
      webBaseUrl={VEIL_SITE_URL}
      onVerifyPhrase={handleVerifyPhrase}
      onSwitchToPhraseSignIn={handleSwitchToPhraseSignIn}
      onSignOutOtherDevices={handleSignOutOtherDevices} /* b77s (owner decision): refused in decoy mode by requireSensitive */
      onChangeAccountPassword={handleChangeAccountPassword}
      onRemoveIdentity={handleRemoveIdentity}
      onGenerateNewVeilId={handleGenerateNewVeilId}
      regLock={decoyMode ? undefined : regLock} /* b76 (registration lock): never the real account's lock in decoy mode */
      onRegLockRefresh={decoyMode ? undefined : refreshRegLock}
      onRegLockSet={handleRegLockSet}
      onRegLockOff={handleRegLockOff}
      opkElsewhereSince={decoyMode ? undefined : opkElsewhereSince} /* b76r1 (audit P-4) */
      onOpkReclaim={decoyMode ? undefined : handleOpkReclaim}
      onPushServiceChosen={decoyMode ? undefined : async () => { await registerPushHook?.(); } /* audit VAR-17 */}
      onCreateIdentity={handleOpenIdentityFlow}
      securePrompt={securePrompt && !decoyMode} /* b70 (re-review 9): the real account's card is a tell in decoy mode */
      onDismissSecurePrompt={() => setSecurePrompt(false)}
    />
    {/* b144 W3: encrypted-call surface — rings over any screen */}
    {appPromptShown}<CallOverlay /><PrivacyCover />
    </>
  );
}

const styles = StyleSheet.create({
  safeArea: { flex: 1, backgroundColor: '#0B0B0F' },
  boot: { flex: 1, backgroundColor: '#0B0B0F', alignItems: 'center', justifyContent: 'center', padding: 24 },
  bootText: { color: '#5E6464', marginTop: 14, fontSize: 13, letterSpacing: 1 },
  errTitle: { color: '#ff6b6b', fontSize: 16, fontWeight: '700', marginBottom: 16, textAlign: 'center' },
  errText: { color: '#8E9696', fontSize: 11, lineHeight: 16, textAlign: 'left' },
});

class VeilErrorBoundary extends React.Component<{ children: React.ReactNode }, { msg: string | null }> {
  state: { msg: string | null } = { msg: null };
  static getDerivedStateFromError(e: unknown) {
    // audit VAR-64: release builds show fixed text and an opaque id, never the raw error or stack
    const cid = crashId();
    console.log(`[veil-crash] ${cid}: ${String((e as Error)?.message || e)}`);
    return { msg: crashScreenText(e, __DEV__, cid) };
  }
  render() {
    if (this.state.msg) {
      return (
        <View style={styles.boot}>
          <Text style={styles.errTitle}>{__DEV__ ? 'Vardum hit an error — please screenshot this' : 'Vardum hit an error'}</Text>
          <Text style={styles.errText}>{this.state.msg}</Text>
        </View>
      );
    }
    return this.props.children;
  }
}


const DEFAULTS = normalizeSettings(null);

/** 21 Oct 2026 (build 67, owner: "a tiny bit too stretched"): targeting API 36
 *  makes Android draw behind the status and navigation bars, and
 *  react-native's SafeAreaView is iOS-only. On Android the root pads itself by
 *  the real insets instead. */
function AndroidSafeRoot({ children }: { children: React.ReactNode }) {
  const insets = useSafeAreaInsets();
  return (
    <View
      style={[styles.safeArea, { paddingTop: insets.top, paddingBottom: insets.bottom, paddingLeft: insets.left, paddingRight: insets.right }]}
      onStartShouldSetResponderCapture={() => { veilActivityPing(); return false; }}
    >
      {children}
    </View>
  );
}

export default function App() {
  if (Platform.OS === 'android') {
    return (
      <SafeAreaProvider>
        <AndroidSafeRoot>
          <VeilErrorBoundary>
            <VeilApp />
          </VeilErrorBoundary>
        </AndroidSafeRoot>
      </SafeAreaProvider>
    );
  }
  return (
    // BUG FIXED (Sept 19): no screen accounted for the notch / Dynamic Island
    // safe area, so header content (e.g. Settings/Sign-out in the top-right)
    // rendered too high and got visually clipped by the status bar on iPhones
    // with a notch or Dynamic Island. react-native's own SafeAreaView is
    // iOS-native (no extra pod, no rebuild) and covers every screen from here.
    <SafeAreaView
      style={styles.safeArea}
      // (b66) CAPTURE phase: the non-capture responder was skipped whenever a
      // child (TouchableOpacity, keypad, composer…) claimed the touch, so
      // taps on actual controls never reset the inactivity clock and the
      // passcode gate fired while the app was actively in use. Capture fires
      // for EVERY touch before any child can claim it.
      onStartShouldSetResponderCapture={() => { veilActivityPing(); return false; }}
    >
      <VeilErrorBoundary>
        <VeilApp />
      </VeilErrorBoundary>
    </SafeAreaView>
  );
}
