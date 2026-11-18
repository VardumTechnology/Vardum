/**
 * Contentless push plumbing — iOS 1.0.
 *
 * VEIL's threat model: the push channel must leak NOTHING about who or what.
 * The APNs payload carries no sender, no ciphertext, no session token — the
 * client wakes, polls its own sessions over the encrypted relay, and shows a
 * generic local banner. Server side, the relay's push trigger sends the SAME
 * generic ping regardless of which peer/session/message fired it.
 */
import * as Notifications from 'expo-notifications';
import Constants from 'expo-constants';
import { Platform } from 'react-native';
import { CallManager } from './calls/CallManager';
import { withSystemSheet } from './lock-hold';
import { isUnifiedPushAvailable, unifiedPushChosen, ensureEndpoint, storedEndpoint, unregisterUnifiedPush, upTokenFor, UP_TOKEN_PREFIX, migratePushChoice } from './unifiedpush';
import type { WakeTarget } from '../vendor/crypto-core/src/wake';

/** b77p round 2 (owner decision 1, 31 Oct): this phone's push address, kept ON THE PHONE ONLY (the wake boxes it seals
 *  into its own inbound mailboxes read it through currentWakeTarget). v4: there is no account push row any more; the
 *  first run of this build retires any row an earlier build registered (registerPushToken). */
export const PUSH_CACHE_KEY = 'veil_push_target_v4';
/** the keys earlier builds cached the registered address under (b77p round 2, review M1: only a sign that an earlier
 *  build ran, so its rows are retired; the addresses themselves are never sent) */
const OLD_PUSH_CACHE_KEYS = ['veil_push_token_cached_v3', 'veil_push_token_cached_v2', 'veil_push_token_cached'];
/** b77p round 2: '1' once this phone's earlier account push rows are gone (a veil_ key: every wipe clears it) */
export const PUSH_ROWS_RETIRED_KEY = 'veil_push_rows_retired_v1';
/** b77p (audit 2 VAR-14): the ONE banner every kind shows — message, call, invite, remote or local, foreground or
 *  not (the relay's push text is the same words; VardumNotifier too) */
export const BANNER_TITLE = 'Vardum';
export const BANNER_BODY = 'Notification';

/** b77p round 2 (owner decision 2): a call wake RINGS. The relay names this channel (Android) and this sound (iOS)
 *  on call wakes only (relay/main.ts RING_CHANNEL / RING_SOUND); the banner text stays BANNER_TITLE / BANNER_BODY.
 *  The sound file is bundled through the expo-notifications plugin's "sounds" (app.json); VardumNotifier.kt (the
 *  UnifiedPush path) uses the same channel id. */
export const RING_CHANNEL_ID = 'vardum-ring';
export const RING_SOUND = 'veil_ring.wav'; // b77 rollout: Android raw resource names allow only a-z, 0-9 and _

// b199 ANDROID CHANNELS (Android handover TODO, owner OK Oct 17). Android
// shows a push only as loudly as its channel allows, and a channel's
// importance AND SOUND are fixed once created on a device — so they are made
// here, at module load, before the first push can arrive. 'default' is what
// Expo uses for any push without a channelId (messages): HIGH, so it heads-up
// like the iOS banner. b77p round 2 (owner decision 2): call wakes name
// RING_CHANNEL_ID ('vardum-ring', MAX, the ring sound). It replaces 'calls',
// which was made without a sound and can't be given one (deleted here).
// Lock-screen text is the one contentless "Vardum / Notification", so PUBLIC
// visibility leaks nothing. iOS ignores all of this (the APNs payload names
// the sound).
if (Platform.OS === 'android') {
  void Notifications.setNotificationChannelAsync('default', {
    name: 'Messages',
    importance: Notifications.AndroidImportance.HIGH,
    lockscreenVisibility: Notifications.AndroidNotificationVisibility.PUBLIC,
    vibrationPattern: [0, 250, 250, 250],
  }).catch(() => undefined);
  void Notifications.setNotificationChannelAsync(RING_CHANNEL_ID, {
    name: 'Calls',
    importance: Notifications.AndroidImportance.MAX,
    lockscreenVisibility: Notifications.AndroidNotificationVisibility.PUBLIC,
    vibrationPattern: [0, 600, 800, 600, 800],
    sound: RING_SOUND,
    bypassDnd: false,
  }).catch(() => undefined);
  void Notifications.deleteNotificationChannelAsync('calls').catch(() => undefined);
}


// b77 FIX: the handler below used to return the SAME suppressed result for
// every notification, remote or local. The remote APNs wake-ping (contentless,
// fired on every VeilEnvelope insert including cover-traffic decoys) is
// correctly silent by design — but that blanket suppression also silently ate
// the LOCAL "new message" banner scheduled by notifyNewMessage() below,
// after this device had actually decrypted a real message. Net effect:
// notifications never showed at all, foreground or background. (b198: the
// blanket suppression below is retired — see the new posture comment.)
// b198 (owner report: no lock-screen notifications): the OLD posture suppressed
// ALL remote pings and showed a LOCAL banner only after a background wake →
// sync → decrypt cycle. That chain requires the OS to background-wake the app
// on the silent ping — which Metro/dev-client builds cannot do, so the lock
// screen showed NOTHING. On this relay the ping fires ONLY on real text/media
// sends (notifySent — never for cover traffic), so the old reason for the
// suppression is gone: the remote ping itself is now the visible, CONTENTLESS
// lock-screen notification (no sender, no session, no content).
// b77p round 2 (owner decision 1): the push-verify flow (b71 F-19 / b74 VAR-13: a silent code proving this phone
// receives its address, so the relay would accept its ACCOUNT push row) is gone with the account push row. A
// 'push-verify' push that still arrives (from a relay serving a pre-b77p phone during the transition window) is
// dropped silently below and used for nothing.

Notifications.setNotificationHandler({
  handleNotification: async (notification) => {
    const d = notification.request.content.data as { veilLocal?: boolean; kind?: string; code?: string } | null;
    // b71 (audit F-19): the relay's silent push-verify code — never shown (b77p round 2: and no longer used)
    if (d?.kind === 'push-verify') {
      return { shouldShowAlert: false, shouldPlaySound: false, shouldSetBadge: false };
    }
    // b198 CALL RING BURST: call pushes (kind 'call', body "Incoming call")
    // display like messages UNTIL the call connects — once the ringing
    // overlay or the call itself is up, the remaining burst banners go silent
    // (the in-call ring + vibration take over; banners would stack over the
    // call UI).
    let callLive = false;
    try { const s = CallManager.snapshot(); callLive = !!s && (s.phase === 'ringing' || s.phase === 'connecting' || s.phase === 'active' || s.phase === 'calling'); } catch { /* no call state */ }
    // b70 (re-review): in decoy mode the real account's pings stay hidden too
    // while the app is open (in the background the OS shows server pushes itself)
    // b77p (audit 2 VAR-35): every relay push now says kind 'wake' (providers can't tell a call from a message);
    // 'new-message' / 'call' are what an older relay sent
    const remoteActivity = d?.kind === 'wake' || d?.kind === 'new-message' || d?.kind === 'call';
    const show = !localNotifySuppressed && (d?.veilLocal === true || (remoteActivity && !callLive));
    if (d?.kind === 'wake' || d?.kind === 'new-message') lastRemotePingAt = Date.now();
    // b75 round 2 (audit D7): a remote push's title and body are whatever the relay put in
    // the payload. In the foreground the app never shows that text: the remote banner is
    // dropped and the app shows its own fixed one (in the background the OS shows the
    // payload itself; the relay sends only fixed neutral text, spec 8.2)
    if (show && d?.veilLocal !== true) {
      void showFixedBanner();
      return { shouldShowAlert: false, shouldShowBanner: false, shouldShowList: false, shouldPlaySound: false, shouldSetBadge: false };
    }
    return {
      shouldShowAlert: show,
      shouldShowBanner: show,
      shouldShowList: show,
      shouldPlaySound: show,
      shouldSetBadge: false,
    };
  },
});

/** b75 round 2 (audit D7): the app's own text for a remote push shown in the foreground */
export const FIXED_BANNER = { title: BANNER_TITLE, body: BANNER_BODY } as const; // b77p (VAR-14): was 'New activity'
async function showFixedBanner(): Promise<void> {
  try {
    await Notifications.scheduleNotificationAsync({ content: { ...FIXED_BANNER, data: { veilLocal: true } }, trigger: null });
  } catch { /* notifications are best-effort */ }
}

/** b198: when a remote ping just landed, the local post-decrypt banner would
 *  double-fire behind it — skip the local one for a short window. */
let lastRemotePingAt = 0;
const REMOTE_PING_DEDUP_MS = 30_000;

/** Rate limit for local new-message banners (ms). */
const NOTIFY_MIN_INTERVAL_MS = 15_000;
let lastNotifyAt = 0;

/**
 * Generic local banner for an actual new chat message found by polling.
 * Carries no sender, no content, no session — same threat model as the ping.
 * Rate-limited so a burst of arrivals (or a peer's cover stream) can't spam.
 */
/** Rate limit for invite banners (ms) — independent of message banners. */
const NOTIFY_INVITE_MIN_INTERVAL_MS = 30_000;
let lastInviteNotifyAt = 0;

/**
 * b178: generic local banner when a NEW invite session appears on the poll
 * (owner report: invites arrived with zero notification, foreground or
 * background). Same contentless rule as the message banner — no sender,
 * no session identity — the body only says an invite exists. Suppression on
 * the lock screen still requires the server-side VeilSession push trigger
 * (see the b178 note in App.tsx refreshSessions).
 */
export async function notifyNewInvite(): Promise<void> {
  try {
    const now = Date.now();
    if (localNotifySuppressed) return;
    if (now - lastInviteNotifyAt < NOTIFY_INVITE_MIN_INTERVAL_MS) return;
    lastInviteNotifyAt = now;
    await Notifications.scheduleNotificationAsync({
      content: { title: BANNER_TITLE, body: BANNER_BODY, data: { veilLocal: true } }, // b77p (audit 2 VAR-14): was 'New chat invite'
      trigger: null,
    });
  } catch { /* notifications are best-effort */ }
}

export async function notifyNewMessage(): Promise<void> {
  try {
    if (localNotifySuppressed) return;
    const now = Date.now();
    if (now - lastRemotePingAt < REMOTE_PING_DEDUP_MS) return; // the visible remote ping already covered this
    if (now - lastNotifyAt < NOTIFY_MIN_INTERVAL_MS) return;
    lastNotifyAt = now;
    await Notifications.scheduleNotificationAsync({
      content: { title: BANNER_TITLE, body: BANNER_BODY, data: { veilLocal: true } },
      trigger: null,
    });
  } catch { /* notifications are best-effort */ }
}

export async function ensurePushPermission(): Promise<boolean> {
  try {
    const cur = (await Notifications.getPermissionsAsync()) as unknown as { status: string; canAskAgain?: boolean };
    if (cur.status === 'granted') return true;
    // ask ONCE: after a denial never re-prompt automatically (the OS keeps
    // its answer; repeated requests are the "endless permission prompts").
    // b199 (ZTE device run): Android 13+ reports "denied" BEFORE the first
    // ask, with canAskAgain=true — that is "never asked", not a refusal, and
    // reading it as a refusal meant Android never showed the prompt at all.
    if (cur.status === 'denied' && cur.canAskAgain === false) return false;
    if (cur.status === 'denied' && Platform.OS !== 'android') return false;
    const req = (await withSystemSheet(() => Notifications.requestPermissionsAsync())) as unknown as { status: string };
    return req.status === 'granted';
  } catch { return false; }
}

/** Relay + keychain shapes (injected — keeps this module pure for tests). */
export interface PushRegistrationDeps {
  /** Batch H (round-6 review R6-3-09): relay functions (veilPushReset) */
  invoke?: (fn: string, payload: Record<string, unknown>) => Promise<unknown>;
  /** b77p round 2: unused (no push row is ever created); kept optional for callers that still pass it */
  entityCreate?: (entity: string, record: Record<string, unknown>) => Promise<unknown>;
  /** user-scoped entity LIST (own rows only) — finds a row an earlier build registered */
  entityList: (entity: string, params: Record<string, string | number>) => Promise<unknown>;
  /** b77p round 2: deletes that row (account-level push is gone) */
  entityDelete?: (entity: string, id: string) => Promise<unknown>;
  getCached: (key: string) => Promise<string | null>;
  setCached: (key: string, value: string) => Promise<unknown>;
  /** b75 round 2 (audit D6): false once a wipe has happened since this registration
   *  started (it then stops, and undoes a distributor registration it made) */
  stillValid?: () => boolean;
  /** tests: where this phone's pushes go, instead of asking the OS / the distributor */
  resolveTarget?: () => Promise<{ token: string; extra?: Record<string, string> } | null>;
}

/** b77p round 2 (review M1): deletes every push row of the signed-in account. Listed with NO filter: the relay's list
 *  of an owner-scoped entity answers the caller's own rows only (relay/main.ts listEntity), so no request names a push
 *  address (looking rows up by expo_token told a logging relay "this account owns this address", the address every
 *  wake box carries, §12.19.1). Throws when the relay can't be reached. */
async function deleteOwnPushRows(relay: PushRegistrationDeps): Promise<void> {
  const listed = (await relay.entityList('VeilPushToken', {})) as unknown;
  const rows = (Array.isArray(listed) ? listed : ((listed as { data?: unknown[] })?.data ?? [])) as Record<string, unknown>[];
  for (const r of rows) if (r.id && relay.entityDelete) await relay.entityDelete('VeilPushToken', String(r.id));
}

/** b77p round 2 (owner decision 1): deletes every account push row an earlier build of this phone registered — the
 *  account's own rows (deleteOwnPushRows), and by its install id (veilPushReset). Best effort (offline: the next
 *  registration tries again, and the relay drops every push row when the transition window ends anyway). Never makes
 *  a device id. b77p round 2 (review M1): never sends an address, and runs only when an earlier build left a trace
 *  (an old cached address or an install id); a fresh install makes no request at all. Once done, those traces go. */
async function retireAccountPushRows(relay: PushRegistrationDeps): Promise<boolean> {
  let earlier = false;
  for (const k of OLD_PUSH_CACHE_KEYS) { try { if (await relay.getCached(k)) earlier = true; } catch { /* none */ } }
  let deviceId: string | null = null;
  try { deviceId = await relay.getCached(PUSH_DEVICE_KEY); } catch { /* none */ }
  if (!earlier && !deviceId) return true; // no earlier build on this phone: nothing to retire
  let ok = true;
  try { await deleteOwnPushRows(relay); } catch { ok = false; }
  try {
    if (deviceId && relay.invoke) await relay.invoke('veilPushReset', { device_id: deviceId });
  } catch { ok = false; }
  if (ok) for (const k of [...OLD_PUSH_CACHE_KEYS, PUSH_DEVICE_KEY]) await relay.setCached(k, '').catch(() => undefined);
  return ok;
}

/**
 * b77p round 2 (owner decision 1, 31 Oct): NO ACCOUNT PUSH ROW. This used to register the phone's push address with
 * the relay as a VeilPushToken row tied to the account (for contact-request and group-post pushes); a relay that
 * logs its pushes could then tie the account to the same address the phone's mailbox wake boxes carry. Now
 * "registering" is local: resolve where this phone's pushes go (the UnifiedPush distributor the user chose, else the
 * Expo token), keep it under PUSH_CACHE_KEY — every inbound's sealed wake box follows it (vendor/device sealed.ts
 * bindWake re-seals when it changes) — and retire any account row an earlier build made. Nothing is created on the
 * relay. Contact requests and group messages show when the app next opens or is woken by a chat.
 * Returns true once the address is known (and cached).
 */
export async function registerPushToken(relay: PushRegistrationDeps): Promise<boolean> {
  // b75 round 2 (audit D6): a wipe while this waited (on the OS, the distributor or the
  // relay) ends it; a UnifiedPush registration made meanwhile is released again
  const wiped = (t?: { token: string } | null): boolean => {
    if (!relay.stillValid || relay.stillValid()) return false;
    if (t?.token?.startsWith(UP_TOKEN_PREFIX)) { try { unregisterUnifiedPush(); } catch { /* best-effort */ } }
    console.log('[veil-push] registration overtaken by a wipe — stopped');
    return true;
  };
  try {
    // b77m review (L7): a distributor saved by a build before b77m (its silent auto-pick) is not a choice
    if (Platform.OS === 'android') await migratePushChoice({ get: relay.getCached, set: relay.setCached }).catch(() => undefined);
    const target = relay.resolveTarget ? await relay.resolveTarget() : await resolvePushTarget();
    if (wiped(target)) return false;
    const token = target?.token ?? null;
    if (!token) {
      console.log('[veil-push] registerPushToken: no push address available — wakes stay off');
      return false;
    }
    const known = (await relay.getCached(PUSH_CACHE_KEY)) === token;
    if (known && (await relay.getCached(PUSH_ROWS_RETIRED_KEY)) === '1') return true; // nothing left to do
    // an account row an earlier build registered goes (the account's own rows and by install id; no address is sent,
    // review M1); a failure is retried at the next registration (the wakes don't wait for it: the address is kept either way)
    const retired = await retireAccountPushRows(relay);
    if (wiped(target)) return false;
    if (!known) await relay.setCached(PUSH_CACHE_KEY, token);
    if (retired) await relay.setCached(PUSH_ROWS_RETIRED_KEY, '1');
    console.log(`[veil-push] push address kept on this phone for its wake boxes${retired ? '' : ' (an older account row could not be removed yet — retried at the next registration)'}`);
    return true;
  } catch (e) {
    console.log(`[veil-push] registerPushToken FAILED: ${(e as Error).message ?? e}`);
    return false;
  }
}

/**
 * b77p (audit 2 VAR-01): where this phone's mailbox wakes go — sealed by the device library into each of its own
 * inbound mailboxes (vendor/device/src/sealed.ts bindWake, crypto-core wake.ts). Read without asking the OS (no
 * prompt): the UnifiedPush endpoint and its Web Push keys from the app's own store, else the registered Expo token.
 * null = unknown (nothing registered yet): the device library then changes nothing. b77's push_refs, which this
 * phone's ACCOUNT push row listed (so the relay joined every inbound mailbox to the account), are gone.
 */
export async function currentWakeTarget(getCached: (key: string) => Promise<string | null>): Promise<WakeTarget | null> {
  try {
    const upEp = Platform.OS === 'android' ? storedEndpoint() : null;
    if (upEp) return { t: upTokenFor(upEp), ...(upEp.pubKey ? { p: upEp.pubKey } : {}), ...(upEp.auth ? { a: upEp.auth } : {}) };
    const token = await getCached(PUSH_CACHE_KEY);
    return token ? { t: token } : null;
  } catch { return null; }
}

/**
 * b95 NaR v2: remove this device's push registration from the relay so a
 * wiped (Nothing-at-Rest) device goes SILENT — no lock-screen banners, no
 * APNs pings — until the identity is restored from the 24-word phrase, at
 * which point the registration effect in App.tsx re-registers it.
 * Server-side the rows are user-scoped, so deleting own rows is authorized.
 */
/**
 * Batch G (round-5 review R5-3-04): the wipe-time unregister. It uses ONLY the
 * token cached at registration: no permission request and no fresh token from
 * the OS, so a duress wipe never raises a system prompt. No cached token, nothing to do.
 */
/** Batch H (round-6 reviews R6-1-01 / R6-3-10): what a wipe unregisters, read
 *  BEFORE the local wipe deletes the cached token. */
export interface PushTarget { token: string; up: boolean; /** Batch H (R6-3-09) */ deviceId?: string }

/** Batch H (round-6 review R6-3-09): a random id for this install's push rows, so
 *  the phone can remove its own earlier rows. b70: a Nothing-at-Rest wipe drops it
 *  (after unregistering), so rows before and after a wipe can't be linked.
 *  b77p round 2: only READ now (an earlier build's rows are retired by it); no new one is made. */
export const PUSH_DEVICE_KEY = 'veil_push_device_v1';

/** Batch H (R6-3-08): log the push host, never the endpoint (the topic is a capability) */
function pushHostOf(url: string): string {
  try { return new URL(url).host; } catch { return '?'; }
}

/** Batch H: read this phone's push target without asking the OS (no prompt):
 *  the UnifiedPush endpoint from the app's own store, else the cached token. */
export async function capturePushTarget(getCached: (key: string) => Promise<string | null>): Promise<PushTarget | null> {
  try {
    const upEp = Platform.OS === 'android' ? storedEndpoint() : null;
    const deviceId = (await getCached(PUSH_DEVICE_KEY).catch(() => null)) || undefined;
    if (upEp) return { token: upTokenFor(upEp), up: true, deviceId };
    let token = (await getCached(PUSH_CACHE_KEY)) || '';
    for (const k of OLD_PUSH_CACHE_KEYS) if (!token) token = (await getCached(k)) || ''; // an earlier build's address
    return token || deviceId ? { token, up: false, deviceId } : null;
  } catch { return null; }
}

/**
 * b75 (audit AL-7): turn this phone's push delivery off locally, with no network:
 * the UnifiedPush distributor registration and the OS push token (APNs / FCM). A
 * relay row that could not be deleted then points at a dead address, so a wiped
 * phone shows no "Vardum" banner. The next registration (a new identity) turns it
 * back on. Never prompts.
 */
export async function unregisterPushLocally(): Promise<void> {
  try { unregisterUnifiedPush(); } catch { /* best-effort */ }
  try { await Notifications.unregisterForNotificationsAsync(); } catch { /* not registered / unsupported */ }
}

/** b75 (audit DEV-L3): release only the OS push token (Expo / APNs / FCM), locally, no
 *  network. Decoy mode uses it; UnifiedPush keeps its registration and is silenced instead. */
export async function releaseOsPushToken(): Promise<void> {
  await Notifications.unregisterForNotificationsAsync();
}

/** b75 (AL-7): resolves true once the relay side is done (rows deleted, or none to
 *  delete), false when the relay could not be reached — the wipe then keeps its
 *  unregister-pending marker. */
export async function unregisterCachedPushToken(relay: PushRegistrationDeps & {
  entityDelete: (entity: string, id: string) => Promise<unknown>;
}, target?: PushTarget | null): Promise<boolean> {
  // a wipe passes the target it read before wiping; other callers read it now
  const t = target !== undefined ? target : await capturePushTarget((k) => relay.getCached(k));
  // Batch H (R6-1-03 = R6-3-02): release the UnifiedPush registration FIRST. It is
  // local and needs no network, so an offline or slow wipe still leaves no live
  // push address (it used to run only after the relay answered).
  if (t?.up) { try { unregisterUnifiedPush(); } catch { /* best-effort */ } }
  // b75 (AL-7): and the OS push token too (Expo / APNs / FCM), for the same reason
  if (t) { try { await Notifications.unregisterForNotificationsAsync(); } catch { /* not registered / unsupported */ } }
  let relayOk = true;
  // b77p round 2 (review M1): the account's own rows, listed with no filter (looking them up by expo_token named this
  // phone's push address next to its account)
  try {
    if (t?.token || t?.deviceId) await deleteOwnPushRows(relay);
  } catch { relayOk = false; }
  // Batch H (R6-3-09): and every earlier row of this phone (an older token or endpoint)
  if (t?.deviceId && relay.invoke) { try { await relay.invoke('veilPushReset', { device_id: t.deviceId }); } catch { relayOk = false; } }
  // after a wipe the cached markers are already gone; don't write them back
  if (target === undefined) {
    for (const k of [...OLD_PUSH_CACHE_KEYS, PUSH_CACHE_KEY, PUSH_ROWS_RETIRED_KEY]) await relay.setCached(k, '').catch(() => undefined);
  }
  return relayOk;
}

export async function unregisterPushToken(relay: PushRegistrationDeps & {
  entityDelete: (entity: string, id: string) => Promise<unknown>;
}): Promise<void> {
  try {
    const upEp = Platform.OS === 'android' ? storedEndpoint() : null;
    // b77p round 2 (review M1): the account's own rows, listed with no filter — no push address is sent (this used to
    // ask the OS for the token and look the row up by it)
    await deleteOwnPushRows(relay).catch(() => undefined);
    // cached marker dies too — a later re-register (post phrase-restore) must
    // actually create a fresh row, not skip on the stale cache
    for (const k of [...OLD_PUSH_CACHE_KEYS, PUSH_CACHE_KEY, PUSH_ROWS_RETIRED_KEY]) await relay.setCached(k, '');
    // also drop the distributor registration, so a wiped phone holds no live
    // push address at all; phrase restore registers a fresh one
    if (upEp) unregisterUnifiedPush();
  } catch { /* best-effort: offline wipe retries at next boot */ }
}

/**
 * Where this device's contentless pings should go.
 * Android with a UnifiedPush distributor (ntfy) installed — the GrapheneOS
 * path, no Google — files the distributor endpoint + its Web Push keys.
 * Everything else uses the Expo token as before.
 *
 * The relay row keeps the same shape (expo_token is the lookup key, here
 * "up:<endpoint>"), plus up_* fields the relay uses to send a Web Push
 * (RFC 8030/8291) ping instead of an Expo one.
 */
async function resolvePushTarget(): Promise<{ token: string; extra?: Record<string, string> } | null> {
  // audit VAR-17: only a distributor the user chose (Settings → Push service); never one picked silently
  if (Platform.OS === 'android' && unifiedPushChosen()) {
    if (!(await ensurePushPermission())) {
      console.log('[veil-push] permission not granted — skipping UnifiedPush registration');
      return null;
    }
    const ep = await ensureEndpoint();
    if (!ep) return null;
    console.log(`[veil-push] UnifiedPush endpoint OK (${pushHostOf(ep.url)})`); // Batch H (R6-3-08)
    return {
      token: upTokenFor(ep),
      extra: { transport: 'unifiedpush', up_endpoint: ep.url, up_p256dh: ep.pubKey, up_auth: ep.auth },
    };
  }
  if (Platform.OS === 'android') {
    console.log(isUnifiedPushAvailable()
      ? '[veil-push] a UnifiedPush distributor is installed but none is chosen (Settings → Push service) — trying Expo/FCM'
      : '[veil-push] no UnifiedPush distributor installed (install ntfy for push on GrapheneOS) — trying Expo/FCM');
  }
  const t = await getPushToken();
  return t ? { token: t } : null;
}

/**
 * b124 FIX: getExpoPushTokenAsync() needs an explicit projectId on SDK 52 —
 * without one it throws, and the old catch-and-return-null here made that
 * failure invisible (registerPushToken() below just silently never wrote a
 * row to the relay). Root cause of "no remote push ever arrives": a fresh
 * dev-client install had no linked EAS project, so every registration
 * attempt died at this line with zero trace. Now: read the projectId from
 * app.json (baked in at build time) or the EAS update manifest fallback,
 * and log loudly on failure so this can't go dark again.
 */
function resolveProjectId(): string | null {
  const fromExtra = (Constants.expoConfig?.extra as { eas?: { projectId?: string } } | undefined)?.eas?.projectId;
  const fromEasConfig = (Constants as unknown as { easConfig?: { projectId?: string } }).easConfig?.projectId;
  return fromExtra ?? fromEasConfig ?? null;
}

/** Expo push token for the relay's contentless push trigger. */
export async function getPushToken(): Promise<string | null> {
  try {
    if (!(await ensurePushPermission())) {
      console.log('[veil-push] permission not granted — skipping token fetch');
      return null;
    }
    const projectId = resolveProjectId();
    if (!projectId) {
      console.log('[veil-push] FAILED: no EAS projectId found in app config — run `eas init` and rebuild');
      return null;
    }
    const t = await Notifications.getExpoPushTokenAsync({ projectId });
    const token = (t.data as string) ?? null;
    console.log(`[veil-push] token fetched OK: ${token ? token.slice(0, 24) + '…' : 'null'}`);
    return token;
  } catch (e) {
    console.log(`[veil-push] FAILED to fetch push token: ${(e as Error).message ?? e}`);
    return null;
  }
}



/** b70 (audit VAR-16): decoy mode shows no banners from the real account */
let localNotifySuppressed = false;
export function setLocalNotifySuppressed(on: boolean): void {
  localNotifySuppressed = on;
}
export function localNotifyIsSuppressed(): boolean {
  return localNotifySuppressed;
}

/**
 * b77u (audit 6 W11 / IH device F-03, full I-9): every wipe (duress, Nothing-at-Rest, sign-out, wipe device,
 * self-destruct) clears what Vardum already showed: the delivered "Vardum / Notification" banners (with their
 * times) in the shade / Notification Center, and the badge. Android's cancelAll (expo's dismissAll) covers every
 * notification of the app, the UnifiedPush notifier's too. Best-effort, never throws, never waits.
 */
export function dismissDeliveredNotifications(): void {
  try { void Notifications.dismissAllNotificationsAsync().catch(() => undefined); } catch { /* no module */ }
  try { void Notifications.setBadgeCountAsync(0).catch(() => undefined); } catch { /* no module */ }
}
