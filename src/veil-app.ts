/**
 * Expo shell — the VEIL device context.
 *
 * Everything crypto/storage/relay-shaped comes from the tested pure packages;
 * this file only wires platform pieces and holds app state. No crypto here.
 */
import {
  KeychainStorage, PinStore, IdentityVault, SessionStore, VeilRelay, Base44Auth, SettingsStore, AppLockStore, NotesStore,
} from '../vendor/device/src/index';
import { createRnSecureStore, type RnSecureStoreOptions } from './secure-store.rn';
import { createLockEpochMirror } from './lock-epoch';
import * as FileSystem from 'expo-file-system';
import { toB64, MemoryStorage } from '../vendor/crypto-core/src/index';
import { withRelayClock, relayClockAnswerHook } from './relay-clock';
import { DecoyAux, decoySecureStore } from './decoy-account'; // b77t (audit 5 M-E)

/** b77t (audit 5 L-4): fetch for the relay clients — the same fetch, noting the relay's time from signed-in
 *  answers (relay-clock.ts). Media downloads keep the platform XMLHttpRequest (relay.ts uses it only when it
 *  is passed explicitly once a fetch is injected).
 *  b77t (audit 5 L-4 x L-27): + `onAnswer`: on React Native the JSON relay calls go through that XMLHttpRequest
 *  (L-27), bypassing the wrapped fetch, so the relay client reports every answer to the clock itself. The auth
 *  client (plain fetch) gets the wrapped fetch. */
/** b77t2 (CL-6): the auth client's share of relayTransport: the bounded XHR path on React Native, and every
 *  answer reported to the relay clock */
export function authTransport(t: ReturnType<typeof relayTransport> = relayTransport()): Pick<ConstructorParameters<typeof Base44Auth>[0], 'fetchImpl' | 'xhrImpl' | 'onAnswer'> {
  return { fetchImpl: t.fetchImpl, xhrImpl: t.xhrImpl as ConstructorParameters<typeof Base44Auth>[0]['xhrImpl'], onAnswer: t.onAnswer };
}
export function relayTransport(): { fetchImpl: typeof fetch; xhrImpl: unknown; onAnswer: ReturnType<typeof relayClockAnswerHook> } {
  const xhr = (globalThis as { XMLHttpRequest?: unknown }).XMLHttpRequest;
  return {
    fetchImpl: withRelayClock((input, init) => fetch(input as RequestInfo, init), VEIL_BASE_URL),
    xhrImpl: typeof xhr === 'function' ? xhr : null,
    onAnswer: relayClockAnswerHook(VEIL_BASE_URL),
  };
}

// b198 RELAY FLIP (founder-approved): self-hosted relay behind Caddy TLS.
// Base44 remains the production/TestFlight relay until the staged cutover completes.
// b71: a staging build can point at the staging relay (EXPO_PUBLIC_VEIL_RELAY_URL is
// inlined at build time; only https://<name>.tryveil.app is accepted, anything else is ignored)
const STAGING_RELAY = String(process.env.EXPO_PUBLIC_VEIL_RELAY_URL || '');
export const VEIL_BASE_URL = /^https:\/\/[a-z0-9-]+\.tryveil\.app$/.test(STAGING_RELAY) ? STAGING_RELAY : 'https://relay2.tryveil.app'; // b77 rollout (5 Nov, owner): build 77 runs on its own relay beside the older one; older builds keep relay.tryveil.app until they update
/** b71: true in a build pointed at a non-production relay */
export const VEIL_RELAY_IS_STAGING = VEIL_BASE_URL !== 'https://relay2.tryveil.app';
// b199 (Oct 16): the public website, for Settings' privacy policy, terms and
// Security Centre links. They pointed at the relay, which has no web pages.
export const VEIL_SITE_URL = 'https://tryveil.app';
// b70 (audit VAR-04): links that carry a secret in their fragment (invites,
// group invites, device transfer) are built on the app-link domain, never on
// the relay's own origin, so the relay's web server can't read the fragment.
export const VEIL_LINK_URL = VEIL_SITE_URL;
export let VEIL_APP_ID = '6a9dae3b8bc7a581e4ab310a';
export const setVeilAppId = (id: string) => { VEIL_APP_ID = id; };

export interface VeilApp {
  storage: KeychainStorage;
  auth: Base44Auth;
  pins: PinStore;
  settings: SettingsStore;
  vault: IdentityVault;
  sessions: SessionStore;
  appLock: AppLockStore;
  notes: NotesStore;
  relay: VeilRelay;
}

export async function createVeilApp(secureStoreOpts: RnSecureStoreOptions = {}): Promise<VeilApp> {
  const storage = new KeychainStorage(createRnSecureStore(secureStoreOpts));
  const auth = new Base44Auth({ baseUrl: VEIL_BASE_URL, appId: VEIL_APP_ID, ...authTransport() }, storage); // b77t (audit 5 L-4, b77t2 CL-6): bounded, and its signed-in answers set the relay clock
  // the relay authorizes every gate call with the account session token.
  // bytesToTempFile routes bytes-based uploads (Vault containers, Device
  // Transfer bundles) through a real cache file — RN's FormData cannot
  // construct a Blob from raw bytes (VEIL-P1, Sept 19), but it CAN send a
  // {uri,name,type} part, the same path media sends already use.
  const relay = new VeilRelay({
    baseUrl: VEIL_BASE_URL,
    appId: VEIL_APP_ID,
    getToken: () => auth.getToken(),
    setToken: (t: string) => auth.replaceToken(t), // b77t (audit 5 L-6): the relay rotated this phone's sign-in
    ...(relayTransport() as Pick<ConstructorParameters<typeof VeilRelay>[0], 'fetchImpl' | 'xhrImpl' | 'onAnswer'>), // b77t (audit 5 L-4)
    bytesToTempFile: async (bytes: Uint8Array, name: string) => {
      const uri = `${FileSystem.cacheDirectory}veil-upload-${Date.now()}-${name}`;
      await FileSystem.writeAsStringAsync(uri, toB64(bytes), { encoding: FileSystem.EncodingType.Base64 });
      return { uri, cleanup: () => { FileSystem.deleteAsync(uri, { idempotent: true }).catch(() => undefined); } };
    },
  });
  return {
    storage,
    auth,
    pins: new PinStore((k) => storage.get(k), (k, v) => storage.set(k, v)),
    settings: new SettingsStore((k) => storage.get(k), (k, v) => storage.set(k, v)),
    vault: new IdentityVault(storage),
    sessions: new SessionStore(storage),
    appLock: new AppLockStore(storage, undefined, createLockEpochMirror()), // b75 (audit AL-2): row epochs noted outside the store
    notes: new NotesStore((k) => storage.get(k), (k, v) => storage.set(k, v)),
    relay,
  };
}

/**
 * b70 (re-review 5): what the screens get in decoy mode. The app lock stays the real one: the Notes gate must
 * still recognise the decoy and duress codes.
 * b77t (audit 5 M-E / IH V-02, owner decision "a real throwaway account"): it used to sit on an empty in-memory
 * store with a relay and account that refused every call. Now it is a working Vardum on the decoy's OWN account:
 * its stores are the decoy's records (src/decoy-account.ts: veil_dk_* plus the kept aux record), its account
 * signs in with the decoy's own login, and its relay client sends the decoy's token only — never the real one.
 * Nothing it writes can land under a real record's name.
 */
export const DECOY_RELAY_REFUSAL = 'Could not reach the relay. Try again later.';

/** b77t merge (owner decision: removing the decoy code deletes the decoy's relay account): a throwaway account and
 *  relay client over an in-memory store, for signing in as a removed decoy and deleting its account
 *  (decoy-account.ts deleteDecoyAccount). Nothing it holds touches a stored record; never the real token. */
export function createDecoyEndClients(): { auth: Base44Auth; relay: VeilRelay } {
  const t = relayTransport();
  const auth = new Base44Auth({ baseUrl: VEIL_BASE_URL, appId: VEIL_APP_ID, ...authTransport(t) }, new MemoryStorage());
  const relay = new VeilRelay({ baseUrl: VEIL_BASE_URL, appId: VEIL_APP_ID, getToken: () => auth.getToken(), ...(t as Pick<ConstructorParameters<typeof VeilRelay>[0], 'fetchImpl' | 'xhrImpl' | 'onAnswer'>) });
  return { auth, relay };
}
export function createDecoyApp(real: VeilApp, aux: DecoyAux = new DecoyAux(real.storage)): VeilApp {
  const storage = new KeychainStorage(decoySecureStore(real.storage, aux));
  const auth = new Base44Auth({ baseUrl: VEIL_BASE_URL, appId: VEIL_APP_ID, ...authTransport() }, storage); // b77t (audit 5 L-4, b77t2 CL-6): bounded, and its signed-in answers set the relay clock
  const relay = new VeilRelay({
    baseUrl: VEIL_BASE_URL,
    appId: VEIL_APP_ID,
    getToken: () => auth.getToken(), // the decoy's own login only
    setToken: (t: string) => auth.replaceToken(t), // b77t (audit 5 L-6): a rotation replaces the decoy's own login
    ...(relayTransport() as Pick<ConstructorParameters<typeof VeilRelay>[0], 'fetchImpl' | 'xhrImpl' | 'onAnswer'>),
    bytesToTempFile: async (bytes: Uint8Array, name: string) => {
      const uri = `${FileSystem.cacheDirectory}veil-upload-${Date.now()}-${name}`;
      await FileSystem.writeAsStringAsync(uri, toB64(bytes), { encoding: FileSystem.EncodingType.Base64 });
      return { uri, cleanup: () => { FileSystem.deleteAsync(uri, { idempotent: true }).catch(() => undefined); } };
    },
  });
  return {
    storage,
    auth,
    pins: new PinStore((k) => storage.get(k), (k, v) => storage.set(k, v)),
    settings: new SettingsStore((k) => storage.get(k), (k, v) => storage.set(k, v)),
    vault: new IdentityVault(storage),
    sessions: new SessionStore(storage, { deliveryCache: false }), // b77g (NaR-1): no capabilities in memory in decoy mode
    appLock: real.appLock,
    notes: new NotesStore((k) => storage.get(k), (k, v) => storage.set(k, v)),
    relay,
  };
}
