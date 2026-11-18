/**
 * b77 rollout (5 Nov 2026, owner): build 77 runs on its own relay (relay2.tryveil.app) beside the relay older builds
 * use. A phone updated from an older build still holds that relay's login, which this relay has never seen: every
 * call answered 401 and the app showed nothing (found on TestFlight build 65). At start-up the stored login is checked
 * once against this relay.
 *
 * Which build saved the login: every login THIS build saves is marked with its relay (auth.ts AUTH_RELAY_HOME_KEY,
 * written with the login). "moved" = a login with no mark for this relay AND this relay answers 401 for it. A login
 * this build made is marked from the start, so one that merely expired or was revoked is never taken for an old one.
 * (Build 67 used the login's date instead and missed a build 59 login made on the day: owner's iPhone, 5 Nov;
 * repro/b77_upgrade_from_old_build_e2e.test.ts now runs that update on this PC.) A network failure decides nothing.
 */
import { AUTH_RELAY_HOME_KEY } from '../vendor/device/src/auth';

export const RELAY_HOME_KEY = AUTH_RELAY_HOME_KEY;

export type RelayHomeVerdict = 'home' | 'moved' | 'unknown';

export interface RelayHomeDeps {
  get: (key: string) => Promise<string | null>;
  set: (key: string, value: string) => Promise<unknown>;
  /** this build's relay (VEIL_BASE_URL) */
  base: string;
  /** an authenticated call to this relay with the stored login; throws the relay's error ({ status }) on refusal */
  probe: () => Promise<unknown>;
}

export async function relayHomeCheck(d: RelayHomeDeps): Promise<RelayHomeVerdict> {
  const home = await d.get(RELAY_HOME_KEY).catch(() => null);
  if (home === d.base) return 'home';
  try {
    await d.probe();
  } catch (e) {
    const status = Number((e as { status?: unknown } | null)?.status);
    return status === 401 ? 'moved' : 'unknown';
  }
  await d.set(RELAY_HOME_KEY, d.base).catch(() => undefined);
  return 'home';
}

export const RELAY_MOVED_TITLE = 'Vardum has moved';
export const RELAY_MOVED_TEXT =
  'This version of Vardum uses a new, more private server, and your old chats can’t come across. ' +
  'Tap Restore and enter your 24 words to keep your Vardum ID, or create a new one. Ask your contacts to update too: the new version can’t message the old one.';
