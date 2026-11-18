/**
 * b75 (audit DEV-L3): decoy mode turns the real account's push delivery OFF on the
 * phone itself, and back on at the real unlock.
 *
 * b74 silenced only the UnifiedPush banners (the native service's silent flag) and the
 * in-app banners. On iOS (APNs) and on Android with Google push, the OS shows a server
 * push itself while Vardum is in the background, so the real account's "New message" and
 * "Incoming call" banners kept appearing over a decoy session.
 *
 * Now, entering decoy mode releases the OS push token locally
 * (Notifications.unregisterForNotificationsAsync: iOS stops taking remote notifications,
 * Android deletes the FCM token), with no network call and no relay change: pushes the
 * relay sends meanwhile go to a token the phone no longer answers to, and the push
 * service drops them. The real unlock registers again (a fresh OS token; the relay row
 * is replaced through the usual registration, which removes this phone's older rows).
 * Registration requests made while the decoy is up are held and run at the real unlock.
 *
 * Every step runs in order on one chain, so a quick decoy → real → decoy never leaves a
 * registration that finished after the release.
 *
 * b75 round 2 (audit D3): the hold survives an app restart. b75 kept it in memory only:
 * the next launch, before any code was entered, cleared the native silent flag (the
 * [decoyMode] effect ran with decoyMode false) and registered push again (the identity
 * loads behind the lock screen), so the real account's banners came back on a phone
 * whose holder had been given the decoy code. Now entering decoy mode saves a hold
 * marker (sealed under the store's kept slot, outside the veil_ keys every wipe sweeps);
 * every launch reads it before any registration (restore) and keeps push released,
 * banners silenced and in-app banners suppressed until the real code is entered
 * (setDecoy(false) is called only there). A wipe ends the hold without registering.
 *
 * b75 round 3 (audit DV-3): every step is bound to the wipe it was asked before: a step
 * still queued when a wipe forgets the gate (or the wipe generation moves) does nothing.
 * A decoy entry queued just before a wipe used to save the hold after it, making a new
 * kept-slot key on a wiped phone. (audit DV-7): the hold record fails closed: a read error
 * or anything but "no record" keeps the hold (App.tsx, restore).
 */

/** b75 round 2 (audit D3): the hold marker; in CK_KEPT_KEYS (survives Nothing-at-Rest).
 *  b77t (audit 5 L-3, IH DEV-1): every install keeps this record, '1' while held and '0' otherwise (same
 *  length, sealed the same way). It used to exist only during a decoy session, so its plain name in the
 *  platform store told an examiner the phone was showing a decoy. Only a wipe removes it (a wiped phone
 *  holds nothing); the next launch writes '0' again. */
export const PUSH_HOLD_KEY = 'vardum_push_hold_v1';
/** b77t (L-3): the stored value for a hold state */
export function holdRecord(on: boolean): '1' | '0' {
  return on ? '1' : '0';
}
/** b77t (L-3): what a launch read of the record means: 'missing' = no record yet (a new install or after a
 *  wipe: not held, and '0' is written); '0' = not held; anything else = held (fail closed, DV-7) */
export function holdState(v: string | null): boolean | 'missing' {
  return v === null || v === undefined ? 'missing' : v !== '0';
}

export interface DecoyPushDeps {
  /** UnifiedPush: the native service's silent flag (b74 VAR-03) */
  setUnifiedPushSilent(on: boolean): void;
  /** release the OS push token locally (no network) */
  releaseOsToken(): Promise<void>;
  /** register this phone's push with the relay (needs an identity; false/throw = not done) */
  register(): Promise<unknown>;
  /** b75 round 2 (D3): the app's own (in-app) banners */
  setLocalSuppressed?(on: boolean): void;
  /** b75 round 2 (D3): save the hold marker. b77t (L-3): on = '1', off = '0' (the record stays) */
  saveHold?(on: boolean): Promise<unknown>;
  /** b77t (L-3): a wipe removes the record (nothing is written after a wipe, DV-3); without this,
   *  saveHold(false) */
  dropHold?(): Promise<unknown>;
  log?(msg: string): void;
  /** b75 round 3 (DV-3): the app's wipe generation */
  generation?(): number;
}

export interface DecoyPushGate {
  /** decoy mode on (the hold starts and is saved) / off (the real code was entered: the
   *  hold ends and the held registration runs) */
  setDecoy(on: boolean): Promise<void>;
  /** b75 round 2 (D3): at launch, before any registration: a saved hold applies again.
   *  b77t (L-3): 'missing' = no record yet: not held, and the '0' record is written */
  restore(held: boolean | 'missing'): Promise<void>;
  /** ask for a registration (held while the decoy is up) */
  register(): Promise<void>;
  /** for tests and the app: is delivery turned off right now */
  silenced(): boolean;
  /** a wipe: decoy mode is over and nothing is registered again (the wipe already
   *  dropped push; a new identity registers through the usual path) */
  forget(): Promise<void>;
}

export function createDecoyPushGate(d: DecoyPushDeps): DecoyPushGate {
  let decoy = false;
  let released = false;
  let chain: Promise<void> = Promise.resolve();
  const log = (m: string) => { try { d.log?.(m); } catch { /* never throws */ } };
  // b75 round 3 (audit DV-3): bumped by forget() (every wipe calls it)
  let epoch = 0;
  const gen = () => { try { return d.generation?.() ?? 0; } catch { return 0; } };
  const run = (fn: () => Promise<void>, always = false): Promise<void> => {
    const e = epoch;
    const g = gen();
    chain = chain.then(() => {
      // asked before a wipe that has happened since: nothing (b75 round 3, DV-3)
      if (!always && (epoch !== e || gen() !== g)) return undefined;
      return fn();
    }).catch((err) => log(`[veil-push] decoy push step failed: ${String((err as Error)?.message ?? err)}`));
    return chain;
  };
  const local = (on: boolean) => { try { d.setLocalSuppressed?.(on); } catch { /* best-effort */ } };
  const save = async (on: boolean) => { try { await d.saveHold?.(on); } catch (e) { log(`[veil-push] decoy hold not saved: ${String((e as Error)?.message ?? e)}`); } };
  const hold = async () => {
    try { d.setUnifiedPushSilent(true); } catch { /* best-effort */ }
    local(true);
    released = true;
    await save(true); // before the release: a kill right after it still finds the hold
    await d.releaseOsToken();
  };
  return {
    setDecoy(on: boolean): Promise<void> {
      decoy = on;
      if (on) local(true);
      return run(async () => {
        if (decoy && !released) {
          await hold();
        } else if (!decoy && released) {
          try { d.setUnifiedPushSilent(false); } catch { /* best-effort */ }
          local(false);
          released = false;
          await save(false);
          await d.register();
        } else if (!decoy) local(false);
      });
    },
    restore(held: boolean | 'missing'): Promise<void> {
      if (held === true) local(true);
      return run(async () => {
        if (held === true && !released) await hold();
        else if (held === 'missing' && !decoy && !released) await save(false); // b77t (L-3): every install has it
      });
    },
    register(): Promise<void> {
      return run(async () => {
        if (decoy || released) return; // held: the real unlock registers
        await d.register();
      });
    },
    silenced: () => released,
    forget(): Promise<void> {
      decoy = false;
      epoch++; // b75 round 3 (DV-3): every step queued before this wipe is dropped
      return run(async () => {
        const was = released;
        released = false;
        local(false);
        if (was) { try { d.setUnifiedPushSilent(false); } catch { /* best-effort */ } }
        if (d.dropHold) { try { await d.dropHold(); } catch (e) { log(`[veil-push] decoy hold not removed: ${String((e as Error)?.message ?? e)}`); } }
        else await save(false);
      }, true);
    },
  };
}
