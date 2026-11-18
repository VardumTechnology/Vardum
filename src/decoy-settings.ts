import { normalizeSettings, type VeilSettings } from '../vendor/device/src/settings';

const DEFAULTS = normalizeSettings(null);
/**
 * b77t2 (decoy gaps, owner "fix the cheap ones now"): the settings a decoy session shows and keeps. Nothing at rest
 * (the key storage mode), the self-destruct countdown and erase-after-10-wrong-passwords act on the WHOLE PHONE (the
 * real data with it), so they can't be changed from inside the decoy, and the real values must not show there
 * either. The decoy keeps them at a fresh install's values, and Settings shows them read-only in a decoy session
 * (SettingsScreen lockOptionsFixed). "Hold messages while locked" is the decoy's own and really holds the decoy
 * session's fetches (App decoyHoldNow).
 */
export function decoySettingsView(s: VeilSettings): VeilSettings {
  return { ...s, storageMode: DEFAULTS.storageMode, selfDestruct: DEFAULTS.selfDestruct, selfDestructArmedAt: DEFAULTS.selfDestructArmedAt, wipeAfterFails: DEFAULTS.wipeAfterFails, localHistory: s.storageMode === 'memory' ? DEFAULTS.localHistory : s.localHistory };
}
