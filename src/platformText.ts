/**
 * Platform wording (20 Oct 2026, GrapheneOS test on a Pixel 8 Pro): the
 * Android build showed iPhone-only copy ("check Vardum in iPhone Settings",
 * "Free during TestFlight", Face ID). One place for the words that differ.
 */
import { Platform } from 'react-native';

export const IS_ANDROID = Platform.OS === 'android';

/** where the user fixes a declined permission */
export const SETTINGS_APP = IS_ANDROID ? 'Android Settings → Apps → Vardum' : 'iPhone Settings';

/** the biometric the phone asks for */
export const BIOMETRIC = IS_ANDROID ? 'your fingerprint or face unlock' : 'Face ID or Touch ID';
export const BIOMETRIC_SHORT = IS_ANDROID ? 'Biometric' : 'Face ID';

/** the hardware that seals keys */
export const SECURE_CHIP = IS_ANDROID ? 'the phone’s security chip (Android Keystore)' : 'the Secure Enclave';

/** where the beta comes from */
export const BETA_SOURCE = IS_ANDROID ? 'the beta download page' : 'TestFlight';

/** "A permission was declined …" message, same on every screen */
export const PERMISSION_DECLINED = `A permission was declined — check Vardum in ${SETTINGS_APP}, then try again.`;

/**
 * audit VAR-02 (1f51): the "Screen protection" claim. Every screen that can
 * show chat content, keys, codes or a call draws in the main window
 * (components/SecureOverlay), so the window-level protection covers all of
 * it: FLAG_SECURE on Android (screenshots AND recordings come out blank), the
 * recording black-out on iOS (screenshots can't be blocked there, only seen).
 * b77s (audit 4 DV-2): the iOS screenshot-notice claim matches the code's gates (App.tsx capture
 * listener: a chat open, unlocked, not decoy; 1:1 also needs a ready handshake and confirmed safety codes).
 */
export function screenProtectionInfo(android: boolean): string {
  return android
    ? 'Screenshots and screen recordings of Vardum come out blank while it is open, on every screen including photos, videos, safety codes and calls, and the app-switcher preview shows nothing of your chats. A second camera pointed at the screen can still capture it. There is no setting: the protection is for the person being captured.'
    : 'Screen recordings are blocked while Vardum is open (they show black, on every screen including photos, videos, safety codes and calls), and the app-switcher preview shows a blank Vardum screen instead of your chats. no app on iOS can block or redact a plain screenshot. If one is taken while a chat is open on screen (Vardum unlocked, not in decoy mode), Vardum sends a notice into that chat over the encrypted channel: in a group chat always, in a one-to-one chat only once the chat is set up and you have confirmed its safety codes. A screenshot taken anywhere else sends no notice, and the other person sees it when their app next fetches messages. A second camera pointed at the screen can still capture it. There is no setting: the protection is for the person being captured.';
}
export const SCREEN_PROTECTION_INFO = screenProtectionInfo(IS_ANDROID);
