/**
 * audit VAR-02 (1f51 report): the one way to show a full-screen or sheet view
 * that can hold chat content, keys, codes, the phrase or call info.
 *
 * React Native's <Modal> is a separate native window on both platforms:
 *   - Android: an android.app.Dialog. ReactModalHostView copies only
 *     FLAG_FULLSCREEN / FLAG_DIM_BEHIND from the activity, never FLAG_SECURE,
 *     so screenshots, screen recording and MediaProjection capture it while
 *     the activity behind it is blacked out.
 *   - iOS: a presented view controller above the root view. expo-screen-capture
 *     adds its recording black-out view to the ROOT view (keyWindow.subviews
 *     .first), and <PrivacyCover /> is an in-tree view too, so neither covers a
 *     presented Modal: a recording or the app-switcher snapshot shows it.
 *
 * SecureOverlay draws in the main window instead (an absolutely positioned
 * view in the React tree, the pattern ThemedPrompt already uses), so it is
 * covered by the activity's FLAG_SECURE on Android and by the recording
 * black-out and PrivacyCover on iOS. Android Back closes it, like the Modal's
 * onRequestClose did. No native presentation also means no collision with the
 * native photo picker (the b25 freeze class).
 *
 * repro/b77p_app.test.ts fails if any src/ file renders a bare RN <Modal>.
 */
import React, { useEffect, useRef } from 'react';
import { BackHandler, StyleSheet, View, type StyleProp, type ViewStyle } from 'react-native';

export type SecureOverlayProps = {
  visible: boolean;
  /** Android Back (and the caller's own close controls) */
  onRequestClose?: () => void;
  /** false = an opaque app-coloured backdrop (the old transparent={false}) */
  transparent?: boolean;
  /** draw above other overlays (the call screen) */
  layer?: 'content' | 'call';
  style?: StyleProp<ViewStyle>;
  children?: React.ReactNode;
};

/** z-order for the overlay layers: content below the themed prompts / choosers (90, so a question asked
 *  over a sheet is seen) and above the in-screen panels (40-50); the call above everything in the app;
 *  PrivacyCover (9999) always stays on top */
export const SECURE_OVERLAY_Z = { content: 80, call: 9000 } as const;

export function SecureOverlay({ visible, onRequestClose, transparent = true, layer = 'content', style, children }: SecureOverlayProps) {
  const closeRef = useRef(onRequestClose);
  closeRef.current = onRequestClose;
  useEffect(() => {
    if (!visible) return;
    // the newest listener runs first, so the top-most overlay takes Back
    const sub = BackHandler.addEventListener('hardwareBackPress', () => {
      closeRef.current?.();
      return true;
    });
    return () => sub.remove();
  }, [visible]);
  if (!visible) return null;
  const z = SECURE_OVERLAY_Z[layer];
  return (
    <View
      style={[styles.fill, { zIndex: z, elevation: z }, transparent ? null : styles.opaque, style]}
      pointerEvents="auto"
      accessibilityViewIsModal
    >
      {children}
    </View>
  );
}

const styles = StyleSheet.create({
  fill: { ...StyleSheet.absoluteFillObject },
  opaque: { backgroundColor: '#0B0B0F' },
});
