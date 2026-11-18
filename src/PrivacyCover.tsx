/**
 * b71 (audit F-22): the app-switcher cover. The old code called
 * enableAppSwitcherProtectionAsync, which expo-screen-capture 7.0.1 does not
 * have, and logged "confirmed" anyway. iOS takes the app-switcher snapshot as
 * the app goes inactive, so an opaque cover drawn then is what the snapshot
 * shows. Android needs nothing here: FLAG_SECURE (preventScreenCaptureAsync,
 * always on) already blanks the recents preview.
 */
import React, { useEffect, useState } from 'react';
import { AppState, Platform, StyleSheet, Text, View } from 'react-native';

export function PrivacyCover() {
  const [covered, setCovered] = useState(false);
  useEffect(() => {
    if (Platform.OS !== 'ios') return;
    const sub = AppState.addEventListener('change', (s) => setCovered(s !== 'active'));
    return () => sub.remove();
  }, []);
  if (!covered) return null;
  return (
    <View style={styles.cover} pointerEvents="none">
      <Text style={styles.mark}>Vardum</Text>
    </View>
  );
}

const styles = StyleSheet.create({
  cover: { ...StyleSheet.absoluteFillObject, backgroundColor: '#0B0B0F', alignItems: 'center', justifyContent: 'center', zIndex: 9999, elevation: 9999 },
  mark: { color: '#3A3F45', fontSize: 22, fontWeight: '600', letterSpacing: 1 },
});
