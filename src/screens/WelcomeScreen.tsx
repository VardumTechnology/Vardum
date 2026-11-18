import React from 'react';
import { View, Text, TouchableOpacity, StyleSheet, ScrollView, Share } from 'react-native';

/**
 * WelcomeScreen — the "Getting started" thread (onboarding-funnel-fix-spec,
 * item 2: a new user must land in a conversation, not an empty app).
 *
 * HONEST LIMITS (claims discipline, b187): a server-crafted "message from Matt"
 * cannot exist in a zero-knowledge relay (the server holds no keys). This note
 * is therefore a LOCAL, on-device welcome — clearly labelled as such.
 */

export interface WelcomeScreenProps {
  veilId: string | null;
  onRunCheckup: () => void;
  onViewIntro: () => void;
  onHide: () => void;
  onBack: () => void;
}

export function WelcomeScreen({ veilId, onRunCheckup, onViewIntro, onHide, onBack }: WelcomeScreenProps) {
  const shareId = () => {
    if (!veilId) return;
    Share.share({ message: veilId }).catch(() => undefined);
  };
  return (
    <View style={styles.fill}>
      <View style={styles.topBar}>
        <TouchableOpacity onPress={onBack}><Text style={styles.backTxt}>‹ Conversations</Text></TouchableOpacity>
        <TouchableOpacity onPress={onHide} hitSlop={{ top: 10, bottom: 10, left: 10, right: 10 }}>
          <Text style={styles.hideTxt}>Don't show again</Text>
        </TouchableOpacity>
      </View>
      <ScrollView style={styles.scroll} contentContainerStyle={styles.wrap}>
        <Text style={styles.kicker}>GETTING STARTED</Text>
        <Text style={styles.title}>Welcome to Vardum.</Text>
        <View style={styles.bubble}>
          <Text style={styles.bubbleWho}>A note from Matt, Vardum's developer</Text>
          <Text style={styles.bubbleTxt}>
            Thanks for testing Vardum. Your identity and keys were created on this device — nothing to verify, nothing to hand over.
          </Text>
          <Text style={styles.bubbleTxt}>
            Three things worth doing in your first hour: start a conversation, run the privacy checkup to set your protections, and keep your 24-word recovery phrase somewhere safe.
          </Text>
          <Text style={styles.bubbleNote}>This welcome note lives only on your device. It is not a message and nothing was sent.</Text>
        </View>

        <TouchableOpacity style={styles.actionBtn} onPress={onRunCheckup}>
          <Text style={styles.actionTxt}>Run the privacy checkup</Text>
          <Text style={styles.actionSub}>Set your protections — nothing is pre-set, every control is yours.</Text>
        </TouchableOpacity>
        <TouchableOpacity style={styles.actionBtn} onPress={onViewIntro}>
          <Text style={styles.actionTxt}>View the introduction</Text>
          <Text style={styles.actionSub}>What Vardum protects against — and what it honestly does not.</Text>
        </TouchableOpacity>
        <TouchableOpacity style={styles.actionBtn} onPress={shareId} disabled={!veilId}>
          <Text style={styles.actionTxt}>Share your Vardum ID</Text>
          <Text style={styles.actionSub}>People use it to look you up. Your keys are kept in this phone’s secure storage.</Text>
        </TouchableOpacity>
      </ScrollView>
    </View>
  );
}

const styles = StyleSheet.create({
  fill: { flex: 1, backgroundColor: '#0B0B0F' },
  topBar: { flexDirection: 'row', alignItems: 'center', justifyContent: 'space-between', paddingHorizontal: 20, paddingTop: 16, paddingBottom: 10 },
  backTxt: { color: '#FFFFFF', fontSize: 14 },
  hideTxt: { color: '#5E6464', fontSize: 12.5 },
  scroll: { flex: 1 },
  wrap: { padding: 20, paddingTop: 8 },
  kicker: { color: '#5E6464', fontSize: 11, fontWeight: '700', letterSpacing: 1.2, marginBottom: 4 },
  title: { color: '#FFFFFF', fontSize: 24, fontWeight: '800', marginBottom: 16 },
  bubble: { backgroundColor: '#15151B', borderWidth: 1, borderColor: '#24242D', borderRadius: 16, padding: 18, marginBottom: 18 },
  bubbleWho: { color: '#FFFFFF', fontSize: 12, fontWeight: '700', marginBottom: 8 },
  bubbleTxt: { color: '#C9CFCE', fontSize: 14.5, lineHeight: 21, marginBottom: 10 },
  bubbleNote: { color: '#5E6464', fontSize: 11.5, lineHeight: 16, marginTop: 4 },
  actionBtn: { backgroundColor: '#15151B', borderWidth: 1, borderColor: '#24242D', borderRadius: 14, padding: 16, marginBottom: 12 },
  actionTxt: { color: '#FFFFFF', fontSize: 15, fontWeight: '700', marginBottom: 4 },
  actionSub: { color: '#8E9696', fontSize: 12.5, lineHeight: 17 },
});
