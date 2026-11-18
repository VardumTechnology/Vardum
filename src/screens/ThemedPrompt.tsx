/**
 * ThemedPrompt — VEIL's replacement for React Native's system Alert.prompt /
 * Alert.alert dialogs (owner request, Sept 19 b57): the OS alerts are plain
 * white iPhone boxes whose text can't match the app theme. This overlay uses
 * the same proven in-screen pattern as the chat preview / image viewer
 * (absolute overlay, NOT RN Modal — the modal/native-picker collision freeze
 * from b25 stays avoided).
 *
 * Usage (one hook per screen):
 *   const { node, ask } = useThemedPrompt();
 *   ... render {node} anywhere in the tree ...
 *   const pw = await ask({ title: 'Unlock vault', secure: true, numeric: true });
 *
 * ask() resolves with:
 *   - input prompts: the typed string, or null when cancelled
 *   - confirm dialogs: true / false
 *   - info notices: true (dismiss)
 */
import React, { useCallback, useEffect, useRef, useState } from 'react';
import {
  View, Text, TextInput, TouchableOpacity, StyleSheet,
  Keyboard, Platform, ActivityIndicator,
} from 'react-native';
import { useKbPadding } from '../hooks/useKbPadding';
import { phraseEntryProps, promptKeypadVariant, PHONE_KEYBOARD_FALLBACK, VARDUM_KEYBOARD_BACK } from '../secret-entry'; // b77m (audit VAR-08); b77n
import { SecureInput, SecureKeypadHost } from '../components/SecureKeypad'; // b77n (owner, 30 Oct)
import { pastePhraseFromClipboard } from '../clipboard-guard'; // b77n: the phrase keypad's Paste key

export interface PromptSpec {
  title: string;
  message?: string;
  /** text input shown when set: 'secure' masks, 'text' is plain, 'phrase' is the recovery phrase
   *  (readable, with the no-learning keyboard flags: src/secret-entry.ts, audit VAR-08).
   *  b77n (owner decision, 30 Oct): 'code' = an app lock password, decoy or duress code — masked,
   *  typed on Vardum's own keypad; 'phrase' is typed on the keypad's phrase layout (a–z, space,
   *  BIP39 suggestions, Paste). 'secure' (vault passphrases, the registration lock PIN) and 'text'
   *  stay on the phone keyboard (promptKeypadVariant). */
  input?: 'secure' | 'text' | 'phrase' | 'code';
  /** b77n: with input 'code', the code typed is an EXISTING one (the current password): the prompt
   *  offers the phone keyboard for a password with characters the keypad lacks. New codes: keypad only. */
  existing?: boolean;
  placeholder?: string;
  defaultValue?: string;
  numeric?: boolean;
  maxLength?: number;
  submitLabel?: string;
  /** confirm dialog (no input): resolves true/false */
  confirm?: boolean;
  /** info notice (single OK): resolves true */
  info?: boolean;
  /** renders the confirm button in the destructive red */
  danger?: boolean;
  /** b77t (audit 5 L-20): a confirm dialog's own button words (default Confirm / Cancel). Cancel is also
   *  what a tap outside the card answers, so it must be the safe choice */
  cancelLabel?: string;
  /** b77t2 (CM-2): a choice of several answers (it replaces a three-button system Alert that escaped the lock).
   *  Resolves with the chosen `value`; a tap outside the card answers null, which must be the safe choice */
  choices?: { label: string; value: string; danger?: boolean }[];
  /** spinner state rendered by the caller after submit */
  busy?: boolean;
}

interface ActivePrompt {
  id: number;
  spec: PromptSpec;
  resolve: (v: string | boolean | null) => void;
}

export function useThemedPrompt(): { node: React.ReactNode; ask: (spec: PromptSpec) => Promise<string | boolean | null>; dismiss: () => void } {
  const [active, setActive] = useState<ActivePrompt | null>(null);
  const activeRef = useRef<ActivePrompt | null>(null);
  const nextId = useRef(0);

  const ask = useCallback((spec: PromptSpec) => {
    return new Promise<string | boolean | null>((resolve) => {
      // b71 (device test): a prompt still open is answered "cancel" rather than left hanging
      activeRef.current?.resolve(null);
      const p = { id: ++nextId.current, spec, resolve };
      activeRef.current = p;
      setActive(p);
    });
  }, []);

  // b71 (device test): resolved outside the state updater (React may run an
  // updater twice or late), and only for the prompt that is still showing
  const settle = useCallback((id: number, v: string | boolean | null) => {
    const cur = activeRef.current;
    if (!cur || cur.id !== id) return;
    activeRef.current = null;
    setActive((a) => (a && a.id === id ? null : a));
    cur.resolve(v);
  }, []);

  // b71 (device test): keyed per prompt — a prompt that follows another straight
  // away (password, then "Type it again", then the decoy code) used to reuse
  // the same input and start with the previous prompt's text in it
  const node = active ? <ThemedPromptView key={active.id} spec={active.spec} onSettle={(v) => settle(active.id, v)} /> : null;

  // b77t2 (CM-2): close the open prompt without an answer (null) — the app's lock and account switch
  const dismiss = useCallback(() => { const cur = activeRef.current; if (cur) settle(cur.id, null); }, [settle]);

  return { node, ask, dismiss };
}

function ThemedPromptView({ spec, onSettle }: { spec: PromptSpec; onSettle: (v: string | boolean | null) => void }) {
  const [value, setValue] = useState(spec.defaultValue ?? '');

  const submit = () => {
    if (spec.input) onSettle(value);
    else onSettle(true); // confirm + info both settle true
  };
  const cancel = () => onSettle(spec.confirm ? false : (spec.input || spec.choices) ? null : true);

  // b111: deterministic keyboard lift (KAV "padding" mode proved unreliable
  // on device) — the backdrop shrinks by the real keyboard height, so the
  // centered card (and its input) always sit above the keys.
  const kbIos = useKbPadding();
  // b71 (device test): Android had no lift at all ("pan" only keeps the
  // focused input visible), so Save/Cancel could sit under the keyboard and
  // taps on them landed on the keys instead
  const [kbAndroid, setKbAndroid] = useState(0);
  useEffect(() => {
    if (Platform.OS !== 'android') return;
    const show = Keyboard.addListener('keyboardDidShow', (e) => setKbAndroid(e.endCoordinates.height));
    const hide = Keyboard.addListener('keyboardDidHide', () => setKbAndroid(0));
    return () => { show.remove(); hide.remove(); };
  }, []);
  const kbH = Platform.OS === 'android' ? kbAndroid : kbIos;
  // b77n (owner, 30 Oct): lock codes and the phrase type on the Vardum keypad, docked at the bottom
  const [phoneKb, setPhoneKb] = useState(false);
  const keypad = phoneKb ? null : promptKeypadVariant(spec.input);
  const masked = spec.input === 'secure' || spec.input === 'code';
  const pastePhrase = async () => {
    const p = await pastePhraseFromClipboard(); // read once, clipboard cleared (src/clipboard-guard.ts)
    if (p) setValue(p);
  };

  return (
    <View style={[styles.backdrop, !keypad && kbH > 0 && { paddingBottom: kbH }]}>
      <SecureKeypadHost style={styles.hostFill}>
      <View style={styles.center}>
      <TouchableOpacity style={StyleSheet.absoluteFill} activeOpacity={1} onPress={cancel} />
      <View style={styles.card}>
        <Text style={styles.title}>{spec.title}</Text>
        {spec.message ? <Text style={styles.message}>{spec.message}</Text> : null}

        {spec.input && keypad ? (
          <SecureInput
            style={styles.input}
            value={value}
            onChangeText={setValue}
            placeholder={spec.placeholder ?? (keypad === 'phrase' ? 'word word word …' : undefined)}
            variant={keypad}
            multiline={keypad === 'phrase'}
            maxLength={spec.maxLength}
            autoFocus
            stayOpen
            doneLabel={spec.submitLabel || 'OK'}
            onSubmit={submit} // the keypad's Done key answers the prompt, as its main button does
            onPaste={keypad === 'phrase' ? () => { void pastePhrase(); } : undefined}
            accessibilityLabel={spec.title}
          />
        ) : spec.input ? (
          <TextInput
            style={styles.input}
            value={value}
            onChangeText={setValue}
            placeholder={spec.placeholder}
            placeholderTextColor="#5E6464"
            secureTextEntry={masked /* b77n: a lock code on the phone-keyboard fallback stays masked */}
            keyboardAppearance="dark"
            /* b199: secrets typed here (app password, decoy/duress, vault and
               phrase entries) must never be offered to iOS AutoFill or saved
               to the phone's password store. audit VAR-08: the recovery phrase
               gets the no-learning flags (src/secret-entry.ts) */
            {...(spec.input === 'phrase' ? phraseEntryProps(Platform.OS) : {
              keyboardType: spec.numeric ? 'numeric' as const : 'default' as const,
              autoCapitalize: 'none' as const,
              autoCorrect: false,
              spellCheck: false,
              textContentType: masked ? 'oneTimeCode' as const : undefined, // 'none' still let iOS offer Use Strong Password
              autoComplete: masked ? 'off' as const : undefined,
              importantForAutofill: masked ? 'no' as const : undefined,
            })}
            maxLength={spec.maxLength}
            autoFocus
            returnKeyType="done"
            onSubmitEditing={submit} // b71: Enter answers the prompt, as its main button does
            underlineColorAndroid="transparent"
          />
        ) : null}
        {spec.input === 'code' && spec.existing ? (
          <TouchableOpacity style={styles.kbSwitch} onPress={() => { setValue(''); setPhoneKb(!phoneKb); }} accessibilityRole="button">
            <Text style={styles.kbSwitchTxt}>{phoneKb ? VARDUM_KEYBOARD_BACK : PHONE_KEYBOARD_FALLBACK}</Text>
          </TouchableOpacity>
        ) : null}

        {spec.choices ? (
          <View>
            {spec.choices.map((c) => (
              <TouchableOpacity key={c.value} style={[styles.btn, c.danger && styles.btnDanger]} onPress={() => onSettle(c.value)}>
                <Text style={[styles.btnText, c.danger && styles.btnTextDanger]}>{c.label}</Text>
              </TouchableOpacity>
            ))}
          </View>
        ) : spec.confirm ? (
          <View>
            <TouchableOpacity style={[styles.btn, spec.danger && styles.btnDanger]} onPress={submit}>
              <Text style={[styles.btnText, spec.danger && styles.btnTextDanger]}>{spec.submitLabel || 'Confirm'}</Text>
            </TouchableOpacity>
            <TouchableOpacity style={styles.btnGhost} onPress={cancel}>
              <Text style={styles.btnGhostText}>{spec.cancelLabel || 'Cancel'}</Text>
            </TouchableOpacity>
          </View>
        ) : spec.info ? (
          <TouchableOpacity style={styles.btn} onPress={submit}>
            <Text style={styles.btnText}>OK</Text>
          </TouchableOpacity>
        ) : (
          <View>
            <TouchableOpacity style={styles.btn} onPress={submit}>
              <Text style={styles.btnText}>{spec.submitLabel || 'OK'}</Text>
            </TouchableOpacity>
            <TouchableOpacity style={styles.btnGhost} onPress={cancel}>
              <Text style={styles.btnGhostText}>Cancel</Text>
            </TouchableOpacity>
          </View>
        )}
      </View>
      </View>
      </SecureKeypadHost>
    </View>
  );
}

const styles = StyleSheet.create({
  backdrop: {
    ...StyleSheet.absoluteFillObject,
    backgroundColor: 'rgba(11,11,15,0.86)',
    // b77n: centring and padding moved to `center` (the keypad host fills the backdrop)
    zIndex: 90,
  },
  // b77n: the card centred above the docked Vardum keypad
  hostFill: { flex: 1, alignSelf: 'stretch' },
  center: { flex: 1, justifyContent: 'center', alignItems: 'center', padding: 22 },
  kbSwitch: { paddingVertical: 6, marginTop: -6, marginBottom: 6 },
  kbSwitchTxt: { color: '#8E9696', fontSize: 12, textAlign: 'center' },
  card: {
    width: '100%', maxWidth: 420,
    backgroundColor: '#15151B',
    borderRadius: 14,
    borderWidth: 1,
    borderColor: '#24242D',
    padding: 18,
  },
  title: { color: '#FFFFFF', fontSize: 15, fontWeight: '800', marginBottom: 6 },
  message: { color: '#d69a5c', fontSize: 12, lineHeight: 17, marginBottom: 10 },
  input: {
    backgroundColor: '#0B0B0F',
    borderWidth: 1,
    borderColor: '#3A3A44',
    borderRadius: 10,
    color: '#FFFFFF',
    fontSize: 15,
    paddingHorizontal: 12,
    paddingVertical: 10,
    marginBottom: 12,
  },
  btn: {
    backgroundColor: '#15151B',
    borderWidth: 1,
    borderColor: '#3A3A44',
    borderRadius: 10,
    paddingVertical: 11,
    alignItems: 'center',
    marginBottom: 8,
  },
  btnDanger: { backgroundColor: '#241213', borderColor: '#5c2a24' },
  btnText: { color: '#FFFFFF', fontSize: 14, fontWeight: '700' },
  btnTextDanger: { color: '#e06c5c' },
  btnGhost: {
    borderWidth: 1,
    borderColor: '#24242D',
    borderRadius: 10,
    paddingVertical: 10,
    alignItems: 'center',
  },
  btnGhostText: { color: '#8E9696', fontSize: 13, fontWeight: '600' },
});
