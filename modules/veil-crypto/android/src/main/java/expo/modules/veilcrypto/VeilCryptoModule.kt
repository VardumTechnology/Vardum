package expo.modules.veilcrypto

import android.app.Activity
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.security.keystore.UserNotAuthenticatedException
import android.util.Base64
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.fragment.app.FragmentActivity
import java.security.KeyStore
import java.security.SecureRandom
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import expo.modules.kotlin.Promise
import expo.modules.kotlin.exception.CodedException
import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition

/**
 * Vardum native crypto for Android — the Kotlin counterpart of the iOS
 * VeilCryptoModule (Swift). The JS-facing contract is byte-compatible:
 *
 *  - pbkdf2Sha256(password, saltHex, iterations, dkLen) -> hex
 *      PBKDF2-SHA256, byte-identical to the web/iOS contract (210k iterations).
 *  - aesGcmEncrypt(keyHex, ivHex, plaintextBase64, aadHex) -> base64(ct || tag)
 *  - aesGcmDecrypt(keyHex, ivHex, combinedBase64, aadHex) -> base64(pt)
 *      Combined layout is ciphertext||tag(16) — identical to CryptoKit's
 *      sealed-box layout and noble's combined output. A GCM tag mismatch MUST
 *      surface with the message "authentication failure (GCM tag mismatch)"
 *      — noble-subtle.ts matches on exactly that (and "code 20") to fail fast
 *      on wrong passphrases instead of retrying in JS.
 *  - randomBytesBase64(n) -> base64 (SecureRandom; up to 64 MB)
 *  - seIsAvailable / seWrapKey / seUnwrapKey / seResetKey
 *      "Security chip" key mode. iOS seals the master key via ECDH against a
 *      Secure Enclave P-256 key. The Android equivalent is a Keystore AES-GCM
 *      key (StrongBox where available) with setUserAuthenticationRequired +
 *      invalidated-by-biometric-enrollment, unlocked by a BiometricPrompt
 *      CryptoObject at key use. The sealed blob format is device-local and
 *      never crosses platforms — only the JS-facing {eph, salt, ct} shape and
 *      the "biometrics prompt at unwrap" behaviour are the contract here.
 *  - onScreenCapture event {kind: "screenshot"}
 *      Android 14+ (API 34) system screenshot callback. (iOS also reports
 *      "recording"; Android has no equivalent API — the JS side treats the
 *      event shape gracefully.) Blocking screenshots is done JS-side with
 *      expo-screen-capture / FLAG_SECURE — that power is Android-only.
 */
class VeilCryptoModule : Module() {
  private val mainHandler = Handler(Looper.getMainLooper())

  private var captureCallback: Activity.ScreenCaptureCallback? = null
  /** b77q (audit 3 AP-3): the pending native clipboard clear (touched on the main thread only) */
  private var clipClear: Runnable? = null

  override fun definition() = ModuleDefinition {
    Name("VeilCrypto")

    Events("onScreenCapture")

    // ---------- Screen-capture watch (Android 14+) ----------
    // Mirrors the iOS side's post-hoc screenshot notice. Android cannot
    // detect screenshots before API 34; the watch simply stays silent there
    // (screen-watch.ts handles an absent watch fine).
    OnActivityEntersForeground {
      val activity = appContext.currentActivity
      if (Build.VERSION.SDK_INT >= 34 && activity != null && captureCallback == null) {
        val cb = Activity.ScreenCaptureCallback {
          sendEvent("onScreenCapture", mapOf("kind" to "screenshot"))
        }
        try {
          // Needs android.permission.DETECT_SCREEN_CAPTURE (module manifest).
          activity.registerScreenCaptureCallback(mainExecutor(), cb)
          captureCallback = cb
        } catch (e: SecurityException) {
          // permission missing — stay silent, same as pre-34 devices
        }
      }
    }
    OnActivityEntersBackground {
      val activity = appContext.currentActivity
      val cb = captureCallback
      if (Build.VERSION.SDK_INT >= 34 && activity != null && cb != null) {
        try { activity.unregisterScreenCaptureCallback(cb) } catch (e: Exception) { }
      }
      captureCallback = null
    }

    // ---------- Secure chip availability ----------
    // b199 (Android handover TODO, owner OK Oct 17): the phone's ringer mode,
    // so the call ringtone obeys silent/vibrate the way iOS obeys the mute
    // switch. Android-only; JS calls it only when present (older builds and
    // iOS fall back to today's behaviour).
    Function("ringerMode") {
      val ctx = appContext.reactContext?.applicationContext ?: return@Function "normal"
      val am = ctx.getSystemService(android.content.Context.AUDIO_SERVICE) as? android.media.AudioManager
        ?: return@Function "normal"
      when (am.ringerMode) {
        android.media.AudioManager.RINGER_MODE_SILENT -> "silent"
        android.media.AudioManager.RINGER_MODE_VIBRATE -> "vibrate"
        else -> "normal"
      }
    }

    // Call quality (owner test 20 Oct 2026: "you can hear yourself"): Android
    // only applies its call echo cancellation and earpiece routing in
    // MODE_IN_COMMUNICATION. JS turns it on for a call and back to
    // MODE_NORMAL at teardown. A connected headset wins over the earpiece.
    Function("setCallAudioMode") { active: Boolean ->
      val ctx = appContext.reactContext?.applicationContext ?: return@Function false
      val am = ctx.getSystemService(android.content.Context.AUDIO_SERVICE) as? android.media.AudioManager
        ?: return@Function false
      try {
        if (active) {
          am.mode = android.media.AudioManager.MODE_IN_COMMUNICATION
          if (android.os.Build.VERSION.SDK_INT >= 31) {
            val devices = am.availableCommunicationDevices
            val headset = devices.firstOrNull {
              it.type == android.media.AudioDeviceInfo.TYPE_WIRED_HEADSET ||
                it.type == android.media.AudioDeviceInfo.TYPE_WIRED_HEADPHONES ||
                it.type == android.media.AudioDeviceInfo.TYPE_USB_HEADSET ||
                it.type == android.media.AudioDeviceInfo.TYPE_BLUETOOTH_SCO ||
                it.type == android.media.AudioDeviceInfo.TYPE_BLE_HEADSET
            }
            val target = headset ?: devices.firstOrNull { it.type == android.media.AudioDeviceInfo.TYPE_BUILTIN_EARPIECE }
            if (target != null) am.setCommunicationDevice(target)
          } else {
            @Suppress("DEPRECATION")
            am.isSpeakerphoneOn = false
          }
        } else {
          if (android.os.Build.VERSION.SDK_INT >= 31) am.clearCommunicationDevice()
          am.mode = android.media.AudioManager.MODE_NORMAL
        }
        true
      } catch (e: Exception) {
        false
      }
    }

    Function("seIsAvailable") {
      val ctx = appContext.reactContext?.applicationContext ?: return@Function false
      val can = BiometricManager.from(ctx)
        .canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG)
      can == BiometricManager.BIOMETRIC_SUCCESS
    }

    // ---------- PBKDF2-SHA256 (native C; javax.crypto fallback) ----------
    AsyncFunction("pbkdf2Sha256") { password: String, saltHex: String, iterations: Int, dkLen: Int, promise: Promise ->
      try {
        val salt = hexToBytes(saltHex)
        if (salt.isEmpty()) throw CodedException("ERR_INVALID_SALT", "invalid salt hex", null)
        // RV-27: same bounds as the JS entry point (vendor/device/src/kdf.ts
        // pbkdf2Sha256Bytes); a 1-iteration request is refused here too.
        if (iterations < PBKDF2_MIN_ITERATIONS || iterations > PBKDF2_MAX_ITERATIONS || dkLen < 16 || dkLen > 64) {
          throw CodedException("ERR_INVALID_PARAMS", "pbkdf2Sha256: unsupported iterations or dkLen", null)
        }
        // b199: native C, ~20x faster on budget phones, same bytes (Pbkdf2Sha256.kt).
        val derived = Pbkdf2Sha256.derive(password, salt, iterations, dkLen)
        try {
          promise.resolve(bytesToHex(derived))
        } finally {
          derived.fill(0) // RV-29 (the hex String itself can't be wiped)
        }
      } catch (e: CodedException) {
        promise.reject(e)
      } catch (e: Exception) {
        promise.reject("ERR_PBKDF2", "pbkdf2Sha256 failed: ${e.message}", e)
      }
    }

    // ---------- AES-256-GCM ----------
    AsyncFunction("aesGcmEncrypt") { keyHex: String, ivHex: String, plaintextBase64: String, aadHex: String, promise: Promise ->
      try {
        val key = hexToBytes(keyHex)
        if (key.size != 32) throw CodedException("ERR_BAD_KEY", "aesGcmEncrypt: key must be 32 bytes", null)
        val iv = hexToBytes(ivHex)
        if (iv.size != 12) throw CodedException("ERR_BAD_IV", "aesGcmEncrypt: iv must be 12 bytes", null)
        val pt = b64ToBytes(plaintextBase64)
          ?: throw CodedException("ERR_BAD_INPUT", "aesGcmEncrypt: invalid base64 plaintext", null)
        val aad = strictHexToBytes(aadHex) // b77t (audit 5 L-31): malformed AAD hex is refused, never read as no AAD
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, iv))
        if (aad.isNotEmpty()) cipher.updateAAD(aad)
        // javax.crypto GCM doFinal output is ciphertext||tag(16) — the same
        // combined layout CryptoKit and noble produce.
        val out = cipher.doFinal(pt)
        key.fill(0); pt.fill(0) // RV-29
        promise.resolve(bytesToB64(out))
      } catch (e: CodedException) {
        promise.reject(e)
      } catch (e: Exception) {
        promise.reject("ERR_AES", "aesGcmEncrypt failed: ${e.message}", e)
      }
    }

    AsyncFunction("aesGcmDecrypt") { keyHex: String, ivHex: String, combinedBase64: String, aadHex: String, promise: Promise ->
      try {
        val key = hexToBytes(keyHex)
        if (key.size != 32) throw CodedException("ERR_BAD_KEY", "aesGcmDecrypt: key must be 32 bytes", null)
        val iv = hexToBytes(ivHex)
        if (iv.size != 12) throw CodedException("ERR_BAD_IV", "aesGcmDecrypt: iv must be 12 bytes", null)
        val combined = b64ToBytes(combinedBase64)
          ?: throw CodedException("ERR_BAD_INPUT", "aesGcmDecrypt: invalid base64 ciphertext", null)
        if (combined.size < 16) {
          throw CodedException("ERR_BAD_INPUT", "aesGcmDecrypt: ciphertext shorter than a bare GCM tag", null)
        }
        val aad = strictHexToBytes(aadHex) // b77t (audit 5 L-31): malformed AAD hex is refused, never read as no AAD
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, iv))
        if (aad.isNotEmpty()) cipher.updateAAD(aad)
        val pt: ByteArray
        try {
          // javax.crypto expects the tag appended to the ciphertext — the
          // combined layout, exactly as the Swift module receives it.
          pt = cipher.doFinal(combined)
        } catch (e: javax.crypto.AEADBadTagException) {
          // MUST match noble-subtle.ts's detection: it looks for
          // "code 20" or "authentication failure" in the message.
          throw CodedException("ERR_GCM_AUTH", "authentication failure (GCM tag mismatch)", null)
        }
        key.fill(0) // RV-29
        try { promise.resolve(bytesToB64(pt)) } finally { pt.fill(0) }
      } catch (e: CodedException) {
        promise.reject(e)
      } catch (e: Exception) {
        promise.reject("ERR_AES", "aesGcmDecrypt failed: ${e.message}", e)
      }
    }

    // ---------- SecureRandom ----------
    AsyncFunction("randomBytesBase64") { byteLength: Int, promise: Promise ->
      try {
        if (byteLength <= 0 || byteLength > 64 * 1024 * 1024) {
          throw CodedException("ERR_BAD_LENGTH", "randomBytesBase64: length out of range", null)
        }
        val bytes = ByteArray(byteLength)
        SecureRandom().nextBytes(bytes)
        promise.resolve(bytesToB64(bytes))
      } catch (e: CodedException) {
        promise.reject(e)
      } catch (e: Exception) {
        promise.reject("ERR_RANDOM", "randomBytesBase64 failed: ${e.message}", e)
      }
    }

    // ---------- "Security chip" seal (Android Keystore + BiometricPrompt) ----------
    AsyncFunction("seWrapKey") { masterKeyB64: String, promise: Promise ->
      try {
        val master = b64ToBytes(masterKeyB64)
          ?: throw CodedException("ERR_SE_INPUT", "seWrapKey: master key is not valid base64", null)
        if (master.isEmpty()) {
          throw CodedException("ERR_SE_INPUT", "seWrapKey: master key is not valid base64", null)
        }
        val out = try {
          runAuthed({ loadSeCipher(Cipher.ENCRYPT_MODE, null) }) { it.doFinal(master) }
        } finally {
          master.fill(0) // RV-29
        }
        // Device-local blob format: [version:1][iv:12][ct||tag]
        val blob = ByteArray(1 + 12 + out.output.size)
        blob[0] = SE_BLOB_VERSION
        System.arraycopy(out.ivBytes, 0, blob, 1, 12)
        System.arraycopy(out.output, 0, blob, 13, out.output.size)
        val rng = SecureRandom()
        val eph = ByteArray(32); rng.nextBytes(eph)
        val salt = ByteArray(32); rng.nextBytes(salt)
        val hw = seKeyHardware()
        android.util.Log.i("veil-se", "wrap key hw=$hw")
        promise.resolve(
          mapOf(
            "eph" to bytesToB64(eph),
            "salt" to bytesToB64(salt),
            "ct" to bytesToB64(blob),
            // D-20 (RV-57): where the wrap key really lives. Extra field;
            // callers that only read eph/salt/ct are unaffected.
            "hw" to hw,
          )
        )
      } catch (e: SeAuthCancelled) {
        promise.reject("ERR_SE_CANCELLED", "seWrapKey: biometric prompt cancelled (${e.message})", e)
      } catch (e: SeAuthTimeout) {
        promise.reject("ERR_SE_TIMEOUT", "seWrapKey: biometric prompt timed out", e)
      } catch (e: CodedException) {
        promise.reject(e)
      } catch (e: Exception) {
        promise.reject("ERR_SE", "seWrapKey failed: ${e.message}", e)
      }
    }

    AsyncFunction("seUnwrapKey") { ephB64: String, saltB64: String, ctB64: String, promise: Promise ->
      try {
        val blob = b64ToBytes(ctB64)
          ?: throw CodedException("ERR_SE_INPUT", "seUnwrapKey: malformed sealed blob", null)
        if (blob.size < 1 + 12 + 16 || blob[0] != SE_BLOB_VERSION) {
          throw CodedException("ERR_SE_INPUT", "seUnwrapKey: malformed sealed blob", null)
        }
        val iv = blob.copyOfRange(1, 13)
        val ct = blob.copyOfRange(13, blob.size)
        val master = runAuthed({ loadSeCipher(Cipher.DECRYPT_MODE, GCMParameterSpec(128, iv)) }) { it.doFinal(ct) }
        try { promise.resolve(bytesToB64(master.output)) } finally { master.output.fill(0) } // RV-29
      } catch (e: SeAuthCancelled) {
        promise.reject("ERR_SE_CANCELLED", "seUnwrapKey: biometric prompt cancelled (${e.message})", e)
      } catch (e: SeAuthTimeout) {
        promise.reject("ERR_SE_TIMEOUT", "seUnwrapKey: biometric prompt timed out", e)
      } catch (e: CodedException) {
        promise.reject(e)
      } catch (e: Exception) {
        promise.reject("ERR_SE", "seUnwrapKey failed: ${e.message}", e)
      }
    }

    AsyncFunction("seResetKey") { promise: Promise ->
      try {
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        if (ks.containsAlias(SE_KEY_ALIAS)) ks.deleteEntry(SE_KEY_ALIAS)
        // Same rule as iOS D-19: reset must really replace the key.
        if (KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }.containsAlias(SE_KEY_ALIAS)) {
          throw CodedException("ERR_SE", "seResetKey: old Keystore key still present after delete", null)
        }
        ensureSeKey()
        promise.resolve(true)
      } catch (e: Exception) {
        promise.reject("ERR_SE", "seResetKey failed: ${e.message}", e)
      }
    }

    // ---------- App-lock MAC (b70 audit fix VAR-07) ----------
    // The app-lock verifier is HMAC(key, PBKDF2(code)) with a non-exportable
    // Keystore HMAC key (StrongBox where available, no user auth so the lock
    // screen works without a fingerprint). A copied lock record can't be
    // guessed offline: every guess needs this phone's Keystore.
    // "The Keystore can make and use the lock's HMAC key" — records made with it
    // keep using it (mac: 'hw'). b75 (audit AL-11): whether that key really sits in
    // secure hardware is a separate question, answered by lockMacHardware below.
    Function("lockMacAvailable") { true }

    // b75 (audit AL-11): true only when the lock key is inside secure hardware
    // (TEE or StrongBox) by its KeyInfo. It used to be assumed on every Android
    // phone; a software-only Keystore now reports false, and the app tells the user.
    Function("lockMacHardware") {
      try { keyInsideSecureHardware(loadLockMacKey()) } catch (e: Exception) { false }
    }

    AsyncFunction("lockMac") { inputHex: String, promise: Promise ->
      try {
        val input = hexToBytes(inputHex)
        if (input.isEmpty()) throw CodedException("ERR_LOCK_INPUT", "lockMac: input is not valid hex", null)
        val mac = javax.crypto.Mac.getInstance("HmacSHA256")
        mac.init(loadLockMacKey())
        promise.resolve(bytesToHex(mac.doFinal(input)))
      } catch (e: CodedException) {
        promise.reject(e)
      } catch (e: Exception) {
        promise.reject("ERR_LOCK", "lockMac failed: ${e.message}", e)
      }
    }

    // b71 (audit): copy text marked sensitive — Android 13+ then shows no preview
    // of it in the clipboard overlay, and keyboards keep it out of their clipboard
    // history. b77q (audit 3 AP-3): and it is cleared natively after expireSeconds. The JS
    // timer that used to do it alone is paused with the activity, so a copy taken into another
    // app stayed until Vardum came back. A Handler on the main looper still runs while the
    // activity is paused (not after the process dies). Android withholds the clipboard from a
    // background app, so when it can't be read it is cleared without the "still ours" check.
    // b77s (audit 4 A-01): every wipe drops the app's cookies. React Native's networking keeps them
    // in the WebView CookieManager store (ForwardingCookieHandler), so a relay that set one could link
    // requests made before and after a wipe. Best-effort: resolves false when it can't run.
    // (Not compiled in the b77s round: no Android toolchain there; needs a device build check.)
    AsyncFunction("clearCookies") { promise: Promise ->
      Handler(Looper.getMainLooper()).post {
        try {
          val cm = android.webkit.CookieManager.getInstance()
          cm.removeAllCookies { _ ->
            try { cm.flush() } catch (e: Exception) { }
            promise.resolve(true)
          }
        } catch (e: Exception) {
          promise.resolve(false)
        }
      }
    }

    AsyncFunction("setSensitiveClipboard") { text: String, expireSeconds: Double, promise: Promise ->
      val ctx = appContext.reactContext?.applicationContext
      if (ctx == null) {
        promise.reject("ERR_CLIP", "setSensitiveClipboard: no context", null)
        return@AsyncFunction
      }
      Handler(Looper.getMainLooper()).post {
        try {
          val cm = ctx.getSystemService(android.content.Context.CLIPBOARD_SERVICE) as android.content.ClipboardManager
          val clip = android.content.ClipData.newPlainText("Vardum", text)
          val extras = android.os.PersistableBundle()
          // the constant is API 33; older versions read the same literal key
          extras.putBoolean(if (Build.VERSION.SDK_INT >= 33) android.content.ClipDescription.EXTRA_IS_SENSITIVE else "android.content.extra.IS_SENSITIVE", true)
          clip.description.extras = extras
          cm.setPrimaryClip(clip)
          // b77q (audit 3 AP-3): the delayed native clear (a newer copy replaces the pending one)
          clipClear?.let { mainHandler.removeCallbacks(it) }
          val clear = Runnable {
            clipClear = null
            try {
              val cur = cm.primaryClip // null when Android withholds it (Vardum in the background)
              val ours = cur == null || (cur.itemCount > 0 && cur.getItemAt(0).text?.toString() == text)
              if (ours) {
                if (Build.VERSION.SDK_INT >= 28) cm.clearPrimaryClip()
                else cm.setPrimaryClip(android.content.ClipData.newPlainText("", ""))
              }
            } catch (e: Exception) { /* best-effort */ }
          }
          clipClear = clear
          mainHandler.postDelayed(clear, ((if (expireSeconds > 0) expireSeconds else 60.0) * 1000).toLong())
          promise.resolve(true)
        } catch (e: Exception) {
          promise.reject("ERR_CLIP", "setSensitiveClipboard failed: ${e.message}", e)
        }
      }
    }

    AsyncFunction("lockMacReset") { promise: Promise ->
      try {
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        if (ks.containsAlias(LOCK_KEY_ALIAS)) ks.deleteEntry(LOCK_KEY_ALIAS)
        promise.resolve(true)
      } catch (e: Exception) {
        promise.reject("ERR_LOCK", "lockMacReset failed: ${e.message}", e)
      }
    }

    // Time since boot, counting deep sleep. Changing the phone's clock doesn't
    // move it, so lockouts can't be skipped that way.
    Function("uptimeMs") { android.os.SystemClock.elapsedRealtime().toDouble() }

    // D-20 (RV-57): report where the wrap key lives without using it (no
    // prompt). New, optional: JS that doesn't call it is unaffected. Creates
    // the key if missing, like seWrapKey would.
    AsyncFunction("seKeyInfo") { promise: Promise ->
      try {
        val hw = seKeyHardware()
        promise.resolve(mapOf("hw" to hw, "insideSecureHardware" to (hw == "strongbox" || hw == "tee")))
      } catch (e: Exception) {
        promise.reject("ERR_SE", "seKeyInfo failed: ${e.message}", e)
      }
    }

    // ---------- b75 (audit AL-10): delete the security-chip wrap key outright ----------
    // A wipe used seResetKey, which makes a fresh key straight away, so a wiped
    // phone still held a Vardum Keystore key. This deletes it and makes none.
    AsyncFunction("seDeleteKey") { promise: Promise ->
      try {
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        if (ks.containsAlias(SE_KEY_ALIAS)) ks.deleteEntry(SE_KEY_ALIAS)
        promise.resolve(!KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }.containsAlias(SE_KEY_ALIAS))
      } catch (e: Exception) {
        promise.reject("ERR_SE", "seDeleteKey failed: ${e.message}", e)
      }
    }

    // ---------- b75 (audit AL-6): container keys ----------
    // Every secure-store value is AES-GCM sealed (in JS) under a random 256-bit key
    // kept in a file in this app's no-backup directory. The file holds that key
    // sealed again under a Keystore AES key that, where the phone supports it, works
    // only while the phone is unlocked (setUnlockedDeviceRequired, API 28+). JS reads
    // the key once per process (the phone is unlocked when Vardum is opened) and keeps
    // it in memory, so receiving in the background keeps working; a copy of the store
    // taken from a locked phone can't be opened with this file. Deleting the file is
    // the crypto-shred every wipe does first.
    // File: [ver=1][gen:4 BE][iv:12][ct||tag of the 32-byte key], AAD "vardum-ck|<slot>|<gen>".
    // b75 round 3 (audit DV-11): every container-key file operation runs under one lock, so
    // the re-binding below (which re-writes the files) can never race a wipe's delete (and
    // put a destroyed key back) or a read that picks the wrap key from the file's version.
    AsyncFunction("ckRead") { slot: String, promise: Promise ->
      synchronized(ckLock) {
        try {
          val f = ckFile(slot)
          if (!f.exists()) { promise.resolve(null); return@AsyncFunction }
          val bytes = f.readBytes()
          // b75 round 3 (DV-11): the version byte names the wrap key (1: the first one,
          // 2: the one made later, bound to an unlocked phone)
          val alias = if (bytes.size == 1 + 4 + 12 + 32 + 16) ckAliasFor(bytes[0]) else null
          if (alias == null) {
            throw CodedException("ERR_CK_BAD", "container key file is malformed", null)
          }
          val gen = java.nio.ByteBuffer.wrap(bytes, 1, 4).int
          val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
          if (!ks.containsAlias(alias)) {
            // the Keystore key that sealed this file is gone (app data restored onto a
            // phone without it): the file can never open again — it is garbage
            ckShredFile(f)
            promise.resolve(null)
            return@AsyncFunction
          }
          val key = (ks.getEntry(alias, null) as? KeyStore.SecretKeyEntry)?.secretKey
            ?: throw CodedException("ERR_CK_UNAVAILABLE", "container wrap key unavailable", null)
          val cipher = Cipher.getInstance("AES/GCM/NoPadding")
          val plain = try {
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, bytes.copyOfRange(5, 17)))
            cipher.updateAAD("vardum-ck|$slot|$gen".toByteArray(Charsets.UTF_8))
            cipher.doFinal(bytes.copyOfRange(17, bytes.size))
          } catch (e: javax.crypto.AEADBadTagException) {
            throw CodedException("ERR_CK_BAD", "container key file failed its check", null)
          } catch (e: Exception) {
            // e.g. the phone is locked and the key is bound to an unlocked phone: try later
            throw CodedException("ERR_CK_UNAVAILABLE", "container key can't be opened right now: ${e.javaClass.simpleName}", null)
          }
          try { promise.resolve(mapOf("key" to bytesToB64(plain), "gen" to gen)) } finally { plain.fill(0) }
        } catch (e: CodedException) {
          promise.reject(e)
        } catch (e: Exception) {
          promise.reject("ERR_CK", "ckRead failed: ${e.message}", e)
        }
      }
    }

    AsyncFunction("ckCreate") { slot: String, gen: Int, promise: Promise ->
      synchronized(ckLock) {
        try {
          val f = ckFile(slot)
          // never overwrite: a key in use is only ever replaced by remove + create
          if (f.exists()) throw CodedException("ERR_CK_EXISTS", "container key slot is in use", null)
          // b75 round 3 (DV-11): the unlock-bound key made later, once there is one
          val ksNow = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
          val bound = if (ksNow.containsAlias(CK_WRAP_ALIAS_U)) (ksNow.getEntry(CK_WRAP_ALIAS_U, null) as? KeyStore.SecretKeyEntry)?.secretKey else null
          val wrap = bound ?: ckWrapKey()
          val ver = if (bound != null) CK_VERSION_U else CK_VERSION
          val raw = ByteArray(32).also { SecureRandom().nextBytes(it) }
          try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, wrap)
            cipher.updateAAD("vardum-ck|$slot|$gen".toByteArray(Charsets.UTF_8))
            val ct = cipher.doFinal(raw)
            val iv = cipher.iv
            if (iv.size != 12 || ct.size != 48) throw CodedException("ERR_CK", "unexpected GCM sizes", null)
            val out = java.nio.ByteBuffer.allocate(1 + 4 + 12 + 48).put(ver).putInt(gen).put(iv).put(ct).array()
            // durable before it is used: temp file, fsync, rename, fsync the directory
            val tmp = java.io.File(f.parentFile, "${f.name}.tmp")
            java.io.FileOutputStream(tmp).use { os -> os.write(out); os.flush(); os.fd.sync() }
            if (!tmp.renameTo(f)) { tmp.delete(); throw CodedException("ERR_CK", "container key file could not be placed", null) }
            ckSyncDir(f.parentFile!!)
            promise.resolve(mapOf("key" to bytesToB64(raw), "gen" to gen))
          } finally {
            raw.fill(0)
          }
        } catch (e: CodedException) {
          promise.reject(e)
        } catch (e: Exception) {
          promise.reject("ERR_CK", "ckCreate failed: ${e.message}", e)
        }
      }
    }

    AsyncFunction("ckRemove") { slot: String, promise: Promise ->
      synchronized(ckLock) {
        try {
          val f = ckFile(slot)
          ckShredFile(f)
          promise.resolve(!f.exists())
        } catch (e: CodedException) {
          promise.reject(e)
        } catch (e: Exception) {
          promise.reject("ERR_CK", "ckRemove failed: ${e.message}", e)
        }
      }
    }

    // b75 round 2 (audit I1): the wrap key itself, once no slot file is left (a full wipe
    // ends with this; the media slot can outlive the wipe until its files are deleted, and
    // the key stays while it does). Resolves true when no wrap key is left.
    // b75 round 3 (DV-11): both wrap keys (the first one and the unlock-bound one made later)
    AsyncFunction("ckDropWrapIfIdle") { promise: Promise ->
      synchronized(ckLock) {
        try {
          val left = ckDir().listFiles()?.any { it.isFile && it.name.endsWith(".ck") } ?: false
          val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
          if (!left) {
            if (ks.containsAlias(CK_WRAP_ALIAS)) ks.deleteEntry(CK_WRAP_ALIAS)
            if (ks.containsAlias(CK_WRAP_ALIAS_U)) ks.deleteEntry(CK_WRAP_ALIAS_U)
            try { ckUnlockBoundFlag().delete() } catch (e: Exception) { }
          }
          val after = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
          promise.resolve(!after.containsAlias(CK_WRAP_ALIAS) && !after.containsAlias(CK_WRAP_ALIAS_U))
        } catch (e: Exception) {
          promise.reject("ERR_CK", "ckDropWrapIfIdle failed: ${e.message}", e)
        }
      }
    }

    // every slot file and the wrap keys themselves (a fresh install's sweep)
    AsyncFunction("ckRemoveAll") { promise: Promise ->
      synchronized(ckLock) {
        try {
          val dir = ckDir()
          dir.listFiles()?.forEach { ckShredFile(it) }
          val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
          for (a in listOf(CK_WRAP_ALIAS, CK_WRAP_ALIAS_U)) if (ks.containsAlias(a)) ks.deleteEntry(a)
          promise.resolve(true)
        } catch (e: Exception) {
          promise.reject("ERR_CK", "ckRemoveAll failed: ${e.message}", e)
        }
      }
    }

    // b75 round 3 (audit DV-11): a phone that had no screen lock when the first wrap key was
    // made got a key that works while the phone is locked, for good. Asked at each launch
    // (Vardum in front, the phone unlocked): once the phone has a screen lock, a new wrap
    // key bound to an unlocked phone is made, every slot file is re-sealed under it (one
    // file at a time: temp file, fsync, rename; reads pick the key by the file's version
    // byte, so a launch cut short anywhere leaves every file readable and the next launch
    // carries on), and only then is the old key deleted. Resolves true when the files are
    // bound to an unlocked phone; false when it can't be done (yet).
    AsyncFunction("ckRebindUnlocked") { promise: Promise ->
      try {
        promise.resolve(ckRebind())
      } catch (e: Exception) {
        promise.reject("ERR_CK", "ckRebindUnlocked failed: ${e.message}", e)
      }
    }

    // where the wrap key lives and whether it is bound to an unlocked phone (a diagnostic).
    // b75 (audit DEV-I6): reads only an existing key; asking never creates one (a wiped
    // phone used to get a new wrap key just from being asked)
    Function("ckInfo") {
      try {
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        val alias = if (ks.containsAlias(CK_WRAP_ALIAS_U)) CK_WRAP_ALIAS_U else if (ks.containsAlias(CK_WRAP_ALIAS)) CK_WRAP_ALIAS else null
        val k = if (alias != null) (ks.getEntry(alias, null) as? KeyStore.SecretKeyEntry)?.secretKey else null
        if (k == null) mapOf("hardware" to false, "unlockBound" to false)
        else mapOf("hardware" to keyInsideSecureHardware(k), "unlockBound" to (alias == CK_WRAP_ALIAS_U || ckUnlockBoundFlag().exists()))
      } catch (e: Exception) {
        mapOf("hardware" to false, "unlockBound" to false)
      }
    }
  }

  // ================= internals =================

  companion object {
    private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    private const val SE_KEY_ALIAS = "veil-se-wrap-key"
    private const val SE_BLOB_VERSION: Byte = 1
    private const val LOCK_KEY_ALIAS = "veil-lock-mac-key"
    /** b75 (AL-6): the Keystore key that seals the container key files */
    private const val CK_WRAP_ALIAS = "vardum-ck-wrap"
    private const val CK_VERSION: Byte = 1
    /** b75 round 3 (audit DV-11): the wrap key made later, once the phone has a screen lock:
     *  always bound to an unlocked phone; files sealed under it carry version 2 */
    private const val CK_WRAP_ALIAS_U = "vardum-ck-wrap-u"
    private const val CK_VERSION_U: Byte = 2
    /** Must match PBKDF2_MIN_ITERATIONS / PBKDF2_MAX_ITERATIONS in vendor/device/src/kdf.ts. */
    private const val PBKDF2_MIN_ITERATIONS = 100_000
    private const val PBKDF2_MAX_ITERATIONS = 1_000_000
    /** D-20: how long a key operation waits for the biometric prompt. */
    private const val SE_PROMPT_TIMEOUT_S = 120L
  }

  /** Thrown locally when the biometric prompt ends with an error (cancel, lockout…), to route the reject. */
  private class SeAuthCancelled(val code: Int, why: String) : Exception("biometric prompt ended ($code: $why)")

  /** Thrown locally when the biometric prompt got no answer in time. */
  private class SeAuthTimeout : Exception()

  private class AuthedResult(val output: ByteArray, val ivBytes: ByteArray)

  private fun mainExecutor(): Executor {
    val activity = appContext.currentActivity
    return if (activity != null && Build.VERSION.SDK_INT >= 28) {
      activity.mainExecutor
    } else {
      Executor { r -> mainHandler.post(r) }
    }
  }

  private fun currentFragmentActivity(): FragmentActivity? =
    appContext.currentActivity as? FragmentActivity

  /**
   * Load the persisted Keystore wrap key or create it: AES-256-GCM,
   * StrongBox where available, biometry-gated per use, invalidated when the
   * biometric set changes (matches iOS's .biometryCurrentSet semantics).
   */
  private fun ensureSeKey() {
    val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
    if (ks.containsAlias(SE_KEY_ALIAS)) return

    val builder = KeyGenParameterSpec.Builder(
      SE_KEY_ALIAS,
      KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
    )
      .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
      .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
      .setKeySize(256)
      .setUserAuthenticationRequired(true)
      .setInvalidatedByBiometricEnrollment(true)

    if (Build.VERSION.SDK_INT >= 30) {
      builder.setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
    } else {
      // -1 = authentication required for every use (CryptoObject flow)
      builder.setUserAuthenticationValidityDurationSeconds(-1)
    }

    val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)

    if (Build.VERSION.SDK_INT >= 28) {
      try {
        builder.setIsStrongBoxBacked(true)
        generator.init(builder.build())
        generator.generateKey()
        return
      } catch (e: StrongBoxUnavailableException) {
        // no StrongBox hardware — fall through to the normal Keystore
      } catch (e: java.security.ProviderException) {
        // some OEM keystore providers wrap StrongBox errors in ProviderException
      }
      // IMPORTANT: clear the StrongBox flag before the fallback build — the
      // builder is mutable and keeps whatever was last set.
      builder.setIsStrongBoxBacked(false)
    }
    generator.init(builder.build())
    generator.generateKey()
  }

  /** The app-lock HMAC key (VAR-07), created on first use: StrongBox where available. */
  private fun loadLockMacKey(): javax.crypto.SecretKey {
    val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
    if (!ks.containsAlias(LOCK_KEY_ALIAS)) {
      val builder = KeyGenParameterSpec.Builder(LOCK_KEY_ALIAS, KeyProperties.PURPOSE_SIGN)
        .setDigests(KeyProperties.DIGEST_SHA256)
      val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_HMAC_SHA256, ANDROID_KEYSTORE)
      var made = false
      if (Build.VERSION.SDK_INT >= 28) {
        try {
          builder.setIsStrongBoxBacked(true)
          generator.init(builder.build())
          generator.generateKey()
          made = true
        } catch (e: StrongBoxUnavailableException) {
        } catch (e: java.security.ProviderException) {
        }
        if (!made) builder.setIsStrongBoxBacked(false)
      }
      if (!made) {
        generator.init(builder.build())
        generator.generateKey()
      }
    }
    val entry = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }.getEntry(LOCK_KEY_ALIAS, null) as? KeyStore.SecretKeyEntry
      ?: throw CodedException("ERR_LOCK_KEY", "app-lock key unavailable", null)
    return entry.secretKey
  }

  /** The wrap key from the Keystore (created on first use). */
  private fun loadSeSecretKey(): javax.crypto.SecretKey {
    ensureSeKey()
    val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
    val entry = ks.getEntry(SE_KEY_ALIAS, null) as? KeyStore.SecretKeyEntry
      ?: throw CodedException("ERR_SE_KEY", "Keystore wrap key unavailable (re-enrolled biometrics?)", null)
    return entry.secretKey
  }

  /**
   * A FRESH cipher on the auth-gated wrap key, initialised but not yet used.
   * For a per-use biometric key, init succeeds without auth; the operation
   * is authorised only through the BiometricPrompt CryptoObject that wraps
   * this exact cipher. A cipher is never reused after a failed operation.
   * (D-20: the old code swallowed UserNotAuthenticatedException here and
   * returned an UNinitialised cipher.)
   */
  private fun loadSeCipher(mode: Int, spec: GCMParameterSpec?): Cipher {
    val key = loadSeSecretKey()
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    try {
      if (spec != null) cipher.init(mode, key, spec) else cipher.init(mode, key)
    } catch (e: KeyPermanentlyInvalidatedException) {
      throw CodedException("ERR_SE_KEY", "Keystore wrap key was invalidated (biometrics changed); reset needed", e)
    }
    return cipher
  }

  /**
   * "strongbox" / "tee" / "software" / "unknown": where the wrap key really
   * lives, from KeyInfo (RV-57: StrongBox falls back to TEE or software
   * silently; "security chip" must not be claimed over a software key).
   */
  private fun seKeyHardware(): String = try {
    val key = loadSeSecretKey()
    val factory = javax.crypto.SecretKeyFactory.getInstance(key.algorithm, ANDROID_KEYSTORE)
    val info = factory.getKeySpec(key, KeyInfo::class.java) as KeyInfo
    if (Build.VERSION.SDK_INT >= 31) {
      when (info.securityLevel) {
        KeyProperties.SECURITY_LEVEL_STRONGBOX -> "strongbox"
        KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> "tee"
        KeyProperties.SECURITY_LEVEL_SOFTWARE -> "software"
        KeyProperties.SECURITY_LEVEL_UNKNOWN_SECURE -> "tee"
        else -> "unknown"
      }
    } else {
      @Suppress("DEPRECATION")
      if (info.isInsideSecureHardware) "tee" else "software"
    }
  } catch (e: Exception) {
    "unknown"
  }

  /**
   * D-20 (RV-17): run a cipher operation on the per-use, biometric-only wrap
   * key. The old code tried the operation WITHOUT auth and showed the prompt
   * only on UserNotAuthenticatedException, but a per-use Keystore key fails
   * at doFinal with IllegalBlockSizeException instead, so the prompt never
   * appeared; it also reused the failed cipher and waited forever.
   *
   * Now every call: fresh cipher -> BiometricPrompt.authenticate(CryptoObject)
   * built and shown on the main thread -> the operation runs on the cipher
   * the prompt hands back. The wait is bounded (SE_PROMPT_TIMEOUT_S) and the
   * prompt is cancelled on timeout. If the authorised operation itself fails
   * for a key-store reason, one more attempt is made with a NEW cipher and a
   * new prompt. Throws SeAuthCancelled / SeAuthTimeout for those outcomes.
   */
  private fun runAuthed(newCipher: () -> Cipher, op: (Cipher) -> ByteArray): AuthedResult {
    if (Looper.myLooper() == Looper.getMainLooper()) {
      // waiting on the main thread would deadlock the prompt's own callbacks
      throw CodedException("ERR_SE", "biometric key operation called on the main thread", null)
    }
    var lastFailure: Exception? = null
    for (attempt in 1..2) {
      try {
        return promptOnce(newCipher(), op)
      } catch (e: javax.crypto.IllegalBlockSizeException) {
        lastFailure = e // key-store refusal after auth: retry with a fresh cipher
      } catch (e: UserNotAuthenticatedException) {
        lastFailure = e
      } catch (e: java.security.ProviderException) {
        lastFailure = e
      }
    }
    throw CodedException("ERR_SE", "biometric key operation failed: ${lastFailure?.message}", lastFailure)
  }

  private fun promptOnce(cipher: Cipher, op: (Cipher) -> ByteArray): AuthedResult {
    val activity = currentFragmentActivity()
      ?: throw CodedException("ERR_SE_UNAVAILABLE", "no biometric-capable activity is in the foreground", null)

    val latch = CountDownLatch(1)
    val finished = AtomicBoolean(false)
    var result: AuthedResult? = null
    var failure: Exception? = null
    var prompt: BiometricPrompt? = null

    fun finish(r: AuthedResult?, f: Exception?) {
      if (!finished.compareAndSet(false, true)) return // late callback after a timeout
      result = r
      failure = f
      latch.countDown()
    }

    val info = BiometricPrompt.PromptInfo.Builder()
      .setTitle("Vardum")
      .setSubtitle("Unlock your identity key")
      .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
      .setNegativeButtonText("Cancel")
      .setConfirmationRequired(false)
      .build()

    mainHandler.post {
      try {
        // androidx expects BiometricPrompt to be constructed on the main thread.
        val executor: Executor = if (Build.VERSION.SDK_INT >= 28) activity.mainExecutor else Executor { r -> mainHandler.post(r) }
        val p = BiometricPrompt(
          activity,
          executor,
          object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(authResult: BiometricPrompt.AuthenticationResult) {
              if (finished.get()) return
              // Use the cipher the prompt authorised, never a stale one.
              val authed = authResult.cryptoObject?.cipher ?: cipher
              try {
                finish(AuthedResult(op(authed), authed.iv), null)
              } catch (e: javax.crypto.AEADBadTagException) {
                finish(null, CodedException("ERR_GCM_AUTH", "authentication failure (GCM tag mismatch)", null))
              } catch (e: Exception) {
                finish(null, e)
              }
            }

            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
              finish(null, SeAuthCancelled(errorCode, errString.toString()))
            }

            override fun onAuthenticationFailed() {
              // single failed attempt (unrecognised finger) — the prompt stays up
            }
          },
        )
        prompt = p
        p.authenticate(info, BiometricPrompt.CryptoObject(cipher))
      } catch (e: Exception) {
        finish(null, e)
      }
    }

    if (!latch.await(SE_PROMPT_TIMEOUT_S, TimeUnit.SECONDS)) {
      if (finished.compareAndSet(false, true)) {
        mainHandler.post { try { prompt?.cancelAuthentication() } catch (e: Exception) { } }
        throw SeAuthTimeout()
      }
      // a callback won the race just now; its result is set
      latch.await()
    }

    failure?.let { throw it }
    return result ?: throw CodedException("ERR_SE", "se operation failed without a result", null)
  }


  // ---------- b75 (AL-6 / AL-11) helpers ----------

  private fun ckContext(): android.content.Context =
    appContext.reactContext?.applicationContext ?: throw CodedException("ERR_CK", "no context", null)

  private fun ckDir(): java.io.File {
    val d = java.io.File(ckContext().noBackupFilesDir, "vardum_ck")
    if (!d.exists() && !d.mkdirs()) throw CodedException("ERR_CK", "container key directory could not be made", null)
    return d
  }

  private fun ckFile(slot: String): java.io.File {
    if (!Regex("^[a-z]$").matches(slot)) throw CodedException("ERR_CK", "bad container key slot", null)
    return java.io.File(ckDir(), "$slot.ck")
  }

  private fun ckUnlockBoundFlag(): java.io.File = java.io.File(ckDir(), "wrap.unlock-bound")

  /** b75 round 3 (audit DV-11): one lock for every container-key file operation */
  private val ckLock = Any()

  /** b75 round 3 (DV-11): the wrap key a file's version byte names, or null (malformed) */
  private fun ckAliasFor(ver: Byte): String? = when (ver) {
    CK_VERSION -> CK_WRAP_ALIAS
    CK_VERSION_U -> CK_WRAP_ALIAS_U
    else -> null
  }

  private fun ckSecretKey(ks: KeyStore, alias: String): javax.crypto.SecretKey? =
    if (ks.containsAlias(alias)) (ks.getEntry(alias, null) as? KeyStore.SecretKeyEntry)?.secretKey else null

  /** b75 round 3 (audit DV-11): see ckRebindUnlocked. True when the slot files are bound to
   *  an unlocked phone (or there is nothing to bind); false when it can't be done yet. */
  private fun ckRebind(): Boolean {
    if (Build.VERSION.SDK_INT < 28) return false
    val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
    val hasOld = ks.containsAlias(CK_WRAP_ALIAS)
    val hasNew = ks.containsAlias(CK_WRAP_ALIAS_U)
    if (!hasOld) return hasNew // no first key: nothing sealed under it
    if (!hasNew && ckUnlockBoundFlag().exists()) return true // the first key is already bound
    val km = ckContext().getSystemService(android.content.Context.KEYGUARD_SERVICE) as? android.app.KeyguardManager ?: return false
    if (!km.isDeviceSecure || km.isDeviceLocked) return false // no screen lock yet, or locked now
    // 1. the new key, bound to an unlocked phone (made once; a launch cut short reuses it)
    if (!hasNew) {
      try {
        val g = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        g.init(
          KeyGenParameterSpec.Builder(CK_WRAP_ALIAS_U, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setRandomizedEncryptionRequired(true)
            .setUnlockedDeviceRequired(true)
            .build()
        )
        g.generateKey()
      } catch (e: Exception) {
        try { KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }.deleteEntry(CK_WRAP_ALIAS_U) } catch (e2: Exception) { }
        return false
      }
    }
    // 2. every file still sealed under the first key, re-sealed under the new one
    val dir = ckDir()
    val names = dir.listFiles()?.filter { it.isFile && it.name.endsWith(".ck") }?.map { it.name } ?: emptyList()
    for (name in names) {
      synchronized(ckLock) {
        val f = java.io.File(dir, name)
        val slot = name.removeSuffix(".ck")
        if (!f.exists() || !Regex("^[a-z]$").matches(slot)) return@synchronized
        val bytes = f.readBytes()
        if (bytes.size != 1 + 4 + 12 + 32 + 16 || bytes[0] != CK_VERSION) return@synchronized
        val ks2 = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        val oldKey = ckSecretKey(ks2, CK_WRAP_ALIAS) ?: return false
        val newKey = ckSecretKey(ks2, CK_WRAP_ALIAS_U) ?: return false
        val gen = java.nio.ByteBuffer.wrap(bytes, 1, 4).int
        val aad = "vardum-ck|$slot|$gen".toByteArray(Charsets.UTF_8)
        val dec = Cipher.getInstance("AES/GCM/NoPadding")
        dec.init(Cipher.DECRYPT_MODE, oldKey, GCMParameterSpec(128, bytes.copyOfRange(5, 17)))
        dec.updateAAD(aad)
        val raw = dec.doFinal(bytes.copyOfRange(17, bytes.size))
        try {
          val enc = Cipher.getInstance("AES/GCM/NoPadding")
          enc.init(Cipher.ENCRYPT_MODE, newKey)
          enc.updateAAD(aad)
          val ct = enc.doFinal(raw)
          val iv = enc.iv
          if (iv.size != 12 || ct.size != 48) return false
          val out = java.nio.ByteBuffer.allocate(1 + 4 + 12 + 48).put(CK_VERSION_U).putInt(gen).put(iv).put(ct).array()
          val tmp = java.io.File(dir, "$name.tmp")
          java.io.FileOutputStream(tmp).use { os -> os.write(out); os.flush(); os.fd.sync() }
          if (!tmp.renameTo(f)) { tmp.delete(); return false }
          ckSyncDir(dir)
        } finally {
          raw.fill(0)
        }
      }
    }
    // 3. nothing left under the first key: it goes, and the flag records the binding
    synchronized(ckLock) {
      val stillOld = dir.listFiles()?.any { it.isFile && it.name.endsWith(".ck") && it.length() == 65L && it.readBytes()[0] == CK_VERSION } ?: false
      if (stillOld) return false // a file made meanwhile: the next launch moves it
      KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }.deleteEntry(CK_WRAP_ALIAS)
      java.io.FileOutputStream(ckUnlockBoundFlag()).use { it.write(1); it.fd.sync() }
    }
    return true
  }

  /** overwrite with zeros, sync, delete. b75 round 2 (audit I2): the delete (the key is
   *  gone) is the protection; the zero overwrite is best-effort, since flash storage may
   *  keep the old blocks. */
  private fun ckShredFile(f: java.io.File) {
    if (!f.exists()) return
    try {
      val n = f.length().toInt().coerceAtLeast(0)
      java.io.RandomAccessFile(f, "rw").use { raf -> raf.seek(0); raf.write(ByteArray(n)); raf.fd.sync() }
    } catch (e: Exception) { /* the delete below still runs */ }
    if (!f.delete() && f.exists()) throw CodedException("ERR_CK", "container key file could not be deleted", null)
    f.parentFile?.let { ckSyncDir(it) }
  }

  private fun ckSyncDir(dir: java.io.File) {
    try {
      val fd = android.system.Os.open(dir.absolutePath, android.system.OsConstants.O_RDONLY, 0)
      try { android.system.Os.fsync(fd) } finally { android.system.Os.close(fd) }
    } catch (e: Exception) { /* not every filesystem allows a directory fsync */ }
  }

  /** The Keystore key that seals the container key files: AES-256-GCM, TEE (never
   *  StrongBox: speed), no user auth (background receive), bound to an unlocked phone
   *  where the platform allows it. */
  private fun ckWrapKey(): javax.crypto.SecretKey {
    val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
    if (!ks.containsAlias(CK_WRAP_ALIAS)) {
      val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
      fun spec(unlocked: Boolean): KeyGenParameterSpec {
        val b = KeyGenParameterSpec.Builder(CK_WRAP_ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
          .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
          .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
          .setKeySize(256)
          .setRandomizedEncryptionRequired(true)
        if (unlocked && Build.VERSION.SDK_INT >= 28) b.setUnlockedDeviceRequired(true)
        return b.build()
      }
      var bound = false
      if (Build.VERSION.SDK_INT >= 28) {
        try {
          generator.init(spec(true))
          generator.generateKey()
          bound = true
        } catch (e: Exception) {
          try { ks.deleteEntry(CK_WRAP_ALIAS) } catch (e2: Exception) { }
        }
      }
      if (!bound) {
        generator.init(spec(false))
        generator.generateKey()
      }
      val flag = ckUnlockBoundFlag()
      if (bound) { java.io.FileOutputStream(flag).use { it.write(1); it.fd.sync() } } else if (flag.exists()) flag.delete()
    }
    val entry = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }.getEntry(CK_WRAP_ALIAS, null) as? KeyStore.SecretKeyEntry
      ?: throw CodedException("ERR_CK_UNAVAILABLE", "container wrap key unavailable", null)
    return entry.secretKey
  }

  /** b75 (audit AL-11): the key's real security level, from its KeyInfo */
  private fun keyInsideSecureHardware(key: javax.crypto.SecretKey): Boolean {
    val factory = javax.crypto.SecretKeyFactory.getInstance(key.algorithm, ANDROID_KEYSTORE)
    val info = factory.getKeySpec(key, KeyInfo::class.java) as KeyInfo
    return if (Build.VERSION.SDK_INT >= 31) {
      info.securityLevel == KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT ||
        info.securityLevel == KeyProperties.SECURITY_LEVEL_STRONGBOX ||
        info.securityLevel == KeyProperties.SECURITY_LEVEL_UNKNOWN_SECURE
    } else {
      @Suppress("DEPRECATION")
      info.isInsideSecureHardware
    }
  }

  // ---------- hex / base64 helpers (mirror the Swift helpers) ----------

  /** b77t (audit 5 L-31, IH DEV-8): hex that must be well-formed (the AES-GCM AAD). hexToBytes returns an empty
   *  array for malformed hex, which for the AAD meant "no AAD" (fail open); this throws instead. "" = no AAD. */
  private fun strictHexToBytes(hex: String): ByteArray {
    val out = hexToBytes(hex)
    if (out.size * 2 != hex.length) throw CodedException("ERR_BAD_INPUT", "malformed hex (AAD)", null)
    return out
  }

  private fun hexToBytes(hex: String): ByteArray {
    val chars = hex.toCharArray()
    if (chars.size % 2 != 0) return ByteArray(0)
    val out = ByteArray(chars.size / 2)
    for (i in out.indices) {
      val hi = hexDigit(chars[i * 2]) ?: return ByteArray(0)
      val lo = hexDigit(chars[i * 2 + 1]) ?: return ByteArray(0)
      out[i] = ((hi shl 4) or lo).toByte()
    }
    return out
  }

  private fun hexDigit(c: Char): Int? = when (c) {
    in '0'..'9' -> c - '0'
    in 'a'..'f' -> c - 'a' + 10
    in 'A'..'F' -> c - 'A' + 10
    else -> null
  }

  private fun bytesToHex(bytes: ByteArray): String {
    val sb = StringBuilder(bytes.size * 2)
    for (b in bytes) {
      val v = b.toInt() and 0xff
      sb.append("0123456789abcdef"[v ushr 4])
      sb.append("0123456789abcdef"[v and 0x0f])
    }
    return sb.toString()
  }

  private fun b64ToBytes(b64: String): ByteArray? = try {
    Base64.decode(b64, Base64.NO_WRAP)
  } catch (e: IllegalArgumentException) {
    null
  }

  private fun bytesToB64(bytes: ByteArray): String = Base64.encodeToString(bytes, Base64.NO_WRAP)
}
