package app.tryvardum.unifiedpush

import android.content.Context
import android.content.SharedPreferences
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyStore
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.KeyGenerator
import javax.crypto.Mac
import javax.crypto.SecretKey

/**
 * Persists the current UnifiedPush endpoint so it survives the app being
 * killed (the distributor can deliver a new endpoint while no JS is running).
 * Holds only the endpoint URL and its public Web Push keys — no secrets; the
 * private decryption keys stay inside the connector's own key store.
 */
object VardumPushStore {
  private const val PREFS = "vardum_unifiedpush"
  private const val K_URL = "url"
  private const val K_PUB = "pubKey"
  private const val K_AUTH = "auth"
  private const val K_ERR = "lastError"

  /** Set by the JS module while it is alive, so a new endpoint reaches JS at once. */
  @Volatile
  var listener: (() -> Unit)? = null

  private fun prefs(c: Context): SharedPreferences =
    c.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

  fun saveEndpoint(c: Context, url: String, pubKey: String?, auth: String?) {
    prefs(c).edit()
      .putString(K_URL, url)
      .putString(K_PUB, pubKey ?: "")
      .putString(K_AUTH, auth ?: "")
      .remove(K_ERR)
      .apply()
    runCatching { listener?.invoke() }
  }

  fun endpoint(c: Context): Map<String, String>? {
    val p = prefs(c)
    val url = p.getString(K_URL, null) ?: return null
    return mapOf(
      "url" to url,
      "pubKey" to (p.getString(K_PUB, "") ?: ""),
      "auth" to (p.getString(K_AUTH, "") ?: ""),
    )
  }

  /** b75 (audit PU-3): the pre-b75 list of every push's (kind, time) — a plaintext
   *  timeline of when messages and calls arrived — is no longer kept; removed on sight */
  private const val K_SEEN_LEGACY = "seenPushes"
  private const val K_FLOOR_LEGACY = "seenFloor"

  /** per kind: "m" message, "c" call, "v" push-verify */
  private fun kindKey(kind: String): String = when (kind) { "call" -> "c"; "push-verify" -> "v"; else -> "m" }

  /**
   * audit fix (b71): true the FIRST time a push with this (kind, t) arrives,
   * false for a replay.
   * b75 (audit PU-3): kept per kind as a floor and the last few times shown (at most
   * RECENT_MAX) instead of a list of up to 200 push times. A push at or below the floor,
   * or equal to a recent one, is dropped (an older push arriving after a newer one of
   * the same kind adds no banner: the newer one already showed it). The floor never
   * moves past this phone's own clock (`now`), so a push dated ahead — up to the 60 s
   * the service allows — can't silence the genuine pushes sent after it; the recent
   * times keep such a push from showing again.
   * b77n (pre-audit INFO-4): the floor and the recent times live in this process's memory
   * only. Kept in SharedPreferences (floor_* / recent_*) they were a plaintext record of
   * when the last four pings of each kind arrived; the persisted keys are removed on sight.
   * Trade-off: after the service process dies, a push already shown (still inside the
   * service's 24 h window, and encrypted to this phone, so only the relay or the
   * distributor can send it again) can show one more contentless banner.
   */
  private const val RECENT_MAX = 4
  private val floors = HashMap<String, Long>()
  private val recents = HashMap<String, List<Long>>()

  /** b77n (INFO-4): the replay notes older builds persisted (and b75's legacy timeline) */
  private fun isPersistedReplayKey(key: String): Boolean =
    key == K_SEEN_LEGACY || key == K_FLOOR_LEGACY || key.startsWith("floor_") || key.startsWith("recent_")

  @Synchronized
  fun firstSighting(c: Context, kind: String, t: Long, now: Long): Boolean {
    val k = kindKey(kind)
    val floor = floors[k] ?: 0L
    val recent = recents[k] ?: emptyList()
    if (t <= floor || recent.contains(t)) return false
    val p = prefs(c)
    val stale = p.all.keys.filter { isPersistedReplayKey(it) }
    if (stale.isNotEmpty()) { val e = p.edit(); stale.forEach { e.remove(it) }; e.commit() }
    recents[k] = (recent + t).filter { it > floor }.takeLast(RECENT_MAX)
    floors[k] = maxOf(floor, minOf(t, now))
    return true
  }

  /**
   * b74 (review VAR-03): true while the app is in decoy mode. The service then shows no
   * banner, so the real account's pings can't give the decoy away. Written with
   * commit() (synchronous) so a kill right after entering the decoy can't lose it; it
   * stays set until the real password unlocks again.
   *
   * b77n (pre-audit INFO-4): the flag is no longer a plain boolean ("silent" = true told
   * anyone who could read this app's SharedPreferences that a decoy session was up). The
   * service runs without the JS engine and can't open the app's sealed decoy hold
   * (vardum_push_hold_v1, sealed under the container key in JS), so a bit has to be kept
   * here; it is kept so that ON and OFF look alike at rest:
   *   K_SILENT_TAG = base64(nonce16 || x32), always the same shape
   *   ON : x = HMAC-SHA256(K, SILENT_LABEL || nonce)
   *   OFF: x = 32 random bytes
   * K is an HMAC key generated inside the Android Keystore (alias SILENT_KEY_ALIAS; it never
   * leaves the Keystore), so without running code as this app on this phone the two can't
   * be told apart, and a fresh nonce per write means a copy taken earlier says nothing either.
   * Reading fails SILENT: a record of the wrong shape, a missing key while a record exists,
   * or any Keystore error reads as ON. No record at all reads as OFF. If the Keystore refuses
   * while turning the flag ON, an unverifiable record is written instead (it reads as ON).
   *
   * b77q (audit 3 AP-2): the record (and its Keystore key) used to appear only once decoy
   * mode had been used, so its mere presence said so. Now every install keeps one from the
   * start: ensureSilentRecord() writes an OFF record whenever none exists (the module's
   * creation, the service's first read, and right after clear()), so a phone that never used
   * the decoy holds the same key and the same-shaped record as one that did.
   */
  private const val K_SILENT_LEGACY = "silent"
  private const val K_SILENT_TAG = "st"
  private const val SILENT_KEY_ALIAS = "vardum_up_silent_v1"
  private const val SILENT_LABEL = "vardum-up-silent-v1|"
  private const val NONCE_LEN = 16
  private const val TAG_LEN = 32

  private fun silentKey(create: Boolean): SecretKey? {
    val ks = KeyStore.getInstance("AndroidKeyStore")
    ks.load(null)
    val have = ks.getKey(SILENT_KEY_ALIAS, null) as? SecretKey
    if (have != null || !create) return have
    val g = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_HMAC_SHA256, "AndroidKeyStore")
    g.init(KeyGenParameterSpec.Builder(SILENT_KEY_ALIAS, KeyProperties.PURPOSE_SIGN).build())
    return g.generateKey()
  }

  private fun silentMac(k: SecretKey, nonce: ByteArray): ByteArray {
    val m = Mac.getInstance("HmacSHA256")
    m.init(k)
    m.update(SILENT_LABEL.toByteArray(Charsets.UTF_8))
    return m.doFinal(nonce)
  }

  @Synchronized
  fun setSilent(c: Context, on: Boolean) {
    val rnd = SecureRandom()
    val nonce = ByteArray(NONCE_LEN).also { rnd.nextBytes(it) }
    val key = runCatching { silentKey(true) }.getOrNull()
    val x: ByteArray? = if (on) {
      if (key != null) runCatching { silentMac(key, nonce) }.getOrNull() else null
    } else {
      ByteArray(TAG_LEN).also { rnd.nextBytes(it) }
    }
    // ON with the Keystore refusing: an unverifiable record (wrong shape), which reads as ON
    val v = if (x != null) Base64.encodeToString(nonce + x, Base64.NO_WRAP) else "-"
    prefs(c).edit().putString(K_SILENT_TAG, v).remove(K_SILENT_LEGACY).commit()
  }

  /** b77q (audit 3 AP-2): an OFF record (and the Keystore key) when none exists yet. Only
   *  once the key exists: a well-shaped record without its key reads as ON (fail silent). */
  @Synchronized
  fun ensureSilentRecord(c: Context) {
    val p = prefs(c)
    if (p.contains(K_SILENT_TAG) || p.contains(K_SILENT_LEGACY)) return
    if (runCatching { silentKey(true) }.getOrNull() == null) return
    setSilent(c, false)
  }

  @Synchronized
  fun isSilent(c: Context): Boolean {
    val p = prefs(c)
    // an older build's plain flag: carried over once, then removed
    if (p.contains(K_SILENT_LEGACY)) setSilent(c, runCatching { p.getBoolean(K_SILENT_LEGACY, true) }.getOrDefault(true))
    val s = p.getString(K_SILENT_TAG, null)
    if (s == null) { runCatching { ensureSilentRecord(c) }; return false } // b77q (AP-2): no record = OFF, now written
    return try {
      val b = Base64.decode(s, Base64.NO_WRAP)
      val k = if (b.size == NONCE_LEN + TAG_LEN) silentKey(false) else null
      if (k == null) true
      else MessageDigest.isEqual(silentMac(k, b.copyOfRange(0, NONCE_LEN)), b.copyOfRange(NONCE_LEN, b.size))
    } catch (e: Exception) {
      true
    }
  }

  /**
   * b77n2 (review INFO): true when a flag record exists that can't be verified — the Keystore key is
   * missing or refuses, or the record is the "-" written when the Keystore refused while turning the flag
   * ON. isSilent() reads such a record as ON (fail silent, unchanged), so while it lasts no banner shows,
   * whatever the app last set. This only lets the app SEE that state (Settings); it changes no reading.
   * Not a decoy tell: a verifiable ON record (the normal decoy case) reads false here.
   */
  @Synchronized
  fun silentUnverifiable(c: Context): Boolean {
    val s = prefs(c).getString(K_SILENT_TAG, null) ?: return false
    return try {
      val b = Base64.decode(s, Base64.NO_WRAP)
      b.size != NONCE_LEN + TAG_LEN || silentKey(false) == null
    } catch (e: Exception) {
      true
    }
  }

  private const val K_PV_CODE = "pushVerifyCode"
  private const val K_PV_AT = "pushVerifyAt"
  /** b74 (audit VAR-13): how long a kept push-verify code stays usable (the relay's own TTL) */
  private const val PUSH_VERIFY_MAX_AGE_MS = 10L * 60 * 1000

  /** b74 (audit VAR-13): keep the relay's push-verify code for the app (the newest wins) */
  fun savePushVerify(c: Context, code: String, at: Long) {
    prefs(c).edit().putString(K_PV_CODE, code).putLong(K_PV_AT, at).apply()
  }

  /** b74 (audit VAR-13): the kept code, once (cleared on read); null when none or stale */
  @Synchronized
  fun takePushVerify(c: Context, now: Long): String? {
    val p = prefs(c)
    val code = p.getString(K_PV_CODE, null) ?: return null
    val at = p.getLong(K_PV_AT, 0L)
    p.edit().remove(K_PV_CODE).remove(K_PV_AT).apply()
    return if (now - at in 0..PUSH_VERIFY_MAX_AGE_MS) code else null
  }

  fun saveError(c: Context, reason: String) {
    prefs(c).edit().putString(K_ERR, reason).apply()
  }

  fun lastError(c: Context): String? = prefs(c).getString(K_ERR, null)

  fun clear(c: Context) {
    // b75 (audit PU-3): synchronous, so a wipe's unregister can't leave the old
    // endpoint and replay notes behind after a hard kill
    prefs(c).edit().clear().commit()
    // b77q (audit 3 AP-2): an OFF silent record is written back at once (clearing used to
    // leave the record missing, and a missing record now never happens on a used install)
    runCatching { ensureSilentRecord(c) }
    // b77n (INFO-4): and the in-memory replay notes
    synchronized(this) { floors.clear(); recents.clear() }
    runCatching { listener?.invoke() }
  }

  /** b75 (audit AL-12 / PU-3): log lines only in a debuggable build (release logcat
   *  gets no push timeline) */
  fun debugLog(c: Context, tag: String, msg: String) {
    if ((c.applicationInfo.flags and android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE) != 0) android.util.Log.i(tag, msg)
  }
}
