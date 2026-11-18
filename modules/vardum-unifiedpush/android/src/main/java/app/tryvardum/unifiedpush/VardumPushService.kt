package app.tryvardum.unifiedpush

import android.util.Log
import org.json.JSONObject
import org.unifiedpush.android.connector.FailedReason
import org.unifiedpush.android.connector.PushService
import org.unifiedpush.android.connector.data.PushEndpoint
import org.unifiedpush.android.connector.data.PushMessage

/**
 * Receives UnifiedPush events from the distributor (ntfy). Runs without the
 * JS engine, so a ping shows even when Vardum is closed.
 *
 * Contentless by design: whatever the payload says, the banner is only ever
 * "Notification" (b77p, audit 2 VAR-14: calls too — it said "Incoming call"; b77p round 2: a call still
 * RINGS, on the calls channel, VardumNotifier). The only thing read from the
 * (Web Push–encrypted) payload is kind == "call" and the relay's send time t
 * (freshness and replay check).
 */
class VardumPushService : PushService() {
  private val tag = "VardumPush"
  private companion object {
    const val CALL_FRESH_MS = 60_000L
    /** audit fix (b71): any push sent more than this ahead of our clock is dropped */
    const val MAX_FUTURE_MS = 60_000L
    /** audit fix (b71): any push older than this is dropped (a message ping
     *  can wait at the distributor while the phone is offline; a call can't) */
    const val MAX_AGE_MS = 24L * 60 * 60 * 1000
    /** b74 (audit VAR-13): the shape of the relay's push-verify code (base64url) */
    val PUSH_VERIFY_CODE = Regex("^[A-Za-z0-9_-]{8,64}$")
  }

  /** b75 (audit AL-12 / PU-3): debuggable builds only */
  private fun log(msg: String) = VardumPushStore.debugLog(applicationContext, tag, msg)

  override fun onNewEndpoint(endpoint: PushEndpoint, instance: String) {
    log("new endpoint received")
    VardumPushStore.saveEndpoint(
      applicationContext,
      endpoint.url,
      endpoint.pubKeySet?.pubKey,
      endpoint.pubKeySet?.auth,
    )
  }

  override fun onMessage(message: PushMessage, instance: String) {
    // Batch H (round-6 review R6-3-03): only a push encrypted to this phone's keys
    // (sent by the relay) shows a banner. On ntfy.sh anyone who knows the topic
    // can publish to it; such a push is dropped silently.
    if (!message.decrypted) {
      log("push not encrypted to this phone — ignored")
      return
    }
    // audit fix (b71): a captured push used to replay forever, and a call push
    // with no time (or a future one) counted as fresh. Now: the relay's send
    // time t is required; outside [now - 24 h, now + 60 s] the push is dropped;
    // each (kind, t) shows once (VardumPushStore.firstSighting). "Incoming
    // call" only while |now - t| < 60 s (Batch H R6-3-07), otherwise the
    // plain "Notification" (someone did call; the app shows the missed call).
    // The same rules are modelled in repro/push_replay_model.test.ts.
    val o = runCatching { JSONObject(String(message.content, Charsets.UTF_8).trim()) }.getOrNull()
    if (o == null) {
      log("push payload unreadable — ignored")
      return
    }
    val kind = o.optString("kind")
    val t = o.optLong("t", 0L)
    val now = System.currentTimeMillis()
    if (t <= 0L || t - now > MAX_FUTURE_MS || now - t > MAX_AGE_MS) {
      log("push without a plausible send time — ignored")
      return
    }
    // b74 (review VAR-03): decoy mode shows nothing. b75 (audit PU-3): and records
    // nothing either (checked before the replay notes are touched)
    if (kind != "push-verify" && VardumPushStore.isSilent(applicationContext)) {
      log("ping received while silenced — not shown")
      return
    }
    if (!VardumPushStore.firstSighting(applicationContext, kind, t, now)) {
      log("push already seen (replay) — ignored")
      return
    }
    // b74 (audit VAR-13): the relay's possession challenge for this address. It is kept
    // for the app (which re-registers with the code) and never shown as a banner.
    if (kind == "push-verify") {
      val code = o.optString("code")
      if (PUSH_VERIFY_CODE.matches(code)) VardumPushStore.savePushVerify(applicationContext, code, now)
      log("push-verify code received")
      return
    }
    // b74 (review VAR-03): decoy mode shows nothing (re-checked: the flag may have
    // been set while this push was being handled)
    if (VardumPushStore.isSilent(applicationContext)) {
      log("ping received while silenced — not shown")
      return
    }
    val isCall = kind == "call" && kotlin.math.abs(now - t) < CALL_FRESH_MS
    log("ping received (call=$isCall)")
    VardumNotifier.show(applicationContext, isCall)
  }

  override fun onRegistrationFailed(reason: FailedReason, instance: String) {
    log("registration failed: ${reason.name}")
    VardumPushStore.saveError(applicationContext, reason.name)
  }

  override fun onUnregistered(instance: String) {
    log("unregistered by distributor")
    VardumPushStore.clear(applicationContext)
  }
}
