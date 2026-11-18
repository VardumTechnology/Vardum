package app.tryvardum.unifiedpush

import android.Manifest
import android.annotation.SuppressLint
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.BitmapFactory
import android.media.AudioAttributes
import android.net.Uri
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat

/**
 * Shows the contentless Vardum banner natively.
 *
 * Uses the SAME channel ids the JS side creates in src/notifications.ts
 * ('default' = Messages, HIGH; 'vardum-ring' = Calls, MAX, the ring sound), so the
 * user's channel settings apply to both paths. If JS has never run on this install,
 * the channels are created here with the same importance (and sound).
 *
 * b77p round 2 (owner decision 2): a call RINGS again — the calls channel (ring sound,
 * MAX, CATEGORY_CALL) — with the SAME text as a message, "Vardum / Notification". Which
 * kind it is comes from inside the Web Push encryption, so the push server sees nothing new.
 */
object VardumNotifier {
  private const val CH_MESSAGES = "default"
  private const val CH_CALLS = "vardum-ring" // b77p round 2: replaces "calls" (made without a sound; a channel's sound can't change)
  private const val ID_MESSAGE = 7001
  private const val ID_CALL = 7002
  private const val TEAL = 0xFF20D9C2.toInt()

  @SuppressLint("MissingPermission") // checked explicitly below
  fun show(c: Context, call: Boolean) {
    // b77p (audit 2 VAR-14): ONE text for every kind (the lock screen said "Incoming call").
    // b77p round 2 (owner decision 2): a call rings on the calls channel; the text stays the same.
    if (Build.VERSION.SDK_INT >= 33 &&
      ContextCompat.checkSelfPermission(c, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
    ) return

    ensureChannels(c)

    val launch = c.packageManager.getLaunchIntentForPackage(c.packageName)?.apply {
      addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP)
    }
    val tap = launch?.let {
      PendingIntent.getActivity(
        c,
        if (call) ID_CALL else ID_MESSAGE,
        it,
        PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
      )
    }

    val n = NotificationCompat.Builder(c, if (call) CH_CALLS else CH_MESSAGES)
      .setSmallIcon(R.drawable.vardum_notify)
      .setLargeIcon(BitmapFactory.decodeResource(c.resources, R.drawable.vardum_notify_large))
      .setColor(TEAL)
      .setContentTitle("Vardum")
      .setContentText("Notification") // b77p (audit 2 VAR-14): one text for every kind
      .setPriority(if (call) NotificationCompat.PRIORITY_MAX else NotificationCompat.PRIORITY_HIGH)
      .setCategory(if (call) NotificationCompat.CATEGORY_CALL else NotificationCompat.CATEGORY_MESSAGE)
      .setVisibility(NotificationCompat.VISIBILITY_PUBLIC)
      .setAutoCancel(true)
      .apply { if (tap != null) setContentIntent(tap) }
      .build()

    NotificationManagerCompat.from(c).notify(if (call) ID_CALL else ID_MESSAGE, n)
  }

  private fun ensureChannels(c: Context) {
    if (Build.VERSION.SDK_INT < 26) return
    val nm = c.getSystemService(NotificationManager::class.java) ?: return
    if (nm.getNotificationChannel(CH_MESSAGES) == null) {
      nm.createNotificationChannel(
        NotificationChannel(CH_MESSAGES, "Messages", NotificationManager.IMPORTANCE_HIGH).apply {
          lockscreenVisibility = android.app.Notification.VISIBILITY_PUBLIC
          vibrationPattern = longArrayOf(0, 250, 250, 250)
          enableVibration(true)
        },
      )
    }
    if (nm.getNotificationChannel(CH_CALLS) == null) {
      nm.createNotificationChannel(
        NotificationChannel(CH_CALLS, "Calls", NotificationManager.IMPORTANCE_MAX).apply {
          lockscreenVisibility = android.app.Notification.VISIBILITY_PUBLIC
          vibrationPattern = longArrayOf(0, 600, 800, 600, 800)
          enableVibration(true)
          // the ring the expo-notifications plugin bundles (app.json "sounds" -> res/raw/veil_ring.wav)
          val ring = c.resources.getIdentifier("veil_ring", "raw", c.packageName)
          if (ring != 0) setSound(
            Uri.parse("android.resource://" + c.packageName + "/" + ring),
            AudioAttributes.Builder().setUsage(AudioAttributes.USAGE_NOTIFICATION_RINGTONE).setContentType(AudioAttributes.CONTENT_TYPE_SONIFICATION).build(),
          )
        },
      )
    }
    nm.deleteNotificationChannel("calls") // b77p round 2: the old soundless calls channel
  }
}
