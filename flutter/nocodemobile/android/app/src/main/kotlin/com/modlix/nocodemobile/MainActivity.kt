package com.modlix.nocodemobile

import android.Manifest
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import com.google.firebase.FirebaseApp
import com.google.firebase.messaging.FirebaseMessaging
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel

// Push (FCM) for the web app through the `modlix/push` channel (lib/push.dart):
//   status   -> {status}
//   register -> {status, platform, token, appIdentifier, providerAccount}; asks with {prompt: true}
//   token    -> the same, never asking
//   initialUrl -> the url of the notification that started the app, once
// and "open" (url) to Dart when a notification is tapped while the app runs.
//
// Firebase starts on its own from res/values/firebase.xml (google_app_id and friends), which
// make.py writes only for an app with push on; without it there is no FirebaseApp and push
// answers "unsupported". A notification arriving in the background is shown by FCM itself;
// in the foreground the web app's own in-app toast shows it, so nothing is drawn here.
class MainActivity : FlutterActivity() {
    private var channel: MethodChannel? = null
    private var pendingPermission: MethodChannel.Result? = null
    private var initialUrl: String? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        initialUrl = urlOf(intent)
        super.onCreate(savedInstanceState)
        // The channel AndroidManifest.xml names for FCM; it must exist before a push arrives.
        if (Build.VERSION.SDK_INT >= 26) {
            val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            nm.createNotificationChannel(NotificationChannel(CHANNEL_ID, "Notifications", NotificationManager.IMPORTANCE_HIGH))
        }
    }

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        val ch = MethodChannel(flutterEngine.dartExecutor.binaryMessenger, "modlix/push")
        channel = ch
        ch.setMethodCallHandler { call, result ->
            when (call.method) {
                "status" -> result.success(mapOf("status" to status()))
                "register" -> register(call.argument<Boolean>("prompt") == true, result)
                "token" -> register(false, result)
                "initialUrl" -> {
                    result.success(initialUrl)
                    initialUrl = null
                }
                else -> result.notImplemented()
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        urlOf(intent)?.let { channel?.invokeMethod("open", it) }
    }

    /** The `url` data of a tapped FCM notification (FCM puts data keys in the extras). */
    private fun urlOf(intent: Intent?): String? = intent?.extras?.getString("url")?.takeIf { it.isNotBlank() }

    private fun firebaseReady(): Boolean = FirebaseApp.getApps(this).isNotEmpty()

    private fun permissionGranted(): Boolean =
        Build.VERSION.SDK_INT < 33 || checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED

    private fun status(): String {
        if (!firebaseReady()) return "unsupported"
        if (!permissionGranted()) return "default"
        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        return if (Build.VERSION.SDK_INT >= 24 && !nm.areNotificationsEnabled()) "denied" else "granted"
    }

    private fun register(prompt: Boolean, result: MethodChannel.Result) {
        if (!firebaseReady()) return result.success(mapOf("status" to "unsupported"))
        if (!permissionGranted()) {
            if (!prompt || Build.VERSION.SDK_INT < 33) return result.success(mapOf("status" to "default"))
            pendingPermission?.success(mapOf("status" to "default"))
            pendingPermission = result
            requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), PERMISSION_REQUEST)
            return
        }
        val current = status()
        if (current != "granted") return result.success(mapOf("status" to current))
        FirebaseMessaging.getInstance().token.addOnCompleteListener { task ->
            if (!task.isSuccessful || task.result.isNullOrBlank()) {
                result.success(mapOf("status" to "unsupported"))
                return@addOnCompleteListener
            }
            result.success(
                mapOf(
                    "status" to "granted",
                    "platform" to "ANDROID",
                    "token" to task.result,
                    "appIdentifier" to packageName,
                    "providerAccount" to FirebaseApp.getInstance().options.projectId,
                ),
            )
        }
    }

    override fun onRequestPermissionsResult(requestCode: Int, permissions: Array<out String>, grantResults: IntArray) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode != PERMISSION_REQUEST) return
        val waiting = pendingPermission ?: return
        pendingPermission = null
        if (grantResults.firstOrNull() == PackageManager.PERMISSION_GRANTED) {
            register(false, waiting)
        } else {
            waiting.success(mapOf("status" to "denied"))
        }
    }

    companion object {
        private const val PERMISSION_REQUEST = 7301
        private const val CHANNEL_ID = "notifications"
    }
}
