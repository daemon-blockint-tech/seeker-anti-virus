package com.daemonblockint.sync

import android.app.Application
import android.app.NotificationChannel
import android.app.NotificationManager
import android.os.Build
import com.daemonblockint.sync.yara.NativeYaraBridge
import dagger.hilt.android.HiltAndroidApp
import javax.inject.Inject

@HiltAndroidApp
class SyncApp : Application() {

    @Inject
    lateinit var yaraBridge: NativeYaraBridge

    override fun onCreate() {
        super.onCreate()

        // Initialize native YARA engine (falls back to Kotlin if unavailable)
        yaraBridge.init()

        // Create notification channel for threat alerts
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_THREAT_ALERTS,
                "Threat Alerts",
                NotificationManager.IMPORTANCE_HIGH,
            ).apply {
                description = "Real-time threat detection alerts from Sync"
            }
            val nm = getSystemService(NotificationManager::class.java)
            nm.createNotificationChannel(channel)
        }
    }

    companion object {
        const val CHANNEL_THREAT_ALERTS = "sync_threat_alerts"
    }
}
