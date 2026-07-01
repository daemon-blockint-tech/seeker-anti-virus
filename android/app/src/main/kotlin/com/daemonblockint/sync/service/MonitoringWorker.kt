package com.daemonblockint.sync.service

import android.app.Notification
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import androidx.core.app.NotificationCompat
import androidx.work.CoroutineWorker
import androidx.work.ForegroundInfo
import androidx.work.WorkerParameters
import com.daemonblockint.sync.MainActivity
import com.daemonblockint.sync.R
import com.daemonblockint.sync.SyncApp
import com.daemonblockint.sync.engine.monitor.Monitor
import com.daemonblockint.sync.engine.monitor.ThreatAlert
import dagger.hilt.android.qualifiers.ApplicationContext
import javax.inject.Inject

/**
 * Background monitoring worker that continuously evaluates app behavior
 * and pushes real-time threat alerts (PRD FR-1, FR-3).
 *
 * Runs as a foreground service with a persistent notification.
 */
class MonitoringWorker @Inject constructor(
    @ApplicationContext private val context: Context,
    params: WorkerParameters,
) : CoroutineWorker(context, params) {

    override suspend fun doWork(): Result {
        // In production, this sets up accessibility service listeners,
        // network monitors, and clipboard watchers that feed BehaviorEvents
        // into the Monitor. For now, it's a placeholder that keeps the
        // foreground notification active.
        setForeground(buildForegroundInfo())
        return Result.success()
    }

    private fun buildForegroundInfo(): ForegroundInfo {
        val notification = NotificationCompat.Builder(context, SyncApp.CHANNEL_THREAT_ALERTS)
            .setContentTitle("Sync is monitoring")
            .setContentText("Real-time threat protection active")
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setOngoing(true)
            .build()

        return ForegroundInfo(NOTIFICATION_ID, notification)
    }

    companion object {
        private const val NOTIFICATION_ID = 1001

        /**
         * Build a threat alert notification for a detected threat.
         */
        fun buildAlertNotification(context: Context, alert: ThreatAlert): Notification {
            val intent = Intent(context, MainActivity::class.java).apply {
                flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK
            }
            val pendingIntent = PendingIntent.getActivity(
                context, 0, intent,
                PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
            )

            val priority = when (alert.severity) {
                com.daemonblockint.sync.engine.Severity.CRITICAL -> NotificationCompat.PRIORITY_MAX
                com.daemonblockint.sync.engine.Severity.HIGH -> NotificationCompat.PRIORITY_HIGH
                else -> NotificationCompat.PRIORITY_DEFAULT
            }

            return NotificationCompat.Builder(context, SyncApp.CHANNEL_THREAT_ALERTS)
                .setContentTitle("Threat Detected: ${alert.title}")
                .setContentText("Risk score ${alert.score}/100 — ${alert.severity}")
                .setSmallIcon(android.R.drawable.ic_dialog_alert)
                .setPriority(priority)
                .setContentIntent(pendingIntent)
                .setAutoCancel(true)
                .build()
        }

        fun showAlert(context: Context, alert: ThreatAlert) {
            val nm = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            nm.notify(alert.at.toInt(), buildAlertNotification(context, alert))
        }
    }
}
