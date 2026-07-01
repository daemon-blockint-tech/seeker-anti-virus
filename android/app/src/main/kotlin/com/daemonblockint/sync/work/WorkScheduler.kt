package com.daemonblockint.sync.work

import android.content.Context
import androidx.work.Constraints
import androidx.work.NetworkType
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import java.util.concurrent.TimeUnit

object WorkScheduler {

    private const val OTA_WORK_NAME = "sync_ota_update"

    fun scheduleOtaUpdates(context: Context) {
        val constraints = Constraints.Builder()
            .setRequiredNetworkType(NetworkType.UNMETERED)
            .setRequiresBatteryNotLow(true)
            .build()

        val request = PeriodicWorkRequestBuilder<OtaUpdateWorker>(6, TimeUnit.HOURS)
            .setConstraints(constraints)
            .build()

        WorkManager.getInstance(context).enqueueUniquePeriodicWork(
            OTA_WORK_NAME,
            androidx.work.ExistingPeriodicWorkPolicy.KEEP,
            request,
        )
    }
}
