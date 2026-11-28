package net.aptist.loft.service

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.Binder
import android.os.IBinder
import android.os.Process
import androidx.work.BackoffPolicy
import androidx.work.Constraints
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.ExistingWorkPolicy
import androidx.work.NetworkType
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.withTimeoutOrNull
import net.aptist.loft.ipc.ILoftControl
import net.aptist.loft.ipc.ILoftHubEvents
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicLong

internal object NotesSyncSchedule {
    private const val PERIODIC = "secure-notes-periodic-v1"
    private const val EDITS = "secure-notes-edits-v1"
    private const val RESET = "secure-notes-reset-v1"
    private val constraints = Constraints.Builder().setRequiredNetworkType(NetworkType.CONNECTED)
        .setRequiresBatteryNotLow(true).build()

    fun configure(context: Context, eligible: Boolean) {
        val manager = WorkManager.getInstance(context)
        if (eligible) {
            val request = PeriodicWorkRequestBuilder<NotesSyncWorker>(60, TimeUnit.MINUTES, 15, TimeUnit.MINUTES)
                .setConstraints(constraints)
                .setBackoffCriteria(BackoffPolicy.EXPONENTIAL, 30, TimeUnit.SECONDS)
                .build()
            manager.enqueueUniquePeriodicWork(PERIODIC, ExistingPeriodicWorkPolicy.KEEP, request)
        } else {
            manager.cancelUniqueWork(PERIODIC)
            manager.cancelUniqueWork(EDITS)
            manager.cancelUniqueWork(RESET)
        }
    }

    fun reset(context: Context) {
        val request = OneTimeWorkRequestBuilder<NotesSyncWorker>()
            .setBackoffCriteria(BackoffPolicy.EXPONENTIAL, 30, TimeUnit.SECONDS)
            .setConstraints(constraints)
            .build()
        WorkManager.getInstance(context).enqueueUniqueWork(RESET, ExistingWorkPolicy.KEEP, request)
    }

    fun edited(context: Context) {
        val request = OneTimeWorkRequestBuilder<NotesSyncWorker>()
            .setInitialDelay(30, TimeUnit.SECONDS)
            .setBackoffCriteria(BackoffPolicy.EXPONENTIAL, 30, TimeUnit.SECONDS)
            .setConstraints(constraints)
            .build()
        WorkManager.getInstance(context).enqueueUniqueWork(EDITS, ExistingWorkPolicy.REPLACE, request)
    }
}

class NotesSyncWorker(context: Context, parameters: WorkerParameters) : CoroutineWorker(context, parameters) {
    override suspend fun doWork(): Result {
        val requestId = ids.incrementAndGet()
        val pending = CompletableDeferred<String>()
        var control: ILoftControl? = null
        val callback = object : ILoftHubEvents.Stub() {
            override fun onResult(id: Long, code: String, payload: ByteArray) {
                if (Binder.getCallingUid() == Process.myUid() && id == requestId && payload.isEmpty()) pending.complete(code)
                payload.fill(0)
            }
        }
        val connection = object : ServiceConnection {
            override fun onServiceConnected(name: ComponentName, service: IBinder) {
                control = ILoftControl.Stub.asInterface(service)
                runCatching { control?.executeNotesSync(requestId, callback) }
                    .onFailure { pending.complete("unavailable") }
            }
            override fun onServiceDisconnected(name: ComponentName) { pending.complete("unavailable") }
            override fun onBindingDied(name: ComponentName) { pending.complete("unavailable") }
            override fun onNullBinding(name: ComponentName) { pending.complete("unavailable") }
        }
        val bound = applicationContext.bindService(Intent(applicationContext, LoftCoreService::class.java),
            connection, Context.BIND_AUTO_CREATE)
        val outcome = if (bound) try {
            withTimeoutOrNull(85_000) { pending.await() }
        } finally {
            runCatching { control?.cancelNotesSync(requestId) }
            applicationContext.unbindService(connection)
        } else null
        if (outcome in setOf("ok", "ineligible", "sign_in", "unsupported", "authentication", "capacity", "invalid")) {
            return Result.success()
        }
        return if (runAttemptCount < 2) Result.retry() else Result.success()
    }

    private companion object { val ids = AtomicLong() }
}
