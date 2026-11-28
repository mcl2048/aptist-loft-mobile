package net.aptist.loft.service

import android.os.SystemClock
import net.aptist.loft.core.generated.AppCore
import net.aptist.loft.core.generated.VaultException
import net.aptist.loft.ipc.ILoftHubEvents
import java.io.IOException
import java.util.concurrent.SynchronousQueue
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

internal class VaultControl(private val unavailable: (AppCore) -> Unit) {
    class Work(val id: Long, val command: VaultCommand, val observer: ILoftHubEvents, private val visible: () -> Boolean) {
        val cancelled = AtomicBoolean(false)
        fun active() = !cancelled.get() && visible()
    }

    private val sync = ThreadPoolExecutor(0, 1, 30, TimeUnit.SECONDS, SynchronousQueue())
    private val activeSync = AtomicReference<Work?>(null)
    private val reveal = AtomicReference<Work?>(null)

    fun admit(work: Work): Boolean = when (work.command) {
        is VaultCommand.Sync -> activeSync.compareAndSet(null, work)
        is VaultCommand.Reveal -> reveal.compareAndSet(null, work)
        else -> true
    }

    fun cancel(id: Long? = null) {
        sequenceOf(activeSync.get(), reveal.get()).filterNotNull()
            .filter { id == null || it.id == id }.forEach { it.cancelled.set(true) }
    }

    fun reject(work: Work, code: String) {
        clear(work)
        if (work.active()) reply(work, code)
    }

    private fun clear(work: Work) {
        work.command.clear()
        activeSync.compareAndSet(work, null)
        reveal.compareAndSet(work, null)
    }

    fun local(core: AppCore, work: Work) {
        var result: VaultResult? = null
        var code = "ok"
        try {
            if (work.active()) when (val command = work.command) {
                is VaultCommand.ListPage -> result = VaultResult.Page(core.vaultList(command.archived, command.offset, command.generation))
                is VaultCommand.Import -> core.vaultImport(command.uri)
                is VaultCommand.Save -> core.vaultSave(command.draft)
                is VaultCommand.Archive -> core.vaultArchive(command.id, command.archived)
                is VaultCommand.Reveal -> {
                    val elapsed = SystemClock.elapsedRealtime()
                    val wall = System.currentTimeMillis()
                    val reveal = core.vaultReveal(command.id, (wall / 1000).toULong())
                    val lifetime = reveal.validForSeconds?.let { it.toLong() * 1000 - wall.mod(1000L) } ?: 15_000L
                    result = VaultResult.Reveal(reveal, elapsed + lifetime)
                }
                is VaultCommand.Sync -> error("VAULT_SYNC_WORKER_REQUIRED")
            }
        } catch (failure: VaultException) {
            code = problem(core, failure)
        } catch (_: Exception) {
            code = "unavailable"
        } catch (_: LinkageError) {
            code = "unavailable"
        } finally { clear(work) }
        try { if (work.active()) reply(work, code, result) }
        finally { (result as? VaultResult.Reveal)?.value?.value?.fill(0) }
    }

    fun sync(core: AppCore, work: Work, release: () -> Unit) {
        try {
            sync.execute {
                val code = try {
                    if (work.active()) exchange(core, work)
                    "ok"
                } catch (failure: VaultException) { problem(core, failure) }
                catch (_: IOException) { "network" }
                catch (_: Exception) { "unavailable" }
                catch (_: LinkageError) { "unavailable" }
                finally { clear(work); release() }
                if (work.active()) reply(work, code)
            }
        } catch (_: java.util.concurrent.RejectedExecutionException) {
            release()
            reject(work, "busy")
        }
    }

    private fun exchange(core: AppCore, work: Work) {
        val command = work.command as VaultCommand.Sync
        var request = try { core.vaultSyncBegin(command.passphrase) } finally { command.clear() }
        // Rust owns the bounded GET/PUT sequence and admits each follow-up.
        repeat(3) {
            var next: net.aptist.loft.core.generated.HubRequest? = null
            try {
                val response = exchangeHub(request) { work.active() }
                try {
                    if (!work.active()) throw IOException()
                    next = core.vaultSyncFinish(request.requestId, response.status, response.mediaType, response.body).nextRequest
                } finally { response.body.fill(0) }
            } finally {
                request.body.fill(0)
                if (next == null) runCatching { core.vaultSyncAbandon(request.requestId) }
            }
            request = next ?: return
        }
        request.body.fill(0)
        runCatching { core.vaultSyncAbandon(request.requestId) }
        throw IOException()
    }

    private fun problem(core: AppCore, failure: VaultException): String {
        return when (failure) {
            is VaultException.InvalidInput -> "invalid"
            is VaultException.NotFound, is VaultException.Archived -> "missing"
            is VaultException.Conflict, is VaultException.StaleGeneration -> "conflict"
            is VaultException.TooLarge -> "capacity"
            is VaultException.NotSignedIn -> "sign_in"
            is VaultException.AuthenticationFailed -> "passphrase"
            is VaultException.Busy -> "busy"
            is VaultException.NetworkUnavailable -> "network"
            is VaultException.StorageRecoveryRequired -> "unavailable"
            is VaultException.Unavailable -> { unavailable(core); "unavailable" }
        }
    }

    private fun reply(work: Work, code: String, result: VaultResult? = null) {
        val data = try { result?.let(VaultWire::result) } catch (_: IOException) { null }
        try { work.observer.onResult(work.id, if (result != null && data == null) "unavailable" else code, data ?: byteArrayOf()) }
        catch (_: android.os.RemoteException) { }
        finally { data?.fill(0) }
    }
}
