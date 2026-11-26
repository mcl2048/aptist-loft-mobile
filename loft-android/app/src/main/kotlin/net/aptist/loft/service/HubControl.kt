package net.aptist.loft.service

import android.os.ParcelFileDescriptor
import android.os.RemoteException
import net.aptist.loft.core.generated.AppCore
import net.aptist.loft.core.generated.HubAction
import net.aptist.loft.core.generated.HubException
import net.aptist.loft.ipc.ILoftHubEvents
import java.io.IOException
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

internal class HubControl(private val publishCoreAvailability: (AppCore) -> Unit) {
    private val worker = ThreadPoolExecutor(1, 1, 30, TimeUnit.SECONDS, ArrayBlockingQueue(1))
        .also { it.allowCoreThreadTimeOut(true) }
    private val active = AtomicReference<Work?>(null)

    class Work(val id: Long, val action: HubAction?, val input: String?, val mailAccess: Boolean,
        val destination: ParcelFileDescriptor?, val observer: ILoftHubEvents) {
        val cancelled = AtomicBoolean(false)
    }

    fun reserve(work: Work) = active.compareAndSet(null, work)

    fun cancel(id: Long? = null) {
        active.get()?.takeIf { id == null || it.id == id }?.cancelled?.set(true)
    }

    fun reject(work: Work, code: String) {
        active.compareAndSet(work, null)
        runCatching { work.destination?.close() }
        reply(work.id, work.observer, code)
    }

    fun execute(core: AppCore, work: Work, closeCoreLease: () -> Unit) {
        try {
            worker.execute {
                var result: HubResult? = null
                var code = "ok"
                try {
                    if (!work.cancelled.get()) result = exchange(core, work)
                } catch (failure: HubException) {
                    if (failure is HubException.StateUnavailable) publishCoreAvailability(core)
                    code = problem(failure)
                } catch (_: HubResponseTooLarge) {
                    code = "too_large"
                } catch (_: HubDestinationFailure) {
                    code = "destination_failed"
                } catch (_: IOException) {
                    code = "network_unavailable"
                } catch (_: Exception) {
                    code = "unavailable"
                } catch (_: LinkageError) {
                    code = "unavailable"
                } finally {
                    if (result == null && !work.cancelled.get()) {
                        // An explicit cancel/logout still clears local scope if remote revocation failed.
                        val local = runCatching { core.hubSnapshot() }.getOrNull()
                        if ((work.action == HubAction.CANCEL && local?.transactionPending == false) ||
                            (work.action == HubAction.LOGOUT && local != null && local.session == null)) {
                            if (code in setOf("network_unavailable", "invalid_response", "unavailable", "rate_limited", "too_large")) {
                                code = "revocation_unconfirmed"
                            }
                        }
                        result = local?.let { HubResult(it) }
                    }
                    runCatching { work.destination?.close() }
                    active.compareAndSet(work, null)
                    closeCoreLease()
                }
                if (!work.cancelled.get()) reply(work.id, work.observer, code, result)
            }
        } catch (_: RejectedExecutionException) {
            closeCoreLease()
            reject(work, "busy")
        }
    }

    private fun exchange(core: AppCore, work: Work): HubResult {
        val action = work.action ?: return HubResult(core.hubSnapshot())
        val request = core.hubBegin(action, work.input, work.mailAccess)
        try {
            val response = exchangeHub(request) { !work.cancelled.get() }
            try {
                if (work.cancelled.get()) throw IOException()
                val receipt = core.hubFinish(request.requestId, response.status, response.mediaType, response.body)
                receipt.file?.let { file ->
                    try {
                        val destination = work.destination ?: throw IOException()
                        try {
                            ParcelFileDescriptor.AutoCloseOutputStream(destination).use { stream ->
                                for (offset in file.indices step (64 * 1024)) {
                                    if (work.cancelled.get()) throw IOException()
                                    stream.write(file, offset, minOf(64 * 1024, file.size - offset))
                                }
                            }
                        } catch (_: IOException) {
                            throw HubDestinationFailure()
                        }
                    } finally { file.fill(0) }
                }
                return HubResult(receipt.snapshot, receipt.browserUrl, receipt.page, receipt.message)
            } finally { response.body.fill(0) }
        } finally {
            request.body.fill(0)
            runCatching { core.hubAbandon(request.requestId) }
        }
    }

    private class HubDestinationFailure : Exception()

    private fun problem(failure: HubException) = when (failure) {
        is HubException.NoServer -> "no_server"
        is HubException.IncompatibleServer -> "incompatible_server"
        is HubException.Busy -> "busy"
        is HubException.StaleRequest -> "stale_request"
        is HubException.InvalidInput -> "invalid_request"
        is HubException.InvalidResponse -> "invalid_response"
        is HubException.NetworkUnavailable -> "network_unavailable"
        is HubException.NotSignedIn -> "not_signed_in"
        is HubException.MailConsentRequired -> "insufficient_scope"
        is HubException.NoTransaction -> "no_transaction"
        is HubException.TransactionExpired -> "transaction_expired"
        is HubException.SessionExpired -> "session_expired"
        is HubException.AccessDenied -> "access_denied"
        is HubException.RateLimited -> "rate_limited"
        is HubException.NotFound -> "not_found"
        is HubException.TooLarge -> "too_large"
        is HubException.StateUnavailable -> "unavailable"
    }

    companion object {
        fun reply(id: Long, observer: ILoftHubEvents, code: String, result: HubResult? = null) {
            val bytes = try { result?.let(HubWire::encode) } catch (_: IOException) { null }
            val safeCode = if (result != null && bytes == null) "invalid_response" else code
            try { observer.onResult(id, safeCode, bytes ?: byteArrayOf()) } catch (_: RemoteException) { }
            finally { bytes?.fill(0) }
        }
    }
}
