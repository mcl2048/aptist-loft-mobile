package net.aptist.loft.service

import android.net.Network
import net.aptist.loft.core.generated.AppCore
import net.aptist.loft.core.generated.SecureException
import net.aptist.loft.ipc.ILoftHubEvents
import java.io.IOException
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

internal class NotesSyncRoute(val network: Network, val stillCurrent: () -> Boolean)

internal class NotesSyncControl(
    private val route: () -> NotesSyncRoute?,
    private val notify: (Long, Boolean) -> Unit,
) {
    private val transport = ThreadPoolExecutor(1, 1, 30, TimeUnit.SECONDS, ArrayBlockingQueue(1))
        .apply { allowCoreThreadTimeOut(true) }
    private val active = AtomicReference<Work?>()

    class Work(val id: Long, val observer: ILoftHubEvents) {
        val cancelled = AtomicBoolean(false)
    }

    fun reserve(work: Work) = active.compareAndSet(null, work)
    fun cancel(id: Long) { active.get()?.takeIf { it.id == id }?.cancelled?.set(true) }

    fun reject(work: Work, code: String) {
        active.compareAndSet(work, null)
        if (!work.cancelled.get()) ProtectionControl.reply(work.id, work.observer, code)
    }

    fun execute(core: AppCore, work: Work, release: () -> Unit) {
        try {
            transport.execute {
                val code = try { exchange(core, work) }
                catch (failure: SecureException) {
                    if (failure is SecureException.NotSignedIn) notify(0, true)
                    ProtectionControl.problem(failure)
                }
                catch (_: IOException) { "network" }
                catch (_: Exception) { "unavailable" }
                catch (_: LinkageError) { "unavailable" }
                finally { release() }
                reject(work, code)
            }
        } catch (_: RejectedExecutionException) {
            release()
            reject(work, "busy")
        }
    }

    private fun exchange(core: AppCore, work: Work): String {
        if (work.cancelled.get() || !core.notesSyncEligible()) return "ineligible"
        val path = route() ?: return "network"
        val valid = { !work.cancelled.get() && path.stillCurrent() }
        var request = core.notesSyncBegin() ?: return "ineligible"
        repeat(3) {
            var next: net.aptist.loft.core.generated.HubRequest? = null
            try {
                val response = exchangeHub(request, path.network, valid)
                try {
                    if (!valid()) throw IOException()
                    val step = core.notesSyncFinish(request.requestId, response.status, response.mediaType, response.body)
                    next = step.nextRequest
                    if (next == null) notify(step.generation.toLong(), false)
                } finally { response.body.fill(0) }
            } finally {
                request.body.fill(0)
                if (next == null) runCatching { core.notesSyncAbandon(request.requestId) }
            }
            request = next ?: return "ok"
        }
        request.body.fill(0)
        runCatching { core.notesSyncAbandon(request.requestId) }
        return "conflict"
    }
}
