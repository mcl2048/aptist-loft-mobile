package net.aptist.loft.foundation

import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit

class PriorityControlQueue(capacity: Int = 8) : AutoCloseable {
    private val normal = ThreadPoolExecutor(1, 1, 0L, TimeUnit.MILLISECONDS, ArrayBlockingQueue(capacity))
    fun submit(work: () -> Unit): Boolean = try { normal.execute { work() }; true } catch (_: RejectedExecutionException) { false }
    fun cancelNow(cancellation: () -> Unit) { cancellation() }
    override fun close() {
        normal.shutdown()
        if (!normal.awaitTermination(1, TimeUnit.SECONDS)) normal.shutdownNow()
    }
}
