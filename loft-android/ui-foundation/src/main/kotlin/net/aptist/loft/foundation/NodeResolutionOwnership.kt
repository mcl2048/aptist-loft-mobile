package net.aptist.loft.foundation

import java.util.concurrent.atomic.AtomicBoolean

/** One terminal physical-node-resolution lifetime; worker joining stays Android. */
class NodeResolutionOwnership<T : Any>(timeoutMillis: Long = 5000, maxPending: Int = 1) : AutoCloseable {
    private val stoppedFlag = AtomicBoolean(false)
    private val queries = QueryGate<T>(timeoutMillis, maxPending)
    val stopped: Boolean get() = stoppedFlag.get()
    fun start(cancellation: () -> Unit): QueryGate<T>.Pending? = queries.start(cancellation)
    fun cancelCurrent() = queries.cancelAll()
    fun cancelPending() { stoppedFlag.set(true); queries.close() }
    override fun close() = cancelPending()
}
