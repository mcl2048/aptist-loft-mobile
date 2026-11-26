package net.aptist.loft.foundation

import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

class QueryGate<T : Any>(private val timeoutMillis: Long = 5000, private val maxPending: Int = 1,
    private val monotonicNanos: () -> Long = System::nanoTime) : AutoCloseable {
    init { require(timeoutMillis in 1..5000); require(maxPending in 1..8) }
    private val lock = Any()
    private val active = linkedSetOf<Pending>()
    private var closed = false
    inner class Pending internal constructor(internal val cancellation: () -> Unit) {
        private val deadlineNanos = monotonicNanos() + TimeUnit.MILLISECONDS.toNanos(timeoutMillis)
        internal val latch = CountDownLatch(1)
        internal var terminal = false
        internal var answer: T? = null
        fun complete(answer: T): Boolean {
            var expired = false
            val accepted = synchronized(lock) {
                if (terminal || closed) false else {
                    expired = deadlineNanos - monotonicNanos() <= 0L
                    terminal = true
                    if (!expired) this.answer = answer
                    active.remove(this); latch.countDown()
                    !expired
                }
            }
            if (expired) runCatching(cancellation)
            return accepted
        }
        fun cancel() {
            val shouldCancel = synchronized(lock) {
                if (terminal) false else { terminal = true; active.remove(this); latch.countDown(); true }
            }
            if (shouldCancel) runCatching(cancellation)
        }
        fun await(): T? {
            val remaining = synchronized(lock) { if (terminal) 0L else deadlineNanos - monotonicNanos() }
            try { if (remaining <= 0L || !latch.await(remaining, TimeUnit.NANOSECONDS)) cancel() }
            catch (_: InterruptedException) { cancel(); Thread.currentThread().interrupt() }
            return synchronized(lock) { answer }
        }
    }
    fun start(cancellation: () -> Unit): Pending? = synchronized(lock) {
        if (closed || active.size >= maxPending) null else Pending(cancellation).also { active += it }
    }
    fun cancelAll() {
        val canceled = synchronized(lock) {
            active.toList().also { queries ->
                active.clear()
                queries.forEach { it.terminal = true; it.latch.countDown() }
            }
        }
        canceled.forEach { runCatching(it.cancellation) }
    }
    override fun close() { synchronized(lock) { closed = true }; cancelAll() }
}
