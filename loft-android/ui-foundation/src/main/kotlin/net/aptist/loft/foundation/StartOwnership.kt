package net.aptist.loft.foundation

import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

/** Join ownership for an admitted construction task, independent of Rust state. */
class StartOwnership {
    private val state = AtomicInteger(0)
    private val done = CountDownLatch(1)
    fun schedule(): Boolean = state.compareAndSet(0, 1)
    fun cancelUnscheduled(): Boolean {
        if (!state.compareAndSet(0, 2)) return false
        done.countDown()
        return true
    }
    fun complete() {
        check(state.compareAndSet(1, 2) || state.get() == 2)
        done.countDown()
    }
    fun joined(): Boolean = done.count == 0L
    fun await(timeoutMillis: Long): Boolean {
        require(timeoutMillis in 1..5000)
        return try { done.await(timeoutMillis, TimeUnit.MILLISECONDS) }
        catch (_: InterruptedException) { Thread.currentThread().interrupt(); false }
    }
}
