package net.aptist.loft.foundation

import java.util.concurrent.atomic.AtomicBoolean

/** One terminal forwarding-failure handler per native resource attempt. */
class FailureDispatch {
    private val started = AtomicBoolean(false)
    fun begin(): Boolean = started.compareAndSet(false, true)
}
