package net.aptist.loft.foundation

/** Physical cancellation precedes coalescing and reserved off-thread cleanup. */
class StopDispatch {
    fun request(cancelOriginal: () -> Unit, prepareCleanup: () -> (() -> Unit)?,
        enqueueCleanup: (() -> Unit) -> Boolean): Boolean {
        cancelOriginal()
        val cleanup = prepareCleanup() ?: return true
        return enqueueCleanup(cleanup)
    }
}
