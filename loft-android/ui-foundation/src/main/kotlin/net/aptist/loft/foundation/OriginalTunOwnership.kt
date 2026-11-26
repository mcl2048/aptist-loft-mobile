package net.aptist.loft.foundation

data class TunOwnershipFacts(val held: Boolean, val establishmentPending: Boolean, val closeFailed: Boolean) {
    val tunClosed: Boolean get() = !held && !establishmentPending && !closeFailed
}

/** Physical Android descriptor ownership; it does not decide connection state. */
class OriginalTunOwnership<T : AutoCloseable> {
    private val lock = Any()
    private var attempt: ULong? = null
    private var accepting = false
    private var pending = false
    private var descriptor: T? = null
    private var closing = false
    private var closeFailed = false

    fun begin(attempt: ULong): Boolean = synchronized(lock) {
        if (attempt == 0uL || accepting || pending || descriptor != null || closing) false else {
            this.attempt = attempt
            accepting = true; pending = true; closeFailed = false
            true
        }
    }

    fun adopt(attempt: ULong, descriptor: T): Boolean {
        val accepted = synchronized(lock) {
            if (this.attempt != attempt || !pending) null else {
                pending = false
                this.descriptor = descriptor
                accepting
            }
        }
        if (accepted == true) return true
        if (accepted == false) stop() else descriptor.close()
        return false
    }

    fun establishmentFailed(attempt: ULong) = synchronized(lock) {
        if (this.attempt == attempt && pending) { pending = false; accepting = false }
    }

    fun original(attempt: ULong): T? = synchronized(lock) {
        if (this.attempt == attempt && accepting) descriptor else null
    }

    fun stop(): TunOwnershipFacts {
        val owned = synchronized(lock) {
            accepting = false
            if (closing) null else descriptor?.also { closing = true }
        }
        if (owned != null) {
            val closed = runCatching { owned.close() }.isSuccess
            synchronized(lock) {
                if (descriptor === owned) {
                    if (closed) descriptor = null
                    closeFailed = !closed
                }
                closing = false
            }
        }
        return facts()
    }

    fun facts(): TunOwnershipFacts = synchronized(lock) {
        TunOwnershipFacts(descriptor != null, pending, closeFailed)
    }
}
