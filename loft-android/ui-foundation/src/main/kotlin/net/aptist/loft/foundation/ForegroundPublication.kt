package net.aptist.loft.foundation

/** One physical foreground lease and its transport-publication admission. */
class ForegroundPublication : AutoCloseable {
    private var lease: Any? = null
    private var closed = false
    private val sequence = SnapshotSequence().also { it.begin(1L) }
    @Synchronized fun retain(token: Any) { check(!closed); lease = token }
    @Synchronized fun retainIfReleased(token: Any) { check(!closed); if (lease == null) lease = token }
    @Synchronized fun release(token: Any): Boolean {
        if (lease !== token) return false
        lease = null
        return true
    }
    @Synchronized fun released(): Boolean = lease == null
    @Synchronized fun matches(token: Any): Boolean = !closed && lease === token
    @Synchronized fun admits(token: Any, publication: ULong): Boolean = matches(token) && sequence.accepts(1L, publication)
    @Synchronized override fun close() { closed = true; lease = null; sequence.end() }
}
