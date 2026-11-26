package net.aptist.loft.service

import net.aptist.loft.foundation.SnapshotSequence

/** The retained Binder client uses this exact decoder/admission boundary. */
class SnapshotConsumer {
    private val sequence = SnapshotSequence()
    fun begin(binding: Long) = sequence.begin(binding)
    fun end() = sequence.end()
    fun consume(binding: Long, payload: ByteArray): SnapshotFrame? {
        val frame = SnapshotWire.decode(payload)
        return if (sequence.accepts(binding, frame.publicationSequence)) frame else null
    }
}
