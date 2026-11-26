package net.aptist.loft.service

import net.aptist.loft.core.generated.CoreSnapshot

data class SnapshotMetadata(val engineVersion: String = "", val transportReady: Boolean = false,
    val tunHeld: Boolean = false, val forwardingDisabled: Boolean = true, val resourcesReleased: Boolean = true,
    val networkResources: NetworkResourceSnapshot? = null)
class PublicationExhaustedException : IllegalStateException("PUBLICATION_EXHAUSTED")

/** One process owner shares this publisher across every snapshot capture path. */
class SnapshotPublisher(initialSequence: ULong = 0uL) {
    private var lastSequence = initialSequence
    fun capture(snapshot: () -> CoreSnapshot, metadata: SnapshotMetadata): ByteArray = capture(snapshot) { _ -> metadata }

    // Rust snapshot is nonblocking. Metadata reads only cached/owned facts;
    // callers never query Go, sockets, DNS or the OS inside this capture lock.
    @Synchronized fun capture(snapshot: () -> CoreSnapshot, metadata: (CoreSnapshot) -> SnapshotMetadata): ByteArray {
        if (lastSequence == ULong.MAX_VALUE) throw PublicationExhaustedException()
        val publication = ++lastSequence
        val core = snapshot()
        val facts = metadata(core)
        return SnapshotWire.encode(SnapshotFrame(core, facts.engineVersion, facts.transportReady,
            publication, facts.tunHeld, facts.forwardingDisabled, facts.resourcesReleased, facts.networkResources))
    }
}
