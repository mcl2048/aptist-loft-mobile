package net.aptist.loft.service

import net.aptist.loft.core.generated.ConnectionState

/** Abort forwarding outside capture locks when Rust can no longer own state. */
class CoreAvailabilityGuard(private val unavailable: () -> Unit) {
    fun observe(frame: SnapshotFrame) { if (frame.core.connectionState == ConnectionState.UNAVAILABLE) unavailable() }
}
