package net.aptist.loft.foundation

import org.junit.Assert.*
import org.junit.Test

class VisibilityEpochTest {
    // Catches a callback queued before onStop updating a hidden/replaced page.
    @Test fun stoppedObservationRejectsPreviouslyIssuedCallbacks() {
        val gate = VisibilityEpoch()
        val ticket = gate.begin()
        assertTrue(gate.accepts(ticket))
        gate.end()
        assertFalse(gate.accepts(ticket))
    }

    // Catches stale Binder callbacks from a dead service overwriting the next session.
    @Test fun resumedObservationAcceptsOnlyItsNewTicket() {
        val gate = VisibilityEpoch()
        val oldTicket = gate.begin()
        gate.end()
        val newTicket = gate.begin()
        assertFalse(gate.accepts(oldTicket))
        assertTrue(gate.accepts(newTicket))
    }
}
