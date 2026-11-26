package net.aptist.loft.service

import net.aptist.loft.core.generated.*
import net.aptist.loft.testing.NetworkPrivacyFixtures
import org.junit.Assert.*
import org.junit.Test

class VpnNotificationProjectionTest {
    private fun frame(state: ConnectionState, held: Boolean = true, ready: Boolean = false,
        disabled: Boolean = true, released: Boolean = false, privacy: NetworkPrivacyEnforcement = NetworkPrivacyEnforcement.INACTIVE) =
        SnapshotFrame(CoreSnapshot(2u, "0.1.2-LYNX", emptyList(), 0u, null, false, false, emptyList(), state, 1uL,
            1uL, null, null, null, NetworkPrivacyFixtures.policy(), 1uL,
            if (privacy == NetworkPrivacyEnforcement.INACTIVE) null else NetworkPrivacyFixtures.applied(), privacy),
            "engine", ready, 1uL, held, disabled, released)

    // The general held/drop condition must never mask Rust's real stop state.
    @Test fun stoppingAndUnavailableTakePriorityOverHeldDropResources() {
        assertEquals(VpnNotificationState.STOPPING, VpnNotificationProjection.state(frame(ConnectionState.STOPPING)))
        assertEquals(VpnNotificationState.UNAVAILABLE, VpnNotificationProjection.state(frame(ConnectionState.UNAVAILABLE)))
    }

    @Test fun connectedAndBlockedRequireTheirMatchingActualProofs() {
        assertEquals(VpnNotificationState.CONNECTED, VpnNotificationProjection.state(frame(ConnectionState.CONNECTED,
            ready = true, disabled = false, privacy = NetworkPrivacyEnforcement.ACTIVE)))
        assertEquals(VpnNotificationState.BLOCKED, VpnNotificationProjection.state(frame(ConnectionState.BLOCKED,
            privacy = NetworkPrivacyEnforcement.BLOCKED)))
        assertEquals(VpnNotificationState.UNAVAILABLE, VpnNotificationProjection.state(frame(ConnectionState.CONNECTED)))
        assertEquals(VpnNotificationState.UNAVAILABLE, VpnNotificationProjection.state(frame(ConnectionState.BLOCKED, held = false)))
    }

    @Test fun disconnectedIsReleasedOnlyAfterOriginalAndDynamicJoin() {
        assertEquals(VpnNotificationState.RELEASED, VpnNotificationProjection.state(frame(ConnectionState.DISCONNECTED, held = false, released = true)))
        assertEquals(VpnNotificationState.UNAVAILABLE, VpnNotificationProjection.state(frame(ConnectionState.DISCONNECTED)))
    }

    @Test fun connectingCannotBorrowAReadyOrBlockedLabelFromResourceFacts() {
        assertEquals(VpnNotificationState.CONNECTING, VpnNotificationProjection.state(frame(ConnectionState.CONNECTING)))
        assertEquals(VpnNotificationState.UNAVAILABLE, VpnNotificationProjection.state(frame(ConnectionState.CONNECTING, ready = true)))
    }

    @Test fun currentStopFenceRejectsQueuedActiveAndUnsequencedStatusUpdates() {
        for (old in listOf(frame(ConnectionState.CONNECTING), frame(ConnectionState.CONNECTED, ready = true,
            disabled = false, privacy = NetworkPrivacyEnforcement.ACTIVE), frame(ConnectionState.BLOCKED,
            privacy = NetworkPrivacyEnforcement.BLOCKED))) {
            assertFalse(VpnNotificationProjection.snapshotAllowed(old, true))
        }
        assertTrue(VpnNotificationProjection.snapshotAllowed(frame(ConnectionState.STOPPING), true))
        assertTrue(VpnNotificationProjection.snapshotAllowed(frame(ConnectionState.UNAVAILABLE), true))
        assertFalse(VpnNotificationProjection.unsequencedAllowed(true))
        assertTrue(VpnNotificationProjection.unsequencedAllowed(false))
    }
}
