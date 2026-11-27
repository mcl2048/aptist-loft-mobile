package net.aptist.loft.ui

import net.aptist.loft.core.generated.AppliedRouting
import net.aptist.loft.core.generated.ConnectionState
import net.aptist.loft.core.generated.CoreSnapshot
import net.aptist.loft.core.generated.Ipv6Policy
import net.aptist.loft.core.generated.NetworkPrivacyEnforcement
import net.aptist.loft.core.generated.NodeSummary
import net.aptist.loft.core.generated.ProtocolKind
import net.aptist.loft.foundation.PresentationState
import net.aptist.loft.service.SnapshotFrame
import net.aptist.loft.testing.NetworkPrivacyFixtures
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class VpnShieldPresentationTest {
    @Test fun disconnectedRequiresASelectedNode() {
        val state = disconnected()
        assertEquals(VpnShieldStatus.DISCONNECTED, vpnShieldPresentation(state).status)
        assertEquals(VpnShieldAction.CONNECT, vpnShieldPresentation(state).action)
        assertTrue(vpnShieldPresentation(state).enabled)
        assertFalse(vpnShieldPresentation(state.copy(presentation = PresentationState())).enabled)
    }

    @Test fun aNodeSelectedOnAnotherPageCanConnect() {
        val state = disconnected()
        val selection = node.copy(id = "n-51")
        val frame = checkNotNull(state.native)
        val offPage = state.copy(
            native = frame.copy(core = frame.core.copy(nodeCount = 51u)),
            presentation = PresentationState(selectedNodeId = selection.id),
            selectedNodeMetadata = selection,
        )
        assertTrue(vpnShieldPresentation(offPage).enabled)
    }

    @Test fun ordinaryMutationPreventsDuplicateStart() {
        assertFalse(vpnShieldPresentation(disconnected().copy(pendingRequest = 2)).enabled)
    }

    @Test fun permissionDraftCanBeCancelled() {
        val shield = vpnShieldPresentation(disconnected().copy(vpnPermissionPending = true))
        assertEquals(VpnShieldStatus.AWAITING_PERMISSION, shield.status)
        assertEquals(VpnShieldAction.CANCEL, shield.action)
        assertTrue(shield.enabled)
    }

    @Test fun queuedStartCanBeCancelledBeforeTheConnectingReceipt() {
        val shield = vpnShieldPresentation(disconnected().copy(vpnStartPending = true, pendingRequest = 2))
        assertEquals(VpnShieldStatus.CONNECTING, shield.status)
        assertEquals(VpnShieldAction.CANCEL, shield.action)
        assertTrue(shield.enabled)
    }

    @Test fun connectingCanBeCancelledDuringOrdinaryWork() {
        val state = disconnected()
        val frame = checkNotNull(state.native)
        val connecting = state.copy(
            native = frame.copy(
                core = frame.core.copy(
                    connectionState = ConnectionState.CONNECTING,
                    connectionAttemptId = 3uL,
                    activeNodeId = node.id,
                ),
                resourcesReleased = false,
            ),
            pendingRequest = 2,
        )
        val shield = vpnShieldPresentation(connecting)
        assertEquals(VpnShieldStatus.CONNECTING, shield.status)
        assertEquals(VpnShieldAction.CANCEL, shield.action)
        assertTrue(shield.enabled)
    }

    @Test fun confirmedConnectionCanBeStoppedDuringOrdinaryWork() {
        val shield = vpnShieldPresentation(connected().copy(pendingRequest = 2))
        assertEquals(VpnShieldStatus.CONNECTED, shield.status)
        assertEquals(VpnShieldAction.STOP, shield.action)
        assertTrue(shield.enabled)
    }

    @Test fun stopRequestSupersedesTheOldConnectionDisplayWithoutAllowingRepeat() {
        val shield = vpnShieldPresentation(connected().copy(stopRequest = 2))
        assertEquals(VpnShieldStatus.STOPPING, shield.status)
        assertEquals(VpnShieldAction.STOP, shield.action)
        assertFalse(shield.enabled)
    }

    @Test fun lostBinderStillOffersPriorityStop() {
        val shield = vpnShieldPresentation(LoftUiState(availability = ServiceAvailability.UNAVAILABLE))
        assertEquals(VpnShieldStatus.UNAVAILABLE, shield.status)
        assertEquals(VpnShieldAction.STOP, shield.action)
        assertTrue(shield.enabled)
    }

    private fun disconnected(): LoftUiState {
        val core = CoreSnapshot(
            schemaVersion = 2u,
            coreVersion = "0.1.5-LYNX",
            nodes = listOf(node),
            nodeCount = 1u,
            serverAddress = null,
            serverVerified = false,
            routingEnabled = false,
            selectedApps = emptyList(),
            connectionState = ConnectionState.DISCONNECTED,
            generation = 1uL,
            connectionAttemptId = 0uL,
            activeNodeId = null,
            appliedRouting = null,
            vpnFailure = null,
            networkPrivacyPolicy = NetworkPrivacyFixtures.policy(),
            networkPrivacyPolicyEpoch = 1uL,
            appliedNetworkPrivacy = null,
            networkPrivacyEnforcement = NetworkPrivacyEnforcement.INACTIVE,
        )
        return LoftUiState(
            presentation = PresentationState(selectedNodeId = node.id),
            native = SnapshotFrame(core, "0.1.5-LYNX", transportReady = false),
            availability = ServiceAvailability.AVAILABLE,
            selectedNodeMetadata = node,
        )
    }

    private fun connected(): LoftUiState {
        val state = disconnected()
        val frame = checkNotNull(state.native)
        return state.copy(native = frame.copy(
            core = frame.core.copy(
                connectionState = ConnectionState.CONNECTED,
                connectionAttemptId = 3uL,
                activeNodeId = node.id,
                appliedRouting = AppliedRouting(false, emptyList(), Ipv6Policy.BLOCKED_IN_VPN),
                appliedNetworkPrivacy = NetworkPrivacyFixtures.applied(),
                networkPrivacyEnforcement = NetworkPrivacyEnforcement.ACTIVE,
            ),
            transportReady = true,
            tunHeld = true,
            forwardingDisabled = false,
            resourcesReleased = false,
        ))
    }

    private val node = NodeSummary("n-1", "Example", ProtocolKind.SOCKS5, "test.invalid:1080", 0u, 65507u, true)
}
