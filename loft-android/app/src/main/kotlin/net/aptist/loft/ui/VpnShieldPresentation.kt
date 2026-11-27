package net.aptist.loft.ui

import net.aptist.loft.core.generated.ConnectionState

internal enum class VpnShieldStatus {
    OPENING, DISCONNECTED, AWAITING_PERMISSION, CONNECTING, CONNECTED, STOPPING, BLOCKED, UNAVAILABLE,
}

internal enum class VpnShieldAction { CONNECT, CANCEL, STOP }

internal data class VpnShieldPresentation(
    val status: VpnShieldStatus,
    val action: VpnShieldAction,
    val enabled: Boolean,
)

internal fun vpnShieldPresentation(state: LoftUiState): VpnShieldPresentation {
    val core = state.native?.core
    val status = when {
        // Local cancellation can precede the next published native receipt.
        state.stopRequest != null -> VpnShieldStatus.STOPPING
        else -> when (core?.connectionState) {
            ConnectionState.DISCONNECTED -> when {
                state.vpnPermissionPending -> VpnShieldStatus.AWAITING_PERMISSION
                state.vpnStartPending -> VpnShieldStatus.CONNECTING
                else -> VpnShieldStatus.DISCONNECTED
            }
            ConnectionState.CONNECTING -> VpnShieldStatus.CONNECTING
            ConnectionState.CONNECTED -> VpnShieldStatus.CONNECTED
            ConnectionState.STOPPING -> VpnShieldStatus.STOPPING
            ConnectionState.BLOCKED -> VpnShieldStatus.BLOCKED
            ConnectionState.UNAVAILABLE -> VpnShieldStatus.UNAVAILABLE
            null -> if (state.availability == ServiceAvailability.OPENING) VpnShieldStatus.OPENING else VpnShieldStatus.UNAVAILABLE
        }
    }
    val action = when (status) {
        VpnShieldStatus.DISCONNECTED -> VpnShieldAction.CONNECT
        VpnShieldStatus.AWAITING_PERMISSION, VpnShieldStatus.CONNECTING -> VpnShieldAction.CANCEL
        else -> VpnShieldAction.STOP
    }
    val enabled = when (action) {
        VpnShieldAction.CONNECT -> {
            val nodeId = state.presentation.selectedNodeId
            val hasSelection = nodeId != null && core != null && core.nodeCount > 0u &&
                (state.selectedNodeMetadata?.id == nodeId || core.nodes.any { it.id == nodeId })
            state.canChangeConfiguration && state.pendingRequest == null && hasSelection
        }
        VpnShieldAction.CANCEL, VpnShieldAction.STOP -> state.stopRequest == null
    }
    return VpnShieldPresentation(status, action, enabled)
}
