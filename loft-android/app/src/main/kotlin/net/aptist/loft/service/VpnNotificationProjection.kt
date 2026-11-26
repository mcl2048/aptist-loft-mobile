package net.aptist.loft.service

import net.aptist.loft.core.generated.ConnectionState
import net.aptist.loft.core.generated.NetworkPrivacyEnforcement
enum class VpnNotificationState { CONNECTING, CONNECTED, BLOCKED, STOPPING, UNAVAILABLE, RELEASED }

/** Presentation mapping of Rust state plus actual resource receipts. */
object VpnNotificationProjection {
    fun snapshotAllowed(frame: SnapshotFrame, stopPending: Boolean): Boolean = !stopPending || state(frame) in
        setOf(VpnNotificationState.STOPPING, VpnNotificationState.UNAVAILABLE, VpnNotificationState.RELEASED)
    fun unsequencedAllowed(stopPending: Boolean): Boolean = !stopPending
    fun state(frame: SnapshotFrame): VpnNotificationState = when (frame.core.connectionState) {
        ConnectionState.STOPPING -> VpnNotificationState.STOPPING
        ConnectionState.UNAVAILABLE -> VpnNotificationState.UNAVAILABLE
        ConnectionState.CONNECTED -> if (frame.transportReady && frame.tunHeld && !frame.forwardingDisabled && !frame.resourcesReleased &&
            frame.core.appliedNetworkPrivacy != null && frame.core.networkPrivacyEnforcement == NetworkPrivacyEnforcement.ACTIVE)
            VpnNotificationState.CONNECTED else VpnNotificationState.UNAVAILABLE
        ConnectionState.BLOCKED -> if (frame.tunHeld && frame.forwardingDisabled && !frame.transportReady && !frame.resourcesReleased &&
            frame.core.appliedNetworkPrivacy != null && frame.core.networkPrivacyEnforcement == NetworkPrivacyEnforcement.BLOCKED)
            VpnNotificationState.BLOCKED else VpnNotificationState.UNAVAILABLE
        ConnectionState.DISCONNECTED -> if (!frame.tunHeld && !frame.transportReady && frame.forwardingDisabled && frame.resourcesReleased)
            VpnNotificationState.RELEASED else VpnNotificationState.UNAVAILABLE
        ConnectionState.CONNECTING -> if (!frame.transportReady) VpnNotificationState.CONNECTING else VpnNotificationState.UNAVAILABLE
    }
}
