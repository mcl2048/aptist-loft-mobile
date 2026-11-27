package net.aptist.loft.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import net.aptist.loft.R

@Composable
internal fun VpnShieldControl(
    state: LoftUiState,
    onConnect: () -> Unit,
    onStop: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val shield = vpnShieldPresentation(state)
    val action = stringResource(when (shield.action) {
        VpnShieldAction.CONNECT -> R.string.connect
        VpnShieldAction.CANCEL -> R.string.vpn_cancel_connection
        VpnShieldAction.STOP -> R.string.stop_vpn
    })
    val status = stringResource(vpnStatusLabel(shield.status))
    val onClick = if (shield.action == VpnShieldAction.CONNECT) onConnect else onStop

    Surface(modifier.fillMaxWidth()) {
        BoxWithConstraints {
            val compact = maxHeight < 290.dp
            Column {
                HorizontalDivider(color = LocalLoftColors.current.divider)
                if (compact) {
                    Row(
                        Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 4.dp),
                        horizontalArrangement = Arrangement.spacedBy(12.dp, Alignment.CenterHorizontally),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        ShieldButton(shield, action, status, onClick, Modifier.size(48.dp))
                        ShieldLabel(action)
                    }
                } else {
                    Column(
                        Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 8.dp),
                        horizontalAlignment = Alignment.CenterHorizontally,
                        verticalArrangement = Arrangement.spacedBy(4.dp),
                    ) {
                        ShieldButton(shield, action, status, onClick, Modifier.size(64.dp))
                        ShieldLabel(action)
                    }
                }
            }
        }
    }
}

@Composable
private fun ShieldLabel(action: String) {
    Text(
        action,
        modifier = Modifier.clearAndSetSemantics { },
        style = MaterialTheme.typography.labelLarge,
        textAlign = TextAlign.Center,
    )
}

@Composable
private fun ShieldButton(
    shield: VpnShieldPresentation,
    action: String,
    status: String,
    onClick: () -> Unit,
    modifier: Modifier,
) {
    val scheme = MaterialTheme.colorScheme
    val loft = LocalLoftColors.current
    val (icon, container, tint) = when (shield.status) {
        VpnShieldStatus.CONNECTED -> Triple(R.drawable.ic_shield, scheme.primary, scheme.onPrimary)
        VpnShieldStatus.BLOCKED, VpnShieldStatus.UNAVAILABLE ->
            Triple(R.drawable.ic_shield_alert, loft.warningContainer, loft.warning)
        VpnShieldStatus.AWAITING_PERMISSION, VpnShieldStatus.CONNECTING ->
            Triple(R.drawable.ic_shield_outline, scheme.primaryContainer, scheme.onPrimaryContainer)
        VpnShieldStatus.DISCONNECTED -> if (shield.enabled) {
            Triple(R.drawable.ic_shield_outline, scheme.primaryContainer, scheme.onPrimaryContainer)
        } else {
            Triple(R.drawable.ic_shield_outline, scheme.surfaceVariant, scheme.onSurfaceVariant)
        }
        VpnShieldStatus.OPENING, VpnShieldStatus.STOPPING ->
            Triple(R.drawable.ic_shield_outline, scheme.surfaceVariant, scheme.onSurfaceVariant)
    }

    Box(
        modifier.clip(CircleShape).background(container)
            .clickable(enabled = shield.enabled, role = Role.Button, onClick = onClick)
            .semantics {
                contentDescription = action
                stateDescription = status
            },
        contentAlignment = Alignment.Center,
    ) {
        Icon(painterResource(icon), contentDescription = null, modifier = Modifier.size(28.dp), tint = tint)
    }
}

internal fun vpnStatusLabel(status: VpnShieldStatus): Int = when (status) {
    VpnShieldStatus.OPENING -> R.string.service_starting
    VpnShieldStatus.DISCONNECTED -> R.string.disconnected
    VpnShieldStatus.AWAITING_PERMISSION -> R.string.vpn_permission_pending
    VpnShieldStatus.CONNECTING -> R.string.connecting
    VpnShieldStatus.CONNECTED -> R.string.connected
    VpnShieldStatus.STOPPING -> R.string.stopping
    VpnShieldStatus.BLOCKED -> R.string.blocked
    VpnShieldStatus.UNAVAILABLE -> R.string.connection_unavailable
}
