@file:OptIn(androidx.compose.foundation.layout.ExperimentalLayoutApi::class)

package net.aptist.loft.ui

import android.text.format.Formatter
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LocalContentColor
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import net.aptist.loft.R
import net.aptist.loft.core.generated.VpnFailure
import net.aptist.loft.foundation.ModuleCatalog
import net.aptist.loft.foundation.ModuleId
import net.aptist.loft.foundation.Page

@Composable
internal fun OverviewPage(
    state: LoftUiState,
    model: LoftViewModel,
    onConnect: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Column(modifier.fillMaxSize()) {
        BoxWithConstraints(
            Modifier.fillMaxWidth().weight(1f),
            contentAlignment = Alignment.TopCenter,
        ) {
            val margin = if (maxWidth < 300.dp) 12.dp else 16.dp
            Column(
                Modifier.widthIn(max = 568.dp).fillMaxWidth().fillMaxHeight()
                    .verticalScroll(rememberScrollState()).padding(horizontal = margin, vertical = 16.dp),
                verticalArrangement = Arrangement.spacedBy(16.dp),
            ) {
                Text(
                    stringResource(R.string.overview_title),
                    style = MaterialTheme.typography.headlineSmall,
                    modifier = Modifier.semantics { heading() },
                )
                NativeNotice(state)
                OverviewConnection(state, model)
                OverviewAccount(state) { model.navigate(Page.ACCOUNT) }
                OverviewTraffic(state, model::refreshVpnTraffic)
                OverviewShortcuts(state, model::navigate)
            }
        }
        VpnShieldControl(state, onConnect, model::stopControl)
    }
}

@Composable
private fun OverviewConnection(state: LoftUiState, model: LoftViewModel) {
    val status = vpnShieldPresentation(state).status
    val colors = MaterialTheme.colorScheme
    val emphasized = when (status) {
        VpnShieldStatus.CONNECTED, VpnShieldStatus.CONNECTING, VpnShieldStatus.AWAITING_PERMISSION -> true
        else -> false
    }
    val connectionTint = when (status) {
        VpnShieldStatus.BLOCKED, VpnShieldStatus.UNAVAILABLE -> LocalLoftColors.current.warning
        else -> colors.onPrimaryContainer
    }
    val badgeColor = when (status) {
        VpnShieldStatus.BLOCKED, VpnShieldStatus.UNAVAILABLE -> LocalLoftColors.current.warningContainer
        VpnShieldStatus.CONNECTED -> colors.primary
        else -> colors.primaryContainer
    }
    val badgeTint = if (status == VpnShieldStatus.CONNECTED) colors.onPrimary else connectionTint
    val badgeIcon = when (status) {
        VpnShieldStatus.CONNECTED -> R.drawable.ic_shield
        VpnShieldStatus.BLOCKED, VpnShieldStatus.UNAVAILABLE -> R.drawable.ic_shield_alert
        else -> R.drawable.ic_shield_outline
    }

    Surface(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(24.dp),
        color = if (emphasized) colors.primaryContainer else colors.surface,
        contentColor = if (emphasized) colors.onPrimaryContainer else colors.onSurface,
    ) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
                Box(Modifier.size(32.dp).background(badgeColor, CircleShape), contentAlignment = Alignment.Center) {
                    Icon(painterResource(badgeIcon), contentDescription = null, modifier = Modifier.size(20.dp), tint = badgeTint)
                }
                Text(stringResource(R.string.module_vpn), style = MaterialTheme.typography.labelLarge)
            }
            Text(
                stringResource(vpnStatusLabel(status)),
                style = MaterialTheme.typography.displaySmall,
                modifier = Modifier.semantics { heading(); liveRegion = LiveRegionMode.Polite },
            )
            if (state.native == null) {
                if (status != VpnShieldStatus.OPENING) ServiceState(state, model)
            } else {
                OverviewVpnDetail(state, status)
                OverviewNode(state, model::navigate)
            }
        }
    }
}

@Composable
private fun OverviewVpnDetail(state: LoftUiState, status: VpnShieldStatus) {
    val native = state.native ?: return
    val failure = native.core.vpnFailure.takeIf { status == VpnShieldStatus.DISCONNECTED }
    val message = when (status) {
        VpnShieldStatus.CONNECTING -> R.string.vpn_starting_body
        VpnShieldStatus.STOPPING -> R.string.vpn_stopping_body
        VpnShieldStatus.BLOCKED -> R.string.vpn_blocked_body
        VpnShieldStatus.UNAVAILABLE -> R.string.vpn_blocked_body.takeIf { native.tunHeld && native.forwardingDisabled }
        VpnShieldStatus.DISCONNECTED -> when (failure) {
            VpnFailure.REVOKED -> R.string.err_vpn_permission
            VpnFailure.ENGINE_STOP_FAILED -> R.string.err_engine_stop_incomplete
            VpnFailure.CANCELLED -> R.string.err_ticket_expired
            VpnFailure.ENGINE_START_FAILED, VpnFailure.ENGINE_UNAVAILABLE -> R.string.err_vpn_start_failed
            null -> null
        }
        else -> null
    }
    message?.let {
        Text(
            stringResource(it),
            style = MaterialTheme.typography.bodyMedium,
            color = if (failure != null) LocalLoftColors.current.warning else LocalContentColor.current,
        )
    }
}

@Composable
private fun OverviewNode(state: LoftUiState, navigate: (Page) -> Unit) {
    val core = state.native?.core ?: return
    val selectedId = state.presentation.selectedNodeId
    val selected = state.selectedNodeMetadata?.takeIf { it.id == selectedId } ?: core.nodes.find { it.id == selectedId }
    val activeId = core.activeNodeId
    val selectedText = selected?.label ?: stringResource(when {
        core.nodeCount == 0u -> R.string.add_node
        selectedId == null -> R.string.choose_node
        else -> R.string.node_metadata_unavailable
    })
    if (activeId != null && activeId != selectedId) {
        val active = core.nodes.find { it.id == activeId }
        Column {
            Text(stringResource(R.string.active_node), style = MaterialTheme.typography.labelSmall)
            Text(active?.label ?: stringResource(R.string.node_metadata_unavailable), style = MaterialTheme.typography.bodyMedium)
        }
    }
    Surface(
        onClick = {
            navigate(if (core.nodeCount == 0u) Page.IMPORT_NODE else ModuleCatalog.entry(ModuleId.VPN))
        },
        enabled = state.pendingRequest == null,
        modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp),
        color = MaterialTheme.colorScheme.background,
        shape = RoundedCornerShape(12.dp),
    ) {
        Row(
            Modifier.padding(horizontal = 12.dp, vertical = 8.dp),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column(Modifier.weight(1f)) {
                if (selectedId != null) {
                    val role = if (activeId == selectedId) R.string.active_node else R.string.selected_candidate
                    Text(stringResource(role), style = MaterialTheme.typography.labelSmall, color = LocalLoftColors.current.secondaryText)
                }
                Text(selectedText, style = MaterialTheme.typography.titleMedium)
                selected?.let {
                    Text(protocolName(it), style = MaterialTheme.typography.bodySmall, color = LocalLoftColors.current.secondaryText)
                }
            }
            Icon(painterResource(R.drawable.ic_chevron), contentDescription = null, modifier = Modifier.size(18.dp))
        }
    }
}

@Composable
private fun OverviewAccount(state: LoftUiState, onClick: () -> Unit) {
    val hub = state.hub
    val status = when {
        hub?.session != null -> R.string.hub_signed_in
        hub != null || state.native?.core?.let { it.serverAddress == null } == true -> R.string.anonymous
        else -> R.string.overview_account_unavailable
    }
    Surface(
        onClick = onClick,
        enabled = state.pendingRequest == null,
        modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp),
        shape = RoundedCornerShape(12.dp),
        color = MaterialTheme.colorScheme.surface,
    ) {
        Row(
            Modifier.padding(12.dp),
            horizontalArrangement = Arrangement.spacedBy(10.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Icon(painterResource(R.drawable.ic_account), contentDescription = null, tint = LocalLoftColors.current.link)
            Column(Modifier.weight(1f)) {
                Text(stringResource(R.string.module_account), style = MaterialTheme.typography.titleMedium)
                Text(stringResource(status), color = LocalLoftColors.current.secondaryText)
            }
            Icon(painterResource(R.drawable.ic_chevron), contentDescription = null, modifier = Modifier.size(18.dp))
        }
    }
}

@Composable
private fun OverviewTraffic(state: LoftUiState, onRefresh: () -> Unit) {
    val sample = state.vpnTraffic
    Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
        Row(
            Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(
                stringResource(R.string.overview_traffic),
                modifier = Modifier.weight(1f).semantics { heading() },
                style = MaterialTheme.typography.titleMedium,
            )
            IconButton(onClick = onRefresh, enabled = canRefreshVpnTraffic(state)) {
                Icon(painterResource(R.drawable.ic_refresh), stringResource(R.string.overview_traffic_refresh))
            }
        }
        if (sample == null) {
            Text(stringResource(R.string.overview_traffic_unavailable), color = LocalLoftColors.current.secondaryText)
        } else {
            Text(
                stringResource(if (sample.finalized) R.string.overview_traffic_last else R.string.overview_traffic_current),
                color = LocalLoftColors.current.secondaryText,
                style = MaterialTheme.typography.bodySmall,
            )
            BoxWithConstraints(Modifier.fillMaxWidth()) {
                val columns = overviewColumns(maxWidth.value, LocalDensity.current.fontScale)
                FlowRow(
                    Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(12.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                    maxItemsInEachRow = columns,
                ) {
                    OverviewTrafficValue(R.string.overview_traffic_upload, sample.uploadBytes, Modifier.weight(1f))
                    OverviewTrafficValue(R.string.overview_traffic_download, sample.downloadBytes, Modifier.weight(1f))
                }
            }
        }
        HorizontalDivider(color = LocalLoftColors.current.divider)
    }
}

@Composable
private fun OverviewTrafficValue(label: Int, bytes: Long, modifier: Modifier) {
    val context = LocalContext.current
    Column(modifier.padding(bottom = 4.dp)) {
        Text(stringResource(label), color = LocalLoftColors.current.secondaryText, style = MaterialTheme.typography.bodySmall)
        Text(Formatter.formatFileSize(context, bytes), style = MaterialTheme.typography.headlineSmall)
    }
}

@Composable
private fun OverviewShortcuts(state: LoftUiState, navigate: (Page) -> Unit) {
    val modules = ModuleCatalog.rail(mailAvailable = state.hub?.mailSupported == true).filter {
        it in overviewModules
    }
    Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
        Text(
            stringResource(R.string.overview_shortcuts),
            style = MaterialTheme.typography.titleMedium,
            modifier = Modifier.semantics { heading() },
        )
        BoxWithConstraints(Modifier.fillMaxWidth()) {
            val columns = overviewColumns(maxWidth.value, LocalDensity.current.fontScale)
            FlowRow(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
                maxItemsInEachRow = columns,
            ) {
                modules.forEach { module ->
                    OverviewShortcut(module, state.pendingRequest == null, { navigate(ModuleCatalog.entry(module)) }, Modifier.weight(1f))
                }
            }
        }
    }
}

@Composable
private fun OverviewShortcut(module: ModuleId, enabled: Boolean, onClick: () -> Unit, modifier: Modifier) {
    val colors = MaterialTheme.colorScheme
    Surface(
        onClick = onClick,
        enabled = enabled,
        shape = RoundedCornerShape(16.dp),
        color = colors.surface,
        modifier = modifier.heightIn(min = 48.dp),
    ) {
        Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Box(Modifier.size(34.dp).background(colors.primaryContainer, RoundedCornerShape(10.dp)), contentAlignment = Alignment.Center) {
                Icon(
                    painterResource(moduleIcon(module)),
                    contentDescription = null,
                    tint = colors.onPrimaryContainer,
                    modifier = Modifier.size(20.dp),
                )
            }
            Text(stringResource(moduleTitle(module)), style = MaterialTheme.typography.titleMedium)
        }
    }
}

private val overviewModules = setOf(ModuleId.VPN, ModuleId.SHIELD, ModuleId.MAIL, ModuleId.TOTP, ModuleId.AUDIT)

private fun overviewColumns(width: Float, fontScale: Float): Int = if (width >= 228f * fontScale) 2 else 1
