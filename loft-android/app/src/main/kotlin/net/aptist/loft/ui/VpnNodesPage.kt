package net.aptist.loft.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.selection.selectableGroup
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import net.aptist.loft.R
import net.aptist.loft.core.generated.ConnectionState
import net.aptist.loft.core.generated.NodeSummary
import net.aptist.loft.foundation.Page

@Composable
internal fun VpnNodesPage(state: LoftUiState, model: LoftViewModel, dual: Boolean, modifier: Modifier) {
    val core = state.native?.core
    val selectedId = state.presentation.selectedNodeId
    val activeId = core?.takeIf { it.connectionState == ConnectionState.CONNECTED }?.activeNodeId
    val rows = state.nodePage?.nodes.orEmpty()
    val selectedOffPage = state.selectedNodeMetadata?.takeIf { selected ->
        core != null && selected.id == selectedId && rows.none { it.id == selected.id }
    }
    val canNavigate = state.pendingRequest == null
    val canSelect = canNavigate && !state.nodePageLoading && state.canChangeConfiguration
    val canRefresh = core != null && !state.nodePageLoading
    val listState = key(state.nodePageOffset) { rememberLazyListState() }

    Box(modifier.fillMaxWidth(), contentAlignment = Alignment.TopCenter) {
        Column(Modifier.widthIn(max = 600.dp).fillMaxSize().padding(horizontal = 16.dp)) {
            Row(Modifier.fillMaxWidth().heightIn(min = 56.dp), verticalAlignment = Alignment.CenterVertically) {
                Text(stringResource(R.string.node_list), Modifier.weight(1f).semantics { heading() },
                    style = MaterialTheme.typography.headlineSmall)
                NodeMenu(canNavigate, canRefresh, model)
            }
            LazyColumn(
                Modifier.weight(1f).fillMaxWidth().selectableGroup(), state = listState,
                contentPadding = PaddingValues(top = 4.dp, bottom = 12.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                item {
                    Column(Modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        NativeNotice(state)
                        if (core != null && core.nodeCount > 0u) {
                            Text(stringResource(R.string.node_count, core.nodeCount.toInt()),
                                color = LocalLoftColors.current.secondaryText, style = MaterialTheme.typography.bodyMedium)
                        }
                        if (selectedOffPage != null) {
                            Surface(color = MaterialTheme.colorScheme.primaryContainer, shape = RoundedCornerShape(12.dp)) {
                                Column(Modifier.fillMaxWidth().padding(12.dp)) {
                                    Text(stringResource(R.string.vpn_node_choice), color = MaterialTheme.colorScheme.onPrimaryContainer,
                                        style = MaterialTheme.typography.labelSmall)
                                    Text(selectedOffPage.label, color = MaterialTheme.colorScheme.onPrimaryContainer,
                                        style = MaterialTheme.typography.titleMedium)
                                }
                            }
                        }
                        if (activeId != null && selectedId != null && activeId != selectedId) {
                            Text(stringResource(R.string.vpn_nodes_next_connection), color = LocalLoftColors.current.secondaryText,
                                style = MaterialTheme.typography.bodyMedium)
                        }
                        if (core == null) ServiceState(state, model)
                    }
                }
                if (core?.nodeCount == 0u) item {
                    EmptyDirectory(canNavigate && state.canChangeConfiguration) { model.navigate(Page.IMPORT_NODE) }
                }
                if (core != null && core.nodeCount > 0u && state.nodePageLoading) item {
                    Text(stringResource(R.string.node_page_loading), Modifier.semantics { liveRegion = LiveRegionMode.Polite },
                        color = LocalLoftColors.current.secondaryText, style = MaterialTheme.typography.bodyMedium)
                }
                state.nodePageError?.let { error ->
                    item {
                        Column {
                            Notice(error)
                            TextButton(model::refreshNodes, Modifier.heightIn(min = 48.dp), enabled = canRefresh,
                                colors = ButtonDefaults.textButtonColors(contentColor = LocalLoftColors.current.link)) {
                                Text(stringResource(R.string.node_page_refresh))
                            }
                        }
                    }
                }
                if (core != null) {
                    items(rows, key = { it.id }) { node ->
                        NodeRow(
                            node, selected = node.id == selectedId, active = node.id == activeId, enabled = canSelect,
                            onChoose = { model.selectNode(node.id, showDetails = false) },
                            onDetails = if (dual) null else ({ model.selectNode(node.id, showDetails = true) }),
                        )
                    }
                    if (core.nodeCount > 50u) item {
                        NodePagination(state, core.nodeCount, model)
                    }
                }
            }
        }
    }
}

@Composable
private fun NodeMenu(canNavigate: Boolean, canRefresh: Boolean, model: LoftViewModel) {
    var expanded by remember { mutableStateOf(false) }
    Box {
        IconButton(onClick = { expanded = true }, modifier = Modifier.size(48.dp)) {
            Icon(painterResource(R.drawable.ic_menu), stringResource(R.string.open_secondary))
        }
        DropdownMenu(expanded = expanded, onDismissRequest = { expanded = false }) {
            DropdownMenuItem(text = { Text(stringResource(R.string.import_link)) }, enabled = canNavigate,
                leadingIcon = { Icon(painterResource(R.drawable.ic_link), null) },
                onClick = { expanded = false; model.navigate(Page.IMPORT_NODE) })
            DropdownMenuItem(text = { Text(stringResource(R.string.routing_title)) }, enabled = canNavigate,
                leadingIcon = { Icon(painterResource(R.drawable.ic_apps), null) },
                onClick = { expanded = false; model.navigate(Page.ROUTING) })
            DropdownMenuItem(text = { Text(stringResource(R.string.vpn_connection_details)) }, enabled = canNavigate,
                leadingIcon = { Icon(painterResource(R.drawable.ic_shield), null) },
                onClick = { expanded = false; model.navigate(Page.VPN_HOME) })
            DropdownMenuItem(text = { Text(stringResource(R.string.diagnostics_title)) }, enabled = canNavigate,
                leadingIcon = { Icon(painterResource(R.drawable.ic_log), null) },
                onClick = { expanded = false; model.navigate(Page.DIAGNOSTICS) })
            HorizontalDivider()
            DropdownMenuItem(text = { Text(stringResource(R.string.node_page_refresh)) }, enabled = canRefresh,
                onClick = { expanded = false; model.refreshNodes() })
        }
    }
}

@Composable
private fun EmptyDirectory(canImport: Boolean, onImport: () -> Unit) {
    Surface(shape = RoundedCornerShape(16.dp), color = MaterialTheme.colorScheme.surfaceVariant) {
        Column(Modifier.fillMaxWidth().padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Icon(painterResource(R.drawable.ic_network), null, Modifier.size(28.dp), tint = LocalLoftColors.current.link)
            Text(stringResource(R.string.no_nodes), style = MaterialTheme.typography.titleMedium)
            Text(stringResource(R.string.vpn_nodes_empty_body), color = LocalLoftColors.current.secondaryText)
            Button(onClick = onImport, modifier = Modifier.heightIn(min = 48.dp), enabled = canImport) {
                Text(stringResource(R.string.import_link))
            }
        }
    }
}

@Composable
private fun NodeRow(node: NodeSummary, selected: Boolean, active: Boolean, enabled: Boolean,
    onChoose: () -> Unit, onDetails: (() -> Unit)?) {
    val colors = MaterialTheme.colorScheme
    val shape = RoundedCornerShape(12.dp)
    Row(Modifier.fillMaxWidth().clip(shape)
        .background(if (selected) colors.primaryContainer else colors.surface), verticalAlignment = Alignment.CenterVertically) {
        Row(
            Modifier.weight(1f).heightIn(min = 64.dp)
                .selectable(selected = selected, enabled = enabled, role = Role.RadioButton, onClick = onChoose)
                .padding(start = 12.dp, top = 12.dp, end = 8.dp, bottom = 12.dp),
            horizontalArrangement = Arrangement.spacedBy(12.dp), verticalAlignment = Alignment.CenterVertically,
        ) {
            RadioButton(selected = selected, onClick = null, enabled = enabled,
                colors = RadioButtonDefaults.colors(selectedColor = colors.onPrimaryContainer))
            Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                Text(node.label, style = MaterialTheme.typography.titleMedium,
                    color = if (selected) colors.onPrimaryContainer else colors.onSurface)
                Text(protocolName(node), color = if (selected) colors.onPrimaryContainer else LocalLoftColors.current.secondaryText,
                    style = MaterialTheme.typography.bodySmall)
                if (selected) Text(stringResource(R.string.vpn_node_choice), color = colors.onPrimaryContainer,
                    style = MaterialTheme.typography.labelSmall)
                if (active) Text(stringResource(R.string.active_node), color = LocalLoftColors.current.link,
                    style = MaterialTheme.typography.labelSmall)
            }
        }
        if (onDetails != null) {
            IconButton(onClick = onDetails, modifier = Modifier.size(48.dp), enabled = enabled) {
                Icon(painterResource(R.drawable.ic_chevron), stringResource(R.string.vpn_node_details_action, node.label))
            }
        }
    }
}

@Composable
private fun NodePagination(state: LoftUiState, nodeCount: UInt, model: LoftViewModel) {
    Column(Modifier.fillMaxWidth().padding(vertical = 4.dp)) {
        Text(stringResource(R.string.node_page_number, state.nodePageOffset.toInt() / 50 + 1, (nodeCount.toInt() + 49) / 50),
            color = LocalLoftColors.current.secondaryText, style = MaterialTheme.typography.bodySmall)
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            val colors = ButtonDefaults.textButtonColors(contentColor = LocalLoftColors.current.link)
            TextButton(model::previousNodePage, Modifier.weight(1f).heightIn(min = 48.dp),
                enabled = state.nodePageOffset > 0u && !state.nodePageLoading, colors = colors) { Text(stringResource(R.string.previous_page)) }
            TextButton(model::nextNodePage, Modifier.weight(1f).heightIn(min = 48.dp),
                enabled = state.nodePage?.nextOffset != null && !state.nodePageLoading, colors = colors) { Text(stringResource(R.string.next_page)) }
        }
    }
}
