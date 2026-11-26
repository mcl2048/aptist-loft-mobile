@file:OptIn(androidx.compose.foundation.layout.ExperimentalLayoutApi::class)

package net.aptist.loft.ui

import androidx.activity.compose.BackHandler
import androidx.activity.compose.LocalActivity
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.selection.selectableGroup
import androidx.compose.foundation.selection.toggleable
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.clipToBounds
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.layout.onGloballyPositioned
import androidx.compose.ui.layout.positionInWindow
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.platform.LocalSoftwareKeyboardController
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.*
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.IntOffset
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import net.aptist.loft.R
import net.aptist.loft.MainActivity
import net.aptist.loft.core.generated.NodeSummary
import net.aptist.loft.core.generated.ProtocolKind
import net.aptist.loft.core.generated.ConnectionState
import net.aptist.loft.core.generated.VpnFailure
import net.aptist.loft.foundation.*
import net.aptist.loft.service.ReceiptCode
import java.text.DateFormat
import java.util.Date
import java.util.Locale
import kotlin.math.roundToInt

@Composable
fun LoftApp(model: LoftViewModel, onExit: () -> Unit, onTheme: (ThemeChoice) -> Unit, onLocale: (String) -> Unit, onConnect: () -> Unit) {
    val state by model.ui.collectAsStateWithLifecycle()
    val keyboard = LocalSoftwareKeyboardController.current
    val imeVisible = WindowInsets.isImeVisible
    val activity = LocalActivity.current as? MainActivity
    SideEffect { activity?.setSensitivePage(state.presentation.navigation.page) }
    BackHandler {
        if (imeVisible) keyboard?.hide()
        else if (!model.back()) onExit()
    }
    LoftTheme(state.theme) {
        Surface(Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
            val density = LocalDensity.current
            var origin by remember { mutableStateOf(IntOffset.Zero) }
            Box(Modifier.fillMaxSize().safeDrawingPadding().imePadding()) {
            BoxWithConstraints(Modifier.fillMaxSize().onGloballyPositioned {
                val position = it.positionInWindow()
                origin = IntOffset(position.x.roundToInt(), position.y.roundToInt())
            }) {
                val folds = state.folds.filter { it.separating || it.occluding || it.halfOpened }.map {
                    FoldRegion(
                        start = if (it.vertical) (it.left - origin.x) / density.density else (it.top - origin.y) / density.density,
                        end = if (it.vertical) (it.right - origin.x) / density.density else (it.bottom - origin.y) / density.density,
                        axis = if (it.vertical) FoldAxis.VERTICAL else FoldAxis.HORIZONTAL,
                        separating = it.separating, occluding = it.occluding, halfOpened = it.halfOpened,
                    )
                }
                val viewport = Viewport(maxWidth.value, maxHeight.value, density.fontScale, folds.firstOrNull(), folds.drop(1))
                val layout = AdaptiveLayoutPolicy.measure(viewport)
                SideEffect { model.resize(viewport) }
                val blocked = state.presentation.navigation.pendingPage != null
                Box(Modifier.fillMaxSize().then(if (blocked) Modifier.clearAndSetSemantics { } else Modifier)) {
                    ModuleRail(state, model, layout, viewport.height, Modifier.offset(x = layout.railLeft.dp).width(layout.railWidth.dp).fillMaxHeight())
                    Pane(layout.primary) {
                        Column(Modifier.fillMaxSize()) {
                            AppHeader(state, model)
                            StorageFailure(state, model)
                            PrimaryContent(state, model, layout.secondary != null, onTheme, onLocale, onConnect, Modifier.weight(1f))
                        }
                    }
                    layout.secondary?.let { secondary ->
                        Pane(secondary) { SupportingContent(state, model, onTheme, onLocale) }
                    }
                    if (state.presentation.navigation.menuOpen) SecondaryMenu(state, model, layout.primary)
                }
                if (blocked) DiscardOverlay(model, layout.primary)
            }
            }
        }
    }
}

@Composable
private fun Pane(bounds: PaneBounds, content: @Composable BoxScope.() -> Unit) {
    val density = LocalDensity.current
    Box(Modifier.offset { IntOffset((bounds.left * density.density).roundToInt(), (bounds.top * density.density).roundToInt()) }
        .size(bounds.width.dp, bounds.height.dp).clipToBounds(), content = content)
}

@Composable
private fun ModuleRail(state: LoftUiState, model: LoftViewModel, layout: AdaptiveLayout, height: Float, modifier: Modifier) {
    val modules = ModuleCatalog.rail(mailAvailable = false).filterNot { it == ModuleId.SETTING }
    Column(modifier.background(LocalLoftColors.current.rail).clipToBounds().selectableGroup()) {
        val gap = layout.horizontalRailGap
        if (gap == null) {
            RailBrand(model)
            RailModules(modules, state, model, Modifier.weight(1f))
            RailButton(ModuleId.SETTING, state.presentation.navigation.module, model)
        } else {
            val top = gap.start.coerceIn(0f, height)
            val bottom = (height - gap.endInclusive).coerceAtLeast(0f)
            Column(Modifier.height(top.dp).fillMaxWidth().clipToBounds()) {
                if (top >= 112f) {
                    RailBrand(model)
                    RailModules(modules, state, model, Modifier.weight(1f))
                    if (bottom < 80f) RailButton(ModuleId.SETTING, state.presentation.navigation.module, model)
                }
            }
            Spacer(Modifier.height((gap.endInclusive - gap.start).coerceAtLeast(0f).dp))
            Column(Modifier.height(bottom.dp).fillMaxWidth().clipToBounds()) {
                if (top < 112f) { RailBrand(model); RailModules(modules, state, model, Modifier.weight(1f)) }
                else Spacer(Modifier.weight(1f))
                if (bottom >= 80f) RailButton(ModuleId.SETTING, state.presentation.navigation.module, model)
            }
        }
    }
}

@Composable private fun RailBrand(model: LoftViewModel) {
    IconButton(onClick = { model.navigate(Page.ACCOUNT) }, modifier = Modifier.fillMaxWidth().heightIn(min = 56.dp)) {
        Icon(painterResource(R.drawable.ic_loft), stringResource(R.string.open_account), Modifier.size(36.dp), tint = Color.Unspecified)
    }
}
@Composable private fun RailModules(modules: List<ModuleId>, state: LoftUiState, model: LoftViewModel, modifier: Modifier) {
    Column(modifier.fillMaxWidth().verticalScroll(rememberScrollState())) {
        modules.forEach { module ->
            key(module.stableId) { RailButton(module, state.presentation.navigation.module, model) }
        }
    }
}
@Composable private fun RailButton(module: ModuleId, selected: ModuleId, model: LoftViewModel) {
    val active = selected == module
    val fullTitle = stringResource(moduleTitle(module))
    Box(Modifier.fillMaxWidth().heightIn(min = 56.dp)
        .selectable(selected = active, role = Role.Tab, onClick = { model.navigate(ModuleCatalog.entry(module)) })
        .semantics { contentDescription = fullTitle }, contentAlignment = Alignment.Center) {
        if (active) Box(Modifier.align(Alignment.CenterStart).width(3.dp).height(24.dp)
            .background(MaterialTheme.colorScheme.primary, RoundedCornerShape(2.dp)))
        Box(Modifier.padding(horizontal = 4.dp).size(44.dp)
            .background(if (active) MaterialTheme.colorScheme.primaryContainer else Color.Transparent, RoundedCornerShape(14.dp)),
            contentAlignment = Alignment.Center) {
            Icon(painterResource(moduleIcon(module)), null, Modifier.size(24.dp),
                tint = if (active) MaterialTheme.colorScheme.onPrimaryContainer else LocalLoftColors.current.secondaryText)
        }
    }
}

@Composable private fun AppHeader(state: LoftUiState, model: LoftViewModel) {
    Row(Modifier.fillMaxWidth().heightIn(min = 56.dp), verticalAlignment = Alignment.CenterVertically) {
        val child = state.presentation.navigation.page in setOf(Page.NODE_DETAILS, Page.IMPORT_NODE, Page.ROUTING, Page.DIAGNOSTICS)
        IconButton(onClick = { if (child) model.back() else model.toggleMenu() }) {
            Icon(painterResource(if (child) R.drawable.ic_arrow_back else R.drawable.ic_menu), stringResource(if (child) R.string.navigate_back else R.string.open_secondary))
        }
        Text(stringResource(R.string.app_name), style = MaterialTheme.typography.titleMedium, modifier = Modifier.weight(1f))
        IconButton(onClick = { model.navigate(Page.ACCOUNT) }) {
            Icon(painterResource(R.drawable.ic_account), stringResource(R.string.open_account))
        }
    }
}

@Composable
private fun PrimaryContent(state: LoftUiState, model: LoftViewModel, dual: Boolean, onTheme: (ThemeChoice) -> Unit, onLocale: (String) -> Unit, onConnect: () -> Unit, modifier: Modifier) {
    when (state.presentation.navigation.page) {
        Page.NODES -> NodesPage(state, model, dual, modifier)
        Page.NODE_DETAILS -> if (dual) NodesPage(state, model, true, modifier) else ScrollPage(modifier) { NodeDetails(state, model) }
        Page.ROUTING -> RoutingPage(state, model, dual, modifier)
        Page.WELCOME -> ScrollPage(modifier) {
            PageTitle(R.string.welcome_title)
            Text(stringResource(R.string.welcome_body))
            InfoRow(R.string.module_account, stringResource(R.string.anonymous))
            PrimaryButton(R.string.continue_guest, { model.navigate(Page.VPN_HOME) })
            OutlinedButton(onClick = { model.navigate(Page.ACCOUNT) }, colors = ButtonDefaults.outlinedButtonColors(contentColor = LocalLoftColors.current.link),
                modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp)) { Text(stringResource(R.string.enterprise_account)) }
            if (!dual) { LocalStorage(); Explanation(R.string.framework_title, R.string.framework_body) }
            ServiceState(state, model)
        }
        Page.VPN_HOME -> ScrollPage(modifier) {
            PageTitle(R.string.module_vpn)
            NativeNotice(state)
            if (state.native != null) {
                Text(stringResource(R.string.connection_status), color = LocalLoftColors.current.secondaryText)
                val connection = state.native.core.connectionState
                Text(stringResource(when (connection) {
                    ConnectionState.DISCONNECTED -> R.string.disconnected
                    ConnectionState.CONNECTING -> R.string.connecting
                    ConnectionState.CONNECTED -> R.string.connected
                    ConnectionState.STOPPING -> R.string.stopping
                    ConnectionState.BLOCKED -> R.string.blocked
                    ConnectionState.UNAVAILABLE -> R.string.connection_unavailable
                }), style = MaterialTheme.typography.displaySmall,
                    modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite })
                when (connection) {
                    ConnectionState.CONNECTED -> Text(stringResource(R.string.vpn_ready_body))
                    ConnectionState.CONNECTING -> Text(stringResource(R.string.vpn_starting_body))
                    ConnectionState.STOPPING -> Text(stringResource(R.string.vpn_stopping_body))
                    ConnectionState.BLOCKED -> Explanation(R.string.vpn_blocked_title, R.string.vpn_blocked_body)
                    ConnectionState.UNAVAILABLE -> if (state.native.tunHeld && state.native.forwardingDisabled) Explanation(R.string.vpn_blocked_title, R.string.vpn_blocked_body)
                    ConnectionState.DISCONNECTED -> state.native.core.vpnFailure?.let { failure ->
                        Text(stringResource(when (failure) {
                            VpnFailure.REVOKED -> R.string.err_vpn_permission
                            VpnFailure.ENGINE_STOP_FAILED -> R.string.err_engine_stop_incomplete
                            VpnFailure.CANCELLED -> R.string.err_ticket_expired
                            VpnFailure.ENGINE_START_FAILED, VpnFailure.ENGINE_UNAVAILABLE -> R.string.err_vpn_start_failed
                        }), color = LocalLoftColors.current.warning)
                    }
                }
                if (connection == ConnectionState.DISCONNECTED) {
                    if (state.native.core.nodeCount == 0u) PrimaryButton(R.string.add_node, { model.navigate(Page.IMPORT_NODE) })
                    else PrimaryButton(R.string.connect, onConnect, state.canChangeConfiguration && state.pendingRequest == null &&
                        state.stopRequest == null && !state.vpnPermissionPending)
                } else PrimaryButton(R.string.stop_vpn, model::stopControl, state.stopRequest == null)
                if (!dual) { SelectedNodeSummary(state, model); RoutingSummary(state, model) }
            } else { ServiceState(state, model); PrimaryButton(R.string.stop_vpn, model::stopControl, state.stopRequest == null) }
            Explanation(R.string.vpn_policy_title, R.string.vpn_policy_body)
            NetworkPrivacyStatus(state)
            NotificationStatus(state, model)
            LinkButton(onClick = { model.navigate(Page.NODES) }, modifier = Modifier.heightIn(min = 48.dp)) { Text(stringResource(R.string.node_list)) }
            LinkButton(onClick = { model.navigate(Page.ROUTING) }, modifier = Modifier.heightIn(min = 48.dp)) { Text(stringResource(R.string.routing_title)) }
        }
        Page.IMPORT_NODE -> ScrollPage(modifier) {
            PageTitle(R.string.import_link)
            NativeNotice(state)
            Text(stringResource(R.string.link_help))
            OutlinedTextField(value = state.importText, onValueChange = model::setImportText,
                label = { Text(stringResource(R.string.complete_link)) }, modifier = Modifier.fillMaxWidth(), minLines = 4, maxLines = 10,
                enabled = state.pendingRequest == null && !state.importConfirmation,
                visualTransformation = PasswordVisualTransformation(),
                keyboardOptions = KeyboardOptions(autoCorrectEnabled = false, keyboardType = KeyboardType.Password))
            LinkButton(onClick = model::readClipboard, enabled = state.pendingRequest == null && !state.importConfirmation,
                modifier = Modifier.heightIn(min = 48.dp)) { Text(stringResource(R.string.read_clipboard)) }
            if (state.importConfirmation) {
                Explanation(R.string.confirm_import_title, R.string.confirm_import_body)
                PrimaryButton(R.string.confirm, model::confirmImport, state.pendingRequest == null && state.canChangeConfiguration)
                LinkButton(onClick = model::cancelImportConfirmation, enabled = state.pendingRequest == null) { Text(stringResource(R.string.cancel)) }
            } else PrimaryButton(R.string.review_import, model::reviewImport, state.importText.isNotBlank() && state.pendingRequest == null)
            if (!dual) { Text(stringResource(R.string.import_limit), style = MaterialTheme.typography.bodySmall); LocalStorage() }
        }
        Page.ACCOUNT -> ScrollPage(modifier) {
            PageTitle(R.string.account_title)
            NativeNotice(state)
            InfoRow(R.string.module_account, stringResource(R.string.anonymous))
            Text(stringResource(R.string.account_guest_body))
            SectionTitle(R.string.server_candidate)
            OutlinedTextField(value = state.serverText, onValueChange = model::setServerText,
                label = { Text(stringResource(R.string.server_address)) }, modifier = Modifier.fillMaxWidth(),
                keyboardOptions = KeyboardOptions(autoCorrectEnabled = false, keyboardType = KeyboardType.Uri), enabled = state.pendingRequest == null)
            Text(stringResource(R.string.server_help), style = MaterialTheme.typography.bodySmall)
            PrimaryButton(R.string.validate_address, model::stageServer, state.serverText.isNotBlank() && state.pendingRequest == null && state.canChangeConfiguration)
            LinkButton(onClick = model::resetServer, enabled = state.canChangeConfiguration && state.pendingRequest == null &&
                state.native?.core?.serverAddress != null) { Text(stringResource(R.string.reset_candidate)) }
            SelectionContainer { Text(state.native?.core?.serverAddress ?: stringResource(R.string.no_server)) }
            if (state.native?.core?.serverAddress != null) Text(stringResource(R.string.server_not_verified), color = LocalLoftColors.current.warning)
            if (!dual) { LoginDependency(model); MailDependency(model) }
        }
        Page.SHIELD -> ScrollPage(modifier) {
            PageTitle(R.string.shield_title)
            NetworkPrivacyStatus(state)
            Explanation(R.string.software_checks, R.string.software_unknown)
            if (!dual) { Explanation(R.string.device_trust, R.string.device_unknown); Text(stringResource(R.string.shield_scope)) }
        }
        Page.MAIL -> ScrollPage(modifier) { PageTitle(R.string.mail_title); MailDependency(model); if (!dual) Text(stringResource(R.string.mail_privacy)) }
        Page.AUDIT -> LazyColumn(modifier.fillMaxSize().padding(horizontal = 16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            item { PageTitle(R.string.audit_title); Text(stringResource(R.string.audit_body)) }
            if (state.receipts.isEmpty()) item { Text(stringResource(R.string.no_receipts)) }
            items(state.receipts, key = { it.requestId }) { receipt ->
                Column(Modifier.fillMaxWidth().padding(vertical = 8.dp)) {
                    Text(stringResource(R.string.receipt_number, receipt.requestId), style = MaterialTheme.typography.titleMedium)
                    Text(stringResource(receipt.code.text))
                    Text(DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT, Locale.forLanguageTag(state.locale)).format(Date(receipt.receivedAt)),
                        color = LocalLoftColors.current.secondaryText, style = MaterialTheme.typography.bodySmall)
                    HorizontalDivider(color = LocalLoftColors.current.divider)
                }
            }
        }
        Page.SETTINGS -> ScrollPage(modifier) {
            PageTitle(R.string.settings_title)
            AppearanceChoices(state, onTheme, onLocale)
            NotificationStatus(state, model)
            LinkButton(onClick = { model.navigate(Page.ACCOUNT) }, modifier = Modifier.heightIn(min = 48.dp)) { Text(stringResource(R.string.account_title)) }
            LinkButton(onClick = { model.navigate(Page.MAIL) }, modifier = Modifier.heightIn(min = 48.dp)) { Text(stringResource(R.string.mail_title)) }
            if (!dual) PrivacyAndBackground()
        }
        Page.DIAGNOSTICS -> ScrollPage(modifier) { Diagnostics(state, model) }
    }
}

@Composable private fun SupportingContent(state: LoftUiState, model: LoftViewModel, onTheme: (ThemeChoice) -> Unit, onLocale: (String) -> Unit) {
    ScrollPage(Modifier.fillMaxSize()) {
        Spacer(Modifier.height(12.dp))
        when (state.presentation.navigation.page) {
            Page.NODES, Page.NODE_DETAILS -> NodeDetails(state, model)
            Page.ROUTING -> { RoutingSummary(state, model); RoutingSave(state, model); LocalStorage() }
            Page.VPN_HOME -> { SelectedNodeSummary(state, model); RoutingSummary(state, model); Explanation(R.string.software_checks, R.string.software_unknown) }
            Page.IMPORT_NODE -> { Explanation(R.string.storage_title, R.string.storage_body); Text(stringResource(R.string.import_limit)); Text(stringResource(R.string.camera_unavailable)) }
            Page.ACCOUNT -> { LoginDependency(model); MailDependency(model) }
            Page.MAIL -> { Explanation(R.string.privacy, R.string.mail_privacy); LoginDependency(model) }
            Page.SHIELD -> { Explanation(R.string.device_trust, R.string.device_unknown); Text(stringResource(R.string.shield_scope)) }
            Page.SETTINGS -> PrivacyAndBackground()
            Page.AUDIT, Page.DIAGNOSTICS -> { Explanation(R.string.framework_title, R.string.framework_body); LocalStorage() }
            Page.WELCOME -> { Explanation(R.string.framework_title, R.string.framework_body); LocalStorage() }
        }
    }
}

@Composable private fun NodesPage(state: LoftUiState, model: LoftViewModel, dual: Boolean, modifier: Modifier) {
    LazyColumn(modifier.fillMaxSize().padding(horizontal = 16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        item {
            PageTitle(R.string.node_list)
            NativeNotice(state)
            PrimaryButton(R.string.import_link, { model.navigate(Page.IMPORT_NODE) }, state.pendingRequest == null)
            Text(stringResource(R.string.camera_unavailable), style = MaterialTheme.typography.bodySmall)
            state.native?.core?.let { Text(stringResource(R.string.node_count, it.nodeCount.toInt())) }
        }
        val native = state.native
        if (native == null) item { ServiceState(state, model) }
        else if (native.core.nodeCount == 0u) item { Text(stringResource(R.string.no_nodes)); LocalStorage() }
        if (state.nodePageLoading) item { Text(stringResource(R.string.node_page_loading)) }
        state.nodePageError?.let { error -> item { Notice(error) } }
        if (native != null) item {
            LinkButton(onClick = model::refreshNodes, enabled = !state.nodePageLoading) { Text(stringResource(R.string.node_page_refresh)) }
        }
        if (native != null) items(state.nodePage?.nodes.orEmpty(), key = { it.id }) { node ->
            val selected = node.id == state.presentation.selectedNodeId
            Column(Modifier.fillMaxWidth().clip(RoundedCornerShape(12.dp))
                .background(if (selected) MaterialTheme.colorScheme.primaryContainer else Color.Transparent)
                .clickable(enabled = !state.nodePageLoading && state.pendingRequest == null) { model.selectNode(node.id, showDetails = !dual) }.semantics(mergeDescendants = true) { this.selected = selected }
                .padding(12.dp)) {
                Text(node.label, style = MaterialTheme.typography.titleMedium)
                Text(protocolName(node), color = LocalLoftColors.current.secondaryText)
                if (selected) Text(stringResource(R.string.selected_candidate), style = MaterialTheme.typography.bodySmall)
                HorizontalDivider(Modifier.padding(top = 8.dp), color = LocalLoftColors.current.divider)
            }
        }
        if (native != null && native.core.nodeCount > 0u) item {
            Text(stringResource(R.string.node_page_number, state.nodePageOffset.toInt() / 50 + 1, (native.core.nodeCount.toInt() + 49) / 50))
            Row(Modifier.fillMaxWidth()) {
                LinkButton(onClick = model::previousNodePage, modifier = Modifier.weight(1f), enabled = state.nodePageOffset > 0u && !state.nodePageLoading) { Text(stringResource(R.string.previous_page)) }
                LinkButton(onClick = model::nextNodePage, modifier = Modifier.weight(1f), enabled = state.nodePage?.nextOffset != null && !state.nodePageLoading) { Text(stringResource(R.string.next_page)) }
            }
        }
        item { Spacer(Modifier.height(16.dp)) }
    }
}

@Composable private fun NodeDetails(state: LoftUiState, model: LoftViewModel) {
    PageTitle(R.string.node_details)
    NativeNotice(state)
    val node = state.selectedNodeMetadata?.takeIf { it.id == state.presentation.selectedNodeId }
    if (node == null) { Text(stringResource(if (state.native == null) R.string.service_lost_title else R.string.node_metadata_unavailable)); return }
    Text(node.label, style = MaterialTheme.typography.titleMedium)
    InfoRow(R.string.protocol, protocolName(node))
    SelectionContainer { InfoRow(R.string.endpoint, node.endpoint) }
    InfoRow(R.string.credentials, stringResource(if (node.credentialMaterialPresent) R.string.material_present else R.string.material_absent))
    Text(stringResource(if (node.protocol == ProtocolKind.SOCKS5) R.string.socks_security else R.string.hyraken_security))
    Text(stringResource(R.string.udp_range, node.udpMin.toInt(), node.udpMax.toInt()), style = MaterialTheme.typography.bodySmall)
    PrimaryButton(R.string.select_candidate, { model.navigate(Page.VPN_HOME) }, state.pendingRequest == null)
    if (state.deleteConfirmation) {
        Text(stringResource(R.string.remove_node_confirmation))
        LinkButton(onClick = model::removeNode, enabled = state.pendingRequest == null) { Text(stringResource(R.string.confirm), color = MaterialTheme.colorScheme.error) }
        LinkButton(onClick = { model.deleteConfirmation(false) }) { Text(stringResource(R.string.cancel)) }
    } else LinkButton(onClick = { model.deleteConfirmation(true) }, enabled = state.pendingRequest == null) { Text(stringResource(R.string.remove_node), color = MaterialTheme.colorScheme.error) }
}

@Composable private fun RoutingPage(state: LoftUiState, model: LoftViewModel, dual: Boolean, modifier: Modifier) {
    val draft = state.presentation.routingDraft
    if (draft == null) { ScrollPage(modifier) { PageTitle(R.string.routing_title); ServiceState(state, model) }; return }
    val rows = remember(state.apps, state.appQuery, state.selectedOnly, state.appPage, draft.selectedPackages) {
        AppCatalog(state.apps).page(state.appQuery, draft.selectedPackages, state.selectedOnly, state.appPage * 50)
    }
    Column(modifier.fillMaxSize()) {
        LazyColumn(Modifier.weight(1f).fillMaxWidth().padding(horizontal = 16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            item {
                PageTitle(R.string.routing_title)
                NativeNotice(state)
                Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                    Text(stringResource(R.string.routing_mode), modifier = Modifier.weight(1f))
                    Switch(draft.enabled, model::setRoutingEnabled, enabled = state.pendingRequest == null)
                }
                Text(stringResource(if (draft.enabled) R.string.routing_selected_help else R.string.routing_full_help))
                Text(stringResource(R.string.draft_selected_count, draft.selectedPackages.size), style = MaterialTheme.typography.titleMedium)
                Text(stringResource(R.string.visible_scope), style = MaterialTheme.typography.bodySmall)
                OutlinedTextField(state.appQuery, model::setAppQuery, label = { Text(stringResource(R.string.search_apps)) }, modifier = Modifier.fillMaxWidth(), singleLine = true)
                Row(Modifier.fillMaxWidth().heightIn(min = 48.dp).toggleable(state.selectedOnly, role = Role.Checkbox, onValueChange = model::setSelectedOnly), verticalAlignment = Alignment.CenterVertically) {
                    Checkbox(state.selectedOnly, onCheckedChange = null)
                    Text(stringResource(R.string.selected_only), modifier = Modifier.weight(1f))
                }
                if (state.appsLoading) Text(stringResource(R.string.app_loading))
                state.appsError?.let { Notice(it) }
            }
            if (state.appsLoaded && rows.isEmpty()) item { Text(stringResource(R.string.no_visible_apps)) }
            items(rows, key = { it.packageName }) { app ->
                Row(Modifier.fillMaxWidth().heightIn(min = 64.dp).toggleable(app.packageName in draft.selectedPackages,
                    enabled = state.pendingRequest == null, role = Role.Checkbox, onValueChange = { model.toggleApp(app.packageName) })
                    .semantics(mergeDescendants = true) { }, verticalAlignment = Alignment.CenterVertically) {
                    Checkbox(app.packageName in draft.selectedPackages, onCheckedChange = null)
                    Column(Modifier.weight(1f).padding(vertical = 8.dp)) {
                        Text(app.label, style = MaterialTheme.typography.titleMedium)
                        Text(app.packageName, style = MaterialTheme.typography.bodySmall, color = LocalLoftColors.current.secondaryText)
                        if (state.apps.count { it.uid == app.uid } > 1) Text(stringResource(R.string.shared_uid), style = MaterialTheme.typography.bodySmall)
                    }
                }
            }
            val missing = draft.selectedPackages.filter { selected -> state.apps.none { it.packageName == selected } }
            if (state.appsLoaded) items(missing, key = { "missing:$it" }) { packageName ->
                Column(Modifier.fillMaxWidth().clickable { model.toggleApp(packageName) }.padding(12.dp)) {
                    Text(packageName)
                    Text(stringResource(R.string.err_app_unavailable), color = LocalLoftColors.current.warning)
                }
            }
            item {
                Column(Modifier.fillMaxWidth()) {
                    Text(stringResource(R.string.page_number, state.appPage + 1))
                    Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                        LinkButton(onClick = { model.setAppPage(state.appPage - 1) }, modifier = Modifier.weight(1f), enabled = state.appPage > 0) { Text(stringResource(R.string.previous_page)) }
                        LinkButton(onClick = { model.setAppPage(state.appPage + 1) }, modifier = Modifier.weight(1f), enabled = rows.size == 50) { Text(stringResource(R.string.next_page)) }
                    }
                }
            }
        }
        if (!dual) Column(Modifier.fillMaxWidth().padding(16.dp)) { RoutingSave(state, model) }
    }
}

@Composable private fun RoutingSave(state: LoftUiState, model: LoftViewModel) {
    PrimaryButton(R.string.save_draft, model::saveRoutingDraft,
        state.presentation.routingDraft?.dirty == true && state.appsLoaded && !state.appsLoading && state.pendingRequest == null)
    Text(stringResource(R.string.routing_saved), style = MaterialTheme.typography.bodySmall)
}
@Composable private fun RoutingSummary(state: LoftUiState, model: LoftViewModel) {
    SectionTitle(R.string.routing_title)
    if (state.native == null) { ServiceState(state, model); return }
    Text(stringResource(R.string.confirmed_selected_count, state.native.core.selectedApps.size))
    Text(stringResource(if (state.native.core.routingEnabled) R.string.routing_selected_help else R.string.routing_full_help))
    state.native.core.appliedRouting?.let { applied ->
        SectionTitle(R.string.routing_applied_title)
        Text(stringResource(if (applied.enabled) R.string.routing_applied_count else R.string.routing_applied_full, applied.packageNames.size))
    }
    if (state.presentation.navigation.page == Page.ROUTING) {
        Text(stringResource(R.string.draft_selected_count, state.presentation.routingDraft?.selectedPackages?.size ?: 0))
        state.presentation.selectedAppPackage?.let { SelectionContainer { Text(it) } }
    } else LinkButton(onClick = { model.navigate(Page.ROUTING) }) { Text(stringResource(R.string.routing_title)) }
}
@Composable private fun SelectedNodeSummary(state: LoftUiState, model: LoftViewModel) {
    SectionTitle(R.string.selected_candidate)
    val node = state.selectedNodeMetadata?.takeIf { it.id == state.presentation.selectedNodeId }
    if (node != null) { Text(node.label, style = MaterialTheme.typography.titleMedium); Text(protocolName(node)) }
    else if (state.native != null) Text(state.presentation.selectedNodeId ?: stringResource(if (state.native.core.nodeCount == 0u) R.string.no_nodes else R.string.choose_node)) else ServiceState(state, model)
    state.native?.core?.activeNodeId?.let { active -> InfoRow(R.string.active_node, state.selectedNodeMetadata?.takeIf { it.id == active }?.label ?: active) }
    LinkButton(onClick = { model.navigate(Page.NODES) }) { Text(stringResource(R.string.choose_node)) }
}
@Composable private fun LoginDependency(model: LoftViewModel) {
    Explanation(R.string.login_unavailable, R.string.login_dependency)
    LinkButton(onClick = { model.navigate(Page.VPN_HOME) }) { Text(stringResource(R.string.continue_guest)) }
}
@Composable private fun MailDependency(model: LoftViewModel) {
    Explanation(R.string.mail_unavailable, R.string.mail_dependency)
    LinkButton(onClick = { model.navigate(Page.ACCOUNT) }) { Text(stringResource(R.string.account_title)) }
    LinkButton(onClick = { model.navigate(Page.MAIL) }) { Text(stringResource(R.string.mail_title)) }
}

@Composable private fun AppearanceChoices(state: LoftUiState, onTheme: (ThemeChoice) -> Unit, onLocale: (String) -> Unit) {
    SectionTitle(R.string.theme)
    ThemeChoice.entries.forEach { choice ->
        ChoiceRow(when (choice) { ThemeChoice.SYSTEM -> R.string.theme_system; ThemeChoice.LIGHT -> R.string.theme_light; ThemeChoice.DARK -> R.string.theme_dark },
            state.theme == choice) { onTheme(choice) }
    }
    HorizontalDivider(color = LocalLoftColors.current.divider)
    SectionTitle(R.string.language)
    listOf("en" to R.string.language_en, "zh" to R.string.language_zh, "ja" to R.string.language_ja, "de" to R.string.language_de).forEach { (locale, title) ->
        ChoiceRow(title, state.locale == locale) { onLocale(locale) }
    }
}
@Composable private fun ChoiceRow(title: Int, selected: Boolean, onClick: () -> Unit) {
    Row(Modifier.fillMaxWidth().heightIn(min = 48.dp).selectable(selected, role = Role.RadioButton, onClick = onClick).semantics(mergeDescendants = true) { },
        verticalAlignment = Alignment.CenterVertically) { RadioButton(selected, onClick = null); Text(stringResource(title), modifier = Modifier.weight(1f)) }
}
@Composable private fun PrivacyAndBackground() { Explanation(R.string.privacy, R.string.privacy_body); LocalStorage(); Explanation(R.string.long_running, R.string.long_running_body) }
@Composable private fun Diagnostics(state: LoftUiState, model: LoftViewModel) {
    PageTitle(R.string.diagnostics_title)
    NativeNotice(state)
    Text(stringResource(R.string.diagnostics_body))
    state.native?.let { frame ->
        InfoRow(R.string.core_version, frame.core.coreVersion)
        InfoRow(R.string.engine_version, frame.engineVersion.ifBlank { stringResource(R.string.engine_not_started) })
        InfoRow(R.string.control_generation, frame.core.generation.toString())
        InfoRow(R.string.physical_vpn_scope, stringResource(if (frame.tunHeld) R.string.tun_held else R.string.tun_released))
    } ?: ServiceState(state, model)
    Explanation(R.string.vpn_policy_title, R.string.vpn_policy_body)
    NetworkPrivacyStatus(state)
    NotificationStatus(state, model)
    PrimaryButton(R.string.stop_vpn, model::stopControl, state.stopRequest == null)
}

@Composable private fun NetworkPrivacyStatus(state: LoftUiState) {
    SectionTitle(R.string.network_protection)
    val core = state.native?.core
    if (core == null) { Text(stringResource(R.string.network_unknown)); return }
    val enforcement = core.networkPrivacyEnforcement
    Text(stringResource(when (enforcement) {
        net.aptist.loft.core.generated.NetworkPrivacyEnforcement.ACTIVE -> R.string.network_privacy_active
        net.aptist.loft.core.generated.NetworkPrivacyEnforcement.BLOCKED -> R.string.network_privacy_blocked
        net.aptist.loft.core.generated.NetworkPrivacyEnforcement.INACTIVE -> R.string.network_privacy_inactive
    }))
    val applied = core.appliedNetworkPrivacy?.takeIf { enforcement != net.aptist.loft.core.generated.NetworkPrivacyEnforcement.INACTIVE }
    val policy = applied?.policy ?: core.networkPrivacyPolicy
    InfoRow(R.string.dns_policy_title, stringResource(if (policy.dnsMode == net.aptist.loft.core.generated.DnsMode.NODE_DOMAIN_FAKE_IP) R.string.dns_mode_synthetic else R.string.dns_mode_wire))
    InfoRow(R.string.dns_guard_title, stringResource(if (policy.dnsLeakPolicy == net.aptist.loft.core.generated.LeakProtectionMode.PROXY_ONLY) R.string.policy_proxy_only else R.string.policy_block))
    InfoRow(R.string.rtc_guard_title, stringResource(if (policy.webrtcPolicy == net.aptist.loft.core.generated.LeakProtectionMode.PROXY_ONLY) R.string.policy_proxy_only else R.string.policy_block))
    InfoRow(R.string.hydra_profile_title, stringResource(when {
        !policy.hydra.enabled -> R.string.hydra_off
        applied?.hydraScope == net.aptist.loft.core.generated.HydraScope.LOGICAL_STREAMS -> R.string.hydra_streams
        applied?.hydraScope == net.aptist.loft.core.generated.HydraScope.TCP_ONLY -> R.string.hydra_tcp
        else -> R.string.hydra_saved_inactive
    }))
    if (applied != null && applied.policyEpoch != core.networkPrivacyPolicyEpoch) Text(stringResource(R.string.network_policy_next_start))
    Text(stringResource(R.string.browser_sdp_scope), style = MaterialTheme.typography.bodySmall)
}

@Composable private fun NotificationStatus(state: LoftUiState, model: LoftViewModel) {
    SectionTitle(R.string.notifications_title)
    InfoRow(R.string.vpn_notifications, stringResource(notificationLabel(state.notifications.vpn)))
    InfoRow(R.string.mail_notifications, stringResource(notificationLabel(state.notifications.mail)))
    if (state.notifications.vpn in setOf(NotificationAccessStatus.PERMISSION_DENIED, NotificationAccessStatus.APP_DISABLED,
        NotificationAccessStatus.CHANNEL_DISABLED)) Text(stringResource(R.string.notification_fgs_denied_body), style = MaterialTheme.typography.bodySmall)
    Text(stringResource(R.string.mail_event_unavailable), style = MaterialTheme.typography.bodySmall)
    LinkButton(onClick = model::openNotificationSettings) { Text(stringResource(R.string.notification_settings)) }
}

private fun notificationLabel(value: NotificationAccessStatus): Int = when (value) {
    NotificationAccessStatus.ALLOWED -> R.string.notification_allowed
    NotificationAccessStatus.PERMISSION_DENIED -> R.string.notification_permission_denied
    NotificationAccessStatus.APP_DISABLED -> R.string.notification_app_disabled
    NotificationAccessStatus.CHANNEL_DISABLED -> R.string.notification_channel_disabled
    NotificationAccessStatus.CHANNEL_QUIET -> R.string.notification_channel_quiet
    NotificationAccessStatus.NOT_CREATED -> R.string.notification_channel_absent
    NotificationAccessStatus.UNKNOWN -> R.string.notification_unknown
}

@Composable private fun SecondaryMenu(state: LoftUiState, model: LoftViewModel, primary: PaneBounds) {
    Box(Modifier.fillMaxSize().background(Color.Black.copy(alpha = 0.28f)).clickable { model.toggleMenu() })
    val density = LocalDensity.current
    val menuPages = (listOf(ModuleCatalog.entry(state.presentation.navigation.module)) + ModuleCatalog.children(state.presentation.navigation.module))
        .filterNot { it == Page.NODE_DETAILS }
    Surface(Modifier.offset { IntOffset((primary.left * density.density).roundToInt(), ((primary.top + 56f) * density.density).roundToInt()) }
        .width((primary.width - 24f).coerceIn(48f, 240f).dp).heightIn(max = (primary.height - 56f).coerceAtLeast(48f).dp),
        shape = RoundedCornerShape(12.dp), color = MaterialTheme.colorScheme.surface) {
        Column(Modifier.verticalScroll(rememberScrollState()).padding(8.dp)) {
            LinkButton(onClick = model::toggleMenu, modifier = Modifier.fillMaxWidth()) { Text(stringResource(R.string.close_secondary)) }
            menuPages.forEach { page -> LinkButton(onClick = { model.navigate(page) }, modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp)) { Text(stringResource(pageTitle(page))) } }
        }
    }
}
@Composable private fun DiscardOverlay(model: LoftViewModel, primary: PaneBounds) {
    Box(Modifier.fillMaxSize().background(Color.Black.copy(alpha = 0.5f)).clickable { })
    Pane(primary) {
        val title = stringResource(R.string.discard_title)
        Surface(Modifier.align(Alignment.Center).padding(16.dp).fillMaxWidth().semantics { paneTitle = title }, shape = RoundedCornerShape(12.dp)) {
            Column(Modifier.padding(16.dp).verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text(title, style = MaterialTheme.typography.titleMedium)
                Text(stringResource(R.string.discard_body))
                PrimaryButton(R.string.keep_editing, model::keepEditing)
                LinkButton(onClick = model::discardEdits) { Text(stringResource(R.string.discard), color = MaterialTheme.colorScheme.error) }
            }
        }
    }
}

@Composable private fun ScrollPage(modifier: Modifier, content: @Composable ColumnScope.() -> Unit) {
    Column(modifier.fillMaxSize().widthIn(max = 720.dp).verticalScroll(rememberScrollState()).padding(horizontal = 16.dp, vertical = 12.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp), content = content)
}
@Composable private fun PageTitle(title: Int) { Text(stringResource(title), style = MaterialTheme.typography.headlineSmall, modifier = Modifier.semantics { heading() }) }
@Composable private fun SectionTitle(title: Int) { Text(stringResource(title), style = MaterialTheme.typography.titleMedium, modifier = Modifier.semantics { heading() }) }
@Composable private fun Explanation(title: Int, body: Int) {
    Column(Modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(8.dp)) { SectionTitle(title); Text(stringResource(body)); HorizontalDivider(color = LocalLoftColors.current.divider) }
}
@Composable private fun LocalStorage() { Explanation(R.string.storage_title, R.string.storage_body) }
@Composable private fun InfoRow(title: Int, value: String) {
    Column(Modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(4.dp)) {
        Text(stringResource(title), style = MaterialTheme.typography.bodySmall, color = LocalLoftColors.current.secondaryText)
        Text(value); HorizontalDivider(Modifier.padding(top = 8.dp), color = LocalLoftColors.current.divider)
    }
}
@Composable private fun PrimaryButton(title: Int, onClick: () -> Unit, enabled: Boolean = true) {
    Button(onClick = onClick, enabled = enabled, modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp), shape = RoundedCornerShape(12.dp)) { Text(stringResource(title)) }
}
@Composable private fun LinkButton(onClick: () -> Unit, modifier: Modifier = Modifier, enabled: Boolean = true, content: @Composable RowScope.() -> Unit) {
    TextButton(onClick = onClick, modifier = modifier.heightIn(min = 48.dp), enabled = enabled,
        colors = ButtonDefaults.textButtonColors(contentColor = LocalLoftColors.current.link), content = content)
}
@Composable private fun Notice(code: ReceiptCode) {
    Surface(color = if (code.successful) MaterialTheme.colorScheme.primaryContainer else LocalLoftColors.current.warningContainer, shape = RoundedCornerShape(12.dp)) {
        Row(Modifier.padding(12.dp), verticalAlignment = Alignment.Top) {
            if (!code.successful) Icon(painterResource(R.drawable.ic_alert), null, Modifier.size(20.dp), tint = LocalLoftColors.current.warning)
            Text(stringResource(code.text), Modifier.padding(start = if (code.successful) 0.dp else 8.dp), style = MaterialTheme.typography.bodyMedium)
        }
    }
}
@Composable private fun NativeNotice(state: LoftUiState) {
    state.notice?.takeUnless { it == state.storageOpenFailure }?.let { Notice(it) }
    if (state.pendingRequest != null) Text(stringResource(R.string.working), style = MaterialTheme.typography.bodySmall)
}
@Composable private fun ServiceState(state: LoftUiState, model: LoftViewModel) {
    if (state.availability == ServiceAvailability.OPENING) Text(stringResource(R.string.service_starting))
    if (state.availability == ServiceAvailability.UNAVAILABLE && state.storageOpenFailure == null) {
        Explanation(R.string.service_lost_title, R.string.service_lost_body)
        PrimaryButton(R.string.reopen_service, model::reopenService)
    }
}
@Composable private fun StorageFailure(state: LoftUiState, model: LoftViewModel) {
    val failure = state.storageOpenFailure ?: return
    val connection = state.native?.core?.connectionState
    val idle = connection == null || connection == ConnectionState.DISCONNECTED
    Column(Modifier.fillMaxWidth().heightIn(max = 200.dp).verticalScroll(rememberScrollState()).padding(horizontal = 16.dp)) {
        Notice(failure)
        if (idle) {
            LinkButton(onClick = model::reopenService, enabled = state.pendingRequest == null && state.stopRequest == null) {
                Text(stringResource(R.string.reopen_service))
            }
        } else {
            LinkButton(onClick = model::stopControl, enabled = state.stopRequest == null) { Text(stringResource(R.string.stop_vpn)) }
        }
    }
}
private fun protocolName(node: NodeSummary): String = when (node.protocol) {
    ProtocolKind.SOCKS5 -> "SOCKS5"; ProtocolKind.HYRAKEN_X -> "HyrakenX"; ProtocolKind.HYRAKEN_PRO -> "Hyraken Pro"
}
private fun moduleIcon(module: ModuleId): Int = when (module) {
    ModuleId.WELCOME -> R.drawable.ic_home; ModuleId.VPN -> R.drawable.ic_network; ModuleId.SHIELD -> R.drawable.ic_shield
    ModuleId.MAIL -> R.drawable.ic_mail; ModuleId.AUDIT -> R.drawable.ic_log; ModuleId.SETTING -> R.drawable.ic_settings; ModuleId.ACCOUNT -> R.drawable.ic_account
}
private fun moduleTitle(module: ModuleId): Int = when (module) {
    ModuleId.WELCOME -> R.string.module_welcome; ModuleId.VPN -> R.string.module_vpn; ModuleId.SHIELD -> R.string.module_shield
    ModuleId.MAIL -> R.string.module_mail; ModuleId.AUDIT -> R.string.module_audit; ModuleId.SETTING -> R.string.module_setting; ModuleId.ACCOUNT -> R.string.module_account
}
private fun pageTitle(page: Page): Int = when (page) {
    Page.NODES -> R.string.node_list; Page.NODE_DETAILS -> R.string.node_details; Page.IMPORT_NODE -> R.string.import_link
    Page.ROUTING -> R.string.routing_title; Page.DIAGNOSTICS -> R.string.diagnostics_title; else -> moduleTitle(page.module)
}
