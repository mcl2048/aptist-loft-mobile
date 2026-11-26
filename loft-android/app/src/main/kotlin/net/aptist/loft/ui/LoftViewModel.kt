package net.aptist.loft.ui

import android.app.Application
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.provider.Settings
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import net.aptist.loft.foundation.*
import net.aptist.loft.service.*
import net.aptist.loft.core.generated.ConnectionState
import net.aptist.loft.core.generated.NodePage
import net.aptist.loft.core.generated.NodeSummary

data class PhysicalFold(val left: Int, val top: Int, val right: Int, val bottom: Int,
    val vertical: Boolean, val separating: Boolean, val occluding: Boolean, val halfOpened: Boolean)
data class UiReceipt(val requestId: Long, val operation: OperationKind, val code: ReceiptCode, val receivedAt: Long)
enum class ServiceAvailability { OPENING, AVAILABLE, UNAVAILABLE }

data class LoftUiState(
    val presentation: PresentationState = PresentationState(),
    val native: SnapshotFrame? = null,
    val availability: ServiceAvailability = ServiceAvailability.OPENING,
    val storageOpenFailure: ReceiptCode? = null,
    val importText: String = "",
    val importConfirmation: Boolean = false,
    val deleteConfirmation: Boolean = false,
    val serverText: String = "",
    val pendingRequest: Long? = null,
    val stopRequest: Long? = null,
    val vpnPermissionPending: Boolean = false,
    val nodePage: NodePage? = null,
    val nodePageOffset: UInt = 0u,
    val nodePageLoading: Boolean = false,
    val nodePageError: ReceiptCode? = null,
    val selectedNodeMetadata: NodeSummary? = null,
    val notice: ReceiptCode? = null,
    val receipts: List<UiReceipt> = emptyList(),
    val apps: List<VisibleApp> = emptyList(),
    val appsLoaded: Boolean = false,
    val appsLoading: Boolean = false,
    val appsError: ReceiptCode? = null,
    val appQuery: String = "",
    val selectedOnly: Boolean = false,
    val appPage: Int = 0,
    val folds: List<PhysicalFold> = emptyList(),
    val theme: ThemeChoice = ThemeChoice.SYSTEM,
    val locale: String = "en",
    val notifications: AppNotificationAccess = AppNotificationAccess(),
) {
    val canChangeConfiguration: Boolean
        get() = availability == ServiceAvailability.AVAILABLE && storageOpenFailure == null
    override fun toString() = "LoftUiState(<redacted>)"
}

class AppearancePreferences(context: Context) {
    private val preferences = context.applicationContext.getSharedPreferences("appearance", Context.MODE_PRIVATE)
    fun theme(): ThemeChoice = ThemeChoice.entries.find { it.name == preferences.getString("theme", "SYSTEM") } ?: ThemeChoice.SYSTEM
    fun locale(): String = preferences.getString("locale", "en").takeIf { it in setOf("en", "zh", "ja", "de") } ?: "en"
    fun setTheme(value: ThemeChoice) { preferences.edit().putString("theme", value.name).apply() }
    fun setLocale(value: String) { if (value in setOf("en", "zh", "ja", "de")) preferences.edit().putString("locale", value).apply() }
}

/** All mutable state here is presentation state. Native is a generated Rust receipt. */
class LoftViewModel(application: Application) : AndroidViewModel(application) {
    private val preferences = AppearancePreferences(application)
    private val mutable = MutableStateFlow(LoftUiState(theme = preferences.theme(), locale = preferences.locale()))
    val ui: StateFlow<LoftUiState> = mutable
    private var nextRequest = 0L
    private var pendingOperation: OperationKind? = null
    private val vpnPermission = VpnPermissionDraft()
    private var nextNodeQuery = 0L
    private var nodeQuery: Long? = null
    private var nodeQueryGeneration: ULong? = null
    private var nodeQueryOffset: UInt? = null
    private var removingNode: String? = null
    private var visible = false
    private var appsJob: Job? = null
    private var appsEpoch = 0L
    private val client = CoreServiceClient(application, ::receivedFrame, ::receivedReceipt, ::serviceLost, ::receivedNodePage)

    init { client.setPresentationLocale(mutable.value.locale); client.bind() }

    fun setVisible(value: Boolean) {
        visible = value
        client.setVisible(value)
        if (!value) { cancelApps(); cancelNodePage() }
        else if (mutable.value.presentation.navigation.page == Page.ROUTING) loadApps()
        else if (nodePageVisible()) loadNodePage()
    }
    fun setFolds(folds: List<PhysicalFold>) { mutable.value = mutable.value.copy(folds = folds.take(2).toList()) }
    fun resize(viewport: Viewport) {
        val old = mutable.value
        val resized = old.presentation.resize(viewport)
        if (old.presentation != resized) mutable.value = old.copy(presentation = resized)
    }
    fun navigate(target: Page) {
        val state = mutable.value
        if (state.presentation.navigation.pendingPage != null || state.pendingRequest != null) return
        changeNavigation(state.presentation.navigation.navigate(target, dirty(state)))
    }
    fun toggleMenu() {
        val state = mutable.value
        if (state.presentation.navigation.pendingPage != null) return
        mutable.value = state.copy(presentation = state.presentation.copy(navigation = state.presentation.navigation.copy(menuOpen = !state.presentation.navigation.menuOpen)))
    }
    fun back(): Boolean {
        val state = mutable.value
        if (state.pendingRequest != null) return true
        if (state.importConfirmation) { mutable.value = state.copy(importConfirmation = false); return true }
        if (state.deleteConfirmation) { mutable.value = state.copy(deleteConfirmation = false); return true }
        if (state.presentation.navigation.pendingPage != null) { keepEditing(); return true }
        if (state.presentation.navigation.page == Page.WELCOME && !state.presentation.navigation.menuOpen) return false
        changeNavigation(state.presentation.navigation.back(dirty(state)))
        return true
    }
    fun discardEdits() {
        val state = mutable.value
        val clean = state.copy(importText = "", importConfirmation = false, serverText = state.native?.core?.serverAddress.orEmpty(),
            presentation = state.presentation.copy(routingDraft = state.native?.core?.let { RoutingDraft.from(it.routingEnabled, it.selectedApps.toSet()) }))
        mutable.value = clean
        changeNavigation(clean.presentation.navigation.discardAndNavigate())
    }
    fun keepEditing() {
        val state = mutable.value
        mutable.value = state.copy(presentation = state.presentation.copy(navigation = state.presentation.navigation.keepEditing()))
    }
    private fun dirty(state: LoftUiState): Boolean = when (state.presentation.navigation.page) {
        Page.IMPORT_NODE -> state.importText.isNotBlank()
        Page.ROUTING -> state.presentation.routingDraft?.dirty == true
        Page.ACCOUNT -> state.serverText != state.native?.core?.serverAddress.orEmpty()
        else -> false
    }
    private fun changeNavigation(navigation: NavigationState) {
        val old = mutable.value
        if (old.presentation.navigation.page != navigation.page && navigation.pendingPage == null) {
            if (old.presentation.navigation.page == Page.ROUTING) cancelApps()
            if (old.presentation.navigation.page in setOf(Page.NODES, Page.NODE_DETAILS) && navigation.page !in setOf(Page.NODES, Page.NODE_DETAILS)) cancelNodePage()
            val current = mutable.value
            mutable.value = current.copy(importConfirmation = false, deleteConfirmation = false,
                presentation = current.presentation.copy(navigation = navigation,
                    routingDraft = if (navigation.page == Page.ROUTING) current.native?.core?.let { RoutingDraft.from(it.routingEnabled, it.selectedApps.toSet()) } else current.presentation.routingDraft))
            if (navigation.page == Page.ROUTING && visible) loadApps()
            if (navigation.page in setOf(Page.NODES, Page.NODE_DETAILS) && visible) loadNodePage()
        } else mutable.value = old.copy(presentation = old.presentation.copy(navigation = navigation))
    }

    fun setImportText(value: String) {
        if (value.length > ControlCodec.MAX_CONTROL_BYTES || value.toByteArray(Charsets.UTF_8).size > ControlCodec.MAX_CONTROL_BYTES - 9) {
            showNotice(ReceiptCode.CONTROL_TOO_LARGE); return
        }
        mutable.value = mutable.value.copy(importText = value, importConfirmation = false, notice = null)
    }
    fun readClipboard() {
        val clipboard = getApplication<Application>().getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        val text = clipboard.primaryClip?.takeIf { it.itemCount > 0 }?.getItemAt(0)?.text?.toString()
        if (text == null) showNotice(ReceiptCode.CLIPBOARD_EMPTY) else setImportText(text)
    }
    fun reviewImport() { if (mutable.value.importText.isNotBlank()) mutable.value = mutable.value.copy(importConfirmation = true) }
    fun cancelImportConfirmation() { mutable.value = mutable.value.copy(importConfirmation = false) }
    fun confirmImport() { submit(CoreCommand.ImportNode(mutable.value.importText)) }
    fun setServerText(value: String) {
        if (value.length > 2048 || value.toByteArray(Charsets.UTF_8).size > 2048) { showNotice(ReceiptCode.INPUT_TOO_LARGE); return }
        mutable.value = mutable.value.copy(serverText = value, notice = null)
    }
    fun stageServer() { submit(CoreCommand.StageServer(mutable.value.serverText)) }
    fun resetServer() { submit(CoreCommand.ResetServer) }
    fun selectNode(id: String, showDetails: Boolean) {
        val state = mutable.value
        val node = state.nodePage?.nodes?.find { it.id == id } ?: state.native?.core?.nodes?.find { it.id == id } ?: return
        val choice = NodeChoice(state.presentation.selectedNodeId, state.selectedNodeMetadata).select(node)
        mutable.value = state.copy(selectedNodeMetadata = choice.summary, presentation = state.presentation.copy(selectedNodeId = choice.id))
        if (showDetails) navigate(Page.NODE_DETAILS)
    }
    fun deleteConfirmation(value: Boolean) { mutable.value = mutable.value.copy(deleteConfirmation = value) }
    fun removeNode() { mutable.value.presentation.selectedNodeId?.let { removingNode = it; submit(CoreCommand.RemoveNode(it)) } }
    fun prepareVpnPermission(): Boolean {
        val state = mutable.value
        val native = state.native
        val node = state.presentation.selectedNodeId
        if (state.pendingRequest != null || state.stopRequest != null || state.vpnPermissionPending) return false
        if (!state.canChangeConfiguration) { showNotice(state.storageOpenFailure ?: ReceiptCode.STATE_UNAVAILABLE); return false }
        if (native == null || node == null) { showNotice(ReceiptCode.STATE_UNAVAILABLE); return false }
        if (native.core.connectionState != ConnectionState.DISCONNECTED) { showNotice(ReceiptCode.CONNECTION_BUSY); return false }
        if (!vpnPermission.request(node, native.core.generation)) return false
        mutable.value = state.copy(vpnPermissionPending = true, notice = null)
        return true
    }
    fun completeVpnPermission(granted: Boolean) {
        val command = vpnPermission.finish(granted)
        mutable.value = mutable.value.copy(vpnPermissionPending = false)
        if (command != null) submit(command)
        else showNotice(if (granted) ReceiptCode.TICKET_EXPIRED else ReceiptCode.VPN_PERMISSION_DENIED)
    }
    fun stopControl() {
        vpnPermission.cancel()
        val state = mutable.value
        if (state.stopRequest != null) return
        val request = runCatching { Math.addExact(nextRequest, 1L) }.getOrNull()
        if (request == null) { stopViaOs(); showNotice(ReceiptCode.GENERATION_EXHAUSTED); return }
        nextRequest = request
        mutable.value = state.copy(stopRequest = request, notice = null)
        if (!client.execute(request, CoreCommand.Stop)) {
            stopViaOs()
            serviceLost(ReceiptCode.STATE_UNAVAILABLE)
        }
    }
    private fun stopViaOs() {
        runCatching { getApplication<Application>().startService(Intent(getApplication(), LoftVpnService::class.java).setAction(LoftVpnService.ACTION_STOP)) }
    }
    fun setRoutingEnabled(value: Boolean) {
        val state = mutable.value
        val draft = state.presentation.routingDraft ?: return
        mutable.value = state.copy(notice = null, presentation = state.presentation.copy(routingDraft = draft.withEnabled(value)))
    }
    fun toggleApp(packageName: String) {
        val state = mutable.value
        val draft = state.presentation.routingDraft ?: return
        mutable.value = state.copy(notice = null, presentation = state.presentation.copy(
            routingDraft = draft.toggle(state.apps, packageName), selectedAppPackage = packageName))
    }
    fun setAppQuery(value: String) { mutable.value = mutable.value.copy(appQuery = value.take(128), appPage = 0) }
    fun setSelectedOnly(value: Boolean) { mutable.value = mutable.value.copy(selectedOnly = value, appPage = 0) }
    fun setAppPage(value: Int) { mutable.value = mutable.value.copy(appPage = value.coerceAtLeast(0)) }
    fun saveRoutingDraft() {
        if (!mutable.value.appsLoaded) { showNotice(ReceiptCode.APP_QUERY_FAILED); return }
        // Re-read the actual installation scope immediately before submitting a
        // draft; the Rust core independently validates all domain/config limits.
        loadApps(saveAfterRead = true)
    }
    private fun loadApps(saveAfterRead: Boolean = false) {
        if (appsJob?.isActive == true) return
        val ticket = ++appsEpoch
        mutable.value = mutable.value.copy(appsLoading = true, appsError = null)
        appsJob = viewModelScope.launch {
            try {
                val rows = withContext(Dispatchers.IO) {
                    ensureActive()
                    AndroidPackageScope(getApplication<Application>()).visibleCatalog().also { ensureActive() }
                }
                if (ticket != appsEpoch || !visible || mutable.value.presentation.navigation.page != Page.ROUTING) return@launch
                mutable.value = mutable.value.copy(apps = rows, appsLoaded = true, appsLoading = false)
                if (saveAfterRead) when (val result = mutable.value.presentation.routingDraft?.submission(rows)) {
                    is RoutingSubmission.Ready -> submit(result.command)
                    is RoutingSubmission.Invalid -> showNotice(when (result.problem) {
                        DraftProblem.EMPTY_SELECTION -> ReceiptCode.EMPTY_ROUTING_SELECTION
                        DraftProblem.APP_UNAVAILABLE -> ReceiptCode.APP_UNAVAILABLE
                        DraftProblem.TOO_MANY_APPS -> ReceiptCode.ROUTING_SELECTION_TOO_LARGE
                    })
                    else -> Unit
                }
            } catch (cancelled: CancellationException) { throw cancelled }
            catch (failure: AppScopeException) {
                if (ticket == appsEpoch) mutable.value = mutable.value.copy(appsLoading = false, appsLoaded = false,
                    appsError = if (failure.problem == ScopeProblem.CATALOG_TOO_LARGE) ReceiptCode.APP_CATALOG_LIMIT else ReceiptCode.APP_UNAVAILABLE)
            }
            catch (_: Exception) {
                if (ticket == appsEpoch) mutable.value = mutable.value.copy(appsLoading = false, appsLoaded = false, appsError = ReceiptCode.APP_QUERY_FAILED)
            }
        }
    }
    private fun cancelApps() {
        appsEpoch++; appsJob?.cancel(); appsJob = null
        mutable.value = mutable.value.copy(apps = emptyList(), appsLoaded = false, appsLoading = false)
    }
    private fun nodePageVisible() = mutable.value.presentation.navigation.page in setOf(Page.NODES, Page.NODE_DETAILS)
    fun refreshNodes() = loadNodePage(force = true)
    fun previousNodePage() {
        val state = mutable.value
        if (state.nodePageLoading || state.nodePageOffset == 0u) return
        mutable.value = state.copy(nodePageOffset = state.nodePageOffset - 50u, nodePage = null)
        loadNodePage()
    }
    fun nextNodePage() {
        val state = mutable.value
        if (state.nodePageLoading) return
        val next = state.nodePage?.nextOffset ?: return
        mutable.value = state.copy(nodePageOffset = next, nodePage = null)
        loadNodePage()
    }
    private fun cancelNodePage() {
        client.cancelNodePages()
        nodeQuery = null; nodeQueryGeneration = null; nodeQueryOffset = null
        mutable.value = mutable.value.copy(nodePageLoading = false)
    }
    private fun loadNodePage(force: Boolean = false) {
        if (!visible || !nodePageVisible()) return
        val state = mutable.value
        val core = state.native?.core ?: return
        val maxOffset = if (core.nodeCount == 0u) 0u else (core.nodeCount - 1u) / 50u * 50u
        val offset = minOf(state.nodePageOffset, maxOffset)
        if (!force && state.nodePage?.let { it.generation == core.generation && it.offset == offset } == true) return
        if (!force && state.nodePageLoading && nodeQueryGeneration == core.generation && nodeQueryOffset == offset) return
        client.cancelNodePages()
        val request = runCatching { Math.addExact(nextNodeQuery, 1L) }.getOrNull()
        if (request == null) { mutable.value = state.copy(nodePageError = ReceiptCode.GENERATION_EXHAUSTED, nodePageLoading = false); return }
        nextNodeQuery = request; nodeQuery = request; nodeQueryGeneration = core.generation; nodeQueryOffset = offset
        mutable.value = state.copy(nodePage = null, nodePageOffset = offset, nodePageLoading = true, nodePageError = null)
        if (!client.queryNodePage(request, offset, core.generation)) {
            nodeQuery = null
            mutable.value = mutable.value.copy(nodePageLoading = false, nodePageError = ReceiptCode.STATE_UNAVAILABLE)
        }
    }
    private fun receivedNodePage(requestId: Long, page: NodePage?, error: ReceiptCode?) {
        if (!visible || !nodePageVisible() || requestId != nodeQuery) return
        val state = mutable.value
        nodeQuery = null
        if (page == null || error != null) {
            mutable.value = state.copy(nodePageLoading = false, nodePageError = error ?: ReceiptCode.INVALID_NODE_PAGE)
            return
        }
        val core = state.native?.core
        if (core == null || page.generation != core.generation || page.offset != state.nodePageOffset || page.nodeCount != core.nodeCount) {
            mutable.value = state.copy(nodePageLoading = false, nodePageError = ReceiptCode.STALE_GENERATION)
            return
        }
        val choice = NodeChoice(state.presentation.selectedNodeId, state.selectedNodeMetadata).receive(page)
        mutable.value = state.copy(nodePage = page, nodePageLoading = false, nodePageError = null, selectedNodeMetadata = choice.summary)
    }
    fun showNotice(code: ReceiptCode) { mutable.value = mutable.value.copy(notice = code) }
    fun setTheme(value: ThemeChoice) { preferences.setTheme(value); mutable.value = mutable.value.copy(theme = value) }
    fun setLocale(value: String) {
        if (value !in setOf("en", "zh", "ja", "de")) return
        preferences.setLocale(value); mutable.value = mutable.value.copy(locale = value)
        client.setPresentationLocale(value)
    }
    fun refreshNotificationAccess() {
        mutable.value = mutable.value.copy(notifications = LoftNotificationChannels.access(getApplication()))
    }
    fun openNotificationSettings() {
        val context = getApplication<Application>()
        context.startActivity(Intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS)
            .putExtra(Settings.EXTRA_APP_PACKAGE, context.packageName).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
    }
    fun reopenService() {
        val state = mutable.value
        if (state.pendingRequest != null || state.stopRequest != null) return
        cancelNodePage()
        if (state.storageOpenFailure != null) {
            val request = Math.addExact(nextRequest, 1L)
            if (client.reopenStorage(request)) {
                nextRequest = request
                pendingOperation = OperationKind.STORAGE_REOPEN
                mutable.value = mutable.value.copy(pendingRequest = request, notice = null)
                return
            }
        }
        mutable.value = mutable.value.copy(availability = ServiceAvailability.OPENING, native = null, nodePage = null,
            pendingRequest = null, notice = null, storageOpenFailure = null)
        client.reopen()
    }
    private fun submit(command: CoreCommand) {
        if (command == CoreCommand.Stop) { stopControl(); return }
        val state = mutable.value
        if (state.pendingRequest != null) return
        if (!state.canChangeConfiguration) { showNotice(state.storageOpenFailure ?: ReceiptCode.STATE_UNAVAILABLE); return }
        val request = Math.addExact(nextRequest, 1L)
        nextRequest = request; pendingOperation = OperationKind.of(command)
        mutable.value = state.copy(pendingRequest = request, notice = null)
        try {
            if (!client.execute(request, command)) serviceLost(ReceiptCode.STATE_UNAVAILABLE)
        } catch (failure: ControlMessageException) {
            mutable.value = mutable.value.copy(pendingRequest = null, notice = if (failure.problem == ControlProblem.TOO_LARGE) ReceiptCode.CONTROL_TOO_LARGE else ReceiptCode.INVALID_COMMAND)
            pendingOperation = null
        }
    }
    private fun receivedFrame(frame: SnapshotFrame) {
        val state = mutable.value
        val existingDraft = state.presentation.routingDraft
        val draft = if (existingDraft == null || !existingDraft.dirty) RoutingDraft.from(frame.core.routingEnabled, frame.core.selectedApps.toSet()) else existingDraft
        val choice = NodeChoice(state.presentation.selectedNodeId, state.selectedNodeMetadata).receive(frame.core)
        val server = if (state.serverText == state.native?.core?.serverAddress.orEmpty()) frame.core.serverAddress.orEmpty() else state.serverText
        mutable.value = state.copy(native = frame, availability = ServiceAvailability.AVAILABLE, serverText = server, selectedNodeMetadata = choice.summary,
            presentation = state.presentation.copy(routingDraft = draft, selectedNodeId = choice.id))
        if (visible && nodePageVisible()) loadNodePage()
    }
    private fun receivedReceipt(requestId: Long, code: ReceiptCode) {
        val state = mutable.value
        val stopping = requestId == state.stopRequest
        val operation = if (stopping) OperationKind.STOP else pendingOperation ?: return
        if (!stopping && requestId != state.pendingRequest) return
        if (!stopping) pendingOperation = null
        val receipt = UiReceipt(requestId, operation, code, System.currentTimeMillis())
        var updated = state.copy(pendingRequest = if (stopping) state.pendingRequest else null,
            stopRequest = if (stopping) null else state.stopRequest, notice = code, receipts = (listOf(receipt) + state.receipts).take(20))
        if (code == ReceiptCode.NODE_IMPORTED) updated = updated.copy(importText = "", importConfirmation = false,
            presentation = updated.presentation.copy(navigation = NavigationState(Page.NODES)))
        if (code == ReceiptCode.NODE_REMOVED) {
            val choice = NodeChoice(updated.presentation.selectedNodeId, updated.selectedNodeMetadata).removed(removingNode.orEmpty())
            updated = updated.copy(deleteConfirmation = false, selectedNodeMetadata = choice.summary,
                presentation = updated.presentation.copy(selectedNodeId = choice.id))
        }
        if (operation == OperationKind.REMOVE) removingNode = null
        if (code == ReceiptCode.SERVER_STAGED || code == ReceiptCode.SERVER_RESET) updated = updated.copy(serverText = updated.native?.core?.serverAddress.orEmpty())
        if (code == ReceiptCode.ROUTING_STAGED) updated = updated.copy(presentation = updated.presentation.copy(
            routingDraft = updated.native?.core?.let { RoutingDraft.from(it.routingEnabled, it.selectedApps.toSet()) }))
        if (code in setOf(ReceiptCode.NATIVE_UNAVAILABLE, ReceiptCode.STATE_UNAVAILABLE, ReceiptCode.PUBLICATION_EXHAUSTED, ReceiptCode.TUN_CLOSED_CORE_UNAVAILABLE)) {
            updated = updated.copy(native = updated.native.takeIf { it?.core?.connectionState == ConnectionState.UNAVAILABLE }, availability = ServiceAvailability.UNAVAILABLE)
        }
        if (operation == OperationKind.STORAGE_REOPEN && isStorageOpenFailure(code)) {
            updated = updated.copy(native = null, availability = ServiceAvailability.UNAVAILABLE, storageOpenFailure = code)
        } else if (code == ReceiptCode.STORAGE_RECOVERY_REQUIRED || (updated.native == null && isStorageOpenFailure(code))) {
            updated = updated.copy(availability = if (updated.native == null) ServiceAvailability.UNAVAILABLE else updated.availability,
                storageOpenFailure = code)
        }
        if (code == ReceiptCode.STORAGE_REOPENED) {
            updated = updated.copy(storageOpenFailure = null)
        }
        mutable.value = updated
        if (visible && nodePageVisible()) loadNodePage()
    }
    private fun serviceLost(code: ReceiptCode) {
        pendingOperation = null
        vpnPermission.cancel()
        cancelNodePage()
        val state = mutable.value
        mutable.value = state.copy(native = null, nodePage = null, availability = ServiceAvailability.UNAVAILABLE,
            pendingRequest = null, stopRequest = null, notice = code,
            storageOpenFailure = if (isStorageOpenFailure(code)) code else state.storageOpenFailure)
    }

    private fun isStorageOpenFailure(code: ReceiptCode): Boolean =
        code == ReceiptCode.STORAGE_UNAVAILABLE || code == ReceiptCode.STORAGE_RECOVERY_REQUIRED
    override fun onCleared() {
        client.close(); cancelApps(); cancelNodePage()
        mutable.value = mutable.value.copy(importText = "", serverText = "", native = null,
            presentation = mutable.value.presentation.copy(routingDraft = null))
        super.onCleared()
    }
}
