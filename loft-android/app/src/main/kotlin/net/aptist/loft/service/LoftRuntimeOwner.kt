package net.aptist.loft.service

import android.content.Context
import android.content.Intent
import android.content.res.Configuration
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService
import android.os.Handler
import android.os.Looper
import android.os.ParcelFileDescriptor
import android.os.RemoteCallbackList
import android.os.RemoteException
import net.aptist.loft.core.generated.*
import net.aptist.loft.engine.Engine
import net.aptist.loft.engine.VPNRuntime
import net.aptist.loft.engine.VPNStateListener
import net.aptist.loft.foundation.*
import net.aptist.loft.ipc.ILoftEvents
import net.aptist.loft.ipc.ILoftHubEvents
import net.aptist.loft.ipc.ILoftTrafficEvents
import java.io.File
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import java.util.Locale

/** Physical/IPC ownership only. AppCore owns every business connection state. */
class LoftRuntimeOwner private constructor(context: Context) {
    private val app = context.applicationContext
    private val main = Handler(Looper.getMainLooper())
    private val observers = RemoteCallbackList<ILoftEvents>()
    private val observerLock = Any()
    private val admissionLock = Any()
    private var stopEpoch = Any()
    private val active = AtomicReference<Attempt?>(null)
    private val closedNetworkResources = AtomicReference<NetworkResourceSnapshot?>(null)
    private val closedTraffic = AtomicReference<VpnTrafficSample?>(null)
    private val tun = OriginalTunOwnership<ParcelFileDescriptor>()
    private val publisher = SnapshotPublisher()
    private val publicationFailed = AtomicBoolean(false)
    private val availabilityGuard = CoreAvailabilityGuard { unavailableNotice(); fault(active.get()) }
    private val commands = executor(8)
    private val hub = HubControl { core -> broadcast(capture(core)) }
    private val protection = ProtectionControl()
    private val notesSync = NotesSyncControl(::notesSyncRoute, ::notifyNotesSync)
    private val vault = VaultControl(
        unavailable = { core -> broadcast(capture(core)) },
        onIdentityChanged = { notifyNotesSync(0, "session_changed") },
    )
    private val starts = executor(1)
    private val events = executor(1)
    private val priority = executor(1)
    private val uiController = AtomicReference<Any?>(null)
    private var workerUiLease = false
    private val stopDispatch = StopDispatch()
    private val eventQueued = AtomicBoolean(false)
    private val stopLock = Any()
    @Volatile private var stopQueued = false
    private val stopObservers = linkedMapOf<Long, ILoftEvents>()
    @Volatile private var engineVersion = ""
    @Volatile private var notificationContext: Context = app
    private val mailNotifications = LoftMailNotifications(app, { notificationContext })
    private val resources = NativeResources(
        coreFactory = {
            System.setProperty("jna.library.path", app.applicationInfo.nativeLibraryDir)
            System.loadLibrary("loft_ffi")
            AndroidDatabaseKey(File(app.noBackupFilesDir, "local-store"), "net.aptist.loft.database-wrap.v1")
                .open { path, key, allowCreate -> AppCore.openPersistent(path, key, allowCreate) }
        },
        goFactory = {
            val attempt = checkNotNull(active.get())
            val protector = checkNotNull(attempt.protector)
            engineVersion = GoRuntimeInfo.decodeEngineVersion(Engine.vpnRuntimeInfo())
            GoResource(Engine.newVPNRuntime(protector))
        },
    )
    private class GoResource(val runtime: VPNRuntime) : AutoCloseable {
        override fun close() { runtime.setStateListener(null); runtime.close() }
    }
    private class Attempt(val core: AppCore, val ticket: VpnStartTicket, val id: ULong,
        val routingEnabled: Boolean, val packages: List<String>, val uidScope: PlatformUidScope,
        val networkPolicy: CapturedNetworkPolicy) {
        val cancelled = AtomicBoolean(false)
        val faulted = AtomicBoolean(false)
        val failureDispatch = FailureDispatch()
        val blockedSubmitted = AtomicBoolean(false)
        val readySubmitted = AtomicBoolean(false)
        val privacyConfirmed = AtomicBoolean(false)
        val start = StartOwnership()
        val go = AtomicReference<GoResource?>(null)
        val facts = GoSnapshotAdmission()
        val platform = AtomicReference<PlatformTunReceipt?>(null)
        @Volatile var protector: AndroidSocketProtector? = null
        @Volatile var service: LoftVpnService? = null
        @Volatile var networkCallback: Pair<ConnectivityManager, ConnectivityManager.NetworkCallback>? = null
        override fun toString() = "VpnAttempt(<redacted>)"
    }
    private class StopAdmission(val attempt: Attempt?, val epoch: Any, val fresh: Boolean, val busy: Boolean)

    init { LoftNotificationChannels.ensure(notificationContext) }

    fun notificationContext(): Context = notificationContext
    // No provider/IPC ingress is registered in the default product. This local
    // boundary always denies until an actual Rust authority is implemented.
    internal fun acceptMailEvent(payload: ByteArray): MailDeliveryReceipt = mailNotifications.receive(payload)
    fun setPresentationLocale(locale: String) {
        if (locale.length != 2 || locale !in setOf("en", "zh", "ja", "de")) return
        val configuration = Configuration(app.resources.configuration).apply { setLocale(Locale.forLanguageTag(locale)) }
        notificationContext = app.createConfigurationContext(configuration)
        LoftNotificationChannels.ensure(notificationContext)
        active.get()?.service?.refreshLocalizedNotification()
    }

    fun attachUi(token: Any) { uiController.set(token) }

    fun detachUi(token: Any) {
        if (!uiController.compareAndSet(token, null)) return
        hub.cancel()
        vault.cancel()
        protection.detach(token)
        observerTargets().forEach { observers.unregister(it) }
        // If the queue is full, every already queued job runs the same cleanup.
        submitCommand { }
    }

    private fun submitCommand(work: () -> Unit): Boolean = submit(commands) {
        try { work() } finally {
            protection.retire(runCatching { resources.currentCore() }.getOrNull())
            if (workerUiLease && uiController.get() == null) {
                workerUiLease = false
                resources.releaseUi()
                if (runCatching { resources.currentCore() }.isFailure) engineVersion = ""
            }
        }
    }

    private fun retainCoreOnWorker(): AppCore {
        val core = resources.retainUi()
        if (!workerUiLease && uiController.get() != null) {
            resources.retainExistingUi()
            workerUiLease = true
        }
        return core
    }

    fun subscribe(observer: ILoftEvents) {
        synchronized(observerLock) {
            if (observers.registeredCallbackCount >= 4) { sendReceipt(observer, 0, ReceiptCode.RESOURCE_BUSY, byteArrayOf()); return }
            observers.register(observer)
        }
        if (!submitCommand {
            val core = try { retainCoreOnWorker() }
            catch (failure: Exception) { sendReceipt(observer, 0, openFailure(failure), byteArrayOf()); return@submitCommand }
            catch (_: LinkageError) { sendReceipt(observer, 0, ReceiptCode.NATIVE_UNAVAILABLE, byteArrayOf()); return@submitCommand }
            val payload = try { capture(core) } finally { resources.releaseUi() }
            if (payload.isEmpty()) sendReceipt(observer, 0, unavailableCode(), payload) else sendSnapshot(observer, payload)
        }) {
            observers.unregister(observer)
            sendReceipt(observer, 0, ReceiptCode.RESOURCE_BUSY, byteArrayOf())
        }
    }
    fun unsubscribe(observer: ILoftEvents) { observers.unregister(observer) }

    fun queryVpnTraffic(attemptId: ULong, observer: ILoftTrafficEvents) {
        fun reply(sample: VpnTrafficSample?) {
            try {
                if (sample == null) observer.onVpnTrafficUnavailable(attemptId.toLong())
                else observer.onVpnTraffic(attemptId.toLong(), sample.uploadBytes, sample.downloadBytes, sample.finalized)
            } catch (_: RemoteException) { }
        }
        if (attemptId == 0uL || !submitCommand { reply(runCatching { trafficSample(attemptId) }.getOrNull()) }) reply(null)
    }

    private fun trafficSample(attemptId: ULong): VpnTrafficSample? {
        val attempt = active.get()
        if (attempt == null) {
            val history = closedTraffic.get()?.takeIf { it.attemptId == attemptId } ?: return null
            val core = resources.currentCore().snapshot()
            return history.takeIf { active.get() == null && core.connectionAttemptId == attemptId &&
                core.connectionState in setOf(ConnectionState.DISCONNECTED, ConnectionState.UNAVAILABLE) }
        }
        if (attempt.id != attemptId || !trafficReady(attempt)) return null
        val raw = attempt.go.get()?.runtime?.trafficUsage() ?: return null
        return decodeVpnTraffic(raw, attemptId, finalized = false)?.takeIf { trafficReady(attempt) }
    }

    private fun trafficReady(attempt: Attempt): Boolean {
        if (active.get() !== attempt || !attempt.privacyConfirmed.get() || attempt.cancelled.get() || attempt.faulted.get() ||
            !tun.facts().held || attempt.facts.current()?.provesReady != true) return false
        val core = attempt.core.snapshot()
        return core.connectionAttemptId == attempt.id && core.connectionState == ConnectionState.CONNECTED
    }

    fun cancelHubWork(requestId: Long) { hub.cancel(requestId) }

    fun cancelVaultWork(requestId: Long) { vault.cancel(requestId) }

    fun executeNotesSync(requestId: Long, observer: ILoftHubEvents) {
        if (requestId <= 0) { ProtectionControl.reply(requestId, observer, "invalid"); return }
        val work = NotesSyncControl.Work(requestId, observer)
        if (!notesSync.reserve(work)) { ProtectionControl.reply(requestId, observer, "busy"); return }
        if (!submitCommand {
            val core = try { retainCoreOnWorker() }
            catch (_: Exception) { null }
            catch (_: LinkageError) { null }
            if (core == null) notesSync.reject(work, "unavailable")
            else notesSync.execute(core, work) { resources.releaseUi() }
        }) notesSync.reject(work, "busy")
    }

    private fun notifyNotesSync(generation: Long, status: String) {
        observerTargets().forEach { observer ->
            try { observer.onNotesSync(generation, status) }
            catch (_: RemoteException) { observers.unregister(observer) }
        }
    }

    fun cancelNotesSync(requestId: Long) = notesSync.cancel(requestId)

    private fun notesSyncRoute(): NotesSyncRoute? {
        val connectivity = app.getSystemService(ConnectivityManager::class.java) ?: return null
        val attempt = active.get()
        if (stopQueued || (attempt != null && !trafficReady(attempt))) return null
        if (attempt?.routingEnabled == true &&
            attempt.uidScope.packageUids.none { it.uid == attempt.uidScope.vpnOwnerUid }) return null
        val network = connectivity.activeNetwork ?: return null
        fun current(): Boolean {
            if (active.get() !== attempt || stopQueued || connectivity.activeNetwork != network ||
                attempt?.cancelled?.get() == true || attempt?.faulted?.get() == true) return false
            val capabilities = connectivity.getNetworkCapabilities(network) ?: return false
            return attempt == null || capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
        }
        return if (current()) NotesSyncRoute(network, ::current) else null
    }

    internal fun setProtectedArea(controller: Any, epoch: Long, area: ProtectedArea?) {
        if (epoch <= 0 || uiController.get() !== controller) return
        protection.select(controller, epoch, area)
        if (area != ProtectedArea.VAULT) vault.cancel()
        submitCommand { }
    }

    fun executeProtected(controller: Any, epoch: Long, requestId: Long, payload: ByteArray, observer: ILoftHubEvents) {
        val command = try { ProtectedWire.readCommand(payload) } catch (_: java.io.IOException) { null }
        finally { payload.fill(0) }
        if (command == null || requestId <= 0) {
            command?.clear()
            ProtectionControl.reply(requestId, observer, "invalid")
            return
        }
        val session = protection.capture(controller, epoch)
        if (session == null) {
            command.clear()
            ProtectionControl.reply(requestId, observer, "locked")
            return
        }
        if (!submitCommand {
            val core = try { retainCoreOnWorker() }
            catch (_: Exception) { null }
            catch (_: LinkageError) { null }
            if (core == null) {
                command.clear()
                ProtectionControl.reply(requestId, observer, "unavailable")
            } else {
                try { protection.run(core, session, requestId, command, observer) }
                finally { resources.releaseUi() }
            }
        }) {
            command.clear()
            ProtectionControl.reply(requestId, observer, "busy")
        }
    }

    fun executeVault(controller: Any, epoch: Long, requestId: Long, payload: ByteArray, observer: ILoftHubEvents) {
        val command = try { VaultWire.readCommand(payload) } catch (_: java.io.IOException) { null }
        finally { payload.fill(0) }
        if (command == null || requestId <= 0) {
            command?.clear()
            HubControl.reply(requestId, observer, "invalid")
            return
        }
        val session = protection.capture(controller, epoch)
        if (session == null || session.area != ProtectedArea.VAULT) {
            command.clear()
            HubControl.reply(requestId, observer, "locked")
            return
        }
        val work = VaultControl.Work(requestId, command, observer) { protection.isCurrent(session) }
        if (!vault.admit(work)) { vault.reject(work, "busy"); return }
        if (!submitCommand {
            val core = try { retainCoreOnWorker() }
            catch (_: Exception) { vault.reject(work, "unavailable"); return@submitCommand }
            catch (_: LinkageError) { vault.reject(work, "unavailable"); return@submitCommand }
            try { protection.requireVault(core, session) }
            catch (_: Exception) { resources.releaseUi(); vault.reject(work, "locked"); return@submitCommand }
            catch (_: LinkageError) { resources.releaseUi(); vault.reject(work, "unavailable"); return@submitCommand }
            if (command is VaultCommand.Sync) vault.sync(core, work) { resources.releaseUi() }
            else try { vault.local(core, work) } finally { resources.releaseUi() }
        }) vault.reject(work, "busy")
    }

    fun executeHub(requestId: Long, name: String, input: String?, mailAccess: Boolean,
        destination: ParcelFileDescriptor?, observer: ILoftHubEvents) {
        val action = HubAction.entries.firstOrNull { it.name == name }
        val work = HubControl.Work(requestId, action, input, mailAccess, destination, observer)
        val savesFile = action == HubAction.MAIL_CONTENT || action == HubAction.MAIL_ATTACHMENT
        if (requestId <= 0 || (name.isNotEmpty() && action == null) || (input?.length ?: 0) > 4096 ||
            savesFile != (destination != null)) {
            hub.reject(work, "invalid_request"); return
        }
        if (!hub.reserve(work)) { hub.reject(work, "busy"); return }
        if (!submitCommand {
            val core = try { retainCoreOnWorker() }
            catch (_: Exception) { hub.reject(work, "unavailable"); return@submitCommand }
            catch (_: LinkageError) { hub.reject(work, "unavailable"); return@submitCommand }
            hub.execute(core, work) { resources.releaseUi() }
        }) hub.reject(work, "busy")
    }

    fun reopenStorage(requestId: Long, observer: ILoftEvents) {
        if (requestId <= 0) { sendReceipt(observer, requestId, ReceiptCode.INVALID_COMMAND, byteArrayOf()); return }
        if (!submitCommand {
            val admitted = synchronized(admissionLock) {
                if (active.get() != null || stopQueued) false
                else { stopEpoch = Any(); true }
            }
            val released = admitted && if (workerUiLease) resources.releaseSoleUiLease()
                else runCatching { resources.currentCore() }.isFailure
            if (!released) {
                sendReceipt(observer, requestId, ReceiptCode.RESOURCE_BUSY, byteArrayOf())
                return@submitCommand
            }
            workerUiLease = false
            engineVersion = ""
            closedNetworkResources.set(null)
            closedTraffic.set(null)
            val core = try { retainCoreOnWorker() }
            catch (failure: Exception) { sendReceipt(observer, requestId, openFailure(failure), byteArrayOf()); return@submitCommand }
            catch (_: LinkageError) { sendReceipt(observer, requestId, ReceiptCode.NATIVE_UNAVAILABLE, byteArrayOf()); return@submitCommand }
            val payload = try { capture(core) } finally { resources.releaseUi() }
            broadcast(payload)
            sendReceipt(observer, requestId, if (payload.isEmpty()) unavailableCode() else ReceiptCode.STORAGE_REOPENED, payload)
        }) sendReceipt(observer, requestId, ReceiptCode.RESOURCE_BUSY, byteArrayOf())
    }

    fun queryNodePage(requestId: Long, offset: Int, expectedGeneration: ULong, observer: ILoftEvents) {
        if (requestId <= 0 || offset !in 0..150 || offset % 50 != 0) {
            sendNodePage(observer, requestId, ReceiptCode.INVALID_NODE_PAGE, byteArrayOf()); return
        }
        if (!submitCommand {
            val core = try { retainCoreOnWorker() }
            catch (failure: Exception) { sendNodePage(observer, requestId, openFailure(failure), byteArrayOf()); return@submitCommand }
            catch (_: LinkageError) { sendNodePage(observer, requestId, ReceiptCode.NATIVE_UNAVAILABLE, byteArrayOf()); return@submitCommand }
            try {
                val page = NodePageWire.encode(core.nodePage(offset.toUInt(), expectedGeneration))
                sendNodePage(observer, requestId, ReceiptCode.NODE_PAGE_READY, page)
            } catch (failure: Exception) {
                if (failure is CoreException.StateUnavailable) fault(active.get())
                sendNodePage(observer, requestId, if (failure is NodePageWireException) ReceiptCode.INVALID_COMMAND else ReceiptCode.nativeFailure(failure), byteArrayOf())
            } catch (_: LinkageError) { fault(active.get()); sendNodePage(observer, requestId, ReceiptCode.NATIVE_UNAVAILABLE, byteArrayOf()) }
            finally { resources.releaseUi() }
        }) sendNodePage(observer, requestId, ReceiptCode.RESOURCE_BUSY, byteArrayOf())
    }
    fun execute(requestId: Long, payload: ByteArray, observer: ILoftEvents) {
        if (requestId <= 0 || payload.size !in 5..ControlCodec.MAX_CONTROL_BYTES) {
            sendReceipt(observer, requestId, ReceiptCode.CONTROL_TOO_LARGE, byteArrayOf()); return
        }
        val owned = payload.copyOf()
        val command = try { ControlCodec.decode(owned) }
        catch (failure: ControlMessageException) {
            sendReceipt(observer, requestId, if (failure.problem == ControlProblem.TOO_LARGE) ReceiptCode.CONTROL_TOO_LARGE else ReceiptCode.INVALID_COMMAND, byteArrayOf())
            return
        } finally { owned.fill(0) }
        if (command == CoreCommand.Stop) { requestStop(observer, requestId); return }
        val connectEpoch = if (command is CoreCommand.Connect) synchronized(admissionLock) {
            if (stopQueued) null else stopEpoch
        } else null
        if (!submitCommand {
            val core = try { retainCoreOnWorker() }
            catch (failure: Exception) { sendReceipt(observer, requestId, openFailure(failure), byteArrayOf()); return@submitCommand }
            catch (_: LinkageError) { sendReceipt(observer, requestId, ReceiptCode.NATIVE_UNAVAILABLE, byteArrayOf()); return@submitCommand }
            try {
                val code = try {
                    when (command) {
                        is CoreCommand.ImportNode -> { core.importNode(command.raw); ReceiptCode.NODE_IMPORTED }
                        is CoreCommand.RemoveNode -> { core.removeNode(command.id); ReceiptCode.NODE_REMOVED }
                        is CoreCommand.StageServer -> {
                            val previous = core.snapshot().serverAddress
                            if (core.stageServer(command.raw) != previous) { hub.cancel(); mailNotifications.revoke() }
                            ReceiptCode.SERVER_STAGED
                        }
                        CoreCommand.ResetServer -> { core.resetServer(); hub.cancel(); mailNotifications.revoke(); ReceiptCode.SERVER_RESET }
                        is CoreCommand.SetRouting -> { core.setAppRouting(command.enabled, command.packageNames); ReceiptCode.ROUTING_STAGED }
                        is CoreCommand.SetNetworkPrivacyPolicy -> {
                            core.setNetworkPrivacyPolicy(NetworkPrivacyAdapter.native(command.policy), command.expectedGeneration)
                            ReceiptCode.NETWORK_PRIVACY_STAGED
                        }
                        is CoreCommand.Connect -> beginVpn(core, command, connectEpoch)
                        CoreCommand.Stop -> error("STOP_MUST_BYPASS_NORMAL_QUEUE")
                    }
                } catch (failure: AppScopeException) {
                    if (failure.problem == ScopeProblem.SELECTION_TOO_LARGE) ReceiptCode.ROUTING_SELECTION_TOO_LARGE else ReceiptCode.APP_UNAVAILABLE
                } catch (failure: Exception) { ReceiptCode.nativeFailure(failure) }
                catch (_: LinkageError) { fault(active.get()); ReceiptCode.NATIVE_UNAVAILABLE }
                val result = capture(core)
                broadcast(result)
                sendReceipt(observer, requestId, if (result.isEmpty()) unavailableCode() else code, result)
            } finally { resources.releaseUi() }
        }) sendReceipt(observer, requestId, ReceiptCode.RESOURCE_BUSY, byteArrayOf())
    }
    private fun beginVpn(core: AppCore, command: CoreCommand.Connect, epoch: Any?): ReceiptCode {
        if (VpnService.prepare(app) != null) return ReceiptCode.VPN_PERMISSION_DENIED
        synchronized(admissionLock) {
            if (epoch == null || stopQueued) throw CoreException.ConnectionBusy()
            if (epoch !== stopEpoch) throw CoreException.TicketExpired()
        }
        val ticket = core.beginVpn(command.nodeId, command.expectedGeneration)
        var vpnLease = false
        var attempt: Attempt? = null
        try {
            val enabled = ticket.routingEnabled()
            val packages = if (enabled) AndroidPackageScope(app).effectivePackages(ticket.packageNames()) else emptyList()
            val uidScope = AndroidPackageScope(app).freezeIdentity(enabled, packages)
            ticket.freezeEffectivePackages(packages)
            ticket.freezeNetworkScope(NetworkScopeIdentity(uidScope.vpnOwnerUid.toUInt(),
                uidScope.packageUids.map { EffectivePackageUid(it.packageName, it.uid.toUInt()) }))
            val networkPolicy = CapturedNetworkPolicy(ticket.networkPolicyEpoch(), ticket.networkScopeId(),
                NetworkPrivacyAdapter.draft(ticket.networkPrivacyPolicy()))
            resources.retainVpn(); vpnLease = true
            val candidate = Attempt(core, ticket, ticket.attemptId(), enabled, packages, uidScope, networkPolicy)
            attempt = candidate
            synchronized(admissionLock) {
                if (epoch !== stopEpoch) throw CoreException.TicketExpired()
                if (stopQueued || active.get() != null || !tun.begin(candidate.id)) throw CoreException.ConnectionBusy()
                closedNetworkResources.set(null)
                closedTraffic.set(null)
                active.set(candidate)
            }
            main.post {
                try { app.startForegroundService(Intent(app, LoftVpnService::class.java).setAction(LoftVpnService.ACTION_START)) }
                catch (_: Exception) { startFailed(candidate) }
            }
            return ReceiptCode.VPN_STARTING
        } catch (failure: Exception) {
            if (attempt != null && active.get() === attempt) startFailed(attempt)
            else {
                runCatching { core.markVpnFailed(ticket.attemptId(), VpnFailure.ENGINE_START_FAILED) }
                runCatching { core.confirmVpnStopped(VpnStoppedReceipt(ticket.attemptId(), true, true)) }
                ticket.close()
                if (vpnLease) resources.releaseVpn(true)
            }
            throw failure
        }
    }
    fun activate(service: LoftVpnService): Boolean {
        val attempt = active.get() ?: return false
        attempt.service = service
        service.retainForeground(attempt)
        if (attempt.cancelled.get()) {
            if (attempt.start.cancelUnscheduled()) settleNoStart(attempt)
            return true
        }
        if (!attempt.start.schedule()) return true
        if (!submit(starts) { startTransport(attempt, service) }) { settleNoStart(attempt); startFailed(attempt) }
        return true
    }
    private fun startTransport(attempt: Attempt, service: LoftVpnService) {
        try {
            if (attempt.cancelled.get() || active.get() !== attempt) return
            val manager = app.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            val network = manager.activeNetwork ?: throw IllegalStateException("PHYSICAL_NETWORK_UNAVAILABLE")
            val caps = manager.getNetworkCapabilities(network)
            check(caps?.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN) == true && caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET))
            val protector = AndroidSocketProtector(service, network)
            attempt.protector = protector
            val callback = object : ConnectivityManager.NetworkCallback() {
                override fun onLost(lost: Network) { if (lost == network) fault(attempt) }
                override fun onCapabilitiesChanged(changed: Network, capabilities: NetworkCapabilities) {
                    if (changed == network && (!capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN) ||
                        !capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET))) fault(attempt)
                }
            }
            manager.registerNetworkCallback(NetworkRequest.Builder().addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
                .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET).build(), callback, main)
            attempt.networkCallback = manager to callback
            if (attempt.cancelled.get() || attempt.faulted.get()) return
            if (!confirmCurrentScope(attempt)) return
            val established = service.establishTun(network, attempt.routingEnabled, attempt.packages)
            attempt.platform.set(established.receipt)
            if (!tun.adopt(attempt.id, established.descriptor)) return
            if (attempt.cancelled.get() || attempt.faulted.get()) return
            if (!confirmCurrentScope(attempt)) return
            val go = resources.explicitGo()
            attempt.go.set(go)
            val canonical = attempt.ticket.canonicalNetworkPolicy()
            GoNetworkPolicy.decodeCanonical(canonical, attempt.networkPolicy.policyEpoch, attempt.networkPolicy.scopeId, attempt.networkPolicy.policy)
            go.runtime.setNetworkPolicy(canonical)
            go.runtime.setStateListener(object : VPNStateListener { override fun onStateChanged(raw: String) { receiveGo(attempt, raw) } })
            if (attempt.cancelled.get() || attempt.faulted.get()) return
            val descriptor = tun.original(attempt.id) ?: return
            // Only the private service consumes raw material from the opaque ticket.
            val rawNode = attempt.ticket.takeRawNode()
            go.runtime.start(descriptor.fd, rawNode, VpnPolicy.IPV4_PREFIX, VpnPolicy.MTU)
            receiveGo(attempt, go.runtime.snapshot())
        } catch (_: Exception) { startFailed(attempt) }
        catch (_: LinkageError) { startFailed(attempt) }
        finally {
            tun.establishmentFailed(attempt.id)
            attempt.ticket.close()
            attempt.start.complete()
            queueEvent()
        }
    }
    private fun settleNoStart(attempt: Attempt) {
        tun.establishmentFailed(attempt.id)
        attempt.ticket.close()
        attempt.start.complete()
    }
    private fun confirmCurrentScope(attempt: Attempt): Boolean {
        val matches = runCatching { AndroidPackageScope(app).matchesIdentity(attempt.uidScope, attempt.routingEnabled, attempt.packages) }.getOrDefault(false)
        if (active.get() !== attempt || attempt.cancelled.get()) return false
        if (!matches) { requestStopScoped(attempt); return false }
        return true
    }
    private fun startFailed(attempt: Attempt) {
        attempt.faulted.set(true)
        attempt.protector?.cancelPending()
        if (attempt.start.cancelUnscheduled()) settleNoStart(attempt)
        queueEvent()
    }
    private fun receiveGo(attempt: Attempt, raw: String) {
        if (active.get() !== attempt) return
        val facts = try { GoVpnSnapshot.decode(raw) } catch (_: Exception) { fault(attempt); return }
        if (GoSnapshotAdmission.requiresFault(facts, attempt.networkPolicy)) { fault(attempt); return }
        if (attempt.cancelled.get() && !facts.provesReleased) return
        if (attempt.faulted.get() && facts.provesReady) return
        if (facts.state in setOf(GoVpnState.FAILED, GoVpnState.BLOCKED, GoVpnState.UNAVAILABLE)) attempt.faulted.set(true)
        if (!attempt.facts.observe(facts)) return
        queueEvent()
    }
    private fun queueEvent() {
        if (eventQueued.compareAndSet(false, true)) {
            if (!submit(events) { eventQueued.set(false); active.get()?.let(::reconcile) }) eventQueued.set(false)
        }
    }
    private fun reconcile(attempt: Attempt) {
        if (active.get() !== attempt || attempt.cancelled.get()) return
        if (attempt.faulted.get()) { reconcileFailure(attempt); return }
        val facts = attempt.facts.current() ?: return
        if (facts.provesReady && tun.facts().held && !attempt.readySubmitted.get()) {
            if (!confirmCurrentScope(attempt)) return
            val receipt = NetworkPrivacyReceipts.ready(attempt.id, attempt.packages, attempt.networkPolicy,
                facts, attempt.platform.get(), true) ?: run { fault(attempt); return }
            if (!attempt.readySubmitted.compareAndSet(false, true)) return
            try {
                attempt.core.markVpnReady(receipt)
                attempt.privacyConfirmed.set(true)
                if (attempt.cancelled.get() || attempt.faulted.get()) { fault(attempt); return }
            } catch (_: Exception) { fault(attempt); return }
        }
        publish(attempt.core)
    }
    private fun fault(attempt: Attempt?) {
        if (attempt == null || active.get() !== attempt || attempt.cancelled.get()) return
        if (!attempt.faulted.compareAndSet(false, true)) return
        attempt.protector?.cancelPending()
        queueEvent()
    }
    private fun reconcileFailure(attempt: Attempt) {
        if (active.get() !== attempt || attempt.cancelled.get()) return
        val first = attempt.failureDispatch.begin()
        if (first) {
            attempt.faulted.set(true)
            attempt.protector?.cancelPending()
            runCatching { attempt.go.get()?.runtime?.abort() }
            attempt.go.get()?.let { go -> runCatching { GoVpnSnapshot.decode(go.runtime.snapshot()) }.getOrNull()?.let(attempt.facts::observe) }
            if (active.get() !== attempt || attempt.cancelled.get()) return
            runCatching { attempt.core.markVpnFailed(attempt.id, VpnFailure.ENGINE_UNAVAILABLE) }
        }
        if (tun.facts().held) {
            val disabled = attempt.start.joined() && (attempt.go.get() == null || attempt.facts.current()?.provesForwardingDisabled == true)
            if (disabled && !confirmCurrentScope(attempt)) return
            val receipt = if (disabled) NetworkPrivacyReceipts.blocked(attempt.id, attempt.packages, attempt.networkPolicy,
                attempt.facts.current(), attempt.platform.get(), true, true, true) else null
            if (disabled && receipt == null) { requestStopScoped(attempt); return }
            val blocked = receipt != null && attempt.blockedSubmitted.compareAndSet(false, true)
            if (blocked) {
                if (runCatching { attempt.core.markVpnBlocked(receipt!!) }.isFailure) { requestStopScoped(attempt); return }
                attempt.privacyConfirmed.set(true)
                attempt.service?.showBlocked(attempt)
            }
            if (first || blocked) publish(attempt.core)
        } else if (attempt.start.joined()) {
            if (!attempt.cancelled.compareAndSet(false, true)) return
            cleanup(attempt, attempt.core, explicit = false)
        } else if (first) publish(attempt.core)
    }
    fun requestStop(observer: ILoftEvents?, requestId: Long, reason: VpnFailure? = null, foreground: LoftVpnService? = null) =
        requestStopOwned(observer, requestId, reason, foreground, null)

    private fun requestStopScoped(attempt: Attempt) = requestStopOwned(null, 0L, null, null, attempt)

    private fun requestStopOwned(observer: ILoftEvents?, requestId: Long, reason: VpnFailure?, foreground: LoftVpnService?, expected: Attempt?) {
        val admission = synchronized(admissionLock) {
            if (expected != null && active.get() !== expected) return
            synchronized(stopLock) {
                val fresh = !stopQueued
                if (fresh) { stopQueued = true; stopEpoch = Any() }
                val attempt = active.get()
                attempt?.cancelled?.set(true)
                val busy = observer != null && stopObservers.size >= 4 && requestId !in stopObservers
                if (observer != null && !busy) stopObservers[requestId] = observer
                StopAdmission(attempt, stopEpoch, fresh, busy)
            }
        }
        val attempt = admission.attempt
        // This Rust port is an atomic priority fence, not a state/query/Go join.
        if (admission.fresh) attempt?.core?.let { runCatching { it.beginVpnStop() } }
        attempt?.service?.showStopping(attempt)
        attempt?.protector?.cancelPending()
        val scheduled = stopDispatch.request(
            cancelOriginal = {
                synchronized(admissionLock) { if (active.get() === attempt) tun.stop() }
            },
            prepareCleanup = {
                if (!admission.fresh) null else {
                    val work: () -> Unit = {
                        attempt?.core?.let(::publish)
                        // Cancel pending Ready before joining construction. All
                        // bounded Go waits and resource monitors stay off entry.
                        runCatching { attempt?.go?.get()?.runtime?.abort() }
                        val core = resources.retainExistingUi()
                        try {
                            if (core != null && attempt == null) { runCatching { core.beginVpnStop() }; publish(core) }
                            if (core != null && reason != null && attempt != null) runCatching { core.markVpnFailed(attempt.id, reason) }
                            cleanup(attempt, core, explicit = true, foreground = foreground)
                        } finally { if (core != null) resources.releaseUi() }
                    }
                    work
                }
            },
            enqueueCleanup = { work -> submit(priority, work) },
        )
        if (admission.busy && observer != null) sendReceipt(observer, requestId, ReceiptCode.RESOURCE_BUSY, byteArrayOf())
        if (!scheduled && admission.fresh) {
            val callbacks = synchronized(admissionLock) {
                synchronized(stopLock) {
                    if (stopEpoch !== admission.epoch) emptyList()
                    else stopObservers.toList().also { stopObservers.clear(); stopQueued = false }
                }
            }
            callbacks.forEach { (id, callback) -> sendReceipt(callback, id, ReceiptCode.ENGINE_STOP_INCOMPLETE, byteArrayOf()) }
        }
    }
    private fun cleanup(attempt: Attempt?, core: AppCore?, explicit: Boolean, foreground: LoftVpnService? = null) {
        var complete = true
        if (attempt != null) {
            complete = attempt.start.await(5000)
            attempt.protector?.cancelPending()
            val go = attempt.go.get()
            if (go != null) {
                complete = runCatching { go.close() }.isSuccess && complete
                runCatching { GoVpnSnapshot.decode(go.runtime.snapshot()) }.getOrNull()?.let(attempt.facts::observe)
                complete = attempt.facts.current()?.provesReleased == true && complete
            }
            attempt.protector?.close()
            complete = attempt.protector?.released() != false && complete
            attempt.networkCallback?.let { (manager, callback) ->
                val unregistered = runCatching { manager.unregisterNetworkCallback(callback) }.isSuccess
                complete = unregistered && complete
                if (unregistered) attempt.networkCallback = null
            }
        }
        complete = tun.stop().tunClosed && complete
        var code = ReceiptCode.ENGINE_STOP_INCOMPLETE
        if (complete) {
            if (attempt != null) {
                val finalTraffic = if (attempt.privacyConfirmed.get() && attempt.facts.current()?.provesReleased == true) {
                    runCatching { attempt.go.get()?.runtime?.trafficUsage()?.let { decodeVpnTraffic(it, attempt.id, finalized = true) } }.getOrNull()
                } else null
                complete = runCatching { resources.releaseVpn(true) }.getOrDefault(false)
                if (complete) synchronized(admissionLock) {
                    if (active.get() === attempt) {
                        // Only a Rust-accepted applied policy plus actual joined
                        // Go/original closure may survive as bounded history.
                        closedNetworkResources.set(if (attempt.privacyConfirmed.get()) attempt.facts.current()?.let {
                            NetworkResourceSnapshot.from(attempt.id, attempt.networkPolicy, it)?.takeIf { record -> record.finalized }
                        } else null)
                        closedTraffic.set(finalTraffic)
                        active.set(null)
                    }
                }
            }
            if (complete) {
                val confirmed = core != null && runCatching { core.confirmVpnStopped(VpnStoppedReceipt(attempt?.id ?: core.snapshot().connectionAttemptId, true, true)) }.isSuccess
                code = if (confirmed && !publicationFailed.get()) ReceiptCode.CONTROL_STOPPED else ReceiptCode.TUN_CLOSED_CORE_UNAVAILABLE
                if (attempt != null) attempt.service?.releaseForeground(attempt) else foreground?.releaseForeground(foreground)
            }
        }
        if (!complete && core != null && attempt != null) runCatching { core.markVpnFailed(attempt.id, VpnFailure.ENGINE_STOP_FAILED) }
        val payload = if (core != null) capture(core) else byteArrayOf()
        broadcast(payload)
        if (!complete && attempt != null && payload.isNotEmpty()) runCatching { SnapshotWire.decode(payload) }.getOrNull()
            ?.let { attempt.service?.show(it, attempt) }
        if (payload.isEmpty() && code == ReceiptCode.CONTROL_STOPPED) code = ReceiptCode.TUN_CLOSED_CORE_UNAVAILABLE
        if (explicit) {
            val callbacks = synchronized(stopLock) { stopObservers.toList().also { stopObservers.clear(); stopQueued = false } }
            callbacks.forEach { (id, callback) -> sendReceipt(callback, id, code, payload) }
        }
    }
    fun serviceDestroyed(service: LoftVpnService) {
        val attempt = active.get()
        if (attempt?.service === service) requestStop(null, 0L, VpnFailure.REVOKED)
    }
    private fun metadata(core: CoreSnapshot): SnapshotMetadata {
        val attempt = active.get() ?: return SnapshotMetadata(engineVersion = engineVersion,
            networkResources = closedNetworkResources.get()?.takeIf {
                it.attemptId == core.connectionAttemptId && it.policyEpoch <= core.networkPrivacyPolicyEpoch &&
                    core.connectionState in setOf(ConnectionState.DISCONNECTED, ConnectionState.UNAVAILABLE) && core.appliedNetworkPrivacy == null
            })
        val original = tun.facts()
        val go = attempt.facts.current()
        val applied = core.appliedNetworkPrivacy
        val sameApplied = attempt.privacyConfirmed.get() && core.connectionAttemptId == attempt.id && applied != null &&
            applied.policyEpoch == attempt.networkPolicy.policyEpoch && applied.scopeId == attempt.networkPolicy.scopeId &&
            applied.policy == NetworkPrivacyAdapter.native(attempt.networkPolicy.policy)
        val ready = core.connectionState == ConnectionState.CONNECTED && sameApplied && !attempt.cancelled.get() &&
            !attempt.faulted.get() && go?.provesReady == true && go.privacy.samePolicy(attempt.networkPolicy)
        val released = original.tunClosed && attempt.start.joined() && (attempt.go.get() == null || go?.provesReleased == true) &&
            attempt.protector?.released() != false && attempt.networkCallback == null
        val disabled = attempt.start.joined() && (attempt.go.get() == null || go?.provesForwardingDisabled == true)
        val usage = if (sameApplied && go != null && !released) NetworkResourceSnapshot.from(attempt.id, attempt.networkPolicy, go)
            ?.copy(finalized = false) else null
        return SnapshotMetadata(engineVersion, ready, original.held, disabled, released, usage)
    }
    private fun capture(core: AppCore): ByteArray {
        if (publicationFailed.get()) return byteArrayOf()
        return try {
            publisher.capture(core::snapshot, ::metadata).also { payload ->
                availabilityGuard.observe(SnapshotWire.decode(payload))
            }
        }
        catch (_: PublicationExhaustedException) { publicationFailed.set(true); unavailableNotice(); fault(active.get()); byteArrayOf() }
        catch (_: Exception) { unavailableNotice(); fault(active.get()); byteArrayOf() }
        catch (_: LinkageError) { unavailableNotice(); fault(active.get()); byteArrayOf() }
    }
    private fun openFailure(failure: Exception): ReceiptCode = when (failure) {
        is StorageKeyException -> when (failure.failure) {
            StorageKeyFailure.UNAVAILABLE -> ReceiptCode.STORAGE_UNAVAILABLE
            StorageKeyFailure.RECOVERY_REQUIRED -> ReceiptCode.STORAGE_RECOVERY_REQUIRED
        }
        is CoreException -> ReceiptCode.nativeFailure(failure)
        else -> ReceiptCode.NATIVE_UNAVAILABLE
    }
    private fun unavailableCode() = if (publicationFailed.get()) ReceiptCode.PUBLICATION_EXHAUSTED else ReceiptCode.STATE_UNAVAILABLE
    private fun publish(core: AppCore) {
        val payload = capture(core)
        broadcast(payload)
        if (payload.isNotEmpty()) runCatching { SnapshotWire.decode(payload) }.getOrNull()?.let { frame -> active.get()?.let { it.service?.show(frame, it) } }
    }
    private fun unavailableNotice() { active.get()?.let { it.service?.showUnavailable(it) } }
    fun notificationReady(token: Any): Boolean = active.get()?.let { it === token && !it.cancelled.get() && !it.faulted.get() &&
        it.privacyConfirmed.get() && it.facts.current()?.let { facts -> facts.provesReady && facts.privacy.samePolicy(it.networkPolicy) } == true } == true
    fun notificationStopping(token: Any): Boolean = active.get()?.let { it === token && it.cancelled.get() } == true
    fun notificationBlocked(token: Any): Boolean = active.get()?.let { it === token && !it.cancelled.get() &&
        it.privacyConfirmed.get() && it.blockedSubmitted.get() &&
        (it.go.get() == null || it.facts.current()?.provesForwardingDisabled == true) } == true
    private fun observerTargets(): List<ILoftEvents> = synchronized(observerLock) {
        val count = observers.beginBroadcast()
        try { List(count) { observers.getBroadcastItem(it) } } finally { observers.finishBroadcast() }
    }
    private fun broadcast(payload: ByteArray) { if (payload.isNotEmpty()) observerTargets().forEach { sendSnapshot(it, payload) } }
    private fun sendSnapshot(observer: ILoftEvents, payload: ByteArray) {
        if (payload.size > ControlCodec.MAX_CONTROL_BYTES) return
        try { observer.onSnapshot(payload) } catch (_: RemoteException) { observers.unregister(observer) }
    }
    private fun sendReceipt(observer: ILoftEvents, id: Long, code: ReceiptCode, payload: ByteArray) {
        if (payload.size > ControlCodec.MAX_CONTROL_BYTES) return
        try { observer.onReceipt(id, code.name, payload) } catch (_: RemoteException) { observers.unregister(observer) }
    }
    private fun sendNodePage(observer: ILoftEvents, id: Long, code: ReceiptCode, payload: ByteArray) {
        if (payload.size > ControlCodec.MAX_CONTROL_BYTES) return
        try { observer.onNodePage(id, code.name, payload) } catch (_: RemoteException) { observers.unregister(observer) }
    }
    companion object {
        @Volatile private var instance: LoftRuntimeOwner? = null
        fun get(context: Context): LoftRuntimeOwner = instance ?: synchronized(this) { instance ?: LoftRuntimeOwner(context).also { instance = it } }
        private fun executor(capacity: Int) = ThreadPoolExecutor(1, 1, 30L, TimeUnit.SECONDS, ArrayBlockingQueue<Runnable>(capacity)).also { it.allowCoreThreadTimeOut(true) }
        private fun submit(executor: ThreadPoolExecutor, work: () -> Unit): Boolean = try { executor.execute { work() }; true } catch (_: RejectedExecutionException) { false }
    }
}
