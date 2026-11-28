package net.aptist.loft.service

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.Binder
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.ParcelFileDescriptor
import android.os.Process
import android.os.RemoteException
import net.aptist.loft.foundation.ControlCodec
import net.aptist.loft.foundation.CoreCommand
import net.aptist.loft.foundation.VisibilityEpoch
import net.aptist.loft.ipc.ILoftControl
import net.aptist.loft.ipc.ILoftEvents
import net.aptist.loft.ipc.ILoftHubEvents
import net.aptist.loft.ipc.ILoftTrafficEvents
import net.aptist.loft.core.generated.HubAction
import net.aptist.loft.core.generated.NodePage

/** Uses only application Context; retained across Activity and window changes. */
class CoreServiceClient(context: Context, private val onFrame: (SnapshotFrame) -> Unit,
    private val onReceipt: (Long, ReceiptCode) -> Unit, private val onLost: (ReceiptCode) -> Unit,
    private val onNodePage: (Long, NodePage?, ReceiptCode?) -> Unit = { _, _, _ -> },
    private val onNotesSyncReceipt: (Long, String) -> Unit = { _, _ -> }) {
    private val appContext = context.applicationContext
    private val handler = Handler(Looper.getMainLooper())
    private val epoch = VisibilityEpoch()
    private val consumer = SnapshotConsumer()
    private val pages = NodePageConsumer()
    private var remote: ILoftControl? = null
    private var bound = false
    private var visible = false
    private var closed = false
    private var bindingGeneration = 0L
    private var protectedEpoch = 0L
    private var subscribed: ILoftEvents? = null
    private var deathRecipient: IBinder.DeathRecipient? = null
    private var connection: ServiceConnection? = null
    private var presentationLocale = "en"
    private fun makeConnection(bindingTicket: Long) = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName?, service: IBinder?) {
            if (closed || service == null || !bound || bindingTicket != bindingGeneration) return
            remote = ILoftControl.Stub.asInterface(service)
            val ticket = bindingGeneration
            consumer.begin(ticket)
            pages.begin(ticket)
            val death = IBinder.DeathRecipient { handler.post { if (ticket == bindingGeneration) lost(ReceiptCode.STATE_UNAVAILABLE) } }
            deathRecipient = death
            try { service.linkToDeath(death, 0); remote?.setPresentationLocale(presentationLocale); if (visible) subscribe() }
            catch (_: RemoteException) { lost(ReceiptCode.STATE_UNAVAILABLE) }
        }
        override fun onServiceDisconnected(name: ComponentName?) { if (bindingTicket == bindingGeneration) lost(ReceiptCode.STATE_UNAVAILABLE) }
        override fun onBindingDied(name: ComponentName?) { if (bindingTicket == bindingGeneration) lost(ReceiptCode.STATE_UNAVAILABLE) }
        override fun onNullBinding(name: ComponentName?) { if (bindingTicket == bindingGeneration) lost(ReceiptCode.NATIVE_UNAVAILABLE) }
    }

    fun bind() {
        if (closed || bound) return
        val callback = makeConnection(++bindingGeneration)
        connection = callback
        bound = appContext.bindService(Intent(appContext, LoftCoreService::class.java), callback, Context.BIND_AUTO_CREATE)
        if (!bound) onLost(ReceiptCode.STATE_UNAVAILABLE)
    }
    fun setVisible(value: Boolean) {
        visible = value
        if (value) subscribe() else unsubscribe()
    }
    fun setPresentationLocale(locale: String): Boolean {
        if (locale.length != 2 || locale !in setOf("en", "zh", "ja", "de")) return false
        presentationLocale = locale
        return try { remote?.setPresentationLocale(locale); true }
        catch (_: RemoteException) { lost(ReceiptCode.STATE_UNAVAILABLE); false }
    }
    private fun subscribe() {
        val control = remote ?: return
        if (subscribed != null || closed) return
        val observationTicket = epoch.begin()
        val bindingTicket = bindingGeneration
        val callback = object : ILoftEvents.Stub() {
            override fun onNotesSync(generation: Long, status: String) {
                if (Binder.getCallingUid() != Process.myUid() || status.length > 40) return
                handler.post {
                    if (bindingTicket == bindingGeneration && epoch.accepts(observationTicket)) onNotesSyncReceipt(generation, status)
                }
            }
            override fun onNodePage(requestId: Long, code: String, payload: ByteArray) = Unit
            override fun onSnapshot(payload: ByteArray) {
                if (!validCaller(payload)) return
                handler.post { if (bindingTicket == bindingGeneration && epoch.accepts(observationTicket)) acceptFrame(payload) }
            }
            override fun onReceipt(requestId: Long, code: String, payload: ByteArray) {
                if (!validCaller(payload) || code.length > 80) return
                handler.post {
                    if (bindingTicket == bindingGeneration && epoch.accepts(observationTicket) && requestId == 0L) onLost(ReceiptCode.parse(code))
                }
            }
        }
        subscribed = callback
        try { control.subscribe(callback) } catch (_: RemoteException) { lost(ReceiptCode.STATE_UNAVAILABLE) }
    }
    private fun unsubscribe() {
        epoch.end()
        val callback = subscribed
        subscribed = null
        if (callback != null) try { remote?.unsubscribe(callback) } catch (_: RemoteException) { }
    }
    fun execute(requestId: Long, command: CoreCommand): Boolean {
        val payload = ControlCodec.encode(command)
        return try { commandReceipt(requestId) { control, callback -> control.execute(requestId, payload, callback) } }
        finally { payload.fill(0) }
    }

    fun reopenStorage(requestId: Long): Boolean = commandReceipt(requestId) { control, callback ->
        control.reopenStorage(requestId, callback)
    }

    private fun commandReceipt(requestId: Long, send: (ILoftControl, ILoftEvents) -> Unit): Boolean {
        val control = remote ?: return false
        val bindingTicket = bindingGeneration
        val callback = object : ILoftEvents.Stub() {
            override fun onNotesSync(generation: Long, status: String) = Unit
            override fun onSnapshot(payload: ByteArray) = Unit
            override fun onNodePage(requestId: Long, code: String, payload: ByteArray) = Unit
            override fun onReceipt(id: Long, code: String, snapshotPayload: ByteArray) {
                if (!validCaller(snapshotPayload) || code.length > 80 || id != requestId) return
                handler.post {
                    if (!closed && bindingTicket == bindingGeneration) {
                        val receipt = ReceiptCode.parse(code)
                        if (snapshotPayload.isNotEmpty() && !acceptFrame(snapshotPayload)) return@post
                        if (snapshotPayload.isEmpty() && receipt.successful) { lost(ReceiptCode.INVALID_COMMAND); return@post }
                        onReceipt(id, receipt)
                    }
                }
            }
        }
        return try { send(control, callback); true }
        catch (_: RemoteException) { lost(ReceiptCode.STATE_UNAVAILABLE); false }
    }
    fun queryNodePage(requestId: Long, offset: UInt, generation: ULong): Boolean {
        val control = remote ?: return false
        val ticket = bindingGeneration
        if (!pages.expect(ticket, requestId, offset, generation)) return false
        val callback = object : ILoftEvents.Stub() {
            override fun onNotesSync(generation: Long, status: String) = Unit
            override fun onSnapshot(payload: ByteArray) = Unit
            override fun onReceipt(id: Long, code: String, payload: ByteArray) = Unit
            override fun onNodePage(id: Long, code: String, payload: ByteArray) {
                if (!validCaller(payload) || code.length > 80 || id != requestId) return
                handler.post {
                    if (closed || ticket != bindingGeneration || !pages.current(ticket, id)) return@post
                    val receipt = ReceiptCode.parse(code)
                    if (receipt != ReceiptCode.NODE_PAGE_READY) {
                        pages.cancel(); this@CoreServiceClient.onNodePage(id, null, receipt); return@post
                    }
                    try { pages.consume(ticket, id, payload)?.let { this@CoreServiceClient.onNodePage(id, it, null) } }
                    catch (_: NodePageWireException) { pages.cancel(); this@CoreServiceClient.onNodePage(id, null, ReceiptCode.INVALID_COMMAND) }
                }
            }
        }
        return try { control.queryNodePage(requestId, offset.toInt(), generation.toLong(), callback); true }
        catch (_: RemoteException) { pages.cancel(); lost(ReceiptCode.STATE_UNAVAILABLE); false }
    }
    fun cancelNodePages() = pages.cancel()

    fun queryVpnTraffic(attemptId: ULong, receive: (VpnTrafficSample?) -> Unit): Boolean {
        val control = remote ?: return false
        val subscription = subscribed ?: return false
        val ticket = bindingGeneration
        if (attemptId == 0uL) return false
        val callback = object : ILoftTrafficEvents.Stub() {
            override fun onVpnTraffic(id: Long, uploadBytes: Long, downloadBytes: Long, finalized: Boolean) {
                if (uploadBytes < 0 || downloadBytes < 0) return
                deliver(id, VpnTrafficSample(attemptId, uploadBytes, downloadBytes, finalized))
            }

            override fun onVpnTrafficUnavailable(id: Long) { deliver(id, null) }

            private fun deliver(id: Long, sample: VpnTrafficSample?) {
                if (Binder.getCallingUid() != Process.myUid() || id.toULong() != attemptId) return
                handler.post {
                    if (!closed && ticket == bindingGeneration && subscribed === subscription) receive(sample)
                }
            }
        }
        return try { control.queryVpnTraffic(attemptId.toLong(), callback); true }
        catch (_: RemoteException) { lost(ReceiptCode.STATE_UNAVAILABLE); false }
    }

    internal fun executeHub(requestId: Long, action: HubAction?, input: String?, mailAccess: Boolean,
        destination: ParcelFileDescriptor?, receive: (String, HubResult?) -> Unit): Boolean {
        val control = remote ?: return false
        val ticket = bindingGeneration
        val callback = object : ILoftHubEvents.Stub() {
            override fun onResult(id: Long, code: String, payload: ByteArray) {
                if (Binder.getCallingUid() != Process.myUid() || id != requestId || code.length > 64 || payload.size > HubWire.MAX_BYTES) return
                handler.post {
                    try {
                        if (closed || ticket != bindingGeneration) return@post
                        val result = try { payload.takeIf { it.isNotEmpty() }?.let(HubWire::decode) }
                        catch (_: java.io.IOException) { receive("invalid_response", null); return@post }
                        receive(code, result)
                    } finally { payload.fill(0) }
                }
            }
        }
        return try { control.executeHub(requestId, action?.name.orEmpty(), input, mailAccess, destination, callback); true }
        catch (_: RemoteException) { lost(ReceiptCode.STATE_UNAVAILABLE); false }
    }

    internal fun cancelHub(requestId: Long) {
        try { remote?.cancelHubWork(requestId) } catch (_: RemoteException) { }
    }

    internal fun executeVault(epoch: Long, requestId: Long, command: VaultCommand, receive: (String, VaultResult?) -> Unit): Boolean {
        val control = remote ?: run { command.clear(); return false }
        val ticket = bindingGeneration
        val payload = try { VaultWire.command(command) } catch (_: java.io.IOException) { return false }
        finally { command.clear() }
        val callback = object : ILoftHubEvents.Stub() {
            override fun onResult(id: Long, code: String, result: ByteArray) {
                if (Binder.getCallingUid() != Process.myUid() || id != requestId || code.length > 64 || result.size > VaultWire.MAX_FRAME) {
                    result.fill(0)
                    return
                }
                handler.post {
                    try {
                        if (closed || ticket != bindingGeneration || epoch != protectedEpoch) return@post
                        val read = try { result.takeIf { it.isNotEmpty() }?.let(VaultWire::readResult) }
                        catch (_: java.io.IOException) { receive("unavailable", null); return@post }
                        receive(code, read)
                    } finally { result.fill(0) }
                }
            }
        }
        return try { control.executeVault(epoch, requestId, payload, callback); true }
        catch (_: RemoteException) { lost(ReceiptCode.STATE_UNAVAILABLE); false }
        finally { payload.fill(0) }
    }

    internal fun selectProtectedArea(epoch: Long, area: ProtectedArea?): Boolean {
        protectedEpoch = epoch
        val control = remote ?: return false
        return try { control.setProtectedArea(epoch, area?.ordinal ?: -1); true }
        catch (_: RemoteException) { lost(ReceiptCode.STATE_UNAVAILABLE); false }
    }

    internal fun executeProtected(epoch: Long, requestId: Long, command: ProtectedCommand,
        receive: (String, ProtectedResult?) -> Unit): Boolean {
        val control = remote
        if (control == null || requestId <= 0) { command.clear(); return false }
        val generation = bindingGeneration
        val payload = try { ProtectedWire.command(command) } catch (_: java.io.IOException) { return false }
        finally { command.clear() }
        val callback = object : ILoftHubEvents.Stub() {
            override fun onResult(id: Long, code: String, result: ByteArray) {
                if (!validCaller(result) || id != requestId || code.length > 40) { result.fill(0); return }
                handler.post {
                    try {
                        if (generation != bindingGeneration || epoch != protectedEpoch) return@post
                        val decoded = try { result.takeIf { it.isNotEmpty() }?.let(ProtectedWire::readResult) }
                        catch (_: java.io.IOException) { receive("unavailable", null); return@post }
                        receive(code, decoded)
                    } finally { result.fill(0) }
                }
            }
        }
        return try { control.executeProtected(epoch, requestId, payload, callback); true }
        catch (_: RemoteException) { lost(ReceiptCode.STATE_UNAVAILABLE); false }
        finally { payload.fill(0) }
    }

    internal fun cancelVault(requestId: Long) {
        try { remote?.cancelVaultWork(requestId) } catch (_: RemoteException) { }
    }
    private fun validCaller(payload: ByteArray): Boolean = Binder.getCallingUid() == Process.myUid() && payload.size <= ControlCodec.MAX_CONTROL_BYTES
    private fun acceptFrame(payload: ByteArray): Boolean {
        return try {
            consumer.consume(bindingGeneration, payload)?.let(onFrame)
            true
        }
        catch (_: SnapshotWireException) { lost(ReceiptCode.INVALID_COMMAND); false }
    }
    private fun lost(code: ReceiptCode) { detach(); onLost(code) }
    fun reopen() { if (!closed) { detach(); bind() } }
    private fun detach() {
        unsubscribe()
        consumer.end()
        pages.end()
        val service = remote?.asBinder()
        deathRecipient?.let { recipient -> try { service?.unlinkToDeath(recipient, 0) } catch (_: NoSuchElementException) { } }
        remote = null; deathRecipient = null; bindingGeneration++
        val callback = connection
        connection = null
        if (bound) { bound = false; if (callback != null) try { appContext.unbindService(callback) } catch (_: IllegalArgumentException) { } }
    }
    fun close() { closed = true; visible = false; detach(); handler.removeCallbacksAndMessages(null) }
}
