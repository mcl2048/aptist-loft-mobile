package net.aptist.loft.ui

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import net.aptist.loft.core.generated.ProtectionStatus
import net.aptist.loft.service.*

internal class ProtectionDisplay(
    val area: ProtectedArea? = null,
    val epoch: Long = 0,
    val status: ProtectionStatus? = null,
    val unlocked: Boolean = false,
    val busy: Boolean = false,
    val problem: String? = null,
)

internal class ProtectionPresentation(
    private val client: CoreServiceClient,
    private val vault: VaultPresentation,
    private val onNoteCommand: (NotesCommand) -> Unit,
) {
    private val mutable = MutableStateFlow(ProtectionDisplay())
    val state: StateFlow<ProtectionDisplay> = mutable
    private var epoch = 0L
    private var request = 0L
    private var pending: Long? = null

    fun select(area: ProtectedArea?, force: Boolean = false) {
        if (!force && mutable.value.area == area) return
        pending = null
        vault.setActive(null)
        epoch = Math.incrementExact(epoch)
        mutable.value = ProtectionDisplay(area, epoch)
        if (!client.selectProtectedArea(epoch, area) || area == null) return
        control(ProtectedCommand.Open)
    }

    fun configure(current: ByteArray?, replacement: ByteArray?, biometric: Boolean) =
        control(ProtectedCommand.Configure(current, replacement, biometric))

    fun pin(pin: ByteArray) = control(ProtectedCommand.Pin(pin))

    fun biometric(epoch: Long, verified: Boolean) {
        val current = mutable.value
        if (current.epoch != epoch || current.area == null || current.unlocked) return
        if (verified) control(ProtectedCommand.Biometric) else {
            mutable.value = ProtectionDisplay(current.area, epoch, current.status, problem = "device_auth")
        }
    }

    fun retry() = select(mutable.value.area, force = true)

    private fun control(command: ProtectedCommand) {
        val current = mutable.value
        val area = current.area
        if (area == null || pending != null) { command.clear(); return }
        val id = Math.incrementExact(request).also { request = it; pending = it }
        mutable.value = ProtectionDisplay(area, current.epoch, current.status, current.unlocked, busy = true)
        if (!client.executeProtected(current.epoch, id, command) { code, result ->
            if (pending != id || current.epoch != mutable.value.epoch) return@executeProtected
            pending = null
            val access = result as? ProtectedResult.Access
            val unlocked = code == "ok" && access?.unlocked == true
            mutable.value = ProtectionDisplay(area, current.epoch, access?.status ?: current.status,
                unlocked, problem = code.takeUnless { it == "ok" })
            if (area == ProtectedArea.VAULT) vault.setActive(current.epoch.takeIf { unlocked })
        } && pending == id) {
            pending = null
            mutable.value = ProtectionDisplay(area, current.epoch, current.status, problem = "unavailable")
        }
    }

    fun notes(command: NotesCommand, receive: (String, NotesResult?) -> Unit): Boolean {
        val current = mutable.value
        if (current.area != ProtectedArea.NOTES || !current.unlocked || pending != null) {
            command.clear()
            return false
        }
        val id = Math.incrementExact(request).also { request = it; pending = it }
        val admitted = client.executeProtected(current.epoch, id, command) { code, result ->
            if (pending != id || current.epoch != mutable.value.epoch) return@executeProtected
            pending = null
            if (code == "locked") { select(ProtectedArea.NOTES, force = true); return@executeProtected }
            val notes = result as? NotesResult
            if (code == "ok") onNoteCommand(command)
            receive(code, notes)
        }
        if (!admitted && pending == id) pending = null
        return admitted
    }
}
