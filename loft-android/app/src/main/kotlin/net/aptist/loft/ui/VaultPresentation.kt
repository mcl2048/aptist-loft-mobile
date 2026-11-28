package net.aptist.loft.ui

import android.os.SystemClock
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import net.aptist.loft.core.generated.VaultDraft
import net.aptist.loft.core.generated.VaultEntry
import net.aptist.loft.core.generated.VaultPage
import net.aptist.loft.service.CoreServiceClient
import net.aptist.loft.service.VaultCommand
import net.aptist.loft.service.VaultResult

internal class VaultDisplay(
    val archived: Boolean = false,
    val page: VaultPage? = null,
    val busy: Boolean = false,
    val status: String? = null,
    val revealedId: String? = null,
    val revealedLabel: String? = null,
    val revealed: ByteArray? = null,
) {
    override fun toString() = "VaultDisplay(<private>)"
}

internal class VaultPresentation(private val client: CoreServiceClient, private val scope: CoroutineScope) {
    private val mutable = MutableStateFlow(VaultDisplay())
    val state: StateFlow<VaultDisplay> = mutable
    private var activeEpoch: Long? = null
    private var nextId = 0L
    private var pending: Long? = null
    private var expiry: Job? = null
    private var authorized: VaultEntry? = null

    fun setActive(epoch: Long?) {
        if (activeEpoch == epoch) return
        activeEpoch = epoch
        if (epoch != null) {
            load()
            revealIfReady()
        } else {
            pending?.let(client::cancelVault)
            pending = null
            authorized = null
            hide()
            mutable.value = VaultDisplay()
        }
    }

    fun load(archived: Boolean = mutable.value.archived, next: Boolean = false, previous: Boolean = false) {
        val page = mutable.value.page
        val offset = when {
            next -> page?.nextOffset ?: return
            previous -> page?.offset?.takeIf { it >= 30u }?.minus(30u) ?: return
            else -> 0u
        }
        hide()
        submit(VaultCommand.ListPage(archived, offset, page?.generation.takeIf { offset != 0u }), archived)
    }

    fun save(draft: VaultDraft) = change(VaultCommand.Save(draft))
    fun import(uri: ByteArray) = change(VaultCommand.Import(uri))
    fun archive(entry: VaultEntry) = change(VaultCommand.Archive(entry.id, !entry.archived))
    fun synchronize(passphrase: ByteArray) = change(VaultCommand.Sync(passphrase))

    fun authorizedReveal(entry: VaultEntry) {
        authorized = entry
        revealIfReady()
    }

    private fun revealIfReady() {
        if (activeEpoch == null || pending != null) return
        val entry = authorized ?: return
        authorized = null
        hide()
        submit(VaultCommand.Reveal(entry.id), revealEntry = entry)
    }

    fun hide() {
        expiry?.cancel()
        expiry = null
        val old = mutable.value
        old.revealed?.fill(0)
        if (old.revealed != null) mutable.value = VaultDisplay(old.archived, old.page, old.busy, old.status)
    }

    fun notice(status: String) {
        val old = mutable.value
        mutable.value = VaultDisplay(old.archived, old.page, old.busy, status, old.revealedId, old.revealedLabel, old.revealed)
    }

    private fun change(command: VaultCommand) {
        hide()
        submit(command, refresh = true)
    }

    private fun submit(command: VaultCommand, archived: Boolean = mutable.value.archived,
        revealEntry: VaultEntry? = null, refresh: Boolean = false, settledStatus: String? = null) {
        val epoch = activeEpoch
        if (epoch == null || pending != null) { command.clear(); return }
        val id = runCatching { Math.addExact(nextId, 1) }.getOrNull() ?: run { command.clear(); return }
        nextId = id
        pending = id
        val old = mutable.value
        mutable.value = VaultDisplay(archived, old.page.takeIf { archived == old.archived }, busy = true)
        if (!client.executeVault(epoch, id, command) { code, result ->
                if (activeEpoch != epoch || pending != id) {
                    (result as? VaultResult.Reveal)?.value?.value?.fill(0)
                    return@executeVault
                }
                pending = null
                val current = mutable.value
                val page = (result as? VaultResult.Page)?.content ?: current.page
                val reveal = result as? VaultResult.Reveal
                val remaining = reveal?.let { it.validUntilElapsed - SystemClock.elapsedRealtime() }
                if (remaining != null && remaining <= 0L) reveal.value.value.fill(0)
                val showing = reveal?.takeIf { remaining != null && remaining > 0L }
                val status = when {
                    code != "ok" -> code
                    command is VaultCommand.Sync -> "synced"
                    refresh -> "saved"
                    reveal != null && showing == null -> "code_expired"
                    else -> settledStatus
                }
                mutable.value = VaultDisplay(archived, page, status = status, revealedId = revealEntry?.id,
                    revealedLabel = revealEntry?.label, revealed = showing?.value?.value)
                if (showing != null && remaining != null) expiry = scope.launch { delay(remaining); hide() }
                if (refresh && code == "ok") submit(VaultCommand.ListPage(archived, 0u, null), archived, settledStatus = status)
                else revealIfReady()
            }) {
            pending = null
            mutable.value = VaultDisplay(archived, mutable.value.page, status = "unavailable")
        }
    }
}
