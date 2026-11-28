package net.aptist.loft.service

import android.os.RemoteException
import net.aptist.loft.core.generated.AppCore
import net.aptist.loft.core.generated.ProtectionScope
import net.aptist.loft.core.generated.SecureException
import net.aptist.loft.ipc.ILoftHubEvents
import java.io.IOException
import java.util.concurrent.atomic.AtomicReference

/** The Binder ingress fences stale UI work immediately. Only the command worker touches Rust. */
internal class ProtectionControl {
    class Session(val controller: Any, val epoch: Long, val area: ProtectedArea) {
        var challenge: String? = null
    }

    private val visible = AtomicReference<Session?>()
    private var native: Session? = null

    fun select(controller: Any, epoch: Long, area: ProtectedArea?) {
        visible.updateAndGet { current ->
            if (current != null && current.controller === controller && current.epoch == epoch && current.area == area) current
            else area?.let { Session(controller, epoch, it) }
        }
    }

    fun detach(controller: Any) {
        visible.updateAndGet { current -> current?.takeUnless { it.controller === controller } }
    }

    fun capture(controller: Any, epoch: Long): Session? =
        visible.get()?.takeIf { it.controller === controller && it.epoch == epoch }

    fun isCurrent(session: Session): Boolean = visible.get() === session

    fun retire(core: AppCore?) {
        val expired = native?.takeUnless(::isCurrent) ?: return
        native = null
        val challenge = expired.challenge
        expired.challenge = null
        if (core != null && challenge != null) runCatching { core.protectionEnd(challenge) }
    }

    fun requireVault(core: AppCore, session: Session) {
        val challenge = session.challenge?.takeIf { isCurrent(session) && session.area == ProtectedArea.VAULT }
            ?: throw ProtectedPageClosed()
        core.protectionRequire(ProtectionScope.VAULT, challenge)
    }

    fun run(core: AppCore, session: Session, requestId: Long, command: ProtectedCommand, observer: ILoftHubEvents) {
        var result: ProtectedResult? = null
        val code = try {
            retire(core)
            if (!isCurrent(session)) throw ProtectedPageClosed()
            val time = (System.currentTimeMillis().coerceAtLeast(0) / 1_000).toULong()
            result = when (command) {
                ProtectedCommand.Open -> {
                    val status = core.protectionStatus()
                    val access = scope(session.area)?.let { core.protectionBegin(it, time) }
                    session.challenge = access?.challenge
                    native = session
                    ProtectedResult.Access(access?.unlocked ?: false, status)
                }
                is ProtectedCommand.Configure -> {
                    if (session.area != ProtectedArea.SETTINGS) throw ProtectedPageClosed()
                    ProtectedResult.Access(false, core.protectionConfigure(command.current, command.replacement, command.biometric, time))
                }
                is ProtectedCommand.Pin -> {
                    val challenge = session.challenge ?: throw ProtectedPageClosed()
                    core.protectionUnlockPin(challenge, command.value, time)
                    ProtectedResult.Access(true, core.protectionStatus())
                }
                ProtectedCommand.Biometric -> {
                    val challenge = session.challenge ?: throw ProtectedPageClosed()
                    core.protectionUnlockBiometric(challenge, time)
                    ProtectedResult.Access(true, core.protectionStatus())
                }
                is NotesCommand -> {
                    val challenge = session.challenge?.takeIf { session.area == ProtectedArea.NOTES } ?: throw ProtectedPageClosed()
                    notes(core, challenge, command, time)
                }
            }
            "ok"
        } catch (_: ProtectedPageClosed) {
            "locked"
        } catch (failure: SecureException) {
            if (command is ProtectedCommand.Pin || command is ProtectedCommand.Configure) {
                result = runCatching { ProtectedResult.Access(false, core.protectionStatus()) }.getOrNull()
            }
            problem(failure)
        } catch (_: Exception) {
            "unavailable"
        } catch (_: LinkageError) {
            "unavailable"
        } finally { command.clear() }
        if (isCurrent(session)) reply(requestId, observer, code, result)
        retire(core)
    }

    private fun notes(core: AppCore, lease: String, command: NotesCommand, time: ULong): NotesResult? =
        when (command) {
            is NotesCommand.ListPage -> NotesResult.Page(
                core.notesList(lease, command.archived, command.query, command.tag, command.offset, command.expectedGeneration),
            )
            is NotesCommand.Detail -> NotesResult.Detail(core.notesDetail(lease, command.id))
            is NotesCommand.Save -> NotesResult.Saved(core.notesSave(lease, command.draft, time))
            is NotesCommand.Archive -> { core.notesArchive(lease, command.id, command.archived, time); null }
            is NotesCommand.Delete -> { core.notesDelete(lease, command.id); null }
            is NotesCommand.Tags -> NotesResult.Tags(core.notesTags(lease, command.archived))
            NotesCommand.SyncStatus -> NotesResult.SyncStatus(core.notesSyncStatus(lease))
            is NotesCommand.SyncConfigure -> NotesResult.SyncConfigured(core.notesSyncConfigure(lease, command.recoveryCode))
            NotesCommand.SyncDisable -> { core.notesSyncDisable(lease); null }
        }

    private fun scope(area: ProtectedArea): ProtectionScope? = when (area) {
        ProtectedArea.SETTINGS -> null
        ProtectedArea.VAULT -> ProtectionScope.VAULT
        ProtectedArea.NOTES -> ProtectionScope.NOTES
    }

    companion object {
        fun problem(failure: SecureException): String = when (failure) {
            is SecureException.InvalidInput -> "invalid"
            is SecureException.NotFound -> "missing"
            is SecureException.StaleGeneration, is SecureException.Conflict -> "conflict"
            is SecureException.Locked -> "locked"
            is SecureException.IncorrectPin -> "incorrect_pin"
            is SecureException.RateLimited -> "rate_limited"
            is SecureException.TooLarge -> "capacity"
            is SecureException.Busy -> "busy"
            is SecureException.NotSignedIn, is SecureException.Unsupported -> "sign_in"
            is SecureException.AuthenticationFailed -> "authentication"
            is SecureException.NetworkUnavailable -> "network"
            is SecureException.Unavailable, is SecureException.StorageRecoveryRequired -> "unavailable"
        }

        fun reply(requestId: Long, observer: ILoftHubEvents, code: String, result: ProtectedResult? = null) {
            val payload = try { result?.let(ProtectedWire::result) } catch (_: IOException) { null }
            try {
                observer.onResult(requestId, if (result != null && payload == null) "unavailable" else code, payload ?: byteArrayOf())
            } catch (_: RemoteException) {
            } finally { payload?.fill(0) }
        }
    }
}

internal class ProtectedPageClosed : Exception()
