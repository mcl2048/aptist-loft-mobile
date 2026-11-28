package net.aptist.loft.ui.notes

import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.os.Build
import android.os.PersistableBundle
import androidx.compose.animation.core.Animatable
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.tween
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.input.TextFieldState
import androidx.compose.foundation.text.input.clearText
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.AssistChip
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.isSensitiveData
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import androidx.compose.ui.window.SecureFlagPolicy
import net.aptist.loft.R
import net.aptist.loft.core.generated.NoteTag
import net.aptist.loft.core.generated.NotesSyncStatus
import net.aptist.loft.service.NotesCommand
import net.aptist.loft.service.NotesResult

private val notesDialogSecurity = DialogProperties(securePolicy = SecureFlagPolicy.SecureOn)

@Composable
internal fun NotesTagWall(tags: List<NoteTag>, onDismiss: () -> Unit, onChoose: (String) -> Unit) {
    val phase = remember { Animatable(0f) }
    LaunchedEffect(tags) {
        phase.animateTo(1f, tween(durationMillis = 1_450, easing = LinearEasing))
    }
    Dialog(onDismissRequest = onDismiss, properties = notesDialogSecurity) {
        Surface(shape = MaterialTheme.shapes.extraLarge, color = MaterialTheme.colorScheme.surface,
            modifier = Modifier.semantics { isSensitiveData = true }) {
            Column(Modifier.fillMaxWidth().padding(16.dp)) {
                Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                    Text(stringResource(R.string.notes_tag_wall), style = MaterialTheme.typography.headlineSmall,
                        modifier = Modifier.weight(1f))
                    NotesIconButton(R.drawable.ic_notes_close, R.string.notes_close, onDismiss)
                }
                if (tags.isEmpty()) {
                    Text(stringResource(R.string.notes_no_tags), Modifier.padding(vertical = 22.dp),
                        style = MaterialTheme.typography.bodyMedium)
                } else {
                    BoxWithConstraints(Modifier.fillMaxWidth()) {
                        val layout = noteTagWall(maxWidth.value, tags.size, phase.value)
                        Box(Modifier.heightIn(max = 422.dp).verticalScroll(rememberScrollState())) {
                            Box(Modifier.fillMaxWidth().height(layout.height.dp)) {
                                tags.forEachIndexed { index, tag ->
                                    val position = layout.items[index]
                                    val display = stringResource(R.string.notes_tag_count, tag.name, tag.count.toLong())
                                    AssistChip(
                                        onClick = { onChoose(tag.name) },
                                        label = { Text(display, maxLines = 1, overflow = TextOverflow.Ellipsis) },
                                        modifier = Modifier.offset(position.x.dp, position.y.dp)
                                            .width(layout.chipWidth.dp).height(NOTE_TAG_CHIP_HEIGHT.dp)
                                            .alpha(0.35f + phase.value * 0.65f),
                                        enabled = phase.value >= 0.72f,
                                    )
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

@Composable
internal fun NotesSyncDialog(
    requests: NotesRequests,
    execute: (NotesCommand, (String, NotesResult?) -> Unit) -> Boolean,
    refreshGeneration: Long,
    onOpenAccount: () -> Unit,
    onDismiss: () -> Unit,
) {
    var status by remember { mutableStateOf<NotesSyncStatus?>(null) }
    var recoveryCode by remember { mutableStateOf<String?>(null) }
    var joining by remember { mutableStateOf(false) }
    var confirmReset by remember { mutableStateOf<NotesResetChoice?>(null) }
    var showResetChoices by remember { mutableStateOf(false) }
    var retryProblem by remember { mutableStateOf<String?>(null) }
    var requestedRefresh by remember { mutableStateOf<Long?>(null) }
    val input = remember { TextFieldState() }

    fun readStatus() {
        requests.submit(execute, NotesCommand.SyncStatus) { result ->
            status = (result as? NotesResult.SyncStatus)?.value
            if (status?.canShowPairingKey() != true) recoveryCode = null
        }
    }

    // Explicit entry and scoped receipts drive refreshes. An already running Notes command
    // may share this request lane, so wait for it before consuming the refresh epoch.
    LaunchedEffect(refreshGeneration, requests.busy) {
        if (!requests.busy && requestedRefresh != refreshGeneration) {
            requestedRefresh = refreshGeneration
            readStatus()
        }
    }

    fun configure(pairingCode: ByteArray?) {
        requests.submit(execute, NotesCommand.SyncConfigure(pairingCode)) { result ->
            val receipt = result as? NotesResult.SyncConfigured ?: return@submit
            recoveryCode = receipt.code
            joining = false
            readStatus()
        }
    }

    fun account() {
        onDismiss()
        onOpenAccount()
    }

    val currentStatus = status
    val display = currentStatus?.display()
    val key = recoveryCode.takeIf { currentStatus?.canShowPairingKey() == true }
    val choice = confirmReset
    if (choice != null) {
        NotesResetConfirmation(choice, requests.busy, requests.status, onCancel = { confirmReset = null }) {
            requests.submit(execute, NotesCommand.SyncReset(wipe = choice == NotesResetChoice.WIPE)) {
                recoveryCode = null
                input.clearText()
                joining = false
                showResetChoices = false
                confirmReset = null
                // The private command only confirms that reset was queued. Status will
                // expose the key after Hub acknowledges rotation and Rust commits it.
                readStatus()
            }
        }
        return
    }

    AlertDialog(
        properties = notesDialogSecurity,
        onDismissRequest = { if (!requests.busy) onDismiss() },
        title = { Text(stringResource(R.string.notes_sync)) },
        text = {
            Column(
                Modifier.fillMaxWidth().verticalScroll(rememberScrollState()).semantics { isSensitiveData = true },
                verticalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                NotesSyncNotice(requests.status ?: retryProblem)
                if (key != null) {
                    Text(stringResource(R.string.notes_sync_code_help))
                    Text(key, style = MaterialTheme.typography.bodyLarge.copy(fontFamily = FontFamily.Monospace))
                    CopyPairingKey(key)
                } else when (display) {
                    NotesSyncDisplay.SIGN_IN -> {
                        Text(stringResource(R.string.notes_sync_sign_in))
                        TextButton(onClick = ::account, enabled = !requests.busy) {
                            Text(stringResource(R.string.notes_sync_account))
                        }
                    }
                    NotesSyncDisplay.HUB_UNAVAILABLE -> {
                        Text(stringResource(R.string.notes_sync_unavailable))
                        TextButton(onClick = ::account, enabled = !requests.busy) {
                            Text(stringResource(R.string.notes_sync_account))
                        }
                    }
                    NotesSyncDisplay.RESET_PENDING -> {
                        Text(stringResource(R.string.notes_sync_reset_pending),
                            Modifier.semantics { liveRegion = LiveRegionMode.Polite })
                        TextButton(onClick = {
                            retryProblem = null
                            requests.submit(execute, NotesCommand.SyncRetry, onError = { code ->
                                retryProblem = code
                                if (code in setOf("conflict", "sign_in", "unsupported")) readStatus()
                            }) { readStatus() }
                        }, enabled = !requests.busy) {
                            Text(stringResource(R.string.notes_sync_retry_reset))
                        }
                    }
                    NotesSyncDisplay.RESET_COMPLETE -> {
                        Text(stringResource(R.string.notes_sync_reset_complete))
                        TextButton(onClick = {
                            requests.submit(execute, NotesCommand.SyncRecoveryCode) { result ->
                                recoveryCode = (result as? NotesResult.SyncConfigured)?.code
                                if (recoveryCode == null) readStatus()
                            }
                        }, enabled = !requests.busy) { Text(stringResource(R.string.notes_sync_show_code)) }
                    }
                    NotesSyncDisplay.CONFIGURED -> {
                        Text(stringResource(R.string.notes_sync_configured))
                    }
                    NotesSyncDisplay.RECOVER_KEY, NotesSyncDisplay.SETUP -> {
                        val recovering = display == NotesSyncDisplay.RECOVER_KEY
                        Text(stringResource(if (recovering) R.string.notes_sync_recover_help else R.string.notes_sync_setup_help))
                        if (joining || recovering) {
                            NoteField(input, R.string.notes_sync_code, MaterialTheme.typography.bodyMedium, 43,
                                enabled = !requests.busy, hideValue = true)
                            val valid = input.text.length == 43 && input.text.all { it in recoveryAlphabet }
                            TextButton(onClick = {
                                val bytes = input.text.toString().toByteArray(Charsets.US_ASCII)
                                input.clearText()
                                configure(bytes)
                            }, enabled = valid && !requests.busy) { Text(stringResource(R.string.notes_sync_join)) }
                        } else {
                            TextButton(onClick = { configure(null) }, enabled = !requests.busy) {
                                Text(stringResource(R.string.notes_sync_generate))
                            }
                            TextButton(onClick = { joining = true }, enabled = !requests.busy) {
                                Text(stringResource(R.string.notes_sync_use_code))
                            }
                        }
                    }
                    null -> if (requests.busy) CircularProgressIndicator() else {
                        TextButton(onClick = ::readStatus) { Text(stringResource(R.string.notes_retry)) }
                    }
                }
                if (key == null && currentStatus?.configured == true &&
                    (display == NotesSyncDisplay.CONFIGURED || display == NotesSyncDisplay.RESET_COMPLETE)
                ) {
                    TextButton(onClick = {
                        requests.submit(execute, NotesCommand.SyncDisable) { readStatus() }
                    }, enabled = !requests.busy) { Text(stringResource(R.string.notes_sync_disable)) }
                }
                if (key == null && currentStatus?.resetAvailable == true && !currentStatus.resetPending) {
                    if (showResetChoices) {
                        Text(stringResource(R.string.notes_sync_reset_help))
                        if (currentStatus.configured && !currentStatus.needsRecovery) {
                            TextButton(onClick = { confirmReset = NotesResetChoice.KEEP }, enabled = !requests.busy) {
                                Text(stringResource(R.string.notes_sync_reset_keep))
                            }
                        }
                        TextButton(onClick = { confirmReset = NotesResetChoice.WIPE }, enabled = !requests.busy) {
                            Text(stringResource(R.string.notes_sync_reset_wipe), color = MaterialTheme.colorScheme.error)
                        }
                    } else {
                        TextButton(onClick = { retryProblem = null; showResetChoices = true }, enabled = !requests.busy) {
                            Text(stringResource(R.string.notes_sync_reset))
                        }
                    }
                }
            }
        },
        confirmButton = {
            TextButton(onClick = onDismiss, enabled = !requests.busy) { Text(stringResource(R.string.notes_close)) }
        },
    )
}

private enum class NotesResetChoice { KEEP, WIPE }

@Composable
private fun NotesResetConfirmation(
    choice: NotesResetChoice,
    busy: Boolean,
    problem: String?,
    onCancel: () -> Unit,
    onConfirm: () -> Unit,
) {
    val wipe = choice == NotesResetChoice.WIPE
    AlertDialog(
        properties = notesDialogSecurity,
        onDismissRequest = { if (!busy) onCancel() },
        title = { Text(stringResource(if (wipe) R.string.notes_sync_reset_wipe_title else R.string.notes_sync_reset_keep_title)) },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text(stringResource(if (wipe) R.string.notes_sync_reset_wipe_body else R.string.notes_sync_reset_keep_body))
                NotesSyncNotice(problem)
            }
        },
        confirmButton = {
            TextButton(onClick = onConfirm, enabled = !busy) {
                if (wipe) Text(stringResource(R.string.notes_sync_reset_wipe), color = MaterialTheme.colorScheme.error)
                else Text(stringResource(R.string.notes_sync_reset))
            }
        },
        dismissButton = {
            TextButton(onClick = onCancel, enabled = !busy) { Text(stringResource(R.string.cancel)) }
        },
    )
}

@Composable
private fun NotesSyncNotice(problem: String?) {
    val message = when (problem) {
        "invalid" -> R.string.notes_sync_invalid
        "authentication" -> R.string.notes_sync_key_mismatch
        "network" -> R.string.notes_sync_network
        "sign_in" -> R.string.notes_sync_sign_in
        "unsupported" -> R.string.notes_sync_unavailable
        "conflict" -> R.string.notes_sync_retry_conflict
        else -> {
            NotesNotice(problem)
            return
        }
    }
    Text(stringResource(message), Modifier.semantics { liveRegion = LiveRegionMode.Polite },
        color = MaterialTheme.colorScheme.error)
}

@Composable
private fun CopyPairingKey(key: String) {
    val context = LocalContext.current
    val label = stringResource(R.string.notes_sync_code)
    var copyStatus by remember(key) { mutableStateOf<Int?>(null) }
    TextButton(onClick = {
        val clipboard = context.getSystemService(ClipboardManager::class.java)
        val copied = runCatching {
            checkNotNull(clipboard).setPrimaryClip(notesPairingClip(label, key))
        }.isSuccess
        copyStatus = when {
            !copied -> R.string.notes_sync_copy_failed
            Build.VERSION.SDK_INT < 33 -> R.string.notes_sync_copied
            else -> null // Android shows the redacted clipboard notice on API 33+.
        }
    }) {
        Text(stringResource(R.string.notes_sync_copy))
    }
    copyStatus?.let { message ->
        Text(stringResource(message), Modifier.semantics { liveRegion = LiveRegionMode.Polite },
            style = MaterialTheme.typography.bodySmall)
    }
}

internal fun notesPairingClip(label: String, key: String): ClipData =
    ClipData.newPlainText(label, key).apply {
        description.extras = PersistableBundle().apply {
            putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true)
        }
    }

private const val recoveryAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
