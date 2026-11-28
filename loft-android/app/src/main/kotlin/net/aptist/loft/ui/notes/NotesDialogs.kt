package net.aptist.loft.ui.notes

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
import androidx.compose.ui.res.stringResource
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
    onDismiss: () -> Unit,
) {
    var status by remember { mutableStateOf<NotesSyncStatus?>(null) }
    var code by remember { mutableStateOf<String?>(null) }
    var joining by remember { mutableStateOf(false) }
    val input = remember { TextFieldState() }
    fun readStatus() {
        requests.submit(execute, NotesCommand.SyncStatus) { result ->
            status = (result as? NotesResult.SyncStatus)?.value
        }
    }
    LaunchedEffect(Unit) { readStatus() }
    fun configure(pairingCode: ByteArray?) {
        requests.submit(execute, NotesCommand.SyncConfigure(pairingCode)) { result ->
            val receipt = result as? NotesResult.SyncConfigured ?: return@submit
            code = receipt.code
            joining = false
            readStatus()
        }
    }

    val recoveryCode = code
    val currentStatus = status
    AlertDialog(
        properties = notesDialogSecurity,
        onDismissRequest = { if (!requests.busy) onDismiss() },
        title = { Text(stringResource(R.string.notes_sync)) },
        text = {
            Column(Modifier.fillMaxWidth().verticalScroll(rememberScrollState()).semantics { isSensitiveData = true },
                verticalArrangement = Arrangement.spacedBy(12.dp)) {
                if (requests.status == "invalid") Text(stringResource(R.string.notes_sync_invalid),
                    color = MaterialTheme.colorScheme.error)
                else NotesNotice(requests.status)
                if (recoveryCode != null) {
                    Text(stringResource(R.string.notes_sync_code_help))
                    Text(recoveryCode, style = MaterialTheme.typography.bodyLarge.copy(fontFamily = FontFamily.Monospace))
                } else if (currentStatus?.configured == true) {
                    Text(stringResource(R.string.notes_sync_configured))
                    TextButton(onClick = {
                        requests.submit(execute, NotesCommand.SyncDisable) { readStatus() }
                    }, enabled = !requests.busy) { Text(stringResource(R.string.notes_sync_disable)) }
                } else if (currentStatus?.available == true) {
                    Text(stringResource(R.string.notes_sync_setup_help))
                    if (joining) {
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
                } else if (currentStatus != null) Text(stringResource(R.string.notes_sync_unavailable))
                else if (requests.busy) CircularProgressIndicator()
                else TextButton(onClick = ::readStatus) {
                    Text(stringResource(R.string.notes_retry))
                }
            }
        },
        confirmButton = {
            TextButton(onClick = onDismiss, enabled = !requests.busy) { Text(stringResource(R.string.notes_close)) }
        },
    )
}

private const val recoveryAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
