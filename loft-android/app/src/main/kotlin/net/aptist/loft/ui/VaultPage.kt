package net.aptist.loft.ui

import android.Manifest
import android.content.pm.PackageManager
import androidx.activity.compose.LocalActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.material3.Button
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.LifecycleStartEffect
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import net.aptist.loft.MainActivity
import net.aptist.loft.R
import net.aptist.loft.core.generated.VaultAlgorithm
import net.aptist.loft.core.generated.VaultDraft
import net.aptist.loft.core.generated.VaultEntry
import net.aptist.loft.core.generated.VaultKind

private enum class VaultEditor { TOTP, PASSWORD, URI, SYNC }

@Composable
internal fun VaultPageContent(app: LoftUiState, model: VaultPresentation, onOpenAccount: () -> Unit) {
    val state by model.state.collectAsStateWithLifecycle()
    val activity = LocalActivity.current as? MainActivity
    val context = LocalContext.current
    var editor by remember { mutableStateOf<VaultEditor?>(null) }
    var selected by remember { mutableStateOf<VaultEntry?>(null) }
    var scanning by remember { mutableStateOf(false) }
    var scanned by remember { mutableStateOf("") }
    val requestCamera = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
        if (granted && editor == VaultEditor.URI) scanning = true else if (!granted) model.notice("camera_permission")
    }
    LifecycleStartEffect(Unit) {
        onStopOrDispose { scanning = false; scanned = ""; editor = null; selected = null; model.hide() }
    }
    val status = if (state.busy) R.string.vault_busy else vaultStatus(state.status)
    if (status != null) Text(stringResource(status), modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite })
    val enabled = app.canChangeConfiguration && !state.busy
    if (editor != null) {
        val mode = checkNotNull(editor)
        fun done() { scanning = false; scanned = ""; selected = null; editor = null }
        if (scanning) {
            Text(stringResource(R.string.vault_camera_hint))
            VaultScanner(Modifier.fillMaxWidth().height(280.dp), onRead = { value -> scanned = value; scanning = false },
                onUnavailable = { scanning = false; model.notice("camera_unavailable") })
            TextButton(onClick = { scanning = false }) { Text(stringResource(R.string.cancel)) }
        } else {
            VaultEditorPanel(mode, selected, scanned, enabled, onCamera = {
                if (ContextCompat.checkSelfPermission(context, Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED) scanning = true
                else requestCamera.launch(Manifest.permission.CAMERA)
            }, onSave = { draft -> model.save(draft); done() }, onImport = { uri -> model.import(uri); done() },
                onSync = { passphrase -> model.synchronize(passphrase); done() }, onDismiss = ::done)
        }
        return
    }

    val revealed = state.revealed
    if (revealed != null) {
        state.revealedLabel?.let { Text(it, style = MaterialTheme.typography.titleMedium) }
        Text(revealed.toString(Charsets.UTF_8), fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.titleLarge)
        TextButton(onClick = model::hide) { Text(stringResource(R.string.vault_hide)) }
        HorizontalDivider()
    }
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        FilterChip(selected = !state.archived, enabled = enabled, onClick = { model.load(false) }, label = { Text(stringResource(R.string.vault_active)) })
        FilterChip(selected = state.archived, enabled = enabled, onClick = { model.load(true) }, label = { Text(stringResource(R.string.vault_archived)) })
    }
    if (!state.archived) {
        Button(enabled = enabled, onClick = { model.hide(); editor = VaultEditor.URI }) { Text(stringResource(R.string.vault_add_qr)) }
        TextButton(enabled = enabled, onClick = { model.hide(); editor = VaultEditor.TOTP }) { Text(stringResource(R.string.vault_add_totp)) }
        TextButton(enabled = enabled, onClick = { model.hide(); editor = VaultEditor.PASSWORD }) { Text(stringResource(R.string.vault_add_password)) }
    }
    val page = state.page
    if (page?.entries?.isEmpty() == true) Text(stringResource(R.string.vault_empty))
    if (page == null && enabled) TextButton(onClick = { model.load() }) { Text(stringResource(R.string.vault_refresh)) }
    page?.entries?.forEach { entry ->
        HorizontalDivider()
        Text(entry.label, style = MaterialTheme.typography.titleMedium)
        if (entry.account.isNotBlank()) Text(entry.account, style = MaterialTheme.typography.bodyMedium)
        if (entry.issuer.isNotBlank()) Text(entry.issuer, style = MaterialTheme.typography.bodySmall)
        if ((state.revealedId != entry.id || state.revealed == null) && !entry.archived) {
            TextButton(enabled = enabled, onClick = { activity?.requestVaultReveal(entry) }) {
                Text(stringResource(if (entry.kind == VaultKind.TOTP) R.string.vault_show_code else R.string.vault_show_password))
            }
        }
        Row {
            TextButton(enabled = enabled, onClick = {
                model.hide(); selected = entry
                editor = if (entry.kind == VaultKind.TOTP) VaultEditor.TOTP else VaultEditor.PASSWORD
            }) { Text(stringResource(R.string.vault_edit)) }
            TextButton(enabled = enabled, onClick = { model.archive(entry) }) {
                Text(stringResource(if (entry.archived) R.string.vault_restore else R.string.vault_archive))
            }
        }
    }
    if (page?.nextOffset != null) TextButton(enabled = enabled, onClick = { model.load(next = true) }) { Text(stringResource(R.string.vault_next)) }
    if (page != null && page.offset != 0u) TextButton(enabled = enabled, onClick = { model.load(previous = true) }) { Text(stringResource(R.string.vault_previous)) }
    HorizontalDivider()
    Text(stringResource(R.string.vault_offline), style = MaterialTheme.typography.bodySmall)
    val hub = app.hub
    if (hub?.session?.durable == true) {
        TextButton(enabled = enabled, onClick = { model.hide(); editor = VaultEditor.SYNC }) {
            Text(stringResource(R.string.vault_sync))
        }
    } else if (hub != null) {
        val message = if (hub.session == null) R.string.vault_sync_signed_out else R.string.vault_sync_legacy_session
        Text(stringResource(message), style = MaterialTheme.typography.bodySmall)
        TextButton(onClick = onOpenAccount) { Text(stringResource(R.string.account_title)) }
    }
}

@Composable
private fun VaultEditorPanel(mode: VaultEditor, entry: VaultEntry?, scanned: String, enabled: Boolean, onCamera: () -> Unit,
    onSave: (VaultDraft) -> Unit, onImport: (ByteArray) -> Unit, onSync: (ByteArray) -> Unit, onDismiss: () -> Unit) {
    var label by remember { mutableStateOf(entry?.label.orEmpty()) }
    var account by remember { mutableStateOf(entry?.account.orEmpty()) }
    var issuer by remember { mutableStateOf(entry?.issuer.orEmpty()) }
    var secret by remember(scanned) { mutableStateOf(scanned) }
    var repeatSecret by remember { mutableStateOf("") }
    var algorithm by remember { mutableStateOf(entry?.algorithm ?: VaultAlgorithm.SHA1) }
    var digits by remember { mutableStateOf((entry?.digits ?: 6u).toString()) }
    var period by remember { mutableStateOf((entry?.period ?: 30u).toString()) }
    val isForm = mode == VaultEditor.TOTP || mode == VaultEditor.PASSWORD
    Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
        if (mode == VaultEditor.URI) TextButton(enabled = enabled, onClick = onCamera) { Text(stringResource(R.string.vault_scan)) }
        if (isForm) {
            VaultField(label, { label = it }, R.string.vault_label, 160)
            VaultField(account, { account = it }, R.string.vault_account, 160)
            VaultField(issuer, { issuer = it }, R.string.vault_issuer, 160)
        }
        if (mode == VaultEditor.SYNC) Text(stringResource(R.string.vault_sync_help))
        VaultField(secret, { secret = it }, when (mode) {
            VaultEditor.TOTP -> R.string.vault_key
            VaultEditor.PASSWORD -> R.string.vault_password
            VaultEditor.URI -> R.string.vault_uri
            VaultEditor.SYNC -> R.string.vault_passphrase
        }, 4096, masked = true)
        if (mode == VaultEditor.SYNC) VaultField(repeatSecret, { repeatSecret = it }, R.string.vault_repeat_passphrase, 4096, masked = true)
        if (isForm && entry != null) Text(stringResource(R.string.vault_keep_secret), style = MaterialTheme.typography.bodySmall)
        if (mode == VaultEditor.TOTP) {
            Text(stringResource(R.string.vault_algorithm))
            VaultAlgorithm.entries.forEach { candidate ->
                FilterChip(selected = algorithm == candidate, onClick = { algorithm = candidate }, label = { Text(candidate.name.replace("SHA", "SHA-")) })
            }
            VaultField(digits, { digits = it }, R.string.vault_digits, 1)
            VaultField(period, { period = it }, R.string.vault_period, 3)
        }
        val valid = when (mode) {
            VaultEditor.URI -> secret.isNotBlank()
            VaultEditor.SYNC -> secret.length >= 12 && secret == repeatSecret
            VaultEditor.PASSWORD -> label.isNotBlank() && (secret.isNotEmpty() || entry != null)
            VaultEditor.TOTP -> label.isNotBlank() && (secret.isNotBlank() || entry != null) && digits.toUIntOrNull() != null && period.toUIntOrNull() != null
        }
        Button(enabled = enabled && valid, onClick = {
            val bytes = secret.toByteArray(Charsets.UTF_8)
            secret = ""; repeatSecret = ""
            when (mode) {
                VaultEditor.URI -> onImport(bytes)
                VaultEditor.SYNC -> onSync(bytes)
                VaultEditor.TOTP -> onSave(VaultDraft(entry?.id, VaultKind.TOTP, label, account, issuer, bytes.takeIf { it.isNotEmpty() }, algorithm, digits.toUIntOrNull(), period.toUIntOrNull()))
                VaultEditor.PASSWORD -> onSave(VaultDraft(entry?.id, VaultKind.PASSWORD, label, account, issuer, bytes.takeIf { it.isNotEmpty() }, null, null, null))
            }
        }) { Text(stringResource(if (mode == VaultEditor.SYNC) R.string.vault_sync else R.string.vault_save)) }
        TextButton(onClick = { secret = ""; repeatSecret = ""; onDismiss() }) { Text(stringResource(R.string.cancel)) }
    }
}

@Composable
private fun VaultField(value: String, onValue: (String) -> Unit, label: Int, limit: Int, masked: Boolean = false) {
    OutlinedTextField(value, { if (it.length <= limit) onValue(it) }, modifier = Modifier.fillMaxWidth(),
        singleLine = true, label = { Text(stringResource(label)) }, visualTransformation = if (masked) PasswordVisualTransformation() else androidx.compose.ui.text.input.VisualTransformation.None,
        keyboardOptions = androidx.compose.foundation.text.KeyboardOptions(autoCorrectEnabled = false,
            keyboardType = if (masked) androidx.compose.ui.text.input.KeyboardType.Password else androidx.compose.ui.text.input.KeyboardType.Text))
}

private fun vaultStatus(code: String?): Int? = when (code) {
    null -> null
    "invalid" -> R.string.vault_invalid
    "missing" -> R.string.vault_missing
    "conflict" -> R.string.vault_conflict
    "busy" -> R.string.vault_busy
    "capacity" -> R.string.vault_capacity
    "sign_in" -> R.string.vault_sync_enrollment_required
    "passphrase" -> R.string.vault_bad_passphrase
    "network" -> R.string.hub_network_unavailable
    "saved" -> R.string.vault_saved
    "synced" -> R.string.vault_synced
    "code_expired" -> R.string.vault_code_expired
    "device_lock" -> R.string.vault_device_lock
    "device_auth" -> R.string.vault_device_auth
    "camera_permission" -> R.string.vault_camera_permission
    "camera_unavailable" -> R.string.vault_camera_unavailable
    else -> R.string.vault_unavailable
}
