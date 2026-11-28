package net.aptist.loft.ui

import androidx.activity.compose.LocalActivity
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import net.aptist.loft.MainActivity
import net.aptist.loft.R
import net.aptist.loft.ui.notes.PrivateEditorInput

@Composable
internal fun ProtectionGate(display: ProtectionDisplay, model: ProtectionPresentation) {
    val status = display.status
    if (status == null) {
        ProtectionMessage(display.problem)
        if (display.problem != null) TextButton(onClick = model::retry) { Text(stringResource(R.string.protection_retry)) }
        return
    }
    val activity = LocalActivity.current as? MainActivity
    var pin by remember(display.epoch) { mutableStateOf("") }
    Text(stringResource(R.string.protection_unlock_help))
    PrivateEditorInput {
        ProtectionPinField(pin, { pin = it }, R.string.protection_pin, !display.busy)
    }
    ProtectionMessage(display.problem)
    Button(
        onClick = {
            val candidate = pin.toByteArray(Charsets.US_ASCII)
            pin = ""
            model.pin(candidate)
        },
        enabled = pin.length == 6 && !display.busy,
    ) { Text(stringResource(R.string.protection_unlock)) }
    if (status.biometricEnabled && activity?.appBiometricAvailable() == true) {
        TextButton(enabled = !display.busy, onClick = { activity.requestAppBiometric(display.epoch) }) {
            Text(stringResource(R.string.protection_use_biometrics))
        }
    }
}

@Composable
internal fun ProtectionSettings(display: ProtectionDisplay, model: ProtectionPresentation) {
    val status = display.status
    if (status == null) {
        ProtectionMessage(display.problem)
        if (display.problem != null) TextButton(onClick = model::retry) { Text(stringResource(R.string.protection_retry)) }
        return
    }
    val activity = LocalActivity.current as? MainActivity
    val canUseBiometric = activity?.appBiometricAvailable() == true
    var current by remember(display.epoch, status.enabled) { mutableStateOf("") }
    var replacement by remember(display.epoch, status.enabled) { mutableStateOf("") }
    var confirm by remember(display.epoch, status.enabled) { mutableStateOf("") }
    var biometric by remember(display.epoch, status.biometricEnabled) { mutableStateOf(status.biometricEnabled) }
    Text(stringResource(if (status.enabled) R.string.protection_enabled_help else R.string.protection_setup_help))
    PrivateEditorInput {
        if (status.enabled) ProtectionPinField(current, { current = it }, R.string.protection_current_pin, !display.busy)
        ProtectionPinField(replacement, { replacement = it }, R.string.protection_new_pin, !display.busy)
        ProtectionPinField(confirm, { confirm = it }, R.string.protection_confirm_pin, !display.busy)
    }
    if (canUseBiometric || status.biometricEnabled) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Checkbox(
                checked = biometric,
                onCheckedChange = { biometric = it },
                enabled = !display.busy && (canUseBiometric || biometric),
                modifier = Modifier.height(48.dp),
            )
            Spacer(Modifier.width(4.dp))
            Text(stringResource(R.string.protection_use_biometrics))
        }
    }
    ProtectionMessage(display.problem)
    val currentValid = !status.enabled || current.length == 6
    val replacementValid = replacement.length == 6 && replacement == confirm
    val toggleOnly = status.enabled && replacement.isEmpty() && confirm.isEmpty() && biometric != status.biometricEnabled
    Button(
        onClick = {
            val old = current.takeIf { status.enabled }?.toByteArray(Charsets.US_ASCII)
            val next = (if (toggleOnly) current else replacement).toByteArray(Charsets.US_ASCII)
            current = ""; replacement = ""; confirm = ""
            model.configure(old, next, biometric)
        },
        enabled = !display.busy && currentValid && (replacementValid || toggleOnly),
    ) { Text(stringResource(R.string.protection_save)) }
    if (status.enabled) {
        TextButton(
            onClick = {
                val old = current.toByteArray(Charsets.US_ASCII)
                current = ""; replacement = ""; confirm = ""
                model.configure(old, null, false)
            },
            enabled = !display.busy && currentValid,
        ) { Text(stringResource(R.string.protection_disable)) }
    }
}

@Composable
private fun ProtectionPinField(value: String, change: (String) -> Unit, label: Int, enabled: Boolean) {
    OutlinedTextField(
        value = value,
        onValueChange = { candidate -> if (candidate.length <= 6 && candidate.all { it in '0'..'9' }) change(candidate) },
        label = { Text(stringResource(label)) },
        modifier = Modifier.fillMaxWidth(),
        enabled = enabled,
        singleLine = true,
        visualTransformation = PasswordVisualTransformation(),
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword, autoCorrectEnabled = false),
    )
}

@Composable
private fun ProtectionMessage(problem: String?) {
    val resource = when (problem) {
        null -> return
        "incorrect_pin" -> R.string.protection_incorrect
        "rate_limited" -> R.string.protection_rate_limited
        "invalid" -> R.string.protection_invalid
        "device_auth" -> R.string.vault_device_auth
        "busy" -> R.string.vault_busy
        else -> R.string.vault_unavailable
    }
    Text(stringResource(resource), color = MaterialTheme.colorScheme.error)
}
