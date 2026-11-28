package net.aptist.loft.ui.notes

import net.aptist.loft.core.generated.NotesSyncStatus

internal enum class NotesSyncDisplay { SIGN_IN, HUB_UNAVAILABLE, RESET_PENDING, RECOVER_KEY, RESET_COMPLETE, CONFIGURED, SETUP }

internal fun NotesSyncStatus.display(): NotesSyncDisplay = when {
    !signedIn -> NotesSyncDisplay.SIGN_IN
    !available -> NotesSyncDisplay.HUB_UNAVAILABLE
    resetPending -> NotesSyncDisplay.RESET_PENDING
    needsRecovery -> NotesSyncDisplay.RECOVER_KEY
    recoveryCodeReady -> NotesSyncDisplay.RESET_COMPLETE
    configured -> NotesSyncDisplay.CONFIGURED
    else -> NotesSyncDisplay.SETUP
}

internal fun NotesSyncStatus.canShowPairingKey(): Boolean = signedIn && available && !resetPending && !needsRecovery
