package net.aptist.loft.ui.notes

import net.aptist.loft.core.generated.NotesSyncStatus
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class NotesSyncDisplayTest {
    @Test fun noSessionAndUnavailableHubAreDifferentFromAnUnpairedSignedInSession() {
        assertEquals(NotesSyncDisplay.SIGN_IN, status(signedIn = false, configured = true).display())
        assertEquals(NotesSyncDisplay.HUB_UNAVAILABLE, status(available = false, configured = true).display())
        assertEquals(NotesSyncDisplay.SETUP, status().display())
    }

    @Test fun resetPendingAndKeyRecoveryTakePriorityOverCachedPairing() {
        assertEquals(NotesSyncDisplay.RESET_PENDING, status(configured = true, pending = true, needsRecovery = true,
            codeReady = true).display())
        assertEquals(NotesSyncDisplay.RECOVER_KEY, status(configured = true, needsRecovery = true).display())
        assertEquals(NotesSyncDisplay.RESET_COMPLETE, status(configured = true, codeReady = true).display())
        assertEquals(NotesSyncDisplay.CONFIGURED, status(configured = true).display())
    }

    @Test fun inMemoryKeyClearsAsSoonAsResetOrIdentityInvalidatesItsScope() {
        assertFalse(status(signedIn = false, codeReady = true).canShowPairingKey())
        assertFalse(status(available = false, codeReady = true).canShowPairingKey())
        assertFalse(status(pending = true, codeReady = true).canShowPairingKey())
        assertFalse(status(needsRecovery = true, codeReady = true).canShowPairingKey())
        assertTrue(status(configured = true).canShowPairingKey())
    }

    private fun status(
        available: Boolean = true,
        configured: Boolean = false,
        signedIn: Boolean = true,
        pending: Boolean = false,
        needsRecovery: Boolean = false,
        codeReady: Boolean = false,
    ) = NotesSyncStatus(available = available, configured = configured, signedIn = signedIn, resetAvailable = true,
        resetPending = pending, needsRecovery = needsRecovery, recoveryCodeReady = codeReady)
}
