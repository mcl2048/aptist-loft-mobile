package net.aptist.loft.foundation

import org.junit.Assert.*
import org.junit.Test

class VpnPermissionDraftTest {
    @Test fun permissionResultKeepsTheExactOriginalNodeAndGeneration() {
        val draft = VpnPermissionDraft()
        assertTrue(draft.request("n-4", ULong.MAX_VALUE))
        assertFalse(draft.request("n-9", 20uL))
        val command = draft.finish(true)!!
        assertEquals("n-4", command.nodeId)
        assertEquals(ULong.MAX_VALUE, command.expectedGeneration)
        assertNull(draft.finish(true))
    }

    // Stop while the OS dialog is open must invalidate its later grant. A new
    // request cannot reuse that still-pending ActivityResult callback.
    @Test fun stopCancelsALatePermissionGrantBeforeAnotherDraftMayLaunch() {
        val draft = VpnPermissionDraft()
        assertTrue(draft.request("n-4", 17uL))
        draft.cancel()
        assertFalse(draft.request("n-9", 18uL))
        assertNull(draft.finish(true))
        assertTrue(draft.request("n-9", 18uL))
        assertEquals("n-9", draft.finish(true)!!.nodeId)
    }

    @Test fun deniedPermissionConsumesTheDraftWithoutAConnectCommand() {
        val draft = VpnPermissionDraft()
        assertTrue(draft.request("n-4", 17uL))
        assertNull(draft.finish(false))
        assertNull(draft.finish(true))
        assertTrue(draft.request("n-9", 18uL))
        assertEquals(18uL, draft.finish(true)!!.expectedGeneration)
    }
}
