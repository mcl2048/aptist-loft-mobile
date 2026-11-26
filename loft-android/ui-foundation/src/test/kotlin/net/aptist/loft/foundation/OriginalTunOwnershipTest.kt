package net.aptist.loft.foundation

import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.FileInputStream
import java.io.IOException

class OriginalTunOwnershipTest {
    @get:Rule val temporary = TemporaryFolder()
    private fun descriptor() = FileInputStream(temporary.newFile().also { it.writeBytes(byteArrayOf(11)) })

    // A late Builder result after priority Stop must close rather than acquire
    // a new VPN scope, and pending establishment is not a closure receipt.
    @Test fun stopFencesAndClosesALateEstablishedDescriptor() {
        val owner = OriginalTunOwnership<FileInputStream>()
        assertTrue(owner.begin(4uL))
        assertFalse(owner.stop().tunClosed)
        assertFalse(owner.begin(5uL))
        descriptor().use { resource ->
            assertFalse(owner.adopt(4uL, resource))
            expectClosed(resource)
            assertTrue(owner.facts().tunClosed)
        }
        assertTrue(owner.begin(5uL))
        owner.establishmentFailed(5uL)
        assertTrue(owner.stop().tunClosed)
    }

    @Test fun stopClosesTheAdoptedOriginalDescriptor() {
        val owner = OriginalTunOwnership<FileInputStream>()
        assertTrue(owner.begin(4uL))
        descriptor().use { resource ->
            assertTrue(owner.adopt(4uL, resource))
            assertSame(resource, owner.original(4uL))
            assertTrue(owner.facts().held)
            assertFalse(owner.begin(5uL))
            assertTrue(owner.stop().tunClosed)
            expectClosed(resource)
            assertNull(owner.original(4uL))
        }
    }

    // A failed close cannot release the VPN/core lease or report physical Stop.
    @Test fun failedCloseRetainsOwnershipUntilAConfirmedRetry() {
        descriptor().use { resource ->
            var refuse = true
            val owned = AutoCloseable { if (refuse) throw IOException("close denied") else resource.close() }
            val owner = OriginalTunOwnership<AutoCloseable>()
            assertTrue(owner.begin(4uL))
            assertTrue(owner.adopt(4uL, owned))
            val incomplete = owner.stop()
            assertFalse(incomplete.tunClosed)
            assertTrue(incomplete.held)
            assertTrue(incomplete.closeFailed)
            assertEquals(11, resource.read())
            refuse = false
            assertTrue(owner.stop().tunClosed)
            expectClosed(resource)
        }
    }

    @Test fun failedEstablishmentReleasesThePendingOwnershipSlot() {
        val owner = OriginalTunOwnership<FileInputStream>()
        assertTrue(owner.begin(4uL))
        owner.stop()
        assertFalse(owner.begin(5uL))
        owner.establishmentFailed(4uL)
        assertTrue(owner.facts().tunClosed)
        assertTrue(owner.begin(5uL))
    }

    private fun expectClosed(resource: FileInputStream) {
        try { resource.read(); fail("Original TUN descriptor is still open") } catch (_: IOException) { }
    }
}
