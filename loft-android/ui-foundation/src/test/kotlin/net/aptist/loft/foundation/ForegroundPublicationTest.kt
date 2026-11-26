package net.aptist.loft.foundation

import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.FileInputStream
import java.io.IOException

class ForegroundPublicationTest {
    @get:Rule val temporary = TemporaryFolder()
    private fun descriptor() = FileInputStream(temporary.newFile().also { it.writeBytes(byteArrayOf(11)) })

    // A delayed release for an old service attempt cannot stop its replacement.
    @Test fun oldLeaseReleaseCannotCloseTheNewForegroundOwner() {
        val publication = ForegroundPublication()
        val old = Any(); val current = Any()
        publication.retain(old)
        publication.retain(current)
        descriptor().use { resource ->
            if (publication.release(old)) resource.close()
            assertEquals(11, resource.read())
            assertFalse(publication.released())
            assertTrue(publication.release(current))
            resource.close()
            expectClosed(resource)
        }
    }

    @Test fun callbackQueuedBeforeAReplacementCannotReleaseTheNewScope() {
        val publication = ForegroundPublication()
        val old = Any(); val current = Any(); val orphan = Any()
        publication.retain(old)
        assertTrue(publication.release(old))
        publication.retainIfReleased(current)
        publication.retainIfReleased(orphan)
        descriptor().use { resource ->
            if (publication.released()) resource.close()
            assertEquals(11, resource.read())
            assertFalse(publication.release(orphan))
            assertTrue(publication.matches(current))
        }
    }

    @Test fun staleLeaseAndPublicationCannotReviveAnOldNotification() {
        val publication = ForegroundPublication()
        val old = Any(); val current = Any()
        publication.retain(old)
        assertTrue(publication.admits(old, 5uL))
        assertTrue(publication.admits(old, 7uL))
        assertFalse(publication.admits(old, 6uL))
        assertFalse(publication.admits(old, 7uL))
        publication.retain(current)
        assertFalse(publication.admits(old, 9uL))
        assertTrue(publication.admits(current, 8uL))
        publication.close()
        assertFalse(publication.admits(current, 10uL))
    }

    private fun expectClosed(resource: FileInputStream) {
        try { resource.read(); fail("Foreground owner descriptor is still open") } catch (_: IOException) { }
    }
}
