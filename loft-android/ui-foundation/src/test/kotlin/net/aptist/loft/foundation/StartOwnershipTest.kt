package net.aptist.loft.foundation

import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.FileInputStream
import java.io.IOException
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

class StartOwnershipTest {
    @get:Rule val temporary = TemporaryFolder()
    private fun descriptor() = FileInputStream(temporary.newFile().also { it.writeBytes(byteArrayOf(11)) })

    // A duplicate canceled activation cannot claim a running Builder task joined.
    @Test fun canceledDuplicateDoesNotReleaseAnAdmittedConstruction() {
        val owner = StartOwnership()
        assertTrue(owner.schedule())
        assertFalse(owner.schedule())
        descriptor().use { resource ->
            assertFalse(owner.cancelUnscheduled())
            assertFalse(owner.joined())
            assertFalse(owner.await(20))
            assertEquals(11, resource.read())
            resource.close()
            owner.complete()
            assertTrue(owner.await(1000))
            expectClosed(resource)
        }
    }

    @Test fun aRunningConstructionMustCloseItsResourceBeforeTheJoinReceipt() {
        val owner = StartOwnership()
        assertTrue(owner.schedule())
        descriptor().use { resource ->
            val entered = CountDownLatch(1)
            val release = CountDownLatch(1)
            val thread = Thread({ entered.countDown(); check(release.await(1, TimeUnit.SECONDS)); resource.close(); owner.complete() }, "loft-start-join-test")
            thread.start()
            assertTrue(entered.await(1, TimeUnit.SECONDS))
            try { assertFalse(owner.cancelUnscheduled()); assertFalse(owner.joined()); assertEquals(11, resource.read()) }
            finally { release.countDown() }
            assertTrue(owner.await(1000))
            expectClosed(resource)
            thread.join(1000)
            assertFalse(thread.isAlive)
        }
    }

    @Test fun cancelBeforeSchedulingRejectsEveryLaterConstruction() {
        val owner = StartOwnership()
        assertTrue(owner.cancelUnscheduled())
        assertTrue(owner.joined())
        assertFalse(owner.schedule())
        assertFalse(owner.schedule())
    }

    private fun expectClosed(resource: FileInputStream) {
        try { resource.read(); fail("Construction resource is still open") } catch (_: IOException) { }
    }
}
