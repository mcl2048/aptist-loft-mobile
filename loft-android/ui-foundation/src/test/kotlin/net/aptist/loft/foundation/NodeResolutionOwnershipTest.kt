package net.aptist.loft.foundation

import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.FileInputStream
import java.io.IOException
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

class NodeResolutionOwnershipTest {
    @get:Rule val temporary = TemporaryFolder()
    private fun descriptor() = FileInputStream(temporary.newFile().also { it.writeBytes(byteArrayOf(11)) })

    // Forces the actual stale stopped precheck -> Stop -> query admission order.
    @Test fun staleStoppedPrecheckCannotAdmitOrCompleteAQueryAfterStop() {
        val owner = NodeResolutionOwnership<String>()
        val checked = CountDownLatch(1)
        val resume = CountDownLatch(1)
        val attempted = CountDownLatch(1)
        val late = AtomicReference<QueryGate<String>.Pending?>()
        val failure = AtomicReference<Throwable?>()
        descriptor().use { precreated ->
            val resolver = Thread({
                try {
                    check(!owner.stopped)
                    checked.countDown()
                    check(resume.await(1, TimeUnit.SECONDS))
                    late.set(owner.start { precreated.close() })
                } catch (problem: Throwable) { failure.set(problem) }
                finally { attempted.countDown() }
            }, "loft-late-resolution-test")
            try {
                resolver.start(); assertTrue(checked.await(1, TimeUnit.SECONDS))
                owner.cancelPending(); assertTrue(owner.stopped)
                resume.countDown(); assertTrue(attempted.await(1, TimeUnit.SECONDS))
                assertNull(failure.get())
                val pending = late.get()
                val rejected = pending == null
                val resultRejected = pending?.complete("198.51.100.1") != true
                val noUsableResult = pending?.await() == null
                assertEquals(listOf(true, true, true), listOf(rejected, resultRejected, noUsableResult))
            } finally { resume.countDown(); resolver.join(1000); owner.close() }
            assertFalse(resolver.isAlive)
        }
    }

    @Test fun aPrecreatedCancellationOwnerClosesAndCannotDeliverOrRearmAfterStop() {
        val owner = NodeResolutionOwnership<String>()
        descriptor().use { cancellationResource ->
            val pending = checkNotNull(owner.start { cancellationResource.close() })
            try {
                owner.cancelPending()
                assertTrue(owner.stopped)
                try { cancellationResource.read(); fail("Cancellation owner remains open") } catch (_: IOException) { }
                assertFalse(pending.complete("198.51.100.2"))
                assertNull(pending.await())
                assertNull(owner.start { cancellationResource.close() })
            } finally { owner.close() }
        }
    }
}
