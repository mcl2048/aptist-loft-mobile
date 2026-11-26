package net.aptist.loft.foundation

import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.FileInputStream
import java.io.IOException
import java.util.concurrent.CountDownLatch
import java.util.concurrent.FutureTask
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicLong

class QueryGateTest {
    @get:Rule val temporary = TemporaryFolder()
    private fun descriptor() = FileInputStream(temporary.newFile().also { it.writeBytes(byteArrayOf(3)) })

    @Test fun completedAnswerIsDeliveredWithoutChangingIt() {
        QueryGate<String>().use { gate ->
            val query = gate.start { }!!
            assertTrue(query.complete("1.1.1.1\n8.8.8.8"))
            assertEquals("1.1.1.1\n8.8.8.8", query.await())
        }
    }

    // Catches a timeout leaving platform DNS cancellation/resource ownership active.
    @Test fun timeoutCancelsTheOwnedResource() {
        descriptor().use { resource ->
            QueryGate<String>(timeoutMillis = 20).use { gate ->
                assertNull(gate.start { resource.close() }!!.await())
                expectClosed(resource)
            }
        }
    }

    // Catches Stop waiting the entire DNS deadline instead of releasing its latch.
    @Test fun stopUnblocksAWaitingQueryAndCancelsItsResource() {
        descriptor().use { resource ->
            QueryGate<String>().use { gate ->
                val query = gate.start { resource.close() }!!
                val entered = CountDownLatch(1)
                val result = FutureTask { entered.countDown(); query.await() }
                val thread = Thread(result, "loft-query-test")
                thread.start()
                assertTrue(entered.await(1, TimeUnit.SECONDS))
                gate.cancelAll()
                assertNull(result.get(1, TimeUnit.SECONDS))
                expectClosed(resource)
                thread.join(1000)
                assertFalse(thread.isAlive)
            }
        }
    }

    @Test fun pendingQuotaIsReclaimedAfterCompletion() {
        QueryGate<String>(maxPending = 1).use { gate ->
            val first = gate.start { }!!
            assertNull(gate.start { })
            assertTrue(first.complete("1.1.1.1"))
            assertNotNull(gate.start { })
        }
    }

    @Test fun canceledQueryRejectsLateCallback() {
        QueryGate<String>().use { gate ->
            val query = gate.start { }!!
            gate.cancelAll()
            assertFalse(query.complete("1.1.1.1"))
            assertNull(query.await())
        }
    }

    // Catches measuring the deadline from await rather than query creation.
    @Test fun deadlineExpiredCallbackBeforeAwaitCancelsTheOwnedResource() {
        descriptor().use { resource ->
            QueryGate<String>(timeoutMillis = 20).use { gate ->
                val query = gate.start { resource.close() }!!
                Thread.sleep(40)
                assertFalse(query.complete("1.1.1.1"))
                assertNull(query.await())
                expectClosed(resource)
            }
        }
    }

    // A late waiter gets the remainder of the original five seconds, not five
    // extra seconds. Cancellation closes a real descriptor owned by the query.
    @Test fun lateAwaitUsesOnlyTheRemainingCreationDeadline() {
        descriptor().use { resource ->
            val now = AtomicLong(17L)
            QueryGate<String>(monotonicNanos = now::get).use { gate ->
                val query = gate.start { resource.close() }!!
                now.addAndGet(TimeUnit.MILLISECONDS.toNanos(4999))
                val result = FutureTask { query.await() }
                val thread = Thread(result, "loft-query-deadline-test")
                thread.start()
                assertNull(result.get(1, TimeUnit.SECONDS))
                expectClosed(resource)
                thread.join(1000)
                assertFalse(thread.isAlive)
            }
        }
    }

    @Test fun callbackAtTheCreationDeadlineRejectsItsAnswer() {
        descriptor().use { resource ->
            val now = AtomicLong(Long.MAX_VALUE - 10L)
            QueryGate<String>(monotonicNanos = now::get).use { gate ->
                val query = gate.start { resource.close() }!!
                now.addAndGet(TimeUnit.MILLISECONDS.toNanos(5000))
                assertFalse(query.complete("1.1.1.1"))
                assertNull(query.await())
                expectClosed(resource)
            }
        }
    }

    private fun expectClosed(resource: FileInputStream) {
        try { resource.read(); fail("DNS resource was not canceled") } catch (_: IOException) { }
    }
}
