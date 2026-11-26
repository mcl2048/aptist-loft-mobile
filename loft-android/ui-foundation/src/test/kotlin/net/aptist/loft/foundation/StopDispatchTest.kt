package net.aptist.loft.foundation

import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.FileInputStream
import java.io.IOException
import java.nio.ByteBuffer
import java.nio.channels.Pipe
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.CountDownLatch
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference

class StopDispatchTest {
    @get:Rule val temporary = TemporaryFolder()
    private fun descriptor() = FileInputStream(temporary.newFile().also { it.writeBytes(byteArrayOf(11)) })

    // A held native completion is real blocking I/O on an owned pipe descriptor.
    // The callback must return and close the original while that descriptor is held.
    @Test fun heldNativeJoinCannotBlockTheCallerOrOriginalCancellation() {
        val original = OriginalTunOwnership<FileInputStream>()
        val priority = ThreadPoolExecutor(1, 1, 0, TimeUnit.MILLISECONDS, ArrayBlockingQueue(1))
        val pipe = Pipe.open()
        val entered = CountDownLatch(1)
        val returned = CountDownLatch(1)
        val joined = CountDownLatch(1)
        val failure = AtomicReference<Throwable?>(null)
        val joinThread = AtomicReference<Thread?>()
        descriptor().use { retained ->
            assertTrue(original.begin(1u)); assertTrue(original.adopt(1u, retained))
            val caller = Thread({
                try {
                    assertTrue(StopDispatch().request(
                        cancelOriginal = { original.stop() },
                        prepareCleanup = { {
                            joinThread.set(Thread.currentThread())
                            entered.countDown()
                            try { check(pipe.source().read(ByteBuffer.allocate(1)) == 1) }
                            catch (problem: Throwable) { failure.set(problem) }
                            finally { pipe.source().close(); joined.countDown() }
                        } },
                        enqueueCleanup = { work -> priority.execute { work() }; true },
                    ))
                } catch (problem: Throwable) { failure.set(problem) }
                finally { returned.countDown() }
            }, "loft-stop-caller-test")
            try {
                caller.start()
                assertTrue(entered.await(1, TimeUnit.SECONDS))
                val callerReturned = returned.await(1, TimeUnit.SECONDS)
                val originalClosed = closed(retained)
                assertEquals(listOf(true, true), listOf(callerReturned, originalClosed))
                assertNotSame(caller, joinThread.get())
                assertTrue(original.facts().tunClosed)
                assertTrue(pipe.source().isOpen)
                assertEquals(1L, joined.count)
            } finally {
                runCatching { pipe.sink().write(ByteBuffer.wrap(byteArrayOf(1))) }
                caller.join(1000)
                assertTrue(joined.await(1, TimeUnit.SECONDS))
                priority.shutdown(); assertTrue(priority.awaitTermination(1, TimeUnit.SECONDS))
                pipe.source().close(); pipe.sink().close(); original.stop()
            }
            assertFalse(caller.isAlive)
            assertNull(failure.get())
            assertEquals(0L, joined.count)
        }
    }

    @Test fun coalescedStopStillFencesAndClosesALateOriginal() {
        val original = OriginalTunOwnership<FileInputStream>()
        val queued = AtomicInteger()
        assertTrue(original.begin(2u))
        assertTrue(StopDispatch().request(
            cancelOriginal = { original.stop() }, prepareCleanup = { null },
            enqueueCleanup = { queued.incrementAndGet(); true },
        ))
        descriptor().use { late ->
            try {
                assertFalse(original.adopt(2u, late))
                assertTrue(closed(late))
                assertTrue(original.facts().tunClosed)
                assertEquals(0, queued.get())
            } finally { original.stop() }
        }
    }

    private fun closed(resource: FileInputStream): Boolean = try { resource.read(); false } catch (_: IOException) { true }
}
