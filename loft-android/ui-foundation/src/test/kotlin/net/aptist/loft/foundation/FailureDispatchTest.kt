package net.aptist.loft.foundation

import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.FileInputStream
import java.io.IOException
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

class FailureDispatchTest {
    @get:Rule val temporary = TemporaryFolder()
    private fun descriptor() = FileInputStream(temporary.newFile().also { it.writeBytes(byteArrayOf(11)) })

    // Abort publishes a state notification. That notification cannot start the
    // same failure handler again and make an unbounded snapshot/query feedback loop.
    @Test fun abortNotificationCannotReenterTheFailureHandler() {
        val owner = FailureDispatch()
        val callbacks = ArrayDeque<() -> Unit>()
        var publications = 0
        descriptor().use { forwarding -> descriptor().use { original ->
            fun handle() {
                if (!owner.begin()) return
                forwarding.close(); publications++
                callbacks.addLast { handle() }
            }
            callbacks.addLast { handle() }
            repeat(8) { callbacks.removeFirstOrNull()?.invoke() }
            assertEquals(1, publications)
            assertTrue(callbacks.isEmpty())
            expectClosed(forwarding)
            assertEquals(11, original.read())
        } }
    }

    @Test fun racingFailureCallbacksOwnOnlyOneClosureAndPublication() {
        val owner = FailureDispatch()
        val release = CountDownLatch(1)
        val publications = AtomicInteger()
        descriptor().use { forwarding ->
            val threads = (1..2).map { Thread({ check(release.await(1, TimeUnit.SECONDS)); if (owner.begin()) { forwarding.close(); publications.incrementAndGet() } }, "loft-failure-dispatch-test") }
            threads.forEach { it.start() }; release.countDown()
            threads.forEach { it.join(1000); assertFalse(it.isAlive) }
            assertEquals(1, publications.get())
            expectClosed(forwarding)
        }
    }
    private fun expectClosed(resource: FileInputStream) {
        try { resource.read(); fail("Forwarding resource remains open") } catch (_: IOException) { }
    }
}
