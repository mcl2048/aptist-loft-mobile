package net.aptist.loft.foundation

import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.FileInputStream
import java.io.IOException
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

class PriorityControlQueueTest {
    @get:Rule val temporary = TemporaryFolder()

    // Catches Stop/revoke cancellation waiting behind a full import queue.
    @Test fun cancellationClosesARealDescriptorWhileTheNormalQueueIsFull() {
        val file = temporary.newFile().also { it.writeBytes(byteArrayOf(7)) }
        val resource = FileInputStream(file)
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        PriorityControlQueue().use { queue ->
            try {
                assertTrue(queue.submit { entered.countDown(); release.await(5, TimeUnit.SECONDS) })
                assertTrue(entered.await(2, TimeUnit.SECONDS))
                repeat(8) { assertTrue(queue.submit { }) }
                assertFalse(queue.submit { })
                queue.cancelNow { resource.close() }
                try { resource.read(); fail("Cancellation was queued behind imports") } catch (_: IOException) { }
            } finally { release.countDown(); resource.close() }
        }
    }
}
