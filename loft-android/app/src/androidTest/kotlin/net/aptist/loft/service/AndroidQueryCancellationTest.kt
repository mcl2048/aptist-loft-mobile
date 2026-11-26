package net.aptist.loft.service

import android.os.CancellationSignal
import androidx.test.ext.junit.runners.AndroidJUnit4
import net.aptist.loft.foundation.NodeResolutionOwnership
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

/** Actual Android cancellation objects; these checks create no DNS/network/TUN. */
@RunWith(AndroidJUnit4::class)
class AndroidQueryCancellationTest {
    @Test fun anAdmittedPrecreatedSignalIsCanceledAndCannotDeliverALateAnswer() {
        val signal = CancellationSignal()
        NodeResolutionOwnership<String>().use { owner ->
            val pending = checkNotNull(owner.start { signal.cancel() })
            assertFalse(signal.isCanceled)
            owner.cancelPending()
            assertTrue(signal.isCanceled)
            assertFalse(pending.complete("198.51.100.1"))
            assertNull(pending.await())
            assertNull(owner.start { signal.cancel() })
        }
    }

    @Test fun aSignalCreatedBeforeStopCannotStartFromAStalePrecheck() {
        val signal = CancellationSignal()
        NodeResolutionOwnership<String>().use { owner ->
            val staleAllowed = !owner.stopped
            assertTrue(staleAllowed)
            owner.cancelPending()
            val late = if (staleAllowed) owner.start { signal.cancel() } else null
            assertNull(late)
            assertFalse(late?.complete("198.51.100.2") == true)
            assertNull(late?.await())
        }
    }
}
