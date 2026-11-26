package net.aptist.loft.foundation

import org.junit.Assert.*
import org.junit.Test

class SnapshotSequenceTest {
    // Catches a late subscription snapshot rolling back a later command receipt.
    @Test fun lowerPublicationCannotOverwriteTheLatestNativeState() {
        val admission = SnapshotSequence()
        admission.begin(11)
        assertTrue(admission.accepts(11, 0uL))
        assertTrue(admission.accepts(11, 7uL))
        assertFalse(admission.accepts(11, 6uL))
        assertFalse(admission.accepts(11, 7uL))
    }

    // Priority Stop can share a Rust generation with the previous Connected
    // snapshot; only a strictly newer transport capture may replace a frame.
    @Test fun duplicatePublicationCannotOverwriteTheAcceptedFrame() {
        val admission = SnapshotSequence()
        admission.begin(11)
        assertTrue(admission.accepts(11, 18uL))
        assertFalse(admission.accepts(11, 18uL))
    }

    // Catches callbacks from an old service generation contaminating a reopened session.
    @Test fun newBindingAllowsGenerationResetAndRejectsThePreviousBinding() {
        val admission = SnapshotSequence()
        admission.begin(11)
        assertTrue(admission.accepts(11, 90uL))
        admission.end()
        admission.begin(12)
        assertTrue(admission.accepts(12, 0uL))
        assertFalse(admission.accepts(11, 100uL))
    }

    @Test fun detachedBindingRejectsEveryQueuedSnapshot() {
        val admission = SnapshotSequence()
        admission.begin(11)
        admission.end()
        assertFalse(admission.accepts(11, 1uL))
    }

    // Catches converting Rust u64 generations to signed Long before ordering.
    @Test fun generationOrderingUsesUnsignedRustValues() {
        val admission = SnapshotSequence()
        admission.begin(11)
        assertTrue(admission.accepts(11, ULong.MAX_VALUE - 1uL))
        assertFalse(admission.accepts(11, 1uL))
        assertTrue(admission.accepts(11, ULong.MAX_VALUE))
    }
}
