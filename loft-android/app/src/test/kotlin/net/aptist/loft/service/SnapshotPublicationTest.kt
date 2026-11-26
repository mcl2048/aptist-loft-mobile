package net.aptist.loft.service

import net.aptist.loft.core.generated.*
import org.junit.Assert.*
import org.junit.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.FutureTask
import java.util.concurrent.TimeUnit

class SnapshotPublicationTest {
    private fun core() = CoreSnapshot(schemaVersion = 2u, coreVersion = "0.1.2-LYNX",
        nodes = emptyList(), nodeCount = 0u, serverAddress = null, serverVerified = false,
        routingEnabled = false, selectedApps = emptyList(), connectionState = ConnectionState.DISCONNECTED, generation = 7uL,
        connectionAttemptId = 0uL, activeNodeId = null, appliedRouting = null, vpnFailure = null,
        networkPrivacyPolicy = net.aptist.loft.testing.NetworkPrivacyFixtures.policy(), networkPrivacyPolicyEpoch = 1uL,
        appliedNetworkPrivacy = null, networkPrivacyEnforcement = NetworkPrivacyEnforcement.INACTIVE)

    // Rust Stop and poison projections can reuse the stable business generation.
    // The exact consumer used by Binder must keep a newer priority frame when a
    // previously captured Connected payload arrives late with that generation.
    @Test fun sameGenerationLateConnectedCannotOverwritePriorityStopOrUnavailable() {
        val connected = core().copy(connectionState = ConnectionState.CONNECTED, connectionAttemptId = 3uL,
            activeNodeId = "n-4", appliedRouting = AppliedRouting(false, emptyList(), Ipv6Policy.BLOCKED_IN_VPN),
            appliedNetworkPrivacy = net.aptist.loft.testing.NetworkPrivacyFixtures.applied(), networkPrivacyEnforcement = NetworkPrivacyEnforcement.ACTIVE)
        for (priorityState in listOf(ConnectionState.STOPPING, ConnectionState.UNAVAILABLE)) {
            val publisher = SnapshotPublisher()
            val old = publisher.capture({ connected }, SnapshotMetadata(transportReady = true, tunHeld = true,
                forwardingDisabled = false, resourcesReleased = false))
            val priority = publisher.capture({ connected.copy(connectionState = priorityState, networkPrivacyEnforcement = NetworkPrivacyEnforcement.INACTIVE,
                appliedNetworkPrivacy = if (priorityState == ConnectionState.UNAVAILABLE) null else connected.appliedNetworkPrivacy) },
                SnapshotMetadata(tunHeld = true, forwardingDisabled = true, resourcesReleased = false))
            val consumer = SnapshotConsumer()
            consumer.begin(11)
            assertEquals(ConnectionState.CONNECTED, consumer.consume(11, old)!!.core.connectionState)
            val latest = consumer.consume(11, priority)!!
            assertEquals(priorityState, latest.core.connectionState)
            assertEquals(7uL, latest.core.generation)
            assertNull(consumer.consume(11, old))
        }
    }

    @Test fun consumerRejectsOldAndDuplicatePublicationsWithinTheBinding() {
        val publisher = SnapshotPublisher()
        val old = publisher.capture(::core, SnapshotMetadata())
        val fresh = publisher.capture(::core, SnapshotMetadata())
        val consumer = SnapshotConsumer()
        consumer.begin(11)
        assertEquals(2uL, consumer.consume(11, fresh)!!.publicationSequence)
        assertNull(consumer.consume(11, old))
        assertNull(consumer.consume(11, fresh))
        consumer.end()
        assertNull(consumer.consume(11, fresh))
        consumer.begin(12)
        assertEquals(1uL, consumer.consume(12, old)!!.publicationSequence)
        assertNull(consumer.consume(11, fresh))
    }

    @Test fun restoredConfigurationMayHaveLowerGenerationInTheSameBinding() {
        val publisher = SnapshotPublisher()
        val stopped = publisher.capture({ core().copy(generation = 11uL, connectionAttemptId = 3uL) }, SnapshotMetadata())
        val inFlight = publisher.capture({ core().copy(generation = 11uL, connectionAttemptId = 3uL) }, SnapshotMetadata())
        val reopened = publisher.capture(::core, SnapshotMetadata())
        val consumer = SnapshotConsumer()
        consumer.begin(11)
        assertEquals(11uL, consumer.consume(11, stopped)!!.core.generation)
        val restored = consumer.consume(11, reopened)!!
        assertEquals(7uL, restored.core.generation)
        assertEquals(0uL, restored.core.connectionAttemptId)
        assertEquals(ConnectionState.DISCONNECTED, restored.core.connectionState)
        assertNull(consumer.consume(11, inFlight))
    }

    // Exhaustion must break the transport instead of recycling an ordering value
    // or querying a snapshot that can never be published safely.
    @Test fun exhaustedPublicationSequenceFailsBeforeQueryingAnotherSnapshot() {
        var queries = 0
        val publisher = SnapshotPublisher(ULong.MAX_VALUE - 1uL)
        val query = { queries++; core() }
        val last = SnapshotWire.decode(publisher.capture(query, SnapshotMetadata()))
        assertEquals(ULong.MAX_VALUE, last.publicationSequence)
        repeat(2) {
            try { publisher.capture(query, SnapshotMetadata()); fail("Sequence was reused") }
            catch (_: PublicationExhaustedException) { }
        }
        assertEquals(1, queries)
    }

    // Reserve/query/encode must be a single capture operation: a second reader
    // cannot race ahead while the first reader has only reserved its sequence.
    @Test fun concurrentCapturesSerializeTheSnapshotQueryWithItsPublication() {
        val publisher = SnapshotPublisher()
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val secondEntered = CountDownLatch(1)
        val first = FutureTask {
            publisher.capture({ entered.countDown(); check(release.await(1, TimeUnit.SECONDS)); core() }, SnapshotMetadata())
        }
        val second = FutureTask { publisher.capture({ secondEntered.countDown(); core() }, SnapshotMetadata()) }
        val firstThread = Thread(first, "loft-publication-first")
        val secondThread = Thread(second, "loft-publication-second")
        firstThread.start()
        assertTrue(entered.await(1, TimeUnit.SECONDS))
        secondThread.start()
        try { assertFalse(secondEntered.await(40, TimeUnit.MILLISECONDS)) }
        finally { release.countDown() }
        assertEquals(1uL, SnapshotWire.decode(first.get(1, TimeUnit.SECONDS)).publicationSequence)
        assertEquals(2uL, SnapshotWire.decode(second.get(1, TimeUnit.SECONDS)).publicationSequence)
        firstThread.join(1000); secondThread.join(1000)
        assertFalse(firstThread.isAlive); assertFalse(secondThread.isAlive)
    }
}
