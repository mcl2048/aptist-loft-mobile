package net.aptist.loft.service

import net.aptist.loft.core.generated.*
import org.junit.Assert.*
import org.junit.Test

class NodePageSelectionTest {
    private fun node(index: Int) = NodeSummary("n-$index", "Node $index", ProtocolKind.SOCKS5, "example.invalid:1080", 0u, 65507u, false)
    private fun page(offset: UInt = 150u) = NodePage(1u, 7uL, offset, 200u, (offset.toInt() until offset.toInt() + 50).map(::node), if (offset < 150u) offset + 50u else null)
    private fun snapshot() = CoreSnapshot(2u, "0.1.2-LYNX", (0..49).map(::node), 200u, null, false, false, emptyList(), ConnectionState.DISCONNECTED,
        7uL, 0uL, null, null, null, net.aptist.loft.testing.NetworkPrivacyFixtures.policy(), 1uL, null, NetworkPrivacyEnforcement.INACTIVE)

    // Real page wire + consumer + UI selection: first-fifty snapshots cannot
    // erase a selected later node or confuse it with the active connection.
    @Test fun selectingNode180SurvivesFirstPageSnapshotsAndConnectionReceipts() {
        val pages = NodePageConsumer().also { it.begin(11); assertTrue(it.expect(11, 1, 150u, 7uL)) }
        val received = pages.consume(11, 1, NodePageWire.encode(page()))!!
        val selected = NodeChoice().select(received.nodes[30])
        assertEquals("n-180", selected.id)
        val publisher = SnapshotPublisher()
        val native = SnapshotConsumer().also { it.begin(11) }
        val first = native.consume(11, publisher.capture(::snapshot, SnapshotMetadata()))!!
        val retained = selected.receive(first.core)
        assertEquals("n-180", retained.id)
        assertEquals("Node 180", retained.summary!!.label)
        val active = snapshot().copy(connectionState = ConnectionState.CONNECTED, generation = 8uL, connectionAttemptId = 3uL,
            activeNodeId = "n-180", appliedRouting = AppliedRouting(false, emptyList(), Ipv6Policy.BLOCKED_IN_VPN),
            appliedNetworkPrivacy = net.aptist.loft.testing.NetworkPrivacyFixtures.applied(), networkPrivacyEnforcement = NetworkPrivacyEnforcement.ACTIVE)
        val connected = native.consume(11, publisher.capture({ active }, SnapshotMetadata(transportReady = true,
            tunHeld = true, forwardingDisabled = false, resourcesReleased = false)))!!
        assertEquals(ConnectionState.CONNECTED, connected.core.connectionState)
        assertEquals("n-180", retained.receive(connected.core).id)
        assertEquals("n-180", NodeChoice().receive(connected.core).id)
        assertEquals("n-180", retained.receive(page(0u)).id)
        assertNull(retained.removed("n-180").id)
    }

    @Test fun staleBindingPageRequestAndGenerationCannotOverwriteCurrentRows() {
        val consumer = NodePageConsumer().also { it.begin(11) }
        assertTrue(consumer.expect(11, 1, 0u, 7uL))
        assertTrue(consumer.expect(11, 2, 150u, 7uL))
        assertNull(consumer.consume(11, 1, NodePageWire.encode(page(0u))))
        assertEquals(150u, consumer.consume(11, 2, NodePageWire.encode(page()))!!.offset)
        assertNull(consumer.consume(11, 2, NodePageWire.encode(page())))
        assertTrue(consumer.expect(11, 3, 150u, 8uL))
        assertNull(consumer.consume(11, 3, NodePageWire.encode(page())))
        consumer.cancel()
        assertNull(consumer.consume(11, 3, NodePageWire.encode(page().copy(generation = 8uL))))
        consumer.end(); consumer.begin(12)
        assertFalse(consumer.expect(11, 4, 150u, 8uL))
        assertNull(consumer.consume(11, 3, NodePageWire.encode(page())))
    }
}
