package net.aptist.loft.service

import net.aptist.loft.core.generated.*
import net.aptist.loft.foundation.ControlCodec
import org.junit.Assert.*
import org.junit.Test

class NodePageWireTest {
    private fun node(index: Int) = NodeSummary("n-$index", "東京 $index", ProtocolKind.HYRAKEN_X,
        "example.invalid:443", 1u, 1024u, true)
    private fun lastPage() = NodePage(1u, ULong.MAX_VALUE, 150u, 200u, (150..199).map(::node), null)

    // Last fifty nodes must survive the actual bounded wire without secret fields.
    @Test fun lastPageRoundTripsAllFiftyRedactedSummaries() {
        val payload = NodePageWire.encode(lastPage())
        assertTrue(payload.size in 1..ControlCodec.MAX_CONTROL_BYTES)
        val page = NodePageWire.decode(payload)
        assertEquals(ULong.MAX_VALUE, page.generation)
        assertEquals(150u, page.offset)
        assertEquals(200u, page.nodeCount)
        assertNull(page.nextOffset)
        assertEquals(50, page.nodes.size)
        assertEquals("n-150", page.nodes.first().id)
        assertEquals("n-199", page.nodes.last().id)
        assertEquals("東京 180", page.nodes[30].label)
        assertEquals("example.invalid:443", page.nodes[30].endpoint)
        assertEquals(ProtocolKind.HYRAKEN_X, page.nodes[30].protocol)
        assertEquals(1u, page.nodes[30].udpMin)
        assertEquals(1024u, page.nodes[30].udpMax)
        assertTrue(page.nodes[30].credentialMaterialPresent)
        try { (page.nodes as MutableList<NodeSummary>).clear(); fail("Mutable node page") }
        catch (_: UnsupportedOperationException) { }
    }

    @Test fun exactFirstPartialAndEmptyPageBoundariesSurviveEncoding() {
        val cases = listOf(
            NodePage(1u, 7uL, 0u, 0u, emptyList(), null),
            NodePage(1u, 7uL, 0u, 1u, listOf(node(0)), null),
            NodePage(1u, 7uL, 0u, 50u, (0..49).map(::node), null),
            NodePage(1u, 7uL, 0u, 51u, (0..49).map(::node), 50u),
            NodePage(1u, 7uL, 50u, 51u, listOf(node(50)), null),
            NodePage(1u, 7uL, 100u, 200u, (100..149).map(::node), 150u),
        )
        for (expected in cases) assertEquals(expected, NodePageWire.decode(NodePageWire.encode(expected)))
    }

    @Test fun invalidPageCountOffsetAndContinuationAreRejected() {
        invalid { NodePageWire.encode(lastPage().copy(nodes = (149..199).map(::node))) }
        invalid { NodePageWire.encode(lastPage().copy(nodeCount = 201u)) }
        invalid { NodePageWire.encode(lastPage().copy(offset = 151u)) }
        invalid { NodePageWire.encode(lastPage().copy(nextOffset = 200u)) }
        invalid { NodePageWire.encode(lastPage().copy(schemaVersion = 2u)) }
        invalid { NodePageWire.encode(lastPage().copy(nodes = emptyList())) }
    }

    @Test fun trailingAndOversizedBinaryDataNeverBecomeAPage() {
        invalid { NodePageWire.decode(NodePageWire.encode(lastPage()) + byteArrayOf(1)) }
        invalid { NodePageWire.decode(ByteArray(ControlCodec.MAX_CONTROL_BYTES + 1)) }
    }
    private fun invalid(block: () -> Unit) {
        try { block(); fail("Invalid node page was accepted") } catch (_: NodePageWireException) { }
    }
}
