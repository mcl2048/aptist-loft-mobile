package net.aptist.loft.service

import net.aptist.loft.core.generated.NodePage

/** Binding, request and generation admission for one visible node-page query. */
class NodePageConsumer {
    private data class Query(val id: Long, val offset: UInt, val generation: ULong)
    private var binding: Long? = null
    private var query: Query? = null
    @Synchronized fun begin(binding: Long) { this.binding = binding; query = null }
    @Synchronized fun end() { binding = null; query = null }
    @Synchronized fun expect(binding: Long, requestId: Long, offset: UInt, generation: ULong): Boolean {
        if (this.binding != binding || requestId <= 0 || offset > 150u || offset % 50u != 0u) return false
        query = Query(requestId, offset, generation)
        return true
    }
    @Synchronized fun cancel() { query = null }
    @Synchronized fun current(binding: Long, requestId: Long): Boolean = this.binding == binding && query?.id == requestId
    @Synchronized fun consume(binding: Long, requestId: Long, payload: ByteArray): NodePage? {
        if (!current(binding, requestId)) return null
        val expected = checkNotNull(query)
        val page = NodePageWire.decode(payload)
        query = null
        return if (page.offset == expected.offset && page.generation == expected.generation) page else null
    }
}
