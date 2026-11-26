package net.aptist.loft.service

import net.aptist.loft.core.generated.NodePage
import net.aptist.loft.core.generated.NodeSummary
import net.aptist.loft.core.generated.ProtocolKind
import net.aptist.loft.foundation.ControlCodec
import java.io.*
import java.nio.ByteBuffer
import java.nio.CharBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.util.Collections

class NodePageWireException : IllegalArgumentException("INVALID_NODE_PAGE_PAYLOAD")
object NodePageWire {
    private const val MAGIC = 0x4C464E31
    fun encode(page: NodePage): ByteArray {
        validate(page)
        try {
            val bytes = ByteArrayOutputStream()
            DataOutputStream(bytes).use { output ->
                output.writeInt(MAGIC); output.writeInt(page.schemaVersion.toInt()); output.writeLong(page.generation.toLong())
                output.writeInt(page.offset.toInt()); output.writeInt(page.nodeCount.toInt()); output.writeInt(page.nodes.size)
                page.nodes.forEach { node ->
                    output.text(node.id, 64); output.text(node.label, 64); output.text(node.protocol.name, 32); output.text(node.endpoint, 300)
                    output.writeInt(node.udpMin.toInt()); output.writeInt(node.udpMax.toInt()); output.writeBoolean(node.credentialMaterialPresent)
                }
                output.writeBoolean(page.nextOffset != null)
                page.nextOffset?.let { output.writeInt(it.toInt()) }
            }
            if (bytes.size() > ControlCodec.MAX_CONTROL_BYTES) throw NodePageWireException()
            return bytes.toByteArray()
        } catch (failure: NodePageWireException) { throw failure }
        catch (_: Exception) { throw NodePageWireException() }
    }
    fun decode(payload: ByteArray): NodePage {
        if (payload.isEmpty() || payload.size > ControlCodec.MAX_CONTROL_BYTES) throw NodePageWireException()
        try {
            DataInputStream(ByteArrayInputStream(payload)).use { input ->
                if (input.readInt() != MAGIC) throw NodePageWireException()
                val schema = input.readInt().toUInt(); val generation = input.readLong().toULong()
                val offset = input.readInt().toUInt(); val count = input.readInt().toUInt(); val rows = input.readInt()
                if (rows !in 0..50) throw NodePageWireException()
                val nodes = List(rows) {
                    NodeSummary(input.text(64), input.text(64), ProtocolKind.valueOf(input.text(32)), input.text(300),
                        input.readInt().toUInt(), input.readInt().toUInt(), input.strictBoolean())
                }
                val next = if (input.strictBoolean()) input.readInt().toUInt() else null
                if (input.available() != 0) throw NodePageWireException()
                return NodePage(schema, generation, offset, count, Collections.unmodifiableList(ArrayList(nodes)), next).also(::validate)
            }
        } catch (failure: NodePageWireException) { throw failure }
        catch (_: Exception) { throw NodePageWireException() }
    }
    private fun validate(page: NodePage) {
        if (page.schemaVersion != 1u || page.nodeCount > 200u || page.offset > 150u || page.offset % 50u != 0u) throw NodePageWireException()
        if (page.nodeCount == 0u) {
            if (page.offset != 0u || page.nodes.isNotEmpty() || page.nextOffset != null) throw NodePageWireException()
            return
        }
        if (page.offset >= page.nodeCount) throw NodePageWireException()
        val rows = minOf(50u, page.nodeCount - page.offset).toInt()
        val next = if (page.nodeCount > page.offset + 50u) page.offset + 50u else null
        if (page.nodes.size != rows || page.nextOffset != next) throw NodePageWireException()
    }
    private fun DataOutputStream.text(value: String, limit: Int) {
        if (value.length > limit) throw NodePageWireException()
        val encoded = StandardCharsets.UTF_8.newEncoder().onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT).encode(CharBuffer.wrap(value))
        if (encoded.remaining() > limit) throw NodePageWireException()
        val bytes = ByteArray(encoded.remaining()).also { encoded.get(it) }
        writeInt(bytes.size); write(bytes)
    }
    private fun DataInputStream.text(limit: Int): String {
        val size = readInt()
        if (size !in 0..limit || size > available()) throw NodePageWireException()
        val bytes = ByteArray(size).also { readFully(it) }
        return StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString()
    }
    private fun DataInputStream.strictBoolean(): Boolean = when (readUnsignedByte()) { 0 -> false; 1 -> true; else -> throw NodePageWireException() }
}
