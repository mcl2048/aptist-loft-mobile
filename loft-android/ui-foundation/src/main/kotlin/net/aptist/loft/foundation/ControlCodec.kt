package net.aptist.loft.foundation

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.IOException
import java.nio.ByteBuffer
import java.nio.CharBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets

sealed interface CoreCommand {
    class ImportNode(val raw: String) : CoreCommand { override fun toString() = "ImportNode(<redacted>)" }
    class RemoveNode(val id: String) : CoreCommand
    class StageServer(val raw: String) : CoreCommand { override fun toString() = "StageServer(<redacted>)" }
    data object ResetServer : CoreCommand
    class SetRouting(val enabled: Boolean, val packageNames: List<String>) : CoreCommand
    class Connect(val nodeId: String, val expectedGeneration: ULong = 0uL) : CoreCommand
    class SetNetworkPrivacyPolicy(val policy: NetworkPrivacyDraft, val expectedGeneration: ULong) : CoreCommand {
        override fun toString() = "SetNetworkPrivacyPolicy(<redacted>)"
    }
    data object Stop : CoreCommand
}

enum class ControlProblem { TOO_LARGE, INVALID_COMMAND, INVALID_UTF8, TOO_MANY_APPS }
class ControlMessageException(val problem: ControlProblem) : IllegalArgumentException(problem.name)

object ControlCodec {
    const val MAX_CONTROL_BYTES = 60 * 1024
    private const val MAGIC = 0x4C465431
    fun encode(command: CoreCommand): ByteArray {
        val output = ByteArrayOutputStream()
        DataOutputStream(output).use { stream ->
            stream.writeInt(MAGIC)
            when (command) {
                is CoreCommand.ImportNode -> { stream.writeByte(1); stream.writeBoundedString(command.raw) }
                is CoreCommand.RemoveNode -> { stream.writeByte(2); stream.writeBoundedString(command.id) }
                is CoreCommand.StageServer -> { stream.writeByte(3); stream.writeBoundedString(command.raw) }
                CoreCommand.ResetServer -> stream.writeByte(4)
                is CoreCommand.SetRouting -> {
                    if (command.packageNames.size > 100) throw ControlMessageException(ControlProblem.TOO_MANY_APPS)
                    stream.writeByte(5); stream.writeByte(if (command.enabled) 1 else 0)
                    stream.writeInt(command.packageNames.size)
                    command.packageNames.forEach { stream.writeBoundedString(it) }
                }
                is CoreCommand.Connect -> { stream.writeByte(6); stream.writeBoundedString(command.nodeId); stream.writeLong(command.expectedGeneration.toLong()) }
                is CoreCommand.SetNetworkPrivacyPolicy -> {
                    stream.writeByte(8); stream.writeLong(command.expectedGeneration.toLong())
                    val policy = command.policy
                    stream.writeByte(policy.dnsMode.ordinal); stream.writeByte(policy.dnsLeakPolicy.ordinal); stream.writeByte(policy.webrtcPolicy.ordinal)
                    stream.writeBoundedString(policy.resolverEndpoint, 64)
                    with(policy.dnsLimits) {
                        listOf(mapMaxEntries, mapMaxBytes, ttlSeconds, maxQueryBytes, maxResponseBytes).forEach { stream.writeInt(it.toInt()) }
                    }
                    with(policy.hydra) {
                        stream.writeBoolean(enabled); stream.writeBoolean(autoJitter)
                        listOf(rotationSeconds, rotationJitterPercent, chunkMinPercent, burstMinRecords, burstMaxRecords, paddingGapMaxRecords)
                            .forEach { stream.writeInt(it.toInt()) }
                    }
                }
                CoreCommand.Stop -> stream.writeByte(7)
            }
        }
        if (output.size() > MAX_CONTROL_BYTES) throw ControlMessageException(ControlProblem.TOO_LARGE)
        return output.toByteArray()
    }
    fun decode(bytes: ByteArray): CoreCommand {
        if (bytes.size > MAX_CONTROL_BYTES) throw ControlMessageException(ControlProblem.TOO_LARGE)
        if (bytes.size < 5) throw ControlMessageException(ControlProblem.INVALID_COMMAND)
        try {
            DataInputStream(ByteArrayInputStream(bytes)).use { input ->
                if (input.readInt() != MAGIC) throw ControlMessageException(ControlProblem.INVALID_COMMAND)
                val command = when (input.readUnsignedByte()) {
                    1 -> CoreCommand.ImportNode(input.readBoundedString())
                    2 -> CoreCommand.RemoveNode(input.readBoundedString())
                    3 -> CoreCommand.StageServer(input.readBoundedString())
                    4 -> CoreCommand.ResetServer
                    5 -> {
                        val enabledByte = input.readUnsignedByte()
                        if (enabledByte !in 0..1) throw ControlMessageException(ControlProblem.INVALID_COMMAND)
                        val count = input.readInt()
                        if (count !in 0..100) throw ControlMessageException(ControlProblem.INVALID_COMMAND)
                        CoreCommand.SetRouting(enabledByte == 1, List(count) { input.readBoundedString() })
                    }
                    6 -> CoreCommand.Connect(input.readBoundedString(), input.readLong().toULong())
                    7 -> CoreCommand.Stop
                    8 -> {
                        val generation = input.readLong().toULong()
                        val mode = NetworkDnsMode.entries.getOrNull(input.readUnsignedByte()) ?: invalid()
                        val dnsLeak = NetworkLeakPolicy.entries.getOrNull(input.readUnsignedByte()) ?: invalid()
                        val webrtc = NetworkLeakPolicy.entries.getOrNull(input.readUnsignedByte()) ?: invalid()
                        val resolver = input.readBoundedString(64)
                        val limits = DnsLimitsDraft(input.readInt().toUInt(), input.readInt().toUInt(), input.readInt().toUInt(),
                            input.readInt().toUInt(), input.readInt().toUInt())
                        val hydra = HydraDraft(input.strictBoolean(), input.strictBoolean(), input.readInt().toUInt(), input.readInt().toUInt(),
                            input.readInt().toUInt(), input.readInt().toUInt(), input.readInt().toUInt(), input.readInt().toUInt())
                        CoreCommand.SetNetworkPrivacyPolicy(NetworkPrivacyDraft(mode, dnsLeak, webrtc, resolver, limits, hydra), generation)
                    }
                    else -> throw ControlMessageException(ControlProblem.INVALID_COMMAND)
                }
                if (input.available() != 0) throw ControlMessageException(ControlProblem.INVALID_COMMAND)
                return command
            }
        } catch (error: IOException) {
            throw ControlMessageException(ControlProblem.INVALID_COMMAND)
        }
    }
    private fun DataOutputStream.writeBoundedString(value: String, limit: Int = MAX_CONTROL_BYTES - 9) {
        if (value.length > limit) throw ControlMessageException(ControlProblem.TOO_LARGE)
        val bytes = try {
            val buffer = StandardCharsets.UTF_8.newEncoder().onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT).encode(CharBuffer.wrap(value))
            ByteArray(buffer.remaining()).also { buffer.get(it) }
        } catch (failure: CharacterCodingException) { throw ControlMessageException(ControlProblem.INVALID_UTF8) }
        if (bytes.size > limit || size() + bytes.size + 4 > MAX_CONTROL_BYTES) {
            throw ControlMessageException(ControlProblem.TOO_LARGE)
        }
        writeInt(bytes.size); write(bytes)
    }
    private fun DataInputStream.readBoundedString(limit: Int = MAX_CONTROL_BYTES - 9): String {
        val length = readInt()
        if (length < 0 || length > limit || length > available()) throw ControlMessageException(ControlProblem.INVALID_COMMAND)
        val bytes = ByteArray(length).also { readFully(it) }
        return try {
            StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString()
        } catch (failure: CharacterCodingException) { throw ControlMessageException(ControlProblem.INVALID_UTF8) }
    }
    private fun DataInputStream.strictBoolean(): Boolean = when (readUnsignedByte()) { 0 -> false; 1 -> true; else -> invalid() }
    private fun invalid(): Nothing = throw ControlMessageException(ControlProblem.INVALID_COMMAND)
}

object BinderAdmission {
    fun allowed(ownUid: Int, callerUid: Int, size: Int): Boolean = ownUid == callerUid && size in 5..ControlCodec.MAX_CONTROL_BYTES
}
