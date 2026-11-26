package net.aptist.loft.service

import net.aptist.loft.core.generated.VaultAlgorithm
import net.aptist.loft.core.generated.VaultDraft
import net.aptist.loft.core.generated.VaultEntry
import net.aptist.loft.core.generated.VaultKind
import net.aptist.loft.core.generated.VaultPage
import net.aptist.loft.core.generated.VaultReveal
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.IOException
import java.nio.ByteBuffer

internal sealed interface VaultCommand {
    data class ListPage(val archived: Boolean, val offset: UInt, val generation: ULong?) : VaultCommand
    class Import(val uri: ByteArray) : VaultCommand
    class Save(val draft: VaultDraft) : VaultCommand
    data class Archive(val id: String, val archived: Boolean) : VaultCommand
    data class Reveal(val id: String) : VaultCommand
    class Sync(val passphrase: ByteArray) : VaultCommand

    fun clear() {
        when (this) {
            is Import -> uri.fill(0)
            is Save -> draft.secret?.fill(0)
            is Sync -> passphrase.fill(0)
            else -> Unit
        }
    }
}

internal sealed interface VaultResult {
    class Page(val content: VaultPage) : VaultResult
    class Reveal(val value: VaultReveal, val validUntilElapsed: Long) : VaultResult
}

internal object VaultWire {
    const val MAX_FRAME = 60 * 1024
    private const val MAX_FIELD = 4096
    private const val PAGE_ROWS = 30

    fun command(command: VaultCommand): ByteArray = encode {
        when (command) {
            is VaultCommand.ListPage -> { writeByte(1); writeBoolean(command.archived); writeInt(command.offset.toInt()); optionalNumber(command.generation) }
            is VaultCommand.Import -> { writeByte(2); bytes(command.uri) }
            is VaultCommand.Save -> {
                writeByte(3)
                with(command.draft) {
                    optionalText(id); writeByte(kind.ordinal); text(label); text(account); text(issuer)
                    writeByte(algorithm?.ordinal ?: -1); optionalInt(digits); optionalInt(period)
                    writeBoolean(secret != null); secret?.let { bytes(it) }
                }
            }
            is VaultCommand.Archive -> { writeByte(4); text(command.id); writeBoolean(command.archived) }
            is VaultCommand.Reveal -> { writeByte(5); text(command.id) }
            is VaultCommand.Sync -> { writeByte(6); bytes(command.passphrase) }
        }
    }

    fun readCommand(frame: ByteArray): VaultCommand = decode(frame) {
        when (readUnsignedByte()) {
            1 -> VaultCommand.ListPage(flag(), readInt().toUInt(), optionalNumber())
            2 -> VaultCommand.Import(bytes())
            3 -> {
                val id = optionalText(); val kind = kind(); val label = text(); val account = text(); val issuer = text()
                val algorithm = algorithm(); val digits = optionalInt(); val period = optionalInt()
                VaultCommand.Save(VaultDraft(id, kind, label, account, issuer, if (flag()) bytes() else null, algorithm, digits, period))
            }
            4 -> VaultCommand.Archive(text(), flag())
            5 -> VaultCommand.Reveal(text())
            6 -> VaultCommand.Sync(bytes())
            else -> throw IOException()
        }.also { if (available() != 0) { it.clear(); throw IOException() } }
    }

    fun result(result: VaultResult): ByteArray = encode {
        when (result) {
            is VaultResult.Page -> {
                writeByte(1)
                with(result.content) {
                    writeLong(generation.toLong()); writeInt(offset.toInt()); optionalInt(nextOffset)
                    if (entries.size > PAGE_ROWS) throw IOException()
                    writeInt(entries.size)
                    entries.forEach { row ->
                        text(row.id); writeByte(row.kind.ordinal); text(row.label); text(row.account); text(row.issuer)
                        writeBoolean(row.archived); writeByte(row.algorithm?.ordinal ?: -1); optionalInt(row.digits); optionalInt(row.period)
                    }
                }
            }
            is VaultResult.Reveal -> {
                writeByte(2); writeLong(result.validUntilElapsed); optionalInt(result.value.validForSeconds); bytes(result.value.value)
            }
        }
    }

    fun readResult(frame: ByteArray): VaultResult = decode(frame) {
        when (readUnsignedByte()) {
            1 -> {
                val generation = readLong().toULong(); val offset = readInt().toUInt(); val next = optionalInt()
                val count = readInt().also { if (it !in 0..PAGE_ROWS) throw IOException() }
                val rows = List(count) { VaultEntry(text(), kind(), text(), text(), text(), flag(), algorithm(), optionalInt(), optionalInt()) }
                VaultResult.Page(VaultPage(generation, offset, rows, next))
            }
            2 -> {
                val expiry = readLong()
                val seconds = optionalInt()
                VaultResult.Reveal(VaultReveal(bytes(), seconds), expiry).also {
                    if (available() != 0) { it.value.value.fill(0); throw IOException() }
                }
            }
            else -> throw IOException()
        }
    }

    private inline fun encode(block: DataOutputStream.() -> Unit): ByteArray {
        val output = VaultOutput()
        return try {
            DataOutputStream(output).use { it.writeByte(1); it.block() }
            if (output.size() > MAX_FRAME) throw IOException()
            output.toByteArray()
        } finally { output.clear() }
    }
    private inline fun <T> decode(frame: ByteArray, block: DataInputStream.() -> T): T {
        if (frame.size !in 2..MAX_FRAME) throw IOException()
        return DataInputStream(ByteArrayInputStream(frame)).use {
            if (it.readUnsignedByte() != 1) throw IOException()
            val result = it.block()
            if (it.available() != 0) throw IOException()
            result
        }
    }
    private class VaultOutput : ByteArrayOutputStream() { fun clear() { buf.fill(0) } }
    private fun DataOutputStream.bytes(value: ByteArray) { if (value.size > MAX_FIELD) throw IOException(); writeInt(value.size); write(value) }
    private fun DataInputStream.bytes(): ByteArray {
        val size = readInt()
        if (size !in 0..minOf(MAX_FIELD, available())) throw IOException()
        return ByteArray(size).also(::readFully)
    }
    private fun DataOutputStream.text(value: String) { val data = value.toByteArray(); try { bytes(data) } finally { data.fill(0) } }
    private fun DataInputStream.text(): String { val data = bytes(); return try { Charsets.UTF_8.newDecoder().decode(ByteBuffer.wrap(data)).toString() } finally { data.fill(0) } }
    private fun DataOutputStream.optionalText(value: String?) { writeBoolean(value != null); value?.let { text(it) } }
    private fun DataInputStream.optionalText(): String? = if (flag()) text() else null
    private fun DataOutputStream.optionalInt(value: UInt?) { writeBoolean(value != null); value?.let { writeInt(it.toInt()) } }
    private fun DataInputStream.optionalInt(): UInt? = if (flag()) readInt().toUInt() else null
    private fun DataOutputStream.optionalNumber(value: ULong?) { writeBoolean(value != null); value?.let { writeLong(it.toLong()) } }
    private fun DataInputStream.optionalNumber(): ULong? = if (flag()) readLong().toULong() else null
    private fun DataInputStream.flag() = when (readUnsignedByte()) { 0 -> false; 1 -> true; else -> throw IOException() }
    private fun DataInputStream.kind() = VaultKind.entries.getOrNull(readUnsignedByte()) ?: throw IOException()
    private fun DataInputStream.algorithm(): VaultAlgorithm? = readByte().toInt().let { if (it == -1) null else VaultAlgorithm.entries.getOrNull(it) ?: throw IOException() }
}
