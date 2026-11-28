package net.aptist.loft.service

import net.aptist.loft.core.generated.NoteDetail
import net.aptist.loft.core.generated.NoteSummary
import net.aptist.loft.core.generated.NoteTag
import net.aptist.loft.core.generated.NotesDraft
import net.aptist.loft.core.generated.NotesPage
import net.aptist.loft.core.generated.NotesSyncStatus
import net.aptist.loft.core.generated.ProtectionStatus
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.IOException
import java.nio.ByteBuffer

internal enum class ProtectedArea { SETTINGS, VAULT, NOTES }

internal sealed interface ProtectedCommand {
    data object Open : ProtectedCommand
    class Configure(val current: ByteArray?, val replacement: ByteArray?, val biometric: Boolean) : ProtectedCommand
    class Pin(val value: ByteArray) : ProtectedCommand
    data object Biometric : ProtectedCommand

    fun clear() {
        when (this) {
            is Configure -> { current?.fill(0); replacement?.fill(0) }
            is Pin -> value.fill(0)
            is NotesCommand.SyncConfigure -> recoveryCode?.fill(0)
            else -> Unit
        }
    }
}

internal sealed interface NotesCommand : ProtectedCommand {
    data class ListPage(val archived: Boolean, val query: String, val tag: String?, val offset: UInt, val expectedGeneration: ULong?) : NotesCommand
    data class Detail(val id: String) : NotesCommand
    class Save(val draft: NotesDraft) : NotesCommand
    data class Archive(val id: String, val archived: Boolean) : NotesCommand
    data class Delete(val id: String) : NotesCommand
    data class Tags(val archived: Boolean) : NotesCommand
    data object SyncStatus : NotesCommand
    class SyncConfigure(val recoveryCode: ByteArray?) : NotesCommand
    data object SyncDisable : NotesCommand
}

internal sealed interface ProtectedResult {
    class Access(val unlocked: Boolean, val status: ProtectionStatus) : ProtectedResult
}

internal sealed interface NotesResult : ProtectedResult {
    class Page(val value: NotesPage) : NotesResult
    class Detail(val value: NoteDetail) : NotesResult
    class Saved(val value: NoteSummary) : NotesResult
    class Tags(val value: List<NoteTag>) : NotesResult
    class SyncStatus(val value: NotesSyncStatus) : NotesResult
    class SyncConfigured(val code: String?) : NotesResult
}

/** Bounded, strict wire shared by the private protection and notes result callback. */
internal object ProtectedWire {
    private const val TITLE = 240
    private const val BODY = 25_600
    private const val ICON = 64
    private const val TAGS = 1_024
    private const val TAG = 64
    private const val PREVIEW = 560
    private const val QUERY = 256
    private const val ID = 22
    private const val PIN = 6
    private const val RECOVERY_CODE = 43
    private const val MAX_TAGS = 20
    private const val PAGE_ROWS = 20

    fun command(command: ProtectedCommand): ByteArray = encode {
        when (command) {
            ProtectedCommand.Open -> writeByte(1)
            is ProtectedCommand.Configure -> {
                writeByte(2); optionalBytes(command.current, PIN); optionalBytes(command.replacement, PIN); writeBoolean(command.biometric)
            }
            is ProtectedCommand.Pin -> { writeByte(3); bytes(command.value, PIN) }
            ProtectedCommand.Biometric -> writeByte(4)
            is NotesCommand.ListPage -> {
                writeByte(10); writeBoolean(command.archived); text(command.query, QUERY)
                optionalText(command.tag, TAG); writeInt(command.offset.toInt()); optionalLong(command.expectedGeneration)
            }
            is NotesCommand.Detail -> { writeByte(11); text(command.id, ID) }
            is NotesCommand.Save -> {
                writeByte(12)
                with(command.draft) {
                    optionalText(id, ID); text(title, TITLE); text(body, BODY)
                    optionalText(icon, ICON); text(tags, TAGS); optionalText(expectedVersion, ID)
                }
            }
            is NotesCommand.Archive -> { writeByte(13); text(command.id, ID); writeBoolean(command.archived) }
            is NotesCommand.Delete -> { writeByte(14); text(command.id, ID) }
            is NotesCommand.Tags -> { writeByte(15); writeBoolean(command.archived) }
            NotesCommand.SyncStatus -> writeByte(16)
            is NotesCommand.SyncConfigure -> { writeByte(17); optionalBytes(command.recoveryCode, RECOVERY_CODE) }
            NotesCommand.SyncDisable -> writeByte(18)
        }
    }

    fun readCommand(frame: ByteArray): ProtectedCommand = decode(frame) {
        when (readUnsignedByte()) {
            1 -> ProtectedCommand.Open
            2 -> {
                val current = optionalBytes(PIN)
                var replacement: ByteArray? = null
                try {
                    replacement = optionalBytes(PIN)
                    ProtectedCommand.Configure(current, replacement, flag())
                } catch (failure: IOException) {
                    current?.fill(0); replacement?.fill(0); throw failure
                }
            }
            3 -> ProtectedCommand.Pin(bytes(PIN))
            4 -> ProtectedCommand.Biometric
            10 -> NotesCommand.ListPage(flag(), text(QUERY), optionalText(TAG), readInt().toUInt(), optionalLong())
            11 -> NotesCommand.Detail(text(ID))
            12 -> NotesCommand.Save(NotesDraft(optionalText(ID), text(TITLE), text(BODY), optionalText(ICON), text(TAGS), optionalText(ID)))
            13 -> NotesCommand.Archive(text(ID), flag())
            14 -> NotesCommand.Delete(text(ID))
            15 -> NotesCommand.Tags(flag())
            16 -> NotesCommand.SyncStatus
            17 -> NotesCommand.SyncConfigure(optionalBytes(RECOVERY_CODE))
            18 -> NotesCommand.SyncDisable
            else -> throw IOException()
        }.also { if (available() != 0) { it.clear(); throw IOException() } }
    }

    fun result(result: ProtectedResult): ByteArray = encode {
        when (result) {
            is ProtectedResult.Access -> {
                writeByte(1); writeBoolean(result.unlocked)
                writeBoolean(result.status.enabled); writeBoolean(result.status.biometricEnabled); optionalLong(result.status.retryAt)
            }
            is NotesResult.Page -> {
                writeByte(10)
                with(result.value) {
                    writeLong(generation.toLong())
                    writeBoolean(nextOffset != null); nextOffset?.let { writeInt(it.toInt()) }
                    count(entries.size, PAGE_ROWS); entries.forEach { summary(it) }
                }
            }
            is NotesResult.Detail -> { writeByte(11); summary(result.value.summary); text(result.value.body, BODY) }
            is NotesResult.Saved -> { writeByte(12); summary(result.value) }
            is NotesResult.Tags -> {
                writeByte(13); count(result.value.size, MAX_TAGS)
                result.value.forEach { text(it.name, TAG); writeInt(it.count.toInt()) }
            }
            is NotesResult.SyncStatus -> { writeByte(14); writeBoolean(result.value.available); writeBoolean(result.value.configured) }
            is NotesResult.SyncConfigured -> { writeByte(15); optionalText(result.code, RECOVERY_CODE) }
        }
    }

    fun readResult(frame: ByteArray): ProtectedResult = decode(frame) {
        when (readUnsignedByte()) {
            1 -> ProtectedResult.Access(flag(), ProtectionStatus(flag(), flag(), optionalLong()))
            10 -> {
                val generation = readLong().toULong()
                val next = if (flag()) readInt().toUInt() else null
                NotesResult.Page(NotesPage(generation, List(count(PAGE_ROWS)) { summary() }, next))
            }
            11 -> NotesResult.Detail(NoteDetail(summary(), text(BODY)))
            12 -> NotesResult.Saved(summary())
            13 -> NotesResult.Tags(List(count(MAX_TAGS)) { NoteTag(text(TAG), readInt().toUInt()) })
            14 -> NotesResult.SyncStatus(NotesSyncStatus(flag(), flag()))
            15 -> NotesResult.SyncConfigured(optionalText(RECOVERY_CODE))
            else -> throw IOException()
        }
    }

    private fun DataOutputStream.summary(value: NoteSummary) {
        text(value.id, ID); text(value.title, TITLE); text(value.preview, PREVIEW); optionalText(value.icon, ICON)
        count(value.tags.size, MAX_TAGS); value.tags.forEach { text(it, TAG) }
        writeLong(value.createdAt.toLong()); writeLong(value.updatedAt.toLong())
        writeBoolean(value.archived); text(value.version, ID)
    }
    private fun DataInputStream.summary(): NoteSummary = NoteSummary(
        text(ID), text(TITLE), text(PREVIEW), optionalText(ICON), List(count(MAX_TAGS)) { text(TAG) },
        readLong().toULong(), readLong().toULong(), flag(), text(ID),
    )
    private inline fun encode(block: DataOutputStream.() -> Unit): ByteArray {
        val output = ClearOutput()
        return try {
            DataOutputStream(output).use { it.writeByte(1); it.block() }
            if (output.size() > VaultWire.MAX_FRAME) throw IOException()
            output.toByteArray()
        } finally { output.clear() }
    }
    private inline fun <T> decode(frame: ByteArray, block: DataInputStream.() -> T): T {
        if (frame.size !in 2..VaultWire.MAX_FRAME) throw IOException()
        return DataInputStream(ByteArrayInputStream(frame)).use {
            if (it.readUnsignedByte() != 1) throw IOException()
            val result = it.block()
            if (it.available() != 0) throw IOException()
            result
        }
    }
    private class ClearOutput : ByteArrayOutputStream() { fun clear() { buf.fill(0) } }
    private fun DataOutputStream.count(value: Int, limit: Int) {
        if (value !in 0..limit) throw IOException()
        writeInt(value)
    }
    private fun DataInputStream.count(limit: Int): Int = readInt().also { if (it !in 0..limit) throw IOException() }
    private fun DataOutputStream.bytes(value: ByteArray, limit: Int) { count(value.size, limit); write(value) }
    private fun DataInputStream.bytes(limit: Int): ByteArray = ByteArray(count(minOf(limit, available() - 4))).also(::readFully)
    private fun DataOutputStream.text(value: String, limit: Int) {
        val data = value.toByteArray()
        try { bytes(data, limit) } finally { data.fill(0) }
    }
    private fun DataInputStream.text(limit: Int): String {
        val data = bytes(limit)
        return try { Charsets.UTF_8.newDecoder().decode(ByteBuffer.wrap(data)).toString() } finally { data.fill(0) }
    }
    private fun DataOutputStream.optionalBytes(value: ByteArray?, limit: Int) { writeBoolean(value != null); value?.let { bytes(it, limit) } }
    private fun DataInputStream.optionalBytes(limit: Int): ByteArray? = if (flag()) bytes(limit) else null
    private fun DataOutputStream.optionalText(value: String?, limit: Int) { writeBoolean(value != null); value?.let { text(it, limit) } }
    private fun DataInputStream.optionalText(limit: Int): String? = if (flag()) text(limit) else null
    private fun DataOutputStream.optionalLong(value: ULong?) { writeBoolean(value != null); value?.let { writeLong(it.toLong()) } }
    private fun DataInputStream.optionalLong(): ULong? = if (flag()) readLong().toULong() else null
    private fun DataInputStream.flag(): Boolean = when (readUnsignedByte()) { 0 -> false; 1 -> true; else -> throw IOException() }
}
