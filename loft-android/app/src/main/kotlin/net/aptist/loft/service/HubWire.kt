package net.aptist.loft.service

import net.aptist.loft.core.generated.HubMailAttachment
import net.aptist.loft.core.generated.HubMailMessage
import net.aptist.loft.core.generated.HubMailPage
import net.aptist.loft.core.generated.HubMailSummary
import net.aptist.loft.core.generated.HubSession
import net.aptist.loft.core.generated.HubSnapshot
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.IOException
import java.nio.ByteBuffer

internal class HubResult(
    val snapshot: HubSnapshot,
    val browserUrl: String? = null,
    val page: HubMailPage? = null,
    val message: HubMailMessage? = null,
)

internal object HubWire {
    const val MAX_BYTES = 60 * 1024
    private const val MAX_TEXT = 16 * 1024

    internal fun encode(result: HubResult): ByteArray {
        val bytes = ByteArrayOutputStream()
        DataOutputStream(bytes).use { out ->
            out.writeByte(2)
            with(result.snapshot) {
                out.writeLong(generation.toLong())
                out.optional(origin); out.optional(issuer)
                out.writeBoolean(mailSupported); out.writeBoolean(transactionPending)
                out.writeBoolean(session != null)
                session?.let { out.text(it.subject); out.optional(it.email); out.writeBoolean(it.mailAccess); out.writeInt(it.expiresInSeconds.toInt()); out.writeBoolean(it.mailAvailable) }
            }
            out.optional(result.browserUrl)
            out.writeBoolean(result.page != null)
            result.page?.let { page ->
                out.text(page.folder); out.optional(page.cursor)
                out.writeInt(page.messages.size)
                page.messages.forEach { out.summary(it) }
            }
            out.writeBoolean(result.message != null)
            result.message?.let { message ->
                out.summary(message.summary); out.text(message.text); out.writeBoolean(message.truncated)
                out.writeInt(message.attachments.size)
                message.attachments.forEach { out.text(it.id); out.text(it.filename); out.text(it.mime); out.writeInt(it.size.toInt()) }
            }
        }
        if (bytes.size() !in 1..MAX_BYTES) throw IOException()
        return bytes.toByteArray()
    }

    internal fun decode(bytes: ByteArray): HubResult {
        if (bytes.size !in 1..MAX_BYTES) throw IOException()
        val input = DataInputStream(ByteArrayInputStream(bytes))
        if (input.readUnsignedByte() != 2) throw IOException()
        val generation = input.readLong().toULong()
        val origin = input.optional(); val issuer = input.optional()
        val mailSupported = input.flag(); val transactionPending = input.flag()
        val session = if (input.flag()) {
            val subject = input.text()
            val email = input.optional()
            val mailAccess = input.flag()
            val remaining = input.readInt().toUInt()
            HubSession(subject, email, mailAccess, input.flag(), remaining)
        } else null
        val snapshot = HubSnapshot(generation, origin, issuer, mailSupported, transactionPending, session)
        val browser = input.optional()
        val page = if (input.flag()) {
            val folder = input.text(); val cursor = input.optional()
            HubMailPage(folder, List(input.count(20)) { input.summary() }, cursor)
        } else null
        val message = if (input.flag()) {
            val summary = input.summary(); val text = input.text(); val truncated = input.flag()
            val attachments = List(input.count(100)) {
                HubMailAttachment(input.text(), input.text(), input.text(), input.readInt().toUInt())
            }
            HubMailMessage(summary, text, truncated, attachments)
        } else null
        if (input.available() != 0) throw IOException()
        return HubResult(snapshot, browser, page, message)
    }

    private fun DataOutputStream.summary(row: HubMailSummary) {
        text(row.id); text(row.from); text(row.to); text(row.subject); text(row.receivedAt); writeBoolean(row.read)
        text(row.folder); writeInt(row.attachmentCount.toInt()); writeInt(row.size.toInt())
    }
    private fun DataInputStream.summary() = HubMailSummary(text(), text(), text(), text(), text(), flag(), text(), readInt().toUInt(), readInt().toUInt())
    private fun DataOutputStream.optional(value: String?) { writeBoolean(value != null); value?.let { text(it) } }
    private fun DataInputStream.optional(): String? = if (flag()) text() else null
    private fun DataOutputStream.text(value: String) {
        val utf8 = value.toByteArray(Charsets.UTF_8)
        try {
            if (utf8.size > MAX_TEXT) throw IOException()
            writeInt(utf8.size); write(utf8)
        } finally { utf8.fill(0) }
    }
    private fun DataInputStream.text(): String {
        val size = count(minOf(MAX_TEXT, available() - Int.SIZE_BYTES))
        val bytes = ByteArray(size)
        try {
            readFully(bytes)
            return Charsets.UTF_8.newDecoder().decode(ByteBuffer.wrap(bytes)).toString()
        } finally { bytes.fill(0) }
    }
    private fun DataInputStream.count(max: Int): Int = readInt().also { if (it !in 0..max) throw IOException() }
    private fun DataInputStream.flag(): Boolean = when (readUnsignedByte()) {
        0 -> false
        1 -> true
        else -> throw IOException()
    }
}
