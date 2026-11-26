package net.aptist.loft.foundation

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.URI
import java.nio.ByteBuffer
import java.nio.CharBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.Collections

data class MailDeliveryScope(val productId: String, val serverProfileId: String, val issuer: String,
    val subject: String, val subscriptionGeneration: ULong) {
    override fun toString() = "MailDeliveryScope(<redacted>)"
}
data class MailNotificationEvent(val scope: MailDeliveryScope, val subscriptionId: String, val eventId: String,
    val countHint: Int, val issuedAtMillis: Long, val expiresAtMillis: Long) {
    override fun toString() = "MailNotificationEvent(<redacted>)"
}
data class MailDeliveryGrant(val scope: MailDeliveryScope, val subscriptionId: String, val eventId: String,
    val authorizedUntilMillis: Long) {
    override fun toString() = "MailDeliveryGrant(<redacted>)"
}

/** Future Rust adapter must confirm source/current subscription for each event. */
fun interface MailEventAuthority {
    fun confirm(event: MailNotificationEvent, nowMillis: Long): MailDeliveryGrant?
}
object DenyAllMailEvents : MailEventAuthority {
    override fun confirm(event: MailNotificationEvent, nowMillis: Long): MailDeliveryGrant? = null
}

data class MailNotificationSummary(val scope: MailDeliveryScope, val countHint: Int) {
    override fun toString() = "MailNotificationSummary(<redacted>)"
}
data class MailNotificationUsage(val pendingEvents: Int = 0, val pendingBytes: Int = 0,
    val recentEvents: Int = 0, val recentBytes: Int = 0)
enum class MailEventOffer { ACCEPTED, DENIED, INVALID, STALE, DUPLICATE, RESOURCE_BUSY }

object MailEventCodec {
    const val MAX_EVENT_BYTES = 2048
    private const val MAGIC = 0x4C4D4E31
    fun encode(event: MailNotificationEvent): ByteArray? = try {
        validate(event)
        val bytes = ByteArrayOutputStream()
        DataOutputStream(bytes).use { output ->
            output.writeInt(MAGIC)
            with(event.scope) {
                output.text(productId, 64); output.text(serverProfileId, 64); output.text(issuer, 512); output.text(subject, 128)
                output.writeLong(subscriptionGeneration.toLong())
            }
            output.text(event.subscriptionId, 128); output.text(event.eventId, 128)
            output.writeInt(event.countHint); output.writeLong(event.issuedAtMillis); output.writeLong(event.expiresAtMillis)
        }
        bytes.toByteArray().takeIf { it.size <= MAX_EVENT_BYTES }
    } catch (_: Exception) { null }

    fun decode(raw: ByteArray): MailNotificationEvent? {
        if (raw.isEmpty() || raw.size > MAX_EVENT_BYTES) return null
        return try {
            DataInputStream(ByteArrayInputStream(raw)).use { input ->
                require(input.readInt() == MAGIC)
                val scope = MailDeliveryScope(input.text(64), input.text(64), input.text(512), input.text(128), input.readLong().toULong())
                val event = MailNotificationEvent(scope, input.text(128), input.text(128), input.readInt(), input.readLong(), input.readLong())
                require(input.available() == 0)
                validate(event)
                event
            }
        } catch (_: Exception) { null }
    }

    private fun validate(event: MailNotificationEvent) {
        fun identifier(value: String, limit: Int) {
            require(value.length in 1..limit && value.all { it in 'a'..'z' || it in 'A'..'Z' || it in '0'..'9' || it in "._:-" })
        }
        with(event.scope) {
            identifier(productId, 64); identifier(serverProfileId, 64); identifier(subject, 128)
            require(subscriptionGeneration != 0uL && issuer.length in 1..512)
            val address = URI(issuer)
            require(address.scheme == "https" && address.host != null && address.rawUserInfo == null && address.rawQuery == null &&
                address.rawFragment == null && (address.port == -1 || address.port in 1..65535))
        }
        identifier(event.subscriptionId, 128); identifier(event.eventId, 128)
        require(event.countHint in 1..100 && event.issuedAtMillis >= 0L && event.expiresAtMillis > event.issuedAtMillis &&
            event.expiresAtMillis - event.issuedAtMillis <= 300000L)
    }

    private fun DataOutputStream.text(value: String, limit: Int) {
        require(value.length <= limit)
        val encoded = StandardCharsets.UTF_8.newEncoder().onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT).encode(CharBuffer.wrap(value))
        require(encoded.remaining() <= limit)
        writeInt(encoded.remaining())
        val bytes = ByteArray(encoded.remaining()).also { encoded.get(it) }
        write(bytes)
    }
    private fun DataInputStream.text(limit: Int): String {
        val length = readInt()
        require(length in 1..limit && length <= available())
        val bytes = ByteArray(length).also { readFully(it) }
        return StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString()
    }
}

/** Bounded delivery bookkeeping only; the default authority always denies. */
class MailNotificationGate(private val authority: MailEventAuthority = DenyAllMailEvents) {
    private data class Pending(val event: MailNotificationEvent, val bytes: Int)
    private val pending = ArrayDeque<Pending>()
    private val recent = LinkedHashMap<String, Long>()
    private var pendingBytes = 0

    @Synchronized fun offer(raw: ByteArray, nowMillis: Long): MailEventOffer {
        if (raw.isEmpty() || raw.size > MailEventCodec.MAX_EVENT_BYTES || nowMillis < 0L) return MailEventOffer.INVALID
        val event = MailEventCodec.decode(raw.copyOf()) ?: return MailEventOffer.INVALID
        prune(nowMillis)
        if (event.issuedAtMillis > nowMillis || event.expiresAtMillis <= nowMillis) return MailEventOffer.STALE
        if (!confirmed(event, nowMillis)) return MailEventOffer.DENIED
        val key = key(event)
        if (recent.containsKey(key)) return MailEventOffer.DUPLICATE
        if (pending.size >= 8 || pendingBytes + raw.size > 32768 || recent.size >= 128 || (recent.size + 1) * 72 > 32768) {
            return MailEventOffer.RESOURCE_BUSY
        }
        pending.addLast(Pending(event, raw.size))
        pendingBytes += raw.size
        recent[key] = event.expiresAtMillis
        return MailEventOffer.ACCEPTED
    }

    @Synchronized fun drain(nowMillis: Long): List<MailNotificationSummary> {
        if (nowMillis < 0L) return emptyList()
        prune(nowMillis)
        val summaries = LinkedHashMap<MailDeliveryScope, Int>()
        while (pending.isNotEmpty()) {
            val next = pending.removeFirst()
            pendingBytes -= next.bytes
            if (!confirmed(next.event, nowMillis)) continue
            summaries[next.event.scope] = ((summaries[next.event.scope] ?: 0) + next.event.countHint).coerceAtMost(100)
        }
        return Collections.unmodifiableList(summaries.map { (scope, hint) -> MailNotificationSummary(scope, hint) })
    }

    @Synchronized fun revoke() { pending.clear(); recent.clear(); pendingBytes = 0 }
    @Synchronized fun usage() = MailNotificationUsage(pending.size, pendingBytes, recent.size, recent.size * 72)

    private fun confirmed(event: MailNotificationEvent, nowMillis: Long): Boolean {
        val grant = try { authority.confirm(event, nowMillis) } catch (_: Exception) { null } catch (_: LinkageError) { null }
        return grant != null && grant.scope == event.scope && grant.subscriptionId == event.subscriptionId && grant.eventId == event.eventId &&
            event.issuedAtMillis <= nowMillis && event.expiresAtMillis > nowMillis && grant.authorizedUntilMillis > nowMillis &&
            grant.authorizedUntilMillis >= event.expiresAtMillis
    }

    private fun prune(nowMillis: Long) {
        val pendingEntries = pending.iterator()
        while (pendingEntries.hasNext()) {
            val value = pendingEntries.next()
            if (value.event.expiresAtMillis <= nowMillis) { pendingBytes -= value.bytes; pendingEntries.remove() }
        }
        val recentEntries = recent.iterator()
        while (recentEntries.hasNext()) if (recentEntries.next().value <= nowMillis) recentEntries.remove()
    }

    // Hash only opaque scope/event identities, preserving explicit boundaries.
    // The recent ledger stores 64 ASCII digest bytes + 8 expiry bytes per entry.
    private fun key(event: MailNotificationEvent): String {
        val digest = MessageDigest.getInstance("SHA-256")
        for (field in listOf(event.scope.productId, event.scope.serverProfileId, event.scope.issuer, event.scope.subject,
            event.scope.subscriptionGeneration.toString(), event.subscriptionId, event.eventId)) {
            val bytes = field.toByteArray(Charsets.UTF_8)
            for (shift in listOf(24, 16, 8, 0)) digest.update((bytes.size ushr shift).toByte())
            digest.update(bytes)
        }
        val bytes = digest.digest()
        val alphabet = "0123456789abcdef"
        return CharArray(bytes.size * 2).also { chars ->
            bytes.forEachIndexed { index, value ->
                chars[index * 2] = alphabet[(value.toInt() ushr 4) and 15]
                chars[index * 2 + 1] = alphabet[value.toInt() and 15]
            }
        }.concatToString()
    }
}
