package net.aptist.loft.service

import net.aptist.loft.core.generated.HubMailAttachment
import net.aptist.loft.core.generated.HubMailMessage
import net.aptist.loft.core.generated.HubMailPage
import net.aptist.loft.core.generated.HubMailSummary
import net.aptist.loft.core.generated.HubSession
import net.aptist.loft.core.generated.HubSnapshot
import org.junit.Assert.*
import org.junit.Test
import java.io.IOException

class HubWireTest {
    private val profile = HubSnapshot(
        generation = 1u, origin = "https://hub.invalid", issuer = "https://idp.invalid/api/idp",
        mailSupported = true, notesDiscoveryRequired = false, transactionPending = false,
        session = HubSession("subject", "guest@example.invalid", true, true, 60u, durable = true),
    )
    private val row = HubMailSummary("a".repeat(64), "Example Sender", "Example Recipient", "Review", "2026-01-01T00:00:00Z",
        false, "inbox", 1u, 100u)

    @Test fun userMailRetainsOriginalReadStatusAndPageCursor() {
        val page = HubMailPage("inbox", listOf(row), "next")
        val receipt = HubWire.decode(HubWire.encode(HubResult(profile, page = page)))
        assertEquals(profile, receipt.snapshot)
        assertEquals(page, receipt.page)
        assertFalse(checkNotNull(receipt.page).messages.single().read)
    }

    @Test fun expiredMailGrantPreservesAuthenticatedIdentity() {
        val expired = profile.copy(session = profile.session?.copy(mailAvailable = false, expiresInSeconds = 0u))
        val actual = HubWire.decode(HubWire.encode(HubResult(expired))).snapshot
        assertNotNull(actual.session)
        assertEquals("subject", actual.session?.subject)
        assertTrue(actual.session?.mailAccess == true)
        assertFalse(actual.session?.mailAvailable == true)
    }

    @Test fun identityOnlySessionUsesEnrollmentAwareWire() {
        val identityOnly = profile.copy(session = profile.session?.copy(
            mailAccess = false, mailAvailable = false, expiresInSeconds = 0u,
        ), notesDiscoveryRequired = true)
        val encoded = HubWire.encode(HubResult(identityOnly))
        assertEquals(4, encoded.first().toInt())
        val projected = HubWire.decode(encoded).snapshot
        assertTrue(projected.notesDiscoveryRequired)
        val restored = checkNotNull(projected.session)
        assertTrue(restored.durable)
        assertEquals("subject", restored.subject)
        assertFalse(restored.mailAccess)
        assertFalse(restored.mailAvailable)
    }

    @Test fun completeBoundedDetailCarriesTheFileDescriptorsMetadataOnly() {
        val attachments = List(100) { index -> HubMailAttachment("${index + 100}", "e".repeat(192), "m".repeat(120), 4u) }
        val message = HubMailMessage(row.copy(attachmentCount = 100u), "z".repeat(16 * 1024), true, attachments)
        val encoded = HubWire.encode(HubResult(profile, message = message))
        assertTrue(encoded.size <= HubWire.MAX_BYTES)
        assertEquals(message, HubWire.decode(encoded).message)
        assertThrows(IOException::class.java) { HubWire.decode(encoded + byteArrayOf(0)) }
    }
}
