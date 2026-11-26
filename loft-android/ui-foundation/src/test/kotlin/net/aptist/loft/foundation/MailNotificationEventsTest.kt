package net.aptist.loft.foundation

import org.junit.Assert.*
import org.junit.Test

/** Host codec/queue checks. The test grant is not a deployed mail authority. */
class MailNotificationEventsTest {
    private val scope = MailDeliveryScope("loft-test", "server-one", "https://issuer.invalid", "user-one", 1uL)
    private fun event(id: String = "event-one", hint: Int = 1) = MailNotificationEvent(scope, "subscription-one", id, hint, 90000L, 150000L)
    private fun encoded(value: MailNotificationEvent = event()): ByteArray {
        val raw = MailEventCodec.encode(value)
        assertNotNull("BOUNDED_MAIL_CODEC_REQUIRED", raw)
        return raw!!
    }
    private fun grant(value: MailNotificationEvent, until: Long = 150000L) =
        MailDeliveryGrant(value.scope, value.subscriptionId, value.eventId, until)
    private fun allowed() = MailNotificationGate(MailEventAuthority { value, _ -> grant(value) })

    @Test fun codecCarriesOnlyBoundedOpaqueEventAndSubscriptionFacts() {
        val raw = encoded()
        assertTrue(raw.size in 1..2048)
        val decoded = MailEventCodec.decode(raw)
        assertNotNull(decoded)
        assertEquals("event-one", decoded!!.eventId)
        assertEquals("subscription-one", decoded.subscriptionId)
        assertEquals(scope, decoded.scope)
        assertEquals(1, decoded.countHint)
        assertEquals(90000L, decoded.issuedAtMillis)
        assertEquals(150000L, decoded.expiresAtMillis)
    }

    @Test fun malformedOversizedCredentialBearingAndTrailingEventsAreRejected() {
        val raw = encoded()
        assertNull(MailEventCodec.decode(raw.copyOf(raw.size - 1)))
        assertNull(MailEventCodec.decode(raw + byteArrayOf(1)))
        assertNull(MailEventCodec.decode(ByteArray(2049)))
        assertNull(MailEventCodec.encode(event().copy(scope = scope.copy(subscriptionGeneration = 0uL))))
        assertNull(MailEventCodec.encode(event().copy(scope = scope.copy(issuer = "https://user:private@issuer.invalid"))))
        assertNull(MailEventCodec.encode(event().copy(scope = scope.copy(issuer = "https://issuer.invalid?token=private"))))
        assertNull(MailEventCodec.encode(event().copy(eventId = "message\nbody")))
        assertNull(MailEventCodec.encode(event().copy(countHint = 101)))
    }

    @Test fun defaultAuthorityNeverQueuesOrDeliversMail() {
        val gate = MailNotificationGate()
        assertEquals(MailEventOffer.DENIED, gate.offer(encoded(), 100000L))
        assertTrue(gate.drain(100000L).isEmpty())
        assertEquals(MailNotificationUsage(), gate.usage())
    }

    @Test fun wrongScopeGenerationSubscriptionAndExpiredGrantFailClosed() {
        val raw = encoded()
        for (invalid in listOf(grant(event()).copy(scope = scope.copy(serverProfileId = "server-two")),
            grant(event()).copy(scope = scope.copy(subject = "user-two")),
            grant(event()).copy(scope = scope.copy(subscriptionGeneration = 2uL)),
            grant(event()).copy(subscriptionId = "subscription-two"), grant(event()).copy(eventId = "event-two"),
            grant(event(), 99999L), grant(event(), 149999L))) {
            val gate = MailNotificationGate(MailEventAuthority { _, _ -> invalid })
            assertEquals(MailEventOffer.DENIED, gate.offer(raw, 100000L))
            assertTrue(gate.drain(100000L).isEmpty())
        }
    }

    @Test fun duplicateAndStaleEventsCannotGrowPendingDelivery() {
        val gate = allowed()
        assertEquals(MailEventOffer.ACCEPTED, gate.offer(encoded(), 100000L))
        assertEquals(MailEventOffer.DUPLICATE, gate.offer(encoded(event(hint = 10)), 100000L))
        assertEquals(MailEventOffer.STALE, gate.offer(encoded(event("future").copy(issuedAtMillis = 100001L)), 100000L))
        assertEquals(MailEventOffer.STALE, gate.offer(encoded(event("expired")), 150000L))
        assertTrue(gate.usage().pendingEvents <= 1)
    }

    @Test fun pendingAdmissionStopsAtEightEventsAndKeepsItsByteLedgerBounded() {
        val gate = allowed()
        for (index in 1..8) assertEquals(MailEventOffer.ACCEPTED, gate.offer(encoded(event("event-$index")), 100000L))
        assertEquals(MailEventOffer.RESOURCE_BUSY, gate.offer(encoded(event("event-9")), 100000L))
        assertEquals(8, gate.usage().pendingEvents)
        assertTrue(gate.usage().pendingBytes in 1..32768)
        assertTrue(gate.usage().recentBytes in 1..32768)
    }

    @Test fun drainMergesConfirmedHintsAndRevalidatesCurrentAuthority() {
        var current = true
        val gate = MailNotificationGate(MailEventAuthority { value, _ -> if (current) grant(value) else null })
        assertEquals(MailEventOffer.ACCEPTED, gate.offer(encoded(event("first", 80)), 100000L))
        assertEquals(MailEventOffer.ACCEPTED, gate.offer(encoded(event("second", 50)), 100000L))
        val summaries = gate.drain(100000L)
        assertEquals(1, summaries.size)
        assertEquals(100, summaries.single().countHint)
        assertEquals(scope, summaries.single().scope)
        assertEquals(0, gate.usage().pendingEvents)
        assertEquals(0, gate.usage().pendingBytes)
        assertEquals(MailEventOffer.ACCEPTED, gate.offer(encoded(event("third")), 100000L))
        current = false
        assertTrue(gate.drain(100000L).isEmpty())
        assertEquals(0, gate.usage().pendingEvents)
    }

    @Test fun recentDedupCapacityRecoversPassivelyAfterEventExpiry() {
        val gate = allowed()
        for (index in 1..128) {
            assertEquals(MailEventOffer.ACCEPTED, gate.offer(encoded(event("event-$index")), 100000L))
            assertEquals(1, gate.drain(100000L).size)
        }
        assertEquals(MailEventOffer.RESOURCE_BUSY, gate.offer(encoded(event("event-129")), 100000L))
        assertEquals(128, gate.usage().recentEvents)
        assertTrue(gate.usage().recentBytes <= 32768)
        val next = event("new-window").copy(issuedAtMillis = 150000L, expiresAtMillis = 210000L)
        val renewed = MailNotificationGate(MailEventAuthority { value, _ -> grant(value, value.expiresAtMillis) })
        // Exercise expiry on the same real bounded queue using a live grant.
        for (index in 1..128) { renewed.offer(encoded(event("old-$index")), 100000L); renewed.drain(100000L) }
        assertEquals(MailEventOffer.ACCEPTED, renewed.offer(encoded(next), 150000L))
        assertEquals(1, renewed.usage().recentEvents)
    }

    @Test fun revokeClearsPendingAndDedupWithoutCreatingAnyWork() {
        val gate = allowed()
        assertEquals(MailEventOffer.ACCEPTED, gate.offer(encoded(), 100000L))
        gate.revoke()
        assertEquals(MailNotificationUsage(), gate.usage())
        assertTrue(gate.drain(100000L).isEmpty())
    }

    @Test fun malformedInputIsDeniedBeforeCallingTheFutureAuthority() {
        val gate = MailNotificationGate(MailEventAuthority { _, _ -> throw AssertionError("MALFORMED_EVENT_REACHED_AUTHORITY") })
        assertEquals(MailEventOffer.INVALID, gate.offer(ByteArray(2049), 100000L))
        assertEquals(MailEventOffer.INVALID, gate.offer(byteArrayOf(1, 2, 3), 100000L))
        assertEquals(MailNotificationUsage(), gate.usage())
    }
}
