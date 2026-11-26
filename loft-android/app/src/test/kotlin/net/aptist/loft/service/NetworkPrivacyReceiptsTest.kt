package net.aptist.loft.service

import net.aptist.loft.core.generated.*
import net.aptist.loft.foundation.*
import net.aptist.loft.testing.NetworkPrivacyFixtures
import org.junit.Assert.*
import org.junit.Test

class NetworkPrivacyReceiptsTest {
    private val expected = CapturedNetworkPolicy(1uL, "a".repeat(64), NetworkPrivacyAdapter.draft(NetworkPrivacyFixtures.policy()))
    private val platform = PlatformTunReceipt(true, true, true)
    private fun running() = GoVpnFacts(1L, GoVpnState.RUNNING, true, true, true, true, true,
        false, false, false, 1, 0, 0L, "", GoNetworkPrivacyFacts(policyInstalled = true, policyEpoch = 1uL,
            scopeId = "a".repeat(64), dnsMode = NetworkDnsMode.NODE_DOMAIN_FAKE_IP,
            dnsLeakPolicy = NetworkLeakPolicy.PROXY_ONLY, webrtcPolicy = NetworkLeakPolicy.PROXY_ONLY,
            enforcementActive = true, dnsProtectionEnforced = true, webrtcProtectionEnforced = true, ipv6DropActive = true))
    private fun closed() = running().copy(state = GoVpnState.CLOSED, transportReady = false, authenticated = false,
        tunReady = false, tunOwned = false, socketsProtected = false, forwardingDisabled = true, resourcesReleased = true,
        physicalOpen = 0, privacy = running().privacy.copy(enforcementActive = false, dnsProtectionEnforced = false,
            webrtcProtectionEnforced = false, ipv6DropActive = false))

    // Dropping a privacy/platform field from the receipt must fail this boundary.
    @Test fun readyMapsTheActualCapturedProofAndAllPlatformFacts() {
        val receipt = NetworkPrivacyReceipts.ready(7uL, listOf("net.example.alpha"), expected, running(), platform, true)
        assertNotNull(receipt)
        assertEquals(7uL, receipt!!.attemptId)
        assertEquals(listOf("net.example.alpha"), receipt.appliedPackageNames)
        assertEquals(1uL, receipt.privacy.policyEpoch)
        assertEquals("a".repeat(64), receipt.privacy.scopeId)
        assertEquals(DnsMode.NODE_DOMAIN_FAKE_IP, receipt.privacy.dnsMode)
        assertTrue(receipt.privacy.policyInstalled)
        assertTrue(receipt.privacy.enforcementActive)
        assertTrue(receipt.privacy.dnsProtectionEnforced)
        assertTrue(receipt.privacy.webrtcProtectionEnforced)
        assertTrue(receipt.privacy.ipv6DropActive)
        assertFalse(receipt.privacy.ownershipPending)
        assertEquals(HydraScope.OFF, receipt.privacy.hydraScope)
        assertTrue(receipt.ipv4CaptureConfirmed && receipt.noBypassConfirmed && receipt.ipv6BlockedConfirmed)
    }

    @Test fun readyRejectsStaleScopePolicyMissingPlatformAndUnjoinedProof() {
        fun denied(facts: GoVpnFacts = running(), proof: PlatformTunReceipt? = platform, current: Boolean = true) {
            assertNull(NetworkPrivacyReceipts.ready(7uL, emptyList(), expected, facts, proof, current))
        }
        denied(running().copy(privacy = running().privacy.copy(policyEpoch = 2uL)))
        denied(running().copy(privacy = running().privacy.copy(scopeId = "b".repeat(64))))
        denied(running().copy(privacy = running().privacy.copy(dnsLeakPolicy = NetworkLeakPolicy.BLOCK)))
        denied(running().copy(privacy = running().privacy.copy(webrtcProtectionEnforced = false)))
        denied(running().copy(ownershipPending = true))
        denied(proof = null)
        denied(proof = platform.copy(ipv4CaptureConfirmed = false))
        denied(proof = platform.copy(noBypassConfirmed = false))
        denied(proof = platform.copy(ipv6BlockedConfirmed = false))
        denied(current = false)
    }

    @Test fun blockedMapsCapturedScopeOnlyAfterActualDisableAndStartJoin() {
        val receipt = NetworkPrivacyReceipts.blocked(7uL, emptyList(), expected, closed(), platform, true, true, true)
        assertNotNull(receipt)
        assertEquals(1uL, receipt!!.policyEpoch)
        assertEquals("a".repeat(64), receipt.scopeId)
        assertTrue(receipt.tunHeld && receipt.forwardingDisabled)
        assertTrue(receipt.ipv4CaptureConfirmed && receipt.noBypassConfirmed && receipt.ipv6BlockedConfirmed)
        assertNotNull(NetworkPrivacyReceipts.blocked(7uL, emptyList(), expected, null, platform, true, true, true))
    }

    @Test fun blockedCannotHidePendingOwnershipLostTunOrChangedUidScope() {
        fun denied(facts: GoVpnFacts? = closed(), proof: PlatformTunReceipt? = platform,
            current: Boolean = true, joined: Boolean = true, held: Boolean = true) {
            assertNull(NetworkPrivacyReceipts.blocked(7uL, emptyList(), expected, facts, proof, current, joined, held))
        }
        denied(running())
        denied(closed().copy(ownershipPending = true))
        denied(closed().copy(privacy = closed().privacy.copy(scopeId = "b".repeat(64))))
        denied(proof = null)
        denied(current = false)
        denied(joined = false)
        denied(held = false)
    }
}
