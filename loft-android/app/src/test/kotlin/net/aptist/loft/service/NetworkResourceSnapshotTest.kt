package net.aptist.loft.service

import net.aptist.loft.foundation.*
import net.aptist.loft.testing.NetworkPrivacyFixtures
import org.junit.Assert.*
import org.junit.Test

class NetworkResourceSnapshotTest {
    private val expected = CapturedNetworkPolicy(1uL, "a".repeat(64), NetworkPrivacyAdapter.draft(NetworkPrivacyFixtures.policy()))
    private fun running() = GoVpnFacts(1L, GoVpnState.RUNNING, true, true, true, true, true,
        false, false, false, 1, 2, 1024L, "", GoNetworkPrivacyFacts(policyInstalled = true, policyEpoch = 1uL,
            scopeId = "a".repeat(64), dnsMode = NetworkDnsMode.NODE_DOMAIN_FAKE_IP,
            dnsLeakPolicy = NetworkLeakPolicy.PROXY_ONLY, webrtcPolicy = NetworkLeakPolicy.PROXY_ONLY,
            enforcementActive = true, dnsProtectionEnforced = true, webrtcProtectionEnforced = true, ipv6DropActive = true,
            dnsMapEntries = 1, dnsMapBytes = 128L, dnsSyntheticCount = 3L, nodeResolverCalls = 1L))

    @Test fun matchingActualFactsProduceScopedResourceUsage() {
        val value = NetworkResourceSnapshot.from(9uL, expected, running())
        assertNotNull(value)
        assertEquals(9uL, value!!.attemptId)
        assertEquals(1uL, value.policyEpoch)
        assertEquals("a".repeat(64), value.scopeId)
        assertFalse(value.finalized)
        assertEquals(2, value.activeFlows)
        assertEquals(1024L, value.queuedBytes)
        assertEquals(3L, value.dnsSyntheticCount)
        assertEquals(0L, value.dnsValidatedWireCount)
        assertEquals(1L, value.nodeResolverCalls)
        assertEquals(0L, value.businessResolverCalls)
    }

    @Test fun mismatchingScopeAndUninstalledFactsCannotPublishScopedUsage() {
        assertNull(NetworkResourceSnapshot.from(9uL, expected.copy(policyEpoch = 2uL), running()))
        assertNull(NetworkResourceSnapshot.from(9uL, expected.copy(scopeId = "b".repeat(64)), running()))
        assertNull(NetworkResourceSnapshot.from(0uL, expected, running()))
        assertNull(NetworkResourceSnapshot.from(9uL, expected, running().copy(privacy = GoNetworkPrivacyFacts())))
    }

    @Test fun finalHistoryComesOnlyFromActualClosedJoinedFacts() {
        val closed = running().copy(state = GoVpnState.CLOSED, transportReady = false, authenticated = false,
            tunReady = false, tunOwned = false, socketsProtected = false, forwardingDisabled = true, resourcesReleased = true,
            physicalOpen = 0, activeFlows = 0, queuedBytes = 0L,
            privacy = running().privacy.copy(enforcementActive = false, dnsProtectionEnforced = false,
                webrtcProtectionEnforced = false, ipv6DropActive = false, dnsMapEntries = 0, dnsMapBytes = 0L))
        val final = NetworkResourceSnapshot.from(9uL, expected, closed)
        assertNotNull(final)
        assertTrue(final!!.finalized)
        assertEquals(3L, final.dnsSyntheticCount)
        assertEquals(540672L, final.dnsAllocatorBytes)
        assertFalse(NetworkResourceSnapshot.from(9uL, expected, closed.copy(ownershipPending = true))!!.finalized)
    }
}
