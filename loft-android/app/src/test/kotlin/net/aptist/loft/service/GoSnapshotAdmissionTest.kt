package net.aptist.loft.service

import net.aptist.loft.core.generated.*
import net.aptist.loft.foundation.*
import net.aptist.loft.testing.NetworkPrivacyFixtures
import org.junit.Assert.*
import org.junit.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

class GoSnapshotAdmissionTest {
    private fun running() = GoVpnFacts(1L, GoVpnState.RUNNING, true, true, true, true, true,
        false, false, false, 1, 0, 0L, "", GoNetworkPrivacyFacts(policyInstalled = true, policyEpoch = 1uL,
            scopeId = "a".repeat(64), dnsMode = NetworkDnsMode.NODE_DOMAIN_FAKE_IP,
            dnsLeakPolicy = NetworkLeakPolicy.PROXY_ONLY, webrtcPolicy = NetworkLeakPolicy.PROXY_ONLY,
            enforcementActive = true, dnsProtectionEnforced = true, webrtcProtectionEnforced = true, ipv6DropActive = true))
    private fun idle() = running().copy(generation = 0L, state = GoVpnState.IDLE, transportReady = false, authenticated = false,
        tunReady = false, tunOwned = false, socketsProtected = false, forwardingDisabled = true, resourcesReleased = true,
        physicalOpen = 0, privacy = running().privacy.copy(enforcementActive = false, dnsProtectionEnforced = false,
            webrtcProtectionEnforced = false, ipv6DropActive = false))
    private fun starting() = running().copy(state = GoVpnState.STARTING, transportReady = false, authenticated = false,
        tunReady = false, ownershipPending = true, privacy = running().privacy.copy(enforcementActive = false,
            dnsProtectionEnforced = false, webrtcProtectionEnforced = false, ipv6DropActive = false))
    private fun closed(state: GoVpnState = GoVpnState.CLOSED, pending: Boolean = false) = running().copy(state = state,
        transportReady = false, authenticated = false, tunReady = false, tunOwned = false, socketsProtected = false,
        forwardingDisabled = true, resourcesReleased = !pending, ownershipPending = pending, physicalOpen = 0,
        privacy = running().privacy.copy(enforcementActive = false, dnsProtectionEnforced = false,
            webrtcProtectionEnforced = false, ipv6DropActive = false, dnsSyntheticCount = 4L))

    private fun connectedMetadata(ready: Boolean) = SnapshotFrame(CoreSnapshot(2u, "0.1.2-LYNX", emptyList(), 0u,
        null, false, false, emptyList(), ConnectionState.CONNECTED, 1uL, 1uL, "test-node",
        AppliedRouting(false, emptyList(), Ipv6Policy.BLOCKED_IN_VPN), null, NetworkPrivacyFixtures.policy(), 1uL,
        NetworkPrivacyFixtures.applied(), NetworkPrivacyEnforcement.ACTIVE), "engine", ready, 1uL, true, false, false)

    // Reproduces delayed startup captures invalidating an accepted Ready frame.
    @Test fun lateStartupCannotEraseReadyAndBreakTheActualSnapshotEncoder() {
        val admission = GoSnapshotAdmission()
        assertTrue(admission.observe(running()))
        admission.observe(idle())
        val ready = admission.current()?.provesReady == true
        assertNotNull("DELAYED_IDLE_BROKE_CONNECTED_PUBLICATION", runCatching { SnapshotWire.encode(connectedMetadata(ready)) }.getOrNull())
        assertTrue("DELAYED_IDLE_ERASED_READY", ready)
        assertFalse(admission.observe(starting()))
        assertTrue(admission.current()!!.provesReady)
    }

    @Test fun startupGenerationCannotRegressToAnEarlierIdleCapture() {
        val admission = GoSnapshotAdmission()
        assertTrue(admission.observe(idle()))
        assertTrue(admission.observe(starting()))
        assertFalse(admission.observe(idle()))
        assertEquals(GoVpnState.STARTING, admission.current()!!.state)
        assertTrue(admission.current()!!.ownershipPending)
    }

    @Test fun realLossPendingOwnershipAndFinalClosureRemainAdmissible() {
        val admission = GoSnapshotAdmission()
        assertTrue(admission.observe(running()))
        assertTrue(admission.observe(closed(GoVpnState.BLOCKED, pending = true)))
        assertFalse(admission.current()!!.provesReady)
        assertFalse(admission.current()!!.provesReleased)
        assertTrue(admission.observe(closed()))
        assertTrue(admission.current()!!.provesReleased)
        assertEquals(4L, admission.current()!!.privacy.dnsSyntheticCount)
        assertFalse(admission.observe(starting()))
        assertEquals(4L, admission.current()!!.privacy.dnsSyntheticCount)
    }

    @Test fun lateReadyCannotReviveAFailedOrClosedAttemptCache() {
        val admission = GoSnapshotAdmission()
        assertTrue(admission.observe(closed(GoVpnState.BLOCKED, pending = true)))
        assertFalse(admission.observe(running()))
        assertEquals(GoVpnState.BLOCKED, admission.current()!!.state)
        assertTrue(admission.observe(closed()))
        assertFalse(admission.observe(running()))
        assertTrue(admission.current()!!.provesReleased)
    }

    @Test fun invalidRunningProofIsNotMaskedByTheStartupFilter() {
        val admission = GoSnapshotAdmission()
        assertTrue(admission.observe(running()))
        val invalid = running().copy(privacy = running().privacy.copy(webrtcProtectionEnforced = false))
        assertTrue(admission.observe(invalid))
        assertFalse(admission.current()!!.provesReady)
    }

    @Test fun aCapturedIdleCallbackReleasedAfterReadyCannotOverwriteItsAtomicCommit() {
        val admission = GoSnapshotAdmission()
        val captured = CountDownLatch(1)
        val release = CountDownLatch(1)
        val finished = CountDownLatch(1)
        val lateAccepted = AtomicBoolean(false)
        val old = Thread {
            val snapshot = idle()
            captured.countDown()
            if (release.await(5, TimeUnit.SECONDS)) lateAccepted.set(admission.observe(snapshot))
            finished.countDown()
        }
        old.start()
        try {
            assertTrue(captured.await(5, TimeUnit.SECONDS))
            assertTrue(admission.observe(running()))
            release.countDown()
            assertTrue(finished.await(5, TimeUnit.SECONDS))
            assertTrue("LATE_CALLBACK_ERASED_READY", admission.current()!!.provesReady)
            assertFalse(lateAccepted.get())
        } finally { release.countDown(); old.join(5000) }
    }
}
