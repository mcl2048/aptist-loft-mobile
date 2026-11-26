package net.aptist.loft.service

import net.aptist.loft.testing.NetworkPrivacyFixtures
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/** Actual local X/gVisor producer JSON, not task nodes or fabricated receipts.
 * Source observations SHA84459b765e466e3413d394f28a0db0857765754355e69ea22b1897490d5e4100;
 * producer receipt SHAaf0618b66e4dd7d3d91c08f53bc948b10009c78c2adfb54a4e78b0d9e34fec6f.
 */
class GoPendingStartupReceiptTest {
    private val expected = CapturedNetworkPolicy(1uL, "a".repeat(64), NetworkPrivacyAdapter.draft(NetworkPrivacyFixtures.policy()))
    private val platform = PlatformTunReceipt(true, true, true)
    private fun observed(name: String): GoVpnFacts {
        val raw = javaClass.getResourceAsStream("observed-go-start-frames.json")!!.bufferedReader(Charsets.UTF_8).use { it.readText() }
        return GoVpnSnapshot.decode(JSONObject(raw).getJSONObject(name).toString())
    }
    private fun pending() = observed("OBSERVED_PENDING_CALLBACK")
    private fun settled() = observed("OBSERVED_SETTLED_DIRECT")

    @Test fun actualPendingCallbackAndDirectFramesWaitWithoutFaultOrEarlyReady() {
        for (name in listOf("OBSERVED_PENDING_CALLBACK", "OBSERVED_PENDING_DIRECT")) {
            val facts = observed(name)
            assertEquals(GoVpnState.RUNNING, facts.state)
            assertTrue(facts.ownershipPending)
            assertTrue(facts.transportReady && facts.authenticated && facts.tunReady && facts.tunOwned && facts.socketsProtected)
            assertFalse(facts.provesReady)
            assertNull(NetworkPrivacyReceipts.ready(7uL, emptyList(), expected, facts, platform, true))
            assertFalse("LEGITIMATE_PENDING_START_WAS_FAULTED", GoSnapshotAdmission.requiresFault(facts, expected))
        }
    }

    @Test fun actualJoinedCallbackAndDirectFramesKeepTheFullReadyProof() {
        for (name in listOf("OBSERVED_SETTLED_CALLBACK", "OBSERVED_SETTLED_DIRECT")) {
            val facts = observed(name)
            assertFalse(facts.ownershipPending)
            assertTrue(facts.provesReady)
            assertFalse(GoSnapshotAdmission.requiresFault(facts, expected))
            assertNotNull(NetworkPrivacyReceipts.ready(7uL, emptyList(), expected, facts, platform, true))
        }
    }

    @Test fun settledRunningMissingRequiredProofStillFaults() {
        val facts = settled()
        for (bad in listOf(facts.copy(authenticated = false), facts.copy(tunReady = false), facts.copy(tunOwned = false),
            facts.copy(transportReady = false), facts.copy(socketsProtected = false), facts.copy(forwardingDisabled = true),
            facts.copy(resourcesReleased = true), facts.copy(privacy = facts.privacy.copy(enforcementActive = false)),
            facts.copy(privacy = facts.privacy.copy(dnsProtectionEnforced = false)),
            facts.copy(privacy = facts.privacy.copy(webrtcProtectionEnforced = false)),
            facts.copy(privacy = facts.privacy.copy(ipv6DropActive = false)))) {
            assertTrue("SETTLED_INVALID_PROOF_WAS_IGNORED", GoSnapshotAdmission.requiresFault(bad, expected))
        }
        assertTrue(GoSnapshotAdmission.requiresFault(pending(), expected.copy(policyEpoch = 2uL)))
        assertTrue(GoSnapshotAdmission.requiresFault(pending(), expected.copy(scopeId = "b".repeat(64))))
    }

    @Test fun capturedPendingRunningCannotReplaceAnActualSettledReadyCache() {
        val admission = GoSnapshotAdmission()
        assertTrue(admission.observe(settled()))
        val accepted = admission.observe(pending())
        assertTrue("DELAYED_PENDING_ERASED_JOINED_READY", admission.current()!!.provesReady)
        assertFalse(accepted)
    }

    @Test fun actualClosedOwnershipReceiptSurvivesLatePendingAndReadyCaptures() {
        val admission = GoSnapshotAdmission()
        assertTrue(admission.observe(pending()))
        assertTrue(admission.observe(observed("OBSERVED_CLOSED")))
        assertTrue(admission.current()!!.provesReleased)
        assertFalse(admission.observe(pending()))
        assertFalse(admission.observe(settled()))
        assertTrue(admission.current()!!.provesReleased)
    }

    @Test fun delayedPendingCallbackComparisonAndCommitRemainAtomic() {
        val admission = GoSnapshotAdmission()
        val captured = CountDownLatch(1)
        val release = CountDownLatch(1)
        val finished = CountDownLatch(1)
        val accepted = AtomicBoolean(false)
        val callback = Thread {
            val frame = pending()
            captured.countDown()
            if (release.await(5, TimeUnit.SECONDS)) accepted.set(admission.observe(frame))
            finished.countDown()
        }
        callback.start()
        try {
            assertTrue(captured.await(5, TimeUnit.SECONDS))
            assertTrue(admission.observe(settled()))
            release.countDown()
            assertTrue(finished.await(5, TimeUnit.SECONDS))
            assertTrue("LATE_PENDING_CALLBACK_ERASED_READY", admission.current()!!.provesReady)
            assertFalse(accepted.get())
        } finally { release.countDown(); callback.join(5000) }
    }
}
