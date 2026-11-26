package net.aptist.loft.service

import org.junit.Assert.*
import org.junit.Test

class GoVpnSnapshotTest {
    private fun running() = """{"schema_version":1,"generation":1,"runtime_state":"running","transport_ready":true,"authenticated":true,"tun_ready":true,"tun_owned":true,"socket_protection_succeeded":true,"forwarding_disabled":false,"resources_released":false,"ownership_pending":false,"physical_open":1,"active_flows":0,"queued_bytes":0,""" + privacy(true) + "}"
    private fun closed() = """{"schema_version":1,"generation":1,"runtime_state":"closed","transport_ready":false,"authenticated":false,"tun_ready":false,"tun_owned":false,"socket_protection_succeeded":false,"forwarding_disabled":true,"resources_released":true,"ownership_pending":false,"physical_open":0,"active_flows":0,"queued_bytes":0,""" + privacy(false) + "}"
    private fun closedWithPolicy(): String = closed().replace(privacy(false), privacy(true)
        .replace("\"enforcement_active\":true", "\"enforcement_active\":false")
        .replace("\"dns_protection_enforced\":true", "\"dns_protection_enforced\":false")
        .replace("\"webrtc_protection_enforced\":true", "\"webrtc_protection_enforced\":false")
        .replace("\"ipv6_drop_active\":true", "\"ipv6_drop_active\":false"))
    private fun privacy(active: Boolean): String {
        val epoch = if (active) "1" else ""
        val scope = if (active) "a".repeat(64) else ""
        val mode = if (active) "node_domain_fake_ip" else ""
        val source = if (active) "proxy_only" else ""
        return """"policy_installed":$active,"policy_epoch":"$epoch","scope_id":"$scope","dns_mode":"$mode","dns_leak_policy":"$source","webrtc_policy":"$source","enforcement_active":$active,"dns_protection_enforced":$active,"webrtc_protection_enforced":$active,"ipv6_drop_active":$active,"dns_allocator_bytes":540672,"dns_map_entries":0,"dns_map_bytes":0,"dns_synthetic_count":0,"dns_validated_wire_count":0,"dns_policy_drop_count":0,"webrtc_classified_count":0,"webrtc_policy_drop_count":0,"node_resolver_calls":0,"business_resolver_calls":0,"hydra_enabled":false,"hydra_applied":false,"hydra_scope":"off","hydra_shaped_records":0,"hydra_padding_bytes":0"""
    }

    @Test fun strictResourceFieldsAndCapturedScopeAreRetained() {
        val facts = GoVpnSnapshot.decode(running())
        assertTrue(facts.privacy.policyInstalled)
        assertEquals(1uL, facts.privacy.policyEpoch)
        assertEquals("a".repeat(64), facts.privacy.scopeId)
        assertEquals(540672L, facts.privacy.dnsAllocatorBytes)
        val expected = CapturedNetworkPolicy(1uL, "a".repeat(64), NetworkPrivacyAdapter.draft(net.aptist.loft.testing.NetworkPrivacyFixtures.policy()))
        assertTrue(facts.privacy.samePolicy(expected))
        assertFalse(facts.privacy.samePolicy(expected.copy(policyEpoch = 2uL)))
        assertFalse(facts.privacy.samePolicy(expected.copy(scopeId = "b".repeat(64))))
    }

    @Test fun missingOrCoercedPrivacyFieldsCannotBecomeAnEngineReceipt() {
        invalid(running().replace("\"policy_installed\":true,", ""))
        invalid(running().replace("\"dns_allocator_bytes\":540672,", ""))
        invalid(running().replace("\"policy_epoch\":\"1\"", "\"policy_epoch\":1"))
        invalid(running().replace("\"enforcement_active\":true", "\"enforcement_active\":\"true\""))
        invalid(running().replace("\"business_resolver_calls\":0", "\"business_resolver_calls\":-1"))
    }

    @Test fun unknownDuplicateNullAndTrailingResourceDataAreRejected() {
        invalid(running().replace("\"schema_version\":1", "\"schema_version\":1,\"direct_fallback\":true"))
        invalid(running().replace("\"policy_epoch\":\"1\"", "\"policy_epoch\":\"1\",\"policy_epoch\":\"1\""))
        invalid(running().replace("\"scope_id\":\"" + "a".repeat(64) + "\"", "\"scope_id\":null"))
        invalid(running() + "{}")
    }

    @Test fun resourceJsonRejectsNonJsonWhitespaceAndNonDecimalIntegerSyntax() {
        invalid("\u000b" + running())
        invalid(running() + "\u0000")
        invalid(running() + "\u0000{}")
        invalid(running().replace("\"schema_version\":1", "\"schema_version\":01"))
        invalid(running().replace("\"schema_version\":1", "\"schema_version\":0x1"))
        invalid(running().replace("\"physical_open\":1", "\"physical_open\":1e0"))
        invalid(running().replace("\"physical_open\":1", "\"physical_open\":+1"))
    }

    @Test fun transportReadyAloneCannotClaimTheSharedEnforcerIsReady() {
        assertFalse(GoVpnSnapshot.decode(running().replace("\"enforcement_active\":true", "\"enforcement_active\":false")).provesReady)
        assertFalse(GoVpnSnapshot.decode(running().replace("\"dns_protection_enforced\":true", "\"dns_protection_enforced\":false")).provesReady)
        assertFalse(GoVpnSnapshot.decode(running().replace("\"webrtc_protection_enforced\":true", "\"webrtc_protection_enforced\":false")).provesReady)
    }

    @Test fun fixedAllocatorAndDynamicByteBoundsStaySeparate() {
        val maximum = GoVpnSnapshot.decode(running().replace("\"queued_bytes\":0", "\"queued_bytes\":7847936"))
        assertEquals(7847936L, maximum.queuedBytes)
        invalid(running().replace("\"queued_bytes\":0", "\"queued_bytes\":7847937"))
        invalid(running().replace("\"dns_allocator_bytes\":540672", "\"dns_allocator_bytes\":540671"))
        assertTrue(GoVpnSnapshot.decode(closed()).provesReleased)
        assertFalse(GoVpnSnapshot.decode(closedWithPolicy().replace("\"dns_map_entries\":0", "\"dns_map_entries\":1")
            .replace("\"dns_map_bytes\":0", "\"dns_map_bytes\":1024")).provesReleased)
    }

    @Test fun joinedClosedScopeMayKeepRedactedTotalsWithoutKeepingActiveProtection() {
        val closed = GoVpnSnapshot.decode(closedWithPolicy().replace("\"dns_synthetic_count\":0", "\"dns_synthetic_count\":3")
            .replace("\"node_resolver_calls\":0", "\"node_resolver_calls\":1"))
        assertTrue(closed.provesReleased)
        assertFalse(closed.provesReady)
        assertEquals(1uL, closed.privacy.policyEpoch)
        assertEquals("a".repeat(64), closed.privacy.scopeId)
        assertEquals(3L, closed.privacy.dnsSyntheticCount)
        assertEquals(1L, closed.privacy.nodeResolverCalls)
        assertFalse(closed.privacy.enforcementActive)
        assertFalse(closed.privacy.hydraApplied)
        assertEquals(GoHydraScope.OFF, closed.privacy.hydraScope)
    }

    // A capability or TUN alone is insufficient to make Rust accept Connected.
    @Test fun readinessRequiresAuthenticatedProtectedOwnedTunFacts() {
        val ready = GoVpnSnapshot.decode(running())
        assertTrue(ready.provesReady)
        assertFalse(ready.provesReleased)
        assertEquals(1L, ready.generation)
        assertFalse(GoVpnSnapshot.decode(running().replace("\"authenticated\":true", "\"authenticated\":false")).provesReady)
        assertFalse(GoVpnSnapshot.decode(running().replace("\"socket_protection_succeeded\":true", "\"socket_protection_succeeded\":false")).provesReady)
        assertFalse(GoVpnSnapshot.decode(running().replace("\"tun_owned\":true", "\"tun_owned\":false")).provesReady)
    }

    @Test fun explicitClosedReceiptRequiresAllResourceCountersToBeZero() {
        assertTrue(GoVpnSnapshot.decode(closed()).provesReleased)
        assertFalse(GoVpnSnapshot.decode(closed().replace("\"physical_open\":0", "\"physical_open\":1")).provesReleased)
        assertFalse(GoVpnSnapshot.decode(closed().replace("\"resources_released\":true", "\"resources_released\":false")).provesReleased)
        assertFalse(GoVpnSnapshot.decode(closed().replace("\"runtime_state\":\"closed\"", "\"runtime_state\":\"idle\"")).provesReleased)
        assertFalse(GoVpnSnapshot.decode(closed().replace("\"ownership_pending\":false", "\"ownership_pending\":true")).provesReleased)
    }

    // A SOCKS handshake may close its protected warm association before the
    // first demand-driven flow. Actual authentication/TUN facts still prove Ready.
    @Test fun authenticatedReadinessDoesNotRequireAPersistentPhysicalSocket() {
        val facts = GoVpnSnapshot.decode(running().replace("\"physical_open\":1", "\"physical_open\":0"))
        assertTrue(facts.provesReady)
        assertFalse(facts.provesReleased)
    }

    @Test fun forwardingDisableCannotBeClaimedWhileConstructionOwnsPendingResources() {
        val blocked = running().replace("\"runtime_state\":\"running\"", "\"runtime_state\":\"blocked\"")
            .replace("\"transport_ready\":true", "\"transport_ready\":false")
            .replace("\"forwarding_disabled\":false", "\"forwarding_disabled\":true")
        assertTrue(GoVpnSnapshot.decode(blocked).provesForwardingDisabled)
        assertFalse(GoVpnSnapshot.decode(blocked).provesReleased)
        assertFalse(GoVpnSnapshot.decode(blocked.replace("\"ownership_pending\":false", "\"ownership_pending\":true")).provesForwardingDisabled)
    }

    @Test fun incompleteOrCoercedFactsAreRejectedRatherThanDefaultingToClosure() {
        invalid("""{"schema_version":1,"runtime_state":"closed","resources_released":true}""")
        invalid(closed().replace("\"tun_owned\":false", "\"tun_owned\":\"false\""))
        invalid(closed().replace("\"generation\":1", "\"generation\":1.5"))
        invalid(closed().replace("\"queued_bytes\":0", "\"queued_bytes\":-1"))
    }

    @Test fun oversizedJsonAndNonCodeErrorTextAreRejected() {
        invalid(" ".repeat(8193))
        invalid(closed().dropLast(1) + ",\"error_code\":\"node material must stay private\"}")
        val failed = GoVpnSnapshot.decode(closed().dropLast(1) + ",\"error_code\":\"loft.vpn.stop_timeout\"}")
        assertEquals("loft.vpn.stop_timeout", failed.errorCode)
    }

    private fun invalid(raw: String) {
        try { GoVpnSnapshot.decode(raw); fail("Invalid engine facts were accepted") }
        catch (_: GoSnapshotException) { }
    }
}
