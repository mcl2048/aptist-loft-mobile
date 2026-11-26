package net.aptist.loft.service

import net.aptist.loft.core.generated.*
import net.aptist.loft.foundation.ControlCodec
import org.junit.Assert.*
import org.junit.Test

class SnapshotWireTest {
    private fun activeFrame(): SnapshotFrame = frame().let { initial ->
        initial.copy(core = initial.core.copy(connectionState = ConnectionState.CONNECTED, connectionAttemptId = 3uL,
            activeNodeId = "n-17", appliedRouting = AppliedRouting(true, listOf("net.example.alpha"), Ipv6Policy.BLOCKED_IN_VPN),
            appliedNetworkPrivacy = net.aptist.loft.testing.NetworkPrivacyFixtures.applied(),
            networkPrivacyEnforcement = NetworkPrivacyEnforcement.ACTIVE), transportReady = true, tunHeld = true,
            forwardingDisabled = false, resourcesReleased = false)
    }

    private fun resources() = NetworkResourceSnapshot(3uL, 1uL, "a".repeat(64),
        net.aptist.loft.testing.NetworkPrivacyFixtures.policy(), dnsSyntheticCount = 7L, nodeResolverCalls = 1L)

    @Test fun scopedCountersRoundTripWithoutReplacingRustPolicyProof() {
        val active = activeFrame().copy(networkResources = resources(), core = activeFrame().core.copy(
            networkPrivacyPolicyEpoch = 2uL,
            networkPrivacyPolicy = activeFrame().core.networkPrivacyPolicy.copy(dnsLeakPolicy = LeakProtectionMode.BLOCK)))
        val decoded = SnapshotWire.decode(SnapshotWire.encode(active))
        assertNotNull("SCOPED_RESOURCE_METADATA_REQUIRED", decoded.networkResources)
        assertEquals(7L, decoded.networkResources!!.dnsSyntheticCount)
        assertEquals(0L, decoded.networkResources.dnsValidatedWireCount)
        assertEquals(1L, decoded.networkResources.nodeResolverCalls)
        assertEquals(0L, decoded.networkResources.businessResolverCalls)
        assertEquals(1uL, decoded.networkResources.policyEpoch)
        assertEquals(2uL, decoded.core.networkPrivacyPolicyEpoch)
        assertEquals(NetworkPrivacyEnforcement.ACTIVE, decoded.core.networkPrivacyEnforcement)
        assertEquals(active, decoded)
    }

    @Test fun publisherForwardsOnlyItsCapturedScopedMetadata() {
        val active = activeFrame()
        val encoded = SnapshotPublisher().capture({ active.core }, SnapshotMetadata("engine", true, true, false, false, resources()))
        val decoded = SnapshotWire.decode(encoded)
        assertNotNull("CAPTURED_RESOURCE_METADATA_REQUIRED", decoded.networkResources)
        assertEquals(7L, decoded.networkResources!!.dnsSyntheticCount)
    }

    @Test fun staleResourceEpochScopeAndModeCannotAttachToAppliedPolicy() {
        val active = activeFrame()
        expectInvalid { SnapshotWire.encode(active.copy(networkResources = resources().copy(policyEpoch = 2uL))) }
        expectInvalid { SnapshotWire.encode(active.copy(networkResources = resources().copy(scopeId = "b".repeat(64)))) }
        expectInvalid { SnapshotWire.encode(active.copy(networkResources = resources().copy(policy = resources().policy.copy(
            dnsMode = DnsMode.WIRE_TCP, resolverEndpoint = "1.1.1.1:53")))) }
    }

    @Test fun closedScopedTotalsRequireReleasedOwnershipAndTheCurrentAttempt() {
        val closed = frame().copy(core = frame().core.copy(connectionAttemptId = 3uL), networkResources = resources().copy(finalized = true))
        val decoded = SnapshotWire.decode(SnapshotWire.encode(closed))
        assertNotNull("FINAL_SCOPED_TOTALS_REQUIRED", decoded.networkResources)
        assertTrue(decoded.networkResources!!.finalized)
        assertEquals(7L, decoded.networkResources.dnsSyntheticCount)
        assertEquals(NetworkPrivacyEnforcement.INACTIVE, decoded.core.networkPrivacyEnforcement)
        expectInvalid { SnapshotWire.encode(closed.copy(networkResources = resources().copy(finalized = true, dnsMapEntries = 1))) }
        expectInvalid { SnapshotWire.encode(closed.copy(networkResources = resources().copy(finalized = true, physicalOpen = 1))) }
        expectInvalid { SnapshotWire.encode(closed.copy(networkResources = resources().copy(finalized = true, ownershipPending = true))) }
        expectInvalid { SnapshotWire.encode(closed.copy(networkResources = resources().copy(finalized = true, attemptId = 4uL))) }
        expectInvalid { SnapshotWire.encode(closed.copy(networkResources = resources())) }
    }

    @Test fun resourceBoundsAndStrictBinaryDecodingAreEnforced() {
        val active = activeFrame()
        for (bad in listOf(resources().copy(dnsSyntheticCount = -1L), resources().copy(dnsAllocatorBytes = 540671L),
            resources().copy(queuedBytes = 7847937L), resources().copy(dnsMapEntries = 257), resources().copy(dnsMapBytes = 262145L))) {
            expectInvalid { SnapshotWire.encode(active.copy(networkResources = bad)) }
        }
        val encoded = SnapshotWire.encode(active.copy(networkResources = resources()))
        expectInvalid { SnapshotWire.decode(encoded.copyOf(encoded.size - 1)) }
        expectInvalid { SnapshotWire.decode(encoded.copyOf().apply { this[lastIndex] = 2 }) }
    }

    @Test fun savedDraftAndConfirmedAppliedPolicyRemainDistinctOnTheWire() {
        val initial = frame()
        val active = initial.copy(core = initial.core.copy(connectionState = ConnectionState.CONNECTED,
            connectionAttemptId = 3uL, activeNodeId = "n-17",
            appliedRouting = AppliedRouting(true, listOf("net.example.alpha"), Ipv6Policy.BLOCKED_IN_VPN),
            networkPrivacyPolicy = initial.core.networkPrivacyPolicy.copy(dnsLeakPolicy = LeakProtectionMode.BLOCK),
            networkPrivacyPolicyEpoch = 2uL, appliedNetworkPrivacy = net.aptist.loft.testing.NetworkPrivacyFixtures.applied(),
            networkPrivacyEnforcement = NetworkPrivacyEnforcement.ACTIVE), transportReady = true, tunHeld = true,
            forwardingDisabled = false, resourcesReleased = false)
        val decoded = SnapshotWire.decode(SnapshotWire.encode(active))
        assertEquals(2uL, decoded.core.networkPrivacyPolicyEpoch)
        assertEquals(LeakProtectionMode.BLOCK, decoded.core.networkPrivacyPolicy.dnsLeakPolicy)
        assertEquals(1uL, decoded.core.appliedNetworkPrivacy!!.policyEpoch)
        assertEquals(LeakProtectionMode.PROXY_ONLY, decoded.core.appliedNetworkPrivacy!!.policy.dnsLeakPolicy)
        assertEquals(NetworkPrivacyEnforcement.ACTIVE, decoded.core.networkPrivacyEnforcement)
    }

    @Test fun stoppedOrUnavailableFramesCannotRetainAnActiveProtectionProjection() {
        expectInvalid { SnapshotWire.encode(frame().copy(core = frame().core.copy(networkPrivacyEnforcement = NetworkPrivacyEnforcement.ACTIVE))) }
        expectInvalid { SnapshotWire.encode(frame().copy(core = frame().core.copy(schemaVersion = 1u))) }
        expectInvalid { SnapshotWire.decode(ByteArray(0)) }
    }

    @Test fun largestLegalCorePrivacyFrameIsMeasuredAsActualBinaryBytes() {
        val names = List(100) { "net.example.app${it.toString().padStart(3, '0')}".padEnd(40, 'x') }
        val nodes = List(50) { NodeSummary("n-$it".padEnd(64, 'x'), "L".repeat(64), ProtocolKind.HYRAKEN_PRO,
            "e".repeat(300), 0u, 65507u, true) }
        val initial = frame()
        val full = initial.copy(core = initial.core.copy(nodes = nodes, nodeCount = 200u, selectedApps = names,
            connectionState = ConnectionState.BLOCKED, connectionAttemptId = ULong.MAX_VALUE, activeNodeId = nodes.last().id,
            appliedRouting = AppliedRouting(true, names, Ipv6Policy.BLOCKED_IN_VPN),
            appliedNetworkPrivacy = net.aptist.loft.testing.NetworkPrivacyFixtures.applied(ULong.MAX_VALUE),
            networkPrivacyPolicyEpoch = ULong.MAX_VALUE, networkPrivacyEnforcement = NetworkPrivacyEnforcement.BLOCKED),
            tunHeld = true, forwardingDisabled = true, resourcesReleased = false,
            networkResources = resources().copy(attemptId = ULong.MAX_VALUE, policyEpoch = ULong.MAX_VALUE,
                physicalOpen = 4096, activeFlows = 4096, queuedBytes = 7847936L, dnsMapEntries = 256, dnsMapBytes = 262144L,
                dnsSyntheticCount = Long.MAX_VALUE, dnsValidatedWireCount = Long.MAX_VALUE, hydraShapedRecords = Long.MAX_VALUE))
        val payload = SnapshotWire.encode(full)
        assertTrue(payload.size <= ControlCodec.MAX_CONTROL_BYTES)
        assertEquals(full, SnapshotWire.decode(payload))
        println("MAX_BINARY_SNAPSHOT_BYTES=${payload.size}")
    }

    private fun frame(): SnapshotFrame {
        val node = NodeSummary(id = "n-17", label = "東京", protocol = ProtocolKind.SOCKS5,
            endpoint = "example.invalid:1080", udpMin = 0u, udpMax = 65507u, credentialMaterialPresent = true)
        return SnapshotFrame(CoreSnapshot(schemaVersion = 2u, coreVersion = "0.1.2-LYNX", nodes = listOf(node), nodeCount = 1u,
            serverAddress = "https://server.invalid", serverVerified = false, routingEnabled = true,
            selectedApps = listOf("net.example.alpha"), connectionState = ConnectionState.DISCONNECTED, generation = 7uL,
            connectionAttemptId = 0uL, activeNodeId = null, appliedRouting = null, vpnFailure = null,
            networkPrivacyPolicy = net.aptist.loft.testing.NetworkPrivacyFixtures.policy(), networkPrivacyPolicyEpoch = 1uL,
            appliedNetworkPrivacy = null, networkPrivacyEnforcement = NetworkPrivacyEnforcement.INACTIVE), "0.1.2-LYNX", false, 1uL)
    }

    // Catches IPC mapping dropping fields or making unavailable transport look active.
    @Test fun generatedSnapshotRoundTripsAllAuthoritativeFields() {
        val decoded = SnapshotWire.decode(SnapshotWire.encode(frame()))
        assertEquals("東京", decoded.core.nodes.single().label)
        assertEquals("n-17", decoded.core.nodes.single().id)
        assertEquals("example.invalid:1080", decoded.core.nodes.single().endpoint)
        assertEquals(65507u, decoded.core.nodes.single().udpMax)
        assertTrue(decoded.core.nodes.single().credentialMaterialPresent)
        assertEquals(1u, decoded.core.nodeCount)
        assertEquals("https://server.invalid", decoded.core.serverAddress)
        assertFalse(decoded.core.serverVerified)
        assertEquals(listOf("net.example.alpha"), decoded.core.selectedApps)
        assertEquals(7uL, decoded.core.generation)
        assertFalse(decoded.transportReady)
    }

    // Catches exposing mutable lists that a UI draft could change as business state.
    @Test fun decodedCollectionsRejectUiMutation() {
        val decoded = SnapshotWire.decode(SnapshotWire.encode(frame()))
        try { (decoded.core.nodes as MutableList<NodeSummary>).clear(); fail("Mutable node snapshot") }
        catch (_: UnsupportedOperationException) { }
        try { (decoded.core.selectedApps as MutableList<String>).clear(); fail("Mutable route snapshot") }
        catch (_: UnsupportedOperationException) { }
    }

    @Test fun unsignedGenerationHighBitSurvivesIpc() {
        val original = frame().copy(core = frame().core.copy(generation = ULong.MAX_VALUE))
        assertEquals(ULong.MAX_VALUE, SnapshotWire.decode(SnapshotWire.encode(original)).core.generation)
    }

    @Test fun unsignedPublicationSequenceSurvivesIpcIndependentlyOfRustGeneration() {
        val original = frame().copy(publicationSequence = ULong.MAX_VALUE)
        val decoded = SnapshotWire.decode(SnapshotWire.encode(original))
        assertEquals(ULong.MAX_VALUE, decoded.publicationSequence)
        assertEquals(7uL, decoded.core.generation)
    }

    @Test fun appliedRoutingFailureAndPhysicalFactsSurviveTheWire() {
        val original = frame().copy(core = frame().core.copy(connectionState = ConnectionState.BLOCKED,
            connectionAttemptId = ULong.MAX_VALUE, activeNodeId = "n-17",
            appliedRouting = AppliedRouting(true, listOf("net.example.alpha", "net.example.alpha.helper"), Ipv6Policy.BLOCKED_IN_VPN),
            vpnFailure = VpnFailure.ENGINE_UNAVAILABLE, appliedNetworkPrivacy = net.aptist.loft.testing.NetworkPrivacyFixtures.applied(),
            networkPrivacyEnforcement = NetworkPrivacyEnforcement.BLOCKED), tunHeld = true, forwardingDisabled = true, resourcesReleased = false)
        val decoded = SnapshotWire.decode(SnapshotWire.encode(original))
        assertEquals(ULong.MAX_VALUE, decoded.core.connectionAttemptId)
        assertEquals("n-17", decoded.core.activeNodeId)
        assertEquals(VpnFailure.ENGINE_UNAVAILABLE, decoded.core.vpnFailure)
        val applied = decoded.core.appliedRouting!!
        assertEquals(listOf("net.example.alpha", "net.example.alpha.helper"), applied.packageNames)
        assertEquals(Ipv6Policy.BLOCKED_IN_VPN, applied.ipv6Policy)
        assertTrue(decoded.tunHeld)
        assertTrue(decoded.forwardingDisabled)
        assertFalse(decoded.resourcesReleased)
        try { (applied.packageNames as MutableList<String>).clear(); fail("Mutable applied scope") }
        catch (_: UnsupportedOperationException) { }
    }

    @Test fun schemaMismatchNeverProducesAValidFrame() {
        expectInvalid { SnapshotWire.encode(frame().copy(core = frame().core.copy(schemaVersion = 99u))) }
    }

    @Test fun tooManyRowsNeverProduceAValidFrame() {
        val node = frame().core.nodes.first()
        expectInvalid { SnapshotWire.encode(frame().copy(core = frame().core.copy(nodes = List(51) { node }, nodeCount = 51u))) }
    }

    @Test fun unsupportedReadyTransportIsRejected() {
        expectInvalid { SnapshotWire.encode(frame().copy(transportReady = true)) }
    }

    @Test fun oversizedPayloadIsRejected() {
        expectInvalid { SnapshotWire.decode(ByteArray(ControlCodec.MAX_CONTROL_BYTES + 1)) }
    }

    @Test fun trailingPayloadIsRejected() {
        expectInvalid { SnapshotWire.decode(SnapshotWire.encode(frame()) + byteArrayOf(1)) }
    }

    private fun expectInvalid(block: () -> Unit) {
        try { block(); fail("Expected invalid snapshot") }
        catch (_: SnapshotWireException) { }
    }
}
