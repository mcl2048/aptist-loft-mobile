package net.aptist.loft.service

import net.aptist.loft.foundation.*

enum class GoHydraScope(val wire: String) { OFF("off"), LOGICAL_STREAMS("logical_streams"), TCP_ONLY("tcp_only") }

data class GoNetworkPrivacyFacts(
    val policyInstalled: Boolean = false, val policyEpoch: ULong = 0uL, val scopeId: String = "",
    val dnsMode: NetworkDnsMode? = null, val dnsLeakPolicy: NetworkLeakPolicy? = null, val webrtcPolicy: NetworkLeakPolicy? = null,
    val enforcementActive: Boolean = false, val dnsProtectionEnforced: Boolean = false, val webrtcProtectionEnforced: Boolean = false,
    val ipv6DropActive: Boolean = false, val dnsAllocatorBytes: Long = 540672L, val dnsMapEntries: Int = 0, val dnsMapBytes: Long = 0L,
    val dnsSyntheticCount: Long = 0L, val dnsValidatedWireCount: Long = 0L, val dnsPolicyDropCount: Long = 0L,
    val webrtcClassifiedCount: Long = 0L, val webrtcPolicyDropCount: Long = 0L, val nodeResolverCalls: Long = 0L,
    val businessResolverCalls: Long = 0L, val hydraEnabled: Boolean = false, val hydraApplied: Boolean = false,
    val hydraScope: GoHydraScope = GoHydraScope.OFF, val hydraShapedRecords: Long = 0L, val hydraPaddingBytes: Long = 0L,
) {
    fun samePolicy(expected: CapturedNetworkPolicy): Boolean = policyInstalled && policyEpoch == expected.policyEpoch &&
        scopeId == expected.scopeId && dnsMode == expected.policy.dnsMode && dnsLeakPolicy == expected.policy.dnsLeakPolicy &&
        webrtcPolicy == expected.policy.webrtcPolicy && hydraEnabled == expected.policy.hydra.enabled &&
        dnsMapEntries.toUInt() <= expected.policy.dnsLimits.mapMaxEntries && dnsMapBytes.toULong() <= expected.policy.dnsLimits.mapMaxBytes.toULong()

    fun provesEnforced(ownershipPending: Boolean): Boolean = !ownershipPending && policyInstalled && policyEpoch != 0uL &&
        scopeId.matches(Regex("[0-9a-f]{64}")) && dnsMode != null && dnsLeakPolicy != null && webrtcPolicy != null &&
        enforcementActive && dnsProtectionEnforced && webrtcProtectionEnforced && ipv6DropActive &&
        (if (hydraEnabled) hydraApplied && hydraScope != GoHydraScope.OFF else !hydraApplied && hydraScope == GoHydraScope.OFF)
}
