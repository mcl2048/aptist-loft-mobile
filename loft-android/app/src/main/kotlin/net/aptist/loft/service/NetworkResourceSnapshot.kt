package net.aptist.loft.service

import net.aptist.loft.core.generated.NetworkPrivacyPolicy

/** Scoped resource usage/history only. These totals never authorize forwarding. */
data class NetworkResourceSnapshot(
    val attemptId: ULong, val policyEpoch: ULong, val scopeId: String, val policy: NetworkPrivacyPolicy,
    val finalized: Boolean = false, val physicalOpen: Int = 0, val activeFlows: Int = 0, val queuedBytes: Long = 0L,
    val dnsAllocatorBytes: Long = 540672L, val dnsMapEntries: Int = 0, val dnsMapBytes: Long = 0L,
    val dnsSyntheticCount: Long = 0L, val dnsValidatedWireCount: Long = 0L, val dnsPolicyDropCount: Long = 0L,
    val webrtcClassifiedCount: Long = 0L, val webrtcPolicyDropCount: Long = 0L, val nodeResolverCalls: Long = 0L,
    val businessResolverCalls: Long = 0L, val hydraShapedRecords: Long = 0L, val hydraPaddingBytes: Long = 0L,
    val ownershipPending: Boolean = false,
) {
    override fun toString() = "NetworkResourceSnapshot(<redacted>)"
    companion object {
        fun from(attemptId: ULong, expected: CapturedNetworkPolicy, facts: GoVpnFacts): NetworkResourceSnapshot? {
            if (attemptId == 0uL || !facts.privacy.samePolicy(expected)) return null
            val privacy = facts.privacy
            return NetworkResourceSnapshot(attemptId, expected.policyEpoch, expected.scopeId,
                NetworkPrivacyAdapter.native(expected.policy), facts.provesReleased, facts.physicalOpen, facts.activeFlows, facts.queuedBytes,
                privacy.dnsAllocatorBytes, privacy.dnsMapEntries, privacy.dnsMapBytes, privacy.dnsSyntheticCount,
                privacy.dnsValidatedWireCount, privacy.dnsPolicyDropCount, privacy.webrtcClassifiedCount, privacy.webrtcPolicyDropCount,
                privacy.nodeResolverCalls, privacy.businessResolverCalls, privacy.hydraShapedRecords, privacy.hydraPaddingBytes,
                facts.ownershipPending)
        }
    }
}
