package net.aptist.loft.service

import net.aptist.loft.core.generated.*
import net.aptist.loft.foundation.*

/** Mechanical record conversion. Rust remains the policy authority. */
object NetworkPrivacyAdapter {
    fun native(policy: NetworkPrivacyDraft) = NetworkPrivacyPolicy(DnsMode.valueOf(policy.dnsMode.name),
        LeakProtectionMode.valueOf(policy.dnsLeakPolicy.name), LeakProtectionMode.valueOf(policy.webrtcPolicy.name), policy.resolverEndpoint,
        with(policy.dnsLimits) { DnsPrivacyLimits(mapMaxEntries, mapMaxBytes, ttlSeconds, maxQueryBytes, maxResponseBytes) },
        with(policy.hydra) { HydraConfig(enabled, autoJitter, rotationSeconds, rotationJitterPercent, chunkMinPercent,
            burstMinRecords, burstMaxRecords, paddingGapMaxRecords) })

    fun draft(policy: NetworkPrivacyPolicy) = NetworkPrivacyDraft(NetworkDnsMode.valueOf(policy.dnsMode.name),
        NetworkLeakPolicy.valueOf(policy.dnsLeakPolicy.name), NetworkLeakPolicy.valueOf(policy.webrtcPolicy.name), policy.resolverEndpoint,
        with(policy.dnsLimits) { DnsLimitsDraft(mapMaxEntries, mapMaxBytes, ttlSeconds, maxQueryBytes, maxResponseBytes) },
        with(policy.hydra) { HydraDraft(enabled, autoJitter, rotationSeconds, rotationJitterPercent, chunkMinPercent,
            burstMinRecords, burstMaxRecords, paddingGapMaxRecords) })
}
