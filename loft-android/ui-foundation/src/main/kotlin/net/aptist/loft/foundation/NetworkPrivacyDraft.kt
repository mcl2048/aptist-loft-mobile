package net.aptist.loft.foundation

/** Mechanical IPC drafts; Rust owns validation, normalization and application. */
enum class NetworkDnsMode { NODE_DOMAIN_FAKE_IP, WIRE_TCP }
enum class NetworkLeakPolicy { PROXY_ONLY, BLOCK }
data class DnsLimitsDraft(val mapMaxEntries: UInt, val mapMaxBytes: UInt, val ttlSeconds: UInt,
    val maxQueryBytes: UInt, val maxResponseBytes: UInt)
data class HydraDraft(val enabled: Boolean, val autoJitter: Boolean, val rotationSeconds: UInt,
    val rotationJitterPercent: UInt, val chunkMinPercent: UInt, val burstMinRecords: UInt,
    val burstMaxRecords: UInt, val paddingGapMaxRecords: UInt)
data class NetworkPrivacyDraft(val dnsMode: NetworkDnsMode, val dnsLeakPolicy: NetworkLeakPolicy,
    val webrtcPolicy: NetworkLeakPolicy, val resolverEndpoint: String, val dnsLimits: DnsLimitsDraft, val hydra: HydraDraft)
