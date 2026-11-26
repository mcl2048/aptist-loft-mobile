package net.aptist.loft.service

import net.aptist.loft.foundation.*
import java.nio.CharBuffer
import java.nio.charset.CodingErrorAction

data class CapturedNetworkPolicy(val policyEpoch: ULong, val scopeId: String, val policy: NetworkPrivacyDraft)
class GoNetworkPolicyException : IllegalArgumentException("INVALID_NETWORK_POLICY")

object GoNetworkPolicy {
    fun decodeCanonical(raw: String, expectedEpoch: ULong, expectedScopeId: String,
        expectedPolicy: NetworkPrivacyDraft): CapturedNetworkPolicy {
        try {
            require(raw.isNotEmpty() && raw.length <= 4096 && expectedEpoch != 0uL && expectedScopeId.matches(Regex("[0-9a-f]{64}")))
            val encoded = Charsets.UTF_8.newEncoder().onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT).encode(CharBuffer.wrap(raw))
            require(encoded.remaining() <= 4096)
            validate(expectedPolicy)
            // The source ticket defines deterministic field order and normalized
            // literal strings. Exact equality rejects duplicates/unknown fields,
            // coercions, missing values, stale scope and trailing JSON at once.
            require(raw == canonical(expectedEpoch, expectedScopeId, expectedPolicy))
            return CapturedNetworkPolicy(expectedEpoch, expectedScopeId, expectedPolicy)
        } catch (_: Exception) { throw GoNetworkPolicyException() }
    }

    fun validate(policy: NetworkPrivacyDraft) {
        with(policy.dnsLimits) {
            require(mapMaxEntries in 1u..256u && mapMaxBytes in 1024u..262144u &&
                mapMaxBytes.toULong() >= mapMaxEntries.toULong() * 1024uL)
            require(ttlSeconds in 1u..60u && maxQueryBytes in 12u..4096u && maxResponseBytes in 12u..65535u)
        }
        if (policy.dnsMode == NetworkDnsMode.NODE_DOMAIN_FAKE_IP) require(policy.resolverEndpoint.isEmpty())
        else validateResolver(policy.resolverEndpoint)
        with(policy.hydra) {
            require(rotationSeconds in 10u..86400u && rotationJitterPercent <= 40u &&
                (chunkMinPercent == 0u || chunkMinPercent in 25u..50u) && burstMinRecords <= 32u &&
                burstMaxRecords <= 32u && paddingGapMaxRecords <= 64u)
            require((if (burstMinRecords == 0u) 2u else burstMinRecords) <= (if (burstMaxRecords == 0u) 32u else burstMaxRecords))
        }
    }

    private fun validateResolver(endpoint: String) {
        require(endpoint.length <= 64)
        val parts = endpoint.split(':')
        require(parts.size == 2 && parts[1].isNotEmpty() && parts[1].all { it in '0'..'9' })
        val port = parts[1].toInt()
        val text = parts[0].split('.')
        require(text.size == 4 && text.all { it.isNotEmpty() && it.length <= 3 && it.all { character -> character in '0'..'9' } })
        val octets = text.map(String::toInt)
        require(octets.all { it in 0..255 } && octets.any { it != 0 } && octets[0] !in 224..239 && port in 1..65535)
        require(endpoint == octets.joinToString(".") + ":" + port)
    }

    private fun canonical(epoch: ULong, scope: String, policy: NetworkPrivacyDraft): String = buildString {
        append("{\"schema_version\":1,\"policy_epoch\":\"").append(epoch).append("\",\"scope_id\":\"").append(scope)
        append("\",\"dns_mode\":\"").append(if (policy.dnsMode == NetworkDnsMode.NODE_DOMAIN_FAKE_IP) "node_domain_fake_ip" else "wire_tcp")
        append("\",\"dns_leak_policy\":\"").append(if (policy.dnsLeakPolicy == NetworkLeakPolicy.PROXY_ONLY) "proxy_only" else "block")
        append("\",\"webrtc_policy\":\"").append(if (policy.webrtcPolicy == NetworkLeakPolicy.PROXY_ONLY) "proxy_only" else "block")
        append("\",\"resolver_endpoint\":\"").append(policy.resolverEndpoint).append('"')
        with(policy.dnsLimits) {
            append(",\"dns_map_max_entries\":").append(mapMaxEntries).append(",\"dns_map_max_bytes\":").append(mapMaxBytes)
            append(",\"dns_ttl_seconds\":").append(ttlSeconds).append(",\"dns_max_query_bytes\":").append(maxQueryBytes)
            append(",\"dns_max_response_bytes\":").append(maxResponseBytes)
        }
        with(policy.hydra) {
            append(",\"hydra\":{\"enabled\":").append(enabled).append(",\"auto_jitter\":").append(autoJitter)
            append(",\"rotation_seconds\":").append(rotationSeconds).append(",\"rotation_jitter_percent\":").append(rotationJitterPercent)
            append(",\"chunk_min_percent\":").append(chunkMinPercent).append(",\"burst_min_records\":").append(burstMinRecords)
            append(",\"burst_max_records\":").append(burstMaxRecords).append(",\"padding_gap_max_records\":").append(paddingGapMaxRecords)
        }
        append("}}")
    }
}
