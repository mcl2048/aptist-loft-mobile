package net.aptist.loft.service

import net.aptist.loft.foundation.*
import org.junit.Assert.*
import org.junit.Test

class GoNetworkPolicyTest {
    private val scope = "a".repeat(64)
    private val draft = NetworkPrivacyDraft(NetworkDnsMode.NODE_DOMAIN_FAKE_IP, NetworkLeakPolicy.PROXY_ONLY,
        NetworkLeakPolicy.PROXY_ONLY, "", DnsLimitsDraft(256u, 262144u, 60u, 4096u, 65535u),
        HydraDraft(false, false, 300u, 0u, 0u, 0u, 0u, 0u))
    private fun canonical() = """{"schema_version":1,"policy_epoch":"18446744073709551615","scope_id":"$scope","dns_mode":"node_domain_fake_ip","dns_leak_policy":"proxy_only","webrtc_policy":"proxy_only","resolver_endpoint":"","dns_map_max_entries":256,"dns_map_max_bytes":262144,"dns_ttl_seconds":60,"dns_max_query_bytes":4096,"dns_max_response_bytes":65535,"hydra":{"enabled":false,"auto_jitter":false,"rotation_seconds":300,"rotation_jitter_percent":0,"chunk_min_percent":0,"burst_min_records":0,"burst_max_records":0,"padding_gap_max_records":0}}"""

    // A native string is transferred only if it describes the captured Rust ticket.
    @Test fun exactCanonicalPolicyRetainsCapturedUnsignedEpochScopeAndAllFields() {
        val decoded = GoNetworkPolicy.decodeCanonical(canonical(), ULong.MAX_VALUE, scope, draft)
        assertEquals(ULong.MAX_VALUE, decoded.policyEpoch)
        assertEquals(scope, decoded.scopeId)
        assertEquals(draft, decoded.policy)
    }

    @Test fun mismatchedOrNonCanonicalEpochAndScopeAreRejected() {
        invalid(canonical(), epoch = 1uL)
        invalid(canonical(), identity = "b".repeat(64))
        invalid(canonical().replace("18446744073709551615", "01"))
        invalid(canonical().replace("18446744073709551615", "18446744073709551616"))
        invalid(canonical().replace(scope, scope.uppercase()))
        invalid(canonical().replace("\"18446744073709551615\"", "1"))
    }

    @Test fun duplicateUnknownCoercedAndTrailingNativeFieldsCannotInstallPolicy() {
        invalid(canonical().replace("\"schema_version\":1", "\"schema_version\":1,\"schema_version\":1"))
        invalid(canonical().replace("\"enabled\":false", "\"enabled\":false,\"enabled\":false"))
        invalid(canonical().replace("\"schema_version\":1", "\"schema_version\":1,\"direct_fallback\":true"))
        invalid(canonical().replace("\"enabled\":false", "\"enabled\":\"false\""))
        invalid(canonical().replace("\"dns_map_max_entries\":256", "\"dns_map_max_entries\":256.0"))
        invalid(canonical() + "{}")
        invalid(" ".repeat(4097))
    }

    @Test fun changedModesAndLimitsCannotReplaceTheCapturedPolicy() {
        invalid(canonical().replace("\"dns_leak_policy\":\"proxy_only\"", "\"dns_leak_policy\":\"block\""))
        invalid(canonical().replace("\"webrtc_policy\":\"proxy_only\"", "\"webrtc_policy\":\"allow\""))
        invalid(canonical().replace("\"dns_map_max_bytes\":262144", "\"dns_map_max_bytes\":261120"))
        invalid(canonical().replace("\"dns_ttl_seconds\":60", "\"dns_ttl_seconds\":61"))
        invalid(canonical().replace("\"rotation_jitter_percent\":0", "\"rotation_jitter_percent\":41"))
        invalid(canonical().replace("\"chunk_min_percent\":0", "\"chunk_min_percent\":24"))
    }

    @Test fun wireTcpRequiresLiteralResolverAndFakeModeCannotAddOne() {
        invalid(canonical().replace("\"resolver_endpoint\":\"\"", "\"resolver_endpoint\":\"9.9.9.9:53\""))
        val wire = draft.copy(dnsMode = NetworkDnsMode.WIRE_TCP, resolverEndpoint = "9.9.9.9:53")
        val raw = canonical().replace("node_domain_fake_ip", "wire_tcp")
            .replace("\"resolver_endpoint\":\"\"", "\"resolver_endpoint\":\"9.9.9.9:53\"")
        assertEquals(wire, GoNetworkPolicy.decodeCanonical(raw, ULong.MAX_VALUE, scope, wire).policy)
        invalid(raw.replace("9.9.9.9:53", "resolver.invalid:53"), policy = wire)
        invalid(raw.replace("9.9.9.9:53", "0.0.0.0:53"), policy = wire)
    }

    private fun invalid(raw: String, epoch: ULong = ULong.MAX_VALUE, identity: String = scope,
        policy: NetworkPrivacyDraft = draft) {
        try { GoNetworkPolicy.decodeCanonical(raw, epoch, identity, policy); fail("INVALID_POLICY_TRANSFER_ADMITTED") }
        catch (_: GoNetworkPolicyException) { }
    }
}
