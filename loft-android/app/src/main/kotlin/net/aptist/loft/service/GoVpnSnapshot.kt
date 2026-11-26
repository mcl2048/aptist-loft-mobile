package net.aptist.loft.service

import org.json.JSONObject
import net.aptist.loft.foundation.NetworkDnsMode
import net.aptist.loft.foundation.NetworkLeakPolicy

enum class GoVpnState(val wire: String) {
    IDLE("idle"), STARTING("starting"), RUNNING("running"), DRAINING("draining"), BLOCKED("blocked"),
    STOPPING("stopping"), STOPPED("stopped"), CLOSED("closed"), FAILED("failed"), UNAVAILABLE("unavailable")
}

data class GoVpnFacts(val generation: Long, val state: GoVpnState, val transportReady: Boolean,
    val authenticated: Boolean, val tunReady: Boolean, val tunOwned: Boolean, val socketsProtected: Boolean,
    val forwardingDisabled: Boolean, val resourcesReleased: Boolean, val ownershipPending: Boolean, val physicalOpen: Int,
    val activeFlows: Int, val queuedBytes: Long, val errorCode: String,
    val privacy: GoNetworkPrivacyFacts = GoNetworkPrivacyFacts()) {
    val provesForwardingDisabled: Boolean get() = forwardingDisabled && !ownershipPending
    val provesReady: Boolean get() = generation > 0 && state == GoVpnState.RUNNING && transportReady && authenticated &&
        tunReady && tunOwned && socketsProtected && !forwardingDisabled && !resourcesReleased && !ownershipPending && privacy.provesEnforced(ownershipPending)
    val provesReleased: Boolean get() = state in setOf(GoVpnState.STOPPED, GoVpnState.CLOSED) && resourcesReleased && !ownershipPending &&
        forwardingDisabled && !transportReady && !authenticated && !tunReady && !tunOwned && !socketsProtected && physicalOpen == 0 && activeFlows == 0 && queuedBytes == 0L &&
        privacy.dnsMapEntries == 0 && privacy.dnsMapBytes == 0L && !privacy.enforcementActive && !privacy.dnsProtectionEnforced &&
        !privacy.webrtcProtectionEnforced && !privacy.ipv6DropActive && !privacy.hydraApplied && privacy.hydraScope == GoHydraScope.OFF
}
class GoSnapshotException : IllegalArgumentException("INVALID_ENGINE_SNAPSHOT")
object GoVpnSnapshot {
    fun decode(raw: String): GoVpnFacts {
        if (raw.isEmpty() || raw.length > 8192 || raw.toByteArray(Charsets.UTF_8).size > 8192) throw GoSnapshotException()
        try {
            val json = flatObject(raw)
            if (json.integer("schema_version") != 1L) throw GoSnapshotException()
            val generation = json.integer("generation")
            val state = GoVpnState.entries.firstOrNull { it.wire == json.get("runtime_state") } ?: throw GoSnapshotException()
            val physical = json.integer("physical_open")
            val flows = json.integer("active_flows")
            val queued = json.integer("queued_bytes")
            // [bytes] Fixed 528 KiB allocator is separate from the dynamic ledger.
            if (generation < 0 || physical !in 0..4096L || flows !in 0..4096L || queued !in 0..7847936L) throw GoSnapshotException()
            val code = if (json.has("error_code")) json.get("error_code") as? String ?: throw GoSnapshotException() else ""
            if (code.isNotEmpty() && !code.matches(Regex("loft\\.vpn\\.[a-z0-9_.]{1,80}"))) throw GoSnapshotException()
            return GoVpnFacts(generation, state, json.boolean("transport_ready"), json.boolean("authenticated"),
                json.boolean("tun_ready"), json.boolean("tun_owned"), json.boolean("socket_protection_succeeded"),
                json.boolean("forwarding_disabled"), json.boolean("resources_released"), json.boolean("ownership_pending"),
                physical.toInt(), flows.toInt(), queued, code, privacy(json))
        } catch (failure: GoSnapshotException) { throw failure }
        catch (_: Exception) { throw GoSnapshotException() }
    }
    private val resourceKeys = setOf("schema_version", "generation", "runtime_state", "transport_ready", "authenticated", "tun_ready", "tun_owned",
        "socket_protection_succeeded", "forwarding_disabled", "resources_released", "ownership_pending", "physical_open", "active_flows", "queued_bytes", "error_code",
        "policy_installed", "policy_epoch", "scope_id", "dns_mode", "dns_leak_policy", "webrtc_policy", "enforcement_active", "dns_protection_enforced",
        "webrtc_protection_enforced", "ipv6_drop_active", "dns_allocator_bytes", "dns_map_entries", "dns_map_bytes", "dns_synthetic_count", "dns_validated_wire_count",
        "dns_policy_drop_count", "webrtc_classified_count", "webrtc_policy_drop_count", "node_resolver_calls", "business_resolver_calls", "hydra_enabled",
        "hydra_applied", "hydra_scope", "hydra_shaped_records", "hydra_padding_bytes")

    // This schema is flat and integer-only. Read the actual end position so
    // Android JSONTokener's permissive syntax/NUL sentinel cannot be a receipt.
    private fun flatObject(raw: String): JSONObject {
        val input = FlatReader(raw)
        input.expect('{')
        val result = JSONObject()
        val seen = HashSet<String>()
        if (input.peek() == '}') throw GoSnapshotException()
        while (true) {
            val name = input.string()
            if (name !in resourceKeys || !seen.add(name)) throw GoSnapshotException()
            input.expect(':')
            result.put(name, input.value())
            when (input.peek()) {
                '}' -> { input.expect('}'); input.end(); return result }
                ',' -> input.expect(',')
                else -> throw GoSnapshotException()
            }
        }
    }

    private class FlatReader(private val raw: String) {
        private var position = 0
        private fun whitespace() { while (position < raw.length && raw[position] in " \t\r\n") position++ }
        fun peek(): Char { whitespace(); return raw.getOrNull(position) ?: throw GoSnapshotException() }
        fun expect(value: Char) { if (peek() != value) throw GoSnapshotException(); position++ }
        fun end() { whitespace(); if (position != raw.length) throw GoSnapshotException() }
        fun value(): Any = when (peek()) {
            '"' -> string()
            't' -> literal("true", true)
            'f' -> literal("false", false)
            '-', in '0'..'9' -> integer()
            else -> throw GoSnapshotException()
        }
        private fun literal(text: String, value: Boolean): Boolean {
            if (!raw.startsWith(text, position)) throw GoSnapshotException()
            position += text.length
            return value
        }
        private fun integer(): Long {
            val start = position
            if (raw[position] == '-') position++
            val first = raw.getOrNull(position) ?: throw GoSnapshotException()
            if (first == '0') {
                position++
                if (raw.getOrNull(position) in '0'..'9') throw GoSnapshotException()
            } else {
                if (first !in '1'..'9') throw GoSnapshotException()
                while (raw.getOrNull(position) in '0'..'9') position++
            }
            return raw.substring(start, position).toLongOrNull() ?: throw GoSnapshotException()
        }
        fun string(): String {
            expect('"')
            val decoded = StringBuilder()
            while (position < raw.length) {
                val next = raw[position++]
                when {
                    next == '"' -> return decoded.toString()
                    next < ' ' -> throw GoSnapshotException()
                    next != '\\' -> decoded.append(next)
                    else -> {
                        val escaped = raw.getOrNull(position++) ?: throw GoSnapshotException()
                        decoded.append(when (escaped) {
                            '"', '\\', '/' -> escaped
                            'b' -> '\b'
                            'f' -> '\u000c'
                            'n' -> '\n'
                            'r' -> '\r'
                            't' -> '\t'
                            'u' -> {
                                if (position + 4 > raw.length) throw GoSnapshotException()
                                val code = raw.substring(position, position + 4)
                                if (code.any { it !in '0'..'9' && it !in 'a'..'f' && it !in 'A'..'F' }) throw GoSnapshotException()
                                position += 4
                                code.toInt(16).toChar()
                            }
                            else -> throw GoSnapshotException()
                        })
                    }
                }
            }
            throw GoSnapshotException()
        }
    }
    private fun privacy(json: JSONObject): GoNetworkPrivacyFacts {
        val installed = json.boolean("policy_installed")
        val epochText = json.get("policy_epoch") as? String ?: throw GoSnapshotException()
        val scope = json.get("scope_id") as? String ?: throw GoSnapshotException()
        val epoch = if (installed) {
            if (!epochText.matches(Regex("[1-9][0-9]{0,19}"))) throw GoSnapshotException()
            epochText.toULongOrNull() ?: throw GoSnapshotException()
        } else { if (epochText.isNotEmpty() || scope.isNotEmpty()) throw GoSnapshotException(); 0uL }
        if (installed && !scope.matches(Regex("[0-9a-f]{64}"))) throw GoSnapshotException()
        fun mode(name: String): String = (json.get(name) as? String ?: throw GoSnapshotException()).also {
            if (!installed && it.isNotEmpty()) throw GoSnapshotException()
        }
        val dns = when (mode("dns_mode")) {
            "node_domain_fake_ip" -> NetworkDnsMode.NODE_DOMAIN_FAKE_IP
            "wire_tcp" -> NetworkDnsMode.WIRE_TCP
            "" -> if (!installed) null else throw GoSnapshotException()
            else -> throw GoSnapshotException()
        }
        fun leak(name: String): NetworkLeakPolicy? = when (mode(name)) {
            "proxy_only" -> NetworkLeakPolicy.PROXY_ONLY
            "block" -> NetworkLeakPolicy.BLOCK
            "" -> if (!installed) null else throw GoSnapshotException()
            else -> throw GoSnapshotException()
        }
        fun counter(name: String): Long = json.integer(name).also { if (it < 0L) throw GoSnapshotException() }
        val allocator = counter("dns_allocator_bytes")
        val entries = counter("dns_map_entries")
        val bytes = counter("dns_map_bytes")
        if (allocator != 540672L || entries > 256L || bytes > 262144L) throw GoSnapshotException()
        val hydraScope = GoHydraScope.entries.firstOrNull { it.wire == json.get("hydra_scope") } ?: throw GoSnapshotException()
        val facts = GoNetworkPrivacyFacts(installed, epoch, scope, dns, leak("dns_leak_policy"), leak("webrtc_policy"),
            json.boolean("enforcement_active"), json.boolean("dns_protection_enforced"), json.boolean("webrtc_protection_enforced"),
            json.boolean("ipv6_drop_active"), allocator, entries.toInt(), bytes, counter("dns_synthetic_count"),
            counter("dns_validated_wire_count"), counter("dns_policy_drop_count"), counter("webrtc_classified_count"),
            counter("webrtc_policy_drop_count"), counter("node_resolver_calls"), counter("business_resolver_calls"),
            json.boolean("hydra_enabled"), json.boolean("hydra_applied"), hydraScope, counter("hydra_shaped_records"), counter("hydra_padding_bytes"))
        if (!facts.hydraEnabled && (facts.hydraApplied || facts.hydraScope != GoHydraScope.OFF)) throw GoSnapshotException()
        if (!installed && (facts.enforcementActive || facts.dnsProtectionEnforced || facts.webrtcProtectionEnforced || facts.ipv6DropActive ||
            facts.hydraEnabled || facts.hydraApplied || facts.dnsMapEntries != 0 || facts.dnsMapBytes != 0L ||
            facts.dnsSyntheticCount != 0L || facts.dnsValidatedWireCount != 0L || facts.dnsPolicyDropCount != 0L ||
            facts.webrtcClassifiedCount != 0L || facts.webrtcPolicyDropCount != 0L || facts.nodeResolverCalls != 0L ||
            facts.businessResolverCalls != 0L || facts.hydraShapedRecords != 0L || facts.hydraPaddingBytes != 0L)) throw GoSnapshotException()
        return facts
    }
    private fun JSONObject.boolean(name: String): Boolean = get(name) as? Boolean ?: throw GoSnapshotException()
    private fun JSONObject.integer(name: String): Long = when (val value = get(name)) {
        is Int -> value.toLong()
        is Long -> value
        else -> throw GoSnapshotException()
    }
}
