package net.aptist.loft.service

import net.aptist.loft.core.generated.*
import net.aptist.loft.foundation.ControlCodec
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.nio.ByteBuffer
import java.nio.CharBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.util.Collections

data class SnapshotFrame(val core: CoreSnapshot, val engineVersion: String, val transportReady: Boolean,
    val publicationSequence: ULong = 0uL, val tunHeld: Boolean = false,
    val forwardingDisabled: Boolean = true, val resourcesReleased: Boolean = true,
    val networkResources: NetworkResourceSnapshot? = null)
class SnapshotWireException : IllegalArgumentException("INVALID_SNAPSHOT")

// Mechanical IPC mapping only. AppCore exists exclusively in LoftCoreService.
object SnapshotWire {
    private const val MAGIC = 0x4C465333
    fun encode(frame: SnapshotFrame): ByteArray {
        try {
            validate(frame)
            val bytes = ByteArrayOutputStream()
            DataOutputStream(bytes).use { output ->
                val core = frame.core
                output.writeInt(MAGIC)
                output.writeLong(frame.publicationSequence.toLong())
                output.writeInt(core.schemaVersion.toInt())
                output.text(core.coreVersion, 64)
                output.writeInt(core.nodeCount.toInt())
                output.writeInt(core.nodes.size)
                core.nodes.forEach { node ->
                    output.text(node.id, 64); output.text(node.label, 64)
                    output.text(node.protocol.name, 32); output.text(node.endpoint, 300)
                    output.writeInt(node.udpMin.toInt()); output.writeInt(node.udpMax.toInt())
                    output.writeBoolean(node.credentialMaterialPresent)
                }
                output.writeBoolean(core.serverAddress != null)
                core.serverAddress?.let { output.text(it, 2048) }
                output.writeBoolean(core.serverVerified); output.writeBoolean(core.routingEnabled)
                output.writeInt(core.selectedApps.size)
                core.selectedApps.forEach { output.text(it, 255) }
                output.text(core.connectionState.name, 32)
                output.writeLong(core.generation.toLong())
                output.writeLong(core.connectionAttemptId.toLong())
                output.writeBoolean(core.activeNodeId != null)
                core.activeNodeId?.let { output.text(it, 64) }
                output.writeBoolean(core.appliedRouting != null)
                core.appliedRouting?.let { applied ->
                    output.writeBoolean(applied.enabled)
                    output.writeInt(applied.packageNames.size)
                    applied.packageNames.forEach { output.text(it, 255) }
                    output.text(applied.ipv6Policy.name, 32)
                }
                output.writeBoolean(core.vpnFailure != null)
                core.vpnFailure?.let { output.text(it.name, 32) }
                output.policy(core.networkPrivacyPolicy)
                output.writeLong(core.networkPrivacyPolicyEpoch.toLong())
                output.writeBoolean(core.appliedNetworkPrivacy != null)
                core.appliedNetworkPrivacy?.let { applied ->
                    output.writeLong(applied.policyEpoch.toLong()); output.text(applied.scopeId, 64)
                    output.policy(applied.policy); output.text(applied.hydraScope.name, 32)
                }
                output.text(core.networkPrivacyEnforcement.name, 32)
                output.text(frame.engineVersion, 64)
                output.writeBoolean(frame.transportReady)
                output.writeBoolean(frame.tunHeld)
                output.writeBoolean(frame.forwardingDisabled)
                output.writeBoolean(frame.resourcesReleased)
                output.writeBoolean(frame.networkResources != null)
                frame.networkResources?.let { output.resources(it) }
            }
            if (bytes.size() > ControlCodec.MAX_CONTROL_BYTES) throw SnapshotWireException()
            return bytes.toByteArray()
        } catch (failure: SnapshotWireException) { throw failure }
        catch (_: Exception) { throw SnapshotWireException() }
    }

    fun decode(payload: ByteArray): SnapshotFrame {
        if (payload.isEmpty() || payload.size > ControlCodec.MAX_CONTROL_BYTES) throw SnapshotWireException()
        try {
            DataInputStream(ByteArrayInputStream(payload)).use { input ->
                if (input.readInt() != MAGIC) throw SnapshotWireException()
                val publication = input.readLong().toULong()
                val schema = input.readInt().toUInt()
                if (schema != 2u) throw SnapshotWireException()
                val version = input.text(64)
                val count = input.readInt().toUInt()
                val rows = input.readInt()
                if (rows !in 0..50) throw SnapshotWireException()
                val nodes = List(rows) {
                    NodeSummary(id = input.text(64), label = input.text(64), protocol = ProtocolKind.valueOf(input.text(32)),
                        endpoint = input.text(300), udpMin = input.readInt().toUInt(), udpMax = input.readInt().toUInt(),
                        credentialMaterialPresent = input.strictBoolean())
                }
                val server = if (input.strictBoolean()) input.text(2048) else null
                val verified = input.strictBoolean()
                val routing = input.strictBoolean()
                val packageCount = input.readInt()
                if (packageCount !in 0..100) throw SnapshotWireException()
                val packages = List(packageCount) { input.text(255) }
                val connection = ConnectionState.valueOf(input.text(32))
                val generation = input.readLong().toULong()
                val attempt = input.readLong().toULong()
                val activeNode = if (input.strictBoolean()) input.text(64) else null
                val applied = if (input.strictBoolean()) {
                    val enabled = input.strictBoolean()
                    val appliedCount = input.readInt()
                    if (appliedCount !in 0..100) throw SnapshotWireException()
                    val names = List(appliedCount) { input.text(255) }
                    AppliedRouting(enabled, Collections.unmodifiableList(ArrayList(names)), Ipv6Policy.valueOf(input.text(32)))
                } else null
                val failure = if (input.strictBoolean()) VpnFailure.valueOf(input.text(32)) else null
                val policy = input.policy()
                val policyEpoch = input.readLong().toULong()
                val appliedPrivacy = if (input.strictBoolean()) AppliedNetworkPrivacy(input.readLong().toULong(),
                    input.text(64), input.policy(), HydraScope.valueOf(input.text(32))) else null
                val privacyEnforcement = NetworkPrivacyEnforcement.valueOf(input.text(32))
                val engineVersion = input.text(64)
                val ready = input.strictBoolean()
                val held = input.strictBoolean()
                val disabled = input.strictBoolean()
                val released = input.strictBoolean()
                val networkResources = if (input.strictBoolean()) input.resources() else null
                if (input.available() != 0) throw SnapshotWireException()
                val core = CoreSnapshot(schemaVersion = schema, coreVersion = version,
                    nodes = Collections.unmodifiableList(ArrayList(nodes)), nodeCount = count, serverAddress = server,
                    serverVerified = verified, routingEnabled = routing,
                    selectedApps = Collections.unmodifiableList(ArrayList(packages)), connectionState = connection, generation = generation,
                    connectionAttemptId = attempt, activeNodeId = activeNode, appliedRouting = applied, vpnFailure = failure,
                    networkPrivacyPolicy = policy, networkPrivacyPolicyEpoch = policyEpoch, appliedNetworkPrivacy = appliedPrivacy,
                    networkPrivacyEnforcement = privacyEnforcement)
                return SnapshotFrame(core, engineVersion, ready, publication, held, disabled, released, networkResources).also(::validate)
            }
        } catch (failure: SnapshotWireException) { throw failure }
        catch (_: Exception) { throw SnapshotWireException() }
    }

    private fun validate(frame: SnapshotFrame) {
        val core = frame.core
        if (frame.publicationSequence == 0uL || core.schemaVersion != 2u || core.nodeCount > 200u || core.nodes.size > 50 ||
            core.nodes.size > core.nodeCount.toInt() || core.serverVerified || core.activeNodeId?.length?.let { it > 64 } == true) throw SnapshotWireException()
        validatePackages(core.selectedApps)
        core.appliedRouting?.let {
            validatePackages(it.packageNames)
            if (it.ipv6Policy != Ipv6Policy.BLOCKED_IN_VPN || it.enabled == it.packageNames.isEmpty()) throw SnapshotWireException()
        }
        if (core.networkPrivacyPolicyEpoch == 0uL) throw SnapshotWireException()
        GoNetworkPolicy.validate(NetworkPrivacyAdapter.draft(core.networkPrivacyPolicy))
        core.appliedNetworkPrivacy?.let { applied ->
            if (applied.policyEpoch == 0uL || applied.policyEpoch > core.networkPrivacyPolicyEpoch ||
                !applied.scopeId.matches(Regex("[0-9a-f]{64}"))) throw SnapshotWireException()
            GoNetworkPolicy.validate(NetworkPrivacyAdapter.draft(applied.policy))
            if ((!applied.policy.hydra.enabled && applied.hydraScope != HydraScope.OFF) ||
                (core.networkPrivacyEnforcement == NetworkPrivacyEnforcement.ACTIVE && applied.policy.hydra.enabled && applied.hydraScope == HydraScope.OFF) ||
                (core.networkPrivacyEnforcement == NetworkPrivacyEnforcement.BLOCKED && applied.hydraScope != HydraScope.OFF)) throw SnapshotWireException()
        }
        when (core.connectionState) {
            ConnectionState.CONNECTED -> if (core.networkPrivacyEnforcement != NetworkPrivacyEnforcement.ACTIVE || core.appliedNetworkPrivacy == null) throw SnapshotWireException()
            ConnectionState.BLOCKED -> if (core.networkPrivacyEnforcement != NetworkPrivacyEnforcement.BLOCKED || core.appliedNetworkPrivacy == null) throw SnapshotWireException()
            else -> if (core.networkPrivacyEnforcement != NetworkPrivacyEnforcement.INACTIVE) throw SnapshotWireException()
        }
        if (core.connectionState in setOf(ConnectionState.DISCONNECTED, ConnectionState.UNAVAILABLE) && core.appliedNetworkPrivacy != null) throw SnapshotWireException()
        if (frame.resourcesReleased && (frame.tunHeld || frame.transportReady || !frame.forwardingDisabled)) throw SnapshotWireException()
        when (core.connectionState) {
            ConnectionState.CONNECTED -> if (!frame.transportReady || !frame.tunHeld || frame.forwardingDisabled || frame.resourcesReleased ||
                core.connectionAttemptId == 0uL || core.activeNodeId == null || core.appliedRouting == null) throw SnapshotWireException()
            ConnectionState.BLOCKED -> if (frame.transportReady || !frame.tunHeld || !frame.forwardingDisabled || frame.resourcesReleased ||
                core.appliedRouting == null) throw SnapshotWireException()
            ConnectionState.DISCONNECTED -> if (frame.transportReady || frame.tunHeld) throw SnapshotWireException()
            ConnectionState.CONNECTING, ConnectionState.STOPPING, ConnectionState.UNAVAILABLE -> if (frame.transportReady) throw SnapshotWireException()
        }
        frame.networkResources?.let { validateResources(it, frame) }
    }

    private fun validateResources(resources: NetworkResourceSnapshot, frame: SnapshotFrame) {
        val core = frame.core
        if (resources.attemptId == 0uL || resources.attemptId != core.connectionAttemptId || resources.policyEpoch == 0uL ||
            resources.policyEpoch > core.networkPrivacyPolicyEpoch || !resources.scopeId.matches(Regex("[0-9a-f]{64}"))) throw SnapshotWireException()
        GoNetworkPolicy.validate(NetworkPrivacyAdapter.draft(resources.policy))
        if (resources.physicalOpen !in 0..4096 || resources.activeFlows !in 0..4096 || resources.queuedBytes !in 0L..7847936L ||
            resources.dnsAllocatorBytes != 540672L || resources.dnsMapEntries < 0 ||
            resources.dnsMapEntries.toUInt() > resources.policy.dnsLimits.mapMaxEntries || resources.dnsMapBytes < 0L ||
            resources.dnsMapBytes.toULong() > resources.policy.dnsLimits.mapMaxBytes.toULong() ||
            listOf(resources.dnsSyntheticCount, resources.dnsValidatedWireCount, resources.dnsPolicyDropCount,
                resources.webrtcClassifiedCount, resources.webrtcPolicyDropCount, resources.nodeResolverCalls,
                resources.businessResolverCalls, resources.hydraShapedRecords, resources.hydraPaddingBytes).any { it < 0L }) throw SnapshotWireException()
        if (resources.finalized) {
            if (core.connectionState !in setOf(ConnectionState.DISCONNECTED, ConnectionState.UNAVAILABLE) ||
                core.appliedNetworkPrivacy != null || !frame.resourcesReleased || frame.transportReady || frame.tunHeld ||
                !frame.forwardingDisabled || resources.ownershipPending || resources.physicalOpen != 0 ||
                resources.activeFlows != 0 || resources.queuedBytes != 0L || resources.dnsMapEntries != 0 || resources.dnsMapBytes != 0L) throw SnapshotWireException()
        } else {
            val applied = core.appliedNetworkPrivacy ?: throw SnapshotWireException()
            if (applied.policyEpoch != resources.policyEpoch || applied.scopeId != resources.scopeId || applied.policy != resources.policy ||
                frame.resourcesReleased || (core.connectionState in setOf(ConnectionState.CONNECTED, ConnectionState.BLOCKED) && resources.ownershipPending)) throw SnapshotWireException()
        }
    }
    private fun validatePackages(packages: List<String>) {
        if (packages.size > 100 || packages.any { it.length > 255 } ||
            packages.sumOf { it.toByteArray(Charsets.UTF_8).size } > 4096) throw SnapshotWireException()
    }
    private fun DataOutputStream.policy(policy: NetworkPrivacyPolicy) {
        text(policy.dnsMode.name, 32); text(policy.dnsLeakPolicy.name, 32); text(policy.webrtcPolicy.name, 32)
        text(policy.resolverEndpoint, 64)
        with(policy.dnsLimits) {
            listOf(mapMaxEntries, mapMaxBytes, ttlSeconds, maxQueryBytes, maxResponseBytes).forEach { writeInt(it.toInt()) }
        }
        with(policy.hydra) {
            writeBoolean(enabled); writeBoolean(autoJitter)
            listOf(rotationSeconds, rotationJitterPercent, chunkMinPercent, burstMinRecords, burstMaxRecords, paddingGapMaxRecords)
                .forEach { writeInt(it.toInt()) }
        }
    }
    private fun DataInputStream.policy(): NetworkPrivacyPolicy {
        val mode = DnsMode.valueOf(text(32)); val dns = LeakProtectionMode.valueOf(text(32)); val rtc = LeakProtectionMode.valueOf(text(32))
        val resolver = text(64)
        val limits = DnsPrivacyLimits(readInt().toUInt(), readInt().toUInt(), readInt().toUInt(), readInt().toUInt(), readInt().toUInt())
        val hydra = HydraConfig(strictBoolean(), strictBoolean(), readInt().toUInt(), readInt().toUInt(), readInt().toUInt(),
            readInt().toUInt(), readInt().toUInt(), readInt().toUInt())
        return NetworkPrivacyPolicy(mode, dns, rtc, resolver, limits, hydra)
    }

    private fun DataOutputStream.resources(value: NetworkResourceSnapshot) {
        writeLong(value.attemptId.toLong()); writeLong(value.policyEpoch.toLong()); text(value.scopeId, 64); policy(value.policy)
        writeBoolean(value.finalized); writeInt(value.physicalOpen); writeInt(value.activeFlows); writeLong(value.queuedBytes)
        writeLong(value.dnsAllocatorBytes); writeInt(value.dnsMapEntries); writeLong(value.dnsMapBytes)
        listOf(value.dnsSyntheticCount, value.dnsValidatedWireCount, value.dnsPolicyDropCount, value.webrtcClassifiedCount,
            value.webrtcPolicyDropCount, value.nodeResolverCalls, value.businessResolverCalls, value.hydraShapedRecords,
            value.hydraPaddingBytes).forEach { writeLong(it) }
        writeBoolean(value.ownershipPending)
    }

    private fun DataInputStream.resources() = NetworkResourceSnapshot(readLong().toULong(), readLong().toULong(), text(64), policy(),
        strictBoolean(), readInt(), readInt(), readLong(), readLong(), readInt(), readLong(), readLong(), readLong(), readLong(),
        readLong(), readLong(), readLong(), readLong(), readLong(), readLong(), strictBoolean())
    private fun DataOutputStream.text(value: String, limit: Int) {
        if (value.length > limit) throw SnapshotWireException()
        val buffer = StandardCharsets.UTF_8.newEncoder().onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT).encode(CharBuffer.wrap(value))
        if (buffer.remaining() > limit) throw SnapshotWireException()
        writeInt(buffer.remaining())
        val bytes = ByteArray(buffer.remaining()).also { buffer.get(it) }
        write(bytes)
    }
    private fun DataInputStream.text(limit: Int): String {
        val length = readInt()
        if (length < 0 || length > limit || length > available()) throw SnapshotWireException()
        val bytes = ByteArray(length).also { readFully(it) }
        return StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString()
    }
    private fun DataInputStream.strictBoolean(): Boolean = when (readUnsignedByte()) { 0 -> false; 1 -> true; else -> throw SnapshotWireException() }
}
