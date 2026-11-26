package net.aptist.loft.foundation

import org.junit.Assert.*
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.io.DataOutputStream

class NetworkPrivacyCommandTest {
    private val policy = NetworkPrivacyDraft(NetworkDnsMode.WIRE_TCP, NetworkLeakPolicy.BLOCK,
        NetworkLeakPolicy.PROXY_ONLY, "9.9.9.9:53", DnsLimitsDraft(128u, 131072u, 30u, 2048u, 32768u),
        HydraDraft(true, true, 600u, 20u, 40u, 4u, 8u, 16u))

    // Detect a dropped policy field or generation in the actual Binder command.
    @Test fun policyAndGenerationCrossTheExistingBoundedCommandPath() {
        val command = ControlCodec.decode(ControlCodec.encode(CoreCommand.SetNetworkPrivacyPolicy(policy, ULong.MAX_VALUE)))
        assertTrue("POLICY_COMMAND_REQUIRED", command is CoreCommand.SetNetworkPrivacyPolicy)
        val decoded = command as CoreCommand.SetNetworkPrivacyPolicy
        assertEquals(ULong.MAX_VALUE, decoded.expectedGeneration)
        assertEquals(NetworkDnsMode.WIRE_TCP, decoded.policy.dnsMode)
        assertEquals(NetworkLeakPolicy.BLOCK, decoded.policy.dnsLeakPolicy)
        assertEquals(NetworkLeakPolicy.PROXY_ONLY, decoded.policy.webrtcPolicy)
        assertEquals("9.9.9.9:53", decoded.policy.resolverEndpoint)
        assertEquals(DnsLimitsDraft(128u, 131072u, 30u, 2048u, 32768u), decoded.policy.dnsLimits)
        assertEquals(HydraDraft(true, true, 600u, 20u, 40u, 4u, 8u, 16u), decoded.policy.hydra)
    }

    @Test fun nonBooleanAndUnknownModeCannotReachTheRustMutationPort() {
        invalid(raw(enabled = 2))
        invalid(raw(dnsMode = 2))
        invalid(raw(dnsLeak = 2))
        invalid(raw(webrtc = 2))
    }

    @Test fun resolverPayloadIsBoundedBeforeNativePolicyValidation() {
        try {
            ControlCodec.encode(CoreCommand.SetNetworkPrivacyPolicy(policy.copy(resolverEndpoint = "x".repeat(65)), 1uL))
            fail("OVERSIZED_POLICY_ENDPOINT_ADMITTED")
        } catch (failure: ControlMessageException) { assertEquals(ControlProblem.TOO_LARGE, failure.problem) }
    }

    @Test fun truncatedOrTrailingPolicyBytesAreRejected() {
        val encoded = ControlCodec.encode(CoreCommand.SetNetworkPrivacyPolicy(policy, 1uL))
        invalid(encoded.copyOf(encoded.size - 1))
        invalid(encoded + byteArrayOf(0))
    }

    // Literal wire fixture independent of ControlCodec's encoder.
    private fun raw(enabled: Int = 0, dnsMode: Int = 0, dnsLeak: Int = 0, webrtc: Int = 0): ByteArray {
        val bytes = ByteArrayOutputStream()
        DataOutputStream(bytes).use { out ->
            out.writeInt(0x4C465431); out.writeByte(8); out.writeLong(1L)
            out.writeByte(dnsMode); out.writeByte(dnsLeak); out.writeByte(webrtc)
            out.writeInt(0)
            listOf(256, 262144, 60, 4096, 65535).forEach(out::writeInt)
            out.writeByte(enabled); out.writeByte(0)
            listOf(300, 0, 0, 0, 0, 0).forEach(out::writeInt)
        }
        return bytes.toByteArray()
    }

    private fun invalid(bytes: ByteArray) {
        try { ControlCodec.decode(bytes); fail("INVALID_POLICY_COMMAND_ADMITTED") }
        catch (failure: ControlMessageException) { assertEquals(ControlProblem.INVALID_COMMAND, failure.problem) }
    }
}
