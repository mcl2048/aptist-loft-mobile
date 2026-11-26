package net.aptist.loft.foundation

import org.junit.Assert.*
import org.junit.Test
import java.nio.ByteBuffer

class ControlCodecTest {
    // Catches dropping or rewriting credential-bearing bytes before Rust validation.
    @Test fun completeImportTextRoundTripsWithoutTruncation() {
        val text = "socks5://example.invalid:1080/#東京"
        val decoded = ControlCodec.decode(ControlCodec.encode(CoreCommand.ImportNode(text))) as CoreCommand.ImportNode
        assertEquals(text, decoded.raw)
        assertFalse(decoded.toString().contains("example.invalid"))
    }

    // Catches checking UTF-16 length instead of actual Binder bytes.
    @Test fun inputLimitCountsUtf8AndPreservesTheExactBoundary() {
        val boundary = "x".repeat(ControlCodec.MAX_CONTROL_BYTES - 9)
        assertEquals(ControlCodec.MAX_CONTROL_BYTES, ControlCodec.encode(CoreCommand.ImportNode(boundary)).size)
        expectProblem(ControlProblem.TOO_LARGE) { ControlCodec.encode(CoreCommand.ImportNode(boundary + "x")) }
        expectProblem(ControlProblem.TOO_LARGE) { ControlCodec.encode(CoreCommand.ImportNode("界".repeat(22000))) }
    }

    // Catches allocating an attacker-declared string before bounding its actual payload.
    @Test fun malformedLengthAndTrailingBytesAreRejected() {
        val encoded = ControlCodec.encode(CoreCommand.ImportNode("socks5://example.invalid"))
        ByteBuffer.wrap(encoded).putInt(5, Int.MAX_VALUE)
        expectProblem(ControlProblem.INVALID_COMMAND) { ControlCodec.decode(encoded) }
        expectProblem(ControlProblem.INVALID_COMMAND) { ControlCodec.decode(ControlCodec.encode(CoreCommand.Stop) + byteArrayOf(1)) }
    }

    @Test fun malformedUtf8IsRejectedInsteadOfReplacingCredentialBytes() {
        val encoded = ControlCodec.encode(CoreCommand.ImportNode("x"))
        encoded[9] = 0xFF.toByte()
        expectProblem(ControlProblem.INVALID_UTF8) { ControlCodec.decode(encoded) }
    }

    @Test fun unknownOpcodeAndOversizedTransactionAreRejected() {
        val encoded = ControlCodec.encode(CoreCommand.Stop)
        encoded[4] = 99
        expectProblem(ControlProblem.INVALID_COMMAND) { ControlCodec.decode(encoded) }
        expectProblem(ControlProblem.TOO_LARGE) { ControlCodec.decode(ByteArray(ControlCodec.MAX_CONTROL_BYTES + 1)) }
    }

    @Test fun routingCommandRoundTripsTheCompleteSelection() {
        val command = ControlCodec.decode(ControlCodec.encode(CoreCommand.SetRouting(true, listOf("net.example.alpha", "net.example.beta")))) as CoreCommand.SetRouting
        assertTrue(command.enabled)
        assertEquals(listOf("net.example.alpha", "net.example.beta"), command.packageNames)
    }

    @Test fun binderAdmissionRejectsOtherUidsEvenForSmallCommands() {
        assertTrue(BinderAdmission.allowed(10001, 10001, 100))
        assertFalse(BinderAdmission.allowed(10001, 10002, 100))
        assertFalse(BinderAdmission.allowed(10001, 10001, ControlCodec.MAX_CONTROL_BYTES + 1))
    }

    // The node and generation selected before OS permission must reach Rust
    // unchanged so an older permission result cannot start a different draft.
    @Test fun connectCarriesTheExactExpectedGeneration() {
        val decoded = ControlCodec.decode(ControlCodec.encode(CoreCommand.Connect("n-4", ULong.MAX_VALUE))) as CoreCommand.Connect
        assertEquals("n-4", decoded.nodeId)
        assertEquals(ULong.MAX_VALUE, decoded.expectedGeneration)
    }

    @Test fun connectWithoutAnExpectedGenerationIsRejected() {
        val legacy = ByteBuffer.allocate(12).putInt(0x4C465431).put(6).putInt(3).put("n-4".toByteArray()).array()
        expectProblem(ControlProblem.INVALID_COMMAND) { ControlCodec.decode(legacy) }
    }

    private fun expectProblem(problem: ControlProblem, block: () -> Unit) {
        try { block(); fail("Expected $problem") }
        catch (failure: ControlMessageException) { assertEquals(problem, failure.problem) }
    }
}
