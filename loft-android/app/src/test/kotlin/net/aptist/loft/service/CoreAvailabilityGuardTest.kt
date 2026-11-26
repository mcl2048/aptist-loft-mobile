package net.aptist.loft.service

import net.aptist.loft.core.generated.*
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.FileInputStream
import java.io.IOException

class CoreAvailabilityGuardTest {
    @get:Rule val temporary = TemporaryFolder()
    private fun descriptor() = FileInputStream(temporary.newFile().also { it.writeBytes(byteArrayOf(11)) })
    private fun core() = CoreSnapshot(2u, "0.1.2-LYNX", emptyList(), 0u, null, false, false, emptyList(),
        ConnectionState.UNAVAILABLE, 7uL, 3uL, "n-4", AppliedRouting(false, emptyList(), Ipv6Policy.BLOCKED_IN_VPN), VpnFailure.ENGINE_UNAVAILABLE,
        net.aptist.loft.testing.NetworkPrivacyFixtures.policy(), 1uL, null, NetworkPrivacyEnforcement.INACTIVE)

    // Hiding Connected is insufficient: poison must close actual forwarding
    // resources while the original Android descriptor is retained until Stop.
    @Test fun unavailableWireFrameAbortsForwardingAndRetainsTheOriginalScope() {
        descriptor().use { forwarding -> descriptor().use { original ->
            val publisher = SnapshotPublisher()
            val payload = publisher.capture(::core, SnapshotMetadata(tunHeld = true, forwardingDisabled = false, resourcesReleased = false))
            val consumer = SnapshotConsumer().also { it.begin(11) }
            val frame = consumer.consume(11, payload)!!
            assertEquals(7uL, frame.core.generation)
            assertFalse(frame.forwardingDisabled)
            CoreAvailabilityGuard { forwarding.close() }.observe(frame)
            expectClosed(forwarding)
            assertEquals(11, original.read())
        } }
    }

    @Test fun anAvailableWireFrameDoesNotAbortItsResources() {
        descriptor().use { forwarding ->
            val payload = SnapshotPublisher().capture({ core().copy(connectionState = ConnectionState.CONNECTING) },
                SnapshotMetadata(tunHeld = true, forwardingDisabled = false, resourcesReleased = false))
            val frame = SnapshotWire.decode(payload)
            CoreAvailabilityGuard { forwarding.close() }.observe(frame)
            assertEquals(11, forwarding.read())
        }
    }
    private fun expectClosed(resource: FileInputStream) {
        try { resource.read(); fail("Forwarding resource is still open") } catch (_: IOException) { }
    }
}
