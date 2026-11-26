package net.aptist.loft.service

import androidx.test.ext.junit.runners.AndroidJUnit4
import net.aptist.loft.BuildConfig
import net.aptist.loft.engine.Engine
import net.aptist.loft.engine.SocketProtector
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.util.concurrent.atomic.AtomicBoolean

/** Run individually in a fresh test process. No service binding, node or Start. */
@RunWith(AndroidJUnit4::class)
class AndroidNativeBoundaryTest {
    @Test fun nativeCapabilitiesAndInertGoRequireNoTransport() {
        val capabilities = nativeBoundary(Stage.INFO_JNI) { Engine.vpnRuntimeInfo() }
        val version = nativeBoundary(Stage.INFO_ADMISSION) { GoRuntimeInfo.decodeEngineVersion(capabilities) }
        assertTrue("ENGINE_VERSION_REQUIRED", version.isNotEmpty())
        assertTrue("ENGINE_VERSION_MATCH_REQUIRED", version == BuildConfig.VERSION_NAME)

        val callbackUsed = AtomicBoolean(false)
        val protector = object : SocketProtector {
            override fun protect(fd: Int): Boolean { callbackUsed.set(true); return false }
            override fun resolveNode(hostname: String): String { callbackUsed.set(true); return "" }
        }
        val runtime = nativeBoundary(Stage.INERT_CREATE) { Engine.newVPNRuntime(protector) }
        var failed = false
        try {
            val idle = nativeBoundary(Stage.IDLE_SNAPSHOT) { GoVpnSnapshot.decode(runtime.snapshot()) }
            assertEquals("INERT_STATE_REQUIRED", GoVpnState.IDLE, idle.state)
            assertQuiescent(idle)
            assertFalse("INERT_PLATFORM_CALLBACK_USED", callbackUsed.get())
        } catch (failure: Throwable) {
            failed = true
            throw failure
        } finally {
            try { nativeBoundary(Stage.INERT_CLOSE) { runtime.close() } }
            catch (failure: AssertionError) { if (!failed) throw failure }
        }

        val closed = nativeBoundary(Stage.CLOSED_SNAPSHOT) { GoVpnSnapshot.decode(runtime.snapshot()) }
        assertEquals("CLOSED_STATE_REQUIRED", GoVpnState.CLOSED, closed.state)
        assertQuiescent(closed)
        assertTrue("CLOSED_RELEASE_RECEIPT_REQUIRED", closed.provesReleased)
        assertFalse("INERT_PLATFORM_CALLBACK_USED", callbackUsed.get())
    }

    private fun assertQuiescent(facts: GoVpnFacts) {
        assertTrue("INERT_GENERATION_REQUIRED", facts.generation == 0L)
        assertFalse("INERT_TRANSPORT_READY", facts.transportReady)
        assertFalse("INERT_AUTHENTICATION", facts.authenticated)
        assertFalse("INERT_TUN_READY", facts.tunReady)
        assertFalse("INERT_TUN_OWNED", facts.tunOwned)
        assertFalse("INERT_SOCKET_PROTECTION", facts.socketsProtected)
        assertTrue("INERT_FORWARDING_DISABLED_REQUIRED", facts.forwardingDisabled)
        assertTrue("INERT_RESOURCES_RELEASED_REQUIRED", facts.resourcesReleased)
        assertFalse("INERT_OWNERSHIP_PENDING", facts.ownershipPending)
        assertTrue("INERT_PHYSICAL_WORK", facts.physicalOpen == 0)
        assertTrue("INERT_FLOW_WORK", facts.activeFlows == 0)
        assertTrue("INERT_QUEUED_BYTES", facts.queuedBytes == 0L)
        assertTrue("INERT_ERROR_CODE", facts.errorCode.isEmpty())
        assertFalse("INERT_POLICY_INSTALLED", facts.privacy.policyInstalled)
        assertTrue("INERT_POLICY_SCOPE", facts.privacy.policyEpoch == 0uL && facts.privacy.scopeId.isEmpty())
        assertFalse("INERT_NETWORK_PROOF", facts.privacy.enforcementActive || facts.privacy.dnsProtectionEnforced ||
            facts.privacy.webrtcProtectionEnforced || facts.privacy.ipv6DropActive)
        assertTrue("INERT_FIXED_ALLOCATOR", facts.privacy.dnsAllocatorBytes == 540672L)
        assertTrue("INERT_MAPS", facts.privacy.dnsMapEntries == 0 && facts.privacy.dnsMapBytes == 0L)
        assertTrue("INERT_DNS_TOTALS", facts.privacy.dnsSyntheticCount == 0L && facts.privacy.dnsValidatedWireCount == 0L &&
            facts.privacy.nodeResolverCalls == 0L && facts.privacy.businessResolverCalls == 0L)
        assertFalse("INERT_HYDRA", facts.privacy.hydraEnabled || facts.privacy.hydraApplied)
        assertEquals("INERT_HYDRA_SCOPE", GoHydraScope.OFF, facts.privacy.hydraScope)
    }

    // Replace every JNI/Go/decoder Throwable without retaining its message/cause.
    private fun <T> nativeBoundary(stage: Stage, call: () -> T): T = try { call() }
    catch (_: Throwable) { throw AssertionError("NATIVE_BOUNDARY_${stage.name}") }

    private enum class Stage { INFO_JNI, INFO_ADMISSION, INERT_CREATE, IDLE_SNAPSHOT, INERT_CLOSE, CLOSED_SNAPSHOT }
}
