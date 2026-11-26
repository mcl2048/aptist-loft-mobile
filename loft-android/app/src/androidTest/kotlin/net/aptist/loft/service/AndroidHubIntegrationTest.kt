package net.aptist.loft.service

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import net.aptist.loft.core.generated.HubAction
import net.aptist.loft.foundation.CoreCommand
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.net.URI
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.TimeUnit

@RunWith(AndroidJUnit4::class)
class AndroidHubIntegrationTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()

    @Test fun realDiscoveryManualCompletionAndCancellationUsePrivateService() {
        val configured = InstrumentationRegistry.getArguments().getString("loftHubOrigin")
        assumeTrue("Pass the deployed public Hub origin explicitly", !configured.isNullOrBlank())
        val origin = checkNotNull(configured)
        val frames = ArrayBlockingQueue<SnapshotFrame>(8)
        val receipts = ArrayBlockingQueue<ReceiptCode>(8)
        val hub = ArrayBlockingQueue<Pair<String, HubResult?>>(8)
        lateinit var client: CoreServiceClient
        instrumentation.runOnMainSync {
            client = CoreServiceClient(instrumentation.targetContext, { frames.offer(it) },
                { _, code -> receipts.offer(code) }, { code -> receipts.offer(code) })
            client.bind()
            client.setVisible(true)
        }
        fun send(id: Long, action: HubAction?, mail: Boolean = false): Pair<String, HubResult?> {
            instrumentation.runOnMainSync {
                assertTrue(client.executeHub(id, action, null, mail, null) { code, result -> hub.offer(code to result) })
            }
            return checkNotNull(hub.poll(35, TimeUnit.SECONDS)) { "HUB_RECEIPT_MISSING" }
        }
        var previous: String? = null
        var initialReceived = false
        try {
            previous = checkNotNull(frames.poll(20, TimeUnit.SECONDS)) { "HUB_LOCAL_FRAME_MISSING" }.core.serverAddress
            initialReceived = true
            instrumentation.runOnMainSync { assertTrue(client.execute(1, CoreCommand.StageServer(origin))) }
            assertEquals(ReceiptCode.SERVER_STAGED, receipts.poll(20, TimeUnit.SECONDS))
            val initial = send(2, null)
            assertEquals("ok", initial.first)
            assertNull(initial.second?.snapshot?.session)
            assertNull(initial.second?.snapshot?.issuer)
            val (discoveryCode, discovery) = send(3, HubAction.DISCOVER)
            assertEquals("ok", discoveryCode)
            assertEquals(origin, discovery?.snapshot?.origin)
            assertTrue(discovery?.snapshot?.mailSupported == true)
            val issuer = URI(checkNotNull(discovery?.snapshot?.issuer))
            assertEquals("https", issuer.scheme)
            val (signInCode, signIn) = send(4, HubAction.SIGN_IN, mail = true)
            assertEquals("ok", signInCode)
            val started = checkNotNull(signIn)
            assertTrue(started.snapshot.transactionPending)
            assertEquals(issuer.host, URI(checkNotNull(started.browserUrl)).host)
            assertNull(started.snapshot.session)
            val (pendingCode, pending) = send(5, HubAction.COMPLETE)
            assertEquals("ok", pendingCode)
            assertTrue(pending?.snapshot?.transactionPending == true)
            assertNull(pending?.browserUrl)
            val (cancelCode, cancelled) = send(6, HubAction.CANCEL)
            assertEquals("ok", cancelCode)
            assertFalse(checkNotNull(cancelled).snapshot.transactionPending)
            assertEquals("not_signed_in", send(7, HubAction.MAIL_INBOX).first)
        } finally {
            if (initialReceived) {
                val restore = previous?.let { CoreCommand.StageServer(it) } ?: CoreCommand.ResetServer
                instrumentation.runOnMainSync { client.execute(8, restore) }
                receipts.poll(20, TimeUnit.SECONDS)
            }
            instrumentation.runOnMainSync { client.close() }
        }
    }
}
