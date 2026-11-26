package net.aptist.loft.service

import android.content.Context
import android.app.ActivityManager
import android.app.Notification
import android.app.NotificationManager
import android.content.res.Configuration
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.VpnService
import android.net.DnsResolver
import android.os.CancellationSignal
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import net.aptist.loft.core.generated.ConnectionState
import net.aptist.loft.core.generated.DnsMode
import net.aptist.loft.core.generated.NetworkPrivacyEnforcement
import net.aptist.loft.foundation.ControlCodec
import net.aptist.loft.foundation.CoreCommand
import net.aptist.loft.testing.BoundedPrivateInput
import net.aptist.loft.testing.NetworkPrivacyFixtures
import net.aptist.loft.R
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.net.InetSocketAddress
import java.net.Socket
import java.net.Inet4Address
import java.net.InetAddress
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.CountDownLatch
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import java.util.Locale
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

/** Run individually after staging one private node file via stdin/run-as.
 * The production APK, instrumentation arguments and test reports contain no URI.
 */
@RunWith(AndroidJUnit4::class)
class AndroidVpnIntegrationTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context: Context get() = instrumentation.targetContext
    private val frames = ArrayBlockingQueue<SnapshotFrame>(32)
    private val receipts = ArrayBlockingQueue<Pair<Long, ReceiptCode>>(32)
    private lateinit var client: CoreServiceClient
    private var nextRequest = 0L
    private var newest: SnapshotFrame? = null
    private val boundaries = ArrayDeque<String>(12)

    @Before fun bindPrivateControl() {
        instrumentation.runOnMainSync {
            client = CoreServiceClient(context, { frame ->
                recordBoundary("state=${frame.core.connectionState.name},failure=${frame.core.vpnFailure?.name ?: "NONE"}," +
                    "tun=${frame.tunHeld},ready=${frame.transportReady},released=${frame.resourcesReleased}," +
                    "forwardingDisabled=${frame.forwardingDisabled},engineKnown=${frame.engineVersion.isNotEmpty()}")
                if (!frames.offer(frame)) { frames.poll(); frames.offer(frame) }
            }, { id, code -> recordBoundary("receipt=${code.name}"); receipts.offer(id to code) },
                { code -> recordBoundary("receipt=${code.name}"); receipts.offer(-1L to code) })
            client.bind(); client.setVisible(true)
        }
        awaitFrame { true }
    }

    @After fun releaseOwners() {
        if (::client.isInitialized) {
            runCatching { send(CoreCommand.Stop); awaitFrame { !it.tunHeld && it.resourcesReleased } }
            instrumentation.runOnMainSync { client.close() }
        }
        File(context.filesDir, PRIVATE_INPUT).delete()
    }

    @Test fun guestCreatesNoTunOrGoTransport() {
        val first = newest ?: fail("SNAPSHOT_REQUIRED").let { error("SNAPSHOT_REQUIRED") }
        assertEquals(ConnectionState.DISCONNECTED, first.core.connectionState)
        assertEquals("", first.engineVersion)
        assertFalse(first.tunHeld)
        assertFalse(first.transportReady)
        assertTrue(first.resourcesReleased)
        assertEquals(NetworkPrivacyEnforcement.INACTIVE, first.core.networkPrivacyEnforcement)
        assertNull(first.core.appliedNetworkPrivacy)
        assertNull(first.networkResources)
        assertInertNotificationChannels()
    }

    @Test fun guestPolicyAndLocaleChangesRemainLocalWithInertChannels() {
        val first = newest ?: error("SNAPSHOT_REQUIRED")
        stagePrivacyPolicy(DnsMode.WIRE_TCP)
        val staged = newest ?: error("SNAPSHOT_REQUIRED")
        assertTrue(staged.core.generation > first.core.generation)
        assertEquals(DnsMode.WIRE_TCP, staged.core.networkPrivacyPolicy.dnsMode)
        for (locale in listOf("en", "zh", "ja", "de")) {
            instrumentation.runOnMainSync { assertTrue(client.setPresentationLocale(locale)) }
            awaitCondition("LOCALIZED_CHANNEL_REQUIRED") {
                context.getSystemService(NotificationManager::class.java).getNotificationChannel(LoftNotificationChannels.VPN_CHANNEL)?.name?.toString() ==
                    localized(locale).getString(R.string.vpn_notification_channel)
            }
            val fresh = freshFrame()
            assertEquals(staged.core.generation, fresh.core.generation)
            assertEquals(staged.core.networkPrivacyPolicyEpoch, fresh.core.networkPrivacyPolicyEpoch)
            assertEquals(ConnectionState.DISCONNECTED, fresh.core.connectionState)
            assertEquals("", fresh.engineVersion)
            assertFalse(fresh.tunHeld || fresh.transportReady)
            assertTrue(fresh.resourcesReleased)
            assertInertNotificationChannels()
        }
    }

    @Test fun realSelectedUidLiteralTlsTunAndStops() {
        requireOsPermission()
        val manager = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val physical = manager.activeNetwork ?: error("PHYSICAL_NETWORK_REQUIRED")
        assertTrue(manager.getNetworkCapabilities(physical)?.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN) == true)
        // Physical bootstrap before VPN. This literal test provides no tunneled
        // DNS evidence and never binds the selected UID to a physical escape.
        val targets = physical.getAllByName("example.com").filterIsInstance<Inet4Address>()
        assertTrue("PHYSICAL_IPV4_TARGET_REQUIRED", targets.isNotEmpty())
        val target = targets.first()
        val node = importPrivateNode()
        assertEquals(ReceiptCode.ROUTING_STAGED, send(CoreCommand.SetRouting(true, listOf(context.packageName))))
        val selected = newest ?: error("SNAPSHOT_REQUIRED")
        assertEquals(ReceiptCode.VPN_STARTING, send(CoreCommand.Connect(node, selected.core.generation)))
        val connected = awaitFrame { it.core.connectionState == ConnectionState.CONNECTED }
        assertTrue(connected.transportReady)
        assertTrue(connected.tunHeld)
        assertFalse(connected.forwardingDisabled)
        val routing = connected.core.appliedRouting ?: error("APPLIED_ROUTING_REQUIRED")
        assertTrue(routing.enabled)
        assertTrue(context.packageName in routing.packageNames)
        assertTrue(manager.getNetworkCapabilities(manager.activeNetwork)?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true)
        // Ordinary literal-IP TLS from the selected UID must traverse the TUN.
        hostnameTls(target)
        assertEquals(ReceiptCode.CONTROL_STOPPED, send(CoreCommand.Stop))
        val stopped = awaitFrame { !it.tunHeld && it.resourcesReleased }
        assertEquals(ConnectionState.DISCONNECTED, stopped.core.connectionState)
    }

    @Test fun realSelectedUidSyntheticDnsRestoresDomainTlsAndStops() {
        requireOsPermission()
        stagePrivacyPolicy(DnsMode.NODE_DOMAIN_FAKE_IP)
        val node = importPrivateNode()
        assertEquals(ReceiptCode.ROUTING_STAGED, send(CoreCommand.SetRouting(true, listOf(context.packageName))))
        assertEquals(ReceiptCode.VPN_STARTING, send(CoreCommand.Connect(node, newest!!.core.generation)))
        val connected = awaitFrame { it.core.connectionState == ConnectionState.CONNECTED }
        assertEquals(NetworkPrivacyEnforcement.ACTIVE, connected.core.networkPrivacyEnforcement)
        val applied = connected.core.appliedNetworkPrivacy ?: error("APPLIED_PRIVACY_REQUIRED")
        assertEquals(DnsMode.NODE_DOMAIN_FAKE_IP, applied.policy.dnsMode)
        assertTrue(connected.transportReady && connected.tunHeld && !connected.forwardingDisabled)
        val manager = context.getSystemService(ConnectivityManager::class.java)
        val vpn = manager.activeNetwork ?: error("VPN_NETWORK_REQUIRED")
        assertTrue(manager.getNetworkCapabilities(vpn)?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true)
        // No physical business-DNS bootstrap: actual uncached VPN A → alias →
        // ordinary selected-UID socket, original-hostname certificate and HTTP200.
        val alias = vpnAQuery(vpn)
        assertTrue("SYNTHETIC_ROUTING_ALIAS_REQUIRED", syntheticAlias(alias))
        hostnameTls(alias)
        assertEquals(ReceiptCode.CONTROL_STOPPED, send(CoreCommand.Stop))
        val stopped = awaitFrame { it.core.connectionState == ConnectionState.DISCONNECTED && !it.tunHeld && it.resourcesReleased }
        assertEquals(NetworkPrivacyEnforcement.INACTIVE, stopped.core.networkPrivacyEnforcement)
        assertNull(stopped.core.appliedNetworkPrivacy)
        val totals = stopped.networkResources ?: error("FINAL_SCOPED_TOTALS_REQUIRED")
        assertTrue(totals.finalized)
        assertTrue("FINAL_POLICY_SCOPE_REQUIRED", totals.policyEpoch == applied.policyEpoch && totals.scopeId == applied.scopeId)
        assertTrue("CONFIRMED_SYNTHETIC_REPLY_REQUIRED", totals.dnsSyntheticCount > 0L)
        assertEquals(0L, totals.dnsValidatedWireCount)
        assertTrue(totals.nodeResolverCalls in 0L..1L)
        assertEquals(0L, totals.businessResolverCalls)
        assertEquals(540672L, totals.dnsAllocatorBytes)
        assertEquals(0, totals.dnsMapEntries)
        assertEquals(0L, totals.dnsMapBytes)
        assertEquals(0, totals.physicalOpen)
        assertEquals(0, totals.activeFlows)
        assertEquals(0L, totals.queuedBytes)
        assertFalse(totals.ownershipPending)
    }

    private fun hostnameTls(target: Inet4Address) {
        Socket().use { tcp ->
            tcp.connect(InetSocketAddress(target, 443), 5000)
            ((SSLSocketFactory.getDefault() as SSLSocketFactory).createSocket(tcp, "example.com", 443, false) as SSLSocket).use { tls ->
                tls.soTimeout = 5000
                tls.sslParameters = tls.sslParameters.also { it.endpointIdentificationAlgorithm = "HTTPS" }
                tls.startHandshake()
                tls.outputStream.write("HEAD / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n".toByteArray(Charsets.US_ASCII))
                tls.outputStream.flush()
                requireHttp200(tls)
            }
        }
    }

    private fun requireHttp200(tls: SSLSocket) {
        val status = ByteArray(128)
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
        var count = 0
        var complete = false
        while (count < status.size && !complete) {
            val remaining = deadline - System.nanoTime()
            check(remaining > 0) { "TLS_STATUS_DEADLINE" }
            tls.soTimeout = ((remaining + 999_999L) / 1_000_000L).coerceIn(1, 5000).toInt()
            val next = tls.inputStream.read()
            if (next < 0) break
            status[count++] = next.toByte()
            complete = count >= 2 && status[count - 2] == 13.toByte() && status[count - 1] == 10.toByte()
        }
        assertTrue("TLS_STATUS_LINE_REQUIRED", complete)
        val line = String(status, 0, count - 2, Charsets.US_ASCII)
        assertTrue("TLS_HTTP_200_REQUIRED", line.startsWith("HTTP/1.1 200 ") || line.startsWith("HTTP/1.0 200 "))
        status.fill(0)
    }

    // Kept separate from ordinary TLS: gateway resolver policy can deny this.
    // A failed/pending DNS result must not erase successful literal TUN evidence.
    @Test fun realSelectedUidDnsUsesUncachedVpnNetworkQuery() {
        requireOsPermission()
        stagePrivacyPolicy(DnsMode.WIRE_TCP)
        val node = importPrivateNode()
        assertEquals(ReceiptCode.ROUTING_STAGED, send(CoreCommand.SetRouting(true, listOf(context.packageName))))
        assertEquals(ReceiptCode.VPN_STARTING, send(CoreCommand.Connect(node, newest!!.core.generation)))
        awaitFrame { it.core.connectionState == ConnectionState.CONNECTED }
        val manager = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val vpn = manager.activeNetwork ?: error("VPN_NETWORK_REQUIRED")
        assertTrue(manager.getNetworkCapabilities(vpn)?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true)
        val target = vpnAQuery(vpn)
        assertFalse("WIRE_DNS_MUST_NOT_BE_SYNTHETIC", syntheticAlias(target))
        assertEquals(ReceiptCode.CONTROL_STOPPED, send(CoreCommand.Stop))
        val stopped = awaitFrame { it.core.connectionState == ConnectionState.DISCONNECTED && it.resourcesReleased && !it.tunHeld }
        val totals = stopped.networkResources ?: error("FINAL_WIRE_TOTALS_REQUIRED")
        assertTrue(totals.finalized)
        assertEquals(DnsMode.WIRE_TCP, totals.policy.dnsMode)
        assertTrue("CONFIRMED_WIRE_REPLY_REQUIRED", totals.dnsValidatedWireCount > 0L)
        assertEquals(0L, totals.dnsSyntheticCount)
        assertEquals(0L, totals.businessResolverCalls)
    }

    private fun vpnAQuery(vpn: android.net.Network): Inet4Address {
        val signal = CancellationSignal()
        val callbacks = ThreadPoolExecutor(1, 1, 0L, TimeUnit.MILLISECONDS, ArrayBlockingQueue<Runnable>(1))
        val done = CountDownLatch(1)
        val answered = AtomicBoolean(false)
        val address = AtomicReference<Inet4Address?>(null)
        try {
            DnsResolver.getInstance().query(vpn, "example.com", DnsResolver.TYPE_A,
                DnsResolver.FLAG_NO_CACHE_LOOKUP or DnsResolver.FLAG_NO_CACHE_STORE,
                callbacks, signal, object : DnsResolver.Callback<List<InetAddress>> {
                    override fun onAnswer(answer: List<InetAddress>, rcode: Int) {
                        if (rcode == 0 && answer.size <= 8) address.set(answer.filterIsInstance<Inet4Address>().firstOrNull())
                        answered.set(address.get() != null); done.countDown()
                    }
                    override fun onError(error: DnsResolver.DnsException) { done.countDown() }
                })
            assertTrue("VPN_DNS_QUERY_TIMEOUT", done.await(10, TimeUnit.SECONDS))
            assertTrue("VPN_DNS_QUERY_FAILED_CHECK_ALLOWED_RESOLVER", answered.get())
            return address.get() ?: error("VPN_DNS_IPV4_REQUIRED")
        } finally {
            signal.cancel(); callbacks.shutdownNow()
            assertTrue("VPN_DNS_CALLBACK_JOIN_REQUIRED", callbacks.awaitTermination(5, TimeUnit.SECONDS))
        }
    }

    private fun syntheticAlias(address: Inet4Address): Boolean = address.address.let { (it[0].toInt() and 255) == 198 && (it[1].toInt() and 255) == 19 }

    private fun stagePrivacyPolicy(mode: DnsMode) {
        val policy = NetworkPrivacyFixtures.policy().copy(dnsMode = mode, resolverEndpoint = if (mode == DnsMode.WIRE_TCP) VpnPolicy.DNS_UPSTREAM else "")
        assertEquals(ReceiptCode.NETWORK_PRIVACY_STAGED, send(CoreCommand.SetNetworkPrivacyPolicy(NetworkPrivacyAdapter.draft(policy), newest!!.core.generation)))
    }

    @Test fun realReadyNotificationStopActionClosesTunAndKeepsLocaleState() {
        requireOsPermission()
        stagePrivacyPolicy(DnsMode.NODE_DOMAIN_FAKE_IP)
        val node = importPrivateNode()
        assertEquals(ReceiptCode.ROUTING_STAGED, send(CoreCommand.SetRouting(true, listOf(context.packageName))))
        assertEquals(ReceiptCode.VPN_STARTING, send(CoreCommand.Connect(node, newest!!.core.generation)))
        val connected = awaitFrame { it.core.connectionState == ConnectionState.CONNECTED }
        val applied = connected.core.appliedNetworkPrivacy ?: error("APPLIED_PRIVACY_REQUIRED")
        for (locale in listOf("en", "zh", "ja", "de")) {
            instrumentation.runOnMainSync { assertTrue(client.setPresentationLocale(locale)); client.setVisible(false) }
            val notice = requireVpnNotification(localized(locale).getString(R.string.vpn_notification_connected))
            assertTrue("VPN_SMALL_ICON_REQUIRED", notice.smallIcon?.resId == R.drawable.ic_network)
            assertTrue("READY_FOREGROUND_NOTIFICATION_FLAG_REQUIRED ${notificationEvidence(NotificationProbeStage.READY_BEFORE_FLAG, notice)}",
                notice.flags and Notification.FLAG_FOREGROUND_SERVICE != 0)
            assertTrue(notice.flags and Notification.FLAG_ONGOING_EVENT != 0)
            assertNotNull(notice.contentIntent)
            requireActualForegroundService()
            instrumentation.runOnMainSync { client.setVisible(true) }
            val fresh = freshFrame()
            assertEquals(connected.core.generation, fresh.core.generation)
            assertEquals(connected.core.connectionAttemptId, fresh.core.connectionAttemptId)
            assertTrue("LOCALE_POLICY_SCOPE_REQUIRED", fresh.core.appliedNetworkPrivacy?.scopeId == applied.scopeId)
            assertTrue(fresh.transportReady && fresh.tunHeld && !fresh.resourcesReleased)
        }
        val notice = requireVpnNotification(localized("de").getString(R.string.vpn_notification_connected))
        val stop = notice.actions?.singleOrNull()?.actionIntent ?: error("NATIVE_STOP_ACTION_REQUIRED")
        stop.send()
        awaitFrame { it.core.connectionState == ConnectionState.DISCONNECTED && it.resourcesReleased && !it.tunHeld }
        awaitCondition("FOREGROUND_NOTIFICATION_RELEASE_REQUIRED") {
            context.getSystemService(NotificationManager::class.java).activeNotifications.none { it.id == LoftNotificationChannels.VPN_NOTIFICATION }
        }
    }

    @Test fun realStartFailureKeepsBlockedNotificationUntilStop() {
        requireOsPermission()
        stagePrivacyPolicy(DnsMode.NODE_DOMAIN_FAKE_IP)
        // An actual loopback dial/authentication failure, without task material
        // or a fake engine receipt. Run individually on the prepared emulator.
        assertEquals(ReceiptCode.NODE_IMPORTED, send(CoreCommand.ImportNode("socks5://127.0.0.1:9")))
        val node = newest!!.core.nodes.last().id
        assertEquals(ReceiptCode.VPN_STARTING, send(CoreCommand.Connect(node, newest!!.core.generation)))
        val blocked = awaitFrame { it.core.connectionState == ConnectionState.BLOCKED }
        assertTrue(blocked.tunHeld && blocked.forwardingDisabled && !blocked.resourcesReleased)
        assertFalse(blocked.transportReady)
        assertEquals(NetworkPrivacyEnforcement.BLOCKED, blocked.core.networkPrivacyEnforcement)
        val notice = requireVpnNotification(localized("en").getString(R.string.vpn_notification_blocked))
        assertTrue("BLOCKED_SMALL_ICON_REQUIRED", notice.smallIcon?.resId == R.drawable.ic_network)
        assertTrue("BLOCKED_FOREGROUND_NOTIFICATION_FLAG_REQUIRED ${notificationEvidence(NotificationProbeStage.BLOCKED_BEFORE_FLAG, notice)}",
            notice.flags and Notification.FLAG_FOREGROUND_SERVICE != 0)
        requireActualForegroundService()
        assertEquals(ReceiptCode.CONTROL_STOPPED, send(CoreCommand.Stop))
        awaitFrame { it.core.connectionState == ConnectionState.DISCONNECTED && it.resourcesReleased && !it.tunHeld }
        awaitCondition("BLOCKED_NOTIFICATION_RELEASE_REQUIRED") {
            context.getSystemService(NotificationManager::class.java).activeNotifications.none { it.id == LoftNotificationChannels.VPN_NOTIFICATION }
        }
    }

    private fun localized(locale: String): Context = context.createConfigurationContext(Configuration(context.resources.configuration)
        .apply { setLocale(Locale.forLanguageTag(locale)) })

    private fun freshFrame(): SnapshotFrame {
        val sequence = newest?.publicationSequence ?: 0uL
        instrumentation.runOnMainSync { client.setVisible(false); client.setVisible(true) }
        return awaitFrame { it.publicationSequence > sequence }
    }

    private fun assertInertNotificationChannels() {
        val manager = context.getSystemService(NotificationManager::class.java)
        assertNotNull(manager.getNotificationChannel(LoftNotificationChannels.VPN_CHANNEL))
        assertNotNull(manager.getNotificationChannel(LoftNotificationChannels.MAIL_CHANNEL))
        assertTrue("GUEST_POSTED_VPN_OR_MAIL", manager.activeNotifications.none {
            it.id == LoftNotificationChannels.VPN_NOTIFICATION || it.id == LoftNotificationChannels.MAIL_NOTIFICATION
        })
    }

    private fun requireVpnNotification(text: String): Notification {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
        while (true) {
            val notice = context.getSystemService(NotificationManager::class.java).activeNotifications.firstOrNull {
                it.id == LoftNotificationChannels.VPN_NOTIFICATION && it.notification.extras.getCharSequence(Notification.EXTRA_TEXT)?.toString() == text
            }?.notification
            // Android10's getter includes enqueued replacements. Wait for the
            // actual NMS FGS flag and independent current AMS foreground fact.
            if (notice != null && notice.flags and Notification.FLAG_FOREGROUND_SERVICE != 0 && actualForegroundService()) return notice
            assertTrue("ACTUAL_POSTED_VPN_NOTIFICATION_REQUIRED " +
                (notice?.let { notificationEvidence(NotificationProbeStage.WAITING_FOR_POST, it) } ?: "stage=WAITING_FOR_POST,notice=false"),
                System.nanoTime() < deadline)
            Thread.sleep(20)
        }
    }

    @Suppress("DEPRECATION")
    private fun requireActualForegroundService() {
        awaitCondition("ACTUAL_VPN_FOREGROUND_SERVICE_REQUIRED", ::actualForegroundService)
    }

    @Suppress("DEPRECATION")
    private fun actualForegroundService(): Boolean = try {
        context.getSystemService(ActivityManager::class.java).getRunningServices(32).any {
                it.service.className == LoftVpnService::class.java.name && it.foreground
        }
    } catch (_: Exception) { false }

    private enum class NotificationProbeStage { READY_BEFORE_FLAG, BLOCKED_BEFORE_FLAG, WAITING_FOR_POST }

    // Test-only current AMS/NMS observation: no endpoint, node ID, notification
    // text, UID, credentials or exception message/cause can enter this record.
    @Suppress("DEPRECATION")
    private fun notificationEvidence(stage: NotificationProbeStage, notice: Notification): String {
        val records = try {
            context.getSystemService(ActivityManager::class.java).getRunningServices(32)
                .filter { it.service.className == LoftVpnService::class.java.name }
        } catch (_: Exception) { null }
        val frame = newest
        return "stage=${stage.name},flags=0x${notice.flags.toUInt().toString(16)}," +
            "fgRecords=${records?.size ?: -1},foreground=${records?.count { it.foreground } ?: -1}," +
            "started=${records?.count { it.started } ?: -1},pidKnown=${records?.any { it.pid > 0 } == true}," +
            "state=${frame?.core?.connectionState?.name ?: "UNKNOWN"},tun=${frame?.tunHeld == true}," +
            "ready=${frame?.transportReady == true},disabled=${frame?.forwardingDisabled == true},released=${frame?.resourcesReleased == true}"
    }

    private fun awaitCondition(code: String, test: () -> Boolean) {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
        while (!test()) {
            assertTrue(code, System.nanoTime() < deadline)
            Thread.sleep(20)
        }
    }

    @Test fun stopDuringConnectionClosesEveryOwnedDescriptor() {
        requireOsPermission()
        val node = importPrivateNode()
        val generation = newest!!.core.generation
        assertEquals(ReceiptCode.VPN_STARTING, send(CoreCommand.Connect(node, generation)))
        val result = send(CoreCommand.Stop)
        assertTrue(result == ReceiptCode.CONTROL_STOPPED || result == ReceiptCode.TUN_CLOSED_CORE_UNAVAILABLE)
        val stopped = awaitFrame { !it.tunHeld && it.resourcesReleased }
        assertFalse(stopped.transportReady)
        assertTrue(stopped.core.connectionState != ConnectionState.CONNECTED)
        val end = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
        while (true) {
            val remaining = end - System.nanoTime()
            if (remaining <= 0) break
            val late = frames.poll(remaining, TimeUnit.NANOSECONDS) ?: break
            assertFalse("LATE_READY_AFTER_STOP", late.core.connectionState == ConnectionState.CONNECTED)
            assertFalse(late.tunHeld)
        }
    }

    private fun requireOsPermission() { assertNull("VPN_PERMISSION_REQUIRED", VpnService.prepare(context)) }

    private fun importPrivateNode(): String {
        val file = File(context.filesDir, PRIVATE_INPUT)
        val limit = ControlCodec.MAX_CONTROL_BYTES - 9
        val material = try {
            assertTrue("PRIVATE_INPUT_REQUIRED", file.isFile)
            assertTrue("PRIVATE_INPUT_TOO_LARGE", file.length() in 1..limit.toLong())
            file.inputStream().use { input ->
                assertTrue("PRIVATE_INPUT_DELETE_FAILED", file.delete())
                BoundedPrivateInput.read(input, limit)
            }
        } finally { file.delete() }
        try {
            assertTrue("PRIVATE_INPUT_TOO_LARGE", material.size in 1..limit)
            val raw = Charsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(material)).toString().trim()
            assertEquals(ReceiptCode.NODE_IMPORTED, send(CoreCommand.ImportNode(raw)))
            return newest!!.core.nodes.last().id
        } finally { material.fill(0) }
    }

    private fun send(command: CoreCommand): ReceiptCode {
        val request = ++nextRequest
        var admitted = false
        instrumentation.runOnMainSync { admitted = client.execute(request, command) }
        assertTrue("CONTROL_BINDING_REQUIRED ${boundarySummary()}", admitted)
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(15)
        while (true) {
            val remaining = deadline - System.nanoTime()
            assertTrue("RECEIPT_TIMEOUT ${boundarySummary()}", remaining > 0)
            val receipt = receipts.poll(remaining, TimeUnit.NANOSECONDS) ?: error("RECEIPT_TIMEOUT ${boundarySummary()}")
            assertTrue("SERVICE_LOST_${receipt.second.name} ${boundarySummary()}", receipt.first != -1L)
            drainFrames()
            if (receipt.first == request) return receipt.second
        }
    }

    private fun drainFrames() { while (true) newest = frames.poll() ?: return }

    // Test-only, bounded, and built exclusively from stable enum/Boolean fields.
    // Never retain/emit a SnapshotFrame, endpoint, node ID or exception message.
    private fun recordBoundary(line: String) {
        synchronized(boundaries) {
            if (boundaries.lastOrNull() == line) return
            if (boundaries.size == 12) boundaries.removeFirst()
            boundaries.addLast(line)
        }
    }
    private fun boundarySummary(): String = synchronized(boundaries) {
        boundaries.joinToString(separator = " | ", prefix = "boundaries=[", postfix = "]")
    }

    private fun awaitFrame(predicate: (SnapshotFrame) -> Boolean): SnapshotFrame {
        newest?.let { if (predicate(it)) return it }
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(30)
        while (true) {
            val remaining = deadline - System.nanoTime()
            assertTrue("SNAPSHOT_TIMEOUT ${boundarySummary()}", remaining > 0)
            val frame = frames.poll(remaining, TimeUnit.NANOSECONDS) ?: error("SNAPSHOT_TIMEOUT ${boundarySummary()}")
            newest = frame
            if (predicate(frame)) return frame
        }
    }

    companion object { const val PRIVATE_INPUT = "loft-vpn-private-input" }
}
