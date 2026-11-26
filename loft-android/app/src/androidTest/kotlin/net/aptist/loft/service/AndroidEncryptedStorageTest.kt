package net.aptist.loft.service

import android.content.Context
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import net.aptist.loft.core.generated.AppCore
import net.aptist.loft.core.generated.ConnectionState
import net.aptist.loft.core.generated.DnsMode
import net.aptist.loft.core.generated.NodePage
import net.aptist.loft.core.generated.ProtocolKind
import net.aptist.loft.foundation.CoreCommand
import net.aptist.loft.testing.NetworkPrivacyFixtures
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.nio.file.Files
import java.security.KeyStore
import java.util.UUID
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.TimeUnit

@RunWith(AndroidJUnit4::class)
class AndroidEncryptedStorageTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context: Context get() = instrumentation.targetContext

    @Test fun wrappedDatabaseReopensAndRetainsCiphertextAfterKeyLoss() = withIsolatedStorage { directory, alias ->
        val store = AndroidDatabaseKey(directory, alias)
        loadRust()
        var issuedKey: ByteArray? = null
        val id = store.open { path, key, allowCreate ->
            assertTrue(allowCreate)
            issuedKey = key
            AppCore.openPersistent(path, key, allowCreate)
        }.use { it.importNode(NODE).id }
        assertTrue(issuedKey?.all { it == 0.toByte() } == true)
        val database = File(directory, "config.db")
        val ciphertext = database.readBytes()
        assertTrue(ciphertext.size > 16)
        assertFalse(ciphertext.copyOfRange(0, 16).contentEquals("SQLite format 3\u0000".encodeToByteArray()))
        assertFalse(ciphertext.toString(Charsets.ISO_8859_1).contains("durability.invalid"))
        AndroidDatabaseKey(directory, alias).open { path, key, allowCreate ->
            assertFalse(allowCreate)
            AppCore.openPersistent(path, key, allowCreate)
        }.use { assertEquals(id, it.snapshot().nodes.single().id) }
        keyStore().deleteEntry(alias)
        assertRecoveryRequired {
            AndroidDatabaseKey(directory, alias).open { _, _, _ -> error("DATABASE_OPEN_AFTER_KEY_LOSS") }
        }
        assertFalse(keyStore().containsAlias(alias))
        assertArrayEquals(ciphertext, database.readBytes())
    }

    @Test fun activeEnvelopeCannotRecreateMissingDatabase() = withIsolatedStorage { directory, alias ->
        val store = AndroidDatabaseKey(directory, alias)
        loadRust()
        store.open { path, key, allowCreate -> AppCore.openPersistent(path, key, allowCreate) }.close()
        val database = File(directory, "config.db")
        val priorBytes = database.readBytes()
        assertTrue(database.delete())
        assertRecoveryRequired {
            AndroidDatabaseKey(directory, alias).open { _, _, _ -> error("DATABASE_RECREATION_ADMITTED") }
        }
        assertFalse(database.exists())
        assertTrue(priorBytes.isNotEmpty())
    }

    @Test fun androidDirectoryAliasIsResolvedWithoutResolvingTheDatabaseLeaf() = withIsolatedStorage { directory, alias ->
        loadRust()
        val actual = File(directory, "store").apply { check(mkdirs()) }
        val link = File(directory, "android-path-alias").toPath()
        Files.createSymbolicLink(link, actual.toPath())
        val store = AndroidDatabaseKey(link.toFile(), alias)
        store.open { path, key, allowCreate -> AppCore.openPersistent(path, key, allowCreate) }.close()
        val database = File(actual, "config.db").toPath()
        val moved = File(actual, "moved.db").toPath()
        Files.move(database, moved)
        Files.createSymbolicLink(database, moved)
        assertRecoveryRequired { store.open { _, _, _ -> error("SYMLINK_DATABASE_LEAF_ACCEPTED") } }
        Files.delete(database)
        Files.delete(link)
    }

    @Test fun tamperingWithTheProvisioningPhaseCannotAuthorizeDatabaseCreation() = withIsolatedStorage { directory, alias ->
        loadRust()
        val store = AndroidDatabaseKey(directory, alias)
        store.open { path, key, allowCreate -> AppCore.openPersistent(path, key, allowCreate) }.close()
        val wrapper = File(directory, "key.wrap")
        val tampered = wrapper.readBytes().apply { this[1] = 1 }
        wrapper.writeBytes(tampered)
        assertRecoveryRequired { store.open { _, _, _ -> error("TAMPERED_PHASE_ACCEPTED") } }
        assertArrayEquals(tampered, wrapper.readBytes())
        assertTrue(keyStore().containsAlias(alias))
    }

    @Test fun interruptedProvisioningRetriesWithTheSameKey() = withIsolatedStorage { directory, alias ->
        var firstKey: ByteArray? = null
        try {
            try {
                AndroidDatabaseKey(directory, alias).open<AppCore> { _, key, allowCreate ->
                    assertTrue(allowCreate)
                    firstKey = key.copyOf()
                    throw IllegalStateException("TEST_INTERRUPTION")
                }
                fail("PROVISIONING_TEST_INTERRUPTION_MISSING")
            } catch (failure: IllegalStateException) {
                assertEquals("TEST_INTERRUPTION", failure.message)
            }
            loadRust()
            AndroidDatabaseKey(directory, alias).open { path, key, allowCreate ->
                assertTrue(allowCreate)
                assertArrayEquals(firstKey, key)
                AppCore.openPersistent(path, key, allowCreate)
            }.close()
        } finally {
            firstKey?.fill(0)
        }
    }

    @Test fun binderWritesDurableLocalConfiguration() = withPrivateControl { client, frames, receipts, _ ->
        val initial = awaitFrame(frames) { true }
        assertQuiescent(initial)
        val imported = send(client, receipts, 1, CoreCommand.ImportNode(NODE))
        assertEquals(ReceiptCode.NODE_IMPORTED, imported)
        val node = awaitFrame(frames) { it.core.nodes.any { node -> node.label == LABEL } }
        assertEquals("node-0000000000000001", node.core.nodes.single { it.label == LABEL }.id)
        assertEquals(ReceiptCode.ROUTING_STAGED, send(client, receipts, 2, CoreCommand.SetRouting(true, listOf(context.packageName))))
        assertEquals(ReceiptCode.SERVER_STAGED, send(client, receipts, 3, CoreCommand.StageServer(SERVER)))
        val staged = awaitFrame(frames) { it.core.serverAddress == SERVER }
        assertEquals(ReceiptCode.NETWORK_PRIVACY_STAGED, send(client, receipts, 4,
            CoreCommand.SetNetworkPrivacyPolicy(NetworkPrivacyAdapter.draft(NetworkPrivacyFixtures.policy().copy(
                dnsMode = DnsMode.WIRE_TCP, resolverEndpoint = "192.0.2.1:53")), staged.core.generation)))
        val saved = awaitFrame(frames) { it.core.networkPrivacyPolicy.dnsMode == DnsMode.WIRE_TCP }
        assertSaved(saved)
    }

    /** Run in a fresh instrumentation invocation after force-stopping the app. */
    @Test fun afterProcessRestartReadsDurableLocalConfiguration() = withPrivateControl { client, frames, receipts, pages ->
        val frame = awaitFrame(frames) { true }
        assertSaved(frame)
        instrumentation.runOnMainSync { assertTrue(client.queryNodePage(1, 0u, frame.core.generation)) }
        val page = pages.poll(15, TimeUnit.SECONDS) ?: error("DURABLE_NODE_PAGE_MISSING")
        assertEquals(frame.core.nodes, page.nodes)
        assertRedacted(NodePageWire.encode(page))
        // The original encoded credentials must still participate in canonical duplicate detection.
        assertEquals(ReceiptCode.DUPLICATE_NODE, send(client, receipts, 2, CoreCommand.ImportNode(NODE)))
        instrumentation.runOnMainSync { assertTrue(client.reopenStorage(3)) }
        assertEquals(3L to ReceiptCode.STORAGE_REOPENED, receipts.poll(15, TimeUnit.SECONDS))
        val reopened = awaitFrame(frames) { it.publicationSequence > frame.publicationSequence + 1uL }
        assertSaved(reopened)
    }

    private fun assertSaved(frame: SnapshotFrame) {
        assertQuiescent(frame)
        assertTrue(frame.core.routingEnabled)
        assertEquals(listOf(context.packageName), frame.core.selectedApps)
        assertEquals(SERVER, frame.core.serverAddress)
        assertFalse(frame.core.serverVerified)
        assertEquals(DnsMode.WIRE_TCP, frame.core.networkPrivacyPolicy.dnsMode)
        val node = frame.core.nodes.single { it.label == LABEL }
        assertEquals("node-0000000000000001", node.id)
        assertEquals("durability.invalid:1080", node.endpoint)
        assertEquals(ProtocolKind.SOCKS5, node.protocol)
        assertTrue(node.credentialMaterialPresent)
        assertRedacted(SnapshotWire.encode(frame))
        assertNull(frame.core.activeNodeId)
    }

    private fun assertRedacted(encoded: ByteArray) {
        val wire = encoded.toString(Charsets.ISO_8859_1)
        for (marker in listOf("fixture-user", "fixture%2Duser", "fixture:password", "fixture%3Apassword")) {
            assertFalse("CREDENTIAL_IN_NODE_WIRE", marker in wire)
        }
    }

    private fun assertQuiescent(frame: SnapshotFrame) {
        assertEquals(ConnectionState.DISCONNECTED, frame.core.connectionState)
        assertFalse(frame.tunHeld || frame.transportReady)
        assertTrue(frame.resourcesReleased)
        assertEquals("", frame.engineVersion)
    }

    private fun withPrivateControl(
        block: (CoreServiceClient, ArrayBlockingQueue<SnapshotFrame>, ArrayBlockingQueue<Pair<Long, ReceiptCode>>, ArrayBlockingQueue<NodePage>) -> Unit,
    ) {
        val frames = ArrayBlockingQueue<SnapshotFrame>(32)
        val receipts = ArrayBlockingQueue<Pair<Long, ReceiptCode>>(32)
        val pages = ArrayBlockingQueue<NodePage>(2)
        lateinit var client: CoreServiceClient
        instrumentation.runOnMainSync {
            client = CoreServiceClient(context, { frames.offer(it) },
                { id, code -> receipts.offer(id to code) }, { receipts.offer(0L to it) },
                { _, page, _ -> if (page != null) pages.offer(page) })
            client.bind()
            client.setVisible(true)
        }
        try { block(client, frames, receipts, pages) }
        finally { instrumentation.runOnMainSync { client.close() } }
    }

    private fun awaitFrame(frames: ArrayBlockingQueue<SnapshotFrame>, accept: (SnapshotFrame) -> Boolean): SnapshotFrame {
        repeat(16) {
            val frame = frames.poll(15, TimeUnit.SECONDS) ?: error("DURABLE_STORAGE_FRAME_MISSING")
            if (accept(frame)) return frame
        }
        error("DURABLE_STORAGE_FRAME_NOT_MATCHED")
    }

    private fun send(client: CoreServiceClient, receipts: ArrayBlockingQueue<Pair<Long, ReceiptCode>>,
        id: Long, command: CoreCommand): ReceiptCode {
        instrumentation.runOnMainSync { assertTrue(client.execute(id, command)) }
        val result = receipts.poll(15, TimeUnit.SECONDS) ?: error("DURABLE_STORAGE_RECEIPT_MISSING")
        assertEquals(id, result.first)
        return result.second
    }

    private fun withIsolatedStorage(block: (File, String) -> Unit) {
        val suffix = UUID.randomUUID().toString()
        val directory = File(context.noBackupFilesDir, "test-$suffix")
        val alias = "net.aptist.loft.test.$suffix"
        try { block(directory, alias) }
        finally {
            keyStore().deleteEntry(alias)
            directory.deleteRecursively()
        }
    }

    private fun assertRecoveryRequired(block: () -> Unit) {
        try {
            block()
            fail("EXPECTED_STORAGE_RECOVERY_REQUIRED")
        } catch (failure: StorageKeyException) {
            assertEquals(StorageKeyFailure.RECOVERY_REQUIRED, failure.failure)
        }
    }

    private fun loadRust() {
        System.setProperty("jna.library.path", context.applicationInfo.nativeLibraryDir)
        System.loadLibrary("loft_ffi")
    }

    private fun keyStore() = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    companion object {
        private const val LABEL = "Restart fixture"
        private const val NODE = "socks5://fixture%2Duser:fixture%3Apassword@durability.invalid:1080#Restart%20fixture"
        private const val SERVER = "https://profile.invalid"
    }
}
