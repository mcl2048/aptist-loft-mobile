package net.aptist.loft.foundation

import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.After
import org.junit.rules.TemporaryFolder
import java.io.FileInputStream
import java.io.IOException

class NativeResourcesTest {
    @get:Rule val temporary = TemporaryFolder()
    private val opened = mutableListOf<FileInputStream>()
    private fun open(file: java.io.File) = FileInputStream(file).also { opened += it }
    @After fun closeTestDescriptors() { opened.forEach { it.close() } }
    private fun coreFile() = temporary.newFile().also { it.writeBytes(byteArrayOf(10, 20, 30, 40)) }
    private fun goFile() = temporary.newFile().also { it.writeBytes(byteArrayOf(50, 60, 70)) }

    // Catches creating Go as a prerequisite of guest/import/account core access.
    @Test fun localCoreAccessNeverConstructsGo() {
        val input = coreFile()
        val goInput = goFile()
        val marker = java.io.File(temporary.root, "go-created")
        NativeResources({ open(input) }, { marker.writeText("created"); open(goInput) }).use { owner ->
            owner.retainUi()
            assertEquals(10, owner.currentCore().read())
            assertEquals(20, owner.currentCore().read())
            assertFalse(marker.exists())
        }
    }

    // Catches a Go load/init failure invalidating an otherwise usable Rust core.
    @Test fun failedExplicitGoInitializationKeepsTheCoreReadable() {
        val input = coreFile()
        NativeResources<FileInputStream, FileInputStream>({ open(input) }, { throw IOException("unavailable") }).use { owner ->
            owner.retainUi()
            assertEquals(10, owner.currentCore().read())
            try { owner.explicitGo(); fail("Expected Go factory failure") } catch (_: IOException) { }
            assertEquals(20, owner.currentCore().read())
        }
    }

    // Catches allocating a second core during Activity/binding recreation.
    @Test fun twoUiLeasesReuseOneCoreAndCloseAfterTheLastLease() {
        val input = coreFile()
        val goInput = goFile()
        NativeResources({ open(input) }, { open(goInput) }).use { owner ->
            val original = owner.retainUi()
            assertEquals(10, original.read())
            assertEquals(20, owner.retainUi().read())
            owner.releaseUi()
            assertEquals(30, original.read())
            owner.releaseUi()
            expectClosed(original)
        }
    }

    // Catches UI finish implicitly stopping an active/blocked VPN owner.
    @Test fun vpnLeaseKeepsTheCoreAfterUiUnbind() {
        val input = coreFile()
        val goInput = goFile()
        NativeResources({ open(input) }, { open(goInput) }).use { owner ->
            val original = owner.retainUi()
            owner.retainVpn()
            owner.releaseUi()
            assertEquals(10, original.read())
            assertTrue(owner.releaseVpn(confirmedReleased = true))
            expectClosed(original)
        }
    }

    // Catches treating Go dup closure as proof that the original TUN is released.
    @Test fun unconfirmedVpnReleasePreservesBothNativeLeases() {
        val input = coreFile()
        val goInput = goFile()
        NativeResources({ open(input) }, { open(goInput) }).use { owner ->
            val original = owner.retainVpn()
            val go = owner.explicitGo()
            assertFalse(owner.releaseVpn(confirmedReleased = false))
            assertEquals(10, original.read())
            assertEquals(50, go.read())
            assertTrue(owner.releaseVpn(confirmedReleased = true))
            expectClosed(original)
            expectClosed(go)
        }
    }

    // Catches retaining idle Go after VPN stop while local configuration remains open.
    @Test fun confirmedVpnReleaseClosesGoAndPreservesUiCore() {
        val input = coreFile()
        val goInput = goFile()
        NativeResources({ open(input) }, { open(goInput) }).use { owner ->
            val original = owner.retainUi()
            owner.retainVpn()
            val go = owner.explicitGo()
            assertTrue(owner.releaseVpn(confirmedReleased = true))
            expectClosed(go)
            assertEquals(10, original.read())
            assertEquals(20, owner.currentCore().read())
        }
    }

    @Test fun explicitDiagnosticGoIsReusedAndThenReleasedWithoutClosingCore() {
        val input = coreFile()
        val goInput = goFile()
        NativeResources({ open(input) }, { open(goInput) }).use { owner ->
            owner.retainUi()
            val go = owner.explicitGo()
            assertEquals(50, go.read())
            assertEquals(60, owner.explicitGo().read())
            owner.releaseGo()
            expectClosed(go)
            assertEquals(10, owner.currentCore().read())
        }
    }

    private fun expectClosed(stream: FileInputStream) {
        try { stream.read(); fail("Native file descriptor remained open") } catch (_: IOException) { }
    }
}
