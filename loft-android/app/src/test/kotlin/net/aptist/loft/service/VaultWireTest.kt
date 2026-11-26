package net.aptist.loft.service

import net.aptist.loft.core.generated.VaultDraft
import net.aptist.loft.core.generated.VaultKind
import net.aptist.loft.core.generated.VaultPage
import net.aptist.loft.core.generated.VaultReveal
import org.junit.Assert.*
import org.junit.Test
import java.io.IOException

class VaultWireTest {
    @Test fun metadataEditPreservesOmittedSecretAndRoundTrips() {
        val edit = VaultDraft("local", VaultKind.PASSWORD, "Name", "Account", "Issuer", null, null, null, null)
        val encoded = VaultWire.command(VaultCommand.Save(edit))
        assertEquals(edit, (VaultWire.readCommand(encoded) as VaultCommand.Save).draft)
        assertThrows(IOException::class.java) { VaultWire.readCommand(encoded + byteArrayOf(0)) }
    }

    @Test fun privateRevealCarriesOnlySelectedValueAndItsValidity() {
        val value = byteArrayOf(0x31, 0x32, 0x33, 0x34, 0x35, 0x36)
        val encoded = VaultWire.result(VaultResult.Reveal(VaultReveal(value, 9u), 9_000))
        val response = VaultWire.readResult(encoded) as VaultResult.Reveal
        val decoded = response.value
        assertArrayEquals(value, decoded.value)
        assertEquals(9u, decoded.validForSeconds)
        assertEquals(9_000L, response.validUntilElapsed)
        assertThrows(IOException::class.java) { VaultWire.readResult(encoded + byteArrayOf(0)) }
    }

    @Test fun pageResponseHasASeparateGenerationAndNoReveal() {
        val metadata = VaultPage(4u, 30u, emptyList(), 60u)
        val result = VaultWire.readResult(VaultWire.result(VaultResult.Page(metadata)))
        assertEquals(metadata, (result as VaultResult.Page).content)
    }
}
