package net.aptist.loft.service

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.IOException

class HubTransportTest {
    @Test fun consumesOnlyTheDeclaredBudgetEvenWithoutAContentLength() {
        val exact = ByteArray(65_536) { it.toByte() }
        assertArrayEquals(exact, readHubBody(ByteArrayInputStream(exact), exact.size) {})
        assertThrows(HubResponseTooLarge::class.java) {
            readHubBody(ByteArrayInputStream(exact + 0.toByte()), exact.size) {}
        }
    }

    @Test fun cancellationIsCheckedBeforeReadingTheBody() {
        assertThrows(IOException::class.java) {
            readHubBody(ByteArrayInputStream(byteArrayOf(1)), 2) { throw IOException() }
        }
    }
}
