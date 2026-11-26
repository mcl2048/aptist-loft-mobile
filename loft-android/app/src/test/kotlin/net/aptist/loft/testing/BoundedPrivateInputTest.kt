package net.aptist.loft.testing

import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.FileInputStream
import java.io.FilterInputStream
import java.io.IOException

class BoundedPrivateInputTest {
    @get:Rule val temporary = TemporaryFolder()
    private class ObservedReads(input: FileInputStream, private val chunk: Int, private val failAfterFirst: Boolean = false) : FilterInputStream(input) {
        var scratch: ByteArray? = null
        private var reads = 0
        override fun read(buffer: ByteArray, offset: Int, length: Int): Int {
            scratch = buffer
            if (failAfterFirst && reads++ > 0) super.close()
            return super.read(buffer, offset, minOf(chunk, length))
        }
    }
    private fun file(vararg bytes: Int) = temporary.newFile().also { file -> file.writeBytes(bytes.map(Int::toByte).toByteArray()) }
    private fun wiped(input: ObservedReads) {
        val scratch = input.scratch ?: fail("Reader did not execute actual file I/O").let { error("READ_REQUIRED") }
        assertTrue("Sensitive scratch remains after return/failure", scratch.all { it == 0.toByte() })
    }

    @Test fun shortFileReadsReturnTheExactAllowedContentAndWipeScratch() {
        ObservedReads(FileInputStream(file(11, 12, 13, 14, 15)), chunk = 2).use { input ->
            val bytes = BoundedPrivateInput.read(input, 5)
            try { assertArrayEquals(byteArrayOf(11, 12, 13, 14, 15), bytes); wiped(input) }
            finally { bytes.fill(0) }
        }
    }
    @Test fun oversizedActualFileConsumesOnlyTheLimitPlusOneByte() {
        ObservedReads(FileInputStream(file(1, 2, 3, 4, 5, 6, 7, 8)), chunk = 3).use { input ->
            val bytes = BoundedPrivateInput.read(input, 4)
            try {
                assertArrayEquals(byteArrayOf(1, 2, 3, 4, 5), bytes)
                assertEquals(6, input.read())
                wiped(input)
            } finally { bytes.fill(0) }
        }
    }
    @Test fun actualClosedDescriptorFailureStillWipesItsWrittenScratch() {
        ObservedReads(FileInputStream(file(11, 12)), chunk = 1, failAfterFirst = true).use { input ->
            try { BoundedPrivateInput.read(input, 4); fail("Closed descriptor unexpectedly read") }
            catch (_: IOException) { wiped(input) }
        }
    }
}
