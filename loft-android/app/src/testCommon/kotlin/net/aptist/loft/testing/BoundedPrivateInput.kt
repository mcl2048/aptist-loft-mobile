package net.aptist.loft.testing

import java.io.InputStream

/** Test-only input boundary. The returned bytes belong to the caller for wiping. */
internal object BoundedPrivateInput {
    fun read(input: InputStream, limit: Int): ByteArray {
        require(limit in 0..(64 * 1024))
        val scratch = ByteArray(limit + 1)
        try {
            var count = 0
            while (count < scratch.size) {
                val read = input.read(scratch, count, scratch.size - count)
                if (read < 0) break
                if (read == 0) {
                    val single = input.read()
                    if (single < 0) break
                    scratch[count++] = single.toByte()
                } else count += read
            }
            return scratch.copyOf(count)
        } finally { scratch.fill(0) }
    }
}
