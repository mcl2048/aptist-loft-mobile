package net.aptist.loft.service

import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream

internal class HubResponseTooLarge : IOException()

internal fun readHubBody(input: InputStream, limit: Int, checkActive: () -> Unit): ByteArray {
    require(limit in 0..(4 * 1024 * 1024))
    val buffer = ByteArray(16 * 1024)
    val output = ByteArrayOutputStream(minOf(limit, buffer.size))
    try {
        while (true) {
            checkActive()
            val count = input.read(buffer, 0, minOf(buffer.size, limit - output.size() + 1))
            checkActive()
            if (count == -1) return output.toByteArray()
            if (count > limit - output.size()) throw HubResponseTooLarge()
            output.write(buffer, 0, count)
        }
    } finally {
        buffer.fill(0)
    }
}
