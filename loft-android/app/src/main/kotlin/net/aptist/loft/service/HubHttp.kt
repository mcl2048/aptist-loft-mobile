package net.aptist.loft.service

import android.net.Network
import net.aptist.loft.core.generated.HubRequest
import java.io.IOException
import java.net.Proxy
import java.net.URI
import java.util.concurrent.TimeUnit
import javax.net.ssl.HttpsURLConnection

internal class HubHttpResponse(val status: UInt, val mediaType: String?, val body: ByteArray)

internal fun exchangeHub(request: HubRequest, network: Network? = null, stillActive: () -> Boolean): HubHttpResponse {
    val started = System.nanoTime()
    val checkActive = {
        if (!stillActive() || System.nanoTime() - started >= TimeUnit.SECONDS.toNanos(25)) throw IOException()
    }
    checkActive()
    val uri = URI(request.url)
    if (uri.scheme != "https" || uri.host == null || uri.rawUserInfo != null || uri.rawFragment != null) throw IOException()
    val url = uri.toURL()
    val connection = (network?.openConnection(url, Proxy.NO_PROXY) ?: url.openConnection(Proxy.NO_PROXY)) as HttpsURLConnection
    try {
        connection.instanceFollowRedirects = false
        connection.useCaches = false
        connection.connectTimeout = 8_000
        connection.readTimeout = 8_000
        connection.requestMethod = request.method
        connection.setRequestProperty("Accept-Encoding", "identity")
        connection.setRequestProperty("Connection", "close")
        connection.setRequestProperty("Cache-Control", "no-store")
        request.requestedCapabilities?.let { connection.setRequestProperty("X-Loft-Capabilities", it) }
        request.ifNoneMatch?.let { connection.setRequestProperty("If-None-Match", it) }
        request.bearer?.let { connection.setRequestProperty("Authorization", "Bearer $it") }
        if (request.body.isNotEmpty()) {
            connection.doOutput = true
            connection.setRequestProperty("Content-Type", "application/json")
            connection.setFixedLengthStreamingMode(request.body.size)
            checkActive()
            connection.outputStream.use { output ->
                for (offset in request.body.indices step (16 * 1024)) {
                    checkActive()
                    output.write(request.body, offset, minOf(16 * 1024, request.body.size - offset))
                }
            }
        }
        checkActive()
        val status = connection.responseCode
        checkActive()
        if (status == 304 && request.ifNoneMatch != null) return HubHttpResponse(304u, null, byteArrayOf())
        if (status !in 200..599 || status in 300..399) throw IOException()
        val limit = request.maxResponseBytes.toInt()
        if (connection.contentLengthLong > limit) throw HubResponseTooLarge()
        val input = if (status >= 400) connection.errorStream else connection.inputStream
        val body = input?.use { readHubBody(it, limit, checkActive) } ?: byteArrayOf()
        return HubHttpResponse(status.toUInt(), connection.contentType, body)
    } finally {
        request.body.fill(0)
        connection.disconnect()
    }
}
