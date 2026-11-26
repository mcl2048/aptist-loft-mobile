package net.aptist.loft.service

import android.content.Context
import android.net.ConnectivityManager
import android.net.DnsResolver
import android.net.Network
import android.net.NetworkCapabilities
import android.net.VpnService
import android.os.CancellationSignal
import android.os.ParcelFileDescriptor
import android.system.Os
import android.system.OsConstants
import net.aptist.loft.engine.SocketProtector
import net.aptist.loft.foundation.NodeResolutionOwnership
import java.net.Inet4Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.Executor
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

/** Called only in :vpn by the owned Go socket/TUN adapter. */
class AndroidSocketProtector(private val service: VpnService, val network: Network) : SocketProtector, AutoCloseable {
    private val connectivity = service.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
    private val resolution = NodeResolutionOwnership<List<InetAddress>>(timeoutMillis = 5000, maxPending = 1)
    private val callbacks = ThreadPoolExecutor(1, 1, 0L, TimeUnit.MILLISECONDS, ArrayBlockingQueue(8))
    private val callbackExecutor = Executor { task ->
        if (!resolution.stopped) try { callbacks.execute(task) }
        catch (_: RejectedExecutionException) { resolution.cancelCurrent() }
    }
    val protectedSockets = AtomicInteger(0)

    override fun protect(fd: Int): Boolean {
        if (resolution.stopped || !physicalNetworkAvailable() || fd < 0) return false
        return try {
            ParcelFileDescriptor.fromFd(fd).use { duplicate ->
                if (!OsConstants.S_ISSOCK(Os.fstat(duplicate.fileDescriptor).st_mode) ||
                    Os.getsockname(duplicate.fileDescriptor) !is InetSocketAddress) return false
                network.bindSocket(duplicate.fileDescriptor)
                if (!service.protect(fd) || resolution.stopped || !physicalNetworkAvailable()) return false
                protectedSockets.incrementAndGet()
                true
            }
        } catch (_: Exception) { false }
    }

    override fun resolveNode(hostname: String): String {
        if (resolution.stopped || !physicalNetworkAvailable() || hostname.length > 253 || hostname.isBlank()) return ""
        val signal = CancellationSignal()
        val pending = resolution.start { signal.cancel() } ?: return ""
        try {
            DnsResolver.getInstance().query(network, hostname, DnsResolver.TYPE_A, DnsResolver.FLAG_EMPTY,
                callbackExecutor, signal, object : DnsResolver.Callback<List<InetAddress>> {
                    override fun onAnswer(answer: List<InetAddress>, rcode: Int) {
                        pending.complete(if (rcode == 0) answer.filterIsInstance<Inet4Address>().distinct().take(8) else emptyList())
                    }
                    override fun onError(error: DnsResolver.DnsException) { pending.complete(emptyList()) }
                })
        } catch (_: Exception) { pending.cancel() }
        val result = pending.await().orEmpty().filterIsInstance<Inet4Address>().mapNotNull { it.hostAddress }.distinct().take(8).joinToString("\n")
        return if (!resolution.stopped && result.toByteArray(Charsets.UTF_8).size <= 1024) result else ""
    }

    fun cancelPending() = resolution.cancelPending()
    private fun physicalNetworkAvailable(): Boolean {
        val caps = connectivity.getNetworkCapabilities(network) ?: return false
        return caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN) && caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
    }
    fun released(): Boolean = resolution.stopped && callbacks.isTerminated
    override fun close() {
        cancelPending(); callbacks.shutdownNow()
        try { callbacks.awaitTermination(250, TimeUnit.MILLISECONDS) }
        catch (_: InterruptedException) { Thread.currentThread().interrupt() }
    }
}
