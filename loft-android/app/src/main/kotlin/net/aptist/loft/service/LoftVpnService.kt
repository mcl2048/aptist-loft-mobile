package net.aptist.loft.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.Network
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.ParcelFileDescriptor
import net.aptist.loft.MainActivity
import net.aptist.loft.R
import net.aptist.loft.core.generated.VpnFailure
import net.aptist.loft.foundation.ForegroundPublication

data class EstablishedTun(val descriptor: ParcelFileDescriptor, val receipt: PlatformTunReceipt)

/** OS VPN capability guarded by BIND_VPN_SERVICE, in the same private process. */
class LoftVpnService : VpnService() {
    private lateinit var owner: LoftRuntimeOwner
    private val main = Handler(Looper.getMainLooper())
    private val foreground = ForegroundPublication()
    private var lastText = R.string.vpn_notification_connecting
    override fun onCreate() {
        super.onCreate()
        owner = LoftRuntimeOwner.get(applicationContext)
        foreground.retain(this)
        LoftNotificationChannels.ensure(owner.notificationContext())
    }
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        foreground.retainIfReleased(this)
        lastText = if (intent?.action == ACTION_STOP) R.string.vpn_notification_stopping else R.string.vpn_notification_connecting
        val notification = notification(lastText)
        if (Build.VERSION.SDK_INT >= 34) startForeground(NOTIFICATION, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED)
        else startForeground(NOTIFICATION, notification)
        when (intent?.action) {
            ACTION_STOP -> owner.requestStop(null, 0L, foreground = this)
            ACTION_START -> if (!owner.activate(this)) releaseForeground(this)
            else -> releaseForeground(this)
        }
        return START_NOT_STICKY
    }
    fun establishTun(network: Network, enabled: Boolean, packages: List<String>): EstablishedTun {
        val open = PendingIntent.getActivity(this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        // The service setter requires an established VPN. Initial configuration:
        // https://android.googlesource.com/platform/frameworks/base/+/refs/tags/android-10.0.0_r1/core/java/android/net/VpnService.java
        val builder = Builder().setSession(getString(R.string.app_name)).setConfigureIntent(open)
            .setUnderlyingNetworks(arrayOf(network))
            .setMtu(VpnPolicy.MTU).addAddress(VpnPolicy.IPV4_ADDRESS, VpnPolicy.IPV4_PREFIX_LENGTH)
            .addRoute("0.0.0.0", 0).addDnsServer(VpnPolicy.SYNTHETIC_DNS).setBlocking(false)
        // No IPv6 address/route/allowFamily: Android blocks this family in the
        // effective UID scope. The Go packet adapter also rejects IPv6.
        if (enabled) { require(packages.isNotEmpty()); packages.forEach { builder.addAllowedApplication(it) } }
        val descriptor = builder.establish() ?: throw IllegalStateException("TUN_ESTABLISH_FAILED")
        // These confirm the successfully established Builder configuration. UID
        // identity is rechecked separately; this is not a kernel attestation.
        return EstablishedTun(descriptor, PlatformTunReceipt(true, true, true))
    }
    fun retainForeground(token: Any) = foreground.retain(token)
    fun show(frame: SnapshotFrame, token: Any) {
        main.post {
            if (!foreground.admits(token, frame.publicationSequence) ||
                !VpnNotificationProjection.snapshotAllowed(frame, owner.notificationStopping(token)) ||
                (frame.transportReady && !owner.notificationReady(token))) return@post
            val text = when (VpnNotificationProjection.state(frame)) {
                VpnNotificationState.CONNECTED -> R.string.vpn_notification_connected
                VpnNotificationState.BLOCKED -> R.string.vpn_notification_blocked
                VpnNotificationState.STOPPING -> R.string.vpn_notification_stopping
                VpnNotificationState.UNAVAILABLE -> R.string.vpn_notification_unavailable
                VpnNotificationState.CONNECTING -> R.string.vpn_notification_connecting
                VpnNotificationState.RELEASED -> return@post
            }
            lastText = text
            (getSystemService(NOTIFICATION_SERVICE) as NotificationManager).notify(NOTIFICATION, notification(text))
        }
    }
    fun showBlocked(token: Any) { main.post { if (foreground.matches(token) &&
        VpnNotificationProjection.unsequencedAllowed(owner.notificationStopping(token)) && owner.notificationBlocked(token)) {
        lastText = R.string.vpn_notification_blocked; (getSystemService(NOTIFICATION_SERVICE) as NotificationManager).notify(NOTIFICATION, notification(lastText))
    } } }
    fun showUnavailable(token: Any) { main.post { if (foreground.matches(token) &&
        VpnNotificationProjection.unsequencedAllowed(owner.notificationStopping(token))) {
        lastText = R.string.vpn_notification_unavailable; (getSystemService(NOTIFICATION_SERVICE) as NotificationManager).notify(NOTIFICATION, notification(lastText))
    } } }
    fun showStopping(token: Any) { main.post { if (foreground.matches(token) && owner.notificationStopping(token)) {
        lastText = R.string.vpn_notification_stopping; (getSystemService(NOTIFICATION_SERVICE) as NotificationManager).notify(NOTIFICATION, notification(lastText))
    } } }
    fun refreshLocalizedNotification() { main.post { if (!foreground.released()) (getSystemService(NOTIFICATION_SERVICE) as NotificationManager).notify(NOTIFICATION, notification(lastText)) } }
    fun releaseForeground(token: Any) {
        if (!foreground.release(token)) return
        main.post { if (foreground.released()) { stopForeground(STOP_FOREGROUND_REMOVE); stopSelf() } }
    }
    private fun notification(text: Int): Notification {
        val labels = owner.notificationContext()
        val open = PendingIntent.getActivity(this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        val stop = PendingIntent.getService(this, 1, Intent(this, LoftVpnService::class.java).setAction(ACTION_STOP), PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        return Notification.Builder(this, CHANNEL).setSmallIcon(R.drawable.ic_network).setContentTitle(labels.getString(R.string.app_name))
            .setContentText(labels.getString(text)).setContentIntent(open).setOngoing(true).setCategory(Notification.CATEGORY_SERVICE)
            .addAction(Notification.Action.Builder(null, labels.getString(R.string.stop_vpn), stop).build()).build()
    }
    override fun onRevoke() { owner.requestStop(null, 0L, VpnFailure.REVOKED, this) }
    override fun onDestroy() {
        owner.serviceDestroyed(this)
        foreground.close()
        main.removeCallbacksAndMessages(null)
        super.onDestroy()
    }
    companion object {
        const val ACTION_START = "net.aptist.loft.START_VPN"
        const val ACTION_STOP = "net.aptist.loft.STOP_VPN"
        private const val CHANNEL = LoftNotificationChannels.VPN_CHANNEL
        private const val NOTIFICATION = LoftNotificationChannels.VPN_NOTIFICATION
    }
}
