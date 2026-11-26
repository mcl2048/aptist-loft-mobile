package net.aptist.loft.service

import android.Manifest
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import net.aptist.loft.R
import net.aptist.loft.foundation.NotificationAccess
import net.aptist.loft.foundation.NotificationAccessStatus

data class AppNotificationAccess(val vpn: NotificationAccessStatus = NotificationAccessStatus.UNKNOWN,
    val mail: NotificationAccessStatus = NotificationAccessStatus.UNKNOWN)

object LoftNotificationChannels {
    const val VPN_CHANNEL = "vpn_connection"
    const val MAIL_CHANNEL = "mail_new_messages"
    const val VPN_NOTIFICATION = 71
    const val MAIL_NOTIFICATION = 72
    const val OPEN_MAIL = "net.aptist.loft.OPEN_MAIL"

    // Creating channels is local and inert. It never subscribes or posts mail.
    fun ensure(context: Context) {
        val manager = context.getSystemService(NotificationManager::class.java)
        manager.createNotificationChannels(listOf(
            NotificationChannel(VPN_CHANNEL, context.getString(R.string.vpn_notification_channel), NotificationManager.IMPORTANCE_LOW),
            NotificationChannel(MAIL_CHANNEL, context.getString(R.string.mail_notification_channel), NotificationManager.IMPORTANCE_DEFAULT)
                .apply { lockscreenVisibility = android.app.Notification.VISIBILITY_PRIVATE },
        ))
    }

    fun access(context: Context): AppNotificationAccess = try {
        val manager = context.getSystemService(NotificationManager::class.java)
        val permission = Build.VERSION.SDK_INT < 33 || context.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED
        val enabled = manager.areNotificationsEnabled()
        AppNotificationAccess(NotificationAccess.channel(permission, enabled, manager.getNotificationChannel(VPN_CHANNEL)?.importance),
            NotificationAccess.channel(permission, enabled, manager.getNotificationChannel(MAIL_CHANNEL)?.importance))
    } catch (_: Exception) { AppNotificationAccess() }
}
