package net.aptist.loft.foundation

enum class NotificationAccessStatus { ALLOWED, PERMISSION_DENIED, APP_DISABLED, CHANNEL_DISABLED, CHANNEL_QUIET, NOT_CREATED, UNKNOWN }

/** Presentation of real OS permission/channel facts; never VPN business state. */
object NotificationAccess {
    fun channel(permissionGranted: Boolean, applicationEnabled: Boolean, importance: Int?): NotificationAccessStatus = when {
        !permissionGranted -> NotificationAccessStatus.PERMISSION_DENIED
        !applicationEnabled -> NotificationAccessStatus.APP_DISABLED
        importance == null -> NotificationAccessStatus.NOT_CREATED
        importance !in 0..5 -> NotificationAccessStatus.UNKNOWN
        importance == 0 -> NotificationAccessStatus.CHANNEL_DISABLED
        importance == 1 -> NotificationAccessStatus.CHANNEL_QUIET
        else -> NotificationAccessStatus.ALLOWED
    }
}
