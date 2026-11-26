package net.aptist.loft.service

import android.Manifest
import android.app.Notification
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import net.aptist.loft.MainActivity
import net.aptist.loft.BuildConfig
import net.aptist.loft.R
import net.aptist.loft.foundation.*

enum class MailPlatformSubmission { NOT_ATTEMPTED, SETTINGS_DENIED, SUBMITTED, UNAVAILABLE }
data class MailDeliveryReceipt(val admission: MailEventOffer, val platform: MailPlatformSubmission)

/** Inert until a real Rust authority/provider adapter is supplied by a product. */
internal class LoftMailNotifications(private val app: Context, private val labels: () -> Context,
    authority: MailEventAuthority = DenyAllMailEvents) {
    private val gate = MailNotificationGate(authority)

    @Synchronized fun receive(raw: ByteArray): MailDeliveryReceipt {
        val nowMillis = System.currentTimeMillis()
        val admission = gate.offer(raw, nowMillis)
        if (admission != MailEventOffer.ACCEPTED) return MailDeliveryReceipt(admission, MailPlatformSubmission.NOT_ATTEMPTED)
        val access = LoftNotificationChannels.access(app).mail
        if (access != NotificationAccessStatus.ALLOWED && access != NotificationAccessStatus.CHANNEL_QUIET) {
            revoke()
            return MailDeliveryReceipt(admission, MailPlatformSubmission.SETTINGS_DENIED)
        }
        val summaries = gate.drain(nowMillis)
        val summary = summaries.singleOrNull()
        if (summary == null || summary.scope.productId != BuildConfig.PRODUCT_ID) {
            revoke()
            return MailDeliveryReceipt(MailEventOffer.DENIED, MailPlatformSubmission.NOT_ATTEMPTED)
        }
        if (Build.VERSION.SDK_INT >= 33 && app.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
            revoke()
            return MailDeliveryReceipt(admission, MailPlatformSubmission.SETTINGS_DENIED)
        }
        return try {
            val localized = labels()
            LoftNotificationChannels.ensure(localized)
            val open = PendingIntent.getActivity(app, 2, Intent(app, MainActivity::class.java)
                .setAction(LoftNotificationChannels.OPEN_MAIL)
                .addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP),
                PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
            val public = Notification.Builder(app, LoftNotificationChannels.MAIL_CHANNEL).setSmallIcon(R.drawable.ic_mail)
                .setContentTitle(localized.getString(R.string.mail_notification_title)).setContentText(localized.getString(R.string.mail_notification_body)).build()
            val notification = Notification.Builder(app, LoftNotificationChannels.MAIL_CHANNEL).setSmallIcon(R.drawable.ic_mail)
                .setContentTitle(localized.getString(R.string.mail_notification_title)).setContentText(localized.getString(R.string.mail_notification_body))
                .setPublicVersion(public).setVisibility(Notification.VISIBILITY_PRIVATE).setCategory(Notification.CATEGORY_EMAIL)
                .setNumber(summary.countHint).setContentIntent(open).setAutoCancel(true).setOnlyAlertOnce(true).build()
            app.getSystemService(NotificationManager::class.java).notify(LoftNotificationChannels.MAIL_NOTIFICATION, notification)
            // notify() confirms platform submission. Visibility/provider delivery
            // have separate receipts and are not inferred here.
            MailDeliveryReceipt(admission, MailPlatformSubmission.SUBMITTED)
        } catch (_: Exception) { revoke(); MailDeliveryReceipt(admission, MailPlatformSubmission.UNAVAILABLE) }
    }

    @Synchronized fun revoke() {
        gate.revoke()
        runCatching { app.getSystemService(NotificationManager::class.java).cancel(LoftNotificationChannels.MAIL_NOTIFICATION) }
    }
}
