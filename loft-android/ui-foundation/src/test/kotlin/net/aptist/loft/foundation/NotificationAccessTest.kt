package net.aptist.loft.foundation

import org.junit.Assert.assertEquals
import org.junit.Test

class NotificationAccessTest {
    @Test fun grantedPermissionDoesNotOverrideDisabledApplicationOrChannel() {
        assertEquals(NotificationAccessStatus.APP_DISABLED, NotificationAccess.channel(true, false, 2))
        assertEquals(NotificationAccessStatus.CHANNEL_DISABLED, NotificationAccess.channel(true, true, 0))
    }

    @Test fun deniedRuntimePermissionNeverClaimsDrawerVisibility() {
        assertEquals(NotificationAccessStatus.PERMISSION_DENIED, NotificationAccess.channel(false, true, 2))
        assertEquals(NotificationAccessStatus.PERMISSION_DENIED, NotificationAccess.channel(false, false, 3))
    }

    @Test fun absentOrUnknownChannelCannotLookAllowed() {
        assertEquals(NotificationAccessStatus.NOT_CREATED, NotificationAccess.channel(true, true, null))
        assertEquals(NotificationAccessStatus.UNKNOWN, NotificationAccess.channel(true, true, -1000))
        assertEquals(NotificationAccessStatus.UNKNOWN, NotificationAccess.channel(true, true, 6))
    }

    @Test fun quietImportanceIsDistinguishedFromStatusNotificationImportance() {
        assertEquals(NotificationAccessStatus.CHANNEL_QUIET, NotificationAccess.channel(true, true, 1))
        assertEquals(NotificationAccessStatus.ALLOWED, NotificationAccess.channel(true, true, 2))
        assertEquals(NotificationAccessStatus.ALLOWED, NotificationAccess.channel(true, true, 3))
    }
}
