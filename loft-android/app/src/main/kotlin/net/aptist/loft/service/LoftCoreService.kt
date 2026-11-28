package net.aptist.loft.service

import android.app.Service
import android.content.Intent
import android.os.Binder
import android.os.IBinder
import android.os.ParcelFileDescriptor
import android.os.Process
import net.aptist.loft.ipc.ILoftControl
import net.aptist.loft.ipc.ILoftEvents
import net.aptist.loft.ipc.ILoftHubEvents
import net.aptist.loft.ipc.ILoftTrafficEvents

/** Private UI binding; the process owner also serves LoftVpnService. */
class LoftCoreService : Service() {
    private lateinit var owner: LoftRuntimeOwner
    private val controllerToken = Any()
    private val binder = object : ILoftControl.Stub() {
        override fun subscribe(observer: ILoftEvents) { enforceCaller(); owner.subscribe(observer) }
        override fun unsubscribe(observer: ILoftEvents) { enforceCaller(); owner.unsubscribe(observer) }
        override fun execute(requestId: Long, command: ByteArray, receiptObserver: ILoftEvents) {
            enforceCaller(); owner.execute(requestId, command, receiptObserver)
        }
        override fun queryNodePage(requestId: Long, offset: Int, expectedGeneration: Long, observer: ILoftEvents) {
            enforceCaller(); owner.queryNodePage(requestId, offset, expectedGeneration.toULong(), observer)
        }
        override fun setPresentationLocale(locale: String) { enforceCaller(); owner.setPresentationLocale(locale) }
        override fun reopenStorage(requestId: Long, receiptObserver: ILoftEvents) {
            enforceCaller(); owner.reopenStorage(requestId, receiptObserver)
        }
        override fun executeHub(requestId: Long, action: String, input: String?, mailAccess: Boolean,
            destination: ParcelFileDescriptor?, observer: ILoftHubEvents) {
            enforceCaller(); owner.executeHub(requestId, action, input, mailAccess, destination, observer)
        }
        override fun cancelHubWork(requestId: Long) { enforceCaller(); owner.cancelHubWork(requestId) }
        override fun executeVault(epoch: Long, requestId: Long, command: ByteArray, observer: ILoftHubEvents) {
            enforceCaller(); owner.executeVault(controllerToken, epoch, requestId, command, observer)
        }
        override fun setProtectedArea(epoch: Long, area: Int) {
            enforceCaller(); owner.setProtectedArea(controllerToken, epoch, ProtectedArea.entries.getOrNull(area))
        }
        override fun executeProtected(epoch: Long, requestId: Long, command: ByteArray, observer: ILoftHubEvents) {
            enforceCaller(); owner.executeProtected(controllerToken, epoch, requestId, command, observer)
        }
        override fun cancelVaultWork(requestId: Long) { enforceCaller(); owner.cancelVaultWork(requestId) }
        override fun executeNotesSync(requestId: Long, observer: ILoftHubEvents) {
            enforceCaller(); owner.executeNotesSync(requestId, observer)
        }
        override fun cancelNotesSync(requestId: Long) {
            enforceCaller(); owner.cancelNotesSync(requestId)
        }
        override fun queryVpnTraffic(attemptId: Long, observer: ILoftTrafficEvents) {
            enforceCaller(); owner.queryVpnTraffic(attemptId.toULong(), observer)
        }
    }
    override fun onCreate() {
        super.onCreate()
        owner = LoftRuntimeOwner.get(applicationContext)
        owner.attachUi(controllerToken)
    }
    override fun onBind(intent: Intent?): IBinder = binder
    private fun enforceCaller() {
        if (Binder.getCallingUid() != Process.myUid()) throw SecurityException("Private LOFT control service")
    }
    override fun onDestroy() {
        owner.detachUi(controllerToken)
        super.onDestroy()
    }
}
