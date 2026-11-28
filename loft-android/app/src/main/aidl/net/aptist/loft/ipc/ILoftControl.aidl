package net.aptist.loft.ipc;

import net.aptist.loft.ipc.ILoftEvents;
import net.aptist.loft.ipc.ILoftHubEvents;
import net.aptist.loft.ipc.ILoftTrafficEvents;
import android.os.ParcelFileDescriptor;

interface ILoftControl {
    void subscribe(ILoftEvents observer);
    void unsubscribe(ILoftEvents observer);
    void execute(long requestId, in byte[] command, ILoftEvents receiptObserver);
    void queryNodePage(long requestId, int offset, long expectedGeneration, ILoftEvents observer);
    oneway void setPresentationLocale(String locale);
    oneway void reopenStorage(long requestId, ILoftEvents receiptObserver);
    oneway void executeHub(long requestId, String action, @nullable String input, boolean mailAccess,
        in @nullable ParcelFileDescriptor destination, ILoftHubEvents observer);
    oneway void cancelHubWork(long requestId);
    oneway void executeVault(long epoch, long requestId, in byte[] command, ILoftHubEvents observer);
    oneway void setProtectedArea(long epoch, int area);
    oneway void executeProtected(long epoch, long requestId, in byte[] command, ILoftHubEvents observer);
    oneway void cancelVaultWork(long requestId);
    oneway void executeNotesSync(long requestId, ILoftHubEvents observer);
    oneway void cancelNotesSync(long requestId);
    oneway void queryVpnTraffic(long attemptId, ILoftTrafficEvents observer);
}
