package net.aptist.loft.ipc;

import net.aptist.loft.ipc.ILoftEvents;
import net.aptist.loft.ipc.ILoftHubEvents;
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
}
