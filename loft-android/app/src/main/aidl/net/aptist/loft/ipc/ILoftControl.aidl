package net.aptist.loft.ipc;

import net.aptist.loft.ipc.ILoftEvents;

interface ILoftControl {
    void subscribe(ILoftEvents observer);
    void unsubscribe(ILoftEvents observer);
    void execute(long requestId, in byte[] command, ILoftEvents receiptObserver);
    void queryNodePage(long requestId, int offset, long expectedGeneration, ILoftEvents observer);
    oneway void setPresentationLocale(String locale);
}
