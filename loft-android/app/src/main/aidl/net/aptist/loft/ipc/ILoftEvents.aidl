package net.aptist.loft.ipc;

oneway interface ILoftEvents {
    void onSnapshot(in byte[] payload);
    void onReceipt(long requestId, String code, in byte[] snapshotPayload);
    void onNotesSync(long generation, String status);
    void onNodePage(long requestId, String code, in byte[] pagePayload);
}
