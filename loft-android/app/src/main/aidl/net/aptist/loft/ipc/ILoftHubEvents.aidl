package net.aptist.loft.ipc;

oneway interface ILoftHubEvents {
    void onResult(long requestId, String code, in byte[] payload);
}
