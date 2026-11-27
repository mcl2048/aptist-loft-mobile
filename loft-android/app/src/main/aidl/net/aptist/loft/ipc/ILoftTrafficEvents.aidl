package net.aptist.loft.ipc;

oneway interface ILoftTrafficEvents {
    void onVpnTraffic(long attemptId, long uploadBytes, long downloadBytes, boolean finalized);
    void onVpnTrafficUnavailable(long attemptId);
}
