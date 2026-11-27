package net.aptist.loft.service

/** A point-in-time application payload count for one accepted VPN attempt. */
data class VpnTrafficSample(val attemptId: ULong, val uploadBytes: Long, val downloadBytes: Long, val finalized: Boolean)

internal fun decodeVpnTraffic(raw: String, attemptId: ULong, finalized: Boolean): VpnTrafficSample? {
    if (attemptId == 0uL || raw.length !in 9..45) return null
    val fields = raw.split(':', limit = 6)
    // Android allocates a new Go runtime for each attempt. Its first real
    // session is generation 1. Reject a baseline or a reused native session.
    if (fields.size != 5 || fields[0] != "1" || fields[1] != "1" || fields[4] != if (finalized) "1" else "0") return null
    val upload = fields[2].trafficByteCount() ?: return null
    val download = fields[3].trafficByteCount() ?: return null
    return VpnTrafficSample(attemptId, upload, download, finalized)
}

private fun String.trafficByteCount(): Long? {
    if (length !in 1..19 || (length > 1 && first() == '0') || any { it !in '0'..'9' }) return null
    return toLongOrNull()
}
