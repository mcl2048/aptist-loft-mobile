package net.aptist.loft.service

import org.json.JSONObject

class GoRuntimeInfoException : IllegalArgumentException("INVALID_ENGINE_CAPABILITIES")

/** Inert generated-engine capabilities, validated before explicit VPN construction. */
object GoRuntimeInfo {
    fun decodeEngineVersion(raw: String): String {
        try {
            require(raw.toByteArray(Charsets.UTF_8).size <= 16 * 1024)
            val info = JSONObject(raw)
            require(info.getInt("schema_version") == 1 && info.getBoolean("gvisor_built") && !info.getBoolean("transport_ready"))
            require(info.get("gomaxprocs") == 2)
            val version = info.getString("engine_version")
            require(version.toByteArray(Charsets.UTF_8).size <= 64)
            return version
        } catch (_: Exception) { throw GoRuntimeInfoException() }
    }
}
