package net.aptist.loft.service

import org.junit.Assert.*
import org.junit.Test

class GoRuntimeInfoTest {
    private fun compiled() = """{"schema_version":1,"engine_version":"0.1.1-LYNX","gvisor_built":true,"transport_ready":false,"gomaxprocs":2}"""

    @Test fun compiledBudgetAndVersionAreAdmittedWithoutClaimingTransportReadiness() {
        assertEquals("0.1.1-LYNX", GoRuntimeInfo.decodeEngineVersion(compiled()))
    }
    @Test fun runtimeProcessorBudgetMustBeReportedAsTheActualAndroidTwo() {
        invalid(compiled().replace("\"gomaxprocs\":2", "\"gomaxprocs\":3"))
        invalid(compiled().replace("\"gomaxprocs\":2", "\"gomaxprocs\":1"))
        invalid(compiled().replace("\"gomaxprocs\":2", "\"gomaxprocs\":\"2\""))
        invalid(compiled().replace(",\"gomaxprocs\":2", ""))
    }
    @Test fun invalidCapabilitiesAndOversizedVersionCannotConstructVpn() {
        invalid(compiled().replace("\"gvisor_built\":true", "\"gvisor_built\":false"))
        invalid(compiled().replace("\"transport_ready\":false", "\"transport_ready\":true"))
        invalid(compiled().replace("\"schema_version\":1", "\"schema_version\":2"))
        invalid(compiled().replace("0.1.1-LYNX", "a".repeat(65)))
        invalid(" ".repeat(16 * 1024 + 1))
    }
    private fun invalid(raw: String) {
        try { GoRuntimeInfo.decodeEngineVersion(raw); fail("Invalid engine capabilities were admitted") }
        catch (_: GoRuntimeInfoException) { }
    }
}
