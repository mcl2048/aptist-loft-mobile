package net.aptist.loft.service

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class VpnTrafficSampleTest {
    @Test fun retainsExactByteCountsAndAcceptsRealZeros() {
        assertEquals(VpnTrafficSample(8uL, 0, Long.MAX_VALUE, false), decodeVpnTraffic("1:1:0:9223372036854775807:0", 8uL, false))
        assertEquals(VpnTrafficSample(8uL, Long.MAX_VALUE, Long.MAX_VALUE, true),
            decodeVpnTraffic("1:1:9223372036854775807:9223372036854775807:1", 8uL, true))
        assertEquals(VpnTrafficSample(8uL, 7, 12, true), decodeVpnTraffic("1:1:7:12:1", 8uL, true))
    }

    @Test fun rejectsUnrelatedGenerationAndNoncanonicalNativeSamples() {
        listOf("", "2:1:7:12:0", "1:2:7:12:0", "1:1:7:12:1", "1:1:-7:12:0", "1:1:007:12:0",
            "1:1:7:9223372036854775808:0", "1:1:7:12:0:", "1:1:7:12:0\u0000", "1:1:7:12:+0").forEach { unknown ->
            assertNull(unknown, decodeVpnTraffic(unknown, 8uL, false))
        }
        assertNull(decodeVpnTraffic("1:1:7:12:0", 0uL, false))
    }
}
