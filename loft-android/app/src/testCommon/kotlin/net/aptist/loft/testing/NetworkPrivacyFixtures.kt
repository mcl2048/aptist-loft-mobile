package net.aptist.loft.testing

import net.aptist.loft.core.generated.*

object NetworkPrivacyFixtures {
    fun policy() = NetworkPrivacyPolicy(DnsMode.NODE_DOMAIN_FAKE_IP, LeakProtectionMode.PROXY_ONLY,
        LeakProtectionMode.PROXY_ONLY, "", DnsPrivacyLimits(256u, 262144u, 60u, 4096u, 65535u),
        HydraConfig(false, false, 300u, 0u, 0u, 0u, 0u, 0u))
    fun applied(epoch: ULong = 1uL) = AppliedNetworkPrivacy(epoch, "a".repeat(64), policy(), HydraScope.OFF)
}
