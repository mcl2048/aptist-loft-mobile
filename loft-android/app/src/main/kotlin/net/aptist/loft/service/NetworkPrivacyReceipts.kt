package net.aptist.loft.service

import net.aptist.loft.core.generated.*

data class PlatformTunReceipt(val ipv4CaptureConfirmed: Boolean, val noBypassConfirmed: Boolean, val ipv6BlockedConfirmed: Boolean)

/** Mechanical admission of captured platform/engine facts; Rust decides state. */
object NetworkPrivacyReceipts {
    fun ready(attemptId: ULong, packages: List<String>, expected: CapturedNetworkPolicy,
        facts: GoVpnFacts, platform: PlatformTunReceipt?, currentUidScope: Boolean): VpnReadyReceipt? {
        if (attemptId == 0uL || !currentUidScope || platform?.confirmed() != true ||
            !facts.provesReady || !facts.privacy.samePolicy(expected)) return null
        val privacy = facts.privacy
        return VpnReadyReceipt(attemptId, facts.transportReady, facts.authenticated, facts.tunReady, facts.socketsProtected,
            packages, Ipv6Policy.BLOCKED_IN_VPN,
            NetworkPrivacyReceipt(privacy.policyEpoch, privacy.scopeId, DnsMode.valueOf(privacy.dnsMode!!.name),
                LeakProtectionMode.valueOf(privacy.dnsLeakPolicy!!.name), LeakProtectionMode.valueOf(privacy.webrtcPolicy!!.name),
                privacy.policyInstalled, privacy.enforcementActive, privacy.dnsProtectionEnforced, privacy.webrtcProtectionEnforced,
                privacy.ipv6DropActive, facts.ownershipPending, privacy.hydraEnabled, privacy.hydraApplied,
                HydraScope.valueOf(privacy.hydraScope.name)),
            platform.ipv4CaptureConfirmed, platform.noBypassConfirmed, platform.ipv6BlockedConfirmed)
    }

    fun blocked(attemptId: ULong, packages: List<String>, expected: CapturedNetworkPolicy,
        facts: GoVpnFacts?, platform: PlatformTunReceipt?, currentUidScope: Boolean,
        startJoined: Boolean, originalHeld: Boolean): VpnBlockedReceipt? {
        if (attemptId == 0uL || !currentUidScope || platform?.confirmed() != true || !startJoined || !originalHeld) return null
        if (facts != null && (!facts.provesForwardingDisabled ||
            facts.privacy.enforcementActive || facts.privacy.dnsProtectionEnforced || facts.privacy.webrtcProtectionEnforced ||
            facts.privacy.ipv6DropActive || facts.privacy.hydraApplied || facts.privacy.hydraScope != GoHydraScope.OFF ||
            (facts.privacy.policyInstalled && !facts.privacy.samePolicy(expected)))) return null
        return VpnBlockedReceipt(attemptId, true, true, packages, Ipv6Policy.BLOCKED_IN_VPN, expected.policyEpoch, expected.scopeId,
            platform.ipv4CaptureConfirmed, platform.noBypassConfirmed, platform.ipv6BlockedConfirmed)
    }

    private fun PlatformTunReceipt.confirmed() = ipv4CaptureConfirmed && noBypassConfirmed && ipv6BlockedConfirmed
}
