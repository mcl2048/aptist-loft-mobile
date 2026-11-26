//! Synthetic reducer receipts only; these helpers do not prove OS/packet protection.
use loft_core::{
    EffectivePackageUid, HydraScope, NetworkPrivacyReceipt, NetworkScopeIdentity, VpnStartTicket,
};

pub fn freeze(ticket: &VpnStartTicket, packages: Vec<String>) {
    ticket.freeze_effective_packages(packages.clone()).unwrap();
    ticket
        .freeze_network_scope(NetworkScopeIdentity {
            vpn_owner_uid: 10001,
            package_uids: packages
                .into_iter()
                .map(|package_name| EffectivePackageUid {
                    package_name,
                    uid: 10002,
                })
                .collect(),
        })
        .unwrap();
    ticket.canonical_network_policy().unwrap();
}

pub fn privacy(ticket: &VpnStartTicket) -> NetworkPrivacyReceipt {
    let policy = ticket.network_privacy_policy();
    NetworkPrivacyReceipt {
        policy_epoch: ticket.network_policy_epoch(),
        scope_id: ticket.network_scope_id().unwrap_or_default(),
        dns_mode: policy.dns_mode,
        dns_leak_policy: policy.dns_leak_policy,
        webrtc_policy: policy.webrtc_policy,
        policy_installed: true,
        enforcement_active: true,
        dns_protection_enforced: true,
        webrtc_protection_enforced: true,
        ipv6_drop_active: true,
        ownership_pending: false,
        hydra_enabled: false,
        hydra_applied: false,
        hydra_scope: HydraScope::Off,
    }
}
