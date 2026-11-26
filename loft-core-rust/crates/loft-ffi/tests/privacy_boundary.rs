pub mod support;
use loft_ffi::{
    AppCore, CoreError, DnsMode, HydraScope, Ipv6Policy, LeakProtectionMode,
    NetworkPrivacyEnforcement, VpnReadyReceipt,
};

fn start(core: &AppCore) -> std::sync::Arc<loft_ffi::VpnStartTicket> {
    let node = core
        .import_node("socks5://user:boundary-private@proxy.example".into())
        .unwrap();
    let ticket = core.begin_vpn(node.id, core.snapshot().generation).unwrap();
    support::freeze(&ticket, vec![]);
    ticket
}
fn ready(ticket: &loft_ffi::VpnStartTicket) -> VpnReadyReceipt {
    VpnReadyReceipt {
        attempt_id: ticket.attempt_id(),
        transport_ready: true,
        authenticated: true,
        tun_ready: true,
        sockets_protected: true,
        applied_package_names: vec![],
        ipv6_policy: Ipv6Policy::BlockedInVpn,
        privacy: support::privacy(ticket),
        ipv4_capture_confirmed: true,
        no_bypass_confirmed: true,
        ipv6_blocked_confirmed: true,
    }
}

#[test]
fn exported_policy_commands_normalize_without_mutating_caller_records() {
    let core = AppCore::new();
    let before = core.snapshot();
    assert_eq!(before.schema_version, 2);
    assert_eq!(before.network_privacy_policy_epoch, 1);
    let mut policy = before.network_privacy_policy;
    policy.dns_mode = DnsMode::WireTcp;
    policy.resolver_endpoint = "1.1.1.1:00053".into();
    core.set_network_privacy_policy(policy.clone(), before.generation)
        .unwrap();
    policy.resolver_endpoint.clear();
    let saved = core.snapshot();
    assert_eq!(saved.network_privacy_policy.resolver_endpoint, "1.1.1.1:53");
    assert_eq!(saved.network_privacy_policy_epoch, 2);
    assert_eq!(saved.generation, 1);
    assert_eq!(
        core.set_network_privacy_policy(policy, saved.generation),
        Err(CoreError::InvalidNetworkPrivacyPolicy)
    );
    assert_eq!(core.snapshot(), saved);
}

#[test]
fn exported_ticket_has_bounded_redacted_canonical_policy_and_uid_identity() {
    let core = AppCore::new();
    let ticket = start(&core);
    let policy = ticket.canonical_network_policy().unwrap();
    assert!(policy.len() <= 4096);
    assert_eq!(ticket.network_scope_id().unwrap().len(), 64);
    assert!(policy.contains("\"dns_mode\":\"node_domain_fake_ip\""));
    assert!(!policy.contains("boundary-private"));
    ticket.take_raw_node().unwrap();
    core.mark_vpn_ready(ready(&ticket)).unwrap();
    assert_eq!(
        core.snapshot().network_privacy_enforcement,
        NetworkPrivacyEnforcement::Active
    );
    assert_eq!(
        core.snapshot().applied_network_privacy.unwrap().hydra_scope,
        HydraScope::Off
    );
    core.begin_vpn_stop().unwrap();
    assert_eq!(
        ticket.canonical_network_policy(),
        Err(CoreError::TicketExpired)
    );
    assert_eq!(
        core.snapshot().network_privacy_enforcement,
        NetworkPrivacyEnforcement::Inactive
    );
}

#[test]
fn exported_ready_denies_unenforced_pending_and_wrong_scope_receipts() {
    for bad in 0..4 {
        let core = AppCore::new();
        let ticket = start(&core);
        ticket.take_raw_node().unwrap();
        let before = core.snapshot();
        let mut receipt = ready(&ticket);
        match bad {
            0 => receipt.privacy.dns_protection_enforced = false,
            1 => receipt.privacy.ownership_pending = true,
            2 => receipt.privacy.scope_id = "0".repeat(64),
            _ => receipt.no_bypass_confirmed = false,
        }
        assert_eq!(
            core.mark_vpn_ready(receipt),
            Err(CoreError::InvalidNetworkPrivacyReceipt)
        );
        assert_eq!(core.snapshot(), before);
    }
}

#[test]
fn a_policy_save_invalidates_old_pages_without_changing_their_schema_or_capacity() {
    let core = AppCore::new();
    for index in 0..200 {
        core.import_node(format!("socks5://privacy-page-{index}.example"))
            .unwrap();
    }
    let before = core.snapshot();
    let mut policy = before.network_privacy_policy;
    policy.webrtc_policy = LeakProtectionMode::Block;
    core.set_network_privacy_policy(policy, before.generation)
        .unwrap();
    assert_eq!(
        core.node_page(50, before.generation),
        Err(CoreError::StaleGeneration)
    );
    let page = core.node_page(150, core.snapshot().generation).unwrap();
    assert_eq!(page.schema_version, 1);
    assert_eq!(page.node_count, 200);
    assert_eq!(page.nodes.len(), 50);
}
