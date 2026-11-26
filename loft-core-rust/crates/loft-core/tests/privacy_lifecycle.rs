use loft_core::{
    CoreError, CoreState, DnsMode, EffectivePackageUid, HydraScope, Ipv6Policy, LeakProtectionMode,
    NetworkPrivacyEnforcement, NetworkPrivacyPolicy, NetworkPrivacyReceipt, NetworkScopeIdentity,
    VpnBlockedReceipt, VpnFailure, VpnReadyReceipt, VpnStartTicket, VpnStoppedReceipt,
};

fn start(core: &mut CoreState) -> std::sync::Arc<VpnStartTicket> {
    let node = core
        .import_node("socks5://user:synthetic-secret@proxy.example#Local".into())
        .unwrap();
    core.begin_vpn(node.id, core.snapshot().generation).unwrap()
}

fn identity(packages: &[String], owner_uid: u32, package_uid: u32) -> NetworkScopeIdentity {
    NetworkScopeIdentity {
        vpn_owner_uid: owner_uid,
        package_uids: packages
            .iter()
            .map(|name| EffectivePackageUid {
                package_name: name.clone(),
                uid: package_uid,
            })
            .collect(),
    }
}

fn freeze(ticket: &VpnStartTicket, packages: Vec<String>) {
    ticket.freeze_effective_packages(packages.clone()).unwrap();
    ticket
        .freeze_network_scope(identity(&packages, 10001, 10002))
        .unwrap();
    ticket.canonical_network_policy().unwrap();
}

fn ready(ticket: &VpnStartTicket, packages: Vec<String>) -> VpnReadyReceipt {
    let policy = ticket.network_privacy_policy();
    VpnReadyReceipt {
        attempt_id: ticket.attempt_id(),
        transport_ready: true,
        authenticated: true,
        tun_ready: true,
        sockets_protected: true,
        applied_package_names: packages,
        ipv6_policy: Ipv6Policy::BlockedInVpn,
        privacy: NetworkPrivacyReceipt {
            policy_epoch: ticket.network_policy_epoch(),
            scope_id: ticket.network_scope_id().unwrap(),
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
        },
        ipv4_capture_confirmed: true,
        no_bypass_confirmed: true,
        ipv6_blocked_confirmed: true,
    }
}

#[test]
fn anonymous_snapshot_has_a_local_draft_and_no_effective_protection() {
    let core = CoreState::new();
    let snapshot = core.snapshot();
    assert_eq!(snapshot.schema_version, 2);
    assert_eq!(snapshot.core_version, "0.1.2-LYNX");
    assert_eq!(snapshot.generation, 0);
    assert_eq!(snapshot.network_privacy_policy_epoch, 1);
    assert_eq!(
        snapshot.network_privacy_policy.dns_mode,
        DnsMode::NodeDomainFakeIp
    );
    assert_eq!(
        snapshot.network_privacy_enforcement,
        NetworkPrivacyEnforcement::Inactive
    );
    assert_eq!(snapshot.applied_network_privacy, None);
}

#[test]
fn saving_a_policy_advances_both_generations_and_rejections_are_atomic() {
    let mut core = CoreState::new();
    let mut policy = NetworkPrivacyPolicy {
        dns_leak_policy: LeakProtectionMode::Block,
        ..Default::default()
    };
    core.set_network_privacy_policy(policy.clone(), 0).unwrap();
    let saved = core.snapshot();
    assert_eq!(saved.generation, 1);
    assert_eq!(saved.network_privacy_policy_epoch, 2);
    policy.hydra.rotation_seconds = 0;
    core.set_network_privacy_policy(policy, 1).unwrap();
    assert_eq!(core.snapshot(), saved);
    let invalid = NetworkPrivacyPolicy {
        dns_mode: DnsMode::WireTcp,
        ..Default::default()
    };
    assert_eq!(
        core.set_network_privacy_policy(invalid.clone(), 1),
        Err(CoreError::InvalidNetworkPrivacyPolicy)
    );
    assert_eq!(
        core.set_network_privacy_policy(invalid, 0),
        Err(CoreError::StaleGeneration)
    );
    assert_eq!(core.snapshot(), saved);
    core.stage_server("cloud.example".into()).unwrap();
    assert_eq!(core.snapshot().generation, 2);
    assert_eq!(core.snapshot().network_privacy_policy_epoch, 2);
}

#[test]
fn canonical_policy_requires_one_frozen_actual_uid_scope_before_uri_delivery() {
    let mut core = CoreState::new();
    let ticket = start(&mut core);
    assert_eq!(
        ticket.canonical_network_policy(),
        Err(CoreError::InvalidNetworkPrivacyReceipt)
    );
    ticket.freeze_effective_packages(vec![]).unwrap();
    assert_eq!(
        ticket.take_raw_node(),
        Err(CoreError::InvalidNetworkPrivacyReceipt)
    );
    ticket
        .freeze_network_scope(identity(&[], 10001, 10002))
        .unwrap();
    assert_eq!(
        ticket.take_raw_node(),
        Err(CoreError::InvalidNetworkPrivacyReceipt)
    );
    let raw = ticket.canonical_network_policy().unwrap();
    let json: serde_json::Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(json["schema_version"], 1);
    assert_eq!(json["policy_epoch"], "1");
    assert_eq!(json["scope_id"], ticket.network_scope_id().unwrap());
    assert_eq!(json["dns_mode"], "node_domain_fake_ip");
    assert_eq!(json["resolver_endpoint"], "");
    assert_eq!(json["dns_map_max_entries"], 256);
    assert_eq!(json["dns_map_max_bytes"], 262144);
    assert_eq!(json["dns_ttl_seconds"], 60);
    assert_eq!(json["dns_max_query_bytes"], 4096);
    assert_eq!(json["dns_max_response_bytes"], 65535);
    assert_eq!(json["hydra"]["enabled"], false);
    assert_eq!(json.as_object().unwrap().len(), 13);
    assert!(raw.len() <= 4096);
    assert!(!raw.contains("synthetic-secret"));
    assert!(!raw.contains("socks5://"));
    assert_eq!(ticket.canonical_network_policy().unwrap(), raw);
    assert!(ticket.take_raw_node().is_ok());
    assert_eq!(ticket.take_raw_node(), Err(CoreError::TicketExpired));
    assert_eq!(
        ticket.freeze_network_scope(identity(&[], 10001, 10002)),
        Err(CoreError::TicketExpired)
    );
}

#[test]
fn a_uid_or_installation_profile_change_changes_the_scope_digest() {
    let packages = vec!["org.example.app".into(), "org.example.shared".into()];
    let mut scopes = Vec::new();
    for (owner_uid, package_uid) in [(10001, 10002), (10001, 10003), (110001, 110002)] {
        let mut core = CoreState::new();
        core.set_app_routing(true, vec!["org.example.app".into()])
            .unwrap();
        let ticket = start(&mut core);
        ticket.freeze_effective_packages(packages.clone()).unwrap();
        ticket
            .freeze_network_scope(identity(&packages, owner_uid, package_uid))
            .unwrap();
        let scope = ticket.network_scope_id().unwrap();
        assert_eq!(scope.len(), 64);
        assert!(
            scope
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        );
        scopes.push(scope);
    }
    assert_ne!(scopes[0], scopes[1]);
    assert_ne!(scopes[0], scopes[2]);
}

#[test]
fn identity_freeze_rejects_missing_duplicate_and_cross_profile_uid_maps() {
    let mut core = CoreState::new();
    core.set_app_routing(true, vec!["org.example.app".into()])
        .unwrap();
    let ticket = start(&mut core);
    let packages = vec!["org.example.app".into(), "org.example.shared".into()];
    ticket.freeze_effective_packages(packages.clone()).unwrap();
    for scope in [
        identity(&[], 10001, 10002),
        identity(&packages[..1], 10001, 10002),
        identity(
            &["org.example.app".into(), "org.example.app".into()],
            10001,
            10002,
        ),
        identity(&packages, 0, 10002),
        identity(&packages, u32::MAX, 10002),
        identity(&packages, 10001, 0),
        identity(&packages, 10001, 110002),
    ] {
        assert_eq!(
            ticket.freeze_network_scope(scope),
            Err(CoreError::InvalidNetworkPrivacyReceipt)
        );
        assert_eq!(
            ticket.network_scope_id(),
            Err(CoreError::InvalidNetworkPrivacyReceipt)
        );
    }
    ticket
        .freeze_network_scope(identity(&packages, 10001, 10002))
        .unwrap();
    assert_eq!(
        ticket.freeze_network_scope(identity(&packages, 10001, 10003)),
        Err(CoreError::TicketExpired)
    );
}

#[test]
fn pending_ticket_and_applied_policy_are_not_overwritten_by_a_saved_draft() {
    let mut core = CoreState::new();
    let ticket = start(&mut core);
    freeze(&ticket, vec![]);
    let receipt = ready(&ticket, vec![]);
    ticket.take_raw_node().unwrap();
    let draft = NetworkPrivacyPolicy {
        webrtc_policy: LeakProtectionMode::Block,
        ..Default::default()
    };
    core.set_network_privacy_policy(draft.clone(), core.snapshot().generation)
        .unwrap();
    assert_eq!(ticket.network_policy_epoch(), 1);
    assert_eq!(
        ticket.network_privacy_policy().webrtc_policy,
        LeakProtectionMode::ProxyOnly
    );
    core.mark_vpn_ready(receipt.clone()).unwrap();
    let active = core.snapshot();
    assert_eq!(active.network_privacy_policy_epoch, 2);
    assert_eq!(active.network_privacy_policy, draft);
    assert_eq!(
        active
            .applied_network_privacy
            .as_ref()
            .unwrap()
            .policy_epoch,
        1
    );
    assert_eq!(
        active
            .applied_network_privacy
            .as_ref()
            .unwrap()
            .policy
            .webrtc_policy,
        LeakProtectionMode::ProxyOnly
    );
    assert_eq!(
        active.network_privacy_enforcement,
        NetworkPrivacyEnforcement::Active
    );
    assert_eq!(core.mark_vpn_ready(receipt.clone()), Ok(()));
    assert_eq!(core.snapshot(), active);
    let mut stale = receipt;
    stale.privacy.policy_epoch = 2;
    assert_eq!(core.mark_vpn_ready(stale), Err(CoreError::StaleGeneration));
    assert_eq!(core.snapshot(), active);
}

#[test]
fn ready_rejects_static_modes_pending_owners_and_unconfirmed_platform_capture() {
    for bad in 0..17 {
        let mut core = CoreState::new();
        let ticket = start(&mut core);
        freeze(&ticket, vec![]);
        ticket.take_raw_node().unwrap();
        let before = core.snapshot();
        let mut receipt = ready(&ticket, vec![]);
        match bad {
            0 => receipt.privacy.policy_installed = false,
            1 => receipt.privacy.enforcement_active = false,
            2 => receipt.privacy.dns_protection_enforced = false,
            3 => receipt.privacy.webrtc_protection_enforced = false,
            4 => receipt.privacy.ipv6_drop_active = false,
            5 => receipt.privacy.ownership_pending = true,
            6 => receipt.privacy.scope_id = "0".repeat(64),
            7 => receipt.privacy.policy_epoch += 1,
            8 => receipt.privacy.dns_mode = DnsMode::WireTcp,
            9 => receipt.privacy.dns_leak_policy = LeakProtectionMode::Block,
            10 => receipt.privacy.webrtc_policy = LeakProtectionMode::Block,
            11 => receipt.privacy.hydra_enabled = true,
            12 => receipt.privacy.hydra_applied = true,
            13 => receipt.privacy.hydra_scope = HydraScope::LogicalStreams,
            14 => receipt.ipv4_capture_confirmed = false,
            15 => receipt.no_bypass_confirmed = false,
            _ => receipt.ipv6_blocked_confirmed = false,
        }
        let expected = if bad == 7 {
            CoreError::StaleGeneration
        } else {
            CoreError::InvalidNetworkPrivacyReceipt
        };
        assert_eq!(core.mark_vpn_ready(receipt), Err(expected));
        assert_eq!(core.snapshot(), before);
        assert_eq!(
            core.snapshot().network_privacy_enforcement,
            NetworkPrivacyEnforcement::Inactive
        );
    }
}

#[test]
fn stop_retracts_active_protection_and_invalidates_policy_and_uri_access() {
    let mut core = CoreState::new();
    let ticket = start(&mut core);
    freeze(&ticket, vec![]);
    let receipt = ready(&ticket, vec![]);
    ticket.take_raw_node().unwrap();
    core.mark_vpn_ready(receipt.clone()).unwrap();
    let scope = ticket.network_scope_id().unwrap();
    let attempt = core.begin_vpn_stop().unwrap();
    assert_eq!(
        core.snapshot().network_privacy_enforcement,
        NetworkPrivacyEnforcement::Inactive
    );
    assert_eq!(
        ticket.canonical_network_policy(),
        Err(CoreError::TicketExpired)
    );
    assert_eq!(ticket.take_raw_node(), Err(CoreError::TicketExpired));
    assert_eq!(ticket.network_scope_id().unwrap(), scope);
    assert_eq!(
        core.mark_vpn_ready(receipt),
        Err(CoreError::StaleGeneration)
    );
    core.confirm_vpn_stopped(VpnStoppedReceipt {
        attempt_id: attempt,
        tun_closed: true,
        resources_released: true,
    })
    .unwrap();
    assert_eq!(core.snapshot().applied_network_privacy, None);
}

#[test]
fn blocked_protection_requires_the_original_tun_and_exact_frozen_scope() {
    let mut core = CoreState::new();
    let ticket = start(&mut core);
    freeze(&ticket, vec![]);
    core.mark_vpn_failed(ticket.attempt_id(), VpnFailure::EngineStartFailed)
        .unwrap();
    let receipt = VpnBlockedReceipt {
        attempt_id: ticket.attempt_id(),
        tun_held: true,
        forwarding_disabled: true,
        effective_package_names: vec![],
        ipv6_policy: Ipv6Policy::BlockedInVpn,
        policy_epoch: ticket.network_policy_epoch(),
        scope_id: ticket.network_scope_id().unwrap(),
        ipv4_capture_confirmed: true,
        no_bypass_confirmed: true,
        ipv6_blocked_confirmed: true,
    };
    let before = core.snapshot();
    let mut wrong = receipt.clone();
    wrong.scope_id = "0".repeat(64);
    assert_eq!(
        core.mark_vpn_blocked(wrong),
        Err(CoreError::InvalidNetworkPrivacyReceipt)
    );
    let mut wrong = receipt.clone();
    wrong.ipv6_blocked_confirmed = false;
    assert_eq!(
        core.mark_vpn_blocked(wrong),
        Err(CoreError::InvalidNetworkPrivacyReceipt)
    );
    assert_eq!(core.snapshot(), before);
    core.mark_vpn_blocked(receipt).unwrap();
    assert_eq!(
        core.snapshot().network_privacy_enforcement,
        NetworkPrivacyEnforcement::Blocked
    );
    assert_eq!(
        core.snapshot()
            .applied_network_privacy
            .as_ref()
            .unwrap()
            .hydra_scope,
        HydraScope::Off
    );
    core.begin_vpn_stop().unwrap();
    assert_eq!(
        core.snapshot().network_privacy_enforcement,
        NetworkPrivacyEnforcement::Inactive
    );
}

#[test]
fn optional_hydra_cannot_be_silently_enabled_on_plain_socks() {
    let mut core = CoreState::new();
    let mut policy = NetworkPrivacyPolicy::default();
    policy.hydra.enabled = true;
    core.set_network_privacy_policy(policy, 0).unwrap();
    let node = core.import_node("socks5://proxy.example".into()).unwrap();
    let before = core.snapshot();
    assert!(matches!(
        core.begin_vpn(node.id, before.generation),
        Err(CoreError::UnsupportedNetworkPrivacyPolicy)
    ));
    assert_eq!(core.snapshot(), before);
}
