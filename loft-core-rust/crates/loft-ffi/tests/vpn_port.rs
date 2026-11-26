pub mod support;
use loft_ffi::{
    AppCore, ConnectionState, CoreError, Ipv6Policy, VpnBlockedReceipt, VpnFailure,
    VpnReadyReceipt, VpnStoppedReceipt,
};

// Contract inputs only; real Android/Go VPN acceptance is performed separately.
#[test]
fn exported_private_ticket_and_receipts_preserve_frozen_routing() {
    let core = AppCore::new();
    let node = core
        .import_node("socks5://fixture-user:p%3Aa%2Bss@proxy.example".into())
        .unwrap();
    core.set_app_routing(true, vec!["org.example.selected".into()])
        .unwrap();
    let ticket = core
        .begin_vpn(node.id.clone(), core.snapshot().generation)
        .unwrap();
    support::freeze(
        &ticket,
        vec![
            "org.example.selected".into(),
            "org.example.shared_uid".into(),
        ],
    );
    assert_eq!(
        ticket.take_raw_node(),
        Ok("socks5://fixture-user:p%3Aa%2Bss@proxy.example:1080".into())
    );
    assert_eq!(ticket.take_raw_node(), Err(CoreError::TicketExpired));
    core.mark_vpn_ready(VpnReadyReceipt {
        attempt_id: ticket.attempt_id(),
        transport_ready: true,
        authenticated: true,
        tun_ready: true,
        sockets_protected: true,
        applied_package_names: vec![
            "org.example.selected".into(),
            "org.example.shared_uid".into(),
        ],
        ipv6_policy: Ipv6Policy::BlockedInVpn,
        privacy: support::privacy(&ticket),
        ipv4_capture_confirmed: true,
        no_bypass_confirmed: true,
        ipv6_blocked_confirmed: true,
    })
    .unwrap();
    let snapshot = core.snapshot();
    assert_eq!(snapshot.connection_state, ConnectionState::Connected);
    assert_eq!(snapshot.active_node_id, Some(node.id));
    assert_eq!(snapshot.applied_routing.unwrap().package_names.len(), 2);
    assert!(!format!("{:?}", core.snapshot()).contains("p:a+ss"));
    let attempt = core.begin_vpn_stop().unwrap();
    core.confirm_vpn_stopped(VpnStoppedReceipt {
        attempt_id: attempt,
        tun_closed: true,
        resources_released: true,
    })
    .unwrap();
    assert_eq!(
        core.snapshot().connection_state,
        ConnectionState::Disconnected
    );
}

#[test]
fn exported_blocked_receipt_requires_held_original_tun_and_disabled_forwarding() {
    let core = AppCore::new();
    let node = core.import_node("socks5://proxy.example".into()).unwrap();
    let ticket = core.begin_vpn(node.id, core.snapshot().generation).unwrap();
    support::freeze(&ticket, vec![]);
    ticket.take_raw_node().unwrap();
    core.mark_vpn_failed(ticket.attempt_id(), VpnFailure::EngineStartFailed)
        .unwrap();
    let mut blocked = VpnBlockedReceipt {
        attempt_id: ticket.attempt_id(),
        tun_held: false,
        forwarding_disabled: true,
        effective_package_names: vec![],
        ipv6_policy: Ipv6Policy::BlockedInVpn,
        policy_epoch: ticket.network_policy_epoch(),
        scope_id: ticket.network_scope_id().unwrap_or_default(),
        ipv4_capture_confirmed: true,
        no_bypass_confirmed: true,
        ipv6_blocked_confirmed: true,
    };
    assert_eq!(
        core.mark_vpn_blocked(blocked.clone()),
        Err(CoreError::InvalidEngineReceipt)
    );
    blocked.tun_held = true;
    core.mark_vpn_blocked(blocked).unwrap();
    assert_eq!(core.snapshot().connection_state, ConnectionState::Blocked);
}
