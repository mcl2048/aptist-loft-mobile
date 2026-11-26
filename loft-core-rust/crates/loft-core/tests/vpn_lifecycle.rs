pub mod support;
use loft_core::{
    ConnectionState, CoreError, CoreState, Ipv6Policy, VpnBlockedReceipt, VpnFailure,
    VpnReadyReceipt, VpnStoppedReceipt,
};

fn node(core: &mut CoreState) -> String {
    core.import_node("socks5://fixture-user:p%3Aa%2Bss@proxy.example#Office".into())
        .unwrap()
        .id
}

fn ready(ticket: &loft_core::VpnStartTicket, packages: Vec<String>) -> VpnReadyReceipt {
    VpnReadyReceipt {
        attempt_id: ticket.attempt_id(),
        transport_ready: true,
        authenticated: true,
        tun_ready: true,
        sockets_protected: true,
        applied_package_names: packages,
        ipv6_policy: Ipv6Policy::BlockedInVpn,
        privacy: support::privacy(ticket),
        ipv4_capture_confirmed: true,
        no_bypass_confirmed: true,
        ipv6_blocked_confirmed: true,
    }
}

fn stopped(attempt_id: u64) -> VpnStoppedReceipt {
    VpnStoppedReceipt {
        attempt_id,
        tun_closed: true,
        resources_released: true,
    }
}

// Reducer/port tests only: these inputs are not evidence of a real TUN or live protocol connection.
#[test]
fn private_ticket_is_single_use_and_never_appears_in_snapshots() {
    let mut core = CoreState::new();
    let id = node(&mut core);
    let ticket = core
        .begin_vpn(id.clone(), core.snapshot().generation)
        .unwrap();
    assert_eq!(ticket.attempt_id(), 1);
    assert_eq!(ticket.node_id(), id);
    assert_eq!(
        core.snapshot().connection_state,
        ConnectionState::Connecting
    );
    assert_eq!(
        ticket.take_raw_node(),
        Err(CoreError::InvalidRoutingReceipt)
    );
    support::freeze(&ticket, vec![]);
    assert_eq!(
        ticket.take_raw_node(),
        Ok("socks5://fixture-user:p%3Aa%2Bss@proxy.example:1080".into())
    );
    assert_eq!(ticket.take_raw_node(), Err(CoreError::TicketExpired));
    let metadata = format!("{:?}", core.snapshot());
    assert!(!metadata.contains("p:a+ss"));
    assert!(!metadata.contains("socks5://"));
    core.mark_vpn_ready(ready(&ticket, vec![])).unwrap();
    assert_eq!(core.snapshot().connection_state, ConnectionState::Connected);
    assert_eq!(core.snapshot().active_node_id, Some(id));
    assert!(core.snapshot().applied_routing.is_some());
}

#[test]
fn ready_requires_real_engine_tun_auth_and_protection_facts() {
    for failed in 0..4 {
        let mut core = CoreState::new();
        let id = node(&mut core);
        let ticket = core.begin_vpn(id, core.snapshot().generation).unwrap();
        support::freeze(&ticket, vec![]);
        ticket.take_raw_node().unwrap();
        let before = core.snapshot();
        let mut receipt = ready(&ticket, vec![]);
        match failed {
            0 => receipt.transport_ready = false,
            1 => receipt.authenticated = false,
            2 => receipt.tun_ready = false,
            _ => receipt.sockets_protected = false,
        }
        assert_eq!(
            core.mark_vpn_ready(receipt),
            Err(CoreError::InvalidEngineReceipt)
        );
        assert_eq!(core.snapshot(), before);
    }
}

#[test]
fn frozen_effective_routing_is_distinct_from_later_saved_drafts() {
    let mut core = CoreState::new();
    let id = node(&mut core);
    core.set_app_routing(true, vec!["org.example.selected".into()])
        .unwrap();
    let ticket = core.begin_vpn(id, core.snapshot().generation).unwrap();
    let effective = vec![
        "org.example.selected".into(),
        "org.example.shared_uid".into(),
    ];
    support::freeze(&ticket, effective.clone());
    ticket.take_raw_node().unwrap();
    core.set_app_routing(true, vec!["org.example.next".into()])
        .unwrap();
    let before = core.snapshot();
    assert_eq!(
        core.mark_vpn_ready(ready(&ticket, vec!["org.example.next".into()])),
        Err(CoreError::InvalidRoutingReceipt)
    );
    assert_eq!(core.snapshot(), before);
    core.mark_vpn_ready(ready(&ticket, effective.clone()))
        .unwrap();
    let snapshot = core.snapshot();
    assert_eq!(snapshot.selected_apps, vec!["org.example.next"]);
    assert_eq!(snapshot.applied_routing.unwrap().package_names, effective);
    assert!(snapshot.routing_enabled);
}

#[test]
fn empty_effective_selected_routing_is_rejected_before_secret_delivery() {
    let mut core = CoreState::new();
    let id = node(&mut core);
    core.set_app_routing(true, vec!["org.example.selected".into()])
        .unwrap();
    let ticket = core.begin_vpn(id, core.snapshot().generation).unwrap();
    assert_eq!(
        ticket.freeze_effective_packages(vec![]),
        Err(CoreError::EmptyRoutingSelection)
    );
    assert_eq!(
        ticket.take_raw_node(),
        Err(CoreError::InvalidRoutingReceipt)
    );
    assert_eq!(
        core.snapshot().connection_state,
        ConnectionState::Connecting
    );
}

#[test]
fn server_and_import_changes_do_not_replace_the_frozen_attempt() {
    let mut core = CoreState::new();
    let id = node(&mut core);
    let ticket = core
        .begin_vpn(id.clone(), core.snapshot().generation)
        .unwrap();
    support::freeze(&ticket, vec![]);
    ticket.take_raw_node().unwrap();
    core.stage_server("cloud.example".into()).unwrap();
    core.import_node("socks5://another.example".into()).unwrap();
    core.mark_vpn_ready(ready(&ticket, vec![])).unwrap();
    assert_eq!(core.snapshot().connection_attempt_id, ticket.attempt_id());
    assert_eq!(core.snapshot().active_node_id, Some(id));
    assert_eq!(core.snapshot().connection_state, ConnectionState::Connected);
}

#[test]
fn stop_invalidates_ready_and_waits_for_original_tun_and_resource_closure() {
    let mut core = CoreState::new();
    let id = node(&mut core);
    let ticket = core.begin_vpn(id, core.snapshot().generation).unwrap();
    support::freeze(&ticket, vec![]);
    let stop_id = core.begin_vpn_stop().unwrap();
    assert_eq!(ticket.take_raw_node(), Err(CoreError::TicketExpired));
    assert_eq!(
        core.mark_vpn_ready(ready(&ticket, vec![])),
        Err(CoreError::StaleGeneration)
    );
    assert_eq!(core.snapshot().connection_state, ConnectionState::Stopping);
    let mut receipt = stopped(stop_id);
    receipt.tun_closed = false;
    assert_eq!(
        core.confirm_vpn_stopped(receipt),
        Err(CoreError::EngineStopIncomplete)
    );
    assert_eq!(core.snapshot().connection_state, ConnectionState::Stopping);
    let mut receipt = stopped(stop_id);
    receipt.resources_released = false;
    assert_eq!(
        core.confirm_vpn_stopped(receipt),
        Err(CoreError::EngineStopIncomplete)
    );
    core.confirm_vpn_stopped(stopped(stop_id)).unwrap();
    core.confirm_vpn_stopped(stopped(stop_id)).unwrap();
    assert_eq!(
        core.snapshot().connection_state,
        ConnectionState::Disconnected
    );
    assert_eq!(core.snapshot().node_count, 1);
    assert_eq!(core.snapshot().active_node_id, None);
    assert_eq!(core.snapshot().applied_routing, None);
}

#[test]
fn failure_blocks_only_after_actual_held_tun_and_disabled_forwarding_receipt() {
    let mut core = CoreState::new();
    let id = node(&mut core);
    core.set_app_routing(true, vec!["org.example.selected".into()])
        .unwrap();
    let ticket = core
        .begin_vpn(id.clone(), core.snapshot().generation)
        .unwrap();
    support::freeze(&ticket, vec!["org.example.selected".into()]);
    ticket.take_raw_node().unwrap();
    core.mark_vpn_failed(ticket.attempt_id(), VpnFailure::EngineStartFailed)
        .unwrap();
    assert_eq!(core.snapshot().connection_state, ConnectionState::Stopping);
    let mut blocked = VpnBlockedReceipt {
        attempt_id: ticket.attempt_id(),
        tun_held: true,
        forwarding_disabled: false,
        effective_package_names: vec!["org.example.selected".into()],
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
    blocked.forwarding_disabled = true;
    core.mark_vpn_blocked(blocked).unwrap();
    assert_eq!(core.snapshot().connection_state, ConnectionState::Blocked);
    assert_eq!(core.snapshot().active_node_id, Some(id));
    assert!(core.snapshot().applied_routing.is_some());
    assert_eq!(
        core.snapshot().vpn_failure,
        Some(VpnFailure::EngineStartFailed)
    );
    let stop_id = core.begin_vpn_stop().unwrap();
    core.confirm_vpn_stopped(stopped(stop_id)).unwrap();
    assert_eq!(
        core.snapshot().connection_state,
        ConnectionState::Disconnected
    );
}

#[test]
fn stale_user_grant_and_old_callbacks_cannot_start_or_overwrite_a_new_attempt() {
    let mut core = CoreState::new();
    let id = node(&mut core);
    let grant_generation = core.snapshot().generation;
    core.stage_server("cloud.example".into()).unwrap();
    assert!(matches!(
        core.begin_vpn(id.clone(), grant_generation),
        Err(CoreError::StaleGeneration)
    ));
    let first = core
        .begin_vpn(id.clone(), core.snapshot().generation)
        .unwrap();
    let stop_id = core.begin_vpn_stop().unwrap();
    core.confirm_vpn_stopped(stopped(stop_id)).unwrap();
    let second = core.begin_vpn(id, core.snapshot().generation).unwrap();
    assert_eq!(second.attempt_id(), first.attempt_id() + 1);
    assert_eq!(
        core.mark_vpn_ready(ready(&first, vec![])),
        Err(CoreError::StaleGeneration)
    );
    assert_eq!(
        core.mark_vpn_failed(first.attempt_id(), VpnFailure::EngineStartFailed),
        Err(CoreError::StaleGeneration)
    );
    assert_eq!(
        core.snapshot().connection_state,
        ConnectionState::Connecting
    );
}

#[test]
fn pending_or_active_node_cannot_be_removed_or_started_twice() {
    let mut core = CoreState::new();
    let id = node(&mut core);
    let ticket = core
        .begin_vpn(id.clone(), core.snapshot().generation)
        .unwrap();
    assert_eq!(core.remove_node(id.clone()), Err(CoreError::NodeInUse));
    assert!(matches!(
        core.begin_vpn(id.clone(), core.snapshot().generation),
        Err(CoreError::ConnectionBusy)
    ));
    support::freeze(&ticket, vec![]);
    ticket.take_raw_node().unwrap();
    core.mark_vpn_ready(ready(&ticket, vec![])).unwrap();
    assert_eq!(core.remove_node(id), Err(CoreError::NodeInUse));
}

#[test]
fn revocation_reason_can_follow_priority_cancellation_without_reopening_traffic() {
    let mut core = CoreState::new();
    let id = node(&mut core);
    let ticket = core.begin_vpn(id, core.snapshot().generation).unwrap();
    support::freeze(&ticket, vec![]);
    ticket.take_raw_node().unwrap();
    core.mark_vpn_ready(ready(&ticket, vec![])).unwrap();
    let attempt = core.begin_vpn_stop().unwrap();
    assert_eq!(core.mark_vpn_failed(attempt, VpnFailure::Revoked), Ok(()));
    assert_eq!(core.snapshot().connection_state, ConnectionState::Stopping);
    assert_eq!(core.snapshot().vpn_failure, Some(VpnFailure::Revoked));
    assert_eq!(
        core.mark_vpn_failed(attempt, VpnFailure::EngineStartFailed),
        Err(CoreError::StaleGeneration)
    );
    assert_eq!(core.snapshot().vpn_failure, Some(VpnFailure::Revoked));
    assert_eq!(
        core.mark_vpn_ready(ready(&ticket, vec![])),
        Err(CoreError::StaleGeneration)
    );
    core.confirm_vpn_stopped(stopped(attempt)).unwrap();
    assert_eq!(
        core.snapshot().connection_state,
        ConnectionState::Disconnected
    );
    assert_eq!(core.snapshot().vpn_failure, Some(VpnFailure::Revoked));
}
