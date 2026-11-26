use loft_core::{ConnectionState, CoreError, CoreState, ProtocolKind};

#[test]
fn anonymous_startup_has_no_claimed_server_or_connection() {
    let core = CoreState::new();
    let snapshot = core.snapshot();
    assert_eq!(snapshot.schema_version, 2);
    assert_eq!(snapshot.node_count, 0);
    assert_eq!(snapshot.generation, 0);
    assert_eq!(snapshot.server_address, None);
    assert!(!snapshot.server_verified);
    assert!(!snapshot.routing_enabled);
    assert!(snapshot.nodes.is_empty());
    assert!(snapshot.selected_apps.is_empty());
    assert_eq!(snapshot.connection_state, ConnectionState::Disconnected);
}

// Catches raw credentials in exported metadata and import not committing a real node.
#[test]
fn imports_socks_credentials_as_redacted_session_metadata() {
    let mut core = CoreState::new();
    let node = core
        .import_node("socks5://user%40company:p%3Aa%2Bss@Example.COM:1080#Work%20proxy".into())
        .unwrap();
    assert_eq!(node.protocol, ProtocolKind::Socks5);
    assert_eq!(node.endpoint, "example.com:1080");
    assert_eq!(node.label, "Work proxy");
    assert!(node.credential_material_present);
    assert_eq!((node.udp_min, node.udp_max), (0, 65507));
    let metadata = format!("{:?}", core.snapshot());
    for secret in ["user@company", "p:a+ss", "socks5://", "%3A"] {
        assert!(!metadata.contains(secret));
    }
    assert_eq!(core.snapshot().node_count, 1);
    assert_eq!(core.snapshot().generation, 1);
}

#[test]
fn no_auth_socks_and_ipv6_have_explicit_distinct_metadata() {
    let mut core = CoreState::new();
    let node = core
        .import_node("socks://[2001:db8::1]#IPv6".into())
        .unwrap();
    assert_eq!(node.endpoint, "[2001:db8::1]:1080");
    assert!(!node.credential_material_present);
}

// Catches comparing raw URI text or label instead of normalized configuration.
#[test]
fn duplicate_alias_and_renamed_node_does_not_mutate_state() {
    let mut core = CoreState::new();
    core.import_node("socks5://proxy.example#One".into())
        .unwrap();
    let before = core.snapshot();
    assert_eq!(
        core.import_node("socks://PROXY.EXAMPLE:1080#Two".into()),
        Err(CoreError::DuplicateNode)
    );
    assert_eq!(core.snapshot(), before);
    core.import_node("socks5://u:p@proxy.example:1080#Other%20credentials".into())
        .unwrap();
    assert_eq!(core.snapshot().node_count, 2);
}

#[test]
fn remove_node_changes_only_its_owned_session_state() {
    let mut core = CoreState::new();
    let node = core.import_node("socks5://proxy.example".into()).unwrap();
    core.set_app_routing(true, vec!["net.aptist.loft".into()])
        .unwrap();
    core.stage_server("cloud.example".into()).unwrap();
    core.remove_node(node.id.clone()).unwrap();
    let snapshot = core.snapshot();
    assert_eq!(snapshot.node_count, 0);
    assert_eq!(
        snapshot.server_address.as_deref(),
        Some("https://cloud.example")
    );
    assert_eq!(snapshot.selected_apps, vec!["net.aptist.loft"]);
    assert_eq!(core.remove_node(node.id), Err(CoreError::NodeNotFound));
    assert_eq!(core.snapshot(), snapshot);
}

// Catches allocating past either the record count or page quota.
#[test]
fn retains_two_hundred_nodes_but_snapshots_only_fifty_rows() {
    let mut core = CoreState::new();
    for number in 0..200 {
        core.import_node(format!("socks5://proxy-{number}.example"))
            .unwrap();
    }
    let before = core.snapshot();
    assert_eq!(before.node_count, 200);
    assert_eq!(before.nodes.len(), 50);
    assert_eq!(
        core.import_node("socks5://overflow.example".into()),
        Err(CoreError::NodeCapacityReached)
    );
    assert_eq!(core.snapshot(), before);
    core.remove_node(before.nodes[0].id.clone()).unwrap();
    core.import_node("socks5://after-removal.example".into())
        .unwrap();
    assert_eq!(core.snapshot().node_count, 200);
}

// Catches routing empty selection broadening the effective allowlist or partial validation commits.
#[test]
fn rejects_empty_enabled_routing_atomically() {
    let mut core = CoreState::new();
    core.set_app_routing(true, vec!["net.aptist.loft".into()])
        .unwrap();
    let before = core.snapshot();
    assert_eq!(
        core.set_app_routing(true, Vec::new()),
        Err(CoreError::EmptyRoutingSelection)
    );
    assert_eq!(
        core.set_app_routing(true, vec!["net.aptist.loft".into(), "bad/package".into()]),
        Err(CoreError::InvalidPackageName)
    );
    assert_eq!(core.snapshot(), before);
}

#[test]
fn routing_is_a_normalized_draft_and_disabled_preferences_are_retained() {
    let mut core = CoreState::new();
    core.set_app_routing(
        true,
        vec![
            "org.example.beta".into(),
            "net.aptist.loft".into(),
            "net.aptist.loft".into(),
        ],
    )
    .unwrap();
    let staged = core.snapshot();
    assert!(staged.routing_enabled);
    assert_eq!(
        staged.selected_apps,
        vec!["net.aptist.loft", "org.example.beta"]
    );
    core.set_app_routing(
        true,
        vec!["net.aptist.loft".into(), "org.example.beta".into()],
    )
    .unwrap();
    assert_eq!(core.snapshot(), staged);
    core.set_app_routing(false, staged.selected_apps).unwrap();
    assert!(!core.snapshot().routing_enabled);
    assert_eq!(core.snapshot().selected_apps.len(), 2);
    assert_eq!(
        core.snapshot().connection_state,
        ConnectionState::Disconnected
    );
}

#[test]
fn routing_input_has_count_and_aggregate_byte_admission() {
    let mut core = CoreState::new();
    assert_eq!(
        core.set_app_routing(
            true,
            (0..101).map(|i| format!("org.example.app{i}")).collect()
        ),
        Err(CoreError::RoutingSelectionTooLarge)
    );
    let oversized: Vec<String> = (0..100)
        .map(|i| format!("org.{}.app{i}", "a".repeat(100)))
        .collect();
    assert_eq!(
        core.set_app_routing(true, oversized),
        Err(CoreError::RoutingSelectionTooLarge)
    );
    assert!(!core.snapshot().routing_enabled);
}

// Catches URL normalization being reported as verification or stale profile generation retained.
#[test]
fn server_candidate_replacement_advances_generation_without_verifying() {
    let mut core = CoreState::new();
    assert_eq!(
        core.stage_server("Cloud.EXAMPLE".into()),
        Ok("https://cloud.example".into())
    );
    let first = core.snapshot();
    assert_eq!(first.generation, 1);
    assert!(!first.server_verified);
    core.stage_server("https://cloud.example:443/".into())
        .unwrap();
    assert_eq!(core.snapshot(), first);
    core.stage_server("next.example:8443".into()).unwrap();
    assert_eq!(core.snapshot().generation, 2);
    assert_eq!(
        core.stage_server("https://user:secret@evil.example".into()),
        Err(CoreError::InvalidServerAddress)
    );
    assert_eq!(core.snapshot().generation, 2);
    assert!(!core.snapshot().server_verified);
    core.reset_server().unwrap();
    assert_eq!(core.snapshot().generation, 3);
    assert_eq!(core.snapshot().server_address, None);
    core.reset_server().unwrap();
    assert_eq!(core.snapshot().generation, 3);
}

// Catches a successful connection inferred from importing a node or repeated stop erasing preferences.
#[test]
fn unavailable_data_plane_never_reports_connected_and_stop_is_idempotent() {
    let mut core = CoreState::new();
    assert_eq!(core.connect("missing".into()), Err(CoreError::NodeNotFound));
    let node = core.import_node("socks5://proxy.example".into()).unwrap();
    core.set_app_routing(true, vec!["net.aptist.loft".into()])
        .unwrap();
    let before = core.snapshot();
    assert_eq!(core.connect(node.id), Err(CoreError::DataPlaneUnavailable));
    assert_eq!(core.snapshot(), before);
    core.stop().unwrap();
    core.stop().unwrap();
    assert_eq!(core.snapshot(), before);
    assert_eq!(CoreState::new().snapshot().node_count, 0);
}

#[test]
fn legacy_numeric_node_addresses_cannot_change_identity_in_an_adapter() {
    let mut core = CoreState::new();
    assert_eq!(
        core.import_node("socks5://0x7f.0.0.1:1080".into()),
        Err(CoreError::InvalidEndpoint)
    );
    assert_eq!(core.snapshot().node_count, 0);
}
