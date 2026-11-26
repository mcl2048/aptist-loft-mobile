use loft_ffi::{AppCore, ConnectionState, CoreError, ProtocolKind};
use std::collections::HashSet;

// Catches incorrect exported type conversion or successful receipts without owned core state.
#[test]
fn exported_commands_produce_owned_redacted_snapshots() {
    let core = AppCore::new();
    let node = core
        .import_node("socks5://u:secret@proxy.example#Office".into())
        .unwrap();
    assert_eq!(node.endpoint, "proxy.example:1080");
    assert_eq!(node.protocol, ProtocolKind::Socks5);
    assert_eq!((node.udp_min, node.udp_max), (0, 65507));
    core.set_app_routing(true, vec!["net.aptist.loft".into()])
        .unwrap();
    assert_eq!(
        core.stage_server("Cloud.EXAMPLE".into()),
        Ok("https://cloud.example".into())
    );
    let snapshot = core.snapshot();
    assert_eq!(snapshot.schema_version, 2);
    assert_eq!(snapshot.generation, 3);
    assert_eq!(snapshot.node_count, 1);
    assert!(!snapshot.server_verified);
    assert!(snapshot.routing_enabled);
    assert_eq!(snapshot.connection_state, ConnectionState::Disconnected);
    assert_eq!(
        core.connect(node.id.clone()),
        Err(CoreError::DataPlaneUnavailable)
    );
    assert_eq!(core.snapshot(), snapshot);
    core.stop().unwrap();
    core.remove_node(node.id).unwrap();
    core.reset_server().unwrap();
    assert_eq!(core.snapshot().node_count, 0);
    assert_eq!(core.snapshot().server_address, None);
}

// Catches FFI retaining aliases to mutable snapshot records instead of giving the caller a copy.
#[test]
fn modifying_an_exported_snapshot_cannot_mutate_the_core() {
    let core = AppCore::new();
    core.import_node("socks5://proxy.example#Office".into())
        .unwrap();
    core.set_app_routing(true, vec!["net.aptist.loft".into()])
        .unwrap();
    let original = core.snapshot();
    let mut local = core.snapshot();
    local.nodes[0].label = "Changed locally".into();
    local.selected_apps.clear();
    assert_eq!(core.snapshot(), original);
}

// Uses real concurrent callers; catches lost updates or reused IDs at the single-owner FFI boundary.
#[test]
fn concurrent_imports_commit_each_node_once_with_finite_state() {
    let core = AppCore::new();
    let workers: Vec<_> = (0..4)
        .map(|worker| {
            let core = core.clone();
            std::thread::spawn(move || {
                (0..50)
                    .map(|index| {
                        core.import_node(format!("socks5://worker-{worker}-node-{index}.example"))
                            .unwrap()
                            .id
                    })
                    .collect::<Vec<_>>()
            })
        })
        .collect();
    let ids: HashSet<_> = workers
        .into_iter()
        .flat_map(|worker| worker.join().unwrap())
        .collect();
    let snapshot = core.snapshot();
    assert_eq!(ids.len(), 200);
    assert_eq!(snapshot.node_count, 200);
    assert_eq!(snapshot.nodes.len(), 50);
    assert_eq!(snapshot.generation, 200);
    assert_eq!(
        core.import_node("socks5://overflow.example".into()),
        Err(CoreError::NodeCapacityReached)
    );
}

#[test]
fn exported_errors_remain_typed_and_failed_routes_are_atomic() {
    let core = AppCore::new();
    assert_eq!(
        core.stage_server("https://u:secret@evil.example".into()),
        Err(CoreError::InvalidServerAddress)
    );
    assert_eq!(
        core.import_node("trojan://secret@evil.example".into()),
        Err(CoreError::UnsupportedProtocol)
    );
    core.set_app_routing(true, vec!["net.aptist.loft".into()])
        .unwrap();
    let before = core.snapshot();
    assert_eq!(
        core.set_app_routing(true, vec![]),
        Err(CoreError::EmptyRoutingSelection)
    );
    assert_eq!(core.snapshot(), before);
}
