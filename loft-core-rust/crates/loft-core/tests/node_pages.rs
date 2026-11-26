pub mod support;
use loft_core::{CoreError, CoreState, NodeSummary, VpnStoppedReceipt};
use std::collections::HashSet;

fn import_nodes(core: &mut CoreState, count: usize) -> Vec<NodeSummary> {
    (0..count)
        .map(|index| {
            core.import_node(format!("socks5://page-node-{index}.example#Node%20{index}"))
                .unwrap()
        })
        .collect()
}

// Catches accepted nodes disappearing behind the fixed first snapshot page.
#[test]
fn four_pages_expose_all_two_hundred_nodes_in_original_order() {
    let mut core = CoreState::new();
    let imported = import_nodes(&mut core, 200);
    let before = core.snapshot();
    let mut discovered = Vec::new();
    for (offset, next_offset) in [
        (0, Some(50)),
        (50, Some(100)),
        (100, Some(150)),
        (150, None),
    ] {
        let page = core.node_page(offset, before.generation).unwrap();
        assert_eq!(page.schema_version, 1);
        assert_eq!(page.generation, 200);
        assert_eq!(page.offset, offset);
        assert_eq!(page.node_count, 200);
        assert_eq!(page.nodes.len(), 50);
        assert_eq!(page.next_offset, next_offset);
        discovered.extend(page.nodes);
    }
    assert_eq!(discovered, imported);
    let ids: HashSet<_> = discovered.iter().map(|node| &node.id).collect();
    assert_eq!(ids.len(), 200);
    assert_eq!(core.snapshot(), before);
    assert_eq!(before.nodes.len(), 50);
    assert_eq!(
        core.import_node("socks5://overflow.example".into()),
        Err(CoreError::NodeCapacityReached)
    );
}

// Catches treating an empty workset as an invalid first page or inventing a continuation.
#[test]
fn empty_and_partial_last_pages_have_explicit_terminal_shape() {
    let mut core = CoreState::new();
    let empty = core.node_page(0, 0).unwrap();
    assert_eq!(empty.schema_version, 1);
    assert_eq!(empty.generation, 0);
    assert_eq!(empty.offset, 0);
    assert_eq!(empty.node_count, 0);
    assert!(empty.nodes.is_empty());
    assert_eq!(empty.next_offset, None);

    let imported = import_nodes(&mut core, 51);
    let first = core.node_page(0, 51).unwrap();
    assert_eq!(first.nodes.len(), 50);
    assert_eq!(first.next_offset, Some(50));
    let last = core.node_page(50, 51).unwrap();
    assert_eq!(last.nodes, vec![imported[50].clone()]);
    assert_eq!(last.node_count, 51);
    assert_eq!(last.next_offset, None);
}

// Catches overlapping/empty/out-of-range pages and unchecked integer indexing.
#[test]
fn invalid_offsets_are_typed_errors_without_changing_state() {
    let mut core = CoreState::new();
    for offset in [1, 50, 200, u32::MAX] {
        assert_eq!(core.node_page(offset, 0), Err(CoreError::InvalidNodePage));
    }
    import_nodes(&mut core, 51);
    let before = core.snapshot();
    for offset in [1, 49, 51, 100, 200, u32::MAX] {
        assert_eq!(
            core.node_page(offset, before.generation),
            Err(CoreError::InvalidNodePage)
        );
    }
    assert_eq!(core.snapshot(), before);
    assert!(core.node_page(0, before.generation).is_ok());
    assert!(core.node_page(50, before.generation).is_ok());
}

// Catches mixing page rows from different generations after off-page or profile/draft changes.
#[test]
fn changed_generations_reject_old_pages_before_offset_validation() {
    let mut core = CoreState::new();
    let imported = import_nodes(&mut core, 51);
    let old = core.node_page(50, 51).unwrap();
    core.import_node("socks5://later.example".into()).unwrap();
    assert_eq!(
        core.node_page(50, old.generation),
        Err(CoreError::StaleGeneration)
    );
    assert_eq!(
        core.node_page(u32::MAX, old.generation),
        Err(CoreError::StaleGeneration)
    );

    let generation = core.snapshot().generation;
    core.remove_node(imported[0].id.clone()).unwrap();
    assert_eq!(
        core.node_page(0, generation),
        Err(CoreError::StaleGeneration)
    );
    let generation = core.snapshot().generation;
    core.stage_server("cloud.example".into()).unwrap();
    assert_eq!(
        core.node_page(50, generation),
        Err(CoreError::StaleGeneration)
    );
    let generation = core.snapshot().generation;
    core.set_app_routing(true, vec!["org.example.selected".into()])
        .unwrap();
    assert_eq!(
        core.node_page(50, generation),
        Err(CoreError::StaleGeneration)
    );
    let before = core.snapshot();
    assert_eq!(
        core.node_page(50, before.generation + 1),
        Err(CoreError::StaleGeneration)
    );
    assert_eq!(core.snapshot(), before);
}

// Catches later-page IDs being unusable by the existing target/admission and removal paths.
#[test]
fn later_page_ids_remain_valid_for_selection_and_removal() {
    let mut core = CoreState::new();
    let imported = import_nodes(&mut core, 200);
    let selected = core.node_page(50, 200).unwrap().nodes[0].id.clone();
    let removed = core.node_page(150, 200).unwrap().nodes[49].id.clone();
    assert_eq!(selected, imported[50].id);
    assert_eq!(removed, imported[199].id);
    assert_eq!(
        core.connect(selected.clone()),
        Err(CoreError::DataPlaneUnavailable)
    );
    let ticket = core.begin_vpn(selected.clone(), 200).unwrap();
    assert_eq!(ticket.node_id(), selected);
    assert_eq!(
        core.remove_node(selected.clone()),
        Err(CoreError::NodeInUse)
    );
    core.remove_node(removed.clone()).unwrap();
    assert_eq!(core.node_page(150, 200), Err(CoreError::StaleGeneration));
    let page = core.node_page(150, core.snapshot().generation).unwrap();
    assert_eq!(page.nodes.len(), 49);
    assert_eq!(page.node_count, 199);
    assert_eq!(page.next_offset, None);
    assert!(page.nodes.iter().all(|node| node.id != removed));

    core.begin_vpn_stop().unwrap();
    core.confirm_vpn_stopped(VpnStoppedReceipt {
        attempt_id: ticket.attempt_id(),
        tun_closed: true,
        resources_released: true,
    })
    .unwrap();
    core.remove_node(selected).unwrap();
    assert_eq!(core.snapshot().node_count, 198);
    assert_eq!(
        core.node_page(50, core.snapshot().generation)
            .unwrap()
            .nodes[0]
            .id,
        imported[51].id
    );
}

// Catches page queries cancelling an admitted ticket, publishing state or mutating caller-owned data.
#[test]
fn page_queries_are_owned_copies_without_business_side_effects() {
    let mut core = CoreState::new();
    let imported = import_nodes(&mut core, 51);
    core.stage_server("cloud.example".into()).unwrap();
    core.set_app_routing(true, vec!["org.example.selected".into()])
        .unwrap();
    let ticket = core
        .begin_vpn(imported[50].id.clone(), core.snapshot().generation)
        .unwrap();
    let before = core.snapshot();
    let original = core.node_page(50, before.generation).unwrap();
    let mut local = original.clone();
    local.nodes[0].label = "Local only".into();
    local.nodes.clear();
    assert_eq!(core.node_page(50, before.generation).unwrap(), original);
    assert_eq!(core.snapshot(), before);
    support::freeze(&ticket, vec!["org.example.selected".into()]);
    assert!(ticket.take_raw_node().is_ok());
}

// Catches a separate page formatter leaking stored credentials or raw configuration text.
#[test]
fn later_page_metadata_omits_credentials_and_raw_links() {
    let mut core = CoreState::new();
    import_nodes(&mut core, 50);
    core.import_node("socks5://page-user:page-private-password@secret.example#Private".into())
        .unwrap();
    let page = core.node_page(50, core.snapshot().generation).unwrap();
    assert_eq!(page.nodes.len(), 1);
    assert!(
        page.nodes
            .iter()
            .all(|node| node.credential_material_present)
    );
    let metadata = format!("{page:?}");
    for secret in ["page-user", "page-private-password", "socks5://"] {
        assert!(!metadata.contains(secret));
    }
}
