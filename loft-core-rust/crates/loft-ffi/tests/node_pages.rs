pub mod support;
use loft_ffi::{AppCore, CoreError};
use std::collections::HashSet;

// Exercises the actual exported owner, not a UI cache of import receipts.
#[test]
fn exported_pages_discover_the_entire_bounded_workset() {
    let core = AppCore::new();
    let imported: Vec<_> = (0..200)
        .map(|index| {
            core.import_node(format!("socks5://ffi-page-{index}.example"))
                .unwrap()
        })
        .collect();
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
    assert_eq!(
        discovered
            .iter()
            .map(|node| &node.id)
            .collect::<HashSet<_>>()
            .len(),
        200
    );
    assert_eq!(core.snapshot(), before);
    assert_eq!(before.nodes.len(), 50);
    assert_eq!(
        core.import_node("socks5://overflow.example".into()),
        Err(CoreError::NodeCapacityReached)
    );
}

// Catches dropping error conversion or treating a stale page as a successful empty result.
#[test]
fn exported_pages_have_typed_generation_and_offset_boundaries() {
    let core = AppCore::new();
    let empty = core.node_page(0, 0).unwrap();
    assert_eq!(empty.node_count, 0);
    assert!(empty.nodes.is_empty());
    assert_eq!(empty.next_offset, None);
    for offset in [1, 50, u32::MAX] {
        assert_eq!(core.node_page(offset, 0), Err(CoreError::InvalidNodePage));
    }
    for index in 0..51 {
        core.import_node(format!("socks5://ffi-boundary-{index}.example"))
            .unwrap();
    }
    let before = core.snapshot();
    for offset in [1, 49, 51, 100, 200, u32::MAX] {
        assert_eq!(
            core.node_page(offset, before.generation),
            Err(CoreError::InvalidNodePage)
        );
    }
    assert_eq!(
        core.node_page(50, before.generation - 1),
        Err(CoreError::StaleGeneration)
    );
    assert_eq!(
        core.node_page(u32::MAX, before.generation + 1),
        Err(CoreError::StaleGeneration)
    );
    assert_eq!(
        core.node_page(50, before.generation).unwrap().nodes.len(),
        1
    );
    assert_eq!(core.snapshot(), before);
}

// Catches mutable aliases, query-driven lifecycle changes and accidentally returning private configuration.
#[test]
fn exported_page_copies_preserve_ticket_and_redacted_business_state() {
    let core = AppCore::new();
    for index in 0..50 {
        core.import_node(format!("socks5://ffi-copy-{index}.example"))
            .unwrap();
    }
    let node = core
        .import_node("socks5://private-user:private-password@private.example#Office".into())
        .unwrap();
    core.stage_server("cloud.example".into()).unwrap();
    core.set_app_routing(true, vec!["org.example.selected".into()])
        .unwrap();
    let ticket = core
        .begin_vpn(node.id.clone(), core.snapshot().generation)
        .unwrap();
    let before = core.snapshot();
    let original = core.node_page(50, before.generation).unwrap();
    assert_eq!(original.nodes[0], node);
    let mut copy = original.clone();
    copy.nodes[0].label = "Local only".into();
    copy.nodes.clear();
    assert_eq!(core.node_page(50, before.generation).unwrap(), original);
    assert_eq!(core.snapshot(), before);
    for secret in ["private-user", "private-password", "socks5://"] {
        assert!(!format!("{original:?}").contains(secret));
    }
    support::freeze(&ticket, vec!["org.example.selected".into()]);
    assert!(ticket.take_raw_node().is_ok());
}
