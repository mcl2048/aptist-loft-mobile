use loft_ffi::{AppCore, ConnectionState, CoreError, LeakProtectionMode};

#[test]
fn reopens_configuration_and_preserves_node_ids_without_restoring_vpn_ownership() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.db");
    let path = path.to_str().unwrap();
    let key = vec![21; 32];
    let core = AppCore::open_persistent(path.into(), key.clone(), true).unwrap();
    let removed = core.import_node("socks5://removed.example".into()).unwrap();
    let saved = core
        .import_node("socks5://local-user:fixture-only@proxy.example#Saved%20node".into())
        .unwrap();
    core.remove_node(removed.id.clone()).unwrap();
    core.stage_server("https://example.com".into()).unwrap();
    core.set_app_routing(true, vec!["net.example.browser".into()])
        .unwrap();
    let mut policy = core.snapshot().network_privacy_policy;
    policy.webrtc_policy = LeakProtectionMode::Block;
    core.set_network_privacy_policy(policy.clone(), core.snapshot().generation)
        .unwrap();
    let before = core.snapshot();
    core.begin_vpn(saved.id.clone(), before.generation).unwrap();
    drop(core);

    let reopened = AppCore::open_persistent(path.into(), key, false).unwrap();
    let actual = reopened.snapshot();
    assert_eq!(actual.nodes, vec![saved.clone()]);
    assert_eq!(actual.server_address, before.server_address);
    assert_eq!(actual.selected_apps, before.selected_apps);
    assert!(actual.routing_enabled);
    assert_eq!(actual.network_privacy_policy, policy);
    assert_eq!(
        actual.network_privacy_policy_epoch,
        before.network_privacy_policy_epoch
    );
    assert_eq!(actual.generation, before.generation);
    assert_eq!(actual.connection_state, ConnectionState::Disconnected);
    assert_eq!(actual.connection_attempt_id, 0);
    assert!(actual.active_node_id.is_none());
    assert!(actual.applied_network_privacy.is_none());
    let imported = reopened
        .import_node("socks5://later.example".into())
        .unwrap();
    assert!(imported.id > saved.id);
}

#[test]
fn a_wrong_key_and_missing_active_database_are_recovery_failures() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.db");
    let path = path.to_str().unwrap();
    let key = vec![37; 32];
    let core = AppCore::open_persistent(path.into(), key.clone(), true).unwrap();
    core.import_node("socks5://private-user:fixture-key@proxy.example".into())
        .unwrap();
    drop(core);
    let saved = std::fs::read(path).unwrap();
    assert!(!saved.starts_with(b"SQLite format 3"));
    assert!(
        !saved
            .windows(b"fixture-key".len())
            .any(|bytes| bytes == b"fixture-key")
    );
    assert!(matches!(
        AppCore::open_persistent(path.into(), vec![38; 32], true),
        Err(CoreError::StorageRecoveryRequired)
    ));
    assert_eq!(std::fs::read(path).unwrap(), saved);
    std::fs::remove_file(path).unwrap();
    assert!(matches!(
        AppCore::open_persistent(path.into(), key, false),
        Err(CoreError::StorageRecoveryRequired)
    ));
    assert!(!std::path::Path::new(path).exists());
}

#[path = "../../loft-core/tests/support/node_fixtures.rs"]
mod node_fixtures;
#[allow(dead_code)]
mod support;

#[test]
fn all_protocol_material_and_options_survive_reopen() {
    use node_fixtures::{pro_uri, x_uri};
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.db");
    let path = path.to_str().unwrap();
    let key = vec![63; 32];
    let core = AppCore::open_persistent(path.into(), key.clone(), true).unwrap();
    let socks_raw = "socks5://local%3Auser:fixture%3Ap%2Bss@[2001:db8::2]:2022#SOCKS%20label";
    let x_raw = x_uri().replace(
        "scenario=bulk&rate=100#X",
        "scenario=lossy&rate=321#X%20label",
    );
    let pro_raw = pro_uri()
        .replace("path=%2Fhyraken.pro%2FTunnel", "path=%2Ffixture%2FRoute")
        .replace("engine=ghostx&suite=auto&congestion=beast&connections=1&traffic_profile=auto", "engine=naive&suite=chacha20-poly1305&congestion=bbr&connections=7&traffic_profile=gaming")
        .replace("#Pro", "#Pro%20label");
    let nodes = [
        core.import_node(socks_raw.into()).unwrap(),
        core.import_node(x_raw.clone()).unwrap(),
        core.import_node(pro_raw.clone()).unwrap(),
    ];
    let expected = [
        ticket_digest(&core, &nodes[0].id, socks_raw),
        ticket_digest(&core, &nodes[1].id, &x_raw),
        ticket_digest(&core, &nodes[2].id, &pro_raw),
    ];
    drop(core);
    let restored = AppCore::open_persistent(path.into(), key, false).unwrap();
    assert_eq!(restored.snapshot().nodes, nodes);
    assert_eq!(
        restored
            .snapshot()
            .nodes
            .iter()
            .map(|node| node.label.as_str())
            .collect::<Vec<_>>(),
        ["SOCKS label", "X label", "Pro label"]
    );
    assert_eq!(
        ticket_digest(&restored, &nodes[0].id, socks_raw),
        expected[0]
    );
    assert_eq!(ticket_digest(&restored, &nodes[1].id, &x_raw), expected[1]);
    assert_eq!(
        ticket_digest(&restored, &nodes[2].id, &pro_raw),
        expected[2]
    );
}

fn ticket_digest(core: &AppCore, node_id: &str, expected_uri: &str) -> [u8; 32] {
    use loft_ffi::VpnStoppedReceipt;
    use sha2::{Digest, Sha256};
    use zeroize::Zeroizing;

    let ticket = core
        .begin_vpn(node_id.into(), core.snapshot().generation)
        .unwrap();
    support::freeze(&ticket, vec![]);
    let raw = Zeroizing::new(ticket.take_raw_node().unwrap());
    let actual: [u8; 32] = Sha256::digest(raw.as_bytes()).into();
    let expected: [u8; 32] =
        Sha256::digest(expected_uri.split_once('#').unwrap().0.as_bytes()).into();
    assert!(
        actual == expected,
        "engine ticket material differs from the expected normalized fixture"
    );
    let attempt_id = core.begin_vpn_stop().unwrap();
    core.confirm_vpn_stopped(VpnStoppedReceipt {
        attempt_id,
        tun_closed: true,
        resources_released: true,
    })
    .unwrap();
    actual
}

#[test]
fn an_expired_previously_saved_node_can_be_removed_after_restart() {
    use base64::{Engine, engine::general_purpose::STANDARD};
    use loft_core::{LocalConfigEdit, LocalConfigStore};
    use node_fixtures::{encoded_material, percent_encode};
    use rcgen::{KeyPair, PublicKeyData, date_time_ymd};
    use sha2::{Digest, Sha256};

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.db");
    let key = [22; 32];
    let mut store = loft_storage::SqlCipherStore::open(&path, &key, true).unwrap();
    let mut config = node_fixtures::parameters(vec!["expired.example".into()]);
    config.not_before = date_time_ymd(2000, 1, 1);
    config.not_after = date_time_ymd(2001, 1, 1);
    let cert_key = KeyPair::generate().unwrap();
    let pem = config.self_signed(&cert_key).unwrap().pem();
    let pin = STANDARD.encode(Sha256::digest(cert_key.subject_public_key_info()));
    let uri = format!(
        "hyraken-pro://11111111111111111111111111111111@expired.example:10994?sni=expired.example&pin={}&certificate={}",
        percent_encode(&pin),
        encoded_material(&pem)
    );
    // Populate an authenticated historical row to exercise the real reopen path without changing the clock.
    store
        .commit(1, LocalConfigEdit::ImportNode { id: 1, uri: &uri })
        .unwrap();
    drop(store);

    let path = path.to_str().unwrap();
    let restored = AppCore::open_persistent(path.into(), key.to_vec(), false).unwrap();
    assert_eq!(
        restored.import_node(uri),
        Err(CoreError::InvalidCertificate)
    );
    let unrelated = restored
        .import_node("socks5://other.example".into())
        .unwrap();
    let snapshot = restored.snapshot();
    assert_eq!(snapshot.node_count, 2);
    let expired = &snapshot.nodes[0].id;
    assert!(matches!(
        restored.begin_vpn(expired.clone(), snapshot.generation),
        Err(CoreError::InvalidCertificate)
    ));
    restored.remove_node(expired.clone()).unwrap();
    let digest = restored.snapshot();
    assert_eq!(digest.nodes, vec![unrelated]);
    drop(restored);
    assert_eq!(
        AppCore::open_persistent(path.into(), key.to_vec(), false)
            .unwrap()
            .snapshot(),
        digest
    );
}

#[test]
fn vault_records_and_archival_survive_sqlcipher_reopen() {
    use loft_ffi::{VaultDraft, VaultKind};
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("device-vault.db");
    let path_text = path.to_str().unwrap().to_owned();
    let secret = b"synthetic credential stored only in SQLCipher";
    let core = AppCore::open_persistent(path_text.clone(), vec![51; 32], true).unwrap();
    let entry = core
        .vault_save(VaultDraft {
            id: None,
            kind: VaultKind::Password,
            label: "Fixture".into(),
            account: "".into(),
            issuer: "".into(),
            secret: Some(secret.to_vec()),
            algorithm: None,
            digits: None,
            period: None,
        })
        .unwrap();
    core.vault_archive(entry.id.clone(), true).unwrap();
    drop(core);
    assert!(
        !std::fs::read(path)
            .unwrap()
            .windows(secret.len())
            .any(|bytes| bytes == secret)
    );
    let core = AppCore::open_persistent(path_text, vec![51; 32], false).unwrap();
    assert_eq!(
        core.vault_list(true, 0, None).unwrap().entries[0].id,
        entry.id
    );
    core.vault_archive(entry.id.clone(), false).unwrap();
    assert_eq!(core.vault_reveal(entry.id, 0).unwrap().value, secret);
}

#[test]
fn durable_identity_restores_from_sqlcipher_and_logout_stays_local_without_network() {
    use loft_ffi::HubAction;

    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("durable-account.db");
    let path_text = path.to_str().unwrap().to_owned();
    let core = AppCore::open_persistent(path_text.clone(), vec![91; 32], true).unwrap();
    core.stage_server("hub.example".into()).unwrap();
    let discovery = core.hub_begin(HubAction::Discover, None, false).unwrap();
    let media = Some("application/json".to_string());
    core.hub_finish(discovery.request_id, 200, media.clone(), br#"{"version":1,"product":"loft","authMode":"portal_bff","issuer":"https://portal.example/api/idp","modules":["mail"]}"#.to_vec()).unwrap();
    let login = core.hub_begin(HubAction::SignIn, None, false).unwrap();
    core.hub_finish(login.request_id, 201, media.clone(), br#"{"transactionId":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE","authorizationUrl":"https://portal.example/api/idp/authorize?state=fixture","expiresAt":1800000300,"expiresIn":300}"#.to_vec()).unwrap();
    let complete = core.hub_begin(HubAction::Complete, None, false).unwrap();
    core.hub_finish(complete.request_id, 200, media, br#"{"status":"complete","sessionToken":"AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI","issuer":"https://portal.example/api/idp","subject":"fixture-subject","mailRead":false,"expiresAt":0,"expiresIn":0,"durable":true}"#.to_vec()).unwrap();
    drop(core);
    let core = AppCore::open_persistent(path_text.clone(), vec![91; 32], false).unwrap();
    let session = core.hub_snapshot().unwrap().session.unwrap();
    assert_eq!(session.subject, "fixture-subject");
    assert!(!session.mail_available);
    let revoke = core.hub_begin(HubAction::Logout, None, false).unwrap();
    core.hub_abandon(revoke.request_id).unwrap();
    drop(core);
    let core = AppCore::open_persistent(path_text, vec![91; 32], false).unwrap();
    assert!(core.hub_snapshot().unwrap().session.is_none());
}
