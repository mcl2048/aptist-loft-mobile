pub mod support;
use base64::{Engine, engine::general_purpose::STANDARD};
use loft_core::{CoreError, CoreState, ProtocolKind};
use rcgen::{
    BasicConstraints, CustomExtension, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, PublicKeyData, date_time_ymd,
};
use sha2::{Digest, Sha256};

#[path = "support/node_fixtures.rs"]
mod node_fixtures;
use node_fixtures::{encoded_material, identity, parameters, percent_encode, pro_uri, x_uri};

// Catches mapping an X transport's outer UDP to an unsupported application datagram range.
#[test]
fn hyraken_x_import_retains_required_material_but_only_exposes_metadata() {
    let mut core = CoreState::new();
    let node = core.import_node(x_uri()).unwrap();
    assert_eq!(node.protocol, ProtocolKind::HyrakenX);
    assert_eq!(node.endpoint, "node.example:10995");
    assert_eq!((node.udp_min, node.udp_max), (1, 1024));
    assert!(node.credential_material_present);
    let metadata = format!("{:?}", core.snapshot());
    for secret in [
        "0123456789abcdef0123456789abcdef",
        "PRIVATE KEY",
        "CERTIFICATE",
        "hyrakenx://",
    ] {
        assert!(!metadata.contains(secret));
    }
}

// Catches page-specific disclosure of real, independently generated X/Pro import material.
#[test]
fn later_node_page_redacts_actual_x_and_pro_material() {
    let mut core = CoreState::new();
    for index in 0..50 {
        core.import_node(format!("socks5://material-page-{index}.example"))
            .unwrap();
    }
    core.import_node(x_uri()).unwrap();
    core.import_node(pro_uri()).unwrap();
    core.import_node("socks5://page-user:page-private-password@private.example#Private".into())
        .unwrap();
    let page = core.node_page(50, core.snapshot().generation).unwrap();
    assert_eq!(page.nodes.len(), 3);
    assert_eq!(page.nodes[0].protocol, ProtocolKind::HyrakenX);
    assert_eq!(page.nodes[1].protocol, ProtocolKind::HyrakenPro);
    assert_eq!(page.nodes[2].protocol, ProtocolKind::Socks5);
    assert!(
        page.nodes
            .iter()
            .all(|node| node.credential_material_present)
    );
    let metadata = format!("{page:?}");
    for secret in [
        "0123456789abcdef0123456789abcdef",
        "PRIVATE KEY",
        "CERTIFICATE",
        "LS0tLS1CRUdJTi",
        "hyrakenx://",
        "hyraken-pro://",
        "socks5://",
        "page-user",
        "page-private-password",
    ] {
        assert!(!metadata.contains(secret));
    }
}

// Catches using the XUDP envelope limit as application payload or dropping empty datagrams.
#[test]
fn hyraken_pro_import_has_source_payload_bounds_and_no_server_private_key() {
    let mut core = CoreState::new();
    let node = core.import_node(pro_uri()).unwrap();
    assert_eq!(node.protocol, ProtocolKind::HyrakenPro);
    assert_eq!((node.udp_min, node.udp_max), (0, 65507));
    assert!(node.credential_material_present);
    let metadata = format!("{:?}", core.snapshot());
    assert!(!metadata.contains("0123456789abcdef0123456789abcdef"));
    assert!(!metadata.contains("CERTIFICATE"));
    let with_key = pro_uri().replace(
        &encoded_material(&identity().server_pem),
        &encoded_material(&identity().client_key),
    );
    assert_eq!(
        core.import_node(with_key),
        Err(CoreError::InvalidCertificate)
    );
}

#[test]
fn malformed_uri_or_incomplete_auth_never_leaves_partial_node() {
    let mut core = CoreState::new();
    for (raw, error) in [
        ("http://proxy.example", CoreError::UnsupportedProtocol),
        ("hyraken://proxy.example", CoreError::UnsupportedProtocol),
        ("socks5://", CoreError::InvalidEndpoint),
        ("socks5://proxy.example:0", CoreError::InvalidEndpoint),
        ("socks5://proxy.example:65536", CoreError::InvalidEndpoint),
        ("socks5://proxy.example:1080x", CoreError::InvalidEndpoint),
        ("socks5://proxy.example:1/path", CoreError::InvalidUri),
        ("socks5://u@proxy.example", CoreError::InvalidCredential),
        ("socks5://:p@proxy.example", CoreError::InvalidCredential),
        ("socks5://u:@proxy.example", CoreError::InvalidCredential),
        ("socks5://u:p%ZZ@proxy.example", CoreError::InvalidUri),
        (
            "socks5://u:p%0A@proxy.example",
            CoreError::InvalidCredential,
        ),
        (
            "socks5://u:p@proxy.example#bad%0Aname",
            CoreError::InvalidUri,
        ),
        ("socks5://proxy.example\n", CoreError::InvalidUri),
        (
            "socks5://proxy.example?allowInsecure=1",
            CoreError::UnknownParameter,
        ),
        (
            "hyrakenx://short@node.example:1",
            CoreError::InvalidCredential,
        ),
        (
            "hyraken-pro://0123456789abcdef0123456789abcdef@node.example:1",
            CoreError::MissingField,
        ),
    ] {
        assert_eq!(core.import_node(raw.into()), Err(error), "{raw:?}");
        assert_eq!(core.snapshot().node_count, 0);
        assert_eq!(core.snapshot().generation, 0);
    }
}

// Catches percent-decoded duplicate keys or permissive parsers changing supplied trust configuration.
#[test]
fn duplicate_and_unknown_query_parameters_are_rejected() {
    let mut core = CoreState::new();
    for suffix in ["&pin=second", "&%70in=second", "&sni=second"] {
        let raw = pro_uri().replace("#Pro", suffix);
        assert_eq!(core.import_node(raw), Err(CoreError::DuplicateParameter));
    }
    assert_eq!(
        core.import_node(pro_uri().replace("#Pro", "&allowInsecure=1")),
        Err(CoreError::UnknownParameter)
    );
    assert_eq!(core.snapshot().node_count, 0);
}

#[test]
fn wrong_pin_name_expiration_and_private_key_relationship_are_rejected() {
    let mut core = CoreState::new();
    let wrong_pin = pro_uri().replace(
        &percent_encode(&identity().pin),
        &percent_encode(&STANDARD.encode([0u8; 32])),
    );
    assert_eq!(
        core.import_node(wrong_pin),
        Err(CoreError::InvalidCertificate)
    );
    assert_eq!(
        core.import_node(pro_uri().replace("sni=node.example", "sni=other.example")),
        Err(CoreError::InvalidCertificate)
    );
    let wrong_key = KeyPair::generate().unwrap().serialize_pem();
    assert_eq!(
        core.import_node(x_uri().replace(
            &encoded_material(&identity().client_key),
            &encoded_material(&wrong_key)
        )),
        Err(CoreError::InvalidCertificate)
    );
    let expired_key = KeyPair::generate().unwrap();
    let mut expired_params = parameters(vec!["node.example".into()]);
    expired_params.not_before = date_time_ymd(2000, 1, 1);
    expired_params.not_after = date_time_ymd(2001, 1, 1);
    let expired = expired_params.self_signed(&expired_key).unwrap();
    let expired_uri = pro_uri()
        .replace(
            &encoded_material(&identity().server_pem),
            &encoded_material(&expired.pem()),
        )
        .replace(
            &percent_encode(&identity().pin),
            &percent_encode(
                &STANDARD.encode(Sha256::digest(expired_key.subject_public_key_info())),
            ),
        );
    assert_eq!(
        core.import_node(expired_uri),
        Err(CoreError::InvalidCertificate)
    );
    assert_eq!(core.snapshot().node_count, 0);
}

// Catches a decoder replacement rejecting valid LF/CRLF/CR PEM or surrounding ASCII whitespace.
#[test]
fn pem_line_endings_preserve_valid_x_and_pro_imports() {
    let identity = identity();
    for newline in ["\n", "\r\n", "\r"] {
        let mut x = x_uri();
        for material in [
            &identity.server_pem,
            &identity.ca_pem,
            &identity.client_pem,
            &identity.client_key,
        ] {
            let padded = format!(" \t\r\n{}\t\r\n ", material.replace('\n', newline));
            x = x.replace(&encoded_material(material), &encoded_material(&padded));
        }
        let mut core = CoreState::new();
        assert_eq!(
            core.import_node(x).unwrap().protocol,
            ProtocolKind::HyrakenX
        );
        let padded_server = format!(
            " \t\r\n{}\t\r\n ",
            identity.server_pem.replace('\n', newline)
        );
        let pro = pro_uri().replace(
            &encoded_material(&identity.server_pem),
            &encoded_material(&padded_server),
        );
        assert_eq!(
            core.import_node(pro).unwrap().protocol,
            ProtocolKind::HyrakenPro
        );
        assert_eq!(core.snapshot().node_count, 2);
        assert_eq!(core.snapshot().generation, 2);
    }
}

// Catches replacing the strict envelope with a decoder that skips junk/foreign blocks or a bad tail.
#[test]
fn pem_certificate_envelope_failures_are_atomic() {
    let pem = &identity().server_pem;
    let bad_materials = [
        " \t\r\n ".into(),
        format!("untrusted preamble\n{pem}"),
        format!("{pem}\nuntrusted suffix"),
        format!("{pem}{}", identity().client_key),
        pem.replace("-----END CERTIFICATE-----", "-----END PRIVATE KEY-----"),
        pem.replace("-----END CERTIFICATE-----", ""),
        pem.replace(
            "-----BEGIN CERTIFICATE-----\n",
            "-----BEGIN CERTIFICATE-----",
        ),
        pem.replace("CERTIFICATE", "CERTIFICATE REQUEST"),
        "-----BEGIN CERTIFICATE-----\nAA!A\n-----END CERTIFICATE-----\n".into(),
        "-----BEGIN CERTIFICATE-----\nA===\n-----END CERTIFICATE-----\n".into(),
    ];
    let mut core = CoreState::new();
    core.import_node("socks5://retained.example".into())
        .unwrap();
    core.stage_server("cloud.example".into()).unwrap();
    core.set_app_routing(true, vec!["org.example.selected".into()])
        .unwrap();
    let before = core.snapshot();
    assert_eq!(
        core.import_node(pro_uri().replace(&encoded_material(pem), "")),
        Err(CoreError::MissingField)
    );
    for material in bad_materials {
        let uri = pro_uri().replace(&encoded_material(pem), &encoded_material(&material));
        assert_eq!(core.import_node(uri), Err(CoreError::InvalidCertificate));
        assert_eq!(core.snapshot(), before);
    }
    let invalid_utf8 = percent_encode(&STANDARD.encode([0xff, 0xfe]));
    assert_eq!(
        core.import_node(pro_uri().replace(&encoded_material(pem), &invalid_utf8)),
        Err(CoreError::InvalidCertificate)
    );
    assert_eq!(core.snapshot(), before);
}

// Catches accepting only the first key, silently skipping extra sections or dropping strict key tags.
#[test]
fn pem_private_key_envelope_failures_are_atomic() {
    let key = &identity().client_key;
    let bad_materials = [
        " \t\r\n ".into(),
        format!("untrusted preamble\n{key}"),
        format!("{key}\nuntrusted suffix"),
        format!("{key}{key}"),
        format!("{key}{}", identity().client_pem),
        key.replace("-----END PRIVATE KEY-----", "-----END RSA PRIVATE KEY-----"),
        key.replace("-----END PRIVATE KEY-----", ""),
        key.replace(
            "-----BEGIN PRIVATE KEY-----\n",
            "-----BEGIN PRIVATE KEY-----",
        ),
        key.replace("PRIVATE KEY", "ENCRYPTED PRIVATE KEY"),
        "-----BEGIN PRIVATE KEY-----\nAA!A\n-----END PRIVATE KEY-----\n".into(),
        "-----BEGIN PRIVATE KEY-----\nA===\n-----END PRIVATE KEY-----\n".into(),
    ];
    let mut core = CoreState::new();
    core.import_node("socks5://retained.example".into())
        .unwrap();
    let before = core.snapshot();
    assert_eq!(
        core.import_node(x_uri().replace(&encoded_material(key), "")),
        Err(CoreError::MissingField)
    );
    for material in bad_materials {
        let uri = x_uri().replace(&encoded_material(key), &encoded_material(&material));
        assert_eq!(core.import_node(uri), Err(CoreError::InvalidCertificate));
        assert_eq!(core.snapshot(), before);
    }
}

// Independently signed eight-link chain catches incomplete decoding, changed order and a relaxed cap.
#[test]
fn pem_eight_certificate_chain_and_link_validation_are_preserved() {
    let keys: Vec<_> = (0..8).map(|_| KeyPair::generate().unwrap()).collect();
    let params: Vec<_> = (0..8)
        .map(|index| {
            let mut params = parameters(vec![if index == 0 {
                "node.example".into()
            } else {
                format!("authority-{index}.example")
            }]);
            params
                .distinguished_name
                .push(DnType::CommonName, format!("PEM test identity {index}"));
            if index == 0 {
                params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
            } else {
                params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
                params.key_usages = vec![
                    KeyUsagePurpose::KeyCertSign,
                    KeyUsagePurpose::DigitalSignature,
                ];
            }
            params
        })
        .collect();
    let pem: Vec<_> = (0..8)
        .map(|index| {
            if index == 7 {
                params[index].self_signed(&keys[index]).unwrap().pem()
            } else {
                params[index]
                    .signed_by(
                        &keys[index],
                        &Issuer::from_params(&params[index + 1], &keys[index + 1]),
                    )
                    .unwrap()
                    .pem()
            }
        })
        .collect();
    let pin = percent_encode(&STANDARD.encode(Sha256::digest(keys[0].subject_public_key_info())));
    let uri_with_chain = |chain: &str| {
        pro_uri()
            .replace(&percent_encode(&identity().pin), &pin)
            .replace(
                &encoded_material(&identity().server_pem),
                &encoded_material(chain),
            )
    };
    let chain = pem.concat();
    let mut core = CoreState::new();
    assert_eq!(
        core.import_node(uri_with_chain(&chain)).unwrap().protocol,
        ProtocolKind::HyrakenPro
    );
    let before = core.snapshot();
    assert_eq!(
        core.import_node(uri_with_chain(&format!("{chain}{}", pem[7]))),
        Err(CoreError::InvalidCertificate)
    );
    let mut reordered = pem;
    reordered.swap(1, 2);
    assert_eq!(
        core.import_node(uri_with_chain(&reordered.concat())),
        Err(CoreError::InvalidCertificate)
    );
    assert_eq!(core.snapshot(), before);
}

#[test]
fn required_x_materials_and_option_combinations_are_enforced() {
    let mut core = CoreState::new();
    assert_eq!(
        core.import_node(x_uri().replace(
            &format!("&key={}", encoded_material(&identity().client_key)),
            ""
        )),
        Err(CoreError::MissingField)
    );
    assert_eq!(
        core.import_node(x_uri().replace("mode=beast", "mode=flash")),
        Err(CoreError::InvalidOption)
    );
    assert_eq!(
        core.import_node(x_uri().replace("scenario=bulk", "scenario=unknown")),
        Err(CoreError::InvalidOption)
    );
    assert_eq!(
        core.import_node(x_uri().replace("rate=100", "rate=-1")),
        Err(CoreError::InvalidOption)
    );
    assert_eq!(
        core.import_node(x_uri().replace("rate=100", "rate=20001")),
        Err(CoreError::InvalidOption)
    );
    assert_eq!(core.snapshot().node_count, 0);
}

#[test]
fn pro_options_reject_malformed_booleans_counts_or_unsupported_values() {
    let mut core = CoreState::new();
    for (old, new) in [
        ("transport=grpc", "transport=udp"),
        ("engine=ghostx", "engine=other"),
        ("suite=auto", "suite=none"),
        ("congestion=beast", "congestion=unknown"),
        ("connections=1", "connections=0"),
        ("connections=1", "connections=9"),
        ("connections=1", "connections=1.5"),
        ("elastic_mux=0", "elastic_mux=false"),
        ("isolation=1", "isolation=true"),
        ("packet_encoding=xudp", "packet_encoding=bad"),
        ("path=%2Fhyraken.pro%2FTunnel", "path=%2F%2Fbad"),
    ] {
        assert_eq!(
            core.import_node(pro_uri().replace(old, new)),
            Err(CoreError::InvalidOption),
            "{new}"
        );
    }
    assert_eq!(core.snapshot().node_count, 0);
}

// Catches hidden truncation, percent/Base64 expansion bypass, or importing over-size material.
#[test]
fn raw_decoded_material_and_label_quotas_fail_before_commit() {
    let mut core = CoreState::new();
    assert_eq!(
        core.import_node("a".repeat(512 * 1024 + 1)),
        Err(CoreError::InputTooLarge)
    );
    assert_eq!(
        core.import_node(format!("socks5://proxy.example#{}", "a".repeat(65))),
        Err(CoreError::InputTooLarge)
    );
    let large_cert = encoded_material(&"A".repeat(65537));
    assert_eq!(
        core.import_node(pro_uri().replace(&encoded_material(&identity().server_pem), &large_cert)),
        Err(CoreError::InputTooLarge)
    );
    let large_key = encoded_material(&"A".repeat(16385));
    assert_eq!(
        core.import_node(x_uri().replace(&encoded_material(&identity().client_key), &large_key)),
        Err(CoreError::InputTooLarge)
    );
    assert_eq!(core.snapshot().node_count, 0);
}

#[test]
fn labels_cannot_republish_known_credential_or_raw_link() {
    let mut core = CoreState::new();
    let node = core
        .import_node("socks5://u:my-secret@proxy.example#my-secret".into())
        .unwrap();
    assert_eq!(node.label, "SOCKS5 Node");
    let node = core
        .import_node(pro_uri().replace("#Pro", "#0123456789abcdef0123456789abcdef"))
        .unwrap();
    assert_eq!(node.label, "Hyraken Pro");
    assert!(!format!("{:?}", core.snapshot()).contains("my-secret"));
}

// Catches retaining 200 maximum-size materials without a byte budget or failing to return freed bytes.
#[test]
fn retained_material_bytes_are_admitted_and_returned_on_removal() {
    let key = KeyPair::generate().unwrap();
    let mut params = parameters(vec!["node.example".into()]);
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    params
        .custom_extensions
        .push(CustomExtension::from_oid_content(
            &[1, 3, 6, 1, 4, 1, 55555, 1],
            vec![0x41; 44_000],
        ));
    let certificate = params.self_signed(&key).unwrap().pem();
    assert!(certificate.len() < 65_536);
    let pin = percent_encode(&STANDARD.encode(Sha256::digest(key.subject_public_key_info())));
    let template = pro_uri()
        .replace(
            &encoded_material(&identity().server_pem),
            &encoded_material(&certificate),
        )
        .replace(&percent_encode(&identity().pin), &pin);
    let mut core = CoreState::new();
    let mut first_id = String::new();
    let mut denied = None;
    for index in 0..200 {
        let raw = template.replace(
            "0123456789abcdef0123456789abcdef",
            &format!("test-seed-material-{index:032}"),
        );
        match core.import_node(raw.clone()) {
            Ok(node) => {
                if first_id.is_empty() {
                    first_id = node.id;
                }
            }
            Err(CoreError::NodeCapacityReached) => {
                denied = Some(raw);
                break;
            }
            Err(error) => panic!("unexpected admission error: {error}"),
        }
    }
    assert!(core.snapshot().node_count > 1);
    assert!(core.snapshot().node_count < 200);
    let denied = denied.expect("byte budget must fill before the record quota");
    let before = core.snapshot();
    assert_eq!(
        core.import_node(denied.clone()),
        Err(CoreError::NodeCapacityReached)
    );
    assert_eq!(core.snapshot(), before);
    core.remove_node(first_id).unwrap();
    core.import_node(denied).unwrap();
    assert_eq!(core.snapshot().node_count, before.node_count);
}

#[test]
fn private_vpn_uri_preserves_hyraken_credentials_and_all_options() {
    for raw in [x_uri(), pro_uri()] {
        let mut core = CoreState::new();
        let node = core.import_node(raw).unwrap();
        let ticket = core.begin_vpn(node.id, core.snapshot().generation).unwrap();
        support::freeze(&ticket, vec![]);
        let private_uri = ticket.take_raw_node().unwrap();
        assert_eq!(core.import_node(private_uri), Err(CoreError::DuplicateNode));
        assert_eq!(core.snapshot().node_count, 1);
        assert!(!format!("{:?}", core.snapshot()).contains("PRIVATE KEY"));
    }
}

#[test]
fn hydra_requires_an_actual_profile_receipt_for_the_selected_protocol_scope() {
    use loft_core::{
        HydraScope, Ipv6Policy, NetworkPrivacyEnforcement, NetworkPrivacyPolicy, VpnReadyReceipt,
    };
    for (raw, hydra_scope) in [
        (x_uri(), HydraScope::LogicalStreams),
        (pro_uri(), HydraScope::TcpOnly),
    ] {
        let mut core = CoreState::new();
        let mut policy = NetworkPrivacyPolicy::default();
        policy.hydra.enabled = true;
        core.set_network_privacy_policy(policy, 0).unwrap();
        let node = core.import_node(raw).unwrap();
        let ticket = core.begin_vpn(node.id, core.snapshot().generation).unwrap();
        support::freeze(&ticket, vec![]);
        ticket.take_raw_node().unwrap();
        let mut privacy = support::privacy(&ticket);
        privacy.hydra_enabled = true;
        let mut receipt = VpnReadyReceipt {
            attempt_id: ticket.attempt_id(),
            transport_ready: true,
            authenticated: true,
            tun_ready: true,
            sockets_protected: true,
            applied_package_names: vec![],
            ipv6_policy: Ipv6Policy::BlockedInVpn,
            privacy,
            ipv4_capture_confirmed: true,
            no_bypass_confirmed: true,
            ipv6_blocked_confirmed: true,
        };
        let before = core.snapshot();
        assert_eq!(
            core.mark_vpn_ready(receipt.clone()),
            Err(CoreError::InvalidNetworkPrivacyReceipt)
        );
        receipt.privacy.hydra_applied = true;
        assert_eq!(
            core.mark_vpn_ready(receipt.clone()),
            Err(CoreError::InvalidNetworkPrivacyReceipt)
        );
        assert_eq!(core.snapshot(), before);
        receipt.privacy.hydra_scope = hydra_scope;
        core.mark_vpn_ready(receipt).unwrap();
        assert_eq!(
            core.snapshot().network_privacy_enforcement,
            NetworkPrivacyEnforcement::Active
        );
        assert_eq!(
            core.snapshot().applied_network_privacy.unwrap().hydra_scope,
            hydra_scope
        );
    }
}
