pub mod support;
use loft_core::{
    ConnectionState, CoreSnapshot, CoreState, DnsMode, Ipv6Policy, LeakProtectionMode,
    NetworkPrivacyEnforcement, NetworkPrivacyPolicy, VpnReadyReceipt,
};
use serde_json::json;

fn large_core() -> CoreState {
    let mut core = CoreState::new();
    for number in 0..50 {
        let host = format!(
            "{}.{}.{}.{number:02}{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(59)
        );
        let label = "%22%5C".repeat(32);
        core.import_node(format!("socks5://{host}:65535#{label}"))
            .unwrap();
    }
    let packages: Vec<String> = (0..100)
        .map(|index| format!("org.{}.app{index}", "p".repeat(29)))
        .collect();
    core.set_app_routing(true, packages).unwrap();
    let server_host = format!(
        "{}.{}.{}.{}",
        "x".repeat(63),
        "y".repeat(63),
        "z".repeat(63),
        "w".repeat(61)
    );
    core.stage_server(format!("https://{server_host}:65535"))
        .unwrap();
    let mut policy = NetworkPrivacyPolicy {
        dns_mode: DnsMode::WireTcp,
        resolver_endpoint: "198.51.100.254:65535".into(),
        ..Default::default()
    };
    policy.hydra.auto_jitter = true;
    policy.hydra.rotation_seconds = 86400;
    policy.hydra.rotation_jitter_percent = 40;
    policy.hydra.chunk_min_percent = 50;
    policy.hydra.burst_min_records = 32;
    policy.hydra.burst_max_records = 32;
    policy.hydra.padding_gap_max_records = 64;
    core.set_network_privacy_policy(policy, core.snapshot().generation)
        .unwrap();
    core
}

fn encode_policy(policy: &NetworkPrivacyPolicy) -> serde_json::Value {
    let leak = |mode| match mode {
        LeakProtectionMode::ProxyOnly => "PROXY_ONLY",
        LeakProtectionMode::Block => "BLOCK",
    };
    json!({
        "dnsMode": match policy.dns_mode { DnsMode::NodeDomainFakeIp => "NODE_DOMAIN_FAKE_IP", DnsMode::WireTcp => "WIRE_TCP" },
        "dnsLeakPolicy": leak(policy.dns_leak_policy), "webrtcPolicy": leak(policy.webrtc_policy), "resolverEndpoint": policy.resolver_endpoint,
        "dnsLimits": { "mapMaxEntries": policy.dns_limits.map_max_entries, "mapMaxBytes": policy.dns_limits.map_max_bytes,
            "ttlSeconds": policy.dns_limits.ttl_seconds, "maxQueryBytes": policy.dns_limits.max_query_bytes, "maxResponseBytes": policy.dns_limits.max_response_bytes },
        "hydra": { "enabled": policy.hydra.enabled, "autoJitter": policy.hydra.auto_jitter, "rotationSeconds": policy.hydra.rotation_seconds,
            "rotationJitterPercent": policy.hydra.rotation_jitter_percent, "chunkMinPercent": policy.hydra.chunk_min_percent,
            "burstMinRecords": policy.hydra.burst_min_records, "burstMaxRecords": policy.hydra.burst_max_records, "paddingGapMaxRecords": policy.hydra.padding_gap_max_records },
    })
}

fn encode_snapshot(snapshot: CoreSnapshot) -> String {
    let nodes: Vec<_> = snapshot
        .nodes
        .iter()
        .map(|node| {
            json!({
                "id": node.id, "label": node.label, "protocol": "SOCKS5", "endpoint": node.endpoint,
                "udpMin": node.udp_min, "udpMax": node.udp_max,
                "credentialMaterialPresent": node.credential_material_present,
            })
        })
        .collect();
    let applied = snapshot.applied_routing.as_ref().map(|routing| {
        json!({
            "enabled": routing.enabled, "packageNames": routing.package_names,
            "ipv6Policy": "BLOCKED_IN_VPN",
        })
    });
    let state = match snapshot.connection_state {
        ConnectionState::Disconnected => "DISCONNECTED",
        ConnectionState::Connecting => "CONNECTING",
        ConnectionState::Connected => "CONNECTED",
        ConnectionState::Stopping => "STOPPING",
        ConnectionState::Blocked => "BLOCKED",
        ConnectionState::Unavailable => "UNAVAILABLE",
    };
    let applied_privacy = snapshot.applied_network_privacy.as_ref().map(|privacy| json!({
        "policyEpoch": privacy.policy_epoch, "scopeId": privacy.scope_id, "policy": encode_policy(&privacy.policy), "hydraScope": format!("{:?}", privacy.hydra_scope),
    }));
    let enforcement = match snapshot.network_privacy_enforcement {
        NetworkPrivacyEnforcement::Inactive => "INACTIVE",
        NetworkPrivacyEnforcement::Active => "ACTIVE",
        NetworkPrivacyEnforcement::Blocked => "BLOCKED",
    };
    serde_json::to_string(&json!({
        "schemaVersion": snapshot.schema_version, "coreVersion": snapshot.core_version,
        "nodes": nodes, "nodeCount": snapshot.node_count, "serverAddress": snapshot.server_address,
        "serverVerified": snapshot.server_verified, "routingEnabled": snapshot.routing_enabled,
        "selectedApps": snapshot.selected_apps, "connectionState": state,
        "generation": snapshot.generation, "connectionAttemptId": snapshot.connection_attempt_id,
        "activeNodeId": snapshot.active_node_id, "appliedRouting": applied,
        "vpnFailure": snapshot.vpn_failure.map(|failure| format!("{failure:?}")),
        "networkPrivacyPolicy": encode_policy(&snapshot.network_privacy_policy), "networkPrivacyPolicyEpoch": snapshot.network_privacy_policy_epoch,
        "appliedNetworkPrivacy": applied_privacy, "networkPrivacyEnforcement": enforcement,
    }))
    .unwrap()
}

#[test]
fn worst_case_snapshot_stays_below_binder_message_limit() {
    let core = large_core();
    assert_eq!(core.snapshot().nodes.len(), 50);
    let wire = encode_snapshot(core.snapshot());
    let parcel_bytes = wire.encode_utf16().count() * 2 + 4 + 2;
    println!("maximum initial metadata JSON Parcel: {parcel_bytes} bytes");
    assert!(
        parcel_bytes < 64 * 1024,
        "JSON Parcel used {parcel_bytes} bytes"
    );
}

// Typed reducer/serialization fixture only. Android owns actual binary envelope/payload evidence.
#[test]
fn maximum_draft_and_applied_scope_fit_the_real_byte_array_frame() {
    let mut core = large_core();
    let before = core.snapshot();
    let ticket = core
        .begin_vpn(before.nodes[0].id.clone(), before.generation)
        .unwrap();
    support::freeze(&ticket, before.selected_apps.clone());
    ticket.take_raw_node().unwrap();
    core.mark_vpn_ready(VpnReadyReceipt {
        attempt_id: ticket.attempt_id(),
        transport_ready: true,
        authenticated: true,
        tun_ready: true,
        sockets_protected: true,
        applied_package_names: before.selected_apps,
        ipv6_policy: Ipv6Policy::BlockedInVpn,
        privacy: support::privacy(&ticket),
        ipv4_capture_confirmed: true,
        no_bypass_confirmed: true,
        ipv6_blocked_confirmed: true,
    })
    .unwrap();
    let wire = encode_snapshot(core.snapshot());
    println!("maximum draft/applied UTF-8 frame: {} bytes", wire.len());
    assert!(wire.len() < 60 * 1024);
}
