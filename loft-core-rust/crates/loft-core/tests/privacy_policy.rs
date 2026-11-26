use loft_core::{CoreError, DnsMode, DnsPrivacyLimits, LeakProtectionMode, NetworkPrivacyPolicy};

#[test]
fn the_default_policy_is_valid_without_a_resolver_or_network_work() {
    let policy = NetworkPrivacyPolicy::default().normalized().unwrap();
    assert_eq!(policy.dns_mode, DnsMode::NodeDomainFakeIp);
    assert_eq!(policy.dns_leak_policy, LeakProtectionMode::ProxyOnly);
    assert_eq!(policy.webrtc_policy, LeakProtectionMode::ProxyOnly);
    assert!(policy.resolver_endpoint.is_empty());
    assert!(!policy.hydra.enabled);
    assert!(!policy.hydra.auto_jitter);
}

#[test]
fn wire_dns_accepts_only_a_canonical_literal_ipv4_endpoint() {
    let policy = NetworkPrivacyPolicy {
        dns_mode: DnsMode::WireTcp,
        resolver_endpoint: "1.1.1.1:00053".into(),
        ..Default::default()
    };
    assert_eq!(policy.normalized().unwrap().resolver_endpoint, "1.1.1.1:53");
    for endpoint in [
        "",
        "dns.example:53",
        "https://1.1.1.1:53",
        "user@1.1.1.1:53",
        " 1.1.1.1:53",
        "01.1.1.1:53",
        "0x1.1.1.1:53",
        "[::1]:53",
        "0.0.0.0:53",
        "224.0.0.1:53",
        "1.1.1.1:0",
        "1.1.1.1:65536",
        "1.1.1.1:53:54",
    ] {
        let policy = NetworkPrivacyPolicy {
            dns_mode: DnsMode::WireTcp,
            resolver_endpoint: endpoint.into(),
            ..Default::default()
        };
        assert_eq!(
            policy.normalized(),
            Err(CoreError::InvalidNetworkPrivacyPolicy)
        );
    }
}

#[test]
fn synthetic_dns_cannot_hide_a_configured_wire_resolver() {
    let policy = NetworkPrivacyPolicy {
        resolver_endpoint: "1.1.1.1:53".into(),
        ..Default::default()
    };
    assert_eq!(
        policy.normalized(),
        Err(CoreError::InvalidNetworkPrivacyPolicy)
    );
}

#[test]
fn dns_block_is_an_explicit_valid_policy_without_a_direct_fallback() {
    let policy = NetworkPrivacyPolicy {
        dns_leak_policy: LeakProtectionMode::Block,
        webrtc_policy: LeakProtectionMode::Block,
        ..Default::default()
    };
    let normalized = policy.normalized().unwrap();
    assert_eq!(normalized.dns_leak_policy, LeakProtectionMode::Block);
    assert_eq!(normalized.webrtc_policy, LeakProtectionMode::Block);
    assert!(normalized.resolver_endpoint.is_empty());
}

#[test]
fn dns_limits_admit_the_minimum_and_maximum_owned_worksets() {
    for limits in [
        DnsPrivacyLimits {
            map_max_entries: 1,
            map_max_bytes: 1024,
            ttl_seconds: 1,
            max_query_bytes: 12,
            max_response_bytes: 12,
        },
        DnsPrivacyLimits {
            map_max_entries: 256,
            map_max_bytes: 262144,
            ttl_seconds: 60,
            max_query_bytes: 4096,
            max_response_bytes: 65535,
        },
    ] {
        let policy = NetworkPrivacyPolicy {
            dns_limits: limits.clone(),
            ..Default::default()
        };
        assert_eq!(policy.normalized().unwrap().dns_limits, limits);
    }
}

#[test]
fn dns_limits_reject_overflow_and_unfunded_entries() {
    for (field, value) in [
        (0, 0),
        (0, 257),
        (0, u32::MAX),
        (1, 1023),
        (1, 262145),
        (2, 0),
        (2, 61),
        (3, 11),
        (3, 4097),
        (4, 11),
        (4, 65536),
    ] {
        let mut policy = NetworkPrivacyPolicy::default();
        match field {
            0 => policy.dns_limits.map_max_entries = value,
            1 => policy.dns_limits.map_max_bytes = value,
            2 => policy.dns_limits.ttl_seconds = value,
            3 => policy.dns_limits.max_query_bytes = value,
            _ => policy.dns_limits.max_response_bytes = value,
        }
        assert_eq!(
            policy.normalized(),
            Err(CoreError::InvalidNetworkPrivacyPolicy)
        );
    }
    let mut policy = NetworkPrivacyPolicy::default();
    policy.dns_limits.map_max_bytes = 262143;
    assert_eq!(
        policy.normalized(),
        Err(CoreError::InvalidNetworkPrivacyPolicy)
    );
}

#[test]
fn hydra_normalization_preserves_source_zero_defaults() {
    let mut policy = NetworkPrivacyPolicy::default();
    policy.hydra.rotation_seconds = 0;
    policy.hydra.burst_min_records = 0;
    policy.hydra.burst_max_records = 0;
    let normalized = policy.normalized().unwrap();
    assert_eq!(normalized.hydra.rotation_seconds, 300);
    assert_eq!(normalized.hydra.burst_min_records, 0);
    assert_eq!(normalized.hydra.burst_max_records, 0);
}

#[test]
fn hydra_is_validated_even_when_disabled() {
    for (field, value) in [
        (0, 9),
        (0, 86401),
        (1, 41),
        (2, 24),
        (2, 51),
        (3, 33),
        (4, 33),
        (5, 65),
    ] {
        let mut policy = NetworkPrivacyPolicy::default();
        match field {
            0 => policy.hydra.rotation_seconds = value,
            1 => policy.hydra.rotation_jitter_percent = value,
            2 => policy.hydra.chunk_min_percent = value,
            3 => policy.hydra.burst_min_records = value,
            4 => policy.hydra.burst_max_records = value,
            _ => policy.hydra.padding_gap_max_records = value,
        }
        assert_eq!(
            policy.normalized(),
            Err(CoreError::InvalidNetworkPrivacyPolicy)
        );
    }
    let mut policy = NetworkPrivacyPolicy::default();
    policy.hydra.burst_min_records = 0;
    policy.hydra.burst_max_records = 1;
    assert_eq!(
        policy.normalized(),
        Err(CoreError::InvalidNetworkPrivacyPolicy)
    );
}
