use loft_core::{CoreError, normalize_server_origin};

// Catches omitted HTTPS defaults, noncanonical authority and unsafe URL parser normalization.
#[test]
fn normalizes_only_a_server_origin() {
    for (raw, expected) in [
        ("Example.COM", "https://example.com"),
        (" https://Example.COM:443/ ", "https://example.com"),
        ("example.com:8443", "https://example.com:8443"),
        ("https://[2001:db8::1]:8443/", "https://[2001:db8::1]:8443"),
        ("https://192.0.2.1", "https://192.0.2.1"),
    ] {
        assert_eq!(normalize_server_origin(raw), Ok(expected.to_owned()));
    }
}

// Catches silently dropping credentials, paths, malformed ports, controls or encoded authority.
#[test]
fn rejects_non_origin_or_ambiguous_addresses() {
    for raw in [
        "",
        "http://example.com",
        "ftp://example.com",
        "https://user:secret@example.com",
        "https://@example.com",
        "https://example.com/path",
        "https://example.com/../",
        "https://example.com?",
        "https://example.com#",
        "https://example.com:0",
        "https://example.com:65536",
        "https://example.com:443junk",
        "https://example.com:",
        "https://example.com\\evil",
        "https://example.com\n",
        "https://exa mple.com",
        "https://%65xample.com",
        "https:///example.com",
        "https://-bad.example",
        "https://bad_.example",
        "https://example..com",
        "https://example.com.",
        "https://2001:db8::1",
        "https://[fe80::1%25eth0]",
        "https://1.2.3.999",
        "https://2130706433",
        "https://0x7f000001",
        "https://127.1",
    ] {
        assert_eq!(
            normalize_server_origin(raw),
            Err(CoreError::InvalidServerAddress),
            "{raw:?}"
        );
    }
}

#[test]
fn rejects_server_input_before_unbounded_parsing() {
    assert_eq!(
        normalize_server_origin(&"a".repeat(2049)),
        Err(CoreError::InputTooLarge)
    );
}

#[test]
fn hexadecimal_ipv4_components_are_rejected_as_ambiguous_origins() {
    for raw in [
        "https://0x7f.0.0.1",
        "https://0x7f.1",
        "https://0x7f.0x0.0x0.0x1",
        "https://host.0x1",
    ] {
        assert_eq!(
            normalize_server_origin(raw),
            Err(CoreError::InvalidServerAddress)
        );
    }
}
