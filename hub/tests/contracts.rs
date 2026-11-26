use loft_hub::{
    Callback, Claims, challenge, check_claims, decode_callback, deployment_origin, mail_text, open,
    preview, scope, seal,
};

const PROOF: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const ISSUER: &str = "https://portal.example/api/idp";

#[test]
fn app_proof_hashes_the_ascii_verifier_and_rejects_noncanonical_base64() {
    assert_eq!(
        challenge(PROOF).unwrap(),
        "DwBzhbb51LfusnSGBa_hqYSgo7-j8BTQnip4TOnlzRo"
    );
    assert!(challenge("not-a-verifier").is_err());
    assert!(challenge(&format!("{}B", &PROOF[..42])).is_err());
}

#[test]
fn canonical_hub_origin_rejects_credentials_paths_and_non_tls() {
    assert_eq!(
        deployment_origin("https://hub.example").unwrap(),
        "https://hub.example"
    );
    for bad in [
        "http://hub.example",
        "https://user@hub.example",
        "https://hub.example/path",
        "https://hub.example/?query",
        "https://hub.example/#anchor",
        "https://HUB.example",
        "https://hub.example:443",
    ] {
        assert!(deployment_origin(bad).is_err(), "{bad}");
    }
}

#[test]
fn callback_is_issuer_bound_and_rejects_duplicate_or_mixed_outcomes() {
    let code = format!("8b438de5-6082-4d77-9a50-f41417fd4081.{PROOF}");
    let query = format!("state={PROOF}&code={code}&iss={ISSUER}");
    assert_eq!(
        decode_callback(&query, ISSUER).unwrap(),
        Callback::Code {
            state: PROOF.into(),
            code
        }
    );
    let denied = format!("state={PROOF}&error=access_denied&iss={ISSUER}");
    assert_eq!(
        decode_callback(&denied, ISSUER).unwrap(),
        Callback::Denied {
            state: PROOF.into()
        }
    );
    assert!(decode_callback(&query, "https://other.example/api/idp").is_err());
    assert!(decode_callback(&format!("{query}&state={PROOF}"), ISSUER).is_err());
    assert!(decode_callback(&format!("{query}&error=access_denied"), ISSUER).is_err());
}

#[test]
fn openid_is_requested_without_tenant_authority_and_mail_requires_selection() {
    assert_eq!(scope(false), "openid email");
    assert_eq!(scope(true), "openid email mail.read");
}

#[test]
fn id_token_claims_bind_issuer_audience_nonce_and_original_deadline() {
    let mut valid = Claims {
        iss: ISSUER.into(),
        aud: "client".into(),
        sub: PROOF.into(),
        nonce: PROOF.into(),
        exp: 1300,
        iat: 1000,
    };
    assert!(check_claims(&valid, ISSUER, "client", PROOF, 1000).is_ok());
    assert!(check_claims(&valid, ISSUER, "different-client", PROOF, 1000).is_err());
    assert!(check_claims(&valid, ISSUER, "client", "different-nonce", 1000).is_err());
    assert!(check_claims(&valid, ISSUER, "client", PROOF, 1300).is_err());
    valid.exp += 1;
    assert!(check_claims(&valid, ISSUER, "client", PROOF, 1000).is_err());
}

#[test]
fn stored_secrets_are_bound_to_the_owner_and_unreadable_with_another_key() {
    let key = [11; 32];
    let sealed = seal(&key, &[22; 12], b"tenant-a|session-1", &"fixture secret").unwrap();
    assert!(!sealed.contains("fixture secret"));
    assert_eq!(
        open::<String>(&key, b"tenant-a|session-1", &sealed).unwrap(),
        "fixture secret"
    );
    assert!(open::<String>(&key, b"tenant-b|session-1", &sealed).is_err());
    assert!(open::<String>(&[12; 32], b"tenant-a|session-1", &sealed).is_err());
}

#[test]
fn html_only_mail_is_inert_text_and_unicode_preview_uses_byte_budget() {
    let text = mail_text("", "<p>Hello &amp; world</p><script>invisible()</script><img src='https://tracking.example/pixel'><a href='https://foreign.example/path'>Link</a>").unwrap();
    assert!(text.contains("Hello & world"));
    assert!(text.contains("https://foreign.example/path"));
    assert!(!text.contains("invisible()"));
    assert!(!text.contains("tracking.example"));
    assert_eq!(preview("ok界end", 4), ("ok".into(), true));
    assert_eq!(preview("ok界end", 5), ("ok界".into(), true));
}
