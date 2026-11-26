use loft_core::{CoreState, VaultAlgorithm, VaultDraft, VaultError, VaultKind};

fn password(id: Option<String>, secret: Option<&[u8]>) -> VaultDraft {
    VaultDraft {
        id,
        kind: VaultKind::Password,
        label: "Work sign-in".into(),
        account: "person@example.test".into(),
        issuer: "Example".into(),
        secret: secret.map(<[u8]>::to_vec),
        algorithm: None,
        digits: None,
        period: None,
    }
}

#[test]
fn explicit_password_reveal_and_archive_preserve_saved_value() {
    let mut core = CoreState::new();
    let entry = core
        .vault_save(password(None, Some(b"local fixture passphrase")))
        .unwrap();
    let mut changed = password(Some(entry.id.clone()), None);
    changed.label = "Changed label".into();
    core.vault_save(changed).unwrap();
    let page = core.vault_list(false, 0, None).unwrap();
    assert_eq!(page.entries[0].label, "Changed label");
    assert!(!format!("{page:?}").contains("local fixture passphrase"));
    assert_eq!(
        core.vault_reveal(&entry.id, 0).unwrap().value,
        b"local fixture passphrase"
    );
    core.vault_archive(&entry.id, true).unwrap();
    assert!(core.vault_list(false, 0, None).unwrap().entries.is_empty());
    assert_eq!(
        core.vault_list(true, 0, None).unwrap().entries[0].id,
        entry.id
    );
    assert_eq!(
        core.vault_reveal(&entry.id, 0).err(),
        Some(VaultError::Archived)
    );
    core.vault_archive(&entry.id, false).unwrap();
    assert_eq!(
        core.vault_reveal(&entry.id, 0).unwrap().value,
        b"local fixture passphrase"
    );
}

#[test]
fn rfc6238_sha1_vectors_and_strict_otpauth_metadata() {
    let mut core = CoreState::new();
    let uri = concat!(
        "otpauth://totp/Example:person%40example.test",
        "?issuer=Example",
        "&secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&algorithm=SHA1&digits=8&period=30"
    );
    let entry = core.vault_import(uri.as_bytes().to_vec()).unwrap();
    assert_eq!(entry.algorithm, Some(VaultAlgorithm::Sha1));
    assert_eq!(entry.account, "person@example.test");
    let first = core.vault_reveal(&entry.id, 59).unwrap();
    assert_eq!(first.value, b"94287082");
    assert_eq!(first.valid_for_seconds, Some(1));
    assert_eq!(
        core.vault_reveal(&entry.id, 20_000_000_000).unwrap().value,
        b"65353130"
    );
    assert_eq!(
        core.vault_import(format!("{uri}&issuer=Other").into_bytes())
            .err(),
        Some(VaultError::InvalidInput)
    );
    assert_eq!(
        core.vault_import(uri.replace("totp/", "hotp/").into_bytes())
            .err(),
        Some(VaultError::InvalidInput)
    );
    assert_eq!(
        core.vault_import(uri.replace("issuer=Example", "issuer=Other").into_bytes())
            .err(),
        Some(VaultError::InvalidInput)
    );
    assert_eq!(core.vault_list(false, 0, None).unwrap().entries.len(), 1);
}

#[test]
fn appendix_b_sha256_and_sha512_vectors() {
    use data_encoding::BASE32_NOPAD;

    let mut core = CoreState::new();
    let cases = [
        (
            VaultAlgorithm::Sha256,
            "46119246",
            "77737706",
            &b"12345678901234567890123456789012"[..],
        ),
        (
            VaultAlgorithm::Sha512,
            "90693936",
            "47863826",
            &b"1234567890123456789012345678901234567890123456789012345678901234"[..],
        ),
    ];
    for (algorithm, first, last, seed) in cases {
        let entry = core
            .vault_save(VaultDraft {
                id: None,
                kind: VaultKind::Totp,
                label: "RFC 6238".into(),
                account: "".into(),
                issuer: "".into(),
                secret: Some(BASE32_NOPAD.encode(seed).into_bytes()),
                algorithm: Some(algorithm),
                digits: Some(8),
                period: Some(30),
            })
            .unwrap();
        assert_eq!(
            core.vault_reveal(&entry.id, 59).unwrap().value,
            first.as_bytes()
        );
        assert_eq!(
            core.vault_reveal(&entry.id, 20_000_000_000).unwrap().value,
            last.as_bytes()
        );
    }
}
