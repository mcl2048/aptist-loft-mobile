use loft_ffi::{AppCore, NotesDraft, ProtectionScope, SecureError, VaultError};

fn draft(title: &str, body: &str, tags: &str) -> NotesDraft {
    NotesDraft {
        id: None,
        title: title.into(),
        body: body.into(),
        icon: Some("📚".into()),
        tags: tags.into(),
        expected_version: None,
    }
}

#[test]
fn protection_fences_vault_and_notes_and_revokes_old_challenges() {
    let core = AppCore::new();
    assert_eq!(
        core.protection_configure(None, Some(b"12345x".to_vec()), false, 100),
        Err(SecureError::InvalidInput)
    );
    core.protection_configure(None, Some(b"052819".to_vec()), true, 100)
        .unwrap();
    assert_eq!(
        core.vault_list(false, 0, None).err(),
        Some(VaultError::AuthenticationFailed)
    );
    let vault = core.protection_begin(ProtectionScope::Vault, 100).unwrap();
    assert!(!vault.unlocked);
    core.protection_unlock_pin(vault.challenge.clone(), b"052819".to_vec(), 100)
        .unwrap();
    assert!(core.vault_list(false, 0, None).is_ok());
    let notes = core.protection_begin(ProtectionScope::Notes, 100).unwrap();
    assert_eq!(
        core.protection_unlock_biometric(vault.challenge, 100),
        Err(SecureError::Locked)
    );
    assert_eq!(
        core.notes_tags(notes.challenge.clone(), false).err(),
        Some(SecureError::Locked)
    );
    core.protection_unlock_biometric(notes.challenge.clone(), 100)
        .unwrap();
    assert!(
        core.notes_tags(notes.challenge.clone(), false)
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        core.vault_list(false, 0, None).err(),
        Some(VaultError::AuthenticationFailed)
    );
    core.protection_end(notes.challenge.clone()).unwrap();
    assert_eq!(
        core.notes_tags(notes.challenge, false).err(),
        Some(SecureError::Locked)
    );
}

#[test]
fn notes_persist_with_canonical_tags_and_reopen_throttled() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("loft.db");
    let path = file.to_str().unwrap().to_owned();
    let key = vec![72; 32];
    let core = AppCore::open_persistent(path.clone(), key.clone(), true).unwrap();
    let notes = core.protection_begin(ProtectionScope::Notes, 100).unwrap();
    assert!(notes.unlocked);
    let saved = core
        .notes_save(
            notes.challenge,
            draft("Notebook", "A private phrase", " Work|writing/work,计划 "),
            100,
        )
        .unwrap();
    assert_eq!(saved.tags, ["Work", "writing", "计划"]);
    core.protection_configure(None, Some(b"392587".to_vec()), false, 100)
        .unwrap();
    let scope = core.protection_begin(ProtectionScope::Notes, 100).unwrap();
    for _ in 0..5 {
        assert_eq!(
            core.protection_unlock_pin(scope.challenge.clone(), b"000000".to_vec(), 100),
            Err(SecureError::IncorrectPin)
        );
    }
    let deadline = core.protection_status().unwrap().retry_at.unwrap();
    drop(core);
    let disk = std::fs::read(&file).unwrap();
    assert!(
        !disk
            .windows(b"A private phrase".len())
            .any(|w| w == b"A private phrase")
    );
    let core = AppCore::open_persistent(path, key, false).unwrap();
    assert_eq!(core.protection_status().unwrap().retry_at, Some(deadline));
    let scope = core.protection_begin(ProtectionScope::Notes, 100).unwrap();
    assert_eq!(
        core.protection_unlock_biometric(scope.challenge.clone(), 100),
        Err(SecureError::Locked)
    );
    assert_eq!(
        core.protection_unlock_pin(scope.challenge.clone(), b"392587".to_vec(), 100),
        Err(SecureError::RateLimited)
    );
    core.protection_unlock_pin(scope.challenge.clone(), b"392587".to_vec(), deadline)
        .unwrap();
    let detail = core.notes_detail(scope.challenge, saved.id).unwrap();
    assert_eq!(detail.body, "A private phrase");
}

#[test]
fn search_archive_pagination_and_stale_edits_follow_notes_receipts() {
    let core = AppCore::new();
    let access = core.protection_begin(ProtectionScope::Notes, 100).unwrap();
    let lease = access.challenge;
    let saved = core
        .notes_save(
            lease.clone(),
            draft("March itinerary", "Reserve hotel", "TRAVEL|To do"),
            100,
        )
        .unwrap();
    let page = core
        .notes_list(
            lease.clone(),
            false,
            "itineray hotel".into(),
            Some("travel".into()),
            0,
            None,
        )
        .unwrap();
    assert_eq!(page.entries.len(), 1);
    let mut edited = draft("New itinerary", "Keep hotel", "Travel");
    edited.id = Some(saved.id.clone());
    edited.expected_version = Some(saved.version);
    let edited_version = core.notes_save(lease.clone(), edited, 101).unwrap().version;
    let mut stale = draft("Stale", "outdated", "Travel");
    stale.id = Some(saved.id.clone());
    stale.expected_version = Some("wrong".into());
    assert_eq!(
        core.notes_save(lease.clone(), stale, 101).err(),
        Some(SecureError::Conflict)
    );
    core.notes_archive(lease.clone(), saved.id.clone(), true, 102)
        .unwrap();
    assert_eq!(
        core.notes_list(
            lease.clone(),
            false,
            String::new(),
            None,
            0,
            Some(page.generation)
        )
        .err(),
        Some(SecureError::StaleGeneration)
    );
    let archived = core.notes_detail(lease.clone(), saved.id.clone()).unwrap();
    assert!(archived.summary.archived);
    assert_ne!(archived.summary.version, edited_version);
    assert_eq!(core.notes_tags(lease.clone(), true).unwrap()[0].count, 1);
    core.notes_delete(lease.clone(), saved.id.clone()).unwrap();
    assert_eq!(
        core.notes_detail(lease, saved.id).err(),
        Some(SecureError::NotFound)
    );
}
