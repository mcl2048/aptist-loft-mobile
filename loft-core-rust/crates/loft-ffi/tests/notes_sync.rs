use loft_ffi::{AppCore, HubAction, HubRequest, NotesDraft, ProtectionScope, SecureError};
use serde_json::{Value, json};

fn reply(core: &AppCore, request: HubRequest, status: u32, body: Value) {
    let media = Some("application/json".into());
    let bytes = serde_json::to_vec(&body).unwrap();
    let receipt = core
        .hub_finish(request.request_id, status, media.clone(), bytes.clone())
        .unwrap();
    if let Some(next) = receipt.next_request {
        assert_eq!(next.requested_capabilities.as_deref(), Some("notes-sync/1"));
        core.hub_finish(next.request_id, status, media, bytes)
            .unwrap();
    }
}

fn login(core: &AppCore, subject: &str, modules: &[&str]) {
    core.stage_server("https://notes.example".into()).unwrap();
    let request = core.hub_begin(HubAction::Discover, None, false).unwrap();
    assert_eq!(
        request.requested_capabilities.as_deref(),
        Some("notes-sync/2")
    );
    reply(
        core,
        request,
        200,
        json!({"version":1,"product":"loft","authMode":"portal_bff",
        "issuer":"https://identity.example/api/idp","modules":modules}),
    );
    let request = core.hub_begin(HubAction::SignIn, None, false).unwrap();
    reply(
        core,
        request,
        201,
        json!({
            "transactionId":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE",
            "authorizationUrl":"https://identity.example/api/idp/authorize?state=test",
            "expiresAt":1_800_000_120u64,"expiresIn":120
        }),
    );
    let request = core.hub_begin(HubAction::Complete, None, false).unwrap();
    reply(
        core,
        request,
        200,
        json!({
            "status":"complete", "sessionToken":"AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI",
            "issuer":"https://identity.example/api/idp","subject":subject,"mailRead":false,
            "expiresAt":0,"expiresIn":0,"durable":true
        }),
    );
}

fn save(core: &AppCore, lease: &str, title: &str) -> String {
    core.notes_save(
        lease.into(),
        NotesDraft {
            id: None,
            title: title.into(),
            body: "Confidential phrase".into(),
            icon: None,
            tags: String::new(),
            expected_version: None,
        },
        100,
    )
    .unwrap()
    .id
}

fn exchange(core: &AppCore, revision: &mut u32, ciphertext: &mut Option<Value>) {
    let get = core.notes_sync_begin().unwrap().unwrap();
    assert!(get.url.ends_with("/v1/notes"));
    let expected = format!("\"{}\"", revision);
    let current = match ciphertext {
        Some(_) if get.if_none_match.as_deref() == Some(expected.as_str()) => (304, Vec::new()),
        Some(body) => (
            200,
            serde_json::to_vec(&json!({"revision": revision, "ciphertext": body})).unwrap(),
        ),
        None => (404, br#"{"error":"not_found"}"#.to_vec()),
    };
    let content_type = (current.0 != 304).then(|| "application/json".into());
    let step = core
        .notes_sync_finish(get.request_id, current.0, content_type, current.1)
        .unwrap();
    if let Some(put) = step.next_request {
        let body: Value = serde_json::from_slice(&put.body).unwrap();
        assert_eq!(put.method, "PUT");
        assert_eq!(body["baseRevision"].as_u64(), Some(u64::from(*revision)));
        assert!(!body.to_string().contains("Confidential phrase"));
        *ciphertext = Some(body["ciphertext"].clone());
        *revision += 1;
        core.notes_sync_finish(
            put.request_id,
            200,
            Some("application/json".into()),
            serde_json::to_vec(&json!({"revision": revision})).unwrap(),
        )
        .unwrap();
    }
}

#[test]
fn offline_edits_merge_and_deletion_wins_while_scope_changes_hide_cloud_notes() {
    let a = AppCore::new();
    let b = AppCore::new();
    login(&a, "same-user", &["mail", "notes_sync"]);
    login(&b, "same-user", &["notes_sync"]);
    let a_lease = a
        .protection_begin(ProtectionScope::Notes, 100)
        .unwrap()
        .challenge;
    let b_lease = b
        .protection_begin(ProtectionScope::Notes, 100)
        .unwrap()
        .challenge;
    let code = a
        .notes_sync_configure(a_lease.clone(), None)
        .unwrap()
        .unwrap();
    assert_eq!(code.len(), 43);
    b.notes_sync_configure(b_lease.clone(), Some(code.into_bytes()))
        .unwrap();
    let id = save(&a, &a_lease, "First note");
    let second = save(&b, &b_lease, "Second note");
    let mut revision = 0;
    let mut ciphertext = None;
    exchange(&a, &mut revision, &mut ciphertext);
    exchange(&b, &mut revision, &mut ciphertext);
    assert_eq!(revision, 2);
    assert!(b.notes_detail(b_lease.clone(), id.clone()).is_ok());
    a.notes_delete(a_lease.clone(), id.clone()).unwrap();
    exchange(&a, &mut revision, &mut ciphertext);
    exchange(&b, &mut revision, &mut ciphertext);
    assert_eq!(revision, 3);
    assert_eq!(
        b.notes_detail(b_lease.clone(), id).err(),
        Some(SecureError::NotFound)
    );
    assert!(a.notes_detail(a_lease, second.clone()).is_ok());

    b.hub_clear().unwrap();
    assert_eq!(
        b.notes_detail(b_lease, second.clone()).err(),
        Some(SecureError::Locked)
    );
    login(&b, "different-user", &["notes_sync"]);
    let lease = b
        .protection_begin(ProtectionScope::Notes, 100)
        .unwrap()
        .challenge;
    assert_eq!(
        b.notes_detail(lease, second).err(),
        Some(SecureError::NotFound)
    );
    assert!(b.notes_sync_begin().unwrap().is_none());
}

#[test]
fn local_edits_fence_in_flight_sync_and_legacy_profile_stays_local() {
    let core = AppCore::new();
    login(&core, "same-user", &["mail"]);
    let lease = core
        .protection_begin(ProtectionScope::Notes, 100)
        .unwrap()
        .challenge;
    let local = save(&core, &lease, "Local owner");
    assert!(core.notes_sync_begin().unwrap().is_none());
    assert_eq!(
        core.notes_sync_configure(lease, None).err(),
        Some(SecureError::Unsupported)
    );
    core.hub_clear().unwrap();
    login(&core, "same-user", &["notes_sync"]);
    let lease = core
        .protection_begin(ProtectionScope::Notes, 100)
        .unwrap()
        .challenge;
    core.notes_sync_configure(lease.clone(), None).unwrap();
    let get = core.notes_sync_begin().unwrap().unwrap();
    save(&core, &lease, "Later local change");
    assert_eq!(
        core.notes_sync_finish(
            get.request_id,
            404,
            Some("application/json".into()),
            br#"{"error":"not_found"}"#.to_vec()
        )
        .err(),
        Some(SecureError::StaleGeneration),
    );
    assert!(core.notes_detail(lease, local).is_ok());
    assert!(core.notes_sync_begin().unwrap().is_some());
}

#[test]
fn rediscovering_an_added_notes_capability_keeps_the_durable_login() {
    let core = AppCore::new();
    login(&core, "same-user", &["mail"]);
    let request = core.hub_begin(HubAction::Discover, None, false).unwrap();
    reply(
        &core,
        request,
        200,
        json!({"version":1,"product":"loft","authMode":"portal_bff",
        "issuer":"https://identity.example/api/idp","modules":["mail","notes_sync"]}),
    );
    let lease = core
        .protection_begin(ProtectionScope::Notes, 100)
        .unwrap()
        .challenge;
    assert!(core.notes_sync_status(lease).unwrap().available);
}

#[test]
fn enrollment_keeps_existing_guest_notes_on_the_device() {
    let a = AppCore::new();
    let b = AppCore::new();
    let guest = a
        .protection_begin(ProtectionScope::Notes, 100)
        .unwrap()
        .challenge;
    let local = save(&a, &guest, "Guest notebook");
    login(&a, "same-user", &["notes_sync"]);
    login(&b, "same-user", &["notes_sync"]);
    let a_lease = a
        .protection_begin(ProtectionScope::Notes, 100)
        .unwrap()
        .challenge;
    let b_lease = b
        .protection_begin(ProtectionScope::Notes, 100)
        .unwrap()
        .challenge;
    let code = a
        .notes_sync_configure(a_lease.clone(), None)
        .unwrap()
        .unwrap();
    b.notes_sync_configure(b_lease.clone(), Some(code.into_bytes()))
        .unwrap();
    let paired = save(&a, &a_lease, "Paired notebook");
    let mut revision = 0;
    let mut ciphertext = None;
    exchange(&a, &mut revision, &mut ciphertext);
    exchange(&b, &mut revision, &mut ciphertext);
    assert_eq!(
        b.notes_detail(b_lease.clone(), local.clone()).err(),
        Some(SecureError::NotFound)
    );
    assert!(b.notes_detail(b_lease, paired.clone()).is_ok());
    a.notes_sync_disable(a_lease.clone()).unwrap();
    let paused = save(&a, &a_lease, "Paused notebook");
    assert!(!a.notes_sync_eligible());
    a.notes_sync_configure(a_lease, None).unwrap();
    exchange(&a, &mut revision, &mut ciphertext);
    let b_lease = b
        .protection_begin(ProtectionScope::Notes, 100)
        .unwrap()
        .challenge;
    exchange(&b, &mut revision, &mut ciphertext);
    assert_eq!(
        b.notes_detail(b_lease, paused.clone()).err(),
        Some(SecureError::NotFound)
    );
    a.hub_clear().unwrap();
    let guest = a
        .protection_begin(ProtectionScope::Notes, 100)
        .unwrap()
        .challenge;
    assert!(a.notes_detail(guest.clone(), local).is_ok());
    assert!(a.notes_detail(guest.clone(), paused).is_ok());
    assert_eq!(
        a.notes_detail(guest, paired).err(),
        Some(SecureError::NotFound)
    );
}

#[test]
fn concurrent_edits_to_one_note_keep_each_device_copy() {
    let a = AppCore::new();
    let b = AppCore::new();
    login(&a, "same-user", &["notes_sync"]);
    login(&b, "same-user", &["notes_sync"]);
    let a_lease = a
        .protection_begin(ProtectionScope::Notes, 100)
        .unwrap()
        .challenge;
    let b_lease = b
        .protection_begin(ProtectionScope::Notes, 100)
        .unwrap()
        .challenge;
    let code = a
        .notes_sync_configure(a_lease.clone(), None)
        .unwrap()
        .unwrap();
    b.notes_sync_configure(b_lease.clone(), Some(code.into_bytes()))
        .unwrap();
    let id = save(&a, &a_lease, "Shared before edits");
    let mut revision = 0;
    let mut ciphertext = None;
    exchange(&a, &mut revision, &mut ciphertext);
    exchange(&b, &mut revision, &mut ciphertext);
    for (core, lease, title) in [(&a, &a_lease, "Edited on A"), (&b, &b_lease, "Edited on B")] {
        let version = core
            .notes_detail(lease.clone(), id.clone())
            .unwrap()
            .summary
            .version;
        core.notes_save(
            lease.clone(),
            NotesDraft {
                id: Some(id.clone()),
                expected_version: Some(version),
                title: title.into(),
                body: "Confidential phrase".into(),
                icon: None,
                tags: String::new(),
            },
            100,
        )
        .unwrap();
    }
    exchange(&a, &mut revision, &mut ciphertext);
    let get = b.notes_sync_begin().unwrap().unwrap();
    let result = b.notes_sync_finish(
        get.request_id,
        200,
        Some("application/json".into()),
        serde_json::to_vec(&json!({"revision":revision,"ciphertext":ciphertext})).unwrap(),
    );
    assert_eq!(result.err(), Some(SecureError::Conflict));
    assert_eq!(
        b.notes_detail(b_lease, id.clone()).unwrap().summary.title,
        "Edited on B"
    );
    assert_eq!(
        a.notes_detail(a_lease, id).unwrap().summary.title,
        "Edited on A"
    );
}

fn reply_notes(
    core: &AppCore,
    request: &HubRequest,
    status: u32,
    body: Value,
) -> loft_ffi::NotesSyncStep {
    core.notes_sync_finish(
        request.request_id,
        status,
        Some("application/json".into()),
        serde_json::to_vec(&body).unwrap(),
    )
    .unwrap()
}

#[test]
fn staged_rotation_replays_identical_ciphertext_after_sqlcipher_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("notes.db").to_string_lossy().into_owned();
    let key = vec![38; 32];
    let core = AppCore::open_persistent(path.clone(), key.clone(), true).unwrap();
    login(&core, "same-user", &["mail", "notes_sync", "notes_reset"]);
    let lease = core
        .protection_begin(ProtectionScope::Notes, 100)
        .unwrap()
        .challenge;
    let old_code = core
        .notes_sync_configure(lease.clone(), None)
        .unwrap()
        .unwrap();
    let note = save(&core, &lease, "Kept during rotation");
    let mut revision = 0;
    let mut ciphertext = None;
    exchange(&core, &mut revision, &mut ciphertext);
    core.notes_sync_reset(lease.clone(), false).unwrap();
    assert!(core.notes_sync_status(lease.clone()).unwrap().reset_pending);
    assert!(core.notes_sync_recovery_code(lease).unwrap().is_none());
    let get = core.notes_sync_begin().unwrap().unwrap();
    assert!(get.if_none_match.is_none());
    let post = reply_notes(
        &core,
        &get,
        200,
        json!({"revision":revision,"ciphertext":ciphertext}),
    )
    .next_request
    .unwrap();
    assert!(post.url.ends_with("/v1/notes/reset"));
    let reset: Value = serde_json::from_slice(&post.body).unwrap();
    assert_eq!(reset["baseRevision"], 1);
    drop(core);
    let core = AppCore::open_persistent(path, key, false).unwrap();
    let lease = core
        .protection_begin(ProtectionScope::Notes, 100)
        .unwrap()
        .challenge;
    let resumed = core.notes_sync_begin().unwrap().unwrap();
    assert_eq!(resumed.body, post.body);
    let ack = reply_notes(
        &core,
        &resumed,
        200,
        json!({"revision":2,"operationId":reset["operationId"]}),
    );
    assert!(ack.reset_completed);
    assert_eq!(
        core.notes_detail(lease.clone(), note.clone())
            .unwrap()
            .summary
            .title,
        "Kept during rotation"
    );
    let code = core.notes_sync_recovery_code(lease).unwrap().unwrap();
    assert_ne!(old_code, code);
    let peer = AppCore::new();
    login(&peer, "same-user", &["notes_sync", "notes_reset"]);
    let peer_lease = peer
        .protection_begin(ProtectionScope::Notes, 100)
        .unwrap()
        .challenge;
    peer.notes_sync_configure(peer_lease.clone(), Some(old_code.into_bytes()))
        .unwrap();
    let remote =
        json!({"revision":2,"ciphertext":reset["ciphertext"],"keyEpoch":reset["operationId"]});
    let get = peer.notes_sync_begin().unwrap().unwrap();
    assert!(reply_notes(&peer, &get, 200, remote.clone()).needs_recovery);
    assert!(!peer.notes_sync_eligible());
    peer.notes_sync_configure(peer_lease.clone(), Some(code.into_bytes()))
        .unwrap();
    let get = peer.notes_sync_begin().unwrap().unwrap();
    assert!(reply_notes(&peer, &get, 200, remote).next_request.is_none());
    assert_eq!(
        peer.notes_detail(peer_lease, note).unwrap().summary.title,
        "Kept during rotation"
    );
}

#[test]
fn reset_wipe_waits_for_exact_receipt_and_keeps_later_local_edits() {
    let core = AppCore::new();
    login(&core, "same-user", &["notes_sync", "notes_reset"]);
    let lease = core
        .protection_begin(ProtectionScope::Notes, 100)
        .unwrap()
        .challenge;
    let wipe = save(&core, &lease, "Erase after acknowledgement");
    let preserve = save(&core, &lease, "Preserve subsequent modification");
    core.notes_sync_reset(lease.clone(), true).unwrap();
    let current = core
        .notes_detail(lease.clone(), preserve.clone())
        .unwrap()
        .summary;
    core.notes_save(
        lease.clone(),
        NotesDraft {
            id: Some(preserve.clone()),
            expected_version: Some(current.version),
            title: "Edited after confirmation".into(),
            body: "Unaffected".into(),
            icon: None,
            tags: String::new(),
        },
        101,
    )
    .unwrap();
    let get = core.notes_sync_begin().unwrap().unwrap();
    let post = reply_notes(&core, &get, 404, json!({"error":"not_found"}))
        .next_request
        .unwrap();
    let reset: Value = serde_json::from_slice(&post.body).unwrap();
    assert!(core.notes_detail(lease.clone(), wipe.clone()).is_ok());
    let wrong = core.notes_sync_finish(
        post.request_id,
        200,
        Some("application/json".into()),
        serde_json::to_vec(&json!({"revision":2,"operationId":reset["operationId"]})).unwrap(),
    );
    assert_eq!(wrong.err(), Some(SecureError::InvalidInput));
    assert!(core.notes_detail(lease.clone(), wipe.clone()).is_ok());
    let retry = core.notes_sync_begin().unwrap().unwrap();
    assert_eq!(retry.body, post.body);
    assert!(
        reply_notes(
            &core,
            &retry,
            200,
            json!({"revision":1,"operationId":reset["operationId"]})
        )
        .reset_completed
    );
    assert_eq!(
        core.notes_detail(lease.clone(), wipe).err(),
        Some(SecureError::NotFound)
    );
    assert_eq!(
        core.notes_detail(lease, preserve).unwrap().summary.title,
        "Edited after confirmation"
    );
}

#[test]
fn ordinary_durable_login_survives_legacy_descriptor_fallback() {
    let core = AppCore::new();
    login(&core, "same-user", &["notes_sync"]);
    let request = core.hub_begin(HubAction::Discover, None, false).unwrap();
    let next = core
        .hub_finish(
            request.request_id,
            200,
            Some("application/json".into()),
            serde_json::to_vec(
                &json!({"version":1,"product":"loft","authMode":"portal_bff",
            "issuer":"https://identity.example/api/idp","modules":[]}),
            )
            .unwrap(),
        )
        .unwrap()
        .next_request
        .unwrap();
    assert_eq!(next.requested_capabilities.as_deref(), Some("notes-sync/1"));
    let snapshot = core
        .hub_finish(
            next.request_id,
            200,
            Some("application/json".into()),
            serde_json::to_vec(
                &json!({"version":1,"product":"loft","authMode":"portal_bff",
            "issuer":"https://identity.example/api/idp","modules":["notes_sync"]}),
            )
            .unwrap(),
        )
        .unwrap()
        .snapshot;
    let session = snapshot.session.unwrap();
    assert!(session.durable);
    assert!(!session.mail_access);
    let lease = core
        .protection_begin(ProtectionScope::Notes, 100)
        .unwrap()
        .challenge;
    assert!(core.notes_sync_status(lease).unwrap().available);
}
