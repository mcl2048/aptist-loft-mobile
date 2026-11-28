use loft_ffi::{AppCore, HubAction, HubRequest, NotesDraft, ProtectionScope, SecureError};
use serde_json::{Value, json};

fn reply(core: &AppCore, request: HubRequest, status: u32, body: Value) {
    core.hub_finish(
        request.request_id,
        status,
        Some("application/json".into()),
        serde_json::to_vec(&body).unwrap(),
    )
    .unwrap();
}

fn login(core: &AppCore, subject: &str, modules: &[&str]) {
    core.stage_server("https://notes.example".into()).unwrap();
    let request = core.hub_begin(HubAction::Discover, None, false).unwrap();
    assert_eq!(
        request.requested_capabilities.as_deref(),
        Some("notes-sync/1")
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
