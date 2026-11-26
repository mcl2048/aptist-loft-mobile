use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use loft_core::{CoreState, HubAction, HubError};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const ORIGIN: &str = "https://hub.example";
const ISSUER: &str = "https://portal.example/api/idp";

fn discovery() -> Vec<u8> {
    json!({"version": 1, "product": "loft", "authMode": "portal_bff",
        "issuer": ISSUER, "modules": ["mail"]})
    .to_string()
    .into_bytes()
}

fn json_reply(
    core: &mut CoreState,
    request_id: u64,
    status: u32,
    body: Value,
) -> Result<loft_core::HubReceipt, HubError> {
    core.hub_finish(
        request_id,
        status,
        Some("application/json; charset=utf-8"),
        body.to_string().into_bytes(),
    )
}

fn prepare(core: &mut CoreState) {
    core.stage_server(ORIGIN.into()).unwrap();
    let request = core.hub_begin(HubAction::Discover, None, false).unwrap();
    assert_eq!(request.url, format!("{ORIGIN}/.well-known/loft-app"));
    assert_eq!(request.method, "GET");
    assert!(request.bearer.is_none() && request.body.is_empty());
    core.hub_finish(
        request.request_id,
        200,
        Some("application/json"),
        discovery(),
    )
    .unwrap();
}

fn start(core: &mut CoreState, mail_read: bool) -> Value {
    let had_session = core.hub_snapshot().session.is_some();
    let request = core.hub_begin(HubAction::SignIn, None, mail_read).unwrap();
    assert_eq!(request.url, format!("{ORIGIN}/v1/auth/portal/transactions"));
    assert_eq!(request.method, "POST");
    assert!(request.bearer.is_none());
    let body: Value = serde_json::from_slice(&request.body).unwrap();
    assert_eq!(body["mailRead"], mail_read);
    let url = format!("{ISSUER}/authorize?response_type=code&state=fixture");
    let receipt = json_reply(
        core,
        request.request_id,
        201,
        json!({
            "transactionId": URL_SAFE_NO_PAD.encode([1; 32]),
            "authorizationUrl": url,
            "expiresAt": 1_800_000_120u64,
            "expiresIn": 120
        }),
    )
    .unwrap();
    assert_eq!(receipt.browser_url.as_deref(), Some(url.as_str()));
    assert!(receipt.snapshot.transaction_pending);
    assert_eq!(receipt.snapshot.session.is_some(), had_session);
    body
}

fn completion(mail_read: bool, issuer: &str, expires_in: u32) -> Value {
    json!({
        "status": "complete", "sessionToken": URL_SAFE_NO_PAD.encode([2; 32]),
        "issuer": issuer, "subject": "person-fixture", "email": "member@example.test",
        "mailRead": mail_read, "expiresAt": 1_800_000_100u64, "expiresIn": expires_in
    })
}

#[test]
fn explicit_login_uses_independent_proof_and_redacted_receipts() {
    let mut core = CoreState::new();
    assert_eq!(
        core.hub_begin(HubAction::Discover, None, false).err(),
        Some(HubError::NoServer)
    );
    prepare(&mut core);
    let sign_in = start(&mut core, true);
    let first = core.hub_begin(HubAction::Complete, None, false).unwrap();
    assert!(first.url.ends_with("/complete") && first.bearer.is_none());
    let proof: Value = serde_json::from_slice(&first.body).unwrap();
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(proof["proof"].as_str().unwrap()));
    assert_eq!(sign_in["proofChallenge"], challenge);
    let receipt = json_reply(
        &mut core,
        first.request_id,
        202,
        json!({"status": "pending"}),
    )
    .unwrap();
    assert!(receipt.snapshot.transaction_pending && receipt.snapshot.session.is_none());
    let second = core.hub_begin(HubAction::Complete, None, false).unwrap();
    assert_eq!(first.body, second.body);
    let receipt = json_reply(
        &mut core,
        second.request_id,
        200,
        completion(true, ISSUER, 95),
    )
    .unwrap();
    assert!(!receipt.snapshot.transaction_pending && receipt.browser_url.is_none());
    let session = receipt.snapshot.session.unwrap();
    assert_eq!(session.subject, "person-fixture");
    assert_eq!(session.email.as_deref(), Some("member@example.test"));
    assert!(session.mail_access && session.expires_in_seconds <= 95);
    assert!(!format!("{:?}", core.hub_snapshot()).contains(&URL_SAFE_NO_PAD.encode([2; 32])));
}

#[test]
fn candidate_changes_invalidate_receipts_even_after_returning_to_old_origin() {
    let mut core = CoreState::new();
    prepare(&mut core);
    let discover = core.hub_begin(HubAction::Discover, None, false).unwrap();
    core.stage_server("different.example".into()).unwrap();
    core.stage_server(ORIGIN.into()).unwrap();
    let fresh = core.hub_begin(HubAction::Discover, None, false).unwrap();
    assert_ne!(fresh.request_id, discover.request_id);
    assert_ne!(fresh.generation, discover.generation);
    assert_eq!(
        core.hub_finish(
            discover.request_id,
            200,
            Some("application/json"),
            discovery()
        )
        .err(),
        Some(HubError::StaleRequest)
    );
    assert!(core.hub_snapshot().issuer.is_none());
    core.hub_finish(fresh.request_id, 200, Some("application/json"), discovery())
        .unwrap();
    assert_eq!(core.hub_snapshot().issuer.as_deref(), Some(ISSUER));
}

#[test]
fn mail_scope_is_explicit_and_a_late_mail_result_cannot_survive_logout() {
    let mut core = CoreState::new();
    prepare(&mut core);
    start(&mut core, false);
    let complete = core.hub_begin(HubAction::Complete, None, false).unwrap();
    json_reply(
        &mut core,
        complete.request_id,
        200,
        completion(false, ISSUER, 100),
    )
    .unwrap();
    assert_eq!(
        core.hub_begin(HubAction::MailInbox, None, false).err(),
        Some(HubError::MailConsentRequired)
    );

    start(&mut core, true);
    let complete = core.hub_begin(HubAction::Complete, None, false).unwrap();
    json_reply(
        &mut core,
        complete.request_id,
        200,
        completion(true, ISSUER, 100),
    )
    .unwrap();
    let mail = core.hub_begin(HubAction::MailInbox, None, false).unwrap();
    assert!(mail.url.ends_with("/v1/mail/messages?folder=inbox"));
    assert!(mail.bearer.is_some());
    let logout = core.hub_begin(HubAction::Logout, None, false).unwrap();
    assert_eq!(logout.bearer.as_deref(), mail.bearer.as_deref());
    assert!(core.hub_snapshot().session.is_none());
    assert_eq!(
        json_reply(&mut core, mail.request_id, 200, json!({"messages": []})).err(),
        Some(HubError::StaleRequest)
    );
    core.hub_finish(logout.request_id, 204, None, vec![])
        .unwrap();
    assert_eq!(
        core.hub_begin(HubAction::MailInbox, None, false).err(),
        Some(HubError::NotSignedIn)
    );
}

fn sign_in_for_mail(core: &mut CoreState) {
    prepare(core);
    start(core, true);
    let request = core.hub_begin(HubAction::Complete, None, false).unwrap();
    json_reply(core, request.request_id, 200, completion(true, ISSUER, 100)).unwrap();
}

#[test]
fn hub_browser_target_and_completed_issuer_must_match_discovery() {
    let mut core = CoreState::new();
    prepare(&mut core);
    let request = core.hub_begin(HubAction::SignIn, None, false).unwrap();
    let invalid_target = json!({
        "transactionId": URL_SAFE_NO_PAD.encode([1; 32]),
        "authorizationUrl": format!("{ISSUER}/authorize/alternate?response_type=code"),
        "expiresAt": 1_800_000_120u64,
        "expiresIn": 120
    });
    assert_eq!(
        json_reply(&mut core, request.request_id, 201, invalid_target).err(),
        Some(HubError::InvalidResponse)
    );
    assert!(!core.hub_snapshot().transaction_pending);
    start(&mut core, false);
    let request = core.hub_begin(HubAction::Complete, None, false).unwrap();
    assert_eq!(
        json_reply(
            &mut core,
            request.request_id,
            200,
            completion(false, "https://other.example/api/idp", 95)
        )
        .err(),
        Some(HubError::InvalidResponse)
    );
    assert!(core.hub_snapshot().session.is_none());
}

#[test]
fn inbox_cursor_and_attachment_are_bound_to_confirmed_folder_detail_and_size() {
    let mut core = CoreState::new();
    sign_in_for_mail(&mut core);
    let message_id = "a".repeat(64);
    let row = json!({
        "id": message_id, "from": "sender@example.test", "to":"member@example.test",
        "subject":"Subject", "receivedAt":"2026-11-26T12:00:00.000Z", "read":false,
        "folder":"inbox", "attachmentCount":1, "size":150
    });
    let cursor = URL_SAFE_NO_PAD.encode([3; 32]);
    let page_request = core.hub_begin(HubAction::MailInbox, None, false).unwrap();
    let page = json_reply(
        &mut core,
        page_request.request_id,
        200,
        json!({"messages": [row.clone()], "cursor":cursor}),
    )
    .unwrap()
    .page
    .unwrap();
    assert_eq!(page.messages.len(), 1);
    assert!(!page.messages[0].read);
    assert_eq!(page.cursor.as_deref(), Some(cursor.as_str()));
    assert_eq!(
        core.hub_begin(HubAction::MailTrash, Some(cursor.clone()), false)
            .err(),
        Some(HubError::InvalidInput)
    );
    let next = core
        .hub_begin(HubAction::MailInbox, Some(cursor.clone()), false)
        .unwrap();
    assert!(next.url.ends_with(&format!("folder=inbox&cursor={cursor}")));
    core.hub_abandon(next.request_id);

    let file = format!("{message_id}:0");
    assert_eq!(
        core.hub_begin(HubAction::MailAttachment, Some(file.clone()), false)
            .err(),
        Some(HubError::InvalidInput)
    );
    let message_request = core
        .hub_begin(HubAction::MailMessage, Some(message_id), false)
        .unwrap();
    let mut detail = row;
    detail["text"] = json!("你".repeat(7000));
    detail["truncated"] = json!(false);
    detail["attachments"] =
        json!([{"id":"0", "filename":"../report.txt", "mime":"text/plain", "size":3}]);
    let message = json_reply(
        &mut core,
        message_request.request_id,
        200,
        json!({"message":detail}),
    )
    .unwrap()
    .message
    .unwrap();
    assert!(!message.summary.read);
    assert!(message.truncated);
    assert_eq!(message.text.len(), 16_383);
    assert_eq!(message.attachments[0].filename, ".._report.txt");
    let attachment = core
        .hub_begin(HubAction::MailAttachment, Some(file.clone()), false)
        .unwrap();
    assert!(attachment.url.ends_with("/attachments/0"));
    assert_eq!(
        core.hub_finish(
            attachment.request_id,
            200,
            Some("application/octet-stream"),
            b"AB".to_vec()
        )
        .err(),
        Some(HubError::InvalidResponse)
    );
    let retry = core
        .hub_begin(HubAction::MailAttachment, Some(file), false)
        .unwrap();
    let receipt = core
        .hub_finish(
            retry.request_id,
            200,
            Some("application/octet-stream"),
            b"ABC".to_vec(),
        )
        .unwrap();
    assert_eq!(receipt.file.unwrap(), b"ABC");
}

#[test]
fn explicit_upstream_session_rejection_clears_mail_scope_and_cached_cursor() {
    let mut core = CoreState::new();
    sign_in_for_mail(&mut core);
    let generation = core.hub_snapshot().generation;
    let mail = core.hub_begin(HubAction::MailInbox, None, false).unwrap();
    assert_eq!(
        json_reply(
            &mut core,
            mail.request_id,
            401,
            json!({"error":"session_expired"})
        )
        .err(),
        Some(HubError::SessionExpired)
    );
    let snapshot = core.hub_snapshot();
    assert!(snapshot.generation > generation && snapshot.session.is_none());
}
