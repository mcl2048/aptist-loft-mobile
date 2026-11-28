use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use worker::{D1Database, Method, Request, Response};

use super::http::{self, CONFLICT, INVALID, NOT_FOUND, Result, SESSION, UNAVAILABLE};
use super::{Config, MailPermit, first, first_col, number, vault};

thread_local! {
    static REQUESTS: std::cell::Cell<u8> = const { std::cell::Cell::new(0) };
}

#[derive(Deserialize)]
struct Read {
    revision: Option<u32>,
    ciphertext: Option<String>,
    key_epoch: Option<String>,
}

#[derive(Serialize)]
struct Entry {
    revision: u32,
    ciphertext: String,
    #[serde(rename = "keyEpoch", skip_serializing_if = "Option::is_none")]
    key_epoch: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Write {
    base_revision: u32,
    ciphertext: String,
    key_epoch: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Reset {
    base_revision: u32,
    ciphertext: String,
    operation_id: String,
}

pub(super) async fn access(
    config: &Config,
    db: &D1Database,
    request: &mut Request,
) -> Result<Response> {
    let hash = super::bearer_hash(config, request)?;
    let _permit = MailPermit::acquire(&REQUESTS, 4)?;
    if request.method() == Method::Get {
        return read(db, request, &hash).await;
    }
    require_device(db, &hash).await?;
    let put: Write = http::input_bounded(request, vault::JSON_LIMIT).await?;
    vault::check_upload(put.base_revision, &put.ciphertext)?;
    if put
        .key_epoch
        .as_deref()
        .is_some_and(|epoch| !valid_epoch(epoch))
    {
        return Err(INVALID);
    }
    let revision: Option<u32> = first_col(
        db,
        include_str!("../sql/notes_write.sql"),
        "revision",
        &[
            hash.clone().into(),
            number(put.base_revision.into()),
            put.ciphertext.into(),
            put.key_epoch
                .map_or(wasm_bindgen::JsValue::NULL, Into::into),
        ],
    )
    .await?;
    match revision {
        Some(revision) => http::json(200, &serde_json::json!({"revision": revision})),
        None => {
            require_device(db, &hash).await?;
            Err(CONFLICT)
        }
    }
}

pub(super) async fn reset(
    config: &Config,
    db: &D1Database,
    request: &mut Request,
) -> Result<Response> {
    let hash = super::bearer_hash(config, request)?;
    let _permit = MailPermit::acquire(&REQUESTS, 4)?;
    require_device(db, &hash).await?;
    let reset: Reset = http::input_bounded(request, vault::JSON_LIMIT).await?;
    if !valid_epoch(&reset.operation_id) {
        return Err(INVALID);
    }
    vault::check_upload(reset.base_revision, &reset.ciphertext)?;
    let fingerprint = crate::digest(&reset.ciphertext);
    let mut revision: Option<u32> = first_col(
        db,
        include_str!("../sql/notes_reset.sql"),
        "revision",
        &[
            hash.clone().into(),
            number(reset.base_revision.into()),
            reset.ciphertext.into(),
            reset.operation_id.clone().into(),
            fingerprint.clone().into(),
        ],
    )
    .await?;
    if revision.is_none() {
        revision = first_col(
            db,
            include_str!("../sql/notes_reset_receipt.sql"),
            "reset_revision",
            &[
                hash.clone().into(),
                reset.operation_id.clone().into(),
                number(reset.base_revision.into()),
                fingerprint.into(),
            ],
        )
        .await?;
    }
    let Some(revision) = revision else {
        require_device(db, &hash).await?;
        return Err(CONFLICT);
    };
    http::json(
        200,
        &serde_json::json!({
            "revision": revision, "operationId": reset.operation_id
        }),
    )
}

fn valid_epoch(epoch: &str) -> bool {
    let mut decoded = [0; 16];
    epoch.len() == 22 && URL_SAFE_NO_PAD.decode_slice(epoch, &mut decoded) == Ok(16)
}

async fn require_device(db: &D1Database, hash: &str) -> Result<()> {
    let present: Option<String> = first_col(
        db,
        "SELECT session_hash FROM hub_device_session WHERE session_hash = ?1",
        "session_hash",
        &[hash.into()],
    )
    .await?;
    present.map(|_| ()).ok_or(SESSION)
}

async fn read(db: &D1Database, request: &Request, hash: &str) -> Result<Response> {
    let known = request
        .headers()
        .get("If-None-Match")
        .map_err(|_| INVALID)?;
    let known = known.as_deref().map(parse_tag).transpose()?.unwrap_or(0);
    let current: Read = first(
        db,
        include_str!("../sql/notes_read.sql"),
        &[hash.into(), number(known.into())],
    )
    .await?
    .ok_or(SESSION)?;
    let revision = current.revision.ok_or(NOT_FOUND)?;
    let mut response = match current.ciphertext {
        Some(ciphertext) => http::json(
            200,
            &Entry {
                revision,
                ciphertext,
                key_epoch: current.key_epoch,
            },
        )?,
        None if revision == known => http::empty(304)?,
        None => return Err(UNAVAILABLE),
    };
    response
        .headers_mut()
        .set("ETag", &format!("\"{revision}\""))
        .map_err(|_| UNAVAILABLE)?;
    Ok(response)
}

fn parse_tag(value: &str) -> Result<u32> {
    let decimal = value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .ok_or(INVALID)?;
    if decimal.starts_with('0') || !decimal.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(INVALID);
    }
    decimal.parse().map_err(|_| INVALID)
}
