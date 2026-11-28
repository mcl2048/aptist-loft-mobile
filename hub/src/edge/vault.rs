use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Deserialize;
use worker::{D1Database, Method, Request, Response};

use super::http::{self, CONFLICT, INVALID, NOT_FOUND, Result, SESSION, TOO_LARGE};
use super::{Config, MailPermit, device, first, first_col, number};
use crate::opaque_token;

const CIPHERTEXT_LIMIT: usize = 256 * 1024;
const JSON_LIMIT: usize = 350 * 1024;

thread_local! {
    static REQUESTS: std::cell::Cell<u8> = const { std::cell::Cell::new(0) };
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(super) struct Put {
    pub(super) base_revision: u32,
    pub(super) ciphertext: String,
}

#[derive(Deserialize, serde::Serialize)]
struct Entry {
    revision: u32,
    ciphertext: String,
}

pub(super) async fn access(
    config: &Config,
    db: &D1Database,
    request: &mut Request,
    id: &str,
) -> Result<Response> {
    if !opaque_token(id) {
        return Err(INVALID);
    }
    let hash = super::bearer_hash(config, request)?;
    let _permit = MailPermit::acquire(&REQUESTS, 4)?;
    if request.method() == Method::Get {
        let current: Option<Entry> = first(
            db,
            include_str!("../sql/vault_read.sql"),
            &[hash.clone().into(), id.into()],
        )
        .await?;
        return match current {
            Some(entry) => http::json(200, &entry),
            None if device::find(db, &hash).await?.is_some() => Err(NOT_FOUND),
            None => Err(SESSION),
        };
    }
    if device::find(db, &hash).await?.is_none() {
        return Err(SESSION);
    }
    let put = read_upload(request).await?;
    let result: Option<u32> = first_col(
        db,
        include_str!("../sql/vault_write.sql"),
        "revision",
        &[
            hash.clone().into(),
            id.into(),
            number(put.base_revision.into()),
            put.ciphertext.into(),
            number(8),
        ],
    )
    .await?;
    match result {
        Some(revision) => http::json(200, &serde_json::json!({"revision": revision})),
        None if device::find(db, &hash).await?.is_some() => Err(CONFLICT),
        None => Err(SESSION),
    }
}

pub(super) async fn read_upload(request: &mut Request) -> Result<Put> {
    let put: Put = http::input_bounded(request, JSON_LIMIT).await?;
    if put.base_revision == u32::MAX {
        return Err(CONFLICT);
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(&put.ciphertext)
        .map_err(|_| INVALID)?;
    if decoded.len() > CIPHERTEXT_LIMIT {
        return Err(TOO_LARGE);
    }
    if decoded.len() < 16 {
        return Err(INVALID);
    }
    Ok(put)
}
