use serde::{Deserialize, Serialize};
use url::form_urlencoded;
use worker::{AbortSignal, Response};

use super::http::{self, INVALID, Result, TOO_LARGE, UNAVAILABLE};
use super::{
    Config,
    portal::{self, Session},
};
use crate::{MAX_MAIL_BYTES, mail_text, opaque_token, preview};

const ATTACHMENT_BYTES: usize = 2 * 1024 * 1024;
const PREVIEW_BYTES: usize = 128 * 1024;
const MAX_MIME_PARTS: usize = 100;

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct Summary {
    id: String,
    from: String,
    to: String,
    subject: String,
    received_at: String,
    read: bool,
    folder: String,
    attachment_count: u32,
    size: u32,
}

#[derive(Deserialize, Serialize)]
struct Attachment {
    id: String,
    filename: String,
    mime: String,
    size: u32,
}

#[derive(Deserialize)]
struct PortalPage {
    sub: String,
    messages: Vec<Summary>,
    cursor: Option<String>,
}

#[derive(Deserialize)]
struct PortalMessage {
    sub: String,
    message: PortalDetail,
}

#[derive(Deserialize)]
struct PortalDetail {
    #[serde(flatten)]
    summary: Summary,
    text: String,
    html: String,
    attachments: Vec<Attachment>,
}

#[derive(Serialize)]
struct Detail {
    #[serde(flatten)]
    summary: Summary,
    text: String,
    truncated: bool,
    attachments: Vec<Attachment>,
}

pub(super) async fn list(
    config: &Config,
    session: &Session,
    query: &str,
    signal: &AbortSignal,
) -> Result<Response> {
    if query.len() > 256 {
        return Err(INVALID);
    }
    let (mut folder, mut cursor) = (None, None);
    for (name, value) in form_urlencoded::parse(query.as_bytes()) {
        let slot = match name.as_ref() {
            "folder" if matches!(value.as_ref(), "inbox" | "trash") => &mut folder,
            "cursor" if opaque_token(&value) => &mut cursor,
            _ => return Err(INVALID),
        };
        if slot.replace(value).is_some() {
            return Err(INVALID);
        }
    }
    let folder = folder.as_deref().unwrap_or("inbox");
    let mut path = format!("/mail?folder={folder}&limit=20");
    if let Some(cursor) = cursor {
        path.push_str("&cursor=");
        path.push_str(&cursor);
    }
    let mut page: PortalPage = portal::get(
        config,
        &path,
        Some(&session.portal_access),
        512 * 1024,
        signal,
    )
    .await?;
    if page.sub != session.subject
        || page.messages.len() > 20
        || page.cursor.as_deref().is_some_and(|c| !opaque_token(c))
    {
        return Err(UNAVAILABLE);
    }
    for row in &mut page.messages {
        if row.folder != folder {
            return Err(UNAVAILABLE);
        }
        normalize_summary(row)?;
    }
    let mut result = serde_json::json!({"messages": page.messages});
    if let Some(cursor) = page.cursor {
        result["cursor"] = cursor.into();
    }
    http::json(200, &result)
}

pub(super) async fn detail(
    config: &Config,
    session: &Session,
    id: &str,
    content: bool,
    signal: &AbortSignal,
) -> Result<Response> {
    if !message_id(id) {
        return Err(INVALID);
    }
    let result: PortalMessage = portal::get(
        config,
        &format!("/mail/{id}"),
        Some(&session.portal_access),
        MAX_MAIL_BYTES,
        signal,
    )
    .await?;
    if result.sub != session.subject || result.message.summary.id != id {
        return Err(UNAVAILABLE);
    }
    let PortalDetail {
        mut summary,
        text,
        html,
        mut attachments,
    } = result.message;
    if attachments.len() > MAX_MIME_PARTS || attachments.len() != summary.attachment_count as usize
    {
        return Err(UNAVAILABLE);
    }
    normalize_summary(&mut summary)?;
    for attachment in &mut attachments {
        if !attachment_id(&attachment.id)
            || attachment.size as usize > ATTACHMENT_BYTES
            || attachment.mime.len() > 200
        {
            return Err(UNAVAILABLE);
        }
        attachment.filename = preview(&attachment.filename, 512).0;
    }
    let text = mail_text(&text, &html).map_err(|_| TOO_LARGE)?;
    if content {
        let headers = http::headers()?;
        headers
            .set("Content-Type", "text/plain; charset=utf-8")
            .map_err(|_| UNAVAILABLE)?;
        headers
            .set(
                "Content-Disposition",
                "attachment; filename=\"message.txt\"",
            )
            .map_err(|_| UNAVAILABLE)?;
        headers
            .set("Content-Length", &text.len().to_string())
            .map_err(|_| UNAVAILABLE)?;
        return Response::from_bytes(text.into_bytes())
            .map(|response| response.with_headers(headers))
            .map_err(|_| UNAVAILABLE);
    }
    let (text, truncated) = preview(&text, PREVIEW_BYTES);
    http::json(
        200,
        &serde_json::json!({"message": Detail { summary, text, truncated, attachments }}),
    )
}

pub(super) async fn attachment(
    config: &Config,
    session: &Session,
    id: &str,
    part: &str,
    signal: &AbortSignal,
) -> Result<Response> {
    if !message_id(id) || !attachment_id(part) {
        return Err(INVALID);
    }
    let mut source = portal::get_raw(
        config,
        &format!("/mail/{id}/attachments/{part}"),
        Some(&session.portal_access),
        signal,
    )
    .await?;
    let headers = source.headers();
    if headers
        .get("Content-Type")
        .map_err(|_| UNAVAILABLE)?
        .as_deref()
        != Some("application/octet-stream")
    {
        return Err(UNAVAILABLE);
    }
    let length = headers
        .get("Content-Length")
        .map_err(|_| UNAVAILABLE)?
        .and_then(|length| length.parse::<usize>().ok())
        .ok_or(UNAVAILABLE)?;
    if length > ATTACHMENT_BYTES {
        return Err(TOO_LARGE);
    }
    let disposition = headers
        .get("Content-Disposition")
        .map_err(|_| UNAVAILABLE)?
        .filter(|value| {
            value.len() <= 2048
                && value
                    .strip_prefix("attachment; filename=\"attachment\"; filename*=UTF-8''")
                    .is_some_and(|suffix| {
                        suffix
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b"%!~_.-".contains(&b))
                    })
        })
        .unwrap_or_else(|| "attachment; filename=\"attachment\"".into());
    let body =
        http::read_chunks(source.stream().map_err(|_| UNAVAILABLE)?, length, TOO_LARGE).await?;
    if body.len() != length {
        return Err(UNAVAILABLE);
    }
    let headers = http::headers()?;
    headers
        .set("Content-Type", "application/octet-stream")
        .map_err(|_| UNAVAILABLE)?;
    headers
        .set("Content-Length", &body.len().to_string())
        .map_err(|_| UNAVAILABLE)?;
    headers
        .set("Content-Disposition", &disposition)
        .map_err(|_| UNAVAILABLE)?;
    Response::from_bytes(body)
        .map(|response| response.with_headers(headers))
        .map_err(|_| UNAVAILABLE)
}

fn message_id(input: &str) -> bool {
    input.len() == 64
        && input
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn attachment_id(input: &str) -> bool {
    (1..=3).contains(&input.len())
        && (input.len() == 1 || !input.starts_with('0'))
        && input.bytes().all(|byte| byte.is_ascii_digit())
}

fn normalize_summary(row: &mut Summary) -> Result<()> {
    if !message_id(&row.id)
        || row.received_at.len() > 64
        || !matches!(row.folder.as_str(), "inbox" | "trash")
        || row.attachment_count as usize > MAX_MIME_PARTS
    {
        return Err(UNAVAILABLE);
    }
    row.from = preview(&row.from, 512).0;
    row.to = preview(&row.to, 512).0;
    row.subject = preview(&row.subject, 1024).0;
    Ok(())
}
