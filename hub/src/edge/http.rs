use futures_util::{Stream, StreamExt};
use serde::{Serialize, de::DeserializeOwned};
use worker::{Headers, Request, Response};

#[derive(Clone, Copy)]
pub(super) struct Fault(pub(super) u16, pub(super) &'static str);

impl Fault {
    pub(super) fn response(self) -> worker::Result<Response> {
        json(self.0, &serde_json::json!({"error":self.1}))
            .map_err(|_| worker::Error::RustError("response unavailable".into()))
    }
}
pub(super) type Result<T> = std::result::Result<T, Fault>;
pub(super) const INVALID: Fault = Fault(400, "invalid_request");
pub(super) const SESSION: Fault = Fault(401, "session_expired");
pub(super) const CONSENT: Fault = Fault(403, "mail_consent_required");
pub(super) const CONFLICT: Fault = Fault(409, "revision_conflict");
pub(super) const SCOPE: Fault = Fault(403, "insufficient_scope");
pub(super) const DENIED: Fault = Fault(403, "access_denied");
pub(super) const NOT_FOUND: Fault = Fault(404, "not_found");
pub(super) const EXPIRED: Fault = Fault(410, "transaction_expired");
pub(super) const TOO_LARGE: Fault = Fault(413, "too_large");
pub(super) const SLOW: Fault = Fault(429, "slow_down");
pub(super) const UNAVAILABLE: Fault = Fault(503, "unavailable");

pub(super) fn headers() -> Result<Headers> {
    let headers = Headers::new();
    for (name, value) in [
        ("Cache-Control", "private, no-store"),
        ("Referrer-Policy", "no-referrer"),
        ("X-Content-Type-Options", "nosniff"),
        ("X-Frame-Options", "DENY"),
        (
            "Content-Security-Policy",
            "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; sandbox",
        ),
    ] {
        headers.set(name, value).map_err(|_| UNAVAILABLE)?;
    }
    Ok(headers)
}

pub(super) fn json(status: u16, value: &impl Serialize) -> Result<Response> {
    let headers = headers()?;
    headers
        .set("Content-Type", "application/json")
        .map_err(|_| UNAVAILABLE)?;
    Response::from_json(value)
        .map(|response| response.with_status(status).with_headers(headers))
        .map_err(|_| UNAVAILABLE)
}

pub(super) fn empty(status: u16) -> Result<Response> {
    Response::empty()
        .map(|response| {
            response
                .with_status(status)
                .with_headers(headers().unwrap_or_default())
        })
        .map_err(|_| UNAVAILABLE)
}

pub(super) async fn read_chunks(
    mut stream: impl Stream<Item = worker::Result<Vec<u8>>> + Unpin,
    limit: usize,
    overflow: Fault,
) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| UNAVAILABLE)?;
        if chunk.len() > limit.saturating_sub(bytes.len()) {
            return Err(overflow);
        }
        bytes.extend(chunk);
    }
    Ok(bytes)
}

pub(super) async fn input<T: DeserializeOwned>(request: &mut Request) -> Result<T> {
    input_bounded(request, 1024).await
}

pub(super) async fn input_bounded<T: DeserializeOwned>(
    request: &mut Request,
    limit: usize,
) -> Result<T> {
    if request
        .headers()
        .get("Origin")
        .map_err(|_| INVALID)?
        .is_some()
    {
        return Err(INVALID);
    }
    let content_type = request.headers().get("Content-Type").map_err(|_| INVALID)?;
    if !content_type.as_deref().is_some_and(|value| {
        value
            .split(';')
            .next()
            .is_some_and(|kind| kind.trim().eq_ignore_ascii_case("application/json"))
    }) {
        return Err(INVALID);
    }
    if request
        .headers()
        .get("Content-Length")
        .map_err(|_| INVALID)?
        .is_some_and(|value| value.parse::<usize>().is_ok_and(|size| size > limit))
    {
        return Err(TOO_LARGE);
    }
    let stream = request.stream().map_err(|_| INVALID)?;
    let bytes = read_chunks(stream, limit, TOO_LARGE).await?;
    serde_json::from_slice(&bytes).map_err(|_| INVALID)
}

pub(super) async fn response_json<T: DeserializeOwned>(
    mut response: Response,
    limit: usize,
) -> Result<T> {
    if !response
        .headers()
        .get("Content-Type")
        .map_err(|_| UNAVAILABLE)?
        .is_some_and(|value| {
            value
                .split(';')
                .next()
                .is_some_and(|kind| kind.trim().eq_ignore_ascii_case("application/json"))
        })
    {
        return Err(UNAVAILABLE);
    }
    let bytes = read_chunks(
        response.stream().map_err(|_| UNAVAILABLE)?,
        limit,
        TOO_LARGE,
    )
    .await?;
    serde_json::from_slice(&bytes).map_err(|_| UNAVAILABLE)
}
