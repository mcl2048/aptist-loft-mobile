mod http;
mod mail;
mod portal;

use std::cell::Cell;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use url::Url;
use wasm_bindgen::JsValue;
use worker::{
    AbortSignal, Context, D1Database, D1PreparedStatement, Env, Method, Request, Response,
    ScheduleContext, ScheduledEvent, event,
};

use self::http::{DENIED, EXPIRED, INVALID, NOT_FOUND, Result, SCOPE, SESSION, SLOW, UNAVAILABLE};
use self::portal::{Session, Transaction};
use crate::{
    Callback, IDENTITY_LIFETIME, challenge, client_id, decode_callback, deployment_origin, digest,
    opaque_token, open, seal,
};

const START: &str = "/v1/auth/portal/transactions";
const CALLBACK: &str = "/v1/auth/portal/callback";
const RETURN: &str = "/v1/auth/portal/return";
const MAIL: &str = "/v1/mail/messages";

struct Config {
    origin: String,
    issuer: String,
    client_id: String,
    client_secret: String,
    key: [u8; 32],
    namespace: String,
}

impl Config {
    fn read(env: &Env) -> Result<Self> {
        let variable = |name| {
            env.var(name)
                .map(|value| value.to_string())
                .map_err(|_| UNAVAILABLE)
        };
        let secret = |name| {
            env.secret(name)
                .map(|value| value.to_string())
                .map_err(|_| UNAVAILABLE)
        };
        let origin = deployment_origin(&variable("HUB_ORIGIN")?).map_err(|_| UNAVAILABLE)?;
        let issuer = variable("PORTAL_ISSUER")?;
        deployment_origin(issuer.strip_suffix("/api/idp").ok_or(UNAVAILABLE)?)
            .map_err(|_| UNAVAILABLE)?;
        let id = variable("PORTAL_CLIENT_ID")?;
        let client_secret = secret("PORTAL_CLIENT_SECRET")?;
        if !client_id(&id)
            || client_secret.len() != 64
            || URL_SAFE_NO_PAD.decode(&client_secret).is_err()
        {
            return Err(UNAVAILABLE);
        }
        let key = URL_SAFE_NO_PAD
            .decode(secret("HUB_ENCRYPTION_KEY")?)
            .map_err(|_| UNAVAILABLE)?
            .try_into()
            .map_err(|_| UNAVAILABLE)?;
        let namespace = digest(&format!("loft-hub-v1\n{origin}\n{issuer}\n{id}"));
        Ok(Self {
            origin,
            issuer,
            client_id: id,
            client_secret,
            key,
            namespace,
        })
    }

    fn endpoint(&self, suffix: &str) -> String {
        format!("{}{suffix}", self.issuer)
    }
    fn callback(&self) -> String {
        format!("{}{CALLBACK}", self.origin)
    }
    fn owns(&self, url: &Url) -> bool {
        url.username().is_empty()
            && url.password().is_none()
            && self.origin == url.origin().ascii_serialization()
    }

    fn hash(&self, kind: &str, value: &str) -> String {
        digest(&format!("{}\n{kind}\n{value}", self.namespace))
    }

    fn aad(&self, kind: &str, id: &str) -> String {
        format!("{}\n{kind}\n{id}", self.namespace)
    }

    fn seal(&self, kind: &str, id: &str, value: &impl Serialize) -> Result<String> {
        seal(&self.key, &random()?, self.aad(kind, id).as_bytes(), value).map_err(|_| UNAVAILABLE)
    }

    fn open<T: DeserializeOwned>(&self, kind: &str, id: &str, value: &str) -> Result<T> {
        open(&self.key, self.aad(kind, id).as_bytes(), value).map_err(|_| UNAVAILABLE)
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Create {
    proof_challenge: String,
    mail_read: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Proof {
    proof: String,
}

#[derive(Deserialize)]
struct Claim {
    id: String,
    auth_box: String,
}

#[derive(Deserialize)]
struct Stored {
    id: String,
    session_hash: String,
    session_box: String,
    session_expires_at: u64,
}

#[derive(Deserialize)]
struct Pending {
    phase: String,
    session_hash: Option<String>,
    session_box: Option<String>,
    session_expires_at: Option<u64>,
}

#[event(fetch)]
async fn main(request: Request, env: Env, _context: Context) -> worker::Result<Response> {
    match route(request, env).await {
        Ok(response) => Ok(response),
        Err(error) => error.response(),
    }
}

#[event(scheduled)]
async fn scheduled(_event: ScheduledEvent, env: Env, _context: ScheduleContext) {
    if let Ok(db) = env.d1("DB") {
        let _ = prune(&db).await;
    }
}

async fn prune(db: &D1Database) -> Result<()> {
    write(db, "DELETE FROM hub_login WHERE (expires_at <= ?1 AND phase != 'issued') OR (session_expires_at <= ?1 AND phase IN ('issued','ready'))", &[number(now())]).await
}

async fn route(mut request: Request, env: Env) -> Result<Response> {
    let config = Config::read(&env)?;
    let url = request.url().map_err(|_| INVALID)?;
    if !config.owns(&url) {
        return Err(NOT_FOUND);
    }
    let path = url.path();
    let method = request.method();
    let query = url.query().unwrap_or_default();
    if !query.is_empty() && (method != Method::Get || !matches!(path, CALLBACK | MAIL)) {
        return Err(INVALID);
    }
    if !matches!(path, CALLBACK | RETURN)
        && request
            .headers()
            .get("Origin")
            .map_err(|_| INVALID)?
            .is_some()
    {
        return Err(INVALID);
    }
    if method == Method::Get && path == "/.well-known/loft-app" {
        return http::json(
            200,
            &serde_json::json!({
                "version": 1, "product": "loft", "authMode": "portal_bff", "issuer": config.issuer, "modules": ["mail"]
            }),
        );
    }
    if method == Method::Get && path == RETURN {
        return browser_return(
            request
                .headers()
                .get("Accept-Language")
                .map_err(|_| INVALID)?
                .as_deref()
                .unwrap_or(""),
        );
    }
    let signals = js_sys::Array::new();
    signals.push(&*request.signal());
    signals.push(&web_sys::AbortSignal::timeout_with_u32(15_000));
    let signal = AbortSignal::from(web_sys::AbortSignal::any(&signals));
    let db = env.d1("DB").map_err(|_| UNAVAILABLE)?;
    match (method, path) {
        (Method::Post, START) => start(&config, &db, &mut request, &signal).await,
        (Method::Get, CALLBACK) => callback(&config, &db, query, &signal).await,
        (Method::Get, "/v1/session") => {
            let stored = require_session(&config, &db, &request).await?;
            let mut session = config.open::<Session>("session", &stored.id, &stored.session_box)?;
            session.email =
                portal::userinfo(&config, &session.portal_access, &session.subject, &signal)
                    .await?
                    .email;
            ensure_current(&db, &stored.session_hash).await?;
            response_session(&config, &session, stored.session_expires_at, false)
        }
        (Method::Post, "/v1/logout") => {
            let hash = bearer_hash(&config, &request)?;
            write(
                &db,
                "DELETE FROM hub_login WHERE phase = 'issued' AND session_hash = ?1",
                &[hash.into()],
            )
            .await?;
            http::empty(204)
        }
        (Method::Post, path) if path.starts_with(START) => {
            let tail = path
                .strip_prefix(START)
                .and_then(|path| path.strip_prefix('/'))
                .ok_or(NOT_FOUND)?;
            let (id, action) = tail.split_once('/').ok_or(NOT_FOUND)?;
            if !opaque_token(id) {
                return Err(INVALID);
            }
            let proof: Proof = http::input(&mut request).await?;
            let proof = config.hash("proof", &challenge(&proof.proof).map_err(|_| INVALID)?);
            match action {
                "complete" => complete(&config, &db, id, &proof, &signal).await,
                "cancel" => {
                    write(
                        &db,
                        include_str!("../sql/cancel.sql"),
                        &[id.into(), proof.into()],
                    )
                    .await?;
                    http::empty(204)
                }
                _ => Err(NOT_FOUND),
            }
        }
        (Method::Get, path)
            if path == MAIL
                || path
                    .strip_prefix(MAIL)
                    .is_some_and(|path| path.starts_with('/')) =>
        {
            let stored = require_session(&config, &db, &request).await?;
            let session: Session = config.open("session", &stored.id, &stored.session_box)?;
            if !session.mail_read {
                return Err(SCOPE);
            }
            let _request = MailPermit::acquire(&MAIL_REQUESTS, 4)?;
            let result = if path == MAIL {
                mail::list(&config, &session, query, &signal).await
            } else {
                let segments: Vec<_> = path[MAIL.len() + 1..].split('/').collect();
                match segments.as_slice() {
                    [id] | [id, "content"] => {
                        let _conversion = MailPermit::acquire(&MAIL_CONVERSIONS, 1)?;
                        mail::detail(&config, &session, id, segments.len() == 2, &signal).await
                    }
                    [id, "attachments", part] => {
                        mail::attachment(&config, &session, id, part, &signal).await
                    }
                    _ => Err(NOT_FOUND),
                }
            }?;
            ensure_current(&db, &stored.session_hash).await?;
            Ok(result)
        }
        _ => Err(NOT_FOUND),
    }
}

fn browser_return(languages: &str) -> Result<Response> {
    let language = languages
        .get(..languages.len().min(512))
        .unwrap_or("")
        .split(',')
        .find_map(|part| {
            let (tag, quality) = part.trim().split_once(';').unwrap_or((part.trim(), ""));
            if !quality.is_empty()
                && !quality
                    .trim()
                    .strip_prefix("q=")
                    .and_then(|q| q.parse::<f32>().ok())
                    .is_some_and(|q| q > 0.0 && q <= 1.0)
            {
                return None;
            }
            let primary = tag.split('-').next().unwrap_or("").to_ascii_lowercase();
            matches!(primary.as_str(), "en" | "zh" | "ja" | "de").then_some(primary)
        })
        .unwrap_or_else(|| "en".into());
    let (title, instructions) = match language.as_str() {
        "zh" => (
            "返回 LOFT",
            "打开 LOFT 并选择“完成登录”。你可以关闭此页面。",
        ),
        "ja" => (
            "LOFT に戻る",
            "LOFT を開いて「ログインを完了」を選択してください。このページは閉じてかまいません。",
        ),
        "de" => (
            "Zu LOFT zurückkehren",
            "Öffnen Sie LOFT und wählen Sie „Anmeldung abschließen“. Sie können diese Seite schließen.",
        ),
        _ => (
            "Return to LOFT",
            "Open LOFT and select Complete sign-in. You can close this page.",
        ),
    };
    let body = format!(
        r#"<!doctype html><html lang="{language}"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>LOFT</title><main><h1>{title}</h1><p>{instructions}</p></main>"#
    );
    let headers = http::headers()?;
    headers
        .set("Content-Type", "text/html; charset=utf-8")
        .map_err(|_| UNAVAILABLE)?;
    Response::from_html(body)
        .map(|response| response.with_headers(headers))
        .map_err(|_| UNAVAILABLE)
}

// A Worker isolate interleaves requests at await points. Each permit spans the
// upstream read and conversion so another request cannot expand that work set.
thread_local! {
    static MAIL_REQUESTS: Cell<u8> = const { Cell::new(0) };
    static MAIL_CONVERSIONS: Cell<u8> = const { Cell::new(0) };
}
struct MailPermit(&'static std::thread::LocalKey<Cell<u8>>);
impl MailPermit {
    fn acquire(count: &'static std::thread::LocalKey<Cell<u8>>, maximum: u8) -> Result<Self> {
        count.with(|active| {
            if active.get() >= maximum {
                return Err(SLOW);
            }
            active.set(active.get() + 1);
            Ok(Self(count))
        })
    }
}
impl Drop for MailPermit {
    fn drop(&mut self) {
        self.0.with(|active| active.set(active.get() - 1));
    }
}

async fn start(
    config: &Config,
    db: &D1Database,
    request: &mut Request,
    signal: &AbortSignal,
) -> Result<Response> {
    let body: Create = http::input(request).await?;
    if !opaque_token(&body.proof_challenge) {
        return Err(INVALID);
    }
    let _rate: u64 = first_col(
        db,
        include_str!("../sql/rate.sql"),
        "used",
        &[number(1), number(now() / 60), number(60)],
    )
    .await?
    .ok_or(SLOW)?;
    portal::discover(config, body.mail_read, signal).await?;
    let id = token()?;
    let state = token()?;
    let transaction = Transaction {
        mail_read: body.mail_read,
        nonce: token()?,
        verifier: token()?,
    };
    let sealed = config.seal("transaction", &id, &transaction)?;
    let at = now();
    let expires_at = at + IDENTITY_LIFETIME;
    let _id: String = first_col(
        db,
        include_str!("../sql/create.sql"),
        "id",
        &[
            id.clone().into(),
            config.hash("state", &state).into(),
            config.hash("proof", &body.proof_challenge).into(),
            sealed.into(),
            number(expires_at),
            number(at),
            number(64),
        ],
    )
    .await?
    .ok_or(SLOW)?;
    http::json(
        201,
        &serde_json::json!({
            "transactionId": id, "authorizationUrl": portal::authorization_url(config, &state, &transaction)?,
            "expiresAt": expires_at, "expiresIn": expires_at.saturating_sub(now()),
        }),
    )
}

async fn callback(
    config: &Config,
    db: &D1Database,
    query: &str,
    signal: &AbortSignal,
) -> Result<Response> {
    let callback = decode_callback(query, &config.issuer).map_err(|_| INVALID)?;
    let (state, code) = match callback {
        Callback::Code { state, code } => (state, Some(code)),
        Callback::Denied { state } => (state, None),
    };
    let claimed: Claim = first(
        db,
        include_str!("../sql/claim.sql"),
        &[config.hash("state", &state).into(), number(now())],
    )
    .await?
    .ok_or(EXPIRED)?;
    if let Some(code) = code {
        let transaction: Transaction =
            config.open("transaction", &claimed.id, &claimed.auth_box)?;
        match portal::exchange(config, &code, &transaction, token()?, signal).await {
            Ok((session, expires_at)) => {
                let sealed = config.seal("session", &claimed.id, &session)?;
                let _id: String = first_col(
                    db,
                    include_str!("../sql/finish.sql"),
                    "id",
                    &[
                        claimed.id.into(),
                        config.hash("session", &session.token).into(),
                        sealed.into(),
                        number(expires_at),
                        number(now()),
                    ],
                )
                .await?
                .ok_or(EXPIRED)?;
            }
            Err(error) => {
                mark_callback(
                    db,
                    &claimed.id,
                    if error.0 == 403 { "denied" } else { "failed" },
                )
                .await?
            }
        }
    } else {
        mark_callback(db, &claimed.id, "denied").await?;
    }
    let headers = http::headers()?;
    headers
        .set("Location", &format!("{}{RETURN}", config.origin))
        .map_err(|_| UNAVAILABLE)?;
    http::empty(303).map(|response| response.with_headers(headers))
}

async fn mark_callback(db: &D1Database, id: &str, phase: &str) -> Result<()> {
    write(
        db,
        "UPDATE hub_login SET phase = ?1, auth_box = NULL WHERE id = ?2 AND phase = 'claimed'",
        &[phase.into(), id.into()],
    )
    .await
}

async fn complete(
    config: &Config,
    db: &D1Database,
    id: &str,
    proof: &str,
    signal: &AbortSignal,
) -> Result<Response> {
    let pending: Pending = first(db, "SELECT phase, session_hash, session_box, session_expires_at FROM hub_login WHERE id = ?1 AND proof_hash = ?2 AND expires_at > ?3",
        &[id.into(), proof.into(), number(now())]).await?.ok_or(EXPIRED)?;
    match pending.phase.as_str() {
        "pending" | "claimed" => return http::json(202, &serde_json::json!({"status":"pending"})),
        "denied" => return Err(DENIED),
        "failed" => return Err(UNAVAILABLE),
        "ready" | "issued" => (),
        _ => return Err(UNAVAILABLE),
    }
    if pending.session_expires_at.ok_or(UNAVAILABLE)? <= now() {
        return Err(EXPIRED);
    }
    let sealed = pending.session_box.ok_or(UNAVAILABLE)?;
    let mut session: Session = config.open("session", id, &sealed)?;
    session.email = portal::userinfo(config, &session.portal_access, &session.subject, signal)
        .await?
        .email;
    let stored: Stored = first(
        db,
        include_str!("../sql/complete.sql"),
        &[id.into(), proof.into(), number(now())],
    )
    .await?
    .ok_or(EXPIRED)?;
    if Some(&stored.session_hash) != pending.session_hash.as_ref() || stored.session_box != sealed {
        return Err(EXPIRED);
    }
    response_session(config, &session, stored.session_expires_at, true)
}

fn response_session(
    config: &Config,
    session: &Session,
    deadline: u64,
    include_token: bool,
) -> Result<Response> {
    let remaining = deadline
        .checked_sub(now())
        .filter(|remaining| *remaining > 0 && *remaining <= IDENTITY_LIFETIME)
        .ok_or(SESSION)?;
    let mut response = serde_json::json!({
        "issuer": config.issuer, "subject": session.subject, "mailRead": session.mail_read, "expiresAt": deadline, "expiresIn": remaining,
    });
    if let Some(email) = &session.email {
        response["email"] = email.as_str().into();
    }
    if include_token {
        response["status"] = "complete".into();
        response["sessionToken"] = session.token.as_str().into();
    }
    http::json(200, &response)
}

fn bearer_hash(config: &Config, request: &Request) -> Result<String> {
    let authorization = request
        .headers()
        .get("Authorization")
        .map_err(|_| SESSION)?
        .ok_or(SESSION)?;
    let token = authorization
        .strip_prefix("Bearer ")
        .filter(|value| opaque_token(value))
        .ok_or(SESSION)?;
    Ok(config.hash("session", token))
}

async fn require_session(config: &Config, db: &D1Database, request: &Request) -> Result<Stored> {
    let hash = bearer_hash(config, request)?;
    first(
        db,
        include_str!("../sql/session.sql"),
        &[hash.into(), number(now())],
    )
    .await?
    .ok_or(SESSION)
}

async fn ensure_current(db: &D1Database, hash: &str) -> Result<()> {
    let _id: String = first_col(db, "SELECT id FROM hub_login WHERE session_hash = ?1 AND phase = 'issued' AND session_expires_at > ?2", "id",
        &[hash.into(), number(now())]).await?.ok_or(SESSION)?;
    Ok(())
}

fn prepare(db: &D1Database, sql: &str, args: &[JsValue]) -> Result<D1PreparedStatement> {
    db.prepare(sql).bind(args).map_err(|_| UNAVAILABLE)
}

async fn first<T: DeserializeOwned>(
    db: &D1Database,
    sql: &str,
    args: &[JsValue],
) -> Result<Option<T>> {
    prepare(db, sql, args)?
        .first(None)
        .await
        .map_err(|_| UNAVAILABLE)
}

async fn first_col<T: DeserializeOwned>(
    db: &D1Database,
    sql: &str,
    column: &str,
    args: &[JsValue],
) -> Result<Option<T>> {
    prepare(db, sql, args)?
        .first(Some(column))
        .await
        .map_err(|_| UNAVAILABLE)
}

async fn write(db: &D1Database, sql: &str, args: &[JsValue]) -> Result<()> {
    if !prepare(db, sql, args)?
        .run()
        .await
        .map_err(|_| UNAVAILABLE)?
        .success()
    {
        return Err(UNAVAILABLE);
    }
    Ok(())
}

fn now() -> u64 {
    (js_sys::Date::now() / 1000.0) as u64
}
fn number(value: u64) -> JsValue {
    JsValue::from_f64(value as f64)
}
fn random<const N: usize>() -> Result<[u8; N]> {
    let mut bytes = [0_u8; N];
    getrandom::fill(&mut bytes).map_err(|_| UNAVAILABLE)?;
    Ok(bytes)
}
fn token() -> Result<String> {
    Ok(URL_SAFE_NO_PAD.encode(random::<32>()?))
}
