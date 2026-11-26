use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use js_sys::{Array, Object, Reflect, Uint8Array};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use url::{Url, form_urlencoded};
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;
use worker::{
    AbortSignal, Fetch, Headers, Method, Request, RequestInit, RequestRedirect, Response,
};

use super::http::{self, DENIED, INVALID, NOT_FOUND, Result, SCOPE, SESSION, SLOW, UNAVAILABLE};
use super::{Config, now};
use crate::{Claims, IDENTITY_LIFETIME, check_claims, digest, opaque_token, portal_token, scope};

#[derive(Serialize, Deserialize)]
pub(super) struct Transaction {
    pub(super) verifier: String,
    pub(super) nonce: String,
    pub(super) mail_read: bool,
    #[serde(default)]
    pub(super) durable: bool,
    #[serde(default)]
    pub(super) renewal: Option<Renewal>,
}

#[derive(Serialize, Deserialize)]
pub(super) struct Session {
    pub(super) token: String,
    pub(super) portal_access: String,
    pub(super) subject: String,
    pub(super) email: Option<String>,
    pub(super) mail_read: bool,
    #[serde(default)]
    pub(super) durable: bool,
    #[serde(default)]
    pub(super) renewal: Option<Renewal>,
}

#[derive(Serialize, Deserialize)]
pub(super) struct Renewal {
    pub(super) device_token: String,
    pub(super) owner_hash: String,
    pub(super) mail_revision: u32,
}
#[derive(Deserialize)]
struct Discovery {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    userinfo_endpoint: String,
    jwks_uri: String,
    grant_types_supported: Vec<String>,
    response_types_supported: Vec<String>,
    token_endpoint_auth_methods_supported: Vec<String>,
    id_token_signing_alg_values_supported: Vec<String>,
    code_challenge_methods_supported: Vec<String>,
    scopes_supported: Vec<String>,
    authorization_response_iss_parameter_supported: bool,
}

#[derive(Deserialize)]
struct Tokens {
    access_token: String,
    token_type: String,
    expires_in: u64,
    scope: String,
    id_token: String,
}

#[derive(Deserialize)]
pub(super) struct UserInfo {
    pub(super) sub: String,
    pub(super) email: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct JwtHeader {
    alg: String,
    kid: String,
    typ: Option<String>,
}

#[derive(Deserialize)]
struct Jwks {
    keys: Vec<Jwk>,
}

#[derive(Deserialize)]
struct Jwk {
    kid: String,
    kty: String,
    alg: String,
    #[serde(rename = "use")]
    usage: String,
    n: String,
    e: String,
}

pub(super) async fn discover(config: &Config, mail_read: bool, signal: &AbortSignal) -> Result<()> {
    let discovery: Discovery = get(
        config,
        "/.well-known/openid-configuration",
        None,
        16 * 1024,
        signal,
    )
    .await?;
    let contains = |values: &[String], name: &str| values.iter().any(|value| value == name);
    if discovery.issuer != config.issuer
        || discovery.authorization_endpoint != config.endpoint("/authorize")
        || discovery.token_endpoint != config.endpoint("/token")
        || discovery.userinfo_endpoint != config.endpoint("/userinfo")
        || discovery.jwks_uri != config.endpoint("/jwks")
        || !contains(&discovery.grant_types_supported, "authorization_code")
        || !contains(&discovery.response_types_supported, "code")
        || !contains(
            &discovery.token_endpoint_auth_methods_supported,
            "client_secret_basic",
        )
        || !contains(&discovery.id_token_signing_alg_values_supported, "RS256")
        || !contains(&discovery.code_challenge_methods_supported, "S256")
        || !scope(mail_read)
            .split_whitespace()
            .all(|s| contains(&discovery.scopes_supported, s))
        || !discovery.authorization_response_iss_parameter_supported
    {
        return Err(UNAVAILABLE);
    }
    Ok(())
}

pub(super) fn authorization_url(
    config: &Config,
    state: &str,
    transaction: &Transaction,
) -> Result<String> {
    let mut url = Url::parse(&config.endpoint("/authorize")).map_err(|_| UNAVAILABLE)?;
    url.query_pairs_mut().extend_pairs([
        ("response_type", "code"),
        ("client_id", &config.client_id),
        ("redirect_uri", &config.callback()),
        ("scope", scope(transaction.mail_read)),
        ("state", state),
        ("nonce", &transaction.nonce),
        ("code_challenge", &digest(&transaction.verifier)),
        ("code_challenge_method", "S256"),
    ]);
    Ok(url.into())
}

pub(super) async fn exchange(
    config: &Config,
    code: &str,
    transaction: Transaction,
    loft_token: String,
    signal: &AbortSignal,
) -> Result<(Session, u64)> {
    if !code.starts_with(&format!("{}.", config.client_id)) {
        return Err(DENIED);
    }
    let body = form_urlencoded::Serializer::new(String::new())
        .extend_pairs([
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", &config.callback()),
            ("code_verifier", &transaction.verifier),
        ])
        .finish();
    let encode =
        |value: &str| form_urlencoded::byte_serialize(value.as_bytes()).collect::<String>();
    let basic = STANDARD.encode(format!(
        "{}:{}",
        encode(&config.client_id),
        encode(&config.client_secret)
    ));
    let request = upstream_request(
        &config.endpoint("/token"),
        Method::Post,
        Some(&format!("Basic {basic}")),
        Some(body),
    )?;
    let started = now();
    let response = fetch(request, signal).await?;
    if matches!(response.status_code(), 400 | 401 | 403) {
        return Err(DENIED);
    }
    let tokens: Tokens = http::response_json(accept(response)?, 16 * 1024).await?;
    let mut actual = tokens.scope.split_ascii_whitespace().collect::<Vec<_>>();
    let mut expected = scope(transaction.mail_read)
        .split_ascii_whitespace()
        .collect::<Vec<_>>();
    actual.sort_unstable();
    expected.sort_unstable();
    if tokens.token_type != "Bearer"
        || !portal_token(&tokens.access_token)
        || !tokens
            .access_token
            .starts_with(&format!("{}.", config.client_id))
        || !(1..=IDENTITY_LIFETIME).contains(&tokens.expires_in)
        || actual != expected
    {
        return Err(DENIED);
    }
    let claims = verify_id_token(config, &tokens.id_token, signal).await?;
    check_claims(
        &claims,
        &config.issuer,
        &config.client_id,
        &transaction.nonce,
        now(),
    )
    .map_err(|_| DENIED)?;
    let identity = userinfo(config, &tokens.access_token, &claims.sub, signal).await?;
    if transaction
        .renewal
        .as_ref()
        .is_some_and(|renewal| renewal.owner_hash != config.owner_hash(&identity.sub))
    {
        return Err(DENIED);
    }
    let expires_at = claims.exp.min(started + tokens.expires_in);
    if expires_at <= now() {
        return Err(SESSION);
    }
    Ok((
        Session {
            token: loft_token,
            portal_access: tokens.access_token,
            subject: identity.sub,
            email: identity.email,
            mail_read: transaction.mail_read,
            durable: transaction.durable,
            renewal: transaction.renewal,
        },
        expires_at,
    ))
}

pub(super) async fn userinfo(
    config: &Config,
    token: &str,
    subject: &str,
    signal: &AbortSignal,
) -> Result<UserInfo> {
    let info: UserInfo = get(config, "/userinfo", Some(token), 8 * 1024, signal).await?;
    if info.sub != subject || !opaque_token(&info.sub) {
        return Err(SESSION);
    }
    if info
        .email
        .as_deref()
        .is_some_and(|email| email.len() > 512 || email.chars().any(char::is_control))
    {
        return Err(UNAVAILABLE);
    }
    Ok(info)
}

pub(super) async fn get<T: DeserializeOwned>(
    config: &Config,
    suffix: &str,
    bearer: Option<&str>,
    limit: usize,
    signal: &AbortSignal,
) -> Result<T> {
    http::response_json(get_raw(config, suffix, bearer, signal).await?, limit).await
}

pub(super) async fn get_raw(
    config: &Config,
    suffix: &str,
    bearer: Option<&str>,
    signal: &AbortSignal,
) -> Result<Response> {
    let auth = bearer.map(|token| format!("Bearer {token}"));
    let request = upstream_request(&config.endpoint(suffix), Method::Get, auth.as_deref(), None)?;
    accept(fetch(request, signal).await?)
}

fn upstream_request(
    url: &str,
    method: Method,
    auth: Option<&str>,
    body: Option<String>,
) -> Result<Request> {
    let headers = Headers::new();
    headers
        .set("Cache-Control", "no-store")
        .map_err(|_| UNAVAILABLE)?;
    if let Some(auth) = auth {
        headers
            .set("Authorization", auth)
            .map_err(|_| UNAVAILABLE)?;
    }
    if body.is_some() {
        headers
            .set("Content-Type", "application/x-www-form-urlencoded")
            .map_err(|_| UNAVAILABLE)?;
    }
    let mut init = RequestInit::new();
    init.with_method(method)
        .with_headers(headers)
        .with_redirect(RequestRedirect::Manual)
        .with_body(body.map(|value| JsValue::from_str(&value)));
    Request::new_with_init(url, &init).map_err(|_| UNAVAILABLE)
}

async fn fetch(request: Request, signal: &AbortSignal) -> Result<Response> {
    Fetch::Request(request)
        .send_with_signal(signal)
        .await
        .map_err(|_| UNAVAILABLE)
}

fn accept(response: Response) -> Result<Response> {
    match response.status_code() {
        200 => Ok(response),
        400 => Err(INVALID),
        401 => Err(SESSION),
        403 => Err(SCOPE),
        404 => Err(NOT_FOUND),
        429 => Err(SLOW),
        _ => Err(UNAVAILABLE),
    }
}

async fn verify_id_token(config: &Config, token: &str, signal: &AbortSignal) -> Result<Claims> {
    if token.len() > 8192 {
        return Err(DENIED);
    }
    let (message, signature) = token.rsplit_once('.').ok_or(DENIED)?;
    let (header, payload) = message.split_once('.').ok_or(DENIED)?;
    let header: JwtHeader =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(header).map_err(|_| DENIED)?)
            .map_err(|_| DENIED)?;
    if header.alg != "RS256"
        || header.typ.as_deref().is_some_and(|kind| kind != "JWT")
        || !crate::client_id(&header.kid)
    {
        return Err(DENIED);
    }
    let jwks: Jwks = get(config, "/jwks", None, 16 * 1024, signal).await?;
    let mut matching = jwks.keys.iter().filter(|key| key.kid == header.kid);
    let key = matching.next().ok_or(DENIED)?;
    if matching.next().is_some()
        || key.kty != "RSA"
        || key.alg != "RS256"
        || key.usage != "sig"
        || key.e != "AQAB"
    {
        return Err(DENIED);
    }
    let n = URL_SAFE_NO_PAD.decode(&key.n).map_err(|_| DENIED)?;
    let sig = URL_SAFE_NO_PAD.decode(signature).map_err(|_| DENIED)?;
    if n.len() != 256 || n[0] < 128 || sig.len() != n.len() {
        return Err(DENIED);
    }
    verify_rs256(&key.n, &key.e, &sig, message.as_bytes()).await?;
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).map_err(|_| DENIED)?)
        .map_err(|_| DENIED)
}

async fn verify_rs256(n: &str, e: &str, signature: &[u8], message: &[u8]) -> Result<()> {
    let crypto: web_sys::Crypto = Reflect::get(&js_sys::global(), &"crypto".into())
        .and_then(JsCast::dyn_into)
        .map_err(|_| UNAVAILABLE)?;
    let subtle = crypto.subtle();
    let algorithm = Object::new();
    Reflect::set(&algorithm, &"name".into(), &"RSASSA-PKCS1-v1_5".into())
        .map_err(|_| UNAVAILABLE)?;
    Reflect::set(&algorithm, &"hash".into(), &"SHA-256".into()).map_err(|_| UNAVAILABLE)?;
    let jwk = Object::new();
    for (field, value) in [("kty", "RSA"), ("alg", "RS256"), ("n", n), ("e", e)] {
        Reflect::set(&jwk, &field.into(), &value.into()).map_err(|_| UNAVAILABLE)?;
    }
    let usages = Array::new();
    usages.push(&"verify".into());
    let key: web_sys::CryptoKey = JsFuture::from(
        subtle
            .import_key_with_object("jwk", &jwk, &algorithm, false, &usages)
            .map_err(|_| DENIED)?,
    )
    .await
    .and_then(JsCast::dyn_into)
    .map_err(|_| DENIED)?;
    let signature = Uint8Array::from(signature);
    let message = Uint8Array::from(message);
    let verified = JsFuture::from(
        subtle
            .verify_with_object_and_buffer_source_and_buffer_source(
                &algorithm, &key, &signature, &message,
            )
            .map_err(|_| DENIED)?,
    )
    .await
    .map_err(|_| DENIED)?;
    if verified.as_bool() != Some(true) {
        return Err(DENIED);
    }
    Ok(())
}
