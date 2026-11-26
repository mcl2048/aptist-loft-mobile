use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use url::{Url, form_urlencoded};

#[cfg(target_arch = "wasm32")]
mod edge;

const MAX_MAIL_BYTES: usize = 5 * 1024 * 1024;
pub const IDENTITY_LIFETIME: u64 = 300;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Invalid;

pub fn digest(input: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(input.as_bytes()))
}

pub fn opaque_token(input: &str) -> bool {
    input.len() == 43 && URL_SAFE_NO_PAD.decode(input).is_ok()
}

pub fn challenge(proof: &str) -> Result<String, Invalid> {
    opaque_token(proof).then(|| digest(proof)).ok_or(Invalid)
}

pub fn deployment_origin(input: &str) -> Result<String, Invalid> {
    let parsed = Url::parse(input).map_err(|_| Invalid)?;
    let origin = parsed.origin().ascii_serialization();
    if parsed.scheme() != "https" || input != origin || input.len() > 300 {
        return Err(Invalid);
    }
    Ok(origin)
}

pub fn client_id(input: &str) -> bool {
    input.len() == 36
        && input.bytes().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte == b'-',
            14 => byte == b'4',
            19 => matches!(byte, b'8' | b'9' | b'a' | b'b'),
            _ => byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte),
        })
}

pub fn portal_token(input: &str) -> bool {
    input
        .split_once('.')
        .is_some_and(|(id, token)| client_id(id) && opaque_token(token))
}

#[derive(Debug, PartialEq, Eq)]
pub enum Callback {
    Code { state: String, code: String },
    Denied { state: String },
}

pub fn decode_callback(query: &str, issuer: &str) -> Result<Callback, Invalid> {
    if query.len() > 2048 {
        return Err(Invalid);
    }
    let (mut state, mut code, mut response_issuer, mut error) = (None, None, None, None);
    for (name, value) in form_urlencoded::parse(query.as_bytes()) {
        let slot = match name.as_ref() {
            "state" => &mut state,
            "code" => &mut code,
            "iss" => &mut response_issuer,
            "error" => &mut error,
            _ => return Err(Invalid),
        };
        if slot.replace(value).is_some() {
            return Err(Invalid);
        }
    }
    let state = state
        .filter(|value| opaque_token(value))
        .ok_or(Invalid)?
        .into_owned();
    if response_issuer.as_deref() != Some(issuer) {
        return Err(Invalid);
    }
    match (code, error.as_deref()) {
        (Some(code), None) if portal_token(&code) => Ok(Callback::Code {
            state,
            code: code.into_owned(),
        }),
        (None, Some("access_denied")) => Ok(Callback::Denied { state }),
        _ => Err(Invalid),
    }
}

pub fn scope(mail_read: bool) -> &'static str {
    if mail_read {
        "openid email mail.read"
    } else {
        "openid email"
    }
}

#[derive(Deserialize)]
pub struct Claims {
    pub iss: String,
    pub aud: String,
    pub sub: String,
    pub nonce: String,
    pub exp: u64,
    pub iat: u64,
}

pub fn check_claims(
    claims: &Claims,
    issuer: &str,
    audience: &str,
    nonce: &str,
    now: u64,
) -> Result<(), Invalid> {
    (claims.iss == issuer
        && claims.aud == audience
        && claims.nonce == nonce
        && opaque_token(&claims.sub)
        && claims.iat <= now.saturating_add(5)
        && claims.exp > now
        && claims.exp > claims.iat
        && claims.exp - claims.iat <= IDENTITY_LIFETIME)
        .then_some(())
        .ok_or(Invalid)
}

pub fn seal<T: Serialize>(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    value: &T,
) -> Result<String, Invalid> {
    let json = serde_json::to_vec(value).map_err(|_| Invalid)?;
    let ciphertext = Aes256Gcm::new(key.into())
        .encrypt(Nonce::from_slice(nonce), Payload { msg: &json, aad })
        .map_err(|_| Invalid)?;
    let mut encoded = nonce.to_vec();
    encoded.extend(ciphertext);
    Ok(URL_SAFE_NO_PAD.encode(encoded))
}

pub fn open<T: for<'de> Deserialize<'de>>(
    key: &[u8; 32],
    aad: &[u8],
    encoded: &str,
) -> Result<T, Invalid> {
    if encoded.len() > 16 * 1024 {
        return Err(Invalid);
    }
    let decoded = URL_SAFE_NO_PAD.decode(encoded).map_err(|_| Invalid)?;
    let (nonce, ciphertext) = decoded.split_at_checked(12).ok_or(Invalid)?;
    let json = Aes256Gcm::new(key.into())
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| Invalid)?;
    serde_json::from_slice(&json).map_err(|_| Invalid)
}

pub fn mail_text(text: &str, html: &str) -> Result<String, Invalid> {
    if text.len() > MAX_MAIL_BYTES || html.len() > MAX_MAIL_BYTES {
        return Err(Invalid);
    }
    let text = if text.trim().is_empty() && !html.is_empty() {
        html2text::from_read(html.as_bytes(), 100).map_err(|_| Invalid)?
    } else {
        text.into()
    };
    if text.len() > MAX_MAIL_BYTES {
        return Err(Invalid);
    }
    Ok(text)
}

pub fn preview(text: &str, limit: usize) -> (String, bool) {
    if text.len() <= limit {
        return (text.into(), false);
    }
    (text[..text.floor_char_boundary(limit)].into(), true)
}
