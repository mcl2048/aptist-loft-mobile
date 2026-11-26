use crate::CoreError;
use std::net::IpAddr;

pub const MAX_SERVER_INPUT_BYTES: usize = 2048;
pub(crate) const MAX_HOST_BYTES: usize = 253;

/// Normalizes an explicit HTTPS origin locally. It does not contact or verify a server.
pub fn normalize_server_origin(raw: &str) -> Result<String, CoreError> {
    if raw.len() > MAX_SERVER_INPUT_BYTES {
        return Err(CoreError::InputTooLarge);
    }
    if raw.chars().any(|character| character.is_control()) {
        return Err(CoreError::InvalidServerAddress);
    }
    let raw = raw.trim_matches(' ');
    if raw.is_empty() || raw.chars().any(char::is_whitespace) || raw.contains('\\') {
        return Err(CoreError::InvalidServerAddress);
    }
    let remainder = if let Some((scheme, remainder)) = raw.split_once("://") {
        if !scheme.eq_ignore_ascii_case("https") {
            return Err(CoreError::InvalidServerAddress);
        }
        remainder
    } else {
        raw
    };
    if remainder.contains(['@', '?', '#', '%']) {
        return Err(CoreError::InvalidServerAddress);
    }
    let authority = match remainder.split_once('/') {
        Some((authority, "")) => authority,
        Some(_) => return Err(CoreError::InvalidServerAddress),
        None => remainder,
    };
    let endpoint =
        parse_endpoint(authority, Some(443)).map_err(|_| CoreError::InvalidServerAddress)?;
    let host = display_host(&endpoint.host);
    if endpoint.port == 443 {
        Ok(format!("https://{host}"))
    } else {
        Ok(format!("https://{host}:{}", endpoint.port))
    }
}

#[derive(PartialEq, Eq)]
pub(crate) struct Endpoint {
    pub(crate) host: String,
    pub(crate) port: u16,
}

impl Endpoint {
    pub(crate) fn display(&self) -> String {
        format!("{}:{}", display_host(&self.host), self.port)
    }
}

pub(crate) fn parse_endpoint(raw: &str, default_port: Option<u16>) -> Result<Endpoint, CoreError> {
    if raw.is_empty() || raw.len() > MAX_HOST_BYTES + 8 {
        return Err(CoreError::InvalidEndpoint);
    }
    let (host, port) = if let Some(bracketed) = raw.strip_prefix('[') {
        let (host, suffix) = bracketed
            .split_once(']')
            .ok_or(CoreError::InvalidEndpoint)?;
        if !matches!(host.parse::<IpAddr>(), Ok(IpAddr::V6(_))) {
            return Err(CoreError::InvalidEndpoint);
        }
        let port = if suffix.is_empty() {
            default_port.ok_or(CoreError::InvalidEndpoint)?
        } else {
            parse_port(suffix.strip_prefix(':').ok_or(CoreError::InvalidEndpoint)?)?
        };
        (normalize_host(host)?, port)
    } else {
        if raw.contains(['[', ']']) {
            return Err(CoreError::InvalidEndpoint);
        }
        let (host, port) = match raw.split_once(':') {
            Some((host, port)) => (host, parse_port(port)?),
            None => (raw, default_port.ok_or(CoreError::InvalidEndpoint)?),
        };
        (normalize_host(host)?, port)
    };
    Ok(Endpoint { host, port })
}

fn parse_port(raw: &str) -> Result<u16, CoreError> {
    if raw.is_empty() || raw.len() > 5 || !raw.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(CoreError::InvalidEndpoint);
    }
    let port = raw.parse::<u16>().map_err(|_| CoreError::InvalidEndpoint)?;
    if port == 0 {
        return Err(CoreError::InvalidEndpoint);
    }
    Ok(port)
}

pub(crate) fn normalize_host(raw: &str) -> Result<String, CoreError> {
    if raw.is_empty() || raw.len() > MAX_HOST_BYTES || !raw.is_ascii() {
        return Err(CoreError::InvalidEndpoint);
    }
    if let Ok(address) = raw.parse::<IpAddr>() {
        return Ok(address.to_string());
    }
    // Do not accept browsers' legacy numeric IPv4 forms as a DNS identity.
    let last_label = raw.rsplit('.').next().unwrap_or("");
    let hexadecimal_tail = last_label
        .strip_prefix("0x")
        .or_else(|| last_label.strip_prefix("0X"))
        .is_some_and(|tail| !tail.is_empty() && tail.bytes().all(|byte| byte.is_ascii_hexdigit()));
    if raw
        .bytes()
        .all(|byte| byte.is_ascii_digit() || byte == b'.')
        || last_label.bytes().all(|byte| byte.is_ascii_digit())
        || hexadecimal_tail
    {
        return Err(CoreError::InvalidEndpoint);
    }
    for label in raw.split('.') {
        if label.is_empty()
            || label.len() > 63
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            || !label.as_bytes()[0].is_ascii_alphanumeric()
            || !label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
        {
            return Err(CoreError::InvalidEndpoint);
        }
    }
    Ok(raw.to_ascii_lowercase())
}

fn display_host(host: &str) -> String {
    if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_owned()
    }
}
