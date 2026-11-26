use crate::certificates::{validate_pro_material, validate_x_material};
use crate::origin::{Endpoint, normalize_host, parse_endpoint};
use crate::{CoreError, NodeSummary, ProtocolKind};
use base64::{Engine, engine::general_purpose::STANDARD};
use std::{collections::BTreeMap, fmt};
use x509_parser::time::ASN1Time;
use zeroize::Zeroizing;

pub const MAX_NODE_INPUT_BYTES: usize = 512 * 1024;
pub const MAX_NODE_LABEL_BYTES: usize = 64;
const MAX_QUERY_PARAMETERS: usize = 32;
const MAX_QUERY_VALUE_BYTES: usize = 100_000;
const MAX_PUBLIC_CERT_BYTES: usize = 65_536;
const MAX_CLIENT_MATERIAL_BYTES: usize = 16_384;

#[derive(PartialEq, Eq)]
pub(crate) struct SecretBytes(pub(crate) Zeroizing<Vec<u8>>);

impl fmt::Debug for SecretBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("[redacted]")
    }
}

#[derive(PartialEq, Eq)]
pub(crate) struct SecretString(Zeroizing<String>);

impl SecretString {
    fn as_str(&self) -> &str {
        self.0.as_str()
    }
    fn capacity(&self) -> usize {
        self.0.capacity()
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("[redacted]")
    }
}

#[derive(PartialEq, Eq)]
enum SocksAuth {
    None,
    UsernamePassword {
        username: SecretString,
        password: SecretString,
    },
}

#[derive(PartialEq, Eq)]
pub(crate) struct XMaterial {
    pub(crate) server_certificate: SecretBytes,
    pub(crate) client_ca: SecretBytes,
    pub(crate) client_certificate: SecretBytes,
    pub(crate) client_key: SecretBytes,
}

#[derive(PartialEq, Eq)]
enum XMode {
    Flash,
    Beast,
}
#[derive(PartialEq, Eq)]
enum XScenario {
    Bulk,
    Lossy,
    Speedtest,
}
#[derive(PartialEq, Eq)]
struct XOptions {
    mode: XMode,
    scenario: XScenario,
    rate_mbps: u32,
}

#[derive(PartialEq, Eq)]
enum ProTransport {
    Auto,
    Tcp,
    Grpc,
}
#[derive(PartialEq, Eq)]
enum ProEngine {
    Ghostx,
    Naive,
}
#[derive(PartialEq, Eq)]
enum ProSuite {
    Auto,
    Aes256Gcm,
    Chacha20Poly1305,
    RoccaS,
    AsconAead128,
}
#[derive(PartialEq, Eq)]
enum ProCongestion {
    Beast,
    Bbr,
}
#[derive(PartialEq, Eq)]
enum TrafficProfile {
    Auto,
    Gaming,
    Streaming,
    WebBrowsing,
    WechatVoice,
}
#[derive(PartialEq, Eq)]
enum PacketEncoding {
    None,
    Xudp,
}
#[derive(PartialEq, Eq)]
struct ProOptions {
    path: String,
    transport: ProTransport,
    engine: ProEngine,
    suite: ProSuite,
    congestion: ProCongestion,
    connections: u32,
    traffic_profile: TrafficProfile,
    elastic_mux: bool,
    isolation: bool,
    packet_encoding: PacketEncoding,
}

#[derive(PartialEq, Eq)]
enum ProtocolConfig {
    Socks5(SocksAuth),
    HyrakenX {
        seed: SecretString,
        sni: String,
        pin: [u8; 32],
        material: XMaterial,
        options: XOptions,
    },
    HyrakenPro {
        seed: SecretString,
        sni: String,
        pin: [u8; 32],
        certificate: SecretBytes,
        options: ProOptions,
    },
}

#[derive(PartialEq, Eq)]
pub(crate) struct NodeConfig {
    endpoint: Endpoint,
    protocol: ProtocolConfig,
}

impl NodeConfig {
    pub(crate) fn validate_certificate_times(&self) -> Result<(), CoreError> {
        use crate::certificates::validate_certificate_times;
        match &self.protocol {
            ProtocolConfig::Socks5(_) => Ok(()),
            ProtocolConfig::HyrakenX { material, .. } => validate_certificate_times(&[
                &material.server_certificate.0,
                &material.client_ca.0,
                &material.client_certificate.0,
            ]),
            ProtocolConfig::HyrakenPro { certificate, .. } => {
                validate_certificate_times(&[&certificate.0])
            }
        }
    }

    pub(crate) fn canonical_uri(&self) -> Result<Zeroizing<String>, CoreError> {
        let mut uri = Zeroizing::new(String::new());
        match &self.protocol {
            ProtocolConfig::Socks5(auth) => {
                uri.push_str("socks5://");
                if let SocksAuth::UsernamePassword { username, password } = auth {
                    encode_into(&mut uri, username.as_str().as_bytes())?;
                    uri.push(':');
                    encode_into(&mut uri, password.as_str().as_bytes())?;
                    uri.push('@');
                }
                uri.push_str(&self.endpoint.display());
            }
            ProtocolConfig::HyrakenX {
                seed,
                sni,
                pin,
                material,
                options,
            } => {
                uri.push_str("hyrakenx://");
                encode_into(&mut uri, seed.as_str().as_bytes())?;
                uri.push('@');
                uri.push_str(&self.endpoint.display());
                append_query(&mut uri, "sni", sni.as_bytes())?;
                append_base64(&mut uri, "pin", pin)?;
                append_base64(&mut uri, "server_cert", &material.server_certificate.0)?;
                append_base64(&mut uri, "ca", &material.client_ca.0)?;
                append_base64(&mut uri, "cert", &material.client_certificate.0)?;
                append_base64(&mut uri, "key", &material.client_key.0)?;
                append_query(
                    &mut uri,
                    "mode",
                    match options.mode {
                        XMode::Flash => b"flash",
                        XMode::Beast => b"beast",
                    },
                )?;
                append_query(
                    &mut uri,
                    "scenario",
                    match options.scenario {
                        XScenario::Bulk => b"bulk",
                        XScenario::Lossy => b"lossy",
                        XScenario::Speedtest => b"speedtest",
                    },
                )?;
                append_query(&mut uri, "rate", options.rate_mbps.to_string().as_bytes())?;
            }
            ProtocolConfig::HyrakenPro {
                seed,
                sni,
                pin,
                certificate,
                options,
            } => {
                uri.push_str("hyraken-pro://");
                encode_into(&mut uri, seed.as_str().as_bytes())?;
                uri.push('@');
                uri.push_str(&self.endpoint.display());
                append_query(&mut uri, "sni", sni.as_bytes())?;
                append_base64(&mut uri, "pin", pin)?;
                append_base64(&mut uri, "certificate", &certificate.0)?;
                append_query(&mut uri, "path", options.path.as_bytes())?;
                append_query(
                    &mut uri,
                    "transport",
                    match options.transport {
                        ProTransport::Auto => b"auto",
                        ProTransport::Tcp => b"tcp",
                        ProTransport::Grpc => b"grpc",
                    },
                )?;
                append_query(
                    &mut uri,
                    "engine",
                    match options.engine {
                        ProEngine::Ghostx => b"ghostx",
                        ProEngine::Naive => b"naive",
                    },
                )?;
                append_query(
                    &mut uri,
                    "suite",
                    match options.suite {
                        ProSuite::Auto => b"auto",
                        ProSuite::Aes256Gcm => b"aes-256-gcm",
                        ProSuite::Chacha20Poly1305 => b"chacha20-poly1305",
                        ProSuite::RoccaS => b"rocca-s",
                        ProSuite::AsconAead128 => b"ascon-aead128",
                    },
                )?;
                append_query(
                    &mut uri,
                    "congestion",
                    match options.congestion {
                        ProCongestion::Beast => b"beast",
                        ProCongestion::Bbr => b"bbr",
                    },
                )?;
                append_query(
                    &mut uri,
                    "connections",
                    options.connections.to_string().as_bytes(),
                )?;
                append_query(
                    &mut uri,
                    "traffic_profile",
                    match options.traffic_profile {
                        TrafficProfile::Auto => b"auto",
                        TrafficProfile::Gaming => b"gaming",
                        TrafficProfile::Streaming => b"streaming",
                        TrafficProfile::WebBrowsing => b"web_browsing",
                        TrafficProfile::WechatVoice => b"wechat_voice",
                    },
                )?;
                append_query(
                    &mut uri,
                    "elastic_mux",
                    if options.elastic_mux { b"1" } else { b"0" },
                )?;
                append_query(
                    &mut uri,
                    "isolation",
                    if options.isolation { b"1" } else { b"0" },
                )?;
                append_query(
                    &mut uri,
                    "packet_encoding",
                    match options.packet_encoding {
                        PacketEncoding::None => b"none",
                        PacketEncoding::Xudp => b"xudp",
                    },
                )?;
            }
        }
        if uri.len() > MAX_NODE_INPUT_BYTES {
            return Err(CoreError::InputTooLarge);
        }
        Ok(uri)
    }
}

fn append_query(uri: &mut String, key: &str, value: &[u8]) -> Result<(), CoreError> {
    uri.push(if uri.contains('?') { '&' } else { '?' });
    uri.push_str(key);
    uri.push('=');
    encode_into(uri, value)
}

fn append_base64(uri: &mut String, key: &str, value: &[u8]) -> Result<(), CoreError> {
    let encoded = Zeroizing::new(STANDARD.encode(value));
    append_query(uri, key, encoded.as_bytes())
}

fn encode_into(output: &mut String, raw: &[u8]) -> Result<(), CoreError> {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for byte in raw {
        let plain = byte.is_ascii_alphanumeric() || b"-._~".contains(byte);
        let extra = if plain { 1 } else { 3 };
        if output
            .len()
            .checked_add(extra)
            .is_none_or(|length| length > MAX_NODE_INPUT_BYTES)
        {
            return Err(CoreError::InputTooLarge);
        }
        if plain {
            output.push(char::from(*byte));
        } else {
            output.push('%');
            output.push(char::from(HEX[usize::from(byte >> 4)]));
            output.push(char::from(HEX[usize::from(byte & 15)]));
        }
    }
    Ok(())
}

pub(crate) struct NodeCandidate {
    pub(crate) config: NodeConfig,
    label: String,
}

impl NodeCandidate {
    pub(crate) fn summary(&self, id: String) -> NodeSummary {
        let (protocol, udp_min, udp_max, credential_material_present) = match &self.config.protocol
        {
            ProtocolConfig::Socks5(auth) => (
                ProtocolKind::Socks5,
                0,
                65_507,
                !matches!(auth, SocksAuth::None),
            ),
            ProtocolConfig::HyrakenX { .. } => (ProtocolKind::HyrakenX, 1, 1024, true),
            ProtocolConfig::HyrakenPro { .. } => (ProtocolKind::HyrakenPro, 0, 65_507, true),
        };
        NodeSummary {
            id,
            label: self.label.clone(),
            protocol,
            endpoint: self.config.endpoint.display(),
            udp_min,
            udp_max,
            credential_material_present,
        }
    }

    /// Charges owned configuration capacities plus bounded record/metadata overhead; not process PSS.
    pub(crate) fn retained_charge(&self) -> usize {
        let mut bytes = 1024 + self.label.capacity() + self.config.endpoint.host.capacity();
        match &self.config.protocol {
            ProtocolConfig::Socks5(SocksAuth::None) => {}
            ProtocolConfig::Socks5(SocksAuth::UsernamePassword { username, password }) => {
                bytes += username.capacity() + password.capacity();
            }
            ProtocolConfig::HyrakenX {
                seed,
                sni,
                material,
                ..
            } => {
                bytes += seed.capacity()
                    + sni.capacity()
                    + material.server_certificate.0.capacity()
                    + material.client_ca.0.capacity()
                    + material.client_certificate.0.capacity()
                    + material.client_key.0.capacity();
            }
            ProtocolConfig::HyrakenPro {
                seed,
                sni,
                certificate,
                options,
                ..
            } => {
                bytes += seed.capacity()
                    + sni.capacity()
                    + certificate.0.capacity()
                    + options.path.capacity();
            }
        }
        bytes
    }
}

type Query = BTreeMap<String, Zeroizing<Vec<u8>>>;

pub(crate) fn parse_node(raw: &str, now: Option<ASN1Time>) -> Result<NodeCandidate, CoreError> {
    if raw.len() > MAX_NODE_INPUT_BYTES {
        return Err(CoreError::InputTooLarge);
    }
    if raw.is_empty()
        || raw
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
    {
        return Err(CoreError::InvalidUri);
    }
    let (scheme, rest) = raw.split_once("://").ok_or(CoreError::InvalidUri)?;
    let kind = if scheme.eq_ignore_ascii_case("socks5") || scheme.eq_ignore_ascii_case("socks") {
        ProtocolKind::Socks5
    } else if scheme.eq_ignore_ascii_case("hyrakenx") {
        ProtocolKind::HyrakenX
    } else if scheme.eq_ignore_ascii_case("hyraken-pro") {
        ProtocolKind::HyrakenPro
    } else {
        return Err(CoreError::UnsupportedProtocol);
    };
    let (address_query, fragment) = match rest.split_once('#') {
        Some((rest, fragment)) if !fragment.contains('#') => (rest, Some(fragment)),
        Some(_) => return Err(CoreError::InvalidUri),
        None => (rest, None),
    };
    let (authority, query) = match address_query.split_once('?') {
        Some((authority, query)) if !query.contains('?') => (authority, Some(query)),
        Some(_) => return Err(CoreError::InvalidUri),
        None => (address_query, None),
    };
    if authority.contains(['/', '\\']) {
        return Err(CoreError::InvalidUri);
    }
    let (userinfo, host_port) = match authority.split_once('@') {
        Some((userinfo, host_port)) if !host_port.contains('@') => (Some(userinfo), host_port),
        Some(_) => return Err(CoreError::InvalidUri),
        None => (None, authority),
    };
    let endpoint = parse_endpoint(
        host_port,
        if kind == ProtocolKind::Socks5 {
            Some(1080)
        } else {
            None
        },
    )?;
    let mut budget = ParseBudget::default();
    let protocol = match kind {
        ProtocolKind::Socks5 => {
            let auth = parse_socks_auth(userinfo, &mut budget)?;
            let _query = parse_query(query, &[], &mut budget)?;
            ProtocolConfig::Socks5(auth)
        }
        ProtocolKind::HyrakenX => {
            let seed = parse_seed(userinfo, &mut budget)?;
            let mut query = parse_query(
                query,
                &[
                    "sni",
                    "pin",
                    "server_cert",
                    "ca",
                    "cert",
                    "key",
                    "mode",
                    "scenario",
                    "rate",
                ],
                &mut budget,
            )?;
            let sni = required_sni(&query)?;
            let pin = required_pin(&mut query, &mut budget)?;
            let options = x_options(&query)?;
            let material = XMaterial {
                server_certificate: required_material(
                    &mut query,
                    "server_cert",
                    MAX_PUBLIC_CERT_BYTES,
                    &mut budget,
                )?,
                client_ca: required_material(&mut query, "ca", MAX_PUBLIC_CERT_BYTES, &mut budget)?,
                client_certificate: required_material(
                    &mut query,
                    "cert",
                    MAX_CLIENT_MATERIAL_BYTES,
                    &mut budget,
                )?,
                client_key: required_material(
                    &mut query,
                    "key",
                    MAX_CLIENT_MATERIAL_BYTES,
                    &mut budget,
                )?,
            };
            validate_x_material(&material, &sni, &pin, now)?;
            ProtocolConfig::HyrakenX {
                seed,
                sni,
                pin,
                material,
                options,
            }
        }
        ProtocolKind::HyrakenPro => {
            let seed = parse_seed(userinfo, &mut budget)?;
            let mut query = parse_query(
                query,
                &[
                    "sni",
                    "pin",
                    "certificate",
                    "path",
                    "transport",
                    "engine",
                    "suite",
                    "congestion",
                    "connections",
                    "traffic_profile",
                    "elastic_mux",
                    "isolation",
                    "packet_encoding",
                ],
                &mut budget,
            )?;
            let sni = required_sni(&query)?;
            let pin = required_pin(&mut query, &mut budget)?;
            let options = pro_options(&query)?;
            let certificate = required_material(
                &mut query,
                "certificate",
                MAX_PUBLIC_CERT_BYTES,
                &mut budget,
            )?;
            validate_pro_material(&certificate.0, &sni, &pin, now)?;
            ProtocolConfig::HyrakenPro {
                seed,
                sni,
                pin,
                certificate,
                options,
            }
        }
    };
    let default = match kind {
        ProtocolKind::Socks5 => "SOCKS5 Node",
        ProtocolKind::HyrakenX => "HyrakenX",
        ProtocolKind::HyrakenPro => "Hyraken Pro",
    };
    let label = match fragment {
        None | Some("") => default.to_owned(),
        Some(fragment) => {
            let label = Zeroizing::new(decode_text(
                fragment,
                MAX_NODE_LABEL_BYTES,
                false,
                &mut budget,
            )?);
            if label
                .chars()
                .any(|character| character.is_control() || is_display_control(character))
            {
                return Err(CoreError::InvalidUri);
            }
            if label.trim().is_empty()
                || label.contains("://")
                || label.contains("PRIVATE KEY")
                || label.contains("-----BEGIN")
                || contains_credential(&label, &protocol)
                || userinfo.is_some_and(|userinfo| {
                    userinfo
                        .split(':')
                        .any(|part| !part.is_empty() && label.contains(part))
                })
            {
                default.to_owned()
            } else {
                label.to_string()
            }
        }
    };
    Ok(NodeCandidate {
        config: NodeConfig { endpoint, protocol },
        label,
    })
}

fn contains_credential(label: &str, protocol: &ProtocolConfig) -> bool {
    match protocol {
        ProtocolConfig::Socks5(SocksAuth::None) => false,
        ProtocolConfig::Socks5(SocksAuth::UsernamePassword { username, password }) => {
            label.contains(username.as_str()) || label.contains(password.as_str())
        }
        ProtocolConfig::HyrakenX { seed, .. } | ProtocolConfig::HyrakenPro { seed, .. } => {
            label.contains(seed.as_str())
        }
    }
}

fn is_display_control(character: char) -> bool {
    matches!(character, '\u{061c}' | '\u{200b}'..='\u{200f}' | '\u{2028}'..='\u{202e}' | '\u{2060}'..='\u{206f}' | '\u{feff}')
}

#[derive(Default)]
struct ParseBudget {
    decoded_bytes: usize,
}
impl ParseBudget {
    fn charge(&mut self, count: usize) -> Result<(), CoreError> {
        self.decoded_bytes = self
            .decoded_bytes
            .checked_add(count)
            .ok_or(CoreError::InputTooLarge)?;
        if self.decoded_bytes > MAX_NODE_INPUT_BYTES {
            return Err(CoreError::InputTooLarge);
        }
        Ok(())
    }
}

fn decode_bytes(
    raw: &str,
    limit: usize,
    form_query: bool,
    budget: &mut ParseBudget,
) -> Result<Zeroizing<Vec<u8>>, CoreError> {
    let source = raw.as_bytes();
    let mut decoded = Zeroizing::new(Vec::with_capacity(source.len().min(limit)));
    let mut cursor = 0;
    while cursor < source.len() {
        if decoded.len() == limit {
            return Err(CoreError::InputTooLarge);
        }
        let byte = if source[cursor] == b'%' {
            let pair = source
                .get(cursor + 1..cursor + 3)
                .ok_or(CoreError::InvalidUri)?;
            let hi = hex_digit(pair[0]).ok_or(CoreError::InvalidUri)?;
            let lo = hex_digit(pair[1]).ok_or(CoreError::InvalidUri)?;
            cursor += 3;
            hi * 16 + lo
        } else {
            let byte = if form_query && source[cursor] == b'+' {
                b' '
            } else {
                source[cursor]
            };
            cursor += 1;
            byte
        };
        decoded.push(byte);
    }
    budget.charge(decoded.len())?;
    Ok(decoded)
}

pub(crate) fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn decode_text(
    raw: &str,
    limit: usize,
    form_query: bool,
    budget: &mut ParseBudget,
) -> Result<String, CoreError> {
    let decoded = decode_bytes(raw, limit, form_query, budget)?;
    std::str::from_utf8(&decoded)
        .map(str::to_owned)
        .map_err(|_| CoreError::InvalidUri)
}

fn parse_socks_auth(raw: Option<&str>, budget: &mut ParseBudget) -> Result<SocksAuth, CoreError> {
    let Some(raw) = raw else {
        return Ok(SocksAuth::None);
    };
    let (username, password) = raw.split_once(':').ok_or(CoreError::InvalidCredential)?;
    let username = SecretString(Zeroizing::new(decode_text(username, 255, false, budget)?));
    let password = SecretString(Zeroizing::new(decode_text(password, 255, false, budget)?));
    if username.as_str().is_empty()
        || password.as_str().is_empty()
        || username.as_str().chars().any(char::is_control)
        || password.as_str().chars().any(char::is_control)
    {
        return Err(CoreError::InvalidCredential);
    }
    Ok(SocksAuth::UsernamePassword { username, password })
}

fn parse_seed(raw: Option<&str>, budget: &mut ParseBudget) -> Result<SecretString, CoreError> {
    let raw = raw.ok_or(CoreError::MissingField)?;
    if raw.contains(':') {
        return Err(CoreError::InvalidCredential);
    }
    let seed = SecretString(Zeroizing::new(decode_text(raw, 256, false, budget)?));
    if seed.as_str().len() < 32
        || seed
            .as_str()
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
    {
        return Err(CoreError::InvalidCredential);
    }
    Ok(seed)
}

fn parse_query(
    raw: Option<&str>,
    allowed: &[&str],
    budget: &mut ParseBudget,
) -> Result<Query, CoreError> {
    let Some(raw) = raw else {
        return Ok(Query::new());
    };
    if raw.is_empty() {
        return Err(CoreError::InvalidUri);
    }
    let mut query = Query::new();
    for (index, item) in raw.split('&').enumerate() {
        if index == MAX_QUERY_PARAMETERS {
            return Err(CoreError::InputTooLarge);
        }
        let (key, value) = item.split_once('=').ok_or(CoreError::InvalidUri)?;
        let key = Zeroizing::new(decode_text(key, 64, true, budget)?);
        if query.contains_key(key.as_str()) {
            return Err(CoreError::DuplicateParameter);
        }
        if !allowed.contains(&key.as_str()) {
            return Err(CoreError::UnknownParameter);
        }
        query.insert(
            key.to_string(),
            decode_bytes(value, MAX_QUERY_VALUE_BYTES, true, budget)?,
        );
    }
    Ok(query)
}

fn text<'a>(query: &'a Query, key: &str, default: &'a str) -> Result<&'a str, CoreError> {
    match query.get(key) {
        Some(value) => std::str::from_utf8(value).map_err(|_| CoreError::InvalidOption),
        None => Ok(default),
    }
}

fn required_sni(query: &Query) -> Result<String, CoreError> {
    let raw = query
        .get("sni")
        .filter(|value| !value.is_empty())
        .ok_or(CoreError::MissingField)?;
    let raw = std::str::from_utf8(raw).map_err(|_| CoreError::InvalidEndpoint)?;
    normalize_host(raw)
}

fn required_pin(query: &mut Query, budget: &mut ParseBudget) -> Result<[u8; 32], CoreError> {
    let raw = query
        .remove("pin")
        .filter(|value| !value.is_empty())
        .ok_or(CoreError::MissingField)?;
    if raw.len() != 44 {
        return Err(CoreError::InvalidCertificate);
    }
    let decoded = Zeroizing::new(
        STANDARD
            .decode(&raw)
            .map_err(|_| CoreError::InvalidCertificate)?,
    );
    budget.charge(decoded.len())?;
    decoded
        .as_slice()
        .try_into()
        .map_err(|_| CoreError::InvalidCertificate)
}

fn required_material(
    query: &mut Query,
    key: &str,
    limit: usize,
    budget: &mut ParseBudget,
) -> Result<SecretBytes, CoreError> {
    let raw = query
        .remove(key)
        .filter(|value| !value.is_empty())
        .ok_or(CoreError::MissingField)?;
    if raw.len() > limit.div_ceil(3) * 4 + 4 {
        return Err(CoreError::InputTooLarge);
    }
    let decoded = Zeroizing::new(
        STANDARD
            .decode(&raw)
            .map_err(|_| CoreError::InvalidCertificate)?,
    );
    if decoded.len() > limit {
        return Err(CoreError::InputTooLarge);
    }
    budget.charge(decoded.len())?;
    if decoded.is_empty() {
        return Err(CoreError::MissingField);
    }
    Ok(SecretBytes(decoded))
}

fn option_number(
    query: &Query,
    key: &str,
    default: u32,
    minimum: u32,
    maximum: u32,
) -> Result<u32, CoreError> {
    let Some(raw) = query.get(key) else {
        return Ok(default);
    };
    if raw.is_empty() || raw.len() > 10 || !raw.iter().all(u8::is_ascii_digit) {
        return Err(CoreError::InvalidOption);
    }
    let value = std::str::from_utf8(raw)
        .map_err(|_| CoreError::InvalidOption)?
        .parse::<u32>()
        .map_err(|_| CoreError::InvalidOption)?;
    if value < minimum || value > maximum {
        return Err(CoreError::InvalidOption);
    }
    Ok(value)
}

fn option_bool(query: &Query, key: &str, default: bool) -> Result<bool, CoreError> {
    match query.get(key).map(|value| value.as_slice()) {
        None => Ok(default),
        Some(b"0") => Ok(false),
        Some(b"1") => Ok(true),
        _ => Err(CoreError::InvalidOption),
    }
}

fn x_options(query: &Query) -> Result<XOptions, CoreError> {
    let mode = match text(query, "mode", "flash")? {
        "flash" => XMode::Flash,
        "beast" => XMode::Beast,
        _ => return Err(CoreError::InvalidOption),
    };
    let scenario = match text(query, "scenario", "bulk")? {
        "bulk" => XScenario::Bulk,
        "lossy" => XScenario::Lossy,
        "speedtest" => XScenario::Speedtest,
        _ => return Err(CoreError::InvalidOption),
    };
    let rate_mbps = option_number(query, "rate", 0, 0, 20_000)?;
    if mode == XMode::Flash && rate_mbps != 0 {
        return Err(CoreError::InvalidOption);
    }
    Ok(XOptions {
        mode,
        scenario,
        rate_mbps,
    })
}

fn pro_options(query: &Query) -> Result<ProOptions, CoreError> {
    let path = text(query, "path", "/hyraken.pro/Tunnel")?;
    if path.len() < 2
        || path.len() > 256
        || !path.starts_with('/')
        || path.contains("//")
        || !path
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"/_.-".contains(&byte))
    {
        return Err(CoreError::InvalidOption);
    }
    let transport = match text(query, "transport", "auto")? {
        "auto" => ProTransport::Auto,
        "tcp" => ProTransport::Tcp,
        "grpc" => ProTransport::Grpc,
        _ => return Err(CoreError::InvalidOption),
    };
    let engine = match text(query, "engine", "ghostx")? {
        "ghostx" => ProEngine::Ghostx,
        "naive" => ProEngine::Naive,
        _ => return Err(CoreError::InvalidOption),
    };
    let suite = match text(query, "suite", "auto")? {
        "auto" => ProSuite::Auto,
        "aes-256-gcm" => ProSuite::Aes256Gcm,
        "chacha20-poly1305" => ProSuite::Chacha20Poly1305,
        "rocca-s" => ProSuite::RoccaS,
        "ascon-aead128" => ProSuite::AsconAead128,
        _ => return Err(CoreError::InvalidOption),
    };
    let congestion = match text(query, "congestion", "beast")? {
        "beast" => ProCongestion::Beast,
        "bbr" => ProCongestion::Bbr,
        _ => return Err(CoreError::InvalidOption),
    };
    let traffic_profile = match text(query, "traffic_profile", "auto")? {
        "auto" => TrafficProfile::Auto,
        "gaming" => TrafficProfile::Gaming,
        "streaming" => TrafficProfile::Streaming,
        "web_browsing" => TrafficProfile::WebBrowsing,
        "wechat_voice" => TrafficProfile::WechatVoice,
        _ => return Err(CoreError::InvalidOption),
    };
    let packet_encoding = match text(query, "packet_encoding", "")? {
        "" | "none" => PacketEncoding::None,
        "xudp" => PacketEncoding::Xudp,
        _ => return Err(CoreError::InvalidOption),
    };
    Ok(ProOptions {
        path: path.to_owned(),
        transport,
        engine,
        suite,
        congestion,
        connections: option_number(query, "connections", 4, 1, 8)?,
        traffic_profile,
        elastic_mux: option_bool(query, "elastic_mux", true)?,
        isolation: option_bool(query, "isolation", false)?,
        packet_encoding,
    })
}
