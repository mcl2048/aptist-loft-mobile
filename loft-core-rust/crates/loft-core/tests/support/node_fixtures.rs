use base64::{Engine, engine::general_purpose::STANDARD};
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, PublicKeyData, date_time_ymd,
};
use sha2::{Digest, Sha256};
use std::sync::OnceLock;

// Test-only, generated independently of import code; no production or task credentials.
pub struct TestIdentity {
    pub server_pem: String,
    pub pin: String,
    pub ca_pem: String,
    pub client_pem: String,
    pub client_key: String,
}

pub fn parameters(names: Vec<String>) -> CertificateParams {
    let mut params = CertificateParams::new(names).unwrap();
    params.not_before = date_time_ymd(2020, 1, 1);
    params.not_after = date_time_ymd(2100, 1, 1);
    params
}

pub fn identity() -> &'static TestIdentity {
    static IDENTITY: OnceLock<TestIdentity> = OnceLock::new();
    IDENTITY.get_or_init(|| {
        let server_key = KeyPair::generate().unwrap();
        let mut server_params = parameters(vec!["node.example".into()]);
        server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let server = server_params.self_signed(&server_key).unwrap();
        let ca_key = KeyPair::generate().unwrap();
        let mut ca_params = parameters(vec!["test-ca.example".into()]);
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        let ca = ca_params.self_signed(&ca_key).unwrap();
        let client_key = KeyPair::generate().unwrap();
        let mut client_params = parameters(vec!["client.example".into()]);
        client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        client_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        let client = client_params
            .signed_by(&client_key, &Issuer::from_params(&ca_params, &ca_key))
            .unwrap();
        TestIdentity {
            server_pem: server.pem(),
            pin: STANDARD.encode(Sha256::digest(server_key.subject_public_key_info())),
            ca_pem: ca.pem(),
            client_pem: client.pem(),
            client_key: client_key.serialize_pem(),
        }
    })
}

pub fn percent_encode(raw: &str) -> String {
    let mut output = String::new();
    for byte in raw.bytes() {
        if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) {
            output.push(char::from(byte));
        } else {
            output.push_str(&format!("%{byte:02X}"));
        }
    }
    output
}

pub fn encoded_material(raw: &str) -> String {
    percent_encode(&STANDARD.encode(raw))
}

pub fn pro_uri() -> String {
    let test = identity();
    format!(
        "hyraken-pro://0123456789abcdef0123456789abcdef@node.example:10994?sni=node.example&pin={}&certificate={}&path=%2Fhyraken.pro%2FTunnel&transport=grpc&engine=ghostx&suite=auto&congestion=beast&connections=1&traffic_profile=auto&elastic_mux=0&isolation=1&packet_encoding=xudp#Pro",
        percent_encode(&test.pin),
        encoded_material(&test.server_pem)
    )
}

pub fn x_uri() -> String {
    let test = identity();
    format!(
        "hyrakenx://0123456789abcdef0123456789abcdef@node.example:10995?sni=node.example&pin={}&server_cert={}&ca={}&cert={}&key={}&mode=beast&scenario=bulk&rate=100#X",
        percent_encode(&test.pin),
        encoded_material(&test.server_pem),
        encoded_material(&test.ca_pem),
        encoded_material(&test.client_pem),
        encoded_material(&test.client_key)
    )
}
