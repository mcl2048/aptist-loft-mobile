use crate::{CoreError, import::XMaterial};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use sha2::{Digest, Sha256};
use std::net::IpAddr;
use x509_parser::{extensions::GeneralName, prelude::*};
use zeroize::Zeroizing;

const MAX_PEM_CERTIFICATES: usize = 8;

/// Checks import material only. Live TLS identity/chain/revocation remains the data-plane adapter's job.
pub(crate) fn validate_pro_material(
    pem: &[u8],
    sni: &str,
    pin: &[u8; 32],
    now: Option<ASN1Time>,
) -> Result<(), CoreError> {
    let certificates = certificates(pem)?;
    validate_server_certificates(&certificates, sni, pin, now)
}

pub(crate) fn validate_x_material(
    material: &XMaterial,
    sni: &str,
    pin: &[u8; 32],
    now: Option<ASN1Time>,
) -> Result<(), CoreError> {
    let server = certificates(&material.server_certificate.0)?;
    validate_server_certificates(&server, sni, pin, now)?;
    let client = certificates(&material.client_certificate.0)?;
    let authorities = certificates(&material.client_ca.0)?;
    let leaf = checked_certificate(&client[0], now)?;
    if leaf
        .extended_key_usage()
        .map_err(|_| CoreError::InvalidCertificate)?
        .is_some_and(|usage| !usage.value.client_auth && !usage.value.any)
    {
        return Err(CoreError::InvalidCertificate);
    }
    validate_chain_links(&client, now)?;
    let last = checked_certificate(client.last().ok_or(CoreError::InvalidCertificate)?, now)?;
    let mut signed_by_authority = false;
    for authority in &authorities {
        let authority = checked_certificate(authority, now)?;
        if !authority
            .basic_constraints()
            .map_err(|_| CoreError::InvalidCertificate)?
            .is_some_and(|constraints| constraints.value.ca)
            || authority
                .key_usage()
                .map_err(|_| CoreError::InvalidCertificate)?
                .is_some_and(|usage| !usage.value.key_cert_sign())
        {
            return Err(CoreError::InvalidCertificate);
        }
        if last.issuer() == authority.subject()
            && last.verify_signature(Some(authority.public_key())).is_ok()
        {
            signed_by_authority = true;
        }
    }
    if !signed_by_authority {
        return Err(CoreError::InvalidCertificate);
    }
    strict_pem_envelope(
        &material.client_key.0,
        &["PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY"],
        1,
    )?;
    let key = Zeroizing::new(
        PrivateKeyDer::from_pem_slice(&material.client_key.0)
            .map_err(|_| CoreError::InvalidCertificate)?,
    );
    let signing_key = rustls::crypto::ring::sign::any_supported_type(&key)
        .map_err(|_| CoreError::InvalidCertificate)?;
    let public_key = signing_key
        .public_key()
        .ok_or(CoreError::InvalidCertificate)?;
    if public_key.as_ref() != leaf.public_key().raw {
        return Err(CoreError::InvalidCertificate);
    }
    Ok(())
}

fn validate_server_certificates(
    certificates: &[CertificateDer<'_>],
    sni: &str,
    pin: &[u8; 32],
    now: Option<ASN1Time>,
) -> Result<(), CoreError> {
    let leaf = checked_certificate(&certificates[0], now)?;
    if leaf
        .extended_key_usage()
        .map_err(|_| CoreError::InvalidCertificate)?
        .is_some_and(|usage| !usage.value.server_auth && !usage.value.any)
    {
        return Err(CoreError::InvalidCertificate);
    }
    let digest: [u8; 32] = Sha256::digest(leaf.public_key().raw).into();
    if digest != *pin || !matches_server_name(&leaf, sni)? {
        return Err(CoreError::InvalidCertificate);
    }
    validate_chain_links(certificates, now)
}

fn checked_certificate<'a>(
    der: &'a CertificateDer<'_>,
    now: Option<ASN1Time>,
) -> Result<X509Certificate<'a>, CoreError> {
    let (remainder, certificate) =
        X509Certificate::from_der(der.as_ref()).map_err(|_| CoreError::InvalidCertificate)?;
    if !remainder.is_empty()
        || certificate.validity().not_before >= certificate.validity().not_after
        || now.is_some_and(|now| {
            now < certificate.validity().not_before || now >= certificate.validity().not_after
        })
        || certificate.extensions_map().is_err()
    {
        return Err(CoreError::InvalidCertificate);
    }
    Ok(certificate)
}

fn validate_chain_links(
    certificates: &[CertificateDer<'_>],
    now: Option<ASN1Time>,
) -> Result<(), CoreError> {
    for certificate in certificates {
        checked_certificate(certificate, now)?;
    }
    for pair in certificates.windows(2) {
        let child = checked_certificate(&pair[0], now)?;
        let parent = checked_certificate(&pair[1], now)?;
        if child.issuer() != parent.subject()
            || !parent
                .basic_constraints()
                .map_err(|_| CoreError::InvalidCertificate)?
                .is_some_and(|constraints| constraints.value.ca)
            || child.verify_signature(Some(parent.public_key())).is_err()
        {
            return Err(CoreError::InvalidCertificate);
        }
    }
    Ok(())
}

/// Stored certificates remain manageable after expiry, but they cannot open a new VPN.
pub(crate) fn validate_certificate_times(pem: &[&[u8]]) -> Result<(), CoreError> {
    let now = Some(ASN1Time::now());
    for chain in pem {
        for certificate in certificates(chain)? {
            checked_certificate(&certificate, now)?;
        }
    }
    Ok(())
}

fn matches_server_name(certificate: &X509Certificate<'_>, sni: &str) -> Result<bool, CoreError> {
    let names = certificate
        .subject_alternative_name()
        .map_err(|_| CoreError::InvalidCertificate)?
        .ok_or(CoreError::InvalidCertificate)?;
    Ok(names
        .value
        .general_names
        .iter()
        .any(|name| match (name, sni.parse::<IpAddr>()) {
            (GeneralName::DNSName(pattern), Err(_)) => dns_name_matches(pattern, sni),
            (GeneralName::IPAddress(raw), Ok(IpAddr::V4(address))) => *raw == address.octets(),
            (GeneralName::IPAddress(raw), Ok(IpAddr::V6(address))) => *raw == address.octets(),
            _ => false,
        }))
}

fn dns_name_matches(pattern: &str, name: &str) -> bool {
    if let Some(suffix) = pattern.strip_prefix("*.") {
        name.split_once('.')
            .is_some_and(|(label, rest)| !label.is_empty() && rest.eq_ignore_ascii_case(suffix))
    } else {
        pattern.eq_ignore_ascii_case(name)
    }
}

fn certificates(pem: &[u8]) -> Result<Vec<CertificateDer<'static>>, CoreError> {
    let count = strict_pem_envelope(pem, &["CERTIFICATE"], MAX_PEM_CERTIFICATES)?;
    let mut certificates = Vec::with_capacity(count);
    for certificate in CertificateDer::pem_slice_iter(pem) {
        certificates.push(certificate.map_err(|_| CoreError::InvalidCertificate)?);
    }
    if certificates.len() != count {
        return Err(CoreError::InvalidCertificate);
    }
    Ok(certificates)
}

// The PEM decoder intentionally skips surrounding text; the import boundary rejects that ambiguity.
fn strict_pem_envelope(raw: &[u8], allowed: &[&str], maximum: usize) -> Result<usize, CoreError> {
    let mut remainder = std::str::from_utf8(raw)
        .map_err(|_| CoreError::InvalidCertificate)?
        .trim_matches(|character: char| character.is_ascii_whitespace());
    let mut count = 0;
    while !remainder.is_empty() {
        if count == maximum {
            return Err(CoreError::InvalidCertificate);
        }
        let after_begin = remainder
            .strip_prefix("-----BEGIN ")
            .ok_or(CoreError::InvalidCertificate)?;
        let (kind, body) = after_begin
            .split_once("-----")
            .ok_or(CoreError::InvalidCertificate)?;
        if !allowed.contains(&kind) || !body.starts_with(['\r', '\n']) {
            return Err(CoreError::InvalidCertificate);
        }
        let end_marker = format!("-----END {kind}-----");
        let (body, rest) = body
            .split_once(&end_marker)
            .ok_or(CoreError::InvalidCertificate)?;
        if !body.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || b"+/=".contains(&byte) || byte.is_ascii_whitespace()
        }) {
            return Err(CoreError::InvalidCertificate);
        }
        remainder = rest.trim_matches(|character: char| character.is_ascii_whitespace());
        count += 1;
    }
    if count == 0 {
        return Err(CoreError::InvalidCertificate);
    }
    Ok(count)
}
