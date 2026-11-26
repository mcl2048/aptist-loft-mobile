use crate::{CoreError, CoreState, import::hex_digit};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use data_encoding::{BASE32, BASE32_NOPAD};
use ring::{
    hmac,
    rand::{SecureRandom, SystemRandom},
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use zeroize::{Zeroize, Zeroizing};
mod sync;
pub(crate) use sync::State as SyncState;
pub use sync::{VaultSyncReceipt, VaultSyncStep};

pub const VAULT_IMAGE_LIMIT: usize = 240 * 1024;
const PAGE_SIZE: usize = 30;
const MAX_ENTRIES: usize = 200;
const MAX_SECRET: usize = 1024;
const MAX_FIELD: usize = 160;
const MAX_URI: usize = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub enum VaultKind {
    Totp,
    Password,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub enum VaultAlgorithm {
    Sha1,
    Sha256,
    Sha512,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VaultError {
    InvalidInput,
    NotFound,
    Archived,
    TooLarge,
    StaleGeneration,
    Unavailable,
    StorageRecoveryRequired,
    NotSignedIn,
    Busy,
    Conflict,
    AuthenticationFailed,
    NetworkUnavailable,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VaultEntry {
    pub id: String,
    pub kind: VaultKind,
    pub label: String,
    pub account: String,
    pub issuer: String,
    pub archived: bool,
    pub algorithm: Option<VaultAlgorithm>,
    pub digits: Option<u32>,
    pub period: Option<u32>,
}

pub struct VaultDraft {
    pub id: Option<String>,
    pub kind: VaultKind,
    pub label: String,
    pub account: String,
    pub issuer: String,
    pub secret: Option<Vec<u8>>,
    pub algorithm: Option<VaultAlgorithm>,
    pub digits: Option<u32>,
    pub period: Option<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultPage {
    pub generation: u64,
    pub offset: u32,
    pub entries: Vec<VaultEntry>,
    pub next_offset: Option<u32>,
}

pub struct VaultReveal {
    pub value: Vec<u8>,
    pub valid_for_seconds: Option<u32>,
}

#[derive(Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct VaultState {
    pub(crate) generation: u64,
    pub(crate) entries: BTreeMap<String, Record>,
    revisions: BTreeMap<String, sync::Baseline>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Record {
    pub(crate) entry: VaultEntry,
    #[serde(with = "secret_bytes")]
    secret: Zeroizing<Vec<u8>>,
    pub(crate) owner: Option<String>,
    pub(crate) version: u64,
}

mod secret_bytes {
    use super::*;

    pub(super) fn serialize<S: serde::Serializer>(
        value: &Zeroizing<Vec<u8>>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let encoded = Zeroizing::new(URL_SAFE_NO_PAD.encode(value));
        serializer.serialize_str(&encoded)
    }

    pub(super) fn deserialize<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Zeroizing<Vec<u8>>, D::Error> {
        let encoded = Zeroizing::new(String::deserialize(deserializer)?);
        if encoded.len() > MAX_SECRET.div_ceil(3) * 4 {
            return Err(serde::de::Error::custom("vault secret limit"));
        }
        let mut decoded = Zeroizing::new(vec![0; (encoded.len() * 3).div_ceil(4)]);
        let length = URL_SAFE_NO_PAD
            .decode_slice(&*encoded, &mut decoded)
            .map_err(|_| serde::de::Error::custom("vault secret encoding"))?;
        decoded.truncate(length);
        Ok(decoded)
    }
}

impl CoreState {
    pub fn vault_save(&mut self, draft: VaultDraft) -> Result<VaultEntry, VaultError> {
        let secret_input = draft.secret.map(Zeroizing::new);
        let mut next = self.vault.clone();
        let prior = draft
            .id
            .as_deref()
            .map(|id| next.entries.get(id).ok_or(VaultError::NotFound))
            .transpose()?;
        if prior.is_none() && next.entries.len() >= MAX_ENTRIES {
            return Err(VaultError::TooLarge);
        }
        let secret = match (draft.kind, secret_input, prior) {
            (VaultKind::Totp, Some(bytes), _) => decode_secret(&bytes)?,
            (VaultKind::Password, Some(bytes), _) => bytes,
            (kind, None, Some(record)) if record.entry.kind == kind => record.secret.clone(),
            _ => return Err(VaultError::InvalidInput),
        };
        let id = match draft.id {
            Some(id) => id,
            None => random_id::<16>()?,
        };
        let entry = VaultEntry {
            id: id.clone(),
            kind: draft.kind,
            label: draft.label,
            account: draft.account,
            issuer: draft.issuer,
            archived: prior.is_some_and(|record| record.entry.archived),
            algorithm: draft.algorithm,
            digits: draft.digits,
            period: draft.period,
        };
        let record = Record {
            entry: entry.clone(),
            secret,
            owner: prior.and_then(|record| record.owner.clone()),
            version: prior.map_or(Ok(1), |record| {
                record.version.checked_add(1).ok_or(VaultError::Unavailable)
            })?,
        };
        record.validate()?;
        next.entries.insert(id, record);
        self.commit_vault(next)?;
        Ok(entry)
    }

    pub fn vault_import(&mut self, uri: Vec<u8>) -> Result<VaultEntry, VaultError> {
        let uri = Zeroizing::new(uri);
        self.vault_save(parse_uri(&uri)?)
    }

    pub fn vault_archive(&mut self, id: &str, archived: bool) -> Result<VaultEntry, VaultError> {
        let mut next = self.vault.clone();
        let record = next.entries.get_mut(id).ok_or(VaultError::NotFound)?;
        if record.entry.archived == archived {
            return Ok(record.entry.clone());
        }
        record.entry.archived = archived;
        record.version = record
            .version
            .checked_add(1)
            .ok_or(VaultError::Unavailable)?;
        let entry = record.entry.clone();
        self.commit_vault(next)?;
        Ok(entry)
    }

    pub fn vault_list(
        &self,
        archived: bool,
        offset: u32,
        expected_generation: Option<u64>,
    ) -> Result<VaultPage, VaultError> {
        self.require_local_config().map_err(storage_error)?;
        if expected_generation.is_some_and(|generation| generation != self.vault.generation)
            || (offset != 0 && expected_generation.is_none())
        {
            return Err(VaultError::StaleGeneration);
        }
        let skip = offset as usize;
        if skip >= MAX_ENTRIES || !skip.is_multiple_of(PAGE_SIZE) {
            return Err(VaultError::InvalidInput);
        }
        let mut entries = self
            .vault
            .entries
            .values()
            .filter(|record| record.entry.archived == archived)
            .skip(skip)
            .take(PAGE_SIZE + 1)
            .map(|record| record.entry.clone())
            .collect::<Vec<_>>();
        let next_offset = if entries.len() > PAGE_SIZE {
            entries.pop();
            Some(offset + PAGE_SIZE as u32)
        } else {
            None
        };
        Ok(VaultPage {
            generation: self.vault.generation,
            offset,
            entries,
            next_offset,
        })
    }

    pub fn vault_reveal(&self, id: &str, unix_seconds: u64) -> Result<VaultReveal, VaultError> {
        self.require_local_config().map_err(storage_error)?;
        let record = self.vault.entries.get(id).ok_or(VaultError::NotFound)?;
        if record.entry.archived {
            return Err(VaultError::Archived);
        }
        match record.entry.kind {
            VaultKind::Password => Ok(VaultReveal {
                value: record.secret.to_vec(),
                valid_for_seconds: None,
            }),
            VaultKind::Totp => {
                let (algorithm, digits, period) = parameters(&record.entry)?;
                let code = generate_code(
                    &record.secret,
                    algorithm,
                    digits,
                    unix_seconds / u64::from(period),
                );
                Ok(VaultReveal {
                    value: code,
                    valid_for_seconds: Some(period - (unix_seconds % u64::from(period)) as u32),
                })
            }
        }
    }

    pub(crate) fn commit_vault(&mut self, mut next: VaultState) -> Result<(), VaultError> {
        next.generation = self
            .vault
            .generation
            .checked_add(1)
            .ok_or(VaultError::Unavailable)?;
        let encoded =
            Zeroizing::new(serde_json::to_vec(&next).map_err(|_| VaultError::Unavailable)?);
        if encoded.len() > VAULT_IMAGE_LIMIT {
            return Err(VaultError::TooLarge);
        }
        self.commit_private(crate::PrivateRecord::Vault, Some(&encoded))
            .map_err(storage_error)?;
        self.vault = next;
        Ok(())
    }
}

impl VaultState {
    pub(crate) fn restore(raw: &[u8]) -> Result<Self, CoreError> {
        if raw.len() > VAULT_IMAGE_LIMIT {
            return Err(CoreError::StorageRecoveryRequired);
        }
        let state: Self =
            serde_json::from_slice(raw).map_err(|_| CoreError::StorageRecoveryRequired)?;
        if state.entries.len() > MAX_ENTRIES
            || state.revisions.len() > MAX_ENTRIES
            || (state.generation == 0 && (!state.entries.is_empty() || !state.revisions.is_empty()))
            || state
                .entries
                .iter()
                .any(|(id, record)| id != &record.entry.id || record.validate().is_err())
            || state
                .revisions
                .iter()
                .any(|(scope, revision)| !fixed_id(scope, 32) || !revision.valid())
        {
            return Err(CoreError::StorageRecoveryRequired);
        }
        Ok(state)
    }
}

impl Record {
    pub(crate) fn validate(&self) -> Result<(), VaultError> {
        let entry = &self.entry;
        if !fixed_id(&entry.id, 16)
            || self.version == 0
            || self
                .owner
                .as_ref()
                .is_some_and(|scope| !fixed_id(scope, 32))
            || !valid_field(&entry.label, true)
            || !valid_field(&entry.account, false)
            || !valid_field(&entry.issuer, false)
        {
            return Err(VaultError::InvalidInput);
        }
        match entry.kind {
            VaultKind::Totp => {
                parameters(entry)?;
                if !(10..=64).contains(&self.secret.len()) {
                    return Err(VaultError::InvalidInput);
                }
            }
            VaultKind::Password => {
                if entry.algorithm.is_some()
                    || entry.digits.is_some()
                    || entry.period.is_some()
                    || !(1..=MAX_SECRET).contains(&self.secret.len())
                    || !std::str::from_utf8(&self.secret)
                        .is_ok_and(|text| !text.chars().any(char::is_control))
                {
                    return Err(VaultError::InvalidInput);
                }
            }
        }
        Ok(())
    }
}

pub(crate) fn random_id<const LENGTH: usize>() -> Result<String, VaultError> {
    let mut bytes = [0u8; LENGTH];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| VaultError::Unavailable)?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

fn fixed_id(value: &str, bytes: usize) -> bool {
    value.len() == (bytes * 8).div_ceil(6)
        && URL_SAFE_NO_PAD
            .decode(value)
            .is_ok_and(|decoded| decoded.len() == bytes)
}

fn storage_error(error: CoreError) -> VaultError {
    match error {
        CoreError::StorageRecoveryRequired => VaultError::StorageRecoveryRequired,
        _ => VaultError::Unavailable,
    }
}

fn valid_field(value: &str, required: bool) -> bool {
    value.len() <= MAX_FIELD
        && (!required || !value.trim().is_empty())
        && !value.chars().any(|character| {
            character.is_control() || matches!(character, '\u{061c}' | '\u{200e}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
        })
}

fn parameters(entry: &VaultEntry) -> Result<(VaultAlgorithm, u32, u32), VaultError> {
    match (entry.algorithm, entry.digits, entry.period) {
        (Some(algorithm), Some(digits @ (6 | 8)), Some(period @ 15..=120)) => {
            Ok((algorithm, digits, period))
        }
        _ => Err(VaultError::InvalidInput),
    }
}

fn decode_secret(raw: &[u8]) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    if raw.len() > 104 || !raw.is_ascii() {
        return Err(VaultError::InvalidInput);
    }
    let upper = Zeroizing::new(raw.to_ascii_uppercase());
    let encoding = if upper.last() == Some(&b'=') {
        BASE32
    } else {
        BASE32_NOPAD
    };
    let mut decoded = Zeroizing::new(vec![
        0;
        encoding
            .decode_len(upper.len())
            .map_err(|_| VaultError::InvalidInput)?
    ]);
    let length = encoding
        .decode_mut(&upper, &mut decoded)
        .map_err(|_| VaultError::InvalidInput)?;
    decoded.truncate(length);
    if !(10..=64).contains(&length) {
        return Err(VaultError::InvalidInput);
    }
    Ok(decoded)
}

fn parse_uri(uri: &[u8]) -> Result<VaultDraft, VaultError> {
    if uri.len() > MAX_URI
        || uri
            .iter()
            .any(|byte| byte.is_ascii_control() || matches!(byte, b' ' | b'#'))
    {
        return Err(VaultError::InvalidInput);
    }
    let raw = std::str::from_utf8(uri).map_err(|_| VaultError::InvalidInput)?;
    let (label, query) = raw
        .strip_prefix("otpauth://totp/")
        .and_then(|path| path.split_once('?'))
        .ok_or(VaultError::InvalidInput)?;
    let label = percent_decode(label)?;
    let label = std::str::from_utf8(&label).map_err(|_| VaultError::InvalidInput)?;
    if label.contains(['/', '\\', '?', '#']) {
        return Err(VaultError::InvalidInput);
    }
    let (prefix, account) = label
        .split_once(':')
        .map_or(("", label), |(prefix, account)| {
            (prefix.trim(), account.trim())
        });
    if account.is_empty() || account.contains(':') || (label.contains(':') && prefix.is_empty()) {
        return Err(VaultError::InvalidInput);
    }
    let mut fields = BTreeMap::new();
    for field in query.split('&') {
        let (key, value) = field.split_once('=').ok_or(VaultError::InvalidInput)?;
        if !matches!(key, "secret" | "issuer" | "algorithm" | "digits" | "period")
            || fields.insert(key, percent_decode(value)?).is_some()
        {
            return Err(VaultError::InvalidInput);
        }
    }
    let issuer = field_text(&fields, "issuer")?.unwrap_or(prefix);
    if !prefix.is_empty() && issuer != prefix {
        return Err(VaultError::InvalidInput);
    }
    let algorithm = match field_text(&fields, "algorithm")?.unwrap_or("SHA1") {
        "SHA1" => VaultAlgorithm::Sha1,
        "SHA256" => VaultAlgorithm::Sha256,
        "SHA512" => VaultAlgorithm::Sha512,
        _ => return Err(VaultError::InvalidInput),
    };
    let digits = field_text(&fields, "digits")?
        .unwrap_or("6")
        .parse()
        .map_err(|_| VaultError::InvalidInput)?;
    let period = field_text(&fields, "period")?
        .unwrap_or("30")
        .parse()
        .map_err(|_| VaultError::InvalidInput)?;
    let secret = fields.get("secret").ok_or(VaultError::InvalidInput)?;
    Ok(VaultDraft {
        id: None,
        kind: VaultKind::Totp,
        label: if issuer.is_empty() {
            account.into()
        } else {
            issuer.into()
        },
        account: account.into(),
        issuer: issuer.into(),
        secret: Some(secret.to_vec()),
        algorithm: Some(algorithm),
        digits: Some(digits),
        period: Some(period),
    })
}

fn field_text<'a>(
    fields: &'a BTreeMap<&str, Zeroizing<Vec<u8>>>,
    key: &str,
) -> Result<Option<&'a str>, VaultError> {
    fields
        .get(key)
        .map(|value| std::str::from_utf8(value).map_err(|_| VaultError::InvalidInput))
        .transpose()
}

fn percent_decode(raw: &str) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    let mut decoded = Zeroizing::new(Vec::with_capacity(raw.len()));
    let mut bytes = raw.bytes();
    while let Some(byte) = bytes.next() {
        let byte = if byte == b'%' {
            let high = bytes
                .next()
                .and_then(hex_digit)
                .ok_or(VaultError::InvalidInput)?;
            let low = bytes
                .next()
                .and_then(hex_digit)
                .ok_or(VaultError::InvalidInput)?;
            (high << 4) | low
        } else {
            byte
        };
        decoded.push(byte);
    }
    Ok(decoded)
}

fn generate_code(secret: &[u8], algorithm: VaultAlgorithm, digits: u32, counter: u64) -> Vec<u8> {
    let algorithm = match algorithm {
        VaultAlgorithm::Sha1 => hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
        VaultAlgorithm::Sha256 => hmac::HMAC_SHA256,
        VaultAlgorithm::Sha512 => hmac::HMAC_SHA512,
    };
    let digest = hmac::sign(&hmac::Key::new(algorithm, secret), &counter.to_be_bytes());
    let mut mac = Zeroizing::new([0u8; 64]);
    mac[..digest.as_ref().len()].copy_from_slice(digest.as_ref());
    let offset = u32::from(mac[digest.as_ref().len() - 1] & 0x0f);
    let mut binary = 0u32;
    // RFC 4226's offset comes from the secret-dependent digest. Read a fixed window.
    for window in 0..16 {
        let equal = ((u32::from(window as u8) ^ offset).wrapping_sub(1)) >> 31;
        let word = u32::from_be_bytes([
            mac[window],
            mac[window + 1],
            mac[window + 2],
            mac[window + 3],
        ]);
        binary |= word & 0u32.wrapping_sub(equal);
    }
    binary &= 0x7fff_ffff;
    let mut code = vec![0; digits as usize];
    // Fixed decimal extraction of the low digits avoids a divide by a dynamic modulus.
    for position in code.iter_mut().rev() {
        let quotient = ((u64::from(binary) * 0xcccc_cccd) >> 35) as u32;
        *position = b'0' + (binary - quotient * 10) as u8;
        binary = quotient;
    }
    binary.zeroize();
    code
}
