use crate::{CoreError, CoreState, PrivateRecord, vault::random_id};
use argon2::{Algorithm, Argon2, Block, Params, Version};
use ring::{
    hmac,
    rand::{SecureRandom, SystemRandom},
};
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

pub const PROTECTION_IMAGE_LIMIT: usize = 2048;
const PIN_KDF_KIB: u32 = 19 * 1024;
const PIN_TAG_CONTEXT: &[u8] = b"LOFT application PIN v1";
const MAX_PIN_DELAY: u64 = 30 * 60;
const BIOMETRIC_WINDOW: Duration = Duration::from_secs(120);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecureError {
    InvalidInput,
    NotFound,
    StaleGeneration,
    Locked,
    IncorrectPin,
    RateLimited,
    TooLarge,
    Unavailable,
    StorageRecoveryRequired,
    NotSignedIn,
    Busy,
    Conflict,
    AuthenticationFailed,
    NetworkUnavailable,
    Unsupported,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProtectionScope {
    Vault,
    Notes,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProtectionStatus {
    pub enabled: bool,
    pub biometric_enabled: bool,
    pub retry_at: Option<u64>,
}

pub struct ProtectionAccess {
    pub challenge: String,
    pub unlocked: bool,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PinRecord {
    salt: [u8; 16],
    tag: [u8; 32],
    biometric_enabled: bool,
    failed: u8,
    retry_at: Option<u64>,
}

impl PinRecord {
    pub(crate) fn restore(data: &[u8]) -> Result<Self, CoreError> {
        let record: Self =
            serde_json::from_slice(data).map_err(|_| CoreError::StorageRecoveryRequired)?;
        if record.failed > 32 || (record.failed >= 5) != record.retry_at.is_some() {
            return Err(CoreError::StorageRecoveryRequired);
        }
        Ok(record)
    }
}

#[derive(Default)]
pub(crate) struct Protection {
    pub(crate) pin: Option<PinRecord>,
    page: Option<Page>,
    auth_job: Option<u64>,
    auth_sequence: u64,
}

struct Page {
    scope: ProtectionScope,
    challenge: String,
    issued: Instant,
    notes_generation: Option<u64>,
    unlocked: bool,
}

enum Action {
    Unlock {
        challenge: String,
    },
    Configure {
        pin: Option<Zeroizing<Vec<u8>>>,
        biometric: bool,
    },
}

pub struct ProtectionWork {
    id: u64,
    verifier: Option<PinRecord>,
    current: Option<Zeroizing<Vec<u8>>>,
    action: Action,
}

pub struct ProtectionResult {
    id: u64,
    outcome: Result<Verified, SecureError>,
}

enum Verified {
    Unlock(String),
    Configure(Option<PinRecord>),
}

impl CoreState {
    pub fn protection_status(&self) -> Result<ProtectionStatus, SecureError> {
        self.require_local_config().map_err(storage_error)?;
        Ok(ProtectionStatus {
            enabled: self.protection.pin.is_some(),
            biometric_enabled: self
                .protection
                .pin
                .as_ref()
                .is_some_and(|pin| pin.biometric_enabled),
            retry_at: self.protection.pin.as_ref().and_then(|pin| pin.retry_at),
        })
    }

    pub fn protection_begin(
        &mut self,
        scope: ProtectionScope,
    ) -> Result<ProtectionAccess, SecureError> {
        let unlocked = !self.protection_status()?.enabled;
        self.protection.page = None;
        let challenge = random_id::<24>().map_err(|_| SecureError::Unavailable)?;
        self.protection.page = Some(Page {
            scope,
            challenge: challenge.clone(),
            issued: Instant::now(),
            notes_generation: (scope == ProtectionScope::Notes)
                .then(|| self.hub.scope_generation()),
            unlocked,
        });
        Ok(ProtectionAccess {
            challenge,
            unlocked,
        })
    }

    pub fn protection_end(&mut self, challenge: &str) {
        if self
            .protection
            .page
            .as_ref()
            .is_some_and(|page| page.challenge == challenge)
        {
            self.protection.page = None;
        }
    }

    pub fn protection_require(
        &self,
        scope: ProtectionScope,
        lease: &str,
    ) -> Result<(), SecureError> {
        self.require_local_config().map_err(storage_error)?;
        if self.protection.page.as_ref().is_some_and(|page| {
            page.scope == scope
                && page.challenge == lease
                && page.unlocked
                && self.protection_page_current(page)
        }) {
            Ok(())
        } else {
            Err(SecureError::Locked)
        }
    }

    pub fn protection_require_vault(&self) -> Result<(), SecureError> {
        if self.protection.pin.is_none() {
            return Ok(());
        }
        let page = self.protection.page.as_ref().ok_or(SecureError::Locked)?;
        self.protection_require(ProtectionScope::Vault, &page.challenge)
    }

    pub fn protection_configure_prepare(
        &mut self,
        current: Option<Vec<u8>>,
        new: Option<Vec<u8>>,
        biometric: bool,
        now: u64,
    ) -> Result<ProtectionWork, SecureError> {
        let new = new.map(Zeroizing::new);
        let current = current.map(Zeroizing::new);
        if new.as_deref().is_some_and(|pin| !valid_pin(pin)) || (new.is_none() && biometric) {
            return Err(SecureError::InvalidInput);
        }
        self.protection_prepare(
            current,
            Action::Configure {
                pin: new,
                biometric,
            },
            now,
        )
    }

    pub fn protection_unlock_prepare(
        &mut self,
        challenge: String,
        pin: Vec<u8>,
        now: u64,
    ) -> Result<ProtectionWork, SecureError> {
        let pin = Zeroizing::new(pin);
        let page = self.protection.page.as_ref().ok_or(SecureError::Locked)?;
        if page.challenge != challenge
            || page.unlocked
            || self.protection.pin.is_none()
            || !self.protection_page_current(page)
        {
            return Err(SecureError::Locked);
        }
        self.protection_prepare(Some(pin), Action::Unlock { challenge }, now)
    }

    fn protection_prepare(
        &mut self,
        current: Option<Zeroizing<Vec<u8>>>,
        action: Action,
        now: u64,
    ) -> Result<ProtectionWork, SecureError> {
        if self.protection.auth_job.is_some() {
            return Err(SecureError::Busy);
        }
        self.require_local_config().map_err(storage_error)?;
        if current.is_some() != self.protection.pin.is_some()
            || current.as_deref().is_some_and(|pin| !valid_pin(pin))
        {
            return Err(SecureError::InvalidInput);
        }
        if let Some(mut record) = self.protection.pin.clone() {
            if record.retry_at.is_some_and(|until| until > now) {
                return Err(SecureError::RateLimited);
            }
            // Reserve the attempt before starting the KDF. Process death cannot
            // avoid the failed-attempt charge by interrupting its result.
            record.failed = record.failed.saturating_add(1).min(32);
            record.retry_at = (record.failed >= 5).then(|| {
                let seconds = (30u64 << (record.failed - 5)).min(MAX_PIN_DELAY);
                now.saturating_add(seconds)
            });
            self.commit_pin(Some(record))?;
        }
        let id = self
            .protection
            .auth_sequence
            .checked_add(1)
            .ok_or(SecureError::Unavailable)?;
        self.protection.auth_sequence = id;
        self.protection.auth_job = Some(id);
        Ok(ProtectionWork {
            id,
            verifier: self.protection.pin.clone(),
            current,
            action,
        })
    }

    pub fn protection_commit(
        &mut self,
        result: ProtectionResult,
    ) -> Result<ProtectionStatus, SecureError> {
        if self.protection.auth_job != Some(result.id) {
            return Err(SecureError::StaleGeneration);
        }
        self.protection.auth_job = None;
        match result.outcome? {
            Verified::Configure(record) => {
                self.commit_pin(record)?;
                self.protection.page = None;
            }
            Verified::Unlock(challenge) => {
                self.unlock_page(&challenge)?;
            }
        }
        self.protection_status()
    }

    pub fn protection_unlock_biometric(&mut self, challenge: &str) -> Result<(), SecureError> {
        let page = self.protection.page.as_ref().ok_or(SecureError::Locked)?;
        if page.issued.elapsed() > BIOMETRIC_WINDOW
            || !self.protection_status()?.biometric_enabled
            || page.unlocked
        {
            return Err(SecureError::Locked);
        }
        if self.protection.auth_job.is_some() {
            return Err(SecureError::Busy);
        }
        self.unlock_page(challenge)
    }

    fn unlock_page(&mut self, challenge: &str) -> Result<(), SecureError> {
        if !self.protection.page.as_ref().is_some_and(|page| {
            page.challenge == challenge && !page.unlocked && self.protection_page_current(page)
        }) {
            return Err(SecureError::Locked);
        }
        if let Some(mut record) = self.protection.pin.clone().filter(|pin| pin.failed > 0) {
            record.failed = 0;
            record.retry_at = None;
            self.commit_pin(Some(record))?;
        }
        self.protection
            .page
            .as_mut()
            .ok_or(SecureError::Locked)?
            .unlocked = true;
        Ok(())
    }

    fn protection_page_current(&self, page: &Page) -> bool {
        page.notes_generation
            .is_none_or(|generation| generation == self.hub.scope_generation())
    }

    fn commit_pin(&mut self, pin: Option<PinRecord>) -> Result<(), SecureError> {
        let data = pin
            .as_ref()
            .map(serde_json::to_vec)
            .transpose()
            .map_err(|_| SecureError::Unavailable)?
            .map(Zeroizing::new);
        self.commit_private(
            PrivateRecord::Protection,
            data.as_deref().map(Vec::as_slice),
        )
        .map_err(storage_error)?;
        self.protection.pin = pin;
        Ok(())
    }
}

impl ProtectionWork {
    pub fn compute(self) -> ProtectionResult {
        let id = self.id;
        ProtectionResult {
            id,
            outcome: self.verify(),
        }
    }

    fn verify(self) -> Result<Verified, SecureError> {
        if let Some(verifier) = self.verifier {
            let current = self.current.ok_or(SecureError::InvalidInput)?;
            let key = pin_key(&current, &verifier.salt)?;
            hmac::verify(&key, PIN_TAG_CONTEXT, &verifier.tag)
                .map_err(|_| SecureError::IncorrectPin)?;
        }
        match self.action {
            Action::Unlock { challenge } => Ok(Verified::Unlock(challenge)),
            Action::Configure { pin, biometric } => Ok(Verified::Configure(
                pin.map(|pin| PinRecord::create(&pin, biometric))
                    .transpose()?,
            )),
        }
    }
}

impl PinRecord {
    fn create(pin: &[u8], biometric_enabled: bool) -> Result<Self, SecureError> {
        let mut salt = [0; 16];
        SystemRandom::new()
            .fill(&mut salt)
            .map_err(|_| SecureError::Unavailable)?;
        let key = pin_key(pin, &salt)?;
        let mut tag = [0; 32];
        tag.copy_from_slice(hmac::sign(&key, PIN_TAG_CONTEXT).as_ref());
        Ok(Self {
            salt,
            tag,
            biometric_enabled,
            failed: 0,
            retry_at: None,
        })
    }
}

fn pin_key(pin: &[u8], salt: &[u8; 16]) -> Result<hmac::Key, SecureError> {
    let params = Params::new(PIN_KDF_KIB, 2, 1, Some(32)).map_err(|_| SecureError::Unavailable)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut memory = Zeroizing::new(vec![Block::default(); PIN_KDF_KIB as usize]);
    let mut bytes = Zeroizing::new([0; 32]);
    argon
        .hash_password_into_with_memory(pin, salt, &mut *bytes, &mut *memory)
        .map_err(|_| SecureError::Unavailable)?;
    Ok(hmac::Key::new(hmac::HMAC_SHA256, &bytes[..]))
}

fn valid_pin(pin: &[u8]) -> bool {
    pin.len() == 6 && pin.iter().all(u8::is_ascii_digit)
}

pub(crate) fn storage_error(error: CoreError) -> SecureError {
    match error {
        CoreError::StorageRecoveryRequired => SecureError::StorageRecoveryRequired,
        _ => SecureError::Unavailable,
    }
}
