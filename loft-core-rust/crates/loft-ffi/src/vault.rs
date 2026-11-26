//! Process-private vault exports and immutable redacted records.
use crate::AppCore;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum VaultAlgorithm {
    Sha1,
    Sha256,
    Sha512,
}

impl From<loft_core::VaultAlgorithm> for VaultAlgorithm {
    fn from(value: loft_core::VaultAlgorithm) -> Self {
        match value {
            loft_core::VaultAlgorithm::Sha1 => Self::Sha1,
            loft_core::VaultAlgorithm::Sha256 => Self::Sha256,
            loft_core::VaultAlgorithm::Sha512 => Self::Sha512,
        }
    }
}

impl From<VaultAlgorithm> for loft_core::VaultAlgorithm {
    fn from(value: VaultAlgorithm) -> Self {
        match value {
            VaultAlgorithm::Sha1 => Self::Sha1,
            VaultAlgorithm::Sha256 => Self::Sha256,
            VaultAlgorithm::Sha512 => Self::Sha512,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum VaultKind {
    Totp,
    Password,
}

impl From<loft_core::VaultKind> for VaultKind {
    fn from(value: loft_core::VaultKind) -> Self {
        match value {
            loft_core::VaultKind::Totp => Self::Totp,
            loft_core::VaultKind::Password => Self::Password,
        }
    }
}

impl From<VaultKind> for loft_core::VaultKind {
    fn from(value: VaultKind) -> Self {
        match value {
            VaultKind::Totp => Self::Totp,
            VaultKind::Password => Self::Password,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Error)]
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

impl From<loft_core::VaultError> for VaultError {
    fn from(value: loft_core::VaultError) -> Self {
        match value {
            loft_core::VaultError::InvalidInput => Self::InvalidInput,
            loft_core::VaultError::NotFound => Self::NotFound,
            loft_core::VaultError::Archived => Self::Archived,
            loft_core::VaultError::TooLarge => Self::TooLarge,
            loft_core::VaultError::StaleGeneration => Self::StaleGeneration,
            loft_core::VaultError::Unavailable => Self::Unavailable,
            loft_core::VaultError::StorageRecoveryRequired => Self::StorageRecoveryRequired,
            loft_core::VaultError::NotSignedIn => Self::NotSignedIn,
            loft_core::VaultError::Busy => Self::Busy,
            loft_core::VaultError::Conflict => Self::Conflict,
            loft_core::VaultError::AuthenticationFailed => Self::AuthenticationFailed,
            loft_core::VaultError::NetworkUnavailable => Self::NetworkUnavailable,
        }
    }
}

impl fmt::Display for VaultError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}
impl std::error::Error for VaultError {}

#[derive(uniffi::Record)]
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

impl From<loft_core::VaultEntry> for VaultEntry {
    fn from(value: loft_core::VaultEntry) -> Self {
        Self {
            id: value.id,
            kind: value.kind.into(),
            label: value.label,
            account: value.account,
            issuer: value.issuer,
            archived: value.archived,
            algorithm: value.algorithm.map(Into::into),
            digits: value.digits,
            period: value.period,
        }
    }
}

#[derive(uniffi::Record)]
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

impl From<VaultDraft> for loft_core::VaultDraft {
    fn from(value: VaultDraft) -> Self {
        Self {
            id: value.id,
            kind: value.kind.into(),
            label: value.label,
            account: value.account,
            issuer: value.issuer,
            secret: value.secret,
            algorithm: value.algorithm.map(Into::into),
            digits: value.digits,
            period: value.period,
        }
    }
}

#[derive(uniffi::Record)]
pub struct VaultPage {
    pub generation: u64,
    pub offset: u32,
    pub entries: Vec<VaultEntry>,
    pub next_offset: Option<u32>,
}

impl From<loft_core::VaultPage> for VaultPage {
    fn from(value: loft_core::VaultPage) -> Self {
        Self {
            generation: value.generation,
            offset: value.offset,
            entries: value.entries.into_iter().map(Into::into).collect(),
            next_offset: value.next_offset,
        }
    }
}

#[derive(uniffi::Record)]
pub struct VaultReveal {
    pub value: Vec<u8>,
    pub valid_for_seconds: Option<u32>,
}

impl From<loft_core::VaultReveal> for VaultReveal {
    fn from(value: loft_core::VaultReveal) -> Self {
        Self {
            value: value.value,
            valid_for_seconds: value.valid_for_seconds,
        }
    }
}

#[uniffi::export]
impl AppCore {
    pub fn vault_list(
        &self,
        archived: bool,
        offset: u32,
        expected_generation: Option<u64>,
    ) -> Result<VaultPage, VaultError> {
        let state = self.state.lock().map_err(|_| VaultError::Unavailable)?;
        Ok(state
            .vault_list(archived, offset, expected_generation)?
            .into())
    }

    pub fn vault_save(&self, draft: VaultDraft) -> Result<VaultEntry, VaultError> {
        let mut state = self.state.lock().map_err(|_| VaultError::Unavailable)?;
        Ok(state.vault_save(draft.into())?.into())
    }

    pub fn vault_import(&self, uri: Vec<u8>) -> Result<VaultEntry, VaultError> {
        let mut state = self.state.lock().map_err(|_| VaultError::Unavailable)?;
        Ok(state.vault_import(uri)?.into())
    }

    pub fn vault_archive(&self, id: String, archived: bool) -> Result<VaultEntry, VaultError> {
        let mut state = self.state.lock().map_err(|_| VaultError::Unavailable)?;
        Ok(state.vault_archive(&id, archived)?.into())
    }

    pub fn vault_reveal(&self, id: String, unix_seconds: u64) -> Result<VaultReveal, VaultError> {
        let state = self.state.lock().map_err(|_| VaultError::Unavailable)?;
        Ok(state.vault_reveal(&id, unix_seconds)?.into())
    }
}

#[derive(uniffi::Record)]
pub struct VaultSyncStep {
    pub next_request: Option<crate::HubRequest>,
    pub generation: u64,
}

#[uniffi::export]
impl AppCore {
    pub fn vault_sync_begin(&self, passphrase: Vec<u8>) -> Result<crate::HubRequest, VaultError> {
        let mut state = self.state.lock().map_err(|_| VaultError::Unavailable)?;
        Ok(state.vault_sync_begin(passphrase)?.into())
    }

    pub fn vault_sync_finish(
        &self,
        request_id: u64,
        status: u32,
        media_type: Option<String>,
        body: Vec<u8>,
    ) -> Result<VaultSyncStep, VaultError> {
        let receipt = {
            let mut state = self.state.lock().map_err(|_| VaultError::Unavailable)?;
            state.vault_sync_accept(request_id, status, media_type.as_deref(), body)?
        };
        let step = match receipt {
            loft_core::VaultSyncReceipt::Complete(step) => step,
            loft_core::VaultSyncReceipt::Compute(work) => {
                let result = work.compute();
                let mut state = self.state.lock().map_err(|_| VaultError::Unavailable)?;
                state.vault_sync_commit(result)?
            }
        };
        Ok(VaultSyncStep {
            next_request: step.next_request.map(Into::into),
            generation: step.generation,
        })
    }

    pub fn vault_sync_abandon(&self, request_id: u64) -> Result<(), VaultError> {
        let mut state = self.state.lock().map_err(|_| VaultError::Unavailable)?;
        state.vault_sync_abandon(request_id);
        Ok(())
    }
}
