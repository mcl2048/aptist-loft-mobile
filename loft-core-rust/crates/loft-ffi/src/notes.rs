use crate::{AppCore, HubRequest};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Error)]
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

impl fmt::Display for SecureError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for SecureError {}

impl From<loft_core::SecureError> for SecureError {
    fn from(error: loft_core::SecureError) -> Self {
        use loft_core::SecureError as Core;
        match error {
            Core::InvalidInput => Self::InvalidInput,
            Core::NotFound => Self::NotFound,
            Core::StaleGeneration => Self::StaleGeneration,
            Core::Locked => Self::Locked,
            Core::IncorrectPin => Self::IncorrectPin,
            Core::RateLimited => Self::RateLimited,
            Core::TooLarge => Self::TooLarge,
            Core::Unavailable => Self::Unavailable,
            Core::StorageRecoveryRequired => Self::StorageRecoveryRequired,
            Core::NotSignedIn => Self::NotSignedIn,
            Core::Busy => Self::Busy,
            Core::Conflict => Self::Conflict,
            Core::AuthenticationFailed => Self::AuthenticationFailed,
            Core::NetworkUnavailable => Self::NetworkUnavailable,
            Core::Unsupported => Self::Unsupported,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum ProtectionScope {
    Vault,
    Notes,
}

impl From<ProtectionScope> for loft_core::ProtectionScope {
    fn from(scope: ProtectionScope) -> Self {
        match scope {
            ProtectionScope::Vault => Self::Vault,
            ProtectionScope::Notes => Self::Notes,
        }
    }
}

#[derive(Debug, PartialEq, Eq, uniffi::Record)]
pub struct ProtectionStatus {
    pub enabled: bool,
    pub biometric_enabled: bool,
    pub retry_at: Option<u64>,
}

impl From<loft_core::ProtectionStatus> for ProtectionStatus {
    fn from(status: loft_core::ProtectionStatus) -> Self {
        Self {
            enabled: status.enabled,
            biometric_enabled: status.biometric_enabled,
            retry_at: status.retry_at,
        }
    }
}

#[derive(uniffi::Record)]
pub struct ProtectionAccess {
    pub challenge: String,
    pub unlocked: bool,
}

#[derive(uniffi::Record)]
pub struct NotesDraft {
    pub id: Option<String>,
    pub title: String,
    pub body: String,
    pub icon: Option<String>,
    pub tags: String,
    pub expected_version: Option<String>,
}

impl From<NotesDraft> for loft_core::NotesDraft {
    fn from(draft: NotesDraft) -> Self {
        Self {
            id: draft.id,
            title: draft.title,
            body: draft.body,
            icon: draft.icon,
            tags: draft.tags,
            expected_version: draft.expected_version,
        }
    }
}

#[derive(uniffi::Record)]
pub struct NoteSummary {
    pub id: String,
    pub title: String,
    pub preview: String,
    pub icon: Option<String>,
    pub tags: Vec<String>,
    pub created_at: u64,
    pub updated_at: u64,
    pub archived: bool,
    pub version: String,
}

impl From<loft_core::NoteSummary> for NoteSummary {
    fn from(note: loft_core::NoteSummary) -> Self {
        Self {
            id: note.id,
            title: note.title,
            preview: note.preview,
            icon: note.icon,
            tags: note.tags,
            created_at: note.created_at,
            updated_at: note.updated_at,
            archived: note.archived,
            version: note.version,
        }
    }
}

#[derive(uniffi::Record)]
pub struct NoteDetail {
    pub summary: NoteSummary,
    pub body: String,
}

#[derive(uniffi::Record)]
pub struct NotesPage {
    pub generation: u64,
    pub entries: Vec<NoteSummary>,
    pub next_offset: Option<u32>,
}

#[derive(uniffi::Record)]
pub struct NoteTag {
    pub name: String,
    pub count: u32,
}

#[derive(uniffi::Record)]
pub struct NotesSyncStatus {
    pub available: bool,
    pub configured: bool,
    pub signed_in: bool,
    pub reset_available: bool,
    pub reset_pending: bool,
    pub needs_recovery: bool,
    pub recovery_code_ready: bool,
}

#[derive(uniffi::Record)]
pub struct NotesSyncStep {
    pub next_request: Option<HubRequest>,
    pub generation: u64,
    pub reset_completed: bool,
    pub needs_recovery: bool,
}

#[uniffi::export]
impl AppCore {
    pub fn protection_status(&self) -> Result<ProtectionStatus, SecureError> {
        let state = self.state.lock().map_err(|_| SecureError::Unavailable)?;
        Ok(state.protection_status()?.into())
    }

    pub fn protection_configure(
        &self,
        current_pin: Option<Vec<u8>>,
        new_pin: Option<Vec<u8>>,
        biometric_enabled: bool,
        unix_seconds: u64,
    ) -> Result<ProtectionStatus, SecureError> {
        let work = {
            let mut state = self.state.lock().map_err(|_| SecureError::Unavailable)?;
            state.protection_configure_prepare(
                current_pin,
                new_pin,
                biometric_enabled,
                unix_seconds,
            )?
        };
        let outcome = work.compute();
        let mut state = self.state.lock().map_err(|_| SecureError::Unavailable)?;
        Ok(state.protection_commit(outcome)?.into())
    }

    pub fn protection_begin(
        &self,
        scope: ProtectionScope,
        _unix_seconds: u64,
    ) -> Result<ProtectionAccess, SecureError> {
        let mut state = self.state.lock().map_err(|_| SecureError::Unavailable)?;
        let access = state.protection_begin(scope.into())?;
        Ok(ProtectionAccess {
            challenge: access.challenge,
            unlocked: access.unlocked,
        })
    }

    pub fn protection_unlock_pin(
        &self,
        challenge: String,
        pin: Vec<u8>,
        unix_seconds: u64,
    ) -> Result<(), SecureError> {
        let work = {
            let mut state = self.state.lock().map_err(|_| SecureError::Unavailable)?;
            state.protection_unlock_prepare(challenge, pin, unix_seconds)?
        };
        let outcome = work.compute();
        let mut state = self.state.lock().map_err(|_| SecureError::Unavailable)?;
        state.protection_commit(outcome)?;
        Ok(())
    }

    pub fn protection_unlock_biometric(
        &self,
        challenge: String,
        _unix_seconds: u64,
    ) -> Result<(), SecureError> {
        let mut state = self.state.lock().map_err(|_| SecureError::Unavailable)?;
        state.protection_unlock_biometric(&challenge)?;
        Ok(())
    }

    pub fn protection_end(&self, challenge: String) -> Result<(), SecureError> {
        let mut state = self.state.lock().map_err(|_| SecureError::Unavailable)?;
        state.protection_end(&challenge);
        Ok(())
    }

    pub fn protection_require(
        &self,
        scope: ProtectionScope,
        lease: String,
    ) -> Result<(), SecureError> {
        let state = self.state.lock().map_err(|_| SecureError::Unavailable)?;
        Ok(state.protection_require(scope.into(), &lease)?)
    }

    pub fn notes_list(
        &self,
        lease: String,
        archived: bool,
        query: String,
        tag: Option<String>,
        offset: u32,
        expected_generation: Option<u64>,
    ) -> Result<NotesPage, SecureError> {
        let state = self.state.lock().map_err(|_| SecureError::Unavailable)?;
        let page = state.notes_list(
            &lease,
            archived,
            &query,
            tag.as_deref(),
            offset,
            expected_generation,
        )?;
        Ok(NotesPage {
            generation: page.generation,
            entries: page.entries.into_iter().map(Into::into).collect(),
            next_offset: page.next_offset,
        })
    }

    pub fn notes_detail(&self, lease: String, id: String) -> Result<NoteDetail, SecureError> {
        let state = self.state.lock().map_err(|_| SecureError::Unavailable)?;
        let detail = state.notes_detail(&lease, &id)?;
        Ok(NoteDetail {
            summary: detail.summary.into(),
            body: detail.body,
        })
    }

    pub fn notes_save(
        &self,
        lease: String,
        draft: NotesDraft,
        unix_seconds: u64,
    ) -> Result<NoteSummary, SecureError> {
        let mut state = self.state.lock().map_err(|_| SecureError::Unavailable)?;
        Ok(state.notes_save(&lease, draft.into(), unix_seconds)?.into())
    }

    pub fn notes_archive(
        &self,
        lease: String,
        id: String,
        archived: bool,
        unix_seconds: u64,
    ) -> Result<(), SecureError> {
        let mut state = self.state.lock().map_err(|_| SecureError::Unavailable)?;
        Ok(state.notes_archive(&lease, &id, archived, unix_seconds)?)
    }

    pub fn notes_delete(&self, lease: String, id: String) -> Result<(), SecureError> {
        let mut state = self.state.lock().map_err(|_| SecureError::Unavailable)?;
        Ok(state.notes_delete(&lease, &id)?)
    }

    pub fn notes_tags(&self, lease: String, archived: bool) -> Result<Vec<NoteTag>, SecureError> {
        let state = self.state.lock().map_err(|_| SecureError::Unavailable)?;
        Ok(state
            .notes_tags(&lease, archived)?
            .into_iter()
            .map(|tag| NoteTag {
                name: tag.name,
                count: tag.count,
            })
            .collect())
    }

    pub fn notes_sync_status(&self, lease: String) -> Result<NotesSyncStatus, SecureError> {
        let state = self.state.lock().map_err(|_| SecureError::Unavailable)?;
        let status = state.notes_sync_status(&lease)?;
        Ok(NotesSyncStatus {
            available: status.available,
            configured: status.configured,
            signed_in: status.signed_in,
            reset_available: status.reset_available,
            reset_pending: status.reset_pending,
            needs_recovery: status.needs_recovery,
            recovery_code_ready: status.recovery_code_ready,
        })
    }

    pub fn notes_sync_configure(
        &self,
        lease: String,
        recovery_code: Option<Vec<u8>>,
    ) -> Result<Option<String>, SecureError> {
        let mut state = self.state.lock().map_err(|_| SecureError::Unavailable)?;
        Ok(state.notes_sync_configure(&lease, recovery_code)?)
    }

    pub fn notes_sync_reset(&self, lease: String, wipe: bool) -> Result<(), SecureError> {
        let mut state = self.state.lock().map_err(|_| SecureError::Unavailable)?;
        Ok(state.notes_sync_reset(&lease, wipe)?)
    }

    pub fn notes_sync_recovery_code(&self, lease: String) -> Result<Option<String>, SecureError> {
        let state = self.state.lock().map_err(|_| SecureError::Unavailable)?;
        Ok(state.notes_sync_recovery_code(&lease)?)
    }

    pub fn notes_sync_disable(&self, lease: String) -> Result<(), SecureError> {
        let mut state = self.state.lock().map_err(|_| SecureError::Unavailable)?;
        Ok(state.notes_sync_disable(&lease)?)
    }

    pub fn notes_sync_eligible(&self) -> bool {
        self.state
            .lock()
            .is_ok_and(|state| state.notes_sync_eligible())
    }

    pub fn notes_sync_begin(&self) -> Result<Option<HubRequest>, SecureError> {
        let mut state = self.state.lock().map_err(|_| SecureError::Unavailable)?;
        Ok(state.notes_sync_begin()?.map(Into::into))
    }

    pub fn notes_sync_finish(
        &self,
        request_id: u64,
        status: u32,
        media_type: Option<String>,
        body: Vec<u8>,
    ) -> Result<NotesSyncStep, SecureError> {
        let receipt = {
            let mut state = self.state.lock().map_err(|_| SecureError::Unavailable)?;
            state.notes_sync_accept(request_id, status, media_type.as_deref(), body)?
        };
        let step = match receipt {
            loft_core::NotesSyncReceipt::Complete(step) => step,
            loft_core::NotesSyncReceipt::Compute(work) => {
                let update = work.compute();
                let mut state = self.state.lock().map_err(|_| SecureError::Unavailable)?;
                state.notes_sync_commit(update)?
            }
        };
        Ok(NotesSyncStep {
            next_request: step.next_request.map(Into::into),
            generation: step.generation,
            reset_completed: step.reset_completed,
            needs_recovery: step.needs_recovery,
        })
    }

    pub fn notes_sync_abandon(&self, request_id: u64) -> Result<(), SecureError> {
        let mut state = self.state.lock().map_err(|_| SecureError::Unavailable)?;
        state.notes_sync_abandon(request_id);
        Ok(())
    }
}
