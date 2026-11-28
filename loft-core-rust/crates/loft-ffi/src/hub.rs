//! Generated-binding field definitions for the service-private Hub port.
use crate::AppCore;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum HubAction {
    Discover,
    SignIn,
    Complete,
    Cancel,
    Logout,
    Session,
    MailInbox,
    MailTrash,
    MailMessage,
    MailContent,
    MailAttachment,
}

impl From<HubAction> for loft_core::HubAction {
    fn from(value: HubAction) -> Self {
        match value {
            HubAction::Discover => Self::Discover,
            HubAction::SignIn => Self::SignIn,
            HubAction::Complete => Self::Complete,
            HubAction::Cancel => Self::Cancel,
            HubAction::Logout => Self::Logout,
            HubAction::Session => Self::Session,
            HubAction::MailInbox => Self::MailInbox,
            HubAction::MailTrash => Self::MailTrash,
            HubAction::MailMessage => Self::MailMessage,
            HubAction::MailContent => Self::MailContent,
            HubAction::MailAttachment => Self::MailAttachment,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Error)]
pub enum HubError {
    NoServer,
    IncompatibleServer,
    Busy,
    StaleRequest,
    InvalidInput,
    InvalidResponse,
    NetworkUnavailable,
    NotSignedIn,
    MailConsentRequired,
    NoTransaction,
    TransactionExpired,
    SessionExpired,
    AccessDenied,
    RateLimited,
    NotFound,
    TooLarge,
    StateUnavailable,
}

impl From<loft_core::HubError> for HubError {
    fn from(value: loft_core::HubError) -> Self {
        match value {
            loft_core::HubError::NoServer => Self::NoServer,
            loft_core::HubError::IncompatibleServer => Self::IncompatibleServer,
            loft_core::HubError::Busy => Self::Busy,
            loft_core::HubError::StaleRequest => Self::StaleRequest,
            loft_core::HubError::InvalidInput => Self::InvalidInput,
            loft_core::HubError::InvalidResponse => Self::InvalidResponse,
            loft_core::HubError::NetworkUnavailable => Self::NetworkUnavailable,
            loft_core::HubError::NotSignedIn => Self::NotSignedIn,
            loft_core::HubError::MailConsentRequired => Self::MailConsentRequired,
            loft_core::HubError::NoTransaction => Self::NoTransaction,
            loft_core::HubError::TransactionExpired => Self::TransactionExpired,
            loft_core::HubError::SessionExpired => Self::SessionExpired,
            loft_core::HubError::AccessDenied => Self::AccessDenied,
            loft_core::HubError::RateLimited => Self::RateLimited,
            loft_core::HubError::NotFound => Self::NotFound,
            loft_core::HubError::TooLarge => Self::TooLarge,
            loft_core::HubError::StateUnavailable => Self::StateUnavailable,
        }
    }
}

impl fmt::Display for HubError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}
impl std::error::Error for HubError {}

#[derive(uniffi::Record)]
pub struct HubRequest {
    pub request_id: u64,
    pub generation: u64,
    pub url: String,
    pub method: String,
    pub bearer: Option<String>,
    pub body: Vec<u8>,
    pub max_response_bytes: u32,
    pub if_none_match: Option<String>,
    pub requested_capabilities: Option<String>,
}

impl From<loft_core::HubRequest> for HubRequest {
    fn from(value: loft_core::HubRequest) -> Self {
        Self {
            request_id: value.request_id,
            generation: value.generation,
            url: value.url,
            method: value.method,
            bearer: value.bearer,
            body: value.body,
            max_response_bytes: value.max_response_bytes,
            if_none_match: value.if_none_match,
            requested_capabilities: value.requested_capabilities,
        }
    }
}

#[derive(uniffi::Record)]
pub struct HubSnapshot {
    pub generation: u64,
    pub origin: Option<String>,
    pub issuer: Option<String>,
    pub mail_supported: bool,
    pub notes_discovery_required: bool,
    pub transaction_pending: bool,
    pub session: Option<HubSession>,
}

impl From<loft_core::HubSnapshot> for HubSnapshot {
    fn from(value: loft_core::HubSnapshot) -> Self {
        Self {
            generation: value.generation,
            origin: value.origin,
            issuer: value.issuer,
            mail_supported: value.mail_supported,
            notes_discovery_required: value.notes_discovery_required,
            transaction_pending: value.transaction_pending,
            session: value.session.map(Into::into),
        }
    }
}

#[derive(uniffi::Record)]
pub struct HubSession {
    pub subject: String,
    pub email: Option<String>,
    pub mail_access: bool,
    pub mail_available: bool,
    pub expires_in_seconds: u32,
    pub durable: bool,
}

impl From<loft_core::HubSession> for HubSession {
    fn from(value: loft_core::HubSession) -> Self {
        Self {
            subject: value.subject,
            email: value.email,
            mail_access: value.mail_access,
            mail_available: value.mail_available,
            expires_in_seconds: value.expires_in_seconds,
            durable: value.durable,
        }
    }
}

#[derive(uniffi::Record)]
pub struct HubReceipt {
    pub snapshot: HubSnapshot,
    pub next_request: Option<HubRequest>,
    pub browser_url: Option<String>,
    pub page: Option<HubMailPage>,
    pub message: Option<HubMailMessage>,
    pub file: Option<Vec<u8>>,
}

impl From<loft_core::HubReceipt> for HubReceipt {
    fn from(value: loft_core::HubReceipt) -> Self {
        Self {
            snapshot: value.snapshot.into(),
            next_request: value.next_request.map(Into::into),
            browser_url: value.browser_url,
            page: value.page.map(Into::into),
            message: value.message.map(Into::into),
            file: value.file,
        }
    }
}

#[derive(uniffi::Record)]
pub struct HubMailPage {
    pub folder: String,
    pub messages: Vec<HubMailSummary>,
    pub cursor: Option<String>,
}

impl From<loft_core::HubMailPage> for HubMailPage {
    fn from(value: loft_core::HubMailPage) -> Self {
        Self {
            folder: value.folder,
            messages: value.messages.into_iter().map(Into::into).collect(),
            cursor: value.cursor,
        }
    }
}

#[derive(uniffi::Record)]
pub struct HubMailSummary {
    pub id: String,
    pub from: String,
    pub to: String,
    pub subject: String,
    pub received_at: String,
    pub read: bool,
    pub folder: String,
    pub attachment_count: u32,
    pub size: u32,
}

impl From<loft_core::HubMailSummary> for HubMailSummary {
    fn from(value: loft_core::HubMailSummary) -> Self {
        Self {
            id: value.id,
            from: value.from,
            to: value.to,
            subject: value.subject,
            received_at: value.received_at,
            read: value.read,
            folder: value.folder,
            attachment_count: value.attachment_count,
            size: value.size,
        }
    }
}

#[derive(uniffi::Record)]
pub struct HubMailMessage {
    pub summary: HubMailSummary,
    pub text: String,
    pub truncated: bool,
    pub attachments: Vec<HubMailAttachment>,
}

impl From<loft_core::HubMailMessage> for HubMailMessage {
    fn from(value: loft_core::HubMailMessage) -> Self {
        Self {
            summary: value.summary.into(),
            text: value.text,
            truncated: value.truncated,
            attachments: value.attachments.into_iter().map(Into::into).collect(),
        }
    }
}

#[derive(uniffi::Record)]
pub struct HubMailAttachment {
    pub id: String,
    pub filename: String,
    pub mime: String,
    pub size: u32,
}

impl From<loft_core::HubMailAttachment> for HubMailAttachment {
    fn from(value: loft_core::HubMailAttachment) -> Self {
        Self {
            id: value.id,
            filename: value.filename,
            mime: value.mime,
            size: value.size,
        }
    }
}

#[uniffi::export]
impl AppCore {
    pub fn hub_begin(
        &self,
        action: HubAction,
        input: Option<String>,
        mail_access: bool,
    ) -> Result<HubRequest, HubError> {
        let mut state = self.state.lock().map_err(|_| HubError::StateUnavailable)?;
        Ok(state.hub_begin(action.into(), input, mail_access)?.into())
    }

    pub fn hub_finish(
        &self,
        request_id: u64,
        status: u32,
        media_type: Option<String>,
        body: Vec<u8>,
    ) -> Result<HubReceipt, HubError> {
        // The HTTP executor submits only bounded receipts. This lock is never held during I/O.
        let mut state = self.state.lock().map_err(|_| HubError::StateUnavailable)?;
        Ok(state
            .hub_finish(request_id, status, media_type.as_deref(), body)?
            .into())
    }

    pub fn hub_snapshot(&self) -> Result<HubSnapshot, HubError> {
        let mut state = self.state.lock().map_err(|_| HubError::StateUnavailable)?;
        Ok(state.hub_snapshot().into())
    }

    pub fn hub_abandon(&self, request_id: u64) -> Result<(), HubError> {
        let mut state = self.state.lock().map_err(|_| HubError::StateUnavailable)?;
        state.hub_abandon(request_id);
        Ok(())
    }

    pub fn hub_clear(&self) -> Result<HubSnapshot, HubError> {
        let mut state = self.state.lock().map_err(|_| HubError::StateUnavailable)?;
        Ok(state.hub_clear()?.into())
    }
}
