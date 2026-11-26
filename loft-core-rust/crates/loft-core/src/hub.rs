//! Service-private Hub requests and redacted account receipts.
use crate::{CoreState, normalize_server_origin};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

mod mail;

const DISCOVERY: &str = "/.well-known/loft-app";
const TRANSACTIONS: &str = "/v1/auth/portal/transactions";
const MAX_AUTH_BYTES: u32 = 16 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HubAction {
    Discover,
    SignIn,
    Complete,
    Cancel,
    Logout,
    MailInbox,
    MailTrash,
    MailMessage,
    MailContent,
    MailAttachment,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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

pub struct HubRequest {
    pub request_id: u64,
    pub generation: u64,
    pub url: String,
    pub method: String,
    pub bearer: Option<String>,
    pub body: Vec<u8>,
    pub max_response_bytes: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HubSnapshot {
    pub generation: u64,
    pub origin: Option<String>,
    pub issuer: Option<String>,
    pub mail_supported: bool,
    pub transaction_pending: bool,
    pub session: Option<HubSession>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HubSession {
    pub subject: String,
    pub email: Option<String>,
    pub mail_access: bool,
    pub expires_in_seconds: u32,
}

pub struct HubReceipt {
    pub snapshot: HubSnapshot,
    pub browser_url: Option<String>,
    pub page: Option<HubMailPage>,
    pub message: Option<HubMailMessage>,
    pub file: Option<Vec<u8>>,
}

pub struct HubMailPage {
    pub folder: String,
    pub messages: Vec<HubMailSummary>,
    pub cursor: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
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

pub struct HubMailMessage {
    pub summary: HubMailSummary,
    pub text: String,
    pub truncated: bool,
    pub attachments: Vec<HubMailAttachment>,
}

#[derive(Deserialize)]
pub struct HubMailAttachment {
    pub id: String,
    pub filename: String,
    pub mime: String,
    pub size: u32,
}

impl CoreState {
    pub fn hub_snapshot(&mut self) -> HubSnapshot {
        self.hub.expire(Instant::now());
        self.hub.snapshot(self.local.server_candidate.as_deref())
    }

    pub fn hub_begin(
        &mut self,
        action: HubAction,
        input: Option<String>,
        mail_access: bool,
    ) -> Result<HubRequest, HubError> {
        let origin = self
            .local
            .server_candidate
            .as_deref()
            .ok_or(HubError::NoServer)?;
        self.hub
            .begin(origin, action, input.as_deref(), mail_access)
    }

    pub fn hub_finish(
        &mut self,
        request_id: u64,
        status: u32,
        media_type: Option<&str>,
        body: Vec<u8>,
    ) -> Result<HubReceipt, HubError> {
        self.hub.finish(
            self.local.server_candidate.as_deref(),
            request_id,
            status,
            media_type,
            Zeroizing::new(body),
        )
    }

    pub fn hub_abandon(&mut self, request_id: u64) {
        if self
            .hub
            .active
            .as_ref()
            .is_some_and(|request| request.id == request_id)
        {
            self.hub.active = None;
        }
    }

    pub fn hub_clear(&mut self) -> HubSnapshot {
        self.hub.clear_scope();
        self.hub_snapshot()
    }
}

#[derive(Default)]
pub(crate) struct HubState {
    generation: u64,
    request_id: u64,
    profile: Option<Profile>,
    transaction: Option<Transaction>,
    session: Option<Session>,
    active: Option<InFlight>,
}

#[derive(PartialEq, Eq)]
struct Profile {
    issuer: String,
    mail: bool,
}

struct Transaction {
    id: String,
    proof: Zeroizing<String>,
    mail: bool,
    deadline: Instant,
}

struct Session {
    bearer: Zeroizing<String>,
    subject: String,
    email: Option<String>,
    mail: bool,
    deadline: Instant,
    mail_state: mail::State,
}

struct InFlight {
    id: u64,
    started: Instant,
    operation: Operation,
    limit: u32,
}

enum Operation {
    Discover,
    SignIn {
        proof: Zeroizing<String>,
        mail: bool,
    },
    Complete,
    Cancel,
    Logout,
    Mail(mail::Operation),
}

impl HubState {
    pub(crate) fn change_candidate(&mut self) {
        self.profile = None;
        self.clear_scope();
    }

    fn advance(&mut self) {
        // Even at exhaustion, local cleanup must continue to fence the current request.
        self.generation = self.generation.saturating_add(1);
        self.active = None;
    }

    fn clear_scope(&mut self) {
        self.advance();
        self.transaction = None;
        self.session = None;
    }

    fn expire(&mut self, now: Instant) {
        if self
            .session
            .as_ref()
            .is_some_and(|session| session.deadline <= now)
        {
            self.session = None;
            self.generation = self.generation.saturating_add(1);
            if self
                .active
                .as_ref()
                .is_some_and(|request| matches!(request.operation, Operation::Mail(_)))
            {
                self.active = None;
            }
        }
        if self
            .transaction
            .as_ref()
            .is_some_and(|transaction| transaction.deadline <= now)
        {
            self.transaction = None;
            self.generation = self.generation.saturating_add(1);
            if self
                .active
                .as_ref()
                .is_some_and(|request| matches!(request.operation, Operation::Complete))
            {
                self.active = None;
            }
        }
    }

    fn snapshot(&self, origin: Option<&str>) -> HubSnapshot {
        HubSnapshot {
            generation: self.generation,
            origin: origin.map(str::to_owned),
            issuer: self.profile.as_ref().map(|profile| profile.issuer.clone()),
            mail_supported: self.profile.as_ref().is_some_and(|profile| profile.mail),
            transaction_pending: self.transaction.is_some(),
            session: self.session.as_ref().map(|session| HubSession {
                subject: session.subject.clone(),
                email: session.email.clone(),
                mail_access: session.mail,
                expires_in_seconds: session
                    .deadline
                    .saturating_duration_since(Instant::now())
                    .as_millis()
                    .div_ceil(1000) as u32,
            }),
        }
    }

    fn begin(
        &mut self,
        origin: &str,
        action: HubAction,
        input: Option<&str>,
        mail_access: bool,
    ) -> Result<HubRequest, HubError> {
        let started = Instant::now();
        let transaction_was_live = self.transaction.is_some();
        let session_was_live = self.session.is_some();
        self.expire(started);
        if self.generation == u64::MAX {
            return Err(HubError::StateUnavailable);
        }
        if self.active.is_some() && !matches!(action, HubAction::Cancel | HubAction::Logout) {
            return Err(HubError::Busy);
        }
        if input.is_some()
            && !matches!(
                action,
                HubAction::MailInbox
                    | HubAction::MailTrash
                    | HubAction::MailMessage
                    | HubAction::MailContent
                    | HubAction::MailAttachment
            )
        {
            return Err(HubError::InvalidInput);
        }
        let id = self
            .request_id
            .checked_add(1)
            .ok_or(HubError::StateUnavailable)?;
        let mut request = HubRequest {
            request_id: id,
            generation: self.generation,
            url: origin.to_owned(),
            method: "GET".into(),
            bearer: None,
            body: Vec::new(),
            max_response_bytes: MAX_AUTH_BYTES,
        };
        let operation = match action {
            HubAction::Discover => {
                request.url.push_str(DISCOVERY);
                Operation::Discover
            }
            HubAction::SignIn => {
                let profile = self.profile.as_ref().ok_or(HubError::IncompatibleServer)?;
                if mail_access && !profile.mail {
                    return Err(HubError::MailConsentRequired);
                }
                if self.transaction.is_some() {
                    return Err(HubError::Busy);
                }
                let mut random = Zeroizing::new([0; 32]);
                rustls::crypto::ring::default_provider()
                    .secure_random
                    .fill(random.as_mut())
                    .map_err(|_| HubError::StateUnavailable)?;
                let proof = Zeroizing::new(URL_SAFE_NO_PAD.encode(random.as_ref()));
                let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(proof.as_bytes()));
                request.url.push_str(TRANSACTIONS);
                request.post(&StartBody {
                    proof_challenge: &challenge,
                    mail_read: mail_access,
                })?;
                Operation::SignIn {
                    proof,
                    mail: mail_access,
                }
            }
            HubAction::Complete | HubAction::Cancel => {
                let transaction = self.transaction.as_ref().ok_or(if transaction_was_live {
                    HubError::TransactionExpired
                } else {
                    HubError::NoTransaction
                })?;
                let suffix = if action == HubAction::Complete {
                    "complete"
                } else {
                    "cancel"
                };
                request
                    .url
                    .push_str(&format!("{TRANSACTIONS}/{}/{suffix}", transaction.id));
                request.post(&ProofBody {
                    proof: &transaction.proof,
                })?;
                if action == HubAction::Complete {
                    Operation::Complete
                } else {
                    self.advance();
                    self.transaction = None;
                    Operation::Cancel
                }
            }
            HubAction::Logout => {
                let session = self.session.as_ref().ok_or(if session_was_live {
                    HubError::SessionExpired
                } else {
                    HubError::NotSignedIn
                })?;
                request.url.push_str("/v1/logout");
                request.method = "POST".into();
                request.bearer = Some(session.bearer.to_string());
                self.clear_scope();
                Operation::Logout
            }
            action => {
                let session = self.session.as_ref().ok_or(if session_was_live {
                    HubError::SessionExpired
                } else {
                    HubError::NotSignedIn
                })?;
                if !session.mail {
                    return Err(HubError::MailConsentRequired);
                }
                let operation = session.mail_state.operation(action, input)?;
                request.url.push_str(&operation.path());
                request.max_response_bytes = operation.limit();
                request.bearer = Some(session.bearer.to_string());
                Operation::Mail(operation)
            }
        };
        request.generation = self.generation;
        self.request_id = id;
        self.active = Some(InFlight {
            id,
            started,
            operation,
            limit: request.max_response_bytes,
        });
        Ok(request)
    }

    fn finish(
        &mut self,
        origin: Option<&str>,
        id: u64,
        status: u32,
        media_type: Option<&str>,
        mut body: Zeroizing<Vec<u8>>,
    ) -> Result<HubReceipt, HubError> {
        let now = Instant::now();
        self.expire(now);
        let active = self
            .active
            .take_if(|request| request.id == id)
            .ok_or(HubError::StaleRequest)?;
        if body.len() > active.limit as usize {
            return Err(HubError::TooLarge);
        }
        if !(200..300).contains(&status) {
            return Err(self.reject(&active.operation, status, &body));
        }
        let mut browser_url = None;
        let mut page = None;
        let mut message = None;
        let mut file = None;
        match active.operation {
            Operation::Discover if status == 200 => {
                let descriptor: Descriptor =
                    read_json(media_type, &body).map_err(|_| HubError::IncompatibleServer)?;
                let profile = descriptor.profile()?;
                if self
                    .profile
                    .as_ref()
                    .is_some_and(|current| current != &profile)
                {
                    self.clear_scope();
                }
                self.profile = Some(profile);
            }
            Operation::SignIn { proof, mail } if status == 201 => {
                let started: Started = read_json(media_type, &body)?;
                let profile = self.profile.as_ref().ok_or(HubError::StaleRequest)?;
                if !token(&started.transaction_id)
                    || !authorize_url(&profile.issuer, &started.authorization_url)
                {
                    return Err(HubError::InvalidResponse);
                }
                self.transaction = Some(Transaction {
                    id: started.transaction_id,
                    proof,
                    mail,
                    deadline: deadline(
                        active.started,
                        now,
                        started.expires_at,
                        started.expires_in,
                    )?,
                });
                browser_url = Some(started.authorization_url);
            }
            Operation::Complete if status == 202 => {
                let pending: Pending = read_json(media_type, &body)?;
                if pending.status != "pending" {
                    return Err(HubError::InvalidResponse);
                }
            }
            Operation::Complete if status == 200 => {
                let complete: Completed = read_json(media_type, &body)?;
                let profile = self.profile.as_ref().ok_or(HubError::StaleRequest)?;
                let transaction = self
                    .transaction
                    .as_ref()
                    .ok_or(HubError::TransactionExpired)?;
                if complete.status != "complete"
                    || complete.issuer != profile.issuer
                    || complete.mail_read != transaction.mail
                    || !token(&complete.session_token)
                    || !safe_identity(&complete.subject)
                    || complete
                        .email
                        .as_ref()
                        .is_some_and(|email| !safe_identity(email))
                {
                    return Err(HubError::InvalidResponse);
                }
                let session = Session {
                    bearer: complete.session_token,
                    subject: complete.subject,
                    email: complete.email,
                    mail: complete.mail_read,
                    deadline: deadline(
                        active.started,
                        now,
                        complete.expires_at,
                        complete.expires_in,
                    )?,
                    mail_state: mail::State::default(),
                };
                self.clear_scope();
                self.session = Some(session);
            }
            Operation::Cancel | Operation::Logout if status == 204 && body.is_empty() => {}
            Operation::Mail(operation) if status == 200 => {
                let session = self.session.as_mut().ok_or(HubError::SessionExpired)?;
                match operation {
                    mail::Operation::Page { folder, .. } => {
                        page = Some(
                            session
                                .mail_state
                                .finish_page(folder, read_json(media_type, &body)?)?,
                        );
                    }
                    mail::Operation::Message { id } => {
                        message = Some(
                            session
                                .mail_state
                                .finish_message(id, read_json(media_type, &body)?)?,
                        );
                    }
                    mail::Operation::Content { .. } if media_is(media_type, "text/plain") => {
                        let text =
                            std::str::from_utf8(&body).map_err(|_| HubError::InvalidResponse)?;
                        if text.contains('\0') {
                            return Err(HubError::InvalidResponse);
                        }
                        file = Some(std::mem::take(&mut *body));
                    }
                    mail::Operation::Attachment { size, .. }
                        if media_is(media_type, "application/octet-stream")
                            && body.len() == size as usize =>
                    {
                        file = Some(std::mem::take(&mut *body));
                    }
                    _ => return Err(HubError::InvalidResponse),
                }
            }
            _ => return Err(HubError::InvalidResponse),
        }
        Ok(HubReceipt {
            snapshot: self.snapshot(origin),
            browser_url,
            page,
            message,
            file,
        })
    }

    fn reject(&mut self, operation: &Operation, status: u32, body: &[u8]) -> HubError {
        let wire = serde_json::from_slice::<Rejected>(body)
            .ok()
            .map(|response| response.error);
        let code = wire.as_deref();
        match (operation, status, code) {
            (Operation::Discover, 404, _) => HubError::IncompatibleServer,
            (Operation::Complete, _, Some("transaction_expired" | "access_denied")) => {
                self.advance();
                self.transaction = None;
                if code == Some("transaction_expired") {
                    HubError::TransactionExpired
                } else {
                    HubError::AccessDenied
                }
            }
            (Operation::Mail(_), 401, _) => {
                self.clear_scope();
                HubError::SessionExpired
            }
            (_, 403, Some("insufficient_scope")) => HubError::MailConsentRequired,
            (_, 403, _) => HubError::AccessDenied,
            (_, 404, _) => HubError::NotFound,
            (_, 410, Some("transaction_expired")) => HubError::TransactionExpired,
            (_, 413, _) => HubError::TooLarge,
            (_, 429, _) => HubError::RateLimited,
            (_, 500..=599, _) => HubError::NetworkUnavailable,
            _ => HubError::InvalidResponse,
        }
    }
}

impl HubRequest {
    fn post(&mut self, body: &impl Serialize) -> Result<(), HubError> {
        self.method = "POST".into();
        self.body = serde_json::to_vec(body).map_err(|_| HubError::StateUnavailable)?;
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Descriptor {
    version: u32,
    product: String,
    auth_mode: String,
    issuer: String,
    modules: Vec<String>,
}

impl Descriptor {
    fn profile(self) -> Result<Profile, HubError> {
        let origin = self
            .issuer
            .strip_suffix("/api/idp")
            .ok_or(HubError::IncompatibleServer)?;
        if self.version != 1
            || self.product != "loft"
            || self.auth_mode != "portal_bff"
            || !normalize_server_origin(origin).is_ok_and(|normalized| normalized == origin)
            || (!self.modules.is_empty() && self.modules != ["mail"])
        {
            return Err(HubError::IncompatibleServer);
        }
        Ok(Profile {
            issuer: self.issuer,
            mail: !self.modules.is_empty(),
        })
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct StartBody<'a> {
    proof_challenge: &'a str,
    mail_read: bool,
}

#[derive(Serialize)]
struct ProofBody<'a> {
    proof: &'a str,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Started {
    transaction_id: String,
    authorization_url: String,
    expires_at: u64,
    expires_in: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Pending {
    status: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Completed {
    status: String,
    #[serde(deserialize_with = "secret")]
    session_token: Zeroizing<String>,
    issuer: String,
    subject: String,
    email: Option<String>,
    #[serde(rename = "name")]
    _name: Option<String>,
    mail_read: bool,
    expires_at: u64,
    expires_in: u32,
}

#[derive(Deserialize)]
struct Rejected {
    error: String,
}

fn secret<'de, D: serde::Deserializer<'de>>(decoder: D) -> Result<Zeroizing<String>, D::Error> {
    String::deserialize(decoder).map(Zeroizing::new)
}

fn safe_identity(value: &str) -> bool {
    !value.is_empty() && value.len() <= 320 && !value.chars().any(char::is_control)
}

fn authorize_url(issuer: &str, target: &str) -> bool {
    target.len() <= 4096
        && target
            .strip_prefix(issuer)
            .and_then(|suffix| suffix.strip_prefix("/authorize?"))
            .is_some_and(|query| !query.is_empty())
        && target
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && !b"#\\\"<>".contains(&byte))
}

fn deadline(started: Instant, now: Instant, epoch: u64, seconds: u32) -> Result<Instant, HubError> {
    if epoch == 0 || !(1..=300).contains(&seconds) {
        return Err(HubError::InvalidResponse);
    }
    let deadline = started + Duration::from_secs(u64::from(seconds));
    if deadline <= now {
        return Err(HubError::TransactionExpired);
    }
    Ok(deadline)
}

fn token(value: &str) -> bool {
    if value.len() != 43 {
        return false;
    }
    let mut decoded = Zeroizing::new([0; 32]);
    URL_SAFE_NO_PAD
        .decode_slice(value, decoded.as_mut())
        .is_ok_and(|length| length == 32)
}

fn media_is(value: Option<&str>, wanted: &str) -> bool {
    value
        .and_then(|value| value.split(';').next())
        .is_some_and(|value| value.trim().eq_ignore_ascii_case(wanted))
}

fn read_json<T: DeserializeOwned>(media_type: Option<&str>, body: &[u8]) -> Result<T, HubError> {
    if !media_is(media_type, "application/json") {
        return Err(HubError::InvalidResponse);
    }
    serde_json::from_slice(body).map_err(|_| HubError::InvalidResponse)
}
