use super::{MAX_NOTES, Note, NotesState, fixed_id};
use crate::{CoreState, HubRequest, SecureError};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::{
    aead, hkdf,
    rand::{SecureRandom, SystemRandom},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

pub(super) const MAX_PROFILES: usize = 4;
const MAX_IDENTITIES: usize = 2048;
const CIPHER_LIMIT: usize = 256 * 1024;
const WIRE_LIMIT: usize = 360 * 1024;
const HEADER: &[u8; 8] = b"LOFTNTE1";
const HEADER_BYTES: usize = HEADER.len() + aead::NONCE_LEN;
const PENDING_TIMEOUT: Duration = Duration::from_secs(90);

pub struct NotesSyncStatus {
    pub available: bool,
    pub configured: bool,
}

pub struct NotesSyncStep {
    pub next_request: Option<HubRequest>,
    pub generation: u64,
}

#[derive(Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Collection {
    pub(super) notes: BTreeMap<String, Note>,
    pub(super) deleted: BTreeSet<String>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Profile {
    pub(super) data: Collection,
    #[serde(serialize_with = "serialize_key", deserialize_with = "deserialize_key")]
    key: Zeroizing<[u8; 32]>,
    revision: u32,
    enabled: bool,
    pub(super) dirty: bool,
}

fn serialize_key<S: serde::Serializer>(value: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error> {
    value.serialize(serializer)
}

fn deserialize_key<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Zeroizing<[u8; 32]>, D::Error> {
    <[u8; 32]>::deserialize(deserializer).map(Zeroizing::new)
}

impl Profile {
    pub(super) fn enabled(&self) -> bool {
        self.enabled
    }

    pub(super) fn valid(&self) -> bool {
        self.data.valid()
    }
}

impl Collection {
    fn valid(&self) -> bool {
        self.notes.len() <= MAX_NOTES
            && self.deleted.len() + self.notes.len() <= MAX_IDENTITIES
            && self
                .notes
                .iter()
                .all(|(id, note)| note.valid(id) && !self.deleted.contains(id))
            && self.deleted.iter().all(|id| fixed_id(id, 16))
    }

    pub(super) fn validate(&self) -> Result<(), SecureError> {
        if !self.valid() {
            return Err(SecureError::TooLarge);
        }
        self.plaintext().map(|_| ())
    }

    fn plaintext(&self) -> Result<Zeroizing<Vec<u8>>, SecureError> {
        let data = Zeroizing::new(serde_json::to_vec(self).map_err(|_| SecureError::Unavailable)?);
        if data.len() > CIPHER_LIMIT - HEADER_BYTES - aead::AES_256_GCM.tag_len() {
            return Err(SecureError::TooLarge);
        }
        Ok(data)
    }

    fn merge(mut self, other: &Self) -> Result<Self, SecureError> {
        self.deleted.extend(other.deleted.iter().cloned());
        self.notes.retain(|id, _| !self.deleted.contains(id));
        for (id, record) in &other.notes {
            if self.deleted.contains(id) {
                continue;
            }
            // Use the per-note logical revision. A random tie-breaker converges
            // concurrent edits without depending on the devices' wall clocks.
            match self.notes.get(id) {
                Some(local) if (local.clock, &local.version) >= (record.clock, &record.version) => {
                }
                _ => {
                    self.notes.insert(id.clone(), record.clone());
                }
            }
        }
        self.validate()?;
        Ok(self)
    }
}

#[derive(Default)]
pub(crate) struct NotesSync {
    sequence: u64,
    active: Option<Active>,
    computing: Option<u64>,
}

struct Active {
    id: u64,
    began: Instant,
    origin: String,
    scope: String,
    bearer: Zeroizing<String>,
    generation: u64,
    hub_generation: u64,
    phase: Phase,
}

enum Phase {
    Get,
    Put(Profile),
}

pub struct NotesSyncWork {
    active: Active,
    profile: Profile,
    status: u32,
    body: Vec<u8>,
}

pub struct NotesSyncUpdate {
    active: Active,
    update: Result<Update, SecureError>,
}

pub enum NotesSyncReceipt {
    Complete(NotesSyncStep),
    Compute(Box<NotesSyncWork>),
}

enum Update {
    Pull(Profile),
    Push(Profile, Vec<u8>),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Remote {
    revision: u32,
    ciphertext: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Applied {
    revision: u32,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Upload {
    base_revision: u32,
    ciphertext: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Rejected {
    error: String,
}

impl CoreState {
    pub(super) fn notes_identity(&self) -> Option<(String, &str)> {
        let origin = self.local.server_candidate.as_deref()?;
        self.hub.scope_for_notes(origin).ok()
    }

    pub fn notes_sync_status(&self, lease: &str) -> Result<NotesSyncStatus, SecureError> {
        let scope = self.notes_visible_scope(lease)?;
        Ok(NotesSyncStatus {
            available: scope.is_some(),
            configured: scope
                .as_ref()
                .and_then(|scope| self.notes.profiles.get(scope))
                .is_some_and(|profile| profile.enabled),
        })
    }

    pub fn notes_sync_configure(
        &mut self,
        lease: &str,
        recovery: Option<Vec<u8>>,
    ) -> Result<Option<String>, SecureError> {
        let recovery = recovery.map(Zeroizing::new);
        let scope = self
            .notes_visible_scope(lease)?
            .ok_or(SecureError::Unsupported)?;
        let mut next = self.notes.clone();
        if let Some(profile) = next.profiles.get_mut(&scope) {
            if profile.enabled {
                return Err(SecureError::Conflict);
            }
            if let Some(recovery) = recovery {
                let key = recovery_key(&recovery)?;
                if profile.revision != 0 && key != profile.key {
                    return Err(SecureError::AuthenticationFailed);
                }
                profile.key = key;
            }
            profile.enabled = true;
            self.commit_notes(next)?;
            return Ok(None);
        }
        if next.profiles.len() >= MAX_PROFILES {
            return Err(SecureError::TooLarge);
        }
        let (key, code) = if let Some(recovery) = recovery {
            (recovery_key(&recovery)?, None)
        } else {
            let mut key = Zeroizing::new([0; 32]);
            SystemRandom::new()
                .fill(key.as_mut())
                .map_err(|_| SecureError::Unavailable)?;
            let code = Some(URL_SAFE_NO_PAD.encode(key.as_ref()));
            (key, code)
        };
        // Existing device-local notes are never promoted automatically.
        let data = Collection::default();
        next.profiles.insert(
            scope,
            Profile {
                data,
                key,
                revision: 0,
                enabled: true,
                dirty: true,
            },
        );
        self.commit_notes(next)?;
        Ok(code)
    }

    pub fn notes_sync_disable(&mut self, lease: &str) -> Result<(), SecureError> {
        let scope = self
            .notes_visible_scope(lease)?
            .ok_or(SecureError::Unsupported)?;
        let mut next = self.notes.clone();
        let profile = next.profiles.get_mut(&scope).ok_or(SecureError::NotFound)?;
        if !profile.enabled {
            return Ok(());
        }
        profile.enabled = false;
        self.commit_notes(next)?;
        self.notes_sync.active = None;
        Ok(())
    }

    pub fn notes_sync_eligible(&self) -> bool {
        self.require_local_config().is_ok()
            && self.notes_identity().is_some_and(|(scope, _)| {
                self.notes
                    .profiles
                    .get(&scope)
                    .is_some_and(|profile| profile.enabled)
            })
    }

    pub fn notes_sync_begin(&mut self) -> Result<Option<HubRequest>, SecureError> {
        self.require_local_config().map_err(super::storage_error)?;
        let Some((scope, bearer)) = self.notes_identity() else {
            return Ok(None);
        };
        let Some(profile) = self
            .notes
            .profiles
            .get(&scope)
            .filter(|profile| profile.enabled)
        else {
            return Ok(None);
        };
        let bearer = Zeroizing::new(bearer.to_owned());
        let hub_generation = self.hub.scope_generation();
        if self.notes_sync.active.as_ref().is_some_and(|active| {
            active.began.elapsed() <= PENDING_TIMEOUT && active.hub_generation == hub_generation
        }) || self.notes_sync.computing.is_some()
        {
            return Err(SecureError::Busy);
        }
        let origin = self
            .local
            .server_candidate
            .clone()
            .ok_or(SecureError::NotSignedIn)?;
        let id = self
            .notes_sync
            .sequence
            .checked_add(1)
            .ok_or(SecureError::Unavailable)?;
        self.notes_sync.sequence = id;
        let active = Active {
            id,
            began: Instant::now(),
            origin,
            scope,
            bearer,
            generation: self.notes.generation,
            hub_generation,
            phase: Phase::Get,
        };
        let request = active.request(
            "GET",
            Vec::new(),
            (profile.revision != 0).then(|| format!("\"{}\"", profile.revision)),
        );
        self.notes_sync.active = Some(active);
        Ok(Some(request))
    }

    pub fn notes_sync_accept(
        &mut self,
        request_id: u64,
        status: u32,
        media_type: Option<&str>,
        body: Vec<u8>,
    ) -> Result<NotesSyncReceipt, SecureError> {
        let active = self
            .notes_sync
            .active
            .take_if(|active| active.id == request_id)
            .ok_or(SecureError::StaleGeneration)?;
        self.require_current_sync(&active)?;
        if body.len() > WIRE_LIMIT {
            return Err(SecureError::TooLarge);
        }
        if matches!(status, 0 | 429 | 500..=599) {
            return Err(SecureError::NetworkUnavailable);
        }
        if status == 403 {
            return Err(SecureError::Unsupported);
        }
        if status != 304
            && !media_type.is_some_and(|value| {
                value
                    .split(';')
                    .next()
                    .is_some_and(|name| name.trim().eq_ignore_ascii_case("application/json"))
            })
        {
            return Err(SecureError::InvalidInput);
        }
        if status == 401 {
            let rejected: Rejected =
                serde_json::from_slice(&body).map_err(|_| SecureError::InvalidInput)?;
            if rejected.error != "session_expired" {
                return Err(SecureError::AuthenticationFailed);
            }
            self.hub_clear().map_err(|_| {
                self.require_local_config()
                    .err()
                    .map_or(SecureError::Unavailable, super::storage_error)
            })?;
            return Err(SecureError::NotSignedIn);
        }
        match active.phase {
            Phase::Get if matches!(status, 200 | 304 | 404) => {
                let profile = self
                    .notes
                    .profiles
                    .get(&active.scope)
                    .ok_or(SecureError::StaleGeneration)?;
                if status == 304 && body.is_empty() && profile.revision != 0 && !profile.dirty {
                    return Ok(NotesSyncReceipt::Complete(self.notes_sync_step(None)));
                }
                let profile = profile.clone();
                self.notes_sync.computing = Some(active.id);
                Ok(NotesSyncReceipt::Compute(Box::new(NotesSyncWork {
                    active,
                    profile,
                    status,
                    body,
                })))
            }
            Phase::Put(_) if status == 409 => Err(SecureError::Conflict),
            Phase::Put(profile) if status == 200 => {
                let ack: Applied =
                    serde_json::from_slice(&body).map_err(|_| SecureError::InvalidInput)?;
                if ack.revision != profile.revision {
                    return Err(SecureError::StaleGeneration);
                }
                self.commit_sync_profile(active.scope, profile)?;
                Ok(NotesSyncReceipt::Complete(self.notes_sync_step(None)))
            }
            _ => Err(SecureError::InvalidInput),
        }
    }

    pub fn notes_sync_commit(
        &mut self,
        update: NotesSyncUpdate,
    ) -> Result<NotesSyncStep, SecureError> {
        if self.notes_sync.computing != Some(update.active.id) {
            return Err(SecureError::StaleGeneration);
        }
        self.notes_sync.computing = None;
        let mut active = update.active;
        self.require_current_sync(&active)?;
        match update.update? {
            Update::Pull(profile) => {
                self.commit_sync_profile(active.scope, profile)?;
                Ok(self.notes_sync_step(None))
            }
            Update::Push(profile, body) => {
                let id = self
                    .notes_sync
                    .sequence
                    .checked_add(1)
                    .ok_or(SecureError::Unavailable)?;
                self.notes_sync.sequence = id;
                active.id = id;
                let request = active.request("PUT", body, None);
                active.phase = Phase::Put(profile);
                self.notes_sync.active = Some(active);
                Ok(self.notes_sync_step(Some(request)))
            }
        }
    }

    pub fn notes_sync_abandon(&mut self, request_id: u64) {
        self.notes_sync
            .active
            .take_if(|active| active.id == request_id);
        self.notes_sync.computing.take_if(|id| *id == request_id);
    }

    fn notes_sync_step(&self, next_request: Option<HubRequest>) -> NotesSyncStep {
        NotesSyncStep {
            next_request,
            generation: self.notes.generation,
        }
    }

    fn require_current_sync(&self, active: &Active) -> Result<(), SecureError> {
        self.require_local_config().map_err(super::storage_error)?;
        if active.began.elapsed() > PENDING_TIMEOUT
            || self.notes.generation != active.generation
            || self.hub.scope_generation() != active.hub_generation
            || self.local.server_candidate.as_deref() != Some(&active.origin)
        {
            return Err(SecureError::StaleGeneration);
        }
        let Some((scope, bearer)) = self.notes_identity() else {
            return Err(SecureError::NotSignedIn);
        };
        if scope != active.scope || bearer != active.bearer.as_str() {
            return Err(SecureError::StaleGeneration);
        }
        Ok(())
    }

    fn commit_sync_profile(&mut self, scope: String, profile: Profile) -> Result<(), SecureError> {
        let mut next: NotesState = self.notes.clone();
        next.profiles.insert(scope, profile);
        self.commit_notes(next)
    }
}

impl Active {
    fn request(&self, method: &str, body: Vec<u8>, if_none_match: Option<String>) -> HubRequest {
        HubRequest {
            request_id: self.id,
            generation: self.hub_generation,
            url: format!("{}/v1/notes", self.origin),
            method: method.into(),
            bearer: Some(self.bearer.to_string()),
            body,
            max_response_bytes: WIRE_LIMIT as u32,
            if_none_match,
            requested_capabilities: None,
        }
    }
}

impl NotesSyncWork {
    pub fn compute(self) -> NotesSyncUpdate {
        let outcome = collect_update(&self.active.scope, self.profile, self.status, &self.body);
        NotesSyncUpdate {
            active: self.active,
            update: outcome,
        }
    }
}

fn collect_update(
    scope: &str,
    mut profile: Profile,
    status: u32,
    body: &[u8],
) -> Result<Update, SecureError> {
    let base = match status {
        304 if body.is_empty() && profile.revision != 0 && profile.dirty => profile.revision,
        404 if profile.revision == 0 => {
            let receipt: Rejected =
                serde_json::from_slice(body).map_err(|_| SecureError::InvalidInput)?;
            if receipt.error != "not_found" {
                return Err(SecureError::InvalidInput);
            }
            0
        }
        200 => {
            let remote: Remote =
                serde_json::from_slice(body).map_err(|_| SecureError::InvalidInput)?;
            if remote.revision == 0 || remote.revision < profile.revision {
                return Err(SecureError::StaleGeneration);
            }
            let remote_data = decrypt(scope, remote.revision, &profile.key, &remote.ciphertext)?;
            profile.data = profile.data.merge(&remote_data)?;
            if profile.data == remote_data {
                profile.revision = remote.revision;
                profile.dirty = false;
                return Ok(Update::Pull(profile));
            }
            remote.revision
        }
        _ => return Err(SecureError::StaleGeneration),
    };
    let revision = base.checked_add(1).ok_or(SecureError::Unavailable)?;
    let cipher = encrypt(scope, revision, &profile.key, &profile.data)?;
    let body = serde_json::to_vec(&Upload {
        base_revision: base,
        ciphertext: cipher,
    })
    .map_err(|_| SecureError::Unavailable)?;
    if body.len() > WIRE_LIMIT {
        return Err(SecureError::TooLarge);
    }
    profile.revision = revision;
    profile.dirty = false;
    Ok(Update::Push(profile, body))
}

fn recovery_key(code: &[u8]) -> Result<Zeroizing<[u8; 32]>, SecureError> {
    if code.len() != 43 {
        return Err(SecureError::InvalidInput);
    }
    let mut bytes = Zeroizing::new([0; 32]);
    let length = URL_SAFE_NO_PAD
        .decode_slice(code, bytes.as_mut())
        .map_err(|_| SecureError::InvalidInput)?;
    if length != bytes.len() {
        return Err(SecureError::InvalidInput);
    }
    Ok(bytes)
}

fn context(scope: &str, revision: u32) -> Vec<u8> {
    [HEADER.as_slice(), scope.as_bytes(), &revision.to_be_bytes()].concat()
}

fn cipher_key(master: &[u8; 32], context: &[u8]) -> Result<aead::LessSafeKey, SecureError> {
    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, b"LOFT notes key v1");
    let binding = salt.extract(master);
    let info = [context];
    let expanded = binding
        .expand(&info, &aead::AES_256_GCM)
        .map_err(|_| SecureError::Unavailable)?;
    let mut key = Zeroizing::new([0; 32]);
    expanded
        .fill(key.as_mut())
        .map_err(|_| SecureError::Unavailable)?;
    aead::UnboundKey::new(&aead::AES_256_GCM, key.as_ref())
        .map(aead::LessSafeKey::new)
        .map_err(|_| SecureError::Unavailable)
}

fn encrypt(
    scope: &str,
    revision: u32,
    master: &[u8; 32],
    data: &Collection,
) -> Result<String, SecureError> {
    let mut nonce = [0; aead::NONCE_LEN];
    SystemRandom::new()
        .fill(&mut nonce)
        .map_err(|_| SecureError::Unavailable)?;
    let context = context(scope, revision);
    let mut plaintext = data.plaintext()?;
    cipher_key(master, &context)?
        .seal_in_place_append_tag(
            aead::Nonce::assume_unique_for_key(nonce),
            aead::Aad::from(&context),
            &mut *plaintext,
        )
        .map_err(|_| SecureError::Unavailable)?;
    let image = [HEADER.as_slice(), &nonce, &plaintext].concat();
    Ok(URL_SAFE_NO_PAD.encode(image))
}

fn decrypt(
    scope: &str,
    revision: u32,
    master: &[u8; 32],
    ciphertext: &str,
) -> Result<Collection, SecureError> {
    if ciphertext.len() > (CIPHER_LIMIT * 8).div_ceil(6) {
        return Err(SecureError::TooLarge);
    }
    let mut image = Zeroizing::new(
        URL_SAFE_NO_PAD
            .decode(ciphertext)
            .map_err(|_| SecureError::InvalidInput)?,
    );
    if image.len() < HEADER_BYTES + aead::AES_256_GCM.tag_len()
        || image.len() > CIPHER_LIMIT
        || !image.starts_with(HEADER)
    {
        return Err(SecureError::InvalidInput);
    }
    let nonce = aead::Nonce::try_assume_unique_for_key(&image[HEADER.len()..HEADER_BYTES])
        .map_err(|_| SecureError::InvalidInput)?;
    let context = context(scope, revision);
    let plaintext = cipher_key(master, &context)?
        .open_in_place(nonce, aead::Aad::from(&context), &mut image[HEADER_BYTES..])
        .map_err(|_| SecureError::AuthenticationFailed)?;
    let data: Collection =
        serde_json::from_slice(plaintext).map_err(|_| SecureError::InvalidInput)?;
    if !data.valid() {
        return Err(SecureError::InvalidInput);
    }
    Ok(data)
}
