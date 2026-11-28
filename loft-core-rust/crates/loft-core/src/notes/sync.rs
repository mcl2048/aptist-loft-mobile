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
    pub signed_in: bool,
    pub reset_available: bool,
    pub reset_pending: bool,
    pub needs_recovery: bool,
    pub recovery_code_ready: bool,
}

pub struct NotesSyncStep {
    pub next_request: Option<HubRequest>,
    pub generation: u64,
    pub reset_completed: bool,
    pub needs_recovery: bool,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    key_epoch: Option<String>,
    #[serde(default)]
    baseline: BTreeMap<String, String>,
    #[serde(default)]
    locally_changed: BTreeSet<String>,
    #[serde(default)]
    needs_recovery: bool,
    #[serde(default)]
    pairing: bool,
    #[serde(default)]
    code_ready: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    reset: Option<ResetIntent>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ResetIntent {
    operation: String,
    #[serde(serialize_with = "serialize_key", deserialize_with = "deserialize_key")]
    key: Zeroizing<[u8; 32]>,
    wipe_local_versions: Option<BTreeMap<String, String>>,
    prepared: Option<ResetPrepared>,
}

#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ResetPrepared {
    base_revision: u32,
    nonce: [u8; aead::NONCE_LEN],
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
        self.enabled && !self.needs_recovery
    }

    pub(super) fn valid(&self) -> bool {
        self.data.valid()
            && self
                .key_epoch
                .as_ref()
                .is_none_or(|epoch| fixed_id(epoch, 16))
            && self.baseline.len() <= MAX_NOTES
            && self
                .baseline
                .iter()
                .all(|(id, version)| fixed_id(id, 16) && fixed_id(version, 16))
            && self.locally_changed.len() <= MAX_NOTES
            && self
                .locally_changed
                .iter()
                .all(|id| self.data.notes.contains_key(id))
            && self.reset.as_ref().is_none_or(|reset| {
                fixed_id(&reset.operation, 16)
                    && reset.wipe_local_versions.as_ref().is_none_or(|ids| {
                        ids.len() <= MAX_NOTES
                            && ids
                                .iter()
                                .all(|(id, version)| fixed_id(id, 16) && fixed_id(version, 16))
                    })
            })
    }

    pub(super) fn ensure_editable(&self) -> Result<(), SecureError> {
        if self
            .reset
            .as_ref()
            .is_some_and(|reset| reset.prepared.is_some() || reset.wipe_local_versions.is_some())
        {
            return Err(SecureError::Busy);
        }
        Ok(())
    }

    pub(super) fn restore_baseline(&mut self) {
        if self.revision == 0 || !self.baseline.is_empty() || !self.locally_changed.is_empty() {
            return;
        }
        if self.dirty {
            self.locally_changed.extend(self.data.notes.keys().cloned());
        } else {
            self.baseline.extend(
                self.data
                    .notes
                    .iter()
                    .map(|(id, note)| (id.clone(), note.version.clone())),
            );
        }
    }

    pub(super) fn changed(&mut self, id: String) {
        self.dirty = true;
        self.locally_changed.insert(id);
    }

    pub(super) fn deleted(&mut self, id: &str) {
        self.dirty = true;
        self.locally_changed.remove(id);
    }

    fn sync_needed(&self) -> bool {
        self.reset.is_some() || (self.enabled && (!self.needs_recovery || self.pairing))
    }

    fn finish_revision(&mut self, revision: u32) {
        self.revision = revision;
        self.dirty = false;
        self.pairing = false;
        self.needs_recovery = false;
        self.locally_changed.clear();
        self.baseline = self
            .data
            .notes
            .iter()
            .map(|(id, note)| (id.clone(), note.version.clone()))
            .collect();
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

    fn merge(
        mut self,
        other: &Self,
        baseline: &BTreeMap<String, String>,
        locally_changed: &BTreeSet<String>,
    ) -> Result<Self, SecureError> {
        self.deleted.extend(other.deleted.iter().cloned());
        self.notes.retain(|id, _| !self.deleted.contains(id));
        for (id, remote) in &other.notes {
            if self.deleted.contains(id) {
                continue;
            }
            if let Some(local) = self.notes.get(id) {
                if local.same_content(remote) {
                    self.notes.insert(id.clone(), remote.clone());
                    continue;
                }
                let agreed = baseline.get(id);
                if agreed == Some(&remote.version) {
                    continue;
                }
                let local_unchanged = agreed == Some(&local.version)
                    || (!locally_changed.contains(id) && agreed.is_none());
                if !local_unchanged {
                    return Err(SecureError::Conflict);
                }
            }
            self.notes.insert(id.clone(), remote.clone());
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
    PrepareReset(ResetIntent),
    Reset,
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
    AdoptEpoch(Profile, Vec<Note>),
    Push(Profile, Vec<u8>),
    ReloadKey(Profile),
    StageReset(Profile, Vec<u8>),
    RejectReset(Profile, SecureError),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Remote {
    revision: u32,
    ciphertext: String,
    key_epoch: Option<String>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    key_epoch: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ResetUpload<'a> {
    base_revision: u32,
    ciphertext: String,
    operation_id: &'a str,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ResetApplied {
    revision: u32,
    operation_id: String,
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
        let profile = scope
            .as_ref()
            .and_then(|scope| self.notes.profiles.get(scope));
        Ok(NotesSyncStatus {
            available: scope.is_some(),
            configured: profile.is_some_and(|profile| profile.enabled),
            signed_in: self.hub.signed_in(),
            reset_available: scope.is_some() && self.hub.notes_reset_supported(),
            reset_pending: profile.is_some_and(|profile| profile.reset.is_some()),
            needs_recovery: profile.is_some_and(|profile| profile.needs_recovery),
            recovery_code_ready: profile
                .is_some_and(|profile| profile.code_ready && !profile.needs_recovery),
        })
    }

    pub fn notes_sync_reset(&mut self, lease: &str, wipe: bool) -> Result<(), SecureError> {
        let scope = self
            .notes_visible_scope(lease)?
            .ok_or(SecureError::Unsupported)?;
        if !self.hub.notes_reset_supported() {
            return Err(SecureError::Unsupported);
        }
        let mut next = self.notes.clone();
        if !next.profiles.contains_key(&scope) {
            if !wipe {
                return Err(SecureError::NotFound);
            }
            if next.profiles.len() >= MAX_PROFILES {
                return Err(SecureError::TooLarge);
            }
            next.profiles
                .insert(scope.clone(), new_profile(generate_key()?, false));
        }
        let profile = next.profiles.get_mut(&scope).ok_or(SecureError::NotFound)?;
        if profile.reset.is_some() || (!wipe && profile.needs_recovery) {
            return Err(SecureError::Conflict);
        }
        profile.reset = Some(ResetIntent {
            operation: super::random_note_id()?,
            key: generate_key()?,
            wipe_local_versions: wipe.then(|| {
                next.local
                    .iter()
                    .map(|(id, note)| (id.clone(), note.version.clone()))
                    .collect()
            }),
            prepared: None,
        });
        profile.code_ready = false;
        self.commit_notes(next)?;
        self.notes_sync.active = None;
        Ok(())
    }

    pub fn notes_sync_recovery_code(&self, lease: &str) -> Result<Option<String>, SecureError> {
        let scope = self
            .notes_visible_scope(lease)?
            .ok_or(SecureError::Unsupported)?;
        let profile = self
            .notes
            .profiles
            .get(&scope)
            .ok_or(SecureError::NotFound)?;
        Ok(
            (profile.code_ready && !profile.needs_recovery && profile.reset.is_none())
                .then(|| URL_SAFE_NO_PAD.encode(profile.key.as_ref())),
        )
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
            if profile.reset.is_some() {
                return Err(SecureError::Busy);
            }
            if profile.needs_recovery {
                let recovery = recovery.as_deref().ok_or(SecureError::InvalidInput)?;
                profile.key = recovery_key(recovery)?;
                profile.pairing = true;
                profile.enabled = true;
                self.commit_notes(next)?;
                return Ok(None);
            }
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
            let key = generate_key()?;
            let code = Some(URL_SAFE_NO_PAD.encode(key.as_ref()));
            (key, code)
        };
        // Existing device-local notes are never promoted automatically.
        next.profiles.insert(scope, new_profile(key, true));
        self.commit_notes(next)?;
        Ok(code)
    }

    pub fn notes_sync_disable(&mut self, lease: &str) -> Result<(), SecureError> {
        let scope = self
            .notes_visible_scope(lease)?
            .ok_or(SecureError::Unsupported)?;
        let mut next = self.notes.clone();
        let profile = next.profiles.get_mut(&scope).ok_or(SecureError::NotFound)?;
        if profile.reset.is_some() {
            return Err(SecureError::Busy);
        }
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
                    .is_some_and(Profile::sync_needed)
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
            .filter(|profile| profile.sync_needed())
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
        let mut active = active;
        if let Some(reset) = &profile.reset {
            if !self.hub.notes_reset_supported() {
                return Err(SecureError::Unsupported);
            }
            if reset.prepared.is_some() {
                let body = reset_body(&active.scope, profile, reset)?;
                let request = active.request("POST", body, None);
                active.phase = Phase::Reset;
                self.notes_sync.active = Some(active);
                return Ok(Some(request));
            }
            active.phase = Phase::PrepareReset(reset.clone());
        }
        let conditional = (profile.revision != 0 && !profile.pairing && profile.reset.is_none())
            .then(|| format!("\"{}\"", profile.revision));
        let request = active.request("GET", Vec::new(), conditional);
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
            Phase::Get | Phase::PrepareReset(_) if matches!(status, 200 | 304 | 404) => {
                let profile = self
                    .notes
                    .profiles
                    .get(&active.scope)
                    .ok_or(SecureError::StaleGeneration)?;
                if matches!(active.phase, Phase::Get)
                    && status == 304
                    && body.is_empty()
                    && profile.revision != 0
                    && !profile.dirty
                    && !profile.pairing
                {
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
            Phase::Reset if status == 200 => {
                let receipt: ResetApplied =
                    serde_json::from_slice(&body).map_err(|_| SecureError::InvalidInput)?;
                let mut next = self.notes.clone();
                let profile = next
                    .profiles
                    .get_mut(&active.scope)
                    .ok_or(SecureError::StaleGeneration)?;
                let intent = profile.reset.take().ok_or(SecureError::StaleGeneration)?;
                let prepared = intent.prepared.ok_or(SecureError::StaleGeneration)?;
                if receipt.operation_id != intent.operation
                    || prepared.base_revision.checked_add(1) != Some(receipt.revision)
                {
                    return Err(SecureError::InvalidInput);
                }
                if let Some(versions) = intent.wipe_local_versions {
                    next.local
                        .retain(|id, note| versions.get(id) != Some(&note.version));
                    profile.data = Collection::default();
                }
                profile.key = intent.key;
                profile.key_epoch = Some(intent.operation);
                profile.enabled = true;
                profile.code_ready = true;
                profile.finish_revision(receipt.revision);
                self.commit_notes(next)?;
                Ok(NotesSyncReceipt::Complete(NotesSyncStep {
                    reset_completed: true,
                    ..self.notes_sync_step(None)
                }))
            }
            Phase::Reset if status == 409 => {
                let mut next = self.notes.clone();
                let profile = next
                    .profiles
                    .get_mut(&active.scope)
                    .ok_or(SecureError::StaleGeneration)?;
                profile.reset = None;
                self.commit_notes(next)?;
                Err(SecureError::Conflict)
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
            Update::AdoptEpoch(profile, retained) => {
                let mut next = self.notes.clone();
                for mut note in retained {
                    note.id = super::random_note_id()?;
                    note.version = super::random_note_id()?;
                    next.local.insert(note.id.clone(), note);
                }
                next.profiles.insert(active.scope, profile);
                self.commit_notes(next)?;
                Ok(self.notes_sync_step(None))
            }
            Update::RejectReset(profile, error) => {
                self.commit_sync_profile(active.scope, profile)?;
                Err(error)
            }
            Update::ReloadKey(profile) => {
                self.commit_sync_profile(active.scope, profile)?;
                Ok(NotesSyncStep {
                    needs_recovery: true,
                    ..self.notes_sync_step(None)
                })
            }
            Update::StageReset(profile, body) => {
                self.commit_sync_profile(active.scope.clone(), profile)?;
                active.generation = self.notes.generation;
                self.notes_follow_up(active, Phase::Reset, "POST", body)
            }
            Update::Push(profile, body) => {
                self.notes_follow_up(active, Phase::Put(profile), "PUT", body)
            }
        }
    }

    fn notes_follow_up(
        &mut self,
        mut active: Active,
        phase: Phase,
        method: &str,
        body: Vec<u8>,
    ) -> Result<NotesSyncStep, SecureError> {
        let id = self
            .notes_sync
            .sequence
            .checked_add(1)
            .ok_or(SecureError::Unavailable)?;
        self.notes_sync.sequence = id;
        active.id = id;
        let request = active.request(method, body, None);
        active.phase = phase;
        self.notes_sync.active = Some(active);
        Ok(self.notes_sync_step(Some(request)))
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
            reset_completed: false,
            needs_recovery: false,
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
            url: format!(
                "{}/v1/notes{}",
                self.origin,
                if method == "POST" { "/reset" } else { "" }
            ),
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
        let outcome = match &self.active.phase {
            Phase::PrepareReset(reset) => prepare_reset(
                &self.active.scope,
                self.profile,
                reset.clone(),
                self.status,
                &self.body,
            ),
            _ => collect_update(&self.active.scope, self.profile, self.status, &self.body),
        };
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
        304 if body.is_empty() && profile.revision != 0 && profile.dirty && !profile.pairing => {
            profile.revision
        }
        404 if profile.revision == 0 && profile.key_epoch.is_none() => {
            require_not_found(body)?;
            0
        }
        200 => {
            let remote = read_remote(&profile, body)?;
            if remote.key_epoch != profile.key_epoch && profile.revision != 0 && !profile.pairing {
                return Ok(require_recovery(profile));
            }
            let remote_data = match decrypt(
                scope,
                remote.revision,
                remote.key_epoch.as_deref(),
                &profile.key,
                &remote.ciphertext,
            ) {
                Ok(data) => data,
                Err(SecureError::AuthenticationFailed) => return Ok(require_recovery(profile)),
                Err(error) => return Err(error),
            };
            if remote.key_epoch != profile.key_epoch && (profile.revision != 0 || profile.pairing) {
                // Carry unacknowledged work into device-local storage. The
                // new epoch can represent a wipe and cannot import old records.
                let retained = profile
                    .data
                    .notes
                    .values()
                    .filter(|note| {
                        profile.locally_changed.contains(&note.id)
                            && !remote_data
                                .notes
                                .get(&note.id)
                                .is_some_and(|remote| note.same_content(remote))
                    })
                    .cloned()
                    .collect();
                profile.data = remote_data;
                profile.key_epoch = remote.key_epoch;
                profile.finish_revision(remote.revision);
                return Ok(Update::AdoptEpoch(profile, retained));
            }
            profile.data = merge_profile(&profile, &remote_data)?;
            profile.key_epoch = remote.key_epoch;
            if profile.data == remote_data {
                profile.finish_revision(remote.revision);
                return Ok(Update::Pull(profile));
            }
            remote.revision
        }
        _ => return Err(SecureError::StaleGeneration),
    };
    let revision = base.checked_add(1).ok_or(SecureError::Unavailable)?;
    let nonce = generate_nonce()?;
    let cipher = encrypt(
        scope,
        revision,
        profile.key_epoch.as_deref(),
        &profile.key,
        &profile.data,
        nonce,
    )?;
    let body = serde_json::to_vec(&Upload {
        base_revision: base,
        ciphertext: cipher,
        key_epoch: profile.key_epoch.clone(),
    })
    .map_err(|_| SecureError::Unavailable)?;
    if body.len() > WIRE_LIMIT {
        return Err(SecureError::TooLarge);
    }
    profile.finish_revision(revision);
    Ok(Update::Push(profile, body))
}

fn require_recovery(mut profile: Profile) -> Update {
    profile.needs_recovery = true;
    profile.pairing = false;
    profile.code_ready = false;
    Update::ReloadKey(profile)
}

fn read_remote(profile: &Profile, body: &[u8]) -> Result<Remote, SecureError> {
    let remote: Remote = serde_json::from_slice(body).map_err(|_| SecureError::InvalidInput)?;
    if remote.revision == 0 || remote.revision < profile.revision {
        return Err(SecureError::StaleGeneration);
    }
    if remote
        .key_epoch
        .as_ref()
        .is_some_and(|epoch| !fixed_id(epoch, 16))
    {
        return Err(SecureError::InvalidInput);
    }
    Ok(remote)
}

fn require_not_found(body: &[u8]) -> Result<(), SecureError> {
    let receipt: Rejected = serde_json::from_slice(body).map_err(|_| SecureError::InvalidInput)?;
    if receipt.error != "not_found" {
        return Err(SecureError::InvalidInput);
    }
    Ok(())
}

fn merge_profile(profile: &Profile, remote: &Collection) -> Result<Collection, SecureError> {
    profile
        .data
        .clone()
        .merge(remote, &profile.baseline, &profile.locally_changed)
}

fn prepare_reset(
    scope: &str,
    mut profile: Profile,
    mut reset: ResetIntent,
    status: u32,
    body: &[u8],
) -> Result<Update, SecureError> {
    let base_revision = match status {
        404 if profile.revision == 0 => {
            require_not_found(body)?;
            0
        }
        200 => {
            let remote = read_remote(&profile, body)?;
            if reset.wipe_local_versions.is_none() {
                let merged = if remote.key_epoch != profile.key_epoch && profile.revision != 0 {
                    Err(SecureError::AuthenticationFailed)
                } else {
                    decrypt(
                        scope,
                        remote.revision,
                        remote.key_epoch.as_deref(),
                        &profile.key,
                        &remote.ciphertext,
                    )
                    .and_then(|remote| merge_profile(&profile, &remote))
                };
                match merged {
                    Ok(data) => profile.data = data,
                    Err(error) => {
                        profile.reset = None;
                        if error == SecureError::AuthenticationFailed {
                            profile.needs_recovery = true;
                            profile.code_ready = false;
                            profile.pairing = false;
                        }
                        return Ok(Update::RejectReset(profile, error));
                    }
                }
            }
            remote.revision
        }
        _ => return Err(SecureError::StaleGeneration),
    };
    reset.prepared = Some(ResetPrepared {
        base_revision,
        nonce: generate_nonce()?,
    });
    let request = reset_body(scope, &profile, &reset)?;
    profile.reset = Some(reset);
    Ok(Update::StageReset(profile, request))
}

fn new_profile(key: Zeroizing<[u8; 32]>, enabled: bool) -> Profile {
    Profile {
        data: Collection::default(),
        key,
        revision: 0,
        enabled,
        dirty: true,
        key_epoch: None,
        baseline: BTreeMap::new(),
        locally_changed: BTreeSet::new(),
        needs_recovery: false,
        pairing: false,
        code_ready: false,
        reset: None,
    }
}

fn generate_key() -> Result<Zeroizing<[u8; 32]>, SecureError> {
    let mut key = Zeroizing::new([0; 32]);
    SystemRandom::new()
        .fill(key.as_mut())
        .map_err(|_| SecureError::Unavailable)?;
    Ok(key)
}

fn generate_nonce() -> Result<[u8; aead::NONCE_LEN], SecureError> {
    let mut nonce = [0; aead::NONCE_LEN];
    SystemRandom::new()
        .fill(&mut nonce)
        .map_err(|_| SecureError::Unavailable)?;
    Ok(nonce)
}

fn reset_body(scope: &str, profile: &Profile, reset: &ResetIntent) -> Result<Vec<u8>, SecureError> {
    let prepared = reset.prepared.ok_or(SecureError::StaleGeneration)?;
    let data = if reset.wipe_local_versions.is_some() {
        &Collection::default()
    } else {
        &profile.data
    };
    let revision = prepared
        .base_revision
        .checked_add(1)
        .ok_or(SecureError::Unavailable)?;
    let ciphertext = encrypt(
        scope,
        revision,
        Some(&reset.operation),
        &reset.key,
        data,
        prepared.nonce,
    )?;
    let body = serde_json::to_vec(&ResetUpload {
        base_revision: prepared.base_revision,
        ciphertext,
        operation_id: &reset.operation,
    })
    .map_err(|_| SecureError::Unavailable)?;
    if body.len() > WIRE_LIMIT {
        return Err(SecureError::TooLarge);
    }
    Ok(body)
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

fn context(scope: &str, revision: u32, epoch: Option<&str>) -> Vec<u8> {
    [
        HEADER.as_slice(),
        scope.as_bytes(),
        &revision.to_be_bytes(),
        epoch.unwrap_or_default().as_bytes(),
    ]
    .concat()
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
    epoch: Option<&str>,
    master: &[u8; 32],
    data: &Collection,
    nonce: [u8; aead::NONCE_LEN],
) -> Result<String, SecureError> {
    let context = context(scope, revision, epoch);
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
    epoch: Option<&str>,
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
    let context = context(scope, revision, epoch);
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
