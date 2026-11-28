use super::{Record, VAULT_IMAGE_LIMIT, VaultError, VaultState, fixed_id, storage_error};
use crate::{CoreState, HubRequest};
use argon2::{Algorithm, Argon2, Block, Params, Version};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::{
    aead,
    rand::{SecureRandom, SystemRandom},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use zeroize::Zeroizing;

const HEADER: &[u8; 8] = b"LOFTVLT1";
const SALT_BYTES: usize = 16;
const HEADER_BYTES: usize = HEADER.len() + SALT_BYTES + aead::NONCE_LEN;
const WIRE_LIMIT: usize = 360 * 1024;
const CIPHERTEXT_LIMIT: usize = 256 * 1024;
const KDF_MEMORY_KIB: u32 = 64 * 1024;

pub struct VaultSyncStep {
    pub next_request: Option<HubRequest>,
    pub generation: u64,
}

#[derive(Clone, PartialEq, Eq, Deserialize, Serialize)]
pub(super) struct Baseline {
    revision: u32,
    fingerprints: BTreeMap<String, String>,
}

impl Baseline {
    pub(super) fn valid(&self) -> bool {
        self.revision != 0
            && self.fingerprints.len() <= super::MAX_ENTRIES
            && self
                .fingerprints
                .iter()
                .all(|(id, fingerprint)| fixed_id(id, 16) && fixed_id(fingerprint, 32))
    }
}

#[derive(Default)]
pub(crate) struct State {
    last_id: u64,
    active: Option<Active>,
    computing: Option<u64>,
}

struct Active {
    id: u64,
    scope: String,
    bearer: Zeroizing<String>,
    origin: String,
    generation: u64,
    hub_generation: u64,
    passphrase: Zeroizing<Vec<u8>>,
    retried: bool,
    phase: Phase,
}

enum Phase {
    Get,
    Put { revision: u32, next: VaultState },
}

pub enum VaultSyncReceipt {
    Complete(VaultSyncStep),
    Compute(Box<VaultSyncWork>),
}

pub struct VaultSyncWork {
    active: Active,
    vault: VaultState,
    status: u32,
    body: Vec<u8>,
}

pub struct VaultSyncUpdate {
    active: Active,
    outcome: Result<Update, VaultError>,
}

enum Update {
    NoChanges,
    Pull(VaultState),
    Push {
        revision: u32,
        next: VaultState,
        body: Vec<u8>,
    },
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
    pub fn vault_sync_begin(&mut self, passphrase: Vec<u8>) -> Result<HubRequest, VaultError> {
        let passphrase = Zeroizing::new(passphrase);
        if self.vault_sync.active.is_some() || self.vault_sync.computing.is_some() {
            return Err(VaultError::Busy);
        }
        if !(12..=1024).contains(&passphrase.len())
            || !std::str::from_utf8(&passphrase).is_ok_and(|passphrase| {
                !passphrase.trim().is_empty() && !passphrase.chars().any(char::is_control)
            })
        {
            return Err(VaultError::InvalidInput);
        }
        self.require_local_config().map_err(storage_error)?;
        let origin = self
            .local
            .server_candidate
            .clone()
            .ok_or(VaultError::NotSignedIn)?;
        let (scope, bearer) = self
            .hub
            .scope_for_vault(&origin)
            .map_err(|_| VaultError::NotSignedIn)?;
        let active = Active {
            id: self.vault_sync.next_id()?,
            scope,
            bearer: Zeroizing::new(bearer),
            origin,
            generation: self.vault.generation,
            hub_generation: self.hub.scope_generation(),
            passphrase,
            retried: false,
            phase: Phase::Get,
        };
        let request = active.request("GET", Vec::new());
        self.vault_sync.active = Some(active);
        Ok(request)
    }

    pub fn vault_sync_finish(
        &mut self,
        request_id: u64,
        status: u32,
        media_type: Option<&str>,
        body: Vec<u8>,
    ) -> Result<VaultSyncStep, VaultError> {
        match self.vault_sync_accept(request_id, status, media_type, body)? {
            VaultSyncReceipt::Complete(step) => Ok(step),
            VaultSyncReceipt::Compute(work) => self.vault_sync_commit(work.compute()),
        }
    }

    pub fn vault_sync_accept(
        &mut self,
        request_id: u64,
        status: u32,
        media_type: Option<&str>,
        body: Vec<u8>,
    ) -> Result<VaultSyncReceipt, VaultError> {
        let active = self
            .vault_sync
            .active
            .take_if(|active| active.id == request_id)
            .ok_or(VaultError::StaleGeneration)?;
        self.check_sync_scope(&active)?;
        if body.len() > WIRE_LIMIT {
            return Err(VaultError::TooLarge);
        }
        let media_json = media_type
            .and_then(|media| media.split(';').next())
            .is_some_and(|media| media.trim().eq_ignore_ascii_case("application/json"));
        if matches!(status, 429 | 500..=599) {
            return Err(VaultError::NetworkUnavailable);
        }
        if status == 413 {
            return Err(VaultError::TooLarge);
        }
        if !media_json {
            return Err(VaultError::NetworkUnavailable);
        }
        if status == 401 {
            let rejection: Rejected =
                serde_json::from_slice(&body).map_err(|_| VaultError::NetworkUnavailable)?;
            if rejection.error != "session_expired" {
                return Err(VaultError::NetworkUnavailable);
            }
            self.hub_clear().map_err(|_| VaultError::Unavailable)?;
            return Err(VaultError::NotSignedIn);
        }
        match active.phase {
            Phase::Get => {
                self.vault_sync.computing = Some(active.id);
                Ok(VaultSyncReceipt::Compute(Box::new(VaultSyncWork {
                    active,
                    vault: self.vault.clone(),
                    status,
                    body,
                })))
            }
            Phase::Put { revision, next } => {
                if status == 409 {
                    if active.retried {
                        return Err(VaultError::Conflict);
                    }
                    let rejected: Rejected = serde_json::from_slice(&body)
                        .map_err(|_| VaultError::NetworkUnavailable)?;
                    if rejected.error != "conflict" {
                        return Err(VaultError::NetworkUnavailable);
                    }
                    let active = Active {
                        id: self.vault_sync.next_id()?,
                        retried: true,
                        phase: Phase::Get,
                        ..active
                    };
                    let request = active.request("GET", Vec::new());
                    self.vault_sync.active = Some(active);
                    return Ok(VaultSyncReceipt::Complete(self.sync_step(Some(request))));
                }
                let applied: Applied =
                    serde_json::from_slice(&body).map_err(|_| VaultError::NetworkUnavailable)?;
                if status != 200 || applied.revision != revision {
                    return Err(VaultError::NetworkUnavailable);
                }
                self.commit_vault(next)?;
                Ok(VaultSyncReceipt::Complete(self.sync_step(None)))
            }
        }
    }

    pub fn vault_sync_commit(
        &mut self,
        result: VaultSyncUpdate,
    ) -> Result<VaultSyncStep, VaultError> {
        let VaultSyncUpdate { active, outcome } = result;
        if self
            .vault_sync
            .computing
            .take_if(|id| *id == active.id)
            .is_none()
        {
            return Err(VaultError::StaleGeneration);
        }
        self.check_sync_scope(&active)?;
        match outcome? {
            Update::NoChanges => Ok(self.sync_step(None)),
            Update::Pull(next) => {
                self.commit_vault(next)?;
                Ok(self.sync_step(None))
            }
            Update::Push {
                revision,
                next,
                body,
            } => {
                let follow_up = Active {
                    id: self.vault_sync.next_id()?,
                    phase: Phase::Put { revision, next },
                    ..active
                };
                let request = follow_up.request("PUT", body);
                self.vault_sync.active = Some(follow_up);
                Ok(self.sync_step(Some(request)))
            }
        }
    }

    fn sync_step(&self, next_request: Option<HubRequest>) -> VaultSyncStep {
        VaultSyncStep {
            next_request,
            generation: self.vault.generation,
        }
    }

    pub fn vault_sync_abandon(&mut self, request_id: u64) {
        self.vault_sync
            .active
            .take_if(|active| active.id == request_id);
        self.vault_sync.computing.take_if(|id| *id == request_id);
    }

    fn check_sync_scope(&self, active: &Active) -> Result<(), VaultError> {
        if self.vault.generation != active.generation
            || self.hub.scope_generation() != active.hub_generation
            || self.local.server_candidate.as_ref() != Some(&active.origin)
        {
            return Err(VaultError::StaleGeneration);
        }
        let (scope, bearer) = self
            .hub
            .scope_for_vault(&active.origin)
            .map_err(|_| VaultError::NotSignedIn)?;
        if scope != active.scope || Zeroizing::new(bearer) != active.bearer {
            return Err(VaultError::StaleGeneration);
        }
        Ok(())
    }
}

impl VaultSyncWork {
    pub fn compute(self) -> VaultSyncUpdate {
        let outcome = match self.active.phase {
            Phase::Get => self.finish_get(&self.active.passphrase),
            Phase::Put { .. } => Err(VaultError::StaleGeneration),
        };
        VaultSyncUpdate {
            active: self.active,
            outcome,
        }
    }

    fn finish_get(&self, passphrase: &[u8]) -> Result<Update, VaultError> {
        let active = &self.active;
        let body = &self.body;
        let baseline = self.vault.revisions.get(&active.scope);
        let (revision, remote, salt, key) = match self.status {
            200 => {
                let remote: Remote =
                    serde_json::from_slice(body).map_err(|_| VaultError::AuthenticationFailed)?;
                if remote.revision == 0
                    || baseline.is_some_and(|baseline| baseline.revision > remote.revision)
                {
                    return Err(VaultError::Conflict);
                }
                let revision = remote.revision;
                let (records, salt, key) = open(passphrase, &active.scope, remote)?;
                (revision, records, salt, key)
            }
            404 => {
                let rejected: Rejected =
                    serde_json::from_slice(body).map_err(|_| VaultError::NetworkUnavailable)?;
                if rejected.error != "not_found" {
                    return Err(VaultError::NetworkUnavailable);
                }
                if baseline.is_some() {
                    return Err(VaultError::Conflict);
                }
                let mut salt = [0; SALT_BYTES];
                SystemRandom::new()
                    .fill(&mut salt)
                    .map_err(|_| VaultError::Unavailable)?;
                (0, BTreeMap::new(), salt, derive(passphrase, &salt)?)
            }
            _ => return Err(VaultError::NetworkUnavailable),
        };
        let records = merge(&self.vault, &active.scope, baseline, &remote)?;
        let mut next = self.vault.clone();
        next.entries.retain(|_, record| {
            record
                .owner
                .as_deref()
                .is_some_and(|owner| owner != active.scope)
        });
        for (id, record) in &records {
            if next.entries.insert(id.clone(), record.clone()).is_some() {
                return Err(VaultError::Conflict);
            }
        }
        if next.entries.len() > super::MAX_ENTRIES {
            return Err(VaultError::TooLarge);
        }
        if records == remote && revision != 0 {
            next.revisions
                .insert(active.scope.clone(), baseline_for(revision, &records)?);
            return Ok(if next == self.vault {
                Update::NoChanges
            } else {
                Update::Pull(next)
            });
        }
        if records.is_empty() {
            return Ok(Update::NoChanges);
        }

        let next_revision = revision.checked_add(1).ok_or(VaultError::Conflict)?;
        next.revisions
            .insert(active.scope.clone(), baseline_for(next_revision, &records)?);
        // Validate the durable image before offering the remote write.
        let local = Zeroizing::new(serde_json::to_vec(&next).map_err(|_| VaultError::Unavailable)?);
        if local.len() > VAULT_IMAGE_LIMIT {
            return Err(VaultError::TooLarge);
        }
        let ciphertext = seal(&key, salt, &active.scope, next_revision, &records)?;
        let body = serde_json::to_vec(&Upload {
            base_revision: revision,
            ciphertext,
        })
        .map_err(|_| VaultError::Unavailable)?;
        Ok(Update::Push {
            revision: next_revision,
            next,
            body,
        })
    }
}

impl State {
    fn next_id(&mut self) -> Result<u64, VaultError> {
        self.last_id = self.last_id.checked_add(1).ok_or(VaultError::Unavailable)?;
        Ok(self.last_id)
    }
}

impl Active {
    fn request(&self, method: &str, body: Vec<u8>) -> HubRequest {
        HubRequest {
            request_id: self.id,
            generation: self.generation,
            url: format!("{}/v1/vault/{}", self.origin, self.scope),
            method: method.into(),
            bearer: Some(self.bearer.to_string()),
            body,
            max_response_bytes: WIRE_LIMIT as u32,
            if_none_match: None,
            requested_capabilities: None,
        }
    }
}

fn merge(
    vault: &VaultState,
    scope: &str,
    baseline: Option<&Baseline>,
    remote: &BTreeMap<String, Record>,
) -> Result<BTreeMap<String, Record>, VaultError> {
    let local = vault
        .entries
        .iter()
        .filter(|(_, record)| record.owner.as_deref().is_none_or(|owner| owner == scope))
        .collect::<BTreeMap<_, _>>();
    let mut ids = local
        .keys()
        .copied()
        .chain(remote.keys())
        .collect::<BTreeSet<_>>();
    if let Some(baseline) = baseline {
        ids.extend(baseline.fingerprints.keys());
    }
    let mut result = BTreeMap::new();
    for id in ids {
        let local = local.get(id).map(|record| {
            let mut record = (*record).clone();
            record.owner = Some(scope.into());
            record
        });
        let remote = remote.get(id);
        let before = baseline.and_then(|baseline| baseline.fingerprints.get(id));
        let merged = match (local.as_ref(), remote, before) {
            (Some(left), Some(right), _) if left == right => left,
            (Some(left), None, None) => left,
            (None, Some(right), None) => right,
            (Some(left), Some(right), Some(before)) if fingerprint(left)? == *before => right,
            (Some(left), Some(right), Some(before)) if fingerprint(right)? == *before => left,
            _ => return Err(VaultError::Conflict),
        };
        result.insert(id.clone(), merged.clone());
    }
    Ok(result)
}

fn fingerprint(record: &Record) -> Result<String, VaultError> {
    let encoded = Zeroizing::new(serde_json::to_vec(record).map_err(|_| VaultError::Unavailable)?);
    Ok(URL_SAFE_NO_PAD.encode(Sha256::digest(&encoded)))
}

fn baseline_for(revision: u32, records: &BTreeMap<String, Record>) -> Result<Baseline, VaultError> {
    let fingerprints = records
        .iter()
        .map(|(id, record)| Ok((id.clone(), fingerprint(record)?)))
        .collect::<Result<_, VaultError>>()?;
    Ok(Baseline {
        revision,
        fingerprints,
    })
}

fn derive(passphrase: &[u8], salt: &[u8; SALT_BYTES]) -> Result<Zeroizing<[u8; 32]>, VaultError> {
    let params =
        Params::new(KDF_MEMORY_KIB, 3, 4, Some(32)).map_err(|_| VaultError::Unavailable)?;
    let algorithm = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut memory = Vec::<Block>::new();
    memory
        .try_reserve_exact(KDF_MEMORY_KIB as usize)
        .map_err(|_| VaultError::Unavailable)?;
    memory.resize(KDF_MEMORY_KIB as usize, Block::default());
    let mut memory = Zeroizing::new(memory);
    let mut key = Zeroizing::new([0; 32]);
    algorithm
        .hash_password_into_with_memory(passphrase, salt, key.as_mut(), &mut *memory)
        .map_err(|_| VaultError::Unavailable)?;
    Ok(key)
}

fn aad(scope: &str, revision: u32) -> Vec<u8> {
    let mut bytes = Vec::from(&HEADER[..]);
    bytes.extend_from_slice(scope.as_bytes());
    bytes.extend_from_slice(&revision.to_be_bytes());
    bytes
}

fn aead_key(key: &[u8; 32]) -> Result<aead::LessSafeKey, VaultError> {
    aead::UnboundKey::new(&aead::AES_256_GCM, key)
        .map(aead::LessSafeKey::new)
        .map_err(|_| VaultError::Unavailable)
}

fn seal(
    key: &[u8; 32],
    salt: [u8; SALT_BYTES],
    scope: &str,
    revision: u32,
    records: &BTreeMap<String, Record>,
) -> Result<String, VaultError> {
    let data = serde_json::to_vec(records).map_err(|_| VaultError::Unavailable)?;
    let mut data = Zeroizing::new(data);
    if data.len() > VAULT_IMAGE_LIMIT {
        return Err(VaultError::TooLarge);
    }
    let mut nonce = [0; aead::NONCE_LEN];
    SystemRandom::new()
        .fill(&mut nonce)
        .map_err(|_| VaultError::Unavailable)?;
    let tag = aead_key(key)?
        .seal_in_place_separate_tag(
            aead::Nonce::assume_unique_for_key(nonce),
            aead::Aad::from(aad(scope, revision)),
            &mut data,
        )
        .map_err(|_| VaultError::Unavailable)?;
    let mut output = Vec::with_capacity(HEADER_BYTES + data.len() + tag.as_ref().len());
    output.extend_from_slice(HEADER);
    output.extend_from_slice(&salt);
    output.extend_from_slice(&nonce);
    output.extend_from_slice(&data);
    output.extend_from_slice(tag.as_ref());
    Ok(URL_SAFE_NO_PAD.encode(output))
}

type Unsealed = (
    BTreeMap<String, Record>,
    [u8; SALT_BYTES],
    Zeroizing<[u8; 32]>,
);

fn open(passphrase: &[u8], scope: &str, remote: Remote) -> Result<Unsealed, VaultError> {
    if remote.ciphertext.len() > CIPHERTEXT_LIMIT.div_ceil(3) * 4 {
        return Err(VaultError::TooLarge);
    }
    let mut payload = Zeroizing::new(
        URL_SAFE_NO_PAD
            .decode(remote.ciphertext)
            .map_err(|_| VaultError::AuthenticationFailed)?,
    );
    if !(HEADER_BYTES + aead::MAX_TAG_LEN..=CIPHERTEXT_LIMIT).contains(&payload.len())
        || !payload.starts_with(HEADER)
    {
        return Err(VaultError::AuthenticationFailed);
    }
    let salt = payload[HEADER.len()..HEADER.len() + SALT_BYTES]
        .try_into()
        .expect("bounded header");
    let nonce = payload[HEADER.len() + SALT_BYTES..HEADER_BYTES]
        .try_into()
        .expect("bounded header");
    let key = derive(passphrase, &salt)?;
    let bytes = aead_key(&key)?
        .open_in_place(
            aead::Nonce::assume_unique_for_key(nonce),
            aead::Aad::from(aad(scope, remote.revision)),
            &mut payload[HEADER_BYTES..],
        )
        .map_err(|_| VaultError::AuthenticationFailed)?;
    let records: BTreeMap<String, Record> =
        serde_json::from_slice(bytes).map_err(|_| VaultError::AuthenticationFailed)?;
    if records.len() > super::MAX_ENTRIES
        || records.iter().any(|(id, record)| {
            id != &record.entry.id
                || record.owner.as_deref() != Some(scope)
                || record.validate().is_err()
        })
    {
        return Err(VaultError::AuthenticationFailed);
    }
    Ok((records, salt, key))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{VaultEntry, VaultKind};

    #[test]
    fn vault_merge_preserves_independent_changes_and_refuses_conflicts_or_removal() {
        fn record(id: String, scope: &str) -> Record {
            Record {
                entry: VaultEntry {
                    id,
                    kind: VaultKind::Password,
                    label: "Before".into(),
                    account: "".into(),
                    issuer: "".into(),
                    archived: false,
                    algorithm: None,
                    digits: None,
                    period: None,
                },
                secret: Zeroizing::new(b"test material".to_vec()),
                owner: Some(scope.into()),
                version: 1,
            }
        }
        let scope = URL_SAFE_NO_PAD.encode([9; 32]);
        let a = URL_SAFE_NO_PAD.encode([5; 16]);
        let b = URL_SAFE_NO_PAD.encode([6; 16]);
        let c = URL_SAFE_NO_PAD.encode([7; 16]);
        let original = BTreeMap::from([
            (a.clone(), record(a.clone(), &scope)),
            (b.clone(), record(b.clone(), &scope)),
        ]);
        let baseline = baseline_for(1, &original).unwrap();
        let mut local = VaultState {
            entries: original.clone(),
            ..VaultState::default()
        };
        let local_change = local.entries.get_mut(&a).unwrap();
        local_change.entry.archived = true;
        local_change.version += 1;
        let other_scope = URL_SAFE_NO_PAD.encode([10; 32]);
        local
            .entries
            .insert(c.clone(), record(c.clone(), &other_scope));
        let mut remote = original;
        let remote_change = remote.get_mut(&b).unwrap();
        remote_change.entry.label = "Remote edit".into();
        remote_change.version += 1;
        let merged = merge(&local, &scope, Some(&baseline), &remote).unwrap();
        assert!(merged[&a].entry.archived);
        assert_eq!(merged[&b].entry.label, "Remote edit");
        assert!(!merged.contains_key(&c));

        remote.get_mut(&a).unwrap().entry.label = "Competing edit".into();
        assert_eq!(
            merge(&local, &scope, Some(&baseline), &remote).err(),
            Some(VaultError::Conflict)
        );
        remote.remove(&a);
        assert_eq!(
            merge(&local, &scope, Some(&baseline), &remote).err(),
            Some(VaultError::Conflict)
        );
    }
}
