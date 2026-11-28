use crate::{
    CoreError, CoreState, PrivateRecord, ProtectionScope, SecureError, protection::storage_error,
    vault::random_id,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use zeroize::{Zeroize, Zeroizing};

mod sync;
pub(crate) use sync::NotesSync;
pub use sync::{NotesSyncReceipt, NotesSyncStatus, NotesSyncStep};

pub const NOTES_IMAGE_LIMIT: usize = 480 * 1024;
const MAX_NOTE_BYTES: usize = 25 * 1024;
const MAX_TITLE_BYTES: usize = 240;
const MAX_ICON_BYTES: usize = 64;
const MAX_TAG_BYTES: usize = 64;
const MAX_TAGS: usize = 12;
const MAX_TAG_INPUT_BYTES: usize = 1024;
const MAX_NOTES: usize = 200;
const PAGE_SIZE: usize = 20;
const MAX_QUERY_BYTES: usize = 256;

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Note {
    id: String,
    title: String,
    body: String,
    icon: Option<String>,
    tags: Vec<String>,
    created_at: u64,
    updated_at: u64,
    archived: bool,
    version: String,
    clock: u64,
}

impl Drop for Note {
    fn drop(&mut self) {
        self.title.zeroize();
        self.body.zeroize();
        self.icon.zeroize();
        self.tags.zeroize();
    }
}

pub struct NotesDraft {
    pub id: Option<String>,
    pub title: String,
    pub body: String,
    pub icon: Option<String>,
    pub tags: String,
    pub expected_version: Option<String>,
}

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

pub struct NoteDetail {
    pub summary: NoteSummary,
    pub body: String,
}

pub struct NotesPage {
    pub generation: u64,
    pub entries: Vec<NoteSummary>,
    pub next_offset: Option<u32>,
}

pub struct NoteTag {
    pub name: String,
    pub count: u32,
}

#[derive(Default, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NotesState {
    generation: u64,
    local: BTreeMap<String, Note>,
    profiles: BTreeMap<String, sync::Profile>,
}

impl NotesState {
    pub(crate) fn restore(data: &[u8]) -> Result<Self, CoreError> {
        let mut state: Self =
            serde_json::from_slice(data).map_err(|_| CoreError::StorageRecoveryRequired)?;
        if data.len() > NOTES_IMAGE_LIMIT || !state.valid() {
            return Err(CoreError::StorageRecoveryRequired);
        }
        for profile in state.profiles.values_mut() {
            profile.restore_baseline();
        }
        Ok(state)
    }

    fn valid(&self) -> bool {
        self.total_notes() <= MAX_NOTES
            && self.profiles.len() <= sync::MAX_PROFILES
            && self.local.iter().all(|(id, note)| note.valid(id))
            && self
                .profiles
                .iter()
                .all(|(scope, profile)| fixed_id(scope, 32) && profile.valid())
    }

    fn total_notes(&self) -> usize {
        self.local.len()
            + self
                .profiles
                .values()
                .map(|profile| profile.data.notes.len())
                .sum::<usize>()
    }

    fn visible<'a>(&'a self, scope: Option<&str>) -> impl Iterator<Item = &'a Note> {
        self.local.values().chain(
            scope
                .and_then(|scope| self.profiles.get(scope))
                .into_iter()
                .flat_map(|profile| profile.data.notes.values()),
        )
    }

    fn find(&self, scope: Option<&str>, id: &str) -> Option<(&Note, bool)> {
        self.local.get(id).map(|note| (note, false)).or_else(|| {
            let profile = self.profiles.get(scope?)?;
            profile.data.notes.get(id).map(|note| (note, true))
        })
    }

    fn insert(&mut self, scope: Option<&str>, note: Note) -> Result<(), SecureError> {
        if let Some(profile) = scope.and_then(|scope| self.profiles.get_mut(scope)) {
            profile.ensure_editable()?;
            profile.changed(note.id.clone());
            profile.data.notes.insert(note.id.clone(), note);
            profile.data.validate()?;
        } else {
            self.local.insert(note.id.clone(), note);
        }
        Ok(())
    }
}

impl CoreState {
    pub fn notes_list(
        &self,
        lease: &str,
        archived: bool,
        query: &str,
        tag: Option<&str>,
        offset: u32,
        expected_generation: Option<u64>,
    ) -> Result<NotesPage, SecureError> {
        let scope = self.notes_visible_scope(lease)?;
        if expected_generation.is_some_and(|generation| generation != self.notes.generation)
            || (offset > 0 && expected_generation.is_none())
        {
            return Err(SecureError::StaleGeneration);
        }
        if offset as usize > MAX_NOTES
            || query.len() > MAX_QUERY_BYTES
            || tag.is_some_and(|tag| tag.len() > MAX_TAG_BYTES)
        {
            return Err(SecureError::InvalidInput);
        }
        let tag = tag.map(str::to_lowercase);
        let query = Zeroizing::new(query.to_lowercase());
        let terms: Vec<&str> = query.split_whitespace().collect();
        let mut rows: Vec<&Note> = self
            .notes
            .visible(scope.as_deref())
            .filter(|note| {
                note.archived == archived
                    && tag
                        .as_ref()
                        .is_none_or(|tag| note.tags.iter().any(|name| name.to_lowercase() == *tag))
                    && note.matches(&terms)
            })
            .collect();
        rows.sort_unstable_by(|a, b| {
            b.updated_at
                .cmp(&a.updated_at)
                .then_with(|| a.id.cmp(&b.id))
        });
        let entries = rows
            .iter()
            .skip(offset as usize)
            .take(PAGE_SIZE)
            .map(|note| note.summary())
            .collect();
        let next = offset + PAGE_SIZE as u32;
        Ok(NotesPage {
            generation: self.notes.generation,
            entries,
            next_offset: ((next as usize) < rows.len()).then_some(next),
        })
    }

    pub fn notes_detail(&self, lease: &str, id: &str) -> Result<NoteDetail, SecureError> {
        let scope = self.notes_visible_scope(lease)?;
        let (note, _) = self
            .notes
            .find(scope.as_deref(), id)
            .ok_or(SecureError::NotFound)?;
        Ok(NoteDetail {
            summary: note.summary(),
            body: note.body.clone(),
        })
    }

    pub fn notes_save(
        &mut self,
        lease: &str,
        draft: NotesDraft,
        now: u64,
    ) -> Result<NoteSummary, SecureError> {
        let scope = self.notes_visible_scope(lease)?;
        let current = draft
            .id
            .as_deref()
            .map(|id| {
                self.notes
                    .find(scope.as_deref(), id)
                    .ok_or(SecureError::NotFound)
            })
            .transpose()?;
        if current.map(|(note, _)| note.version.as_str()) != draft.expected_version.as_deref() {
            return Err(SecureError::Conflict);
        }
        if current.is_none() && self.notes.total_notes() >= MAX_NOTES {
            return Err(SecureError::TooLarge);
        }
        let tags = parse_tags(&draft.tags)?;
        let clock = current
            .map(|(note, _)| note.clock.checked_add(1).ok_or(SecureError::Unavailable))
            .transpose()?
            .unwrap_or(1);
        let note = Note {
            id: draft.id.map_or_else(random_note_id, Ok)?,
            title: draft.title.trim().to_owned(),
            body: draft.body,
            icon: draft.icon.filter(|icon| !icon.is_empty()),
            tags,
            created_at: current.map_or(now, |(note, _)| note.created_at),
            updated_at: current.map_or(now, |(note, _)| now.max(note.updated_at)),
            archived: current.is_some_and(|(note, _)| note.archived),
            version: random_note_id()?,
            clock,
        };
        if !note.valid(&note.id) {
            return Err(SecureError::InvalidInput);
        }
        let summary = note.summary();
        let mut next = self.notes.clone();
        let scoped = current.map_or_else(
            || {
                scope
                    .as_ref()
                    .and_then(|scope| self.notes.profiles.get(scope))
                    .is_some_and(sync::Profile::enabled)
            },
            |(_, scoped)| scoped,
        );
        next.insert(scope.as_deref().filter(|_| scoped), note)?;
        self.commit_notes(next)?;
        Ok(summary)
    }

    pub fn notes_archive(
        &mut self,
        lease: &str,
        id: &str,
        archived: bool,
        now: u64,
    ) -> Result<(), SecureError> {
        let scope = self.notes_visible_scope(lease)?;
        let (current, scoped) = self
            .notes
            .find(scope.as_deref(), id)
            .ok_or(SecureError::NotFound)?;
        if current.archived == archived {
            return Ok(());
        }
        let mut note = current.clone();
        note.archived = archived;
        note.updated_at = now.max(note.updated_at);
        note.version = random_note_id()?;
        note.clock = note.clock.checked_add(1).ok_or(SecureError::Unavailable)?;
        let mut next = self.notes.clone();
        next.insert(scope.as_deref().filter(|_| scoped), note)?;
        self.commit_notes(next)
    }

    pub fn notes_delete(&mut self, lease: &str, id: &str) -> Result<(), SecureError> {
        let scope = self.notes_visible_scope(lease)?;
        let mut next = self.notes.clone();
        if next.local.remove(id).is_none() {
            let profile = scope
                .as_deref()
                .and_then(|scope| next.profiles.get_mut(scope))
                .ok_or(SecureError::NotFound)?;
            profile.ensure_editable()?;
            let note = profile.data.notes.remove(id).ok_or(SecureError::NotFound)?;
            profile.data.deleted.insert(note.id.clone());
            profile.deleted(id);
        }
        self.commit_notes(next)
    }

    pub fn notes_tags(&self, lease: &str, archived: bool) -> Result<Vec<NoteTag>, SecureError> {
        let scope = self.notes_visible_scope(lease)?;
        let mut counts = BTreeMap::<String, NoteTag>::new();
        for note in self
            .notes
            .visible(scope.as_deref())
            .filter(|note| note.archived == archived)
        {
            for tag in &note.tags {
                let count = counts.entry(tag.to_lowercase()).or_insert_with(|| NoteTag {
                    name: tag.clone(),
                    count: 0,
                });
                count.count += 1;
            }
        }
        let mut tags: Vec<_> = counts.into_values().collect();
        tags.sort_unstable_by(|a, b| b.count.cmp(&a.count).then_with(|| a.name.cmp(&b.name)));
        tags.truncate(20);
        Ok(tags)
    }

    fn notes_visible_scope(&self, lease: &str) -> Result<Option<String>, SecureError> {
        self.protection_require(ProtectionScope::Notes, lease)?;
        Ok(self.notes_identity().map(|(scope, _)| scope))
    }

    fn commit_notes(&mut self, mut next: NotesState) -> Result<(), SecureError> {
        next.generation = self
            .notes
            .generation
            .checked_add(1)
            .ok_or(SecureError::Unavailable)?;
        let data = Zeroizing::new(serde_json::to_vec(&next).map_err(|_| SecureError::Unavailable)?);
        if data.len() > NOTES_IMAGE_LIMIT || !next.valid() {
            return Err(SecureError::TooLarge);
        }
        self.commit_private(PrivateRecord::Notes, Some(&data))
            .map_err(storage_error)?;
        self.notes = next;
        Ok(())
    }
}

impl Note {
    fn same_content(&self, other: &Self) -> bool {
        self.title == other.title
            && self.body == other.body
            && self.icon == other.icon
            && self.tags == other.tags
            && self.archived == other.archived
    }

    fn valid(&self, id: &str) -> bool {
        id == self.id
            && fixed_id(id, 16)
            && fixed_id(&self.version, 16)
            && self.clock != 0
            && self.created_at <= self.updated_at
            && self.title.len() <= MAX_TITLE_BYTES
            && self.title == self.title.trim()
            && self.title.chars().all(|c| !c.is_control())
            && self.body.len() <= MAX_NOTE_BYTES
            && self
                .body
                .chars()
                .all(|c| !c.is_control() || matches!(c, '\n' | '\r' | '\t'))
            && (!self.title.is_empty() || !self.body.trim().is_empty())
            && self.icon.as_ref().is_none_or(|icon| valid_icon(icon))
            && self.tags.len() <= MAX_TAGS
            && self.tags.iter().all(|tag| valid_tag(tag))
            && self
                .tags
                .iter()
                .map(|tag| tag.to_lowercase())
                .collect::<BTreeSet<_>>()
                .len()
                == self.tags.len()
    }

    fn summary(&self) -> NoteSummary {
        let preview: String = self
            .body
            .split_whitespace()
            .flat_map(|word| word.chars().chain(std::iter::once(' ')))
            .take(140)
            .collect();
        NoteSummary {
            id: self.id.clone(),
            title: self.title.clone(),
            preview: preview.trim_end().into(),
            icon: self.icon.clone(),
            tags: self.tags.clone(),
            created_at: self.created_at,
            updated_at: self.updated_at,
            archived: self.archived,
            version: self.version.clone(),
        }
    }

    fn matches(&self, terms: &[&str]) -> bool {
        if terms.is_empty() {
            return true;
        }
        let content = Zeroizing::new(
            [
                self.title.as_str(),
                self.body.as_str(),
                &self.tags.join(" "),
            ]
            .join(" ")
            .to_lowercase(),
        );
        terms
            .iter()
            .all(|term| content.contains(term) || fuzzy_word(&content, term))
    }
}

fn fuzzy_word(content: &str, term: &str) -> bool {
    let needle: Vec<_> = term.chars().collect();
    (4..=32).contains(&needle.len())
        && needle.iter().all(|c| c.is_alphanumeric())
        && content.split(|c: char| !c.is_alphanumeric()).any(|word| {
            // Reject long words before allocating Unicode scalars for typo matching.
            if word.len() > 4 * (needle.len() + 1) {
                return false;
            }
            let word: Vec<_> = word.chars().collect();
            one_edit(&needle, &word)
        })
}

fn one_edit(first: &[char], second: &[char]) -> bool {
    let (short, long) = if first.len() <= second.len() {
        (first, second)
    } else {
        (second, first)
    };
    if long.len() - short.len() > 1 {
        return false;
    }
    let index = short
        .iter()
        .zip(long)
        .position(|(a, b)| a != b)
        .unwrap_or(short.len());
    if long.len() > short.len() {
        return short[index..] == long[index + 1..];
    }
    if index == short.len() || short[index + 1..] == long[index + 1..] {
        return true;
    }
    index + 1 < short.len()
        && short[index] == long[index + 1]
        && short[index + 1] == long[index]
        && short[index + 2..] == long[index + 2..]
}

fn parse_tags(input: &str) -> Result<Vec<String>, SecureError> {
    if input.len() > MAX_TAG_INPUT_BYTES {
        return Err(SecureError::TooLarge);
    }
    let mut canonical = BTreeSet::new();
    let mut tags = Vec::new();
    for tag in input
        .split([',', '|', '/'])
        .map(str::trim)
        .filter(|tag| !tag.is_empty())
    {
        if !valid_tag(tag) {
            return Err(SecureError::InvalidInput);
        }
        if canonical.insert(tag.to_lowercase()) {
            tags.push(tag.into());
        }
        if tags.len() > MAX_TAGS {
            return Err(SecureError::TooLarge);
        }
    }
    Ok(tags)
}

fn valid_tag(tag: &str) -> bool {
    !tag.is_empty()
        && tag.len() <= MAX_TAG_BYTES
        && tag == tag.trim()
        && !tag
            .chars()
            .any(|c| c.is_control() || matches!(c, ',' | '|' | '/'))
}

fn valid_icon(icon: &str) -> bool {
    if icon.len() > MAX_ICON_BYTES {
        return false;
    }
    let mut chars = icon.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if matches!(first, '#' | '*' | '0'..='9') {
        return matches!(chars.as_str(), "\u{20e3}" | "\u{fe0f}\u{20e3}");
    }
    emoji_scalar(first)
        && chars.all(|c| {
            emoji_scalar(c)
                || matches!(
                    c,
                    '\u{200d}' | '\u{fe0e}' | '\u{fe0f}' | '\u{e0020}'..='\u{e007f}'
                )
        })
}

fn emoji_scalar(c: char) -> bool {
    matches!(c,
        '\u{00a9}' | '\u{00ae}' | '\u{203c}' | '\u{2049}' | '\u{2122}' | '\u{2139}'
        | '\u{2194}'..='\u{21ff}' | '\u{2300}'..='\u{23ff}' | '\u{24c2}' | '\u{25a0}'..='\u{27bf}'
        | '\u{2934}' | '\u{2935}' | '\u{2b00}'..='\u{2bff}' | '\u{3030}' | '\u{303d}'
        | '\u{3297}' | '\u{3299}' | '\u{1f000}'..='\u{1faff}'
    )
}

fn random_note_id() -> Result<String, SecureError> {
    random_id::<16>().map_err(|_| SecureError::Unavailable)
}

fn fixed_id(value: &str, size: usize) -> bool {
    value.len() == (size * 8).div_ceil(6)
        && URL_SAFE_NO_PAD
            .decode(value)
            .is_ok_and(|bytes| bytes.len() == size)
}
