use super::{
    HubAction, HubError, HubMailAttachment, HubMailMessage, HubMailPage, HubMailSummary, token,
};
use serde::Deserialize;
use std::collections::BTreeSet;

const PATH: &str = "/v1/mail/messages";
const BODY_BYTES: u32 = 2 * 1024 * 1024;
const PREVIEW_BYTES: usize = 16 * 1024;
const PAGE_ROWS: usize = 20;
const ATTACHMENTS: usize = 100;

#[derive(Clone, Copy)]
pub(super) enum Folder {
    Inbox,
    Trash,
}

impl Folder {
    fn name(self) -> &'static str {
        match self {
            Self::Inbox => "inbox",
            Self::Trash => "trash",
        }
    }
}

pub(super) enum Operation {
    Page {
        folder: Folder,
        cursor: Option<String>,
    },
    Message {
        id: String,
    },
    Content {
        id: String,
    },
    Attachment {
        id: String,
        attachment: String,
        size: u32,
    },
}

impl Operation {
    pub(super) fn path(&self) -> String {
        match self {
            Self::Page { folder, cursor } => {
                let mut path = format!("{PATH}?folder={}", folder.name());
                if let Some(cursor) = cursor {
                    path.push_str("&cursor=");
                    path.push_str(cursor);
                }
                path
            }
            Self::Message { id } => format!("{PATH}/{id}"),
            Self::Content { id } => format!("{PATH}/{id}/content"),
            Self::Attachment { id, attachment, .. } => {
                format!("{PATH}/{id}/attachments/{attachment}")
            }
        }
    }

    pub(super) fn limit(&self) -> u32 {
        match self {
            Self::Page { .. } => 320 * 1024,
            Self::Message { .. } => 1024 * 1024,
            Self::Content { .. } => BODY_BYTES,
            // A typed JSON error can be slightly larger than a small or empty attachment.
            Self::Attachment { size, .. } => (*size).max(16 * 1024),
        }
    }
}

#[derive(Default)]
pub(super) struct State {
    inbox_cursor: Option<String>,
    trash_cursor: Option<String>,
    detail: Option<DetailFileIndex>,
}

struct DetailFileIndex {
    id: String,
    attachments: Vec<(String, u32)>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Page {
    messages: Vec<HubMailSummary>,
    cursor: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Message {
    message: MessageFields,
}

#[derive(Deserialize)]
struct MessageFields {
    #[serde(flatten)]
    summary: HubMailSummary,
    text: String,
    truncated: bool,
    attachments: Vec<HubMailAttachment>,
}

impl State {
    pub(super) fn operation(
        &self,
        action: HubAction,
        input: Option<&str>,
    ) -> Result<Operation, HubError> {
        match action {
            HubAction::MailInbox | HubAction::MailTrash => {
                let (folder, cursor) = if action == HubAction::MailInbox {
                    (Folder::Inbox, &self.inbox_cursor)
                } else {
                    (Folder::Trash, &self.trash_cursor)
                };
                if input.is_some() && input != cursor.as_deref() {
                    return Err(HubError::InvalidInput);
                }
                Ok(Operation::Page {
                    folder,
                    cursor: input.map(str::to_owned),
                })
            }
            HubAction::MailMessage => {
                let id = input
                    .filter(|id| message_id(id))
                    .ok_or(HubError::InvalidInput)?;
                Ok(Operation::Message { id: id.into() })
            }
            HubAction::MailContent => {
                let detail = self.detail(input)?;
                Ok(Operation::Content {
                    id: detail.id.clone(),
                })
            }
            HubAction::MailAttachment => {
                let (id, attachment) = input
                    .and_then(|value| value.split_once(':'))
                    .ok_or(HubError::InvalidInput)?;
                let detail = self.detail(Some(id))?;
                let (attachment, size) = detail
                    .attachments
                    .iter()
                    .find(|(valid, _)| valid == attachment)
                    .ok_or(HubError::InvalidInput)?;
                Ok(Operation::Attachment {
                    id: detail.id.clone(),
                    attachment: attachment.clone(),
                    size: *size,
                })
            }
            _ => Err(HubError::InvalidInput),
        }
    }

    fn detail(&self, input: Option<&str>) -> Result<&DetailFileIndex, HubError> {
        self.detail
            .as_ref()
            .filter(|detail| input == Some(detail.id.as_str()))
            .ok_or(HubError::InvalidInput)
    }

    pub(super) fn finish_page(
        &mut self,
        folder: Folder,
        mut page: Page,
    ) -> Result<HubMailPage, HubError> {
        if page.messages.len() > PAGE_ROWS
            || page.cursor.as_ref().is_some_and(|value| !token(value))
        {
            return Err(HubError::InvalidResponse);
        }
        let mut ids = BTreeSet::new();
        for row in &mut page.messages {
            validate_summary(row)?;
            if row.folder != folder.name() || !ids.insert(&row.id) {
                return Err(HubError::InvalidResponse);
            }
        }
        let cursor = match folder {
            Folder::Inbox => &mut self.inbox_cursor,
            Folder::Trash => &mut self.trash_cursor,
        };
        *cursor = page.cursor.clone();
        self.detail = None;
        Ok(HubMailPage {
            folder: folder.name().into(),
            messages: page.messages,
            cursor: page.cursor,
        })
    }

    pub(super) fn finish_message(
        &mut self,
        id: String,
        message: Message,
    ) -> Result<HubMailMessage, HubError> {
        let MessageFields {
            mut summary,
            text,
            truncated,
            mut attachments,
        } = message.message;
        validate_summary(&mut summary)?;
        if summary.id != id || attachments.len() != summary.attachment_count as usize {
            return Err(HubError::InvalidResponse);
        }
        let mut ids = BTreeSet::new();
        let mut files = Vec::with_capacity(attachments.len());
        for item in &mut attachments {
            if !attachment_id(&item.id) || item.size > BODY_BYTES || !ids.insert(item.id.clone()) {
                return Err(HubError::InvalidResponse);
            }
            item.filename = clean_text(&item.filename.replace(['/', '\\', ':'], "_"), 192, false);
            if item.filename.is_empty() || item.filename == "." || item.filename == ".." {
                item.filename = "attachment".into();
            }
            if item.mime.is_empty()
                || item.mime.len() > 120
                || !item.mime.bytes().all(|byte| byte.is_ascii_graphic())
            {
                item.mime = "application/octet-stream".into();
            }
            files.push((item.id.clone(), item.size));
        }
        let preview = clean_text(&text, PREVIEW_BYTES, true);
        let truncated = truncated || preview.len() < clean_text_length(&text);
        self.detail = Some(DetailFileIndex {
            id,
            attachments: files,
        });
        Ok(HubMailMessage {
            summary,
            text: preview,
            truncated,
            attachments,
        })
    }
}

fn message_id(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn attachment_id(value: &str) -> bool {
    value.len() <= 3 && value.parse::<u32>().is_ok_and(|id| id.to_string() == value)
}

fn validate_summary(row: &mut HubMailSummary) -> Result<(), HubError> {
    if !message_id(&row.id)
        || !matches!(row.folder.as_str(), "inbox" | "trash")
        || row.attachment_count as usize > ATTACHMENTS
        || row.size > BODY_BYTES
        || row.received_at.len() != 24
        || !row
            .received_at
            .bytes()
            .all(|byte| byte.is_ascii_digit() || b"-:.TZ".contains(&byte))
    {
        return Err(HubError::InvalidResponse);
    }
    row.from = clean_text(&row.from, 256, false);
    row.to = clean_text(&row.to, 256, false);
    row.subject = clean_text(&row.subject, 512, false);
    Ok(())
}

fn visible(character: char, multiline: bool) -> bool {
    if multiline && matches!(character, '\n' | '\t') {
        return true;
    }
    !character.is_control()
        && !matches!(character, '\u{061c}' | '\u{200e}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
}

fn clean_text(value: &str, limit: usize, multiline: bool) -> String {
    let mut output = String::with_capacity(value.len().min(limit));
    for character in value
        .chars()
        .filter(|character| visible(*character, multiline))
    {
        if output.len() + character.len_utf8() > limit {
            break;
        }
        output.push(character);
    }
    output
}

fn clean_text_length(value: &str) -> usize {
    value
        .chars()
        .filter(|character| visible(*character, true))
        .map(char::len_utf8)
        .sum()
}
