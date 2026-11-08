// Copyright (C) 2026 Shirofune Security Co., Ltd.
//
// Unless explicitly acquired and licensed from Licensor under another license, the contents of this
// file are subject to the Reciprocal Public License ("RPL") Version 1.5, or subsequent versions as
// allowed by the RPL, and You may not copy or use this file in either source code or executable
// form, except in compliance with the terms and conditions of the RPL.
//
// All software distributed under the RPL is provided strictly on an "AS IS" basis, WITHOUT WARRANTY
// OF ANY KIND, EITHER EXPRESS OR IMPLIED, AND LICENSOR HEREBY DISCLAIMS ALL SUCH WARRANTIES,
// INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
// PURPOSE, QUIET ENJOYMENT, OR NON-INFRINGEMENT. See the RPL for specific language governing rights
// and limitations under the RPL.

//! An Outlook item, whichever file it is in: a message of a PST or OST, or a `.msg` or `.oft`
//! file. Its well-known fields are read from its properties; every property is kept as stored.

use crate::mapi::{NameId, Property, Value, lids, sets, tags};

/// What kind of item a message class says it is ([MS-OXCMSG] 2.2.1.3 and the classes of
/// [MS-OXOCAL], [MS-OXOCNTC], [MS-OXOTASK], [MS-OXONOTE], [MS-OXOJRNL], [MS-OXOPOST]). Message
/// classes are compared without case, by their prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ItemKind {
    /// `IPM.Note…`: an e-mail message (S/MIME and other kinds of note too).
    Mail,
    /// `IPM.Schedule.Meeting…`: a meeting request, response or cancellation.
    MeetingMessage,
    /// `IPM.Appointment…`: a calendar item.
    Appointment,
    /// `IPM.Contact…`.
    Contact,
    /// `IPM.DistList…`: a personal distribution list.
    DistributionList,
    /// `IPM.Task…`.
    Task,
    /// `IPM.TaskRequest…`: a task request, acceptance or decline.
    TaskRequest,
    /// `IPM.StickyNote…`: a note.
    StickyNote,
    /// `IPM.Activity…`: a journal entry.
    Journal,
    /// `IPM.Post…`: a post in a folder.
    Post,
    /// `REPORT.…`: a delivery, non-delivery or read report.
    Report,
    /// `IPM.Configuration.…`: settings Outlook keeps as hidden items (autocomplete, categories,
    /// work hours, …).
    Configuration,
    /// Any other class, or none.
    Other,
}

impl ItemKind {
    /// The kind a message class names.
    pub fn of_class(class: Option<&str>) -> ItemKind {
        let Some(class) = class else {
            return ItemKind::Other;
        };
        let class = class.to_ascii_lowercase();
        let starts = |prefix: &str| class == prefix || class.starts_with(&format!("{prefix}."));
        if class.starts_with("report.") {
            ItemKind::Report
        } else if starts("ipm.schedule.meeting") {
            ItemKind::MeetingMessage
        } else if starts("ipm.appointment") {
            ItemKind::Appointment
        } else if starts("ipm.contact") {
            ItemKind::Contact
        } else if starts("ipm.distlist") {
            ItemKind::DistributionList
        } else if starts("ipm.taskrequest") {
            ItemKind::TaskRequest
        } else if starts("ipm.task") {
            ItemKind::Task
        } else if starts("ipm.stickynote") {
            ItemKind::StickyNote
        } else if starts("ipm.activity") {
            ItemKind::Journal
        } else if starts("ipm.post") {
            ItemKind::Post
        } else if starts("ipm.configuration") {
            ItemKind::Configuration
        } else if starts("ipm.note") || class == "ipm" {
            ItemKind::Mail
        } else {
            ItemKind::Other
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            ItemKind::Mail => "Mail",
            ItemKind::MeetingMessage => "MeetingMessage",
            ItemKind::Appointment => "Appointment",
            ItemKind::Contact => "Contact",
            ItemKind::DistributionList => "DistributionList",
            ItemKind::Task => "Task",
            ItemKind::TaskRequest => "TaskRequest",
            ItemKind::StickyNote => "StickyNote",
            ItemKind::Journal => "Journal",
            ItemKind::Post => "Post",
            ItemKind::Report => "Report",
            ItemKind::Configuration => "Configuration",
            ItemKind::Other => "Other",
        }
    }
}

/// Who sent or was represented: the name, the address type (`SMTP`, `EX`, …), the address of
/// that type, and the SMTP address where one is stored besides.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Party {
    pub name: Option<String>,
    pub address_type: Option<String>,
    pub address: Option<String>,
    pub smtp: Option<String>,
}

impl Party {
    pub fn is_empty(&self) -> bool {
        self.name.is_none()
            && self.address_type.is_none()
            && self.address.is_none()
            && self.smtp.is_none()
    }
}

/// A recipient's role ([MS-OXCMSG] 2.2.3.1, `PidTagRecipientType`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecipientKind {
    Originator,
    To,
    Cc,
    Bcc,
    /// Another value, as stored (with the resend and processed flags of the high bits).
    Other(i32),
}

impl RecipientKind {
    pub fn of(value: Option<i64>) -> Option<RecipientKind> {
        let value = value?;
        // the high bits flag resent and processed recipients
        Some(match value & 0x0FFF_FFFF {
            0 => RecipientKind::Originator,
            1 => RecipientKind::To,
            2 => RecipientKind::Cc,
            3 => RecipientKind::Bcc,
            _ => RecipientKind::Other(value as i32),
        })
    }

    pub fn name(self) -> String {
        match self {
            RecipientKind::Originator => "Originator".into(),
            RecipientKind::To => "To".into(),
            RecipientKind::Cc => "Cc".into(),
            RecipientKind::Bcc => "Bcc".into(),
            RecipientKind::Other(value) => format!("0x{value:08X}"),
        }
    }
}

/// A row of a message's recipient table.
#[derive(Debug, Clone, PartialEq)]
pub struct Recipient {
    /// Its row in the table, from 0.
    pub index: usize,
    pub kind: Option<RecipientKind>,
    pub party: Party,
    pub properties: Vec<Property>,
}

/// An attachment and, for an attached message, the message.
#[derive(Debug, Clone, PartialEq)]
pub struct Attachment {
    /// Its row in the message's attachment table, from 0.
    pub index: usize,
    /// `PidTagAttachMethod`: 1 by value, 2 to 4 by reference, 5 an embedded message, 6 an OLE
    /// object ([MS-OXCMSG] 2.2.2.9).
    pub method: Option<i32>,
    pub filename: Option<String>,
    pub long_filename: Option<String>,
    pub display_name: Option<String>,
    pub extension: Option<String>,
    pub mime_type: Option<String>,
    pub content_id: Option<String>,
    pub content_location: Option<String>,
    /// A path of an attachment by reference.
    pub pathname: Option<String>,
    /// `PidTagAttachSize`: the attachment's size as the store gives it, with its properties.
    pub size: Option<i64>,
    pub flags: Option<i32>,
    pub hidden: Option<bool>,
    pub rendering_position: Option<i32>,
    /// The attached file's bytes (`PidTagAttachDataBinary`), or for an OLE object in a PST or OST
    /// the compound file that holds it; none for an embedded message, an attachment by reference,
    /// or an OLE object in a `.msg` file (whose storage `outlook_msg` gives).
    pub data: Option<Vec<u8>>,
    /// An embedded message (`PidTagAttachDataObject` of method 5).
    pub embedded: Option<Box<Item>>,
    pub properties: Vec<Property>,
    pub problems: Vec<String>,
}

impl Attachment {
    /// The best name to show: the long filename, the short one, or the display name.
    pub fn name(&self) -> Option<&str> {
        self.long_filename
            .as_deref()
            .or(self.filename.as_deref())
            .or(self.display_name.as_deref())
    }

    pub fn is_inline(&self) -> bool {
        // ATT_MHTML_REF (4): referenced from the HTML body
        self.flags.is_some_and(|flags| flags & 0x4 != 0) || self.content_id.is_some()
    }
}

/// The body in its stored forms.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Body {
    /// `PidTagBody`: plain text.
    pub text: Option<String>,
    /// `PidTagHtml`: binary and String8 values keep their bytes (in the message's Internet
    /// code page); Unicode values are represented as UTF-8. The original property's type
    /// and value remain in [`Item::properties`].
    pub html: Option<Vec<u8>>,
    /// `PidTagRtfCompressed`: the compressed RTF as stored.
    pub rtf_compressed: Option<Vec<u8>>,
    /// The RTF it decompresses to, when it does, including zero bytes and any padding.
    pub rtf: Option<Vec<u8>>,
}

/// A contact's own fields ([MS-OXOCNTC]).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Contact {
    pub display_name: Option<String>,
    pub given_name: Option<String>,
    pub surname: Option<String>,
    pub nickname: Option<String>,
    pub file_under: Option<String>,
    pub company: Option<String>,
    pub title: Option<String>,
    pub department: Option<String>,
    /// E-mail 1 to 3: display name, address type and address.
    pub emails: Vec<Party>,
    pub business_phone: Option<String>,
    pub home_phone: Option<String>,
    pub mobile_phone: Option<String>,
    pub instant_messaging: Option<String>,
}

/// A calendar item's own fields ([MS-OXOCAL]). Times are FILETIMEs in UTC.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Appointment {
    pub start: Option<i64>,
    pub end: Option<i64>,
    pub duration_minutes: Option<i64>,
    pub location: Option<String>,
    /// `PidLidAppointmentSubType`: an all-day event.
    pub all_day: Option<bool>,
    /// `PidLidBusyStatus`: 0 free, 1 tentative, 2 busy, 3 out of office, 4 working elsewhere.
    pub busy_status: Option<i64>,
    pub recurring: Option<bool>,
    /// `PidLidResponseStatus`: 0 none, 1 organized, 2 tentative, 3 accepted, 4 declined, 5 not
    /// responded.
    pub response_status: Option<i64>,
    pub all_attendees: Option<String>,
    pub to_attendees: Option<String>,
    pub cc_attendees: Option<String>,
    /// `PidLidGlobalObjectId`: the meeting's identity across mailboxes.
    pub global_object_id: Option<Vec<u8>>,
}

/// A task's own fields ([MS-OXOTASK]). The start and due dates are dates in the user's time zone
/// (midnight, kept as stored); the completion date is the time it was marked complete.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Task {
    /// `PidLidTaskStatus`: 0 not started, 1 in progress, 2 complete, 3 waiting, 4 deferred.
    pub status: Option<i64>,
    pub percent_complete: Option<f64>,
    pub start: Option<i64>,
    pub due: Option<i64>,
    pub completed: Option<i64>,
    pub complete: Option<bool>,
    pub owner: Option<String>,
    pub assigner: Option<String>,
}

/// A reminder of any item ([MS-OXORMDR]).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Reminder {
    pub set: Option<bool>,
    pub time: Option<i64>,
    pub signal_time: Option<i64>,
}

/// An item: its well-known fields, its recipients and attachments, and every property as stored.
#[derive(Debug, Clone, PartialEq)]
pub struct Item {
    pub kind: ItemKind,
    pub class: Option<String>,
    pub subject: Option<String>,
    pub conversation_topic: Option<String>,
    pub conversation_index: Option<Vec<u8>>,
    pub sender: Party,
    pub sent_representing: Party,
    pub display_to: Option<String>,
    pub display_cc: Option<String>,
    pub display_bcc: Option<String>,
    pub message_id: Option<String>,
    pub in_reply_to: Option<String>,
    pub references: Option<String>,
    pub transport_headers: Option<String>,
    /// `PidTagClientSubmitTime`: when the sender's client submitted it (UTC FILETIME).
    pub submitted: Option<i64>,
    /// `PidTagMessageDeliveryTime`: when it was delivered to this mailbox.
    pub delivered: Option<i64>,
    /// `PidTagCreationTime`: when this copy was created in its store or file.
    pub created: Option<i64>,
    /// `PidTagLastModificationTime`.
    pub modified: Option<i64>,
    pub flags: Option<i32>,
    pub importance: Option<i32>,
    pub sensitivity: Option<i32>,
    pub priority: Option<i32>,
    pub size: Option<i64>,
    /// `PidTagInternetCodepage`, else `PidTagMessageCodepage`.
    pub codepage: Option<i32>,
    /// The categories (`Keywords` of `PS_PUBLIC_STRINGS`).
    pub categories: Vec<String>,
    pub body: Body,
    pub reminder: Reminder,
    pub contact: Option<Contact>,
    pub appointment: Option<Appointment>,
    pub task: Option<Task>,
    pub recipients: Vec<Recipient>,
    pub attachments: Vec<Attachment>,
    pub properties: Vec<Property>,
    /// What could not be read, without stopping the rest.
    pub problems: Vec<String>,
}

/// An attachment as a reader gives it, before its fields are read.
#[derive(Debug, Clone, Default)]
pub struct AttachmentParts {
    pub properties: Vec<Property>,
    pub data: Option<Vec<u8>>,
    pub embedded: Option<Box<Item>>,
    pub problems: Vec<String>,
}

/// The properties of one object, looked up by id or name.
pub struct Props<'a>(pub &'a [Property]);

impl<'a> Props<'a> {
    pub fn get(&self, id: u16) -> Option<&'a Value> {
        self.0
            .iter()
            .find(|p| p.id == id && p.name.is_none())
            .map(|p| &p.value)
    }

    pub fn named(&self, (set, lid): lids::Lid) -> Option<&'a Value> {
        self.0
            .iter()
            .find(|p| {
                p.name
                    .as_ref()
                    .is_some_and(|n| n.set == set && n.id == NameId::Number(lid))
            })
            .map(|p| &p.value)
    }

    pub fn named_text(&self, set: [u8; 16], name: &str) -> Option<&'a Value> {
        self.0
            .iter()
            .find(|p| {
                p.name.as_ref().is_some_and(|n| {
                    n.set == set && matches!(&n.id, NameId::Text(t) if t.eq_ignore_ascii_case(name))
                })
            })
            .map(|p| &p.value)
    }

    pub fn text(&self, id: u16) -> Option<String> {
        self.get(id).and_then(Value::as_str).map(str::to_owned)
    }

    fn named_string(&self, lid: lids::Lid) -> Option<String> {
        self.named(lid).and_then(Value::as_str).map(str::to_owned)
    }

    pub fn int(&self, id: u16) -> Option<i64> {
        self.get(id).and_then(Value::as_i64)
    }

    fn int32(&self, id: u16) -> Option<i32> {
        self.int(id).and_then(|v| i32::try_from(v).ok())
    }

    pub fn time(&self, id: u16) -> Option<i64> {
        self.get(id).and_then(Value::as_filetime)
    }

    pub fn bytes(&self, id: u16) -> Option<Vec<u8>> {
        self.get(id).and_then(Value::as_bytes).map(<[u8]>::to_vec)
    }
}

impl Item {
    /// An item from what a reader gives: the message's properties, its recipients' and its
    /// attachments'. A compressed RTF body is decompressed, as far as it goes.
    pub fn build(
        properties: Vec<Property>,
        recipients: Vec<Vec<Property>>,
        attachments: Vec<AttachmentParts>,
        mut problems: Vec<String>,
    ) -> Item {
        let p = Props(&properties);
        let class = p.text(tags::MESSAGE_CLASS);
        let kind = ItemKind::of_class(class.as_deref());
        let rtf_compressed = p.bytes(tags::RTF_COMPRESSED);
        let rtf = rtf_compressed.as_deref().and_then(|data| {
            let rtf = outlook_msg::decompress_rtf(data);
            problems.extend(
                rtf.flags
                    .iter()
                    .map(|flag| format!("compressed RTF body: {flag}")),
            );
            rtf.rtf
        });
        let html = match p.get(tags::HTML).and_then(Value::best_effort) {
            Some(Value::String(text)) => Some(text.as_bytes().to_vec()),
            Some(value) => value.as_bytes().map(<[u8]>::to_vec),
            None => None,
        };
        let categories = p
            .named_text(sets::PUBLIC_STRINGS, "Keywords")
            .map(|value| match value {
                Value::Multiple(values) => values
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect(),
                other => other.as_str().map(str::to_owned).into_iter().collect(),
            })
            .unwrap_or_default();
        let contact =
            matches!(kind, ItemKind::Contact | ItemKind::DistributionList).then(|| contact(&p));
        let appointment = matches!(kind, ItemKind::Appointment | ItemKind::MeetingMessage)
            .then(|| appointment(&p));
        let task = matches!(kind, ItemKind::Task | ItemKind::TaskRequest).then(|| task(&p));
        let reminder = Reminder {
            set: p.named(lids::REMINDER_SET).and_then(Value::as_bool),
            time: p.named(lids::REMINDER_TIME).and_then(Value::as_filetime),
            signal_time: p
                .named(lids::REMINDER_SIGNAL_TIME)
                .and_then(Value::as_filetime),
        };
        let item = Item {
            kind,
            subject: p.text(tags::SUBJECT).map(subject),
            conversation_topic: p.text(tags::CONVERSATION_TOPIC),
            conversation_index: p.bytes(tags::CONVERSATION_INDEX),
            sender: Party {
                name: p.text(tags::SENDER_NAME),
                address_type: p.text(tags::SENDER_ADDRESS_TYPE),
                address: p.text(tags::SENDER_EMAIL_ADDRESS),
                smtp: p.text(tags::SENDER_SMTP_ADDRESS),
            },
            sent_representing: Party {
                name: p.text(tags::SENT_REPRESENTING_NAME),
                address_type: p.text(tags::SENT_REPRESENTING_ADDRESS_TYPE),
                address: p.text(tags::SENT_REPRESENTING_EMAIL_ADDRESS),
                smtp: p.text(tags::SENT_REPRESENTING_SMTP_ADDRESS),
            },
            display_to: p.text(tags::DISPLAY_TO),
            display_cc: p.text(tags::DISPLAY_CC),
            display_bcc: p.text(tags::DISPLAY_BCC),
            message_id: p.text(tags::INTERNET_MESSAGE_ID),
            in_reply_to: p.text(tags::IN_REPLY_TO_ID),
            references: p.text(tags::INTERNET_REFERENCES),
            transport_headers: p.text(tags::TRANSPORT_MESSAGE_HEADERS),
            submitted: p.time(tags::CLIENT_SUBMIT_TIME),
            delivered: p.time(tags::MESSAGE_DELIVERY_TIME),
            created: p.time(tags::CREATION_TIME),
            modified: p.time(tags::LAST_MODIFICATION_TIME),
            flags: p.int32(tags::MESSAGE_FLAGS),
            importance: p.int32(tags::IMPORTANCE),
            sensitivity: p.int32(tags::SENSITIVITY),
            priority: p.int32(tags::PRIORITY),
            size: p.int(tags::MESSAGE_SIZE),
            codepage: p
                .int32(tags::INTERNET_CODEPAGE)
                .or_else(|| p.int32(tags::MESSAGE_CODEPAGE)),
            categories,
            body: Body {
                text: p.text(tags::BODY),
                html,
                rtf_compressed,
                rtf,
            },
            reminder,
            contact,
            appointment,
            task,
            recipients: recipients
                .into_iter()
                .enumerate()
                .map(|(index, properties)| recipient(index, properties))
                .collect(),
            attachments: attachments
                .into_iter()
                .enumerate()
                .map(|(index, parts)| attachment(index, parts))
                .collect(),
            class,
            properties: Vec::new(),
            problems,
        };
        Item { properties, ..item }
    }
}

/// A subject without the marker PST and OST stores may put before it: U+0001 and a character that
/// gives the length of the subject's prefix ("RE: "), which is not part of the subject. The
/// property keeps it.
fn subject(text: String) -> String {
    let mut chars = text.chars();
    match (chars.next(), chars.next()) {
        (Some('\u{1}'), Some(_)) => chars.as_str().to_owned(),
        _ => text,
    }
}

fn recipient(index: usize, properties: Vec<Property>) -> Recipient {
    let p = Props(&properties);
    Recipient {
        index,
        kind: RecipientKind::of(p.int(tags::RECIPIENT_TYPE)),
        party: Party {
            name: p
                .text(tags::DISPLAY_NAME)
                .or_else(|| p.text(tags::RECIPIENT_DISPLAY_NAME)),
            address_type: p.text(tags::ADDRESS_TYPE),
            address: p.text(tags::EMAIL_ADDRESS),
            smtp: p.text(tags::SMTP_ADDRESS),
        },
        properties,
    }
}

fn attachment(index: usize, parts: AttachmentParts) -> Attachment {
    let p = Props(&parts.properties);
    let data = parts.data.or_else(|| match p.get(tags::ATTACH_DATA) {
        Some(Value::Binary(bytes)) => Some(bytes.clone()),
        _ => None,
    });
    Attachment {
        index,
        method: p.int32(tags::ATTACH_METHOD),
        filename: p.text(tags::ATTACH_FILENAME),
        long_filename: p.text(tags::ATTACH_LONG_FILENAME),
        display_name: p.text(tags::DISPLAY_NAME),
        extension: p.text(tags::ATTACH_EXTENSION),
        mime_type: p.text(tags::ATTACH_MIME_TAG),
        content_id: p.text(tags::ATTACH_CONTENT_ID),
        content_location: p.text(tags::ATTACH_CONTENT_LOCATION),
        pathname: p
            .text(tags::ATTACH_LONG_PATHNAME)
            .or_else(|| p.text(tags::ATTACH_PATHNAME)),
        size: p.int(tags::ATTACH_SIZE),
        flags: p.int32(tags::ATTACH_FLAGS),
        hidden: p.get(tags::ATTACHMENT_HIDDEN).and_then(Value::as_bool),
        rendering_position: p.int32(tags::RENDERING_POSITION),
        data,
        embedded: parts.embedded,
        // the bytes are in `data`, not twice in memory
        properties: parts
            .properties
            .into_iter()
            .map(|property| match property {
                Property {
                    id: tags::ATTACH_DATA,
                    kind,
                    value: Value::Binary(_),
                    name: None,
                } => Property::new(tags::ATTACH_DATA, kind, Value::Object),
                other => other,
            })
            .collect(),
        problems: parts.problems,
    }
}

fn contact(p: &Props<'_>) -> Contact {
    let emails = [
        (
            lids::EMAIL1_DISPLAY_NAME,
            lids::EMAIL1_ADDRESS_TYPE,
            lids::EMAIL1_EMAIL_ADDRESS,
        ),
        (
            lids::EMAIL2_DISPLAY_NAME,
            lids::EMAIL2_ADDRESS_TYPE,
            lids::EMAIL2_EMAIL_ADDRESS,
        ),
        (
            lids::EMAIL3_DISPLAY_NAME,
            lids::EMAIL3_ADDRESS_TYPE,
            lids::EMAIL3_EMAIL_ADDRESS,
        ),
    ]
    .into_iter()
    .map(|(name, kind, address)| Party {
        name: p.named_string(name),
        address_type: p.named_string(kind),
        address: p.named_string(address),
        smtp: None,
    })
    .filter(|party| !party.is_empty())
    .collect();
    Contact {
        display_name: p.text(tags::DISPLAY_NAME),
        given_name: p.text(tags::GIVEN_NAME),
        surname: p.text(tags::SURNAME),
        nickname: p.text(tags::NICKNAME),
        file_under: p.named_string(lids::FILE_UNDER),
        company: p.text(tags::COMPANY_NAME),
        title: p.text(tags::TITLE),
        department: p.text(tags::DEPARTMENT_NAME),
        emails,
        business_phone: p.text(tags::BUSINESS_TELEPHONE_NUMBER),
        home_phone: p.text(tags::HOME_TELEPHONE_NUMBER),
        mobile_phone: p.text(tags::MOBILE_TELEPHONE_NUMBER),
        instant_messaging: p.named_string(lids::INSTANT_MESSAGING_ADDRESS),
    }
}

fn appointment(p: &Props<'_>) -> Appointment {
    Appointment {
        start: p
            .named(lids::APPOINTMENT_START_WHOLE)
            .and_then(Value::as_filetime)
            .or_else(|| p.named(lids::COMMON_START).and_then(Value::as_filetime)),
        end: p
            .named(lids::APPOINTMENT_END_WHOLE)
            .and_then(Value::as_filetime)
            .or_else(|| p.named(lids::COMMON_END).and_then(Value::as_filetime)),
        duration_minutes: p.named(lids::APPOINTMENT_DURATION).and_then(Value::as_i64),
        location: p.named_string(lids::LOCATION),
        all_day: p.named(lids::APPOINTMENT_SUB_TYPE).and_then(Value::as_bool),
        busy_status: p.named(lids::BUSY_STATUS).and_then(Value::as_i64),
        recurring: p.named(lids::RECURRING).and_then(Value::as_bool),
        response_status: p.named(lids::RESPONSE_STATUS).and_then(Value::as_i64),
        all_attendees: p.named_string(lids::ALL_ATTENDEES_STRING),
        to_attendees: p.named_string(lids::TO_ATTENDEES_STRING),
        cc_attendees: p.named_string(lids::CC_ATTENDEES_STRING),
        global_object_id: p
            .named(lids::GLOBAL_OBJECT_ID)
            .and_then(Value::as_bytes)
            .map(<[u8]>::to_vec),
    }
}

fn task(p: &Props<'_>) -> Task {
    Task {
        status: p.named(lids::TASK_STATUS).and_then(Value::as_i64),
        percent_complete: p.named(lids::PERCENT_COMPLETE).and_then(|v| match v {
            Value::Floating64(f) => Some(*f),
            Value::Floating32(f) => Some(f64::from(*f)),
            _ => None,
        }),
        start: p.named(lids::TASK_START_DATE).and_then(Value::as_filetime),
        due: p.named(lids::TASK_DUE_DATE).and_then(Value::as_filetime),
        completed: p
            .named(lids::TASK_DATE_COMPLETED)
            .and_then(Value::as_filetime),
        complete: p.named(lids::TASK_COMPLETE).and_then(Value::as_bool),
        owner: p.named_string(lids::TASK_OWNER),
        assigner: p.named_string(lids::TASK_ASSIGNER),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mapi::{PropertyName, types};

    fn text(id: u16, value: &str) -> Property {
        Property::new(id, types::STRING, Value::String(value.into()))
    }

    fn named(set: [u8; 16], lid: u32, value: Value, kind: u16) -> Property {
        Property {
            id: 0x8000,
            kind,
            value,
            name: Some(PropertyName {
                set,
                id: NameId::Number(lid),
            }),
        }
    }

    #[test]
    fn kinds_of_message_classes() {
        for (class, kind) in [
            ("IPM.Note", ItemKind::Mail),
            ("ipm.note.SMIME", ItemKind::Mail),
            ("IPM", ItemKind::Mail),
            ("IPM.Schedule.Meeting.Request", ItemKind::MeetingMessage),
            ("IPM.Appointment", ItemKind::Appointment),
            ("IPM.Contact", ItemKind::Contact),
            ("IPM.DistList", ItemKind::DistributionList),
            ("IPM.Task", ItemKind::Task),
            ("IPM.TaskRequest.Accept", ItemKind::TaskRequest),
            ("IPM.StickyNote", ItemKind::StickyNote),
            ("IPM.Activity", ItemKind::Journal),
            ("IPM.Post", ItemKind::Post),
            ("REPORT.IPM.Note.NDR", ItemKind::Report),
            ("IPM.Configuration.Autocomplete", ItemKind::Configuration),
            ("IPM.Notebook", ItemKind::Other),
            ("IPM.Tasks", ItemKind::Other),
        ] {
            assert_eq!(ItemKind::of_class(Some(class)), kind, "{class}");
        }
        assert_eq!(ItemKind::of_class(None), ItemKind::Other);
    }

    #[test]
    fn subjects_without_their_prefix_marker() {
        assert_eq!(subject("\u{1}\u{1}Test".into()), "Test");
        assert_eq!(subject("\u{1}\u{5}RE: Test".into()), "RE: Test");
        assert_eq!(subject("Test".into()), "Test");
        assert_eq!(subject("\u{1}".into()), "\u{1}");
    }

    #[test]
    fn recovered_unicode_html_is_kept_in_the_item_body() {
        let html = "<p>Recovered 日本語 body</p>";
        let properties = vec![Property::new(
            tags::HTML,
            types::STRING,
            Value::Damaged {
                recovered: Some(Box::new(Value::String(html.into()))),
                raw: html
                    .encode_utf16()
                    .flat_map(u16::to_le_bytes)
                    .chain([0xFF])
                    .collect(),
                reason: "odd UTF-16 byte length".into(),
            },
        )];
        let item = Item::build(properties, Vec::new(), Vec::new(), Vec::new());
        assert_eq!(item.body.html.as_deref(), Some(html.as_bytes()));
        assert!(matches!(item.properties[0].value, Value::Damaged { .. }));
    }

    #[test]
    fn an_item_from_its_properties() {
        let properties = vec![
            text(tags::MESSAGE_CLASS, "IPM.Task"),
            text(tags::SUBJECT, "Report"),
            text(tags::SENDER_NAME, "Alice"),
            Property::new(tags::CLIENT_SUBMIT_TIME, types::TIME, Value::Time(1)),
            named(sets::TASK, 0x8101, Value::Integer32(2), types::INTEGER32),
            named(
                sets::TASK,
                0x8102,
                Value::Floating64(1.0),
                types::FLOATING64,
            ),
            Property {
                id: 0x8001,
                kind: types::STRING | types::MULTIPLE,
                value: Value::Multiple(vec![Value::String("Red".into())]),
                name: Some(PropertyName {
                    set: sets::PUBLIC_STRINGS,
                    id: NameId::Text("Keywords".into()),
                }),
            },
        ];
        let recipients = vec![vec![
            Property::new(tags::RECIPIENT_TYPE, types::INTEGER32, Value::Integer32(2)),
            text(tags::DISPLAY_NAME, "Bob"),
        ]];
        let attachments = vec![AttachmentParts {
            properties: vec![
                Property::new(tags::ATTACH_METHOD, types::INTEGER32, Value::Integer32(1)),
                text(tags::ATTACH_LONG_FILENAME, "a.txt"),
                Property::new(
                    tags::ATTACH_DATA,
                    types::BINARY,
                    Value::Binary(b"x".to_vec()),
                ),
            ],
            ..AttachmentParts::default()
        }];
        let item = Item::build(properties, recipients, attachments, Vec::new());
        assert_eq!(item.kind, ItemKind::Task);
        assert_eq!(item.subject.as_deref(), Some("Report"));
        assert_eq!(item.sender.name.as_deref(), Some("Alice"));
        assert_eq!(item.submitted, Some(1));
        assert_eq!(item.categories, ["Red"]);
        let task = item.task.unwrap();
        assert_eq!((task.status, task.percent_complete), (Some(2), Some(1.0)));
        assert_eq!(item.recipients[0].kind, Some(RecipientKind::Cc));
        assert_eq!(item.recipients[0].party.name.as_deref(), Some("Bob"));
        let attachment = &item.attachments[0];
        assert_eq!(attachment.name(), Some("a.txt"));
        assert_eq!(attachment.data.as_deref(), Some(&b"x"[..]));
        // the data is kept once
        assert!(
            attachment
                .properties
                .iter()
                .any(|p| p.value == Value::Object)
        );
        assert!(item.problems.is_empty());
    }
}
