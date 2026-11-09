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

//! Messages, recipients and attachments ([MS-OXMSG] 2.1 and 2.2), read from their storages.

use crate::Options;
use crate::guid::Guid;
use crate::named::NamedProperties;
use crate::problem::{Problem, ProblemKind, Problems};
use crate::property::{Properties, Property, PropertyEntry, PropertyType, PropertyValue, Value};
use crate::reader::{Child, Reader, depth_of, is_addressable, join};
use crate::rtf::{self, Rtf};
use crate::tags;
use crate::text::{Text, TextEncoding, ansi_code_page_of_locale, windows_code_page_of_internet};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::{Read, Seek};

pub(crate) const PROPERTIES_STREAM: &str = "__properties_version1.0";
pub(crate) const NAMEID_STORAGE: &str = "__nameid_version1.0";
const RECIPIENT_PREFIX: &str = "__recip_version1.0_#";
const ATTACHMENT_PREFIX: &str = "__attach_version1.0_#";
const SUBSTG_PREFIX: &str = "__substg1.0_";
/// `PidTagAttachDataObject`.
const ATTACH_DATA_OBJECT: u32 = 0x3701_000D;
/// `PidTagAttachDataBinary`.
const ATTACH_DATA_BINARY: u32 = 0x3701_0102;
/// Storages nested deeper than this (counted from the root) are not read.
pub(crate) const MAX_STORAGE_DEPTH: usize = 64;

/// The header of a message's property stream ([MS-OXMSG] 2.4.1.1 and 2.4.1.2).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MessageHeader {
    /// The id the next recipient would get.
    pub next_recipient_id: u32,
    /// The id the next attachment would get.
    pub next_attachment_id: u32,
    /// The number of recipient storages.
    pub recipient_count: u32,
    /// The number of attachment storages.
    pub attachment_count: u32,
}

/// Where a message's code page for `PtypString8` values came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CodePageSource {
    /// `PidTagMessageCodepage`.
    MessageCodepage,
    /// The ANSI code page of `PidTagMessageLocaleId`.
    MessageLocaleId,
    /// The code page of the message this one is embedded in (unless that was the default).
    Parent,
    /// The Windows code page of `PidTagInternetCodepage` (for example 932 for ISO-2022-JP).
    InternetCodepage,
    /// None of the above: [`Options::default_code_page`].
    Default,
}

/// The code page used for a message's `PtypString8` values (and those of its recipients and
/// attachments).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CodePage {
    /// The Windows code page.
    pub code_page: u32,
    /// Where it came from.
    pub source: CodePageSource,
}

/// A message: the file itself, or an embedded message of an attachment.
#[derive(Clone, Debug)]
pub struct Message {
    /// Path of the message's storage in the compound file (`/` for the file itself).
    pub path: String,
    /// Whether this is an embedded message (an attachment's `PidTagAttachDataObject`).
    pub embedded: bool,
    /// The property stream header, if the property stream was there and long enough.
    pub header: Option<MessageHeader>,
    /// The code page for `PtypString8` values.
    pub code_page: CodePage,
    /// All properties of the message.
    pub properties: Properties,
    /// The recipients, by storage index.
    pub recipients: Vec<Recipient>,
    /// The attachments, by storage index.
    pub attachments: Vec<Attachment>,
    /// The HTML body: `PidTagHtml` (binary) decoded in `PidTagInternetCodepage` (or
    /// [`Message::code_page`] without it), or `PidTagBodyHtml` (string).
    pub html: Option<Text>,
    /// The RTF body, decompressed from `PidTagRtfCompressed`.
    pub rtf: Option<Rtf>,
    /// Problems found in this message's storage, its recipients and its attachments (but not
    /// in embedded messages, which have their own).
    pub problems: Vec<Problem>,
}

impl Message {
    /// `PidTagMessageClass`, such as `IPM.Note`, `IPM.Contact`, `IPM.Appointment`,
    /// `IPM.Task`, `IPM.StickyNote` or `IPM.Schedule.Meeting.Request`.
    pub fn message_class(&self) -> Option<&str> {
        self.properties.string(tags::MESSAGE_CLASS)
    }

    /// `PidTagSubject`.
    pub fn subject(&self) -> Option<&str> {
        self.properties.string(tags::SUBJECT)
    }

    /// The plain-text body, `PidTagBody`.
    pub fn body(&self) -> Option<&str> {
        self.properties.string(tags::BODY)
    }

    /// The embedded messages of the attachments, depth first, this message excluded.
    pub fn embedded_messages(&self) -> Vec<&Message> {
        let mut out = Vec::new();
        let mut stack: Vec<&Message> = vec![self];
        while let Some(m) = stack.pop() {
            for a in m.attachments.iter().rev() {
                if let AttachmentContent::Message(inner) = &a.content {
                    stack.push(inner);
                }
            }
            if !std::ptr::eq(m, self) {
                out.push(m);
            }
        }
        out
    }
}

/// A recipient (`__recip_version1.0_#XXXXXXXX`).
#[derive(Clone, Debug)]
pub struct Recipient {
    /// The index in the storage name.
    pub index: u32,
    /// Path of the recipient's storage.
    pub path: String,
    /// The recipient's properties.
    pub properties: Properties,
}

impl Recipient {
    /// `PidTagDisplayName`.
    pub fn display_name(&self) -> Option<&str> {
        self.properties.string(tags::DISPLAY_NAME)
    }

    /// `PidTagSmtpAddress`, else `PidTagEmailAddress`.
    pub fn email_address(&self) -> Option<&str> {
        self.properties
            .string(tags::SMTP_ADDRESS)
            .or_else(|| self.properties.string(tags::EMAIL_ADDRESS))
    }

    /// `PidTagRecipientType`: 1 = To, 2 = Cc, 3 = Bcc.
    pub fn recipient_type(&self) -> Option<i64> {
        self.properties.int(tags::RECIPIENT_TYPE)
    }
}

/// What an attachment holds.
#[derive(Clone, Debug)]
pub enum AttachmentContent {
    /// No data in the file (attached by reference, or the data is missing).
    None,
    /// Data bytes: `PidTagAttachDataBinary`, see [`Attachment::data`].
    Binary,
    /// An embedded message (`PidTagAttachDataObject` holding a message).
    Message(Box<Message>),
    /// An OLE storage (`PidTagAttachDataObject` that is not a message).
    Storage(Storage),
    /// An embedded message nested deeper than [`Options::max_depth`]: not read.
    TooDeep,
}

/// An attachment (`__attach_version1.0_#XXXXXXXX`).
#[derive(Clone, Debug)]
pub struct Attachment {
    /// The index in the storage name.
    pub index: u32,
    /// Path of the attachment's storage.
    pub path: String,
    /// The attachment's properties.
    pub properties: Properties,
    /// What the attachment holds.
    pub content: AttachmentContent,
}

impl Attachment {
    /// `PidTagAttachMethod` (see [`tags::attach_method`]).
    pub fn method(&self) -> Option<i64> {
        self.properties.int(tags::ATTACH_METHOD)
    }

    /// `PidTagAttachLongFilename`, else `PidTagAttachFilename`, else `PidTagDisplayName`.
    pub fn file_name(&self) -> Option<&str> {
        [
            tags::ATTACH_LONG_FILENAME,
            tags::ATTACH_FILENAME,
            tags::DISPLAY_NAME,
        ]
        .into_iter()
        .find_map(|id| self.properties.string(id).filter(|s| !s.is_empty()))
    }

    /// `PidTagAttachMimeTag`.
    pub fn mime_type(&self) -> Option<&str> {
        self.properties.string(tags::ATTACH_MIME_TAG)
    }

    /// `PidTagAttachContentId`.
    pub fn content_id(&self) -> Option<&str> {
        self.properties.string(tags::ATTACH_CONTENT_ID)
    }

    /// The data bytes (`PidTagAttachDataBinary`), also when damaged (as far as they could be
    /// read).
    pub fn data(&self) -> Option<&[u8]> {
        let p = self.properties.get_tag(ATTACH_DATA_BINARY)?;
        p.value.best_effort()?.as_bytes()
    }

    /// The embedded message, if the attachment is one.
    pub fn message(&self) -> Option<&Message> {
        match &self.content {
            AttachmentContent::Message(m) => Some(m),
            _ => None,
        }
    }
}

/// An OLE storage held by an attachment: its streams and sub-storages.
#[derive(Clone, Debug, Default)]
pub struct Storage {
    /// The storage's CLSID.
    pub clsid: Guid,
    /// The entries, in directory order.
    pub entries: Vec<StorageEntry>,
}

/// An entry of a [`Storage`].
#[derive(Clone, Debug)]
pub enum StorageEntry {
    /// A stream and its bytes.
    Stream {
        /// The stream name.
        name: String,
        /// The bytes (as far as they could be read).
        data: Vec<u8>,
    },
    /// A sub-storage.
    Storage {
        /// The storage name.
        name: String,
        /// Its contents.
        storage: Storage,
    },
}

/// The kind of storage a property stream belongs to: the header size differs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    TopLevel,
    Embedded,
    Child,
}

impl Kind {
    fn header_len(self) -> usize {
        match self {
            Kind::TopLevel => 32,
            Kind::Embedded => 24,
            Kind::Child => 8,
        }
    }
}

/// What a storage entry's name says it is.
enum Name {
    Properties,
    Substg { tag: u32, index: Option<u32> },
    Recipient(u32),
    Attachment(u32),
    NamedProperties,
    Other,
}

fn strip_prefix_ignore_case<'a>(name: &'a str, prefix: &str) -> Option<&'a str> {
    let head = name.get(..prefix.len())?;
    head.eq_ignore_ascii_case(prefix)
        .then(|| &name[prefix.len()..])
}

fn hex8(s: &str) -> Option<u32> {
    (s.len() == 8 && s.bytes().all(|b| b.is_ascii_hexdigit()))
        .then(|| u32::from_str_radix(s, 16).ok())
        .flatten()
}

fn classify(name: &str) -> Name {
    if name.eq_ignore_ascii_case(PROPERTIES_STREAM) {
        return Name::Properties;
    }
    if name.eq_ignore_ascii_case(NAMEID_STORAGE) {
        return Name::NamedProperties;
    }
    if let Some(rest) = strip_prefix_ignore_case(name, SUBSTG_PREFIX) {
        let parsed = match rest.split_once('-') {
            None => hex8(rest).map(|tag| (tag, None)),
            Some((tag, index)) => hex8(tag).zip(hex8(index).map(Some)),
        };
        return match parsed {
            Some((tag, index)) => Name::Substg { tag, index },
            None => Name::Other,
        };
    }
    if let Some(index) = strip_prefix_ignore_case(name, RECIPIENT_PREFIX).and_then(hex8) {
        return Name::Recipient(index);
    }
    if let Some(index) = strip_prefix_ignore_case(name, ATTACHMENT_PREFIX).and_then(hex8) {
        return Name::Attachment(index);
    }
    Name::Other
}

/// The property-holding entries of one storage.
#[derive(Default)]
struct Entries<'c> {
    /// `__substg1.0_TTTTTTTT` streams.
    streams: HashMap<u32, &'c Child>,
    /// `__substg1.0_TTTTTTTT-NNNNNNNN` streams, by tag and index.
    elements: HashMap<u32, BTreeMap<u32, &'c Child>>,
    /// `__substg1.0_TTTTTTTT` storages.
    storages: HashMap<u32, &'c Child>,
}

/// A raw 16-byte property stream entry.
#[derive(Clone, Copy)]
struct RawEntry {
    tag: u32,
    entry: PropertyEntry,
}

pub(crate) struct Context<'a, F> {
    pub(crate) reader: &'a mut Reader<F>,
    pub(crate) named: &'a NamedProperties,
    pub(crate) options: &'a Options,
}

impl<F: Read + Seek> Context<'_, F> {
    /// Reads the message whose storage is at `path`. `depth` is 0 for the file itself.
    pub(crate) fn read_message(
        &mut self,
        path: &str,
        children: &[Child],
        depth: usize,
        parent_code_page: Option<CodePage>,
    ) -> Message {
        let mut problems = Problems::default();
        let kind = if depth == 0 {
            Kind::TopLevel
        } else {
            Kind::Embedded
        };
        let mut entries = Entries::default();
        let mut recipients = Vec::new();
        let mut attachments = Vec::new();
        let mut has_properties = false;
        for child in children {
            match (classify(&child.name), child.is_stream) {
                (Name::Properties, true) => has_properties = true,
                (Name::Substg { tag, index }, is_stream) => {
                    entries.add(path, child, tag, index, is_stream, &mut problems)
                }
                (Name::Recipient(index), false) => recipients.push((index, child)),
                (Name::Attachment(index), false) => attachments.push((index, child)),
                (Name::NamedProperties, false) if depth == 0 => {}
                _ => problems.push(
                    &join(path, &child.name),
                    ProblemKind::UnknownEntry,
                    format!(
                        "unexpected {} in a message storage",
                        if child.is_stream { "stream" } else { "storage" }
                    ),
                ),
            }
        }
        let (header, raw_entries) = if has_properties {
            self.read_property_stream(path, kind, &mut problems)
        } else {
            problems.push(
                path,
                ProblemKind::PropertyStream,
                "no __properties_version1.0 stream: only the properties stored as streams are read",
            );
            (None, Vec::new())
        };
        let code_page = self.code_page(&raw_entries, parent_code_page);
        // The HTML body in a PtypString8 is in the Internet code page, like the binary one.
        let html_code_page =
            entry_u32(&raw_entries, tags::INTERNET_CODEPAGE).unwrap_or(code_page.code_page);
        let properties = self.decode_properties(
            path,
            &raw_entries,
            &entries,
            (code_page.code_page, html_code_page),
            &mut problems,
        );

        recipients.sort_by_key(|(index, _)| *index);
        let recipients: Vec<Recipient> = recipients
            .into_iter()
            .map(|(index, child)| {
                let rpath = join(path, &child.name);
                let properties = self.read_child_object(&rpath, code_page.code_page, &mut problems);
                Recipient {
                    index,
                    path: rpath,
                    properties: properties.0,
                }
            })
            .collect();

        attachments.sort_by_key(|(index, _)| *index);
        let attachments: Vec<Attachment> = attachments
            .into_iter()
            .map(|(index, child)| {
                let apath = join(path, &child.name);
                self.read_attachment(index, apath, depth, code_page, &mut problems)
            })
            .collect();

        if let Some(h) = &header {
            if h.recipient_count as usize != recipients.len() {
                problems.push(
                    path,
                    ProblemKind::Count,
                    format!(
                        "header says {} recipients, {} recipient storages found",
                        h.recipient_count,
                        recipients.len()
                    ),
                );
            }
            if h.attachment_count as usize != attachments.len() {
                problems.push(
                    path,
                    ProblemKind::Count,
                    format!(
                        "header says {} attachments, {} attachment storages found",
                        h.attachment_count,
                        attachments.len()
                    ),
                );
            }
        }

        let html = html_body(&properties, html_code_page);
        if let Some(TextEncoding::Unsupported { requested }) = html.as_ref().map(Text::encoding) {
            problems.push(
                path,
                ProblemKind::CodePage,
                format!(
                    "code page {requested} is not supported: the HTML body was decoded as Windows-1252"
                ),
            );
        }
        let rtf = properties
            .get_tag((u32::from(tags::RTF_COMPRESSED) << 16) | 0x0102)
            .and_then(|p| p.value.best_effort()?.as_bytes())
            .map(|data| {
                let rtf = rtf::decompress_rtf(data);
                let rtf_path = join(path, "__substg1.0_10090102");
                for flag in &rtf.flags {
                    problems.push(&rtf_path, ProblemKind::Rtf, flag.to_string());
                }
                rtf
            });

        Message {
            path: path.to_owned(),
            embedded: depth > 0,
            header,
            code_page,
            properties,
            recipients,
            attachments,
            html,
            rtf,
            problems: problems.0,
        }
    }

    /// The code page of a message's `PtypString8` values.
    fn code_page(&self, entries: &[RawEntry], parent: Option<CodePage>) -> CodePage {
        let int = |id: u16| entry_u32(entries, id);
        if let Some(cp) = int(tags::MESSAGE_CODEPAGE) {
            return CodePage {
                code_page: cp,
                source: CodePageSource::MessageCodepage,
            };
        }
        if let Some(cp) = int(tags::MESSAGE_LOCALE_ID).and_then(ansi_code_page_of_locale) {
            return CodePage {
                code_page: cp,
                source: CodePageSource::MessageLocaleId,
            };
        }
        if let Some(parent) = parent.filter(|p| p.source != CodePageSource::Default) {
            return CodePage {
                code_page: parent.code_page,
                source: CodePageSource::Parent,
            };
        }
        if let Some(cp) = int(tags::INTERNET_CODEPAGE).and_then(windows_code_page_of_internet) {
            return CodePage {
                code_page: cp,
                source: CodePageSource::InternetCodepage,
            };
        }
        CodePage {
            code_page: self.options.default_code_page,
            source: CodePageSource::Default,
        }
    }

    /// Reads and splits a property stream.
    fn read_property_stream(
        &mut self,
        path: &str,
        kind: Kind,
        problems: &mut Problems,
    ) -> (Option<MessageHeader>, Vec<RawEntry>) {
        let spath = join(path, PROPERTIES_STREAM);
        let (data, _) = self.reader.read(&spath, problems);
        let expected = kind.header_len();
        let fits = |h: usize| data.len() >= h && (data.len() - h).is_multiple_of(16);
        // Some writers give embedded messages the top-level header, or the reverse.
        let other = match kind {
            Kind::TopLevel => Some(24),
            Kind::Embedded => Some(32),
            Kind::Child => None,
        };
        let header_len = if fits(expected) {
            expected
        } else if let Some(h) = other.filter(|&h| fits(h)) {
            problems.push(
                &spath,
                ProblemKind::PropertyStream,
                format!("the header is {h} bytes, not {expected}"),
            );
            h
        } else if data.len() >= expected {
            problems.push(
                &spath,
                ProblemKind::PropertyStream,
                format!(
                    "{} bytes after the header is not a multiple of 16: the last {} bytes are ignored",
                    data.len() - expected,
                    (data.len() - expected) % 16
                ),
            );
            expected
        } else {
            problems.push(
                &spath,
                ProblemKind::PropertyStream,
                format!(
                    "{} bytes is shorter than the {expected}-byte header",
                    data.len()
                ),
            );
            return (None, Vec::new());
        };
        let u32_at = |off: usize| {
            u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]])
        };
        let header = (kind != Kind::Child).then(|| MessageHeader {
            next_recipient_id: u32_at(8),
            next_attachment_id: u32_at(12),
            recipient_count: u32_at(16),
            attachment_count: u32_at(20),
        });
        let mut duplicates: BTreeMap<u32, usize> = BTreeMap::new();
        let mut entries: Vec<RawEntry> = Vec::new();
        for chunk in data[header_len..].as_chunks::<16>().0 {
            let tag = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
            let flags = u32::from_le_bytes([chunk[4], chunk[5], chunk[6], chunk[7]]);
            let mut value = [0; 8];
            value.copy_from_slice(&chunk[8..]);
            if let Some(n) = duplicates.get_mut(&tag) {
                *n += 1;
                continue;
            }
            duplicates.insert(tag, 1);
            entries.push(RawEntry {
                tag,
                entry: PropertyEntry { flags, value },
            });
        }
        for (tag, n) in duplicates.into_iter().filter(|&(_, n)| n > 1) {
            problems.push(
                &spath,
                ProblemKind::PropertyStream,
                format!("property 0x{tag:08X} is listed {n} times; the first entry is used"),
            );
        }
        (header, entries)
    }

    /// Reads the properties of a recipient or attachment storage. Returns them and the
    /// `PidTagAttachDataObject` storage, if there is one.
    fn read_child_object(
        &mut self,
        path: &str,
        code_page: u32,
        problems: &mut Problems,
    ) -> (Properties, Option<Child>) {
        let children = match self.reader.children(path, problems) {
            Ok(c) => c,
            Err(e) => {
                problems.push(path, ProblemKind::Storage, format!("cannot list: {e}"));
                return (Properties::default(), None);
            }
        };
        let mut entries = Entries::default();
        let mut has_properties = false;
        for child in &children {
            match (classify(&child.name), child.is_stream) {
                (Name::Properties, true) => has_properties = true,
                (Name::Substg { tag, index }, is_stream) => {
                    entries.add(path, child, tag, index, is_stream, problems)
                }
                _ => problems.push(
                    &join(path, &child.name),
                    ProblemKind::UnknownEntry,
                    format!(
                        "unexpected {} in a recipient or attachment storage",
                        if child.is_stream { "stream" } else { "storage" }
                    ),
                ),
            }
        }
        let raw_entries = if has_properties {
            self.read_property_stream(path, Kind::Child, problems).1
        } else {
            problems.push(
                path,
                ProblemKind::PropertyStream,
                "no __properties_version1.0 stream: only the properties stored as streams are read",
            );
            Vec::new()
        };
        let properties = self.decode_properties(
            path,
            &raw_entries,
            &entries,
            (code_page, code_page),
            problems,
        );
        let object = entries
            .storages
            .get(&ATTACH_DATA_OBJECT)
            .map(|c| (*c).clone());
        (properties, object)
    }

    fn read_attachment(
        &mut self,
        index: u32,
        path: String,
        depth: usize,
        code_page: CodePage,
        problems: &mut Problems,
    ) -> Attachment {
        let (properties, object) = self.read_child_object(&path, code_page.code_page, problems);
        let method = properties.int(tags::ATTACH_METHOD);
        let content = match object {
            Some(object) => {
                let opath = join(&path, &object.name);
                match self.reader.children(&opath, problems) {
                    Err(e) => {
                        problems.push(&opath, ProblemKind::Storage, format!("cannot list: {e}"));
                        AttachmentContent::None
                    }
                    Ok(children) => {
                        let has_properties = children
                            .iter()
                            .any(|c| c.is_stream && c.name.eq_ignore_ascii_case(PROPERTIES_STREAM));
                        let is_message = match method {
                            Some(tags::attach_method::EMBEDDED_MESSAGE) => true,
                            Some(tags::attach_method::STORAGE) => false,
                            _ => has_properties,
                        };
                        if !is_message {
                            AttachmentContent::Storage(self.read_storage(
                                &opath,
                                object.clsid,
                                children,
                                problems,
                            ))
                        } else if depth + 1 > self.options.max_depth
                            || depth_of(&opath) > MAX_STORAGE_DEPTH
                        {
                            problems.push(
                                &opath,
                                ProblemKind::Depth,
                                format!(
                                    "embedded message nested deeper than {} levels: not read",
                                    self.options.max_depth
                                ),
                            );
                            AttachmentContent::TooDeep
                        } else {
                            AttachmentContent::Message(Box::new(self.read_message(
                                &opath,
                                &children,
                                depth + 1,
                                Some(code_page),
                            )))
                        }
                    }
                }
            }
            None if properties.get_tag(ATTACH_DATA_BINARY).is_some() => AttachmentContent::Binary,
            None => AttachmentContent::None,
        };
        Attachment {
            index,
            path,
            properties,
            content,
        }
    }

    /// Reads an OLE storage held by an attachment, sub-storages included.
    fn read_storage(
        &mut self,
        path: &str,
        clsid: Guid,
        children: Vec<Child>,
        problems: &mut Problems,
    ) -> Storage {
        let mut entries = Vec::with_capacity(children.len());
        for child in children {
            let cpath = join(path, &child.name);
            if !is_addressable(&child.name) {
                problems.push(
                    &cpath,
                    ProblemKind::UnknownEntry,
                    format!(
                        "a {} named {:?} cannot be read by path: skipped",
                        if child.is_stream { "stream" } else { "storage" },
                        child.name
                    ),
                );
            } else if child.is_stream {
                let (data, _) = self.reader.read(&cpath, problems);
                entries.push(StorageEntry::Stream {
                    name: child.name,
                    data,
                });
            } else if depth_of(&cpath) > MAX_STORAGE_DEPTH {
                problems.push(
                    &cpath,
                    ProblemKind::Depth,
                    format!("storage nested deeper than {MAX_STORAGE_DEPTH} levels: not read"),
                );
            } else {
                let storage = match self.reader.children(&cpath, problems) {
                    Ok(grand) => self.read_storage(&cpath, child.clsid, grand, problems),
                    Err(e) => {
                        problems.push(&cpath, ProblemKind::Storage, format!("cannot list: {e}"));
                        Storage {
                            clsid: child.clsid,
                            entries: Vec::new(),
                        }
                    }
                };
                entries.push(StorageEntry::Storage {
                    name: child.name,
                    storage,
                });
            }
        }
        Storage { clsid, entries }
    }

    /// Decodes the properties of one storage: its property stream entries and `__substg1.0_`
    /// entries.
    fn decode_properties(
        &mut self,
        path: &str,
        raw_entries: &[RawEntry],
        entries: &Entries<'_>,
        (code_page, html_code_page): (u32, u32),
        problems: &mut Problems,
    ) -> Properties {
        let by_tag: HashMap<u32, PropertyEntry> =
            raw_entries.iter().map(|e| (e.tag, e.entry)).collect();
        let mut tags: BTreeSet<u32> = by_tag.keys().copied().collect();
        tags.extend(entries.streams.keys());
        tags.extend(entries.storages.keys());
        for &tag in entries.elements.keys() {
            if is_multiple_variable(tag as u16) {
                tags.insert(tag);
            } else {
                problems.push(
                    path,
                    ProblemKind::UnknownEntry,
                    format!(
                        "element streams __substg1.0_{tag:08X}-NNNNNNNN for a type that has none"
                    ),
                );
            }
        }
        let mut unsupported_code_pages = BTreeSet::new();
        let mut unmapped = Vec::new();
        let mut properties = Vec::with_capacity(tags.len());
        for tag in tags {
            let id = (tag >> 16) as u16;
            let type_code = tag as u16;
            let entry = by_tag.get(&tag).copied();
            let mut decoder = Decoder {
                ctx: &mut *self,
                path,
                tag,
                entry,
                entries,
                code_page,
                html_code_page,
                problems,
            };
            let value = decoder.decode();
            let mut lossy = false;
            visit_texts(&value, &mut |t| {
                lossy |= t.is_lossy();
                if let TextEncoding::Unsupported { requested } = t.encoding() {
                    unsupported_code_pages.insert(requested);
                }
            });
            if lossy {
                problems.push(
                    path,
                    ProblemKind::Text,
                    format!(
                        "property 0x{tag:08X} has text that is not valid in its encoding (replaced by U+FFFD; the raw bytes are kept)"
                    ),
                );
            }
            match &value {
                PropertyValue::Unsupported(_) => problems.push(
                    path,
                    ProblemKind::UnsupportedType,
                    format!("property 0x{tag:08X}: type 0x{type_code:04X} is not decoded"),
                ),
                PropertyValue::Damaged { reason, .. } => problems.push(
                    path,
                    ProblemKind::PropertyValue,
                    format!("property 0x{tag:08X}: {reason}"),
                ),
                PropertyValue::Ok(_) => {}
            }
            let named = if id >= 0x8000 {
                let named = self.named.get(id).cloned();
                if named.is_none() {
                    unmapped.push(id);
                }
                named
            } else {
                None
            };
            properties.push(Property {
                id,
                type_code,
                named,
                entry,
                value,
            });
        }
        for code_page in unsupported_code_pages {
            problems.push(
                path,
                ProblemKind::CodePage,
                format!(
                    "code page {code_page} is not supported: PtypString8 values were decoded as Windows-1252"
                ),
            );
        }
        if !unmapped.is_empty() {
            unmapped.dedup();
            let ids: Vec<String> = unmapped.iter().map(|id| format!("0x{id:04X}")).collect();
            problems.push(
                path,
                ProblemKind::NamedProperties,
                format!("no named-property mapping for {}", ids.join(", ")),
            );
        }
        Properties(properties)
    }
}

impl<'c> Entries<'c> {
    fn add(
        &mut self,
        path: &str,
        child: &'c Child,
        tag: u32,
        index: Option<u32>,
        is_stream: bool,
        problems: &mut Problems,
    ) {
        let duplicate = match (index, is_stream) {
            (None, true) => self.streams.insert(tag, child).is_some(),
            (Some(i), true) => self
                .elements
                .entry(tag)
                .or_default()
                .insert(i, child)
                .is_some(),
            (None, false) => self.storages.insert(tag, child).is_some(),
            (Some(_), false) => {
                problems.push(
                    &join(path, &child.name),
                    ProblemKind::UnknownEntry,
                    "an element of a multi-valued property is a storage, not a stream",
                );
                false
            }
        };
        if duplicate {
            problems.push(
                &join(path, &child.name),
                ProblemKind::UnknownEntry,
                "a second entry of the same name (ignoring case)",
            );
        }
    }
}

fn is_multiple_variable(type_code: u16) -> bool {
    matches!(type_code, 0x101E | 0x101F | 0x1102)
}

/// Calls `f` with every [`Text`] of a value.
fn visit_texts(value: &PropertyValue, f: &mut impl FnMut(&Text)) {
    let v = match value {
        PropertyValue::Ok(v) => v,
        PropertyValue::Damaged {
            recovered: Some(v), ..
        } => v,
        _ => return,
    };
    match v {
        Value::String8(t) | Value::Unicode(t) => f(t),
        Value::MultipleString8(ts) | Value::MultipleUnicode(ts) => ts.iter().for_each(f),
        _ => {}
    }
}

/// A positive `PtypInteger32` encoding/locale entry. Negative values must not become
/// enormous unsigned code pages that hide a usable locale or parent encoding.
fn entry_u32(entries: &[RawEntry], id: u16) -> Option<u32> {
    entries
        .iter()
        .find(|e| e.tag == (u32::from(id) << 16) | 0x0003)
        .map(|e| {
            u32::from_le_bytes([
                e.entry.value[0],
                e.entry.value[1],
                e.entry.value[2],
                e.entry.value[3],
            ])
        })
        .filter(|&v| v != 0 && v <= i32::MAX as u32)
}

/// The HTML body: `PidTagHtml` decoded in `html_code_page`, else `PidTagBodyHtml`.
fn html_body(properties: &Properties, html_code_page: u32) -> Option<Text> {
    let id = u32::from(tags::HTML) << 16;
    if let Some(bytes) = properties
        .get_tag(id | 0x0102)
        .and_then(|p| p.value.best_effort()?.as_bytes())
    {
        return Some(Text::from_code_page(bytes.to_vec(), html_code_page));
    }
    if let Some(Value::Unicode(t)) = properties
        .get_tag(id | 0x001F)
        .and_then(|p| p.value.best_effort())
    {
        return Some(t.clone());
    }
    if let Some(Value::String8(t)) = properties
        .get_tag(id | 0x001E)
        .and_then(|p| p.value.best_effort())
    {
        return Some(t.clone());
    }
    None
}

/// Decodes one property.
struct Decoder<'x, 'a, 'c, F> {
    ctx: &'x mut Context<'a, F>,
    path: &'x str,
    tag: u32,
    entry: Option<PropertyEntry>,
    entries: &'x Entries<'c>,
    code_page: u32,
    html_code_page: u32,
    problems: &'x mut Problems,
}

impl<F: Read + Seek> Decoder<'_, '_, '_, F> {
    fn stream_name(&self) -> String {
        format!("{SUBSTG_PREFIX}{:08X}", self.tag)
    }

    /// Reads a child stream.
    fn read(&mut self, child: &Child) -> (Vec<u8>, bool) {
        let path = join(self.path, &child.name);
        self.ctx.reader.read(&path, self.problems)
    }

    fn damaged(recovered: Option<Value>, raw: Vec<u8>, reason: impl Into<String>) -> PropertyValue {
        PropertyValue::Damaged {
            recovered,
            raw,
            reason: reason.into(),
        }
    }

    fn decode(&mut self) -> PropertyValue {
        let type_code = self.tag as u16;
        let stream = self.entries.streams.get(&self.tag).copied();
        let storage = self.entries.storages.get(&self.tag).copied();
        let Some(ty) = PropertyType::from_code(type_code) else {
            return self.unsupported(stream);
        };
        use PropertyType::*;
        match ty {
            Unspecified | ServerId | Restriction | RuleAction => self.unsupported(stream),
            Object => match (storage, stream) {
                (Some(_), _) => PropertyValue::Ok(Value::Object),
                (None, Some(s)) => {
                    let (raw, _) = self.read(s);
                    Self::damaged(
                        None,
                        raw,
                        "an object property stored as a stream, not a storage",
                    )
                }
                (None, None) => Self::damaged(
                    None,
                    Vec::new(),
                    format!("storage {} is missing", self.stream_name()),
                ),
            },
            Null | Integer16 | Integer32 | Floating32 | Floating64 | Currency | FloatingTime
            | ErrorCode | Boolean | Integer64 | Time => self.fixed(ty, stream),
            String8 | Unicode | Binary | Guid => self.variable(ty, stream, storage),
            MultipleInteger16 | MultipleInteger32 | MultipleFloating32 | MultipleFloating64
            | MultipleCurrency | MultipleFloatingTime | MultipleInteger64 | MultipleTime
            | MultipleGuid => self.multiple_fixed(ty, stream),
            MultipleString8 | MultipleUnicode | MultipleBinary => {
                self.multiple_variable(ty, stream)
            }
        }
    }

    fn unsupported(&mut self, stream: Option<&Child>) -> PropertyValue {
        match (stream, self.entry) {
            (Some(s), _) => PropertyValue::Unsupported(self.read(s).0),
            (None, Some(e)) => PropertyValue::Unsupported(e.value.to_vec()),
            (None, None) => PropertyValue::Unsupported(Vec::new()),
        }
    }

    fn fixed(&mut self, ty: PropertyType, stream: Option<&Child>) -> PropertyValue {
        let size = ty.fixed_size().unwrap_or(8);
        if let Some(e) = self.entry {
            return PropertyValue::Ok(fixed_value(ty, &e.value));
        }
        // Only a stream: not where a fixed-size value belongs.
        let Some(s) = stream else {
            return Self::damaged(None, Vec::new(), "no value");
        };
        let (raw, _) = self.read(s);
        let recovered = (raw.len() >= size).then(|| fixed_value(ty, &raw[..size]));
        Self::damaged(
            recovered,
            raw,
            "a fixed-size property stored as a stream, not in the property stream",
        )
    }

    fn variable(
        &mut self,
        ty: PropertyType,
        stream: Option<&Child>,
        storage: Option<&Child>,
    ) -> PropertyValue {
        let Some(s) = stream else {
            if storage.is_some() {
                return Self::damaged(
                    None,
                    Vec::new(),
                    format!("{} is a storage, not a stream", self.stream_name()),
                );
            }
            // A missing stream is an empty value when the entry says the value is empty.
            let declared = self.entry.map(|e| e.size());
            let empty = matches!(
                (ty, declared),
                (PropertyType::String8, Some(0 | 1))
                    | (PropertyType::Unicode, Some(0..=2))
                    | (PropertyType::Binary, Some(0))
            );
            if empty {
                return PropertyValue::Ok(self.variable_value(ty, Vec::new()));
            }
            return Self::damaged(
                None,
                Vec::new(),
                format!(
                    "stream {} is missing{}",
                    self.stream_name(),
                    declared.map_or(String::new(), |d| format!(" (the entry gives size {d})"))
                ),
            );
        };
        let (raw, complete) = self.read(s);
        if ty == PropertyType::Guid {
            let recovered = raw
                .first_chunk::<16>()
                .map(|g| Value::Guid(crate::guid::Guid(*g)));
            if raw.len() == 16 {
                return PropertyValue::Ok(recovered.unwrap_or(Value::Null));
            }
            return Self::damaged(
                recovered,
                raw.clone(),
                format!("a GUID stream of {} bytes, not 16", raw.len()),
            );
        }
        let value = self.variable_value(ty, raw.clone());
        if complete {
            PropertyValue::Ok(value)
        } else {
            Self::damaged(Some(value), raw, "the stream could be read only in part")
        }
    }

    fn variable_value(&self, ty: PropertyType, raw: Vec<u8>) -> Value {
        match ty {
            PropertyType::String8 => {
                let code_page = if self.tag == (u32::from(tags::HTML) << 16) | 0x001E {
                    self.html_code_page
                } else {
                    self.code_page
                };
                Value::String8(Text::from_code_page(raw, code_page))
            }
            PropertyType::Unicode => Value::Unicode(Text::from_utf16le(raw)),
            _ => Value::Binary(raw),
        }
    }

    fn multiple_fixed(&mut self, ty: PropertyType, stream: Option<&Child>) -> PropertyValue {
        let size = ty.fixed_size().unwrap_or(8);
        let Some(s) = stream else {
            if self.entry.is_some_and(|e| e.size() == 0) {
                return PropertyValue::Ok(multiple_fixed_value(ty, &[], size));
            }
            return Self::damaged(
                None,
                Vec::new(),
                format!("stream {} is missing", self.stream_name()),
            );
        };
        let (raw, complete) = self.read(s);
        let value = multiple_fixed_value(ty, &raw, size);
        if !raw.len().is_multiple_of(size) {
            let reason = format!(
                "{} bytes is not a multiple of the {size}-byte value size",
                raw.len()
            );
            Self::damaged(Some(value), raw, reason)
        } else if !complete {
            Self::damaged(Some(value), raw, "the stream could be read only in part")
        } else {
            PropertyValue::Ok(value)
        }
    }

    fn multiple_variable(&mut self, ty: PropertyType, stream: Option<&Child>) -> PropertyValue {
        // The length stream has one 4-byte length per string, or 8 bytes (length and 4
        // reserved bytes) per binary value ([MS-OXMSG] 2.1.4.2.2).
        let unit = if ty == PropertyType::MultipleBinary {
            8
        } else {
            4
        };
        let elements = self.entries.elements.get(&self.tag);
        let mut reasons = Vec::new();
        let (lengths, count) = match stream {
            Some(s) => {
                let (lengths, complete) = self.read(s);
                if !complete {
                    reasons.push("the length stream could be read only in part".to_owned());
                }
                if !lengths.len().is_multiple_of(unit) {
                    reasons.push(format!(
                        "the length stream is {} bytes, not a multiple of {unit}",
                        lengths.len()
                    ));
                }
                let count = (lengths.len() / unit) as u64;
                (lengths, Some(count))
            }
            None => {
                if elements.is_none() && self.entry.is_some_and(|e| e.size() == 0) {
                    return PropertyValue::Ok(empty_multiple_variable(ty));
                }
                reasons.push(format!("length stream {} is missing", self.stream_name()));
                (Vec::new(), None)
            }
        };
        let mut values = Vec::new();
        let mut present = 0u64;
        let mut extra = 0u64;
        for (&index, child) in elements.into_iter().flatten() {
            match count {
                Some(count) if u64::from(index) >= count => extra += 1,
                Some(_) => present += 1,
                None => {}
            }
            let (raw, complete) = self.read(child);
            if !complete {
                reasons.push(format!("element {index} could be read only in part"));
            }
            values.push(raw);
        }
        if let Some(count) = count {
            if present < count {
                reasons.push(format!(
                    "{} of {count} element streams are missing",
                    count - present
                ));
            }
            if extra > 0 {
                reasons.push(format!(
                    "{extra} element streams beyond the {count} the length stream lists (kept at the end)"
                ));
            }
        }
        let value = match ty {
            PropertyType::MultipleBinary => Value::MultipleBinary(values),
            PropertyType::MultipleUnicode => {
                Value::MultipleUnicode(values.into_iter().map(Text::from_utf16le).collect())
            }
            _ => Value::MultipleString8(
                values
                    .into_iter()
                    .map(|raw| Text::from_code_page(raw, self.code_page))
                    .collect(),
            ),
        };
        if reasons.is_empty() {
            PropertyValue::Ok(value)
        } else {
            Self::damaged(Some(value), lengths, reasons.join("; "))
        }
    }
}

/// A fixed-size value from the value bytes of a property stream entry (8 bytes) or of a
/// multi-valued element; missing bytes read as zero.
fn fixed_value(ty: PropertyType, v: &[u8]) -> Value {
    let mut b = [0u8; 16];
    let n = v.len().min(16);
    b[..n].copy_from_slice(&v[..n]);
    let u16_ = || u16::from_le_bytes([b[0], b[1]]);
    let u32_ = || u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
    let u64_ = || u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]);
    use PropertyType::*;
    match ty {
        Integer16 | MultipleInteger16 => Value::Integer16(u16_() as i16),
        Integer32 | MultipleInteger32 => Value::Integer32(u32_() as i32),
        Floating32 | MultipleFloating32 => Value::Floating32(f32::from_bits(u32_())),
        Floating64 | MultipleFloating64 => Value::Floating64(f64::from_bits(u64_())),
        Currency | MultipleCurrency => Value::Currency(u64_() as i64),
        FloatingTime | MultipleFloatingTime => Value::FloatingTime(f64::from_bits(u64_())),
        ErrorCode => Value::ErrorCode(u32_() as i32),
        Boolean => Value::Boolean(b[0] != 0),
        Integer64 | MultipleInteger64 => Value::Integer64(u64_() as i64),
        Time | MultipleTime => Value::Time(u64_() as i64),
        Guid | MultipleGuid => Value::Guid(crate::guid::Guid(b)),
        _ => Value::Null,
    }
}

fn multiple_fixed_value(ty: PropertyType, raw: &[u8], size: usize) -> Value {
    let items = raw.chunks_exact(size).map(|c| fixed_value(ty, c));
    macro_rules! collect {
        ($single:ident, $multiple:ident) => {
            Value::$multiple(
                items
                    .filter_map(|v| match v {
                        Value::$single(x) => Some(x),
                        _ => None,
                    })
                    .collect(),
            )
        };
    }
    use PropertyType::*;
    match ty {
        MultipleInteger16 => collect!(Integer16, MultipleInteger16),
        MultipleInteger32 => collect!(Integer32, MultipleInteger32),
        MultipleFloating32 => collect!(Floating32, MultipleFloating32),
        MultipleFloating64 => collect!(Floating64, MultipleFloating64),
        MultipleCurrency => collect!(Currency, MultipleCurrency),
        MultipleFloatingTime => collect!(FloatingTime, MultipleFloatingTime),
        MultipleInteger64 => collect!(Integer64, MultipleInteger64),
        MultipleTime => collect!(Time, MultipleTime),
        _ => collect!(Guid, MultipleGuid),
    }
}

fn empty_multiple_variable(ty: PropertyType) -> Value {
    match ty {
        PropertyType::MultipleBinary => Value::MultipleBinary(Vec::new()),
        PropertyType::MultipleUnicode => Value::MultipleUnicode(Vec::new()),
        _ => Value::MultipleString8(Vec::new()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        assert!(matches!(
            classify("__substg1.0_0037001F"),
            Name::Substg {
                tag: 0x0037_001F,
                index: None
            }
        ));
        assert!(matches!(
            classify("__substg1.0_8003101f-0000000a"),
            Name::Substg {
                tag: 0x8003_101F,
                index: Some(10)
            }
        ));
        assert!(matches!(classify("__substg1.0_+037001F"), Name::Other));
        assert!(matches!(classify("__substg1.0_0037001"), Name::Other));
        assert!(matches!(
            classify("__RECIP_version1.0_#0000000A"),
            Name::Recipient(10)
        ));
        assert!(matches!(
            classify("__attach_version1.0_#00000001"),
            Name::Attachment(1)
        ));
        assert!(matches!(classify("__attach_version1.0_#zz"), Name::Other));
        assert!(matches!(
            classify("__properties_version1.0"),
            Name::Properties
        ));
        assert!(matches!(classify("é"), Name::Other));
    }

    #[test]
    fn fixed_values() {
        let v = [0xFF, 0xFF, 0, 0, 0, 0, 0, 0];
        assert_eq!(
            fixed_value(PropertyType::Integer16, &v),
            Value::Integer16(-1)
        );
        assert_eq!(
            fixed_value(PropertyType::Integer32, &v),
            Value::Integer32(0xFFFF)
        );
        assert_eq!(fixed_value(PropertyType::Boolean, &v), Value::Boolean(true));
        assert_eq!(
            multiple_fixed_value(PropertyType::MultipleInteger16, &[1, 0, 2, 0, 3], 2),
            Value::MultipleInteger16(vec![1, 2])
        );
    }
}
