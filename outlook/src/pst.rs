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

//! PST and OST stores ([MS-PST]) as folders and [`Item`]s: ANSI and Unicode PSTs, and OSTs,
//! including the 4 KiB pages and compressed blocks of Outlook 2013 and later.
//!
//! [MS-PST]: https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-pst/

use std::cell::Cell;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, BufReader, Read, Seek, SeekFrom};
use std::path::Path;
use std::rc::Rc;
use std::sync::Arc;

use outlook_pst::ltp::prop_context::PropertyValue;
use outlook_pst::ltp::prop_type::PropertyType;
use outlook_pst::ltp::table_context::TableContext;
use outlook_pst::messaging::attachment::{
    AnsiAttachment, Attachment as _, AttachmentData, UnicodeAttachment,
};
use outlook_pst::messaging::folder::walk_folders;
use outlook_pst::messaging::message::{AnsiMessage, Message as _, UnicodeMessage};
use outlook_pst::messaging::named_prop::NamedPropertyId;
use outlook_pst::messaging::store::{AnsiStore, EntryId, Store as _, UnicodeStore};
use outlook_pst::ndb::header::{Header as _, NdbCryptMethod, NdbVersion};
use outlook_pst::ndb::node_id::NodeId;
use outlook_pst::{AnsiPstFile, PstFile, UnicodePstFile};

use crate::item::{AttachmentParts, Item, Props};
use crate::mapi::{NameId, Property, PropertyName, Value, guid, tags};

pub use outlook_pst::Validation;

/// How a store is read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Options {
    /// How strictly the file's structures are checked: leniently by default, so that what can be
    /// read of a damaged file is read, and the damage is reported in [`PstStore::problems`].
    pub validation: Validation,
    /// The code page of `PtypString8` values of a message that gives none (no
    /// `PidTagMessageCodepage`, `PidTagMessageLocaleId` or usable `PidTagInternetCodepage`): the
    /// ANSI code page of the system that wrote the store. Default 1252.
    pub default_code_page: u32,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            validation: Validation::Lenient,
            default_code_page: 1252,
        }
    }
}

/// Which client wrote the file (`wMagicClient` of the header).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreKind {
    /// `SM`: a PST (a personal store).
    Pst,
    /// `SO`: an OST (an offline copy of a mailbox).
    Ost,
    /// Another value, as its two characters.
    Other(String),
}

/// The file's layout (`wVer` of the header).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// 14 or 15: 32-bit block and page ids, of Outlook 97 to 2002.
    Ansi,
    /// 23: 64-bit ids, of Outlook 2003 and later.
    Unicode,
    /// 36: 64-bit ids, 4 KiB pages and compressed blocks, of the OSTs of Outlook 2013 and later.
    Unicode4k,
}

/// How the file's data blocks are encoded (`bCryptMethod` of the header).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encryption {
    None,
    /// `NDB_CRYPT_PERMUTE`, Outlook's "compressible encryption".
    Permute,
    /// `NDB_CRYPT_CYCLIC`, Outlook's "high encryption".
    Cyclic,
}

/// What the header and the message store object say about a store.
#[derive(Debug, Clone, PartialEq)]
pub struct StoreInfo {
    pub kind: StoreKind,
    pub format: Format,
    /// `wVer`.
    pub version: u16,
    /// `wVerClient`.
    pub client_version: u16,
    pub encryption: Encryption,
    /// The store's display name (`PidTagDisplayName`).
    pub display_name: Option<String>,
    /// `PidTagRecordKey`: the store's identity, which its entry ids hold.
    pub record_key: Option<Vec<u8>>,
    /// Every property of the message store object.
    pub properties: Vec<Property>,
}

/// A folder of a store.
#[derive(Debug, Clone, PartialEq)]
pub struct Folder {
    /// Its node id.
    pub node: u32,
    /// The folder whose hierarchy table lists it: none for the root folder.
    pub parent: Option<u32>,
    /// How many levels below the root folder it is.
    pub depth: usize,
    /// `PidTagDisplayName`.
    pub name: Option<String>,
    /// The names of the folders from the root down, each after a `/`: `/` for the root folder
    /// (which has no name), `/Top of Outlook data file/Inbox` for an inbox.
    pub path: String,
    /// `PidTagContainerClass`: what the folder holds (`IPF.Note`, `IPF.Appointment`, …).
    pub container_class: Option<String>,
    /// `PidTagContentCount`: how many messages the folder says it has.
    pub content_count: Option<i64>,
    /// `PidTagContentUnreadCount`.
    pub unread_count: Option<i64>,
    /// `PidTagCreationTime` (UTC FILETIME), when the store keeps it for folders.
    pub created: Option<i64>,
    /// `PidTagLastModificationTime`.
    pub modified: Option<i64>,
    /// The node ids of its sub-folders, from its hierarchy table.
    pub subfolders: Vec<u32>,
    /// The node ids of its messages, from its contents table.
    pub messages: Vec<u32>,
    /// The node ids of its folder associated information (FAI): the hidden messages of its
    /// associated contents table (views, rules, settings and other `IPM.Configuration` items).
    pub associated: Vec<u32>,
    pub properties: Vec<Property>,
    /// Why the folder could not be opened; its sub-folders are then not walked.
    pub problem: Option<String>,
}

/// A message of a folder, read as an item.
#[derive(Debug, Clone, PartialEq)]
pub struct StoreItem {
    /// The folder's node id.
    pub folder: u32,
    /// The message's node id.
    pub node: u32,
    /// Whether it is folder associated information (a hidden message).
    pub associated: bool,
    /// The item, or why it could not be read.
    pub item: Result<Item, String>,
}

enum Inner {
    Unicode {
        pst: Rc<UnicodePstFile>,
        store: Rc<UnicodeStore>,
    },
    Ansi {
        pst: Rc<AnsiPstFile>,
        store: Rc<AnsiStore>,
    },
}

/// A PST or OST file, read-only. It is not `Send`: read one store on one thread.
pub struct PstStore {
    inner: Inner,
    info: StoreInfo,
    names: BTreeMap<u16, PropertyName>,
    default_code_page: u32,
    problems: Vec<String>,
}

impl PstStore {
    /// Opens the file at `path`, read-only.
    pub fn open(path: impl AsRef<Path>, options: &Options) -> io::Result<PstStore> {
        let file = File::open(path)?;
        PstStore::from_reader(BufReader::new(file), options)
    }

    /// Opens a store from a reader; nothing is written to it.
    pub fn from_reader(
        mut reader: impl Read + Seek + 'static,
        options: &Options,
    ) -> io::Result<PstStore> {
        // dwMagic, dwCRCPartial, wMagicClient, wVer, wVerClient ([MS-PST] 2.2.2.6)
        let mut head = [0u8; 14];
        reader.seek(SeekFrom::Start(0))?;
        reader.read_exact(&mut head)?;
        reader.seek(SeekFrom::Start(0))?;
        if head[..4] != *b"!BDN" {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "not a PST or OST file (no !BDN signature)",
            ));
        }
        let kind = match [head[8], head[9]] {
            [b'S', b'M'] => StoreKind::Pst,
            [b'S', b'O'] => StoreKind::Ost,
            other => StoreKind::Other(String::from_utf8_lossy(&other).into_owned()),
        };
        let version = u16::from_le_bytes([head[10], head[11]]);
        let client_version = u16::from_le_bytes([head[12], head[13]]);
        let reader: Box<dyn outlook_pst::PstReader> = Box::new(reader);
        let mut problems = Vec::new();
        let (inner, format, encryption, properties, names) = if version < 23 {
            let pst = Rc::new(AnsiPstFile::read_from_with(reader, options.validation)?);
            let store = AnsiStore::read(pst.clone())?;
            let header = pst.header();
            let names = names(store.as_ref(), &mut problems);
            let properties = store_properties(store.as_ref(), &names, options);
            (
                Inner::Ansi {
                    pst: pst.clone(),
                    store,
                },
                format(header.version()),
                encryption(header.crypt_method()),
                properties,
                names,
            )
        } else {
            let pst = Rc::new(UnicodePstFile::read_from_with(reader, options.validation)?);
            let store = UnicodeStore::read(pst.clone())?;
            let header = pst.header();
            let names = names(store.as_ref(), &mut problems);
            let properties = store_properties(store.as_ref(), &names, options);
            (
                Inner::Unicode {
                    pst: pst.clone(),
                    store,
                },
                format(header.version()),
                encryption(header.crypt_method()),
                properties,
                names,
            )
        };
        let p = Props(&properties);
        let info = StoreInfo {
            kind,
            format,
            version,
            client_version,
            encryption,
            display_name: p.text(tags::DISPLAY_NAME),
            record_key: p.bytes(tags::RECORD_KEY),
            properties,
        };
        Ok(PstStore {
            inner,
            info,
            names,
            default_code_page: options.default_code_page,
            problems,
        })
    }

    pub fn info(&self) -> &StoreInfo {
        &self.info
    }

    /// The named-property map: the name of each property id from 0x8000.
    pub fn named_properties(&self) -> &BTreeMap<u16, PropertyName> {
        &self.names
    }

    /// Every folder reachable from the root folder, parents before their sub-folders, each once
    /// (a corrupt hierarchy that loops ends where a folder comes again).
    pub fn folders(&self) -> Vec<Folder> {
        match &self.inner {
            Inner::Unicode { store, .. } => self.walk(store.as_ref()),
            Inner::Ansi { store, .. } => self.walk(store.as_ref()),
        }
    }

    fn walk(&self, store: &dyn outlook_pst::messaging::store::Store) -> Vec<Folder> {
        let mut paths = BTreeMap::<u32, String>::new();
        let mut folders = Vec::new();
        for entry in walk_folders(store) {
            let node = u32::from(entry.node_id);
            let parent = entry.parent.map(u32::from);
            let mut folder = Folder {
                node,
                parent,
                depth: entry.depth,
                name: None,
                path: String::new(),
                container_class: None,
                content_count: None,
                unread_count: None,
                created: None,
                modified: None,
                subfolders: Vec::new(),
                messages: Vec::new(),
                associated: Vec::new(),
                properties: Vec::new(),
                problem: None,
            };
            match entry.folder {
                Ok(f) => {
                    folder.properties = f
                        .properties()
                        .iter()
                        .map(|(&id, value)| {
                            property(id, value, &self.names, self.default_code_page)
                        })
                        .collect();
                    let p = Props(&folder.properties);
                    folder.name = p.text(tags::DISPLAY_NAME);
                    folder.container_class = p.text(tags::CONTAINER_CLASS);
                    folder.content_count = p.int(tags::CONTENT_COUNT);
                    folder.unread_count = p.int(tags::CONTENT_UNREAD_COUNT);
                    folder.created = p.time(tags::CREATION_TIME);
                    folder.modified = p.time(tags::LAST_MODIFICATION_TIME);
                    let ids = |table: Option<&Rc<dyn TableContext>>| -> Vec<u32> {
                        table
                            .map(|t| t.rows_matrix().map(|row| u32::from(row.id())).collect())
                            .unwrap_or_default()
                    };
                    folder.subfolders = ids(f.hierarchy_table());
                    folder.messages = ids(f.contents_table());
                    folder.associated = ids(f.associated_table());
                }
                Err(e) => folder.problem = Some(e.to_string()),
            }
            let parent_path = parent.and_then(|p| paths.get(&p)).map(String::as_str);
            folder.path = match parent_path {
                None => "/".to_owned(),
                Some(path) => {
                    let name = folder.name.as_deref().unwrap_or_default();
                    if path == "/" {
                        format!("/{name}")
                    } else {
                        format!("{path}/{name}")
                    }
                }
            };
            paths.insert(node, folder.path.clone());
            folders.push(folder);
        }
        folders
    }

    /// The messages of a folder and then its folder associated information, each read as an
    /// item (a message that cannot be read comes with the reason).
    pub fn items<'a>(&'a self, folder: &'a Folder) -> impl Iterator<Item = StoreItem> + 'a {
        let messages = folder.messages.iter().map(|&node| (node, false));
        let associated = folder.associated.iter().map(|&node| (node, true));
        messages
            .chain(associated)
            .map(move |(node, associated)| StoreItem {
                folder: folder.node,
                node,
                associated,
                item: self.item(node),
            })
    }

    /// The message of a node id, read as an item.
    pub fn item(&self, node: u32) -> Result<Item, String> {
        let reader = Reader {
            names: &self.names,
            default_code_page: self.default_code_page,
            embedded: Cell::new(0),
        };
        match &self.inner {
            Inner::Unicode { store, .. } => reader.read::<Unicode>(store, node),
            Inner::Ansi { store, .. } => reader.read::<Ansi>(store, node),
        }
        .map_err(|e| e.to_string())
    }

    /// What was found damaged so far: in the file's structures (each once, in the order found)
    /// and in its named-property map. Items keep their own problems.
    pub fn problems(&self) -> Vec<String> {
        let file = match &self.inner {
            Inner::Unicode { pst, .. } => pst.problems(),
            Inner::Ansi { pst, .. } => pst.problems(),
        };
        self.problems
            .iter()
            .cloned()
            .chain(file.iter().map(ToString::to_string))
            .collect()
    }
}

/// The two kinds of file, for reading messages and attachments as their own types: the
/// attachments of an embedded message can only be read through them.
trait Kind {
    type Store;
    type Message: outlook_pst::messaging::message::Message;
    type Attachment: outlook_pst::messaging::attachment::Attachment;
    fn message(store: &Rc<Self::Store>, entry_id: &EntryId) -> io::Result<Rc<Self::Message>>;
    fn attachment(message: &Rc<Self::Message>, node: NodeId) -> io::Result<Rc<Self::Attachment>>;
    fn embedded(attachment: &Self::Attachment) -> Option<Rc<Self::Message>>;
}

struct Unicode;
struct Ansi;

impl Kind for Unicode {
    type Store = UnicodeStore;
    type Message = UnicodeMessage;
    type Attachment = UnicodeAttachment;
    fn message(store: &Rc<UnicodeStore>, entry_id: &EntryId) -> io::Result<Rc<UnicodeMessage>> {
        UnicodeMessage::read(store.clone(), entry_id, None)
    }
    fn attachment(message: &Rc<UnicodeMessage>, node: NodeId) -> io::Result<Rc<UnicodeAttachment>> {
        UnicodeAttachment::read(message.clone(), node, None)
    }
    fn embedded(attachment: &UnicodeAttachment) -> Option<Rc<UnicodeMessage>> {
        attachment.embedded_message()
    }
}

impl Kind for Ansi {
    type Store = AnsiStore;
    type Message = AnsiMessage;
    type Attachment = AnsiAttachment;
    fn message(store: &Rc<AnsiStore>, entry_id: &EntryId) -> io::Result<Rc<AnsiMessage>> {
        AnsiMessage::read(store.clone(), entry_id, None)
    }
    fn attachment(message: &Rc<AnsiMessage>, node: NodeId) -> io::Result<Rc<AnsiAttachment>> {
        AnsiAttachment::read(message.clone(), node, None)
    }
    fn embedded(attachment: &AnsiAttachment) -> Option<Rc<AnsiMessage>> {
        attachment.embedded_message()
    }
}

/// The code page of a message's `PtypString8` values, and whether it is only the default.
#[derive(Clone, Copy)]
struct CodePage {
    code_page: u32,
    default: bool,
}

/// The most embedded messages read in one item, at every level: a corrupt file whose embedded
/// messages hold themselves again would otherwise be read over and over.
pub const MAX_EMBEDDED_MESSAGES: usize = 1024;

struct Reader<'a> {
    names: &'a BTreeMap<u16, PropertyName>,
    default_code_page: u32,
    /// The embedded messages read so far in this item.
    embedded: Cell<usize>,
}

impl Reader<'_> {
    fn read<K: Kind>(&self, store: &Rc<K::Store>, node: u32) -> io::Result<Item>
    where
        K::Store: outlook_pst::messaging::store::Store,
    {
        let entry_id = store.properties().make_entry_id(NodeId::from(node))?;
        let message = K::message(store, &entry_id)?;
        Ok(self.message::<K>(&message, None))
    }

    fn message<K: Kind>(&self, message: &Rc<K::Message>, parent: Option<CodePage>) -> Item {
        let mut problems = Vec::new();
        let code_page = self.code_page(|id| message.properties().get(id), parent);
        let properties = message
            .properties()
            .iter()
            .map(|(&id, value)| property(id, value, self.names, code_page.code_page))
            .collect();
        let recipients = match message.recipient_table() {
            Some(table) => self.rows(table.as_ref(), code_page.code_page, &mut problems),
            None => Vec::new(),
        };
        let attachment_nodes: Vec<u32> = message
            .attachment_table()
            .map(|t| t.rows_matrix().map(|row| u32::from(row.id())).collect())
            .unwrap_or_default();
        let attachments = attachment_nodes
            .into_iter()
            .map(|node| self.attachment::<K>(message, node, code_page))
            .collect();
        Item::build(properties, recipients, attachments, problems)
    }

    fn attachment<K: Kind>(
        &self,
        message: &Rc<K::Message>,
        node: u32,
        code_page: CodePage,
    ) -> AttachmentParts {
        let attachment = match K::attachment(message, NodeId::from(node)) {
            Ok(attachment) => attachment,
            Err(e) => {
                return AttachmentParts {
                    problems: vec![format!("attachment 0x{node:X}: {e}")],
                    ..AttachmentParts::default()
                };
            }
        };
        let properties = attachment
            .properties()
            .iter()
            .map(|(&id, value)| property(id, value, self.names, code_page.code_page))
            .collect();
        let data = match attachment.data() {
            Some(AttachmentData::Binary(data)) => Some(data.buffer().to_vec()),
            _ => None,
        };
        let mut problems = Vec::new();
        let embedded = K::embedded(&attachment).and_then(|embedded| {
            if self.embedded.get() >= MAX_EMBEDDED_MESSAGES {
                problems.push(format!(
                    "more than {MAX_EMBEDDED_MESSAGES} embedded messages in the item: not read"
                ));
                return None;
            }
            self.embedded.set(self.embedded.get().saturating_add(1));
            Some(Box::new(self.message::<K>(&embedded, Some(code_page))))
        });
        AttachmentParts {
            properties,
            data,
            embedded,
            problems,
        }
    }

    /// The rows of a recipient table, each as its columns' properties.
    fn rows(
        &self,
        table: &dyn TableContext,
        code_page: u32,
        problems: &mut Vec<String>,
    ) -> Vec<Vec<Property>> {
        let context = table.context();
        let mut rows = Vec::new();
        for (index, row) in table.rows_matrix().enumerate() {
            let values = match row.columns(context) {
                Ok(values) => values,
                Err(e) => {
                    problems.push(format!("recipient {index}: {e}"));
                    rows.push(Vec::new());
                    continue;
                }
            };
            let mut properties = Vec::new();
            for (column, value) in context.columns().iter().zip(values) {
                let Some(value) = value else { continue };
                match table.read_column(&value, column.prop_type()) {
                    Ok(value) => {
                        properties.push(property(column.prop_id(), &value, self.names, code_page))
                    }
                    Err(e) => problems.push(format!(
                        "recipient {index}, property 0x{:04X}: {e}",
                        column.prop_id()
                    )),
                }
            }
            rows.push(properties);
        }
        rows
    }

    /// `PidTagMessageCodepage`, then the ANSI code page of `PidTagMessageLocaleId`, then the
    /// code page of the message it is embedded in, then the Windows code page of
    /// `PidTagInternetCodepage`, then the default: as for `.msg` files.
    fn code_page<'p>(
        &self,
        get: impl Fn(u16) -> Option<&'p PropertyValue>,
        parent: Option<CodePage>,
    ) -> CodePage {
        let int = |id: u16| match get(id) {
            Some(PropertyValue::Integer32(v)) => u32::try_from(*v).ok().filter(|&v| v != 0),
            _ => None,
        };
        let found = int(tags::MESSAGE_CODEPAGE)
            .or_else(|| {
                int(tags::MESSAGE_LOCALE_ID).and_then(outlook_msg::ansi_code_page_of_locale)
            })
            .or_else(|| parent.filter(|p| !p.default).map(|p| p.code_page))
            .or_else(|| {
                int(tags::INTERNET_CODEPAGE).and_then(outlook_msg::windows_code_page_of_internet)
            });
        match found {
            Some(code_page) => CodePage {
                code_page,
                default: false,
            },
            None => CodePage {
                code_page: self.default_code_page,
                default: true,
            },
        }
    }
}

fn format(version: NdbVersion) -> Format {
    match version {
        NdbVersion::Ansi => Format::Ansi,
        NdbVersion::Unicode => Format::Unicode,
        NdbVersion::Unicode4k => Format::Unicode4k,
    }
}

fn encryption(method: NdbCryptMethod) -> Encryption {
    match method {
        NdbCryptMethod::None => Encryption::None,
        NdbCryptMethod::Permute => Encryption::Permute,
        NdbCryptMethod::Cyclic => Encryption::Cyclic,
    }
}

fn store_properties(
    store: &dyn outlook_pst::messaging::store::Store,
    names: &BTreeMap<u16, PropertyName>,
    options: &Options,
) -> Vec<Property> {
    store
        .properties()
        .iter()
        .map(|(&id, value)| property(id, value, names, options.default_code_page))
        .collect()
}

/// The store's named-property map ([MS-PST] 2.4.7): property id from 0x8000 → name.
fn names(
    store: &dyn outlook_pst::messaging::store::Store,
    problems: &mut Vec<String>,
) -> BTreeMap<u16, PropertyName> {
    let mut names = BTreeMap::new();
    let map = match store.named_property_map() {
        Ok(map) => map,
        Err(e) => {
            problems.push(format!("named-property map: {e}"));
            return names;
        }
    };
    let map = map.properties();
    let entries = match map.stream_entries() {
        Ok(entries) => entries,
        Err(e) => {
            problems.push(format!("named-property map: entry stream: {e}"));
            return names;
        }
    };
    let mut failed = 0usize;
    let mut first = None;
    let string_bytes = match map.get(0x0004) {
        Some(PropertyValue::Binary(value)) => value.buffer().len(),
        _ => 0,
    };
    let mut strings = NamedStrings::new(string_bytes);
    for (index, entry) in entries.enumerate() {
        let entry = match entry {
            Ok(entry) => entry,
            Err(e) => {
                failed = failed.saturating_add(1);
                first.get_or_insert_with(|| format!("entry {index}: {e}"));
                continue;
            }
        };
        let set = match map.lookup_guid(entry.guid()) {
            Ok(g) => guid(g.data1(), g.data2(), g.data3(), *g.data4()),
            Err(e) => {
                failed = failed.saturating_add(1);
                first.get_or_insert_with(|| format!("0x{:04X}: GUID: {e}", entry.prop_id()));
                continue;
            }
        };
        let id = match entry.id() {
            NamedPropertyId::Number(lid) => NameId::Number(lid),
            NamedPropertyId::StringOffset(offset) => match strings
                .get(offset, || map.lookup_string_bytes(offset))
            {
                Ok(name) => NameId::Text(name),
                Err(e) => {
                    failed = failed.saturating_add(1);
                    first.get_or_insert_with(|| format!("0x{:04X}: name: {e}", entry.prop_id()));
                    continue;
                }
            },
        };
        names.insert(entry.prop_id(), PropertyName { set, id });
    }
    if let Some(first) = first {
        problems.push(format!(
            "named-property map: {failed} entries could not be read (the first: {first})"
        ));
    }
    names
}

/// Decode each string offset once and share it across identities and items. Overlapping
/// offsets must not turn one string stream into a quadratic amount of decoded text.
struct NamedStrings {
    names: BTreeMap<u32, Arc<str>>,
    left: usize,
}

impl NamedStrings {
    fn new(bytes: usize) -> Self {
        Self {
            names: BTreeMap::new(),
            left: bytes.saturating_mul(2).saturating_add(4096),
        }
    }

    fn get<'a>(
        &mut self,
        offset: u32,
        read: impl FnOnce() -> io::Result<&'a [u8]>,
    ) -> io::Result<Arc<str>> {
        if let Some(name) = self.names.get(&offset) {
            return Ok(name.clone());
        }
        let bytes = read()?;
        if bytes.len() > self.left {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "overlapping named-property strings exceeded the decode budget",
            ));
        }
        self.left = self.left.saturating_sub(bytes.len());
        let name: Arc<str> = utf16(bytes).into();
        self.names.insert(offset, name.clone());
        Ok(name)
    }
}

fn utf16(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|&pair| u16::from_le_bytes(pair))
        .collect();
    let text = String::from_utf16_lossy(&units);
    text.trim_end_matches('\0').to_owned()
}

fn property(
    id: u16,
    value: &PropertyValue,
    names: &BTreeMap<u16, PropertyName>,
    code_page: u32,
) -> Property {
    Property {
        id,
        kind: u16::from(PropertyType::from(value)),
        value: self::value(value, code_page),
        name: if id >= 0x8000 {
            names.get(&id).cloned()
        } else {
            None
        },
    }
}

fn string8(bytes: &[u8], code_page: u32) -> Value {
    let text = outlook_msg::Text::from_code_page(bytes.to_vec(), code_page);
    Value::String8 {
        text: text.as_str().to_owned(),
        bytes: text.raw().to_vec(),
    }
}

fn unicode(units: &[u16], trailing_byte: Option<u8>) -> Value {
    match String::from_utf16(units) {
        Ok(text) if trailing_byte.is_none() => {
            Value::String(text.trim_end_matches('\0').to_owned())
        }
        _ => Value::Damaged {
            recovered: Some(Box::new(Value::String(
                String::from_utf16_lossy(units)
                    .trim_end_matches('\0')
                    .to_owned(),
            ))),
            raw: units
                .iter()
                .flat_map(|unit| unit.to_le_bytes())
                .chain(trailing_byte)
                .collect(),
            reason: "text is not valid UTF-16LE".into(),
        },
    }
}

fn value(value: &PropertyValue, code_page: u32) -> Value {
    use PropertyValue as V;
    let many = |values: Vec<Value>| Value::Multiple(values);
    let guid_of = |g: &outlook_pst::ltp::prop_context::GuidValue| {
        Value::Guid(guid(g.data1(), g.data2(), g.data3(), *g.data4()))
    };
    match value {
        V::Null => Value::Null,
        V::Integer16(v) => Value::Integer16(*v),
        V::Integer32(v) => Value::Integer32(*v),
        V::Floating32(v) => Value::Floating32(*v),
        V::Floating64(v) => Value::Floating64(*v),
        V::Currency(v) => Value::Currency(*v),
        V::FloatingTime(v) => Value::FloatingTime(*v),
        V::ErrorCode(v) => Value::ErrorCode(*v as u32),
        V::Boolean(v) => Value::Boolean(*v),
        V::Integer64(v) => Value::Integer64(*v),
        V::String8(s) => string8(s.buffer(), code_page),
        V::Unicode(s) => unicode(s.buffer(), s.trailing_byte()),
        V::Time(v) => Value::Time(*v),
        V::Guid(g) => guid_of(g),
        V::Binary(b) => Value::Binary(b.buffer().to_vec()),
        V::Object(_) => Value::Object,
        V::MultipleInteger16(v) => many(v.iter().map(|&v| Value::Integer16(v)).collect()),
        V::MultipleInteger32(v) => many(v.iter().map(|&v| Value::Integer32(v)).collect()),
        V::MultipleFloating32(v) => many(v.iter().map(|&v| Value::Floating32(v)).collect()),
        V::MultipleFloating64(v) => many(v.iter().map(|&v| Value::Floating64(v)).collect()),
        V::MultipleCurrency(v) => many(v.iter().map(|&v| Value::Currency(v)).collect()),
        V::MultipleFloatingTime(v) => many(v.iter().map(|&v| Value::FloatingTime(v)).collect()),
        V::MultipleInteger64(v) => many(v.iter().map(|&v| Value::Integer64(v)).collect()),
        V::MultipleString8(v) => many(v.iter().map(|s| string8(s.buffer(), code_page)).collect()),
        V::MultipleUnicode(v) => many(
            v.iter()
                .map(|s| unicode(s.buffer(), s.trailing_byte()))
                .collect(),
        ),
        V::MultipleTime(v) => many(v.iter().map(|&v| Value::Time(v)).collect()),
        V::MultipleGuid(v) => many(v.iter().map(guid_of).collect()),
        V::MultipleBinary(v) => many(
            v.iter()
                .map(|b| Value::Binary(b.buffer().to_vec()))
                .collect(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn named_string_reuse_does_not_exhaust_the_overlap_budget() {
        let bytes = [b'N', 0].repeat(4096);
        let mut names = NamedStrings::new(bytes.len());
        let expected = "N".repeat(4096);
        assert_eq!(&*names.get(0, || Ok(&bytes)).unwrap(), expected);
        for _ in 0..1500 {
            assert_eq!(
                &*names
                    .get(0, || panic!("cached name was read again"))
                    .unwrap(),
                expected
            );
        }
        assert_eq!(&*names.get(1, || Ok(&bytes)).unwrap(), expected);
        let error = names.get(2, || Ok(&bytes)).unwrap_err();
        assert!(error.to_string().contains("decode budget"));
        assert_eq!(
            &*names
                .get(0, || panic!("cached name was read again"))
                .unwrap(),
            expected
        );
        assert_eq!(&*names.get(3, || Ok(b"x\0")).unwrap(), "x");
    }

    #[test]
    fn zero_message_codepage_does_not_hide_the_locale_or_parent() {
        let names = BTreeMap::new();
        let reader = Reader {
            names: &names,
            default_code_page: 1252,
            embedded: Cell::new(0),
        };
        let properties = BTreeMap::from([
            (tags::MESSAGE_CODEPAGE, PropertyValue::Integer32(0)),
            (tags::MESSAGE_LOCALE_ID, PropertyValue::Integer32(1041)),
        ]);
        let codepage = reader.code_page(|id| properties.get(&id), None);
        assert_eq!(codepage.code_page, 932);
        assert!(!codepage.default);
        let properties = BTreeMap::from([(tags::MESSAGE_CODEPAGE, PropertyValue::Integer32(0))]);
        let codepage = reader.code_page(
            |id| properties.get(&id),
            Some(CodePage {
                code_page: 1251,
                default: false,
            }),
        );
        assert_eq!(codepage.code_page, 1251);
        let codepage = reader.code_page(|id| properties.get(&id), None);
        assert_eq!(codepage.code_page, 1252);
        assert!(codepage.default);
    }

    #[test]
    fn pst_unicode_keeps_invalid_surrogate_bytes() {
        let raw = b"A\0\0\xd8B\0";
        let parsed = unicode(&[0x0041, 0xD800, 0x0042], None);
        assert_eq!(parsed.as_str(), Some("A\u{FFFD}B"));
        assert!(matches!(parsed, Value::Damaged { raw: stored, .. } if stored == raw));
        let parsed = unicode(&[0x0041], Some(0xFF));
        assert_eq!(parsed.as_str(), Some("A"));
        assert!(matches!(parsed, Value::Damaged { raw: stored, .. } if stored == b"A\0\xff"));
    }
}
