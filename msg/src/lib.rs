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

#![doc = include_str!("../README.md")]

mod guid;
mod message;
mod named;
mod problem;
mod property;
mod reader;
mod rtf;
pub mod tags;
mod text;
mod time;

pub use guid::{
    CLSID_MESSAGE, CLSID_TEMPLATE, Guid, PS_INTERNET_HEADERS, PS_MAPI, PS_PUBLIC_STRINGS,
    PSETID_ADDRESS, PSETID_AIR_SYNC, PSETID_APPOINTMENT, PSETID_ATTACHMENT,
    PSETID_CALENDAR_ASSISTANT, PSETID_COMMON, PSETID_LOG, PSETID_MEETING, PSETID_MESSAGING,
    PSETID_NOTE, PSETID_POST_RSS, PSETID_SHARING, PSETID_TASK, PSETID_UNIFIED_MESSAGING,
    PSETID_XML_EXTRACTED_ENTITIES,
};
pub use message::{
    Attachment, AttachmentContent, CodePage, CodePageSource, Message, MessageHeader, Recipient,
    Storage, StorageEntry,
};
pub use named::{NamedProperties, NamedPropertyEntry};
pub use problem::{Problem, ProblemKind};
pub use property::{
    NamedProperty, Properties, Property, PropertyEntry, PropertyName, PropertyType, PropertyValue,
    Value,
};
pub use rtf::{Rtf, RtfFlag, RtfHeader};
pub use text::{Text, TextEncoding, is_code_page_supported};
pub use time::{filetime_to_unix, floating_time_to_filetime, format_filetime};

use message::{Context, NAMEID_STORAGE, PROPERTIES_STREAM};
use problem::Problems;
use reader::{Reader, join};
use std::io::{self, Cursor, Read, Seek, SeekFrom};

/// The compound file signature.
const CFB_SIGNATURE: [u8; 8] = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];

/// Why a file could not be read at all. Anything less is a [`Problem`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The data does not start with the compound file signature.
    #[error("not a compound file (no CFB signature)")]
    NotCompoundFile,
    /// The compound file structure (header, FAT, directory) is too damaged to open.
    #[error("the compound file cannot be opened: {0}")]
    Cfb(io::Error),
    /// A compound file, but not an Outlook message: no property stream, `__substg1.0_`,
    /// recipient or attachment entries at its root.
    #[error("the compound file is not an Outlook message")]
    NotMessage,
    /// Reading the input failed.
    #[error("cannot read the input: {0}")]
    Io(io::Error),
}

/// Limits and defaults for reading.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Options {
    /// Embedded messages nested deeper than this are not read
    /// ([`AttachmentContent::TooDeep`]). The file itself is depth 0. Default 16.
    pub max_depth: usize,
    /// The code page for `PtypString8` values of a message that gives none (no
    /// `PidTagMessageCodepage`, `PidTagMessageLocaleId` or usable `PidTagInternetCodepage`):
    /// the default ANSI code page of the store or system it came from. Default 1252.
    pub default_code_page: u32,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            max_depth: 16,
            default_code_page: 1252,
        }
    }
}

/// What the root storage CLSID says the file is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FileKind {
    /// A message (`.msg`): CLSID [`CLSID_MESSAGE`].
    Message,
    /// An Outlook template (`.oft`): CLSID [`CLSID_TEMPLATE`].
    Template,
    /// Any other CLSID (many non-Outlook writers leave it all zeros).
    Other,
}

/// A `.msg` or `.oft` file.
#[derive(Clone, Debug)]
pub struct MsgFile {
    /// The CLSID of the root storage (see [`MsgFile::kind`]).
    pub clsid: Guid,
    /// The compound file major version (3: 512-byte sectors, 4: 4096-byte sectors).
    pub cfb_version: u16,
    /// The named-property mapping, shared by the file and its embedded messages.
    pub named_properties: NamedProperties,
    /// The message.
    pub message: Message,
    /// Problems that concern the whole file (the named-property mapping). Problems of the
    /// message, its recipients and attachments are in [`Message::problems`]; see
    /// [`MsgFile::all_problems`].
    pub problems: Vec<Problem>,
}

impl MsgFile {
    /// Reads a file from its bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self, Error> {
        Self::from_bytes_with(data, &Options::default())
    }

    /// Reads a file from its bytes, with options.
    pub fn from_bytes_with(data: &[u8], options: &Options) -> Result<Self, Error> {
        Self::from_reader_with(Cursor::new(data), options)
    }

    /// Reads a file from a reader. Nothing is written to it.
    pub fn from_reader<R: Read + Seek>(reader: R) -> Result<Self, Error> {
        Self::from_reader_with(reader, &Options::default())
    }

    /// Reads a file from a reader, with options. Nothing is written to it.
    pub fn from_reader_with<R: Read + Seek>(
        mut reader: R,
        options: &Options,
    ) -> Result<Self, Error> {
        let file_len = reader.seek(SeekFrom::End(0)).map_err(Error::Io)?;
        reader.seek(SeekFrom::Start(0)).map_err(Error::Io)?;
        let mut header = [0; 512];
        let header_len = (file_len.min(512)) as usize;
        reader
            .read_exact(&mut header[..header_len])
            .map_err(Error::Io)?;
        if header_len < 8 || header[..8] != CFB_SIGNATURE {
            return Err(Error::NotCompoundFile);
        }
        reader.seek(SeekFrom::Start(0)).map_err(Error::Io)?;
        let error = match cfb::CompoundFile::open(&mut reader) {
            Ok(cfb) => return read_compound(cfb, file_len, options, Vec::new()),
            Err(e) => e,
        };
        // Some writers (and truncation) leave a FAT that describes more sectors than the file
        // has: read the missing sectors as zeros.
        if let Some(padded_len) = padded_len(&header, file_len) {
            let padded = ZeroPadded {
                inner: &mut reader,
                inner_len: file_len,
                len: padded_len,
                pos: 0,
            };
            match cfb::CompoundFile::open(padded) {
                Ok(cfb) => {
                    let problem = Problem {
                        path: "/".to_owned(),
                        kind: ProblemKind::CompoundFile,
                        detail: format!(
                            "the file is {file_len} bytes but its FAT describes {padded_len}: read the rest as zeros (first error: {error})"
                        ),
                    };
                    return read_compound(cfb, padded_len, options, vec![problem]);
                }
                Err(again) if again.to_string() != error.to_string() => {
                    return Err(Error::Cfb(io::Error::new(
                        error.kind(),
                        format!("{error}; with the missing sectors read as zeros: {again}"),
                    )));
                }
                Err(_) => {}
            }
        }
        Err(Error::Cfb(error))
    }

    /// What the root CLSID says the file is: a message or a template.
    pub fn kind(&self) -> FileKind {
        if self.clsid == CLSID_MESSAGE {
            FileKind::Message
        } else if self.clsid == CLSID_TEMPLATE {
            FileKind::Template
        } else {
            FileKind::Other
        }
    }

    /// Every problem: the file's, then each message's (embedded messages depth first).
    pub fn all_problems(&self) -> Vec<&Problem> {
        let mut out: Vec<&Problem> = self.problems.iter().collect();
        out.extend(self.message.problems.iter());
        for m in self.message.embedded_messages() {
            out.extend(m.problems.iter());
        }
        out
    }
}

/// Reads the message of an opened compound file.
fn read_compound<F: Read + Seek>(
    cfb: cfb::CompoundFile<F>,
    file_len: u64,
    options: &Options,
    problems: Vec<Problem>,
) -> Result<MsgFile, Error> {
    let clsid = reader::guid_of(&cfb.root_entry());
    let cfb_version = match cfb.version() {
        cfb::Version::V3 => 3,
        cfb::Version::V4 => 4,
    };
    let mut reader = Reader::new(cfb, file_len);
    let root = reader.children("/").map_err(Error::Cfb)?;
    let looks_like_message = root.iter().any(|c| {
        let name = c.name.to_ascii_lowercase();
        name == PROPERTIES_STREAM
            || name.starts_with("__substg1.0_")
            || name.starts_with("__recip_version1.0_#")
            || name.starts_with("__attach_version1.0_#")
    });
    if !looks_like_message {
        return Err(Error::NotMessage);
    }
    let mut problems = Problems(problems);
    let named_properties = read_named_properties(&mut reader, &root, &mut problems);
    let message = Context {
        reader: &mut reader,
        named: &named_properties,
        options,
    }
    .read_message("/", &root, 0, None);
    Ok(MsgFile {
        clsid,
        cfb_version,
        named_properties,
        message,
        problems: problems.0,
    })
}

/// The length the FAT of a compound file header describes, if it is longer than the file
/// (and not absurdly so).
fn padded_len(header: &[u8; 512], file_len: u64) -> Option<u64> {
    let sector_len: u64 = match u16::from_le_bytes([header[0x1E], header[0x1F]]) {
        9 => 512,
        12 => 4096,
        _ => return None,
    };
    let fat_sectors = u64::from(u32::from_le_bytes([
        header[0x2C],
        header[0x2D],
        header[0x2E],
        header[0x2F],
    ]));
    let len = fat_sectors
        .checked_mul(sector_len / 4)?
        .checked_add(1)?
        .checked_mul(sector_len)?;
    (len > file_len && len <= file_len.saturating_mul(8).max(1 << 20)).then_some(len)
}

/// Reads `inner` and then zeros, up to `len` bytes.
struct ZeroPadded<R> {
    inner: R,
    inner_len: u64,
    len: u64,
    pos: u64,
}

impl<R: Read + Seek> Read for ZeroPadded<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pos >= self.len || buf.is_empty() {
            return Ok(0);
        }
        let left = usize::try_from(self.len - self.pos).unwrap_or(usize::MAX);
        let n = if self.pos < self.inner_len {
            let in_file = usize::try_from(self.inner_len - self.pos).unwrap_or(usize::MAX);
            let want = buf.len().min(in_file);
            self.inner.seek(SeekFrom::Start(self.pos))?;
            self.inner.read(&mut buf[..want])?
        } else {
            let want = buf.len().min(left);
            buf[..want].fill(0);
            want
        };
        self.pos += n as u64;
        Ok(n)
    }
}

impl<R: Read + Seek> Seek for ZeroPadded<R> {
    fn seek(&mut self, to: SeekFrom) -> io::Result<u64> {
        let pos = match to {
            SeekFrom::Start(p) => Some(p),
            SeekFrom::End(d) => self.len.checked_add_signed(d),
            SeekFrom::Current(d) => self.pos.checked_add_signed(d),
        };
        match pos {
            Some(p) => {
                self.pos = p;
                Ok(p)
            }
            None => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "seek before the start",
            )),
        }
    }
}

/// Reads `__nameid_version1.0` at the root.
fn read_named_properties<F: Read + Seek>(
    reader: &mut Reader<F>,
    root: &[reader::Child],
    problems: &mut Problems,
) -> NamedProperties {
    let Some(storage) = root
        .iter()
        .find(|c| !c.is_stream && c.name.eq_ignore_ascii_case(NAMEID_STORAGE))
    else {
        return NamedProperties::default();
    };
    let path = join("/", &storage.name);
    let children = match reader.children(&path) {
        Ok(c) => c,
        Err(e) => {
            problems.push(&path, ProblemKind::Storage, format!("cannot list: {e}"));
            return NamedProperties::default();
        }
    };
    let mut read = |name: &str| -> Vec<u8> {
        match children
            .iter()
            .find(|c| c.is_stream && c.name.eq_ignore_ascii_case(name))
        {
            Some(c) => reader.read(&join(&path, &c.name), problems).0,
            None => {
                problems.push(
                    &join(&path, name),
                    ProblemKind::NamedProperties,
                    "stream is missing",
                );
                Vec::new()
            }
        }
    };
    let guids = read("__substg1.0_00020102");
    let entries = read("__substg1.0_00030102");
    let strings = read("__substg1.0_00040102");
    NamedProperties::parse(&guids, &entries, &strings, &path, problems)
}
