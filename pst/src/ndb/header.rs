// Copyright (C) 2026 Shirofune Security Co., Ltd.
// Copyright (c) Microsoft Corporation.
//
// This file is changed from microsoft/outlook-pst-rs (https://github.com/microsoft/outlook-pst-rs) and its copy outlook-pst-ost 1.3.0
// (https://crates.io/crates/outlook-pst-ost), whose code is under the MIT License (LICENSE-MIT).
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

//! [HEADER](https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-pst/c9876f5a-664b-46a3-9887-ba63f113abf5)

use byteorder::{LittleEndian, ReadBytesExt};
use std::io::{self, Cursor, Read, Seek, SeekFrom};

use super::{block_id::*, read_write::*, root::*, *};
use crate::{
    AnsiPstFile, PstFile, UnicodePstFile,
    crc::compute_crc,
    problems::{self, ProblemKind},
};

/// A header field with a value MS-PST does not allow: a problem when reading leniently, else
/// `error`.
fn check_field(
    valid: bool,
    field: &str,
    value: impl std::fmt::Debug,
    error: impl FnOnce() -> NdbError,
) -> io::Result<()> {
    if valid {
        return Ok(());
    }
    problems::check(
        ProblemKind::HeaderField,
        Some(0),
        || format!("{field} is {value:?}"),
        || error().into(),
    )
}

/// The client versions in wVerClient: 19 (MS-PST), and 12, which Outlook writes in OSTs.
fn valid_client_version(version: u16) -> bool {
    version == NDB_CLIENT_VERSION || version == NDB_CLIENT_VERSION_OST
}

/// `dwMagic`
///
/// ### See also
/// [Header]
const HEADER_MAGIC: u32 = u32::from_be_bytes(*b"NDB!");

const HEADER_MAGIC_CLIENT: u16 = u16::from_be_bytes(*b"MS");
/// `wMagicClient` of an OST file.
const HEADER_MAGIC_CLIENT_OST: u16 = u16::from_be_bytes(*b"OS");

/// `wVer`
///
/// ### See also
/// [Header]
#[repr(u16)]
#[derive(Copy, Clone, PartialEq, Eq, Default, Debug)]
pub enum NdbVersion {
    Ansi = 15,
    #[default]
    Unicode = 23,
    /// The Unicode layout with 4 KiB pages, 512-byte block alignment, 24-byte block trailers and
    /// zlib-compressed blocks, which Outlook 2013 and later use for OST files. Read-only.
    Unicode4k = 36,
}

impl TryFrom<u16> for NdbVersion {
    type Error = NdbError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            14..=15 => Ok(NdbVersion::Ansi),
            23 => Ok(NdbVersion::Unicode),
            36 => Ok(NdbVersion::Unicode4k),
            _ => Err(NdbError::InvalidNdbVersion(value)),
        }
    }
}

const NDB_CLIENT_VERSION: u16 = 19;
/// `wVerClient` in OSTs written by Outlook, in both the 512-byte and the 4 KiB layout.
const NDB_CLIENT_VERSION_OST: u16 = 12;
const NDB_PLATFORM_CREATE: u8 = 0x01;
const NDB_PLATFORM_ACCESS: u8 = 0x01;
const NDB_DEFAULT_NIDS: [u32; 32] = [
    0x400, 0x400, 0x400, 0x4000, 0x10000, 0x400, 0x400, 0x400, 0x8000, 0x400, 0x400, 0x400, 0x400,
    0x400, 0x400, 0x400, 0x400, 0x400, 0x400, 0x400, 0x400, 0x400, 0x400, 0x400, 0x400, 0x400,
    0x400, 0x400, 0x400, 0x400, 0x400, 0x400,
];
const NDB_SENTINEL: u8 = 0x80;

/// `bCryptMethod`
///
/// ### See also
/// [Header]
#[repr(u8)]
#[derive(Copy, Clone, PartialEq, Eq, Default, Debug)]
pub enum NdbCryptMethod {
    /// `NDB_CRYPT_NONE`: Data blocks are not encoded
    #[default]
    None = 0x00,
    /// `NDB_CRYPT_PERMUTE`: Encoded with the [Permutation algorithm](https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-pst/5faf4800-645d-49d1-9457-2ac40eb467bd)
    Permute = 0x01,
    /// `NDB_CRYPT_CYCLIC`: Encoded with the [Cyclic algorithm](https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-pst/9979fc01-0a3e-496f-900f-a6a867951f23)
    Cyclic = 0x02,
}

impl TryFrom<u8> for NdbCryptMethod {
    type Error = NdbError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(NdbCryptMethod::None),
            0x01 => Ok(NdbCryptMethod::Permute),
            0x02 => Ok(NdbCryptMethod::Cyclic),
            _ => Err(NdbError::InvalidNdbCryptMethod(value)),
        }
    }
}

pub trait Header<Pst>: Clone
where
    Pst: PstFile,
{
    fn version(&self) -> NdbVersion;
    fn crypt_method(&self) -> NdbCryptMethod;
    fn next_block(&self) -> <Pst as PstFile>::BlockId;
    fn next_page(&self) -> <Pst as PstFile>::PageId;
    fn unique_value(&self) -> u32;
    fn root(&self) -> &<Pst as PstFile>::Root;
    fn root_mut(&mut self) -> &mut <Pst as PstFile>::Root;
}

#[derive(Clone, Debug)]
pub struct UnicodeHeader {
    version: NdbVersion,
    next_page: UnicodePageId,
    unique: u32,
    nids: [u32; 32],
    root: UnicodeRoot,
    free_map: [u8; 128],
    free_page_map: [u8; 128],
    crypt_method: NdbCryptMethod,
    next_block: UnicodeBlockId,

    // Kept as read, for Debug output.
    #[allow(dead_code)]
    reserved1: u32,
    #[allow(dead_code)]
    reserved2: u32,
    #[allow(dead_code)]
    unused1: u64,
    #[allow(dead_code)]
    unused2: u64,
    #[allow(dead_code)]
    reserved3: [u8; 36],
}

impl UnicodeHeader {
    pub fn new(root: UnicodeRoot, crypt_method: NdbCryptMethod) -> Self {
        Self {
            version: NdbVersion::Unicode,
            next_page: UnicodePageId::from(1),
            unique: 0,
            nids: NDB_DEFAULT_NIDS,
            root,
            free_map: [0xFF; 128],
            free_page_map: [0xFF; 128],
            crypt_method,
            next_block: UnicodeBlockId::from(4),
            reserved1: 0,
            reserved2: 0,
            unused1: 0,
            unused2: 0,
            reserved3: [0; 36],
        }
    }

    /// `rgnid`: the next free node index of each `nidType`.
    pub fn nids(&self) -> &[u32; 32] {
        &self.nids
    }

    /// `rgbFM`: the deprecated FMap of the first 128 AMap pages.
    pub fn free_map(&self) -> &[u8; 128] {
        &self.free_map
    }

    /// `rgbFP`: the deprecated FPMap of the first 128 PMap pages.
    pub fn free_page_map(&self) -> &[u8; 128] {
        &self.free_page_map
    }
}

impl Header<UnicodePstFile> for UnicodeHeader {
    fn version(&self) -> NdbVersion {
        self.version
    }

    fn crypt_method(&self) -> NdbCryptMethod {
        self.crypt_method
    }

    fn next_block(&self) -> <UnicodePstFile as PstFile>::BlockId {
        self.next_block
    }

    fn next_page(&self) -> <UnicodePstFile as PstFile>::PageId {
        self.next_page
    }

    fn unique_value(&self) -> u32 {
        self.unique
    }

    fn root(&self) -> &<UnicodePstFile as PstFile>::Root {
        &self.root
    }

    fn root_mut(&mut self) -> &mut <UnicodePstFile as PstFile>::Root {
        &mut self.root
    }
}

impl HeaderReadWrite<UnicodePstFile> for UnicodeHeader {
    fn read(f: &mut dyn Read) -> io::Result<Self> {
        // dwMagic
        let magic = f.read_u32::<LittleEndian>()?;
        if magic != HEADER_MAGIC {
            return Err(NdbError::InvalidNdbHeaderMagicValue(magic).into());
        }

        // dwCRCPartial
        let crc_partial = f.read_u32::<LittleEndian>()?;

        let mut crc_data = [0_u8; 516];
        let (partial, rest) = crc_data.split_at_mut(471);
        f.read_exact(partial)?;
        problems::check_crc(
            ProblemKind::HeaderCrc,
            Some(0),
            "HEADER dwCRCPartial",
            crc_partial,
            compute_crc(0, partial),
            || NdbError::InvalidNdbHeaderPartialCrc(crc_partial).into(),
        )?;

        let mut cursor = Cursor::new(&*partial);

        // wMagicClient
        let magic = cursor.read_u16::<LittleEndian>()?;
        check_field(
            magic == HEADER_MAGIC_CLIENT || magic == HEADER_MAGIC_CLIENT_OST,
            "HEADER wMagicClient",
            magic,
            || NdbError::InvalidNdbHeaderMagicClientValue(magic),
        )?;

        // wVer
        let ndb_version = NdbVersion::try_from(cursor.read_u16::<LittleEndian>()?)?;
        if ndb_version == NdbVersion::Ansi {
            return Err(NdbError::AnsiPstVersion(ndb_version as u16).into());
        }

        f.read_exact(rest)?;

        // dwCRCFull
        let crc_full = f.read_u32::<LittleEndian>()?;
        problems::check_crc(
            ProblemKind::HeaderCrc,
            Some(0),
            "HEADER dwCRCFull",
            crc_full,
            compute_crc(0, &crc_data),
            || NdbError::InvalidNdbHeaderFullCrc(crc_full).into(),
        )?;

        let mut cursor = Cursor::new(crc_data);
        cursor.seek(SeekFrom::Start(4))?;

        // wVerClient: 12 in OSTs.
        let version = cursor.read_u16::<LittleEndian>()?;
        check_field(
            valid_client_version(version),
            "HEADER wVerClient",
            version,
            || NdbError::InvalidNdbHeaderClientVersion(version),
        )?;

        // bPlatformCreate
        let platform_create = cursor.read_u8()?;
        check_field(
            platform_create == NDB_PLATFORM_CREATE,
            "HEADER bPlatformCreate",
            platform_create,
            || NdbError::InvalidNdbHeaderPlatformCreate(platform_create),
        )?;

        // bPlatformAccess
        let platform_access = cursor.read_u8()?;
        check_field(
            platform_access == NDB_PLATFORM_ACCESS,
            "HEADER bPlatformAccess",
            platform_access,
            || NdbError::InvalidNdbHeaderPlatformAccess(platform_access),
        )?;

        // dwReserved1
        let reserved1 = cursor.read_u32::<LittleEndian>()?;

        // dwReserved2
        let reserved2 = cursor.read_u32::<LittleEndian>()?;

        // bidUnused
        let unused1 = cursor.read_u64::<LittleEndian>()?;

        // bidNextP
        let next_page = UnicodePageId::read(&mut cursor)?;

        // dwUnique
        let unique = cursor.read_u32::<LittleEndian>()?;

        // rgnid
        let mut nids = [0_u32; 32];
        for nid in nids.iter_mut() {
            *nid = cursor.read_u32::<LittleEndian>()?;
        }

        // qwUnused
        let unused2 = cursor.read_u64::<LittleEndian>()?;

        // root
        let root = UnicodeRoot::read(&mut cursor)?;

        // dwAlign
        let align = cursor.read_u32::<LittleEndian>()?;
        check_field(align == 0, "HEADER dwAlign", align, || {
            NdbError::InvalidNdbHeaderAlignValue(align)
        })?;

        // rgbFM
        let mut free_map = [0; 128];
        cursor.read_exact(&mut free_map)?;

        // rgbFP
        let mut free_page_map = [0; 128];
        cursor.read_exact(&mut free_page_map)?;

        // bSentinel
        let sentinel = cursor.read_u8()?;
        check_field(
            sentinel == NDB_SENTINEL,
            "HEADER bSentinel",
            sentinel,
            || NdbError::InvalidNdbHeaderSentinelValue(sentinel),
        )?;

        // bCryptMethod
        let crypt_method = NdbCryptMethod::try_from(cursor.read_u8()?)?;

        // rgbReserved
        let reserved = cursor.read_u16::<LittleEndian>()?;
        check_field(reserved == 0, "HEADER rgbReserved", reserved, || {
            NdbError::InvalidNdbHeaderReservedValue(reserved)
        })?;

        // bidNextB
        let next_block = UnicodeBlockId::read(&mut cursor)?;

        // rgbReserved2, bReserved, rgbReserved3 (total 36 bytes)
        let mut reserved3 = [0_u8; 36];
        f.read_exact(&mut reserved3)?;

        Ok(Self {
            version: ndb_version,
            next_page,
            unique,
            nids,
            root,
            free_map,
            free_page_map,
            crypt_method,
            next_block,
            reserved1,
            reserved2,
            unused1,
            unused2,
            reserved3,
        })
    }
}

#[derive(Clone, Debug)]
pub struct AnsiHeader {
    next_block: AnsiBlockId,
    next_page: AnsiPageId,
    unique: u32,
    nids: [u32; 32],
    root: AnsiRoot,
    free_map: [u8; 128],
    free_page_map: [u8; 128],
    crypt_method: NdbCryptMethod,

    // Kept as read, for Debug output.
    #[allow(dead_code)]
    reserved1: u32,
    #[allow(dead_code)]
    reserved2: u32,
    #[allow(dead_code)]
    reserved3: [u8; 36],
}

impl AnsiHeader {
    pub fn new(root: AnsiRoot, crypt_method: NdbCryptMethod) -> Self {
        Self {
            next_block: AnsiBlockId::from(4),
            next_page: AnsiPageId::from(1),
            unique: 0,
            nids: NDB_DEFAULT_NIDS,
            root,
            free_map: [0xFF; 128],
            free_page_map: [0xFF; 128],
            crypt_method,
            reserved1: 0,
            reserved2: 0,
            reserved3: [0; 36],
        }
    }

    /// `rgnid`: the next free node index of each `nidType`.
    pub fn nids(&self) -> &[u32; 32] {
        &self.nids
    }

    /// `rgbFM`: the deprecated FMap of the first 128 AMap pages.
    pub fn free_map(&self) -> &[u8; 128] {
        &self.free_map
    }

    /// `rgbFP`: the deprecated FPMap of the first 128 PMap pages.
    pub fn free_page_map(&self) -> &[u8; 128] {
        &self.free_page_map
    }
}

impl Header<AnsiPstFile> for AnsiHeader {
    fn version(&self) -> NdbVersion {
        NdbVersion::Ansi
    }

    fn crypt_method(&self) -> NdbCryptMethod {
        self.crypt_method
    }

    fn next_block(&self) -> <AnsiPstFile as PstFile>::BlockId {
        self.next_block
    }

    fn next_page(&self) -> <AnsiPstFile as PstFile>::PageId {
        self.next_page
    }

    fn unique_value(&self) -> u32 {
        self.unique
    }

    fn root(&self) -> &<AnsiPstFile as PstFile>::Root {
        &self.root
    }

    fn root_mut(&mut self) -> &mut <AnsiPstFile as PstFile>::Root {
        &mut self.root
    }
}

impl HeaderReadWrite<AnsiPstFile> for AnsiHeader {
    fn read(f: &mut dyn Read) -> io::Result<Self> {
        // dwMagic
        let magic = f.read_u32::<LittleEndian>()?;
        if magic != HEADER_MAGIC {
            return Err(NdbError::InvalidNdbHeaderMagicValue(magic).into());
        }

        // dwCRCPartial
        let crc_partial = f.read_u32::<LittleEndian>()?;

        let mut crc_data = [0_u8; 504];
        f.read_exact(&mut crc_data)?;
        let (partial, _) = crc_data.split_at(471);
        problems::check_crc(
            ProblemKind::HeaderCrc,
            Some(0),
            "HEADER dwCRCPartial",
            crc_partial,
            compute_crc(0, partial),
            || NdbError::InvalidNdbHeaderPartialCrc(crc_partial).into(),
        )?;

        let mut cursor = Cursor::new(crc_data);

        // wMagicClient
        let magic = cursor.read_u16::<LittleEndian>()?;
        check_field(
            magic == HEADER_MAGIC_CLIENT || magic == HEADER_MAGIC_CLIENT_OST,
            "HEADER wMagicClient",
            magic,
            || NdbError::InvalidNdbHeaderMagicClientValue(magic),
        )?;

        // wVer
        let version = NdbVersion::try_from(cursor.read_u16::<LittleEndian>()?)?;
        if version != NdbVersion::Ansi {
            return Err(NdbError::UnicodePstVersion(version as u16).into());
        }

        // wVerClient
        let version = cursor.read_u16::<LittleEndian>()?;
        check_field(
            valid_client_version(version),
            "HEADER wVerClient",
            version,
            || NdbError::InvalidNdbHeaderClientVersion(version),
        )?;

        // bPlatformCreate
        let platform_create = cursor.read_u8()?;
        check_field(
            platform_create == NDB_PLATFORM_CREATE,
            "HEADER bPlatformCreate",
            platform_create,
            || NdbError::InvalidNdbHeaderPlatformCreate(platform_create),
        )?;

        // bPlatformAccess
        let platform_access = cursor.read_u8()?;
        check_field(
            platform_access == NDB_PLATFORM_ACCESS,
            "HEADER bPlatformAccess",
            platform_access,
            || NdbError::InvalidNdbHeaderPlatformAccess(platform_access),
        )?;

        // dwReserved1
        let reserved1 = cursor.read_u32::<LittleEndian>()?;

        // dwReserved2
        let reserved2 = cursor.read_u32::<LittleEndian>()?;

        // bidNextB
        let next_block = AnsiBlockId::read(&mut cursor)?;

        // bidNextP
        let next_page = AnsiPageId::read(&mut cursor)?;

        // dwUnique
        let unique = cursor.read_u32::<LittleEndian>()?;

        // rgnid
        let mut nids = [0_u32; 32];
        for nid in nids.iter_mut() {
            *nid = cursor.read_u32::<LittleEndian>()?;
        }

        // root
        let root = AnsiRoot::read(&mut cursor)?;

        // rgbFM
        let mut free_map = [0; 128];
        cursor.read_exact(&mut free_map)?;

        // rgbFP
        let mut free_page_map = [0; 128];
        cursor.read_exact(&mut free_page_map)?;

        // bSentinel
        let sentinel = cursor.read_u8()?;
        check_field(
            sentinel == NDB_SENTINEL,
            "HEADER bSentinel",
            sentinel,
            || NdbError::InvalidNdbHeaderSentinelValue(sentinel),
        )?;

        // bCryptMethod
        let crypt_method = NdbCryptMethod::try_from(cursor.read_u8()?)?;

        // rgbReserved
        let reserved = cursor.read_u16::<LittleEndian>()?;
        check_field(reserved == 0, "HEADER rgbReserved", reserved, || {
            NdbError::InvalidNdbHeaderReservedValue(reserved)
        })?;

        // ullReserved, dwReserved (total 12 bytes)
        let mut reserved = [0_u8; 12];
        cursor.read_exact(&mut reserved)?;
        check_field(
            reserved == [0; 12],
            "HEADER ullReserved and dwReserved",
            reserved,
            || NdbError::InvalidNdbHeaderAnsiReservedBytes,
        )?;

        // rgbReserved2, bReserved, rgbReserved3 (total 36 bytes)
        let mut reserved3 = [0_u8; 36];
        cursor.read_exact(&mut reserved3)?;

        Ok(Self {
            next_page,
            unique,
            nids,
            root,
            free_map,
            free_page_map,
            crypt_method,
            next_block,
            reserved1,
            reserved2,
            reserved3,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_magic_values() {
        assert_eq!(HEADER_MAGIC, 0x4E444221);
        assert_eq!(HEADER_MAGIC_CLIENT, 0x4D53);
    }
}
