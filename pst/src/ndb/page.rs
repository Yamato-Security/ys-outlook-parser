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

//! [Pages](https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-pst/5774b4f2-cdc4-453e-996a-8c8230116930)

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use core::mem;
use std::{
    fmt::Debug,
    io::{self, Cursor, Read, Seek, SeekFrom, Write},
    marker::PhantomData,
};

use super::{block_id::*, block_ref::*, byte_index::*, node_id::*, read_write::*, *};
use crate::{
    AnsiPstFile, PstFile, PstReader, UnicodePstFile, block_sig::compute_sig, crc::compute_crc,
};

/// `ptype`
///
/// ### See also
/// [PageTrailer]
#[repr(u8)]
#[derive(Copy, Clone, PartialEq, Eq, Default, Debug)]
pub enum PageType {
    #[default]
    None = 0x00,
    /// `ptypeBBT`: Block BTree page
    BlockBTree = 0x80,
    /// `ptypeNBT`: Node BTree page
    NodeBTree = 0x81,
    /// `ptypeFMap`: Free Map page
    FreeMap = 0x82,
    /// `ptypePMap`: Allocation Page Map page
    AllocationPageMap = 0x83,
    /// `ptypeAMap`: Allocation Map page
    AllocationMap = 0x84,
    /// `ptypeFPMap`: Free Page Map page
    FreePageMap = 0x85,
    /// `ptypeDL`: Density List page
    DensityList = 0x86,
}

impl TryFrom<u8> for PageType {
    type Error = NdbError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x80 => Ok(PageType::BlockBTree),
            0x81 => Ok(PageType::NodeBTree),
            0x82 => Ok(PageType::FreeMap),
            0x83 => Ok(PageType::AllocationPageMap),
            0x84 => Ok(PageType::AllocationMap),
            0x85 => Ok(PageType::FreePageMap),
            0x86 => Ok(PageType::DensityList),
            _ => Err(NdbError::InvalidPageType(value)),
        }
    }
}

impl PageType {
    pub fn signature(&self, index: u64, block_id: u64) -> u16 {
        match self {
            PageType::BlockBTree | PageType::NodeBTree | PageType::DensityList => compute_sig(
                (index & u64::from(u32::MAX)) as u32,
                (block_id & u64::from(u32::MAX)) as u32,
            ),
            _ => 0,
        }
    }
}

pub const PAGE_SIZE: usize = 512;

/// [PAGETRAILER](https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-pst/f4ccb38a-930a-4db4-98df-a69c195926ba)
pub trait PageTrailer {
    type BlockId: BlockId + Debug;

    fn page_type(&self) -> PageType;
    fn signature(&self) -> u16;
    fn crc(&self) -> u32;
    fn block_id(&self) -> Self::BlockId;
}

#[derive(Copy, Clone, Default)]
pub struct UnicodePageTrailer {
    page_type: PageType,
    signature: u16,
    crc: u32,
    block_id: UnicodePageId,
}

impl PageTrailer for UnicodePageTrailer {
    type BlockId = UnicodePageId;

    fn page_type(&self) -> PageType {
        self.page_type
    }

    fn signature(&self) -> u16 {
        self.signature
    }

    fn crc(&self) -> u32 {
        self.crc
    }

    fn block_id(&self) -> UnicodePageId {
        self.block_id
    }
}

impl PageTrailerReadWrite for UnicodePageTrailer {
    fn new(page_type: PageType, signature: u16, block_id: UnicodePageId, crc: u32) -> Self {
        Self {
            page_type,
            block_id,
            signature,
            crc,
        }
    }

    fn read(f: &mut dyn Read) -> io::Result<Self> {
        let mut page_type = [0_u8; 2];
        f.read_exact(&mut page_type)?;
        if page_type[0] != page_type[1] {
            return Err(NdbError::MismatchPageTypeRepeat(page_type[0], page_type[1]).into());
        }
        let page_type = PageType::try_from(page_type[0])?;
        let signature = f.read_u16::<LittleEndian>()?;
        let crc = f.read_u32::<LittleEndian>()?;
        let block_id = UnicodePageId::read(f)?;

        Ok(Self {
            page_type,
            signature,
            crc,
            block_id,
        })
    }

    fn write(&self, f: &mut dyn Write) -> io::Result<()> {
        f.write_all(&[self.page_type as u8; 2])?;
        f.write_u16::<LittleEndian>(self.signature)?;
        f.write_u32::<LittleEndian>(self.crc)?;
        self.block_id.write(f)
    }
}

#[derive(Copy, Clone, Default)]
pub struct AnsiPageTrailer {
    page_type: PageType,
    signature: u16,
    block_id: AnsiPageId,
    crc: u32,
}

impl PageTrailer for AnsiPageTrailer {
    type BlockId = AnsiPageId;

    fn page_type(&self) -> PageType {
        self.page_type
    }

    fn signature(&self) -> u16 {
        self.signature
    }

    fn crc(&self) -> u32 {
        self.crc
    }

    fn block_id(&self) -> AnsiPageId {
        self.block_id
    }
}

impl PageTrailerReadWrite for AnsiPageTrailer {
    fn new(page_type: PageType, signature: u16, block_id: AnsiPageId, crc: u32) -> Self {
        Self {
            page_type,
            crc,
            block_id,
            signature,
        }
    }

    fn read(f: &mut dyn Read) -> io::Result<Self> {
        let mut page_type = [0_u8; 2];
        f.read_exact(&mut page_type)?;
        if page_type[0] != page_type[1] {
            return Err(NdbError::MismatchPageTypeRepeat(page_type[0], page_type[1]).into());
        }
        let page_type = PageType::try_from(page_type[0])?;
        let signature = f.read_u16::<LittleEndian>()?;
        let block_id = AnsiPageId::read(f)?;
        let crc = f.read_u32::<LittleEndian>()?;

        Ok(Self {
            page_type,
            signature,
            block_id,
            crc,
        })
    }

    fn write(&self, f: &mut dyn Write) -> io::Result<()> {
        f.write_all(&[self.page_type as u8; 2])?;
        f.write_u16::<LittleEndian>(self.signature)?;
        self.block_id.write(f)?;
        f.write_u32::<LittleEndian>(self.crc)
    }
}

pub type MapBits = [u8; 496];

pub trait MapPage<Pst, const PAGE_TYPE: u8>
where
    Pst: PstFile,
{
    fn map_bits(&self) -> &MapBits;
    fn map_bits_mut(&mut self) -> &mut MapBits;
    fn trailer(&self) -> &Pst::PageTrailer;
}

/// [AMAPPAGE](https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-pst/43d8f556-2c0e-4976-8ec7-84e57f8b1234)
pub trait AllocationMapPage<Pst>: MapPage<Pst, { PageType::AllocationMap as u8 }>
where
    Pst: PstFile,
{
}

impl<Pst, Page> AllocationMapPage<Pst> for Page
where
    Pst: PstFile,
    Page: MapPage<Pst, { PageType::AllocationMap as u8 }>,
{
}

/// [PMAPPAGE](https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-pst/7e64a91f-cbd1-4a11-90c9-df5789e7d9a1)
pub trait AllocationPageMapPage<Pst>: MapPage<Pst, { PageType::AllocationPageMap as u8 }>
where
    Pst: PstFile,
{
}

impl<Pst, Page> AllocationPageMapPage<Pst> for Page
where
    Pst: PstFile,
    Page: MapPage<Pst, { PageType::AllocationPageMap as u8 }>,
{
}

/// [FMAPPAGE](https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-pst/26273ead-797e-4ea6-9b3c-9b9a5c581115)
pub trait FreeMapPage<Pst>: MapPage<Pst, { PageType::FreeMap as u8 }>
where
    Pst: PstFile,
{
}

impl<Pst, Page> FreeMapPage<Pst> for Page
where
    Pst: PstFile,
    Page: MapPage<Pst, { PageType::FreeMap as u8 }>,
{
}

/// [FPMAPPAGE](https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-pst/913a72b0-83f6-4c29-8b0b-40967579a534)
pub trait FreePageMapPage<Pst>: MapPage<Pst, { PageType::FreePageMap as u8 }>
where
    Pst: PstFile,
{
}

impl<Pst, Page> FreePageMapPage<Pst> for Page
where
    Pst: PstFile,
    Page: MapPage<Pst, { PageType::FreePageMap as u8 }>,
{
}

pub struct UnicodeMapPage<const P: u8> {
    map_bits: MapBits,
    trailer: UnicodePageTrailer,
}

impl<const PAGE_TYPE: u8> MapPage<UnicodePstFile, PAGE_TYPE> for UnicodeMapPage<PAGE_TYPE> {
    fn map_bits(&self) -> &MapBits {
        &self.map_bits
    }

    fn map_bits_mut(&mut self) -> &mut MapBits {
        &mut self.map_bits
    }

    fn trailer(&self) -> &UnicodePageTrailer {
        &self.trailer
    }
}

impl<const PAGE_TYPE: u8> MapPageReadWrite<UnicodePstFile, PAGE_TYPE>
    for UnicodeMapPage<PAGE_TYPE>
{
    fn new(map_bits: MapBits, trailer: UnicodePageTrailer) -> NdbResult<Self> {
        if trailer.page_type() as u8 != PAGE_TYPE {
            return Err(NdbError::UnexpectedPageType(trailer.page_type()));
        }
        Ok(Self { map_bits, trailer })
    }

    fn read(f: &mut dyn Read) -> io::Result<Self> {
        let mut map_bits = [0_u8; mem::size_of::<MapBits>()];
        f.read_exact(&mut map_bits)?;

        let trailer = UnicodePageTrailer::read(f)?;
        if trailer.page_type() as u8 != PAGE_TYPE {
            return Err(NdbError::UnexpectedPageType(trailer.page_type()).into());
        }

        let crc = compute_crc(0, &map_bits);
        if crc != trailer.crc() {
            return Err(NdbError::InvalidPageCrc(crc).into());
        }

        Ok(Self { map_bits, trailer })
    }
}

pub struct AnsiMapPage<const P: u8> {
    map_bits: MapBits,
    trailer: AnsiPageTrailer,
    // Kept as read.
    #[allow(dead_code)]
    padding: u32,
}

impl<const PAGE_TYPE: u8> MapPage<AnsiPstFile, PAGE_TYPE> for AnsiMapPage<PAGE_TYPE> {
    fn map_bits(&self) -> &MapBits {
        &self.map_bits
    }

    fn map_bits_mut(&mut self) -> &mut MapBits {
        &mut self.map_bits
    }

    fn trailer(&self) -> &AnsiPageTrailer {
        &self.trailer
    }
}

impl MapPageReadWrite<AnsiPstFile, { PageType::AllocationMap as u8 }>
    for AnsiMapPage<{ PageType::AllocationMap as u8 }>
{
    fn new(amap_bits: MapBits, trailer: AnsiPageTrailer) -> NdbResult<Self> {
        if trailer.page_type() != PageType::AllocationMap {
            return Err(NdbError::UnexpectedPageType(trailer.page_type()));
        }
        Ok(Self {
            map_bits: amap_bits,
            trailer,
            padding: 0,
        })
    }

    fn read(f: &mut dyn Read) -> io::Result<Self> {
        let mut buffer = [0_u8; 500];
        f.read_exact(&mut buffer)?;
        let mut cursor = Cursor::new(buffer);

        let padding = cursor.read_u32::<LittleEndian>()?;

        let mut map_bits = [0_u8; mem::size_of::<MapBits>()];
        cursor.read_exact(&mut map_bits)?;

        let buffer = cursor.into_inner();

        let trailer = AnsiPageTrailer::read(f)?;
        if trailer.page_type() != PageType::AllocationMap {
            return Err(NdbError::UnexpectedPageType(trailer.page_type()).into());
        }

        let crc = compute_crc(0, &buffer);
        if crc != trailer.crc() {
            return Err(NdbError::InvalidPageCrc(crc).into());
        }

        Ok(Self {
            map_bits,
            trailer,
            padding,
        })
    }
}

impl MapPageReadWrite<AnsiPstFile, { PageType::AllocationPageMap as u8 }>
    for AnsiMapPage<{ PageType::AllocationPageMap as u8 }>
{
    fn new(amap_bits: MapBits, trailer: AnsiPageTrailer) -> NdbResult<Self> {
        if trailer.page_type() != PageType::AllocationPageMap {
            return Err(NdbError::UnexpectedPageType(trailer.page_type()));
        }
        Ok(Self {
            map_bits: amap_bits,
            trailer,
            padding: 0,
        })
    }

    fn read(f: &mut dyn Read) -> io::Result<Self> {
        let mut buffer = [0_u8; 500];
        f.read_exact(&mut buffer)?;
        let mut cursor = Cursor::new(buffer);

        let padding = cursor.read_u32::<LittleEndian>()?;

        let mut map_bits = [0_u8; mem::size_of::<MapBits>()];
        cursor.read_exact(&mut map_bits)?;

        let buffer = cursor.into_inner();

        let trailer = AnsiPageTrailer::read(f)?;
        if trailer.page_type() != PageType::AllocationPageMap {
            return Err(NdbError::UnexpectedPageType(trailer.page_type()).into());
        }

        let crc = compute_crc(0, &buffer);
        if crc != trailer.crc() {
            return Err(NdbError::InvalidPageCrc(crc).into());
        }

        Ok(Self {
            map_bits,
            trailer,
            padding,
        })
    }
}

impl MapPageReadWrite<AnsiPstFile, { PageType::FreeMap as u8 }>
    for AnsiMapPage<{ PageType::FreeMap as u8 }>
{
    fn new(amap_bits: MapBits, trailer: AnsiPageTrailer) -> NdbResult<Self> {
        if trailer.page_type() != PageType::FreeMap {
            return Err(NdbError::UnexpectedPageType(trailer.page_type()));
        }
        Ok(Self {
            map_bits: amap_bits,
            trailer,
            padding: 0,
        })
    }

    fn read(f: &mut dyn Read) -> io::Result<Self> {
        let mut buffer = [0_u8; 500];
        f.read_exact(&mut buffer)?;
        let mut cursor = Cursor::new(buffer);

        let mut map_bits = [0_u8; mem::size_of::<MapBits>()];
        cursor.read_exact(&mut map_bits)?;

        let padding = cursor.read_u32::<LittleEndian>()?;

        let buffer = cursor.into_inner();

        let trailer = AnsiPageTrailer::read(f)?;
        if trailer.page_type() != PageType::FreeMap {
            return Err(NdbError::UnexpectedPageType(trailer.page_type()).into());
        }

        let crc = compute_crc(0, &buffer);
        if crc != trailer.crc() {
            return Err(NdbError::InvalidPageCrc(crc).into());
        }

        Ok(Self {
            map_bits,
            trailer,
            padding,
        })
    }
}

impl MapPageReadWrite<AnsiPstFile, { PageType::FreePageMap as u8 }>
    for AnsiMapPage<{ PageType::FreePageMap as u8 }>
{
    fn new(amap_bits: MapBits, trailer: AnsiPageTrailer) -> NdbResult<Self> {
        if trailer.page_type() != PageType::FreePageMap {
            return Err(NdbError::UnexpectedPageType(trailer.page_type()));
        }
        Ok(Self {
            map_bits: amap_bits,
            trailer,
            padding: 0,
        })
    }

    fn read(f: &mut dyn Read) -> io::Result<Self> {
        let mut buffer = [0_u8; 500];
        f.read_exact(&mut buffer)?;
        let mut cursor = Cursor::new(buffer);

        let mut map_bits = [0_u8; mem::size_of::<MapBits>()];
        cursor.read_exact(&mut map_bits)?;

        let padding = cursor.read_u32::<LittleEndian>()?;

        let buffer = cursor.into_inner();

        let trailer = AnsiPageTrailer::read(f)?;
        if trailer.page_type() != PageType::FreePageMap {
            return Err(NdbError::UnexpectedPageType(trailer.page_type()).into());
        }

        let crc = compute_crc(0, &buffer);
        if crc != trailer.crc() {
            return Err(NdbError::InvalidPageCrc(crc).into());
        }

        Ok(Self {
            map_bits,
            trailer,
            padding,
        })
    }
}

const DENSITY_LIST_ENTRY_PAGE_NUMBER_MASK: u32 = 0x000F_FFFF;

/// [DLISTPAGEENT](https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-pst/9d3c45b9-a415-446c-954f-b1b473dbb415)
#[derive(Copy, Clone, Debug)]
pub struct DensityListPageEntry(u32);

impl DensityListPageEntry {
    pub fn new(page: u32, free_slots: u16) -> NdbResult<Self> {
        if page & !0x000F_FFFF != 0 {
            return Err(NdbError::InvalidDensityListEntryPageNumber(page));
        };
        if free_slots & !0x0FFF != 0 {
            return Err(NdbError::InvalidDensityListEntryFreeSlots(free_slots));
        };

        Ok(Self(page | ((free_slots as u32) << 20)))
    }

    pub fn read(f: &mut dyn Read) -> io::Result<Self> {
        Ok(Self(f.read_u32::<LittleEndian>()?))
    }

    pub fn write(&self, f: &mut dyn Write) -> io::Result<()> {
        f.write_u32::<LittleEndian>(self.0)
    }

    pub fn page(&self) -> u32 {
        self.0 & DENSITY_LIST_ENTRY_PAGE_NUMBER_MASK
    }

    pub fn free_slots(&self) -> u16 {
        (self.0 >> 20) as u16
    }
}

pub const DENSITY_LIST_FILE_OFFSET: u64 = 0x4200;

/// [DLISTPAGE](https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-pst/5d426b2d-ec10-4614-b768-46813652d5e3)
pub trait DensityListPage<Pst>
where
    Pst: PstFile,
{
    fn backfill_complete(&self) -> bool;
    fn current_page(&self) -> u32;
    fn entries(&self) -> &[DensityListPageEntry];
    fn trailer(&self) -> &<Pst as PstFile>::PageTrailer;
}

pub struct UnicodeDensityListPage {
    backfill_complete: bool,
    current_page: u32,
    entry_count: u8,
    entries:
        [DensityListPageEntry; <Self as DensityListPageReadWrite<UnicodePstFile>>::MAX_ENTRIES],
    trailer: UnicodePageTrailer,
}

impl DensityListPage<UnicodePstFile> for UnicodeDensityListPage {
    fn backfill_complete(&self) -> bool {
        self.backfill_complete
    }

    fn current_page(&self) -> u32 {
        self.current_page
    }

    fn entries(&self) -> &[DensityListPageEntry] {
        self.entries
            .get(..usize::from(self.entry_count))
            .unwrap_or_default()
    }

    fn trailer(&self) -> &UnicodePageTrailer {
        &self.trailer
    }
}

impl DensityListPageReadWrite<UnicodePstFile> for UnicodeDensityListPage {
    const MAX_ENTRIES: usize = 476 / mem::size_of::<DensityListPageEntry>();

    fn new(
        backfill_complete: bool,
        current_page: u32,
        entries: &[DensityListPageEntry],
        trailer: UnicodePageTrailer,
    ) -> NdbResult<Self> {
        if entries.len() > Self::MAX_ENTRIES {
            return Err(NdbError::InvalidDensityListEntryCount(entries.len()));
        }

        if trailer.page_type() != PageType::DensityList {
            return Err(NdbError::UnexpectedPageType(trailer.page_type()));
        }

        let entry_count = entries.len() as u8;

        let mut buffer = [DensityListPageEntry(0); Self::MAX_ENTRIES];
        for (entry, value) in buffer.iter_mut().zip(entries) {
            *entry = *value;
        }
        let entries = buffer;

        Ok(Self {
            backfill_complete,
            current_page,
            entry_count,
            entries,
            trailer,
        })
    }

    fn read<R: PstReader>(f: &mut R) -> io::Result<Self> {
        f.seek(SeekFrom::Start(DENSITY_LIST_FILE_OFFSET))?;

        let mut buffer = [0_u8; 496];
        f.read_exact(&mut buffer)?;
        let mut cursor = Cursor::new(buffer);

        // bFlags
        let backfill_complete = cursor.read_u8()? & 0x01 != 0;

        // cEntDList
        let entry_count = cursor.read_u8()?;
        if entry_count > Self::MAX_ENTRIES as u8 {
            return Err(NdbError::InvalidDensityListEntryCount(entry_count as usize).into());
        }

        // wPadding
        if cursor.read_u16::<LittleEndian>()? != 0 {
            return Err(NdbError::InvalidDensityListPadding.into());
        }

        // ulCurrentPage
        let current_page = cursor.read_u32::<LittleEndian>()?;

        // rgDListPageEnt
        let mut entries = [DensityListPageEntry(0); Self::MAX_ENTRIES];
        for entry in entries.iter_mut().take(entry_count as usize) {
            *entry = DensityListPageEntry::read(&mut cursor)?;
        }
        let skipped = Self::MAX_ENTRIES
            .saturating_sub(usize::from(entry_count))
            .saturating_mul(mem::size_of::<DensityListPageEntry>());
        cursor.seek(SeekFrom::Current(skipped as i64))?;

        // rgPadding
        let mut padding = [0_u8; 12];
        cursor.read_exact(&mut padding)?;
        if padding != [0; 12] {
            return Err(NdbError::InvalidDensityListPadding.into());
        }

        let buffer = cursor.into_inner();

        // pageTrailer
        let trailer = UnicodePageTrailer::read(f)?;
        if trailer.page_type() != PageType::DensityList {
            return Err(NdbError::UnexpectedPageType(trailer.page_type()).into());
        }

        let crc = compute_crc(0, &buffer);
        if crc != trailer.crc() {
            return Err(NdbError::InvalidPageCrc(crc).into());
        }

        Ok(Self {
            backfill_complete,
            current_page,
            entry_count,
            entries,
            trailer,
        })
    }
}

pub struct AnsiDensityListPage {
    backfill_complete: bool,
    current_page: u32,
    entry_count: u8,
    entries: [DensityListPageEntry; <Self as DensityListPageReadWrite<AnsiPstFile>>::MAX_ENTRIES],
    trailer: AnsiPageTrailer,
}

impl DensityListPage<AnsiPstFile> for AnsiDensityListPage {
    fn backfill_complete(&self) -> bool {
        self.backfill_complete
    }

    fn current_page(&self) -> u32 {
        self.current_page
    }

    fn entries(&self) -> &[DensityListPageEntry] {
        self.entries
            .get(..usize::from(self.entry_count))
            .unwrap_or_default()
    }

    fn trailer(&self) -> &AnsiPageTrailer {
        &self.trailer
    }
}

impl DensityListPageReadWrite<AnsiPstFile> for AnsiDensityListPage {
    const MAX_ENTRIES: usize = 480 / mem::size_of::<DensityListPageEntry>();

    fn new(
        backfill_complete: bool,
        current_page: u32,
        entries: &[DensityListPageEntry],
        trailer: AnsiPageTrailer,
    ) -> NdbResult<Self> {
        if entries.len() > Self::MAX_ENTRIES {
            return Err(NdbError::InvalidDensityListEntryCount(entries.len()));
        }

        if trailer.page_type() != PageType::DensityList {
            return Err(NdbError::UnexpectedPageType(trailer.page_type()));
        }

        let entry_count = entries.len() as u8;

        let mut buffer = [DensityListPageEntry(0); Self::MAX_ENTRIES];
        for (entry, value) in buffer.iter_mut().zip(entries) {
            *entry = *value;
        }
        let entries = buffer;

        Ok(Self {
            backfill_complete,
            current_page,
            entry_count,
            entries,
            trailer,
        })
    }

    fn read<R: PstReader>(f: &mut R) -> io::Result<Self> {
        f.seek(SeekFrom::Start(DENSITY_LIST_FILE_OFFSET))?;

        let mut buffer = [0_u8; 500];
        f.read_exact(&mut buffer)?;
        let mut cursor = Cursor::new(buffer);

        // bFlags
        let backfill_complete = cursor.read_u8()? & 0x01 != 0;

        // cEntDList
        let entry_count = cursor.read_u8()?;
        if entry_count > Self::MAX_ENTRIES as u8 {
            return Err(NdbError::InvalidDensityListEntryCount(entry_count as usize).into());
        }

        // wPadding
        if cursor.read_u16::<LittleEndian>()? != 0 {
            return Err(NdbError::InvalidDensityListPadding.into());
        }

        // ulCurrentPage
        let current_page = cursor.read_u32::<LittleEndian>()?;

        // rgDListPageEnt
        let mut entries = [DensityListPageEntry(0); Self::MAX_ENTRIES];
        for entry in entries.iter_mut().take(entry_count as usize) {
            *entry = DensityListPageEntry::read(&mut cursor)?;
        }
        let skipped = Self::MAX_ENTRIES
            .saturating_sub(usize::from(entry_count))
            .saturating_mul(mem::size_of::<DensityListPageEntry>());
        cursor.seek(SeekFrom::Current(skipped as i64))?;

        // rgPadding
        let mut padding = [0_u8; 12];
        cursor.read_exact(&mut padding)?;
        if padding != [0; 12] {
            return Err(NdbError::InvalidDensityListPadding.into());
        }

        let buffer = cursor.into_inner();

        // pageTrailer
        let trailer = AnsiPageTrailer::read(f)?;
        if trailer.page_type() != PageType::DensityList {
            return Err(NdbError::UnexpectedPageType(trailer.page_type()).into());
        }

        let crc = compute_crc(0, &buffer);
        if crc != trailer.crc() {
            return Err(NdbError::InvalidPageCrc(crc).into());
        }

        Ok(Self {
            backfill_complete,
            current_page,
            entry_count,
            entries,
            trailer,
        })
    }
}

pub trait BTreeEntryKey: Copy + Sized + Into<u64> + From<u32> {}

impl BTreeEntryKey for u32 {}
impl BTreeEntryKey for u64 {}

pub trait BTreeEntry: Copy + Sized {
    type Key: BTreeEntryKey;

    fn key(&self) -> Self::Key;
}

/// [BTPAGE](https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-pst/4f0cd8e7-c2d0-4975-90a4-d417cfca77f8)
pub trait BTreePage {
    type Entry: BTreeEntry;
    type Trailer: PageTrailer;

    fn level(&self) -> u8;
    fn entries(&self) -> &[Self::Entry];
    fn trailer(&self) -> &Self::Trailer;
}

pub struct UnicodeBTreeEntryPage {
    level: u8,
    max_entries: u8,
    entry_size: u8,
    entries: Vec<UnicodeBTreePageEntry>,
    trailer: UnicodePageTrailer,
}

impl UnicodeBTreeEntryPage {
    pub fn new(
        level: u8,
        max_entries: u8,
        entry_size: u8,
        entries: &[UnicodeBTreePageEntry],
        trailer: UnicodePageTrailer,
    ) -> NdbResult<Self> {
        if !(1..=8).contains(&level) {
            return Err(NdbError::InvalidBTreePageLevel(level));
        }

        if entries.len() > usize::from(max_entries) {
            return Err(NdbError::InvalidBTreeEntryCount(entries.len()));
        }

        if trailer.page_type() != PageType::BlockBTree && trailer.page_type() != PageType::NodeBTree
        {
            return Err(NdbError::UnexpectedPageType(trailer.page_type()));
        }

        let entries = entries.to_vec();

        Ok(Self {
            level,
            max_entries,
            entry_size,
            entries,
            trailer,
        })
    }
}

impl BTreePage for UnicodeBTreeEntryPage {
    type Entry = UnicodeBTreePageEntry;
    type Trailer = UnicodePageTrailer;

    fn level(&self) -> u8 {
        self.level
    }

    fn entries(&self) -> &[UnicodeBTreePageEntry] {
        &self.entries
    }

    fn trailer(&self) -> &UnicodePageTrailer {
        &self.trailer
    }
}

impl BTreePageReadWrite for UnicodeBTreeEntryPage {
    fn new(
        level: u8,
        max_entries: u8,
        entry_size: u8,
        entries: &[UnicodeBTreePageEntry],
        trailer: UnicodePageTrailer,
    ) -> NdbResult<Self> {
        Self::new(level, max_entries, entry_size, entries, trailer)
    }

    fn max_entries(&self) -> u8 {
        self.max_entries
    }

    fn entry_size(&self) -> u8 {
        self.entry_size
    }
}

impl UnicodeBTreePageReadWrite<UnicodeBTreePageEntry> for UnicodeBTreeEntryPage {}

pub struct AnsiBTreeEntryPage {
    level: u8,
    max_entries: u8,
    entry_size: u8,
    entries: Vec<AnsiBTreePageEntry>,
    trailer: AnsiPageTrailer,
}

impl BTreePage for AnsiBTreeEntryPage {
    type Entry = AnsiBTreePageEntry;
    type Trailer = AnsiPageTrailer;

    fn level(&self) -> u8 {
        self.level
    }

    fn entries(&self) -> &[AnsiBTreePageEntry] {
        &self.entries
    }

    fn trailer(&self) -> &AnsiPageTrailer {
        &self.trailer
    }
}

impl BTreePageReadWrite for AnsiBTreeEntryPage {
    fn new(
        level: u8,
        max_entries: u8,
        entry_size: u8,
        entries: &[AnsiBTreePageEntry],
        trailer: AnsiPageTrailer,
    ) -> NdbResult<Self> {
        if !(1..=8).contains(&level) {
            return Err(NdbError::InvalidBTreePageLevel(level));
        }

        if entries.len() > usize::from(max_entries) {
            return Err(NdbError::InvalidBTreeEntryCount(entries.len()));
        }

        if trailer.page_type() != PageType::BlockBTree && trailer.page_type() != PageType::NodeBTree
        {
            return Err(NdbError::UnexpectedPageType(trailer.page_type()));
        }

        let entries = entries.to_vec();

        Ok(Self {
            level,
            max_entries,
            entry_size,
            entries,
            trailer,
        })
    }

    fn max_entries(&self) -> u8 {
        self.max_entries
    }

    fn entry_size(&self) -> u8 {
        self.entry_size
    }
}

impl AnsiBTreePageReadWrite<AnsiBTreePageEntry> for AnsiBTreeEntryPage {}

/// [BTENTRY](https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-pst/bc8052a3-f300-4022-be31-f0f408fffca0)
pub trait BTreePageEntry: BTreeEntry {
    type Block: BlockRef;

    fn block(&self) -> Self::Block;
}

impl<Entry> BTreeEntryReadWrite for Entry
where
    Entry: BTreeEntry<Key: BTreePageKeyReadWrite>
        + BTreePageEntry<Block: BlockRefReadWrite<Block: BlockIdReadWrite, Index: ByteIndexReadWrite>>
        + BTreePageEntryReadWrite,
{
    const ENTRY_SIZE: usize = <Entry as BTreePageEntryReadWrite>::ENTRY_SIZE;

    fn read(f: &mut dyn Read) -> io::Result<Self> {
        Ok(Self::new(
            <Self as BTreeEntry>::Key::read(f)?,
            <Self as BTreePageEntry>::Block::read(f)?,
        ))
    }

    fn write(&self, f: &mut dyn Write) -> io::Result<()> {
        self.key().write(f)?;
        self.block().write(f)
    }
}

impl BTreePageKeyReadWrite for u64 {
    fn read(f: &mut dyn Read) -> io::Result<Self> {
        f.read_u64::<LittleEndian>()
    }

    fn write(self, f: &mut dyn Write) -> io::Result<()> {
        f.write_u64::<LittleEndian>(self)
    }
}

#[derive(Copy, Clone, Default, Debug)]
pub struct UnicodeBTreePageEntry {
    key: u64,
    block: UnicodePageRef,
}

impl BTreeEntry for UnicodeBTreePageEntry {
    type Key = u64;

    fn key(&self) -> u64 {
        self.key
    }
}

impl BTreePageEntry for UnicodeBTreePageEntry {
    type Block = UnicodePageRef;

    fn block(&self) -> UnicodePageRef {
        self.block
    }
}

impl BTreePageEntryReadWrite for UnicodeBTreePageEntry {
    const ENTRY_SIZE: usize = 24;

    fn new(key: u64, block: UnicodePageRef) -> Self {
        Self { key, block }
    }
}

impl BTreePageKeyReadWrite for u32 {
    fn read(f: &mut dyn Read) -> io::Result<Self> {
        f.read_u32::<LittleEndian>()
    }

    fn write(self, f: &mut dyn Write) -> io::Result<()> {
        f.write_u32::<LittleEndian>(self)
    }
}

#[derive(Copy, Clone, Default, Debug)]
pub struct AnsiBTreePageEntry {
    key: u32,
    block: AnsiPageRef,
}

impl BTreeEntry for AnsiBTreePageEntry {
    type Key = u32;

    fn key(&self) -> u32 {
        self.key
    }
}

impl BTreePageEntry for AnsiBTreePageEntry {
    type Block = AnsiPageRef;

    fn block(&self) -> AnsiPageRef {
        self.block
    }
}

impl BTreePageEntryReadWrite for AnsiBTreePageEntry {
    const ENTRY_SIZE: usize = 12;

    fn new(key: u32, block: AnsiPageRef) -> Self {
        Self { key, block }
    }
}

/// [BBTENTRY](https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-pst/53a4b926-8ac4-45c9-9c6d-8358d951dbcd)
pub trait BlockBTreeEntry: BTreeEntry {
    type Block: BlockRef;

    fn block(&self) -> Self::Block;
    fn size(&self) -> u16;
    fn ref_count(&self) -> u16;

    /// For an entry from a page in the 4 KiB layout of Outlook 2013 and later OSTs, the block's
    /// size once inflated. Such a block sits in a 512-byte aligned slot with a 24-byte trailer,
    /// and is zlib-compressed when this differs from [`BlockBTreeEntry::size`].
    fn inflated_size(&self) -> Option<u16> {
        None
    }
}

#[derive(Copy, Clone, Default, Debug)]
pub struct UnicodeBlockBTreeEntry {
    block: UnicodeBlockRef,
    size: u16,
    ref_count: u16,
    padding: u32,
    /// The block's size once inflated, for an entry from a page in the 4 KiB layout.
    inflated_size: Option<u16>,
}

impl UnicodeBlockBTreeEntry {
    pub fn new(block: UnicodeBlockRef, size: u16) -> Self {
        Self {
            block,
            size,
            ref_count: 1,
            ..Default::default()
        }
    }
}

impl BTreeEntry for UnicodeBlockBTreeEntry {
    type Key = u64;

    fn key(&self) -> u64 {
        self.block.block().search_key()
    }
}

impl BTreeEntryReadWrite for UnicodeBlockBTreeEntry {
    const ENTRY_SIZE: usize = 24;

    fn read(f: &mut dyn Read) -> io::Result<Self> {
        let block = UnicodeBlockRef::read(f)?;
        let size = f.read_u16::<LittleEndian>()?;
        let ref_count = f.read_u16::<LittleEndian>()?;
        let padding = f.read_u32::<LittleEndian>()?;

        Ok(Self {
            block,
            size,
            ref_count,
            padding,
            inflated_size: None,
        })
    }

    fn write(&self, f: &mut dyn Write) -> io::Result<()> {
        self.block.write(f)?;
        f.write_u16::<LittleEndian>(self.size)?;
        f.write_u16::<LittleEndian>(self.ref_count)?;
        f.write_u32::<LittleEndian>(self.padding)
    }

    /// In the 4 KiB layout the entry is `BREF`, `cb`, the inflated size, `cRef` and two bytes of
    /// padding.
    fn read_4k(f: &mut dyn Read) -> io::Result<Self> {
        let block = UnicodeBlockRef::read(f)?;
        let size = f.read_u16::<LittleEndian>()?;
        let inflated_size = f.read_u16::<LittleEndian>()?;
        let ref_count = f.read_u16::<LittleEndian>()?;
        let padding = u32::from(f.read_u16::<LittleEndian>()?);

        Ok(Self {
            block,
            size,
            ref_count,
            padding,
            inflated_size: Some(inflated_size),
        })
    }
}

impl BlockBTreeEntry for UnicodeBlockBTreeEntry {
    type Block = UnicodeBlockRef;

    fn block(&self) -> UnicodeBlockRef {
        self.block
    }

    fn size(&self) -> u16 {
        self.size
    }

    fn ref_count(&self) -> u16 {
        self.ref_count
    }

    fn inflated_size(&self) -> Option<u16> {
        self.inflated_size
    }
}

impl BlockBTreeEntryReadWrite for UnicodeBlockBTreeEntry {
    fn new(block: UnicodeBlockRef, size: u16) -> Self {
        Self::new(block, size)
    }
}

pub struct UnicodeBlockBTreePage {
    max_entries: u8,
    entry_size: u8,
    entries: Vec<UnicodeBlockBTreeEntry>,
    trailer: UnicodePageTrailer,
}

impl UnicodeBlockBTreePage {
    pub fn new(
        level: u8,
        max_entries: u8,
        entry_size: u8,
        entries: &[UnicodeBlockBTreeEntry],
        trailer: UnicodePageTrailer,
    ) -> NdbResult<Self> {
        if level != 0 {
            return Err(NdbError::InvalidBTreePageLevel(level));
        }

        if entries.len() > usize::from(max_entries) {
            return Err(NdbError::InvalidBTreeEntryCount(entries.len()));
        }

        if trailer.page_type() != PageType::BlockBTree {
            return Err(NdbError::UnexpectedPageType(trailer.page_type()));
        }

        let entries = entries.to_vec();

        Ok(Self {
            max_entries,
            entry_size,
            entries,
            trailer,
        })
    }
}

impl BTreePage for UnicodeBlockBTreePage {
    type Entry = UnicodeBlockBTreeEntry;
    type Trailer = UnicodePageTrailer;

    fn level(&self) -> u8 {
        0
    }

    fn entries(&self) -> &[UnicodeBlockBTreeEntry] {
        &self.entries
    }

    fn trailer(&self) -> &UnicodePageTrailer {
        &self.trailer
    }
}

impl BTreePageReadWrite for UnicodeBlockBTreePage {
    fn new(
        level: u8,
        max_entries: u8,
        entry_size: u8,
        entries: &[UnicodeBlockBTreeEntry],
        trailer: UnicodePageTrailer,
    ) -> NdbResult<Self> {
        Self::new(level, max_entries, entry_size, entries, trailer)
    }

    fn max_entries(&self) -> u8 {
        self.max_entries
    }

    fn entry_size(&self) -> u8 {
        self.entry_size
    }
}

impl UnicodeBTreePageReadWrite<UnicodeBlockBTreeEntry> for UnicodeBlockBTreePage {}

#[derive(Copy, Clone, Default, Debug)]
pub struct AnsiBlockBTreeEntry {
    block: AnsiBlockRef,
    size: u16,
    ref_count: u16,
}

impl AnsiBlockBTreeEntry {
    pub fn new(block: AnsiBlockRef, size: u16) -> Self {
        Self {
            block,
            size,
            ref_count: 1,
        }
    }
}

impl BTreeEntry for AnsiBlockBTreeEntry {
    type Key = u32;

    fn key(&self) -> u32 {
        self.block.block().search_key()
    }
}

impl BTreeEntryReadWrite for AnsiBlockBTreeEntry {
    const ENTRY_SIZE: usize = 12;

    fn read(f: &mut dyn Read) -> io::Result<Self> {
        Ok(Self {
            block: AnsiBlockRef::read(f)?,
            size: f.read_u16::<LittleEndian>()?,
            ref_count: f.read_u16::<LittleEndian>()?,
        })
    }

    fn write(&self, f: &mut dyn Write) -> io::Result<()> {
        self.block.write(f)?;
        f.write_u16::<LittleEndian>(self.size)?;
        f.write_u16::<LittleEndian>(self.ref_count)
    }
}

impl BlockBTreeEntry for AnsiBlockBTreeEntry {
    type Block = AnsiBlockRef;

    fn block(&self) -> AnsiBlockRef {
        self.block
    }

    fn size(&self) -> u16 {
        self.size
    }

    fn ref_count(&self) -> u16 {
        self.ref_count
    }
}

impl BlockBTreeEntryReadWrite for AnsiBlockBTreeEntry {
    fn new(block: AnsiBlockRef, size: u16) -> Self {
        Self::new(block, size)
    }
}

pub struct AnsiBlockBTreePage {
    max_entries: u8,
    entry_size: u8,
    entries: Vec<AnsiBlockBTreeEntry>,
    trailer: AnsiPageTrailer,
}

impl AnsiBlockBTreePage {
    pub fn new(
        level: u8,
        max_entries: u8,
        entry_size: u8,
        entries: &[AnsiBlockBTreeEntry],
        trailer: AnsiPageTrailer,
    ) -> NdbResult<Self> {
        if level != 0 {
            return Err(NdbError::InvalidBTreePageLevel(level));
        }

        if entries.len() > usize::from(max_entries) {
            return Err(NdbError::InvalidBTreeEntryCount(entries.len()));
        }

        if trailer.page_type() != PageType::BlockBTree {
            return Err(NdbError::UnexpectedPageType(trailer.page_type()));
        }

        let entries = entries.to_vec();

        Ok(Self {
            max_entries,
            entry_size,
            entries,
            trailer,
        })
    }
}

impl BTreePage for AnsiBlockBTreePage {
    type Entry = AnsiBlockBTreeEntry;
    type Trailer = AnsiPageTrailer;

    fn level(&self) -> u8 {
        0
    }

    fn entries(&self) -> &[AnsiBlockBTreeEntry] {
        &self.entries
    }

    fn trailer(&self) -> &AnsiPageTrailer {
        &self.trailer
    }
}

impl BTreePageReadWrite for AnsiBlockBTreePage {
    fn new(
        level: u8,
        max_entries: u8,
        entry_size: u8,
        entries: &[AnsiBlockBTreeEntry],
        trailer: AnsiPageTrailer,
    ) -> NdbResult<Self> {
        Self::new(level, max_entries, entry_size, entries, trailer)
    }

    fn max_entries(&self) -> u8 {
        self.max_entries
    }

    fn entry_size(&self) -> u8 {
        self.entry_size
    }
}

impl AnsiBTreePageReadWrite<AnsiBlockBTreeEntry> for AnsiBlockBTreePage {}

/// [NBTENTRY](https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-pst/53a4b926-8ac4-45c9-9c6d-8358d951dbcd)
pub trait NodeBTreeEntry: BTreeEntry {
    type Block: BlockId;

    fn node(&self) -> NodeId;
    fn data(&self) -> Self::Block;
    fn sub_node(&self) -> Option<Self::Block>;
    fn parent(&self) -> Option<NodeId>;
}

#[derive(Copy, Clone, Default, Debug)]
pub struct UnicodeNodeBTreeEntry {
    node: NodeId,
    data: UnicodeBlockId,
    sub_node: Option<UnicodeBlockId>,
    parent: Option<NodeId>,
    padding: u32,
}

impl UnicodeNodeBTreeEntry {
    pub fn new(
        node: NodeId,
        data: UnicodeBlockId,
        sub_node: Option<UnicodeBlockId>,
        parent: Option<NodeId>,
    ) -> Self {
        Self {
            node,
            data,
            sub_node,
            parent,
            ..Default::default()
        }
    }
}

impl BTreeEntry for UnicodeNodeBTreeEntry {
    type Key = u64;

    fn key(&self) -> u64 {
        u64::from(u32::from(self.node))
    }
}

impl BTreeEntryReadWrite for UnicodeNodeBTreeEntry {
    const ENTRY_SIZE: usize = 32;

    fn read(f: &mut dyn Read) -> io::Result<Self> {
        // nid
        let node = f.read_u64::<LittleEndian>()?;
        let Ok(node) = u32::try_from(node) else {
            return Err(NdbError::InvalidNodeBTreeEntryNodeId(node).into());
        };
        let node = NodeId::from(node);

        // bidData
        let data = UnicodeBlockId::read(f)?;

        // bidSub
        let sub_node = UnicodeBlockId::read(f)?;
        let sub_node = if sub_node.search_key() == 0 {
            None
        } else {
            Some(sub_node)
        };

        // nidParent
        let parent = NodeId::read(f)?;
        let parent = if u32::from(parent) == 0 {
            None
        } else {
            Some(parent)
        };

        // dwPadding
        let padding = f.read_u32::<LittleEndian>()?;

        Ok(Self {
            node,
            data,
            sub_node,
            parent,
            padding,
        })
    }

    fn write(&self, f: &mut dyn Write) -> io::Result<()> {
        // nid
        f.write_u64::<LittleEndian>(u64::from(u32::from(self.node)))?;

        // bidData
        self.data.write(f)?;

        // bidSub
        self.sub_node.unwrap_or_default().write(f)?;

        // nidParent
        self.parent.unwrap_or_default().write(f)?;

        // dwPadding
        f.write_u32::<LittleEndian>(self.padding)
    }
}

impl NodeBTreeEntry for UnicodeNodeBTreeEntry {
    type Block = UnicodeBlockId;

    fn node(&self) -> NodeId {
        self.node
    }

    fn data(&self) -> UnicodeBlockId {
        self.data
    }

    fn sub_node(&self) -> Option<UnicodeBlockId> {
        self.sub_node
    }

    fn parent(&self) -> Option<NodeId> {
        self.parent
    }
}

impl NodeBTreeEntryReadWrite for UnicodeNodeBTreeEntry {
    fn new(
        node: NodeId,
        data: UnicodeBlockId,
        sub_node: Option<UnicodeBlockId>,
        parent: Option<NodeId>,
    ) -> Self {
        Self::new(node, data, sub_node, parent)
    }
}

pub struct UnicodeNodeBTreePage {
    max_entries: u8,
    entry_size: u8,
    entries: Vec<UnicodeNodeBTreeEntry>,
    trailer: UnicodePageTrailer,
}

impl UnicodeNodeBTreePage {
    pub fn new(
        level: u8,
        max_entries: u8,
        entry_size: u8,
        entries: &[UnicodeNodeBTreeEntry],
        trailer: UnicodePageTrailer,
    ) -> NdbResult<Self> {
        if level != 0 {
            return Err(NdbError::InvalidBTreePageLevel(level));
        }

        if entries.len() > usize::from(max_entries) {
            return Err(NdbError::InvalidBTreeEntryCount(entries.len()));
        }

        if trailer.page_type() != PageType::NodeBTree {
            return Err(NdbError::UnexpectedPageType(trailer.page_type()));
        }

        let entries = entries.to_vec();

        Ok(Self {
            max_entries,
            entry_size,
            entries,
            trailer,
        })
    }
}

impl BTreePage for UnicodeNodeBTreePage {
    type Entry = UnicodeNodeBTreeEntry;
    type Trailer = UnicodePageTrailer;

    fn level(&self) -> u8 {
        0
    }

    fn entries(&self) -> &[UnicodeNodeBTreeEntry] {
        &self.entries
    }

    fn trailer(&self) -> &UnicodePageTrailer {
        &self.trailer
    }
}

impl BTreePageReadWrite for UnicodeNodeBTreePage {
    fn new(
        level: u8,
        max_entries: u8,
        entry_size: u8,
        entries: &[UnicodeNodeBTreeEntry],
        trailer: UnicodePageTrailer,
    ) -> NdbResult<Self> {
        Self::new(level, max_entries, entry_size, entries, trailer)
    }

    fn max_entries(&self) -> u8 {
        self.max_entries
    }

    fn entry_size(&self) -> u8 {
        self.entry_size
    }
}

impl UnicodeBTreePageReadWrite<UnicodeNodeBTreeEntry> for UnicodeNodeBTreePage {}

#[derive(Copy, Clone, Default, Debug)]
pub struct AnsiNodeBTreeEntry {
    node: NodeId,
    data: AnsiBlockId,
    sub_node: Option<AnsiBlockId>,
    parent: Option<NodeId>,
}

impl AnsiNodeBTreeEntry {
    pub fn new(
        node: NodeId,
        data: AnsiBlockId,
        sub_node: Option<AnsiBlockId>,
        parent: Option<NodeId>,
    ) -> Self {
        Self {
            node,
            data,
            sub_node,
            parent,
        }
    }
}

impl BTreeEntry for AnsiNodeBTreeEntry {
    type Key = u32;

    fn key(&self) -> u32 {
        u32::from(self.node)
    }
}

impl BTreeEntryReadWrite for AnsiNodeBTreeEntry {
    const ENTRY_SIZE: usize = 16;

    fn read(f: &mut dyn Read) -> io::Result<Self> {
        // nid
        let node = NodeId::read(f)?;

        // bidData
        let data = AnsiBlockId::read(f)?;

        // bidSub
        let sub_node = AnsiBlockId::read(f)?;
        let sub_node = if sub_node.search_key() == 0 {
            None
        } else {
            Some(sub_node)
        };

        // nidParent
        let parent = NodeId::read(f)?;
        let parent = if u32::from(parent) == 0 {
            None
        } else {
            Some(parent)
        };

        Ok(Self {
            node,
            data,
            sub_node,
            parent,
        })
    }

    fn write(&self, f: &mut dyn Write) -> io::Result<()> {
        // nid
        self.node.write(f)?;

        // bidData
        self.data.write(f)?;

        // bidSub
        self.sub_node.unwrap_or_default().write(f)?;

        // nidParent
        self.parent.unwrap_or_default().write(f)
    }
}

impl NodeBTreeEntry for AnsiNodeBTreeEntry {
    type Block = AnsiBlockId;

    fn node(&self) -> NodeId {
        self.node
    }

    fn data(&self) -> AnsiBlockId {
        self.data
    }

    fn sub_node(&self) -> Option<AnsiBlockId> {
        self.sub_node
    }

    fn parent(&self) -> Option<NodeId> {
        self.parent
    }
}

impl NodeBTreeEntryReadWrite for AnsiNodeBTreeEntry {
    fn new(
        node: NodeId,
        data: AnsiBlockId,
        sub_node: Option<AnsiBlockId>,
        parent: Option<NodeId>,
    ) -> Self {
        Self::new(node, data, sub_node, parent)
    }
}

pub struct AnsiNodeBTreePage {
    max_entries: u8,
    entry_size: u8,
    entries: Vec<AnsiNodeBTreeEntry>,
    trailer: AnsiPageTrailer,
}

impl AnsiNodeBTreePage {
    pub fn new(
        level: u8,
        max_entries: u8,
        entry_size: u8,
        entries: &[AnsiNodeBTreeEntry],
        trailer: AnsiPageTrailer,
    ) -> NdbResult<Self> {
        if level != 0 {
            return Err(NdbError::InvalidBTreePageLevel(level));
        }

        if entries.len() > usize::from(max_entries) {
            return Err(NdbError::InvalidBTreeEntryCount(entries.len()));
        }

        if trailer.page_type() != PageType::NodeBTree {
            return Err(NdbError::UnexpectedPageType(trailer.page_type()));
        }

        let entries = entries.to_vec();

        Ok(Self {
            max_entries,
            entry_size,
            entries,
            trailer,
        })
    }
}

impl BTreePage for AnsiNodeBTreePage {
    type Entry = AnsiNodeBTreeEntry;
    type Trailer = AnsiPageTrailer;

    fn level(&self) -> u8 {
        0
    }

    fn entries(&self) -> &[AnsiNodeBTreeEntry] {
        &self.entries
    }

    fn trailer(&self) -> &AnsiPageTrailer {
        &self.trailer
    }
}

impl BTreePageReadWrite for AnsiNodeBTreePage {
    fn new(
        level: u8,
        max_entries: u8,
        entry_size: u8,
        entries: &[AnsiNodeBTreeEntry],
        trailer: AnsiPageTrailer,
    ) -> NdbResult<Self> {
        Self::new(level, max_entries, entry_size, entries, trailer)
    }

    fn max_entries(&self) -> u8 {
        self.max_entries
    }

    fn entry_size(&self) -> u8 {
        self.entry_size
    }
}

impl AnsiBTreePageReadWrite<AnsiNodeBTreeEntry> for AnsiNodeBTreePage {}

pub trait RootBTreeIntermediatePage<Pst, Entry, LeafPage>
where
    Pst: PstFile,
    Entry: BTreeEntry<Key = <Pst as PstFile>::BTreeKey>,
    LeafPage: RootBTreeLeafPage<Pst, Entry = Entry>,
    Self: BTreePage<
            Entry = <Self as RootBTreeIntermediatePage<Pst, Entry, LeafPage>>::Entry,
            Trailer = <Pst as PstFile>::PageTrailer,
        >,
{
    type Entry: BTreeEntry<Key = <Pst as PstFile>::BTreeKey>
        + BTreePageEntry<Block = <Pst as PstFile>::PageRef>;
    type Page: BTreePageReadWrite<
            Entry = <Self as RootBTreeIntermediatePage<Pst, Entry, LeafPage>>::Entry,
            Trailer = <Pst as PstFile>::PageTrailer,
        >;
}

impl<Entry, LeafPage> RootBTreeIntermediatePage<UnicodePstFile, Entry, LeafPage>
    for UnicodeBTreeEntryPage
where
    Entry: BTreeEntry<Key = u64> + BTreeEntryReadWrite,
    LeafPage: RootBTreeLeafPage<UnicodePstFile, Entry = Entry>,
{
    type Entry = UnicodeBTreePageEntry;
    type Page = UnicodeBTreeEntryPage;
}

impl<Entry, LeafPage> RootBTreeIntermediatePageReadWrite<UnicodePstFile, Entry, LeafPage>
    for UnicodeBTreeEntryPage
where
    Entry: BTreeEntry<Key = u64> + BTreeEntryReadWrite,
    LeafPage: RootBTreeLeafPage<UnicodePstFile, Entry = Entry>
        + RootBTreeLeafPageReadWrite<UnicodePstFile>,
{
    fn read<R: PstReader>(f: &mut R) -> io::Result<Self> {
        <Self as UnicodeBTreePageReadWrite<UnicodeBTreePageEntry>>::read(f)
    }
}

impl<Entry, LeafPage> RootBTreeIntermediatePage<AnsiPstFile, Entry, LeafPage> for AnsiBTreeEntryPage
where
    Entry: BTreeEntry<Key = u32> + BTreeEntryReadWrite,
    LeafPage: RootBTreeLeafPage<AnsiPstFile, Entry = Entry>,
{
    type Entry = AnsiBTreePageEntry;
    type Page = AnsiBTreeEntryPage;
}

impl<Entry, LeafPage> RootBTreeIntermediatePageReadWrite<AnsiPstFile, Entry, LeafPage>
    for AnsiBTreeEntryPage
where
    Entry: BTreeEntry<Key = u32> + BTreeEntryReadWrite,
    LeafPage:
        RootBTreeLeafPage<AnsiPstFile, Entry = Entry> + RootBTreeLeafPageReadWrite<AnsiPstFile>,
{
    fn read<R: PstReader>(f: &mut R) -> io::Result<Self> {
        <Self as AnsiBTreePageReadWrite<AnsiBTreePageEntry>>::read(f)
    }
}

pub trait RootBTreeLeafPage<Pst>
where
    Pst: PstFile,
    Self: BTreePage<
            Entry = <Self as RootBTreeLeafPage<Pst>>::Entry,
            Trailer = <Pst as PstFile>::PageTrailer,
        >,
{
    type Entry: BTreeEntry<Key = <Pst as PstFile>::BTreeKey>;
}

impl RootBTreeLeafPage<UnicodePstFile> for UnicodeBlockBTreePage {
    type Entry = UnicodeBlockBTreeEntry;
}

impl RootBTreeLeafPageReadWrite<UnicodePstFile> for UnicodeBlockBTreePage {
    const BTREE_ENTRIES_SIZE: usize = UNICODE_BTREE_ENTRIES_SIZE;

    fn read<R: PstReader>(f: &mut R) -> io::Result<Self> {
        <Self as UnicodeBTreePageReadWrite<UnicodeBlockBTreeEntry>>::read(f)
    }
}

impl RootBTreeLeafPage<AnsiPstFile> for AnsiBlockBTreePage {
    type Entry = AnsiBlockBTreeEntry;
}

impl RootBTreeLeafPageReadWrite<AnsiPstFile> for AnsiBlockBTreePage {
    const BTREE_ENTRIES_SIZE: usize = ANSI_BTREE_ENTRIES_SIZE;

    fn read<R: PstReader>(f: &mut R) -> io::Result<Self> {
        <Self as AnsiBTreePageReadWrite<AnsiBlockBTreeEntry>>::read(f)
    }
}

impl RootBTreeLeafPage<UnicodePstFile> for UnicodeNodeBTreePage {
    type Entry = UnicodeNodeBTreeEntry;
}

impl RootBTreeLeafPageReadWrite<UnicodePstFile> for UnicodeNodeBTreePage {
    const BTREE_ENTRIES_SIZE: usize = UNICODE_BTREE_ENTRIES_SIZE;

    fn read<R: PstReader>(f: &mut R) -> io::Result<Self> {
        <Self as UnicodeBTreePageReadWrite<UnicodeNodeBTreeEntry>>::read(f)
    }
}

impl RootBTreeLeafPage<AnsiPstFile> for AnsiNodeBTreePage {
    type Entry = AnsiNodeBTreeEntry;
}

impl RootBTreeLeafPageReadWrite<AnsiPstFile> for AnsiNodeBTreePage {
    const BTREE_ENTRIES_SIZE: usize = ANSI_BTREE_ENTRIES_SIZE;

    fn read<R: PstReader>(f: &mut R) -> io::Result<Self> {
        <Self as AnsiBTreePageReadWrite<AnsiNodeBTreeEntry>>::read(f)
    }
}

pub trait RootBTree {
    type Pst: PstFile<BTreeKey: BTreeEntryKey>;
    type Entry: BTreeEntry<Key = <Self::Pst as PstFile>::BTreeKey> + Sized;
    type IntermediatePage: RootBTreeIntermediatePage<Self::Pst, Self::Entry, Self::LeafPage>;
    type LeafPage: RootBTreeLeafPage<Self::Pst, Entry = Self::Entry>;
}

pub enum RootBTreePage<Pst, Entry, IntermediatePage, LeafPage>
where
    Pst: PstFile,
    Entry: BTreeEntry<Key = <Pst as PstFile>::BTreeKey>,
    IntermediatePage: RootBTreeIntermediatePage<Pst, Entry, LeafPage>,
    LeafPage: RootBTreeLeafPage<Pst, Entry = Entry>,
{
    Intermediate(Box<IntermediatePage>, PhantomData<(Pst, Entry)>),
    Leaf(Box<LeafPage>),
}

impl<Pst, Entry, IntermediatePage, LeafPage> RootBTree
    for RootBTreePage<Pst, Entry, IntermediatePage, LeafPage>
where
    Pst: PstFile,
    Entry: BTreeEntry<Key = <Pst as PstFile>::BTreeKey>,
    IntermediatePage: RootBTreeIntermediatePage<Pst, Entry, LeafPage>,
    LeafPage: RootBTreeLeafPage<Pst, Entry = Entry>,
{
    type Pst = Pst;
    type Entry = Entry;
    type IntermediatePage = IntermediatePage;
    type LeafPage = LeafPage;
}

impl<Pst, Entry, IntermediatePage, LeafPage> RootBTreeReadWrite
    for RootBTreePage<Pst, Entry, IntermediatePage, LeafPage>
where
    Pst: PstFile,
    <Pst as PstFile>::BlockId: BlockIdReadWrite,
    <Pst as PstFile>::ByteIndex: ByteIndexReadWrite,
    <Pst as PstFile>::BlockRef: BlockRefReadWrite,
    <Pst as PstFile>::PageRef: BlockRefReadWrite,
    <Pst as PstFile>::PageTrailer: PageTrailerReadWrite,
    <Pst as PstFile>::BTreeKey: BTreePageKeyReadWrite + Into<u64>,
    Entry: BTreeEntry<Key = <Pst as PstFile>::BTreeKey> + BTreeEntryReadWrite,
    IntermediatePage: RootBTreeIntermediatePage<Pst, Entry, LeafPage>,
    LeafPage: RootBTreeLeafPage<Pst, Entry = Entry>,
    <Self as RootBTree>::Entry: BTreeEntry<Key = <Pst as PstFile>::BTreeKey> + BTreeEntryReadWrite,
    <Self as RootBTree>::IntermediatePage: RootBTreeIntermediatePageReadWrite<Pst, Entry, LeafPage>,
    <Self as RootBTree>::LeafPage: RootBTreeLeafPageReadWrite<Pst>,
{
    fn read<R: PstReader>(f: &mut R, block: <Pst as PstFile>::PageRef) -> io::Result<Self> {
        f.seek(SeekFrom::Start(block.index().index().into()))?;

        // A Unicode page may be a 4 KiB page, whose cEnt and cEntMax are two bytes each.
        let (buffer, level_offset) = if LeafPage::BTREE_ENTRIES_SIZE == UNICODE_BTREE_ENTRIES_SIZE {
            match read_unicode_btree_page(f)? {
                (page, true) => (page, UNICODE_4K_BTREE_ENTRIES_SIZE + 5),
                (page, false) => (page, UNICODE_BTREE_ENTRIES_SIZE + 3),
            }
        } else {
            let mut buffer = vec![0_u8; PAGE_SIZE];
            f.read_exact(&mut buffer)?;
            (buffer, LeafPage::BTREE_ENTRIES_SIZE.saturating_add(3))
        };
        let mut cursor = Cursor::new(buffer);

        cursor.seek(SeekFrom::Start(level_offset as u64))?;
        let level = cursor.read_u8()?;

        cursor.seek(SeekFrom::Start(0))?;
        Ok(if level == 0 {
            Self::Leaf(Box::new(LeafPage::read(&mut cursor)?))
        } else {
            Self::Intermediate(Box::new(IntermediatePage::read(&mut cursor)?), PhantomData)
        })
    }

    fn find_entry<R: PstReader>(
        &self,
        f: &mut R,
        key: <Pst as PstFile>::BTreeKey,
        page_cache: &mut RootBTreePageCache<Self>,
    ) -> io::Result<Entry> {
        self.find_entry_on_path(f, key, page_cache, &mut Vec::new())
    }
}

/// The most pages a BTree lookup goes through below the root page: MS-PST allows 8 levels.
pub const MAX_BTREE_DEPTH: usize = 16;

impl<Pst, Entry, IntermediatePage, LeafPage> RootBTreePage<Pst, Entry, IntermediatePage, LeafPage>
where
    Pst: PstFile,
    <Pst as PstFile>::BlockId: BlockIdReadWrite,
    <Pst as PstFile>::ByteIndex: ByteIndexReadWrite,
    <Pst as PstFile>::BlockRef: BlockRefReadWrite,
    <Pst as PstFile>::PageRef: BlockRefReadWrite,
    <Pst as PstFile>::PageTrailer: PageTrailerReadWrite,
    <Pst as PstFile>::BTreeKey: BTreePageKeyReadWrite + Into<u64>,
    Entry: BTreeEntry<Key = <Pst as PstFile>::BTreeKey> + BTreeEntryReadWrite,
    IntermediatePage: RootBTreeIntermediatePage<Pst, Entry, LeafPage>,
    LeafPage: RootBTreeLeafPage<Pst, Entry = Entry>,
    <Self as RootBTree>::Entry: BTreeEntry<Key = <Pst as PstFile>::BTreeKey> + BTreeEntryReadWrite,
    <Self as RootBTree>::IntermediatePage: RootBTreeIntermediatePageReadWrite<Pst, Entry, LeafPage>,
    <Self as RootBTree>::LeafPage: RootBTreeLeafPageReadWrite<Pst>,
{
    /// Look `key` up below this page. `path` holds the file offsets of the pages the lookup went
    /// through: a page that is already on it (a page that refers to itself or to a page above it)
    /// ends the lookup with an error, and so does a path longer than [`MAX_BTREE_DEPTH`]. A page
    /// whose `cLevel` is not below its parent's is followed: files written by some tools hold such
    /// stale references, and the path check is what guarantees the lookup ends.
    fn find_entry_on_path<R: PstReader>(
        &self,
        f: &mut R,
        key: <Pst as PstFile>::BTreeKey,
        page_cache: &mut RootBTreePageCache<Self>,
        path: &mut Vec<u64>,
    ) -> io::Result<Entry> {
        let search_key: u64 = key.into();
        match self {
            Self::Intermediate(page, ..) => {
                let entries = <IntermediatePage as BTreePage>::entries(page);
                let index =
                    entries.partition_point(|entry| Into::<u64>::into(entry.key()) <= search_key);
                let entry = index
                    .checked_sub(1)
                    .and_then(|index| entries.get(index))
                    .ok_or(NdbError::BTreePageNotFound(search_key))?;
                let block = entry.block();
                let offset: u64 = block.index().index().into();
                if path.contains(&offset) {
                    return Err(NdbError::BTreePageLoop(offset).into());
                }
                if path.len() >= MAX_BTREE_DEPTH {
                    return Err(NdbError::BTreeTooDeep(offset).into());
                }
                let page = match page_cache.remove(&block.block()) {
                    Some(page) => page,
                    None => <Self as RootBTreeReadWrite>::read(f, block)?,
                };
                path.push(offset);
                let entry = page.find_entry_on_path(f, key, page_cache, path);
                path.pop();
                page_cache.insert(block.block(), page);
                entry
            }
            Self::Leaf(page) => {
                let entry = <LeafPage as BTreePage>::entries(page)
                    .iter()
                    .find(|entry| Into::<u64>::into(entry.key()) == search_key)
                    .ok_or(NdbError::BTreePageNotFound(search_key))?;
                Ok(*entry)
            }
        }
    }
}

impl<Pst, Entry, IntermediatePage, LeafPage> RootBTreePage<Pst, Entry, IntermediatePage, LeafPage>
where
    Pst: PstFile,
    Entry: BTreeEntry<Key = <Pst as PstFile>::BTreeKey>,
    IntermediatePage: RootBTreeIntermediatePage<Pst, Entry, LeafPage>,
    LeafPage: RootBTreeLeafPage<Pst, Entry = Entry>,
{
    /// The page's `cLevel`: 0 for a leaf page, 1 to 8 for an intermediate page.
    pub fn level(&self) -> u8 {
        match self {
            Self::Intermediate(page, ..) => page.level(),
            Self::Leaf(_) => 0,
        }
    }
}

impl<Pst, Entry, IntermediatePage, LeafPage> RootBTreePage<Pst, Entry, IntermediatePage, LeafPage>
where
    Pst: PstFile,
    <Pst as PstFile>::BlockId: BlockIdReadWrite,
    <Pst as PstFile>::ByteIndex: ByteIndexReadWrite,
    <Pst as PstFile>::BlockRef: BlockRefReadWrite,
    <Pst as PstFile>::PageRef: BlockRefReadWrite,
    <Pst as PstFile>::PageTrailer: PageTrailerReadWrite,
    <Pst as PstFile>::BTreeKey: BTreePageKeyReadWrite + Into<u64>,
    Entry: BTreeEntry<Key = <Pst as PstFile>::BTreeKey> + BTreeEntryReadWrite,
    IntermediatePage: RootBTreeIntermediatePage<Pst, Entry, LeafPage>,
    LeafPage: RootBTreeLeafPage<Pst, Entry = Entry>,
    <Self as RootBTree>::Entry: BTreeEntry<Key = <Pst as PstFile>::BTreeKey> + BTreeEntryReadWrite,
    <Self as RootBTree>::IntermediatePage: RootBTreeIntermediatePageReadWrite<Pst, Entry, LeafPage>,
    <Self as RootBTree>::LeafPage: RootBTreeLeafPageReadWrite<Pst>,
{
    pub fn read<R: PstReader>(f: &mut R, block: <Pst as PstFile>::PageRef) -> io::Result<Self> {
        <Self as RootBTreeReadWrite>::read(f, block)
    }

    pub fn find_entry<R: PstReader>(
        &self,
        f: &mut R,
        key: <Pst as PstFile>::BTreeKey,
        page_cache: &mut RootBTreePageCache<Self>,
    ) -> io::Result<Entry> {
        <Self as RootBTreeReadWrite>::find_entry(self, f, key, page_cache)
    }
}

pub type UnicodeBTree<Entry, LeafPage> =
    RootBTreePage<UnicodePstFile, Entry, UnicodeBTreeEntryPage, LeafPage>;

pub type AnsiBTree<Entry, LeafPage> =
    RootBTreePage<AnsiPstFile, Entry, AnsiBTreeEntryPage, LeafPage>;

pub trait BlockBTree<Pst, Entry>: RootBTree<Pst = Pst, Entry = Entry>
where
    Pst: PstFile,
    Entry: BTreeEntry<Key = <Pst as PstFile>::BTreeKey>
        + BlockBTreeEntry<Block = <Pst as PstFile>::BlockRef>,
    <Self as RootBTree>::IntermediatePage:
        RootBTreeIntermediatePage<Pst, Entry, <Self as RootBTree>::LeafPage>,
    <Self as RootBTree>::LeafPage: RootBTreeLeafPage<Pst, Entry = <Self as RootBTree>::Entry>,
{
}

pub type UnicodeBlockBTree = UnicodeBTree<UnicodeBlockBTreeEntry, UnicodeBlockBTreePage>;
impl BlockBTree<UnicodePstFile, UnicodeBlockBTreeEntry> for UnicodeBlockBTree {}
impl BlockBTreeReadWrite<UnicodePstFile, UnicodeBlockBTreeEntry> for UnicodeBlockBTree {}

pub type AnsiBlockBTree = AnsiBTree<AnsiBlockBTreeEntry, AnsiBlockBTreePage>;
impl BlockBTree<AnsiPstFile, AnsiBlockBTreeEntry> for AnsiBlockBTree {}
impl BlockBTreeReadWrite<AnsiPstFile, AnsiBlockBTreeEntry> for AnsiBlockBTree {}

pub trait NodeBTree<Pst, Entry>: RootBTree<Pst = Pst, Entry = Entry>
where
    Pst: PstFile,
    Entry: BTreeEntry<Key = <Pst as PstFile>::BTreeKey>
        + NodeBTreeEntry<Block = <Pst as PstFile>::BlockId>,
    <Self as RootBTree>::IntermediatePage:
        RootBTreeIntermediatePage<Pst, Entry, <Self as RootBTree>::LeafPage>,
    <Self as RootBTree>::LeafPage: RootBTreeLeafPage<Pst, Entry = <Self as RootBTree>::Entry>,
{
}

pub type UnicodeNodeBTree = UnicodeBTree<UnicodeNodeBTreeEntry, UnicodeNodeBTreePage>;
impl NodeBTree<UnicodePstFile, UnicodeNodeBTreeEntry> for UnicodeNodeBTree {}
impl NodeBTreeReadWrite<UnicodePstFile, UnicodeNodeBTreeEntry> for UnicodeNodeBTree {}

pub type AnsiNodeBTree = AnsiBTree<AnsiNodeBTreeEntry, AnsiNodeBTreePage>;
impl NodeBTree<AnsiPstFile, AnsiNodeBTreeEntry> for AnsiNodeBTree {}
impl NodeBTreeReadWrite<AnsiPstFile, AnsiNodeBTreeEntry> for AnsiNodeBTree {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// A 512-byte Unicode node BTree page at `offset` of `file`, with a valid CRC: an
    /// intermediate page of `level` whose one entry leads to the page at `child`, or a leaf page
    /// (`child` of `None`) with one entry for NID 0x21.
    fn put_page(file: &mut Vec<u8>, offset: usize, level: u8, child: Option<usize>) {
        if file.len() < offset + PAGE_SIZE {
            file.resize(offset + PAGE_SIZE, 0);
        }
        let page = &mut file[offset..offset + PAGE_SIZE];
        page.fill(0);
        match child {
            Some(child) => {
                page[8..16].copy_from_slice(&(child as u64).to_le_bytes());
                page[16..24].copy_from_slice(&(child as u64).to_le_bytes());
                page[488..492].copy_from_slice(&[1, 20, 24, level]);
            }
            None => {
                page[0..8].copy_from_slice(&0x21_u64.to_le_bytes());
                page[488..492].copy_from_slice(&[1, 15, 32, 0]);
            }
        }
        let crc = compute_crc(0, &page[..496]);
        page[496] = PageType::NodeBTree as u8;
        page[497] = PageType::NodeBTree as u8;
        page[500..504].copy_from_slice(&crc.to_le_bytes());
        page[504..512].copy_from_slice(&(offset as u64).to_le_bytes());
    }

    fn find(file: &[u8], root: usize) -> io::Result<UnicodeNodeBTreeEntry> {
        let mut f = Cursor::new(file.to_vec());
        let root = UnicodePageRef::new(
            UnicodePageId::from(root as u64),
            UnicodeByteIndex::new(root as u64),
        );
        let btree = UnicodeNodeBTree::read(&mut f, root)?;
        btree.find_entry(&mut f, 0x21, &mut Default::default())
    }

    #[test]
    fn test_btree_lookup() {
        let mut file = Vec::new();
        put_page(&mut file, 0x400, 2, Some(0x600));
        put_page(&mut file, 0x600, 1, Some(0x800));
        put_page(&mut file, 0x800, 0, None);
        assert_eq!(u32::from(find(&file, 0x400).unwrap().node()), 0x21);
    }

    #[test]
    fn test_btree_page_that_points_at_itself() {
        let mut file = Vec::new();
        put_page(&mut file, 0x400, 1, Some(0x400));
        let err = find(&file, 0x400).unwrap_err();
        assert!(err.to_string().contains("lookup path"), "{err}");
    }

    #[test]
    fn test_btree_level_that_goes_up() {
        // A level-1 page over a level-2 page over a leaf: a stale reference some writers leave,
        // followed because the path is finite.
        let mut file = Vec::new();
        put_page(&mut file, 0x400, 1, Some(0x600));
        put_page(&mut file, 0x600, 2, Some(0x800));
        put_page(&mut file, 0x800, 0, None);
        assert!(find(&file, 0x400).is_ok());
    }

    #[test]
    fn test_btree_deeper_than_the_limit() {
        // Distinct pages, each the only child of the one before: deeper than any BTree.
        let mut file = Vec::new();
        let depth = MAX_BTREE_DEPTH + 4;
        for i in 0..depth {
            put_page(&mut file, 0x400 * (i + 1), 1, Some(0x400 * (i + 2)));
        }
        put_page(&mut file, 0x400 * (depth + 1), 0, None);
        let err = find(&file, 0x400).unwrap_err();
        assert!(err.to_string().contains("deeper"), "{err}");
    }
}
