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

#![allow(dead_code)]

use std::{
    cell::RefCell,
    collections::BTreeMap,
    io::{self, Cursor, Read, SeekFrom, Write},
    rc::Rc,
};

use super::{
    block::*, block_id::*, block_ref::*, byte_index::*, header::*, node_id::*, page::*, root::*, *,
};
use crate::{
    PstFile, PstReader,
    crc::compute_crc,
    encode::{cyclic, permute},
};

pub trait NodeIdReadWrite: Copy + Sized {
    fn new(id_type: NodeIdType, index: u32) -> NdbResult<Self>;
    fn read(f: &mut dyn Read) -> io::Result<Self>;
    fn write(&self, f: &mut dyn Write) -> io::Result<()>;
}

pub trait BlockIdReadWrite: BlockId {
    fn read(f: &mut dyn Read) -> io::Result<Self>;
    fn write(&self, f: &mut dyn Write) -> io::Result<()>;
}

pub trait ByteIndexReadWrite: ByteIndex {
    fn new(index: Self::Index) -> Self;
    fn read(f: &mut dyn Read) -> io::Result<Self>;
    fn write(&self, f: &mut dyn Write) -> io::Result<()>;
}

pub trait BlockRefReadWrite: BlockRef
where
    <Self as BlockRef>::Block: BlockIdReadWrite,
    <Self as BlockRef>::Index: ByteIndexReadWrite,
{
    fn new(block: Self::Block, index: Self::Index) -> Self;

    fn read(f: &mut dyn Read) -> io::Result<Self> {
        let block = Self::Block::read(f)?;
        let index = Self::Index::read(f)?;
        Ok(Self::new(block, index))
    }

    fn write(&self, f: &mut dyn Write) -> io::Result<()> {
        self.block().write(f)?;
        self.index().write(f)
    }
}

pub trait RootReadWrite<Pst>: Root<Pst> + Sized
where
    Pst: PstFile,
    <Pst as PstFile>::ByteIndex: ByteIndexReadWrite,
    <Pst as PstFile>::PageRef: BlockRefReadWrite,
{
    fn new(
        file_eof_index: <Pst as PstFile>::ByteIndex,
        amap_last_index: <Pst as PstFile>::ByteIndex,
        amap_free_size: <Pst as PstFile>::ByteIndex,
        pmap_free_size: <Pst as PstFile>::ByteIndex,
        node_btree: <Pst as PstFile>::PageRef,
        block_btree: <Pst as PstFile>::PageRef,
        amap_is_valid: AmapStatus,
    ) -> Self;

    fn load_reserved(&mut self, reserved1: u32, reserved2: u8, reserved3: u16);

    fn reserved1(&self) -> u32;
    fn reserved2(&self) -> u8;
    fn reserved3(&self) -> u16;

    fn read(f: &mut dyn Read) -> io::Result<Self> {
        let reserved1 = f.read_u32::<LittleEndian>()?;
        let file_eof_index = <<Pst as PstFile>::ByteIndex as ByteIndexReadWrite>::read(f)?;
        let amap_last_index = <<Pst as PstFile>::ByteIndex as ByteIndexReadWrite>::read(f)?;
        let amap_free_size = <<Pst as PstFile>::ByteIndex as ByteIndexReadWrite>::read(f)?;
        let pmap_free_size = <<Pst as PstFile>::ByteIndex as ByteIndexReadWrite>::read(f)?;
        let node_btree = <<Pst as PstFile>::PageRef as BlockRefReadWrite>::read(f)?;
        let block_btree = <<Pst as PstFile>::PageRef as BlockRefReadWrite>::read(f)?;
        let amap_is_valid = AmapStatus::try_from(f.read_u8()?).unwrap_or(AmapStatus::Invalid);
        let reserved2 = f.read_u8()?;
        let reserved3 = f.read_u16::<LittleEndian>()?;
        let mut root = <Self as RootReadWrite<Pst>>::new(
            file_eof_index,
            amap_last_index,
            amap_free_size,
            pmap_free_size,
            node_btree,
            block_btree,
            amap_is_valid,
        );
        root.load_reserved(reserved1, reserved2, reserved3);
        Ok(root)
    }
}

pub trait HeaderReadWrite<Pst>: Header<Pst> + Sized
where
    Pst: PstFile,
    <Pst as PstFile>::Root: Root<Pst> + RootReadWrite<Pst>,
{
    fn read(f: &mut dyn Read) -> io::Result<Self>;
}

pub trait PageTrailerReadWrite: PageTrailer + Copy + Sized {
    fn new(page_type: PageType, signature: u16, block_id: Self::BlockId, crc: u32) -> Self;
    fn read(f: &mut dyn Read) -> io::Result<Self>;
    fn write(&self, f: &mut dyn Write) -> io::Result<()>;
}

pub trait MapPageReadWrite<Pst, const PAGE_TYPE: u8>: MapPage<Pst, PAGE_TYPE> + Sized
where
    Pst: PstFile,
{
    fn new(amap_bits: MapBits, trailer: Pst::PageTrailer) -> NdbResult<Self>;
    fn read(f: &mut dyn Read) -> io::Result<Self>;
}

pub trait AllocationMapPageReadWrite<Pst>:
    MapPageReadWrite<Pst, { PageType::AllocationMap as u8 }>
where
    Pst: PstFile,
{
    fn new(amap_bits: MapBits, trailer: Pst::PageTrailer) -> NdbResult<Self> {
        <Self as MapPageReadWrite<Pst, { PageType::AllocationMap as u8 }>>::new(amap_bits, trailer)
    }

    fn read(f: &mut dyn Read) -> io::Result<Self> {
        <Self as MapPageReadWrite<Pst, { PageType::AllocationMap as u8 }>>::read(f)
    }
}

impl<Pst, Page> AllocationMapPageReadWrite<Pst> for Page
where
    Pst: PstFile,
    Page: MapPageReadWrite<Pst, { PageType::AllocationMap as u8 }>,
{
}

pub trait AllocationPageMapPageReadWrite<Pst>:
    MapPageReadWrite<Pst, { PageType::AllocationPageMap as u8 }>
where
    Pst: PstFile,
{
    fn new(amap_bits: MapBits, trailer: Pst::PageTrailer) -> NdbResult<Self> {
        <Self as MapPageReadWrite<Pst, { PageType::AllocationPageMap as u8 }>>::new(
            amap_bits, trailer,
        )
    }

    fn read(f: &mut dyn Read) -> io::Result<Self> {
        <Self as MapPageReadWrite<Pst, { PageType::AllocationPageMap as u8 }>>::read(f)
    }
}

impl<Pst, Page> AllocationPageMapPageReadWrite<Pst> for Page
where
    Pst: PstFile,
    Page: MapPageReadWrite<Pst, { PageType::AllocationPageMap as u8 }>,
{
}

pub trait FreeMapPageReadWrite<Pst>: MapPageReadWrite<Pst, { PageType::FreeMap as u8 }>
where
    Pst: PstFile,
{
    fn new(amap_bits: MapBits, trailer: Pst::PageTrailer) -> NdbResult<Self> {
        <Self as MapPageReadWrite<Pst, { PageType::FreeMap as u8 }>>::new(amap_bits, trailer)
    }

    fn read(f: &mut dyn Read) -> io::Result<Self> {
        <Self as MapPageReadWrite<Pst, { PageType::FreeMap as u8 }>>::read(f)
    }
}

impl<Pst, Page> FreeMapPageReadWrite<Pst> for Page
where
    Pst: PstFile,
    Page: MapPageReadWrite<Pst, { PageType::FreeMap as u8 }>,
{
}

pub trait FreePageMapPageReadWrite<Pst>:
    MapPageReadWrite<Pst, { PageType::FreePageMap as u8 }>
where
    Pst: PstFile,
{
    fn new(amap_bits: MapBits, trailer: Pst::PageTrailer) -> NdbResult<Self> {
        <Self as MapPageReadWrite<Pst, { PageType::FreePageMap as u8 }>>::new(amap_bits, trailer)
    }

    fn read(f: &mut dyn Read) -> io::Result<Self> {
        <Self as MapPageReadWrite<Pst, { PageType::FreePageMap as u8 }>>::read(f)
    }
}

impl<Pst, Page> FreePageMapPageReadWrite<Pst> for Page
where
    Pst: PstFile,
    Page: MapPageReadWrite<Pst, { PageType::FreePageMap as u8 }>,
{
}

pub trait DensityListPageReadWrite<Pst>: DensityListPage<Pst> + Sized
where
    Pst: PstFile,
{
    const MAX_ENTRIES: usize;

    fn new(
        backfill_complete: bool,
        current_page: u32,
        entries: &[DensityListPageEntry],
        trailer: <Pst as PstFile>::PageTrailer,
    ) -> NdbResult<Self>;
    fn read<R: PstReader>(f: &mut R) -> io::Result<Self>;
}

pub trait BTreePageKeyReadWrite: BTreeEntryKey + TryFrom<u64> {
    fn read(f: &mut dyn Read) -> io::Result<Self>;
    fn write(self, f: &mut dyn Write) -> io::Result<()>;
}

pub trait BTreeEntryReadWrite: BTreeEntry + Copy + Sized + Default {
    const ENTRY_SIZE: usize;

    fn read(f: &mut dyn Read) -> io::Result<Self>;
    fn write(&self, f: &mut dyn Write) -> io::Result<()>;

    /// Read an entry from a page in the 4 KiB layout ([`NdbVersion::Unicode4k`]), where it may
    /// differ: a block BTree entry carries the block's inflated size.
    fn read_4k(f: &mut dyn Read) -> io::Result<Self> {
        Self::read(f)
    }
}

pub trait BlockBTreeEntryReadWrite: BlockBTreeEntry + BTreeEntryReadWrite {
    fn new(block: Self::Block, size: u16) -> Self;
}

pub trait BTreePageEntryReadWrite: BTreePageEntry
where
    Self: BTreeEntryReadWrite,
    <Self as BTreeEntry>::Key: BTreePageKeyReadWrite,
    <Self as BTreePageEntry>::Block:
        BlockRef<Block: BlockIdReadWrite, Index: ByteIndexReadWrite> + BlockRefReadWrite,
{
    const ENTRY_SIZE: usize;

    fn new(key: Self::Key, block: Self::Block) -> Self;

    fn read(f: &mut dyn Read) -> io::Result<Self> {
        Ok(Self::new(Self::Key::read(f)?, Self::Block::read(f)?))
    }

    fn write(&self, f: &mut dyn Write) -> io::Result<()> {
        self.key().write(f)?;
        self.block().write(f)
    }
}

pub trait BTreePageReadWrite: BTreePage + Sized {
    fn new(
        level: u8,
        max_entries: u8,
        entry_size: u8,
        entries: &[Self::Entry],
        trailer: Self::Trailer,
    ) -> NdbResult<Self>;

    fn max_entries(&self) -> u8;
    fn entry_size(&self) -> u8;
}

pub const UNICODE_BTREE_ENTRIES_SIZE: usize = 488;

/// The size of a page in the 4 KiB layout ([`NdbVersion::Unicode4k`]).
pub const UNICODE_4K_PAGE_SIZE: usize = 4096;

/// The space for entries in a BTree page of the 4 KiB layout.
pub const UNICODE_4K_BTREE_ENTRIES_SIZE: usize = 4056;

/// The page trailer's offset in a page of the 4 KiB layout. The trailer is 24 bytes: the 16 of
/// [`UnicodePageTrailer`] and 8 more.
pub const UNICODE_4K_PAGE_TRAILER_OFFSET: usize = 4072;

/// Whether `page` holds a BTree page trailer at `offset` whose CRC matches the bytes before it.
fn is_btree_page(page: &[u8], offset: usize) -> bool {
    let (Some(data), Some([page_type, repeat, _, _, c0, c1, c2, c3])) = (
        page.get(..offset),
        page.get(offset..)
            .and_then(|trailer| trailer.first_chunk::<8>()),
    ) else {
        return false;
    };
    let crc = u32::from_le_bytes([*c0, *c1, *c2, *c3]);
    page_type == repeat
        && (*page_type == PageType::BlockBTree as u8 || *page_type == PageType::NodeBTree as u8)
        && compute_crc(0, data) == crc
}

/// `data[range]`, or an [`io::ErrorKind::UnexpectedEof`] error if it is out of bounds.
pub(crate) fn get_range<T>(data: &[T], range: std::ops::Range<usize>) -> io::Result<&[T]> {
    data.get(range)
        .ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))
}

/// The entries of a BTree page: `count` of them, `entry_size` bytes apart from its start.
fn read_btree_entries<Entry: BTreeEntryReadWrite>(
    entries: &[u8],
    count: usize,
    entry_size: u8,
    large: bool,
) -> io::Result<Vec<Entry>> {
    if entry_size == 0 {
        return Err(NdbError::InvalidBTreeEntrySize(entry_size).into());
    }
    let chunks = entries.chunks_exact(usize::from(entry_size));
    if chunks.len() < count {
        return Err(NdbError::InvalidBTreeEntryCount(count).into());
    }
    chunks
        .take(count)
        .map(|mut chunk| {
            if large {
                Entry::read_4k(&mut chunk)
            } else {
                Entry::read(&mut chunk)
            }
        })
        .collect()
}

/// Read a Unicode BTree page, in either layout: 512-byte pages, or the 4 KiB pages of Outlook
/// 2013 and later OSTs, told apart by where a trailer with a matching CRC sits, or, when neither
/// matches, by the file's header. Returns the page's bytes and whether it is a 4 KiB page.
pub(crate) fn read_unicode_btree_page(f: &mut dyn Read) -> io::Result<(Vec<u8>, bool)> {
    let mut page = vec![0_u8; PAGE_SIZE];
    f.read_exact(&mut page)?;
    if is_btree_page(&page, UNICODE_BTREE_ENTRIES_SIZE + 8) {
        return Ok((page, false));
    }
    let mut rest = vec![0_u8; UNICODE_4K_PAGE_SIZE.saturating_sub(PAGE_SIZE)];
    if f.read_exact(&mut rest).is_ok() {
        page.extend_from_slice(&rest);
        // Neither CRC matches: the file's header tells which layout it has.
        if is_btree_page(&page, UNICODE_4K_PAGE_TRAILER_OFFSET)
            || crate::problems::large_pages() == Some(true)
        {
            return Ok((page, true));
        }
    }
    // Parse it as a 512-byte page, to report what is wrong with it.
    page.truncate(PAGE_SIZE);
    Ok((page, false))
}

pub trait UnicodeBTreePageReadWrite<Entry>:
    BTreePageReadWrite<Entry = Entry, Trailer = UnicodePageTrailer> + Sized
where
    Entry: BTreeEntryReadWrite,
{
    fn read(f: &mut dyn Read) -> io::Result<Self> {
        let (page, large) = read_unicode_btree_page(f)?;
        let (entries_size, trailer_offset) = if large {
            (
                UNICODE_4K_BTREE_ENTRIES_SIZE,
                UNICODE_4K_PAGE_TRAILER_OFFSET,
            )
        } else {
            (UNICODE_BTREE_ENTRIES_SIZE, UNICODE_BTREE_TRAILER_OFFSET)
        };
        let buffer = get_range(&page, 0..trailer_offset)?;

        let mut cursor = Cursor::new(get_range(buffer, entries_size..buffer.len())?);

        // cEnt, cEntMax: one byte each in 512-byte pages, two in 4 KiB pages.
        let (entry_count, max_entries) = if large {
            let entry_count = usize::from(cursor.read_u16::<LittleEndian>()?);
            let max_entries = cursor.read_u16::<LittleEndian>()?;
            let max_entries = u8::try_from(max_entries)
                .map_err(|_| NdbError::InvalidBTreeEntryMaxCount(u8::MAX))?;
            (entry_count, max_entries)
        } else {
            (usize::from(cursor.read_u8()?), cursor.read_u8()?)
        };

        // cbEnt
        let entry_size = cursor.read_u8()?;

        if entry_count > usize::from(max_entries) {
            return Err(NdbError::InvalidBTreeEntryCount(entry_count).into());
        }
        if usize::from(entry_size) < Entry::ENTRY_SIZE {
            return Err(NdbError::InvalidBTreeEntrySize(entry_size).into());
        }
        if Some(usize::from(max_entries)) > entries_size.checked_div(usize::from(entry_size)) {
            return Err(NdbError::InvalidBTreeEntryMaxCount(max_entries).into());
        }

        // cLevel
        let level = cursor.read_u8()?;
        if !(0..=8).contains(&level) {
            return Err(NdbError::InvalidBTreePageLevel(level).into());
        }

        // dwPadding (10 bytes of padding in 4 KiB pages, not checked)
        if !large {
            let padding = cursor.read_u32::<LittleEndian>()?;
            if padding != 0 {
                crate::problems::check(
                    crate::problems::ProblemKind::PageField,
                    None,
                    || format!("BTPAGE dwPadding is 0x{padding:08X}"),
                    || NdbError::InvalidBTreePagePadding(padding).into(),
                )?;
            }
        }

        // pageTrailer
        let trailer = UnicodePageTrailer::read(&mut get_range(&page, trailer_offset..page.len())?)?;
        if trailer.page_type() != PageType::BlockBTree && trailer.page_type() != PageType::NodeBTree
        {
            return Err(NdbError::UnexpectedPageType(trailer.page_type()).into());
        }

        let crc = compute_crc(0, buffer);
        crate::problems::check_crc(
            crate::problems::ProblemKind::PageCrc,
            None,
            &format!("{:?} page {:?}", trailer.page_type(), trailer.block_id()),
            trailer.crc(),
            crc,
            || NdbError::InvalidPageCrc(crc).into(),
        )?;

        // rgentries
        let entries = read_btree_entries(
            get_range(buffer, 0..entries_size)?,
            entry_count,
            entry_size,
            large,
        )?;

        Ok(<Self as BTreePageReadWrite>::new(
            level,
            max_entries,
            entry_size,
            &entries,
            trailer,
        )?)
    }
}

pub const ANSI_BTREE_ENTRIES_SIZE: usize = 496;

/// The offset of the page trailer in a 512-byte Unicode BTree page.
const UNICODE_BTREE_TRAILER_OFFSET: usize = 496;

pub trait AnsiBTreePageReadWrite<Entry>:
    BTreePageReadWrite<Entry = Entry, Trailer = AnsiPageTrailer> + Sized
where
    Entry: BTreeEntryReadWrite,
{
    fn read(f: &mut dyn Read) -> io::Result<Self> {
        let mut buffer = [0_u8; 500];
        f.read_exact(&mut buffer)?;
        let buffer = buffer.as_slice();

        let (entries_data, page_footer) = buffer
            .split_at_checked(ANSI_BTREE_ENTRIES_SIZE)
            .ok_or(io::Error::from(io::ErrorKind::UnexpectedEof))?;
        let mut cursor = Cursor::new(page_footer);

        // cEnt
        let entry_count = usize::from(cursor.read_u8()?);

        // cEntMax
        let max_entries = cursor.read_u8()?;

        // cbEnt
        let entry_size = cursor.read_u8()?;

        if entry_count > usize::from(max_entries) {
            return Err(NdbError::InvalidBTreeEntryCount(entry_count).into());
        }
        if usize::from(entry_size) < Entry::ENTRY_SIZE {
            return Err(NdbError::InvalidBTreeEntrySize(entry_size).into());
        }
        if Some(usize::from(max_entries))
            > ANSI_BTREE_ENTRIES_SIZE.checked_div(usize::from(entry_size))
        {
            return Err(NdbError::InvalidBTreeEntryMaxCount(max_entries).into());
        }

        // cLevel
        let level = cursor.read_u8()?;
        if !(0..=8).contains(&level) {
            return Err(NdbError::InvalidBTreePageLevel(level).into());
        }

        // pageTrailer
        let trailer = AnsiPageTrailer::read(f)?;
        if trailer.page_type() != PageType::BlockBTree && trailer.page_type() != PageType::NodeBTree
        {
            return Err(NdbError::UnexpectedPageType(trailer.page_type()).into());
        }

        let crc = compute_crc(0, buffer);
        crate::problems::check_crc(
            crate::problems::ProblemKind::PageCrc,
            None,
            &format!("{:?} page {:?}", trailer.page_type(), trailer.block_id()),
            trailer.crc(),
            crc,
            || NdbError::InvalidPageCrc(crc).into(),
        )?;

        // rgentries
        let entries = read_btree_entries(entries_data, entry_count, entry_size, false)?;

        Ok(<Self as BTreePageReadWrite>::new(
            level,
            max_entries,
            entry_size,
            &entries,
            trailer,
        )?)
    }
}

pub trait NodeBTreeEntryReadWrite: NodeBTreeEntry + BTreeEntryReadWrite {
    fn new(
        node: NodeId,
        data: <Self as NodeBTreeEntry>::Block,
        sub_node: Option<<Self as NodeBTreeEntry>::Block>,
        parent: Option<NodeId>,
    ) -> Self;
}

pub trait BlockTrailerReadWrite: BlockTrailer + Copy + Sized {
    const SIZE: u16;

    fn new(size: u16, signature: u16, crc: u32, block_id: Self::BlockId) -> NdbResult<Self>;
    fn read(f: &mut dyn Read) -> io::Result<Self>;
    fn write(&self, f: &mut dyn Write) -> io::Result<()>;
}

pub trait BlockReadWrite: Block + Sized
where
    <Self as Block>::Trailer: BlockTrailerReadWrite,
{
    fn new(encoding: NdbCryptMethod, data: Vec<u8>, trailer: Self::Trailer) -> NdbResult<Self>;

    fn read<R: PstReader>(f: &mut R, size: u16, encoding: NdbCryptMethod) -> io::Result<Self> {
        let mut data = vec![0; usize::from(size)];
        f.read_exact(&mut data)?;

        let padding = block_padding(size, Self::Trailer::SIZE)?;
        if padding > 0 {
            f.seek(SeekFrom::Current(i64::from(padding)))?;
        }

        let trailer = Self::Trailer::read(f)?;
        if trailer.size() != size {
            return Err(NdbError::InvalidBlockSize(trailer.size()).into());
        }
        trailer.verify_block_id(false)?;
        let crc = compute_crc(0, &data);
        crate::problems::check_crc(
            crate::problems::ProblemKind::BlockCrc,
            None,
            &format!("block 0x{:X}", trailer.block_id().into_u64()),
            trailer.crc(),
            crc,
            || NdbError::InvalidBlockCrc(crc).into(),
        )?;

        match encoding {
            NdbCryptMethod::Cyclic => {
                let key = trailer.cyclic_key();
                cyclic::encode_decode_block(&mut data, key);
            }
            NdbCryptMethod::Permute => {
                permute::decode_block(&mut data);
            }
            _ => {}
        }

        Ok(Self::new(encoding, data, trailer)?)
    }
}

pub trait IntermediateTreeHeaderReadWrite: IntermediateTreeHeader + Copy + Sized {
    const HEADER_SIZE: u16;

    fn read(f: &mut dyn Read) -> io::Result<Self>;
    fn write(&self, f: &mut dyn Write) -> io::Result<()>;
}

pub trait SubNodeTreeBlockHeaderReadWrite: IntermediateTreeHeaderReadWrite {
    fn new(level: u8, entry_count: u16) -> Self;
}

pub trait IntermediateTreeEntryReadWrite: IntermediateTreeEntry + Copy + Sized {
    const ENTRY_SIZE: u16;

    fn read(f: &mut dyn Read) -> io::Result<Self>;
    fn write(&self, f: &mut dyn Write) -> io::Result<()>;
}

/// The `count` entries at the start of an intermediate block's data, after its header.
pub(crate) fn read_intermediate_entries<Entry: IntermediateTreeEntryReadWrite>(
    data: &[u8],
    count: u16,
) -> io::Result<Vec<Entry>> {
    let chunks = data.chunks_exact(usize::from(Entry::ENTRY_SIZE.max(1)));
    if chunks.len() < usize::from(count) {
        return Err(NdbError::InvalidInternalBlockEntryCount(count).into());
    }
    chunks
        .take(usize::from(count))
        .map(|mut chunk| Entry::read(&mut chunk))
        .collect()
}

/// The bytes between a block's data of `size` bytes and its trailer of `trailer_size` bytes: the
/// two fill a slot of a multiple of 64 bytes.
pub(crate) fn block_padding(size: u16, trailer_size: u16) -> NdbResult<u16> {
    let used = size
        .checked_add(trailer_size)
        .ok_or(NdbError::InvalidBlockSize(size))?;
    block_size(used)
        .and_then(|slot| slot.checked_sub(used))
        .ok_or(NdbError::InvalidBlockSize(size))
}

pub trait IntermediateTreeBlockReadWrite: IntermediateTreeBlock + Sized
where
    <Self as IntermediateTreeBlock>::Header: IntermediateTreeHeaderReadWrite,
    <Self as IntermediateTreeBlock>::Entry: IntermediateTreeEntryReadWrite,
    <Self as IntermediateTreeBlock>::Trailer: BlockTrailerReadWrite,
{
    fn new(
        header: Self::Header,
        entries: Vec<Self::Entry>,
        trailer: Self::Trailer,
    ) -> NdbResult<Self>;

    fn read<R: PstReader>(f: &mut R, header: Self::Header, size: u16) -> io::Result<Self> {
        let mut data = vec![0; usize::from(size)];
        f.read_exact(&mut data)?;
        let entries_data = get_range(&data, usize::from(Self::Header::HEADER_SIZE)..data.len())
            .map_err(|_| NdbError::InvalidBlockSize(size))?;

        let entry_count = header.entry_count();
        let entries = read_intermediate_entries::<Self::Entry>(entries_data, entry_count)?;

        // The trailer is at the end of the block's slot.
        let padding = block_padding(size, Self::Trailer::SIZE)?;
        if padding > 0 {
            f.seek(SeekFrom::Current(i64::from(padding)))?;
        }

        let trailer = Self::Trailer::read(f)?;
        trailer.verify_block_id(true)?;

        let crc = compute_crc(0, &data);
        crate::problems::check_crc(
            crate::problems::ProblemKind::BlockCrc,
            None,
            &format!("block 0x{:X}", trailer.block_id().into_u64()),
            trailer.crc(),
            crc,
            || NdbError::InvalidBlockCrc(crc).into(),
        )?;

        Ok(Self::new(header, entries, trailer)?)
    }
}

type RootBTreePageReadWrite<BTree> = RootBTreePage<
    <BTree as RootBTree>::Pst,
    <BTree as RootBTree>::Entry,
    <BTree as RootBTree>::IntermediatePage,
    <BTree as RootBTree>::LeafPage,
>;

pub type RootBTreePageCache<BTree> =
    BTreeMap<<<BTree as RootBTree>::Pst as PstFile>::PageId, RootBTreePageReadWrite<BTree>>;

pub type BlockBTreePageCache<Pst> = Rc<RefCell<RootBTreePageCache<<Pst as PstFile>::BlockBTree>>>;
pub type NodeBTreePageCache<Pst> = Rc<RefCell<RootBTreePageCache<<Pst as PstFile>::NodeBTree>>>;

pub trait RootBTreeReadWrite: RootBTree + Sized
where
    <<Self as RootBTree>::Pst as PstFile>::BlockId: BlockIdReadWrite,
    <<Self as RootBTree>::Pst as PstFile>::ByteIndex: ByteIndexReadWrite,
    <<Self as RootBTree>::Pst as PstFile>::BlockRef: BlockRefReadWrite,
    <<Self as RootBTree>::Pst as PstFile>::PageTrailer: PageTrailerReadWrite,
    <<Self as RootBTree>::Pst as PstFile>::BTreeKey: BTreePageKeyReadWrite,
    <Self as RootBTree>::Entry: BTreeEntryReadWrite,
    <Self as RootBTree>::IntermediatePage: RootBTreeIntermediatePageReadWrite<
            <Self as RootBTree>::Pst,
            <Self as RootBTree>::Entry,
            <Self as RootBTree>::LeafPage,
        >,
    <Self as RootBTree>::LeafPage:
        RootBTreeLeafPageReadWrite<<Self as RootBTree>::Pst> + BTreePageReadWrite,
{
    fn read<R: PstReader>(
        f: &mut R,
        block: <<Self as RootBTree>::Pst as PstFile>::PageRef,
    ) -> io::Result<RootBTreePageReadWrite<Self>>;
    fn find_entry<R: PstReader>(
        &self,
        f: &mut R,
        key: <<Self as RootBTree>::Pst as PstFile>::BTreeKey,
        page_cache: &mut RootBTreePageCache<Self>,
    ) -> io::Result<<Self as RootBTree>::Entry>;
}

pub trait RootBTreeIntermediatePageReadWrite<Pst, Entry, LeafPage>:
    RootBTreeIntermediatePage<Pst, Entry, LeafPage> + BTreePageReadWrite
where
    Pst: PstFile,
    <Pst as PstFile>::BlockId: BlockIdReadWrite,
    <Pst as PstFile>::ByteIndex: ByteIndexReadWrite,
    <Pst as PstFile>::BlockRef: BlockRefReadWrite,
    <Pst as PstFile>::PageTrailer: PageTrailerReadWrite,
    <Pst as PstFile>::BTreeKey: BTreePageKeyReadWrite,
    Entry: BTreeEntry<Key = <Pst as PstFile>::BTreeKey> + BTreeEntryReadWrite,
    LeafPage: RootBTreeLeafPage<Pst, Entry = Entry> + RootBTreeLeafPageReadWrite<Pst>,
{
    fn read<R: PstReader>(f: &mut R) -> io::Result<Self>;
}

pub trait RootBTreeLeafPageReadWrite<Pst>: RootBTreeLeafPage<Pst> + BTreePageReadWrite
where
    Pst: PstFile,
    <Pst as PstFile>::BlockId: BlockIdReadWrite,
    <Pst as PstFile>::ByteIndex: ByteIndexReadWrite,
    <Pst as PstFile>::BlockRef: BlockRefReadWrite,
    <Pst as PstFile>::PageTrailer: PageTrailerReadWrite,
    <Pst as PstFile>::BTreeKey: BTreePageKeyReadWrite,
    <Self as RootBTreeLeafPage<Pst>>::Entry: BTreeEntryReadWrite,
{
    const BTREE_ENTRIES_SIZE: usize;

    fn read<R: PstReader>(f: &mut R) -> io::Result<Self>;
}

pub trait BlockBTreeReadWrite<Pst, Entry>: BlockBTree<Pst, Entry> + RootBTreeReadWrite
where
    Pst: PstFile,
    <Pst as PstFile>::BlockId: BlockIdReadWrite,
    <Pst as PstFile>::ByteIndex: ByteIndexReadWrite,
    <Pst as PstFile>::BlockRef: BlockRefReadWrite,
    <Pst as PstFile>::PageTrailer: PageTrailerReadWrite,
    <Pst as PstFile>::BTreeKey: BTreePageKeyReadWrite,
    Entry: BTreeEntry<Key = <Pst as PstFile>::BTreeKey>
        + BTreeEntryReadWrite
        + BlockBTreeEntry<Block = <Pst as PstFile>::BlockRef>,
    <Self as RootBTree>::IntermediatePage:
        RootBTreeIntermediatePageReadWrite<Pst, Entry, <Self as RootBTree>::LeafPage>,
    <Self as RootBTree>::LeafPage: RootBTreeLeafPage<Pst, Entry = <Self as RootBTree>::Entry>
        + RootBTreeLeafPageReadWrite<Pst>,
{
}

pub trait NodeBTreeReadWrite<Pst, Entry>: NodeBTree<Pst, Entry> + RootBTreeReadWrite
where
    Pst: PstFile,
    <Pst as PstFile>::BlockId: BlockIdReadWrite,
    <Pst as PstFile>::ByteIndex: ByteIndexReadWrite,
    <Pst as PstFile>::BlockRef: BlockRefReadWrite,
    <Pst as PstFile>::PageTrailer: PageTrailerReadWrite,
    <Pst as PstFile>::BTreeKey: BTreePageKeyReadWrite,
    Entry: BTreeEntry<Key = <Pst as PstFile>::BTreeKey>
        + BTreeEntryReadWrite
        + NodeBTreeEntry<Block = <Pst as PstFile>::BlockId>,
    <Self as RootBTree>::IntermediatePage:
        RootBTreeIntermediatePageReadWrite<Pst, Entry, <Self as RootBTree>::LeafPage>,
    <Self as RootBTree>::LeafPage: RootBTreeLeafPage<Pst, Entry = <Self as RootBTree>::Entry>
        + RootBTreeLeafPageReadWrite<Pst>,
{
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ndb::{
        block::{
            AnsiDataTreeBlock, DataTreeBlockHeader, MAX_BLOCK_SIZE, UnicodeDataBlock,
            UnicodeDataTreeBlock,
        },
        page::{AnsiBlockBTreePage, UnicodeBlockBTreePage, UnicodeNodeBTreePage},
    };

    /// A 512-byte Unicode BTree page with a valid CRC.
    fn unicode_page(entries: &[u8], count: u8, max: u8, size: u8, level: u8, ptype: u8) -> Vec<u8> {
        let mut page = vec![0_u8; PAGE_SIZE];
        page[..entries.len()].copy_from_slice(entries);
        page[488..492].copy_from_slice(&[count, max, size, level]);
        let crc = compute_crc(0, &page[..496]);
        page[496] = ptype;
        page[497] = ptype;
        page[500..504].copy_from_slice(&crc.to_le_bytes());
        page[504..512].copy_from_slice(&0x100_u64.to_le_bytes());
        page
    }

    /// A 512-byte ANSI BTree page with a valid CRC.
    fn ansi_page(entries: &[u8], count: u8, max: u8, size: u8, level: u8, ptype: u8) -> Vec<u8> {
        let mut page = vec![0_u8; PAGE_SIZE];
        page[..entries.len()].copy_from_slice(entries);
        page[496..500].copy_from_slice(&[count, max, size, level]);
        let crc = compute_crc(0, &page[..500]);
        page[500] = ptype;
        page[501] = ptype;
        page[504..508].copy_from_slice(&0x100_u32.to_le_bytes());
        page[508..512].copy_from_slice(&crc.to_le_bytes());
        page
    }

    fn read_unicode_bbt(page: &[u8]) -> io::Result<UnicodeBlockBTreePage> {
        <UnicodeBlockBTreePage as UnicodeBTreePageReadWrite<_>>::read(&mut &page[..])
    }

    #[test]
    fn test_block_size() {
        assert_eq!(block_size(0), None);
        assert_eq!(block_size(1), Some(64));
        assert_eq!(block_size(64), Some(64));
        assert_eq!(block_size(65), Some(128));
        assert_eq!(block_size(MAX_BLOCK_SIZE), Some(MAX_BLOCK_SIZE));
        assert_eq!(block_size(MAX_BLOCK_SIZE + 1), None);
        assert_eq!(block_size(u16::MAX), None);
        assert_eq!(block_padding(100, 16).unwrap(), 12);
        assert!(block_padding(u16::MAX, 16).is_err());
        assert!(block_padding(MAX_BLOCK_SIZE, 16).is_err());
    }

    #[test]
    fn test_unicode_btree_page_counts() {
        // Two block BTree entries of 24 bytes each.
        let mut entries = vec![0_u8; 48];
        entries[0] = 0x04;
        entries[24] = 0x08;
        let page = unicode_page(&entries, 2, 20, 24, 0, PageType::BlockBTree as u8);
        assert_eq!(read_unicode_bbt(&page).unwrap().entries().len(), 2);

        // More entries than cEntMax, an entry size of 0 or too small, a cEntMax the page
        // cannot hold: errors, not panics.
        for (count, max, size) in [
            (21, 20, 24),
            (1, 20, 0),
            (1, 20, 23),
            (1, 21, 24),
            (0, 255, 1),
        ] {
            let page = unicode_page(&entries, count, max, size, 0, PageType::BlockBTree as u8);
            assert!(read_unicode_bbt(&page).is_err(), "{count} {max} {size}");
        }

        // A level the format does not have.
        let page = unicode_page(&entries, 2, 20, 24, 9, PageType::BlockBTree as u8);
        assert!(read_unicode_bbt(&page).is_err());

        // A node BTree leaf page.
        let page = unicode_page(&[0; 64], 2, 15, 32, 0, PageType::NodeBTree as u8);
        let page = <UnicodeNodeBTreePage as UnicodeBTreePageReadWrite<_>>::read(&mut &page[..]);
        assert_eq!(page.unwrap().entries().len(), 2);
    }

    #[test]
    fn test_ansi_btree_page_counts() {
        let entries = vec![0_u8; 24];
        let read =
            |page: &[u8]| <AnsiBlockBTreePage as AnsiBTreePageReadWrite<_>>::read(&mut &page[..]);
        let page = ansi_page(&entries, 2, 41, 12, 0, PageType::BlockBTree as u8);
        assert_eq!(read(&page).unwrap().entries().len(), 2);
        for (count, max, size) in [(42, 41, 12), (1, 41, 0), (1, 41, 11), (1, 42, 12)] {
            let page = ansi_page(&entries, count, max, size, 0, PageType::BlockBTree as u8);
            assert!(read(&page).is_err(), "{count} {max} {size}");
        }
    }

    #[test]
    fn test_truncated_page_is_an_error() {
        let page = unicode_page(&[], 0, 20, 24, 0, PageType::BlockBTree as u8);
        for len in [0, 1, 100, 511] {
            assert!(read_unicode_bbt(&page[..len]).is_err());
        }
    }

    #[test]
    fn test_block_sizes_from_the_file() {
        // A cb that leaves no room for the trailer in a block slot.
        let data = vec![0_u8; usize::from(u16::MAX) + 64];
        let read = |size| {
            <UnicodeDataBlock as BlockReadWrite>::read(
                &mut Cursor::new(&data),
                size,
                NdbCryptMethod::None,
            )
        };
        assert!(read(u16::MAX).is_err());
        assert!(read(MAX_BLOCK_SIZE).is_err());
        assert!(read(0).is_err());
    }

    #[test]
    fn test_intermediate_block_sizes_from_the_file() {
        let data = vec![0_u8; 512];
        let read = |entry_count, size| {
            <UnicodeDataTreeBlock as IntermediateTreeBlockReadWrite>::read(
                &mut Cursor::new(&data),
                DataTreeBlockHeader::new(1, entry_count, 0),
                size,
            )
        };
        // A cb smaller than the block's header, and more entries than cb holds.
        assert!(read(0, 4).is_err());
        assert!(read(u16::MAX, 64).is_err());
        assert!(read(10, 16).is_err());
        let read = |entry_count, size| {
            <AnsiDataTreeBlock as IntermediateTreeBlockReadWrite>::read(
                &mut Cursor::new(&data),
                DataTreeBlockHeader::new(1, entry_count, 0),
                size,
            )
        };
        assert!(read(u16::MAX, 64).is_err());
        assert!(read(0, 0).is_err());
    }
}
