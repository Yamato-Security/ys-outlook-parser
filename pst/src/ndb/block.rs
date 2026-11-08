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

//! [Blocks](https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-pst/a9c1981d-d1ea-457c-b39e-dc7fb0eb95d4)

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque, btree_map},
    io::{self, Cursor, Read, Seek, SeekFrom, Write},
};
use tracing::error;

use super::{block_id::*, block_ref::*, byte_index::*, node_id::*, page::*, read_write::*, *};
use crate::{
    AnsiPstFile, PstFile, PstFileReadWriteBlockBTree, PstReader, UnicodePstFile,
    crc::compute_crc,
    encode::{cyclic, permute},
};

pub const MAX_BLOCK_SIZE: u16 = 8192;

/// The size of a block trailer in the 4 KiB layout of Outlook 2013 and later OSTs: the 16 bytes of
/// [`UnicodeBlockTrailer`], two bytes, the inflated size and four bytes of padding.
pub const UNICODE_4K_BLOCK_TRAILER_SIZE: usize = 24;

/// Blocks in the 4 KiB layout start on, and fill, slots of a multiple of this size.
pub const UNICODE_4K_BLOCK_ALIGNMENT: usize = 512;

/// The most data a block holds in the 4 KiB layout, once inflated.
pub const MAX_UNICODE_4K_BLOCK_DATA_SIZE: u16 = (65536 - UNICODE_4K_BLOCK_TRAILER_SIZE) as u16;

/// Read a block in the 4 KiB layout: check its trailer and CRC, and inflate it if it is
/// compressed. Returns the (still encoded) data and a trailer describing it as inflated.
fn read_4k_block<Pst, R>(
    f: &mut R,
    block: &<Pst as PstFile>::BlockBTreeEntry,
    inflated_size: u16,
) -> io::Result<(Vec<u8>, <Pst as PstFile>::BlockTrailer)>
where
    Pst: PstFile,
    <Pst as PstFile>::BlockId: BlockIdReadWrite,
    <Pst as PstFile>::BlockTrailer: BlockTrailerReadWrite,
    R: PstReader,
{
    let size = usize::from(block.size());
    // At most 65,535 + 24 bytes, rounded up to 512: no overflow.
    let slot = size
        .saturating_add(UNICODE_4K_BLOCK_TRAILER_SIZE)
        .div_ceil(UNICODE_4K_BLOCK_ALIGNMENT)
        .saturating_mul(UNICODE_4K_BLOCK_ALIGNMENT);
    f.seek(SeekFrom::Start(block.block().index().index().into()))?;
    let mut buffer = vec![0; slot];
    f.read_exact(&mut buffer)?;

    let (stored, mut trailer) = buffer
        .split_at_checked(slot.saturating_sub(UNICODE_4K_BLOCK_TRAILER_SIZE))
        .ok_or(NdbError::InvalidBlockSize(block.size()))?;
    let stored_size = trailer.read_u16::<LittleEndian>()?;
    let signature = trailer.read_u16::<LittleEndian>()?;
    let crc = trailer.read_u32::<LittleEndian>()?;
    let block_id = <Pst as PstFile>::BlockId::read(&mut trailer)?;
    if usize::from(stored_size) != size {
        return Err(NdbError::InvalidBlockSize(stored_size).into());
    }

    let stored = stored
        .get(..size)
        .ok_or(NdbError::InvalidBlockSize(stored_size))?;
    let stored_crc = compute_crc(0, stored);
    crate::problems::check_crc(
        crate::problems::ProblemKind::BlockCrc,
        Some(block.block().index().index().into()),
        &format!("block 0x{:X}", block.block().block().into_u64()),
        crc,
        stored_crc,
        || NdbError::InvalidBlockCrc(stored_crc).into(),
    )?;

    let data = if inflated_size == block.size() {
        stored.to_vec()
    } else {
        let mut data = Vec::with_capacity(usize::from(inflated_size));
        flate2::read::ZlibDecoder::new(stored)
            .take(u64::from(inflated_size) + 1)
            .read_to_end(&mut data)?;
        if data.len() != usize::from(inflated_size) {
            return Err(
                NdbError::InvalidBlockSize(u16::try_from(data.len()).unwrap_or(u16::MAX)).into(),
            );
        }
        data
    };

    let trailer = <<Pst as PstFile>::BlockTrailer as BlockTrailerReadWrite>::new(
        inflated_size,
        signature,
        compute_crc(0, &data),
        block_id,
    )?;
    trailer.verify_block_id(block.block().block().is_internal())?;
    Ok((data, trailer))
}

/// Decode a data block's bytes as [`BlockReadWrite::read`] does.
fn decode_block<Trailer: BlockTrailer>(
    encoding: NdbCryptMethod,
    data: &mut [u8],
    trailer: &Trailer,
) {
    match encoding {
        NdbCryptMethod::Cyclic => cyclic::encode_decode_block(data, trailer.cyclic_key()),
        NdbCryptMethod::Permute => permute::decode_block(data),
        _ => {}
    }
}

/// An intermediate block (XBLOCK, XXBLOCK, SIBLOCK, SLBLOCK) from its inflated data.
fn intermediate_block<Block>(
    data: &[u8],
    header: Block::Header,
    trailer: Block::Trailer,
) -> io::Result<Block>
where
    Block: IntermediateTreeBlockReadWrite,
    Block::Header: IntermediateTreeHeaderReadWrite,
    Block::Entry: IntermediateTreeEntryReadWrite,
    Block::Trailer: BlockTrailerReadWrite,
{
    let entry_count = header.entry_count();
    let entries = data
        .get(usize::from(Block::Header::HEADER_SIZE)..)
        .ok_or(NdbError::InvalidInternalBlockEntryCount(entry_count))?;
    let entries = read_intermediate_entries::<Block::Entry>(entries, entry_count)?;
    Ok(Block::new(header, entries, trailer)?)
}

/// The size of the slot a block fills: its data and trailer, `size` bytes, rounded up to a
/// multiple of 64. `None` for a size of 0 or more than [`MAX_BLOCK_SIZE`].
pub const fn block_size(size: u16) -> Option<u16> {
    if size == 0 || size > MAX_BLOCK_SIZE {
        None
    } else {
        size.div_ceil(64).checked_mul(64)
    }
}

/// [BLOCKTRAILER](https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-pst/a14943ef-70c2-403f-898c-5bc3747117e1)
/// The size of the slot a block with `size` bytes of data fills, with its trailer.
fn slot_size<Pst>(size: u16) -> NdbResult<u16>
where
    Pst: PstFile,
    <Pst as PstFile>::BlockTrailer: BlockTrailerReadWrite,
{
    size.checked_add(<<Pst as PstFile>::BlockTrailer as BlockTrailerReadWrite>::SIZE)
        .and_then(block_size)
        .ok_or(NdbError::InvalidBlockSize(size))
}

pub trait BlockTrailer {
    type BlockId: BlockId;

    fn size(&self) -> u16;
    fn signature(&self) -> u16;
    fn crc(&self) -> u32;
    fn block_id(&self) -> Self::BlockId;
    fn cyclic_key(&self) -> u32;
    fn verify_block_id(&self, is_internal: bool) -> NdbResult<()>;
}

#[derive(Clone, Copy, Default)]
pub struct UnicodeBlockTrailer {
    size: u16,
    signature: u16,
    crc: u32,
    block_id: UnicodeBlockId,
}

impl UnicodeBlockTrailer {
    pub fn new(size: u16, signature: u16, crc: u32, block_id: UnicodeBlockId) -> NdbResult<Self> {
        // Blocks in the 4 KiB layout hold up to MAX_UNICODE_4K_BLOCK_DATA_SIZE bytes inflated.
        if !(1..=MAX_UNICODE_4K_BLOCK_DATA_SIZE).contains(&size) {
            return Err(NdbError::InvalidBlockSize(size));
        }

        Ok(Self {
            size,
            block_id,
            signature,
            crc,
        })
    }
}

impl BlockTrailer for UnicodeBlockTrailer {
    type BlockId = UnicodeBlockId;

    fn size(&self) -> u16 {
        self.size
    }

    fn signature(&self) -> u16 {
        self.signature
    }

    fn crc(&self) -> u32 {
        self.crc
    }

    fn block_id(&self) -> UnicodeBlockId {
        self.block_id
    }

    fn cyclic_key(&self) -> u32 {
        self.block_id.search_key() as u32
    }

    fn verify_block_id(&self, is_internal: bool) -> NdbResult<()> {
        if self.block_id.is_internal() != is_internal {
            return Err(NdbError::InvalidUnicodeBlockTrailerId(u64::from(
                self.block_id,
            )));
        }
        Ok(())
    }
}

impl BlockTrailerReadWrite for UnicodeBlockTrailer {
    const SIZE: u16 = 16;

    fn new(size: u16, signature: u16, crc: u32, block_id: UnicodeBlockId) -> NdbResult<Self> {
        Self::new(size, signature, crc, block_id)
    }

    fn read(f: &mut dyn Read) -> io::Result<Self> {
        let size = f.read_u16::<LittleEndian>()?;
        if !(1..=(MAX_BLOCK_SIZE - Self::SIZE)).contains(&size) {
            return Err(NdbError::InvalidBlockSize(size).into());
        }

        let signature = f.read_u16::<LittleEndian>()?;
        let crc = f.read_u32::<LittleEndian>()?;
        let block_id = UnicodeBlockId::read(f)?;

        Ok(Self {
            size,
            signature,
            crc,
            block_id,
        })
    }

    fn write(&self, f: &mut dyn Write) -> io::Result<()> {
        f.write_u16::<LittleEndian>(self.size)?;
        f.write_u16::<LittleEndian>(self.signature)?;
        f.write_u32::<LittleEndian>(self.crc)?;
        self.block_id.write(f)
    }
}

#[derive(Clone, Copy, Default)]
pub struct AnsiBlockTrailer {
    size: u16,
    signature: u16,
    block_id: AnsiBlockId,
    crc: u32,
}

impl AnsiBlockTrailer {
    pub fn new(size: u16, signature: u16, crc: u32, block_id: AnsiBlockId) -> NdbResult<Self> {
        if !(1..=(MAX_BLOCK_SIZE - Self::SIZE)).contains(&size) {
            return Err(NdbError::InvalidBlockSize(size));
        }

        Ok(Self {
            size,
            signature,
            block_id,
            crc,
        })
    }
}

impl BlockTrailer for AnsiBlockTrailer {
    type BlockId = AnsiBlockId;

    fn size(&self) -> u16 {
        self.size
    }

    fn signature(&self) -> u16 {
        self.signature
    }

    fn crc(&self) -> u32 {
        self.crc
    }

    fn block_id(&self) -> AnsiBlockId {
        self.block_id
    }

    fn cyclic_key(&self) -> u32 {
        self.block_id.search_key()
    }

    fn verify_block_id(&self, is_internal: bool) -> NdbResult<()> {
        if self.block_id.is_internal() != is_internal {
            return Err(NdbError::InvalidAnsiBlockTrailerId(u32::from(
                self.block_id,
            )));
        }
        Ok(())
    }
}

impl BlockTrailerReadWrite for AnsiBlockTrailer {
    const SIZE: u16 = 12;

    fn new(size: u16, signature: u16, crc: u32, block_id: AnsiBlockId) -> NdbResult<Self> {
        Self::new(size, signature, crc, block_id)
    }

    fn read(f: &mut dyn Read) -> io::Result<Self> {
        let size = f.read_u16::<LittleEndian>()?;
        if !(1..=(MAX_BLOCK_SIZE - Self::SIZE)).contains(&size) {
            return Err(NdbError::InvalidBlockSize(size).into());
        }

        let signature = f.read_u16::<LittleEndian>()?;
        let block_id = AnsiBlockId::read(f)?;
        let crc = f.read_u32::<LittleEndian>()?;

        Ok(Self {
            size,
            signature,
            block_id,
            crc,
        })
    }

    fn write(&self, f: &mut dyn Write) -> io::Result<()> {
        f.write_u16::<LittleEndian>(self.size)?;
        f.write_u16::<LittleEndian>(self.signature)?;
        self.block_id.write(f)?;
        f.write_u32::<LittleEndian>(self.crc)
    }
}

/// [Data Blocks](https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-pst/d0e6fbaf-00e3-4d4d-bea8-8ab3cdb4fde6)
pub trait Block {
    type Trailer: BlockTrailer;

    fn encoding(&self) -> NdbCryptMethod;
    fn data(&self) -> &[u8];
    fn trailer(&self) -> &Self::Trailer;
}

#[derive(Clone, Default)]
pub struct UnicodeDataBlock {
    encoding: NdbCryptMethod,
    data: Vec<u8>,
    trailer: UnicodeBlockTrailer,
}

impl UnicodeDataBlock {
    pub fn new(
        encoding: NdbCryptMethod,
        data: Vec<u8>,
        trailer: UnicodeBlockTrailer,
    ) -> NdbResult<Self> {
        Ok(Self {
            data,
            encoding,
            trailer,
        })
    }
}

impl Block for UnicodeDataBlock {
    type Trailer = UnicodeBlockTrailer;

    fn encoding(&self) -> NdbCryptMethod {
        self.encoding
    }

    fn data(&self) -> &[u8] {
        &self.data
    }

    fn trailer(&self) -> &UnicodeBlockTrailer {
        &self.trailer
    }
}

impl BlockReadWrite for UnicodeDataBlock {
    fn new(
        encoding: NdbCryptMethod,
        data: Vec<u8>,
        trailer: UnicodeBlockTrailer,
    ) -> NdbResult<Self> {
        Self::new(encoding, data, trailer)
    }
}

impl From<UnicodeDataBlock> for Vec<u8> {
    fn from(value: UnicodeDataBlock) -> Self {
        value.data
    }
}

#[derive(Clone, Default)]
pub struct AnsiDataBlock {
    encoding: NdbCryptMethod,
    data: Vec<u8>,
    trailer: AnsiBlockTrailer,
}

impl AnsiDataBlock {
    pub fn new(
        encoding: NdbCryptMethod,
        data: Vec<u8>,
        trailer: AnsiBlockTrailer,
    ) -> NdbResult<Self> {
        Ok(Self {
            data,
            encoding,
            trailer,
        })
    }
}

impl Block for AnsiDataBlock {
    type Trailer = AnsiBlockTrailer;

    fn encoding(&self) -> NdbCryptMethod {
        self.encoding
    }

    fn data(&self) -> &[u8] {
        &self.data
    }

    fn trailer(&self) -> &AnsiBlockTrailer {
        &self.trailer
    }
}

impl BlockReadWrite for AnsiDataBlock {
    fn new(encoding: NdbCryptMethod, data: Vec<u8>, trailer: AnsiBlockTrailer) -> NdbResult<Self> {
        Self::new(encoding, data, trailer)
    }
}

impl From<AnsiDataBlock> for Vec<u8> {
    fn from(value: AnsiDataBlock) -> Self {
        value.data
    }
}

pub trait IntermediateTreeHeader {
    fn level(&self) -> u8;
    fn entry_count(&self) -> u16;
}

pub trait IntermediateTreeEntry {}

pub trait IntermediateTreeBlock {
    type Header: IntermediateTreeHeader;
    type Entry: IntermediateTreeEntry;
    type Trailer: BlockTrailer;

    fn header(&self) -> &Self::Header;
    fn entries(&self) -> &[Self::Entry];
    fn trailer(&self) -> &Self::Trailer;
}

#[derive(Clone, Copy, Default)]
pub struct DataTreeBlockHeader {
    level: u8,
    entry_count: u16,
    total_size: u32,
}

impl DataTreeBlockHeader {
    pub fn new(level: u8, entry_count: u16, total_size: u32) -> Self {
        Self {
            level,
            entry_count,
            total_size,
        }
    }

    pub fn total_size(&self) -> u32 {
        self.total_size
    }
}

impl IntermediateTreeHeader for DataTreeBlockHeader {
    fn level(&self) -> u8 {
        self.level
    }

    fn entry_count(&self) -> u16 {
        self.entry_count
    }
}

impl IntermediateTreeHeaderReadWrite for DataTreeBlockHeader {
    const HEADER_SIZE: u16 = 8;

    fn read(f: &mut dyn Read) -> io::Result<Self> {
        let block_type = f.read_u8()?;
        if block_type != 0x01 {
            return Err(NdbError::InvalidInternalBlockType(block_type).into());
        }

        let level = f.read_u8()?;
        let entry_count = f.read_u16::<LittleEndian>()?;
        let total_size = f.read_u32::<LittleEndian>()?;

        Ok(Self {
            level,
            entry_count,
            total_size,
        })
    }

    fn write(&self, f: &mut dyn Write) -> io::Result<()> {
        f.write_u8(0x01)?;
        f.write_u8(self.level)?;
        f.write_u16::<LittleEndian>(self.entry_count)?;
        f.write_u32::<LittleEndian>(self.total_size)
    }
}

pub trait IntermediateDataTreeEntry<Pst>: IntermediateTreeEntry
where
    Pst: PstFile,
{
    fn new(block: <Pst as PstFile>::BlockId) -> Self;
    fn block(&self) -> <Pst as PstFile>::BlockId;
}

#[derive(Clone, Copy, Default)]
pub struct UnicodeDataTreeEntry(UnicodeBlockId);

impl IntermediateTreeEntry for UnicodeDataTreeEntry {}

impl IntermediateDataTreeEntry<UnicodePstFile> for UnicodeDataTreeEntry {
    fn new(block: UnicodeBlockId) -> Self {
        Self(block)
    }

    fn block(&self) -> UnicodeBlockId {
        self.0
    }
}

impl IntermediateTreeEntryReadWrite for UnicodeDataTreeEntry {
    const ENTRY_SIZE: u16 = 8;

    fn read(f: &mut dyn Read) -> io::Result<Self> {
        Ok(Self(UnicodeBlockId::read(f)?))
    }

    fn write(&self, f: &mut dyn Write) -> io::Result<()> {
        self.0.write(f)
    }
}

impl From<UnicodeBlockId> for UnicodeDataTreeEntry {
    fn from(value: UnicodeBlockId) -> Self {
        Self::new(value)
    }
}

impl From<UnicodeDataTreeEntry> for UnicodeBlockId {
    fn from(value: UnicodeDataTreeEntry) -> Self {
        value.block()
    }
}

#[derive(Clone, Copy, Default)]
pub struct AnsiDataTreeEntry(AnsiBlockId);

impl IntermediateTreeEntry for AnsiDataTreeEntry {}

impl IntermediateDataTreeEntry<AnsiPstFile> for AnsiDataTreeEntry {
    fn new(block: AnsiBlockId) -> Self {
        Self(block)
    }

    fn block(&self) -> AnsiBlockId {
        self.0
    }
}

impl IntermediateTreeEntryReadWrite for AnsiDataTreeEntry {
    const ENTRY_SIZE: u16 = 4;

    fn read(f: &mut dyn Read) -> io::Result<Self> {
        Ok(Self(AnsiBlockId::read(f)?))
    }

    fn write(&self, f: &mut dyn Write) -> io::Result<()> {
        self.0.write(f)
    }
}

impl From<AnsiBlockId> for AnsiDataTreeEntry {
    fn from(value: AnsiBlockId) -> Self {
        Self::new(value)
    }
}

impl From<AnsiDataTreeEntry> for AnsiBlockId {
    fn from(value: AnsiDataTreeEntry) -> Self {
        value.block()
    }
}

/// [XBLOCK](https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-pst/5b7a6935-e83d-4917-9f62-6ce3707f09e0)
/// / [XXBLOCK](https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-pst/061b6ac4-d1da-468c-b75d-0303a0a8f468)
struct DataTreeBlockInner<Entry, Trailer>
where
    Entry: IntermediateTreeEntry,
    Trailer: BlockTrailer,
{
    header: DataTreeBlockHeader,
    entries: Vec<Entry>,
    trailer: Trailer,
}

impl<Entry, Trailer> DataTreeBlockInner<Entry, Trailer>
where
    Entry: IntermediateTreeEntry,
    Trailer: BlockTrailer,
{
    pub fn new(
        header: DataTreeBlockHeader,
        entries: Vec<Entry>,
        trailer: Trailer,
    ) -> NdbResult<Self> {
        trailer.verify_block_id(true)?;

        Ok(Self {
            header,
            entries,
            trailer,
        })
    }
}

pub struct UnicodeDataTreeBlock {
    inner: DataTreeBlockInner<UnicodeDataTreeEntry, UnicodeBlockTrailer>,
}

impl IntermediateTreeBlock for UnicodeDataTreeBlock {
    type Header = DataTreeBlockHeader;
    type Entry = UnicodeDataTreeEntry;
    type Trailer = UnicodeBlockTrailer;

    fn header(&self) -> &Self::Header {
        &self.inner.header
    }

    fn entries(&self) -> &[Self::Entry] {
        &self.inner.entries
    }

    fn trailer(&self) -> &Self::Trailer {
        &self.inner.trailer
    }
}

impl IntermediateTreeBlockReadWrite for UnicodeDataTreeBlock {
    fn new(
        header: DataTreeBlockHeader,
        entries: Vec<UnicodeDataTreeEntry>,
        trailer: UnicodeBlockTrailer,
    ) -> NdbResult<Self> {
        Ok(Self {
            inner: DataTreeBlockInner::new(header, entries, trailer)?,
        })
    }
}

pub struct AnsiDataTreeBlock {
    inner: DataTreeBlockInner<AnsiDataTreeEntry, AnsiBlockTrailer>,
}

impl IntermediateTreeBlock for AnsiDataTreeBlock {
    type Header = DataTreeBlockHeader;
    type Entry = AnsiDataTreeEntry;
    type Trailer = AnsiBlockTrailer;

    fn header(&self) -> &Self::Header {
        &self.inner.header
    }

    fn entries(&self) -> &[Self::Entry] {
        &self.inner.entries
    }

    fn trailer(&self) -> &Self::Trailer {
        &self.inner.trailer
    }
}

impl IntermediateTreeBlockReadWrite for AnsiDataTreeBlock {
    fn new(
        header: DataTreeBlockHeader,
        entries: Vec<AnsiDataTreeEntry>,
        trailer: AnsiBlockTrailer,
    ) -> NdbResult<Self> {
        Ok(Self {
            inner: DataTreeBlockInner::new(header, entries, trailer)?,
        })
    }
}

pub type DataBlockCache<Pst> = BTreeMap<<Pst as PstFile>::BlockId, DataTree<Pst>>;

/// An intermediate block of `level` under one of `parent_level`: a problem when its level is not
/// below its parent's (an error when reading strictly). The walk's limits end the walk either way.
fn check_child_level(level: u8, parent_level: u8, offset: u64) -> io::Result<()> {
    if level < parent_level {
        return Ok(());
    }
    crate::problems::check(
        crate::problems::ProblemKind::BlockField,
        Some(offset),
        || format!("intermediate block of cLevel {level} under one of cLevel {parent_level}"),
        || NdbError::InvalidInternalBlockLevel(level).into(),
    )
}

/// The most levels of intermediate blocks a data tree or sub-node tree is walked through below
/// its root: MS-PST has at most 2 (an XXBLOCK over XBLOCKs) and 1 (an SIBLOCK over SLBLOCKs).
pub const MAX_BLOCK_TREE_DEPTH: usize = 8;

/// The limits of a walk over one data tree (XBLOCK, XXBLOCK) or sub-node tree (SIBLOCK,
/// SLBLOCK): each block at most once, at most [`MAX_BLOCK_TREE_DEPTH`] levels down, and no more
/// bytes of blocks than the file holds. A block that refers to itself or to a block above it, or
/// many entries for the same bytes, end the walk with an error instead of recursing forever or
/// reading without end. A block whose `cLevel` is not below its parent's is walked: the limits
/// are what guarantee the walk ends.
pub(crate) struct TreeWalk {
    visited: BTreeSet<u64>,
    remaining: u64,
}

impl TreeWalk {
    /// A walk whose blocks may hold at most as many bytes as the file.
    pub(crate) fn new<R: PstReader>(f: &mut R) -> io::Result<Self> {
        let remaining = f.seek(SeekFrom::End(0))?;
        Ok(Self {
            visited: Default::default(),
            remaining,
        })
    }

    /// Count the tree's root, which the walk does not read.
    fn root<Id: BlockId>(&mut self, block: Id) {
        self.visited.insert(block.search_key().into());
    }

    /// Count a block of the tree: an error if it is already in the tree, or if the tree's blocks
    /// would hold more bytes than the file.
    fn visit<Pst>(&mut self, block: &<Pst as PstFile>::BlockBTreeEntry) -> NdbResult<()>
    where
        Pst: PstFile,
        <Pst as PstFile>::BlockTrailer: BlockTrailerReadWrite,
    {
        let id: u64 = block.block().block().search_key().into();
        if !self.visited.insert(id) {
            return Err(NdbError::BlockTreeLoop(id));
        }
        let size = u64::from(block.size());
        // The slot the block fills in the file: 512-byte aligned with a 24-byte trailer in the
        // 4 KiB layout, else 64-byte aligned with the layout's trailer.
        let slot = if block.inflated_size().is_some() {
            size.saturating_add(UNICODE_4K_BLOCK_TRAILER_SIZE as u64)
                .div_ceil(UNICODE_4K_BLOCK_ALIGNMENT as u64)
                .saturating_mul(UNICODE_4K_BLOCK_ALIGNMENT as u64)
        } else {
            size.saturating_add(u64::from(
                <<Pst as PstFile>::BlockTrailer as BlockTrailerReadWrite>::SIZE,
            ))
            .div_ceil(64)
            .saturating_mul(64)
        };
        self.remaining = self
            .remaining
            .checked_sub(slot)
            .ok_or(NdbError::BlockTreeTooLarge(id))?;
        Ok(())
    }
}

pub enum DataTree<Pst>
where
    Pst: PstFile,
{
    Intermediate(Box<<Pst as PstFile>::DataTreeBlock>),
    Leaf(Box<<Pst as PstFile>::DataBlock>),
}

impl<Pst> DataTree<Pst>
where
    Pst: PstFile,
    <Pst as PstFile>::BlockTrailer: BlockTrailerReadWrite,
    <Pst as PstFile>::DataTreeBlock: IntermediateTreeBlockReadWrite,
    <<Pst as PstFile>::DataTreeBlock as IntermediateTreeBlock>::Entry:
        IntermediateTreeEntryReadWrite,
    <Pst as PstFile>::DataBlock: BlockReadWrite,
{
    pub fn read<R>(
        f: &mut R,
        encoding: NdbCryptMethod,
        block: &<Pst as PstFile>::BlockBTreeEntry,
    ) -> io::Result<Self>
    where
        R: PstReader,
    {
        crate::problems::at_offset(block.block().index().index().into(), || {
            Self::read_at(f, encoding, block)
        })
    }

    fn read_at<R>(
        f: &mut R,
        encoding: NdbCryptMethod,
        block: &<Pst as PstFile>::BlockBTreeEntry,
    ) -> io::Result<Self>
    where
        R: PstReader,
    {
        if let Some(inflated_size) = block.inflated_size() {
            let (mut data, trailer) = read_4k_block::<Pst, R>(f, block, inflated_size)?;
            return Ok(if block.block().block().is_internal() {
                let header = DataTreeBlockHeader::read(&mut data.as_slice())?;
                Self::Intermediate(Box::new(intermediate_block(&data, header, trailer)?))
            } else {
                decode_block(encoding, &mut data, &trailer);
                Self::Leaf(Box::new(
                    <<Pst as PstFile>::DataBlock as BlockReadWrite>::new(encoding, data, trailer)?,
                ))
            });
        }

        f.seek(SeekFrom::Start(block.block().index().index().into()))?;

        let block_size = slot_size::<Pst>(block.size())?;
        let mut data = vec![0; usize::from(block_size)];
        f.read_exact(&mut data)?;
        let mut cursor = Cursor::new(data);

        let block = if block.block().block().is_internal() {
            let header = DataTreeBlockHeader::read(&mut cursor)?;
            cursor.seek(SeekFrom::Start(0))?;
            let block = <<Pst as PstFile>::DataTreeBlock as IntermediateTreeBlockReadWrite>::read(
                &mut cursor,
                header,
                block.size(),
            )?;
            Self::Intermediate(Box::new(block))
        } else {
            let block = <<Pst as PstFile>::DataBlock as BlockReadWrite>::read(
                &mut cursor,
                block.size(),
                encoding,
            )?;
            Self::Leaf(Box::new(block))
        };

        Ok(block)
    }

    pub fn blocks<'a, R>(
        &'a self,
        f: &mut R,
        encoding: NdbCryptMethod,
        block_btree: &PstFileReadWriteBlockBTree<Pst>,
        page_cache: &mut RootBTreePageCache<<Pst as PstFile>::BlockBTree>,
        block_cache: &'a mut DataBlockCache<Pst>,
    ) -> io::Result<Box<dyn 'a + Iterator<Item = <Pst as PstFile>::DataBlock>>>
    where
        R: PstReader,
        <Pst as PstFile>::DataBlock: 'a + Clone,
        <Pst as PstFile>::BlockId: BlockId<Index = <Pst as PstFile>::BTreeKey> + BlockIdReadWrite,
        <Pst as PstFile>::ByteIndex: ByteIndexReadWrite,
        <Pst as PstFile>::BlockRef: BlockRefReadWrite,
        <Pst as PstFile>::PageTrailer: PageTrailerReadWrite,
        <Pst as PstFile>::BTreeKey: BTreePageKeyReadWrite,
        <Pst as PstFile>::BlockBTree: RootBTreeReadWrite,
        <<Pst as PstFile>::BlockBTree as RootBTree>::Entry: BTreeEntryReadWrite,
        <<Pst as PstFile>::BlockBTree as RootBTree>::IntermediatePage:
            RootBTreeIntermediatePageReadWrite<
                    Pst,
                    <<Pst as PstFile>::BlockBTree as RootBTree>::Entry,
                    <<Pst as PstFile>::BlockBTree as RootBTree>::LeafPage,
                >,
        <<Pst as PstFile>::BlockBTree as RootBTree>::LeafPage:
            RootBTreeLeafPageReadWrite<Pst> + BTreePageReadWrite,
    {
        let mut walk = TreeWalk::new(f)?;
        walk.root(self.block_id());
        let mut blocks = Vec::new();
        self.collect_blocks(
            f,
            encoding,
            block_btree,
            page_cache,
            block_cache,
            &mut walk,
            &mut blocks,
            0,
        )?;
        Ok(Box::new(blocks.into_iter()))
    }

    /// The block ID in the block's trailer.
    fn block_id(&self) -> <Pst as PstFile>::BlockId {
        match self {
            Self::Intermediate(block) => block.trailer().block_id(),
            Self::Leaf(block) => block.trailer().block_id(),
        }
    }

    /// The tree's `cLevel`: 0 for a data block, 1 for an XBLOCK and 2 for an XXBLOCK.
    pub fn level(&self) -> u8 {
        match self {
            Self::Intermediate(block) => block.header().level(),
            Self::Leaf(_) => 0,
        }
    }

    /// Read the tree at `entry`, `depth` levels below the root: from the cache, or from the file,
    /// counted in the walk.
    #[allow(clippy::too_many_arguments)]
    fn read_child<R>(
        f: &mut R,
        encoding: NdbCryptMethod,
        block_btree: &PstFileReadWriteBlockBTree<Pst>,
        page_cache: &mut RootBTreePageCache<<Pst as PstFile>::BlockBTree>,
        block_cache: &mut DataBlockCache<Pst>,
        walk: &mut TreeWalk,
        entry: <Pst as PstFile>::BlockId,
        depth: usize,
        parent_level: u8,
    ) -> io::Result<Self>
    where
        R: PstReader,
        <Pst as PstFile>::BlockId: BlockId<Index = <Pst as PstFile>::BTreeKey> + BlockIdReadWrite,
        <Pst as PstFile>::ByteIndex: ByteIndexReadWrite,
        <Pst as PstFile>::BlockRef: BlockRefReadWrite,
        <Pst as PstFile>::PageTrailer: PageTrailerReadWrite,
        <Pst as PstFile>::BTreeKey: BTreePageKeyReadWrite,
        <Pst as PstFile>::BlockBTree: RootBTreeReadWrite,
        <<Pst as PstFile>::BlockBTree as RootBTree>::Entry: BTreeEntryReadWrite,
        <<Pst as PstFile>::BlockBTree as RootBTree>::IntermediatePage:
            RootBTreeIntermediatePageReadWrite<
                    Pst,
                    <<Pst as PstFile>::BlockBTree as RootBTree>::Entry,
                    <<Pst as PstFile>::BlockBTree as RootBTree>::LeafPage,
                >,
        <<Pst as PstFile>::BlockBTree as RootBTree>::LeafPage:
            RootBTreeLeafPageReadWrite<Pst> + BTreePageReadWrite,
    {
        let data_block = block_btree.find_entry(f, entry.search_key(), page_cache)?;
        walk.visit::<Pst>(&data_block)?;
        if depth > MAX_BLOCK_TREE_DEPTH {
            return Err(NdbError::BlockTreeTooDeep(entry.search_key().into()).into());
        }
        let data_tree = match block_cache.remove(&entry) {
            Some(data_tree) => data_tree,
            None => Self::read(&mut *f, encoding, &data_block)?,
        };
        if let Self::Intermediate(_) = &data_tree
            && let Err(err) = check_child_level(
                data_tree.level(),
                parent_level,
                data_block.block().index().index().into(),
            )
        {
            block_cache.insert(entry, data_tree);
            return Err(err);
        }
        Ok(data_tree)
    }

    #[allow(clippy::too_many_arguments)]
    fn collect_blocks<R>(
        &self,
        f: &mut R,
        encoding: NdbCryptMethod,
        block_btree: &PstFileReadWriteBlockBTree<Pst>,
        page_cache: &mut RootBTreePageCache<<Pst as PstFile>::BlockBTree>,
        block_cache: &mut DataBlockCache<Pst>,
        walk: &mut TreeWalk,
        blocks: &mut Vec<<Pst as PstFile>::DataBlock>,
        depth: usize,
    ) -> io::Result<()>
    where
        R: PstReader,
        <Pst as PstFile>::DataBlock: Clone,
        <Pst as PstFile>::BlockId: BlockId<Index = <Pst as PstFile>::BTreeKey> + BlockIdReadWrite,
        <Pst as PstFile>::ByteIndex: ByteIndexReadWrite,
        <Pst as PstFile>::BlockRef: BlockRefReadWrite,
        <Pst as PstFile>::PageTrailer: PageTrailerReadWrite,
        <Pst as PstFile>::BTreeKey: BTreePageKeyReadWrite,
        <Pst as PstFile>::BlockBTree: RootBTreeReadWrite,
        <<Pst as PstFile>::BlockBTree as RootBTree>::Entry: BTreeEntryReadWrite,
        <<Pst as PstFile>::BlockBTree as RootBTree>::IntermediatePage:
            RootBTreeIntermediatePageReadWrite<
                    Pst,
                    <<Pst as PstFile>::BlockBTree as RootBTree>::Entry,
                    <<Pst as PstFile>::BlockBTree as RootBTree>::LeafPage,
                >,
        <<Pst as PstFile>::BlockBTree as RootBTree>::LeafPage:
            RootBTreeLeafPageReadWrite<Pst> + BTreePageReadWrite,
    {
        match self {
            Self::Intermediate(block) => {
                let depth = depth.saturating_add(1);
                for entry in block.entries() {
                    let data_tree = Self::read_child(
                        f,
                        encoding,
                        block_btree,
                        page_cache,
                        block_cache,
                        walk,
                        entry.block(),
                        depth,
                        block.header().level(),
                    )?;
                    let result = data_tree.collect_blocks(
                        f,
                        encoding,
                        block_btree,
                        page_cache,
                        block_cache,
                        walk,
                        blocks,
                        depth,
                    );
                    block_cache.insert(entry.block(), data_tree);
                    result?;
                }
                Ok(())
            }
            Self::Leaf(block) => {
                blocks.push(block.as_ref().clone());
                Ok(())
            }
        }
    }

    pub fn nth<R>(
        &self,
        n: usize,
        f: &mut R,
        encoding: NdbCryptMethod,
        block_btree: &PstFileReadWriteBlockBTree<Pst>,
        page_cache: &mut RootBTreePageCache<<Pst as PstFile>::BlockBTree>,
        block_cache: &mut DataBlockCache<Pst>,
    ) -> io::Result<Option<Vec<u8>>>
    where
        R: PstReader,
        <Pst as PstFile>::BlockId: BlockId<Index = <Pst as PstFile>::BTreeKey> + BlockIdReadWrite,
        <Pst as PstFile>::ByteIndex: ByteIndexReadWrite,
        <Pst as PstFile>::BlockRef: BlockRefReadWrite,
        <Pst as PstFile>::PageTrailer: PageTrailerReadWrite,
        <Pst as PstFile>::BTreeKey: BTreePageKeyReadWrite,
        <Pst as PstFile>::BlockBTree: RootBTreeReadWrite,
        <<Pst as PstFile>::BlockBTree as RootBTree>::Entry: BTreeEntryReadWrite,
        <<Pst as PstFile>::BlockBTree as RootBTree>::IntermediatePage:
            RootBTreeIntermediatePageReadWrite<
                    Pst,
                    <<Pst as PstFile>::BlockBTree as RootBTree>::Entry,
                    <<Pst as PstFile>::BlockBTree as RootBTree>::LeafPage,
                >,
        <<Pst as PstFile>::BlockBTree as RootBTree>::LeafPage:
            RootBTreeLeafPageReadWrite<Pst> + BTreePageReadWrite,
    {
        Ok(Some(match self {
            Self::Intermediate(_) => {
                let Some(data_block) = self
                    .sub_entries(f, encoding, block_btree, page_cache, block_cache)?
                    .nth(n)
                else {
                    return Ok(None);
                };

                let data_tree = match block_cache.entry(data_block.block().block()) {
                    btree_map::Entry::Vacant(entry) => {
                        entry.insert(Self::read(&mut *f, encoding, &data_block)?)
                    }
                    btree_map::Entry::Occupied(entry) => entry.into_mut(),
                };

                let Self::Leaf(block) = data_tree else {
                    error!(
                        name: "PstInvalidDataTreeIntermediateBlock",
                        "Data tree intermediate block has non-leaf sub-entry"
                    );

                    return Err(NdbError::InvalidInternalBlockLevel(0).into());
                };

                block.data().to_vec()
            }
            Self::Leaf(block) => {
                if n != 0 {
                    return Ok(None);
                }

                block.data().to_vec()
            }
        }))
    }

    pub fn reader<'a, R>(
        &self,
        f: &'a mut R,
        encoding: NdbCryptMethod,
        block_btree: &'a PstFileReadWriteBlockBTree<Pst>,
        page_cache: &mut RootBTreePageCache<<Pst as PstFile>::BlockBTree>,
        block_cache: &'a mut DataBlockCache<Pst>,
    ) -> io::Result<Box<dyn 'a + Read>>
    where
        Pst: 'a,
        R: PstReader,
        <Pst as PstFile>::DataBlock: 'a + Clone,
        <Pst as PstFile>::BTreeKey: BTreePageKeyReadWrite,
        <Pst as PstFile>::BlockBTree: RootBTreeReadWrite,
        <<Pst as PstFile>::BlockBTree as RootBTree>::Entry: BTreeEntryReadWrite,
        <<Pst as PstFile>::BlockBTree as RootBTree>::IntermediatePage:
            RootBTreeIntermediatePageReadWrite<
                    Pst,
                    <<Pst as PstFile>::BlockBTree as RootBTree>::Entry,
                    <<Pst as PstFile>::BlockBTree as RootBTree>::LeafPage,
                >,
        <<Pst as PstFile>::BlockBTree as RootBTree>::LeafPage:
            RootBTreeLeafPageReadWrite<Pst> + BTreePageReadWrite,
    {
        let reader: DataTreeReader<'a, Pst, R> =
            DataTreeReader::new(self, f, encoding, block_btree, page_cache, block_cache)?;
        let reader: Box<dyn 'a + Read> = Box::new(reader);
        Ok(reader)
    }

    fn sub_entries<'a, R>(
        &self,
        f: &mut R,
        encoding: NdbCryptMethod,
        block_btree: &PstFileReadWriteBlockBTree<Pst>,
        page_cache: &mut RootBTreePageCache<<Pst as PstFile>::BlockBTree>,
        block_cache: &'a mut DataBlockCache<Pst>,
    ) -> io::Result<Box<dyn 'a + Iterator<Item = <Pst as PstFile>::BlockBTreeEntry>>>
    where
        R: PstReader,
        <Pst as PstFile>::BlockBTreeEntry: 'a,
        <Pst as PstFile>::BlockId: BlockId<Index = <Pst as PstFile>::BTreeKey> + BlockIdReadWrite,
        <Pst as PstFile>::ByteIndex: ByteIndexReadWrite,
        <Pst as PstFile>::BlockRef: BlockRefReadWrite,
        <Pst as PstFile>::PageTrailer: PageTrailerReadWrite,
        <Pst as PstFile>::BTreeKey: BTreePageKeyReadWrite,
        <Pst as PstFile>::BlockBTree: RootBTreeReadWrite,
        <<Pst as PstFile>::BlockBTree as RootBTree>::Entry: BTreeEntryReadWrite,
        <<Pst as PstFile>::BlockBTree as RootBTree>::IntermediatePage:
            RootBTreeIntermediatePageReadWrite<
                    Pst,
                    <<Pst as PstFile>::BlockBTree as RootBTree>::Entry,
                    <<Pst as PstFile>::BlockBTree as RootBTree>::LeafPage,
                >,
        <<Pst as PstFile>::BlockBTree as RootBTree>::LeafPage:
            RootBTreeLeafPageReadWrite<Pst> + BTreePageReadWrite,
    {
        let mut walk = TreeWalk::new(f)?;
        walk.root(self.block_id());
        let mut entries = Vec::new();
        self.collect_sub_entries(
            f,
            encoding,
            block_btree,
            page_cache,
            block_cache,
            &mut walk,
            &mut entries,
            0,
        )?;
        Ok(Box::new(entries.into_iter()))
    }

    #[allow(clippy::too_many_arguments)]
    fn collect_sub_entries<R>(
        &self,
        f: &mut R,
        encoding: NdbCryptMethod,
        block_btree: &PstFileReadWriteBlockBTree<Pst>,
        page_cache: &mut RootBTreePageCache<<Pst as PstFile>::BlockBTree>,
        block_cache: &mut DataBlockCache<Pst>,
        walk: &mut TreeWalk,
        entries: &mut Vec<<Pst as PstFile>::BlockBTreeEntry>,
        depth: usize,
    ) -> io::Result<()>
    where
        R: PstReader,
        <Pst as PstFile>::BlockId: BlockId<Index = <Pst as PstFile>::BTreeKey> + BlockIdReadWrite,
        <Pst as PstFile>::ByteIndex: ByteIndexReadWrite,
        <Pst as PstFile>::BlockRef: BlockRefReadWrite,
        <Pst as PstFile>::PageTrailer: PageTrailerReadWrite,
        <Pst as PstFile>::BTreeKey: BTreePageKeyReadWrite,
        <Pst as PstFile>::BlockBTree: RootBTreeReadWrite,
        <<Pst as PstFile>::BlockBTree as RootBTree>::Entry: BTreeEntryReadWrite,
        <<Pst as PstFile>::BlockBTree as RootBTree>::IntermediatePage:
            RootBTreeIntermediatePageReadWrite<
                    Pst,
                    <<Pst as PstFile>::BlockBTree as RootBTree>::Entry,
                    <<Pst as PstFile>::BlockBTree as RootBTree>::LeafPage,
                >,
        <<Pst as PstFile>::BlockBTree as RootBTree>::LeafPage:
            RootBTreeLeafPageReadWrite<Pst> + BTreePageReadWrite,
    {
        let Self::Intermediate(block) = self else {
            return Ok(());
        };
        let depth = depth.saturating_add(1);
        for entry in block.entries() {
            if entry.block().is_internal() {
                let data_tree = Self::read_child(
                    f,
                    encoding,
                    block_btree,
                    page_cache,
                    block_cache,
                    walk,
                    entry.block(),
                    depth,
                    block.header().level(),
                )?;
                let result = data_tree.collect_sub_entries(
                    f,
                    encoding,
                    block_btree,
                    page_cache,
                    block_cache,
                    walk,
                    entries,
                    depth,
                );
                block_cache.insert(entry.block(), data_tree);
                result?;
            } else {
                let data_block =
                    block_btree.find_entry(f, entry.block().search_key(), page_cache)?;
                walk.visit::<Pst>(&data_block)?;
                entries.push(data_block);
            }
        }
        Ok(())
    }
}

struct DataTreeCursor<Pst>
where
    Pst: PstFile,
{
    current: Cursor<Vec<u8>>,
    next: VecDeque<<Pst as PstFile>::BlockBTreeEntry>,
}

struct DataTreeReader<'a, Pst, R>
where
    Pst: PstFile,
    R: PstReader,
{
    file: &'a mut R,
    encoding: NdbCryptMethod,
    cursor: DataTreeCursor<Pst>,
}

impl<'a, Pst, R> DataTreeReader<'a, Pst, R>
where
    Pst: PstFile,
    R: PstReader,
{
    fn new(
        data_tree: &DataTree<Pst>,
        file: &'a mut R,
        encoding: NdbCryptMethod,
        block_btree: &'a PstFileReadWriteBlockBTree<Pst>,
        page_cache: &mut RootBTreePageCache<<Pst as PstFile>::BlockBTree>,
        block_cache: &'a mut DataBlockCache<Pst>,
    ) -> io::Result<Self>
    where
        <Pst as PstFile>::BlockId: BlockId<Index = <Pst as PstFile>::BTreeKey> + BlockIdReadWrite,
        <Pst as PstFile>::ByteIndex: ByteIndexReadWrite,
        <Pst as PstFile>::BlockRef: BlockRefReadWrite,
        <Pst as PstFile>::PageTrailer: PageTrailerReadWrite,
        <Pst as PstFile>::BTreeKey: BTreePageKeyReadWrite,
        <Pst as PstFile>::BlockBTree: RootBTreeReadWrite,
        <<Pst as PstFile>::BlockBTree as RootBTree>::Entry: BTreeEntryReadWrite,
        <<Pst as PstFile>::BlockBTree as RootBTree>::IntermediatePage:
            RootBTreeIntermediatePageReadWrite<
                    Pst,
                    <<Pst as PstFile>::BlockBTree as RootBTree>::Entry,
                    <<Pst as PstFile>::BlockBTree as RootBTree>::LeafPage,
                >,
        <<Pst as PstFile>::BlockBTree as RootBTree>::LeafPage:
            RootBTreeLeafPageReadWrite<Pst> + BTreePageReadWrite,
        <Pst as PstFile>::BlockTrailer: BlockTrailerReadWrite,
        <Pst as PstFile>::DataTreeBlock: IntermediateTreeBlockReadWrite,
        <<Pst as PstFile>::DataTreeBlock as IntermediateTreeBlock>::Entry:
            IntermediateTreeEntryReadWrite,
        <Pst as PstFile>::DataBlock: BlockReadWrite,
    {
        let cursor = match data_tree {
            DataTree::Intermediate(_) => {
                let next = data_tree
                    .sub_entries(file, encoding, block_btree, page_cache, block_cache)?
                    .collect();

                DataTreeCursor {
                    current: Default::default(),
                    next,
                }
            }
            DataTree::Leaf(block) => DataTreeCursor {
                current: Cursor::new(block.data().to_vec()),
                next: Default::default(),
            },
        };

        Ok(Self {
            cursor,
            file,
            encoding,
        })
    }
}

impl<Pst, R> Read for DataTreeReader<'_, Pst, R>
where
    Pst: PstFile,
    R: PstReader,
    <Pst as PstFile>::BlockId: BlockId<Index = <Pst as PstFile>::BTreeKey> + BlockIdReadWrite,
    <Pst as PstFile>::ByteIndex: ByteIndexReadWrite,
    <Pst as PstFile>::BlockRef: BlockRefReadWrite,
    <Pst as PstFile>::PageTrailer: PageTrailerReadWrite,
    <Pst as PstFile>::BTreeKey: BTreePageKeyReadWrite,
    <Pst as PstFile>::BlockBTree: RootBTreeReadWrite,
    <<Pst as PstFile>::BlockBTree as RootBTree>::Entry: BTreeEntryReadWrite,
    <<Pst as PstFile>::BlockBTree as RootBTree>::IntermediatePage:
        RootBTreeIntermediatePageReadWrite<
                Pst,
                <<Pst as PstFile>::BlockBTree as RootBTree>::Entry,
                <<Pst as PstFile>::BlockBTree as RootBTree>::LeafPage,
            >,
    <<Pst as PstFile>::BlockBTree as RootBTree>::LeafPage:
        RootBTreeLeafPageReadWrite<Pst> + BTreePageReadWrite,
    <Pst as PstFile>::BlockTrailer: BlockTrailerReadWrite,
    <Pst as PstFile>::DataTreeBlock: IntermediateTreeBlockReadWrite,
    <<Pst as PstFile>::DataTreeBlock as IntermediateTreeBlock>::Entry:
        IntermediateTreeEntryReadWrite,
    <Pst as PstFile>::DataBlock: BlockReadWrite,
{
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut total_read = self.cursor.current.read(buf)?;

        while total_read < buf.len() {
            let Some(next) = self.cursor.next.pop_front() else {
                break;
            };

            let next: DataTree<Pst> = DataTree::read(self.file, self.encoding, &next)?;
            let DataTree::Leaf(next) = next else {
                error!(
                    name: "PstInvalidDataTreeIntermediateBlock",
                    "Data tree intermediate block has non-leaf sub-entry"
                );

                return Err(NdbError::InvalidInternalBlockLevel(0).into());
            };
            self.cursor.current = Cursor::new(next.data().to_vec());

            let Some(buf) = buf.get_mut(total_read..) else {
                break;
            };
            total_read = total_read.saturating_add(self.cursor.current.read(buf)?);
        }

        Ok(total_read)
    }
}

pub type UnicodeDataTree = DataTree<UnicodePstFile>;
pub type AnsiDataTree = DataTree<AnsiPstFile>;

#[derive(Clone, Copy, Default)]
struct SubNodeTreeBlockHeader {
    level: u8,
    entry_count: u16,
}

#[derive(Clone, Copy, Default)]
pub struct UnicodeSubNodeTreeBlockHeader(SubNodeTreeBlockHeader);

impl UnicodeSubNodeTreeBlockHeader {
    pub fn new(level: u8, entry_count: u16) -> Self {
        Self(SubNodeTreeBlockHeader { level, entry_count })
    }
}

impl IntermediateTreeHeader for UnicodeSubNodeTreeBlockHeader {
    fn level(&self) -> u8 {
        self.0.level
    }

    fn entry_count(&self) -> u16 {
        self.0.entry_count
    }
}

impl IntermediateTreeHeaderReadWrite for UnicodeSubNodeTreeBlockHeader {
    const HEADER_SIZE: u16 = 8;

    fn read(f: &mut dyn Read) -> io::Result<Self> {
        let block_type = f.read_u8()?;
        if block_type != 0x02 {
            return Err(NdbError::InvalidInternalBlockType(block_type).into());
        }

        let level = f.read_u8()?;
        let entry_count = f.read_u16::<LittleEndian>()?;

        let padding = f.read_u32::<LittleEndian>()?;
        if padding != 0 {
            crate::problems::check(
                crate::problems::ProblemKind::BlockField,
                None,
                || format!("SIBLOCK or SLBLOCK dwPadding is 0x{padding:08X}"),
                || NdbError::InvalidSubNodeBlockPadding(padding).into(),
            )?;
        }

        Ok(Self::new(level, entry_count))
    }

    fn write(&self, f: &mut dyn Write) -> io::Result<()> {
        f.write_u8(0x02)?;
        f.write_u8(self.level())?;
        f.write_u16::<LittleEndian>(self.entry_count())?;
        f.write_u32::<LittleEndian>(0)
    }
}

impl SubNodeTreeBlockHeaderReadWrite for UnicodeSubNodeTreeBlockHeader {
    fn new(level: u8, entry_count: u16) -> Self {
        Self::new(level, entry_count)
    }
}

#[derive(Clone, Copy, Default)]
pub struct AnsiSubNodeTreeBlockHeader(SubNodeTreeBlockHeader);

impl AnsiSubNodeTreeBlockHeader {
    pub fn new(level: u8, entry_count: u16) -> Self {
        Self(SubNodeTreeBlockHeader { level, entry_count })
    }
}

impl IntermediateTreeHeader for AnsiSubNodeTreeBlockHeader {
    fn level(&self) -> u8 {
        self.0.level
    }

    fn entry_count(&self) -> u16 {
        self.0.entry_count
    }
}

impl IntermediateTreeHeaderReadWrite for AnsiSubNodeTreeBlockHeader {
    const HEADER_SIZE: u16 = 4;

    fn read(f: &mut dyn Read) -> io::Result<Self> {
        let block_type = f.read_u8()?;
        if block_type != 0x02 {
            return Err(NdbError::InvalidInternalBlockType(block_type).into());
        }

        let level = f.read_u8()?;
        let entry_count = f.read_u16::<LittleEndian>()?;

        Ok(Self::new(level, entry_count))
    }

    fn write(&self, f: &mut dyn Write) -> io::Result<()> {
        f.write_u8(0x02)?;
        f.write_u8(self.level())?;
        f.write_u16::<LittleEndian>(self.entry_count())
    }
}

impl SubNodeTreeBlockHeaderReadWrite for AnsiSubNodeTreeBlockHeader {
    fn new(level: u8, entry_count: u16) -> Self {
        Self::new(level, entry_count)
    }
}

/// [SLENTRY (Leaf Block Entry)](https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-pst/85c4d943-0779-43c5-bd98-61dc9bb5dfd6)
#[derive(Clone, Copy, Default)]
pub struct LeafSubNodeTreeEntry<Block>
where
    Block: BlockId,
{
    inner: IntermediateSubNodeTreeEntry<Block>,
    sub_node: Option<Block>,
}

impl<Block> LeafSubNodeTreeEntry<Block>
where
    Block: BlockId,
{
    pub fn new(node: NodeId, block: Block, sub_node: Option<Block>) -> Self {
        Self {
            inner: IntermediateSubNodeTreeEntry::new(node, block),
            sub_node,
        }
    }

    pub fn node(&self) -> NodeId {
        self.inner.node()
    }

    pub fn block(&self) -> Block {
        self.inner.block()
    }

    pub fn sub_node(&self) -> Option<Block> {
        self.sub_node
    }
}

pub type UnicodeLeafSubNodeTreeEntry = LeafSubNodeTreeEntry<UnicodeBlockId>;
pub type AnsiLeafSubNodeTreeEntry = LeafSubNodeTreeEntry<AnsiBlockId>;

impl IntermediateTreeEntry for UnicodeLeafSubNodeTreeEntry {}

impl IntermediateTreeEntryReadWrite for UnicodeLeafSubNodeTreeEntry {
    const ENTRY_SIZE: u16 = 24;

    fn read(f: &mut dyn Read) -> io::Result<Self> {
        let inner = UnicodeIntermediateSubNodeTreeEntry::read(f)?;
        let sub_node = UnicodeBlockId::read(f)?;
        let sub_node = if sub_node.search_key() != 0 {
            Some(sub_node)
        } else {
            None
        };

        Ok(Self::new(inner.node(), inner.block(), sub_node))
    }

    fn write(&self, f: &mut dyn Write) -> io::Result<()> {
        self.inner.write(f)?;
        self.sub_node.unwrap_or_default().write(f)
    }
}

impl IntermediateTreeEntry for AnsiLeafSubNodeTreeEntry {}

impl IntermediateTreeEntryReadWrite for AnsiLeafSubNodeTreeEntry {
    const ENTRY_SIZE: u16 = 12;

    fn read(f: &mut dyn Read) -> io::Result<Self> {
        let inner = AnsiIntermediateSubNodeTreeEntry::read(f)?;
        let sub_node = AnsiBlockId::read(f)?;
        let sub_node = if sub_node.search_key() != 0 {
            Some(sub_node)
        } else {
            None
        };

        Ok(Self::new(inner.node(), inner.block(), sub_node))
    }

    fn write(&self, f: &mut dyn Write) -> io::Result<()> {
        self.inner.write(f)?;
        self.sub_node.unwrap_or_default().write(f)
    }
}

/// [SIENTRY (Intermediate Block Entry)](https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-pst/9e79c673-d2f4-49fb-a00b-51b08fd2d1e4)
#[derive(Clone, Copy, Default)]
pub struct IntermediateSubNodeTreeEntry<Block>
where
    Block: BlockId,
{
    node: NodeId,
    block: Block,
}

impl<Block> IntermediateSubNodeTreeEntry<Block>
where
    Block: BlockId,
{
    pub fn new(node: NodeId, block: Block) -> Self {
        Self { node, block }
    }

    pub fn node(&self) -> NodeId {
        self.node
    }

    pub fn block(&self) -> Block {
        self.block
    }
}

pub type UnicodeIntermediateSubNodeTreeEntry = IntermediateSubNodeTreeEntry<UnicodeBlockId>;
pub type AnsiIntermediateSubNodeTreeEntry = IntermediateSubNodeTreeEntry<AnsiBlockId>;

impl IntermediateTreeEntry for UnicodeIntermediateSubNodeTreeEntry {}

impl IntermediateTreeEntryReadWrite for UnicodeIntermediateSubNodeTreeEntry {
    const ENTRY_SIZE: u16 = 16;

    fn read(f: &mut dyn Read) -> io::Result<Self> {
        let node = NodeId::from(f.read_u64::<LittleEndian>()? as u32);
        let block = UnicodeBlockId::read(f)?;
        Ok(Self::new(node, block))
    }

    fn write(&self, f: &mut dyn Write) -> io::Result<()> {
        f.write_u64::<LittleEndian>(u64::from(u32::from(self.node)))?;
        self.block.write(f)
    }
}

impl IntermediateTreeEntry for AnsiIntermediateSubNodeTreeEntry {}

impl IntermediateTreeEntryReadWrite for AnsiIntermediateSubNodeTreeEntry {
    const ENTRY_SIZE: u16 = 8;

    fn read(f: &mut dyn Read) -> io::Result<Self> {
        let node = NodeId::read(f)?;
        let block = AnsiBlockId::read(f)?;
        Ok(Self::new(node, block))
    }

    fn write(&self, f: &mut dyn Write) -> io::Result<()> {
        self.node.write(f)?;
        self.block.write(f)
    }
}

/// [SLBLOCK](https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-pst/5182eb24-4b0b-4816-aa3f-719cc6e6b018)
/// / [SIBLOCK](https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-pst/729fb9bd-060a-4bbc-9b3b-8f014b487dad)
pub struct SubNodeTreeBlock<Header, Entry, Trailer>
where
    Header: IntermediateTreeHeader,
    Entry: IntermediateTreeEntry,
    Trailer: BlockTrailer,
{
    header: Header,
    entries: Vec<Entry>,
    trailer: Trailer,
}

impl<Header, Entry, Trailer> SubNodeTreeBlock<Header, Entry, Trailer>
where
    Header: IntermediateTreeHeader,
    Entry: IntermediateTreeEntry,
    Trailer: BlockTrailer,
{
    pub fn new(header: Header, entries: Vec<Entry>, trailer: Trailer) -> NdbResult<Self> {
        trailer.verify_block_id(true)?;

        Ok(Self {
            header,
            entries,
            trailer,
        })
    }
}

impl<Header, Entry, Trailer> IntermediateTreeBlock for SubNodeTreeBlock<Header, Entry, Trailer>
where
    Header: IntermediateTreeHeader,
    Entry: IntermediateTreeEntry,
    Trailer: BlockTrailer,
{
    type Header = Header;
    type Entry = Entry;
    type Trailer = Trailer;

    fn header(&self) -> &Self::Header {
        &self.header
    }

    fn entries(&self) -> &[Self::Entry] {
        &self.entries
    }

    fn trailer(&self) -> &Trailer {
        &self.trailer
    }
}

impl<Header, Entry, Trailer> IntermediateTreeBlockReadWrite
    for SubNodeTreeBlock<Header, Entry, Trailer>
where
    Header: IntermediateTreeHeaderReadWrite,
    Entry: IntermediateTreeEntryReadWrite,
    Trailer: BlockTrailerReadWrite,
{
    fn new(header: Header, entries: Vec<Entry>, trailer: Trailer) -> NdbResult<Self> {
        Self::new(header, entries, trailer)
    }
}

pub type UnicodeIntermediateSubNodeTreeBlock = SubNodeTreeBlock<
    UnicodeSubNodeTreeBlockHeader,
    UnicodeIntermediateSubNodeTreeEntry,
    UnicodeBlockTrailer,
>;
pub type AnsiIntermediateSubNodeTreeBlock = SubNodeTreeBlock<
    AnsiSubNodeTreeBlockHeader,
    AnsiIntermediateSubNodeTreeEntry,
    AnsiBlockTrailer,
>;

pub type UnicodeLeafSubNodeTreeBlock = SubNodeTreeBlock<
    UnicodeSubNodeTreeBlockHeader,
    UnicodeLeafSubNodeTreeEntry,
    UnicodeBlockTrailer,
>;
pub type AnsiLeafSubNodeTreeBlock =
    SubNodeTreeBlock<AnsiSubNodeTreeBlockHeader, AnsiLeafSubNodeTreeEntry, AnsiBlockTrailer>;

pub enum SubNodeTree<Pst>
where
    Pst: PstFile,
{
    Intermediate(Box<<Pst as PstFile>::SubNodeTreeBlock>),
    Leaf(Box<<Pst as PstFile>::SubNodeBlock>),
}

impl<Pst> SubNodeTree<Pst>
where
    Pst: PstFile,
    <Pst as PstFile>::BlockTrailer: BlockTrailerReadWrite,
    <Pst as PstFile>::SubNodeTreeBlockHeader: IntermediateTreeHeaderReadWrite,
    <Pst as PstFile>::SubNodeTreeBlock: IntermediateTreeBlockReadWrite,
    <<Pst as PstFile>::SubNodeTreeBlock as IntermediateTreeBlock>::Entry:
        IntermediateTreeEntryReadWrite,
    <Pst as PstFile>::SubNodeBlock: IntermediateTreeBlockReadWrite,
    <<Pst as PstFile>::SubNodeBlock as IntermediateTreeBlock>::Entry:
        IntermediateTreeEntryReadWrite,
{
    pub fn read<R: PstReader>(
        f: &mut R,
        block: &<Pst as PstFile>::BlockBTreeEntry,
    ) -> io::Result<Self> {
        crate::problems::at_offset(block.block().index().index().into(), || {
            Self::read_at(f, block)
        })
    }

    fn read_at<R: PstReader>(
        f: &mut R,
        block: &<Pst as PstFile>::BlockBTreeEntry,
    ) -> io::Result<Self> {
        if let Some(inflated_size) = block.inflated_size() {
            let (data, trailer) = read_4k_block::<Pst, R>(f, block, inflated_size)?;
            let header =
                <<Pst as PstFile>::SubNodeTreeBlockHeader as IntermediateTreeHeaderReadWrite>::read(
                    &mut data.as_slice(),
                )?;
            return Ok(if header.level() > 0 {
                Self::Intermediate(Box::new(intermediate_block(&data, header, trailer)?))
            } else {
                Self::Leaf(Box::new(intermediate_block(&data, header, trailer)?))
            });
        }

        f.seek(SeekFrom::Start(block.block().index().index().into()))?;

        let block_size = slot_size::<Pst>(block.size())?;
        let mut data = vec![0; usize::from(block_size)];
        f.read_exact(&mut data)?;
        let mut cursor = Cursor::new(data);
        let header =
            <<Pst as PstFile>::SubNodeTreeBlockHeader as IntermediateTreeHeaderReadWrite>::read(
                &mut cursor,
            )?;
        cursor.seek(SeekFrom::Start(0))?;

        if header.level() > 0 {
            let block =
                <<Pst as PstFile>::SubNodeTreeBlock as IntermediateTreeBlockReadWrite>::read(
                    &mut cursor,
                    header,
                    block.size(),
                )?;
            Ok(Self::Intermediate(Box::new(block)))
        } else {
            let block = <<Pst as PstFile>::SubNodeBlock as IntermediateTreeBlockReadWrite>::read(
                &mut cursor,
                header,
                block.size(),
            )?;
            Ok(Self::Leaf(Box::new(block)))
        }
    }

    pub fn find_entry<R>(
        &self,
        f: &mut R,
        block_btree: &PstFileReadWriteBlockBTree<Pst>,
        node: NodeId,
        page_cache: &mut RootBTreePageCache<<Pst as PstFile>::BlockBTree>,
    ) -> io::Result<<Pst as PstFile>::BlockId>
    where
        R: PstReader,
        <Pst as PstFile>::BlockId: BlockId<Index = <Pst as PstFile>::BTreeKey> + BlockIdReadWrite,
        <Pst as PstFile>::ByteIndex: ByteIndexReadWrite,
        <Pst as PstFile>::BlockRef: BlockRefReadWrite,
        <Pst as PstFile>::PageTrailer: PageTrailerReadWrite,
        <Pst as PstFile>::BTreeKey: BTreePageKeyReadWrite,
        <Pst as PstFile>::BlockBTree: RootBTreeReadWrite,
        <<Pst as PstFile>::BlockBTree as RootBTree>::Entry: BTreeEntryReadWrite,
        <<Pst as PstFile>::BlockBTree as RootBTree>::IntermediatePage:
            RootBTreeIntermediatePageReadWrite<
                    Pst,
                    <<Pst as PstFile>::BlockBTree as RootBTree>::Entry,
                    <<Pst as PstFile>::BlockBTree as RootBTree>::LeafPage,
                >,
        <<Pst as PstFile>::BlockBTree as RootBTree>::LeafPage:
            RootBTreeLeafPageReadWrite<Pst> + BTreePageReadWrite,
    {
        self.find_entry_at(f, block_btree, node, page_cache, 0)
    }

    fn find_entry_at<R>(
        &self,
        f: &mut R,
        block_btree: &PstFileReadWriteBlockBTree<Pst>,
        node: NodeId,
        page_cache: &mut RootBTreePageCache<<Pst as PstFile>::BlockBTree>,
        depth: usize,
    ) -> io::Result<<Pst as PstFile>::BlockId>
    where
        R: PstReader,
        <Pst as PstFile>::BlockId: BlockId<Index = <Pst as PstFile>::BTreeKey> + BlockIdReadWrite,
        <Pst as PstFile>::ByteIndex: ByteIndexReadWrite,
        <Pst as PstFile>::BlockRef: BlockRefReadWrite,
        <Pst as PstFile>::PageTrailer: PageTrailerReadWrite,
        <Pst as PstFile>::BTreeKey: BTreePageKeyReadWrite,
        <Pst as PstFile>::BlockBTree: RootBTreeReadWrite,
        <<Pst as PstFile>::BlockBTree as RootBTree>::Entry: BTreeEntryReadWrite,
        <<Pst as PstFile>::BlockBTree as RootBTree>::IntermediatePage:
            RootBTreeIntermediatePageReadWrite<
                    Pst,
                    <<Pst as PstFile>::BlockBTree as RootBTree>::Entry,
                    <<Pst as PstFile>::BlockBTree as RootBTree>::LeafPage,
                >,
        <<Pst as PstFile>::BlockBTree as RootBTree>::LeafPage:
            RootBTreeLeafPageReadWrite<Pst> + BTreePageReadWrite,
    {
        match self {
            Self::Intermediate(block) => {
                let entries = block.entries();
                let index =
                    entries.partition_point(|entry| u32::from(entry.node()) <= u32::from(node));
                let entry = index
                    .checked_sub(1)
                    .and_then(|index| entries.get(index))
                    .ok_or(NdbError::SubNodeNotFound(node))?;
                if depth >= MAX_BLOCK_TREE_DEPTH {
                    return Err(
                        NdbError::BlockTreeTooDeep(entry.block().search_key().into()).into(),
                    );
                }
                let child = block_btree.find_entry(f, entry.block().search_key(), page_cache)?;
                let page = Self::read(f, &child)?;
                if let Self::Intermediate(_) = &page {
                    check_child_level(
                        page.level(),
                        block.header().level(),
                        child.block().index().index().into(),
                    )?;
                }
                page.find_entry_at(f, block_btree, node, page_cache, depth.saturating_add(1))
            }
            Self::Leaf(block) => {
                let entry = block
                    .entries()
                    .iter()
                    .find(|entry| u32::from(entry.node()) == u32::from(node))
                    .map(|entry| entry.block())
                    .ok_or(NdbError::SubNodeNotFound(node))?;
                Ok(entry)
            }
        }
    }

    pub fn entries<'a, R>(
        &self,
        f: &mut R,
        block_btree: &PstFileReadWriteBlockBTree<Pst>,
        page_cache: &mut RootBTreePageCache<<Pst as PstFile>::BlockBTree>,
    ) -> io::Result<Box<dyn 'a + Iterator<Item = LeafSubNodeTreeEntry<<Pst as PstFile>::BlockId>>>>
    where
        R: PstReader,
        <Pst as PstFile>::BlockId:
            'a + BlockId<Index = <Pst as PstFile>::BTreeKey> + BlockIdReadWrite,
        <Pst as PstFile>::ByteIndex: ByteIndexReadWrite,
        <Pst as PstFile>::BlockRef: BlockRefReadWrite,
        <Pst as PstFile>::PageTrailer: PageTrailerReadWrite,
        <Pst as PstFile>::BTreeKey: BTreePageKeyReadWrite,
        <Pst as PstFile>::BlockBTree: RootBTreeReadWrite,
        <<Pst as PstFile>::BlockBTree as RootBTree>::Entry: BTreeEntryReadWrite,
        <<Pst as PstFile>::BlockBTree as RootBTree>::IntermediatePage:
            RootBTreeIntermediatePageReadWrite<
                    Pst,
                    <<Pst as PstFile>::BlockBTree as RootBTree>::Entry,
                    <<Pst as PstFile>::BlockBTree as RootBTree>::LeafPage,
                >,
        <<Pst as PstFile>::BlockBTree as RootBTree>::LeafPage:
            RootBTreeLeafPageReadWrite<Pst> + BTreePageReadWrite,
    {
        let mut walk = TreeWalk::new(f)?;
        walk.root(match self {
            Self::Intermediate(block) => block.trailer().block_id(),
            Self::Leaf(block) => block.trailer().block_id(),
        });
        let mut entries = Vec::new();
        self.collect_entries(f, block_btree, page_cache, &mut walk, &mut entries, 0)?;
        Ok(Box::new(entries.into_iter()))
    }

    /// The tree's `cLevel`: 0 for an SLBLOCK, 1 for an SIBLOCK.
    pub fn level(&self) -> u8 {
        match self {
            Self::Intermediate(block) => block.header().level(),
            Self::Leaf(_) => 0,
        }
    }

    fn collect_entries<R>(
        &self,
        f: &mut R,
        block_btree: &PstFileReadWriteBlockBTree<Pst>,
        page_cache: &mut RootBTreePageCache<<Pst as PstFile>::BlockBTree>,
        walk: &mut TreeWalk,
        entries: &mut Vec<LeafSubNodeTreeEntry<<Pst as PstFile>::BlockId>>,
        depth: usize,
    ) -> io::Result<()>
    where
        R: PstReader,
        <Pst as PstFile>::BlockId: BlockId<Index = <Pst as PstFile>::BTreeKey> + BlockIdReadWrite,
        <Pst as PstFile>::ByteIndex: ByteIndexReadWrite,
        <Pst as PstFile>::BlockRef: BlockRefReadWrite,
        <Pst as PstFile>::PageTrailer: PageTrailerReadWrite,
        <Pst as PstFile>::BTreeKey: BTreePageKeyReadWrite,
        <Pst as PstFile>::BlockBTree: RootBTreeReadWrite,
        <<Pst as PstFile>::BlockBTree as RootBTree>::Entry: BTreeEntryReadWrite,
        <<Pst as PstFile>::BlockBTree as RootBTree>::IntermediatePage:
            RootBTreeIntermediatePageReadWrite<
                    Pst,
                    <<Pst as PstFile>::BlockBTree as RootBTree>::Entry,
                    <<Pst as PstFile>::BlockBTree as RootBTree>::LeafPage,
                >,
        <<Pst as PstFile>::BlockBTree as RootBTree>::LeafPage:
            RootBTreeLeafPageReadWrite<Pst> + BTreePageReadWrite,
    {
        match self {
            Self::Intermediate(block) => {
                let depth = depth.saturating_add(1);
                let level = block.header().level();
                for entry in block.entries() {
                    let block =
                        block_btree.find_entry(f, entry.block().search_key(), page_cache)?;
                    walk.visit::<Pst>(&block)?;
                    if depth > MAX_BLOCK_TREE_DEPTH {
                        return Err(
                            NdbError::BlockTreeTooDeep(entry.block().search_key().into()).into(),
                        );
                    }
                    let sub_nodes = Self::read(f, &block)?;
                    if let Self::Intermediate(_) = &sub_nodes {
                        check_child_level(
                            sub_nodes.level(),
                            level,
                            block.block().index().index().into(),
                        )?;
                    }
                    sub_nodes.collect_entries(f, block_btree, page_cache, walk, entries, depth)?;
                }
                Ok(())
            }
            Self::Leaf(block) => {
                entries.extend_from_slice(block.entries());
                Ok(())
            }
        }
    }
}

pub type UnicodeSubNodeTree = SubNodeTree<UnicodePstFile>;
pub type AnsiSubNodeTree = SubNodeTree<AnsiPstFile>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ndb::page::{UnicodeBlockBTree, UnicodeBlockBTreeEntry, UnicodeBlockBTreePage};

    /// An in-memory file of blocks, and the block BTree that finds them.
    #[derive(Default)]
    struct Blocks {
        file: Vec<u8>,
        entries: Vec<UnicodeBlockBTreeEntry>,
    }

    impl Blocks {
        /// Write a block of `data` with its trailer at `offset`, and its block BTree entry.
        fn put(&mut self, offset: usize, bid: u64, data: &[u8]) {
            let size = data.len() as u16;
            let slot = usize::from(block_size(size + 16).unwrap());
            if self.file.len() < offset + slot {
                self.file.resize(offset + slot, 0);
            }
            self.file[offset..offset + data.len()].copy_from_slice(data);
            let trailer = offset + slot - 16;
            self.file[trailer..trailer + 2].copy_from_slice(&size.to_le_bytes());
            self.file[trailer + 4..trailer + 8]
                .copy_from_slice(&compute_crc(0, data).to_le_bytes());
            self.file[trailer + 8..trailer + 16].copy_from_slice(&bid.to_le_bytes());
            self.entry(offset, bid, size);
        }

        /// A block BTree entry for a block at `offset`.
        fn entry(&mut self, offset: usize, bid: u64, size: u16) {
            let block = UnicodeBlockRef::new(
                UnicodeBlockId::from(bid),
                UnicodeByteIndex::new(offset as u64),
            );
            self.entries.push(UnicodeBlockBTreeEntry::new(block, size));
        }

        fn btree(&self) -> UnicodeBlockBTree {
            let trailer = <UnicodePageTrailer as PageTrailerReadWrite>::new(
                PageType::BlockBTree,
                0,
                UnicodePageId::from(1),
                0,
            );
            let page = UnicodeBlockBTreePage::new(0, 255, 24, &self.entries, trailer).unwrap();
            RootBTreePage::Leaf(Box::new(page))
        }

        fn find(&self, bid: u64) -> UnicodeBlockBTreeEntry {
            *self
                .entries
                .iter()
                .find(|entry| u64::from(entry.block().block()) == bid)
                .unwrap()
        }
    }

    /// An XBLOCK (level 1) or XXBLOCK (level 2) of `bids`.
    fn xblock(level: u8, bids: &[u64]) -> Vec<u8> {
        let mut data = vec![0x01, level];
        data.extend_from_slice(&(bids.len() as u16).to_le_bytes());
        data.extend_from_slice(&100_u32.to_le_bytes());
        for bid in bids {
            data.extend_from_slice(&bid.to_le_bytes());
        }
        data
    }

    /// An SIBLOCK (level 1) of `(nid, bid)` entries, or an SLBLOCK (level 0) of
    /// `(nid, bid, 0)` entries.
    fn sub_node_block(level: u8, entries: &[(u32, u64)]) -> Vec<u8> {
        let mut data = vec![0x02, level];
        data.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        data.extend_from_slice(&0_u32.to_le_bytes());
        for (nid, bid) in entries {
            data.extend_from_slice(&u64::from(*nid).to_le_bytes());
            data.extend_from_slice(&bid.to_le_bytes());
            if level == 0 {
                data.extend_from_slice(&0_u64.to_le_bytes());
            }
        }
        data
    }

    type Tree = DataTree<UnicodePstFile>;

    fn read_all(blocks: &Blocks, root: u64) -> io::Result<Vec<u8>> {
        let mut f = Cursor::new(blocks.file.clone());
        let btree = blocks.btree();
        let tree = Tree::read(&mut f, NdbCryptMethod::None, &blocks.find(root))?;
        let mut data = Vec::new();
        tree.reader(
            &mut f,
            NdbCryptMethod::None,
            &btree,
            &mut Default::default(),
            &mut Default::default(),
        )?
        .read_to_end(&mut data)?;
        Ok(data)
    }

    fn all_blocks(blocks: &Blocks, root: u64) -> io::Result<usize> {
        let mut f = Cursor::new(blocks.file.clone());
        let btree = blocks.btree();
        let tree = Tree::read(&mut f, NdbCryptMethod::None, &blocks.find(root))?;
        let count = tree
            .blocks(
                &mut f,
                NdbCryptMethod::None,
                &btree,
                &mut Default::default(),
                &mut Default::default(),
            )?
            .count();
        Ok(count)
    }

    #[test]
    fn test_data_tree() {
        let mut blocks = Blocks::default();
        blocks.put(0x000, 0x104, b"hello, ");
        blocks.put(0x040, 0x108, b"world");
        blocks.put(0x080, 0x102, &xblock(1, &[0x104, 0x108]));
        assert_eq!(read_all(&blocks, 0x102).unwrap(), b"hello, world");
        assert_eq!(all_blocks(&blocks, 0x102).unwrap(), 2);

        // An XXBLOCK of that XBLOCK.
        blocks.put(0x0C0, 0x10A, &xblock(2, &[0x102]));
        assert_eq!(read_all(&blocks, 0x10A).unwrap(), b"hello, world");
        assert_eq!(all_blocks(&blocks, 0x10A).unwrap(), 2);
    }

    #[test]
    fn test_xblock_that_contains_itself() {
        // This recursed until the stack overflowed.
        let mut blocks = Blocks::default();
        blocks.put(0x000, 0x102, &xblock(1, &[0x102]));
        assert!(read_all(&blocks, 0x102).is_err());
        assert!(all_blocks(&blocks, 0x102).is_err());
        let mut f = Cursor::new(blocks.file.clone());
        let tree = Tree::read(&mut f, NdbCryptMethod::None, &blocks.find(0x102)).unwrap();
        let nth = tree.nth(
            0,
            &mut f,
            NdbCryptMethod::None,
            &blocks.btree(),
            &mut Default::default(),
            &mut Default::default(),
        );
        assert!(nth.is_err());
    }

    #[test]
    fn test_xxblock_loop() {
        // An XXBLOCK whose XBLOCK claims to be an XXBLOCK of the first one.
        let mut blocks = Blocks::default();
        blocks.put(0x000, 0x102, &xblock(2, &[0x106]));
        blocks.put(0x040, 0x106, &xblock(2, &[0x102]));
        // Strictly, the second XXBLOCK is not below the first.
        let err = all_blocks(&blocks, 0x102).unwrap_err();
        assert!(err.to_string().contains("cLevel"), "{err}");
        // Leniently that is a problem, and the loop back to the first is the error.
        let (_scope, log) = crate::problems::lenient_scope();
        let err = all_blocks(&blocks, 0x102).unwrap_err();
        assert!(err.to_string().contains("twice"), "{err}");
        assert!(read_all(&blocks, 0x102).is_err());
        assert_eq!(
            log.problems()[0].kind(),
            crate::problems::ProblemKind::BlockField
        );
    }

    #[test]
    fn test_data_tree_deeper_than_the_limit() {
        // A chain of XBLOCKs, each the only entry of the one above: each block once, but deeper
        // than any data tree.
        let mut blocks = Blocks::default();
        blocks.put(0x000, 0x104, b"data");
        let depth = MAX_BLOCK_TREE_DEPTH as u64 + 2;
        let mut child = 0x104;
        for i in 0..depth {
            let bid = 0x202 + 4 * i;
            blocks.put(0x40 * (i as usize + 1), bid, &xblock(1, &[child]));
            child = bid;
        }
        // Strictly, an XBLOCK under an XBLOCK is the error.
        assert!(all_blocks(&blocks, child).is_err());
        let (_scope, _log) = crate::problems::lenient_scope();
        let err = all_blocks(&blocks, child).unwrap_err();
        assert!(err.to_string().contains("deeper"), "{err}");
        assert!(read_all(&blocks, child).is_err());

        // The same chain within the limit reads, leniently.
        let mut blocks = Blocks::default();
        blocks.put(0x000, 0x104, b"data");
        blocks.put(0x040, 0x202, &xblock(1, &[0x104]));
        blocks.put(0x080, 0x206, &xblock(1, &[0x202]));
        assert_eq!(read_all(&blocks, 0x206).unwrap(), b"data");
    }

    #[test]
    fn test_sub_node_tree_deeper_than_the_limit() {
        let mut blocks = Blocks::default();
        blocks.put(0x000, 0x106, &sub_node_block(0, &[(0x20, 0x104)]));
        let mut child = 0x106;
        for i in 0..MAX_BLOCK_TREE_DEPTH as u64 + 2 {
            let bid = 0x202 + 4 * i;
            blocks.put(
                0x40 * (i as usize + 1),
                bid,
                &sub_node_block(1, &[(0x20, child)]),
            );
            child = bid;
        }
        let mut f = Cursor::new(blocks.file.clone());
        let btree = blocks.btree();
        let tree = SubNodes::read(&mut f, &blocks.find(child)).unwrap();
        assert!(
            tree.entries(&mut f, &btree, &mut Default::default())
                .is_err()
        );
        let found = tree.find_entry(&mut f, &btree, NodeId::from(0x20), &mut Default::default());
        assert!(found.is_err());
    }

    #[test]
    fn test_block_twice_in_a_tree() {
        let mut blocks = Blocks::default();
        blocks.put(0x000, 0x104, b"data");
        blocks.put(0x040, 0x102, &xblock(1, &[0x104, 0x104]));
        let err = all_blocks(&blocks, 0x102).unwrap_err();
        assert!(err.to_string().contains("twice"), "{err}");
        assert!(read_all(&blocks, 0x102).is_err());
    }

    #[test]
    fn test_tree_larger_than_the_file() {
        // Fifty block IDs for the same 8 KiB of data, in a file of 8.25 KiB.
        let mut blocks = Blocks::default();
        blocks.put(0x000, 0x104, &[0x55; 8000]);
        let bids: Vec<u64> = (0..50).map(|i| 0x200 + 4 * i).collect();
        for bid in &bids {
            blocks.entry(0, *bid, 8000);
        }
        blocks.put(0x2000, 0x102, &xblock(1, &bids));
        let err = all_blocks(&blocks, 0x102).unwrap_err();
        assert!(err.to_string().contains("more than the file"), "{err}");
        assert!(read_all(&blocks, 0x102).is_err());
    }

    type SubNodes = SubNodeTree<UnicodePstFile>;

    #[test]
    fn test_sub_node_tree() {
        let mut blocks = Blocks::default();
        blocks.put(
            0x000,
            0x106,
            &sub_node_block(0, &[(0x20, 0x104), (0x40, 0x108)]),
        );
        blocks.put(0x080, 0x102, &sub_node_block(1, &[(0x20, 0x106)]));
        let mut f = Cursor::new(blocks.file.clone());
        let btree = blocks.btree();
        let tree = SubNodes::read(&mut f, &blocks.find(0x102)).unwrap();
        let entries: Vec<_> = tree
            .entries(&mut f, &btree, &mut Default::default())
            .unwrap()
            .collect();
        assert_eq!(entries.len(), 2);
        let block = tree
            .find_entry(&mut f, &btree, NodeId::from(0x40), &mut Default::default())
            .unwrap();
        assert_eq!(u64::from(block), 0x108);
    }

    #[test]
    fn test_siblock_that_contains_itself() {
        // This recursed until the stack overflowed.
        let mut blocks = Blocks::default();
        blocks.put(0x000, 0x102, &sub_node_block(1, &[(0x20, 0x102)]));
        let mut f = Cursor::new(blocks.file.clone());
        let btree = blocks.btree();
        let tree = SubNodes::read(&mut f, &blocks.find(0x102)).unwrap();
        assert!(
            tree.entries(&mut f, &btree, &mut Default::default())
                .is_err()
        );
        let found = tree.find_entry(&mut f, &btree, NodeId::from(0x21), &mut Default::default());
        assert!(found.is_err());
    }

    #[test]
    fn test_siblocks_that_contain_each_other() {
        let mut blocks = Blocks::default();
        blocks.put(0x000, 0x102, &sub_node_block(1, &[(0x20, 0x106)]));
        blocks.put(0x040, 0x106, &sub_node_block(1, &[(0x20, 0x102)]));
        let mut f = Cursor::new(blocks.file.clone());
        let btree = blocks.btree();
        let tree = SubNodes::read(&mut f, &blocks.find(0x102)).unwrap();
        assert!(
            tree.entries(&mut f, &btree, &mut Default::default())
                .is_err()
        );
        let found = tree.find_entry(&mut f, &btree, NodeId::from(0x21), &mut Default::default());
        assert!(found.is_err());
    }
}
