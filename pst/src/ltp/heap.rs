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

//! ## [HN (Heap-on-Node)](https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-pst/77ce49a3-3772-4d8d-bb2c-2f7520a238a6)

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::{
    cell::OnceCell,
    io::{self, Cursor, Read, Seek, SeekFrom, Write},
};

use super::{read_write::*, *};
use crate::{
    AnsiPstFile, PstFile, PstFileReadWriteBlockBTree, PstReader, UnicodePstFile,
    ndb::{
        block::*,
        block_id::BlockId,
        header::NdbCryptMethod,
        node_id::*,
        page::{AnsiBlockBTree, RootBTree, UnicodeBlockBTree},
        read_write::*,
    },
};

pub const HEAP_INDEX_MASK: u32 = (1_u16.rotate_right(5) - 1) as u32;

/// [HID](https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-pst/85b9e985-ea53-447f-b70c-eb82bfbdcbc9)
#[derive(Clone, Copy, Default, Debug)]
pub struct HeapId(NodeId);

impl HeapId {
    pub fn new(index: u16, block_index: u16) -> LtpResult<Self> {
        let shifted_index = index.rotate_left(5);
        if shifted_index & 0x1F != 0 {
            return Err(LtpError::InvalidHeapIndex(index));
        };

        let node_index = ((block_index as u32) << 11) | index as u32;

        Ok(Self(NodeId::new(NodeIdType::HeapNode, node_index)?))
    }

    pub fn index(&self) -> LtpResult<u16> {
        let index = (self.0.index() & HEAP_INDEX_MASK) as u16;
        index
            .checked_sub(1)
            .ok_or(LtpError::InvalidHeapIndex(index))
    }

    pub fn block_index(&self) -> u16 {
        (self.0.index() >> 11) as u16
    }
}

impl HeapIdReadWrite for HeapId {
    fn new(index: u16, block_index: u16) -> LtpResult<Self> {
        Self::new(index, block_index)
    }

    fn read(f: &mut dyn Read) -> io::Result<Self> {
        let value = NodeId::read(f)?;

        let id_type = value.id_type()?;
        if id_type != NodeIdType::HeapNode {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                LtpError::InvalidNodeType(id_type),
            ));
        }

        Ok(Self(value))
    }

    fn write(&self, f: &mut dyn Write) -> io::Result<()> {
        self.0.write(f)
    }
}

impl From<u32> for HeapId {
    fn from(value: u32) -> Self {
        Self(NodeId::from(value))
    }
}

impl From<HeapId> for u32 {
    fn from(value: HeapId) -> Self {
        u32::from(value.0)
    }
}

/// `bClientSig`
///
/// ### See also
/// [HeapNodeHeader]
#[repr(u8)]
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum HeapNodeType {
    /// `bTypeReserved1`: Reserved
    Reserved1 = 0x6C,
    /// `bTypeTC`: Table Context (TC/HN)
    Table = 0x7C,
    /// `bTypeReserved2`: Reserved
    Reserved2 = 0x8C,
    /// `bTypeReserved3`: Reserved
    Reserved3 = 0x9C,
    /// `bTypeReserved4`: Reserved
    Reserved4 = 0xA5,
    /// `bTypeReserved5`: Reserved
    Reserved5 = 0xAC,
    /// `bTypeBTH`: BTree-on-Heap (BTH)
    Tree = 0xB5,
    /// `bTypePC`: Property Context (PC/BTH)
    Properties = 0xBC,
    /// `bTypeReserved6`: Reserved
    Reserved6 = 0xCC,
}

impl TryFrom<u8> for HeapNodeType {
    type Error = LtpError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x6C => Ok(Self::Reserved1),
            0x7C => Ok(Self::Table),
            0x8C => Ok(Self::Reserved2),
            0x9C => Ok(Self::Reserved3),
            0xA5 => Ok(Self::Reserved4),
            0xAC => Ok(Self::Reserved5),
            0xB5 => Ok(Self::Tree),
            0xBC => Ok(Self::Properties),
            0xCC => Ok(Self::Reserved6),
            _ => Err(LtpError::InvalidHeapNodeTypeSignature(value)),
        }
    }
}

/// `rgbFillLevel`
///
/// ### See also
/// [HeapNodeHeader]
#[repr(u8)]
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum HeapFillLevel {
    /// `FILL_LEVEL_EMPTY`: At least 3584 bytes free / data block does not exist
    Empty = 0x00,
    /// `FILL_LEVEL_1`: 2560-3584 bytes free
    Level1 = 0x01,
    /// `FILL_LEVEL_2`: 2048-2560 bytes free
    Level2 = 0x02,
    /// `FILL_LEVEL_3`: 1792-2048 bytes free
    Level3 = 0x03,
    /// `FILL_LEVEL_4`: 1536-1792 bytes free
    Level4 = 0x04,
    /// `FILL_LEVEL_5`: 1280-1536 bytes free
    Level5 = 0x05,
    /// `FILL_LEVEL_6`: 1024-1280 bytes free
    Level6 = 0x06,
    /// `FILL_LEVEL_7`: 768-1024 bytes free
    Level7 = 0x07,
    /// `FILL_LEVEL_8`: 512-768 bytes free
    Level8 = 0x08,
    /// `FILL_LEVEL_9`: 256-512 bytes free
    Level9 = 0x09,
    /// `FILL_LEVEL_10`: 128-256 bytes free
    Level10 = 0x0A,
    /// `FILL_LEVEL_11`: 64-128 bytes free
    Level11 = 0x0B,
    /// `FILL_LEVEL_12`: 32-64 bytes free
    Level12 = 0x0C,
    /// `FILL_LEVEL_13`: 16-32 bytes free
    Level13 = 0x0D,
    /// `FILL_LEVEL_14`: 8-16 bytes free
    Level14 = 0x0E,
    /// `FILL_LEVEL_15`: Data block has less than 8 bytes free
    Level15 = 0x0F,
}

impl TryFrom<u8> for HeapFillLevel {
    type Error = LtpError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(Self::Empty),
            0x01 => Ok(Self::Level1),
            0x02 => Ok(Self::Level2),
            0x03 => Ok(Self::Level3),
            0x04 => Ok(Self::Level4),
            0x05 => Ok(Self::Level5),
            0x06 => Ok(Self::Level6),
            0x07 => Ok(Self::Level7),
            0x08 => Ok(Self::Level8),
            0x09 => Ok(Self::Level9),
            0x0A => Ok(Self::Level10),
            0x0B => Ok(Self::Level11),
            0x0C => Ok(Self::Level12),
            0x0D => Ok(Self::Level13),
            0x0E => Ok(Self::Level14),
            0x0F => Ok(Self::Level15),
            _ => Err(LtpError::InvalidHeapFillLevel(value)),
        }
    }
}

impl HeapFillLevel {
    /// The fill level of a nibble: every value of 0 to 15 is one.
    fn from_nibble(value: u32) -> HeapFillLevel {
        HeapFillLevel::try_from((value & 0x0F) as u8).unwrap_or(HeapFillLevel::Level15)
    }

    fn unpack_fill_levels(value: u32) -> [HeapFillLevel; 8] {
        [0, 4, 8, 12, 16, 20, 24, 28].map(|shift| Self::from_nibble(value >> shift))
    }

    fn pack_fill_levels(fill_levels: &[HeapFillLevel; 8]) -> u32 {
        fill_levels
            .iter()
            .fold(0, |acc, &x| (acc << 4) | (x as u32))
    }
}

/// [HNHDR](https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-pst/8e4ae05c-3c24-4103-b7e5-ffef6f244834)
#[derive(Clone, Copy, Debug)]
pub struct HeapNodeHeader {
    page_map_offset: u16,
    client_signature: HeapNodeType,
    user_root: HeapId,
    fill_levels: [HeapFillLevel; 8],
}

impl HeapNodeHeader {
    pub fn new(
        page_map_offset: u16,
        client_signature: HeapNodeType,
        user_root: HeapId,
        fill_levels: [HeapFillLevel; 8],
    ) -> Self {
        Self {
            page_map_offset,
            client_signature,
            user_root,
            fill_levels,
        }
    }

    pub fn page_map_offset(&self) -> u16 {
        self.page_map_offset
    }

    pub fn client_signature(&self) -> HeapNodeType {
        self.client_signature
    }

    pub fn user_root(&self) -> HeapId {
        self.user_root
    }

    pub fn fill_levels(&self) -> &[HeapFillLevel; 8] {
        &self.fill_levels
    }
}

impl HeapNodePageReadWrite for HeapNodeHeader {
    fn read(f: &mut dyn Read) -> io::Result<Self> {
        let page_map_offset = f.read_u16::<LittleEndian>()?;
        let heap_signature = f.read_u8()?;
        if heap_signature != 0xEC {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                LtpError::InvalidHeapNodeSignature(heap_signature),
            ));
        }
        let client_signature = HeapNodeType::try_from(f.read_u8()?)?;
        let user_root = HeapId::read(f)?;
        let fill_levels = HeapFillLevel::unpack_fill_levels(f.read_u32::<LittleEndian>()?);

        Ok(Self::new(
            page_map_offset,
            client_signature,
            user_root,
            fill_levels,
        ))
    }

    fn write(&self, f: &mut dyn Write) -> io::Result<()> {
        f.write_u16::<LittleEndian>(self.page_map_offset)?;
        f.write_u8(0xEC)?;
        f.write_u8(self.client_signature as u8)?;
        self.user_root.write(f)?;
        let fill_levels = HeapFillLevel::pack_fill_levels(&self.fill_levels);
        f.write_u32::<LittleEndian>(fill_levels)
    }
}

/// [HNPAGEHDR](https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-pst/9c34ecf8-36bc-45a1-a2df-ee35c6dc840a)
#[derive(Clone, Copy, Debug)]
pub struct HeapNodePageHeader(u16);

impl HeapNodePageHeader {
    pub fn new(page_index: u16) -> Self {
        Self(page_index)
    }

    pub fn page_map_offset(&self) -> u16 {
        self.0
    }
}

impl HeapNodePageReadWrite for HeapNodePageHeader {
    fn read(f: &mut dyn Read) -> io::Result<Self> {
        let page_index = f.read_u16::<LittleEndian>()?;
        Ok(Self::new(page_index))
    }

    fn write(&self, f: &mut dyn Write) -> io::Result<()> {
        f.write_u16::<LittleEndian>(self.0)
    }
}

/// [HNBITMAPHDR](https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-pst/822e2327-b29d-4ec4-91be-45637a438d40)
#[derive(Clone, Copy, Debug)]
pub struct HeapNodeBitmapHeader {
    page_map_offset: u16,
    fill_levels: [HeapFillLevel; 128],
}

impl HeapNodeBitmapHeader {
    pub fn new(page_map_offset: u16, fill_levels: [HeapFillLevel; 128]) -> Self {
        Self {
            page_map_offset,
            fill_levels,
        }
    }

    pub fn page_map_offset(&self) -> u16 {
        self.page_map_offset
    }

    pub fn fill_levels(&self) -> &[HeapFillLevel; 128] {
        &self.fill_levels
    }
}

impl HeapNodePageReadWrite for HeapNodeBitmapHeader {
    fn read(f: &mut dyn Read) -> io::Result<Self> {
        let page_map_offset = f.read_u16::<LittleEndian>()?;

        let mut fill_levels = [HeapFillLevel::Empty; 128];
        for chunk in fill_levels.as_chunks_mut::<8>().0 {
            *chunk = HeapFillLevel::unpack_fill_levels(f.read_u32::<LittleEndian>()?);
        }

        Ok(Self::new(page_map_offset, fill_levels))
    }

    fn write(&self, f: &mut dyn Write) -> io::Result<()> {
        f.write_u16::<LittleEndian>(self.page_map_offset)?;
        for chunk in self.fill_levels.as_chunks::<8>().0 {
            f.write_u32::<LittleEndian>(HeapFillLevel::pack_fill_levels(chunk))?;
        }
        Ok(())
    }
}

pub struct HeapNodePageAllocOffsets(Vec<u16>);

impl HeapNodePageAllocOffsets {
    pub fn new(offsets: Vec<u16>) -> Self {
        Self(offsets)
    }
}

#[derive(Clone, Copy, Default, Debug)]
pub struct HeapNodePageAlloc {
    offset: u16,
    size: u16,
}

impl HeapNodePageAlloc {
    pub fn offset(&self) -> u16 {
        self.offset
    }

    pub fn size(&self) -> u16 {
        self.size
    }
}

/// [HNPAGEMAP](https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-pst/291653c0-b347-4c5b-ba41-85ad780b4ba4)
#[derive(Clone, Default, Debug)]
pub struct HeapNodePageMap {
    allocations: Vec<HeapNodePageAlloc>,
    next_offset: u16,
    free_count: u16,
}

impl HeapNodePageMap {
    pub fn new(
        alloc_count: u16,
        free_count: u16,
        offsets: HeapNodePageAllocOffsets,
    ) -> LtpResult<Self> {
        let page_map = Self::try_from(offsets)?;

        if alloc_count as usize != page_map.allocations.len() {
            return Err(LtpError::InvalidHeapPageAllocCount(alloc_count));
        }

        // markdown-extract: cFree only counts freed allocations, which a reader
        // never needs, and writers leave it stale (the EDRM Enron PSTs have
        // freed items with cFree = 0). Trust the allocation table instead of
        // refusing the whole heap node.
        let _ = free_count;

        Ok(page_map)
    }

    pub fn allocations(&self) -> &[HeapNodePageAlloc] {
        &self.allocations
    }

    pub fn next_offset(&self) -> u16 {
        self.next_offset
    }
}

impl TryFrom<HeapNodePageAllocOffsets> for HeapNodePageMap {
    type Error = LtpError;

    fn try_from(offsets: HeapNodePageAllocOffsets) -> Result<Self, Self::Error> {
        let mut offset = None;
        let mut free_count = 0;
        let allocations = offsets
            .0
            .into_iter()
            .filter_map(|next_offset| {
                let Some(last_offset) = offset else {
                    offset = Some(next_offset);
                    return None;
                };

                let Some(size) = next_offset.checked_sub(last_offset) else {
                    return Some(Err(LtpError::InvalidHeapPageAllocOffset(next_offset)));
                };
                let alloc = HeapNodePageAlloc {
                    offset: last_offset,
                    size,
                };

                if size == 0 {
                    let Ok(value) = u16::try_from(1_u32 + u32::from(free_count)) else {
                        return Some(Err(LtpError::HeapPageOutOfSpace));
                    };

                    free_count = value;
                } else {
                    offset = Some(next_offset);
                }

                Some(Ok(alloc))
            })
            .collect::<LtpResult<_>>()?;

        let next_offset = offset.ok_or(LtpError::EmptyHeapPageAlloc)?;

        Ok(Self {
            allocations,
            next_offset,
            free_count,
        })
    }
}

impl HeapNodePageReadWrite for HeapNodePageMap {
    fn read(f: &mut dyn Read) -> io::Result<Self> {
        let alloc_count = f.read_u16::<LittleEndian>()?;
        let free_count = f.read_u16::<LittleEndian>()?;
        let mut allocations = Vec::with_capacity(alloc_count as usize + 1);
        for _ in 0..=alloc_count {
            let offset = f.read_u16::<LittleEndian>()?;
            allocations.push(offset);
        }

        Ok(Self::new(
            alloc_count,
            free_count,
            HeapNodePageAllocOffsets::new(allocations),
        )?)
    }

    fn write(&self, f: &mut dyn Write) -> io::Result<()> {
        let alloc_count =
            u16::try_from(self.allocations.len()).map_err(|_| LtpError::HeapPageOutOfSpace)?;
        f.write_u16::<LittleEndian>(alloc_count)?;
        f.write_u16::<LittleEndian>(self.free_count)?;
        let mut last_offset = 0;
        for HeapNodePageAlloc { offset, size } in &self.allocations {
            f.write_u16::<LittleEndian>(*offset)?;
            last_offset = offset
                .checked_add(*size)
                .ok_or(LtpError::HeapPageOutOfSpace)?;
        }
        f.write_u16::<LittleEndian>(last_offset)
    }
}

pub trait HeapNode {
    fn header(&self) -> io::Result<HeapNodeHeader>;
    fn find_entry(&self, heap_id: HeapId) -> io::Result<&[u8]>;
}

struct HeapNodeInner<Pst>
where
    Pst: PstFile,
{
    data: Vec<<Pst as PstFile>::DataBlock>,
    /// Each block's page map (HNPAGEMAP), parsed on its first lookup and kept: an object with
    /// many properties looks a block up once for each, and a page map holds up to 65,535
    /// allocations. A page map that does not parse keeps its error's description.
    page_maps: Vec<OnceCell<Result<HeapNodePageMap, String>>>,
}

impl<Pst> HeapNodeInner<Pst>
where
    Pst: PstFile,
{
    fn new(data: Vec<<Pst as PstFile>::DataBlock>) -> Self {
        let page_maps = data.iter().map(|_| OnceCell::new()).collect();
        Self { data, page_maps }
    }
}

impl<Pst> HeapNodeInner<Pst>
where
    Pst: PstFile,
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
    <Pst as PstFile>::DataBlock: BlockReadWrite + Clone,
{
    fn read<R: PstReader>(
        f: &mut R,
        block_btree: &PstFileReadWriteBlockBTree<Pst>,
        page_cache: &mut RootBTreePageCache<<Pst as PstFile>::BlockBTree>,
        encoding: NdbCryptMethod,
        key: <Pst as PstFile>::BTreeKey,
    ) -> io::Result<Self> {
        let block = block_btree.find_entry(f, key, page_cache)?;
        let data_tree = DataTree::<Pst>::read(f, encoding, &block)?;
        let data = data_tree
            .blocks(
                f,
                encoding,
                block_btree,
                page_cache,
                &mut Default::default(),
            )?
            .collect();

        Ok(Self::new(data))
    }

    /// The page map (HNPAGEMAP) of block `block_index` of the heap, `block`.
    fn page_map(block_index: u16, block: &[u8]) -> io::Result<HeapNodePageMap> {
        let mut cursor = Cursor::new(block);

        let page_map_offset = match block_index {
            0 => {
                let header = HeapNodeHeader::read(&mut cursor)?;
                header.page_map_offset()
            }
            bitmap if bitmap % 128 == 8 => {
                let header = HeapNodeBitmapHeader::read(&mut cursor)?;
                header.page_map_offset()
            }
            _ => {
                let header = HeapNodePageHeader::read(&mut cursor)?;
                header.page_map_offset()
            }
        };

        cursor.seek(SeekFrom::Start(u64::from(page_map_offset)))?;
        HeapNodePageMap::read(&mut cursor)
    }

    fn header(&self) -> io::Result<HeapNodeHeader> {
        let data = self.data.first().ok_or(io::ErrorKind::UnexpectedEof)?;
        let mut cursor = Cursor::new(data.data());
        let header = HeapNodeHeader::read(&mut cursor)?;
        Ok(header)
    }

    fn find_entry<'a>(&'a self, heap_id: HeapId) -> io::Result<&'a [u8]>
    where
        <Pst as PstFile>::DataBlock: 'a,
    {
        let block_index = heap_id.block_index();
        let not_found = || LtpError::HeapBlockIndexNotFound(block_index);
        let block = self
            .data
            .get(usize::from(block_index))
            .ok_or_else(not_found)?
            .data();
        let page_map = self
            .page_maps
            .get(usize::from(block_index))
            .ok_or_else(not_found)?
            .get_or_init(|| Self::page_map(block_index, block).map_err(|err| err.to_string()))
            .as_ref()
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.clone()))?;
        let allocations = page_map.allocations();

        let index = heap_id.index()?;
        let alloc = allocations
            .get(usize::from(index))
            .ok_or(LtpError::HeapAllocIndexNotFound(index))?;
        let start = usize::from(alloc.offset());
        let end = start.saturating_add(usize::from(alloc.size()));
        block.get(start..end).ok_or_else(|| {
            LtpError::HeapAllocOutOfBounds(index, alloc.offset(), alloc.size()).into()
        })
    }
}

pub struct UnicodeHeapNode {
    inner: HeapNodeInner<UnicodePstFile>,
}

impl HeapNode for UnicodeHeapNode {
    fn header(&self) -> io::Result<HeapNodeHeader> {
        self.inner.header()
    }

    fn find_entry(&self, heap_id: HeapId) -> io::Result<&[u8]> {
        self.inner.find_entry(heap_id)
    }
}

impl HeapNodeReadWrite<UnicodePstFile> for UnicodeHeapNode {
    fn read<R: PstReader>(
        f: &mut R,
        block_btree: &UnicodeBlockBTree,
        page_cache: &mut RootBTreePageCache<UnicodeBlockBTree>,
        encoding: NdbCryptMethod,
        key: u64,
    ) -> io::Result<Self> {
        let inner = HeapNodeInner::read(f, block_btree, page_cache, encoding, key)?;
        Ok(Self { inner })
    }
}

#[cfg(test)]
impl UnicodeHeapNode {
    /// A heap node of one block holding `allocations`, at HIDs 0x20, 0x40 and so on, with the
    /// first as its user root.
    pub(crate) fn for_test(allocations: &[Vec<u8>]) -> Self {
        use crate::ndb::{block::UnicodeBlockTrailer, block_id::UnicodeBlockId};

        let mut data = vec![0_u8; 12];
        data[2] = 0xEC;
        data[3] = HeapNodeType::Properties as u8;
        data[4..8].copy_from_slice(&0x20_u32.to_le_bytes());
        let mut offsets = vec![data.len() as u16];
        for allocation in allocations {
            data.extend_from_slice(allocation);
            offsets.push(data.len() as u16);
        }
        let page_map = data.len() as u16;
        data[0..2].copy_from_slice(&page_map.to_le_bytes());
        data.extend_from_slice(&(allocations.len() as u16).to_le_bytes());
        data.extend_from_slice(&0_u16.to_le_bytes());
        for offset in offsets {
            data.extend_from_slice(&offset.to_le_bytes());
        }
        let trailer =
            UnicodeBlockTrailer::new(data.len() as u16, 0, 0, UnicodeBlockId::from(4)).unwrap();
        let block = UnicodeDataBlock::new(NdbCryptMethod::None, data, trailer).unwrap();
        Self {
            inner: HeapNodeInner::new(vec![block]),
        }
    }
}

pub struct AnsiHeapNode {
    inner: HeapNodeInner<AnsiPstFile>,
}

impl HeapNode for AnsiHeapNode {
    fn header(&self) -> io::Result<HeapNodeHeader> {
        self.inner.header()
    }

    fn find_entry(&self, heap_id: HeapId) -> io::Result<&[u8]> {
        self.inner.find_entry(heap_id)
    }
}

impl HeapNodeReadWrite<AnsiPstFile> for AnsiHeapNode {
    fn read<R: PstReader>(
        f: &mut R,
        block_btree: &AnsiBlockBTree,
        page_cache: &mut RootBTreePageCache<AnsiBlockBTree>,
        encoding: NdbCryptMethod,
        key: u32,
    ) -> io::Result<Self> {
        let inner = HeapNodeInner::read(f, block_btree, page_cache, encoding, key)?;
        Ok(Self { inner })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ndb::{
        block::{UnicodeBlockTrailer, UnicodeDataBlock},
        block_id::UnicodeBlockId,
    };

    /// A heap node of one block: an HNHDR, then `offsets` as its HNPAGEMAP's rgibAlloc.
    fn heap_node(block_len: usize, offsets: &[u16]) -> HeapNodeInner<UnicodePstFile> {
        let mut data = vec![0_u8; block_len];
        let page_map = block_len - (4 + 2 * offsets.len());
        data[0..2].copy_from_slice(&(page_map as u16).to_le_bytes());
        data[2] = 0xEC;
        data[3] = HeapNodeType::Properties as u8;
        data[4..8].copy_from_slice(&0x20_u32.to_le_bytes());
        let alloc_count = offsets.len() as u16 - 1;
        data[page_map..page_map + 2].copy_from_slice(&alloc_count.to_le_bytes());
        for (i, offset) in offsets.iter().enumerate() {
            let at = page_map + 4 + 2 * i;
            data[at..at + 2].copy_from_slice(&offset.to_le_bytes());
        }
        let trailer =
            UnicodeBlockTrailer::new(block_len as u16, 0, 0, UnicodeBlockId::from(4)).unwrap();
        let block = UnicodeDataBlock::new(NdbCryptMethod::None, data, trailer).unwrap();
        HeapNodeInner::new(vec![block])
    }

    #[test]
    fn test_find_entry() {
        let heap = heap_node(64, &[12, 20, 30]);
        assert_eq!(
            heap.find_entry(HeapId::new(1, 0).unwrap()).unwrap().len(),
            8
        );
        assert_eq!(
            heap.find_entry(HeapId::new(2, 0).unwrap()).unwrap().len(),
            10
        );
        assert!(heap.find_entry(HeapId::new(3, 0).unwrap()).is_err());
        assert!(heap.find_entry(HeapId::new(1, 1).unwrap()).is_err());
        assert!(heap.find_entry(HeapId::from(0)).is_err());
    }

    #[test]
    fn test_allocation_past_its_block_is_an_error() {
        // The second allocation ends at 0x2000, far past the 64-byte block: this sliced out of
        // bounds before.
        let heap = heap_node(64, &[12, 20, 0x2000]);
        assert!(heap.find_entry(HeapId::new(1, 0).unwrap()).is_ok());
        let err = heap.find_entry(HeapId::new(2, 0).unwrap()).unwrap_err();
        assert!(err.to_string().contains("past the end"), "{err}");
        // Offsets that go down.
        let heap = heap_node(64, &[20, 12, 30]);
        assert!(heap.find_entry(HeapId::new(1, 0).unwrap()).is_err());
    }

    #[test]
    fn test_page_map_is_parsed_once() {
        // 30,000 empty allocations and 60,000 lookups, as an object with many properties makes:
        // the page map was parsed on every lookup (65,535 lookups of 32,000 allocations took
        // 14.5 s in a release build).
        let heap = heap_node(12 + 4 + 2 * 30_001, &[12; 30_001]);
        let start = std::time::Instant::now();
        for i in 0..60_000_u16 {
            let entry = heap.find_entry(HeapId::new(1 + i % 2047, 0).unwrap());
            assert_eq!(entry.unwrap().len(), 0);
        }
        assert!(start.elapsed() < std::time::Duration::from_secs(5));
        assert!(heap.page_maps[0].get().is_some_and(|map| map.is_ok()));

        // A page map that does not parse is an error on every lookup.
        let heap = heap_node(64, &[20, 12, 30]);
        for _ in 0..2 {
            assert!(heap.find_entry(HeapId::new(1, 0).unwrap()).is_err());
        }
        assert!(heap.page_maps[0].get().is_some_and(|map| map.is_err()));
    }

    #[test]
    fn test_fill_levels() {
        let levels = HeapFillLevel::unpack_fill_levels(0xFEDC_BA98);
        assert_eq!(levels[0], HeapFillLevel::Level8);
        assert_eq!(levels[7], HeapFillLevel::Level15);
        assert!(HeapId::from(0).index().is_err());
    }
}
