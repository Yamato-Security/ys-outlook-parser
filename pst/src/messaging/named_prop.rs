// Copyright (C) 2026 Shirofune Security Co., Ltd.
// Copyright (c) Microsoft Corporation.
//
// This file is changed from microsoft/outlook-pst-rs (https://github.com/microsoft/outlook-pst-rs), whose code
// is under the MIT License (LICENSE-MIT).
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

//! ## [Named Property Lookup Map](https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-pst/e17e195d-0454-4b9b-b398-c9127a26a678)

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::{
    collections::BTreeMap,
    fmt::Display,
    io::{self, Cursor, Read, Seek, SeekFrom, Write},
    rc::Rc,
};

use super::{read_write::*, store::*, *};
use crate::{
    AnsiPstFile, PstFile, PstFileLock, UnicodePstFile,
    crc::compute_crc,
    ltp::{
        heap::HeapNode,
        prop_context::{GuidValue, PropertyContext, PropertyValue},
        prop_type::PropertyType,
        read_write::*,
    },
    ndb::{
        block_id::BlockId,
        header::Header,
        node_id::NID_NAME_TO_ID_MAP,
        page::{BTreePage, NodeBTreeEntry, RootBTree},
        read_write::*,
        root::Root,
    },
};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum NamedPropertyId {
    Number(u32),
    StringOffset(u32),
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum NamedPropertyGuid {
    None,
    Mapi,
    PublicStrings,
    GuidIndex(u16),
}

impl From<NamedPropertyGuid> for u16 {
    fn from(guid: NamedPropertyGuid) -> Self {
        match guid {
            NamedPropertyGuid::None => 0x0000,
            NamedPropertyGuid::Mapi => 0x0001,
            NamedPropertyGuid::PublicStrings => 0x0002,
            NamedPropertyGuid::GuidIndex(index) => index.saturating_add(3),
        }
    }
}

impl TryFrom<u16> for NamedPropertyGuid {
    type Error = MessagingError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        if value & 0x8000 != 0 {
            return Err(MessagingError::NamedPropertyMapGuidIndexOutOfBounds(value));
        }

        Ok(match value {
            0x0000 => Self::None,
            0x0001 => Self::Mapi,
            0x0002 => Self::PublicStrings,
            index => Self::GuidIndex(index - 3),
        })
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct NamedPropertyIndex(u16);

impl NamedPropertyIndex {
    pub fn prop_id(&self) -> u16 {
        self.0
    }
}

impl From<NamedPropertyIndex> for u16 {
    fn from(value: NamedPropertyIndex) -> Self {
        value.0 - 0x8000
    }
}

impl TryFrom<u16> for NamedPropertyIndex {
    type Error = MessagingError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        if value >= 0x8000 {
            return Err(MessagingError::NamedPropertyMapPropertyIndexOutOfBounds(
                value,
            ));
        }
        Ok(Self(value + 0x8000))
    }
}

pub const PS_MAPI: GuidValue = GuidValue::new(
    0x00020328,
    0x0000,
    0x0000,
    [0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46],
);

pub const PS_PUBLIC_STRINGS: GuidValue = GuidValue::new(
    0x00020329,
    0x0000,
    0x0000,
    [0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46],
);

#[derive(Clone, Default, Debug)]
pub struct StringEntry {
    size: u32,
    buffer: Vec<u8>,
}

impl StringEntry {
    pub fn new(size: u32, buffer: Vec<u8>) -> MessagingResult<Self> {
        if !size.is_multiple_of(2) || size as usize != buffer.len() {
            Err(MessagingError::NamedPropertyMapStringEntryOutOfBounds)
        } else {
            Ok(Self { size, buffer })
        }
    }

    pub fn size(&self) -> u32 {
        self.size
    }

    pub fn buffer(&self) -> &[u8] {
        &self.buffer
    }
}

impl NamedPropReadWrite for StringEntry {
    fn read(f: &mut dyn Read) -> io::Result<Self> {
        let size = f.read_u32::<LittleEndian>()?;

        if size % 2 != 0 {
            return Err(
                MessagingError::InvalidNamedPropertyMapStreamString(PropertyType::Binary).into(),
            );
        }

        let mut buffer = vec![0; size as usize];
        f.read_exact(&mut buffer)?;

        Ok(Self::new(size, buffer)?)
    }

    fn write(&self, f: &mut dyn Write) -> io::Result<()> {
        f.write_u32::<LittleEndian>(self.size)?;
        f.write_all(&self.buffer)
    }
}

impl Display for StringEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut cursor = Cursor::new(self.buffer.as_slice());
        let count = self.size / 2;
        let mut buffer = Vec::with_capacity(count as usize);
        for _ in 0..count {
            buffer.push(cursor.read_u16::<LittleEndian>().unwrap_or_default());
        }
        let value = String::from_utf16_lossy(&buffer);
        write!(f, "{value}")
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct NameIdEntry {
    id: NamedPropertyId,
    guid: NamedPropertyGuid,
    prop_index: NamedPropertyIndex,
}

impl NameIdEntry {
    pub fn new(
        id: NamedPropertyId,
        guid: NamedPropertyGuid,
        prop_index: NamedPropertyIndex,
    ) -> Self {
        Self {
            id,
            guid,
            prop_index,
        }
    }

    pub fn id(&self) -> NamedPropertyId {
        self.id
    }

    pub fn guid(&self) -> NamedPropertyGuid {
        self.guid
    }

    pub fn prop_id(&self) -> u16 {
        self.prop_index.0
    }

    pub fn hash_value(&self) -> u32 {
        let guid = u16::from(self.guid);
        let (prop_id, guid_index) = match self.id {
            NamedPropertyId::Number(id) => (id, guid << 1),
            NamedPropertyId::StringOffset(offset) => (offset, (guid << 1) | 0x0001),
        };

        prop_id ^ u32::from(guid_index)
    }
}

impl NamedPropReadWrite for NameIdEntry {
    fn read(f: &mut dyn Read) -> io::Result<Self> {
        let prop_id = f.read_u32::<LittleEndian>()?;
        let guid_index = f.read_u16::<LittleEndian>()?;
        let prop_index = NamedPropertyIndex::try_from(f.read_u16::<LittleEndian>()?)?;

        let id = if guid_index & 0x0001 == 0 {
            NamedPropertyId::Number(prop_id)
        } else {
            NamedPropertyId::StringOffset(prop_id)
        };
        let guid_index = guid_index >> 1;
        let guid = NamedPropertyGuid::try_from(guid_index)?;

        Ok(Self {
            id,
            guid,
            prop_index,
        })
    }

    fn write(&self, f: &mut dyn Write) -> io::Result<()> {
        let guid = u16::from(self.guid);
        let (prop_id, guid_index) = match self.id {
            NamedPropertyId::Number(id) => (id, guid << 1),
            NamedPropertyId::StringOffset(offset) => (offset, (guid << 1) | 0x0001),
        };
        let prop_index = u16::from(self.prop_index);

        f.write_u32::<LittleEndian>(prop_id)?;
        f.write_u16::<LittleEndian>(guid_index)?;
        f.write_u16::<LittleEndian>(prop_index)
    }
}

#[derive(Default, Debug)]
pub struct NamedPropertyMapProperties {
    properties: BTreeMap<u16, PropertyValue>,
}

impl NamedPropertyMapProperties {
    pub fn get(&self, id: u16) -> Option<&PropertyValue> {
        self.properties.get(&id)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&u16, &PropertyValue)> {
        self.properties.iter()
    }

    pub fn hash_entry(&self, entry: NameIdEntry) -> io::Result<NameIdEntry> {
        Ok(match &entry.id {
            NamedPropertyId::Number(_) => entry,
            NamedPropertyId::StringOffset(offset) => {
                let string_entry = self.lookup_string(*offset)?;
                let hash_value =
                    NamedPropertyId::StringOffset(compute_crc(0, string_entry.buffer()));
                NameIdEntry::new(hash_value, entry.guid, entry.prop_index)
            }
        })
    }

    pub fn bucket_count(&self) -> io::Result<u16> {
        let bucket_count = self
            .properties
            .get(&0x0001)
            .ok_or(MessagingError::NamedPropertyMapBucketCountNotFound)?;

        match bucket_count {
            PropertyValue::Integer32(value) => {
                let count = u16::try_from(*value)
                    .map_err(|_| MessagingError::NamedPropertyMapBucketCountOutOfBounds(*value))?;
                if count > u16::MAX - 0x1000 {
                    Err(MessagingError::NamedPropertyMapBucketCountOutOfBounds(*value).into())
                } else {
                    Ok(count)
                }
            }
            invalid => Err(
                MessagingError::InvalidNamedPropertyMapBucketCount(PropertyType::from(invalid))
                    .into(),
            ),
        }
    }

    pub fn hash_bucket(&self, name_id: &NameIdEntry) -> io::Result<Vec<NameIdEntry>> {
        let bucket_count = self.bucket_count()?;
        let bucket_offset = name_id.hash_value() % u32::from(bucket_count);
        let bucket_offset = u16::try_from(bucket_offset)
            .map_err(|_| MessagingError::NamedPropertyMapBucketOffsetOutOfBounds(bucket_offset))?;
        if bucket_offset > u16::MAX - 0x1000 {
            return Err(MessagingError::NamedPropertyMapBucketNotFound(bucket_offset).into());
        }
        let bucket_prop = 0x1000 + bucket_offset;

        let hash_bucket = self.properties.get(&bucket_prop).ok_or(
            MessagingError::NamedPropertyMapBucketNotFound(bucket_offset),
        )?;

        match hash_bucket {
            PropertyValue::Binary(value) => {
                let mut results = Vec::with_capacity(value.buffer().len() / 8);
                let mut cursor = Cursor::new(value.buffer());
                while let Ok(value) = NameIdEntry::read(&mut cursor) {
                    results.push(value);
                }
                Ok(results)
            }
            invalid => Err(MessagingError::InvalidNamedPropertyMapStreamString(
                PropertyType::from(invalid),
            )
            .into()),
        }
    }

    /// The GUID of a NAMEID's `wGuid`: [`PS_MAPI`], [`PS_PUBLIC_STRINGS`], or the GUID at that
    /// index of the GUID stream (`PidTagNameidStreamGuid`).
    pub fn lookup_guid(&self, index: NamedPropertyGuid) -> io::Result<GuidValue> {
        let guid_index = match index {
            NamedPropertyGuid::None => {
                return Err(MessagingError::NamedPropertyMapGuidIndexOutOfBounds(0).into());
            }
            NamedPropertyGuid::Mapi => return Ok(PS_MAPI),
            NamedPropertyGuid::PublicStrings => return Ok(PS_PUBLIC_STRINGS),
            NamedPropertyGuid::GuidIndex(guid_index) => guid_index,
        };
        let stream_guid = self
            .properties
            .get(&0x0002)
            .ok_or(MessagingError::NamedPropertyMapStreamGuidNotFound)?;

        match stream_guid {
            PropertyValue::Binary(value) => {
                // wGuid 3 and up index the GUID stream from its start (MS-PST 2.4.7.1).
                let start = usize::from(guid_index) * 16;
                let Some(guid) = value.buffer().get(start..start + 16) else {
                    return Err(
                        MessagingError::NamedPropertyMapGuidIndexOutOfBounds(u16::from(index))
                            .into(),
                    );
                };
                let mut cursor = Cursor::new(guid);
                let entry = PropertyValue::read(&mut cursor, PropertyType::Guid)?;
                match entry {
                    PropertyValue::Guid(guid) => Ok(guid),
                    invalid => Err(MessagingError::InvalidNamedPropertyMapStreamGuid(
                        PropertyType::from(&invalid),
                    )
                    .into()),
                }
            }
            invalid => Err(
                MessagingError::InvalidNamedPropertyMapStreamGuid(PropertyType::from(invalid))
                    .into(),
            ),
        }
    }

    pub fn stream_guid(&self) -> io::Result<Vec<GuidValue>> {
        let stream_guid = self
            .properties
            .get(&0x0002)
            .ok_or(MessagingError::NamedPropertyMapStreamGuidNotFound)?;

        match stream_guid {
            PropertyValue::Binary(value) => {
                let mut results = Vec::with_capacity(value.buffer().len() / 16);
                let mut cursor = Cursor::new(value.buffer());
                while let Ok(value) = PropertyValue::read(&mut cursor, PropertyType::Guid) {
                    match value {
                        PropertyValue::Guid(guid) => results.push(guid),
                        invalid => {
                            return Err(MessagingError::InvalidNamedPropertyMapStreamGuid(
                                PropertyType::from(&invalid),
                            )
                            .into());
                        }
                    }
                }
                Ok(results)
            }
            invalid => Err(
                MessagingError::InvalidNamedPropertyMapStreamGuid(PropertyType::from(invalid))
                    .into(),
            ),
        }
    }

    pub fn stream_entry(&self) -> io::Result<Vec<NameIdEntry>> {
        let stream_entry = self
            .properties
            .get(&0x0003)
            .ok_or(MessagingError::NamedPropertyMapStreamEntryNotFound)?;

        match stream_entry {
            PropertyValue::Binary(value) => {
                let mut results = Vec::with_capacity(value.buffer().len() / 8);
                let mut cursor = Cursor::new(value.buffer());
                while let Ok(value) = NameIdEntry::read(&mut cursor) {
                    results.push(value);
                }
                Ok(results)
            }
            invalid => Err(
                MessagingError::InvalidNamedPropertyMapStreamEntry(PropertyType::from(invalid))
                    .into(),
            ),
        }
    }

    pub fn lookup_string(&self, offset: u32) -> io::Result<StringEntry> {
        let stream_string = self
            .properties
            .get(&0x0004)
            .ok_or(MessagingError::NamedPropertyMapStreamStringNotFound)?;

        match stream_string {
            PropertyValue::Binary(value) => {
                let mut cursor = Cursor::new(&value.buffer()[offset as usize..]);
                let entry = StringEntry::read(&mut cursor)?;
                Ok(entry)
            }
            invalid => Err(MessagingError::InvalidNamedPropertyMapStreamString(
                PropertyType::from(invalid),
            )
            .into()),
        }
    }

    pub fn stream_string(&self) -> io::Result<Vec<StringEntry>> {
        let stream_string = self
            .properties
            .get(&0x0004)
            .ok_or(MessagingError::NamedPropertyMapStreamStringNotFound)?;

        match stream_string {
            PropertyValue::Binary(value) => {
                let mut results = Vec::new();
                let mut cursor = Cursor::new(value.buffer());
                while let Ok(value) = StringEntry::read(&mut cursor) {
                    // Each length and string pair ends on a 4-byte boundary.
                    let padding = (4 - i64::from(value.size() % 4)) % 4;
                    results.push(value);

                    if padding > 0 && cursor.seek(SeekFrom::Current(padding)).is_err() {
                        break;
                    }
                }
                Ok(results)
            }
            invalid => Err(MessagingError::InvalidNamedPropertyMapStreamString(
                PropertyType::from(invalid),
            )
            .into()),
        }
    }
}

pub trait NamedPropertyMap {
    fn store(&self) -> Rc<dyn Store>;
    fn properties(&self) -> &NamedPropertyMapProperties;
}

struct NamedPropertyMapInner<Pst>
where
    Pst: PstFile,
{
    store: Rc<Pst::Store>,
    properties: NamedPropertyMapProperties,
}

impl<Pst> NamedPropertyMapInner<Pst>
where
    Pst: PstFile + PstFileLock<Pst>,
    <Pst as PstFile>::BTreeKey: BTreePageKeyReadWrite,
    <Pst as PstFile>::NodeBTreeEntry: NodeBTreeEntryReadWrite,
    <Pst as PstFile>::NodeBTree: RootBTreeReadWrite,
    <<Pst as PstFile>::NodeBTree as RootBTree>::IntermediatePage:
        RootBTreeIntermediatePageReadWrite<
                Pst,
                <Pst as PstFile>::NodeBTreeEntry,
                <<Pst as PstFile>::NodeBTree as RootBTree>::LeafPage,
            >,
    <<<Pst as PstFile>::NodeBTree as RootBTree>::IntermediatePage as BTreePage>::Entry:
        BTreePageEntryReadWrite,
    <<Pst as PstFile>::NodeBTree as RootBTree>::LeafPage: RootBTreeLeafPageReadWrite<Pst>,
    <Pst as PstFile>::BlockBTreeEntry: BlockBTreeEntryReadWrite,
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
    <Pst as PstFile>::HeapNode: HeapNodeReadWrite<Pst>,
    <Pst as PstFile>::PropertyTree: HeapTreeReadWrite<Pst>,
    <Pst as PstFile>::PropertyContext: PropertyContextReadWrite<Pst>,
    <Pst as PstFile>::Store: StoreReadWrite<Pst>,
{
    fn read(store: Rc<<Pst as PstFile>::Store>) -> io::Result<Self> {
        let pst = store.pst();
        let header = pst.header();
        let root = header.root();

        let properties = {
            let mut file = pst
                .reader()
                .lock()
                .map_err(|_| MessagingError::FailedToLockFile)?;
            let file = &mut *file;

            let encoding = header.crypt_method();
            let node_btree = <<Pst as PstFile>::NodeBTree as RootBTreeReadWrite>::read(
                file,
                *root.node_btree(),
            )?;
            let block_btree = <<Pst as PstFile>::BlockBTree as RootBTreeReadWrite>::read(
                file,
                *root.block_btree(),
            )?;

            let mut page_cache = pst.node_cache();
            let node_key: <Pst as PstFile>::BTreeKey = u32::from(NID_NAME_TO_ID_MAP).into();
            let node = node_btree.find_entry(file, node_key, &mut page_cache)?;

            let mut page_cache = pst.block_cache();
            let data = node.data();
            let heap = <<Pst as PstFile>::HeapNode as HeapNodeReadWrite<Pst>>::read(
                file,
                &block_btree,
                &mut page_cache,
                encoding,
                data.search_key(),
            )?;
            let header = heap.header()?;

            let tree = <Pst as PstFile>::PropertyTree::new(heap, header.user_root());
            let prop_context = <<Pst as PstFile>::PropertyContext as PropertyContextReadWrite<
                Pst,
            >>::new(node, tree);
            let properties = prop_context
                .properties()?
                .into_iter()
                .map(|(prop_id, record)| {
                    prop_context
                        .read_property(file, encoding, &block_btree, &mut page_cache, record)
                        .map(|value| (prop_id, value))
                })
                .collect::<io::Result<BTreeMap<_, _>>>()?;
            NamedPropertyMapProperties { properties }
        };

        Ok(Self { store, properties })
    }
}

pub struct UnicodeNamedPropertyMap {
    inner: NamedPropertyMapInner<UnicodePstFile>,
}

impl NamedPropertyMap for UnicodeNamedPropertyMap {
    fn store(&self) -> Rc<dyn Store> {
        self.inner.store.clone()
    }

    fn properties(&self) -> &NamedPropertyMapProperties {
        &self.inner.properties
    }
}

impl NamedPropertyMapReadWrite<UnicodePstFile> for UnicodeNamedPropertyMap {
    fn read(store: Rc<UnicodeStore>) -> io::Result<Rc<Self>> {
        let inner = NamedPropertyMapInner::read(store)?;
        Ok(Rc::new(Self { inner }))
    }
}

pub struct AnsiNamedPropertyMap {
    inner: NamedPropertyMapInner<AnsiPstFile>,
}

impl NamedPropertyMap for AnsiNamedPropertyMap {
    fn store(&self) -> Rc<dyn Store> {
        self.inner.store.clone()
    }

    fn properties(&self) -> &NamedPropertyMapProperties {
        &self.inner.properties
    }
}

impl NamedPropertyMapReadWrite<AnsiPstFile> for AnsiNamedPropertyMap {
    fn read(store: Rc<AnsiStore>) -> io::Result<Rc<Self>> {
        let inner = NamedPropertyMapInner::read(store)?;
        Ok(Rc::new(Self { inner }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ltp::prop_context::BinaryValue;

    #[test]
    fn test_stream_string_reads_every_name() {
        // Every name the entry stream of Empty.pst points at should be in stream_string().
        let store = crate::open_store(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/Empty.pst"
        ))
        .unwrap();
        let map = store.named_property_map().unwrap();
        let properties = map.properties();
        let offsets: std::collections::BTreeSet<u32> = properties
            .stream_entry()
            .unwrap()
            .iter()
            .filter_map(|entry| match entry.id() {
                NamedPropertyId::StringOffset(offset) => Some(offset),
                NamedPropertyId::Number(_) => None,
            })
            .collect();
        let expected: Vec<String> = offsets
            .iter()
            .map(|offset| properties.lookup_string(*offset).unwrap().to_string())
            .collect();
        let names: Vec<String> = properties
            .stream_string()
            .unwrap()
            .iter()
            .map(ToString::to_string)
            .collect();
        assert!(names.len() > 1);
        assert_eq!(names, expected);
    }

    #[test]
    fn test_lookup_guid() {
        let guid = |data1: u32| {
            let mut bytes = data1.to_le_bytes().to_vec();
            bytes.extend_from_slice(&[0; 12]);
            bytes
        };
        let map = NamedPropertyMapProperties {
            properties: BTreeMap::from([(
                0x0002,
                PropertyValue::Binary(BinaryValue::new([guid(0x11), guid(0x22)].concat())),
            )]),
        };
        let data1 = |index| map.lookup_guid(index).map(|guid| guid.data1());
        // wGuid 3 is the first GUID of the stream, wGuid 4 the second.
        assert_eq!(data1(NamedPropertyGuid::GuidIndex(0)).unwrap(), 0x11);
        assert_eq!(data1(NamedPropertyGuid::GuidIndex(1)).unwrap(), 0x22);
        assert!(data1(NamedPropertyGuid::GuidIndex(2)).is_err());
        assert!(data1(NamedPropertyGuid::GuidIndex(u16::MAX)).is_err());
        assert!(data1(NamedPropertyGuid::None).is_err());
        assert_eq!(data1(NamedPropertyGuid::Mapi).unwrap(), PS_MAPI.data1());
        assert_eq!(
            data1(NamedPropertyGuid::PublicStrings).unwrap(),
            PS_PUBLIC_STRINGS.data1()
        );
    }

    #[test]
    fn test_lookup_guid_of_every_entry() {
        // Every NAMEID of Empty.pst names a GUID that lookup_guid finds.
        let store = crate::open_store(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/Empty.pst"
        ))
        .unwrap();
        let map = store.named_property_map().unwrap();
        let properties = map.properties();
        let guids = properties.stream_guid().unwrap();
        let mut indexed = 0;
        for entry in properties.stream_entry().unwrap() {
            let guid = properties.lookup_guid(entry.guid()).unwrap();
            if let NamedPropertyGuid::GuidIndex(index) = entry.guid() {
                assert_eq!(
                    format!("{guid:?}"),
                    format!("{:?}", guids[usize::from(index)])
                );
                indexed += 1;
            }
        }
        assert!(indexed > 0);
    }

    #[test]
    fn test_hash_entry_keeps_guid() {
        let name: Vec<u8> = "Keywords"
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();
        let mut stream = (name.len() as u32).to_le_bytes().to_vec();
        stream.extend_from_slice(&name);
        let map = NamedPropertyMapProperties {
            properties: BTreeMap::from([(0x0004, PropertyValue::Binary(BinaryValue::new(stream)))]),
        };

        let prop_index = NamedPropertyIndex::try_from(0).unwrap();
        let entry = NameIdEntry::new(
            NamedPropertyId::StringOffset(0),
            NamedPropertyGuid::PublicStrings,
            prop_index,
        );
        assert_eq!(
            map.hash_entry(entry).unwrap(),
            NameIdEntry::new(
                NamedPropertyId::StringOffset(compute_crc(0, &name)),
                NamedPropertyGuid::PublicStrings,
                prop_index,
            )
        );
    }
}
