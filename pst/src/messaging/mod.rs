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

//! ## [Messaging Layer](https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-pst/3f1bc553-d15d-4dcf-9b80-fbf1dd6c7e79)

use std::{
    collections::{BTreeMap, btree_map::Entry},
    io,
};
use thiserror::Error;

use crate::{
    PstFile, PstFileInternal,
    ltp::prop_context::{PropertyTreeRecordValue, PropertyValue, PropertyValueRecord},
    ndb::{block::MAX_BLOCK_TREE_INFLATION, node_id::NodeId},
    problems::{self, Problem, ProblemKind},
};

pub mod attachment;
pub mod folder;
pub mod message;
pub mod named_prop;
pub mod search;
pub mod store;

pub(crate) mod read_write;

#[derive(Error, Debug)]
pub enum MessagingError {
    #[error("Node Database error: {0}")]
    NodeDatabaseError(#[from] crate::ndb::NdbError),
    #[error("Node Database error: {0}")]
    ListsTablesPropertiesError(#[from] crate::ltp::LtpError),
    #[error("Failed to lock PST file")]
    FailedToLockFile,
    #[error("Property value is also the value of property 0x{0:04X}")]
    SharedPropertyValue(u16),
    #[error(
        "Property values of the object hold more than MAX_BLOCK_TREE_INFLATION times the file (0x{0:X} bytes)"
    )]
    ObjectPropertiesTooLarge(u64),
    #[error("Invalid EntryID rgbFlags: 0x{0:08X}")]
    InvalidEntryIdFlags(u32),
    #[error("Missing PidTagRecordKey on store")]
    StoreRecordKeyNotFound,
    #[error("Invalid PidTagRecordKey on store: {0:?}")]
    InvalidStoreRecordKey(crate::ltp::prop_type::PropertyType),
    #[error("Invalid PidTagRecordKey size on store: 0x{0:X}")]
    InvalidStoreRecordKeySize(usize),
    #[error("Failed to read root hierarchy table: {0}")]
    StoreRootHierarchyTableFailed(String),
    #[error("Failed to open a folder: {0}")]
    StoreOpenFolder(String),
    #[error("Failed to read named property map: {0}")]
    StoreNamedPropertyMap(String),
    #[error("Failed to read search update queue: {0}")]
    StoreSearchUpdateQueue(String),
    #[error("Missing PidTagDisplayName on store")]
    StoreDisplayNameNotFound,
    #[error("Invalid PidTagDisplayName on store: {0:?}")]
    InvalidStoreDisplayName(crate::ltp::prop_type::PropertyType),
    #[error("Missing PidTagIpmSubTreeEntryId on store")]
    StoreIpmSubTreeEntryIdNotFound,
    #[error("Invalid PidTagIpmSubTreeEntryId on store: {0:?}")]
    InvalidStoreIpmSubTreeEntryId(crate::ltp::prop_type::PropertyType),
    #[error("Missing PidTagIpmWastebasketEntryId on store")]
    StoreIpmWastebasketEntryIdNotFound,
    #[error("Invalid PidTagIpmWastebasketEntryId on store: {0:?}")]
    InvalidStoreIpmWastebasketEntryId(crate::ltp::prop_type::PropertyType),
    #[error("Missing PidTagFinderEntryId on store")]
    StoreFinderEntryIdNotFound,
    #[error("Invalid PidTagFinderEntryId on store: {0:?}")]
    InvalidStoreFinderEntryId(crate::ltp::prop_type::PropertyType),
    #[error("EntryID in wrong store")]
    EntryIdWrongStore,
    #[error("Missing PidTagDisplayName on folder")]
    FolderDisplayNameNotFound,
    #[error("Invalid PidTagDisplayName on folder: {0:?}")]
    InvalidFolderDisplayName(crate::ltp::prop_type::PropertyType),
    #[error("Missing PidTagContentCount on folder")]
    FolderContentCountNotFound,
    #[error("Invalid PidTagContentCount on folder: {0:?}")]
    InvalidFolderContentCount(crate::ltp::prop_type::PropertyType),
    #[error("Missing PidTagContentUnreadCount on folder")]
    FolderUnreadCountNotFound,
    #[error("Invalid PidTagContentUnreadCount on folder: {0:?}")]
    InvalidFolderUnreadCount(crate::ltp::prop_type::PropertyType),
    #[error("Missing PidTagSubfolders on folder")]
    FolderHasSubfoldersNotFound,
    #[error("Invalid PidTagSubfolders on folder: {0:?}")]
    InvalidFolderHasSubfolders(crate::ltp::prop_type::PropertyType),
    #[error("Invalid folder EntryID NID_TYPE: {0:?}")]
    InvalidFolderEntryIdType(crate::ndb::node_id::NodeIdType),
    #[error("Missing PidTagMessageClass on message")]
    MessageClassNotFound,
    #[error("Invalid PidTagMessageClass on message: {0:?}")]
    InvalidMessageClass(crate::ltp::prop_type::PropertyType),
    #[error("Missing PidTagMessageFlags on message")]
    MessageFlagsNotFound,
    #[error("Invalid PidTagMessageFlags on message: {0:?}")]
    InvalidMessageFlags(crate::ltp::prop_type::PropertyType),
    #[error("Missing PidTagMessageSize on message")]
    MessageSizeNotFound,
    #[error("Invalid PidTagMessageSize on message: {0:?}")]
    InvalidMessageSize(crate::ltp::prop_type::PropertyType),
    #[error("Missing PidTagMessageStatus on message")]
    MessageStatusNotFound,
    #[error("Invalid PidTagMessageStatus on message: {0:?}")]
    InvalidMessageStatus(crate::ltp::prop_type::PropertyType),
    #[error("Missing PidTagMessageCreationTime on message")]
    MessageCreationTimeNotFound,
    #[error("Invalid PidTagMessageCreationTime on message: {0:?}")]
    InvalidMessageCreationTime(crate::ltp::prop_type::PropertyType),
    #[error("Missing PidTagMessageLastModificationTime on message")]
    MessageLastModificationTimeNotFound,
    #[error("Invalid PidTagMessageLastModificationTime on message: {0:?}")]
    InvalidMessageLastModificationTime(crate::ltp::prop_type::PropertyType),
    #[error("Missing PidTagMessageSearchKey on message")]
    MessageSearchKeyNotFound,
    #[error("Invalid PidTagMessageSearchKey on message: {0:?}")]
    InvalidMessageSearchKey(crate::ltp::prop_type::PropertyType),
    #[error("Invalid message EntryID NID_TYPE: {0:?}")]
    InvalidMessageEntryIdType(crate::ndb::node_id::NodeIdType),
    #[error("Missing Sub-Node Tree on message")]
    MessageSubNodeTreeNotFound,
    #[error("Multiple NID_TYPE_RECIPIENT_TABLE sub-nodes on message")]
    MultipleMessageRecipientTables,
    #[error("Multiple NID_TYPE_ATTACHMENT_TABLE sub-nodes on message")]
    MultipleMessageAttachmentTables,
    #[error("Missing PidTagAttachSize on message")]
    AttachmentSizeNotFound,
    #[error("Invalid PidTagAttachSize on message: {0:?}")]
    InvalidAttachmentSize(crate::ltp::prop_type::PropertyType),
    #[error("Missing PidTagAttachMethod on message")]
    AttachmentMethodNotFound,
    #[error("Invalid PidTagAttachMethod on message: {0:?}")]
    InvalidAttachmentMethod(crate::ltp::prop_type::PropertyType),
    #[error("Missing PidTagRenderingPosition on message")]
    AttachmentRenderingPositionNotFound,
    #[error("Invalid PidTagRenderingPosition on message: {0:?}")]
    InvalidAttachmentRenderingPosition(crate::ltp::prop_type::PropertyType),
    #[error("Invalid attachment Sub-Node NID_TYPE: {0:?}")]
    InvalidAttachmentNodeIdType(crate::ndb::node_id::NodeIdType),
    #[error("Unrecognized PidTagAttachMethod on attachment: 0x{0:08X}")]
    UnknownAttachmentMethod(i32),
    #[error("Missing attachment Sub-Node on message: {0:?}")]
    AttachmentSubNodeNotFound(crate::ndb::node_id::NodeId),
    #[error("Embedded message {0} levels down, more than MAX_EMBEDDED_MESSAGE_DEPTH")]
    EmbeddedMessageTooDeep(usize),
    #[error(
        "Embedded message has the data and sub-node blocks of a message it is embedded in (0x{0:X}, {1:X?})"
    )]
    EmbeddedMessageCycle(u64, Option<u64>),
    #[error("Missing PidTagAttachDataObject on afEmbeddedMessage attachment")]
    AttachmentMessageObjectDataNotFound,
    #[error("Invalid PidTagAttachDataObject on afEmbeddedMessage attachment: {0:?}")]
    InvalidMessageObjectData(crate::ltp::prop_type::PropertyType),
    #[error("Missing PidTagAttachDataBinary on afByValue attachment")]
    AttachmentFileBinaryDataNotFound,
    #[error("Invalid PidTagAttachDataBinary on afByValue attachment: {0:?}")]
    InvalidAttachmentFileBinaryData(crate::ltp::prop_type::PropertyType),
    #[error("Missing PidTagAttachDataObject on afStorage attachment")]
    AttachmentStorageObjectDataNotFound,
    #[error("Reading afStorage attachment failed: {0}")]
    AttachmentStorageRead(String),
    #[error("Invalid PidTagAttachDataObject on afStorage attachment: {0:?}")]
    InvalidStorageObjectData(crate::ltp::prop_type::PropertyType),
    #[error("NAMEID wGuid is out of bounds: 0x{0:04X}")]
    NamedPropertyMapGuidIndexOutOfBounds(u16),
    #[error("NAMEID wPropIdx is out of bounds: 0x{0:04X}")]
    NamedPropertyMapPropertyIndexOutOfBounds(u16),
    #[error("PidTagNameidBucketCount on Named Property Lookup Map is out of bounds: 0x{0:08X}")]
    NamedPropertyMapBucketCountOutOfBounds(i32),
    #[error("Hash bucket offset on Named Property Lookup Map is out of bounds: 0x{0:04X}")]
    NamedPropertyMapBucketOffsetOutOfBounds(u32),
    #[error("Invalid PidTagNameidStreamString string")]
    NamedPropertyMapStringEntryOutOfBounds,
    #[error("Missing PidTagNameidBucketCount on Named Property Lookup Map")]
    NamedPropertyMapBucketCountNotFound,
    #[error("Invalid PidTagNameidBucketCount on Named Property Lookup Map: {0:?}")]
    InvalidNamedPropertyMapBucketCount(crate::ltp::prop_type::PropertyType),
    #[error("Missing PidTagNameidStreamGuid on Named Property Lookup Map")]
    NamedPropertyMapStreamGuidNotFound,
    #[error("Invalid PidTagNameidStreamGuid on Named Property Lookup Map: {0:?}")]
    InvalidNamedPropertyMapStreamGuid(crate::ltp::prop_type::PropertyType),
    #[error("Missing PidTagNameidStreamEntry on Named Property Lookup Map")]
    NamedPropertyMapStreamEntryNotFound,
    #[error("Invalid PidTagNameidStreamEntry on Named Property Lookup Map: {0:?}")]
    InvalidNamedPropertyMapStreamEntry(crate::ltp::prop_type::PropertyType),
    #[error("Missing PidTagNameidStreamString on Named Property Lookup Map")]
    NamedPropertyMapStreamStringNotFound,
    #[error("Invalid PidTagNameidStreamString on Named Property Lookup Map: {0:?}")]
    InvalidNamedPropertyMapStreamString(crate::ltp::prop_type::PropertyType),
    #[error("Missing PidTagNameidBucketBase + hash on Named Property Lookup Map")]
    NamedPropertyMapBucketNotFound(u16),
    #[error("Invalid PidTagNameidBucketBase + hash on Named Property Lookup Map: {0:?}")]
    InvalidNamedPropertyMapBucket(crate::ltp::prop_type::PropertyType),
    #[error("Invalid SUD wSUDType: 0x{0:04X}")]
    InvalidSearchUpdateType(u16),
    #[error("Invalid SUD queue offset: 0x{0:08X}")]
    InvalidSearchUpdateQueueOffset(u32),
    #[error("Invalid SUD queue size: {0}")]
    InvalidSearchUpdateQueueSize(usize),
}

impl From<MessagingError> for io::Error {
    fn from(err: MessagingError) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, err)
    }
}

pub type MessagingResult<T> = Result<T, MessagingError>;

/// Read each property of a node's property context with `read`. A property that cannot be read is
/// a [`Problem`] and is left out when reading leniently, else the error.
///
/// Each heap allocation or sub-node holds the value of one property: a property whose value is
/// that of an earlier one cannot be read, so that many records naming one value do not copy it
/// many times. Nor can a property whose value would make the values read for the object hold more
/// than [`MAX_BLOCK_TREE_INFLATION`] times the file.
pub(crate) fn read_properties<Pst>(
    pst: &Pst,
    node: NodeId,
    records: impl IntoIterator<Item = (u16, PropertyTreeRecordValue)>,
    mut read: impl FnMut(PropertyTreeRecordValue) -> io::Result<PropertyValue>,
) -> io::Result<BTreeMap<u16, PropertyValue>>
where
    Pst: PstFile + PstFileInternal<Pst>,
{
    let limit = pst.file_size().saturating_mul(MAX_BLOCK_TREE_INFLATION);
    let mut size = 0_u64;
    let mut values = BTreeMap::new();
    let mut properties = BTreeMap::new();
    for (prop_id, record) in records {
        let prop_type = record.prop_type();
        let value = match record.value() {
            PropertyValueRecord::Heap(heap_id) if u32::from(heap_id) != 0 => {
                Some((false, u32::from(heap_id)))
            }
            PropertyValueRecord::Node(node) => Some((true, u32::from(node))),
            _ => None,
        };
        let first = value.and_then(|value| match values.entry(value) {
            Entry::Occupied(entry) => Some(*entry.get()),
            Entry::Vacant(entry) => {
                entry.insert(prop_id);
                None
            }
        });
        let result = match first {
            Some(first) => Err(MessagingError::SharedPropertyValue(first).into()),
            None => read(record).and_then(|value| {
                let total = size.saturating_add(value.data_size());
                if total > limit {
                    return Err(MessagingError::ObjectPropertiesTooLarge(limit).into());
                }
                size = total;
                Ok(value)
            }),
        };
        let value = problems::isolate(
            pst.validation(),
            pst.problem_log(),
            |err| {
                Problem::new(
                    ProblemKind::Property,
                    None,
                    Some(node),
                    format!("property 0x{prop_id:04X} ({prop_type:?}): {err}"),
                )
            },
            result,
        )?;
        if let Some(value) = value {
            properties.insert(prop_id, value);
        }
    }
    Ok(properties)
}

/// A part of an object that could not be read: a [`Problem`] of `kind` when reading leniently,
/// and the part is left out (`None`), else the error.
pub(crate) fn isolate_part<Pst, T>(
    pst: &Pst,
    kind: ProblemKind,
    node: NodeId,
    what: &str,
    result: io::Result<T>,
) -> io::Result<Option<T>>
where
    Pst: PstFile + PstFileInternal<Pst>,
{
    problems::isolate(
        pst.validation(),
        pst.problem_log(),
        |err| Problem::new(kind, None, Some(node), format!("{what}: {err}")),
        result,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        UnicodePstFile, Validation,
        ltp::{heap::HeapId, prop_context::BinaryValue, prop_type::PropertyType},
    };
    use std::cell::Cell;

    fn empty_pst(validation: Validation) -> UnicodePstFile {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/Empty.pst");
        UnicodePstFile::open_with(path, validation).unwrap()
    }

    fn binary(value: PropertyValueRecord) -> PropertyTreeRecordValue {
        PropertyTreeRecordValue::new(PropertyType::Binary, value)
    }

    fn sub_node(index: u16) -> PropertyValueRecord {
        PropertyValueRecord::Node(NodeId::from((u32::from(index) << 5) | 0x1F))
    }

    #[test]
    fn test_value_of_many_properties_is_read_once() {
        let node = NodeId::from(0x200024);
        for shared in [PropertyValueRecord::Heap(HeapId::from(0x20)), sub_node(1)] {
            let pst = empty_pst(Validation::Lenient);
            let before = pst.problems().len();
            let reads = Cell::new(0);
            let records = (0..8000).map(|prop_id| (prop_id, binary(shared)));
            let properties = read_properties(&pst, node, records, |_| {
                reads.set(reads.get() + 1);
                Ok(PropertyValue::Binary(BinaryValue::new(vec![0x41; 60_000])))
            })
            .unwrap();
            assert_eq!(reads.get(), 1);
            assert_eq!(properties.keys().copied().collect::<Vec<_>>(), [0]);
            let problems = pst.problems().split_off(before);
            assert_eq!(problems.len(), 7999);
            for problem in &problems {
                assert_eq!(problem.kind(), ProblemKind::Property);
                assert_eq!(problem.node(), Some(node));
                assert!(
                    problem
                        .detail()
                        .ends_with("is also the value of property 0x0000"),
                    "{}",
                    problem.detail()
                );
            }

            // A heap ID of 0 is an empty value, not one that is shared.
            let empty = PropertyValueRecord::Heap(HeapId::from(0));
            let records = (0..2).map(|prop_id| (prop_id, binary(empty)));
            let properties =
                read_properties(&pst, node, records, |_| Ok(PropertyValue::Null)).unwrap();
            assert_eq!(properties.len(), 2);

            let pst = empty_pst(Validation::Strict);
            let records = [(1, binary(shared)), (2, binary(shared))];
            let err = read_properties(&pst, node, records, |_| Ok(PropertyValue::Null))
                .unwrap_err()
                .to_string();
            assert!(
                err.ends_with("is also the value of property 0x0001"),
                "{err}"
            );
        }
    }

    #[test]
    fn test_property_values_of_an_object_are_limited() {
        let node = NodeId::from(0x200024);
        let pst = empty_pst(Validation::Lenient);
        let before = pst.problems().len();
        let size = usize::try_from(pst.file_size()).unwrap();
        let records = (0..20).map(|prop_id| (prop_id, binary(sub_node(prop_id))));
        let properties = read_properties(&pst, node, records, |_| {
            Ok(PropertyValue::Binary(BinaryValue::new(vec![0; size])))
        })
        .unwrap();
        assert_eq!(
            properties.keys().copied().collect::<Vec<_>>(),
            (0..8).collect::<Vec<_>>()
        );
        assert_eq!(MAX_BLOCK_TREE_INFLATION, 8);
        let problems = pst.problems().split_off(before);
        assert_eq!(problems.len(), 12);
        for problem in &problems {
            assert_eq!(problem.kind(), ProblemKind::Property);
            assert!(
                problem.detail().contains("MAX_BLOCK_TREE_INFLATION"),
                "{}",
                problem.detail()
            );
        }

        let pst = empty_pst(Validation::Strict);
        let records = (0..9).map(|prop_id| (prop_id, binary(sub_node(prop_id))));
        let err = read_properties(&pst, node, records, |_| {
            Ok(PropertyValue::Binary(BinaryValue::new(vec![0; size])))
        })
        .unwrap_err();
        assert!(
            err.to_string().contains("MAX_BLOCK_TREE_INFLATION"),
            "{err}"
        );
    }
}
