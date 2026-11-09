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

//! ## [Attachment Objects](https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-pst/46eb4828-c6a5-420d-a137-9ee36df317c1)

use std::{collections::BTreeMap, io, rc::Rc};

use super::{message::*, read_write::*, *};
use crate::{
    AnsiPstFile, PstFile, PstFileInternal, UnicodePstFile,
    ltp::{
        heap::HeapNode,
        prop_context::{BinaryValue, ObjectValue, PropertyContext, PropertyValue},
        prop_type::PropertyType,
        read_write::*,
    },
    ndb::{
        block::{DataTree, IntermediateTreeBlock, SubNodeTree},
        block_id::BlockId,
        header::Header,
        node_id::{NodeId, NodeIdType},
        page::{BTreePage, NodeBTreeEntry, RootBTree},
        read_write::*,
        root::Root,
    },
    problems::ProblemKind,
};

#[derive(Default, Debug)]
pub struct AttachmentProperties {
    properties: BTreeMap<u16, PropertyValue>,
}

impl AttachmentProperties {
    pub fn get(&self, id: u16) -> Option<&PropertyValue> {
        self.properties.get(&id)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&u16, &PropertyValue)> {
        self.properties.iter()
    }

    pub fn attachment_size(&self) -> io::Result<i32> {
        let attachment_size = self
            .properties
            .get(&0x0E20)
            .ok_or(MessagingError::AttachmentSizeNotFound)?;

        match attachment_size {
            PropertyValue::Integer32(value) => Ok(*value),
            invalid => {
                Err(MessagingError::InvalidAttachmentSize(PropertyType::from(invalid)).into())
            }
        }
    }

    pub fn attachment_method(&self) -> io::Result<i32> {
        let attachment_method = self
            .properties
            .get(&0x3705)
            .ok_or(MessagingError::AttachmentMethodNotFound)?;

        match attachment_method {
            PropertyValue::Integer32(value) => Ok(*value),
            invalid => {
                Err(MessagingError::InvalidAttachmentMethod(PropertyType::from(invalid)).into())
            }
        }
    }

    /// `PidTagAttachDataBinary` (0x3701) of an `afByValue` attachment.
    fn data_binary(&self) -> MessagingResult<&BinaryValue> {
        match self
            .properties
            .get(&0x3701)
            .ok_or(MessagingError::AttachmentFileBinaryDataNotFound)?
        {
            PropertyValue::Binary(value) => Ok(value),
            invalid => Err(MessagingError::InvalidAttachmentFileBinaryData(
                PropertyType::from(invalid),
            )),
        }
    }

    /// `PidTagAttachDataObject` (0x3701) of an `afEmbeddedMessage` or `afStorage` attachment.
    fn data_object(&self, method: AttachmentMethod) -> MessagingResult<&ObjectValue> {
        let storage = method == AttachmentMethod::Storage;
        let value = self.properties.get(&0x3701).ok_or(if storage {
            MessagingError::AttachmentStorageObjectDataNotFound
        } else {
            MessagingError::AttachmentMessageObjectDataNotFound
        })?;
        match value {
            PropertyValue::Object(value) => Ok(value),
            invalid if storage => Err(MessagingError::InvalidStorageObjectData(
                PropertyType::from(invalid),
            )),
            invalid => Err(MessagingError::InvalidMessageObjectData(
                PropertyType::from(invalid),
            )),
        }
    }

    pub fn rendering_position(&self) -> io::Result<i32> {
        let rendering_position = self
            .properties
            .get(&0x370B)
            .ok_or(MessagingError::AttachmentRenderingPositionNotFound)?;

        match rendering_position {
            PropertyValue::Integer32(value) => Ok(*value),
            invalid => Err(
                MessagingError::InvalidAttachmentRenderingPosition(PropertyType::from(invalid))
                    .into(),
            ),
        }
    }
}

/// [PidTagAttachMethod](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxcmsg/252923d6-dd41-468b-9c57-d3f68051a516)
#[repr(i32)]
#[derive(Clone, Copy, PartialEq, Eq, Default, Debug)]
pub enum AttachmentMethod {
    /// `afNone`: The attachment has just been created.
    #[default]
    None = 0x00000000,
    /// `afByValue`: The `PidTagAttachDataBinary` property (section [2.2.2.7](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxcmsg/42dfb62b-2ff5-4ffc-ae25-bfdd2db3d8e0))
    /// contains the attachment data.
    ByValue = 0x00000001,
    /// `afByReference`: The `PidTagAttachLongPathname` property (section [2.2.2.13](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxcmsg/74b1b39e-1cb4-48ad-b28e-405a261e556c))
    /// contains a fully qualified path identifying the attachment To recipients with access to a
    /// common file server.
    ByReference = 0x00000002,
    /// `afByReferenceOnly`: The `PidTagAttachLongPathname` property contains a fully qualified
    /// path identifying the attachment.
    ByReferenceOnly = 0x00000004,
    /// `afEmbeddedMessage`: The attachment is an embedded message that is accessed via the `RopOpenEmbeddedMessage` ROP ([MS-OXCROPS](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxcrops/13af6911-27e5-4aa0-bb75-637b02d4f2ef)
    /// section [2.2.6.16](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxcrops/bce79473-e082-4452-822c-ab8cb055dee6)).
    EmbeddedMessage = 0x00000005,
    /// `afStorage`: The `PidTagAttachDataObject` property (section [2.2.2.8](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxcmsg/0691206f-0082-463a-a12f-58cb7cb7875f))
    /// contains data in an application-specific format.
    Storage = 0x00000006,
    /// `afByWebReference`: The `PidTagAttachLongPathname` property contains a fully qualified path
    /// identifying the attachment. The `PidNameAttachmentProviderType` defines the web service API
    /// manipulating the attachment.
    ByWebReference = 0x00000007,
}

impl TryFrom<i32> for AttachmentMethod {
    type Error = MessagingError;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            0x00000000 => Ok(Self::None),
            0x00000001 => Ok(Self::ByValue),
            0x00000002 => Ok(Self::ByReference),
            0x00000004 => Ok(Self::ByReferenceOnly),
            0x00000005 => Ok(Self::EmbeddedMessage),
            0x00000006 => Ok(Self::Storage),
            0x00000007 => Ok(Self::ByWebReference),
            _ => Err(MessagingError::UnknownAttachmentMethod(value)),
        }
    }
}

pub enum AttachmentData {
    Binary(BinaryValue),
    Message(Rc<dyn Message>),
}

pub trait Attachment {
    fn message(&self) -> Rc<dyn Message>;
    fn properties(&self) -> &AttachmentProperties;
    fn data(&self) -> Option<&AttachmentData>;
}

struct AttachmentInner<Pst>
where
    Pst: PstFile,
{
    message: Rc<Pst::Message>,
    properties: AttachmentProperties,
    data: Option<AttachmentData>,
    /// The embedded message of [`AttachmentData::Message`], as its own type, so that its
    /// attachments can be read too.
    embedded: Option<Rc<Pst::Message>>,
}

impl<Pst> AttachmentInner<Pst>
where
    Pst: PstFile + PstFileInternal<Pst>,
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
    <Pst as PstFile>::SubNodeTreeBlockHeader: IntermediateTreeHeaderReadWrite,
    <Pst as PstFile>::SubNodeTreeBlock: IntermediateTreeBlockReadWrite,
    <<Pst as PstFile>::SubNodeTreeBlock as IntermediateTreeBlock>::Entry:
        IntermediateTreeEntryReadWrite,
    <Pst as PstFile>::SubNodeBlock: IntermediateTreeBlockReadWrite,
    <<Pst as PstFile>::SubNodeBlock as IntermediateTreeBlock>::Entry:
        IntermediateTreeEntryReadWrite,
    <Pst as PstFile>::DataTreeBlock: IntermediateTreeBlockReadWrite,
    <<Pst as PstFile>::DataTreeBlock as IntermediateTreeBlock>::Entry:
        IntermediateTreeEntryReadWrite,
    <Pst as PstFile>::DataBlock: BlockReadWrite + Clone,
    <Pst as PstFile>::HeapNode: HeapNodeReadWrite<Pst>,
    <Pst as PstFile>::PropertyTree: HeapTreeReadWrite<Pst>,
    <Pst as PstFile>::PropertyContext: PropertyContextReadWrite<Pst>,
    <Pst as PstFile>::Store: StoreReadWrite<Pst>,
    <Pst as PstFile>::Message: MessageReadWrite<Pst> + 'static,
{
    fn read(
        message: Rc<<Pst as PstFile>::Message>,
        sub_node: NodeId,
        prop_ids: Option<&[u16]>,
    ) -> io::Result<Self> {
        let attachment_node = sub_node;
        let node_id_type = sub_node.id_type()?;
        match node_id_type {
            NodeIdType::Attachment => {}
            _ => {
                return Err(MessagingError::InvalidAttachmentNodeIdType(node_id_type).into());
            }
        }

        let store = message.pst_store();
        let pst = store.pst();
        let header = pst.header();
        let root = header.root();

        let mut embedded = None;
        let (properties, data) = {
            let mut file = pst.lock_reader()?;
            let file = &mut *file;

            let encoding = header.crypt_method();
            let block_btree = <<Pst as PstFile>::BlockBTree as RootBTreeReadWrite>::read(
                file,
                *root.block_btree(),
            )?;

            let node = message
                .sub_nodes()
                .get(&sub_node)
                .ok_or(MessagingError::AttachmentSubNodeNotFound(sub_node))?;
            let node = <<Pst as PstFile>::NodeBTreeEntry as NodeBTreeEntryReadWrite>::new(
                node.node(),
                node.block(),
                node.sub_node(),
                None,
            );
            let attachment_sub_nodes = node.sub_node();

            let mut page_cache = pst.block_cache()?;
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
            let properties =
                read_properties(pst, node.node(), prop_context.properties()?, |record| {
                    prop_context.read_property(
                        file,
                        encoding,
                        &block_btree,
                        &mut page_cache,
                        record,
                    )
                })?;
            let properties = AttachmentProperties { properties };

            let data = (|| -> io::Result<Option<AttachmentData>> {
                let attachment_method =
                    AttachmentMethod::try_from(properties.attachment_method()?)?;
                Ok(match attachment_method {
                    AttachmentMethod::ByValue => {
                        let binary_data = properties.data_binary()?;
                        Some(AttachmentData::Binary(binary_data.clone()))
                    }
                    AttachmentMethod::EmbeddedMessage => {
                        let object_data = properties.data_object(attachment_method)?;

                        // The embedded message is in the attachment's sub-node tree, not the message's.
                        let sub_node = object_data.node();
                        let attachment_sub_nodes = attachment_sub_nodes
                            .ok_or(MessagingError::AttachmentSubNodeNotFound(sub_node))?;
                        let block = block_btree.find_entry(
                            file,
                            attachment_sub_nodes.search_key(),
                            &mut page_cache,
                        )?;
                        let entry = SubNodeTree::<Pst>::read(file, &block)?
                            .entries(file, &block_btree, &mut page_cache)?
                            .find(|entry| entry.node() == sub_node)
                            .ok_or(MessagingError::AttachmentSubNodeNotFound(sub_node))?;

                        // Read it once the file lock is released, since read_embedded takes it again.
                        embedded = Some(
                            <<Pst as PstFile>::NodeBTreeEntry as NodeBTreeEntryReadWrite>::new(
                                entry.node(),
                                entry.block(),
                                entry.sub_node(),
                                None,
                            ),
                        );
                        None
                    }
                    AttachmentMethod::Storage => {
                        let object_data = properties.data_object(attachment_method)?;
                        let sub_node = object_data.node();
                        // Like an embedded message, the storage is a sub-node of the attachment
                        // (MS-PST 2.3.3.5); look in the message's sub-nodes too, as before.
                        let mut data_block = None;
                        if let Some(attachment_sub_nodes) = attachment_sub_nodes {
                            let block = block_btree.find_entry(
                                file,
                                attachment_sub_nodes.search_key(),
                                &mut page_cache,
                            )?;
                            data_block = SubNodeTree::<Pst>::read(file, &block)?
                                .entries(file, &block_btree, &mut page_cache)?
                                .find(|entry| entry.node() == sub_node)
                                .map(|entry| entry.block());
                        }
                        let data_block = match data_block {
                            Some(block) => block,
                            None => message
                                .sub_nodes()
                                .get(&sub_node)
                                .ok_or(MessagingError::AttachmentSubNodeNotFound(sub_node))?
                                .block(),
                        };
                        let block = block_btree.find_entry(
                            file,
                            data_block.search_key(),
                            &mut page_cache,
                        )?;
                        let block = DataTree::read(file, encoding, &block)?;
                        let mut data = vec![];
                        let _ = block
                            .reader(
                                file,
                                encoding,
                                &block_btree,
                                &mut page_cache,
                                &mut Default::default(),
                            )?
                            .read_to_end(&mut data)?;
                        Some(AttachmentData::Binary(BinaryValue::new(data)))
                    }
                    _ => None,
                })
            })();
            let data = isolate_part(
                pst,
                ProblemKind::Attachment,
                attachment_node,
                "attachment data",
                data,
            )?
            .flatten();

            (properties, data)
        };

        let mut embedded_message = None;
        let data = match embedded {
            Some(node) => {
                let embedded = <<Pst as PstFile>::Message as MessageReadWrite<Pst>>::read_embedded(
                    store.clone(),
                    node,
                    prop_ids,
                    message.message_blocks(),
                );
                isolate_part(
                    pst,
                    ProblemKind::Attachment,
                    attachment_node,
                    "embedded message",
                    embedded,
                )?
                .map(|message| {
                    embedded_message = Some(message.clone());
                    AttachmentData::Message(message)
                })
            }
            None => data,
        };

        Ok(Self {
            message,
            properties,
            data,
            embedded: embedded_message,
        })
    }
}

pub struct UnicodeAttachment {
    inner: AttachmentInner<UnicodePstFile>,
}

impl UnicodeAttachment {
    pub fn read(
        message: Rc<UnicodeMessage>,
        sub_node: NodeId,
        prop_ids: Option<&[u16]>,
    ) -> io::Result<Rc<Self>> {
        <Self as AttachmentReadWrite<UnicodePstFile>>::read(message, sub_node, prop_ids)
    }
}

impl UnicodeAttachment {
    /// The embedded message of an `afEmbeddedMessage` attachment that was read, as a
    /// [`UnicodeMessage`]: its own recipients and attachments can be read from it.
    pub fn embedded_message(&self) -> Option<Rc<UnicodeMessage>> {
        self.inner.embedded.clone()
    }
}

impl Attachment for UnicodeAttachment {
    fn message(&self) -> Rc<dyn Message> {
        self.inner.message.clone()
    }

    fn properties(&self) -> &AttachmentProperties {
        &self.inner.properties
    }

    fn data(&self) -> Option<&AttachmentData> {
        self.inner.data.as_ref()
    }
}

impl AttachmentReadWrite<UnicodePstFile> for UnicodeAttachment {
    fn read(
        message: Rc<UnicodeMessage>,
        sub_node: NodeId,
        prop_ids: Option<&[u16]>,
    ) -> io::Result<Rc<Self>> {
        let inner = AttachmentInner::read(message, sub_node, prop_ids)?;
        Ok(Rc::new(Self { inner }))
    }
}

pub struct AnsiAttachment {
    inner: AttachmentInner<AnsiPstFile>,
}

impl AnsiAttachment {
    pub fn read(
        message: Rc<AnsiMessage>,
        sub_node: NodeId,
        prop_ids: Option<&[u16]>,
    ) -> io::Result<Rc<Self>> {
        <Self as AttachmentReadWrite<AnsiPstFile>>::read(message, sub_node, prop_ids)
    }
}

impl AnsiAttachment {
    /// The embedded message of an `afEmbeddedMessage` attachment that was read, as a
    /// [`AnsiMessage`]: its own recipients and attachments can be read from it.
    pub fn embedded_message(&self) -> Option<Rc<AnsiMessage>> {
        self.inner.embedded.clone()
    }
}

impl Attachment for AnsiAttachment {
    fn message(&self) -> Rc<dyn Message> {
        self.inner.message.clone()
    }

    fn properties(&self) -> &AttachmentProperties {
        &self.inner.properties
    }

    fn data(&self) -> Option<&AttachmentData> {
        self.inner.data.as_ref()
    }
}

impl AttachmentReadWrite<AnsiPstFile> for AnsiAttachment {
    fn read(
        message: Rc<AnsiMessage>,
        sub_node: NodeId,
        prop_ids: Option<&[u16]>,
    ) -> io::Result<Rc<Self>> {
        let inner = AttachmentInner::read(message, sub_node, prop_ids)?;
        Ok(Rc::new(Self { inner }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Validation,
        messaging::{
            folder::walk_folders,
            store::{Store, UnicodeStore},
        },
        ndb::{block_ref::BlockRef, byte_index::ByteIndex, page::BlockBTreeEntry},
    };
    use std::io::{Cursor, Read};

    fn dist_list() -> Vec<u8> {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/dist-list.pst.gz"
        );
        let mut data = Vec::new();
        flate2::read::GzDecoder::new(std::fs::read(path).unwrap().as_slice())
            .read_to_end(&mut data)
            .unwrap();
        data
    }

    fn open(data: &[u8], validation: Validation) -> Rc<UnicodeStore> {
        let pst = UnicodePstFile::read_from_with(Box::new(Cursor::new(data.to_vec())), validation);
        UnicodeStore::read(Rc::new(pst.unwrap())).unwrap()
    }

    /// The first message with an attachment, and the attachment's node ID.
    fn message_with_attachment(store: &Rc<UnicodeStore>) -> (Rc<UnicodeMessage>, NodeId) {
        for entry in walk_folders(store.as_ref()) {
            let Some(contents) = entry.folder.unwrap().contents_table().cloned() else {
                continue;
            };
            for row in contents.rows_matrix() {
                let node = NodeId::from(u32::from(row.id()));
                let entry_id = store.properties().make_entry_id(node).unwrap();
                let message = UnicodeMessage::read(store.clone(), &entry_id, None).unwrap();
                let attachment = message
                    .attachment_table()
                    .and_then(|table| table.rows_matrix().next().map(|row| u32::from(row.id())));
                if let Some(attachment) = attachment {
                    return (message, NodeId::from(attachment));
                }
            }
        }
        panic!("no attachment");
    }

    /// The first message with an embedded message, its node ID, and the attachment's node ID.
    fn message_with_embedded_message(
        store: &Rc<UnicodeStore>,
    ) -> (Rc<UnicodeMessage>, NodeId, NodeId) {
        for entry in walk_folders(store.as_ref()) {
            let Some(contents) = entry.folder.unwrap().contents_table().cloned() else {
                continue;
            };
            for row in contents.rows_matrix() {
                let node = NodeId::from(u32::from(row.id()));
                let entry_id = store.properties().make_entry_id(node).unwrap();
                let message = UnicodeMessage::read(store.clone(), &entry_id, None).unwrap();
                let Some(table) = message.attachment_table().cloned() else {
                    continue;
                };
                for row in table.rows_matrix() {
                    let attachment = NodeId::from(u32::from(row.id()));
                    let read = UnicodeAttachment::read(message.clone(), attachment, None).unwrap();
                    if read.embedded_message().is_some() {
                        return (message, node, attachment);
                    }
                }
            }
        }
        panic!("no embedded message");
    }

    #[test]
    fn test_message_embedded_in_itself() {
        let mut data = dist_list();
        let store = open(&data, Validation::Strict);
        let (message, node, attachment) = message_with_embedded_message(&store);
        let read = UnicodeAttachment::read(message.clone(), attachment, None).unwrap();
        let embedded = read
            .properties()
            .data_object(AttachmentMethod::EmbeddedMessage)
            .unwrap()
            .node();

        // The attachment's sub-node tree is one SLBLOCK (not encoded): its entry for the
        // embedded message gets the data and sub-node blocks of the message it is attached to.
        let parent = store.pst().read_node(node).unwrap();
        let sub_node = message
            .sub_nodes()
            .get(&attachment)
            .unwrap()
            .sub_node()
            .unwrap();
        let entry = store
            .block_btree()
            .find_entry(
                &mut Cursor::new(data.clone()),
                sub_node.search_key(),
                &mut Default::default(),
            )
            .unwrap();
        let offset = entry.block().index().index() as usize;
        let size = usize::from(entry.size());
        assert_eq!(data[offset..offset + 2], [0x02, 0x00]);
        let count = usize::from(u16::from_le_bytes([data[offset + 2], data[offset + 3]]));
        let at = (0..count)
            .map(|index| offset + 8 + 24 * index)
            .find(|at| data[*at..*at + 4] == u32::from(embedded).to_le_bytes())
            .unwrap();
        data[at + 8..at + 16].copy_from_slice(&parent.data().into_u64().to_le_bytes());
        let sub = parent.sub_node().map_or(0, BlockId::into_u64);
        data[at + 16..at + 24].copy_from_slice(&sub.to_le_bytes());
        let trailer = offset + (size + 16).div_ceil(64) * 64 - 16;
        let crc = crate::crc::compute_crc(0, &data[offset..offset + size]);
        data[trailer + 4..trailer + 8].copy_from_slice(&crc.to_le_bytes());

        let store = open(&data, Validation::Strict);
        let entry_id = store.properties().make_entry_id(node).unwrap();
        let message = UnicodeMessage::read(store.clone(), &entry_id, None).unwrap();
        let err = UnicodeAttachment::read(message, attachment, None)
            .err()
            .unwrap();
        assert!(
            err.to_string()
                .contains("blocks of a message it is embedded in"),
            "{err}"
        );

        let store = open(&data, Validation::Lenient);
        let entry_id = store.properties().make_entry_id(node).unwrap();
        let message = UnicodeMessage::read(store.clone(), &entry_id, None).unwrap();
        let read = UnicodeAttachment::read(message, attachment, None).unwrap();
        assert!(read.embedded_message().is_none());
        assert!(read.data().is_none());
        let problems = store.pst().problems();
        assert_eq!(problems.len(), 1);
        assert_eq!(problems[0].kind(), ProblemKind::Attachment);
        assert_eq!(problems[0].node(), Some(attachment));
        assert!(
            problems[0].detail().starts_with("embedded message: "),
            "{}",
            problems[0].detail()
        );
    }

    #[test]
    fn test_unknown_attach_method_leaves_the_attachment_without_data() {
        let mut data = dist_list();
        let store = open(&data, Validation::Strict);
        let (message, attachment) = message_with_attachment(&store);
        assert!(UnicodeAttachment::read(message.clone(), attachment, None).is_ok());

        // Set PidTagAttachMethod (0x3705, PtypInteger32, a value in the record) to 3, which is no
        // method, in the attachment's permute-encoded heap block, and fix its CRC.
        let block = message.sub_nodes().get(&attachment).unwrap().block();
        let pst = store.pst();
        let mut decoded = pst.read_block(block).unwrap();
        let entry = store
            .block_btree()
            .find_entry(
                &mut Cursor::new(data.clone()),
                block.search_key(),
                &mut Default::default(),
            )
            .unwrap();
        let offset = entry.block().index().index() as usize;
        let size = usize::from(entry.size());
        assert_eq!(decoded.len(), size);
        let at = decoded
            .windows(4)
            .position(|bytes| bytes == [0x05, 0x37, 0x03, 0x00])
            .unwrap();
        decoded[at + 4] = 3;
        crate::encode::permute::encode_block(&mut decoded);
        data[offset..offset + size].copy_from_slice(&decoded);
        let trailer = offset + (size + 16).div_ceil(64) * 64 - 16;
        let crc = crate::crc::compute_crc(0, &decoded);
        data[trailer + 4..trailer + 8].copy_from_slice(&crc.to_le_bytes());

        let store = open(&data, Validation::Strict);
        let (message, attachment) = message_with_attachment(&store);
        let err = UnicodeAttachment::read(message, attachment, None)
            .err()
            .unwrap();
        assert!(err.to_string().contains("PidTagAttachMethod"), "{err}");

        let store = open(&data, Validation::Lenient);
        let (message, attachment) = message_with_attachment(&store);
        let read = UnicodeAttachment::read(message, attachment, None).unwrap();
        assert!(read.data().is_none());
        assert_eq!(read.properties().attachment_method().unwrap(), 3);
        let problems = store.pst().problems();
        assert_eq!(problems.len(), 1);
        assert_eq!(problems[0].kind(), ProblemKind::Attachment);
        assert_eq!(problems[0].node(), Some(attachment));
    }

    fn properties(data: Option<PropertyValue>) -> AttachmentProperties {
        AttachmentProperties {
            properties: data.into_iter().map(|value| (0x3701, value)).collect(),
        }
    }

    #[test]
    fn test_by_value_data_errors_name_the_method() {
        let err = properties(None).data_binary().unwrap_err();
        assert!(matches!(
            err,
            MessagingError::AttachmentFileBinaryDataNotFound
        ));
        assert!(err.to_string().contains("afByValue"));

        let err = properties(Some(PropertyValue::Integer32(1)))
            .data_binary()
            .unwrap_err();
        assert!(matches!(
            err,
            MessagingError::InvalidAttachmentFileBinaryData(PropertyType::Integer32)
        ));
    }

    #[test]
    fn test_storage_data_errors_name_the_method() {
        let err = properties(None)
            .data_object(AttachmentMethod::Storage)
            .unwrap_err();
        assert!(matches!(
            err,
            MessagingError::AttachmentStorageObjectDataNotFound
        ));
        assert!(err.to_string().contains("afStorage"));

        let err = properties(Some(PropertyValue::Binary(BinaryValue::new(vec![1]))))
            .data_object(AttachmentMethod::Storage)
            .unwrap_err();
        assert!(matches!(
            err,
            MessagingError::InvalidStorageObjectData(PropertyType::Binary)
        ));
    }

    #[test]
    fn test_embedded_message_data_errors_name_the_method() {
        let err = properties(None)
            .data_object(AttachmentMethod::EmbeddedMessage)
            .unwrap_err();
        assert!(matches!(
            err,
            MessagingError::AttachmentMessageObjectDataNotFound
        ));
        assert!(err.to_string().contains("afEmbeddedMessage"));
    }
}
