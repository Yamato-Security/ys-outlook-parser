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

//! ## [Message Objects](https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-pst/1042af37-aaa4-4edc-bffd-90a1ede24188)

use std::{collections::BTreeMap, io, rc::Rc};

use super::{read_write::*, store::*, *};
use crate::{
    AnsiPstFile, PstFile, PstFileInternal, UnicodePstFile,
    ltp::{
        heap::HeapNode,
        prop_context::{PropertyContext, PropertyValue},
        prop_type::PropertyType,
        read_write::*,
        table_context::TableContext,
    },
    ndb::{
        block::{IntermediateTreeBlock, LeafSubNodeTreeEntry, SubNodeTree},
        block_id::BlockId,
        header::Header,
        node_id::{NodeId, NodeIdType},
        page::{AnsiNodeBTreeEntry, BTreePage, NodeBTreeEntry, RootBTree, UnicodeNodeBTreeEntry},
        read_write::*,
        root::Root,
    },
    problems::{Problem, ProblemKind},
};

#[derive(Default, Debug)]
pub struct MessageProperties {
    properties: BTreeMap<u16, PropertyValue>,
}

impl MessageProperties {
    pub fn get(&self, id: u16) -> Option<&PropertyValue> {
        self.properties.get(&id)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&u16, &PropertyValue)> {
        self.properties.iter()
    }

    pub fn message_class(&self) -> io::Result<String> {
        let message_class = self
            .properties
            .get(&0x001A)
            .ok_or(MessagingError::MessageClassNotFound)?;

        match message_class {
            PropertyValue::String8(value) => Ok(value.to_string()),
            PropertyValue::Unicode(value) => Ok(value.to_string()),
            invalid => Err(MessagingError::InvalidMessageClass(PropertyType::from(invalid)).into()),
        }
    }

    pub fn message_flags(&self) -> io::Result<i32> {
        let message_flags = self
            .properties
            .get(&0x0E07)
            .ok_or(MessagingError::MessageFlagsNotFound)?;

        match message_flags {
            PropertyValue::Integer32(value) => Ok(*value),
            invalid => Err(MessagingError::InvalidMessageFlags(PropertyType::from(invalid)).into()),
        }
    }

    pub fn message_size(&self) -> io::Result<i32> {
        let message_size = self
            .properties
            .get(&0x0E08)
            .ok_or(MessagingError::MessageSizeNotFound)?;

        match message_size {
            PropertyValue::Integer32(value) => Ok(*value),
            invalid => Err(MessagingError::InvalidMessageSize(PropertyType::from(invalid)).into()),
        }
    }

    pub fn message_status(&self) -> io::Result<i32> {
        let message_status = self
            .properties
            .get(&0x0E17)
            .ok_or(MessagingError::MessageStatusNotFound)?;

        match message_status {
            PropertyValue::Integer32(value) => Ok(*value),
            invalid => {
                Err(MessagingError::InvalidMessageStatus(PropertyType::from(invalid)).into())
            }
        }
    }

    pub fn creation_time(&self) -> io::Result<i64> {
        let creation_time = self
            .properties
            .get(&0x3007)
            .ok_or(MessagingError::MessageCreationTimeNotFound)?;

        match creation_time {
            PropertyValue::Time(value) => Ok(*value),
            invalid => {
                Err(MessagingError::InvalidMessageCreationTime(PropertyType::from(invalid)).into())
            }
        }
    }

    pub fn last_modification_time(&self) -> io::Result<i64> {
        let last_modification_time = self
            .properties
            .get(&0x3008)
            .ok_or(MessagingError::MessageLastModificationTimeNotFound)?;

        match last_modification_time {
            PropertyValue::Time(value) => Ok(*value),
            invalid => Err(
                MessagingError::InvalidMessageLastModificationTime(PropertyType::from(invalid))
                    .into(),
            ),
        }
    }

    pub fn search_key(&self) -> io::Result<&[u8]> {
        let search_key = self
            .properties
            .get(&0x300B)
            .ok_or(MessagingError::MessageSearchKeyNotFound)?;

        match search_key {
            PropertyValue::Binary(value) => Ok(value.buffer()),
            invalid => {
                Err(MessagingError::InvalidMessageSearchKey(PropertyType::from(invalid)).into())
            }
        }
    }
}

/// The most levels of messages embedded in messages that are read: a message attached to a
/// message in a folder is 1 level down. A chain of embedded messages in a corrupt file ends here,
/// and a loop of them sooner, at a message with the blocks of one it is embedded in.
pub const MAX_EMBEDDED_MESSAGE_DEPTH: usize = 64;

/// The data and sub-node blocks of a message's node. A message embedded in a message it holds,
/// in a corrupt file, has the blocks of a message it is embedded in.
pub(crate) type MessageBlocks = (u64, Option<u64>);

pub trait Message {
    fn store(&self) -> Rc<dyn Store>;
    fn properties(&self) -> &MessageProperties;
    fn recipient_table(&self) -> Option<&Rc<dyn TableContext>>;
    fn attachment_table(&self) -> Option<&Rc<dyn TableContext>>;
}

struct MessageInner<Pst>
where
    Pst: PstFile,
{
    store: Rc<Pst::Store>,
    properties: MessageProperties,
    sub_nodes: MessageSubNodes<Pst>,
    recipient_table: Option<Rc<dyn TableContext>>,
    attachment_table: Option<Rc<dyn TableContext>>,
    /// The blocks of the messages the message is embedded in, outermost first, then its own.
    blocks: Vec<MessageBlocks>,
}

impl<Pst> MessageInner<Pst>
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
    <Pst as PstFile>::HeapNode: HeapNodeReadWrite<Pst>,
    <Pst as PstFile>::PropertyTree: HeapTreeReadWrite<Pst>,
    <Pst as PstFile>::TableContext: TableContextReadWrite<Pst>,
    <Pst as PstFile>::PropertyContext: PropertyContextReadWrite<Pst>,
    <Pst as PstFile>::Store: StoreReadWrite<Pst>,
{
    fn read(
        store: Rc<<Pst as PstFile>::Store>,
        entry_id: &EntryId,
        prop_ids: Option<&[u16]>,
    ) -> io::Result<Self> {
        let node_id = entry_id.node_id();
        let node_id_type = node_id.id_type()?;
        match node_id_type {
            NodeIdType::NormalMessage | NodeIdType::AssociatedMessage | NodeIdType::Attachment => {}
            _ => {
                return Err(MessagingError::InvalidMessageEntryIdType(node_id_type).into());
            }
        }
        if !store.properties().matches_record_key(entry_id)? {
            return Err(MessagingError::EntryIdWrongStore.into());
        }

        let pst = store.pst();
        let header = pst.header();
        let root = header.root();

        let node = {
            let mut file = pst.lock_reader()?;
            let file = &mut *file;

            let node_btree = <<Pst as PstFile>::NodeBTree as RootBTreeReadWrite>::read(
                file,
                *root.node_btree(),
            )?;

            let mut page_cache = pst.node_cache()?;
            let node_key: <Pst as PstFile>::BTreeKey = u32::from(node_id).into();
            node_btree.find_entry(file, node_key, &mut page_cache)?
        };

        Self::read_embedded(store, node, prop_ids, &[])
    }

    fn read_embedded(
        store: Rc<<Pst as PstFile>::Store>,
        node: <Pst as PstFile>::NodeBTreeEntry,
        prop_ids: Option<&[u16]>,
        parents: &[MessageBlocks],
    ) -> io::Result<Self> {
        let depth = parents.len();
        if depth > MAX_EMBEDDED_MESSAGE_DEPTH {
            return Err(MessagingError::EmbeddedMessageTooDeep(depth).into());
        }
        let own = (
            node.data().into_u64(),
            node.sub_node().map(BlockId::into_u64),
        );
        if parents.contains(&own) {
            return Err(MessagingError::EmbeddedMessageCycle(own.0, own.1).into());
        }
        let mut blocks = Vec::with_capacity(depth.saturating_add(1));
        blocks.extend_from_slice(parents);
        blocks.push(own);
        let node_id = node.node();

        let pst = store.pst();
        let header = pst.header();
        let root = header.root();

        let (properties, sub_nodes) = {
            let mut file = pst.lock_reader()?;
            let file = &mut *file;

            let encoding = header.crypt_method();
            let block_btree = <<Pst as PstFile>::BlockBTree as RootBTreeReadWrite>::read(
                file,
                *root.block_btree(),
            )?;

            // markdown-extract: a message with no recipients or attachments
            // (a distribution list, say) may have no sub-node tree at all.
            let sub_node = node.sub_node();

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
            let prop_context = <Pst as PstFile>::PropertyContext::new(node, tree);
            let properties = read_properties(
                pst,
                node.node(),
                prop_context
                    .properties()?
                    .into_iter()
                    .filter(|(prop_id, _)| prop_ids.is_none_or(|ids| ids.contains(prop_id))),
                |record| {
                    prop_context.read_property(
                        file,
                        encoding,
                        &block_btree,
                        &mut page_cache,
                        record,
                    )
                },
            )?;
            let properties = MessageProperties { properties };

            let sub_nodes: BTreeMap<_, _> = match sub_node {
                Some(sub_node) => {
                    let sub_nodes = (|| {
                        let block =
                            block_btree.find_entry(file, sub_node.search_key(), &mut page_cache)?;
                        let sub_nodes = SubNodeTree::<Pst>::read(file, &block)?;
                        Ok(sub_nodes
                            .entries(file, &block_btree, &mut page_cache)?
                            .map(|entry| (entry.node(), entry))
                            .collect())
                    })();
                    isolate_part(
                        pst,
                        ProblemKind::SubNodeTree,
                        node_id,
                        "sub-node tree",
                        sub_nodes,
                    )?
                    .unwrap_or_default()
                }
                None => BTreeMap::new(),
            };

            (properties, sub_nodes)
        };

        let recipient_table = read_sub_node_table::<Pst>(
            &store,
            &sub_nodes,
            node_id,
            NodeIdType::RecipientTable,
            || MessagingError::MultipleMessageRecipientTables,
        )?;
        let attachment_table = read_sub_node_table::<Pst>(
            &store,
            &sub_nodes,
            node_id,
            NodeIdType::AttachmentTable,
            || MessagingError::MultipleMessageAttachmentTables,
        )?;

        Ok(Self {
            store,
            properties,
            sub_nodes,
            recipient_table,
            attachment_table,
            blocks,
        })
    }
}

/// Read the message's table of `id_type` (its recipient or attachment table) from its sub-nodes.
/// When it cannot be read, or there are more than one, it is a problem when reading leniently (and
/// the message has no such table, or the first), else an error.
fn read_sub_node_table<Pst>(
    store: &Rc<<Pst as PstFile>::Store>,
    sub_nodes: &MessageSubNodes<Pst>,
    node_id: NodeId,
    id_type: NodeIdType,
    multiple: impl FnOnce() -> MessagingError,
) -> io::Result<Option<Rc<dyn TableContext>>>
where
    Pst: PstFile + PstFileInternal<Pst>,
    <Pst as PstFile>::NodeBTreeEntry: NodeBTreeEntryReadWrite,
    <Pst as PstFile>::TableContext: TableContextReadWrite<Pst>,
    <Pst as PstFile>::Store: StoreReadWrite<Pst>,
{
    let pst = store.pst();
    let what = match id_type {
        NodeIdType::RecipientTable => "recipient table",
        _ => "attachment table",
    };
    let mut nodes = sub_nodes
        .iter()
        .filter(|(node_id, _)| node_id.id_type().ok() == Some(id_type))
        .map(|(_, entry)| {
            <<Pst as PstFile>::NodeBTreeEntry as NodeBTreeEntryReadWrite>::new(
                entry.node(),
                entry.block(),
                entry.sub_node(),
                None,
            )
        });
    let Some(node) = nodes.next() else {
        return Ok(None);
    };
    let count = nodes.count().saturating_add(1);
    if count > 1 {
        crate::problems::isolate(
            pst.validation(),
            pst.problem_log(),
            |_| {
                Problem::new(
                    ProblemKind::Table,
                    None,
                    Some(node_id),
                    format!("{count} {what}s; the first is read"),
                )
            },
            Err::<(), _>(io::Error::from(multiple())),
        )?;
    }
    let table =
        <<Pst as PstFile>::TableContext as TableContextReadWrite<Pst>>::read(store.clone(), node);
    isolate_part(pst, ProblemKind::Table, node_id, what, table)
}

pub type MessageSubNodes<Pst> = BTreeMap<NodeId, LeafSubNodeTreeEntry<<Pst as PstFile>::BlockId>>;
pub type UnicodeMessageSubNodes = MessageSubNodes<UnicodePstFile>;
pub type AnsiMessageSubNodes = MessageSubNodes<AnsiPstFile>;

pub struct UnicodeMessage {
    inner: MessageInner<UnicodePstFile>,
}

impl UnicodeMessage {
    pub fn read(
        store: Rc<UnicodeStore>,
        entry_id: &EntryId,
        prop_ids: Option<&[u16]>,
    ) -> io::Result<Rc<Self>> {
        <Self as MessageReadWrite<UnicodePstFile>>::read(store, entry_id, prop_ids)
    }
}

impl Message for UnicodeMessage {
    fn store(&self) -> Rc<dyn Store> {
        self.inner.store.clone()
    }

    fn properties(&self) -> &MessageProperties {
        &self.inner.properties
    }

    fn recipient_table(&self) -> Option<&Rc<dyn TableContext>> {
        self.inner.recipient_table.as_ref()
    }

    fn attachment_table(&self) -> Option<&Rc<dyn TableContext>> {
        self.inner.attachment_table.as_ref()
    }
}

impl MessageReadWrite<UnicodePstFile> for UnicodeMessage {
    fn read(
        store: Rc<UnicodeStore>,
        entry_id: &EntryId,
        prop_ids: Option<&[u16]>,
    ) -> io::Result<Rc<Self>> {
        let inner = MessageInner::read(store, entry_id, prop_ids)?;
        Ok(Rc::new(Self { inner }))
    }

    fn read_embedded(
        store: Rc<UnicodeStore>,
        node: UnicodeNodeBTreeEntry,
        prop_ids: Option<&[u16]>,
        parents: &[MessageBlocks],
    ) -> io::Result<Rc<Self>> {
        let inner = MessageInner::read_embedded(store, node, prop_ids, parents)?;
        Ok(Rc::new(Self { inner }))
    }

    fn message_blocks(&self) -> &[MessageBlocks] {
        &self.inner.blocks
    }

    fn pst_store(&self) -> &Rc<UnicodeStore> {
        &self.inner.store
    }

    fn sub_nodes(&self) -> &UnicodeMessageSubNodes {
        &self.inner.sub_nodes
    }
}

pub struct AnsiMessage {
    inner: MessageInner<AnsiPstFile>,
}

impl AnsiMessage {
    pub fn read(
        store: Rc<AnsiStore>,
        entry_id: &EntryId,
        prop_ids: Option<&[u16]>,
    ) -> io::Result<Rc<Self>> {
        <Self as MessageReadWrite<AnsiPstFile>>::read(store, entry_id, prop_ids)
    }
}

impl Message for AnsiMessage {
    fn store(&self) -> Rc<dyn Store> {
        self.inner.store.clone()
    }

    fn properties(&self) -> &MessageProperties {
        &self.inner.properties
    }

    fn recipient_table(&self) -> Option<&Rc<dyn TableContext>> {
        self.inner.recipient_table.as_ref()
    }

    fn attachment_table(&self) -> Option<&Rc<dyn TableContext>> {
        self.inner.attachment_table.as_ref()
    }
}

impl MessageReadWrite<AnsiPstFile> for AnsiMessage {
    fn read(
        store: Rc<AnsiStore>,
        entry_id: &EntryId,
        prop_ids: Option<&[u16]>,
    ) -> io::Result<Rc<Self>> {
        let inner = MessageInner::read(store, entry_id, prop_ids)?;
        Ok(Rc::new(Self { inner }))
    }

    fn read_embedded(
        store: Rc<AnsiStore>,
        node: AnsiNodeBTreeEntry,
        prop_ids: Option<&[u16]>,
        parents: &[MessageBlocks],
    ) -> io::Result<Rc<Self>> {
        let inner = MessageInner::read_embedded(store, node, prop_ids, parents)?;
        Ok(Rc::new(Self { inner }))
    }

    fn message_blocks(&self) -> &[MessageBlocks] {
        &self.inner.blocks
    }

    fn pst_store(&self) -> &Rc<AnsiStore> {
        &self.inner.store
    }

    fn sub_nodes(&self) -> &AnsiMessageSubNodes {
        &self.inner.sub_nodes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ndb::node_id::NID_ROOT_FOLDER;

    #[test]
    fn test_embedded_message_depth_limit() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/Empty.pst");
        let store =
            UnicodeStore::read(Rc::new(crate::UnicodePstFile::open(path).unwrap())).unwrap();
        let node = store.pst().read_node(NID_ROOT_FOLDER).unwrap();
        let parents: Vec<_> = (1..=MAX_EMBEDDED_MESSAGE_DEPTH as u64 + 1)
            .map(|block| (u64::MAX - block, None))
            .collect();
        let read = |parents: &[MessageBlocks]| {
            <UnicodeMessage as MessageReadWrite<UnicodePstFile>>::read_embedded(
                store.clone(),
                node,
                None,
                parents,
            )
        };
        let err = read(&parents).err().unwrap();
        assert!(err.to_string().contains("levels down"), "{err}");
        let message = read(&parents[1..]).unwrap();
        assert_eq!(
            message.message_blocks().len(),
            MAX_EMBEDDED_MESSAGE_DEPTH + 1
        );
        assert_eq!(message.message_blocks()[..64], parents[1..]);
    }

    #[test]
    fn test_message_embedded_in_itself() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/Empty.pst");
        let store =
            UnicodeStore::read(Rc::new(crate::UnicodePstFile::open(path).unwrap())).unwrap();
        let node = store.pst().read_node(NID_ROOT_FOLDER).unwrap();
        let blocks = (
            node.data().into_u64(),
            node.sub_node().map(BlockId::into_u64),
        );
        let read = |parents: &[MessageBlocks]| {
            <UnicodeMessage as MessageReadWrite<UnicodePstFile>>::read_embedded(
                store.clone(),
                node,
                None,
                parents,
            )
        };
        let message = read(&[]).unwrap();
        assert_eq!(message.message_blocks(), [blocks]);
        // The same data block with another sub-node tree is another message.
        assert!(read(&[(blocks.0, Some(4))]).is_ok());
        let err = read(&[(4, None), blocks, (8, None)]).err().unwrap();
        assert!(
            err.to_string()
                .contains("blocks of a message it is embedded in"),
            "{err}"
        );
    }
}
