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

//! ## [Folders](https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-pst/dee5b9d0-5513-4c5e-94aa-8bd28a9350b2)

use std::{
    cell::OnceCell,
    collections::{BTreeMap, BTreeSet},
    io,
    rc::Rc,
};

use super::{read_write::*, store::*, *};
use crate::{
    AnsiPstFile, PstFile, PstFileCaches, UnicodePstFile,
    ltp::{
        heap::HeapNode,
        prop_context::{BinaryValue, PropertyContext, PropertyValue},
        prop_type::PropertyType,
        read_write::*,
        table_context::TableContext,
    },
    ndb::{
        block_id::BlockId,
        header::Header,
        node_id::{NID_ROOT_FOLDER, NodeId, NodeIdType},
        page::{BTreePage, NodeBTreeEntry, RootBTree},
        read_write::*,
        root::Root,
    },
};

#[derive(Default, Debug)]
pub struct FolderProperties {
    node_id: NodeId,
    properties: BTreeMap<u16, PropertyValue>,
}

impl FolderProperties {
    pub fn get(&self, id: u16) -> Option<&PropertyValue> {
        self.properties.get(&id)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&u16, &PropertyValue)> {
        self.properties.iter()
    }

    pub fn node_id(&self) -> NodeId {
        self.node_id
    }

    pub fn display_name(&self) -> io::Result<String> {
        let display_name = self
            .properties
            .get(&0x3001)
            .ok_or(MessagingError::FolderDisplayNameNotFound)?;

        match display_name {
            PropertyValue::String8(value) => Ok(value.to_string()),
            PropertyValue::Unicode(value) => Ok(value.to_string()),
            invalid => {
                Err(MessagingError::InvalidFolderDisplayName(PropertyType::from(invalid)).into())
            }
        }
    }

    pub fn content_count(&self) -> io::Result<i32> {
        let content_count = self
            .properties
            .get(&0x3602)
            .ok_or(MessagingError::FolderContentCountNotFound)?;

        match content_count {
            PropertyValue::Integer32(value) => Ok(*value),
            invalid => {
                Err(MessagingError::InvalidFolderContentCount(PropertyType::from(invalid)).into())
            }
        }
    }

    pub fn unread_count(&self) -> io::Result<i32> {
        let unread_count = self
            .properties
            .get(&0x3603)
            .ok_or(MessagingError::FolderUnreadCountNotFound)?;

        match unread_count {
            PropertyValue::Integer32(value) => Ok(*value),
            invalid => {
                Err(MessagingError::InvalidFolderUnreadCount(PropertyType::from(invalid)).into())
            }
        }
    }

    pub fn has_sub_folders(&self) -> io::Result<bool> {
        let entry_id = self
            .properties
            .get(&0x360A)
            .ok_or(MessagingError::FolderHasSubfoldersNotFound)?;

        match entry_id {
            PropertyValue::Boolean(value) => Ok(*value),
            invalid => {
                Err(MessagingError::InvalidFolderHasSubfolders(PropertyType::from(invalid)).into())
            }
        }
    }
}

pub trait Folder {
    fn store(&self) -> Rc<dyn Store>;
    fn properties(&self) -> &FolderProperties;
    fn hierarchy_table(&self) -> Option<&Rc<dyn TableContext>>;
    fn contents_table(&self) -> Option<&Rc<dyn TableContext>>;
    fn associated_table(&self) -> Option<&Rc<dyn TableContext>>;
}

/// The most levels of sub-folders [`walk_folders`] goes down from the root folder.
pub const MAX_FOLDER_DEPTH: usize = 256;

/// A folder [`walk_folders`] reached.
pub struct FolderWalkEntry {
    /// The folder's node ID.
    pub node_id: NodeId,
    /// The folder whose hierarchy table lists it: `None` for the root folder.
    pub parent: Option<NodeId>,
    /// How many levels below the root folder it is.
    pub depth: usize,
    /// The folder, or why it could not be opened.
    pub folder: io::Result<Rc<dyn Folder>>,
}

/// Every folder reachable from the root folder ([`NID_ROOT_FOLDER`]) through the hierarchy
/// tables, depth first and in table order: see [`walk_folders`].
pub struct FolderWalk<'a> {
    store: &'a dyn Store,
    stack: Vec<(NodeId, Option<NodeId>, usize)>,
    visited: BTreeSet<u32>,
}

/// Walk every folder reachable from the root folder through the hierarchy tables, depth first
/// and in table order.
///
/// Each folder comes once, even when hierarchy tables list it more than once or a corrupt table
/// lists a folder above it (a loop). A folder that cannot be opened comes with its error, and its
/// sub-folders are not walked; neither are those of a folder [`MAX_FOLDER_DEPTH`] levels down.
pub fn walk_folders(store: &dyn Store) -> FolderWalk<'_> {
    FolderWalk {
        store,
        stack: vec![(NID_ROOT_FOLDER, None, 0)],
        visited: Default::default(),
    }
}

impl Iterator for FolderWalk<'_> {
    type Item = FolderWalkEntry;

    fn next(&mut self) -> Option<Self::Item> {
        while let Some((node_id, parent, depth)) = self.stack.pop() {
            if !self.visited.insert(u32::from(node_id)) {
                continue;
            }
            let folder = self
                .store
                .properties()
                .make_entry_id(node_id)
                .and_then(|entry_id| self.store.open_folder(&entry_id));
            if let Ok(folder) = &folder
                && depth < MAX_FOLDER_DEPTH
                && let Some(table) = folder.hierarchy_table()
            {
                let children: Vec<_> = table
                    .rows_matrix()
                    .map(|row| NodeId::from(u32::from(row.id())))
                    .filter(|child| !self.visited.contains(&u32::from(*child)))
                    .collect();
                let depth = depth.saturating_add(1);
                self.stack.extend(
                    children
                        .into_iter()
                        .rev()
                        .map(|child| (child, Some(node_id), depth)),
                );
            }
            return Some(FolderWalkEntry {
                node_id,
                parent,
                depth,
                folder,
            });
        }
        None
    }
}

struct FolderInner<Pst>
where
    Pst: PstFile,
{
    store: Rc<Pst::Store>,
    properties: FolderProperties,
    hierarchy_table: OnceCell<Option<Rc<dyn TableContext>>>,
    contents_table: OnceCell<Option<Rc<dyn TableContext>>>,
    associated_table: OnceCell<Option<Rc<dyn TableContext>>>,
}

impl<Pst> FolderInner<Pst>
where
    Pst: PstFile + PstFileCaches<Pst>,
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
    <Pst as PstFile>::TableContext: TableContextReadWrite<Pst>,
    <Pst as PstFile>::PropertyContext: PropertyContextReadWrite<Pst>,
    <Pst as PstFile>::Store: StoreReadWrite<Pst>,
{
    fn read(store: Rc<<Pst as PstFile>::Store>, entry_id: &EntryId) -> io::Result<Self> {
        let node_id = entry_id.node_id();
        let node_id_type = node_id.id_type()?;
        match node_id_type {
            NodeIdType::NormalFolder | NodeIdType::SearchFolder => {}
            _ => {
                return Err(MessagingError::InvalidFolderEntryIdType(node_id_type).into());
            }
        }
        if !store.properties().matches_record_key(entry_id)? {
            return Err(MessagingError::EntryIdWrongStore.into());
        }

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

            let mut node_page_cache = pst.node_cache()?;
            let node_key: <Pst as PstFile>::BTreeKey = u32::from(node_id).into();
            let node = node_btree.find_entry(file, node_key, &mut node_page_cache)?;
            let mut block_page_cache = pst.block_cache()?;
            let data = node.data();
            let heap = <<Pst as PstFile>::HeapNode as HeapNodeReadWrite<Pst>>::read(
                file,
                &block_btree,
                &mut block_page_cache,
                encoding,
                data.search_key(),
            )?;
            let header = heap.header()?;

            let tree = <Pst as PstFile>::PropertyTree::new(heap, header.user_root());
            let prop_context = <Pst as PstFile>::PropertyContext::new(node, tree);
            let folder_type = if entry_id.node_id() == NID_ROOT_FOLDER {
                0
            } else if node_id_type == NodeIdType::SearchFolder {
                2
            } else {
                1
            };
            let entry_id = entry_id.try_into()?;
            let properties = prop_context
                .properties()?
                .into_iter()
                .map(|(prop_id, record)| {
                    prop_context
                        .read_property(file, encoding, &block_btree, &mut block_page_cache, record)
                        .map(|value| (prop_id, value))
                })
                .chain([
                    Ok((0x0FFF, PropertyValue::Binary(BinaryValue::new(entry_id)))),
                    Ok((0x3601, PropertyValue::Integer32(folder_type))),
                ])
                .collect::<io::Result<BTreeMap<_, _>>>()?;

            FolderProperties {
                node_id,
                properties,
            }
        };

        Ok(Self {
            store,
            properties,
            hierarchy_table: Default::default(),
            contents_table: Default::default(),
            associated_table: Default::default(),
        })
    }

    fn read_table(&self, node_id_type: NodeIdType) -> io::Result<Option<Rc<dyn TableContext>>> {
        let pst = self.store.pst();
        let header = pst.header();
        let root = header.root();

        let node = {
            let mut file = pst
                .reader()
                .lock()
                .map_err(|_| MessagingError::FailedToLockFile)?;
            let file = &mut *file;

            let node_btree = <<Pst as PstFile>::NodeBTree as RootBTreeReadWrite>::read(
                file,
                *root.node_btree(),
            )?;

            let node_id = NodeId::new(node_id_type, self.properties.node_id.index())?;
            let node_key: <Pst as PstFile>::BTreeKey = u32::from(node_id).into();
            let mut node_page_cache = pst.node_cache()?;

            let Ok(node) = node_btree.find_entry(file, node_key, &mut node_page_cache) else {
                return Ok(None);
            };
            node
        };

        Ok(Some(
            <<Pst as PstFile>::TableContext as TableContextReadWrite<Pst>>::read(
                self.store.clone(),
                node,
            )?,
        ))
    }

    fn hierarchy_table(&self) -> Option<&Rc<dyn TableContext>> {
        self.hierarchy_table
            .get_or_init(|| self.read_table(NodeIdType::HierarchyTable).ok()?)
            .as_ref()
    }

    fn contents_table(&self) -> Option<&Rc<dyn TableContext>> {
        self.contents_table
            .get_or_init(|| self.read_table(NodeIdType::ContentsTable).ok()?)
            .as_ref()
    }

    fn associated_table(&self) -> Option<&Rc<dyn TableContext>> {
        self.associated_table
            .get_or_init(|| self.read_table(NodeIdType::AssociatedContentsTable).ok()?)
            .as_ref()
    }
}

pub struct UnicodeFolder {
    inner: FolderInner<UnicodePstFile>,
}

impl UnicodeFolder {
    pub fn read(store: Rc<UnicodeStore>, entry_id: &EntryId) -> io::Result<Rc<Self>> {
        <Self as FolderReadWrite<UnicodePstFile>>::read(store, entry_id)
    }
}

impl Folder for UnicodeFolder {
    fn store(&self) -> Rc<dyn Store> {
        self.inner.store.clone()
    }

    fn properties(&self) -> &FolderProperties {
        &self.inner.properties
    }

    fn hierarchy_table(&self) -> Option<&Rc<dyn TableContext>> {
        self.inner.hierarchy_table()
    }

    fn contents_table(&self) -> Option<&Rc<dyn TableContext>> {
        self.inner.contents_table()
    }

    fn associated_table(&self) -> Option<&Rc<dyn TableContext>> {
        self.inner.associated_table()
    }
}

impl FolderReadWrite<UnicodePstFile> for UnicodeFolder {
    fn read(store: Rc<UnicodeStore>, entry_id: &EntryId) -> io::Result<Rc<Self>> {
        let inner = FolderInner::read(store, entry_id)?;
        Ok(Rc::new(Self { inner }))
    }
}

pub struct AnsiFolder {
    inner: FolderInner<AnsiPstFile>,
}

impl AnsiFolder {
    pub fn read(store: Rc<AnsiStore>, entry_id: &EntryId) -> io::Result<Rc<Self>> {
        <Self as FolderReadWrite<AnsiPstFile>>::read(store, entry_id)
    }
}

impl Folder for AnsiFolder {
    fn store(&self) -> Rc<dyn Store> {
        self.inner.store.clone()
    }

    fn properties(&self) -> &FolderProperties {
        &self.inner.properties
    }

    fn hierarchy_table(&self) -> Option<&Rc<dyn TableContext>> {
        self.inner.hierarchy_table()
    }

    fn contents_table(&self) -> Option<&Rc<dyn TableContext>> {
        self.inner.contents_table()
    }

    fn associated_table(&self) -> Option<&Rc<dyn TableContext>> {
        self.inner.associated_table()
    }
}

impl FolderReadWrite<AnsiPstFile> for AnsiFolder {
    fn read(store: Rc<AnsiStore>, entry_id: &EntryId) -> io::Result<Rc<Self>> {
        let inner = FolderInner::read(store, entry_id)?;
        Ok(Rc::new(Self { inner }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ltp::{
        heap::HeapId,
        table_context::{TableContextInfo, TableRowColumnValue, TableRowData, TableRowId},
    };
    use crate::messaging::{
        message::Message, named_prop::NamedPropertyMap, search::SearchUpdateQueue,
    };

    /// A store whose folders are only node IDs and hierarchy tables.
    struct MockStore {
        properties: StoreProperties,
        children: BTreeMap<u32, Vec<u32>>,
    }

    struct MockFolder {
        properties: FolderProperties,
        hierarchy_table: Option<Rc<dyn TableContext>>,
    }

    struct MockTable {
        context: TableContextInfo,
        rows: Vec<TableRowData>,
    }

    impl TableContext for MockTable {
        fn context(&self) -> &TableContextInfo {
            &self.context
        }

        fn rows_matrix<'a>(&'a self) -> Box<dyn 'a + Iterator<Item = &'a TableRowData>> {
            Box::new(self.rows.iter())
        }

        fn find_row(&self, id: TableRowId) -> crate::ltp::LtpResult<&TableRowData> {
            Err(crate::ltp::LtpError::TableRowIdNotFound(u32::from(id)))
        }

        fn read_column(
            &self,
            _value: &TableRowColumnValue,
            _prop_type: PropertyType,
        ) -> io::Result<PropertyValue> {
            Err(io::ErrorKind::Unsupported.into())
        }
    }

    impl Folder for MockFolder {
        fn store(&self) -> Rc<dyn Store> {
            unimplemented!()
        }

        fn properties(&self) -> &FolderProperties {
            &self.properties
        }

        fn hierarchy_table(&self) -> Option<&Rc<dyn TableContext>> {
            self.hierarchy_table.as_ref()
        }

        fn contents_table(&self) -> Option<&Rc<dyn TableContext>> {
            None
        }

        fn associated_table(&self) -> Option<&Rc<dyn TableContext>> {
            None
        }
    }

    impl Store for MockStore {
        fn properties(&self) -> &StoreProperties {
            &self.properties
        }

        fn root_hierarchy_table(&self) -> io::Result<Rc<dyn TableContext>> {
            Err(io::ErrorKind::Unsupported.into())
        }

        fn unique_value(&self) -> u32 {
            0
        }

        fn open_folder(&self, entry_id: &EntryId) -> io::Result<Rc<dyn Folder>> {
            let node_id = u32::from(entry_id.node_id());
            let children = self
                .children
                .get(&node_id)
                .ok_or(io::Error::from(io::ErrorKind::NotFound))?;
            let rows = children
                .iter()
                .map(|child| {
                    TableRowData::new(TableRowId::new(*child), 0, vec![], vec![], vec![], vec![])
                })
                .collect();
            let context = TableContextInfo::new(8, 8, 8, 8, HeapId::from(0), None, vec![]).unwrap();
            Ok(Rc::new(MockFolder {
                properties: FolderProperties {
                    node_id: entry_id.node_id(),
                    properties: Default::default(),
                },
                hierarchy_table: Some(Rc::new(MockTable { context, rows })),
            }))
        }

        fn open_message(
            &self,
            _entry_id: &EntryId,
            _prop_ids: Option<&[u16]>,
        ) -> io::Result<Rc<dyn Message>> {
            Err(io::ErrorKind::Unsupported.into())
        }

        fn named_property_map(&self) -> io::Result<Rc<dyn NamedPropertyMap>> {
            Err(io::ErrorKind::Unsupported.into())
        }

        fn search_update_queue(&self) -> io::Result<Rc<dyn SearchUpdateQueue>> {
            Err(io::ErrorKind::Unsupported.into())
        }
    }

    fn mock_store(children: &[(u32, &[u32])]) -> MockStore {
        MockStore {
            properties: StoreProperties::for_test([7; 16]),
            children: children
                .iter()
                .map(|(folder, children)| (*folder, children.to_vec()))
                .collect(),
        }
    }

    #[test]
    fn test_walk_folders_with_a_loop() {
        // The root lists 0x8022 twice; 0x8022 lists 0x8042, itself and the root; 0x8042 lists
        // 0x8022 again and a folder that cannot be opened.
        let store = mock_store(&[
            (0x122, &[0x8022, 0x8022]),
            (0x8022, &[0x8042, 0x8022, 0x122]),
            (0x8042, &[0x8022, 0x8062]),
        ]);
        let folders: Vec<_> = walk_folders(&store)
            .map(|entry| {
                (
                    u32::from(entry.node_id),
                    entry.parent.map(u32::from),
                    entry.depth,
                    entry.folder.is_ok(),
                )
            })
            .collect();
        assert_eq!(
            folders,
            [
                (0x122, None, 0, true),
                (0x8022, Some(0x122), 1, true),
                (0x8042, Some(0x8022), 2, true),
                (0x8062, Some(0x8042), 3, false),
            ]
        );
    }

    #[test]
    fn test_walk_folders_depth_limit() {
        // A chain of folders deeper than MAX_FOLDER_DEPTH.
        let chain: Vec<(u32, Vec<u32>)> = (0..MAX_FOLDER_DEPTH as u32 + 10)
            .map(|i| {
                let folder = if i == 0 { 0x122 } else { 0x8002 + 0x20 * i };
                (folder, vec![0x8002 + 0x20 * (i + 1)])
            })
            .collect();
        let children: Vec<(u32, &[u32])> = chain
            .iter()
            .map(|(folder, children)| (*folder, children.as_slice()))
            .collect();
        let store = mock_store(&children);
        let depths: Vec<_> = walk_folders(&store).map(|entry| entry.depth).collect();
        assert_eq!(depths.len(), MAX_FOLDER_DEPTH + 1);
        assert_eq!(depths.last(), Some(&MAX_FOLDER_DEPTH));
    }

    #[test]
    fn test_walk_folders() {
        let store = crate::open_store(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/Empty.pst"
        ))
        .unwrap();
        let folders: Vec<_> = walk_folders(store.as_ref()).collect();
        assert_eq!(folders.len(), 6);
        assert_eq!(folders[0].node_id, NID_ROOT_FOLDER);
        assert_eq!((folders[0].parent, folders[0].depth), (None, 0));
        for entry in &folders[1..] {
            assert!(entry.folder.is_ok());
            assert!(entry.parent.is_some() && entry.depth > 0);
        }
        let mut ids: Vec<_> = folders
            .iter()
            .map(|entry| u32::from(entry.node_id))
            .collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), 6);
    }
}
