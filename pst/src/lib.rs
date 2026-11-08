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

#![doc = include_str!("../README.md")]
// No input may panic or abort this crate: outside tests, no unchecked indexing, slicing or
// arithmetic, and no unwrap, expect or panic.
#![cfg_attr(
    not(test),
    deny(
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects,
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::unreachable,
        clippy::todo,
        clippy::unimplemented
    )
)]

use std::{
    cell::RefMut,
    fmt::Debug,
    fs::File,
    io::{self, Read, Seek},
    ops::{Deref, DerefMut},
    path::Path,
    rc::Rc,
    sync::{Mutex, MutexGuard, TryLockError},
};
use thiserror::Error;

pub mod ltp;
pub mod messaging;
pub mod ndb;
pub mod problems;

pub use problems::{Problem, ProblemKind, Validation};

mod block_sig;
mod crc;
mod encode;

use ltp::{heap::*, prop_context::*, table_context::*, tree::*};
use messaging::{folder::*, message::*, named_prop::*, search::*, store::*};
use ndb::{
    block::*, block_id::*, block_ref::*, byte_index::*, header::*, node_id::*, page::*,
    read_write::*, root::*, *,
};

#[derive(Error, Debug)]
pub enum PstError {
    #[error("I/O error: {0:?}")]
    Io(#[from] io::Error),
    #[error("I/O error: {0}")]
    BorrowedIo(String),
    #[error("Failed to lock file")]
    LockError,
    #[error("Integer conversion failed")]
    IntegerConversion,
    #[error("Node Database error: {0}")]
    NodeDatabaseError(#[from] NdbError),
    #[error("Invalid BTree page: offset: 0x{0:X}")]
    InvalidBTreePage(u64),
}

impl From<&PstError> for io::Error {
    fn from(err: &PstError) -> Self {
        Self::other(format!("{err:?}"))
    }
}

impl From<PstError> for io::Error {
    fn from(err: PstError) -> Self {
        match err {
            PstError::Io(err) => err,
            err => Self::other(err),
        }
    }
}

impl From<&io::Error> for PstError {
    fn from(err: &io::Error) -> Self {
        Self::BorrowedIo(format!("{err:?}"))
    }
}

/// Crate-internal access to a file: its reader and B-tree page caches, each used by one reader at
/// a time (a second use is an error, not a panic or a deadlock), and its problem log.
trait PstFileInternal<Pst>
where
    Pst: PstFile,
{
    /// Lock the file's reader, with the file's [`Validation`] in force while it is locked.
    fn lock_reader(&self) -> io::Result<ReaderGuard<'_>>;
    fn problem_log(&self) -> &problems::ProblemLog;

    fn block_cache(
        &self,
    ) -> io::Result<RefMut<'_, RootBTreePageCache<<Pst as PstFile>::BlockBTree>>>;
    fn node_cache(&self)
    -> io::Result<RefMut<'_, RootBTreePageCache<<Pst as PstFile>::NodeBTree>>>;
}

/// A file's locked reader: see [`PstFileInternal::lock_reader`].
struct ReaderGuard<'a> {
    reader: MutexGuard<'a, Box<dyn PstReader>>,
    _scope: problems::ScopeGuard,
}

impl Deref for ReaderGuard<'_> {
    type Target = Box<dyn PstReader>;

    fn deref(&self) -> &Self::Target {
        &self.reader
    }
}

impl DerefMut for ReaderGuard<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.reader
    }
}

/// Borrow a page cache, or fail with [`PstError::LockError`] if it is already borrowed.
fn borrow_cache<T>(cache: &std::cell::RefCell<T>) -> io::Result<RefMut<'_, T>> {
    cache
        .try_borrow_mut()
        .map_err(|_| PstError::LockError.into())
}

pub trait PstReader: Read + Seek {}

impl<T> PstReader for T where T: Read + Seek {}

/// [PST File](https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-pst/6b57253b-0853-47bb-99bb-d4b8f78105f0)
pub trait PstFile: Sized {
    type BlockId: BlockId<Index = Self::BTreeKey> + BlockIdReadWrite;
    type PageId: BlockId<Index = Self::BTreeKey> + BlockIdReadWrite;
    type ByteIndex: ByteIndex + ByteIndexReadWrite;
    type BlockRef: BlockRef<Block = Self::BlockId, Index = Self::ByteIndex> + BlockRefReadWrite;
    type PageRef: BlockRef<Block = Self::PageId, Index = Self::ByteIndex> + BlockRefReadWrite;
    type Root: Root<Self>;
    type Header: Header<Self>;
    type PageTrailer: PageTrailer<BlockId = Self::PageId> + PageTrailerReadWrite;
    type BTreeKey: BTreeEntryKey;
    type NodeBTreeEntry: NodeBTreeEntry<Block = Self::BlockId> + BTreeEntry<Key = Self::BTreeKey>;
    type NodeBTree: NodeBTree<Self, Self::NodeBTreeEntry>;
    type BlockBTreeEntry: BlockBTreeEntry<Block = Self::BlockRef> + BTreeEntry<Key = Self::BTreeKey>;
    type BlockBTree: BlockBTree<Self, Self::BlockBTreeEntry>;
    type BlockTrailer: BlockTrailer<BlockId = Self::BlockId>;
    type AllocationMapPage: AllocationMapPage<Self>;
    type AllocationPageMapPage: AllocationPageMapPage<Self>;
    type FreeMapPage: FreeMapPage<Self>;
    type FreePageMapPage: FreePageMapPage<Self>;
    type DensityListPage: DensityListPage<Self>;
    type DataTreeEntry: IntermediateTreeEntry + IntermediateDataTreeEntry<Self>;
    type DataTreeBlock: IntermediateTreeBlock<
            Header = DataTreeBlockHeader,
            Entry = Self::DataTreeEntry,
            Trailer = Self::BlockTrailer,
        >;
    type DataBlock: Block<Trailer = Self::BlockTrailer>;
    type SubNodeTreeBlockHeader: IntermediateTreeHeader;
    type SubNodeTreeBlock: IntermediateTreeBlock<
            Header = Self::SubNodeTreeBlockHeader,
            Entry = IntermediateSubNodeTreeEntry<Self::BlockId>,
            Trailer = Self::BlockTrailer,
        >;
    type SubNodeBlock: IntermediateTreeBlock<
            Header = Self::SubNodeTreeBlockHeader,
            Entry = LeafSubNodeTreeEntry<Self::BlockId>,
            Trailer = Self::BlockTrailer,
        >;
    type TableContext: TableContext;
    type PropertyContext: PropertyContext;
    type HeapNode: HeapNode;
    type PropertyTree: HeapTree<Key = PropertyTreeRecordKey, Value = PropertyTreeRecordValue>;
    type Store: Store;
    type Folder: Folder;
    type Message: Message;
    type NamedPropertyMap: NamedPropertyMap;
    type SearchUpdateQueue: SearchUpdateQueue;

    fn header(&self) -> &Self::Header;
    fn density_list(&self) -> Result<&dyn DensityListPage<Self>, &io::Error>;
    /// The file's reader. Structures read through it directly are read strictly, whatever the
    /// file's [`Validation`], and their problems are not recorded.
    fn reader(&self) -> &Mutex<Box<dyn PstReader>>;
    /// How strictly the file is checked: see [`problems`].
    fn validation(&self) -> Validation;
    /// The problems found in the file so far, each once, in the order found: see [`problems`].
    fn problems(&self) -> Vec<Problem>;

    fn read_node(&self, node: NodeId) -> io::Result<Self::NodeBTreeEntry>;
    fn read_block(&self, block: Self::BlockId) -> io::Result<Vec<u8>>;
}

struct PstFileInner<Pst>
where
    Pst: PstFile,
{
    reader: Mutex<Box<dyn PstReader>>,
    validation: Validation,
    problems: Rc<problems::ProblemLog>,
    /// Whether the file has the 4 KiB pages of Outlook 2013 and later OSTs.
    large_pages: bool,
    header: Pst::Header,
    density_list: io::Result<Pst::DensityListPage>,
    node_cache: NodeBTreePageCache<Pst>,
    block_cache: BlockBTreePageCache<Pst>,
}

pub struct UnicodePstFile {
    inner: PstFileInner<Self>,
}

impl UnicodePstFile {
    /// Read a file from `reader`, leniently ([`Validation::Lenient`]).
    pub fn read_from(reader: Box<dyn PstReader>) -> io::Result<Self> {
        Self::read_from_with(reader, Validation::default())
    }

    /// Read a file from `reader` with the given [`Validation`].
    pub fn read_from_with(reader: Box<dyn PstReader>, validation: Validation) -> io::Result<Self> {
        let inner = PstFileInner::read_from(reader, validation)?;
        Ok(Self { inner })
    }

    /// Open the file at `path` read-only, leniently ([`Validation::Lenient`]).
    pub fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        Self::open_with(path, Validation::default())
    }

    /// Open the file at `path` read-only with the given [`Validation`].
    pub fn open_with(path: impl AsRef<Path>, validation: Validation) -> io::Result<Self> {
        let inner = PstFileInner::open(path, validation)?;
        Ok(Self { inner })
    }
}

impl PstFileInternal<UnicodePstFile> for UnicodePstFile {
    fn lock_reader(&self) -> io::Result<ReaderGuard<'_>> {
        self.inner.lock_reader()
    }

    fn problem_log(&self) -> &problems::ProblemLog {
        &self.inner.problems
    }

    fn block_cache(
        &self,
    ) -> io::Result<RefMut<'_, RootBTreePageCache<<Self as PstFile>::BlockBTree>>> {
        borrow_cache(&self.inner.block_cache)
    }

    fn node_cache(
        &self,
    ) -> io::Result<RefMut<'_, RootBTreePageCache<<Self as PstFile>::NodeBTree>>> {
        borrow_cache(&self.inner.node_cache)
    }
}

impl PstFile for UnicodePstFile {
    type BlockId = UnicodeBlockId;
    type PageId = UnicodePageId;
    type ByteIndex = UnicodeByteIndex;
    type BlockRef = UnicodeBlockRef;
    type PageRef = UnicodePageRef;
    type Root = UnicodeRoot;
    type Header = UnicodeHeader;
    type PageTrailer = UnicodePageTrailer;
    type BTreeKey = u64;
    type NodeBTreeEntry = UnicodeNodeBTreeEntry;
    type NodeBTree = UnicodeNodeBTree;
    type BlockBTreeEntry = UnicodeBlockBTreeEntry;
    type BlockBTree = UnicodeBlockBTree;
    type BlockTrailer = UnicodeBlockTrailer;
    type AllocationMapPage = UnicodeMapPage<{ PageType::AllocationMap as u8 }>;
    type AllocationPageMapPage = UnicodeMapPage<{ PageType::AllocationPageMap as u8 }>;
    type FreeMapPage = UnicodeMapPage<{ PageType::FreeMap as u8 }>;
    type FreePageMapPage = UnicodeMapPage<{ PageType::FreePageMap as u8 }>;
    type DensityListPage = UnicodeDensityListPage;
    type DataTreeEntry = UnicodeDataTreeEntry;
    type DataTreeBlock = UnicodeDataTreeBlock;
    type DataBlock = UnicodeDataBlock;
    type SubNodeTreeBlockHeader = UnicodeSubNodeTreeBlockHeader;
    type SubNodeTreeBlock = UnicodeIntermediateSubNodeTreeBlock;
    type SubNodeBlock = UnicodeLeafSubNodeTreeBlock;
    type HeapNode = UnicodeHeapNode;
    type PropertyTree = UnicodeHeapTree<PropertyTreeRecordKey, PropertyTreeRecordValue>;
    type TableContext = UnicodeTableContext;
    type PropertyContext = UnicodePropertyContext;
    type Store = UnicodeStore;
    type Folder = UnicodeFolder;
    type Message = UnicodeMessage;
    type NamedPropertyMap = UnicodeNamedPropertyMap;
    type SearchUpdateQueue = UnicodeSearchUpdateQueue;

    fn header(&self) -> &Self::Header {
        &self.inner.header
    }

    fn density_list(&self) -> Result<&dyn DensityListPage<Self>, &io::Error> {
        self.inner.density_list.as_ref().map(|dl| dl as _)
    }

    fn reader(&self) -> &Mutex<Box<dyn PstReader>> {
        &self.inner.reader
    }

    fn validation(&self) -> Validation {
        self.inner.validation
    }

    fn problems(&self) -> Vec<Problem> {
        self.inner.problems.problems()
    }

    fn read_node(&self, node: NodeId) -> io::Result<UnicodeNodeBTreeEntry> {
        self.inner.read_node(node)
    }

    fn read_block(&self, block: UnicodeBlockId) -> io::Result<Vec<u8>> {
        self.inner.read_block(block)
    }
}

pub struct AnsiPstFile {
    inner: PstFileInner<Self>,
}

impl AnsiPstFile {
    /// Read a file from `reader`, leniently ([`Validation::Lenient`]).
    pub fn read_from(reader: Box<dyn PstReader>) -> io::Result<Self> {
        Self::read_from_with(reader, Validation::default())
    }

    /// Read a file from `reader` with the given [`Validation`].
    pub fn read_from_with(reader: Box<dyn PstReader>, validation: Validation) -> io::Result<Self> {
        let inner = PstFileInner::read_from(reader, validation)?;
        Ok(Self { inner })
    }

    /// Open the file at `path` read-only, leniently ([`Validation::Lenient`]).
    pub fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        Self::open_with(path, Validation::default())
    }

    /// Open the file at `path` read-only with the given [`Validation`].
    pub fn open_with(path: impl AsRef<Path>, validation: Validation) -> io::Result<Self> {
        let inner = PstFileInner::open(path, validation)?;
        Ok(Self { inner })
    }
}

impl PstFileInternal<AnsiPstFile> for AnsiPstFile {
    fn lock_reader(&self) -> io::Result<ReaderGuard<'_>> {
        self.inner.lock_reader()
    }

    fn problem_log(&self) -> &problems::ProblemLog {
        &self.inner.problems
    }

    fn block_cache(
        &self,
    ) -> io::Result<RefMut<'_, RootBTreePageCache<<Self as PstFile>::BlockBTree>>> {
        borrow_cache(&self.inner.block_cache)
    }

    fn node_cache(
        &self,
    ) -> io::Result<RefMut<'_, RootBTreePageCache<<Self as PstFile>::NodeBTree>>> {
        borrow_cache(&self.inner.node_cache)
    }
}

impl PstFile for AnsiPstFile {
    type BlockId = AnsiBlockId;
    type PageId = AnsiPageId;
    type ByteIndex = AnsiByteIndex;
    type BlockRef = AnsiBlockRef;
    type PageRef = AnsiPageRef;
    type Root = AnsiRoot;
    type Header = AnsiHeader;
    type PageTrailer = AnsiPageTrailer;
    type BTreeKey = u32;
    type NodeBTreeEntry = AnsiNodeBTreeEntry;
    type NodeBTree = AnsiNodeBTree;
    type BlockBTreeEntry = AnsiBlockBTreeEntry;
    type BlockBTree = AnsiBlockBTree;
    type BlockTrailer = AnsiBlockTrailer;
    type AllocationMapPage = AnsiMapPage<{ PageType::AllocationMap as u8 }>;
    type AllocationPageMapPage = AnsiMapPage<{ PageType::AllocationPageMap as u8 }>;
    type FreeMapPage = AnsiMapPage<{ PageType::FreeMap as u8 }>;
    type FreePageMapPage = AnsiMapPage<{ PageType::FreePageMap as u8 }>;
    type DensityListPage = AnsiDensityListPage;
    type DataTreeEntry = AnsiDataTreeEntry;
    type DataTreeBlock = AnsiDataTreeBlock;
    type DataBlock = AnsiDataBlock;
    type SubNodeTreeBlockHeader = AnsiSubNodeTreeBlockHeader;
    type SubNodeTreeBlock = AnsiIntermediateSubNodeTreeBlock;
    type SubNodeBlock = AnsiLeafSubNodeTreeBlock;
    type HeapNode = AnsiHeapNode;
    type PropertyTree = AnsiHeapTree<PropertyTreeRecordKey, PropertyTreeRecordValue>;
    type TableContext = AnsiTableContext;
    type PropertyContext = AnsiPropertyContext;
    type Store = AnsiStore;
    type Folder = AnsiFolder;
    type Message = AnsiMessage;
    type NamedPropertyMap = AnsiNamedPropertyMap;
    type SearchUpdateQueue = AnsiSearchUpdateQueue;

    fn header(&self) -> &Self::Header {
        &self.inner.header
    }

    fn density_list(&self) -> Result<&dyn DensityListPage<Self>, &io::Error> {
        self.inner.density_list.as_ref().map(|dl| dl as _)
    }

    fn reader(&self) -> &Mutex<Box<dyn PstReader>> {
        &self.inner.reader
    }

    fn validation(&self) -> Validation {
        self.inner.validation
    }

    fn problems(&self) -> Vec<Problem> {
        self.inner.problems.problems()
    }

    fn read_node(&self, node: NodeId) -> io::Result<AnsiNodeBTreeEntry> {
        self.inner.read_node(node)
    }

    fn read_block(&self, block: AnsiBlockId) -> io::Result<Vec<u8>> {
        self.inner.read_block(block)
    }
}

type PstFileReadWriteBTree<Pst, BTree> = RootBTreePage<
    Pst,
    <BTree as RootBTree>::Entry,
    <BTree as RootBTree>::IntermediatePage,
    <BTree as RootBTree>::LeafPage,
>;

type PstFileReadWriteNodeBTree<Pst> = PstFileReadWriteBTree<Pst, <Pst as PstFile>::NodeBTree>;

type PstFileReadWriteBlockBTree<Pst> = PstFileReadWriteBTree<Pst, <Pst as PstFile>::BlockBTree>;

impl<Pst> PstFileInner<Pst>
where
    Pst: PstFile + PstFileInternal<Pst>,
    <Pst as PstFile>::BlockId: BlockId<Index = <Pst as PstFile>::BTreeKey>
        + From<<<Pst as PstFile>::ByteIndex as ByteIndex>::Index>
        + Debug,
    <Pst as PstFile>::PageId: From<<<Pst as PstFile>::ByteIndex as ByteIndex>::Index> + Debug,
    <Pst as PstFile>::ByteIndex: ByteIndex<Index: TryFrom<u64>> + Debug,
    <Pst as PstFile>::BlockRef: Debug,
    <Pst as PstFile>::PageRef: Debug,
    <Pst as PstFile>::Root: RootReadWrite<Pst>,
    <Pst as PstFile>::Header: HeaderReadWrite<Pst>,
    <Pst as PstFile>::DensityListPage: DensityListPageReadWrite<Pst>,
    <Pst as PstFile>::PageTrailer: PageTrailerReadWrite,
    <Pst as PstFile>::BTreeKey: BTreePageKeyReadWrite,
    <Pst as PstFile>::NodeBTreeEntry: NodeBTreeEntryReadWrite,
    <Pst as PstFile>::NodeBTree: NodeBTreeReadWrite<Pst, <Pst as PstFile>::NodeBTreeEntry>,
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
    <Pst as PstFile>::BlockBTree: BlockBTreeReadWrite<Pst, <Pst as PstFile>::BlockBTreeEntry>,
    <<Pst as PstFile>::BlockBTree as RootBTree>::IntermediatePage:
        RootBTreeIntermediatePageReadWrite<
                Pst,
                <Pst as PstFile>::BlockBTreeEntry,
                <<Pst as PstFile>::BlockBTree as RootBTree>::LeafPage,
            >,
    <<<Pst as PstFile>::BlockBTree as RootBTree>::IntermediatePage as BTreePage>::Entry:
        BTreePageEntryReadWrite,
    <<Pst as PstFile>::BlockBTree as RootBTree>::LeafPage: RootBTreeLeafPageReadWrite<Pst>,
    <Pst as PstFile>::BlockTrailer: BlockTrailerReadWrite,
    <Pst as PstFile>::AllocationMapPage: AllocationMapPageReadWrite<Pst>,
    <Pst as PstFile>::AllocationPageMapPage: AllocationPageMapPageReadWrite<Pst>,
    <Pst as PstFile>::FreeMapPage: FreeMapPageReadWrite<Pst>,
    <Pst as PstFile>::FreePageMapPage: FreePageMapPageReadWrite<Pst>,
    <Pst as PstFile>::DensityListPage: DensityListPageReadWrite<Pst>,
    <Pst as PstFile>::DataTreeBlock: IntermediateTreeBlockReadWrite,
    <Pst as PstFile>::DataTreeEntry:
        IntermediateTreeEntryReadWrite + From<<Pst as PstFile>::BlockId>,
    <Pst as PstFile>::DataBlock: BlockReadWrite + Clone,
    <Pst as PstFile>::SubNodeTreeBlockHeader: SubNodeTreeBlockHeaderReadWrite,
    <Pst as PstFile>::SubNodeTreeBlock: IntermediateTreeBlockReadWrite,
    <<Pst as PstFile>::SubNodeTreeBlock as IntermediateTreeBlock>::Entry:
        IntermediateTreeEntryReadWrite,
    <Pst as PstFile>::SubNodeBlock: IntermediateTreeBlockReadWrite,
    <<Pst as PstFile>::SubNodeBlock as IntermediateTreeBlock>::Entry:
        IntermediateTreeEntryReadWrite,
{
    fn read_from(mut reader: Box<dyn PstReader>, validation: Validation) -> io::Result<Self> {
        let problems = Rc::new(problems::ProblemLog::default());
        let header = {
            let _scope = problems::ScopeGuard::new(validation, problems.clone(), None);
            <<Pst as PstFile>::Header as HeaderReadWrite<Pst>>::read(&mut reader)?
        };
        let large_pages = header.version() == NdbVersion::Unicode4k;
        // The density list of the 512-byte layout; the 4 KiB layout keeps another structure there.
        // Nothing is read through it, so it is read strictly and is not a problem: a density list
        // that does not read is an error from density_list(), as it always was.
        let density_list = if large_pages {
            Err(io::ErrorKind::Unsupported.into())
        } else {
            <<Pst as PstFile>::DensityListPage as DensityListPageReadWrite<Pst>>::read(&mut reader)
        };
        Ok(Self {
            reader: Mutex::new(Box::new(reader)),
            validation,
            problems,
            large_pages,
            header,
            density_list,
            node_cache: Default::default(),
            block_cache: Default::default(),
        })
    }

    /// Open the file at `path` read-only: this crate never writes to the file it reads.
    fn open(path: impl AsRef<Path>, validation: Validation) -> io::Result<Self> {
        Self::read_from(Box::new(File::open(path)?), validation)
    }

    fn lock_reader(&self) -> io::Result<ReaderGuard<'_>> {
        // A file is used by one thread, so a lock that is held is held by this thread: waiting
        // for it would never end.
        let reader = self.reader.try_lock().map_err(|err| match err {
            TryLockError::WouldBlock | TryLockError::Poisoned(_) => PstError::LockError,
        })?;
        Ok(ReaderGuard {
            reader,
            _scope: problems::ScopeGuard::new(
                self.validation,
                self.problems.clone(),
                Some(self.large_pages),
            ),
        })
    }

    fn read_node(&self, node: NodeId) -> io::Result<<Pst as PstFile>::NodeBTreeEntry> {
        let node_btree = *self.header.root().node_btree();
        let mut reader = self.lock_reader()?;
        let reader = &mut *reader;
        let node_btree =
            <<Pst as PstFile>::NodeBTree as RootBTreeReadWrite>::read(reader, node_btree)?;
        let mut page_cache = borrow_cache(&self.node_cache)?;
        let node_id: <Pst as PstFile>::BTreeKey = u32::from(node).into();
        let node = node_btree.find_entry(reader, node_id, &mut page_cache)?;
        Ok(node)
    }

    fn read_block(&self, block: <Pst as PstFile>::BlockId) -> io::Result<Vec<u8>> {
        let encoding = self.header.crypt_method();
        let block_btree = *self.header.root().block_btree();
        let mut reader = self.lock_reader()?;
        let reader = &mut *reader;
        let block_btree =
            <<Pst as PstFile>::BlockBTree as RootBTreeReadWrite>::read(reader, block_btree)?;
        let mut page_cache = borrow_cache(&self.block_cache)?;
        let block = block_btree.find_entry(reader, block.search_key(), &mut page_cache)?;
        let block = DataTree::<Pst>::read(reader, encoding, &block)?;
        let mut block_cache = Default::default();
        let mut data = vec![];
        let _ = block
            .reader(
                reader,
                encoding,
                &block_btree,
                &mut page_cache,
                &mut block_cache,
            )?
            .read_to_end(&mut data)?;
        Ok(data)
    }
}

/// Open the store of the Unicode or ANSI PST or OST at `path`, read-only and leniently
/// ([`Validation::Lenient`]).
pub fn open_store(path: impl AsRef<Path>) -> io::Result<Rc<dyn Store>> {
    open_store_with(path, Validation::default())
}

/// Open the store of the Unicode or ANSI PST or OST at `path`, read-only, with the given
/// [`Validation`].
pub fn open_store_with(
    path: impl AsRef<Path>,
    validation: Validation,
) -> io::Result<Rc<dyn Store>> {
    Ok(match UnicodePstFile::open_with(path.as_ref(), validation) {
        Ok(pst_file) => UnicodeStore::read(Rc::new(pst_file))?,
        _ => {
            let pst_file = AnsiPstFile::open_with(path.as_ref(), validation)?;
            AnsiStore::read(Rc::new(pst_file))?
        }
    })
}
