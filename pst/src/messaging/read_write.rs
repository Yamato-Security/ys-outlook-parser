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

#![allow(dead_code)]

use crate::*;
use std::io::{self, Read, Write};

pub trait StoreKeyReadWrite: Sized {
    fn read(f: &mut dyn Read) -> io::Result<Self>;
    fn write(&self, f: &mut dyn Write) -> io::Result<()>;
}

pub trait StoreReadWrite<Pst>: Store + Sized
where
    Pst: PstFile,
{
    fn pst(&self) -> &Pst;
    fn node_btree(&self) -> &PstFileReadWriteNodeBTree<Pst>;
    fn block_btree(&self) -> &PstFileReadWriteBlockBTree<Pst>;
}

pub trait FolderReadWrite<Pst>: Folder + Sized
where
    Pst: PstFile,
{
    fn read(store: Rc<Pst::Store>, entry_id: &EntryId) -> io::Result<Rc<Self>>;
}

pub trait MessageReadWrite<Pst>: Message + Sized
where
    Pst: PstFile,
{
    fn read(
        store: Rc<Pst::Store>,
        entry_id: &EntryId,
        prop_ids: Option<&[u16]>,
    ) -> io::Result<Rc<Self>>;
    /// Read the message embedded `depth` levels down: 1 for a message attached to a message in a
    /// folder. Deeper than [`MAX_EMBEDDED_MESSAGE_DEPTH`] is an error.
    fn read_embedded(
        store: Rc<Pst::Store>,
        node: Pst::NodeBTreeEntry,
        prop_ids: Option<&[u16]>,
        depth: usize,
    ) -> io::Result<Rc<Self>>;
    /// How many levels down the message is embedded: 0 for a message in a folder.
    fn embedded_depth(&self) -> usize;
    fn pst_store(&self) -> &Rc<Pst::Store>;
    fn sub_nodes(&self) -> &MessageSubNodes<Pst>;
}

pub trait AttachmentReadWrite<Pst>: Sized
where
    Pst: PstFile,
{
    fn read(
        message: Rc<Pst::Message>,
        sub_node: NodeId,
        prop_ids: Option<&[u16]>,
    ) -> io::Result<Rc<Self>>;
}

pub trait NamedPropReadWrite: Sized {
    fn read(f: &mut dyn Read) -> io::Result<Self>;
    fn write(&self, f: &mut dyn Write) -> io::Result<()>;
}

pub trait NamedPropertyMapReadWrite<Pst>: NamedPropertyMap + Sized
where
    Pst: PstFile,
{
    fn read(store: Rc<Pst::Store>) -> io::Result<Rc<Self>>;
}

pub trait SearchReadWrite: Sized {
    fn read(f: &mut dyn Read) -> io::Result<Self>;
    fn write(&self, f: &mut dyn Write) -> io::Result<()>;
}

pub trait SearchUpdateQueueReadWrite<Pst>: SearchUpdateQueue + Sized
where
    Pst: PstFile,
{
    fn read(store: Rc<Pst::Store>) -> io::Result<Rc<Self>>;
}
