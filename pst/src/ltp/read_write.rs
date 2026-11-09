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

use std::io::{self, Read, Write};

use super::{prop_type::*, table_context::*, *};
use crate::*;

pub trait HeapIdReadWrite: Copy + Sized {
    fn new(index: u16, block_index: u16) -> LtpResult<Self>;
    fn read(f: &mut dyn Read) -> io::Result<Self>;
    fn write(&self, f: &mut dyn Write) -> io::Result<()>;
}

pub trait HeapNodePageReadWrite: Sized {
    fn read(f: &mut dyn Read) -> io::Result<Self>;
    fn write(&self, f: &mut dyn Write) -> io::Result<()>;
}

pub trait HeapNodeReadWrite<Pst>: HeapNode + Sized
where
    Pst: PstFile,
{
    fn read<R: PstReader>(
        f: &mut R,
        block_btree: &PstFileReadWriteBlockBTree<Pst>,
        page_cache: &mut RootBTreePageCache<<Pst as PstFile>::BlockBTree>,
        encoding: NdbCryptMethod,
        key: <Pst as PstFile>::BTreeKey,
    ) -> io::Result<Self>;
}

pub trait HeapTreeReadWrite<Pst>: HeapTree + Sized
where
    Pst: PstFile,
    <Self as HeapTree>::Key: HeapNodePageReadWrite,
    <Self as HeapTree>::Value: HeapNodePageReadWrite,
{
    fn new(heap: <Pst as PstFile>::HeapNode, user_root: HeapId) -> Self;
}

pub trait PropertyTreeRecordReadWrite: Sized {
    fn read(f: &mut dyn Read) -> io::Result<Self>;
    fn write(&self, f: &mut dyn Write) -> io::Result<()>;
}

pub trait PropertyValueReadWrite: Sized {
    fn read(f: &mut dyn Read, prop_type: PropertyType) -> io::Result<Self>;
    fn write(&self, f: &mut dyn Write) -> io::Result<()>;
}

pub trait PropertyContextReadWrite<Pst>: PropertyContext + Sized
where
    Pst: PstFile,
{
    fn new(node: <Pst as PstFile>::NodeBTreeEntry, tree: <Pst as PstFile>::PropertyTree) -> Self;
    fn read_property<R: PstReader>(
        &self,
        f: &mut R,
        encoding: NdbCryptMethod,
        block_btree: &PstFileReadWriteBlockBTree<Pst>,
        page_cache: &mut RootBTreePageCache<<Pst as PstFile>::BlockBTree>,
        value: PropertyTreeRecordValue,
    ) -> io::Result<PropertyValue>;
}

pub trait TableContextInfoReadWrite: Sized {
    fn read(f: &mut dyn Read) -> io::Result<Self>;
    fn write(&self, f: &mut dyn Write) -> io::Result<()>;
}

pub trait TableColumnDescriptorReadWrite: Sized {
    fn read(f: &mut dyn Read) -> io::Result<Self>;
    fn write(&self, f: &mut dyn Write) -> io::Result<()>;
}

pub trait TableRowReadWrite: Sized {
    fn read(f: &mut dyn Read, context: &TableContextInfo) -> io::Result<Self>;
    fn write(&self, f: &mut dyn Write) -> io::Result<()>;
}

pub trait TableContextReadWrite<Pst>: TableContext + Sized
where
    Pst: PstFile,
{
    fn read(
        store: Rc<Pst::Store>,
        node: <Pst as PstFile>::NodeBTreeEntry,
    ) -> io::Result<Rc<dyn TableContext>>;
}
