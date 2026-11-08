// Copyright (C) 2026 Shirofune Security Co., Ltd.
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

//! Crafted corruption: each test damages a fixture in a way a careless reader would loop on,
//! overflow its stack on, or read without end, and checks that reading it is an error and
//! nothing panics or aborts.

mod common;

use common::{craft::*, *};
use outlook_pst::{
    PstFile, UnicodePstFile,
    messaging::store::UnicodeStore,
    ndb::node_id::{NID_MESSAGE_STORE, NID_ROOT_FOLDER},
};
use std::{io::Cursor, rc::Rc};

fn empty_pst() -> UnicodePst {
    UnicodePst(fixture("Empty.pst"))
}

fn open(pst: &UnicodePst) -> std::io::Result<UnicodePstFile> {
    UnicodePstFile::read_from(Box::new(Cursor::new(pst.0.clone())))
}

#[test]
fn nbt_page_that_points_at_itself() {
    // The first entry of the root NBT page leads back to the root page: the lookup of the
    // message store recursed until the stack overflowed.
    let mut pst = empty_pst();
    let root = pst.nbt_root();
    assert_eq!(pst.page_level(root), 1);
    pst.set_child(root, 0, pst.nbt_root_id(), root);

    let file = open(&pst).unwrap();
    let err = file.read_node(NID_MESSAGE_STORE).unwrap_err();
    assert!(err.to_string().contains("lookup path"), "{err}");
    assert!(UnicodeStore::read(Rc::new(file)).is_err());
}

#[test]
fn nbt_pages_that_point_at_each_other() {
    // The root's first child becomes an intermediate page that leads back to the root.
    let mut pst = empty_pst();
    let root = pst.nbt_root();
    let (_, child) = pst.child(root, 0);
    pst.make_intermediate(child, 1, pst.nbt_root_id(), root);

    let file = open(&pst).unwrap();
    let err = file.read_node(NID_MESSAGE_STORE).unwrap_err();
    assert!(err.to_string().contains("lookup path"), "{err}");
    assert!(UnicodeStore::read(Rc::new(file)).is_err());
}

#[test]
fn bbt_page_that_points_at_itself() {
    let mut pst = empty_pst();
    let root = pst.bbt_root();
    assert_eq!(pst.page_level(root), 1);
    for index in 0..pst.page_entry_count(root) {
        pst.set_child(root, index, pst.bbt_root_id(), root);
    }

    let file = open(&pst).unwrap();
    let node = file.read_node(NID_MESSAGE_STORE).unwrap();
    use outlook_pst::ndb::page::NodeBTreeEntry;
    let err = file.read_block(node.data()).unwrap_err();
    assert!(err.to_string().contains("lookup path"), "{err}");
    assert!(UnicodeStore::read(Rc::new(file)).is_err());
}

#[test]
fn nbt_page_that_points_at_the_bbt_root() {
    // A page of the other tree: its leaves are not node BTree pages.
    let mut pst = empty_pst();
    let root = pst.nbt_root();
    let (bbt_id, bbt) = (pst.bbt_root_id(), pst.bbt_root());
    for index in 0..pst.page_entry_count(root) {
        pst.set_child(root, index, bbt_id, bbt);
    }
    let file = open(&pst).unwrap();
    assert!(file.read_node(NID_ROOT_FOLDER).is_err());
    assert!(UnicodeStore::read(Rc::new(file)).is_err());
}

#[test]
fn walk_of_an_intact_fixture() {
    // The edits above are all that breaks the files.
    let pst = empty_pst();
    let store = UnicodeStore::read(Rc::new(open(&pst).unwrap())).unwrap();
    assert_eq!(walk(&store).folders, 6);
}
