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
    PstFile, UnicodePstFile, Validation,
    messaging::{folder::walk_folders, store::UnicodeStore},
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

/// Every way of reading a file, to be sure it does not panic: open it strictly and leniently,
/// and walk what opens.
fn read_everything(data: &[u8]) {
    for validation in [Validation::Strict, Validation::Lenient] {
        let Ok(file) =
            UnicodePstFile::read_from_with(Box::new(Cursor::new(data.to_vec())), validation)
        else {
            continue;
        };
        let file = Rc::new(file);
        let _ = file.read_node(NID_ROOT_FOLDER);
        if let Ok(store) = UnicodeStore::read(file.clone()) {
            walk(&store);
            let _ = walk_folders(store.as_ref()).count();
        }
        let _ = file.problems();
    }
}

#[test]
fn truncated_files() {
    for name in [
        "Empty.pst",
        "dist-list.pst.gz",
        "outlook.pst.gz",
        "example-2013.ost.gz",
    ] {
        let data = fixture(name);
        // In the header, just after it, and through the B-trees and blocks.
        let mut lengths = vec![0, 1, 4, 100, 470, 511, 512, 600, 0x4400];
        lengths.extend((1..32).map(|i| data.len() * i / 32));
        lengths.push(data.len() - 1);
        for len in lengths {
            read_everything(&data[..len.min(data.len())]);
        }
        // A file cut inside its header does not open, strictly or leniently.
        for len in [0, 100, 511] {
            assert!(
                UnicodePstFile::read_from(Box::new(Cursor::new(data[..len].to_vec()))).is_err(),
                "{name} cut at {len}"
            );
        }
    }
}

/// Empty.pst with the BBT entry of the message store's data block rewritten by `edit`.
fn store_block_entry(edit: impl FnOnce(&mut UnicodePst, usize)) -> UnicodePst {
    let mut pst = empty_pst();
    let (nbt_entry, _) = pst.nbt_entry(u32::from(NID_MESSAGE_STORE));
    let bid = pst.u64_at(nbt_entry + 8);
    let (entry, page) = pst.bbt_entry(bid);
    edit(&mut pst, entry);
    pst.fix_page_crc(page);
    pst
}

#[test]
fn block_sizes_from_the_b_tree() {
    // cb past the largest block, cb 0, and cb that differs from the block's trailer.
    for size in [0xFFFF_u16, 8177, 0, 1] {
        let pst = store_block_entry(|pst, entry| {
            pst.0[entry + 16..entry + 18].copy_from_slice(&size.to_le_bytes());
        });
        for validation in [Validation::Strict, Validation::Lenient] {
            let file =
                UnicodePstFile::read_from_with(Box::new(Cursor::new(pst.0.clone())), validation)
                    .unwrap();
            assert!(UnicodeStore::read(Rc::new(file)).is_err(), "cb {size}");
        }
        read_everything(&pst.0);
    }
}

#[test]
fn block_offsets_from_the_b_tree() {
    // A block past the end of the file, at the very end, and over the header.
    for offset in [u64::MAX - 8, 0x7FFF_FFFF_FFFF, 271_360 - 8, 0] {
        let pst = store_block_entry(|pst, entry| pst.set_u64(entry + 8, offset));
        let file = UnicodePstFile::read_from(Box::new(Cursor::new(pst.0.clone()))).unwrap();
        assert!(
            UnicodeStore::read(Rc::new(file)).is_err(),
            "ib 0x{offset:X}"
        );
        read_everything(&pst.0);
    }
}

#[test]
fn b_tree_page_counts() {
    // cEnt past cEntMax, cbEnt 0 and 255, cLevel 200, on the NBT root.
    for (at, value) in [(488, 25_u8), (490, 0), (490, 255), (491, 200)] {
        let mut pst = empty_pst();
        let root = pst.nbt_root();
        pst.0[root + at] = value;
        pst.fix_page_crc(root);
        let file = UnicodePstFile::read_from(Box::new(Cursor::new(pst.0.clone()))).unwrap();
        assert!(file.read_node(NID_MESSAGE_STORE).is_err(), "{at} {value}");
        read_everything(&pst.0);
    }
}

#[test]
fn root_pages_outside_the_file() {
    // ROOT.BREFNBT.ib past the end of the file, with the header CRCs made to match.
    for offset in [u64::MAX, 271_360, 271_360 - 100] {
        let mut pst = empty_pst();
        pst.set_u64(224, offset);
        pst.fix_header_crcs();
        let file = UnicodePstFile::read_from(Box::new(Cursor::new(pst.0.clone()))).unwrap();
        assert!(file.read_node(NID_ROOT_FOLDER).is_err());
        read_everything(&pst.0);
    }
}
