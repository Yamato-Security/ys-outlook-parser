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

//! Lenient reading: CRC mismatches, header fields MS-PST does not allow and a store without a
//! record key do not stop a file from being read leniently, and are listed by problems(); read
//! strictly, they are errors.

mod common;

use common::{craft::*, *};
use outlook_pst::{
    ProblemKind, PstFile, UnicodePstFile, Validation,
    messaging::{folder::walk_folders, store::UnicodeStore},
    ndb::{
        block_id::BlockId, block_ref::BlockRef, byte_index::ByteIndex, header::Header,
        node_id::NID_MESSAGE_STORE, page::*, root::Root,
    },
};
use std::{io::Cursor, rc::Rc};

fn read(pst: &UnicodePst, validation: Validation) -> std::io::Result<UnicodePstFile> {
    UnicodePstFile::read_from_with(Box::new(Cursor::new(pst.0.clone())), validation)
}

fn kinds(file: &UnicodePstFile) -> Vec<ProblemKind> {
    file.problems()
        .iter()
        .map(|problem| problem.kind())
        .collect()
}

/// The file offset and size of the data block of the message store's node.
fn store_block(pst: &UnicodePst) -> (usize, usize) {
    let file = read(pst, Validation::Strict).unwrap();
    let node = file.read_node(NID_MESSAGE_STORE).unwrap();
    let mut f = Cursor::new(pst.0.clone());
    let bbt = UnicodeBlockBTree::read(&mut f, *file.header().root().block_btree()).unwrap();
    let entry = bbt
        .find_entry(&mut f, node.data().search_key(), &mut Default::default())
        .unwrap();
    let offset = entry.block().index().index() as usize;
    (offset, usize::from(entry.size()))
}

#[test]
fn intact_file_has_no_problems() {
    let pst = UnicodePst(fixture("Empty.pst"));
    let file = read(&pst, Validation::Strict).unwrap();
    assert_eq!(file.validation(), Validation::Strict);
    let store = UnicodeStore::read(Rc::new(file)).unwrap();
    assert_eq!(walk(&store).folders, 6);
    let file = read(&pst, Validation::default()).unwrap();
    assert_eq!(file.validation(), Validation::Lenient);
    let file = Rc::new(file);
    let store = UnicodeStore::read(file.clone()).unwrap();
    walk(&store);
    assert!(file.problems().is_empty(), "{:?}", file.problems());
}

#[test]
fn header_crc_mismatch() {
    let mut pst = UnicodePst(fixture("Empty.pst"));
    pst.0[4] ^= 0xFF;
    pst.0[524] ^= 0xFF;
    assert!(read(&pst, Validation::Strict).is_err());

    let file = Rc::new(read(&pst, Validation::Lenient).unwrap());
    assert_eq!(
        kinds(&file),
        [ProblemKind::HeaderCrc, ProblemKind::HeaderCrc]
    );
    assert_eq!(file.problems()[0].offset(), Some(0));
    let store = UnicodeStore::read(file.clone()).unwrap();
    assert_eq!(walk(&store).folders, 6);
}

#[test]
fn header_fields_ms_pst_does_not_allow() {
    // wVerClient 99, bPlatformCreate 7, bSentinel 0x81, with the CRCs made to match.
    let mut pst = UnicodePst(fixture("Empty.pst"));
    pst.0[12..14].copy_from_slice(&99_u16.to_le_bytes());
    pst.0[14] = 7;
    pst.0[512] = 0x81;
    pst.fix_header_crcs();
    let err = read(&pst, Validation::Strict).err().unwrap();
    assert!(err.to_string().contains("wVerClient"), "{err}");

    let file = Rc::new(read(&pst, Validation::Lenient).unwrap());
    assert_eq!(kinds(&file), [ProblemKind::HeaderField; 3]);
    assert!(file.problems()[0].detail().contains("wVerClient is 99"));
    let store = UnicodeStore::read(file.clone()).unwrap();
    assert_eq!(walk(&store).folders, 6);
}

#[test]
fn ost_client_version_is_allowed() {
    // Outlook writes wVerClient 12 in OSTs, in both page layouts.
    let mut pst = UnicodePst(fixture("Empty.pst"));
    pst.0[12..14].copy_from_slice(&12_u16.to_le_bytes());
    pst.fix_header_crcs();
    let file = read(&pst, Validation::Strict).unwrap();
    assert!(file.problems().is_empty());
}

#[test]
fn page_crc_mismatch() {
    let mut pst = UnicodePst(fixture("Empty.pst"));
    let root = pst.nbt_root();
    pst.0[root + 500] ^= 0x01;
    let file = Rc::new(read(&pst, Validation::Strict).unwrap());
    assert!(UnicodeStore::read(file).is_err());

    let file = Rc::new(read(&pst, Validation::Lenient).unwrap());
    let store = UnicodeStore::read(file.clone()).unwrap();
    assert_eq!(walk(&store).folders, 6);
    let problems = file.problems();
    assert_eq!(kinds(&file), [ProblemKind::PageCrc]);
    assert_eq!(problems[0].offset(), Some(root as u64));
}

#[test]
fn block_crc_mismatch() {
    let mut pst = UnicodePst(fixture("Empty.pst"));
    let (offset, size) = store_block(&pst);
    pst.0[UnicodePst::block_crc_offset(offset, size)] ^= 0x01;
    let file = Rc::new(read(&pst, Validation::Strict).unwrap());
    let err = UnicodeStore::read(file).err().unwrap();
    assert!(err.to_string().contains("dwCRC"), "{err}");

    let file = Rc::new(read(&pst, Validation::Lenient).unwrap());
    let store = UnicodeStore::read(file.clone()).unwrap();
    assert_eq!(walk(&store).folders, 6);
    assert_eq!(kinds(&file), [ProblemKind::BlockCrc]);
    assert_eq!(file.problems()[0].offset(), Some(offset as u64));
}

#[test]
fn store_without_record_key() {
    // Rename the store's PidTagRecordKey (0x0FF9) to 0x0F00, in the permute-encoded heap: the
    // encoding maps each byte value to one other, wherever it is, so the encoded 0x00 is taken
    // from a 0x00 of the same block.
    let mut pst = UnicodePst(fixture("Empty.pst"));
    let (offset, size) = store_block(&pst);
    let file = read(&pst, Validation::Strict).unwrap();
    let node = file.read_node(NID_MESSAGE_STORE).unwrap();
    let decoded = file.read_block(node.data()).unwrap();
    let record = decoded
        .windows(4)
        .position(|bytes| bytes == [0xF9, 0x0F, 0x02, 0x01])
        .unwrap();
    let zero = decoded.iter().position(|byte| *byte == 0).unwrap();
    pst.0[offset + record] = pst.0[offset + zero];
    pst.fix_block_crc(offset, size);

    // Strictly, the folders do not open: their entry IDs need the record key.
    let file = Rc::new(read(&pst, Validation::Strict).unwrap());
    let store = UnicodeStore::read(file).unwrap();
    assert!(walk_folders(store.as_ref()).all(|entry| entry.folder.is_err()));

    // Leniently, they open by node ID.
    let file = Rc::new(read(&pst, Validation::Lenient).unwrap());
    let store = UnicodeStore::read(file.clone()).unwrap();
    assert_eq!(walk(&store).folders, 6);
    assert_eq!(walk_folders(store.as_ref()).count(), 6);
    assert_eq!(kinds(&file), [ProblemKind::StoreRecordKey]);
    assert_eq!(
        file.problems()[0].node().map(u32::from),
        Some(u32::from(NID_MESSAGE_STORE))
    );
}

#[test]
fn open_with_and_open_store_with() {
    let path = format!("{}/tests/fixtures/Empty.pst", env!("CARGO_MANIFEST_DIR"));
    let file = UnicodePstFile::open_with(&path, Validation::Strict).unwrap();
    assert_eq!(file.validation(), Validation::Strict);
    assert!(outlook_pst::open_store_with(&path, Validation::Strict).is_ok());
    assert!(outlook_pst::open_store(&path).is_ok());
}

/// The decoded data block of the message store's node, and where in it the property record of
/// `prop_id` (key, type and value) is.
fn store_record(pst: &UnicodePst, prop_id: u16) -> (Vec<u8>, usize) {
    let file = read(pst, Validation::Strict).unwrap();
    let node = file.read_node(NID_MESSAGE_STORE).unwrap();
    let decoded = file.read_block(node.data()).unwrap();
    let key = prop_id.to_le_bytes();
    let at = (0..decoded.len() - 8)
        .find(|at| decoded[*at..*at + 2] == key && decoded[*at + 2..*at + 4] != [0, 0])
        .unwrap();
    (decoded, at)
}

/// The message store's heap with one property record changed: `edit` gets the decoded record
/// (key, type and value) and returns the bytes it should become; each new byte value must occur
/// somewhere in the decoded block, where its permute-encoded form is taken from.
fn edit_store_record(prop_id: u16, edit: impl FnOnce([u8; 8]) -> [u8; 8]) -> UnicodePst {
    let mut pst = UnicodePst(fixture("Empty.pst"));
    let (offset, size) = store_block(&pst);
    let (decoded, at) = store_record(&pst, prop_id);
    let record: [u8; 8] = decoded[at..at + 8].try_into().unwrap();
    for (i, byte) in edit(record).into_iter().enumerate() {
        let source = decoded.iter().position(|b| *b == byte).unwrap();
        pst.0[offset + at + i] = pst.0[offset + source];
    }
    pst.fix_block_crc(offset, size);
    pst
}

#[test]
fn property_record_of_an_unknown_type() {
    // PidTagDisplayName's record gets wPropType 0x0000: the BTH reader used to stop there, or
    // (with every record read) fail the whole property context.
    let pst = edit_store_record(0x3001, |mut record| {
        record[2] = 0;
        record[3] = 0;
        record
    });
    let file = Rc::new(read(&pst, Validation::Strict).unwrap());
    assert!(UnicodeStore::read(file).is_err());

    let file = Rc::new(read(&pst, Validation::Lenient).unwrap());
    let store = UnicodeStore::read(file.clone()).unwrap();
    use outlook_pst::messaging::store::Store;
    assert!(store.properties().display_name().is_err());
    assert!(store.properties().record_key().is_ok());
    assert_eq!(walk(&store).folders, 6);
    assert_eq!(kinds(&file), [ProblemKind::HeapRecord]);
}

#[test]
fn property_value_that_cannot_be_read() {
    // PidTagDisplayName's HID points past the heap's allocations.
    let pst = edit_store_record(0x3001, |mut record| {
        record[4..8].copy_from_slice(&0x0F00_u32.to_le_bytes());
        record
    });
    let file = Rc::new(read(&pst, Validation::Strict).unwrap());
    assert!(UnicodeStore::read(file).is_err());

    let file = Rc::new(read(&pst, Validation::Lenient).unwrap());
    let store = UnicodeStore::read(file.clone()).unwrap();
    use outlook_pst::messaging::store::Store;
    assert!(store.properties().display_name().is_err());
    assert_eq!(walk(&store).folders, 6);
    let problems = file.problems();
    assert_eq!(kinds(&file), [ProblemKind::Property]);
    assert!(problems[0].detail().starts_with("property 0x3001"));
    assert_eq!(
        problems[0].node().map(u32::from),
        Some(u32::from(NID_MESSAGE_STORE))
    );
}

#[test]
fn property_value_of_two_properties() {
    // PidTagDisplayName's HID is PidTagRecordKey's: the value is PidTagRecordKey's alone.
    let pst = UnicodePst(fixture("Empty.pst"));
    let (decoded, at) = store_record(&pst, 0x0FF9);
    let hid: [u8; 4] = decoded[at + 4..at + 8].try_into().unwrap();
    let pst = edit_store_record(0x3001, |mut record| {
        record[4..8].copy_from_slice(&hid);
        record
    });
    let file = Rc::new(read(&pst, Validation::Strict).unwrap());
    let Err(err) = UnicodeStore::read(file) else {
        panic!("read strictly, the store opened");
    };
    let err = err.to_string();
    assert!(
        err.contains("is also the value of property 0x0FF9"),
        "{err}"
    );

    let file = Rc::new(read(&pst, Validation::Lenient).unwrap());
    let store = UnicodeStore::read(file.clone()).unwrap();
    use outlook_pst::messaging::store::Store;
    assert!(store.properties().display_name().is_err());
    assert!(store.properties().record_key().is_ok());
    assert_eq!(walk(&store).folders, 6);
    let problems = file.problems();
    assert_eq!(kinds(&file), [ProblemKind::Property]);
    assert_eq!(
        problems[0].detail(),
        "property 0x3001 (Unicode): Property value is also the value of property 0x0FF9"
    );
}

#[test]
fn fixed_size_property_with_an_hnid_of_0() {
    // PidTagDisplayName's record becomes a PtypTime with an HNID of 0, which has no empty value:
    // it used to read as PtypNull.
    let pst = edit_store_record(0x3001, |mut record| {
        record[2..4].copy_from_slice(&0x0040_u16.to_le_bytes());
        record[4..8].copy_from_slice(&0_u32.to_le_bytes());
        record
    });
    let file = Rc::new(read(&pst, Validation::Strict).unwrap());
    let Err(err) = UnicodeStore::read(file) else {
        panic!("read strictly, the store opened");
    };
    assert!(err.to_string().contains("HNID of 0"), "{err}");

    let file = Rc::new(read(&pst, Validation::Lenient).unwrap());
    let store = UnicodeStore::read(file.clone()).unwrap();
    use outlook_pst::messaging::store::Store;
    assert!(store.properties().get(0x3001).is_none());
    assert_eq!(walk(&store).folders, 6);
    let problems = file.problems();
    assert_eq!(kinds(&file), [ProblemKind::Property]);
    assert_eq!(
        problems[0].detail(),
        "property 0x3001 (Time): HNID of 0 for a fixed-size value: Time"
    );
}

#[test]
fn folder_table_that_cannot_be_read() {
    // The contents table of a folder with messages gets the store's property context as its data:
    // its TCINFO does not read.
    let data = fixture("outlook.pst.gz");
    let read_store = |data: &[u8], validation| {
        let file = Rc::new(
            UnicodePstFile::read_from_with(Box::new(Cursor::new(data.to_vec())), validation)
                .unwrap(),
        );
        (file.clone(), UnicodeStore::read(file).unwrap())
    };
    let (_, store) = read_store(&data, Validation::Strict);
    let folder = walk_folders(store.as_ref())
        .find(|entry| {
            entry.folder.as_ref().is_ok_and(|folder| {
                folder
                    .contents_table()
                    .is_some_and(|table| table.rows_matrix().count() > 0)
            })
        })
        .map(|entry| u32::from(entry.node_id))
        .unwrap();
    let mut pst = UnicodePst(data);
    let (store_entry, _) = pst.nbt_entry(u32::from(NID_MESSAGE_STORE));
    let store_data = pst.u64_at(store_entry + 8);
    let (entry, page) = pst.nbt_entry((folder & !0x1F) | 0x0E);
    pst.set_u64(entry + 8, store_data);
    pst.fix_page_crc(page);

    // Strictly, the folder does not open.
    let (_, store) = read_store(&pst.0, Validation::Strict);
    let opened = walk_folders(store.as_ref())
        .find(|entry| u32::from(entry.node_id) == folder)
        .unwrap();
    let err = opened.folder.err().unwrap();
    assert!(err.to_string().contains("TCINFO"), "{err}");

    // Leniently, it opens without a contents table, and that is a problem.
    let (file, store) = read_store(&pst.0, Validation::Lenient);
    let opened = walk_folders(store.as_ref())
        .find(|entry| u32::from(entry.node_id) == folder)
        .unwrap();
    let opened = opened.folder.unwrap();
    assert!(opened.contents_table().is_none());
    assert!(opened.hierarchy_table().is_some());
    assert_eq!(kinds(&file), [ProblemKind::Table]);
    assert_eq!(file.problems()[0].node().map(u32::from), Some(folder));
}
