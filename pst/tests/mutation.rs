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

//! A deterministic mutation test: each fixture is read once through a reader that records which
//! bytes are read, then copies of it with a few of those bytes changed (a seeded xorshift picks
//! them) are read in every way the crate offers. Nothing may panic or abort; CRC mismatches are
//! read past, leniently, so that the mutations reach the structures behind them.
//!
//! `PST_MUTATION_CASES` and `PST_MUTATION_SEED` override the number of copies of each fixture and
//! add to the seeds, for longer runs: `PST_MUTATION_CASES=20000 cargo test --release --test
//! mutation`.

mod common;

use common::*;
use outlook_pst::{
    PstFile, UnicodePstFile, Validation,
    ltp::{prop_context::PropertyValue, table_context::TableContext},
    messaging::{
        attachment::*, folder::walk_folders, message::*, named_prop::NamedPropertyId, store::*,
    },
    ndb::node_id::{NID_MESSAGE_STORE, NID_ROOT_FOLDER, NodeId},
};
use std::{
    cell::RefCell,
    io::{self, Cursor, Read, Seek, SeekFrom},
    panic::{AssertUnwindSafe, catch_unwind},
    rc::Rc,
};

/// A fixed-seed xorshift64.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
}

/// A reader that records the ranges it reads.
struct TraceReader {
    inner: Cursor<Vec<u8>>,
    reads: Rc<RefCell<Vec<(usize, usize)>>>,
}

impl Read for TraceReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let start = self.inner.position() as usize;
        let n = self.inner.read(buf)?;
        if n > 0 {
            self.reads.borrow_mut().push((start, n));
        }
        Ok(n)
    }
}

impl Seek for TraceReader {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.inner.seek(pos)
    }
}

/// Read every table cell, message, recipient, attachment and embedded message, the named
/// property map and the search update queue, and decompress every compressed RTF body.
fn read_deeply(file: Rc<UnicodePstFile>) {
    let _ = file.read_node(NID_ROOT_FOLDER);
    let _ = file.read_node(NID_MESSAGE_STORE);
    let Ok(store) = UnicodeStore::read(file.clone()) else {
        return;
    };
    let dyn_store: Rc<dyn Store> = store.clone();
    let _ = dyn_store.properties().display_name();
    if let Ok(table) = dyn_store.root_hierarchy_table() {
        read_table(table.as_ref());
    }
    if let Ok(map) = dyn_store.named_property_map() {
        let properties = map.properties();
        let _ = properties.bucket_count();
        let _ = properties.stream_guid();
        let _ = properties.stream_string();
        if let Ok(entries) = properties.stream_entry() {
            for entry in entries.iter().take(300) {
                let _ = properties.lookup_guid(entry.guid());
                if let NamedPropertyId::StringOffset(offset) = entry.id() {
                    let _ = properties.lookup_string(offset);
                }
                if let Ok(hashed) = properties.hash_entry(*entry) {
                    let _ = properties.hash_bucket(&hashed);
                }
            }
        }
    }
    if let Ok(queue) = dyn_store.search_update_queue() {
        let _ = queue.updates().len();
    }
    for entry in walk_folders(dyn_store.as_ref()).take(300) {
        let Ok(folder) = entry.folder else {
            continue;
        };
        let _ = folder.properties().display_name();
        for table in [
            folder.hierarchy_table(),
            folder.contents_table(),
            folder.associated_table(),
        ]
        .into_iter()
        .flatten()
        {
            read_table(table.as_ref());
        }
        for table in [folder.contents_table(), folder.associated_table()]
            .into_iter()
            .flatten()
        {
            for row in table.rows_matrix().take(100) {
                let node = NodeId::from(u32::from(row.id()));
                let Ok(entry_id) = dyn_store.properties().make_entry_id(node) else {
                    continue;
                };
                if let Ok(message) = UnicodeMessage::read(store.clone(), &entry_id, None) {
                    read_message(&message);
                }
            }
        }
    }
    let _ = file.problems();
}

fn read_table(table: &dyn TableContext) {
    for row in table.rows_matrix().take(300) {
        let _ = table.find_row(row.id());
        let Ok(values) = row.columns(table.context()) else {
            continue;
        };
        for (column, value) in table.context().columns().iter().zip(values) {
            if let Some(value) = value {
                let _ = table.read_column(&value, column.prop_type());
            }
        }
    }
}

fn read_properties(message: &dyn Message) {
    let properties = message.properties();
    let _ = properties.message_class();
    let _ = properties.creation_time();
    if let Some(PropertyValue::Binary(rtf)) = properties.get(0x1009) {
        let _ = compressed_rtf::decompress_rtf(rtf.buffer());
    }
    for table in [message.recipient_table(), message.attachment_table()]
        .into_iter()
        .flatten()
    {
        read_table(table.as_ref());
    }
}

fn read_message(message: &Rc<UnicodeMessage>) {
    read_properties(message.as_ref());
    let attachments: Vec<_> = message
        .attachment_table()
        .map(|table| table.rows_matrix().map(|row| u32::from(row.id())).collect())
        .unwrap_or_default();
    for attachment in attachments.into_iter().take(50) {
        let Ok(attachment) =
            UnicodeAttachment::read(message.clone(), NodeId::from(attachment), None)
        else {
            continue;
        };
        let _ = attachment.properties().attachment_method();
        if let Some(AttachmentData::Message(embedded)) = attachment.data() {
            read_properties(embedded.as_ref());
        }
    }
}

/// Mutate `cases` copies of a fixture and read each.
fn mutate(name: &str, seed: u64, cases: usize) {
    let env = |name| {
        std::env::var(name)
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
    };
    let cases = env("PST_MUTATION_CASES").map_or(cases, |cases| cases as usize);
    let seed = seed.wrapping_add(env("PST_MUTATION_SEED").unwrap_or(0));
    let data = fixture(name);

    // The ranges a clean read reads.
    let reads = Rc::new(RefCell::new(Vec::new()));
    let reader = TraceReader {
        inner: Cursor::new(data.clone()),
        reads: reads.clone(),
    };
    let file = UnicodePstFile::read_from(Box::new(reader)).unwrap();
    read_deeply(Rc::new(file));
    let mut ranges = reads.borrow().clone();
    ranges.sort_unstable();
    ranges.dedup();
    assert!(!ranges.is_empty());

    let mut rng = Rng(seed);
    let mut failures = Vec::new();
    for case in 0..cases {
        let mut mutated = data.clone();
        let last = data.len() - 1;
        let pick = |rng: &mut Rng| {
            let (start, len) = ranges[rng.below(ranges.len())];
            (start + rng.below(len)).min(last)
        };
        let edits = rng.below(4) + 1;
        let mut positions = Vec::new();
        for _ in 0..edits {
            let at = pick(&mut rng);
            positions.push(at);
            match rng.below(6) {
                0 => mutated[at] = rng.next() as u8,
                1 => mutated[at] = 0x00,
                2 => mutated[at] = 0xFF,
                3 => mutated[at] ^= 1 << rng.below(8),
                // Another read field's 8 bytes over this one's, as a loop or an overlap would.
                4 => {
                    let from = pick(&mut rng);
                    for i in 0..8 {
                        if at + i < mutated.len() && from + i < data.len() {
                            mutated[at + i] = data[from + i];
                        }
                    }
                }
                _ => {
                    let value = rng.next().to_le_bytes();
                    for (i, byte) in value.iter().enumerate().take(4) {
                        if at + i < mutated.len() {
                            mutated[at + i] = *byte;
                        }
                    }
                }
            }
        }
        if rng.below(20) == 0 {
            let at = pick(&mut rng);
            mutated.truncate(at);
            positions.push(at);
        }
        // Mostly lenient, so that CRC checks do not stop the reads; one case in five strict.
        let validation = if case % 5 == 4 {
            Validation::Strict
        } else {
            Validation::Lenient
        };
        let result = catch_unwind(AssertUnwindSafe(|| {
            if let Ok(file) =
                UnicodePstFile::read_from_with(Box::new(Cursor::new(mutated)), validation)
            {
                read_deeply(Rc::new(file));
            }
        }));
        if result.is_err() {
            failures.push((case, positions));
        }
    }
    assert!(
        failures.is_empty(),
        "{name}: {} of {cases} mutations panicked (case, offsets): {failures:?}",
        failures.len()
    );
}

#[test]
fn mutated_empty_pst() {
    mutate("Empty.pst", 0x5EED_0001, 300);
}

#[test]
fn mutated_dist_list_pst() {
    mutate("dist-list.pst.gz", 0x5EED_0002, 300);
}

#[test]
fn mutated_outlook_pst() {
    mutate("outlook.pst.gz", 0x5EED_0003, 300);
}

#[test]
fn mutated_example_2013_ost() {
    mutate("example-2013.ost.gz", 0x5EED_0004, 150);
}
