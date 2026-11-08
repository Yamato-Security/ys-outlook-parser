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

//! Helpers shared by the integration tests: the fixtures in `tests/fixtures`, and a walk over every
//! folder, message, recipient and attachment of a store that counts what it reads.

#![allow(dead_code)]

use outlook_pst::{
    UnicodePstFile,
    messaging::{attachment::*, message::*, store::*},
    ndb::node_id::{NID_ROOT_FOLDER, NodeId},
};
use std::{
    collections::BTreeSet,
    io::{self, Cursor, Read},
    rc::Rc,
};

/// The bytes of a fixture in `tests/fixtures`, decompressed if its name ends in `.gz`.
pub fn fixture(name: &str) -> Vec<u8> {
    let path = format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    let bytes = std::fs::read(&path).unwrap_or_else(|err| panic!("{path}: {err}"));
    if name.ends_with(".gz") {
        let mut data = Vec::new();
        flate2::read::GzDecoder::new(bytes.as_slice())
            .read_to_end(&mut data)
            .unwrap_or_else(|err| panic!("{path}: {err}"));
        data
    } else {
        bytes
    }
}

/// What [`walk`] read.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counts {
    /// Folders opened, the root folder included.
    pub folders: usize,
    pub folder_errors: usize,
    /// Rows of the contents tables, and how many of them opened.
    pub messages: usize,
    pub messages_read: usize,
    /// Rows of the associated contents tables (FAI), and how many of them opened.
    pub fai: usize,
    pub fai_read: usize,
    /// Rows of the recipient tables.
    pub recipients: usize,
    /// Rows of the attachment tables, how many opened and how many are embedded messages.
    pub attachments: usize,
    pub attachments_read: usize,
    pub embedded: usize,
}

/// Open a Unicode PST or OST held in memory.
pub fn open_unicode(data: Vec<u8>) -> io::Result<Rc<UnicodeStore>> {
    let pst = UnicodePstFile::read_from(Box::new(Cursor::new(data)))?;
    UnicodeStore::read(Rc::new(pst))
}

/// Walk every folder reachable from the root folder (each at most once), and every message,
/// recipient and attachment in them. Errors below the store are counted, not returned.
pub fn walk(store: &Rc<UnicodeStore>) -> Counts {
    let dyn_store: Rc<dyn Store> = store.clone();
    let mut counts = Counts::default();
    let mut seen = BTreeSet::new();
    let mut stack = vec![NID_ROOT_FOLDER];
    while let Some(node_id) = stack.pop() {
        if !seen.insert(u32::from(node_id)) {
            continue;
        }
        let Ok(entry_id) = dyn_store.properties().make_entry_id(node_id) else {
            counts.folder_errors += 1;
            continue;
        };
        let Ok(folder) = dyn_store.open_folder(&entry_id) else {
            counts.folder_errors += 1;
            continue;
        };
        counts.folders += 1;
        if let Some(table) = folder.hierarchy_table() {
            stack.extend(
                table
                    .rows_matrix()
                    .map(|row| NodeId::from(u32::from(row.id()))),
            );
        }
        let mut messages = Vec::new();
        if let Some(table) = folder.contents_table() {
            messages.extend(table.rows_matrix().map(|row| (u32::from(row.id()), false)));
        }
        if let Some(table) = folder.associated_table() {
            messages.extend(table.rows_matrix().map(|row| (u32::from(row.id()), true)));
        }
        for (node_id, fai) in messages {
            if fai {
                counts.fai += 1;
            } else {
                counts.messages += 1;
            }
            let Ok(entry_id) = dyn_store.properties().make_entry_id(NodeId::from(node_id)) else {
                continue;
            };
            let Ok(message) = UnicodeMessage::read(store.clone(), &entry_id, None) else {
                continue;
            };
            if fai {
                counts.fai_read += 1;
            } else {
                counts.messages_read += 1;
            }
            walk_message(&message, &mut counts);
        }
    }
    counts
}

/// Every embedded message attached to a message of the store, one level deep.
pub fn embedded_messages(store: &Rc<UnicodeStore>) -> Vec<Rc<dyn Message>> {
    let dyn_store: Rc<dyn Store> = store.clone();
    let mut result = Vec::new();
    let mut seen = BTreeSet::new();
    let mut stack = vec![NID_ROOT_FOLDER];
    while let Some(node_id) = stack.pop() {
        if !seen.insert(u32::from(node_id)) {
            continue;
        }
        let Ok(folder) =
            dyn_store.open_folder(&dyn_store.properties().make_entry_id(node_id).unwrap())
        else {
            continue;
        };
        if let Some(table) = folder.hierarchy_table() {
            stack.extend(
                table
                    .rows_matrix()
                    .map(|row| NodeId::from(u32::from(row.id()))),
            );
        }
        let Some(table) = folder.contents_table() else {
            continue;
        };
        for row in table.rows_matrix() {
            let entry_id = dyn_store
                .properties()
                .make_entry_id(NodeId::from(u32::from(row.id())))
                .unwrap();
            let message = UnicodeMessage::read(store.clone(), &entry_id, None).unwrap();
            let Some(attachments) = message.attachment_table() else {
                continue;
            };
            for row in attachments.rows_matrix() {
                let attachment = UnicodeAttachment::read(
                    message.clone(),
                    NodeId::from(u32::from(row.id())),
                    None,
                )
                .unwrap();
                if let Some(AttachmentData::Message(embedded)) = attachment.data() {
                    result.push(embedded.clone());
                }
            }
        }
    }
    result
}

fn walk_message(message: &Rc<UnicodeMessage>, counts: &mut Counts) {
    if let Some(table) = message.recipient_table() {
        counts.recipients += table.rows_matrix().count();
    }
    let attachments: Vec<_> = message
        .attachment_table()
        .map(|table| table.rows_matrix().map(|row| u32::from(row.id())).collect())
        .unwrap_or_default();
    for node_id in attachments {
        counts.attachments += 1;
        if let Ok(attachment) =
            UnicodeAttachment::read(message.clone(), NodeId::from(node_id), None)
        {
            counts.attachments_read += 1;
            if let Some(AttachmentData::Message(_)) = attachment.data() {
                counts.embedded += 1;
            }
        }
    }
}
