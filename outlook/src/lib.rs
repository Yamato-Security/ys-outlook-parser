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

//! Outlook artifacts for forensics, read without Outlook or MAPI: the folders and items of PST
//! and OST stores, and `.msg` and `.oft` items. An item's well-known fields (its class,
//! sender, recipients, times, bodies and attachments, and the fields of contacts, calendar items
//! and tasks) are read from its properties, and every property is kept as stored.
//!
//! ```no_run
//! use outlook::pst::{Options, PstStore};
//!
//! let store = PstStore::open("mailbox.ost", &Options::default())?;
//! for folder in store.folders() {
//!     for stored in store.items(&folder) {
//!         match &stored.item {
//!             Ok(item) => println!("{} {:?} {:?} {:?}", folder.path, item.kind, item.submitted, item.subject),
//!             Err(e) => println!("{}: message {:#x}: {e}", folder.path, stored.node),
//!         }
//!     }
//! }
//! for problem in store.problems() {
//!     println!("{problem}");
//! }
//! let msg = outlook::MsgItem::from_bytes(&std::fs::read("mail.msg")?, &Default::default())?;
//! println!("{:?} {:?}", msg.item.subject, msg.item.attachments.len());
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

// It reads what the readers give, from untrusted files: no unchecked indexing or arithmetic,
// and no unwrap, expect or panic.
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

pub mod item;
pub mod mapi;
pub mod msg;
pub mod pst;

pub use item::{
    Appointment, Attachment, AttachmentParts, Body, Contact, Item, ItemKind, Party, Recipient,
    RecipientKind, Reminder, Task,
};
pub use mapi::{NameId, Property, PropertyName, Value};
pub use msg::MsgItem;
pub use pst::{Folder, PstStore, StoreInfo, StoreItem};

/// The readers this crate builds on, for what its model does not cover.
pub use {outlook_msg, outlook_pst};
