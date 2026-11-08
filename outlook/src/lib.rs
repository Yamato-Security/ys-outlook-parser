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

pub mod item;
pub mod mapi;

pub use item::{
    Appointment, Attachment, AttachmentParts, Body, Contact, Item, ItemKind, Party, Recipient,
    RecipientKind, Reminder, Task,
};
pub use mapi::{NameId, Property, PropertyName, Value};
