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

//! The item model on the fixtures: stores, folders and items of PST and OST files, and `.msg`
//! and `.oft` files.

mod common;

use std::io::Cursor;

use outlook::msg::FileKind;
use outlook::pst::{Encryption, Format, Options, PstStore, StoreKind};
use outlook::{Item, ItemKind, MsgItem, RecipientKind};

fn store(name: &str) -> PstStore {
    PstStore::from_reader(Cursor::new(common::pst_fixture(name)), &Options::default()).unwrap()
}

/// The messages (not the FAI) of the folder at `path`.
fn items(store: &PstStore, path: &str) -> Vec<Item> {
    let folder = store
        .folders()
        .into_iter()
        .find(|f| f.path == path)
        .unwrap_or_else(|| panic!("no folder {path}"));
    store
        .items(&folder)
        .filter(|i| !i.associated)
        .map(|i| i.item.unwrap())
        .collect()
}

#[test]
fn a_unicode_pst() {
    let store = store("outlook.pst");
    let info = store.info();
    assert_eq!(
        (&info.kind, info.format, info.version, info.encryption),
        (&StoreKind::Pst, Format::Unicode, 23, Encryption::Permute)
    );
    assert_eq!(info.display_name.as_deref(), Some("Personal Folders"));
    let folders = store.folders();
    assert_eq!(folders.len(), 22);
    assert_eq!(folders[0].path, "/");
    // folder names are Unicode
    assert!(
        folders
            .iter()
            .any(|f| f.path == "/Top of Personal Folders/收件箱")
    );
    let calendar = folders
        .iter()
        .find(|f| f.path == "/Top of Personal Folders/Calendar")
        .unwrap();
    assert_eq!(calendar.container_class.as_deref(), Some("IPF.Appointment"));

    let inbox = items(&store, "/Top of Personal Folders/Inbox");
    assert_eq!(inbox.len(), 1);
    let mail = &inbox[0];
    assert_eq!(mail.kind, ItemKind::Mail);
    assert_eq!(
        mail.subject.as_deref(),
        Some("Welcome to Microsoft Office Outlook 2003")
    );
    assert_eq!(mail.sender.address_type.as_deref(), Some("SMTP"));
    assert_eq!(mail.submitted, Some(128223592535930000));
    assert_eq!(mail.recipients.len(), 1);
    assert_eq!(mail.recipients[0].kind, Some(RecipientKind::To));
    assert_eq!(mail.attachments.len(), 11);
    let first = &mail.attachments[0];
    assert_eq!(
        (first.method, first.name(), first.mime_type.as_deref()),
        (Some(1), Some("1.jpg"), Some("image/jpeg"))
    );
    let data = first.data.as_deref().unwrap();
    assert_eq!((data.len(), &data[..2]), (1969, &[0xFF, 0xD8][..]));
    assert!(mail.body.rtf.is_some() || mail.body.html.is_some() || mail.body.text.is_some());
    assert!(mail.problems.is_empty(), "{:?}", mail.problems);
    assert!(store.problems().is_empty(), "{:?}", store.problems());
}

#[test]
fn calendar_contacts_and_embedded_messages() {
    let store = store("dist-list.pst");
    let calendar = items(&store, "/Top of Personal Folders/Calendar");
    let appointment = &calendar[0];
    assert_eq!(appointment.kind, ItemKind::Appointment);
    // the subject without the store's prefix marker
    assert_eq!(appointment.subject.as_deref(), Some("Test appointment"));
    let a = appointment.appointment.as_ref().unwrap();
    assert_eq!(
        (a.start, a.end, a.duration_minutes, a.recurring),
        (
            Some(131146236000000000),
            Some(131146254000000000),
            Some(30),
            Some(true)
        )
    );
    assert_eq!(appointment.reminder.set, Some(true));
    // two exceptions of the recurring appointment, as embedded messages
    let bodies: Vec<_> = appointment
        .attachments
        .iter()
        .map(|a| {
            assert_eq!(a.method, Some(5));
            a.embedded.as_ref().unwrap().body.text.clone().unwrap()
        })
        .collect();
    assert_eq!(
        bodies,
        [
            "This is the appointment at 9\r\n",
            "This is the one at 10\r\n"
        ]
    );

    let contacts = items(&store, "/Top of Personal Folders/Contacts");
    let kinds: Vec<_> = contacts.iter().map(|c| c.kind).collect();
    assert_eq!(kinds, [ItemKind::Contact, ItemKind::DistributionList]);
    let contact = contacts[0].contact.as_ref().unwrap();
    assert_eq!(contact.display_name.as_deref(), Some("contact name 1"));
    assert_eq!(contact.file_under.as_deref(), Some("1, contact name"));
    assert_eq!(contact.emails.len(), 1);
    assert_eq!(contact.emails[0].address_type.as_deref(), Some("SMTP"));
}

#[test]
fn an_ost_of_outlook_2013() {
    let store = store("example-2013.ost");
    let info = store.info();
    assert_eq!(
        (&info.kind, info.format, info.version, info.client_version),
        (&StoreKind::Ost, Format::Unicode4k, 36, 12)
    );
    let folders = store.folders();
    assert_eq!(folders.len(), 46);
    let sent = items(&store, "/Root - Mailbox/IPM_SUBTREE/Sent Items");
    assert_eq!(sent[0].subject.as_deref(), Some("Test 2"));
    // folder associated information: hidden configuration messages
    let fai: Vec<_> = folders
        .iter()
        .flat_map(|f| store.items(f).filter(|i| i.associated).collect::<Vec<_>>())
        .collect();
    assert_eq!(fai.len(), 14);
    assert!(fai.iter().all(|i| i.item.is_ok()));
    assert!(store.problems().is_empty(), "{:?}", store.problems());
}

#[test]
fn messages_in_messages_in_a_msg() {
    let msg = MsgItem::from_bytes(
        &common::msg_fixture("msgreader-hiraoka/msgInMsgInMsg.msg"),
        &Default::default(),
    )
    .unwrap();
    assert_eq!(msg.kind, FileKind::Message);
    let item = &msg.item;
    assert_eq!(item.subject.as_deref(), Some("I have sub attachments!"));
    let level1 = item.attachments[0].embedded.as_ref().unwrap();
    assert_eq!(level1.subject.as_deref(), Some("I have attachments!"));
    let level2 = level1.attachments[0].embedded.as_ref().unwrap();
    assert_eq!(
        level2.subject.as_deref(),
        Some("Microsoft Outlook テスト メッセージ")
    );
    assert_eq!(level1.attachments[1].name(), Some("green.png"));
    assert_eq!(item.attachments[1].data.as_ref().map(Vec::len), Some(134));
}

#[test]
fn contacts_tasks_and_templates_in_msg_files() {
    let contact = MsgItem::from_bytes(
        &common::msg_fixture("msgreader-hiraoka/contactAnsi.msg"),
        &Default::default(),
    )
    .unwrap()
    .item;
    assert_eq!(contact.kind, ItemKind::Contact);
    let c = contact.contact.unwrap();
    // ANSI strings in code page 932
    assert_eq!(c.surname.as_deref(), Some("イグザンプル"));
    assert_eq!(c.company.as_deref(), Some("My work company"));

    let task = MsgItem::from_bytes(
        &common::msg_fixture("apache-poi/msgClassTask.msg"),
        &Default::default(),
    )
    .unwrap()
    .item;
    let t = task.task.unwrap();
    assert_eq!(
        (t.status, t.percent_complete, t.complete),
        (Some(1), Some(0.0), Some(false))
    );

    let template = MsgItem::from_bytes(
        &common::msg_fixture("aspose-email-java/mapiToOft.oft"),
        &Default::default(),
    )
    .unwrap();
    assert_eq!(template.kind, FileKind::Template);
    assert_eq!(template.item.subject.as_deref(), Some("template subject"));
}

/// Counts the embedded messages of an item, at every level.
fn embedded(item: &Item) -> usize {
    item.attachments
        .iter()
        .filter_map(|a| a.embedded.as_deref())
        .map(|e| 1 + embedded(e))
        .sum()
}

#[test]
fn embedded_messages_that_hold_themselves() {
    // dist-list.pst with both embedded messages of the appointment pointing back at the
    // appointment's own data: each would hold two copies of itself, level after level.
    let data = common::outlook_fixture("dist-list-embedded-loop.pst");
    let store = PstStore::from_reader(Cursor::new(data), &Options::default()).unwrap();
    let start = std::time::Instant::now();
    let calendar = items(&store, "/Top of Personal Folders/Calendar");
    assert!(start.elapsed().as_secs() < 30, "{:?}", start.elapsed());
    let appointment = &calendar[0];
    // the pst crate refuses an embedded message with the blocks of a message it is in
    assert_eq!(appointment.attachments.len(), 2);
    assert_eq!(embedded(appointment), 0);
    let cycles = store
        .problems()
        .iter()
        .filter(|p| {
            p.contains("embedded message: Embedded message has the data and sub-node blocks")
        })
        .count();
    assert_eq!(cycles, 2, "{:?}", store.problems());
    // what is left of the appointment is read
    assert_eq!(appointment.subject.as_deref(), Some("Test appointment"));
}
