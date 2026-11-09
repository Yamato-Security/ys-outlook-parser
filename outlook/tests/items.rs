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

use std::io::{Cursor, Write};

use outlook::msg::FileKind;
use outlook::pst::{Encryption, Format, Options, PstStore, StoreKind};
use outlook::{Item, ItemKind, MsgItem, RecipientKind};

/// A synthetic MSG containing just the supplied property streams.
fn synthetic_msg(streams: &[(&str, &[u8])]) -> Vec<u8> {
    let mut file = cfb::CompoundFile::create(Cursor::new(Vec::new())).unwrap();
    file.create_stream("/__properties_version1.0")
        .unwrap()
        .write_all(&[0; 32])
        .unwrap();
    for (name, data) in streams {
        if let Some(parent) = std::path::Path::new(name).parent() {
            file.create_storage_all(parent).unwrap();
        }
        file.create_stream(name).unwrap().write_all(data).unwrap();
    }
    file.into_inner().into_inner()
}

#[test]
fn large_shared_property_names_keep_every_property_readable() {
    let name = "N".repeat(65_536);
    let count = 1500u16;
    let mut strings = (name.len() as u32 * 2).to_le_bytes().to_vec();
    strings.extend(name.encode_utf16().flat_map(u16::to_le_bytes));
    let mut mappings = Vec::new();
    let mut properties = vec![0; 32];
    for index in 0..count {
        mappings.extend(0u32.to_le_bytes());
        mappings.extend(((u32::from(index) << 16) | 5).to_le_bytes());
        properties.extend(((u32::from(0x8000 + index) << 16) | 3).to_le_bytes());
        properties.extend(6u32.to_le_bytes());
        properties.extend(u64::from(index).to_le_bytes());
    }
    let bytes = synthetic_msg(&[
        ("/__nameid_version1.0/__substg1.0_00030102", &mappings),
        ("/__nameid_version1.0/__substg1.0_00040102", &strings),
        ("/__properties_version1.0", &properties),
    ]);
    let msg = MsgItem::from_bytes(&bytes, &Default::default()).unwrap();
    assert_eq!(msg.item.properties.len(), usize::from(count));
    for property in &msg.item.properties {
        assert_eq!(
            property.value.as_i64(),
            Some(i64::from(property.id - 0x8000))
        );
        let outlook::NameId::Text(text) = &property.name.as_ref().unwrap().id else {
            panic!("not a string name");
        };
        assert!(
            text.as_ref() == name.as_str(),
            "wrong name on property {:#x}",
            property.id
        );
    }
}

#[test]
fn unified_fields_prefer_unicode_to_ansi() {
    let subject: Vec<u8> = "日本語 subject"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    let body: Vec<u8> = "日本語 body"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    let bytes = synthetic_msg(&[
        ("/__substg1.0_0037001E", b"??? subject"),
        ("/__substg1.0_0037001F", &subject),
        ("/__substg1.0_1000001E", b"??? body"),
        ("/__substg1.0_1000001F", &body),
    ]);
    let raw = outlook::outlook_msg::MsgFile::from_bytes(&bytes).unwrap();
    let msg = MsgItem::from_bytes(&bytes, &Default::default()).unwrap();
    assert_eq!(raw.message.subject(), Some("日本語 subject"));
    assert_eq!(msg.item.subject.as_deref(), raw.message.subject());
    assert_eq!(msg.item.body.text.as_deref(), raw.message.body());
    assert_eq!(
        msg.item.properties.len(),
        4,
        "both representations remain available"
    );
}

#[test]
fn unified_html_uses_the_same_representation_as_the_msg_reader() {
    let unicode: Vec<u8> = "<p>日本語</p>"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    for binary in [None, Some(b"<p>canonical binary HTML</p>".as_slice())] {
        let mut streams = vec![
            ("/__substg1.0_1013001E", b"<p>ANSI fallback</p>".as_slice()),
            ("/__substg1.0_1013001F", unicode.as_slice()),
        ];
        if let Some(binary) = binary {
            streams.push(("/__substg1.0_10130102", binary));
        }
        let bytes = synthetic_msg(&streams);
        let raw = outlook::outlook_msg::MsgFile::from_bytes(&bytes).unwrap();
        let msg = MsgItem::from_bytes(&bytes, &Default::default()).unwrap();
        let expected = binary.unwrap_or("<p>日本語</p>".as_bytes());
        assert_eq!(msg.item.body.html.as_deref(), Some(expected));
        assert_eq!(
            raw.message.html.as_ref().unwrap().as_str().as_bytes(),
            expected
        );
    }
}

#[test]
fn unified_unicode_properties_preserve_malformed_bytes() {
    let raw = b"A\0\0\xd8B\0\xff";
    let bytes = synthetic_msg(&[("/__substg1.0_0037001F", raw)]);
    let msg = MsgItem::from_bytes(&bytes, &Default::default()).unwrap();
    assert_eq!(msg.item.subject.as_deref(), Some("A\u{FFFD}B"));
    assert!(msg.item.problems.iter().any(|p| p.contains("not valid")));
    let property = msg.item.properties.iter().find(|p| p.id == 0x0037).unwrap();
    match &property.value {
        outlook::Value::Damaged {
            raw: stored,
            recovered: Some(value),
            ..
        } => {
            assert_eq!(stored, raw);
            assert_eq!(value.as_str(), Some("A\u{FFFD}B"));
        }
        other => panic!("malformed Unicode lost its raw bytes: {other:?}"),
    }
}

#[test]
fn lossy_string8_does_not_hide_a_recovered_unicode_subject() {
    let bytes = synthetic_msg(&[
        ("/__substg1.0_0037001E", b"\xff"),
        ("/__substg1.0_0037001F", b"A\0\0\xd8"),
    ]);
    let msg = MsgItem::from_bytes(
        &bytes,
        &outlook::msg::Options {
            default_code_page: 65001,
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(msg.item.subject.as_deref(), Some("A\u{FFFD}"));
    let ansi = msg
        .item
        .properties
        .iter()
        .find(|p| p.kind == 0x001E)
        .unwrap();
    assert!(matches!(&ansi.value, outlook::Value::Damaged { raw, .. } if raw == b"\xff"));
    assert_eq!(ansi.value.as_str(), Some("\u{FFFD}"));
}

#[test]
fn unsupported_string8_codepages_are_not_presented_as_clean_text() {
    let bytes = synthetic_msg(&[("/__substg1.0_0037001E", b"fallback")]);
    let msg = MsgItem::from_bytes(
        &bytes,
        &outlook::msg::Options {
            default_code_page: 99999,
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(msg.item.subject.as_deref(), Some("fallback"));
    let value = &msg.item.properties[0].value;
    assert!(
        matches!(value, outlook::Value::Damaged { raw, reason, .. } if raw == b"fallback" && reason.contains("99999"))
    );
}

#[test]
fn multivalue_string8_preserves_each_elements_decoding_quality() {
    let raw = b"B\xffC";
    let lengths = [1u32.to_le_bytes(), (raw.len() as u32).to_le_bytes()].concat();
    let bytes = synthetic_msg(&[
        ("/__substg1.0_3001101E", &lengths),
        ("/__substg1.0_3001101E-00000000", b"A"),
        ("/__substg1.0_3001101E-00000001", raw),
    ]);
    let msg = MsgItem::from_bytes(
        &bytes,
        &outlook::msg::Options {
            default_code_page: 65001,
            ..Default::default()
        },
    )
    .unwrap();
    let values = msg.item.properties[0].value.as_multiple().unwrap();
    assert_eq!(values[0].as_str(), Some("A"));
    assert!(matches!(values[0], outlook::Value::String8 { .. }));
    assert_eq!(values[1].as_str(), Some("B\u{FFFD}C"));
    assert!(matches!(&values[1], outlook::Value::Damaged { raw: stored, .. } if stored == raw));
}

#[test]
fn negative_message_codepages_do_not_hide_the_locale_fallback() {
    let mut properties = vec![0; 32];
    for (tag, value) in [(0x3FFD_0003u32, -1i32), (0x3FF1_0003, 1041)] {
        properties.extend(tag.to_le_bytes());
        properties.extend(6u32.to_le_bytes());
        properties.extend(value.to_le_bytes());
        properties.extend([0; 4]);
    }
    let bytes = synthetic_msg(&[
        ("/__properties_version1.0", &properties),
        ("/__substg1.0_0037001E", b"\x93\xfa\x96{"),
    ]);
    let low = outlook::outlook_msg::MsgFile::from_bytes(&bytes).unwrap();
    assert_eq!(low.message.code_page.code_page, 932);
    let msg = MsgItem::from_bytes(&bytes, &Default::default()).unwrap();
    assert_eq!(msg.item.subject.as_deref(), Some("日本"));
    assert_eq!(
        msg.item
            .properties
            .iter()
            .find(|p| p.id == 0x3FFD)
            .unwrap()
            .value
            .as_i64(),
        Some(-1)
    );
}

#[test]
fn unified_multivalue_unicode_preserves_each_malformed_element() {
    let raw = b"B\0\xff";
    let lengths = [2u32.to_le_bytes(), (raw.len() as u32).to_le_bytes()].concat();
    let bytes = synthetic_msg(&[
        ("/__substg1.0_3001101F", &lengths),
        ("/__substg1.0_3001101F-00000000", b"A\0"),
        ("/__substg1.0_3001101F-00000001", raw),
    ]);
    let msg = MsgItem::from_bytes(&bytes, &Default::default()).unwrap();
    let property = msg.item.properties.iter().find(|p| p.id == 0x3001).unwrap();
    let values = property.value.as_multiple().unwrap();
    assert_eq!(values[0].as_str(), Some("A"));
    assert_eq!(values[1].as_str(), Some("B"));
    assert!(matches!(&values[1], outlook::Value::Damaged { raw: stored, .. } if stored == raw));
}

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

#[test]
fn a_damaged_rtf_body_is_reported_once() {
    // RAWSIZE in its compressed RTF header is wrong
    let msg = MsgItem::from_bytes(
        &common::msg_fixture("aspose-email-net/message.msg"),
        &Default::default(),
    )
    .unwrap();
    let rtf: Vec<_> = msg
        .item
        .problems
        .iter()
        .filter(|p| p.contains("RAWSIZE"))
        .collect();
    assert_eq!(rtf.len(), 1, "{:?}", msg.item.problems);
    assert!(msg.item.body.rtf.is_some());
}
