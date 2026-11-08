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

//! What the crate reads from the fixtures (tests/fixtures/README.md).

mod common;

use common::fixture;
use outlook_msg::*;
use std::io::Cursor;

fn open(rel: &str) -> MsgFile {
    MsgFile::from_bytes(&fixture(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"))
}

#[test]
fn every_readable_fixture_reads_without_problems_but_known_ones() {
    for rel in common::fixture_files() {
        let Ok(file) = MsgFile::from_bytes(&fixture(&rel)) else {
            assert!(rel.contains("cyclic"), "{rel} does not open");
            continue;
        };
        let problems: Vec<String> = file.all_problems().iter().map(|p| p.to_string()).collect();
        let expected: &[&str] = match rel.as_str() {
            // Aspose writes RAWSIZE = COMPSIZE for uncompressed RTF.
            "aspose-email-net/message.msg" => &[
                "/__substg1.0_10090102: rtf: RAWSIZE says 302 bytes but 290 bytes were decompressed",
            ],
            _ => &[],
        };
        assert_eq!(problems, expected, "{rel}");
    }
}

#[test]
fn reader_and_bytes_agree() {
    let data = fixture("msgreader-hiraoka/msgInMsgInMsg.msg");
    let a = MsgFile::from_bytes(&data).unwrap();
    let b = MsgFile::from_reader(Cursor::new(data)).unwrap();
    assert_eq!(a.message.properties, b.message.properties);
    assert_eq!(a.named_properties, b.named_properties);
    assert_eq!(
        a.message.embedded_messages().len(),
        b.message.embedded_messages().len()
    );
}

#[test]
fn ansi_cp1251_from_the_locale() {
    let file = open("apache-poi/ASCII_CP1251_LCID1049.msg");
    let m = &file.message;
    assert_eq!(file.kind(), FileKind::Other);
    assert!(file.clsid.is_nil());
    assert_eq!(
        m.code_page,
        CodePage {
            code_page: 1251,
            source: CodePageSource::MessageLocaleId
        }
    );
    assert_eq!(m.subject(), Some("Subject автоматически Subject"));
    assert_eq!(m.body(), Some("Body автоматически Body"));
    assert_eq!(
        m.html.as_ref().map(Text::as_str),
        Some(
            r#"<!DOCTYPE html><html><meta charset=\"windows-1251\"><body>HTML автоматически</body></html>"#
        )
    );
    // Raw bytes are kept.
    let subject = m.properties.get_tag(0x0037_001E).unwrap();
    let text = subject.value.ok().and_then(Value::as_text).unwrap();
    assert_eq!(text.raw()[8], 0xE0);
    assert_eq!(text.encoding(), TextEncoding::CodePage(1251));
    assert_eq!(subject.entry.map(|e| e.size()), Some(30));
}

#[test]
fn binary_html_in_the_internet_code_page() {
    let m = open("apache-poi/HTMLBodyBinary_CP1251.msg").message;
    // Strings in the locale's code page (1031: Windows-1252), the HTML in PidTagInternetCodepage.
    assert_eq!(m.subject(), Some("Subject öäü Subject"));
    let html = m.html.unwrap();
    assert_eq!(html.encoding(), TextEncoding::CodePage(1251));
    assert!(
        html.as_str()
            .ends_with("<body>HTML автоматически</body></html>")
    );
}

#[test]
fn ansi_cp932() {
    let file = open("msgreader-hiraoka/nonUnicodeCP932.msg");
    let m = &file.message;
    assert_eq!(file.kind(), FileKind::Message);
    assert_eq!(m.code_page.code_page, 932);
    assert_eq!(m.subject(), Some("日本語 Non Unicode タイトル"));
    assert_eq!(m.body(), Some("日本語 Non Unicode 本文\r\n"));
    assert_eq!(m.recipients.len(), 1);
    assert_eq!(
        m.recipients[0].email_address(),
        Some("xmailuser2@xmailserver.test")
    );
    // PidTagInternetCodepage is ISO-2022-JP; the strings are not.
    assert_eq!(m.properties.int(tags::INTERNET_CODEPAGE), Some(50220));
}

#[test]
fn ansi_contact() {
    let m = open("msgreader-hiraoka/contactAnsi.msg").message;
    assert_eq!(m.message_class(), Some("IPM.Contact"));
    assert_eq!(
        m.properties.string(tags::DISPLAY_NAME),
        Some("Mr. イグザンプル ドット コム 殿")
    );
    // A multi-valued fixed-size named property.
    let p = m
        .properties
        .get_named(&PSETID_ADDRESS, &PropertyName::Id(0x8028))
        .unwrap();
    assert_eq!(p.type_code, 0x1003);
    assert_eq!(
        p.value,
        PropertyValue::Ok(Value::MultipleInteger32(vec![0, 3]))
    );
    assert!(p.id >= 0x8000);
}

#[test]
fn string_named_multi_valued_property() {
    let file = open("apache-poi/keywords.msg");
    let m = &file.message;
    let name = PropertyName::Name("Keywords".into());
    let p = m.properties.get_named(&PS_PUBLIC_STRINGS, &name).unwrap();
    assert_eq!(p.property_type(), Some(PropertyType::MultipleUnicode));
    let Some(Value::MultipleUnicode(words)) = p.value.ok() else {
        panic!("{:?}", p.value)
    };
    let words: Vec<&str> = words.iter().map(Text::as_str).collect();
    assert_eq!(
        &words[..3],
        ["TODO", "Currently Important", "Currently To Do"]
    );
    assert_eq!(
        p.named.as_ref().map(ToString::to_string).as_deref(),
        Some("PS_PUBLIC_STRINGS:Keywords")
    );
    // The mapping is the file's.
    assert_eq!(file.named_properties.get(p.id), p.named.as_ref());
    // RTF body.
    let rtf = m.rtf.as_ref().unwrap();
    assert!(rtf.flags.is_empty());
    assert!(rtf.rtf.as_ref().unwrap().starts_with(b"{\\rtf1\\ansi"));
}

#[test]
fn message_classes() {
    for (rel, class) in [
        ("apache-poi/msgClassAppointment.msg", "IPM.Appointment"),
        ("apache-poi/msgClassStickyNote.msg", "IPM.StickyNote"),
        ("apache-poi/msgClassTask.msg", "IPM.Task"),
        (
            "aspose-email-net/Meeting with Recurring Occurrences.msg",
            "IPM.Schedule.Meeting.Request",
        ),
        ("aspose-email-net/NewGroup.msg", "IPM.DistList"),
        ("aspose-email-java/mapiToOft.oft", "IPM.Note"),
    ] {
        assert_eq!(open(rel).message.message_class(), Some(class), "{rel}");
    }
}

#[test]
fn appointment() {
    let m = open("apache-poi/msgClassAppointment.msg").message;
    assert_eq!(m.subject(), Some("Quick brown fox"));
    assert_eq!(m.recipients.len(), 1);
    assert_eq!(m.recipients[0].display_name(), Some("Allison, Timothy B."));
    assert_eq!(m.recipients[0].recipient_type(), Some(1));
    // PidLidAppointmentStartWhole.
    let start = m
        .properties
        .get_named(&PSETID_APPOINTMENT, &PropertyName::Id(0x820D))
        .and_then(|p| p.value.ok()?.as_time())
        .unwrap();
    assert_eq!(format_filetime(start), "2017-02-28T18:30:00.0000000Z");
}

#[test]
fn distribution_list_members() {
    let m = open("aspose-email-net/NewGroup.msg").message;
    // PidLidDistributionListMembers.
    let p = m
        .properties
        .get_named(&PSETID_ADDRESS, &PropertyName::Id(0x8055))
        .unwrap();
    let Some(Value::MultipleBinary(members)) = p.value.ok() else {
        panic!("{:?}", p.value)
    };
    assert!(!members.is_empty());
    assert!(members.iter().all(|m| m.len() > 20));
}

#[test]
fn template() {
    let file = open("aspose-email-java/mapiToOft.oft");
    assert_eq!(file.kind(), FileKind::Template);
    assert_eq!(file.clsid, CLSID_TEMPLATE);
    assert_eq!(
        file.clsid.to_string(),
        "0006F046-0000-0000-C000-000000000046"
    );
    assert_eq!(file.message.subject(), Some("template subject"));
    assert_eq!(open("apache-poi/keywords.msg").clsid, CLSID_MESSAGE);
}

#[test]
fn attachments_by_value() {
    let m = open("msgreader-hiraoka/attachmentFiles.msg").message;
    let attachments: Vec<(Option<&str>, Option<&str>, usize)> = m
        .attachments
        .iter()
        .map(|a| {
            (
                a.file_name(),
                a.mime_type(),
                a.data().map_or(0, <[u8]>::len),
            )
        })
        .collect();
    assert_eq!(
        attachments,
        [
            (Some("jpg.jpg"), Some("image/jpeg"), 726),
            (Some("png.png"), Some("image/png"), 134),
            (Some("tif.tif"), Some("image/tiff"), 664),
        ]
    );
    for a in &m.attachments {
        assert!(matches!(a.content, AttachmentContent::Binary));
        assert_eq!(a.method(), Some(tags::attach_method::BY_VALUE));
    }
    assert!(m.attachments[1].data().unwrap().starts_with(b"\x89PNG"));
    // The header counts match.
    let header = m.header.unwrap();
    assert_eq!((header.recipient_count, header.attachment_count), (1, 3));
}

#[test]
fn embedded_messages_three_levels() {
    let file = open("msgreader-hiraoka/msgInMsgInMsg.msg");
    let top = &file.message;
    assert!(!top.embedded);
    assert_eq!(top.subject(), Some("I have sub attachments!"));
    let level1 = top.attachments[0].message().unwrap();
    assert!(level1.embedded);
    assert_eq!(level1.subject(), Some("I have attachments!"));
    assert_eq!(
        level1.path,
        "/__attach_version1.0_#00000000/__substg1.0_3701000D"
    );
    let level2 = level1.attachments[0].message().unwrap();
    assert_eq!(
        level2.subject(),
        Some("Microsoft Outlook テスト メッセージ")
    );
    assert_eq!(level2.recipients.len(), 1);
    // The innermost message has no code page of its own: its parent's is used.
    assert_eq!(level2.code_page.source, CodePageSource::Parent);
    assert!(level2.header.is_some());
    // Embedded messages use the file's named-property mapping.
    assert!(level2.properties.iter().any(|p| p.named.is_some()));
    assert_eq!(top.embedded_messages().len(), 2);
    assert_eq!(top.attachments[1].file_name(), Some("blue.png"));
    assert_eq!(level1.attachments[1].file_name(), Some("green.png"));

    // With a depth limit of 1 the innermost message is not read, and that is reported.
    let options = Options {
        max_depth: 1,
        ..Options::default()
    };
    let limited =
        MsgFile::from_bytes_with(&fixture("msgreader-hiraoka/msgInMsgInMsg.msg"), &options)
            .unwrap();
    let level1 = limited.message.attachments[0].message().unwrap();
    assert!(matches!(
        level1.attachments[0].content,
        AttachmentContent::TooDeep
    ));
    assert!(level1.problems.iter().any(|p| p.kind == ProblemKind::Depth));
}

#[test]
fn ole_storage_attachment() {
    let m = open("aspose-email-net/MSG file with RTF Formatting.msg").message;
    let a = &m.attachments[0];
    assert_eq!(a.method(), Some(tags::attach_method::STORAGE));
    let AttachmentContent::Storage(storage) = &a.content else {
        panic!("{:?}", a.content)
    };
    assert_eq!(
        storage.clsid.to_string(),
        "0003000C-0000-0000-C000-000000000046"
    );
    let streams: Vec<(&str, usize)> = storage
        .entries
        .iter()
        .filter_map(|e| match e {
            StorageEntry::Stream { name, data } => Some((name.as_str(), data.len())),
            StorageEntry::Storage { .. } => None,
        })
        .collect();
    assert!(streams.contains(&("\u{1}Ole10Native", 470)));
    assert_eq!(
        a.properties.get_tag(0x3701_000D).map(|p| &p.value),
        Some(&PropertyValue::Ok(Value::Object))
    );
}

#[test]
fn rtf_size_problems_are_flags() {
    let m = open("aspose-email-net/message.msg").message;
    let rtf = m.rtf.clone().unwrap();
    assert_eq!(
        rtf.flags,
        [RtfFlag::RawSizeMismatch {
            declared: 302,
            actual: 290
        }]
    );
    let text = rtf.rtf.unwrap();
    assert_eq!(text.len(), 290);
    assert!(text.starts_with(b"{\\rtf1"));
    // The ANSI strings without any code page property: the default.
    assert_eq!(m.code_page.source, CodePageSource::Default);
    assert_eq!(m.subject(), Some("creating an outlook message file"));
}

#[test]
fn malformed_compound_files_are_errors() {
    for rel in [
        "msgreader-hiraoka/cyclicDirTree.msg",
        "msgreader-hiraoka/cyclicFatRing.msg",
    ] {
        assert!(
            matches!(MsgFile::from_bytes(&fixture(rel)), Err(Error::Cfb(_))),
            "{rel}"
        );
    }
    assert!(matches!(
        MsgFile::from_bytes(b"not a compound file"),
        Err(Error::NotCompoundFile)
    ));
    assert!(matches!(
        MsgFile::from_bytes(b""),
        Err(Error::NotCompoundFile)
    ));
}
