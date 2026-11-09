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

//! Damaged input must never panic: deterministic (seeded) mutations of the fixtures, at the
//! byte level and at the level of the streams inside the compound file, and, when
//! `OUTLOOK_MSG_CORPUS` names a directory, every file under it. `OUTLOOK_MSG_MUTATION_SCALE`
//! multiplies the number of mutation rounds (and changes the seeds) for longer runs.

mod common;

use outlook_msg::{
    AttachmentContent, Message, MsgFile, PropertyValue, Storage, StorageEntry, Value,
};
use std::io::{Cursor, Read, Write};

/// `OUTLOOK_MSG_MUTATION_SCALE`, 1 by default.
fn scale() -> usize {
    std::env::var("OUTLOOK_MSG_MUTATION_SCALE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1)
}

/// xorshift64*: small, deterministic, good enough to pick mutations.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next() % n as u64) as usize
        }
    }

    fn byte(&mut self) -> u8 {
        self.next() as u8
    }
}

const FIXTURES: &[&str] = &[
    "msgreader-hiraoka/msgInMsgInMsg.msg",
    "msgreader-hiraoka/attachmentFiles.msg",
    "msgreader-hiraoka/contactAnsi.msg",
    "apache-poi/keywords.msg",
    "apache-poi/ASCII_CP1251_LCID1049.msg",
    "aspose-email-net/NewGroup.msg",
    "aspose-email-net/MSG file with RTF Formatting.msg",
];

/// Reads everything that was read, the way a consumer would.
fn touch(file: &MsgFile) -> usize {
    fn storage(s: &Storage) -> usize {
        s.entries
            .iter()
            .map(|e| match e {
                StorageEntry::Stream { data, .. } => data.len(),
                StorageEntry::Storage { storage: s, .. } => storage(s),
            })
            .sum()
    }
    fn message(m: &Message) -> usize {
        let mut n = format!("{:?}", m.properties).len();
        n += m.subject().map_or(0, str::len) + m.body().map_or(0, str::len);
        n += m.html.as_ref().map_or(0, |t| t.as_str().len());
        n += m
            .rtf
            .as_ref()
            .and_then(|r| r.rtf.as_ref())
            .map_or(0, Vec::len);
        for r in &m.recipients {
            n += format!("{:?}", r.properties).len();
        }
        for a in &m.attachments {
            n += a.data().map_or(0, <[u8]>::len) + a.file_name().map_or(0, str::len);
            n += match &a.content {
                AttachmentContent::Message(inner) => message(inner),
                AttachmentContent::Storage(s) => storage(s),
                _ => 0,
            };
        }
        n
    }
    message(&file.message)
        + file
            .all_problems()
            .iter()
            .map(|p| p.detail.len())
            .sum::<usize>()
}

fn parse(data: &[u8], what: &str) {
    let result = std::panic::catch_unwind(|| {
        if let Ok(file) = MsgFile::from_bytes(data) {
            touch(&file);
        }
    });
    assert!(result.is_ok(), "panic on {what}");
}

/// Byte-level damage: bit flips, overwritten runs, truncation.
fn mutate_bytes(rng: &mut Rng, data: &mut Vec<u8>) {
    match rng.below(5) {
        0 => {
            for _ in 0..1 + rng.below(8) {
                let i = rng.below(data.len());
                data[i] ^= 1 << rng.below(8);
            }
        }
        1 => {
            let i = rng.below(data.len());
            let len = (1 + rng.below(64)).min(data.len() - i);
            let fill = [0x00, 0xFF, rng.byte()][rng.below(3)];
            data[i..i + len].fill(fill);
        }
        2 => {
            // A 32-bit field (sector id, size, count) set to an extreme.
            let i = rng.below(data.len() / 4) * 4;
            let v: u32 = [0xFFFF_FFFF, 0xFFFF_FFFE, 0x7FFF_FFFF, 0, 1][rng.below(5)];
            if i + 4 <= data.len() {
                data[i..i + 4].copy_from_slice(&v.to_le_bytes());
            }
        }
        3 => {
            let len = 512 + rng.below(data.len().saturating_sub(512));
            data.truncate(len);
        }
        _ => {
            let i = rng.below(data.len());
            let j = rng.below(data.len());
            let len = (1 + rng.below(512)).min(data.len() - i.max(j));
            let span = data[i..i + len].to_vec();
            data[j..j + len].copy_from_slice(&span);
        }
    }
}

/// Every stream of a compound file, by path, and every storage path.
fn read_tree(data: &[u8]) -> (Vec<(String, Vec<u8>)>, Vec<String>) {
    let mut cfb = cfb::CompoundFile::open(Cursor::new(data)).unwrap();
    let entries: Vec<(String, bool)> = cfb
        .walk()
        // `/` separators on every platform (names cannot contain `\\`).
        .map(|e| (e.path().to_string_lossy().replace('\\', "/"), e.is_stream()))
        .collect();
    let mut streams = Vec::new();
    let mut storages = Vec::new();
    for (path, is_stream) in entries {
        if is_stream {
            let mut buf = Vec::new();
            cfb.open_stream(&path)
                .unwrap()
                .read_to_end(&mut buf)
                .unwrap();
            streams.push((path, buf));
        } else if path != "/" {
            storages.push(path);
        }
    }
    (streams, storages)
}

/// Writes a compound file from storage paths and streams.
fn write_tree(streams: &[(String, Vec<u8>)], storages: &[String]) -> Vec<u8> {
    let mut cfb =
        cfb::CompoundFile::create_with_version(cfb::Version::V3, Cursor::new(Vec::new())).unwrap();
    for s in storages {
        cfb.create_storage_all(s).unwrap();
    }
    for (path, data) in streams {
        if let Some((parent, _)) = path.rsplit_once('/')
            && !parent.is_empty()
        {
            cfb.create_storage_all(parent).unwrap();
        }
        cfb.create_stream(path).unwrap().write_all(data).unwrap();
    }
    cfb.flush().unwrap();
    cfb.into_inner().into_inner()
}

/// Damage inside a stream (or removing one), keeping the compound file valid.
fn mutate_stream(rng: &mut Rng, streams: &mut Vec<(String, Vec<u8>)>, storages: &mut Vec<String>) {
    // Prefer the streams this crate interprets.
    let pick = |rng: &mut Rng, streams: &[(String, Vec<u8>)]| {
        let interesting: Vec<usize> = (0..streams.len())
            .filter(|&i| {
                let name = &streams[i].0;
                name.ends_with("__properties_version1.0")
                    || name.contains("__nameid_version1.0")
                    || name.ends_with("10090102")
                    || name.contains("101F")
                    || name.contains("1102")
                    || name.contains("1003")
            })
            .collect();
        if !interesting.is_empty() && rng.below(3) > 0 {
            interesting[rng.below(interesting.len())]
        } else {
            rng.below(streams.len())
        }
    };
    if streams.is_empty() {
        return;
    }
    let i = pick(rng, streams);
    let data = &mut streams[i].1;
    match rng.below(7) {
        0 => {
            let len = rng.below(data.len() + 1);
            data.truncate(len);
        }
        1 => {
            for _ in 0..1 + rng.below(16) {
                if !data.is_empty() {
                    let j = rng.below(data.len());
                    data[j] = rng.byte();
                }
            }
        }
        2 => {
            // A size, count, offset or index field set to an extreme.
            if data.len() >= 4 {
                let j = rng.below(data.len() / 4) * 4;
                let v: u32 = [0xFFFF_FFFF, 0xFFFF_FFF0, 0x8000_0000, 0, 0x7FFF][rng.below(5)];
                data[j..j + 4].copy_from_slice(&v.to_le_bytes());
            }
        }
        3 => {
            for _ in 0..rng.below(100) {
                data.push(rng.byte());
            }
        }
        4 => {
            // Lone surrogates and odd lengths for UTF-16.
            data.extend_from_slice(&[0x00, 0xD8, 0x41]);
        }
        5 => {
            streams.remove(i);
        }
        _ => {
            if !storages.is_empty() {
                let s = storages.remove(rng.below(storages.len()));
                streams.retain(|(p, _)| !p.starts_with(&format!("{s}/")));
                storages.retain(|p| !p.starts_with(&format!("{s}/")));
            }
        }
    }
}

#[test]
fn byte_mutations_do_not_panic() {
    let mut rng = Rng(0x5EED_0F0F_1234_5678 ^ scale() as u64);
    let mut opened = 0;
    for rel in FIXTURES {
        let original = common::fixture(rel);
        for round in 0..250 * scale() {
            let mut data = original.clone();
            for _ in 0..1 + rng.below(3) {
                mutate_bytes(&mut rng, &mut data);
            }
            parse(&data, &format!("{rel}, byte mutation round {round}"));
            opened += usize::from(MsgFile::from_bytes(&data).is_ok());
        }
    }
    // Some mutations must leave a readable file, or this tests only the CFB layer.
    assert!(opened > 200, "only {opened} mutated files opened");
}

#[test]
fn stream_mutations_do_not_panic() {
    let mut rng = Rng(0xC0FF_EE00_DEAD_BEEF ^ scale() as u64);
    let mut problems = 0;
    for rel in FIXTURES {
        let (streams, storages) = read_tree(&common::fixture(rel));
        for round in 0..120 * scale() {
            let (mut s, mut d) = (streams.clone(), storages.clone());
            for _ in 0..1 + rng.below(4) {
                mutate_stream(&mut rng, &mut s, &mut d);
            }
            let data = write_tree(&s, &d);
            parse(&data, &format!("{rel}, stream mutation round {round}"));
            let file = MsgFile::from_bytes(&data).expect("a valid compound file opens");
            problems += file.all_problems().len();
        }
    }
    assert!(problems > 100, "only {problems} problems reported");
}

#[test]
fn deep_nesting_is_capped() {
    // Attachments nested 20 levels deep (more than Options::max_depth), each holding the next
    // as an embedded message. (Deeper files, up to 5000 levels, are in the fuzz corpus.)
    let mut storages = Vec::new();
    let mut streams = Vec::new();
    let mut path = String::new();
    streams.push(("/__properties_version1.0".to_owned(), vec![0; 32]));
    for _ in 0..20 {
        path.push_str("/__attach_version1.0_#00000000");
        storages.push(path.clone());
        let mut props = vec![0; 8];
        // PidTagAttachMethod = afEmbeddedMessage.
        props.extend_from_slice(&0x3705_0003u32.to_le_bytes());
        props.extend_from_slice(&[6, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0]);
        streams.push((format!("{path}/__properties_version1.0"), props));
        path.push_str("/__substg1.0_3701000D");
        storages.push(path.clone());
        streams.push((format!("{path}/__properties_version1.0"), vec![0; 24]));
    }
    let data = write_tree(&streams, &storages);
    let file = MsgFile::from_bytes(&data).unwrap();
    let mut depth = 0;
    let mut m = &file.message;
    while let Some(inner) = m.attachments.first().and_then(|a| a.message()) {
        m = inner;
        depth += 1;
    }
    assert_eq!(depth, outlook_msg::Options::default().max_depth);
    assert!(matches!(
        m.attachments[0].content,
        AttachmentContent::TooDeep
    ));
}

/// The directory entries of a version 3 compound file: (offset in the file, entry bytes).
fn directory_entries(data: &[u8]) -> Vec<usize> {
    let fat_sector = u32::from_le_bytes(data[0x4C..0x50].try_into().unwrap()) as usize;
    let fat = &data[512 * (1 + fat_sector)..512 * (2 + fat_sector)];
    let mut sector = u32::from_le_bytes(data[0x30..0x34].try_into().unwrap()) as usize;
    let mut out = Vec::new();
    while sector < 128 && out.len() < 1024 {
        let start = 512 * (1 + sector);
        out.extend((0..4).map(|k| start + 128 * k));
        sector = u32::from_le_bytes(fat[4 * sector..4 * sector + 4].try_into().unwrap()) as usize;
    }
    out
}

/// The stream bytes a value was decoded from.
fn value_bytes(v: &Value) -> usize {
    match v {
        Value::String8(t) | Value::Unicode(t) => t.raw().len(),
        Value::Binary(b) => b.len(),
        Value::MultipleString8(ts) | Value::MultipleUnicode(ts) => {
            ts.iter().map(|t| t.raw().len()).sum()
        }
        Value::MultipleBinary(bs) => bs.iter().map(Vec::len).sum(),
        _ => 0,
    }
}

#[test]
fn multivalue_lengths_detect_truncation_without_discarding_elements() {
    for (ty, raw) in [
        (0x1102u32, b"data".as_slice()),
        (0x101E, b"text\0".as_slice()),
        (0x101F, b"t\0e\0x\0t\0\0\0".as_slice()),
    ] {
        // A complete length stream and all expected element streams exist, but one
        // element's bytes disagree with its recorded length in either direction.
        for adjustment in [-1i64, 1] {
            let declared = (raw.len() as i64 + adjustment) as u32;
            let mut lengths = declared.to_le_bytes().to_vec();
            if ty == 0x1102 {
                lengths.extend([0xFF; 4]); // reserved: ignored even when nonzero
            }
            let tag = 0x3001_0000 | ty;
            let streams = vec![
                ("/__properties_version1.0".into(), vec![0; 32]),
                (format!("/__substg1.0_{tag:08X}"), lengths.clone()),
                (format!("/__substg1.0_{tag:08X}-00000000"), raw.to_vec()),
            ];
            let file = MsgFile::from_bytes(&write_tree(&streams, &[])).unwrap();
            let property = file.message.properties.get_tag(tag).unwrap();
            let PropertyValue::Damaged {
                recovered: Some(value),
                raw: stored_lengths,
                reason,
            } = &property.value
            else {
                panic!("incorrect element length was presented as clean: {property:?}");
            };
            assert_eq!(stored_lengths, &lengths);
            assert!(reason.contains("element 0"));
            assert!(reason.contains(&declared.to_string()));
            assert_eq!(value_bytes(value), raw.len());
            match value {
                Value::MultipleBinary(values) => assert_eq!(values[0], raw),
                Value::MultipleString8(values) | Value::MultipleUnicode(values) => {
                    assert_eq!(values[0].raw(), raw);
                    assert_eq!(values[0].as_str(), "text");
                }
                other => panic!("unexpected recovered value: {other:?}"),
            }
        }
    }
}

#[test]
fn matching_multivalue_lengths_are_clean_and_ignore_binary_reserved_bytes() {
    for (ty, raw) in [
        (0x1102u32, b"data".as_slice()),
        (0x101E, b"text\0".as_slice()),
        (0x101F, b"t\0e\0x\0t\0\0\0".as_slice()),
    ] {
        let mut lengths = (raw.len() as u32).to_le_bytes().to_vec();
        if ty == 0x1102 {
            lengths.extend([0xFF; 4]);
        }
        let tag = 0x3001_0000 | ty;
        let streams = vec![
            ("/__properties_version1.0".into(), vec![0; 32]),
            (format!("/__substg1.0_{tag:08X}"), lengths),
            (format!("/__substg1.0_{tag:08X}-00000000"), raw.to_vec()),
        ];
        let file = MsgFile::from_bytes(&write_tree(&streams, &[])).unwrap();
        assert!(matches!(
            file.message.properties.get_tag(tag).unwrap().value,
            PropertyValue::Ok(_)
        ));
    }
}

#[test]
fn sparse_multivalue_indices_and_untrusted_lengths_keep_recovered_data() {
    // Neither a four-gigabyte declaration nor an enormous stream index should
    // request that much memory or turn an extra element into an indexed lookup.
    let lengths = [u32::MAX.to_le_bytes(), [0; 4]].concat();
    let streams = vec![
        ("/__properties_version1.0".into(), vec![0; 32]),
        ("/__substg1.0_30011102".into(), lengths),
        ("/__substg1.0_30011102-00000000".into(), b"first".to_vec()),
        ("/__substg1.0_30011102-FFFFFFFF".into(), b"last".to_vec()),
    ];
    let file = MsgFile::from_bytes(&write_tree(&streams, &[])).unwrap();
    let PropertyValue::Damaged {
        recovered: Some(Value::MultipleBinary(values)),
        reason,
        ..
    } = &file.message.properties.get_tag(0x3001_1102).unwrap().value
    else {
        panic!("missing recovered binary values");
    };
    assert_eq!(values, &[b"first".to_vec(), b"last".to_vec()]);
    assert!(reason.contains("4294967295"));
    assert!(reason.contains("1 element streams beyond"));
}

#[test]
fn streams_sharing_a_sector_chain_are_read_within_a_budget() {
    // Point every stream at the sector chain of the largest one: a small file that expands to
    // much more data than it holds. The total read is capped; what is cut is reported.
    let mut data = common::fixture("msgreader-hiraoka/msgInMsgInMsg.msg");
    let entries = directory_entries(&data);
    let (start, size) = entries
        .iter()
        .filter(|&&e| data[e + 66] == 2)
        .map(|&e| {
            let start = u32::from_le_bytes(data[e + 116..e + 120].try_into().unwrap());
            let size = u32::from_le_bytes(data[e + 120..e + 124].try_into().unwrap());
            (start, size)
        })
        .max_by_key(|&(_, size)| size)
        .unwrap();
    assert!(size >= 4096, "the largest stream is in regular sectors");
    for &e in &entries {
        if data[e + 66] == 2 {
            data[e + 116..e + 120].copy_from_slice(&start.to_le_bytes());
            data[e + 120..e + 124].copy_from_slice(&size.to_le_bytes());
        }
    }
    let file = MsgFile::from_bytes(&data).unwrap();
    let problems = file.all_problems();
    assert!(
        problems
            .iter()
            .any(|p| p.kind == outlook_msg::ProblemKind::Budget)
    );
    fn raw_total(m: &Message) -> usize {
        let mut n = 0;
        for p in m
            .properties
            .iter()
            .chain(m.recipients.iter().flat_map(|r| r.properties.iter()))
            .chain(m.attachments.iter().flat_map(|a| a.properties.iter()))
        {
            n += match &p.value {
                PropertyValue::Unsupported(raw) | PropertyValue::Damaged { raw, .. } => raw.len(),
                PropertyValue::Ok(v) => value_bytes(v),
            };
        }
        n + m
            .attachments
            .iter()
            .filter_map(|a| a.message())
            .map(raw_total)
            .sum::<usize>()
    }
    assert!(raw_total(&file.message) <= 2 * data.len() + (64 << 10));
}

#[test]
fn stream_lengths_past_the_end_of_the_file_are_bounded() {
    let mut data = common::fixture("apache-poi/keywords.msg");
    for e in directory_entries(&data) {
        if data[e + 66] == 2 {
            data[e + 120..e + 124].copy_from_slice(&0x7FFF_FFF0u32.to_le_bytes());
        }
    }
    parse(&data, "huge stream lengths");
    if let Ok(file) = MsgFile::from_bytes(&data) {
        for p in file.message.properties.iter() {
            if let PropertyValue::Damaged { raw, .. } = &p.value {
                assert!(raw.len() <= data.len());
            }
        }
    }
}

/// Renames the directory entry called `from` (UTF-16, same length or shorter) to `to`.
fn rename_entry(data: &mut [u8], from: &str, to: &str) {
    let from16: Vec<u8> = from.encode_utf16().flat_map(u16::to_le_bytes).collect();
    for e in directory_entries(data) {
        let len = u16::from_le_bytes([data[e + 64], data[e + 65]]) as usize;
        if len == from16.len() + 2 && data[e..e + from16.len()] == from16[..] {
            let to16: Vec<u8> = to.encode_utf16().flat_map(u16::to_le_bytes).collect();
            data[e..e + 64].fill(0);
            data[e..e + to16.len()].copy_from_slice(&to16);
            data[e + 64..e + 66].copy_from_slice(&(to16.len() as u16 + 2).to_le_bytes());
            return;
        }
    }
    panic!("no entry {from}");
}

#[test]
fn storage_names_that_are_path_components_are_not_followed() {
    // An OLE-object attachment whose storage holds storages named "", "." and "..": as paths
    // they would lead back to an ancestor, again and again.
    for (a, b) in [("", ".."), (".", ".."), ("..", "."), ("..", "")] {
        let att = "/__attach_version1.0_#00000000";
        let mut props = vec![0; 8];
        // PidTagAttachMethod = afStorage.
        props.extend_from_slice(&0x3705_0003u32.to_le_bytes());
        props.extend_from_slice(&[6, 0, 0, 0, 6, 0, 0, 0, 0, 0, 0, 0]);
        let object = format!("{att}/__substg1.0_3701000D");
        let storages = vec![
            att.to_owned(),
            object.clone(),
            format!("{object}/QQ"),
            format!("{object}/QQ/RR"),
        ];
        let streams = vec![
            ("/__properties_version1.0".to_owned(), vec![0; 32]),
            (format!("{att}/__properties_version1.0"), props),
            (format!("{object}/QQ/RR/data"), vec![1; 10]),
        ];
        let mut data = write_tree(&streams, &storages);
        rename_entry(&mut data, "QQ", a);
        rename_entry(&mut data, "RR", b);
        let file = MsgFile::from_bytes(&data).unwrap();
        let AttachmentContent::Storage(storage) = &file.message.attachments[0].content else {
            panic!("{:?}", file.message.attachments[0].content)
        };
        assert!(storage.entries.len() <= 1, "{a:?}/{b:?}");
        assert!(
            file.all_problems()
                .iter()
                .any(|p| p.kind == outlook_msg::ProblemKind::UnknownEntry),
            "{a:?}/{b:?}"
        );
    }
}

#[test]
fn property_streams_with_the_wrong_header_size_are_read() {
    // PidTagMessageFlags = 1, written after a 24-byte (embedded-message) header at the top level.
    let mut props = vec![0; 24];
    props[16..20].copy_from_slice(&7u32.to_le_bytes());
    props.extend_from_slice(&0x0E07_0003u32.to_le_bytes());
    props.extend_from_slice(&[6, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0]);
    // The same entry listed three times.
    let entry = props[24..40].to_vec();
    props.extend_from_slice(&entry);
    props.extend_from_slice(&entry);
    let data = write_tree(&[("/__properties_version1.0".to_owned(), props)], &[]);
    let file = MsgFile::from_bytes(&data).unwrap();
    let m = &file.message;
    assert_eq!(m.properties.int(outlook_msg::tags::MESSAGE_FLAGS), Some(1));
    assert_eq!(m.header.map(|h| h.recipient_count), Some(7));
    let details: Vec<&str> = m.problems.iter().map(|p| p.detail.as_str()).collect();
    assert!(
        details.contains(&"the header is 24 bytes, not 32"),
        "{details:?}"
    );
    assert!(
        details.contains(&"property 0x0E070003 is listed 3 times; the first entry is used"),
        "{details:?}"
    );
}

/// Renames every directory entry called `from`; returns how many.
fn rename_all(data: &mut [u8], from: &str, to: &str) -> usize {
    let mut n = 0;
    let from16: Vec<u8> = from.encode_utf16().flat_map(u16::to_le_bytes).collect();
    while directory_entries(data).into_iter().any(|e| {
        u16::from_le_bytes([data[e + 64], data[e + 65]]) as usize == from16.len() + 2
            && data[e..e + from16.len()] == from16[..]
    }) {
        rename_entry(data, from, to);
        n += 1;
    }
    n
}

fn attachment_properties(method: u8) -> Vec<u8> {
    let mut props = vec![0; 8];
    props.extend_from_slice(&0x3705_0003u32.to_le_bytes());
    props.extend_from_slice(&[6, 0, 0, 0, method, 0, 0, 0, 0, 0, 0, 0]);
    props
}

fn storage_entries(s: &Storage) -> usize {
    s.entries
        .iter()
        .map(|e| match e {
            StorageEntry::Storage { storage, .. } => 1 + storage_entries(storage),
            StorageEntry::Stream { .. } => 1,
        })
        .sum()
}

#[test]
fn names_equal_ignoring_case_are_read_once() {
    // cfb checks the order of names only between neighbours, so a storage can hold "CC" and
    // "cc"; both lead to the same entry, and following both at each of 14 levels would read
    // 2^14 storages.
    let att = "/__attach_version1.0_#00000000";
    let object = format!("{att}/__substg1.0_3701000D");
    let mut storages = vec![att.to_owned(), object.clone()];
    let mut path = object.clone();
    for _ in 0..14 {
        for name in ["AA", "BB", "DD", "CC"] {
            storages.push(format!("{path}/{name}"));
        }
        path = format!("{path}/CC");
    }
    let streams = vec![
        ("/__properties_version1.0".to_owned(), vec![0; 32]),
        (
            format!("{att}/__properties_version1.0"),
            attachment_properties(6),
        ),
    ];
    let mut data = write_tree(&streams, &storages);
    assert!(rename_all(&mut data, "BB", "cc") >= 14);
    let file = MsgFile::from_bytes(&data).unwrap();
    let AttachmentContent::Storage(storage) = &file.message.attachments[0].content else {
        panic!("{:?}", file.message.attachments[0].content)
    };
    assert!(
        storage_entries(storage) <= 4 * 14,
        "{}",
        storage_entries(storage)
    );
    assert!(
        file.all_problems()
            .iter()
            .any(|p| p.detail.contains("same name (ignoring case)"))
    );

    // The same with attachment storages holding embedded messages.
    let mut storages = Vec::new();
    let mut streams = vec![("/__properties_version1.0".to_owned(), vec![0; 32])];
    let mut message = String::new();
    for _ in 0..14 {
        for i in [0, 1, 3, 2] {
            storages.push(format!("{message}/__attach_version1.0_#0000000{i}"));
        }
        let a = format!("{message}/__attach_version1.0_#00000002");
        streams.push((
            format!("{a}/__properties_version1.0"),
            attachment_properties(5),
        ));
        message = format!("{a}/__substg1.0_3701000D");
        storages.push(message.clone());
        streams.push((format!("{message}/__properties_version1.0"), vec![0; 24]));
    }
    let mut data = write_tree(&streams, &storages);
    rename_all(
        &mut data,
        "__attach_version1.0_#00000002",
        "__ATTACH_version1.0_#00000001",
    );
    let file = MsgFile::from_bytes(&data).unwrap();
    assert!(file.message.embedded_messages().len() <= 14);
    assert!(
        file.all_problems()
            .iter()
            .any(|p| p.detail.contains("same name (ignoring case)"))
    );
}

#[test]
fn declared_stream_lengths_do_not_reserve_memory() {
    // Streams that declare 2 GiB and hold nothing.
    let mut streams = vec![("/__properties_version1.0".to_owned(), vec![0; 32])];
    for i in 0..300 {
        streams.push((format!("/__substg1.0_{:04X}0102", 0x8000 + i), vec![7]));
    }
    let mut data = write_tree(&streams, &[]);
    let name: Vec<u8> = "__substg1.0_"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    for e in directory_entries(&data) {
        if data[e..e + name.len()] == name[..] && data[e + 66] == 2 {
            data[e + 116..e + 120].copy_from_slice(&0xFFFF_FFFEu32.to_le_bytes());
            data[e + 120..e + 124].copy_from_slice(&0x7FFF_FFF0u32.to_le_bytes());
        }
    }
    let file = MsgFile::from_bytes(&data).unwrap();
    let reserved: usize = file
        .message
        .properties
        .iter()
        .map(|p| match &p.value {
            PropertyValue::Damaged { raw, .. } | PropertyValue::Unsupported(raw) => raw.capacity(),
            PropertyValue::Ok(Value::Binary(b)) => b.capacity(),
            _ => 0,
        })
        .sum();
    assert!(reserved <= data.len(), "{reserved} bytes reserved");
}

#[test]
fn overlapping_named_property_names_are_decoded_within_bounds() {
    // 2000 string-named entries: half at one 16 KB name, half at offsets inside it.
    let len = 16_000u32;
    let mut entries = Vec::new();
    for i in 0..2000u32 {
        let offset = if i % 2 == 0 { 0 } else { 4 * (i / 2 % 100) };
        entries.extend_from_slice(&offset.to_le_bytes());
        entries.extend_from_slice(&((i << 16) | (2 << 1) | 1).to_le_bytes());
    }
    let mut strings = len.to_le_bytes().to_vec();
    strings.extend(std::iter::repeat_n([b'A', 0], len as usize / 2).flatten());
    let streams = vec![
        ("/__properties_version1.0".to_owned(), vec![0; 32]),
        (
            "/__nameid_version1.0/__substg1.0_00020102".to_owned(),
            vec![],
        ),
        (
            "/__nameid_version1.0/__substg1.0_00030102".to_owned(),
            entries,
        ),
        (
            "/__nameid_version1.0/__substg1.0_00040102".to_owned(),
            strings,
        ),
    ];
    let data = write_tree(&streams, &[]);
    let file = MsgFile::from_bytes(&data).unwrap();
    let mut distinct = std::collections::HashSet::new();
    let mut held = 0;
    for e in &file.named_properties.entries {
        if let Some(outlook_msg::NamedProperty {
            name: outlook_msg::PropertyName::Name(name),
            ..
        }) = &e.named
            && distinct.insert(std::sync::Arc::as_ptr(name) as *const u8 as usize)
        {
            held += name.len();
        }
    }
    assert!(held <= 2 * data.len(), "{held} bytes of names held");
    assert!(file.problems.iter().any(|p| p.detail.contains("overlaps")));
}

#[test]
fn truncated_rtf_is_decompressed_as_far_as_it_goes() {
    let text: String = (0..60)
        .map(|i| format!("{{\\rtf1\\ansi word{} }}", i % 37))
        .collect();
    let good = compressed_rtf::compress_rtf(&text).unwrap();
    for cut in 17..good.len() {
        let streams = vec![
            ("/__properties_version1.0".to_owned(), vec![0; 32]),
            ("/__substg1.0_10090102".to_owned(), good[..cut].to_vec()),
        ];
        let file = MsgFile::from_bytes(&write_tree(&streams, &[])).unwrap();
        let rtf = file.message.rtf.as_ref().unwrap();
        let out = rtf
            .rtf
            .as_ref()
            .unwrap_or_else(|| panic!("cut at {cut}: {:?}", rtf.flags));
        assert!(text.as_bytes().starts_with(out), "cut at {cut}");
        assert!(
            rtf.flags.contains(&outlook_msg::RtfFlag::Truncated),
            "cut at {cut}"
        );
    }
}

#[test]
fn corpus_does_not_panic() {
    let Some(dir) = std::env::var_os("OUTLOOK_MSG_CORPUS") else {
        eprintln!("OUTLOOK_MSG_CORPUS is not set: skipped");
        return;
    };
    let mut files = Vec::new();
    let mut stack = vec![std::path::PathBuf::from(dir)];
    while let Some(d) = stack.pop() {
        for entry in std::fs::read_dir(&d).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                stack.push(path);
            } else {
                files.push(path);
            }
        }
    }
    files.sort();
    let (mut ok, mut errors, mut problems) = (0, 0, 0);
    for path in &files {
        let data = std::fs::read(path).unwrap();
        parse(&data, &path.display().to_string());
        match MsgFile::from_bytes(&data) {
            Ok(file) => {
                ok += 1;
                problems += file.all_problems().len();
            }
            Err(_) => errors += 1,
        }
    }
    eprintln!(
        "{} files: {ok} read ({problems} problems), {errors} not readable",
        files.len()
    );
}
