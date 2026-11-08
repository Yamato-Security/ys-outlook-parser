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
