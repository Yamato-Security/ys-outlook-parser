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

//! The crate's side of the oracle comparison: the same line format as
//! `tests/oracle/extract_msg_dump.py` (see its header for the keys and values).

#![allow(dead_code)]

use outlook_msg::{AttachmentContent, Message, MsgFile, Properties, PropertyValue, Text, Value};
use sha2::{Digest, Sha256};
use std::fmt::Write;

/// `LEN:SHA`, the first 16 hex digits of SHA-256.
pub fn sha(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    let mut s = format!("{}:", data.len());
    for b in &digest[..8] {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// A JSON string as Python's `json.dumps(s, ensure_ascii=True)` writes it.
pub fn js(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            ' '..='~' => out.push(c),
            _ => {
                let mut units = [0u16; 2];
                for u in c.encode_utf16(&mut units) {
                    let _ = write!(out, "\\u{u:04x}");
                }
            }
        }
    }
    out.push('"');
    out
}

fn text(prefix: &str, t: &Text) -> String {
    format!("{prefix}:{}", js(t.as_str()))
}

fn apptime(days: f64) -> String {
    if days.is_finite() {
        format!("apptime:{}", (days * 86_400_000_000.0).round() as i64)
    } else {
        "apptime:nan".to_owned()
    }
}

fn list(items: impl Iterator<Item = String>) -> String {
    let items: Vec<String> = items.map(|i| js(&i)).collect();
    format!("mv:[{}]", items.join(","))
}

/// The normalized form of a value.
pub fn norm(value: &Value) -> String {
    match value {
        Value::Null => "null".to_owned(),
        Value::Integer16(v) => format!("i:{v}"),
        Value::Integer32(v) => format!("i:{v}"),
        Value::Integer64(v) => format!("i:{v}"),
        Value::Floating32(v) => format!("f32:{:08x}", v.to_bits()),
        Value::Floating64(v) => format!("f64:{:016x}", v.to_bits()),
        Value::Currency(v) => format!("cur:{v}"),
        Value::FloatingTime(v) => apptime(*v),
        Value::ErrorCode(v) => format!("err:0x{:08X}", *v as u32),
        Value::Boolean(v) => format!("bool:{v}"),
        Value::String8(t) => text("s8", t),
        Value::Unicode(t) => text("u", t),
        Value::Time(t) => format!("time:{}", t.div_euclid(10)),
        Value::Guid(g) => format!("guid:{g}"),
        Value::Binary(b) => format!("bin:{}", sha(b)),
        Value::Object => "object".to_owned(),
        Value::MultipleInteger16(v) => list(v.iter().map(|x| format!("i:{x}"))),
        Value::MultipleInteger32(v) => list(v.iter().map(|x| format!("i:{x}"))),
        Value::MultipleInteger64(v) => list(v.iter().map(|x| format!("i:{x}"))),
        Value::MultipleFloating32(v) => list(v.iter().map(|x| format!("f32:{:08x}", x.to_bits()))),
        Value::MultipleFloating64(v) => list(v.iter().map(|x| format!("f64:{:016x}", x.to_bits()))),
        Value::MultipleCurrency(v) => list(v.iter().map(|x| format!("cur:{x}"))),
        Value::MultipleFloatingTime(v) => list(v.iter().map(|x| apptime(*x))),
        Value::MultipleTime(v) => list(v.iter().map(|x| format!("time:{}", x.div_euclid(10)))),
        Value::MultipleGuid(v) => list(v.iter().map(|g| format!("guid:{g}"))),
        Value::MultipleBinary(v) => list(v.iter().map(|b| format!("bin:{}", sha(b)))),
        Value::MultipleString8(v) => list(v.iter().map(|t| text("s8", t))),
        Value::MultipleUnicode(v) => list(v.iter().map(|t| text("u", t))),
    }
}

/// The normalized form of a property value.
pub fn norm_property(value: &PropertyValue) -> String {
    match value {
        PropertyValue::Ok(v) => norm(v),
        PropertyValue::Unsupported(raw) => format!("unsupported:{}", sha(raw)),
        PropertyValue::Damaged {
            recovered: Some(v), ..
        } => norm(v),
        PropertyValue::Damaged { .. } => "missing".to_owned(),
    }
}

/// The raw stream bytes this crate keeps for a value, if any.
fn raw(value: &PropertyValue) -> Option<&[u8]> {
    match value {
        PropertyValue::Ok(Value::String8(t) | Value::Unicode(t)) => Some(t.raw()),
        PropertyValue::Ok(Value::Binary(b)) => Some(b),
        PropertyValue::Unsupported(raw) if !raw.is_empty() => Some(raw),
        _ => None,
    }
}

struct Out<'a> {
    file: &'a str,
    lines: Vec<String>,
}

impl Out<'_> {
    fn emit(&mut self, object: &str, key: &str, value: impl std::fmt::Display) {
        self.lines
            .push(format!("{}\t{object}\t{key}\t{value}", self.file));
    }

    fn properties(&mut self, object: &str, properties: &Properties) {
        for p in properties {
            let tag = format!("{:08X}", p.tag());
            if let Some(e) = &p.entry {
                self.emit(object, &format!("flags:{tag}"), e.flags);
            }
            self.emit(object, &format!("p:{tag}"), norm_property(&p.value));
            if let Some(raw) = raw(&p.value) {
                self.emit(object, &format!("r:{tag}"), sha(raw));
            }
        }
    }

    fn message(&mut self, object: &str, m: &Message) {
        match &m.header {
            Some(h) => self.emit(
                object,
                "header",
                format!(
                    "{},{},{},{}",
                    h.next_recipient_id,
                    h.next_attachment_id,
                    h.recipient_count,
                    h.attachment_count
                ),
            ),
            None => self.emit(object, "header", "None,None,None,None"),
        }
        self.properties(object, &m.properties);
        if let Some(rtf) = &m.rtf {
            match &rtf.rtf {
                Some(bytes) => {
                    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
                    self.emit(object, "rtf", sha(&bytes[..end]));
                }
                None => self.emit(object, "rtf", "ERROR:not decompressed"),
            }
        }
        self.emit(object, "count:recipients", m.recipients.len());
        for r in &m.recipients {
            self.properties(&format!("{object}/r{}", r.index), &r.properties);
        }
        self.emit(object, "count:attachments", m.attachments.len());
        for a in &m.attachments {
            let o = format!("{object}/a{}", a.index);
            self.properties(&o, &a.properties);
            let kind = match &a.content {
                AttachmentContent::None => "none",
                AttachmentContent::Binary => "binary",
                AttachmentContent::Message(_) => "message",
                AttachmentContent::Storage(_) => "storage",
                AttachmentContent::TooDeep => "toodeep",
            };
            self.emit(&o, "att:kind", kind);
            if let AttachmentContent::Message(inner) = &a.content {
                self.message(&format!("{o}/m"), inner);
            }
        }
    }
}

/// The dump lines of one file (not sorted).
pub fn dump(file: &str, data: &[u8]) -> Vec<String> {
    let mut out = Out {
        file,
        lines: Vec::new(),
    };
    match MsgFile::from_bytes(data) {
        Err(e) => out.emit("file", "open", format!("ERROR:{e}")),
        Ok(f) => {
            out.emit("file", "clsid", f.clsid);
            let mut seen = std::collections::BTreeSet::new();
            for e in &f.named_properties.entries {
                let Some(n) = &e.named else { continue };
                if !seen.insert(e.property_id) {
                    continue;
                }
                let name = match &n.name {
                    outlook_msg::PropertyName::Id(id) => format!("id:0x{id:X}"),
                    outlook_msg::PropertyName::Name(s) => format!("name:{}", js(s)),
                };
                out.emit(
                    "file",
                    &format!("named:{:04X}", e.property_id),
                    format!("{}:{name}", n.guid),
                );
            }
            out.message("m", &f.message);
        }
    }
    out.lines
}
