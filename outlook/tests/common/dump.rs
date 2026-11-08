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

//! What is read from a PST or OST file, as TSV lines in the layout of `tests/oracle/pff_dump.py`
//! (libpff), for a field-by-field comparison: `examples/pst_dump.rs` and `tests/pst_oracle.rs`.

use std::io::{self, Write};

use outlook::pst::PstStore;
use outlook::{Item, Property, Value};
use sha2::{Digest, Sha256};

/// Values longer than this are written as their SHA-256 and length.
const LIMIT: usize = 64;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn value_text(bytes: &[u8]) -> String {
    if bytes.len() > LIMIT {
        format!("sha256:{}:{}", hex(&Sha256::digest(bytes)), bytes.len())
    } else {
        hex(bytes)
    }
}

/// The bytes of a value as stored, as libpff gives them.
fn bytes(value: &Value) -> Option<Vec<u8>> {
    Some(match value {
        Value::Null | Value::Object => return None,
        Value::Integer16(v) => v.to_le_bytes().to_vec(),
        Value::Integer32(v) => v.to_le_bytes().to_vec(),
        Value::Integer64(v) | Value::Currency(v) | Value::Time(v) => v.to_le_bytes().to_vec(),
        Value::Floating32(v) => v.to_le_bytes().to_vec(),
        Value::Floating64(v) | Value::FloatingTime(v) => v.to_le_bytes().to_vec(),
        Value::ErrorCode(v) => v.to_le_bytes().to_vec(),
        Value::Boolean(v) => vec![u8::from(*v)],
        Value::String(text) => text.encode_utf16().flat_map(u16::to_le_bytes).collect(),
        Value::String8 { bytes, .. } | Value::Binary(bytes) | Value::Unsupported(bytes) => {
            bytes.clone()
        }
        Value::Guid(guid) => guid.to_vec(),
        Value::Multiple(values) => multiple(values)?,
        Value::Damaged { raw, .. } => raw.clone(),
    })
}

/// A multi-valued property as a PST stores it: fixed-size values one after another; variable-size
/// ones as a count, an offset to each value, and the values ([MS-PST] 2.3.3.4.2).
fn multiple(values: &[Value]) -> Option<Vec<u8>> {
    let variable = values.first().is_some_and(|v| {
        matches!(
            v.best_effort(),
            Some(Value::String(_) | Value::String8 { .. } | Value::Binary(_))
        )
    });
    let parts: Vec<Vec<u8>> = values.iter().map(bytes).collect::<Option<_>>()?;
    if !variable {
        return Some(parts.concat());
    }
    let mut out = Vec::new();
    out.extend((parts.len() as u32).to_le_bytes());
    let mut offset = 4 + 4 * parts.len() as u32;
    for part in &parts {
        out.extend(offset.to_le_bytes());
        offset += part.len() as u32;
    }
    for part in parts {
        out.extend(part);
    }
    Some(out)
}

fn props(
    out: &mut impl Write,
    name: &str,
    scope: &str,
    owner: u32,
    index: &str,
    properties: &[Property],
) -> io::Result<()> {
    for p in properties {
        let value = match &p.value {
            Value::Object => "object".to_owned(),
            value => bytes(value).map(|b| value_text(&b)).unwrap_or_default(),
        };
        writeln!(
            out,
            "{name}\tprop\t{scope}\t{owner}\t{index}\t{:04x}\t{:04x}\t{value}",
            p.id, p.kind
        )?;
    }
    Ok(())
}

fn item(out: &mut impl Write, name: &str, node: u32, item: &Item) -> io::Result<()> {
    props(out, name, "item", node, "", &item.properties)?;
    for recipient in &item.recipients {
        props(
            out,
            name,
            "recipient",
            node,
            &recipient.index.to_string(),
            &recipient.properties,
        )?;
    }
    for attachment in &item.attachments {
        let index = attachment.index.to_string();
        // the data is kept once, in `data`
        let mut properties = attachment.properties.clone();
        for p in &mut properties {
            if p.id == 0x3701 && p.kind == 0x0102 {
                p.value = Value::Binary(attachment.data.clone().unwrap_or_default());
            }
        }
        props(out, name, "attachment", node, &index, &properties)?;
        let (size, hash) = match &attachment.data {
            Some(data) if !data.is_empty() => (data.len(), hex(&Sha256::digest(data))),
            _ => (0, String::new()),
        };
        writeln!(out, "{name}\tattach\t{node}\t{index}\t{size}\t{hash}")?;
        for problem in &attachment.problems {
            writeln!(out, "{name}\terror\tattachment\t{node}\t{index}\t{problem}")?;
        }
    }
    for problem in &item.problems {
        writeln!(out, "{name}\terror\titem\t{node}\t\t{problem}")?;
    }
    Ok(())
}

pub fn dump(out: &mut impl Write, store: io::Result<PstStore>, name: &str) -> io::Result<()> {
    let store = match store {
        Ok(store) => store,
        Err(e) => return writeln!(out, "{name}\terror\tfile\t\t\t{e}"),
    };
    let info = store.info();
    writeln!(
        out,
        "{name}\tstore\t{:?}\t{:?}\t{}\t{}\t{:?}",
        info.kind, info.format, info.version, info.client_version, info.encryption
    )?;
    props(out, name, "store", 0x21, "", &info.properties)?;
    for folder in store.folders() {
        writeln!(
            out,
            "{name}\tfolder\t{}\t{}\t{}\t{}\t{}\t{}",
            folder.node,
            folder.parent.map(|p| p.to_string()).unwrap_or_default(),
            folder.name.as_deref().unwrap_or_default(),
            folder.subfolders.len(),
            folder.messages.len(),
            folder.associated.len()
        )?;
        if let Some(problem) = &folder.problem {
            writeln!(out, "{name}\terror\tfolder\t{}\t\t{problem}", folder.node)?;
            continue;
        }
        props(out, name, "folder", folder.node, "", &folder.properties)?;
        for stored in store.items(&folder) {
            writeln!(
                out,
                "{name}\titem\t{}\t{}\t{}",
                stored.folder,
                stored.node,
                u8::from(stored.associated)
            )?;
            match &stored.item {
                Ok(read) => item(out, name, stored.node, read)?,
                Err(e) => writeln!(out, "{name}\terror\titem\t{}\t\t{e}", stored.node)?,
            }
        }
    }
    for problem in store.problems() {
        writeln!(out, "{name}\terror\tstore\t\t\t{problem}")?;
    }
    Ok(())
}
