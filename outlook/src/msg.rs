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

//! `.msg` and `.oft` files ([MS-OXMSG]) as [`Item`]s.
//!
//! [MS-OXMSG]: https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxmsg/

use std::io::{Read, Seek};

use outlook_msg::{AttachmentContent, MsgFile, PropertyValue};

use crate::item::{AttachmentParts, Item};
use crate::mapi::{NameId, Property, PropertyName, Value};

pub use outlook_msg::{Error, FileKind, Options};

/// A `.msg` or `.oft` file read as an item.
#[derive(Debug, Clone, PartialEq)]
pub struct MsgItem {
    /// What the root storage's CLSID says the file is: a message, a template or neither.
    pub kind: FileKind,
    /// The root storage's CLSID, as `00020D0B-0000-0000-C000-000000000046`.
    pub clsid: String,
    /// The compound file's major version (3 or 4).
    pub cfb_version: u16,
    /// The message, with its embedded messages in its attachments.
    pub item: Item,
    /// Problems with the whole file (its compound file structure, its named-property map).
    /// Those of the message and its parts are in [`Item::problems`] and
    /// [`Attachment::problems`](crate::Attachment::problems).
    pub problems: Vec<String>,
}

impl MsgItem {
    /// Reads a file from a reader; nothing is written to it.
    pub fn from_reader(reader: impl Read + Seek, options: &Options) -> Result<MsgItem, Error> {
        let file = MsgFile::from_reader_with(reader, options)?;
        Ok(MsgItem::from_file(&file))
    }

    /// Reads a file from its bytes.
    pub fn from_bytes(data: &[u8], options: &Options) -> Result<MsgItem, Error> {
        let file = MsgFile::from_bytes_with(data, options)?;
        Ok(MsgItem::from_file(&file))
    }

    /// The item of a file `outlook_msg` read.
    pub fn from_file(file: &MsgFile) -> MsgItem {
        MsgItem {
            kind: file.kind(),
            clsid: file.clsid.to_string(),
            cfb_version: file.cfb_version,
            item: item(&file.message),
            problems: file.problems.iter().map(ToString::to_string).collect(),
        }
    }
}

fn item(message: &outlook_msg::Message) -> Item {
    let mut problems: Vec<String> = message.problems.iter().map(ToString::to_string).collect();
    let recipients = message
        .recipients
        .iter()
        .map(|recipient| properties(&recipient.properties))
        .collect();
    let attachments = message
        .attachments
        .iter()
        .map(|attachment| {
            let mut parts = AttachmentParts {
                properties: properties(&attachment.properties),
                data: attachment.data().map(<[u8]>::to_vec),
                ..AttachmentParts::default()
            };
            match &attachment.content {
                AttachmentContent::Message(embedded) => {
                    parts.embedded = Some(Box::new(item(embedded)));
                }
                AttachmentContent::TooDeep => parts
                    .problems
                    .push("an embedded message nested too deep: not read".into()),
                AttachmentContent::None
                | AttachmentContent::Binary
                | AttachmentContent::Storage(_) => {}
            }
            parts
        })
        .collect();
    if message.header.is_none() {
        problems.push("no property stream header".into());
    }
    Item::build(
        properties(&message.properties),
        recipients,
        attachments,
        problems,
    )
}

fn properties(properties: &outlook_msg::Properties) -> Vec<Property> {
    properties
        .iter()
        .map(|property| Property {
            id: property.id,
            kind: property.type_code,
            value: match &property.value {
                PropertyValue::Ok(value) => self::value(value),
                PropertyValue::Unsupported(raw) => Value::Unsupported(raw.clone()),
                PropertyValue::Damaged {
                    recovered,
                    raw,
                    reason,
                } => Value::Damaged {
                    recovered: recovered.as_ref().map(|value| Box::new(self::value(value))),
                    raw: raw.clone(),
                    reason: reason.clone(),
                },
            },
            name: property.named.as_ref().map(|named| PropertyName {
                set: named.guid.0,
                id: match &named.name {
                    outlook_msg::PropertyName::Id(lid) => NameId::Number(*lid),
                    outlook_msg::PropertyName::Name(name) => NameId::Text(name.to_string()),
                },
            }),
        })
        .collect()
}

fn text(text: &outlook_msg::Text) -> Value {
    Value::String8 {
        bytes: text.raw().to_vec(),
        text: text.as_str().to_owned(),
    }
}

fn value(value: &outlook_msg::Value) -> Value {
    use outlook_msg::Value as V;
    let many = |values: Vec<Value>| Value::Multiple(values);
    match value {
        V::Null => Value::Null,
        V::Integer16(v) => Value::Integer16(*v),
        V::Integer32(v) => Value::Integer32(*v),
        V::Floating32(v) => Value::Floating32(*v),
        V::Floating64(v) => Value::Floating64(*v),
        V::Currency(v) => Value::Currency(*v),
        V::FloatingTime(v) => Value::FloatingTime(*v),
        V::ErrorCode(v) => Value::ErrorCode(*v as u32),
        V::Boolean(v) => Value::Boolean(*v),
        V::Integer64(v) => Value::Integer64(*v),
        V::String8(t) => text(t),
        V::Unicode(t) => Value::String(t.as_str().to_owned()),
        V::Time(v) => Value::Time(*v),
        V::Guid(g) => Value::Guid(g.0),
        V::Binary(b) => Value::Binary(b.clone()),
        V::Object => Value::Object,
        V::MultipleInteger16(v) => many(v.iter().map(|&v| Value::Integer16(v)).collect()),
        V::MultipleInteger32(v) => many(v.iter().map(|&v| Value::Integer32(v)).collect()),
        V::MultipleFloating32(v) => many(v.iter().map(|&v| Value::Floating32(v)).collect()),
        V::MultipleFloating64(v) => many(v.iter().map(|&v| Value::Floating64(v)).collect()),
        V::MultipleCurrency(v) => many(v.iter().map(|&v| Value::Currency(v)).collect()),
        V::MultipleFloatingTime(v) => many(v.iter().map(|&v| Value::FloatingTime(v)).collect()),
        V::MultipleInteger64(v) => many(v.iter().map(|&v| Value::Integer64(v)).collect()),
        V::MultipleString8(v) => many(v.iter().map(text).collect()),
        V::MultipleUnicode(v) => many(
            v.iter()
                .map(|t| Value::String(t.as_str().to_owned()))
                .collect(),
        ),
        V::MultipleTime(v) => many(v.iter().map(|&v| Value::Time(v)).collect()),
        V::MultipleGuid(v) => many(v.iter().map(|g| Value::Guid(g.0)).collect()),
        V::MultipleBinary(v) => many(v.iter().map(|b| Value::Binary(b.clone())).collect()),
    }
}
