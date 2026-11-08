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

//! MAPI properties: types ([MS-OXCDATA] 2.11.1), values, and the property list of a message,
//! recipient or attachment.

use crate::guid::Guid;
use crate::text::Text;
use std::fmt;

/// A MAPI property type ([MS-OXCDATA] 2.11.1). The names follow `outlook_pst`'s
/// `PropertyType`, so that items read from PST files and from `.msg` files map alike.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum PropertyType {
    /// `PtypUnspecified` (0x0000): only meaningful in requests, never stored.
    Unspecified,
    /// `PtypNull` (0x0001).
    Null,
    /// `PtypInteger16` (0x0002).
    Integer16,
    /// `PtypInteger32` (0x0003).
    Integer32,
    /// `PtypFloating32` (0x0004).
    Floating32,
    /// `PtypFloating64` (0x0005).
    Floating64,
    /// `PtypCurrency` (0x0006): a 64-bit integer, scaled by 10 000.
    Currency,
    /// `PtypFloatingTime` (0x0007): days since 1899-12-30 as a double.
    FloatingTime,
    /// `PtypErrorCode` (0x000A).
    ErrorCode,
    /// `PtypBoolean` (0x000B).
    Boolean,
    /// `PtypObject` / `PtypEmbeddedTable` (0x000D): a storage, such as an embedded message.
    Object,
    /// `PtypInteger64` (0x0014).
    Integer64,
    /// `PtypString8` (0x001E): 8-bit string in a code page.
    String8,
    /// `PtypString` (0x001F): UTF-16LE string.
    Unicode,
    /// `PtypTime` (0x0040): FILETIME.
    Time,
    /// `PtypGuid` (0x0048).
    Guid,
    /// `PtypServerId` (0x00FB).
    ServerId,
    /// `PtypRestriction` (0x00FD).
    Restriction,
    /// `PtypRuleAction` (0x00FE).
    RuleAction,
    /// `PtypBinary` (0x0102).
    Binary,
    /// `PtypMultipleInteger16` (0x1002).
    MultipleInteger16,
    /// `PtypMultipleInteger32` (0x1003).
    MultipleInteger32,
    /// `PtypMultipleFloating32` (0x1004).
    MultipleFloating32,
    /// `PtypMultipleFloating64` (0x1005).
    MultipleFloating64,
    /// `PtypMultipleCurrency` (0x1006).
    MultipleCurrency,
    /// `PtypMultipleFloatingTime` (0x1007).
    MultipleFloatingTime,
    /// `PtypMultipleInteger64` (0x1014).
    MultipleInteger64,
    /// `PtypMultipleString8` (0x101E).
    MultipleString8,
    /// `PtypMultipleString` (0x101F).
    MultipleUnicode,
    /// `PtypMultipleTime` (0x1040).
    MultipleTime,
    /// `PtypMultipleGuid` (0x1048).
    MultipleGuid,
    /// `PtypMultipleBinary` (0x1102).
    MultipleBinary,
}

impl PropertyType {
    /// The type for a property type code, if it is one of [MS-OXCDATA] 2.11.1.
    pub fn from_code(code: u16) -> Option<Self> {
        use PropertyType::*;
        Some(match code {
            0x0000 => Unspecified,
            0x0001 => Null,
            0x0002 => Integer16,
            0x0003 => Integer32,
            0x0004 => Floating32,
            0x0005 => Floating64,
            0x0006 => Currency,
            0x0007 => FloatingTime,
            0x000A => ErrorCode,
            0x000B => Boolean,
            0x000D => Object,
            0x0014 => Integer64,
            0x001E => String8,
            0x001F => Unicode,
            0x0040 => Time,
            0x0048 => Guid,
            0x00FB => ServerId,
            0x00FD => Restriction,
            0x00FE => RuleAction,
            0x0102 => Binary,
            0x1002 => MultipleInteger16,
            0x1003 => MultipleInteger32,
            0x1004 => MultipleFloating32,
            0x1005 => MultipleFloating64,
            0x1006 => MultipleCurrency,
            0x1007 => MultipleFloatingTime,
            0x1014 => MultipleInteger64,
            0x101E => MultipleString8,
            0x101F => MultipleUnicode,
            0x1040 => MultipleTime,
            0x1048 => MultipleGuid,
            0x1102 => MultipleBinary,
            _ => return None,
        })
    }

    /// The property type code.
    pub fn code(self) -> u16 {
        use PropertyType::*;
        match self {
            Unspecified => 0x0000,
            Null => 0x0001,
            Integer16 => 0x0002,
            Integer32 => 0x0003,
            Floating32 => 0x0004,
            Floating64 => 0x0005,
            Currency => 0x0006,
            FloatingTime => 0x0007,
            ErrorCode => 0x000A,
            Boolean => 0x000B,
            Object => 0x000D,
            Integer64 => 0x0014,
            String8 => 0x001E,
            Unicode => 0x001F,
            Time => 0x0040,
            Guid => 0x0048,
            ServerId => 0x00FB,
            Restriction => 0x00FD,
            RuleAction => 0x00FE,
            Binary => 0x0102,
            MultipleInteger16 => 0x1002,
            MultipleInteger32 => 0x1003,
            MultipleFloating32 => 0x1004,
            MultipleFloating64 => 0x1005,
            MultipleCurrency => 0x1006,
            MultipleFloatingTime => 0x1007,
            MultipleInteger64 => 0x1014,
            MultipleString8 => 0x101E,
            MultipleUnicode => 0x101F,
            MultipleTime => 0x1040,
            MultipleGuid => 0x1048,
            MultipleBinary => 0x1102,
        }
    }

    /// Size of a value of a fixed-size type, as stored inline in a property stream entry (or of
    /// one element of a multi-valued fixed-size type); `None` for variable-size types.
    pub fn fixed_size(self) -> Option<usize> {
        use PropertyType::*;
        Some(match self {
            Null => 0,
            Boolean => 1,
            Integer16 | MultipleInteger16 => 2,
            Integer32 | Floating32 | ErrorCode | MultipleInteger32 | MultipleFloating32 => 4,
            Floating64 | Currency | FloatingTime | Integer64 | Time | MultipleFloating64
            | MultipleCurrency | MultipleFloatingTime | MultipleInteger64 | MultipleTime => 8,
            Guid | MultipleGuid => 16,
            _ => return None,
        })
    }
}

/// A decoded property value.
#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    /// `PtypNull`.
    Null,
    /// `PtypInteger16`.
    Integer16(i16),
    /// `PtypInteger32`.
    Integer32(i32),
    /// `PtypFloating32`.
    Floating32(f32),
    /// `PtypFloating64`.
    Floating64(f64),
    /// `PtypCurrency`: the stored integer (the amount times 10 000).
    Currency(i64),
    /// `PtypFloatingTime`: days since 1899-12-30 (see
    /// [`floating_time_to_filetime`](crate::floating_time_to_filetime)).
    FloatingTime(f64),
    /// `PtypErrorCode` (an `HRESULT`, as stored).
    ErrorCode(i32),
    /// `PtypBoolean`: the first byte of the value is not zero.
    Boolean(bool),
    /// `PtypInteger64`.
    Integer64(i64),
    /// `PtypString8`, decoded in the message's code page.
    String8(Text),
    /// `PtypString`.
    Unicode(Text),
    /// `PtypTime`: FILETIME ticks (see [`format_filetime`](crate::format_filetime)).
    Time(i64),
    /// `PtypGuid`.
    Guid(Guid),
    /// `PtypBinary`.
    Binary(Vec<u8>),
    /// `PtypObject`: the value is the storage of the same name. For attachments, see
    /// [`Attachment::content`](crate::Attachment::content).
    Object,
    /// `PtypMultipleInteger16`.
    MultipleInteger16(Vec<i16>),
    /// `PtypMultipleInteger32`.
    MultipleInteger32(Vec<i32>),
    /// `PtypMultipleFloating32`.
    MultipleFloating32(Vec<f32>),
    /// `PtypMultipleFloating64`.
    MultipleFloating64(Vec<f64>),
    /// `PtypMultipleCurrency`.
    MultipleCurrency(Vec<i64>),
    /// `PtypMultipleFloatingTime`.
    MultipleFloatingTime(Vec<f64>),
    /// `PtypMultipleInteger64`.
    MultipleInteger64(Vec<i64>),
    /// `PtypMultipleString8`.
    MultipleString8(Vec<Text>),
    /// `PtypMultipleString`.
    MultipleUnicode(Vec<Text>),
    /// `PtypMultipleTime`.
    MultipleTime(Vec<i64>),
    /// `PtypMultipleGuid`.
    MultipleGuid(Vec<Guid>),
    /// `PtypMultipleBinary`.
    MultipleBinary(Vec<Vec<u8>>),
}

impl Value {
    /// Whether this is an empty string, empty binary or a multi-valued property with no
    /// values. Fixed-size values are never empty.
    pub fn is_empty(&self) -> bool {
        match self {
            Value::String8(t) | Value::Unicode(t) => t.is_empty(),
            Value::Binary(b) => b.is_empty(),
            Value::MultipleInteger16(v) => v.is_empty(),
            Value::MultipleInteger32(v) => v.is_empty(),
            Value::MultipleFloating32(v) => v.is_empty(),
            Value::MultipleFloating64(v) | Value::MultipleFloatingTime(v) => v.is_empty(),
            Value::MultipleCurrency(v) | Value::MultipleInteger64(v) | Value::MultipleTime(v) => {
                v.is_empty()
            }
            Value::MultipleString8(v) | Value::MultipleUnicode(v) => v.is_empty(),
            Value::MultipleGuid(v) => v.is_empty(),
            Value::MultipleBinary(v) => v.is_empty(),
            _ => false,
        }
    }

    /// The string of a `String8` or `Unicode` value.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::String8(t) | Value::Unicode(t) => Some(t.as_str()),
            _ => None,
        }
    }

    /// The [`Text`] of a `String8` or `Unicode` value.
    pub fn as_text(&self) -> Option<&Text> {
        match self {
            Value::String8(t) | Value::Unicode(t) => Some(t),
            _ => None,
        }
    }

    /// An integer value (`Integer16`, `Integer32`, `Integer64`, `ErrorCode`), widened.
    pub fn as_i64(&self) -> Option<i64> {
        match *self {
            Value::Integer16(v) => Some(v.into()),
            Value::Integer32(v) | Value::ErrorCode(v) => Some(v.into()),
            Value::Integer64(v) => Some(v),
            _ => None,
        }
    }

    /// The bytes of a `Binary` value.
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Value::Binary(b) => Some(b),
            _ => None,
        }
    }

    /// The FILETIME ticks of a `Time` value.
    pub fn as_time(&self) -> Option<i64> {
        match *self {
            Value::Time(t) => Some(t),
            _ => None,
        }
    }

    /// A `Boolean` value.
    pub fn as_bool(&self) -> Option<bool> {
        match *self {
            Value::Boolean(b) => Some(b),
            _ => None,
        }
    }
}

/// The state of a property's value. A property that is not in the file at all is simply not in
/// its [`Properties`] ("absent"); an empty value is [`PropertyValue::Ok`] with
/// [`Value::is_empty`].
#[derive(Clone, Debug, PartialEq)]
pub enum PropertyValue {
    /// The value, decoded.
    Ok(Value),
    /// A property type this crate does not decode (`PtypServerId`, `PtypRestriction`,
    /// `PtypRuleAction`, `PtypUnspecified`, or a code that is not a type at all): the bytes as
    /// stored (the stream, or the 8 value bytes of the property stream entry).
    Unsupported(Vec<u8>),
    /// The value is damaged: what could be recovered from it, the bytes as stored, and why.
    Damaged {
        /// What could be decoded anyway (for example the elements of a multi-valued property
        /// that were present, or a stream read only in part).
        recovered: Option<Value>,
        /// The bytes as stored, as far as they could be read.
        raw: Vec<u8>,
        /// Why the value is damaged.
        reason: String,
    },
}

impl PropertyValue {
    /// The value if it was decoded cleanly.
    pub fn ok(&self) -> Option<&Value> {
        match self {
            PropertyValue::Ok(v) => Some(v),
            _ => None,
        }
    }

    /// The decoded value, or what could be recovered from a damaged one.
    pub fn best_effort(&self) -> Option<&Value> {
        match self {
            PropertyValue::Ok(v) => Some(v),
            PropertyValue::Damaged { recovered, .. } => recovered.as_ref(),
            PropertyValue::Unsupported(_) => None,
        }
    }
}

/// How a named property is identified within its property set.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum PropertyName {
    /// A numeric identifier (LID), as in `PidLidAppointmentStartWhole` = 0x820D.
    Id(u32),
    /// A string name, as in `PidNameKeywords` = `"Keywords"`.
    Name(String),
}

impl fmt::Display for PropertyName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PropertyName::Id(id) => write!(f, "0x{id:04X}"),
            PropertyName::Name(name) => f.write_str(name),
        }
    }
}

/// The identity of a named property ([MS-OXCDATA] 2.6.1): property set and name or LID.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NamedProperty {
    /// The property set.
    pub guid: Guid,
    /// The name or numeric identifier within the set.
    pub name: PropertyName,
}

impl fmt::Display for NamedProperty {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.guid.property_set_name() {
            Some(set) => write!(f, "{set}:{}", self.name),
            None => write!(f, "{{{}}}:{}", self.guid, self.name),
        }
    }
}

/// The 16-byte entry of a property in the `__properties_version1.0` stream ([MS-OXMSG] 2.4.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PropertyEntry {
    /// Flags: `PROPATTR_MANDATORY` (1), `PROPATTR_READABLE` (2), `PROPATTR_WRITABLE` (4).
    pub flags: u32,
    /// The 8 value bytes: the value of a fixed-size property, or for a variable-size one its
    /// size (4 bytes) and 4 reserved bytes.
    pub value: [u8; 8],
}

impl PropertyEntry {
    /// The size field of a variable-size or multi-valued property's entry.
    pub fn size(&self) -> u32 {
        u32::from_le_bytes([self.value[0], self.value[1], self.value[2], self.value[3]])
    }
}

/// One property of a message, recipient or attachment.
#[derive(Clone, Debug, PartialEq)]
pub struct Property {
    /// The property id (the upper 16 bits of the tag). Ids 0x8000 and up are named properties.
    pub id: u16,
    /// The property type code (the lower 16 bits of the tag), as stored.
    pub type_code: u16,
    /// The identity of a named property (id 0x8000 and up), from `__nameid_version1.0`.
    pub named: Option<NamedProperty>,
    /// The property stream entry, if the property has one (variable-size properties are
    /// sometimes present only as a stream).
    pub entry: Option<PropertyEntry>,
    /// The value.
    pub value: PropertyValue,
}

impl Property {
    /// The property tag: id and type code.
    pub fn tag(&self) -> u32 {
        (u32::from(self.id) << 16) | u32::from(self.type_code)
    }

    /// The property type, if the type code is a known one.
    pub fn property_type(&self) -> Option<PropertyType> {
        PropertyType::from_code(self.type_code)
    }
}

/// The properties of a message, recipient or attachment, ordered by tag.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Properties(pub(crate) Vec<Property>);

impl Properties {
    /// All properties, ordered by tag.
    pub fn iter(&self) -> std::slice::Iter<'_, Property> {
        self.0.iter()
    }

    /// The number of properties.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether there are no properties.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The property with this tag (id and type).
    pub fn get_tag(&self, tag: u32) -> Option<&Property> {
        self.0
            .binary_search_by_key(&tag, Property::tag)
            .ok()
            .map(|i| &self.0[i])
    }

    /// The property with this id. If it is stored with more than one type, the one with a
    /// cleanly decoded value comes first, then the lowest type code.
    pub fn get(&self, id: u16) -> Option<&Property> {
        let start = self.0.partition_point(|p| p.id < id);
        let same = self.0[start..].iter().take_while(|p| p.id == id);
        let mut first = None;
        for p in same {
            if matches!(p.value, PropertyValue::Ok(_)) {
                return Some(p);
            }
            first.get_or_insert(p);
        }
        first
    }

    /// The value of the property with this id, if decoded cleanly.
    pub fn value(&self, id: u16) -> Option<&Value> {
        self.get(id)?.value.ok()
    }

    /// The named property with this identity.
    pub fn get_named(&self, guid: &Guid, name: &PropertyName) -> Option<&Property> {
        self.0.iter().find(|p| {
            p.named
                .as_ref()
                .is_some_and(|n| &n.guid == guid && &n.name == name)
        })
    }

    /// The string value (`Unicode` or `String8`) of the property with this id.
    pub fn string(&self, id: u16) -> Option<&str> {
        let unicode = self.get_tag((u32::from(id) << 16) | 0x001F);
        let string8 = self.get_tag((u32::from(id) << 16) | 0x001E);
        [unicode, string8]
            .into_iter()
            .flatten()
            .find_map(|p| p.value.ok()?.as_str())
    }

    /// The integer value of the property with this id.
    pub fn int(&self, id: u16) -> Option<i64> {
        self.value(id)?.as_i64()
    }

    /// The `Boolean` value of the property with this id.
    pub fn bool(&self, id: u16) -> Option<bool> {
        self.value(id)?.as_bool()
    }

    /// The `Time` value (FILETIME ticks) of the property with this id.
    pub fn time(&self, id: u16) -> Option<i64> {
        self.value(id)?.as_time()
    }

    /// The `Binary` value of the property with this id.
    pub fn binary(&self, id: u16) -> Option<&[u8]> {
        self.get_tag((u32::from(id) << 16) | 0x0102)?
            .value
            .ok()?
            .as_bytes()
    }
}

impl<'a> IntoIterator for &'a Properties {
    type Item = &'a Property;
    type IntoIter = std::slice::Iter<'a, Property>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn type_codes_round_trip() {
        for code in 0..=0x1200u16 {
            if let Some(t) = PropertyType::from_code(code) {
                assert_eq!(t.code(), code);
            }
        }
        assert_eq!(
            PropertyType::from_code(0x0003),
            Some(PropertyType::Integer32)
        );
        assert_eq!(PropertyType::from_code(0x1234), None);
    }

    fn prop(id: u16, type_code: u16, value: PropertyValue) -> Property {
        Property {
            id,
            type_code,
            named: None,
            entry: None,
            value,
        }
    }

    #[test]
    fn lookups() {
        let props = Properties(vec![
            prop(
                0x0037,
                0x001E,
                PropertyValue::Ok(Value::String8(Text::from_code_page(b"a".to_vec(), 1252))),
            ),
            prop(
                0x0037,
                0x001F,
                PropertyValue::Ok(Value::Unicode(Text::from_utf16le(b"b\0".to_vec()))),
            ),
            prop(0x0E07, 0x0003, PropertyValue::Ok(Value::Integer32(-1))),
            prop(0x1000, 0x001F, PropertyValue::Unsupported(vec![])),
        ]);
        assert_eq!(props.string(0x0037), Some("b"));
        assert_eq!(props.int(0x0E07), Some(-1));
        assert_eq!(props.get(0x0037).map(|p| p.type_code), Some(0x001E));
        assert!(props.get(0x1000).is_some());
        assert_eq!(props.value(0x1000), None);
        assert!(props.get(0x9999).is_none());
        assert_eq!(
            props.get_tag(0x0E07_0003).map(Property::tag),
            Some(0x0E07_0003)
        );
    }
}
