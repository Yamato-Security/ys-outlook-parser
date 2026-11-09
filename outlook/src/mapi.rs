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

//! MAPI properties as both readers give them ([MS-OXCDATA], [MS-OXPROPS]): a property's id, its
//! type, its value and, for a named property, its property set and name.
//!
//! [MS-OXCDATA]: https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxcdata/
//! [MS-OXPROPS]: https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxprops/

use std::fmt;
use std::sync::Arc;

/// A property as stored: its id (the high 16 bits of its tag), its type (the low 16 bits), its
/// value and, for ids from 0x8000, the name the store's or file's name map gives it.
#[derive(Debug, Clone, PartialEq)]
pub struct Property {
    pub id: u16,
    pub kind: u16,
    pub value: Value,
    pub name: Option<PropertyName>,
}

impl Property {
    pub fn new(id: u16, kind: u16, value: Value) -> Self {
        Property {
            id,
            kind,
            value,
            name: None,
        }
    }

    /// The property tag: id and type, as `0x0037001F`.
    pub fn tag(&self) -> u32 {
        (u32::from(self.id) << 16) | u32::from(self.kind)
    }
}

/// A value. Strings of `PtypString8` keep their bytes beside the text their code page gives.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    /// `PtypNull`.
    Null,
    Integer16(i16),
    Integer32(i32),
    Integer64(i64),
    Floating32(f32),
    Floating64(f64),
    /// `PtypCurrency`: ten-thousandths.
    Currency(i64),
    /// `PtypFloatingTime`: days since December 30, 1899.
    FloatingTime(f64),
    ErrorCode(u32),
    Boolean(bool),
    /// `PtypString`.
    String(String),
    /// `PtypString8`: its bytes, and their text in the code page they were read with.
    String8 {
        bytes: Vec<u8>,
        text: String,
    },
    /// `PtypTime`: a FILETIME, 100-nanosecond intervals since January 1, 1601 (UTC).
    Time(i64),
    Guid([u8; 16]),
    Binary(Vec<u8>),
    /// `PtypObject`: an embedded message or OLE storage, read on its own.
    Object,
    /// A multi-valued type's values.
    Multiple(Vec<Value>),
    /// A type this reader does not decode: the bytes as stored.
    Unsupported(Vec<u8>),
    /// A damaged value: what could be recovered from it, the bytes as stored (as far as they
    /// could be read), and why.
    Damaged {
        recovered: Option<Box<Value>>,
        raw: Vec<u8>,
        reason: String,
    },
}

impl Value {
    /// The value itself, or what was recovered from a damaged one, through any nested
    /// recovery records. The `as_` methods read through them too.
    pub fn best_effort(&self) -> Option<&Value> {
        let mut value = self;
        while let Value::Damaged { recovered, .. } = value {
            value = recovered.as_deref()?;
        }
        Some(value)
    }

    /// The text of a string value (`PtypString` or `PtypString8`).
    pub fn as_str(&self) -> Option<&str> {
        match self.best_effort()? {
            Value::String(text) | Value::String8 { text, .. } => Some(text),
            _ => None,
        }
    }

    /// An integer value of any width.
    pub fn as_i64(&self) -> Option<i64> {
        match *self.best_effort()? {
            Value::Integer16(v) => Some(i64::from(v)),
            Value::Integer32(v) => Some(i64::from(v)),
            Value::Integer64(v) => Some(v),
            Value::ErrorCode(v) => Some(i64::from(v)),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match *self.best_effort()? {
            Value::Boolean(v) => Some(v),
            _ => self.as_i64().map(|v| v != 0),
        }
    }

    /// A FILETIME (`PtypTime`); none for zero.
    pub fn as_filetime(&self) -> Option<i64> {
        match *self.best_effort()? {
            Value::Time(ticks) if ticks != 0 => Some(ticks),
            _ => None,
        }
    }

    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self.best_effort()? {
            Value::Binary(bytes) | Value::String8 { bytes, .. } => Some(bytes),
            _ => None,
        }
    }

    /// The values of a multi-valued property.
    pub fn as_multiple(&self) -> Option<&[Value]> {
        match self.best_effort()? {
            Value::Multiple(values) => Some(values),
            _ => None,
        }
    }
}

/// A named property's identity: its property set and its numeric id (LID) or string name.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PropertyName {
    /// The property set GUID, as stored (Data1-3 little-endian).
    pub set: [u8; 16],
    pub id: NameId,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum NameId {
    /// A numeric name (LID).
    Number(u32),
    /// A string name, shared by the properties and entries referring to it. Use `.into()`
    /// when constructing this from an owned string or string literal.
    Text(Arc<str>),
}

impl PropertyName {
    /// The property set GUID in its usual form, `{00062004-0000-0000-C000-000000000046}`.
    pub fn set_text(&self) -> String {
        guid_text(&self.set)
    }
}

impl fmt::Display for PropertyName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.id {
            NameId::Number(lid) => write!(f, "{}:0x{lid:04X}", self.set_text()),
            NameId::Text(name) => write!(f, "{}:{name}", self.set_text()),
        }
    }
}

/// A GUID as stored (Data1, Data2 and Data3 little-endian) in its usual form.
pub fn guid_text(guid: &[u8; 16]) -> String {
    let d1 = u32::from_le_bytes([guid[0], guid[1], guid[2], guid[3]]);
    let d2 = u16::from_le_bytes([guid[4], guid[5]]);
    let d3 = u16::from_le_bytes([guid[6], guid[7]]);
    format!(
        "{{{d1:08X}-{d2:04X}-{d3:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}",
        guid[8], guid[9], guid[10], guid[11], guid[12], guid[13], guid[14], guid[15]
    )
}

/// A GUID from its usual form, as stored.
pub const fn guid(d1: u32, d2: u16, d3: u16, d4: [u8; 8]) -> [u8; 16] {
    let a = d1.to_le_bytes();
    let b = d2.to_le_bytes();
    let c = d3.to_le_bytes();
    [
        a[0], a[1], a[2], a[3], b[0], b[1], c[0], c[1], d4[0], d4[1], d4[2], d4[3], d4[4], d4[5],
        d4[6], d4[7],
    ]
}

const C000_46: [u8; 8] = [0xC0, 0, 0, 0, 0, 0, 0, 0x46];

/// Property sets of the named properties read ([MS-OXPROPS] 1.3.2).
pub mod sets {
    use super::{C000_46, guid};

    /// `PSETID_Address`: contacts.
    pub const ADDRESS: [u8; 16] = guid(0x0006_2004, 0, 0, C000_46);
    /// `PSETID_Appointment`: calendar items.
    pub const APPOINTMENT: [u8; 16] = guid(0x0006_2002, 0, 0, C000_46);
    /// `PSETID_Task`: tasks.
    pub const TASK: [u8; 16] = guid(0x0006_2003, 0, 0, C000_46);
    /// `PSETID_Common`: reminders and other properties of every item.
    pub const COMMON: [u8; 16] = guid(0x0006_2008, 0, 0, C000_46);
    /// `PSETID_Meeting`: meeting objects.
    pub const MEETING: [u8; 16] = guid(
        0x6ED8_DA90,
        0x450B,
        0x101B,
        [0x98, 0xDA, 0x00, 0xAA, 0x00, 0x3F, 0x13, 0x05],
    );
    /// `PS_PUBLIC_STRINGS`: string-named properties such as `Keywords` (the categories).
    pub const PUBLIC_STRINGS: [u8; 16] = guid(0x0002_0329, 0, 0, C000_46);
    /// `PS_MAPI`.
    pub const MAPI: [u8; 16] = guid(0x0002_0328, 0, 0, C000_46);
    /// `PS_INTERNET_HEADERS`: Internet headers kept as named properties.
    pub const INTERNET_HEADERS: [u8; 16] = guid(0x0002_0386, 0, 0, C000_46);
}

/// Property ids ([MS-OXPROPS] 2), by their `PidTag` names.
pub mod tags {
    pub const MESSAGE_CLASS: u16 = 0x001A;
    pub const IMPORTANCE: u16 = 0x0017;
    pub const PRIORITY: u16 = 0x0026;
    pub const SENSITIVITY: u16 = 0x0036;
    pub const SUBJECT: u16 = 0x0037;
    pub const CLIENT_SUBMIT_TIME: u16 = 0x0039;
    pub const SUBJECT_PREFIX: u16 = 0x003D;
    pub const SENT_REPRESENTING_NAME: u16 = 0x0042;
    pub const SENT_REPRESENTING_ADDRESS_TYPE: u16 = 0x0064;
    pub const SENT_REPRESENTING_EMAIL_ADDRESS: u16 = 0x0065;
    pub const CONVERSATION_TOPIC: u16 = 0x0070;
    pub const CONVERSATION_INDEX: u16 = 0x0071;
    pub const TRANSPORT_MESSAGE_HEADERS: u16 = 0x007D;
    pub const SENDER_ENTRY_ID: u16 = 0x0C19;
    pub const SENDER_NAME: u16 = 0x0C1A;
    pub const SENDER_ADDRESS_TYPE: u16 = 0x0C1E;
    pub const SENDER_EMAIL_ADDRESS: u16 = 0x0C1F;
    pub const RECIPIENT_TYPE: u16 = 0x0C15;
    pub const DISPLAY_BCC: u16 = 0x0E02;
    pub const DISPLAY_CC: u16 = 0x0E03;
    pub const DISPLAY_TO: u16 = 0x0E04;
    pub const MESSAGE_DELIVERY_TIME: u16 = 0x0E06;
    pub const MESSAGE_FLAGS: u16 = 0x0E07;
    pub const MESSAGE_SIZE: u16 = 0x0E08;
    pub const NORMALIZED_SUBJECT: u16 = 0x0E1D;
    pub const ATTACH_SIZE: u16 = 0x0E20;
    pub const RECORD_KEY: u16 = 0x0FF9;
    pub const ENTRY_ID: u16 = 0x0FFF;
    pub const BODY: u16 = 0x1000;
    pub const RTF_COMPRESSED: u16 = 0x1009;
    pub const HTML: u16 = 0x1013;
    pub const INTERNET_MESSAGE_ID: u16 = 0x1035;
    pub const INTERNET_REFERENCES: u16 = 0x1039;
    pub const IN_REPLY_TO_ID: u16 = 0x1042;
    pub const DISPLAY_NAME: u16 = 0x3001;
    pub const ADDRESS_TYPE: u16 = 0x3002;
    pub const EMAIL_ADDRESS: u16 = 0x3003;
    pub const CREATION_TIME: u16 = 0x3007;
    pub const LAST_MODIFICATION_TIME: u16 = 0x3008;
    pub const ATTACH_DATA: u16 = 0x3701;
    pub const ATTACH_EXTENSION: u16 = 0x3703;
    pub const ATTACH_FILENAME: u16 = 0x3704;
    pub const ATTACH_METHOD: u16 = 0x3705;
    pub const ATTACH_LONG_FILENAME: u16 = 0x3707;
    pub const ATTACH_PATHNAME: u16 = 0x3708;
    pub const RENDERING_POSITION: u16 = 0x370B;
    pub const ATTACH_LONG_PATHNAME: u16 = 0x370D;
    pub const ATTACH_MIME_TAG: u16 = 0x370E;
    pub const ATTACH_CONTENT_ID: u16 = 0x3712;
    pub const ATTACH_CONTENT_LOCATION: u16 = 0x3713;
    pub const ATTACH_FLAGS: u16 = 0x3714;
    pub const CONTENT_COUNT: u16 = 0x3602;
    pub const CONTENT_UNREAD_COUNT: u16 = 0x3603;
    pub const SUBFOLDERS: u16 = 0x360A;
    pub const CONTAINER_CLASS: u16 = 0x3613;
    pub const SMTP_ADDRESS: u16 = 0x39FE;
    pub const GIVEN_NAME: u16 = 0x3A06;
    pub const BUSINESS_TELEPHONE_NUMBER: u16 = 0x3A08;
    pub const HOME_TELEPHONE_NUMBER: u16 = 0x3A09;
    pub const SURNAME: u16 = 0x3A11;
    pub const COMPANY_NAME: u16 = 0x3A16;
    pub const TITLE: u16 = 0x3A17;
    pub const DEPARTMENT_NAME: u16 = 0x3A18;
    pub const MOBILE_TELEPHONE_NUMBER: u16 = 0x3A1C;
    pub const NICKNAME: u16 = 0x3A4F;
    pub const INTERNET_CODEPAGE: u16 = 0x3FDE;
    pub const MESSAGE_LOCALE_ID: u16 = 0x3FF1;
    pub const MESSAGE_CODEPAGE: u16 = 0x3FFD;
    pub const SENDER_SMTP_ADDRESS: u16 = 0x5D01;
    pub const SENT_REPRESENTING_SMTP_ADDRESS: u16 = 0x5D02;
    pub const ATTACHMENT_HIDDEN: u16 = 0x7FFE;
    /// A recipient's display name as the recipient table gives it.
    pub const RECIPIENT_DISPLAY_NAME: u16 = 0x5FF6;
}

/// Named properties ([MS-OXPROPS] 2), by their `PidLid` names: (property set, LID).
pub mod lids {
    use super::sets;

    pub type Lid = ([u8; 16], u32);

    pub const EMAIL1_DISPLAY_NAME: Lid = (sets::ADDRESS, 0x8080);
    pub const EMAIL1_ADDRESS_TYPE: Lid = (sets::ADDRESS, 0x8082);
    pub const EMAIL1_EMAIL_ADDRESS: Lid = (sets::ADDRESS, 0x8083);
    pub const EMAIL2_DISPLAY_NAME: Lid = (sets::ADDRESS, 0x8090);
    pub const EMAIL2_ADDRESS_TYPE: Lid = (sets::ADDRESS, 0x8092);
    pub const EMAIL2_EMAIL_ADDRESS: Lid = (sets::ADDRESS, 0x8093);
    pub const EMAIL3_DISPLAY_NAME: Lid = (sets::ADDRESS, 0x80A0);
    pub const EMAIL3_ADDRESS_TYPE: Lid = (sets::ADDRESS, 0x80A2);
    pub const EMAIL3_EMAIL_ADDRESS: Lid = (sets::ADDRESS, 0x80A3);
    pub const FILE_UNDER: Lid = (sets::ADDRESS, 0x8005);
    pub const INSTANT_MESSAGING_ADDRESS: Lid = (sets::ADDRESS, 0x8062);
    pub const DISTRIBUTION_LIST_NAME: Lid = (sets::ADDRESS, 0x8053);

    pub const LOCATION: Lid = (sets::APPOINTMENT, 0x8208);
    pub const BUSY_STATUS: Lid = (sets::APPOINTMENT, 0x8205);
    pub const APPOINTMENT_START_WHOLE: Lid = (sets::APPOINTMENT, 0x820D);
    pub const APPOINTMENT_END_WHOLE: Lid = (sets::APPOINTMENT, 0x820E);
    pub const APPOINTMENT_DURATION: Lid = (sets::APPOINTMENT, 0x8213);
    pub const APPOINTMENT_SUB_TYPE: Lid = (sets::APPOINTMENT, 0x8215);
    pub const APPOINTMENT_RECUR: Lid = (sets::APPOINTMENT, 0x8216);
    pub const RESPONSE_STATUS: Lid = (sets::APPOINTMENT, 0x8218);
    pub const RECURRING: Lid = (sets::APPOINTMENT, 0x8223);
    pub const ALL_ATTENDEES_STRING: Lid = (sets::APPOINTMENT, 0x8238);
    pub const TO_ATTENDEES_STRING: Lid = (sets::APPOINTMENT, 0x823B);
    pub const CC_ATTENDEES_STRING: Lid = (sets::APPOINTMENT, 0x823C);

    pub const GLOBAL_OBJECT_ID: Lid = (sets::MEETING, 0x0003);
    pub const CLEAN_GLOBAL_OBJECT_ID: Lid = (sets::MEETING, 0x0023);

    pub const TASK_STATUS: Lid = (sets::TASK, 0x8101);
    pub const PERCENT_COMPLETE: Lid = (sets::TASK, 0x8102);
    pub const TASK_START_DATE: Lid = (sets::TASK, 0x8104);
    pub const TASK_DUE_DATE: Lid = (sets::TASK, 0x8105);
    pub const TASK_DATE_COMPLETED: Lid = (sets::TASK, 0x810F);
    pub const TASK_COMPLETE: Lid = (sets::TASK, 0x811C);
    pub const TASK_OWNER: Lid = (sets::TASK, 0x811F);
    pub const TASK_ASSIGNER: Lid = (sets::TASK, 0x8121);

    pub const REMINDER_TIME: Lid = (sets::COMMON, 0x8502);
    pub const REMINDER_SET: Lid = (sets::COMMON, 0x8503);
    pub const COMMON_START: Lid = (sets::COMMON, 0x8516);
    pub const COMMON_END: Lid = (sets::COMMON, 0x8517);
    pub const REMINDER_SIGNAL_TIME: Lid = (sets::COMMON, 0x8560);
}

/// The type codes of [MS-OXCDATA] 2.11.1.
pub mod types {
    pub const NULL: u16 = 0x0001;
    pub const INTEGER16: u16 = 0x0002;
    pub const INTEGER32: u16 = 0x0003;
    pub const FLOATING32: u16 = 0x0004;
    pub const FLOATING64: u16 = 0x0005;
    pub const CURRENCY: u16 = 0x0006;
    pub const FLOATING_TIME: u16 = 0x0007;
    pub const ERROR_CODE: u16 = 0x000A;
    pub const BOOLEAN: u16 = 0x000B;
    pub const OBJECT: u16 = 0x000D;
    pub const INTEGER64: u16 = 0x0014;
    pub const STRING8: u16 = 0x001E;
    pub const STRING: u16 = 0x001F;
    pub const TIME: u16 = 0x0040;
    pub const GUID: u16 = 0x0048;
    pub const BINARY: u16 = 0x0102;
    /// Added to a single-valued type for its multi-valued type.
    pub const MULTIPLE: u16 = 0x1000;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guids_in_their_usual_form() {
        assert_eq!(
            guid_text(&sets::ADDRESS),
            "{00062004-0000-0000-C000-000000000046}"
        );
        assert_eq!(
            guid_text(&sets::MEETING),
            "{6ED8DA90-450B-101B-98DA-00AA003F1305}"
        );
        assert_eq!(&sets::ADDRESS[..4], &[0x04, 0x20, 0x06, 0x00]);
        let name = PropertyName {
            set: sets::TASK,
            id: NameId::Number(0x8101),
        };
        assert_eq!(
            name.to_string(),
            "{00062003-0000-0000-C000-000000000046}:0x8101"
        );
    }

    #[test]
    fn values() {
        assert_eq!(Value::Integer16(-2).as_i64(), Some(-2));
        assert_eq!(Value::Time(0).as_filetime(), None);
        assert_eq!(
            Value::String8 {
                bytes: b"a".to_vec(),
                text: "a".into()
            }
            .as_str(),
            Some("a")
        );
        assert_eq!(
            Property::new(0x0037, 0x001F, Value::Null).tag(),
            0x0037_001F
        );
    }

    #[test]
    fn nested_recovery_wrappers_keep_readable_values() {
        let damaged = |value| Value::Damaged {
            recovered: Some(Box::new(value)),
            raw: vec![0xFF],
            reason: "recovered text in a partially read property".into(),
        };
        let value = damaged(damaged(Value::String("recovered".into())));
        assert_eq!(value.as_str(), Some("recovered"));
        let value = damaged(damaged(Value::Integer32(42)));
        assert_eq!(value.as_i64(), Some(42));
        let value = damaged(damaged(Value::Binary(vec![1, 2])));
        assert_eq!(value.as_bytes(), Some(&[1, 2][..]));
        assert!(
            damaged(Value::Damaged {
                recovered: None,
                raw: vec![],
                reason: "missing".into()
            })
            .best_effort()
            .is_none()
        );
    }
}
