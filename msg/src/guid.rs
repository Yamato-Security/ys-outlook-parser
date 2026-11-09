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

//! GUIDs: storage CLSIDs and the property sets of named properties.

use std::fmt;

/// A GUID, kept in its on-disk byte order ([MS-DTYP] 2.3.4.2: `Data1`, `Data2` and `Data3`
/// little-endian, then the 8 bytes of `Data4`).
///
/// [`Display`](fmt::Display) gives the registry form in upper case without braces, for example
/// `00020D0B-0000-0000-C000-000000000046`.
#[derive(Clone, Copy, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Guid(pub [u8; 16]);

impl Guid {
    /// The GUID made of all zeros.
    pub const NIL: Self = Self([0; 16]);

    /// A GUID from its fields.
    pub const fn from_fields(data1: u32, data2: u16, data3: u16, data4: [u8; 8]) -> Self {
        let a = data1.to_le_bytes();
        let b = data2.to_le_bytes();
        let c = data3.to_le_bytes();
        let d = data4;
        Self([
            a[0], a[1], a[2], a[3], b[0], b[1], c[0], c[1], d[0], d[1], d[2], d[3], d[4], d[5],
            d[6], d[7],
        ])
    }

    /// `Data1`.
    pub fn data1(&self) -> u32 {
        u32::from_le_bytes([self.0[0], self.0[1], self.0[2], self.0[3]])
    }

    /// `Data2`.
    pub fn data2(&self) -> u16 {
        u16::from_le_bytes([self.0[4], self.0[5]])
    }

    /// `Data3`.
    pub fn data3(&self) -> u16 {
        u16::from_le_bytes([self.0[6], self.0[7]])
    }

    /// `Data4`.
    pub fn data4(&self) -> [u8; 8] {
        let mut d = [0; 8];
        d.copy_from_slice(&self.0[8..]);
        d
    }

    /// Whether all bytes are zero.
    pub fn is_nil(&self) -> bool {
        self.0 == [0; 16]
    }

    /// The name of a well-known property set ([MS-OXPROPS] 1.3.2), such as `"PS_MAPI"` or
    /// `"PSETID_Appointment"`.
    pub fn property_set_name(&self) -> Option<&'static str> {
        PROPERTY_SETS
            .iter()
            .find(|(guid, _)| guid == self)
            .map(|(_, name)| *name)
    }
}

impl fmt::Display for Guid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let d = self.data4();
        write!(
            f,
            "{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
            self.data1(),
            self.data2(),
            self.data3(),
            d[0],
            d[1],
            d[2],
            d[3],
            d[4],
            d[5],
            d[6],
            d[7]
        )
    }
}

impl fmt::Debug for Guid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Guid({self})")
    }
}

/// `{xxxxxxxx-0000-0000-C000-000000000046}`, the form of most MAPI GUIDs.
const fn mapi(data1: u32) -> Guid {
    Guid::from_fields(data1, 0, 0, [0xC0, 0, 0, 0, 0, 0, 0, 0x46])
}

/// Root storage CLSID of a `.msg` file ([MS-OXMSG] 2.1.1: CLSID_MailMessage, the class of an
/// `IMessage` saved by `OleSaveToStream`/`StgCreateStorageEx`).
pub const CLSID_MESSAGE: Guid = mapi(0x0002_0D0B);
/// Root storage CLSID of an Outlook template (`.oft`).
pub const CLSID_TEMPLATE: Guid = mapi(0x0006_F046);

/// `PS_MAPI`: named properties whose identifier is the property id itself (GUID index 1).
pub const PS_MAPI: Guid = mapi(0x0002_0328);
/// `PS_PUBLIC_STRINGS`: string-named properties of no particular set (GUID index 2).
pub const PS_PUBLIC_STRINGS: Guid = mapi(0x0002_0329);
/// `PS_INTERNET_HEADERS`: Internet message headers stored as string-named properties.
pub const PS_INTERNET_HEADERS: Guid = mapi(0x0002_0386);
/// `PSETID_Appointment`.
pub const PSETID_APPOINTMENT: Guid = mapi(0x0006_2002);
/// `PSETID_Task`.
pub const PSETID_TASK: Guid = mapi(0x0006_2003);
/// `PSETID_Address` (contacts).
pub const PSETID_ADDRESS: Guid = mapi(0x0006_2004);
/// `PSETID_Common`.
pub const PSETID_COMMON: Guid = mapi(0x0006_2008);
/// `PSETID_Log` (journal entries).
pub const PSETID_LOG: Guid = mapi(0x0006_200A);
/// `PSETID_Note` (sticky notes).
pub const PSETID_NOTE: Guid = mapi(0x0006_200E);
/// `PSETID_Sharing`.
pub const PSETID_SHARING: Guid = mapi(0x0006_2040);
/// `PSETID_PostRss`.
pub const PSETID_POST_RSS: Guid = mapi(0x0006_2041);
/// `PSETID_Meeting`.
pub const PSETID_MEETING: Guid = Guid::from_fields(
    0x6ED8_DA90,
    0x450B,
    0x101B,
    [0x98, 0xDA, 0x00, 0xAA, 0x00, 0x3F, 0x13, 0x05],
);
/// `PSETID_Messaging`.
pub const PSETID_MESSAGING: Guid = Guid::from_fields(
    0x41F2_8F13,
    0x83F4,
    0x4114,
    [0xA5, 0x84, 0xEE, 0xDB, 0x5A, 0x6B, 0x0B, 0xFF],
);
/// `PSETID_UnifiedMessaging`.
pub const PSETID_UNIFIED_MESSAGING: Guid = Guid::from_fields(
    0x4442_858E,
    0xA9E3,
    0x4E80,
    [0xB9, 0x00, 0x31, 0x7A, 0x21, 0x0C, 0xC1, 0x5B],
);
/// `PSETID_AirSync`.
pub const PSETID_AIR_SYNC: Guid = Guid::from_fields(
    0x7103_5549,
    0x0739,
    0x4DCB,
    [0x91, 0x63, 0x00, 0xF0, 0x58, 0x0D, 0xBB, 0xDF],
);
/// `PSETID_CalendarAssistant`.
pub const PSETID_CALENDAR_ASSISTANT: Guid = Guid::from_fields(
    0x1100_0E07,
    0xB51B,
    0x40D6,
    [0xAF, 0x21, 0xCA, 0xA8, 0x5E, 0xDA, 0xB1, 0xD0],
);
/// `PSETID_Attachment`.
pub const PSETID_ATTACHMENT: Guid = Guid::from_fields(
    0x9635_7F7F,
    0x59E1,
    0x47D0,
    [0x99, 0xA7, 0x46, 0x51, 0x5C, 0x18, 0x3B, 0x54],
);
/// `PSETID_XmlExtractedEntities`.
pub const PSETID_XML_EXTRACTED_ENTITIES: Guid = Guid::from_fields(
    0x2323_9608,
    0x685D,
    0x4732,
    [0x9C, 0x55, 0x4C, 0x95, 0xCB, 0x4E, 0x8E, 0x33],
);

const PROPERTY_SETS: &[(Guid, &str)] = &[
    (PS_MAPI, "PS_MAPI"),
    (PS_PUBLIC_STRINGS, "PS_PUBLIC_STRINGS"),
    (PS_INTERNET_HEADERS, "PS_INTERNET_HEADERS"),
    (PSETID_APPOINTMENT, "PSETID_Appointment"),
    (PSETID_TASK, "PSETID_Task"),
    (PSETID_ADDRESS, "PSETID_Address"),
    (PSETID_COMMON, "PSETID_Common"),
    (PSETID_LOG, "PSETID_Log"),
    (PSETID_NOTE, "PSETID_Note"),
    (PSETID_SHARING, "PSETID_Sharing"),
    (PSETID_POST_RSS, "PSETID_PostRss"),
    (PSETID_MEETING, "PSETID_Meeting"),
    (PSETID_MESSAGING, "PSETID_Messaging"),
    (PSETID_UNIFIED_MESSAGING, "PSETID_UnifiedMessaging"),
    (PSETID_AIR_SYNC, "PSETID_AirSync"),
    (PSETID_CALENDAR_ASSISTANT, "PSETID_CalendarAssistant"),
    (PSETID_ATTACHMENT, "PSETID_Attachment"),
    (PSETID_XML_EXTRACTED_ENTITIES, "PSETID_XmlExtractedEntities"),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_and_fields() {
        assert_eq!(
            CLSID_MESSAGE.to_string(),
            "00020D0B-0000-0000-C000-000000000046"
        );
        assert_eq!(
            CLSID_TEMPLATE.to_string(),
            "0006F046-0000-0000-C000-000000000046"
        );
        assert_eq!(
            PSETID_MEETING.to_string(),
            "6ED8DA90-450B-101B-98DA-00AA003F1305"
        );
        assert_eq!(CLSID_MESSAGE.0[..4], [0x0B, 0x0D, 0x02, 0x00]);
        assert_eq!(PS_MAPI.property_set_name(), Some("PS_MAPI"));
        assert_eq!(Guid::NIL.property_set_name(), None);
        assert!(Guid::NIL.is_nil());
    }
}
