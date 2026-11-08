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

//! Ids of the properties this crate interprets, and a few more that mappers commonly need
//! ([MS-OXPROPS]). Ids only: the type is the lower half of a tag.

/// `PidTagMessageClass`: `IPM.Note`, `IPM.Contact`, `IPM.Appointment`, ...
pub const MESSAGE_CLASS: u16 = 0x001A;
/// `PidTagSubject`.
pub const SUBJECT: u16 = 0x0037;
/// `PidTagClientSubmitTime`.
pub const CLIENT_SUBMIT_TIME: u16 = 0x0039;
/// `PidTagSentRepresentingName`.
pub const SENT_REPRESENTING_NAME: u16 = 0x0042;
/// `PidTagSentRepresentingEmailAddress`.
pub const SENT_REPRESENTING_EMAIL_ADDRESS: u16 = 0x0065;
/// `PidTagConversationTopic`.
pub const CONVERSATION_TOPIC: u16 = 0x0070;
/// `PidTagTransportMessageHeaders`.
pub const TRANSPORT_MESSAGE_HEADERS: u16 = 0x007D;
/// `PidTagRecipientType`: 1 = To, 2 = Cc, 3 = Bcc (`MAPI_P1` 0x10000000 may be set).
pub const RECIPIENT_TYPE: u16 = 0x0C15;
/// `PidTagSenderName`.
pub const SENDER_NAME: u16 = 0x0C1A;
/// `PidTagSenderEmailAddress`.
pub const SENDER_EMAIL_ADDRESS: u16 = 0x0C1F;
/// `PidTagMessageDeliveryTime`.
pub const MESSAGE_DELIVERY_TIME: u16 = 0x0E06;
/// `PidTagMessageFlags`.
pub const MESSAGE_FLAGS: u16 = 0x0E07;
/// `PidTagAttachSize`.
pub const ATTACH_SIZE: u16 = 0x0E20;
/// `PidTagBody`.
pub const BODY: u16 = 0x1000;
/// `PidTagRtfCompressed`.
pub const RTF_COMPRESSED: u16 = 0x1009;
/// `PidTagHtml` (binary) / `PidTagBodyHtml` (string): the same id.
pub const HTML: u16 = 0x1013;
/// `PidTagInternetMessageId`.
pub const INTERNET_MESSAGE_ID: u16 = 0x1035;
/// `PidTagDisplayName`.
pub const DISPLAY_NAME: u16 = 0x3001;
/// `PidTagAddressType`.
pub const ADDRESS_TYPE: u16 = 0x3002;
/// `PidTagEmailAddress`.
pub const EMAIL_ADDRESS: u16 = 0x3003;
/// `PidTagCreationTime`.
pub const CREATION_TIME: u16 = 0x3007;
/// `PidTagLastModificationTime`.
pub const LAST_MODIFICATION_TIME: u16 = 0x3008;
/// `PidTagStoreSupportMask`: `STORE_UNICODE_OK` (0x00040000) when strings are Unicode.
pub const STORE_SUPPORT_MASK: u16 = 0x340D;
/// `PidTagAttachDataBinary` (binary) / `PidTagAttachDataObject` (object): the same id.
pub const ATTACH_DATA: u16 = 0x3701;
/// `PidTagAttachExtension`.
pub const ATTACH_EXTENSION: u16 = 0x3703;
/// `PidTagAttachFilename` (8.3 name).
pub const ATTACH_FILENAME: u16 = 0x3704;
/// `PidTagAttachMethod`.
pub const ATTACH_METHOD: u16 = 0x3705;
/// `PidTagAttachLongFilename`.
pub const ATTACH_LONG_FILENAME: u16 = 0x3707;
/// `PidTagAttachMimeTag`.
pub const ATTACH_MIME_TAG: u16 = 0x370E;
/// `PidTagAttachContentId`.
pub const ATTACH_CONTENT_ID: u16 = 0x3712;
/// `PidTagSmtpAddress`.
pub const SMTP_ADDRESS: u16 = 0x39FE;
/// `PidTagInternetCodepage`: the code page of the body in its Internet (MIME) form.
pub const INTERNET_CODEPAGE: u16 = 0x3FDE;
/// `PidTagMessageLocaleId`.
pub const MESSAGE_LOCALE_ID: u16 = 0x3FF1;
/// `PidTagMessageCodepage`: the code page of the message's `PtypString8` values.
pub const MESSAGE_CODEPAGE: u16 = 0x3FFD;

/// `PidTagAttachMethod` values ([MS-OXCMSG] 2.2.2.9).
pub mod attach_method {
    /// `afNone`: no data.
    pub const NONE: i64 = 0;
    /// `afByValue`: the data is in `PidTagAttachDataBinary`.
    pub const BY_VALUE: i64 = 1;
    /// `afByReference`.
    pub const BY_REFERENCE: i64 = 2;
    /// `afByReferenceOnly`.
    pub const BY_REFERENCE_ONLY: i64 = 4;
    /// `afEmbeddedMessage`: the data is a message in `PidTagAttachDataObject`.
    pub const EMBEDDED_MESSAGE: i64 = 5;
    /// `afStorage`: the data is an OLE storage in `PidTagAttachDataObject`.
    pub const STORAGE: i64 = 6;
    /// `afByWebReference`.
    pub const BY_WEB_REFERENCE: i64 = 7;
}
