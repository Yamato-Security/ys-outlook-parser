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

//! Text values: UTF-16LE (`PtypString`) and code-page strings (`PtypString8`).
//!
//! A [`Text`] always keeps the bytes as stored, so nothing is lost when they are not valid in
//! their encoding: the decoded string has U+FFFD in place of each invalid sequence and
//! [`Text::is_lossy`] says so.

use encoding_rs::Encoding;
use std::fmt;

/// How a [`Text`] was decoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TextEncoding {
    /// UTF-16LE (`PtypString`).
    Utf16Le,
    /// The Windows code page with this number (`PtypString8`).
    CodePage(u32),
    /// The requested code page is not supported by this crate: decoded as Windows-1252.
    Unsupported {
        /// The code page that was asked for.
        requested: u32,
    },
}

/// A decoded string with the bytes it was decoded from.
#[derive(Clone, PartialEq, Eq)]
pub struct Text {
    raw: Vec<u8>,
    text: String,
    encoding: TextEncoding,
    lossy: bool,
}

impl Text {
    /// The decoded string. Trailing NUL terminators are not part of it; NULs inside the string
    /// are kept. Invalid sequences are U+FFFD (see [`Text::is_lossy`]).
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// The bytes as stored in the file, terminators included.
    pub fn raw(&self) -> &[u8] {
        &self.raw
    }

    /// How the bytes were decoded.
    pub fn encoding(&self) -> TextEncoding {
        self.encoding
    }

    /// Whether some bytes were not valid in the encoding (an unpaired surrogate, an odd final
    /// byte of UTF-16, or a byte sequence that the code page does not define), so that
    /// [`Text::as_str`] has U+FFFD in their place. [`Text::raw`] still has them.
    pub fn is_lossy(&self) -> bool {
        self.lossy
    }

    /// Whether the decoded string is empty.
    pub fn is_empty(&self) -> bool {
        self.text.is_empty()
    }

    /// The decoded string, consuming the value.
    pub fn into_string(self) -> String {
        self.text
    }

    /// Decodes UTF-16LE.
    pub fn from_utf16le(raw: Vec<u8>) -> Self {
        let (text, lossy) = decode_utf16le(&raw);
        Self {
            raw,
            text,
            encoding: TextEncoding::Utf16Le,
            lossy,
        }
    }

    /// Decodes bytes in a Windows code page. An unsupported code page is decoded as
    /// Windows-1252 and reported in [`Text::encoding`].
    pub fn from_code_page(raw: Vec<u8>, code_page: u32) -> Self {
        let (text, lossy, encoding) = match code_page {
            1200 => {
                let (t, l) = decode_utf16le(&raw);
                (t, l, TextEncoding::CodePage(1200))
            }
            28591 => {
                let bytes = trim_nul_bytes(&raw);
                (
                    bytes.iter().map(|&b| char::from(b)).collect(),
                    false,
                    TextEncoding::CodePage(28591),
                )
            }
            _ => {
                let (encoding, tag) = match encoding_for_code_page(code_page) {
                    Some(e) => (e, TextEncoding::CodePage(code_page)),
                    None => (
                        encoding_rs::WINDOWS_1252,
                        TextEncoding::Unsupported {
                            requested: code_page,
                        },
                    ),
                };
                let bytes = if encoding == encoding_rs::UTF_16BE {
                    trim_nul_units(&raw)
                } else {
                    trim_nul_bytes(&raw)
                };
                let (text, lossy) = encoding.decode_without_bom_handling(bytes);
                (text.into_owned(), lossy, tag)
            }
        };
        Self {
            raw,
            text,
            encoding,
            lossy,
        }
    }
}

impl fmt::Debug for Text {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut d = f.debug_struct("Text");
        d.field("text", &self.text)
            .field("encoding", &self.encoding);
        if self.lossy {
            d.field("lossy", &true).field("raw", &self.raw);
        }
        d.finish()
    }
}

impl fmt::Display for Text {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text)
    }
}

impl AsRef<str> for Text {
    fn as_ref(&self) -> &str {
        &self.text
    }
}

/// Whether [`Text::from_code_page`] decodes this Windows code page (instead of falling back to
/// Windows-1252).
pub fn is_code_page_supported(code_page: u32) -> bool {
    matches!(code_page, 1200 | 28591) || encoding_for_code_page(code_page).is_some()
}

/// UTF-16LE to a string without trailing NUL units; `true` if something was invalid.
fn decode_utf16le(raw: &[u8]) -> (String, bool) {
    let (pairs, rest) = raw.as_chunks::<2>();
    let mut units: &[[u8; 2]] = pairs;
    while let [head @ .., [0, 0]] = units {
        units = head;
    }
    let mut lossy = !rest.is_empty();
    let mut text = String::with_capacity(units.len());
    for c in char::decode_utf16(units.iter().map(|&u| u16::from_le_bytes(u))) {
        match c {
            Ok(c) => text.push(c),
            Err(_) => {
                lossy = true;
                text.push(char::REPLACEMENT_CHARACTER);
            }
        }
    }
    (text, lossy)
}

fn trim_nul_bytes(mut b: &[u8]) -> &[u8] {
    while let [head @ .., 0] = b {
        b = head;
    }
    b
}

fn trim_nul_units(b: &[u8]) -> &[u8] {
    let mut b = &b[..b.len() & !1];
    while let [head @ .., 0, 0] = b {
        b = head;
    }
    b
}

/// The `encoding_rs` decoder of a Windows code page.
fn encoding_for_code_page(code_page: u32) -> Option<&'static Encoding> {
    use encoding_rs::*;
    Some(match code_page {
        // US-ASCII and Latin 1 as Windows-1252, its superset (as WHATWG does).
        1252 | 20127 => WINDOWS_1252,
        1250 => WINDOWS_1250,
        1251 => WINDOWS_1251,
        1253 => WINDOWS_1253,
        1254 => WINDOWS_1254,
        1255 => WINDOWS_1255,
        1256 => WINDOWS_1256,
        1257 => WINDOWS_1257,
        1258 => WINDOWS_1258,
        874 => WINDOWS_874,
        866 => IBM866,
        932 => SHIFT_JIS,
        936 => GBK,
        54936 => GB18030,
        949 | 51949 => EUC_KR,
        950 => BIG5,
        20932 | 51932 => EUC_JP,
        50220..=50222 => ISO_2022_JP,
        20866 => KOI8_R,
        21866 => KOI8_U,
        10000 => MACINTOSH,
        10017 | 10007 => X_MAC_CYRILLIC,
        28592 => ISO_8859_2,
        28593 => ISO_8859_3,
        28594 => ISO_8859_4,
        28595 => ISO_8859_5,
        28596 => ISO_8859_6,
        28597 => ISO_8859_7,
        28598 => ISO_8859_8,
        38598 => ISO_8859_8_I,
        28599 => WINDOWS_1254,
        28600 => ISO_8859_10,
        28601 => WINDOWS_874,
        28603 => ISO_8859_13,
        28604 => ISO_8859_14,
        28605 => ISO_8859_15,
        28606 => ISO_8859_16,
        1201 => UTF_16BE,
        65001 => UTF_8,
        _ => return None,
    })
}

/// The Windows ANSI code page that `PtypString8` values written under an Internet code page
/// (`PidTagInternetCodepage`, the MIME charset of the message) are most likely in: Outlook
/// stores 8-bit strings in a Windows code page, not in a 7-bit or stateful MIME encoding.
/// `None` for Unicode encodings, which say nothing about the 8-bit strings.
pub fn windows_code_page_of_internet(code_page: u32) -> Option<u32> {
    Some(match code_page {
        0 | 1200 | 1201 | 12000 | 12001 | 65000 | 65001 => return None,
        20127 | 28591 | 28605 => 1252,
        28592 => 1250,
        28595 | 20866 | 21866 => 1251,
        28597 => 1253,
        28599 => 1254,
        28598 | 38598 => 1255,
        28596 => 1256,
        28594 | 28603 => 1257,
        28601 => 874,
        50220..=50222 | 20932 | 51932 => 932,
        20936 | 52936 => 936,
        50225 | 51949 => 949,
        51950 => 950,
        other => other,
    })
}

/// The Windows ANSI code page of a locale (LCID, as in `PidTagMessageLocaleId`), or `None` for
/// locales that have none (Unicode-only languages) or that are not known.
pub fn ansi_code_page_of_locale(lcid: u32) -> Option<u32> {
    let lang = (lcid & 0xFFFF) as u16;
    let primary = lang & 0x03FF;
    Some(match primary {
        // Chinese: Traditional for Taiwan, Hong Kong and Macao, Simplified otherwise.
        0x04 => match lang {
            0x0404 | 0x0C04 | 0x1404 | 0x7C04 => 950,
            _ => 936,
        },
        0x11 => 932,
        0x12 => 949,
        0x1E => 874,
        0x2A => 1258,
        0x08 => 1253,
        0x0D => 1255,
        0x1F => 1254,
        0x25..=0x27 => 1257,
        // Arabic script.
        0x01 | 0x20 | 0x29 | 0x80 | 0x8C | 0x92 => 1256,
        // Cyrillic script.
        0x02 | 0x19 | 0x22 | 0x23 | 0x28 | 0x2F | 0x3F | 0x40 | 0x44 | 0x50 | 0x6D | 0x85 => 1251,
        // Central European (Latin 2).
        0x05 | 0x0E | 0x15 | 0x18 | 0x1B | 0x1C | 0x24 | 0x42 => 1250,
        // Azerbaijani and Uzbek: Cyrillic for sublanguage 2, Latin (Turkish code page) otherwise.
        0x2C | 0x43 => {
            if lang >> 10 == 2 {
                1251
            } else {
                1254
            }
        }
        // Croatian, Serbian and Bosnian: the Cyrillic variants use 1251.
        0x1A => match lang {
            0x0C1A | 0x1C1A | 0x201A | 0x281A | 0x301A | 0x6C1A | 0x7C1A => 1251,
            _ => 1250,
        },
        // Western European and other Latin-script languages.
        0x03 | 0x06 | 0x07 | 0x09 | 0x0A | 0x0B | 0x0C | 0x0F | 0x10 | 0x13 | 0x14 | 0x16
        | 0x17 | 0x1D | 0x21 | 0x2D | 0x2E | 0x32 | 0x34 | 0x35 | 0x36 | 0x38 | 0x3B | 0x3C
        | 0x3E | 0x41 | 0x52 | 0x56 | 0x62 | 0x64 | 0x68 | 0x6A | 0x6B | 0x6C | 0x6E | 0x6F
        | 0x70 | 0x7A | 0x7C | 0x7E | 0x82 | 0x83 | 0x84 | 0x86 | 0x87 | 0x88 => 1252,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utf16() {
        let t = Text::from_utf16le(b"h\0i\0\0\0".to_vec());
        assert_eq!(t.as_str(), "hi");
        assert!(!t.is_lossy());
        assert_eq!(t.raw(), b"h\0i\0\0\0");
        // Unpaired surrogate and an odd final byte: reported, raw bytes kept.
        let t = Text::from_utf16le(vec![b'A', 0, 0, 0xD8, b'B', 0, b'C']);
        assert_eq!(t.as_str(), "A\u{FFFD}B");
        assert!(t.is_lossy());
        assert_eq!(t.raw().len(), 7);
        // A NUL inside the string is kept.
        assert_eq!(Text::from_utf16le(b"a\0\0\0b\0".to_vec()).as_str(), "a\0b");
    }

    #[test]
    fn code_pages() {
        assert_eq!(
            Text::from_code_page(b"caf\xe9\0".to_vec(), 1252).as_str(),
            "café"
        );
        assert_eq!(
            Text::from_code_page(b"\xcf\xf0\xe8\xe2\xe5\xf2".to_vec(), 1251).as_str(),
            "Привет"
        );
        assert_eq!(
            Text::from_code_page(b"\x93\xfa\x96{".to_vec(), 932).as_str(),
            "日本"
        );
        assert_eq!(
            Text::from_code_page(b"\x80".to_vec(), 28591).as_str(),
            "\u{80}"
        );
        let t = Text::from_code_page(b"abc".to_vec(), 437);
        assert_eq!(t.encoding(), TextEncoding::Unsupported { requested: 437 });
        assert_eq!(t.as_str(), "abc");
        let t = Text::from_code_page(b"\xff\xfe".to_vec(), 65001);
        assert!(t.is_lossy());
        assert!(!is_code_page_supported(437));
        assert!(is_code_page_supported(1200));
    }

    #[test]
    fn locales() {
        assert_eq!(ansi_code_page_of_locale(1049), Some(1251));
        assert_eq!(ansi_code_page_of_locale(1031), Some(1252));
        assert_eq!(ansi_code_page_of_locale(1041), Some(932));
        assert_eq!(ansi_code_page_of_locale(1028), Some(950));
        assert_eq!(ansi_code_page_of_locale(2052), Some(936));
        assert_eq!(ansi_code_page_of_locale(0x0C1A), Some(1251));
        assert_eq!(ansi_code_page_of_locale(0x041A), Some(1250));
        assert_eq!(ansi_code_page_of_locale(0x082C), Some(1251));
        assert_eq!(ansi_code_page_of_locale(0x042C), Some(1254));
        assert_eq!(ansi_code_page_of_locale(0x0439), None);
        assert_eq!(windows_code_page_of_internet(50220), Some(932));
        assert_eq!(windows_code_page_of_internet(65001), None);
        assert_eq!(windows_code_page_of_internet(1251), Some(1251));
    }
}
