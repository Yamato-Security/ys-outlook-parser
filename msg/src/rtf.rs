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

//! The RTF body, `PidTagRtfCompressed` ([MS-OXRTFCP]), decompressed with `compressed_rtf`.
//!
//! Problems with the header (sizes, CRC) are flags on the result, not errors: the data is
//! decompressed anyway, as far as it goes.

use std::fmt;

/// `COMPTYPE` of compressed RTF ("LZFu").
const COMPRESSED: u32 = 0x7546_5A4C;
/// `COMPTYPE` of uncompressed RTF ("MELA").
const UNCOMPRESSED: u32 = 0x414C_454D;
/// Header: `COMPSIZE`, `RAWSIZE`, `COMPTYPE`, `CRC`.
const HEADER_LEN: usize = 16;

/// The header of a compressed RTF stream ([MS-OXRTFCP] 2.1.3.1.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RtfHeader {
    /// `COMPSIZE`: the size of the data after this field.
    pub compressed_size: u32,
    /// `RAWSIZE`: the size of the decompressed RTF.
    pub raw_size: u32,
    /// `COMPTYPE`: `0x75465A4C` ("LZFu", compressed) or `0x414C454D` ("MELA", uncompressed).
    pub compression_type: u32,
    /// `CRC` of the compressed data (0 for uncompressed RTF).
    pub crc: u32,
}

/// Something wrong with a compressed RTF stream.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum RtfFlag {
    /// Shorter than the 16-byte header: nothing decompressed.
    TooShort {
        /// The length of the property value.
        len: usize,
    },
    /// `COMPSIZE` does not match the length of the value: the data up to whichever ends first
    /// was decompressed.
    CompressedSizeMismatch {
        /// `COMPSIZE` + 4, the length the header gives.
        declared: u64,
        /// The length of the property value.
        actual: usize,
    },
    /// The CRC of compressed data does not match.
    CrcMismatch {
        /// The CRC in the header.
        stored: u32,
        /// The CRC of the data.
        computed: u32,
    },
    /// The data does not decompress to `RAWSIZE` bytes.
    RawSizeMismatch {
        /// `RAWSIZE`.
        declared: u32,
        /// The length the data decompresses to.
        actual: u64,
    },
    /// `COMPTYPE` is neither compressed nor uncompressed: nothing decompressed.
    UnknownCompressionType(u32),
    /// The decompressor stopped with an error: nothing decompressed.
    Decompression(String),
}

impl fmt::Display for RtfFlag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort { len } => write!(f, "{len} bytes is shorter than the 16-byte header"),
            Self::CompressedSizeMismatch { declared, actual } => write!(
                f,
                "COMPSIZE says {declared} bytes but the value is {actual} bytes"
            ),
            Self::CrcMismatch { stored, computed } => write!(
                f,
                "CRC is 0x{stored:08X} but the data's CRC is 0x{computed:08X}"
            ),
            Self::RawSizeMismatch { declared, actual } => write!(
                f,
                "RAWSIZE says {declared} bytes but {actual} bytes were decompressed"
            ),
            Self::UnknownCompressionType(t) => write!(f, "unknown COMPTYPE 0x{t:08X}"),
            Self::Decompression(e) => write!(f, "decompression failed: {e}"),
        }
    }
}

/// The decompressed RTF body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rtf {
    /// The header, if the value is at least 16 bytes long.
    pub header: Option<RtfHeader>,
    /// The decompressed RTF, if it could be decompressed. RTF is 7-bit text with escapes, so
    /// this is bytes. `compressed_rtf` ends it at the first NUL: writers often pad the RTF
    /// after its final `}` with a NUL and a few bytes, which are left out.
    pub rtf: Option<Vec<u8>>,
    /// The length of the whole decompressed data, NULs and what follows them included, as the
    /// compressed data gives it (see [`RtfFlag::RawSizeMismatch`]).
    pub decompressed_len: Option<u64>,
    /// What is wrong with the stream, if anything.
    pub flags: Vec<RtfFlag>,
}

/// The length of the data that compressed RTF data decompresses to ([MS-OXRTFCP] 2.2.3.2),
/// without decompressing it: up to the end marker (a reference to the dictionary's write
/// offset), or as far as the data goes.
fn decompressed_len(body: &[u8]) -> u64 {
    // The initial dictionary ([MS-OXRTFCP] 2.1.2.1) is 207 bytes long.
    let mut write = 207usize;
    let mut len = 0u64;
    let mut bytes = body.iter().copied();
    while let Some(control) = bytes.next() {
        for bit in 0..8 {
            if control & (1 << bit) == 0 {
                if bytes.next().is_none() {
                    return len;
                }
                len += 1;
                write = (write + 1) % 4096;
            } else {
                let (Some(hi), Some(lo)) = (bytes.next(), bytes.next()) else {
                    return len;
                };
                let reference = u16::from_be_bytes([hi, lo]);
                let offset = usize::from(reference >> 4);
                if offset == write {
                    return len;
                }
                let n = usize::from(reference & 0x0F) + 2;
                len += n as u64;
                write = (write + n) % 4096;
            }
        }
    }
    len
}

/// The CRC of [MS-OXRTFCP] 2.1.3.2: CRC-32 (reflected polynomial 0xEDB88320) starting from 0
/// and without the final inversion.
fn crc(data: &[u8]) -> u32 {
    const TABLE: [u32; 256] = {
        let mut table = [0u32; 256];
        let mut i = 0;
        while i < 256 {
            let mut c = i as u32;
            let mut k = 0;
            while k < 8 {
                c = if c & 1 != 0 {
                    0xEDB8_8320 ^ (c >> 1)
                } else {
                    c >> 1
                };
                k += 1;
            }
            table[i] = c;
            i += 1;
        }
        table
    };
    data.iter().fold(0u32, |crc, &b| {
        TABLE[((crc ^ u32::from(b)) & 0xFF) as usize] ^ (crc >> 8)
    })
}

/// Decompresses a `PidTagRtfCompressed` value.
pub(crate) fn decompress(data: &[u8]) -> Rtf {
    let mut flags = Vec::new();
    let Some(head) = data.first_chunk::<HEADER_LEN>() else {
        flags.push(RtfFlag::TooShort { len: data.len() });
        return Rtf {
            header: None,
            rtf: None,
            decompressed_len: None,
            flags,
        };
    };
    let field = |i: usize| u32::from_le_bytes([head[i], head[i + 1], head[i + 2], head[i + 3]]);
    let header = RtfHeader {
        compressed_size: field(0),
        raw_size: field(4),
        compression_type: field(8),
        crc: field(12),
    };
    // The data ends where COMPSIZE says, or at the end of the value if that comes first.
    let declared = u64::from(header.compressed_size) + 4;
    if declared != data.len() as u64 {
        flags.push(RtfFlag::CompressedSizeMismatch {
            declared,
            actual: data.len(),
        });
    }
    let end = usize::try_from(declared)
        .unwrap_or(usize::MAX)
        .clamp(HEADER_LEN, data.len());
    let body = &data[HEADER_LEN..end];
    // `compressed_rtf::decompress_rtf` trusts the header: give it one that is consistent with
    // the data (the flags above keep what the file said).
    let mut fixed = Vec::with_capacity(end);
    fixed.extend_from_slice(&((end - 4) as u32).to_le_bytes());
    match header.compression_type {
        COMPRESSED => {
            let computed = crc(body);
            if computed != header.crc {
                flags.push(RtfFlag::CrcMismatch {
                    stored: header.crc,
                    computed,
                });
            }
            // RAWSIZE only sizes the output buffer: cap it at what the data can expand to (a
            // control byte and eight 2-byte references give at most 8 * 17 bytes).
            let most = (body.len() as u64).saturating_mul(8);
            let raw = u64::from(header.raw_size)
                .min(most)
                .min(u64::from(u32::MAX)) as u32;
            fixed.extend_from_slice(&raw.to_le_bytes());
            fixed.extend_from_slice(&COMPRESSED.to_le_bytes());
            fixed.extend_from_slice(&computed.to_le_bytes());
        }
        UNCOMPRESSED => {
            let raw = header.raw_size.min(body.len() as u32);
            fixed.extend_from_slice(&raw.to_le_bytes());
            fixed.extend_from_slice(&UNCOMPRESSED.to_le_bytes());
            fixed.extend_from_slice(&header.crc.to_le_bytes());
        }
        other => {
            flags.push(RtfFlag::UnknownCompressionType(other));
            return Rtf {
                header: Some(header),
                rtf: None,
                decompressed_len: None,
                flags,
            };
        }
    }
    let decompressed_len = if header.compression_type == COMPRESSED {
        decompressed_len(body)
    } else {
        u64::from(header.raw_size).min(body.len() as u64)
    };
    fixed.extend_from_slice(body);
    let rtf = match compressed_rtf::decompress_rtf(&fixed) {
        // `decompress_rtf` maps each byte to the char of the same value.
        Ok(text) => Some(text.chars().map(|c| c as u32 as u8).collect::<Vec<u8>>()),
        Err(e) => {
            flags.push(RtfFlag::Decompression(e.to_string()));
            None
        }
    };
    if decompressed_len != u64::from(header.raw_size) {
        flags.push(RtfFlag::RawSizeMismatch {
            declared: header.raw_size,
            actual: decompressed_len,
        });
    }
    Rtf {
        header: Some(header),
        rtf,
        decompressed_len: Some(decompressed_len),
        flags,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc_matches_compressed_rtf() {
        let compressed = compressed_rtf::compress_rtf(r"{\rtf1\ansi Hello}").unwrap();
        let stored = u32::from_le_bytes(compressed[12..16].try_into().unwrap());
        assert_eq!(crc(&compressed[16..]), stored);
        let rtf = decompress(&compressed);
        assert_eq!(rtf.rtf.as_deref(), Some(&br"{\rtf1\ansi Hello}"[..]));
        assert_eq!(rtf.decompressed_len, Some(18));
        assert!(rtf.flags.is_empty(), "{:?}", rtf.flags);
    }

    #[test]
    fn damaged_streams_are_flagged_not_fatal() {
        let good = compressed_rtf::compress_rtf(r"{\rtf1\ansi Hello world}").unwrap();
        // Too short.
        assert_eq!(
            decompress(&good[..10]).flags,
            [RtfFlag::TooShort { len: 10 }]
        );
        // Flipped CRC: still decompressed.
        let mut bad = good.clone();
        bad[12] ^= 0xFF;
        let rtf = decompress(&bad);
        assert!(rtf.rtf.is_some());
        assert!(matches!(rtf.flags[0], RtfFlag::CrcMismatch { .. }));
        // Truncated: size mismatch, partial output.
        let rtf = decompress(&good[..good.len() - 3]);
        assert!(matches!(
            rtf.flags[0],
            RtfFlag::CompressedSizeMismatch { .. }
        ));
        // Huge RAWSIZE must not allocate it.
        let mut huge = good.clone();
        huge[4..8].copy_from_slice(&0xFFFF_FFF0u32.to_le_bytes());
        let rtf = decompress(&huge);
        assert!(rtf.rtf.is_some());
        assert!(
            rtf.flags
                .iter()
                .any(|f| matches!(f, RtfFlag::RawSizeMismatch { .. }))
        );
        // Uncompressed with a RAWSIZE past the end.
        let mut mela = Vec::new();
        mela.extend_from_slice(&24u32.to_le_bytes());
        mela.extend_from_slice(&0xFFFF_FFF0u32.to_le_bytes());
        mela.extend_from_slice(&UNCOMPRESSED.to_le_bytes());
        mela.extend_from_slice(&0u32.to_le_bytes());
        mela.extend_from_slice(b"{\\rtf1 x}abc");
        let rtf = decompress(&mela);
        assert_eq!(rtf.rtf.as_deref(), Some(&b"{\\rtf1 x}abc"[..]));
        // Unknown type.
        let mut unknown = good;
        unknown[8] = 0;
        assert!(decompress(&unknown).rtf.is_none());
    }
}
