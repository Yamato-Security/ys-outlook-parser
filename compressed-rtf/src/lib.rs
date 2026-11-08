// Copyright (C) 2026 Shirofune Security Co., Ltd.
// Copyright (c) Microsoft Corporation.
//
// This file is changed from microsoft/outlook-pst-rs (https://github.com/microsoft/outlook-pst-rs), whose code
// is under the MIT License (LICENSE-MIT).
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

#![doc = include_str!("../README.md")]
// No input may panic or abort this crate: outside tests, no unchecked indexing, slicing or
// arithmetic, and no unwrap, expect or panic.
#![cfg_attr(
    not(test),
    deny(
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects,
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::unreachable,
        clippy::todo,
        clippy::unimplemented
    )
)]

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::io::{self, Cursor, Write};
use thiserror::Error;

mod crc;
mod dictionary;

use dictionary::{DictionaryReference, TokenDictionary};

#[derive(Error, Debug)]
pub enum Error {
    #[error("IO error: {0:?}")]
    IoError(#[from] io::Error),
    #[error("COMPSIZE mismatch: {0}")]
    CompressedSizeMismatch(u32),
    #[error("COMPRESSED CRC mismatch: 0x{0:08X}")]
    CompressedCrcMismatch(u32),
    #[error("Invalid COMPTYPE: 0x{0:08X}")]
    InvalidCompressionType(u32),
    #[error("Dictionary reference error: {0:?}")]
    DictionaryError(#[from] dictionary::Error),
    #[error("Invalid ASCII RTF content")]
    InvalidAsciiRtf,
    #[error("COMPRESSED RTF too large: {0}")]
    CompressedRtfTooLarge(usize),
    #[error("UNCOMPRESSED RTF too large: {0}")]
    UncompressedRtfTooLarge(usize),
    #[error("Compressed RTF shorter than its 16-byte header: {0} bytes")]
    HeaderTooShort(usize),
    #[error("RAWSIZE larger than the uncompressed RTF data: {0}")]
    RawSizeMismatch(u32),
}

pub type Result<T> = std::result::Result<T, Error>;

const COMPRESSED: u32 = 0x75465A4C;
const UNCOMPRESSED: u32 = 0x414C454D;

pub fn decompress_rtf(data: &[u8]) -> Result<String> {
    let Some((header, body)) = data.split_first_chunk::<16>() else {
        return Err(Error::HeaderTooShort(data.len()));
    };
    let mut cursor = Cursor::new(header);
    let compressed_size = cursor.read_u32::<LittleEndian>()?;

    // COMPSIZE counts the bytes after itself.
    if u64::from(compressed_size).checked_add(size_of_val(&compressed_size) as u64)
        != Some(data.len() as u64)
    {
        return Err(Error::CompressedSizeMismatch(compressed_size));
    }

    let raw_size = cursor.read_u32::<LittleEndian>()?;
    let compression_type = cursor.read_u32::<LittleEndian>()?;
    let crc = cursor.read_u32::<LittleEndian>()?;

    match compression_type {
        COMPRESSED => {
            let compressed_crc = crc::calculate_crc(0, body);
            if crc != compressed_crc {
                return Err(Error::CompressedCrcMismatch(crc));
            }

            let mut dictionary = TokenDictionary::default();
            // RAWSIZE comes from the data: reserve no more than the input can expand to (a
            // control byte and eight 2-byte references give at most 136 bytes from 17).
            let capacity = (raw_size as usize).min(body.len().saturating_mul(8));
            let mut output = Vec::with_capacity(capacity);

            let mut cursor = Cursor::new(body);
            'decompress: while let Ok(control) = cursor.read_u8() {
                for i in 0..8 {
                    let bit = control & (0x01 << i);
                    if bit == 0 {
                        let Ok(byte) = cursor.read_u8() else {
                            break 'decompress;
                        };
                        output.push(byte);
                        dictionary.write_byte(byte);
                    } else {
                        let reference = DictionaryReference::read(&mut cursor)?;
                        let Some(mut reference) = dictionary.read_reference(reference) else {
                            break 'decompress;
                        };
                        output.append(&mut reference);
                    }
                }
            }

            Ok(string_from_ascii(&output))
        }
        UNCOMPRESSED => {
            let rtf = body
                .get(..raw_size as usize)
                .ok_or(Error::RawSizeMismatch(raw_size))?;
            Ok(string_from_ascii(rtf))
        }
        invalid => Err(Error::InvalidCompressionType(invalid)),
    }
}

fn string_from_ascii(data: &[u8]) -> String {
    // RTF can contain binary payloads (\binN), including zero bytes. Its length is
    // determined by the compression stream, not a string terminator.
    let data: Vec<_> = data.iter().copied().map(u16::from).collect();
    String::from_utf16_lossy(&data)
}

fn convert_to_ascii(rtf: &str) -> Result<Vec<u8>> {
    rtf.encode_utf16()
        .map(|ch| u8::try_from(ch).map_err(|_| Error::InvalidAsciiRtf))
        .collect()
}

pub fn compress_rtf(rtf: &str) -> Result<Vec<u8>> {
    let data = convert_to_ascii(rtf)?;
    if data.len() > (u32::MAX - 12) as usize {
        return Err(Error::UncompressedRtfTooLarge(data.len()));
    }

    let mut output = Cursor::new(Vec::with_capacity(data.len().saturating_add(16)));
    output.write_all(&[0_u8; 16])?;

    let mut read_offset = 0;
    let mut dictionary = TokenDictionary::default();
    let mut run_buffer = [0_u8; 16];

    // Runs of up to eight literal bytes or references, each after its control byte; the last run
    // ends with the reference to the dictionary's write offset.
    let (control, run_length) = 'runs: loop {
        let mut cursor = Cursor::new(run_buffer.as_mut_slice());
        let mut control = 0_u8;
        let mut run_length = 0_usize;

        for i in 0..8 {
            let Some(input) = data.get(read_offset..).filter(|input| !input.is_empty()) else {
                dictionary.final_reference().write(&mut cursor)?;
                control |= 0x01 << i;
                run_length = run_length.saturating_add(2);
                break 'runs (control, run_length);
            };

            match dictionary.find_longest_match(input)? {
                Some(best_match) => {
                    best_match.write(&mut cursor)?;
                    let best_match_length = best_match.length() as usize;
                    read_offset = read_offset.saturating_add(best_match_length);
                    control |= 0x01 << i;
                    run_length = run_length.saturating_add(2);
                }
                None => {
                    let byte = input.first().copied().unwrap_or_default();
                    cursor.write_u8(byte)?;
                    read_offset = read_offset.saturating_add(1);
                    run_length = run_length.saturating_add(1);
                }
            }
        }

        output.write_u8(control)?;
        output.write_all(run_buffer.get(..run_length).unwrap_or_default())?;
    };

    output.write_u8(control)?;
    output.write_all(run_buffer.get(..run_length).unwrap_or_default())?;

    let mut output = output.into_inner();
    let compressed_size = u32::try_from(output.len())
        .ok()
        .and_then(|size| size.checked_sub(size_of::<u32>() as u32))
        .ok_or(Error::CompressedRtfTooLarge(output.len()))?;
    let raw_size =
        u32::try_from(data.len()).map_err(|_| Error::UncompressedRtfTooLarge(data.len()))?;
    let compression_type = COMPRESSED;
    let (header, body) = output
        .split_first_chunk_mut::<16>()
        .ok_or(Error::CompressedRtfTooLarge(0))?;
    let crc = crc::calculate_crc(0, body);

    let mut header = Cursor::new(header.as_mut_slice());
    header.write_u32::<LittleEndian>(compressed_size)?;
    header.write_u32::<LittleEndian>(raw_size)?;
    header.write_u32::<LittleEndian>(compression_type)?;
    header.write_u32::<LittleEndian>(crc)?;

    Ok(output)
}

pub fn encode_rtf(rtf: &str) -> Result<Vec<u8>> {
    let data = convert_to_ascii(rtf)?;
    if data.len() > (u32::MAX - 12) as usize {
        return Err(Error::UncompressedRtfTooLarge(data.len()));
    }
    let raw_size =
        u32::try_from(data.len()).map_err(|_| Error::UncompressedRtfTooLarge(data.len()))?;
    let compressed_size = raw_size
        .checked_add(12)
        .ok_or(Error::UncompressedRtfTooLarge(data.len()))?;
    let compression_type = UNCOMPRESSED;
    let crc = 0;

    let mut cursor = Cursor::new(Vec::with_capacity(data.len().saturating_add(16)));
    cursor.write_u32::<LittleEndian>(compressed_size)?;
    cursor.write_u32::<LittleEndian>(raw_size)?;
    cursor.write_u32::<LittleEndian>(compression_type)?;
    cursor.write_u32::<LittleEndian>(crc)?;
    cursor.write_all(&data)?;

    Ok(cursor.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;

    const COMPRESSED_SIMPLE_RTF: &[u8] = &[
        0x2d, 0x00, 0x00, 0x00, 0x2b, 0x00, 0x00, 0x00, 0x4c, 0x5a, 0x46, 0x75, 0xf1, 0xc5, 0xc7,
        0xa7, 0x03, 0x00, 0x0a, 0x00, 0x72, 0x63, 0x70, 0x67, 0x31, 0x32, 0x35, 0x42, 0x32, 0x0a,
        0xf3, 0x20, 0x68, 0x65, 0x6c, 0x09, 0x00, 0x20, 0x62, 0x77, 0x05, 0xb0, 0x6c, 0x64, 0x7d,
        0x0a, 0x80, 0x0f, 0xa0,
    ];

    const UNCOMPRESSED_SIMPLE_RTF: &str = "{\\rtf1\\ansi\\ansicpg1252\\pard hello world}\r\n";

    #[test]
    fn binary_rtf_preserves_zero_bytes_and_the_following_text() {
        // The \bin payload is bytes, not a NUL-terminated string.
        let rtf = "{\\rtf1\\ansi\\bin3 A\0B tail}";
        for encoded in [compress_rtf(rtf).unwrap(), encode_rtf(rtf).unwrap()] {
            assert_eq!(decompress_rtf(&encoded).unwrap(), rtf);
        }
        // Exercise every byte, including dictionary references crossing embedded zeroes.
        let bytes: String = (0..=255).map(char::from).collect();
        let rtf = format!("{{\\rtf1\\ansi\\bin512 {bytes}{bytes} tail}}");
        for encoded in [compress_rtf(&rtf).unwrap(), encode_rtf(&rtf).unwrap()] {
            assert_eq!(decompress_rtf(&encoded).unwrap(), rtf);
        }
    }

    /// [Example 1: Simple Compressed RTF](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxrtfcp/029bff74-8c00-402e-ac2b-0210a5f57371)
    #[test]
    fn test_decompress_simple_rtf() {
        let rtf = decompress_rtf(COMPRESSED_SIMPLE_RTF).unwrap();
        assert_eq!(rtf, UNCOMPRESSED_SIMPLE_RTF);
    }

    /// [Example 1: Simple RTF](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxrtfcp/ba662823-d47a-4db3-ad45-a368a82acc90)
    #[test]
    fn test_compress_simple_rtf() {
        let compressed = compress_rtf(UNCOMPRESSED_SIMPLE_RTF).unwrap();
        assert_eq!(&compressed, COMPRESSED_SIMPLE_RTF);
    }

    const COMPRESSED_CROSSING_WRITE_RTF: &[u8] = &[
        0x1a, 0x00, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x00, 0x4c, 0x5a, 0x46, 0x75, 0xe2, 0xd4, 0x4b,
        0x51, 0x41, 0x00, 0x04, 0x20, 0x57, 0x58, 0x59, 0x5a, 0x0d, 0x6e, 0x7d, 0x01, 0x0e, 0xb0,
    ];

    const UNCOMPRESSED_CROSSING_WRITE_RTF: &str = "{\\rtf1 WXYZWXYZWXYZWXYZWXYZ}";

    /// [Example 2: Reading a Token from the Dictionary that Crosses WritePosition](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxrtfcp/421a2da5-7752-4985-8981-0f19f1e5b687)
    #[test]
    fn test_decompress_crossing_write_rtf() {
        let rtf = decompress_rtf(COMPRESSED_CROSSING_WRITE_RTF).unwrap();
        assert_eq!(rtf, UNCOMPRESSED_CROSSING_WRITE_RTF);
    }

    /// [Example 2: Compressing with Tokens that Cross WritePosition](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxrtfcp/59eb3a35-6ee1-4a08-93b9-b9f4a7e3a0ca)
    #[test]
    fn test_compress_crossing_write_rtf() {
        let compressed = compress_rtf(UNCOMPRESSED_CROSSING_WRITE_RTF).unwrap();
        assert_eq!(&compressed, COMPRESSED_CROSSING_WRITE_RTF);
    }

    /// A header for `body`: COMPSIZE, RAWSIZE, COMPTYPE and, for compressed data, the CRC.
    fn with_header(raw_size: u32, compression_type: u32, body: &[u8]) -> Vec<u8> {
        let crc = if compression_type == COMPRESSED {
            crc::calculate_crc(0, body)
        } else {
            0
        };
        let mut data = Vec::new();
        data.extend_from_slice(&(body.len() as u32 + 12).to_le_bytes());
        data.extend_from_slice(&raw_size.to_le_bytes());
        data.extend_from_slice(&compression_type.to_le_bytes());
        data.extend_from_slice(&crc.to_le_bytes());
        data.extend_from_slice(body);
        data
    }

    #[test]
    fn test_short_input_is_an_error() {
        for len in 0..16 {
            assert!(matches!(
                decompress_rtf(&COMPRESSED_SIMPLE_RTF[..len]),
                Err(Error::HeaderTooShort(n)) if n == len
            ));
        }
    }

    #[test]
    fn test_compressed_size_mismatch_is_an_error() {
        let mut data = COMPRESSED_SIMPLE_RTF.to_vec();
        data.push(0);
        assert!(matches!(
            decompress_rtf(&data),
            Err(Error::CompressedSizeMismatch(_))
        ));
        let mut data = COMPRESSED_SIMPLE_RTF.to_vec();
        data[..4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(matches!(
            decompress_rtf(&data),
            Err(Error::CompressedSizeMismatch(u32::MAX))
        ));
    }

    #[test]
    fn test_uncompressed_raw_size_past_the_data_is_an_error() {
        // A RAWSIZE larger than the data panicked on an unchecked slice (seen on a real MSG).
        let data = with_header(100, UNCOMPRESSED, b"{\\rtf1}");
        assert!(matches!(
            decompress_rtf(&data),
            Err(Error::RawSizeMismatch(100))
        ));
        let data = with_header(u32::MAX, UNCOMPRESSED, b"");
        assert!(decompress_rtf(&data).is_err());
        let data = with_header(7, UNCOMPRESSED, b"{\\rtf1}");
        assert_eq!(decompress_rtf(&data).unwrap(), "{\\rtf1}");
    }

    #[test]
    fn test_huge_raw_size_reserves_nothing_unbounded() {
        // RAWSIZE says 4 GiB; the output is what the 34 bytes of input decompress to.
        let body = &COMPRESSED_SIMPLE_RTF[16..];
        let data = with_header(u32::MAX, COMPRESSED, body);
        assert_eq!(decompress_rtf(&data).unwrap(), UNCOMPRESSED_SIMPLE_RTF);
    }

    #[test]
    fn test_truncated_reference_does_not_panic() {
        // Control byte 0x01: a reference follows, but only one of its two bytes does.
        let data = with_header(10, COMPRESSED, &[0x01, 0x00]);
        assert!(decompress_rtf(&data).is_err());
        // Eight references to offset 0 and length 17, then the end of the input.
        let mut body = vec![0xFF];
        body.extend_from_slice(&[0x00, 0x0F].repeat(8));
        let data = with_header(0, COMPRESSED, &body);
        assert!(decompress_rtf(&data).is_ok());
    }

    #[test]
    fn test_mutated_input_does_not_panic() {
        // A fixed-seed xorshift: deterministic, a few thousand inputs.
        let mut state = 0x2545_F491_4F6C_DD1D_u64;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for sample in [COMPRESSED_SIMPLE_RTF, COMPRESSED_CROSSING_WRITE_RTF] {
            let body = &sample[16..];
            for _ in 0..2000 {
                let mut body = body.to_vec();
                for _ in 0..(next() % 4 + 1) {
                    let position = next() as usize % body.len();
                    body[position] = next() as u8;
                }
                body.truncate(next() as usize % (body.len() + 1));
                if next() % 2 == 0 {
                    body.extend((0..next() % 64).map(|_| next() as u8));
                }
                // With a valid header and CRC, so that decompression runs.
                let raw_size = next() as u32;
                let _ = decompress_rtf(&with_header(raw_size, COMPRESSED, &body));
                let _ = decompress_rtf(&with_header(raw_size, UNCOMPRESSED, &body));
                // And the raw mutated bytes.
                let mut raw = sample.to_vec();
                let position = next() as usize % raw.len();
                raw[position] = next() as u8;
                let _ = decompress_rtf(&raw);
            }
        }
    }

    #[test]
    fn test_round_trip() {
        let long: String = (0..10_000)
            .map(|i| char::from(b"{\\rtf1 abcdefgh}\r\n"[(i * 7 + i / 13) % 18]))
            .collect();
        for rtf in ["", "a", UNCOMPRESSED_SIMPLE_RTF, &long] {
            let compressed = compress_rtf(rtf).unwrap();
            assert_eq!(decompress_rtf(&compressed).unwrap(), rtf);
            assert_eq!(decompress_rtf(&encode_rtf(rtf).unwrap()).unwrap(), rtf);
        }
    }
}
