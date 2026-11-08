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

//! ## [Permutative Encoding](https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-pst/5faf4800-645d-49d1-9457-2ac40eb467bd)
//!
//! This is a direct port of the [crate::ndb::NdbCryptMethod::Permute] code from the PST specification.

use super::*;

/// Encode the [crate::ndb::block::DataBlock] data.
#[cfg(test)]
pub fn encode_block(data: &mut [u8]) {
    permute(data, key_data_r());
}

/// Decode the [crate::ndb::block::DataBlock] data.
pub fn decode_block(data: &mut [u8]) {
    permute(data, key_data_i());
}

fn permute(data: &mut [u8], table: &[u8]) {
    for b in data.iter_mut() {
        *b = table[*b as usize];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &[u8] = b"Hello, World!";

    #[test]
    fn test_encode_block() {
        let mut data = SAMPLE.to_vec();
        encode_block(&mut data);
        assert_ne!(SAMPLE, &data);
    }

    #[test]
    fn test_decode_block() {
        let mut data = SAMPLE.to_vec();
        encode_block(&mut data);
        decode_block(&mut data);
        assert_eq!(SAMPLE, &data);
    }
}
