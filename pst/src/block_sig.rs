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

//! ## [Block Signature](https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-pst/e700a913-9db5-46a4-ac76-37cabea823e1)
//!
//! This is a direct port of the block signature calculation code from the PST specification.

/// Compute the block signature.
pub fn compute_sig(index: u32, block_id: u32) -> u16 {
    let value = index ^ block_id;
    (value >> 16) as u16 ^ (value as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_sig() {
        assert_eq!(compute_sig(0x00000000, 0x00000000), 0x0000);
        assert_eq!(compute_sig(0x00000000, 0x00000001), 0x0001);
        assert_eq!(compute_sig(0x00000001, 0x00000000), 0x0001);
        assert_eq!(compute_sig(0x00000001, 0x00000001), 0x0000);
        assert_eq!(compute_sig(0x00000000, 0x00000002), 0x0002);
        assert_eq!(compute_sig(0x00000002, 0x00000000), 0x0002);
        assert_eq!(compute_sig(0x00000002, 0x00000002), 0x0000);
    }

    #[test]
    fn test_overflow() {
        assert_eq!(compute_sig(0x00000000, 0x00010000), 0x0001);
        assert_eq!(compute_sig(0x00010000, 0x00000000), 0x0001);
        assert_eq!(compute_sig(0x00010000, 0x00010000), 0x0000);
    }
}
