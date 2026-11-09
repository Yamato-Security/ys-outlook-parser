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

//! Shared by the integration tests.

#![allow(dead_code)]

pub mod dump;

use std::io::Read;
use std::path::Path;

use flate2::read::GzDecoder;

/// A PST or OST fixture of the pst crate (`pst/tests/fixtures`), decompressed.
pub fn pst_fixture(name: &str) -> Vec<u8> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../pst/tests/fixtures");
    let plain = dir.join(name);
    if plain.exists() {
        return std::fs::read(plain).unwrap();
    }
    let mut data = Vec::new();
    GzDecoder::new(std::fs::File::open(dir.join(format!("{name}.gz"))).unwrap())
        .read_to_end(&mut data)
        .unwrap();
    data
}

/// A fixture of this crate (`tests/fixtures`), decompressed.
pub fn outlook_fixture(name: &str) -> Vec<u8> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(format!("{name}.gz"));
    let mut data = Vec::new();
    GzDecoder::new(std::fs::File::open(path).unwrap())
        .read_to_end(&mut data)
        .unwrap();
    data
}

/// A `.msg` or `.oft` fixture of the msg crate (`msg/tests/fixtures`).
pub fn msg_fixture(path: &str) -> Vec<u8> {
    std::fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../msg/tests/fixtures")
            .join(path),
    )
    .unwrap()
}
