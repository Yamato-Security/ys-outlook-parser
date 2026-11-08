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

//! Dumps what is read from PST and OST files as TSV lines, in the layout of
//! `tests/oracle/pff_dump.py` (libpff), for a field-by-field comparison with
//! `tests/oracle/compare.py`:
//!
//! ```text
//! cargo run --release -p ys-outlook-parser --example pst_dump -- FILE... > crate.tsv
//! ```

#[path = "../tests/common/dump.rs"]
mod dump;

use std::io::{self, BufWriter, Write};

use outlook::pst::{Options, PstStore};

fn main() -> io::Result<()> {
    let out = io::stdout();
    let mut out = BufWriter::new(out.lock());
    for path in std::env::args().skip(1) {
        let name = path.rsplit('/').next().unwrap_or(&path).to_owned();
        dump::dump(&mut out, PstStore::open(&path, &Options::default()), &name)?;
    }
    out.flush()
}
