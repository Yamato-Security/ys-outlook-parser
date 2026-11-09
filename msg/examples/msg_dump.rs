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

//! Dumps .msg/.oft files in the format of `tests/oracle/extract_msg_dump.py`, for comparison with
//! the oracle (`tests/oracle/compare.py`).
//!
//! ```text
//! cargo run --example msg_dump -- ROOT FILE... > crate.tsv
//! cargo run --example msg_dump -- --problems ROOT FILE...
//! ```
//!
//! FILE paths are relative to ROOT. With `--problems`, the problems of each file are listed
//! instead.

#[path = "../tests/common/dump.rs"]
mod dump;

use std::io::Write;

fn main() {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let problems = args.first().is_some_and(|a| a == "--problems");
    if problems {
        args.remove(0);
    }
    let Some((root, files)) = args.split_first() else {
        eprintln!("usage: msg_dump [--problems] ROOT FILE...");
        std::process::exit(2);
    };
    let mut lines = Vec::new();
    for rel in files {
        let data = match std::fs::read(format!("{root}/{rel}")) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("{rel}: {e}");
                continue;
            }
        };
        if problems {
            match outlook_msg::MsgFile::from_bytes(&data) {
                Err(e) => lines.push(format!("{rel}\tERROR\t{e}")),
                Ok(f) => {
                    for p in f.all_problems() {
                        lines.push(format!("{rel}\t{}\t{}\t{}", p.kind, p.path, p.detail));
                    }
                }
            }
        } else {
            lines.extend(dump::dump(rel, &data));
        }
    }
    if !problems {
        lines.sort();
    }
    let mut out = std::io::stdout().lock();
    for line in lines {
        let _ = writeln!(out, "{line}");
    }
}
