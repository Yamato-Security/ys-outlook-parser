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

//! Compares the crate with the output of the extract-msg oracle on the fixtures
//! (tests/oracle/fixtures.oracle.tsv.gz, made by tests/oracle/extract_msg_dump.py). The only
//! differences allowed are those in tests/oracle/fixtures.differences.tsv, each checked and
//! explained there (the same comparison as tests/oracle/compare.py).

mod common;

use flate2::read::GzDecoder;
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::path::Path;

type Key = (String, String, String);

fn parse(text: &str) -> BTreeMap<Key, String> {
    text.lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|line| {
            let mut cols = line.splitn(4, '\t');
            let mut next = || cols.next().expect("4 columns").to_owned();
            ((next(), next(), next()), next())
        })
        .collect()
}

fn close_floating_times(a: &str, b: &str) -> bool {
    match (a.strip_prefix("apptime:"), b.strip_prefix("apptime:")) {
        (Some(a), Some(b)) => match (a.parse::<i64>(), b.parse::<i64>()) {
            (Ok(a), Ok(b)) => (a - b).abs() <= 1,
            _ => false,
        },
        _ => false,
    }
}

#[test]
fn fixtures_match_extract_msg() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/oracle");
    let mut text = String::new();
    GzDecoder::new(std::fs::File::open(dir.join("fixtures.oracle.tsv.gz")).unwrap())
        .read_to_string(&mut text)
        .unwrap();
    let oracle = parse(&text);

    let files = common::fixture_files();
    let oracle_files: BTreeSet<&str> = oracle.keys().map(|k| k.0.as_str()).collect();
    assert_eq!(
        files.iter().map(String::as_str).collect::<BTreeSet<_>>(),
        oracle_files,
        "every fixture has oracle output"
    );
    let ours: BTreeMap<Key, String> = parse(
        &files
            .iter()
            .flat_map(|f| common::dump::dump(f, &common::fixture(f)))
            .map(|l| l + "\n")
            .collect::<String>(),
    );

    // The differences, as compare.py finds them.
    let failed = |facts: &BTreeMap<Key, String>| -> BTreeSet<String> {
        facts
            .keys()
            .filter(|k| k.1 == "file" && k.2 == "open")
            .map(|k| k.0.clone())
            .collect()
    };
    let (failed_oracle, failed_ours) = (failed(&oracle), failed(&ours));
    let mut differences = BTreeMap::new();
    for file in failed_oracle.symmetric_difference(&failed_ours) {
        let key = (file.clone(), "file".to_owned(), "open".to_owned());
        let o = oracle.get(&key).cloned().unwrap_or_else(|| "-".into());
        let c = ours.get(&key).cloned().unwrap_or_else(|| "-".into());
        differences.insert(key, (o, c));
    }
    let keys: BTreeSet<&Key> = oracle.keys().chain(ours.keys()).collect();
    for key in keys {
        if failed_oracle.contains(&key.0) || failed_ours.contains(&key.0) {
            continue;
        }
        let (o, c) = (oracle.get(key), ours.get(key));
        if o == c || o.zip(c).is_some_and(|(o, c)| close_floating_times(o, c)) {
            continue;
        }
        differences.insert(
            key.clone(),
            (
                o.cloned().unwrap_or_else(|| "-".into()),
                c.cloned().unwrap_or_else(|| "-".into()),
            ),
        );
    }

    let explained: BTreeMap<Key, (String, String)> =
        std::fs::read_to_string(dir.join("fixtures.differences.tsv"))
            .unwrap()
            .lines()
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .map(|line| {
                let cols: Vec<&str> = line.split('\t').collect();
                assert_eq!(cols.len(), 6, "{line}");
                (
                    (cols[0].into(), cols[1].into(), cols[2].into()),
                    (cols[3].into(), cols[4].into()),
                )
            })
            .collect();

    let unexplained: Vec<String> = differences
        .iter()
        .filter(|(k, v)| explained.get(*k) != Some(*v))
        .map(|(k, (o, c))| format!("{} | {} | {}\n  oracle: {o}\n  crate:  {c}", k.0, k.1, k.2))
        .collect();
    let gone: Vec<String> = explained
        .keys()
        .filter(|k| !differences.contains_key(*k))
        .map(|k| format!("{} | {} | {}", k.0, k.1, k.2))
        .collect();
    assert!(
        unexplained.is_empty() && gone.is_empty(),
        "differences from extract-msg that are not in fixtures.differences.tsv:\n{}\n\nexplained differences that no longer occur:\n{}",
        unexplained.join("\n"),
        gone.join("\n")
    );
    // The comparison covers something.
    assert!(oracle.keys().filter(|k| k.2.starts_with("p:")).count() > 1000);
}
