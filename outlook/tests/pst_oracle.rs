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

//! Compares what the crate reads from the PST and OST fixtures with what libpff reads
//! (tests/oracle/fixtures.pff.tsv.gz, made by tests/oracle/pff_dump.py), fact by fact. The only
//! differences allowed are those tests/oracle/compare.py explains, by the same rules.

mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Cursor, Read};
use std::path::Path;

use flate2::read::GzDecoder;
use outlook::pst::{Options, PstStore};

/// A fact's key: kind, then the columns that name it.
type Key = Vec<String>;

#[derive(Default)]
struct Facts {
    facts: BTreeMap<Key, Vec<String>>,
    fai: BTreeSet<String>,
}

fn load(text: &str, name: &str) -> Facts {
    let mut out = Facts::default();
    for line in text.lines() {
        let c: Vec<String> = line.split('\t').map(str::to_owned).collect();
        if c.len() < 3 || c[0] != name {
            continue;
        }
        let key = |cols: &[String]| -> Key { cols.to_vec() };
        match c[1].as_str() {
            "folder" => {
                out.facts
                    .insert(vec!["folder".into(), c[2].clone()], key(&c[3..7]));
                if !c[7].is_empty() {
                    out.facts
                        .insert(vec!["folder-fai".into(), c[2].clone()], vec![c[7].clone()]);
                }
            }
            "item" => {
                if c[4] == "1" {
                    out.fai.insert(c[3].clone());
                }
                out.facts
                    .insert(vec!["item".into(), c[3].clone()], vec![c[2].clone()]);
            }
            "prop" => {
                let mut k = vec!["prop".into()];
                k.extend_from_slice(&c[2..6]);
                out.facts.insert(k, key(&c[6..8]));
            }
            "attach" => {
                out.facts.insert(
                    vec!["attach".into(), c[2].clone(), c[3].clone()],
                    key(&c[4..6]),
                );
            }
            _ => {}
        }
    }
    out.facts = reorder_attachments(&out.facts);
    out
}

/// Index each item's attachments by their content (leaving out objects and the data of embedded
/// messages, which the two sides give differently), so that their order does not matter.
fn reorder_attachments(facts: &BTreeMap<Key, Vec<String>>) -> BTreeMap<Key, Vec<String>> {
    let embedded: BTreeSet<(String, String)> = facts
        .iter()
        .filter(|(k, v)| {
            k[0] == "prop" && k[1] == "attachment" && k[4] == "3705" && v[1] == "05000000"
        })
        .map(|(k, _)| (k[2].clone(), k[3].clone()))
        .collect();
    let mut by_item: BTreeMap<String, BTreeMap<String, Vec<Vec<String>>>> = BTreeMap::new();
    for (k, v) in facts {
        let (item, index, signature) = match k[0].as_str() {
            "attach" => {
                let keep = !embedded.contains(&(k[1].clone(), k[2].clone()));
                let mut s = vec!["attach".to_owned()];
                s.extend(v.iter().cloned());
                (&k[1], &k[2], keep.then_some(s))
            }
            "prop" if k[1] == "attachment" => {
                let mut s = vec![k[4].clone()];
                s.extend(v.iter().cloned());
                (&k[2], &k[3], (v[0] != "000d").then_some(s))
            }
            _ => continue,
        };
        let list = by_item
            .entry(item.clone())
            .or_default()
            .entry(index.clone())
            .or_default();
        list.extend(signature);
    }
    let mut order = BTreeMap::new();
    for (item, attachments) in &mut by_item {
        let mut ranked: Vec<(Vec<Vec<String>>, u32, String)> = attachments
            .iter_mut()
            .map(|(index, signature)| {
                signature.sort();
                (signature.clone(), index.parse().unwrap(), index.clone())
            })
            .collect();
        ranked.sort();
        for (new, (_, _, old)) in ranked.into_iter().enumerate() {
            order.insert((item.clone(), old), new.to_string());
        }
    }
    facts
        .iter()
        .map(|(k, v)| {
            let mut k = k.clone();
            if k[0] == "attach" {
                k[2] = order[&(k[1].clone(), k[2].clone())].clone();
            } else if k[0] == "prop" && k[1] == "attachment" {
                k[3] = order[&(k[2].clone(), k[3].clone())].clone();
            }
            (k, v.clone())
        })
        .collect()
}

/// Why a fact differs (see tests/oracle/compare.py), or `None`.
fn explain(
    key: &Key,
    ours: Option<&Vec<String>>,
    theirs: Option<&Vec<String>>,
    crate_facts: &Facts,
) -> Option<&'static str> {
    let owner = match key[0].as_str() {
        "item" | "attach" => Some(&key[1]),
        "prop" if ["item", "recipient", "attachment"].contains(&key[1].as_str()) => Some(&key[2]),
        _ => None,
    };
    match (ours, theirs) {
        (Some(_), None) => {
            if key[0] == "folder-fai" || owner.is_some_and(|o| crate_facts.fai.contains(o)) {
                Some("FAI")
            } else if key[0] == "prop"
                && key[1] == "folder"
                && ["0fff", "3601"].contains(&key[4].as_str())
            {
                Some("computed")
            } else {
                None
            }
        }
        (None, Some(theirs)) => {
            (key[0] == "prop" && key[1] == "recipient" && theirs[1].chars().all(|c| c == '0'))
                .then_some("absent cell")
        }
        (Some(ours), Some(theirs)) => {
            if key[0] == "prop" && ours[0] == "000d" && theirs[0] == "000d" {
                Some("object")
            } else if key[0] == "attach"
                && ours[0] == "0"
                && ours[1].is_empty()
                && crate_facts
                    .facts
                    .get(&vec![
                        "prop".to_owned(),
                        "attachment".to_owned(),
                        key[1].clone(),
                        key[2].clone(),
                        "3705".to_owned(),
                    ])
                    .is_some_and(|m| m[1] == "05000000")
            {
                Some("embedded message")
            } else {
                None
            }
        }
        (None, None) => None,
    }
}

#[test]
fn fixtures_match_libpff() {
    let mut oracle = String::new();
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/oracle/fixtures.pff.tsv.gz");
    GzDecoder::new(std::fs::File::open(path).unwrap())
        .read_to_string(&mut oracle)
        .unwrap();
    let mut counts = BTreeMap::<&str, usize>::new();
    for name in [
        "Empty.pst",
        "dist-list.pst",
        "example-2013.ost",
        "outlook.pst",
    ] {
        let store =
            PstStore::from_reader(Cursor::new(common::pst_fixture(name)), &Options::default());
        let mut dump = Vec::new();
        common::dump::dump(&mut dump, store, name).unwrap();
        let ours = load(&String::from_utf8(dump).unwrap(), name);
        let theirs = load(&oracle, name);
        assert!(!theirs.facts.is_empty(), "{name}: no libpff facts");
        let keys: BTreeSet<&Key> = ours.facts.keys().chain(theirs.facts.keys()).collect();
        for key in keys {
            let (a, b) = (ours.facts.get(key), theirs.facts.get(key));
            if a == b {
                *counts.entry("same").or_default() += 1;
                continue;
            }
            let why = explain(key, a, b, &ours);
            assert!(why.is_some(), "{name}: {key:?}: crate {a:?}, libpff {b:?}");
            *counts.entry(why.unwrap()).or_default() += 1;
        }
    }
    // what tests/oracle/compare.py prints for the fixtures
    assert_eq!(
        counts,
        BTreeMap::from([
            ("same", 2600),
            ("FAI", 360),
            ("computed", 196),
            ("absent cell", 40),
            ("embedded message", 2),
            ("object", 2),
        ])
    );
}
