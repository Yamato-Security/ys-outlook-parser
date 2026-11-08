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

//! The file is only ever read: opening and reading everything in a read-only copy of each fixture
//! works and leaves its bytes and modification time as they were.

mod common;

use common::*;
use outlook_pst::{UnicodePstFile, messaging::store::UnicodeStore};
use std::{fs, path::PathBuf, rc::Rc};

fn read_only_copy(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "ys-outlook-parser-read-only-{}",
        std::process::id()
    ));
    fs::create_dir_all(&dir).unwrap();
    let path = dir.join(name.trim_end_matches(".gz"));
    if path.exists() {
        let mut permissions = fs::metadata(&path).unwrap().permissions();
        #[allow(clippy::permissions_set_readonly_false)]
        permissions.set_readonly(false);
        fs::set_permissions(&path, permissions).unwrap();
    }
    fs::write(&path, fixture(name)).unwrap();
    let mut permissions = fs::metadata(&path).unwrap().permissions();
    permissions.set_readonly(true);
    fs::set_permissions(&path, permissions).unwrap();
    path
}

#[test]
fn reading_leaves_the_file_unchanged() {
    for name in [
        "Empty.pst",
        "dist-list.pst.gz",
        "outlook.pst.gz",
        "example-2013.ost.gz",
    ] {
        let path = read_only_copy(name);
        let before = fs::read(&path).unwrap();
        let modified = fs::metadata(&path).unwrap().modified().unwrap();

        let store = UnicodeStore::read(Rc::new(UnicodePstFile::open(&path).unwrap())).unwrap();
        let counts = walk(&store);
        assert!(counts.folders > 0, "{name}");
        drop(store);
        assert!(outlook_pst::open_store(&path).is_ok(), "{name}");

        assert_eq!(fs::read(&path).unwrap(), before, "{name}");
        assert_eq!(
            fs::metadata(&path).unwrap().modified().unwrap(),
            modified,
            "{name}"
        );
        let mut permissions = fs::metadata(&path).unwrap().permissions();
        #[allow(clippy::permissions_set_readonly_false)]
        permissions.set_readonly(false);
        fs::set_permissions(&path, permissions).unwrap();
        fs::remove_file(&path).unwrap();
    }
}
