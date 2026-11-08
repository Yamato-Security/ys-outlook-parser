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

//! Every fixture opens and reads as libpff reads it: the same folders, messages and attachments.

mod common;

use common::*;

#[test]
fn empty_pst() {
    let store = open_unicode(fixture("Empty.pst")).unwrap();
    let counts = walk(&store);
    assert_eq!(counts.folders, 6);
    assert_eq!(counts.folder_errors, 0);
    assert_eq!(counts.messages, 0);
}

#[test]
fn dist_list_pst() {
    let store = open_unicode(fixture("dist-list.pst.gz")).unwrap();
    let counts = walk(&store);
    assert_eq!((counts.folders, counts.folder_errors), (24, 0));
    assert_eq!((counts.messages, counts.messages_read), (4, 4));
    assert_eq!((counts.fai, counts.fai_read), (3, 3));
    assert_eq!(counts.attachments, 2);
}

#[test]
fn outlook_pst() {
    let store = open_unicode(fixture("outlook.pst.gz")).unwrap();
    let counts = walk(&store);
    assert_eq!((counts.folders, counts.folder_errors), (22, 0));
    assert_eq!((counts.messages, counts.messages_read), (2, 2));
    assert_eq!(counts.recipients, 2);
    assert_eq!((counts.attachments, counts.attachments_read), (22, 22));
}

#[test]
fn example_2013_ost() {
    let store = open_unicode(fixture("example-2013.ost.gz")).unwrap();
    let counts = walk(&store);
    assert_eq!((counts.folders, counts.folder_errors), (46, 0));
    assert_eq!((counts.messages, counts.messages_read), (3, 3));
    assert_eq!((counts.fai, counts.fai_read), (14, 14));
    assert_eq!(counts.attachments, 0);
}
