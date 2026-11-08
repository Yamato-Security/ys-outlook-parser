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

//! Reading storages and streams from the compound file, with a limit on the total amount read.

use crate::guid::Guid;
use crate::problem::{ProblemKind, Problems};
use cfb::CompoundFile;
use std::collections::HashSet;
use std::io::{self, Read, Seek};

/// An entry of a storage.
#[derive(Clone, Debug)]
pub(crate) struct Child {
    pub(crate) name: String,
    pub(crate) is_stream: bool,
    pub(crate) clsid: Guid,
}

/// The compound file being read.
pub(crate) struct Reader<F> {
    cfb: CompoundFile<F>,
    /// Bytes that may still be read. Every byte of a well-formed file belongs to at most one
    /// stream, but directory entries can share a sector chain, so the total is capped.
    budget: u64,
    /// Directory entries that may still be listed. Each entry takes 128 bytes of the file and
    /// is listed once when its storage is read, so a file cannot need more.
    entries: u64,
}

/// The path of `name` in the storage at `parent`.
pub(crate) fn join(parent: &str, name: &str) -> String {
    if parent == "/" {
        format!("/{name}")
    } else {
        format!("{parent}/{name}")
    }
}

/// Whether an entry name can be put in a path: `cfb` resolves paths, so an entry named `""`,
/// `.` or `..` (which it accepts) would lead to the storage itself or to its parent.
pub(crate) fn is_addressable(name: &str) -> bool {
    !matches!(name, "" | "." | "..")
}

/// The number of storages from the root to `path` (0 for the root).
pub(crate) fn depth_of(path: &str) -> usize {
    path.split('/').filter(|p| !p.is_empty()).count()
}

pub(crate) fn guid_of(uuid: &cfb::Entry) -> Guid {
    let (d1, d2, d3, d4) = uuid.clsid().as_fields();
    Guid::from_fields(d1, d2, d3, *d4)
}

impl<F: Read + Seek> Reader<F> {
    pub(crate) fn new(cfb: CompoundFile<F>, file_len: u64) -> Self {
        Self {
            cfb,
            budget: file_len.saturating_mul(2).saturating_add(64 << 10),
            entries: file_len / 128 + 16,
        }
    }

    /// The entries of the storage at `path`.
    ///
    /// `cfb` checks the order of directory entry names only against their direct neighbours
    /// in the tree, so a storage can hold two entries whose names are equal ignoring case; as
    /// paths, both lead to the same entry, and following both at every level is exponential.
    /// The second is reported and left out.
    pub(crate) fn children(
        &mut self,
        path: &str,
        problems: &mut Problems,
    ) -> io::Result<Vec<Child>> {
        let mut seen = HashSet::new();
        let mut children = Vec::new();
        for e in self.cfb.read_storage(path)? {
            if self.entries == 0 {
                problems.push(
                    path,
                    ProblemKind::Budget,
                    "more directory entries listed than the file can hold: the rest of this storage is not read",
                );
                break;
            }
            self.entries -= 1;
            let key: (usize, String) = (
                e.name().encode_utf16().count(),
                e.name().chars().flat_map(char::to_uppercase).collect(),
            );
            if !seen.insert(key) {
                problems.push(
                    &join(path, e.name()),
                    ProblemKind::UnknownEntry,
                    "a second entry of the same name (ignoring case): not read",
                );
                continue;
            }
            children.push(Child {
                name: e.name().to_owned(),
                is_stream: e.is_stream(),
                clsid: guid_of(&e),
            });
        }
        Ok(children)
    }

    /// Reads the stream at `path`. Returns the bytes read and whether that is the whole
    /// stream; what went wrong is in `problems`.
    pub(crate) fn read(&mut self, path: &str, problems: &mut Problems) -> (Vec<u8>, bool) {
        let mut stream = match self.cfb.open_stream(path) {
            Ok(s) => s,
            Err(e) => {
                problems.push(path, ProblemKind::Stream, format!("cannot open: {e}"));
                return (Vec::new(), false);
            }
        };
        let declared = stream.len();
        let allowed = declared.min(self.budget);
        // The declared length is not trusted for the allocation: start small and grow with
        // what is actually read (many streams can declare huge lengths and hold nothing).
        let mut data = Vec::with_capacity(allowed.min(64 << 10) as usize);
        let result = (&mut stream).take(allowed).read_to_end(&mut data);
        data.shrink_to_fit();
        self.budget -= (data.len() as u64).min(self.budget);
        let mut complete = true;
        if let Err(e) = result {
            problems.push(
                path,
                ProblemKind::Stream,
                format!("read {} of {declared} bytes, then failed: {e}", data.len()),
            );
            complete = false;
        } else if (data.len() as u64) < allowed {
            problems.push(
                path,
                ProblemKind::Stream,
                format!(
                    "stream is {declared} bytes long but only {} could be read",
                    data.len()
                ),
            );
            complete = false;
        } else if allowed < declared {
            problems.push(
                path,
                ProblemKind::Budget,
                format!(
                    "read {} of {declared} bytes: the limit on the total data read was reached",
                    data.len()
                ),
            );
            complete = false;
        }
        (data, complete)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths() {
        assert_eq!(join("/", "a"), "/a");
        assert_eq!(join("/a", "b"), "/a/b");
        assert_eq!(depth_of("/"), 0);
        assert_eq!(depth_of("/a/b"), 2);
        assert!(is_addressable("__substg1.0_3701000D"));
        assert!(!is_addressable(""));
        assert!(!is_addressable(".."));
    }
}
