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

//! Lenient reading for forensics: what is wrong with a file but does not stop it from being read.
//!
//! A file is read with a [`Validation`]. [`Validation::Lenient`], the default, records each
//! defect it can read past as a [`Problem`] and goes on: a CRC that does not match, a header
//! field with a value MS-PST does not allow, a page or block with a stray value, and a property,
//! table, attachment or sub-node tree that cannot be read (left out of what it belongs to).
//! [`Validation::Strict`] makes the first of those an error, as upstream outlook-pst does.
//! Whatever the validation, a defect reading cannot go past (a B-tree lookup that loops, a block
//! of the wrong size) is an error.
//!
//! [`PstFile::problems`](crate::PstFile::problems) lists the problems found so far: each once,
//! in the order found, at most [`MAX_PROBLEMS`] of them.

use std::{
    cell::RefCell,
    collections::BTreeSet,
    fmt::{self, Display},
    io,
    rc::Rc,
};

use crate::ndb::node_id::NodeId;

/// How strictly a file is checked as it is read.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Validation {
    /// Record each defect reading can go past as a [`Problem`], and go on. The default, for
    /// forensics.
    #[default]
    Lenient,
    /// Make the first defect an error.
    Strict,
}

/// What a [`Problem`] is about.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum ProblemKind {
    /// The header's `dwCRCPartial` or `dwCRCFull` does not match its bytes.
    HeaderCrc,
    /// A header field holds a value MS-PST does not allow: `wMagicClient`, `wVerClient`,
    /// `bPlatformCreate`, `bPlatformAccess`, `dwAlign`, `bSentinel` or reserved bytes.
    HeaderField,
    /// A page's `dwCRC` does not match its bytes.
    PageCrc,
    /// A page holds a value MS-PST does not allow (`dwPadding`), or a B-tree page's `cLevel` is
    /// not below its parent's.
    PageField,
    /// A block's `dwCRC` does not match its bytes.
    BlockCrc,
    /// A block holds a value MS-PST does not allow (an SIBLOCK's or SLBLOCK's `dwPadding`), or an
    /// intermediate block's `cLevel` is not below its parent's.
    BlockField,
    /// A record of a BTree-on-heap could not be read, and is left out.
    HeapRecord,
    /// A property could not be read, and is left out.
    Property,
    /// A message's sub-node tree could not be read: the message has no recipient or attachment
    /// table.
    SubNodeTree,
    /// A table (a folder's hierarchy, contents or associated contents table, a message's
    /// recipient or attachment table, or a table's row index) could not be read.
    Table,
    /// An attachment's method or data could not be read: the attachment has no data.
    Attachment,
    /// The store has no usable `PidTagRecordKey`: entry IDs are made with a record key of zeros,
    /// and folders and messages open by node ID.
    StoreRecordKey,
    /// More than [`MAX_PROBLEMS`] problems: the rest are not recorded.
    TooManyProblems,
}

/// A defect of a file that did not stop it from being read: see the [module](self) docs.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Problem {
    kind: ProblemKind,
    offset: Option<u64>,
    node: Option<NodeId>,
    detail: String,
}

impl Problem {
    pub fn new(
        kind: ProblemKind,
        offset: Option<u64>,
        node: Option<NodeId>,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            kind,
            offset,
            node,
            detail: detail.into(),
        }
    }

    pub fn kind(&self) -> ProblemKind {
        self.kind
    }

    /// The file offset of the header, page or block, when it is known.
    pub fn offset(&self) -> Option<u64> {
        self.offset
    }

    /// The node it was found in, when it is known.
    pub fn node(&self) -> Option<NodeId> {
        self.node
    }

    /// What is wrong.
    pub fn detail(&self) -> &str {
        &self.detail
    }
}

impl Display for Problem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.kind)?;
        if let Some(offset) = self.offset {
            write!(f, " at 0x{offset:X}")?;
        }
        if let Some(node) = self.node {
            write!(f, " in node 0x{:X}", u32::from(node))?;
        }
        write!(f, ": {}", self.detail)
    }
}

/// The most problems a file records: past this, [`ProblemKind::TooManyProblems`] is the last.
pub const MAX_PROBLEMS: usize = 10_000;

/// The problems of one file: each once, in the order found, at most [`MAX_PROBLEMS`].
#[derive(Default)]
pub(crate) struct ProblemLog {
    inner: RefCell<ProblemLogInner>,
}

#[derive(Default)]
struct ProblemLogInner {
    problems: Vec<Problem>,
    seen: BTreeSet<Problem>,
}

impl ProblemLog {
    pub(crate) fn record(&self, problem: Problem) {
        // Recording must not fail: a log that is in use is skipped.
        let Ok(mut inner) = self.inner.try_borrow_mut() else {
            return;
        };
        if inner.problems.len() > MAX_PROBLEMS || inner.seen.contains(&problem) {
            return;
        }
        let problem = if inner.problems.len() == MAX_PROBLEMS {
            Problem::new(
                ProblemKind::TooManyProblems,
                None,
                None,
                format!("more than {MAX_PROBLEMS} problems; the rest are not recorded"),
            )
        } else {
            inner.seen.insert(problem.clone());
            problem
        };
        inner.problems.push(problem);
    }

    pub(crate) fn problems(&self) -> Vec<Problem> {
        self.inner
            .try_borrow()
            .map(|inner| inner.problems.clone())
            .unwrap_or_default()
    }
}

/// What a read needs to know about the file it reads, available to the code that checks CRCs and
/// fields, deep below the file's methods, while the file's reader is locked.
struct Scope {
    validation: Validation,
    log: Rc<ProblemLog>,
    /// Whether the file has 4 KiB pages ([`crate::ndb::header::NdbVersion::Unicode4k`]), once
    /// its header is read.
    large_pages: Option<bool>,
}

thread_local! {
    static SCOPES: RefCell<Vec<Scope>> = const { RefCell::new(Vec::new()) };
    /// The file offset of the page or block being parsed, for the problems found in it.
    static OFFSET: std::cell::Cell<Option<u64>> = const { std::cell::Cell::new(None) };
}

/// Run `read`, a parse of the page or block at `offset`, with that offset given to the problems
/// it finds.
pub(crate) fn at_offset<T>(offset: u64, read: impl FnOnce() -> T) -> T {
    let outer = OFFSET.with(|current| current.replace(Some(offset)));
    let result = read();
    OFFSET.with(|current| current.set(outer));
    result
}

/// Holds a [`Scope`] for as long as it lives: a file's reader is locked with one.
pub(crate) struct ScopeGuard(());

impl ScopeGuard {
    pub(crate) fn new(
        validation: Validation,
        log: Rc<ProblemLog>,
        large_pages: Option<bool>,
    ) -> Self {
        SCOPES.with(|scopes| {
            if let Ok(mut scopes) = scopes.try_borrow_mut() {
                scopes.push(Scope {
                    validation,
                    log,
                    large_pages,
                });
            }
        });
        Self(())
    }
}

impl Drop for ScopeGuard {
    fn drop(&mut self) {
        SCOPES.with(|scopes| {
            if let Ok(mut scopes) = scopes.try_borrow_mut() {
                scopes.pop();
            }
        });
    }
}

/// Whether the file being read is read leniently. Without a scope (structures read on their own,
/// outside a file's methods), it is not.
#[cfg(test)]
fn lenient() -> bool {
    SCOPES.with(|scopes| {
        scopes
            .try_borrow()
            .ok()
            .and_then(|scopes| scopes.last().map(|scope| scope.validation))
            == Some(Validation::Lenient)
    })
}

/// Whether the file being read has 4 KiB pages, if its header has been read.
pub(crate) fn large_pages() -> Option<bool> {
    SCOPES.with(|scopes| {
        scopes
            .try_borrow()
            .ok()
            .and_then(|scopes| scopes.last().and_then(|scope| scope.large_pages))
    })
}

/// A defect reading can go past: recorded when reading leniently, else `error`.
pub(crate) fn check(
    kind: ProblemKind,
    offset: Option<u64>,
    detail: impl FnOnce() -> String,
    error: impl FnOnce() -> io::Error,
) -> io::Result<()> {
    let log = SCOPES.with(|scopes| {
        scopes.try_borrow().ok().and_then(|scopes| {
            scopes
                .last()
                .filter(|scope| scope.validation == Validation::Lenient)
                .map(|scope| scope.log.clone())
        })
    });
    match log {
        Some(log) => {
            let offset = offset.or_else(|| OFFSET.with(|current| current.get()));
            log.record(Problem::new(kind, offset, None, detail()));
            Ok(())
        }
        None => Err(error()),
    }
}

/// [`check`] for a CRC: no problem when `stored` and `computed` match.
pub(crate) fn check_crc(
    kind: ProblemKind,
    offset: Option<u64>,
    what: &str,
    stored: u32,
    computed: u32,
    error: impl FnOnce() -> io::Error,
) -> io::Result<()> {
    if stored == computed {
        return Ok(());
    }
    check(
        kind,
        offset,
        || format!("{what}: stored CRC 0x{stored:08X}, computed 0x{computed:08X}"),
        error,
    )
}

/// A defect found where the file is known: recorded in `log` when `validation` is lenient, else
/// returned as the error.
pub(crate) fn isolate<T>(
    validation: Validation,
    log: &ProblemLog,
    problem: impl FnOnce(&io::Error) -> Problem,
    result: io::Result<T>,
) -> io::Result<Option<T>> {
    match result {
        Ok(value) => Ok(Some(value)),
        Err(err) if validation == Validation::Lenient => {
            log.record(problem(&err));
            Ok(None)
        }
        Err(err) => Err(err),
    }
}

/// A lenient scope for tests of structures read on their own, and its log.
#[cfg(test)]
pub(crate) fn lenient_scope() -> (ScopeGuard, Rc<ProblemLog>) {
    let log = Rc::new(ProblemLog::default());
    (ScopeGuard::new(Validation::Lenient, log.clone(), None), log)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn problem(detail: &str) -> Problem {
        Problem::new(ProblemKind::PageCrc, Some(0x4400), None, detail)
    }

    #[test]
    fn test_log_records_each_problem_once() {
        let log = ProblemLog::default();
        log.record(problem("a"));
        log.record(problem("b"));
        log.record(problem("a"));
        let problems = log.problems();
        assert_eq!(problems.len(), 2);
        assert_eq!(problems[0].detail(), "a");
        assert_eq!(problems[0].to_string(), "PageCrc at 0x4400: a");
    }

    #[test]
    fn test_log_is_capped() {
        let log = ProblemLog::default();
        for i in 0..MAX_PROBLEMS + 100 {
            log.record(problem(&i.to_string()));
        }
        let problems = log.problems();
        assert_eq!(problems.len(), MAX_PROBLEMS + 1);
        assert_eq!(
            problems.last().map(Problem::kind),
            Some(ProblemKind::TooManyProblems)
        );
    }

    #[test]
    fn test_scopes() {
        let error = || io::Error::other("strict");
        // Without a scope, a check is an error.
        assert!(check(ProblemKind::PageCrc, None, String::new, error).is_err());
        assert!(!lenient());

        let log = Rc::new(ProblemLog::default());
        {
            let _lenient = ScopeGuard::new(Validation::Lenient, log.clone(), Some(true));
            assert!(lenient());
            assert_eq!(large_pages(), Some(true));
            assert!(check_crc(ProblemKind::PageCrc, Some(1), "page", 1, 2, error).is_ok());
            assert!(check_crc(ProblemKind::PageCrc, Some(1), "page", 3, 3, error).is_ok());
            {
                let _strict = ScopeGuard::new(Validation::Strict, log.clone(), None);
                assert!(!lenient());
                assert!(check(ProblemKind::PageCrc, None, String::new, error).is_err());
            }
            assert!(lenient());
        }
        assert!(!lenient());
        assert_eq!(log.problems().len(), 1);
        assert_eq!(
            log.problems()[0].detail(),
            "page: stored CRC 0x00000001, computed 0x00000002"
        );
    }
}
