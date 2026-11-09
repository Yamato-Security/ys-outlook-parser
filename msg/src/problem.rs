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

//! Problems found while reading a file: what was damaged, unsupported or unexpected, and where.

use std::fmt;

/// What kind of problem a [`Problem`] is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum ProblemKind {
    /// The compound file is shorter than its FAT says: the missing sectors were read as
    /// zeros.
    CompoundFile,
    /// A storage could not be listed.
    Storage,
    /// A stream could not be read, or was read only in part.
    Stream,
    /// The `__properties_version1.0` stream is missing, too short, or has a header or entries
    /// that do not fit.
    PropertyStream,
    /// A property value is damaged (see [`PropertyValue::Damaged`](crate::PropertyValue::Damaged)).
    PropertyValue,
    /// A property type this crate does not decode (see
    /// [`PropertyValue::Unsupported`](crate::PropertyValue::Unsupported)).
    UnsupportedType,
    /// The named-property mapping (`__nameid_version1.0`) is missing a stream or has a bad entry.
    NamedProperties,
    /// Text that is not valid in its encoding: invalid UTF-16 (for example an unpaired
    /// surrogate) or bytes that are not valid in the code page. The text has U+FFFD in their
    /// place; the raw bytes are kept.
    Text,
    /// A code page this crate cannot decode; the text was decoded as Windows-1252 instead.
    CodePage,
    /// The compressed RTF body is damaged (bad CRC, size, or compression type).
    Rtf,
    /// The recipient or attachment counts in the property stream header do not match the
    /// storages present.
    Count,
    /// Nesting deeper than the limits in [`Options`](crate::Options): not read.
    Depth,
    /// The total amount of stream data read reached its limit (streams that share sectors can
    /// otherwise make a small file expand to a huge amount of data).
    Budget,
    /// A stream or storage whose name does not belong in this place of a `.msg` file.
    UnknownEntry,
}

impl fmt::Display for ProblemKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::CompoundFile => "compound-file",
            Self::Storage => "storage",
            Self::Stream => "stream",
            Self::PropertyStream => "property-stream",
            Self::PropertyValue => "property-value",
            Self::UnsupportedType => "unsupported-type",
            Self::NamedProperties => "named-properties",
            Self::Text => "text",
            Self::CodePage => "code-page",
            Self::Rtf => "rtf",
            Self::Count => "count",
            Self::Depth => "depth",
            Self::Budget => "budget",
            Self::UnknownEntry => "unknown-entry",
        };
        f.write_str(name)
    }
}

/// One problem found while reading: the rest of the file is still read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Problem {
    /// Path, in the compound file, of the storage or stream concerned (for example
    /// `/__attach_version1.0_#00000000/__substg1.0_37010102`).
    pub path: String,
    /// What kind of problem this is.
    pub kind: ProblemKind,
    /// A human-readable description.
    pub detail: String,
}

impl fmt::Display for Problem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}: {}", self.path, self.kind, self.detail)
    }
}

/// Collects problems while reading one message.
#[derive(Debug, Default)]
pub(crate) struct Problems(pub(crate) Vec<Problem>);

impl Problems {
    pub(crate) fn push(&mut self, path: &str, kind: ProblemKind, detail: impl Into<String>) {
        self.0.push(Problem {
            path: path.to_owned(),
            kind,
            detail: detail.into(),
        });
    }
}
