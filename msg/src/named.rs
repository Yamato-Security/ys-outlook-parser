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

//! The named property mapping, `__nameid_version1.0` ([MS-OXMSG] 2.2.3).

use crate::guid::{Guid, PS_MAPI, PS_PUBLIC_STRINGS};
use crate::problem::{ProblemKind, Problems};
use crate::property::{NamedProperty, PropertyName};
use crate::text::Text;
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

/// One entry of the entry stream (`__substg1.0_00030102`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NamedPropertyEntry {
    /// The property id the entry maps: 0x8000 plus the entry's property index.
    pub property_id: u16,
    /// The GUID index as stored: 1 = `PS_MAPI`, 2 = `PS_PUBLIC_STRINGS`, 3 and up = the entry
    /// at that index minus 3 in the GUID stream.
    pub guid_index: u16,
    /// The identity, or `None` if the GUID index or the string offset is bad (see the problems).
    pub named: Option<NamedProperty>,
}

/// The named property mapping of a file. Embedded messages use the mapping of the file they are
/// in ([MS-OXMSG] 2.2.3).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NamedProperties {
    /// All entries of the entry stream, in stream order.
    pub entries: Vec<NamedPropertyEntry>,
    /// The GUID stream (`__substg1.0_00020102`).
    pub guids: Vec<Guid>,
    by_id: BTreeMap<u16, usize>,
}

impl NamedProperties {
    /// The identity of property id `id` (0x8000 and up).
    pub fn get(&self, id: u16) -> Option<&NamedProperty> {
        self.entries[*self.by_id.get(&id)?].named.as_ref()
    }

    /// Parses the three streams of `__nameid_version1.0`. `path` is that storage's path, for the
    /// problems.
    pub(crate) fn parse(
        guid_stream: &[u8],
        entry_stream: &[u8],
        string_stream: &[u8],
        path: &str,
        problems: &mut Problems,
    ) -> Self {
        let (guid_chunks, rest) = guid_stream.as_chunks::<16>();
        if !rest.is_empty() {
            problems.push(
                &format!("{path}/__substg1.0_00020102"),
                ProblemKind::NamedProperties,
                format!(
                    "GUID stream is {} bytes, not a multiple of 16",
                    guid_stream.len()
                ),
            );
        }
        let guids: Vec<Guid> = guid_chunks.iter().map(|g| Guid(*g)).collect();
        let (entry_chunks, rest) = entry_stream.as_chunks::<8>();
        if !rest.is_empty() {
            problems.push(
                &format!("{path}/__substg1.0_00030102"),
                ProblemKind::NamedProperties,
                format!(
                    "entry stream is {} bytes, not a multiple of 8",
                    entry_stream.len()
                ),
            );
        }
        let entry_path = format!("{path}/__substg1.0_00030102");
        let mut names = Names::new(string_stream.len());
        let mut entries = Vec::with_capacity(entry_chunks.len());
        let mut by_id = BTreeMap::new();
        for (i, e) in entry_chunks.iter().enumerate() {
            let id_or_offset = u32::from_le_bytes([e[0], e[1], e[2], e[3]]);
            let info = u32::from_le_bytes([e[4], e[5], e[6], e[7]]);
            let is_string = info & 1 != 0;
            let guid_index = ((info >> 1) & 0x7FFF) as u16;
            let property_index = (info >> 16) as u16;
            // Property indexes above 0x7FFF would wrap past 0xFFFF.
            let Some(property_id) = 0x8000u16.checked_add(property_index) else {
                problems.push(
                    &entry_path,
                    ProblemKind::NamedProperties,
                    format!("entry {i}: property index 0x{property_index:04X} is above 0x7FFF"),
                );
                continue;
            };
            let guid = match guid_index {
                1 => Some(PS_MAPI),
                2 => Some(PS_PUBLIC_STRINGS),
                0 => None,
                n => guids.get(usize::from(n) - 3).copied(),
            };
            if guid.is_none() {
                problems.push(
                    &entry_path,
                    ProblemKind::NamedProperties,
                    format!(
                        "entry {i} (0x{property_id:04X}): GUID index {guid_index} is not in the GUID stream ({} GUIDs)",
                        guids.len()
                    ),
                );
            }
            let name = if is_string {
                match names.get(string_stream, id_or_offset) {
                    Ok((name, lossy)) => {
                        if lossy {
                            problems.push(
                                &format!("{path}/__substg1.0_00040102"),
                                ProblemKind::Text,
                                format!(
                                    "entry {i} (0x{property_id:04X}): name is not valid UTF-16"
                                ),
                            );
                        }
                        Some(PropertyName::Name(name))
                    }
                    Err(detail) => {
                        problems.push(
                            &format!("{path}/__substg1.0_00040102"),
                            ProblemKind::NamedProperties,
                            format!("entry {i} (0x{property_id:04X}): {detail}"),
                        );
                        None
                    }
                }
            } else {
                Some(PropertyName::Id(id_or_offset))
            };
            let named = guid
                .zip(name)
                .map(|(guid, name)| NamedProperty { guid, name });
            if let std::collections::btree_map::Entry::Vacant(slot) = by_id.entry(property_id) {
                slot.insert(entries.len());
            } else {
                problems.push(
                    &entry_path,
                    ProblemKind::NamedProperties,
                    format!(
                        "entry {i}: property id 0x{property_id:04X} is mapped more than once; the first entry is used"
                    ),
                );
            }
            entries.push(NamedPropertyEntry {
                property_id,
                guid_index,
                named,
            });
        }
        Self {
            entries,
            guids,
            by_id,
        }
    }
}

/// The names of the string stream, decoded once per offset. In a well-formed file the names do
/// not overlap, so the total decoded is capped near the stream's length: entries pointing into
/// the middle of each other's names cannot make the decoded names grow with the square of it.
struct Names {
    by_offset: HashMap<u32, (Arc<str>, bool)>,
    left: usize,
}

impl Names {
    fn new(len: usize) -> Self {
        Self {
            by_offset: HashMap::new(),
            left: len.saturating_mul(2).saturating_add(4096),
        }
    }

    /// The name at `offset` and whether it was not valid UTF-16.
    fn get(&mut self, strings: &[u8], offset: u32) -> Result<(Arc<str>, bool), String> {
        if let Some(name) = self.by_offset.get(&offset) {
            return Ok(name.clone());
        }
        let text = read_name(strings, offset, self.left)?;
        self.left -= text.raw().len();
        let name = (Arc::from(text.as_str()), text.is_lossy());
        self.by_offset.insert(offset, name.clone());
        Ok(name)
    }
}

/// A name of the string stream: a 4-byte length in bytes, then UTF-16LE.
fn read_name(strings: &[u8], offset: u32, left: usize) -> Result<Text, String> {
    let offset = offset as usize;
    let len = strings
        .get(offset..)
        .and_then(|s| s.first_chunk::<4>())
        .map(|b| u32::from_le_bytes(*b) as usize)
        .ok_or_else(|| {
            format!(
                "string offset {offset} is past the string stream ({} bytes)",
                strings.len()
            )
        })?;
    if len > left {
        return Err(format!(
            "string at offset {offset} of {len} bytes overlaps the other names: not decoded"
        ));
    }
    let start = offset + 4;
    let bytes = start
        .checked_add(len)
        .and_then(|end| strings.get(start..end))
        .ok_or_else(|| {
            format!(
                "string at offset {offset} of {len} bytes does not fit in the string stream ({} bytes)",
                strings.len()
            )
        })?;
    Ok(Text::from_utf16le(bytes.to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(id_or_offset: u32, property_index: u16, guid_index: u16, string: bool) -> [u8; 8] {
        let info =
            (u32::from(property_index) << 16) | (u32::from(guid_index) << 1) | u32::from(string);
        let mut e = [0; 8];
        e[..4].copy_from_slice(&id_or_offset.to_le_bytes());
        e[4..].copy_from_slice(&info.to_le_bytes());
        e
    }

    #[test]
    fn parses_ids_names_and_bad_entries() {
        let custom = Guid::from_fields(0x0006_2008, 0, 0, [0xC0, 0, 0, 0, 0, 0, 0, 0x46]);
        let mut strings = Vec::new();
        strings.extend_from_slice(&8u32.to_le_bytes());
        strings.extend_from_slice(b"K\0e\0y\0s\0");
        let entries = [
            entry(0x8501, 0, 3, false),
            entry(0, 1, 2, true),
            entry(0x0E07, 2, 1, false),
            entry(5, 3, 9, false),      // GUID index out of range
            entry(1000, 4, 2, true),    // string offset out of range
            entry(0x8502, 0, 3, false), // duplicate property index
        ]
        .concat();
        let mut problems = Problems::default();
        let n = NamedProperties::parse(&custom.0, &entries, &strings, "/n", &mut problems);
        assert_eq!(n.entries.len(), 6);
        assert_eq!(
            n.get(0x8000),
            Some(&NamedProperty {
                guid: custom,
                name: PropertyName::Id(0x8501)
            })
        );
        assert_eq!(
            n.get(0x8001).map(|p| &p.name),
            Some(&PropertyName::Name("Keys".into()))
        );
        assert_eq!(n.get(0x8002).map(|p| p.guid), Some(PS_MAPI));
        assert_eq!(n.get(0x8003), None);
        assert_eq!(n.get(0x8004), None);
        assert_eq!(problems.0.len(), 3);
        // A huge length must not allocate or panic.
        let mut huge = Vec::new();
        huge.extend_from_slice(&0xFFFF_FFF0u32.to_le_bytes());
        let n = NamedProperties::parse(&[], &entry(0, 0, 2, true), &huge, "/n", &mut problems);
        assert_eq!(n.get(0x8000), None);
    }
}
