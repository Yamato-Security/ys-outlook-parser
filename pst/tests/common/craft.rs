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

//! Byte-level edits of a Unicode PST in memory, for crafted-corruption tests: B-tree pages and
//! blocks are rewritten with valid CRCs, so a test exercises what it means to (a loop, a bad
//! size), not a CRC check.

#![allow(dead_code)]

/// The MS-PST CRC (CRC-32, reflected polynomial 0xEDB88320, no final XOR), one bit at a time.
pub fn crc(data: &[u8]) -> u32 {
    let mut crc = 0_u32;
    for byte in data {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    crc
}

/// The size of a 512-byte page and the offsets in a Unicode B-tree page.
pub const PAGE_SIZE: usize = 512;
const ENTRY_COUNT: usize = 488;
const LEVEL: usize = 491;
const PAGE_CRC_DATA: usize = 496;
const PAGE_CRC: usize = 500;

/// A Unicode PST (wVer 23) held in memory.
pub struct UnicodePst(pub Vec<u8>);

impl UnicodePst {
    pub fn u64_at(&self, offset: usize) -> u64 {
        u64::from_le_bytes(self.0[offset..offset + 8].try_into().unwrap())
    }

    pub fn set_u64(&mut self, offset: usize, value: u64) {
        self.0[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    /// The file offset of the root page of the node BTree (ROOT.BREFNBT.ib).
    pub fn nbt_root(&self) -> usize {
        self.u64_at(224) as usize
    }

    /// The block ID of the root page of the node BTree (ROOT.BREFNBT.bid).
    pub fn nbt_root_id(&self) -> u64 {
        self.u64_at(216)
    }

    /// The file offset of the root page of the block BTree (ROOT.BREFBBT.ib).
    pub fn bbt_root(&self) -> usize {
        self.u64_at(240) as usize
    }

    /// The block ID of the root page of the block BTree (ROOT.BREFBBT.bid).
    pub fn bbt_root_id(&self) -> u64 {
        self.u64_at(232)
    }

    /// The cLevel of the page at `page`.
    pub fn page_level(&self, page: usize) -> u8 {
        self.0[page + LEVEL]
    }

    /// The cEnt of the page at `page`.
    pub fn page_entry_count(&self, page: usize) -> usize {
        usize::from(self.0[page + ENTRY_COUNT])
    }

    /// Point entry `index` of the intermediate page at `page` at another page.
    pub fn set_child(&mut self, page: usize, index: usize, child_id: u64, child: usize) {
        let entry = page + 24 * index;
        self.set_u64(entry + 8, child_id);
        self.set_u64(entry + 16, child as u64);
        self.fix_page_crc(page);
    }

    /// Make the page at `page` an intermediate page of `level` with one entry, for keys from 0,
    /// that leads to another page.
    pub fn make_intermediate(&mut self, page: usize, level: u8, child_id: u64, child: usize) {
        self.0[page..page + ENTRY_COUNT].fill(0);
        self.0[page + ENTRY_COUNT..page + LEVEL + 1].copy_from_slice(&[1, 20, 24, level]);
        self.set_child(page, 0, child_id, child);
    }

    /// The block ID and file offset entry `index` of the intermediate page at `page` leads to.
    pub fn child(&self, page: usize, index: usize) -> (u64, usize) {
        let entry = page + 24 * index;
        (self.u64_at(entry + 8), self.u64_at(entry + 16) as usize)
    }

    /// Recompute the CRC of the page at `page`.
    pub fn fix_page_crc(&mut self, page: usize) {
        let crc = crc(&self.0[page..page + PAGE_CRC_DATA]);
        self.0[page + PAGE_CRC..page + PAGE_CRC + 4].copy_from_slice(&crc.to_le_bytes());
    }
}
