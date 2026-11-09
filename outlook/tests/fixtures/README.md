# Test fixtures

Files the tests of this crate read besides the fixtures of the pst and msg crates
(`pst/tests/fixtures`, `msg/tests/fixtures`). The `.gz` files are compressed with `gzip -9 -n`; the
tests decompress them in memory. SHA-256 is of the decompressed file.

| file | what it is | made from | license | SHA-256 |
|---|---|---|---|---|
| `dist-list-embedded-loop.pst.gz` | A damaged PST whose embedded messages hold themselves: in the sub-node trees of the two attachments of the calendar item, the entries of the embedded messages point at the calendar item's own data and sub-node blocks (12 bytes changed in all: a byte of each block id, and the two blocks' CRCs) | `pst/tests/fixtures/dist-list.pst.gz` ([rjohnsondev/java-libpst](https://github.com/rjohnsondev/java-libpst) `src/test/resources/dist-list.pst`, commit `f158a64acf2a0e46ac3bd699bc7a5a8da6c40d26`), changed as described | Apache-2.0 (as `dist-list.pst`; the project is dual-licensed Apache-2.0 or LGPL, used under [Apache-2.0](https://github.com/rjohnsondev/java-libpst/blob/f158a64acf2a0e46ac3bd699bc7a5a8da6c40d26/LICENSE.APACHE-2.0.txt)) | `56f7feb065f7d9c205bf886c53ed2a1df9ebfdf3a2824b4ed9541ba327f61e04` |
