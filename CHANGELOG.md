# Changelog

## 1.0.0 (Unreleased)

First version of Yamato Security's Outlook parser, of four crates: a fork of
[microsoft/outlook-pst-rs](https://github.com/microsoft/outlook-pst-rs)'s `outlook-pst` 1.2.0 and
`compressed-rtf` (cfb721d), as `ys-outlook-parser-pst` and `ys-outlook-parser-rtf`, and two new
crates, `ys-outlook-parser-msg` and `ys-outlook-parser`. (@YamatoSecurity)

### Added
- The OSTs of Outlook 2013 and later (`wVer` 36: 4 KiB pages, 512-byte block alignment, 24-byte
  block trailers, zlib-compressed blocks), and `wVerClient` 12, as in `outlook-pst-ost` 1.3.0.
  (@YamatoSecurity)
- Lenient reading, the default: each defect reading can go past (a CRC, a header field, a
  B-tree or block level, a part of an object that cannot be read) is a problem
  (`PstFile::problems`) and the rest is read; `Validation::Strict` makes it an error.
  (@YamatoSecurity)
- `walk_folders`: every folder reachable from the root folder, each once.
  `UnicodeAttachment::embedded_message` and `AnsiAttachment::embedded_message`: an embedded message
  as its own type, so that its attachments can be read. (@YamatoSecurity)
- `ys-outlook-parser-msg` (`outlook_msg`): `.msg` and `.oft` files (MS-OXMSG), on `cfb`, with
  their recipients, attachments, embedded messages, named properties, bodies and code pages, read
  leniently. (@YamatoSecurity)
- `ys-outlook-parser` (`outlook`): one item model for PST and OST stores (`pst::PstStore`) and
  `.msg` and `.oft` files (`MsgItem`). (@YamatoSecurity)
- A field-by-field comparison with libpff for PST and OST files, and with extract-msg for `.msg`
  and `.oft` files, both used only as external oracles. (@YamatoSecurity)

### Changed
- String-named properties in the unified model use shared `Arc<str>` names, constructed with
  `.into()` from strings. PST/OST name decoding is cached and bounded by the string stream's
  size so repeated or overlapping names cannot expand into quadratic memory use.
  (@YamatoSecurity)
- Read-only: a file is never opened for writing, and upstream's write support is removed.
  (@YamatoSecurity)
- No input makes the crates panic, abort or allocate without bound, and every walk ends: B-tree,
  block, heap, folder and embedded-message walks have loop and depth limits; a walk's blocks may
  inflate to at most 8 times the file's size; each heap allocation or sub-node is the value of one
  property only, and an object's values are limited; an embedded message that has the blocks of a
  message it is embedded in is refused; and an item reads at most 1024 embedded messages.
  (@YamatoSecurity)

### Fixed
- A malformed record in a PST named-property entry stream or hash bucket silently hid every
  following record. Record iteration now reports each invalid entry and lets the forensic
  reader continue; the strict collecting methods return an error. (@YamatoSecurity)
- From upstream pull requests (MIT): `PtypObject` property records (#86), every BTH record read
  instead of stopping at the first bad one (#87), an embedded message read from the attachment's
  own sub-nodes (#88), the GUID kept when hashing a string-named property (#89), an HNID of 0 read
  as the empty value of its type (#90), only the padding after each name skipped in the string
  stream (#94), and the right attachment method named when its data is missing (#95).
  (@YamatoSecurity)
- A named property's GUID was looked up 3 entries too far in the GUID stream. (@YamatoSecurity)
- An OLE object attachment's data was looked up in the message's sub-nodes instead of the
  attachment's, so it was never read. (@YamatoSecurity)
- The store kept its root hierarchy table, which holds the store, so every store leaked.
  (@YamatoSecurity)
- Decompressed RTF ended at the first zero byte, so the binary data of a `\bin` control word and
  everything after it were lost. (@YamatoSecurity)
- The heap ids of 4 KiB-page OSTs were decoded as those of 512-byte pages (an 11-bit allocation
  index and a 16-bit block index instead of 14 and 13 bits), so a value past a heap's first
  block or 2,047th allocation was not found or was read from the wrong place. (@YamatoSecurity)
- The last byte of a Unicode value with an odd length and no terminator was dropped without a
  trace; it is kept as `UnicodeValue::trailing_byte`. (@YamatoSecurity)
