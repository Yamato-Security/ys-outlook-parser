# ys-outlook-parser

Yamato Security's parser of Outlook artifacts for forensics: the folders and items of PST and OST
files (ANSI and Unicode PSTs, and OSTs, including the 4 KiB pages and compressed blocks of Outlook
2013 and later) and `.msg` and `.oft` files, read without Outlook or MAPI, read-only, and leniently,
so that what can be read of a damaged file is read and the damage is reported. It is the Outlook
parser of [Juntei](https://github.com/Yamato-Security/juntei).

`pst/` and `compressed-rtf/` are a fork of Microsoft's
[outlook-pst-rs](https://github.com/microsoft/outlook-pst-rs) (its `crates/pst` and
`crates/compressed-rtf` at `cfb721d`, imported with their history), whose code stays under the MIT
License (see [Licence](#licence)). `msg/` and `outlook/` are our own.

| Crate | Library | What it reads |
| --- | --- | --- |
| [`ys-outlook-parser`](outlook/) | `outlook` | One item model for every source: `pst::PstStore` (a store's header, folders, messages and folder associated information) and `MsgItem` (a `.msg` or `.oft` file), each item with its well-known fields (class, sender, recipients, times, bodies, attachments, embedded messages, and the fields of contacts, calendar items and tasks) and every property as stored |
| [`ys-outlook-parser-pst`](pst/) | `outlook_pst` | PST and OST files ([MS-PST]): the node and block B-trees, heaps, property and table contexts, and the messaging layer |
| [`ys-outlook-parser-msg`](msg/) | `outlook_msg` | `.msg` and `.oft` files ([MS-OXMSG]) on the [`cfb`](https://crates.io/crates/cfb) crate |
| [`ys-outlook-parser-rtf`](compressed-rtf/) | `compressed_rtf` | Compressed RTF ([MS-OXRTFCP]) |

```rust,no_run
use outlook::pst::{Options, PstStore};

let store = PstStore::open("mailbox.ost", &Options::default())?;
for folder in store.folders() {
    for stored in store.items(&folder) {
        match &stored.item {
            Ok(item) => println!("{} {:?} {:?} {:?}", folder.path, item.kind, item.submitted, item.subject),
            Err(e) => println!("{}: message {:#x}: {e}", folder.path, stored.node),
        }
    }
}
for problem in store.problems() {
    println!("{problem}");
}
let msg = outlook::MsgItem::from_bytes(&std::fs::read("mail.msg")?, &Default::default())?;
println!("{:?} {:?}", msg.item.subject, msg.item.attachments.len());
# Ok::<(), Box<dyn std::error::Error>>(())
```

[MS-PST]: https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-pst/141923d5-15ab-4ef1-a524-6dce75aae546
[MS-OXMSG]: https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxmsg/b046868c-9fbf-41ae-9ffb-8de2bd4eec82
[MS-OXRTFCP]: https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxrtfcp/65dfe2df-1b69-43fc-8ebd-21819a7463fb

## Why outlook-pst

The Rust readers of PST and OST files we found were compared with libpff on real files:
Microsoft's `outlook-pst` 1.2.0 and its forks (`outlook-pst-ost` 1.3.0, `outlook-pst-rw`,
pstsmith), STViewer's `stv-pst`, pstfree, outlook-cli, artemis's Outlook module, ost-mcp and
PSTInsight. Only the `outlook-pst` lineage with `outlook-pst-ost`'s changes read every real file as
libpff does, and it reads from any `Read + Seek` with its lower layers public. But upstream rejects
every OST, failed all 71 messages of an Enron PST, and had no protection against loops (a B-tree
page that points to itself aborted the process with a stack overflow in every file tried) nor
against panics on damaged input. So the fork:

- reads the OSTs of Outlook 2013 and later (`wVer` 36: 4 KiB pages, 512-byte block alignment,
  24-byte block trailers, zlib-compressed blocks) and `wVerClient` 12, as `outlook-pst-ost` 1.3.0
  (MIT) does, and decodes their heap ids (a 14-bit allocation index and a 13-bit block index),
  which `outlook-pst-ost` reads as those of 512-byte pages;
- takes the read fixes still open upstream (PRs #86, #87, #88, #89, #90, #94 and #95, MIT), and
  fixes the GUID of named properties (looked up 3 entries too far) and the data of OLE-object
  attachments (looked up in the wrong sub-node tree);
- never opens the file for writing (upstream's write support is removed);
- reads leniently by default, recording each defect it can go past as a problem (`Validation`,
  `PstFile::problems`), or strictly;
- cannot panic, abort or allocate without bound on any input, and every walk ends (see
  [pst/README.md](pst/README.md)).

No Rust reader of `.msg` files we found was usable as it is, so `msg/` is written from the open
specifications.

## Validation

**PST and OST, against libpff** (pypff 20260926, used only as an external oracle): 66 PST and OST
files from public repositories (Apache Tika, artemis, the Aspose.Email examples, DFIR Artifact
Museum, Enron (ZL Technologies / EDRM), the GroupDocs examples, java-libpst, libyal's testdata,
outlook-pst-rs and pst-extractor), 2 of which neither reader reads at all (one has no message
store object, the other no block for it). Every property of
every store, folder, message, recipient and attachment, and every attachment's data, was compared
(`outlook/tests/oracle/`):

| Facts | Count |
| --- | ---: |
| The same | 324,175 |
| Read only by this crate: messages, recipients and attachments libpff fails on, and a store it cannot open | 15,846 |
| Folder associated information (hidden messages), which pypff cannot list | 8,223 |
| Recipient cells libpff gives as empty or zero though the row says they are absent | 49,077 |
| A folder's `PidTagEntryId` and `PidTagFolderType`, which this crate computes as MAPI does | 2,004 |
| Objects and embedded messages, which libpff gives as their raw node data | 480 |
| Different and not explained | **0** |

Compared with upstream `outlook-pst` on the same files, the fork reads 3,557 messages instead of
3,326, with no message or attachment that fails (upstream: 134 and 221), and 258 embedded messages
(upstream: none). `cargo test -p ys-outlook-parser` repeats the comparison on the fixtures against
libpff's committed output.

**`.msg` and `.oft`, against extract-msg** (0.58.2, used only as an external oracle): 214 public
files, 2,399 messages, recipients and attachments, 40,905 properties. 109,846 facts are the same and
791 differ, each explained (`msg/tests/oracle/`): 601 are extract-msg's errors with FILETIMEs, 35 are
ANSI files it decodes in the wrong code page, and the others are what it leaves out or adds.
Decompressed RTF bodies are compared byte for byte.

**Damaged input**: crafted files and seeded mutations of the fixtures for each crate (more than
260,000 mutated `.msg` files and 160,000 mutated PSTs), without a panic, an abort or an unbounded
allocation.

## Not read yet

The other Outlook artifacts are planned: offline address books (OAB), the autocomplete stream
(`Stream_Autocomplete_*.dat`, NK2), send/receive settings (SRS), Outlook's settings caches
(RoamCache, Autodiscover) and Outlook's SQLite databases. Messages that are no longer in any
folder's table (deleted, but still in the store's B-trees) are not read either.

## Licence

ys-outlook-parser is copyright Shirofune Security Co., Ltd. and released under the [Reciprocal
Public License 1.5](LICENSE) (RPL-1.5). `pst/` and `compressed-rtf/` are changed from
[microsoft/outlook-pst-rs](https://github.com/microsoft/outlook-pst-rs) (copyright Microsoft
Corporation), and some of their files from its copy
[outlook-pst-ost](https://crates.io/crates/outlook-pst-ost) 1.3.0, whose code stays under the MIT
License ([LICENSE-MIT](LICENSE-MIT)): each Rust file changed from them says so in its header, and
those crates are `RPL-1.5 AND MIT`. `msg/` and `outlook/` are under the RPL only. The test files keep
their licences, given in the README beside them.
