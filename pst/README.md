# outlook-pst

The PST file format is publicly documented in the [MS-PST](https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-pst/141923d5-15ab-4ef1-a524-6dce75aae546) open specification. Data structures and type names generally mimic the concepts and names in that document, with some adjustment for readability and to match Rust language conventions. As much as possible, everything in this crate should have a deep link to the documentation it is based on in the doc comments. 

## Read-only

This fork is for forensics and never writes to the file it reads: `UnicodePstFile::open`,
`AnsiPstFile::open` and `open_store` open the file read-only, and `read_from` only reads from and
seeks the reader it is given. Upstream's write support (transactions, the [AMap
rebuild](https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-pst/d9bcc1fd-c66a-41b3-b6d7-ed09d2a25ced)
and the writers of pages and blocks) is removed.

## Lenient reading

Evidence is often damaged, so a file is read leniently by default (`Validation::Lenient`): each
defect reading can go past is recorded as a `Problem` and reading goes on.

- A CRC that does not match (header, B-tree page, block).
- A header field with a value MS-PST does not allow (`wMagicClient`, `wVerClient`,
  `bPlatformCreate`, `bPlatformAccess`, `dwAlign`, `bSentinel`, reserved bytes). `wVerClient` 12,
  which Outlook writes in OSTs, is allowed.
- A stray value in a page or block (`dwPadding`), and a B-tree page or intermediate block whose
  `cLevel` is not below its parent's.
- A part of an object that cannot be read is left out of it, not the whole object: a BTH record or
  a table column that does not parse, a property, a message's sub-node tree, recipient table or
  attachment table, an attachment's data, a table's row index.
- A store without a usable `PidTagRecordKey` makes entry IDs with a record key of zeros, so its
  folders and messages still open by node ID.
- A folder's hierarchy, contents or associated contents table that cannot be read is `None` (read
  strictly, the tables are read when the folder is opened, and opening it fails instead).

`PstFile::problems()` lists the problems found so far, each once, in the order found, each with its
kind (`ProblemKind`), the file offset or node it was found in when known, and a description; at most
`problems::MAX_PROBLEMS`. `UnicodePstFile::read_from_with`, `open_with` (and the same on
`AnsiPstFile`) and `open_store_with` take `Validation::Strict` instead, which makes the first such
defect an error, as upstream outlook-pst does. Either way, a defect that reading cannot go past (a
truncated file, a block of the wrong size, a loop) is an error.

## Limits

No input makes this crate panic, abort or allocate without bound: sizes and offsets from the file are
checked before use, and every walk ends. A B-tree lookup goes through each page at most once and at
most `MAX_BTREE_DEPTH` pages deep; a data tree or sub-node tree reads each block at most once, at
most `MAX_BLOCK_TREE_DEPTH` levels deep and no more bytes than the file holds; a BTree-on-heap reads
each heap allocation at most once; embedded messages are read at most `MAX_EMBEDDED_MESSAGE_DEPTH`
levels down; and `messaging::folder::walk_folders` walks the folder hierarchy with each folder at
most once, at most `MAX_FOLDER_DEPTH` levels down.
