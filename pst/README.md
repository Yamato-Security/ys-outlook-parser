# outlook-pst

The PST file format is publicly documented in the [MS-PST](https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-pst/141923d5-15ab-4ef1-a524-6dce75aae546) open specification. Data structures and type names generally mimic the concepts and names in that document, with some adjustment for readability and to match Rust language conventions. As much as possible, everything in this crate should have a deep link to the documentation it is based on in the doc comments. 

## Read-only

This fork is for forensics and never writes to the file it reads: `UnicodePstFile::open`,
`AnsiPstFile::open` and `open_store` open the file read-only, and `read_from` only reads from and
seeks the reader it is given. Upstream's write support (transactions, the [AMap
rebuild](https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-pst/d9bcc1fd-c66a-41b3-b6d7-ed09d2a25ced)
and the writers of pages and blocks) is removed.
