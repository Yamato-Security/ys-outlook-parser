# Test fixtures

Openly licensed PST and OST files the tests read. The `.gz` files are the original files compressed with
`gzip -9 -n`, and nothing else is changed; the tests decompress them in memory. SHA-256 is of the original
(decompressed) file.

| file | what it is | source | commit | license | SHA-256 |
|---|---|---|---|---|---|
| `Empty.pst` | Empty Unicode PST (wVer 23, permute) made by Outlook: 6 folders, no messages | [microsoft/outlook-pst-rs](https://github.com/microsoft/outlook-pst-rs) `crates/pst/examples/Empty.pst` | `cfb721daee538acc50d2bad6faac5ce724f6037d` | MIT (Copyright (c) Microsoft Corporation; `LICENSE-MIT`) | `c16ae985d12011ad510ccb3b10f19d61b0c3b3311fa4696fb56b87812bd8d5c5` |
| `dist-list.pst.gz` | Unicode PST (wVer 23, permute): 24 folders, 4 messages and 3 FAI items, two embedded-message attachments | [rjohnsondev/java-libpst](https://github.com/rjohnsondev/java-libpst) `src/test/resources/dist-list.pst` | `f158a64acf2a0e46ac3bd699bc7a5a8da6c40d26` | Apache-2.0 (the project is dual-licensed Apache-2.0 or LGPL; used under [Apache-2.0](https://github.com/rjohnsondev/java-libpst/blob/f158a64acf2a0e46ac3bd699bc7a5a8da6c40d26/LICENSE.APACHE-2.0.txt)) | `c86841da106036b5abe5a2141dc7644cbb2bf8b504873515eb35a2efeb8c28ac` |
| `example-2013.ost.gz` | Outlook 2013 OST in the 4 KiB layout (wVer 36, no encoding, zlib-compressed blocks): 46 folders, 3 messages, 14 FAI items | [rjohnsondev/java-libpst](https://github.com/rjohnsondev/java-libpst) `src/test/resources/example-2013.ost` | `f158a64acf2a0e46ac3bd699bc7a5a8da6c40d26` | Apache-2.0 (as above) | `b18ff390d0c22273029ee580ab6025976af69a4f84e276d1b1c01a988650853d` |
| `outlook.pst.gz` | Unicode PST (wVer 23, permute): 22 folders, 2 messages with recipients and 22 attachments; libpff's public test file | [libyal/testdata](https://github.com/libyal/testdata) `pst/outlook.pst` | `f018eb7c91c8356123b021ecd28ae894dd500210` | [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) (libyal testdata, Joachim Metz); changed only by gzip compression | `df01707f76d0e24ab913cf1ffeffa6eaf9c1d590e02102c7ed26bb3ac51d4e24` |

The folder, message and attachment counts above are what libpff reads from the same files; `tests/fixtures.rs`
checks that this crate reads the same.
