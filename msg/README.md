# ys-outlook-parser-msg

A read-only reader for Outlook `.msg` messages and `.oft` templates, for forensics, written from
the open specifications:

- [MS-OXMSG](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxmsg/b046868c-9fbf-41ae-9ffb-8de2bd4eec82):
  Outlook Item (.msg) File Format,
- [MS-OXCDATA](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxcdata/1afa0cd9-b1a0-4520-b623-bf15030af5d8):
  property types and named-property identities,
- [MS-OXPROPS](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxprops/f6ab1613-aefe-447d-a49c-18217230b148):
  property ids and property sets,
- [MS-OXRTFCP](https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxrtfcp/65dfe2df-1b69-43fc-8ebd-21819a7463fb):
  compressed RTF (decompressed with `compressed_rtf` of this workspace).

The compound file (MS-CFB) layer is the [`cfb`](https://crates.io/crates/cfb) crate.

```no_run
let data = std::fs::read("mail.msg")?;
let file = outlook_msg::MsgFile::from_bytes(&data)?;
let message = &file.message;
println!("{:?} {:?}", message.message_class(), message.subject());
for recipient in &message.recipients {
    println!("to {:?} <{:?}>", recipient.display_name(), recipient.email_address());
}
for attachment in &message.attachments {
    println!("attachment {:?}: {:?} bytes", attachment.file_name(), attachment.data().map(<[u8]>::len));
}
for property in &message.properties {
    println!("0x{:08X} {:?} {:?}", property.tag(), property.named, property.value);
}
for problem in file.all_problems() {
    println!("{problem}");
}
# Ok::<(), Box<dyn std::error::Error>>(())
```

## What is read

- The message, its recipients (`__recip_version1.0_#XXXXXXXX`), its attachments
  (`__attach_version1.0_#XXXXXXXX`) and embedded messages (`__substg1.0_3701000D`), recursively
  up to [`Options::max_depth`]. OLE-object attachments are returned as their storage tree.
- Every property: the entries of `__properties_version1.0` (32-, 24- and 8-byte headers),
  fixed-size values inline, variable-size values in `__substg1.0_PPPPTTTT` streams,
  multi-valued properties (fixed-size, and variable-size with their length stream and
  `-XXXXXXXX` element streams), and streams that have no entry. Each [`Property`] has its id,
  type, raw entry, named-property identity and a [`PropertyValue`] that tells a decoded value
  from an unsupported type and from a damaged value (with what could be recovered). An absent
  property is simply not in [`Properties`]; an empty one is a value with [`Value::is_empty`].
- Named properties (`__nameid_version1.0`): ids 0x8000 and up mapped to their property set
  GUID and LID or name.
- Text: `PtypString` as UTF-16LE and `PtypString8` in the message's code page
  (`PidTagMessageCodepage`, else the ANSI code page of `PidTagMessageLocaleId`, else the
  parent message's, else the Windows code page of `PidTagInternetCodepage`, else
  [`Options::default_code_page`]); see [`Message::code_page`]. A [`Text`] keeps the raw bytes,
  so invalid sequences are reported, not lost.
- Bodies: `PidTagBody`, the HTML body (`PidTagHtml` decoded in `PidTagInternetCodepage`, or
  `PidTagBodyHtml`) and the RTF body (`PidTagRtfCompressed`, decompressed; CRC and size
  problems are [`RtfFlag`]s).
- The root storage CLSID: [`FileKind::Message`] (`00020D0B-0000-0000-C000-000000000046`) or
  [`FileKind::Template`] (`0006F046-0000-0000-C000-000000000046`, `.oft`).

## Damaged files

Reading fails soft: a stream, property, recipient or attachment that cannot be read is a
[`Problem`] (of its [`Message`], or of the [`MsgFile`]) and its siblings are still read.
Multi-valued strings and binary values whose element lengths disagree with their length
stream are marked damaged, with every recovered element's bytes kept. Declared lengths
are checked without using them to allocate or truncate the values.
Nothing panics on any input, allocations are bounded by the size of the input (the total
amount of stream data read is capped too), and nesting is capped. Only a compound file that
the `cfb` crate cannot open at all (a broken header, FAT or directory) is an [`Error`]; one
whose FAT describes more sectors than the file has is read with the missing sectors as zeros
(a [`ProblemKind::CompoundFile`] problem).

## Tests

`tests/fixtures/` holds openly licensed sample files (sources and licences in its README).
`tests/oracle.rs` compares what the crate reads from them with the output of extract-msg
(`tests/oracle/`, used only as an external oracle), `tests/robustness.rs` mutates them, and
`cargo run --example msg_dump -- ROOT FILE...` writes the comparison format for any file.
