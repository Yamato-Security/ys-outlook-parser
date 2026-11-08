# Test fixtures

Openly licensed `.msg` and `.oft` files from other projects' test data, unchanged, used by the
tests of this crate (`tests/fixtures.rs`, `tests/oracle.rs`, `tests/robustness.rs`). The
licence texts are in [`LICENSES/`](LICENSES): the Apache License 2.0 (as distributed with
HiraokaHyperTools/msgreader; it is the same licence that covers the Apache POI files), the
Apache POI `NOTICE`, and the MIT License of the Aspose.Email examples.

| file | upstream | commit | licence | what it covers |
|---|---|---|---|---|
| `apache-poi/ASCII_CP1251_LCID1049.msg` | [apache/poi](https://github.com/apache/poi) `test-data/hsmf/ASCII_CP1251_LCID1049.msg` | `519e0a3c3945364e8ea75c172fe1a15fb6d4a202` | Apache-2.0 | ANSI mail in Windows-1251 (from the locale; no `PidTagMessageCodepage`), `PtypString8` HTML body, nil root CLSID |
| `apache-poi/HTMLBodyBinary_CP1251.msg` | apache/poi `test-data/hsmf/HTMLBodyBinary_CP1251.msg` | same | Apache-2.0 | ANSI mail: strings in Windows-1252 (locale 1031), binary HTML body in Windows-1251 (`PidTagInternetCodepage`) |
| `apache-poi/keywords.msg` | apache/poi `test-data/hsmf/keywords.msg` | same | Apache-2.0 | Unicode mail, string-named property `PS_PUBLIC_STRINGS:Keywords` (`PtypMultipleString`), RTF body |
| `apache-poi/msgClassAppointment.msg` | apache/poi `test-data/hsmf/msgClassAppointment.msg` (also Apache Tika `testMSG_Appointment.msg`) | same | Apache-2.0 | appointment (`IPM.Appointment`) with a recipient, `PSETID_Appointment` named properties |
| `apache-poi/msgClassStickyNote.msg` | apache/poi `test-data/hsmf/msgClassStickyNote.msg` (also Tika `testMSG_StickyNote.msg`) | same | Apache-2.0 | sticky note (`IPM.StickyNote`) |
| `apache-poi/msgClassTask.msg` | apache/poi `test-data/hsmf/msgClassTask.msg` (also Tika `testMSG_Task.msg`) | same | Apache-2.0 | task (`IPM.Task`), `PSETID_Task` |
| `msgreader-hiraoka/attachmentFiles.msg` | [HiraokaHyperTools/msgreader](https://github.com/HiraokaHyperTools/msgreader) `test/attachmentFiles.msg` | `8f9b2a3aa53dcabc94ce20ea783cbba47613ec98` | Apache-2.0 | three attachments by value (JPEG, PNG, TIFF), `PS_INTERNET_HEADERS` |
| `msgreader-hiraoka/contactAnsi.msg` | HiraokaHyperTools/msgreader `test/contactAnsi.msg` | same | Apache-2.0 | ANSI contact (`IPM.Contact`) in code page 932 (from the locale), `PtypMultipleInteger32` |
| `msgreader-hiraoka/nonUnicodeCP932.msg` | HiraokaHyperTools/msgreader `test/nonUnicodeCP932.msg` | same | Apache-2.0 | ANSI mail in code page 932 whose `PidTagInternetCodepage` is ISO-2022-JP (50220) |
| `msgreader-hiraoka/msgInMsgInMsg.msg` | HiraokaHyperTools/msgreader `test/msgInMsgInMsg.msg` | same | Apache-2.0 | embedded messages three levels deep (a message in a message in a message) |
| `msgreader-hiraoka/cyclicDirTree.msg` | HiraokaHyperTools/msgreader `test3/cyclicDirTree.msg` | same | Apache-2.0 | malformed compound file: cyclic directory tree |
| `msgreader-hiraoka/cyclicFatRing.msg` | HiraokaHyperTools/msgreader `test3/cyclicFatRing.msg` | same | Apache-2.0 | malformed compound file: cyclic sector chain |
| `aspose-email-java/mapiToOft.oft` | [aspose-email/Aspose.Email-for-Java](https://github.com/aspose-email/Aspose.Email-for-Java) `Examples/src/main/resources/outlook/mapiToOft.oft` | `cf4567e54f7979e7296c99bcae2c6477385d7735` | MIT | Outlook template (root CLSID `0006F046-0000-0000-C000-000000000046`) |
| `aspose-email-net/Meeting with Recurring Occurrences.msg` | [aspose-email/Aspose.Email-for-.NET](https://github.com/aspose-email/Aspose.Email-for-.NET) `Examples/Data/Email/Meeting with Recurring Occurrences.msg` | `88cb2da311382bbbba6d14813127b0e6b3854c12` | MIT | meeting request (`IPM.Schedule.Meeting.Request`) with a recurrence |
| `aspose-email-net/NewGroup.msg` | aspose-email/Aspose.Email-for-.NET `Examples/Data/MAPI/NewGroup.msg` | same | MIT | distribution list (`IPM.DistList`), `PtypMultipleBinary` named properties |
| `aspose-email-net/message.msg` | aspose-email/Aspose.Email-for-.NET `Examples/Data/MAPI/message.msg` | same | MIT | ANSI mail, uncompressed RTF whose `RAWSIZE` is too large (an `RtfFlag`) |
| `aspose-email-net/MSG file with RTF Formatting.msg` | aspose-email/Aspose.Email-for-.NET `Examples/Data/Email/MSG file with RTF Formatting.msg` | same | MIT | OLE-object attachment (`afStorage`) read as a storage tree |

SHA-256:

```text
591eb7aab7d3a16dc64845fec7c211c245eaa6489ba6df39602df5ca93180649  apache-poi/ASCII_CP1251_LCID1049.msg
fbab3d7d2ba92ad8cd917c3ce220f5efec19f5a21afab823ed1f9cf1d584792c  apache-poi/HTMLBodyBinary_CP1251.msg
19c1ac9753cc1ee7eab1ebece51d97de64343567dec02cda7bedc30b8511a13a  apache-poi/keywords.msg
e0a8fb568bc837c4f835a9e85e70280beb1b604b6223a3fa547b22c4860f3eb9  apache-poi/msgClassAppointment.msg
eda4bdadbb24f1b46fce385653c2519c79b944e5724180208541639dcd813525  apache-poi/msgClassStickyNote.msg
3cd593624de75119a0b7d30ad40c62aa19e3b5444c59fece0155dd43a414e31c  apache-poi/msgClassTask.msg
7bb13973976b7fea099e0becd1e152849f258f470855c1a154452cdbf4bfdbd9  aspose-email-java/mapiToOft.oft
7d50cf539b521fa51823a1d1d6793b2d79cb3c2c84343c9dc807986d26fae45e  aspose-email-net/Meeting with Recurring Occurrences.msg
f34ed05a9bb0e1ba77052e8d628da5dc40cb42da8389531c556c3d2a6780e756  aspose-email-net/MSG file with RTF Formatting.msg
400a41db116b4233bdac907b3c2faf311b2c99411fb869a7248477dc08d77f49  aspose-email-net/NewGroup.msg
a6fc2f852e2ad1b89cf43db7b653d2df96aacca9daf1ee12250f1f3f56e211e2  aspose-email-net/message.msg
8643045fd94c3f06df7bf147d1b95db07ff016cd0d52eacceaa15c74a2c9c3c7  msgreader-hiraoka/attachmentFiles.msg
79b82e21d032cca26d25cacb2092b36f25e0f463d3c78b7067cc2a10cca9dc9d  msgreader-hiraoka/contactAnsi.msg
b356f3296174fa2aed8f339f5f82a14fc5019c3d864b5ef5a246ad9648b13269  msgreader-hiraoka/cyclicDirTree.msg
06c8a8c5dc5801bf0f9a55ac7a1c456b01dbe6e4f6518ee77948b3468d61bca4  msgreader-hiraoka/cyclicFatRing.msg
9c77fc1ff1b9132c546959a0ed6c98e3678cd369bf6b0b6abb777abc9e6720d6  msgreader-hiraoka/msgInMsgInMsg.msg
4ed496f2d6af082662b8af96c55b3338763d39206d34c46753bc720063096f06  msgreader-hiraoka/nonUnicodeCP932.msg
```
