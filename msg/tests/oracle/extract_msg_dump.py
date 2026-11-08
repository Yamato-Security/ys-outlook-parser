#!/usr/bin/env python3
# Copyright (C) 2026 Shirofune Security Co., Ltd.
#
# Unless explicitly acquired and licensed from Licensor under another license, the contents of this
# file are subject to the Reciprocal Public License ("RPL") Version 1.5, or subsequent versions as
# allowed by the RPL, and You may not copy or use this file in either source code or executable
# form, except in compliance with the terms and conditions of the RPL.
#
# All software distributed under the RPL is provided strictly on an "AS IS" basis, WITHOUT WARRANTY
# OF ANY KIND, EITHER EXPRESS OR IMPLIED, AND LICENSOR HEREBY DISCLAIMS ALL SUCH WARRANTIES,
# INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
# PURPOSE, QUIET ENJOYMENT, OR NON-INFRINGEMENT. See the RPL for specific language governing rights
# and limitations under the RPL.
"""Oracle dump of .msg/.oft files made with extract-msg, for comparison with outlook_msg.

extract-msg 0.58.2 (https://github.com/TeamMsgExtractor/msg-extractor, GPL-3.0) is used here only
as an independent, external oracle: this script imports it and calls its API; none of its code
is copied into this script or into the crate. Run it with the interpreter of a virtualenv that has
extract-msg 0.58.2 (and its dependency olefile) installed, in isolated mode:

    python -I extract_msg_dump.py ROOT FILE... > oracle.tsv

FILE paths are relative to ROOT; they are what the first column says. The output is one line per
fact, tab-separated and sorted: file, object, key, value. The crate writes the same format
(tests/common/dump.rs, `cargo run --example msg_dump`), and tests/oracle/compare.py compares the
two. The output does not depend on the time zone (extract-msg's local times are made UTC).

To regenerate the fixtures' oracle output and their explained differences (from msg/):

    cd tests/fixtures && find . -name '*.msg' -o -name '*.oft' | sed 's|^./||' | sort > /tmp/f
    tr '\n' '\0' < /tmp/f | xargs -0 python -I ../oracle/extract_msg_dump.py . > /tmp/o.tsv
    tr '\n' '\0' < /tmp/f | xargs -0 cargo run -q --example msg_dump -- . > /tmp/c.tsv
    python3 ../oracle/compare.py /tmp/o.tsv /tmp/c.tsv --differences /tmp/d.tsv
    gzip -9n < /tmp/o.tsv > ../oracle/fixtures.oracle.tsv.gz

then put /tmp/d.tsv, after checking every line, under the header of fixtures.differences.tsv. Objects: `m` is the message, `m/r<N>` recipient N, `m/a<N>` attachment N, `m/a<N>/m` the
message embedded in attachment N, and so on (N is the storage name's hex index, in decimal).

Keys and values:
- `clsid` (object `file`): root storage CLSID, upper case.
- `named:8XXX` (object `file`): `GUID:id:0xLID` or `GUID:name:"json"`.
- `header` (message objects): next recipient id, next attachment id, recipient and attachment
  counts of the property stream header.
- `count:recipients`, `count:attachments` (message objects): storages found.
- `flags:TAG`: the flags of a property stream entry.
- `p:TAG`: the value (union of property stream entries and __substg1.0_ streams), normalized:
  `i:N` integers (signed), `f32:BITS`/`f64:BITS` floats (IEEE bits in hex), `cur:N` currency
  (scaled integer), `apptime:US` (microseconds since 1899-12-30), `err:0xX`, `bool:true|false`,
  `time:US` (microseconds since 1601-01-01), `s8:"json"` and `u:"json"` strings (trailing NULs
  removed), `guid:G`, `bin:LEN:SHA` (first 16 hex digits of SHA-256), `object`, `mv:[...]` for
  multi-valued (a JSON list of the normalized element values), `missing` (an entry without its
  stream), `none` (extract-msg found the property but gave no value), `ERROR:<exception>`.
- `r:TAG`: `LEN:SHA` of the raw `__substg1.0_TAG` stream.
- `att:kind` (attachment objects): `binary`, `message`, `storage` or `none`.
- `rtf` (message objects with PidTagRtfCompressed): `LEN:SHA` of the decompressed RTF up to its
  first NUL, decompressed by the `compressed_rtf` Python package (extract-msg's dependency).
"""

import datetime
import decimal
import hashlib
import json
import logging
import struct
import sys

import compressed_rtf
import olefile
import extract_msg
from extract_msg import constants
from extract_msg.enums import ErrorBehavior, RecipientType
from extract_msg.msg_classes import MSGFile
from extract_msg.recipient import Recipient

logging.disable(logging.CRITICAL)

OUT = []
FIXED = {0x0001, 0x0002, 0x0003, 0x0004, 0x0005, 0x0006, 0x0007, 0x000A, 0x000B, 0x0014, 0x0040}


def emit(file, obj, key, value):
    OUT.append(f"{file}\t{obj}\t{key}\t{value}")


def sha(data):
    return f"{len(data)}:{hashlib.sha256(data).hexdigest()[:16]}"


def js(s):
    return json.dumps(s, ensure_ascii=True)


def us_since(dt, y, m, d):
    # extract-msg returns PtypTime values in the local time zone: back to UTC.
    if dt.tzinfo is not None:
        dt = dt.astimezone(datetime.timezone.utc).replace(tzinfo=None)
    return (dt - datetime.datetime(y, m, d)) // datetime.timedelta(microseconds=1)


def norm_scalar(t, v):
    """Normalizes one value of (single-valued) type t."""
    if v is None:
        return "none"
    if t == 0x0002:
        return f"i:{struct.unpack('<h', struct.pack('<H', v))[0]}"
    if t == 0x0003:
        return f"i:{struct.unpack('<i', struct.pack('<I', v))[0]}"
    if t == 0x0014:
        return f"i:{struct.unpack('<q', struct.pack('<Q', v))[0]}"
    if t == 0x0004:
        return f"f32:{struct.unpack('<I', struct.pack('<f', v))[0]:08x}"
    if t == 0x0005:
        return f"f64:{struct.unpack('<Q', struct.pack('<d', v))[0]:016x}"
    if t == 0x0006:
        return f"cur:{int(decimal.Decimal(v) * 10000)}"
    if t == 0x0007:
        return f"apptime:{us_since(v, 1899, 12, 30)}"
    if t == 0x000A:
        return f"err:0x{int(v):08X}"
    if t == 0x000B:
        return f"bool:{'true' if v else 'false'}"
    if t == 0x0040:
        return f"time:{us_since(v, 1601, 1, 1)}"
    if t == 0x001E:
        return f"s8:{js(v.rstrip(chr(0)))}"
    if t == 0x001F:
        return f"u:{js(v.rstrip(chr(0)))}"
    if t == 0x0048:
        return f"guid:{str(v).strip('{}').upper()}"
    if t == 0x0102:
        return f"bin:{sha(v)}"
    if t == 0x0001:
        return "null"
    if isinstance(v, (bytes, bytearray)):
        return f"unsupported:{sha(bytes(v))}"
    return f"other:{js(repr(v))}"


def norm(t, v):
    if v is None:
        return "none"
    if t & 0x1000 and t not in (0x1000,):
        base = t & ~0x1000
        items = []
        for x in v:
            n = norm_scalar(base, x)
            items.append(n)
        return "mv:" + json.dumps(items, ensure_ascii=True, separators=(",", ":"))
    return norm_scalar(t, v)


def obj_streams(ole_streams, ole_storages, storage):
    """__substg1.0_ streams and storages directly in `storage` (a tuple of path parts)."""
    n = len(storage)
    streams = {}
    for parts in ole_streams:
        if len(parts) == n + 1 and tuple(p.lower() for p in parts[:n]) == tuple(p.lower() for p in storage):
            name = parts[-1]
            if name.lower().startswith("__substg1.0_") and "-" not in name and len(name) == 20:
                streams[int(name[12:], 16)] = "/".join(parts)
    storages = {}
    for parts in ole_storages:
        if len(parts) == n + 1 and tuple(p.lower() for p in parts[:n]) == tuple(p.lower() for p in storage):
            name = parts[-1]
            if name.lower().startswith("__substg1.0_") and len(name) == 20:
                try:
                    storages[int(name[12:], 16)] = "/".join(parts)
                except ValueError:
                    pass
    return streams, storages


def dump_object(file, obj, msg, props, storage, ole_streams, ole_storages):
    """Dumps the properties of the storage `storage` (path parts) read through `msg`."""
    streams, storages = obj_streams(ole_streams, ole_storages, storage)
    entries = {}
    if props is not None:
        for name, prop in props.items():
            try:
                entries[int(name, 16)] = prop
            except ValueError:
                pass
    by_id = {}
    for tag in streams:
        by_id.setdefault(tag >> 16, []).append(tag)
    for tag in sorted(set(entries) | set(streams) | set(storages)):
        t = tag & 0xFFFF
        key = f"{tag:08X}"
        prop = entries.get(tag)
        if prop is not None:
            emit(file, obj, f"flags:{key}", int(prop.flags))
        try:
            if t in FIXED and prop is not None and hasattr(prop, "value"):
                value = norm(t, prop.value)
            elif t == 0x000D:
                value = "object" if tag in storages else "missing"
            elif tag in streams:
                path = streams[tag]
                if len(by_id[tag >> 16]) == 1:
                    # extract-msg picks the stream by property id.
                    found, v = msg._getTypedStream(path[:-4], False)
                else:
                    # More than one type for the id: parse this stream alone.
                    data = msg.getStream(path, False)
                    found, v = True, (None if not data else extract_msg.utils.parseType(t, data, msg.stringEncoding, []))
                if not found:
                    value = "missing"
                elif v is None and t in (0x001E, 0x001F):
                    value = norm(t, "")
                elif v is None and t == 0x0102:
                    value = norm(t, b"")
                elif v is None and t & 0x1000:
                    value = "mv:[]"
                else:
                    value = norm(t, v)
            else:
                value = "missing"
        except Exception as e:  # the oracle failing is a fact too
            value = f"ERROR:{type(e).__name__}"
        emit(file, obj, f"p:{key}", value)
        if tag in streams:
            try:
                emit(file, obj, f"r:{key}", sha(msg.getStream(streams[tag], False) or b""))
            except Exception as e:
                emit(file, obj, f"r:{key}", f"ERROR:{type(e).__name__}")


def dump_message(file, obj, msg, storage, ole_streams, ole_storages, depth):
    props = msg.props
    try:
        emit(file, obj, "header", f"{props.nextRecipientId},{props.nextAttachmentId},{props.recipientCount},{props.attachmentCount}")
    except Exception as e:
        emit(file, obj, "header", f"ERROR:{type(e).__name__}")
    dump_object(file, obj, msg, props, storage, ole_streams, ole_storages)
    rtf_path = "/".join(storage + ("__substg1.0_10090102",))
    if any("/".join(p).lower() == rtf_path.lower() for p in ole_streams):
        try:
            rtf = compressed_rtf.decompress(msg.getStream(rtf_path, False) or b"")
            emit(file, obj, "rtf", sha(rtf.split(b"\0", 1)[0]))
        except Exception as e:
            emit(file, obj, "rtf", f"ERROR:{type(e).__name__}")

    # Recipients, found the way extract-msg's MessageBase does.
    recips = []
    for parts in msg.listDir(False, True, False):
        if parts[0].startswith("__recip") and parts[0] not in recips:
            recips.append(str(parts[0]))
    emit(file, obj, "count:recipients", len(recips))
    for d in recips:
        try:
            idx = int(d.split("#", 1)[1], 16)
        except ValueError:
            continue
        o = f"{obj}/r{idx}"
        try:
            r = Recipient(d, msg, RecipientType)
            rprops = r.props
        except Exception as e:
            emit(file, o, "recipient", f"ERROR:{type(e).__name__}")
            rprops = None
        dump_object(file, o, msg, rprops, storage + (d,), ole_streams, ole_storages)

    try:
        atts = msg.attachments
    except Exception as e:
        emit(file, obj, "count:attachments", f"ERROR:{type(e).__name__}")
        return
    emit(file, obj, "count:attachments", len(atts))
    for att in atts:
        d = str(att.dir)
        try:
            idx = int(d.split("#", 1)[1], 16)
        except ValueError:
            continue
        o = f"{obj}/a{idx}"
        dump_object(file, o, msg, att.props, storage + (d,), ole_streams, ole_storages)
        kind = type(att).__name__
        if kind == "Attachment":
            emit(file, o, "att:kind", "binary")
        elif kind == "EmbeddedMsgAttachment":
            emit(file, o, "att:kind", "message")
            inner = att.data
            if isinstance(inner, MSGFile) and depth < 16:
                dump_message(file, f"{o}/m", inner, storage + (d, "__substg1.0_3701000D"), ole_streams, ole_storages, depth + 1)
        elif kind == "CustomAttachment":
            emit(file, o, "att:kind", "storage")
        else:
            emit(file, o, "att:kind", f"other:{kind}")


def dump_file(root, rel):
    path = f"{root}/{rel}"
    try:
        ole = olefile.OleFileIO(path)
        emit(rel, "file", "clsid", (ole.root.clsid or "00000000-0000-0000-0000-000000000000").upper())
        ole_streams = ole.listdir(streams=True, storages=False)
        ole_storages = ole.listdir(streams=False, storages=True)
        ole.close()
    except Exception as e:
        emit(rel, "file", "open", f"ERROR:{type(e).__name__}")
        return
    try:
        msg = MSGFile(path, errorBehavior=ErrorBehavior.SUPPRESS_ALL)
    except Exception as e:
        emit(rel, "file", "open", f"ERROR:{type(e).__name__}")
        return
    try:
        for _, prop in msg.named.items():
            pid = prop.propertyStreamID
            guid = str(prop.guid).strip("{}").upper()
            if type(prop).__name__ == "StringNamedProperty":
                emit(rel, "file", f"named:{pid}", f"{guid}:name:{js(prop.name)}")
            else:
                emit(rel, "file", f"named:{pid}", f"{guid}:id:0x{prop.rawEntry['id']:X}")
    except Exception as e:
        emit(rel, "file", "named", f"ERROR:{type(e).__name__}")
    try:
        dump_message(rel, "m", msg, (), ole_streams, ole_storages, 0)
    except Exception as e:
        emit(rel, "m", "message", f"ERROR:{type(e).__name__}")
    try:
        msg.close()
    except Exception:
        pass


def main():
    if extract_msg.__version__ != "0.58.2":
        sys.exit(f"extract-msg 0.58.2 expected, found {extract_msg.__version__}")
    root = sys.argv[1]
    for rel in sys.argv[2:]:
        dump_file(root, rel)
    sys.stdout.write("".join(line + "\n" for line in sorted(OUT)))


if __name__ == "__main__":
    main()
