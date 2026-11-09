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
"""Dump what libpff reads from PST and OST files, as TSV lines, for a field-by-field comparison
with the crate (`cargo run --example pst_dump`, which writes the same lines).

libpff (https://github.com/libyal/libpff, LGPL-3.0-or-later), through its Python bindings pypff
(PyPI libpff-python 20260926), is used here only as an independent, external oracle: this script
imports it and calls its API; none of its code is copied into this script or into the crates. Run
it with the interpreter of a virtualenv that has libpff-python installed, in isolated mode:

    python -I pff_dump.py FILE... > libpff.tsv

One line per fact; the first two columns are the file name (without its directory) and the kind:

    folder   folder id, parent id, name, sub-folders, messages, associated (FAI) messages
    item     owner (folder id), item id, associated (always 0: pypff cannot list FAI messages)
    prop     scope (store/folder/item/recipient/attachment), owner, index, property id, type, value
    attach   item id, index, size, sha256 of the data (empty when there is no data)
    error    scope, owner, index, message

`value` is the property's bytes as stored, in hex, or `sha256:<hex>:<length>` when longer than 64
bytes. A `PtypString` value is given without a trailing NUL terminator: the crate gives the text,
and whether the writer stored a terminator is not kept. Owners: a store by 33 (its node id), a
folder by its node id, an item by its node id, a recipient or attachment by its item's node id and
its index.

To regenerate the fixtures' output (from outlook/):

    for f in ../pst/tests/fixtures/*.gz; do gunzip -c $f > /tmp/$(basename ${f%.gz}); done
    cp ../pst/tests/fixtures/Empty.pst /tmp/
    python -I tests/oracle/pff_dump.py /tmp/Empty.pst /tmp/dist-list.pst /tmp/example-2013.ost \
        /tmp/outlook.pst | gzip -9 -n > tests/oracle/fixtures.pff.tsv.gz
"""

import hashlib
import sys

import pypff

LIMIT = 64
PTYP_STRING = 0x001F


def value(data, value_type=None):
    if data is None:
        return ""
    if value_type == PTYP_STRING:
        while len(data) >= 2 and data[-2:] == b"\0\0":
            data = data[:-2]
    if len(data) > LIMIT:
        return f"sha256:{hashlib.sha256(data).hexdigest()}:{len(data)}"
    return data.hex()


def out(*columns):
    print("\t".join("" if c is None else str(c) for c in columns))


def props(name, scope, owner, index, item):
    try:
        sets = item.number_of_record_sets
    except Exception as e:
        out(name, "error", scope, owner, index, f"record sets: {e}")
        return
    for s in range(sets):
        try:
            record_set = item.get_record_set(s)
        except Exception as e:
            out(name, "error", scope, owner, index, f"record set {s}: {e}")
            continue
        for e_index in range(record_set.number_of_entries):
            try:
                entry = record_set.get_entry(e_index)
                out(name, "prop", scope, owner, index if sets == 1 else f"{index}.{s}",
                    f"{entry.entry_type:04x}", f"{entry.value_type:04x}",
                    value(entry.data, entry.value_type))
            except Exception as e:
                out(name, "error", scope, owner, index, f"entry {e_index}: {e}")


def message(name, owner, item, associated):
    nid = item.identifier
    out(name, "item", owner, nid, int(associated))
    props(name, "item", nid, "", item)
    try:
        recipients = item.recipients
    except Exception as e:
        recipients = None
        out(name, "error", "recipient", nid, "", f"recipients: {e}")
    if recipients is not None:
        for r in range(recipients.number_of_record_sets):
            try:
                record_set = recipients.get_record_set(r)
            except Exception as e:
                out(name, "error", "recipient", nid, r, str(e))
                continue
            for e_index in range(record_set.number_of_entries):
                try:
                    entry = record_set.get_entry(e_index)
                    out(name, "prop", "recipient", nid, r, f"{entry.entry_type:04x}",
                        f"{entry.value_type:04x}", value(entry.data, entry.value_type))
                except Exception as e:
                    out(name, "error", "recipient", nid, r, f"entry {e_index}: {e}")
    try:
        count = item.number_of_attachments
    except Exception as e:
        count = 0
        out(name, "error", "attachment", nid, "", f"attachments: {e}")
    for a in range(count):
        try:
            attachment = item.get_attachment(a)
        except Exception as e:
            out(name, "error", "attachment", nid, a, str(e))
            continue
        props(name, "attachment", nid, a, attachment)
        data_hash, size = "", ""
        try:
            size = attachment.size
            if size:
                data = attachment.read_buffer(size)
                data_hash = hashlib.sha256(data).hexdigest()
        except Exception as e:
            out(name, "error", "attachment", nid, a, f"data: {e}")
        out(name, "attach", nid, a, size, data_hash)


def folder(name, parent, item):
    nid = item.identifier
    try:
        messages = item.number_of_sub_messages
    except Exception:
        messages = 0
    try:
        associated = item.number_of_sub_associated_contents
    except Exception:
        associated = ""
    out(name, "folder", nid, parent, item.name, item.number_of_sub_folders, messages, associated)
    props(name, "folder", nid, "", item)
    for m in range(messages):
        try:
            message(name, nid, item.get_sub_message(m), False)
        except Exception as e:
            out(name, "error", "item", nid, m, str(e))
    for f in range(item.number_of_sub_folders):
        try:
            folder(name, nid, item.get_sub_folder(f))
        except Exception as e:
            out(name, "error", "folder", nid, f, str(e))


def main(path, name):
    f = pypff.file()
    try:
        f.open(path)
    except Exception as e:
        out(name, "error", "file", "", "", str(e))
        return
    try:
        store = f.get_message_store()
        if store is not None:
            props(name, "store", 33, "", store)
    except Exception as e:
        out(name, "error", "store", "", "", str(e))
    try:
        root = f.get_root_folder()
        folder(name, "", root)
    except Exception as e:
        out(name, "error", "folder", "", "", str(e))
    f.close()


if __name__ == "__main__":
    for path in sys.argv[1:]:
        main(path, path.rsplit("/", 1)[-1])
