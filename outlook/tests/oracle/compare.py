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
"""Compares the crate's dump of PST and OST files with libpff's (see pff_dump.py for the format).

    python3 compare.py LIBPFF.tsv CRATE.tsv [--details N]

Prints, per file, the facts that are the same, and every difference by category. A difference is
explained when it is one of these (the same rules as tests/pst_oracle.rs):

- absent cell: libpff lists every column of a recipient row, with an empty or zero value where
  the row's cell existence bitmap says the cell is absent; the crate leaves those out.
- computed: the crate gives a folder's PidTagEntryId and PidTagFolderType, as MAPI does; they are
  not stored.
- FAI: the crate reads folder associated information (hidden messages); pypff cannot.
- object: libpff gives a PtypObject value's stored node id and size; the crate reads the object.
- embedded message: libpff gives an embedded message's node data as the attachment's data; the
  crate reads the message.
- read only by the crate: a message, recipient or attachment libpff fails to read.

Attachments are matched regardless of their order: the crate lists them in the order of the
attachment table's rows, libpff by row id. The exit status is 1 if any difference is not explained.
"""

import collections
import sys


def load(path):
    """file -> {key: value}, the FAI items, the attachment methods, the items with errors."""
    facts = collections.defaultdict(dict)
    fai = collections.defaultdict(set)
    errors = collections.defaultdict(set)
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            c = line.rstrip("\n").split("\t")
            if len(c) < 3:
                continue
            name, kind = c[0], c[1]
            if kind == "folder":
                facts[name][("folder", c[2])] = tuple(c[3:7])
                if c[7] != "":
                    facts[name][("folder-fai", c[2])] = c[7]
            elif kind == "item":
                if c[4] == "1":
                    fai[name].add(c[3])
                facts[name][("item", c[3])] = c[2]
            elif kind == "prop":
                scope, owner, index, pid, ptype, value = c[2:8]
                facts[name][("prop", scope, owner, index, pid)] = (ptype, value)
            elif kind == "attach":
                facts[name][("attach", c[2], c[3])] = (c[4], c[5])
            elif kind == "error" and c[2] in ("item", "recipient", "attachment"):
                errors[name].add(c[3])
            elif kind == "error" and c[2] in ("file", "folder") and c[3] == "":
                errors[name].add("file")
    return facts, fai, errors


def reorder_attachments(facts):
    """Index each item's attachments by their content, so that their order does not matter: by
    their properties and data, leaving out what the two sides give differently (objects, and the
    data of embedded messages)."""
    by_item = collections.defaultdict(lambda: collections.defaultdict(list))
    embedded = {
        (key[2], key[3])
        for key, value in facts.items()
        if key[0] == "prop" and key[1] == "attachment" and key[4] == "3705"
        and value[1] == "05000000"
    }
    for key, value in facts.items():
        if key[0] == "attach":
            by_item[key[1]][key[2]]
            if (key[1], key[2]) not in embedded:
                by_item[key[1]][key[2]].append(("attach",) + value)
        elif key[0] == "prop" and key[1] == "attachment":
            by_item[key[2]][key[3]]
            if value[0] != "000d":
                by_item[key[2]][key[3]].append((key[4],) + value)
    order = {}
    for item, attachments in by_item.items():
        ranked = sorted(attachments, key=lambda index: (sorted(attachments[index]), index))
        for new, old in enumerate(ranked):
            order[(item, old)] = str(new)
    out = {}
    for key, value in facts.items():
        if key[0] == "attach":
            key = ("attach", key[1], order[(key[1], key[2])])
        elif key[0] == "prop" and key[1] == "attachment":
            key = key[:3] + (order[(key[2], key[3])],) + key[4:]
        out[key] = value
    return out


def owner(key):
    if key[0] in ("item", "attach"):
        return key[1]
    if key[0] == "prop" and key[1] in ("item", "recipient", "attachment"):
        return key[2]
    return None


def explain(key, ours, theirs, crate, fai, pff_errors, pff_items):
    """Why a fact differs, or None."""
    item = owner(key)
    if theirs is None:
        if not pff_items and "file" in pff_errors:
            return "read only by the crate"
        if key[0] == "folder-fai" or (item is not None and item in fai):
            return "FAI"
        if key[0] == "prop" and key[1] == "folder" and key[4] in ("0fff", "3601"):
            return "computed"
        if item is not None and (item not in pff_items or item in pff_errors):
            return "read only by the crate"
        return None
    if ours is None:
        if key[0] == "prop" and key[1] == "recipient" and set(theirs[1]) <= {"0"}:
            return "absent cell"
        return None
    if key[0] == "prop" and ours[0] == "000d" == theirs[0]:
        return "object"
    if key[0] == "attach" and ours == ("0", ""):
        method = crate.get(("prop", "attachment", key[1], key[2], "3705"))
        if method is not None and method[1] == "05000000":
            return "embedded message"
    return None


def main():
    args = sys.argv[1:]
    details = 5
    if "--details" in args:
        i = args.index("--details")
        details = int(args[i + 1])
        del args[i : i + 2]
    pff, _, pff_errors = load(args[0])
    crate, fai, _ = load(args[1])
    total = collections.Counter()
    unexplained = 0
    for name in sorted(set(pff) | set(crate)):
        a = reorder_attachments(crate.get(name, {}))
        b = reorder_attachments(pff.get(name, {}))
        pff_items = {k[1] for k in b if k[0] == "item"}
        same = 0
        found = collections.defaultdict(list)
        for key in sorted(set(a) | set(b)):
            ours, theirs = a.get(key), b.get(key)
            if ours == theirs:
                same += 1
                continue
            why = explain(key, ours, theirs, a, fai[name], pff_errors[name], pff_items)
            found[why or "UNEXPLAINED"].append((key, ours, theirs))
        total["same"] += same
        line = f"{name}: same {same}"
        for why, keys in sorted(found.items()):
            line += f", {why} {len(keys)}"
            total[why] += len(keys)
        print(line)
        for key, ours, theirs in found.get("UNEXPLAINED", [])[:details]:
            print(f"    UNEXPLAINED {key}: crate {ours}, libpff {theirs}")
        unexplained += len(found.get("UNEXPLAINED", []))
    print("total: " + ", ".join(f"{k} {v}" for k, v in total.most_common()))
    return 1 if unexplained else 0


if __name__ == "__main__":
    sys.exit(main())
