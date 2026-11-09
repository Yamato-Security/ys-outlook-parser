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
"""Compares the crate's dump with the oracle's (see extract_msg_dump.py for the format).

    python3 compare.py ORACLE.tsv CRATE.tsv [--details N] [--differences OUT.tsv]

Prints the number of files, objects and properties compared, and every difference grouped by
category. Differences are explained by the rules in `classify` (where extract-msg is known to
be wrong or to do less) or by known_differences.tsv (file, object, key, reason; shell-style
patterns), and counted separately; the exit status is 1 if any difference is not explained.
Floating times within 1 microsecond are equal (both sides round a double). --differences writes
every explained difference (file, object, key, oracle value, crate value, reason): the list
tests/oracle.rs checks the fixtures against.
"""

import collections
import fnmatch
import os
import sys


def load(path):
    facts = {}
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.rstrip("\n")
            if not line:
                continue
            file, obj, key, value = line.split("\t", 3)
            facts[(file, obj, key)] = value
    return facts


def load_known(path):
    known = []
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.rstrip("\n")
                if not line or line.startswith("#"):
                    continue
                file, obj, key, reason = line.split("\t", 3)
                known.append((file, obj, key, reason))
    return known


def explained(known, fact):
    for file, obj, key, reason in known:
        if fnmatch.fnmatchcase(fact[0], file) and fnmatch.fnmatchcase(fact[1], obj) and fnmatch.fnmatchcase(fact[2], key):
            return reason
    return None


def close_apptime(a, b):
    try:
        if a.startswith("apptime:") and b.startswith("apptime:"):
            return abs(int(a[8:]) - int(b[8:])) <= 1
    except ValueError:
        pass
    return False


def message_object(obj):
    """The message object a recipient or attachment object belongs to."""
    parts = obj.split("/")
    while parts and parts[-1] != "m":
        parts.pop()
    return "/".join(parts)


def classify(key, o, c, oracle, crate):
    """Built-in explanations of differences where extract-msg is wrong or does less."""
    file, obj, k = key
    tag_type = k[-4:] if ":" in k else ""
    if o and c and o.startswith("time:") and c.startswith("time:"):
        ov, cv = int(o[5:]), int(c[5:])
        if abs(ov - cv) == 1:
            return "extract-msg converts FILETIME through a float of seconds: off by 1 microsecond"
        if cv == 91515139200000000 and ov == cv - 60_000_000:
            return "extract-msg turns FILETIME 915151392000000000 (4501-01-01 00:00 UTC) into its NullDate 4500-12-31 23:59"
        if cv * 10 > 915_000_000_000_000_000 and ov - cv == 3_600_000_000:
            return "extract-msg builds dates after 4500 from 1970-01-01 01:00 instead of 00:00: one hour late"
    if o and c and o.startswith("s8:") and c.startswith("s8:"):
        m = message_object(obj)
        if k == "p:1013001E" and (file, m, "p:3FDE0003") in crate:
            return "the crate decodes the PtypString8 HTML body in PidTagInternetCodepage; extract-msg in its message encoding"
        if (file, m, "p:3FFD0003") not in crate:
            return "no PidTagMessageCodepage: extract-msg decodes PtypString8 as ISO-8859-15, the crate in the code page of PidTagMessageLocaleId/PidTagInternetCodepage"
    if k.startswith("r:") and c is None and tag_type not in ("001E", "001F", "0102"):
        return "the crate keeps no raw copy of this type's stream; its decoded value (p:) is compared"
    if k.startswith("named:") and o is None and c is not None:
        same = [kk for kk, v in oracle.items() if kk[0] == file and kk[2].startswith("named:") and v == c]
        if same:
            return "extract-msg keeps one property id per named identity; this file maps the identity to several ids"
    return None


def main():
    oracle = load(sys.argv[1])
    crate = load(sys.argv[2])
    details = 20
    if "--details" in sys.argv:
        details = int(sys.argv[sys.argv.index("--details") + 1])
    known = load_known(os.path.join(os.path.dirname(os.path.abspath(__file__)), "known_differences.tsv"))

    files = {k[0] for k in oracle} | {k[0] for k in crate}
    objects = {k[:2] for k in oracle if k[1] != "file"} | {k[:2] for k in crate if k[1] != "file"}
    props = {k for k in oracle if k[2].startswith("p:")} | {k for k in crate if k[2].startswith("p:")}
    print(f"files: {len(files)}, objects: {len(objects)}, properties: {len(props)}, facts: oracle {len(oracle)}, crate {len(crate)}")

    # Both failing to open a file is agreement, whatever the messages. A file only one side
    # could open is one difference.
    failed_oracle = {k[0] for k in oracle if k[1:] == ("file", "open")}
    failed_crate = {k[0] for k in crate if k[1:] == ("file", "open")}

    groups = collections.defaultdict(list)
    explained_groups = collections.defaultdict(list)
    same = 0

    def record(cat, key, o, c, reason):
        target = explained_groups if reason else groups
        target[(cat, reason)].append((key, o, c))

    for file in sorted(failed_oracle ^ failed_crate):
        key = (file, "file", "open")
        record("open", key, oracle.get(key), crate.get(key), explained(known, key))
    for key in sorted(set(oracle) | set(crate)):
        file = key[0]
        if file in failed_oracle or file in failed_crate:
            continue
        o, c = oracle.get(key), crate.get(key)
        if o == c or (o is not None and c is not None and close_apptime(o, c)):
            same += 1
            continue
        kind = key[2].split(":", 1)[0]
        if o is None:
            cat = f"only-crate {kind}"
        elif c is None:
            cat = f"only-oracle {kind}"
        else:
            cat = f"differ {kind}"
        record(cat, key, o, c, explained(known, key) or classify(key, o, c, oracle, crate))

    if "--differences" in sys.argv:
        out = sys.argv[sys.argv.index("--differences") + 1]
        rows = []
        for (cat, reason), items in explained_groups.items():
            for key, o, c in items:
                rows.append("\t".join([*key, o or "-", c or "-", reason]))
        with open(out, "w", encoding="utf-8") as f:
            f.write("".join(r + "\n" for r in sorted(rows)))

    print(f"identical facts: {same}")
    for title, g in (("EXPLAINED", explained_groups), ("UNEXPLAINED", groups)):
        total = sum(len(v) for v in g.values())
        print(f"\n== {title}: {total}")
        for (cat, reason), items in sorted(g.items(), key=lambda kv: (-len(kv[1]), kv[0])):
            print(f"-- {cat}: {len(items)}" + (f"  [{reason}]" if reason else ""))
            for key, o, c in items[:details]:
                print(f"   {key[0]} | {key[1]} | {key[2]}\n      oracle: {o}\n      crate:  {c}")
    sys.exit(1 if groups else 0)


if __name__ == "__main__":
    main()
