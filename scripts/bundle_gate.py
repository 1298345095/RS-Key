#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""Hold a closed slice's raw evidence bundle to stage 1A's ten-group contract.

The contract is in `docs/authorization-slice.md`: property/subject and owners;
commit/build/features; method and scope/bounds; tool, version, invocation and
environment; principal result; raw artifact; assumptions and TCB; mutation
verdicts; timestamp and revalidation triggers; and measured costs. A missing
field blocks the exit, and "measured costs" means three things — human time,
runner time and peak memory — not one.

**Ten headings with one line each satisfy "all ten groups are present"**, which
is why this counts LEAVES and floors them per group. A leaf is a scalar at the
bottom of the tree; an empty string, an empty list and an empty table are all
findings, in every group, at every depth. That is the only form in which
"unabridged" is a predicate.

Four rules are about the bundle being EVIDENCE rather than prose:

* every `[[method]]`'s `artifact` resolves against the tree. The field is the
  row's whole claim — this obligation, discharged by that proof — and nothing
  read it: renaming `no_authorization_bypass_walk_owner` left the exit at 0, and
  the bundle's own `kani=4` line green at 3;
* every `[[artifact]]` names a path that is in the tree, and it is the unedited
  output of the run beside it — a summarized log is not an artifact;
* every cost is a NUMBER. A range (`"1.5–3×"`, `"a few hours"`) is an estimate,
  and the whole point of the first closed slice is that its cost is measured;
  the calibration counterpart's estimate is labelled as one and lives in the
  design page, not here;
* every `[[mutation]]` records the assertion that fell and its DIRECTION, and
  says whether that describes the modelled defect or its inverse. Two of
  twenty-four co-refutation patches in this tree scored a kill for the inverse
  defect, and the tell was that every failure said "should have succeeded".

Deliberately not here: whether the numbers are RIGHT. Nothing can check that a
recorded wall-clock is the one the run took. What this row keeps honest is that
no field of the contract was quietly dropped, that every artifact it points at
still exists, and that no cost was written as a range.
"""

import hashlib
import pathlib
import re
import sys
import tomllib

ROOT = pathlib.Path(__file__).resolve().parent.parent
BUNDLE = pathlib.Path("assurance/bundle/SEC-FIDO-001.toml")
REGISTRY = pathlib.Path("assurance/properties.toml")
#: Where a bare `Name.cfg` lives. The bundle names TLC configurations without a
#: directory throughout — four of the eight method rows do — and `formal/` is the
#: only place either extension is written.
FORMAL = pathlib.Path("formal")

#: Stage 1A п.3's ten groups, in its order, with the table each is spelled as.
#: The names are the contract's; renaming one here would be renaming the
#: contract, so a group that is gone reads as gone.
GROUPS = (
    "property",
    "build",
    "method",
    "tool",
    "result",
    "artifact",
    "assumption",
    "mutation",
    "freshness",
    "cost",
)

#: The fields each group owes BY NAME. A leaf floor counts volume, not fields:
#: padding a group with a long list of anything clears it, and renaming a field
#: to nonsense keeps the count. Named here so a dropped field is the finding the
#: docstring claims it is — for the array groups every row owes them, for the
#: table groups the group does.
REQUIRED = {
    "property": ("id", "invariant", "statement", "subjects", "requirement", "threat_clause"),
    "build": ("commit", "tree_state", "matrix_column", "cargo_features", "host_triple"),
    "method": ("obligation", "method", "artifact", "shipped_relation", "cfg", "features"),
    "tool": ("name", "version", "provenance", "invocation", "environment"),
    "result": (),  # one key per artifact, and which artifacts exist is the tree's
    "artifact": ("run", "path", "bytes", "sha256"),
    "assumption": ("id", "statement", "kind", "discharger", "expressible", "registered"),
    "mutation": ("level", "mutant", "invocation", "expected", "verdict", "fell", "direction"),
    "freshness": ("measured",),
    "cost": ("artifact", "human_minutes", "runner_seconds", "peak_memory_mb", "basis"),
}

#: Leaves per group, floored so ten headings with one line each cannot pass. Set
#: under the measured counts, the way every other ratchet in this tree is.
FLOORS = {
    "property": 6,
    "build": 6,
    "method": 20,
    "tool": 20,
    # 18 and not 30: 30 was written before the group existed and was never a
    # measurement of anything — the group carries 22 keys, one per artifact plus
    # one per gate this slice moved. Calibrated UNDER the measurement, like every
    # other ratchet here; it has never been green at 30, so this lowers nothing.
    "result": 18,
    "artifact": 8,
    "assumption": 30,
    "mutation": 20,
    "freshness": 6,
    "cost": 12,
}

#: The three the item exists to observe. Each must be a number: a range is an
#: estimate wearing a measurement's field.
COST_FIELDS = ("human_minutes", "runner_seconds", "peak_memory_mb")

#: What makes a word of a `[[method]] artifact` a REFERENCE and not prose. Six
#: spellings sit in the eight rows — a repo path, a bare `Name.cfg`,
#: `path::symbol`, an elided `…suffix`, and two rows trailing off into prose
#: (`bounds table`, `over …`) — so the field is resolved token by token. A rule
#: demanding every word resolve gets switched off inside a week; one reading only
#: `::` walks past `Shipped.cfg`.
REFERENCE_SUFFIXES = (
    ".cfg", ".tla", ".rs", ".py", ".sh", ".md", ".toml", ".txt", ".jsonl", ".log", ".gz",
)

#: `…_creds_begin_at_call_site`: a second harness inside the file the token
#: before it named. The bundle already writes it this way.
ELISION = ("…", "...")

#: Punctuation a reference can be wrapped in without ceasing to be one.
TRIM = "()[]{},;:'\"`"

#: An assertion that fell describes the modelled defect, or its inverse. Anything
#: else is a word nobody has to defend.
DIRECTIONS = ("modelled", "inverse")

#: The two rosters above must name the same ten groups. One in `GROUPS` and not
#: in `FLOORS` is a `KeyError`; one in `FLOORS` and not in `GROUPS` is silently
#: dead, which is the direction nothing would have shown.
assert set(GROUPS) == set(FLOORS) == set(REQUIRED), "GROUPS, FLOORS and REQUIRED drifted"


def leaves(value, path="") -> tuple[int, list[str]]:
    """(leaf count, the paths that are empty) under `value`."""
    if isinstance(value, dict):
        if not value:
            return 0, [path or "<root>"]
        total, empty = 0, []
        for key, item in value.items():
            found, holes = leaves(item, f"{path}.{key}" if path else key)
            total += found
            empty += holes
        return total, empty
    if isinstance(value, list):
        if not value:
            return 0, [path]
        total, empty = 0, []
        for index, item in enumerate(value):
            found, holes = leaves(item, f"{path}[{index + 1}]")
            total += found
            empty += holes
        return total, empty
    if isinstance(value, str) and not value.strip():
        return 1, [path]
    return 1, []


def resolve(root: pathlib.Path, name: str) -> pathlib.Path | None:
    """The file `name` names, or None. A bare configuration is `formal/`'s.

    Absolute and `..` are None rather than resolved: `root / "/etc/hosts"` is
    `/etc/hosts`, which `is_file()` answers yes to, and "in the tree" is what
    this is about — the same spelling the `[[artifact]]` rule already pays for.
    """
    parts = pathlib.PurePosixPath(name).parts
    if pathlib.PurePosixPath(name).is_absolute() or ".." in parts:
        return None
    if (root / name).is_file():
        return root / name
    if "/" not in name and pathlib.PurePosixPath(name).suffix in (".cfg", ".tla"):
        return root / FORMAL / name if (root / FORMAL / name).is_file() else None
    return None


def method_references(root: pathlib.Path, doc: dict, findings: list[str]) -> None:
    """Every `[[method]]`'s `artifact` names something this tree still has.

    A `.rs` file must carry its `::symbol`. Naming the file alone is how this
    rule would be walked past — a bounded proof is identified by its harness, and
    the file outlives any one of them.
    """
    for index, row in enumerate(doc.get("method", []), 1):
        if not isinstance(row, dict) or "artifact" not in row:
            continue  # a dropped field is the REQUIRED rule's, reported once
        where = f"{BUNDLE} method #{index}"
        resolved, last = 0, None
        for word in re.split(r"[\s+]+", str(row["artifact"])):
            token = word.strip(TRIM)
            if token.startswith(ELISION):
                symbol, target = token.lstrip("…. "), last
                if target is None:
                    findings.append(f"{where}: `{token}` elides a file no earlier token named")
                    continue
            else:
                name, _, symbol = token.partition("::")
                if pathlib.PurePosixPath(name).suffix not in REFERENCE_SUFFIXES:
                    continue
                target = resolve(root, name)
                if target is None:
                    findings.append(
                        f"{where}: `{name}` is not in the tree — a method row's"
                        " artifact is the proof it claims, and one nothing resolves"
                        " is a claim nobody can refute"
                    )
                    continue
                resolved, last = resolved + 1, target
                if target.suffix == ".rs" and not symbol:
                    findings.append(
                        f"{where}: `{name}` names a Rust file and no `::harness` —"
                        " the file is not the proof, and it outlives any one of them"
                    )
            if symbol and symbol not in target.read_text(encoding="utf-8", errors="replace"):
                findings.append(
                    f"{where}: `{symbol}` appears nowhere in"
                    f" {target.relative_to(root)} — the harness this row rests on"
                    " is gone or renamed"
                )
        if not resolved:
            findings.append(
                f"{where}: `artifact` resolves nothing in the tree — a method with"
                " no artifact is the obligation restated, not discharged"
            )


def audit(root: pathlib.Path) -> tuple[list[str], str]:
    root = pathlib.Path(root)
    findings: list[str] = []
    path = root / BUNDLE
    if not path.is_file():
        return [f"{BUNDLE}: no such bundle"], ""
    doc = tomllib.loads(path.read_text(encoding="utf-8"))

    for group in GROUPS:
        if group not in doc:
            findings.append(
                f"{BUNDLE}: group `{group}` is missing — stage 1A п.3 blocks the exit"
                " on any field of the contract, not on most of them"
            )
    for group in sorted(set(doc) - set(GROUPS)):
        findings.append(f"{BUNDLE}: `{group}` is in no group of the contract")

    total = 0
    for group in GROUPS:
        if group not in doc:
            continue
        found, empty = leaves(doc[group], group)
        total += found
        for hole in empty:
            findings.append(f"{BUNDLE}: `{hole}` is empty — a blank leaf is a dropped field")
        if found < FLOORS[group]:
            findings.append(
                f"{BUNDLE}: group `{group}` carries {found} leaf/leaves, under the floor"
                f" of {FLOORS[group]} — a heading with one line under it is what"
                " 'unabridged' has to be a predicate about"
            )

    for group in GROUPS:
        if group not in doc:
            continue
        rows = doc[group] if isinstance(doc[group], list) else [doc[group]]
        for index, row in enumerate(rows, 1):
            where = f"{BUNDLE} {group}" + (f" #{index}" if isinstance(doc[group], list) else "")
            if not isinstance(row, dict):
                findings.append(f"{where}: is not a table — the contract's groups are tables")
                continue
            for field in REQUIRED[group]:
                if field not in row:
                    findings.append(f"{where}: no `{field}` — the contract names it")

    registry = tomllib.loads((root / REGISTRY).read_text(encoding="utf-8"))
    known = {entry["id"] for entry in registry.get("property", [])}
    subject = doc.get("property", {}).get("id")
    if subject not in known:
        findings.append(f"{BUNDLE}: property `{subject}` is in no row of {REGISTRY}")

    method_references(root, doc, findings)

    for index, row in enumerate(doc.get("artifact", []), 1):
        where = f"{BUNDLE} artifact #{index}"
        target = row.get("path", "")
        if pathlib.PurePosixPath(target).is_absolute():
            findings.append(
                f"{where}: `{target}` is absolute — `root / path` then leaves the tree,"
                " and 'in the tree' is what this rule is about"
            )
            continue
        if not (root / target).is_file():
            findings.append(f"{where}: `{target}` is not in the tree — a path is not a log")
            continue
        raw = (root / target).read_bytes()
        if len(raw) != row.get("bytes"):
            findings.append(
                f"{where}: `{target}` is {len(raw)} bytes and the bundle records"
                f" {row.get('bytes')} — a log that was edited is not the unedited"
                " output of the run"
            )
        # And a DIGEST, because a byte count is satisfied by any file of the same
        # length: replacing a 10-byte log with a different 10-byte one was green.
        if hashlib.sha256(raw).hexdigest() != row.get("sha256"):
            findings.append(
                f"{where}: `{target}` hashes to {hashlib.sha256(raw).hexdigest()[:16]}…"
                f" and the bundle records {str(row.get('sha256'))[:16]}… — the log is"
                " not the one the run wrote"
            )

    for index, row in enumerate(doc.get("cost", []), 1):
        where = f"{BUNDLE} cost #{index} ({row.get('artifact', '?')})"
        for field in COST_FIELDS:
            value = row.get(field)
            if value is None:
                findings.append(f"{where}: no `{field}` — the item measures three, not one")
            elif not isinstance(value, (int, float)) or isinstance(value, bool):
                findings.append(
                    f"{where}: `{field}` is {value!r}, which is not a number — a range is"
                    " an estimate, and an estimate in any of the three voids the measurement"
                )

    for index, row in enumerate(doc.get("mutation", []), 1):
        where = f"{BUNDLE} mutation #{index} ({row.get('mutant', '?')})"
        if row.get("direction") not in DIRECTIONS:
            findings.append(
                f"{where}: direction {row.get('direction')!r} is not one of {DIRECTIONS}"
                " — a red run is not evidence until the direction is read"
            )

    summary = (
        f"bundle-gate: ok — {BUNDLE.name} carries {len(GROUPS)} groups and {total}"
        f" leaves, {len(doc.get('artifact', []))} raw artifact(s),"
        f" {len(doc.get('mutation', []))} mutation verdict(s)"
    )
    return findings, summary


def main() -> int:
    findings, summary = audit(ROOT)
    if findings:
        print("bundle-gate:", file=sys.stderr)
        for finding in findings:
            print(f"  {finding}", file=sys.stderr)
        return 1
    print(summary)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
