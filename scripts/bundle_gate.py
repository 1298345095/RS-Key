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

Five rules are about the bundle being EVIDENCE rather than prose:

* every `[[method]]` carries its bound as STRUCTURED data — a `bound_*` key —
  and answers its two prose fields with something. Stripping all 30 `bound_*`
  keys from all 8 rows left the exit at 0, and `shipped_relation = "n/a"` still
  does; a scope sentence was demanded and the bounds it is about were not;
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
* every `[[mutation]]` records the assertion that fell and its DIRECTION, and an
  `inverse` one is DISPOSED OF rather than published. Two of twenty-four
  co-refutation patches in this tree scored a kill for the inverse defect, and
  the tell was that every failure said "should have succeeded"; such a row is a
  finding about the mutant and not a result about the property, so it owes the
  corrected mutant that supersedes it or the reason it stands, and the success
  line counts it apart from the verdicts.

Deliberately not here: whether the numbers are RIGHT. Nothing can check that a
recorded wall-clock is the one the run took, or that a row calling itself
`modelled` was read that way. What this row keeps honest is that no field of the
contract was quietly dropped, that every claim it makes about the tree resolves
in the tree, and that no cost was written as a range.
"""

import hashlib
import pathlib
import re
import sys
import tomllib

import gate_lines
#: For `HARNESS` alone — the token that says a Rust `fn` is a Kani proof. A
#: second copy here is the defect one directory over.
import kani_gate

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
#:
#: A trailing `*` is a PREFIX and not a name, and `bound_*` is the one entry that
#: needs it: bounds are per method — a sequence length here, a cardinality there,
#: an unwind somewhere else — so no single key can be named and requiring one by
#: name would be requiring the wrong one. Stripping all 30 `bound_*` keys from
#: all 8 rows took the leaf count 419 -> 389 and left the exit at 0, while the
#: scope SENTENCE beside them was required all along.
REQUIRED = {
    "property": ("id", "invariant", "statement", "subjects", "requirement", "threat_clause"),
    "build": ("commit", "tree_state", "matrix_column", "cargo_features", "host_triple"),
    "method": ("obligation", "method", "artifact", "bound_*", "shipped_relation", "cfg", "features"),
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

#: A token SHAPED like a file reference. Without it the resolver had a "gives up,
#: says nothing" arm: `formal/RSKeySecurityState.tlaa` was read as prose because
#: `.tlaa` is in no list, the row's OTHER token resolved, and the typo went past
#: at exit 0. Alphabetic first character, so `§6.8.2` and `2.3` stay prose.
FILE_SHAPED = re.compile(r"\.[A-Za-z][A-Za-z0-9]{0,5}$")

#: `…_creds_begin_at_call_site`: a second harness inside the file the token
#: before it named. The bundle already writes it this way.
ELISION = ("…", "...")

#: Punctuation a reference can be wrapped in without ceasing to be one.
TRIM = "()[]{},;:'\"`"

#: A Rust item DECLARATION, matched over `gate_lines.rust_code` — the file's
#: source with comments and string literals blanked. Reading raw text was this
#: rule's own first version and its own defect: `credmgmt_kani.rs` names
#: `no_authorization_bypass_walk_owner` in a doc comment, so pointing the walk
#: row at the wrong file resolved at exit 0. What a file MENTIONS is not what it
#: defines, which is the same measurement `platform_gate.py`'s inventory paid for.
#:
#: `extern` carries no ABI here for the same reason: the string is already blank
#: by the time this runs, so the `extern "…"` alternative the first version wrote
#: could never match, and `pub extern "C" fn X` was reported as undeclared — a
#: branch nothing can take, wrong in the direction that refuses real code.
#: Line-anchored, so a one-line `mod m { fn target() {} }` declares only `m`;
#: nothing in this tree is written that way and brace tracking is a lexer.
DECLARED = re.compile(
    r"(?m)^[ \t]*(?:pub(?:\([^)]*\))?[ \t]+)?"
    r"(?:(?:const|async|unsafe|extern)[ \t]+)*"
    r"(?:fn|const|static|struct|enum|trait|type|mod)[ \t]+([A-Za-z_][A-Za-z0-9_]*)"
)

#: What an item's attributes are written on: the lines a declaration is preceded
#: by until the previous item ends. Doc comments are already blank by then, so
#: walking back over blanks and `#[…]` reaches the `#[kani::proof]` and stops at
#: the closing brace above it.
ATTRIBUTE = re.compile(r"^[ \t]*#!?\[")

#: §4.1's method vocabulary, in `docs/authorization-slice.md` п.3's order. A word
#: outside it is a finding and not a shrug: [`METHOD_KIND`] reads this field, so
#: `method = "bounded proofs"` would quietly drop the rule that field carries.
METHODS = (
    "review", "model-check", "bounded proof", "deductive proof",
    "exhaustive sweep", "mutation", "trace", "measurement", "accepted risk",
)

#: The two methods whose own word NAMES the kind of artifact discharging them.
#: Without it a row is satisfied by any file in the tree: re-pointing the walk
#: row's artifact at `CHANGELOG.md`, at `README.md` and at this bundle were all
#: exit 0, as were `state_kani.rs::STEPS` (a const) and `::StepRng` (a struct).
#: The other seven §4.1 methods name no kind — this bundle discharges an
#: `exhaustive sweep` with a `.py` over a `.tla` and with two `.cfg` — and
#: inventing one for them would be requiring the wrong one, which is why
#: `bound_*` is a prefix one field over.
METHOD_KIND = {
    "model-check": (".cfg",),
    "bounded proof": (".rs",),
}

#: The method row's two PROSE fields — what the obligation is, and how the bound
#: relates to the shipped domain. A required field is satisfied by any string, so
#: `shipped_relation = "n/a"` cleared the rule that exists to demand the sentence.
PROSE_FIELDS = ("obligation", "shipped_relation")

#: Words that occupy a field without answering it. Scoped to [`PROSE_FIELDS`] and
#: not to every leaf, because `cfg = "none"` and `features = "none"` ARE answers
#: — eight rows of them — and a global rule would redden every one. Compared with
#: internal whitespace removed and case folded, so `N / A` is the same word.
NON_ANSWERS = frozenset(
    {
        "n/a", "n\\a", "na", "notapplicable",
        "none", "nil", "null", "nothing",
        "unknown", "unspecified", "undefined", "unclear",
        "tbd", "tobedetermined", "todo", "xxx", "pending", "wip",
    }
)

#: `-`, `--`, `—`, `?`, `.`, `...`, `…`: the same non-answer with no letters in
#: it, which is the half a vocabulary alone cannot hold.
PUNCTUATION_ONLY = re.compile(r"[\W_]+")

#: An assertion that fell describes the modelled defect, or its inverse. Anything
#: else is a word nobody has to defend.
DIRECTIONS = ("modelled", "inverse")

#: An `inverse` kill is a finding ABOUT THE MUTANT and not a result about the
#: property, so the row owes what became of it. Refusing the word outright was
#: the other option and is worse three ways: the cheapest way past a refusal is
#: to type `modelled`, which nothing in this tree resolves against a real run; a
#: one-word vocabulary is a constant, and a field nothing branches on is a
#: comment with a type; and the field exists precisely to make the 2-of-24 case
#: SAYABLE, so unsaying it is the verdict column this register replaces.
DISPOSITIONS = ("superseded", "kept-as-a-finding")

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


def declarations(target: pathlib.Path) -> tuple[list[str], set[str]]:
    """(every Rust item `target` declares, and those carrying `#[kani::proof]`).

    Rust is read as code — anything else has no item grammar this could parse and
    the claim there is only that the name occurs, which [`method_references`]
    handles in place.

    The harness half is `kani_gate.HARNESS`'s token and not a second copy of it.
    A bounded proof is discharged by a HARNESS, and `DECLARED` matches a const, a
    struct and anything inside a `#[cfg(test)]` block just as happily: `::STEPS`
    and `::StepRng` each discharged the walk row at exit 0.
    """
    code = gate_lines.rust_code(target.read_text(encoding="utf-8", errors="replace"))
    lines = code.splitlines()
    names, proofs = [], set()
    for match in DECLARED.finditer(code):
        name = match.group(1)
        names.append(name)
        above = code.count("\n", 0, match.start()) - 1
        while above >= 0 and (not lines[above].strip() or ATTRIBUTE.match(lines[above])):
            if kani_gate.HARNESS.search(lines[above]):
                proofs.add(name)
            above -= 1
    return names, proofs


def answers(value) -> bool:
    """Whether a prose field says anything at all.

    Case folded with the internal whitespace removed, so `N / A` is `n/a`, and a
    trailing full stop does not buy a second spelling of the same non-answer.
    """
    if not isinstance(value, str):
        return False
    core = "".join(value.split()).rstrip(".!?…").lower()
    return bool(core) and core not in NON_ANSWERS and not PUNCTUATION_ONLY.fullmatch(core)


def method_answers(doc: dict, findings: list[str]) -> None:
    """A method row's prose fields are answered, not occupied.

    `shipped_relation` was required and refused a dropped key, an empty string
    and a whitespace-only one — and took `"n/a"` at exit 0, which is the same
    dropped field wearing three characters.
    """
    for index, row in enumerate(doc.get("method", []), 1):
        if not isinstance(row, dict):
            continue
        # And every `bound_*` written as PROSE, because half of them are: a
        # cardinality is a number and `bound_totals` is a sentence, so requiring
        # the key is satisfied by one bound reading `n/a` — which was measured.
        fields = list(PROSE_FIELDS) + [
            key for key in row if key.startswith("bound_") and isinstance(row[key], str)
        ]
        for field in fields:
            value = row.get(field)
            if field not in row or (isinstance(value, str) and not value.strip()):
                continue  # dropped or blank: reported once, by the rules that own it
            if not answers(value):
                findings.append(
                    f"{BUNDLE} method #{index}: `{field}` is {value!r}, which answers"
                    " nothing — a required field occupied by a non-answer is the same"
                    " field dropped, in a spelling the REQUIRED roster cannot see"
                )


def method_references(root: pathlib.Path, doc: dict, findings: list[str]) -> None:
    """Every `[[method]]`'s `artifact` names something this tree still has, OF THE
    KIND its own `method` word calls for.

    A `.rs` file must carry its `::symbol`, and for a bounded proof that symbol
    must be a harness. Naming the file alone is how this rule would be walked
    past — a bounded proof is identified by its harness, and the file outlives
    any one of them — and naming any DECLARATION is how it was: six of the eight
    rows carry no `::` at all, so the rule degenerated to "a file of that name
    exists" for all six.
    """
    for index, row in enumerate(doc.get("method", []), 1):
        if not isinstance(row, dict) or "artifact" not in row:
            continue  # a dropped field is the REQUIRED rule's, reported once
        where = f"{BUNDLE} method #{index}"
        method = str(row.get("method", ""))
        if "method" in row and method not in METHODS:
            findings.append(
                f"{where}: method {method!r} is in no row of §4.1's vocabulary"
                f" {METHODS} — the kind rule reads this field, so a word outside"
                " it drops the rule the field carries"
            )
        resolved, last, named, proofs, kinds = 0, None, [], 0, set()
        for word in re.split(r"[\s+]+", str(row["artifact"])):
            token = word.strip(TRIM)
            if token.startswith(ELISION):
                symbol, target = token.lstrip("…. "), last
                if target is None:
                    findings.append(f"{where}: `{token}` elides a file no earlier token named")
                    continue
                if not symbol:
                    findings.append(
                        f"{where}: `{token}` elides nothing — the symbol is empty,"
                        " so the resolver never went looking for one"
                    )
                    continue
                declared, harnesses = declarations(target)
                fresh = [
                    name for name in declared
                    if name.endswith(symbol) and name not in named
                ]
                if len(fresh) != 1:
                    findings.append(
                        f"{where}: `{token}` ends {len(fresh)} declaration(s) of"
                        f" {target.name} this row has not already named — `…site`"
                        " resolved against the token BEFORE it, which is the second"
                        " reference discharged by the first"
                    )
                    continue
                symbol = fresh[0]
            else:
                name, _, symbol = token.partition("::")
                if not FILE_SHAPED.search(name):
                    continue  # prose beside a reference; two rows trail off into it
                if pathlib.PurePosixPath(name).suffix not in REFERENCE_SUFFIXES:
                    findings.append(
                        f"{where}: `{name}` carries an extension this resolver does"
                        " not read, so nothing looked at it — an unresolvable"
                        " reference that says nothing is the hole with more code"
                    )
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
                kinds.add(target.suffix)
                if target.suffix != ".rs":
                    text = target.read_text(encoding="utf-8", errors="replace")
                    if symbol and symbol not in text:
                        findings.append(f"{where}: {name} does not name `{symbol}`")
                    continue
                if not symbol:
                    findings.append(
                        f"{where}: `{name}` names a Rust file and no `::harness` —"
                        " the file is not the proof, and it outlives any one of them"
                    )
                    continue
                declared, harnesses = declarations(target)
                if symbol not in declared:
                    findings.append(
                        f"{where}: {target.relative_to(root)} declares no `{symbol}` —"
                        " the harness this row rests on is gone or renamed, and a file"
                        " that MENTIONS the name is not the file that has it"
                    )
                    continue
            named.append(symbol)
            proofs += symbol in harnesses
        if not resolved:
            findings.append(
                f"{where}: `artifact` resolves nothing in the tree — a method with"
                " no artifact is the obligation restated, not discharged"
            )
            continue
        wanted = METHOD_KIND.get(method, ())
        if wanted and not kinds.intersection(wanted):
            findings.append(
                f"{where}: a {method!r} row resolving {sorted(kinds)} and no"
                f" {'/'.join(wanted)} — a file in the tree is not the artifact this"
                " method's own word says discharged the obligation"
            )
        if method == "bounded proof" and not proofs:
            findings.append(
                f"{where}: a bounded proof naming no `#[kani::proof]` — `::STEPS`"
                " is a const and `::StepRng` a struct, and each discharged this"
                " obligation at exit 0"
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
                stem = field[:-1] if field.endswith("*") else None
                if not (any(k.startswith(stem) for k in row) if stem else field in row):
                    findings.append(f"{where}: no `{field}` — the contract names it")

    registry = tomllib.loads((root / REGISTRY).read_text(encoding="utf-8"))
    known = {entry["id"] for entry in registry.get("property", [])}
    subject = doc.get("property", {}).get("id")
    if subject not in known:
        findings.append(f"{BUNDLE}: property `{subject}` is in no row of {REGISTRY}")

    method_answers(doc, findings)
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

    rows = [row for row in doc.get("mutation", []) if isinstance(row, dict)]
    named = [str(row.get("mutant", "")) for row in rows]
    inverse = 0
    for index, row in enumerate(doc.get("mutation", []), 1):
        where = f"{BUNDLE} mutation #{index} ({row.get('mutant', '?')})"
        if row.get("direction") not in DIRECTIONS:
            findings.append(
                f"{where}: direction {row.get('direction')!r} is not one of {DIRECTIONS}"
                " — a red run is not evidence until the direction is read"
            )
        elif row.get("direction") == "inverse":
            inverse += 1
            disposition = row.get("disposition")
            if disposition not in DISPOSITIONS:
                findings.append(
                    f"{where}: an INVERSE kill is a finding about the mutant, not a"
                    f" result about the property — `disposition` {disposition!r} is"
                    f" not one of {DISPOSITIONS}"
                )
            elif disposition == "superseded":
                # Its own name would satisfy a plain membership test, and a row
                # superseded by itself is the claim with nothing behind it again.
                others = set(named) - {str(row.get("mutant", ""))}
                if str(row.get("superseded_by", "")) not in others:
                    findings.append(
                        f"{where}: `superseded_by` {row.get('superseded_by')!r} names"
                        " no OTHER row of this group — the corrected mutant is what"
                        " makes this one a step rather than a result"
                    )
            if not str(row.get("reading", "")).strip():
                findings.append(
                    f"{where}: an inverse kill with no `reading` — the direction is"
                    " the whole content, and nothing else in the row states it"
                )

    summary = (
        f"bundle-gate: ok — {BUNDLE.name} carries {len(GROUPS)} groups and {total}"
        f" leaves, {len(doc.get('artifact', []))} raw artifact(s),"
        f" {len(doc.get('mutation', [])) - inverse} mutation verdict(s)"
        f" and {inverse} disposed as inverse"
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
