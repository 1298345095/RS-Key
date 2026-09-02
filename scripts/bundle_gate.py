#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""Hold every closed slice's raw evidence bundle to stage 1A's ten-group contract.

EVERY bundle: the roster is `assurance/bundle/*.toml`, read off the directory on
each run and floored, so a file dropped in is audited and a file taken out is a
finding. It was one hard-coded path until the calibration counterpart of §10
needed a second one, and a hard-coded path is the shape where the second bundle
arrives green because nothing looks at it.

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

Six rules are about the bundle being EVIDENCE rather than prose:

* every `[[method]]` carries its bounds as STRUCTURED data — `bound_*` keys, at
  a floor per row and over the group — and every STRING LEAF of the bundle
  answers something. Stripping all 30 `bound_*` keys from all 8 rows left the
  exit at 0, and so did reducing all 8 to a single `bound_nothing = 0`; a scope
  sentence was demanded and the bounds it is about were not. The non-answer rule
  scoped to two prose fields reached 18 of 348 string leaves — `mutation.fell`
  and `build.commit` among the 266 that took `"n/a"` at exit 0;
* every `[[method]]`'s `artifact` resolves against the tree, as something the
  row's own `method` word calls for. The field is the row's whole claim — this
  obligation, discharged by that proof — and nothing read it: renaming
  `no_authorization_bypass_walk_owner` left the exit at 0, and so did pointing
  the row at `CHANGELOG.md` or at a const;
* every number a `[result]` gate line TRANSCRIBES is that gate's own. The
  `kani=4` half of the line above was the other symptom of the same hole and
  outlived the fix: `kani=99` was exit 0 here, in `evidence-gate` and in
  `assurance-gate`. Held against the emitting gate's own derivation, which found
  a count that was wrong the day it was typed;
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

A seventh is about the numbers themselves, and only the numbers a LOG can
settle: a count printed next to an artifact is a transcription of that artifact,
so it must be an integer the artifact prints. 198 of the tree's 492
measurement-shaped numbers reach a log that way — 195 through the configuration
they name, 3 through the log itself — and the floor is what keeps that from
quietly becoming none. `assurance/configurations.toml` already forbids the one
drift it was written for by hand ("the pair 446/172 is NOT a superseded version
of this one and must not be reconciled with it") and nothing read that sentence:
446 and 172 are integers of `cargo-test-always-uv.log`, 493 and 176 are not, and
rewriting one pair into the other was exit 0.

Deliberately not here: whether the OTHER numbers are right. Nothing can check
that a recorded wall-clock is the one the run took, that a row calling itself
`modelled` was read that way, or that a number naming no artifact came off
anything. What this row keeps honest is that no field of the contract was
quietly dropped, that every claim it makes about the tree resolves in the tree,
and that no cost was written as a range.
"""

import ast
import functools
import gzip
import hashlib
import pathlib
import re
import sys
import tomllib

import assumption_gate
import assurance_gate
import gate_lines
import ghost_gate
#: For `HARNESS` alone — the token that says a Rust `fn` is a Kani proof. A
#: second copy here is the defect one directory over, and so is every derivation
#: the five imports around it stand in for.
import kani_gate
import matrix_gate
import token_refinement_gate

ROOT = pathlib.Path(__file__).resolve().parent.parent

#: Where the bundles live. The ROSTER IS THE DIRECTORY and is not written down:
#: a second bundle named here would be a second bundle to remember to name, and
#: this tree has measured that failure four times over (`MODEL_ACTIONS`, the four
#: registries with no allowlist, `comutate.PREFIXES`, the `check.sh` row filter).
#: A file dropped in is held to the contract on the next run; a file taken out is
#: the roster floor below.
BUNDLE_DIR = pathlib.Path("assurance/bundle")

#: The bundle `test_bundle_gate.py` mutates. Still named, because a mutation
#: table over "whichever file the glob returned first" is a table over nothing —
#: but it is no longer WHAT IS AUDITED, which is every row of [`bundles`].
BUNDLE = BUNDLE_DIR / "SEC-FIDO-001.toml"

#: Bundles the tree must carry. Under the measured count like every ratchet here,
#: and a PARAMETER of [`audit`] rather than a global a case can monkeypatch down:
#: the shipped value is then the one every case runs against. `SCAN_FLOOR` in
#: `run_count_gate.py` shipped the other way and its own commit message said so —
#: "the case patches the floor down to 4, so the shipped 8 was never checked
#: against the shipped tree".
#:
#: It is a floor and not an equality because a bundle ARRIVING is the programme
#: working; a bundle LEAVING is a closed slice unclosing itself with the row
#: green, which is the family "the table was DELETED rather than EMPTIED" one
#: layer out.
#:
#: Moved 2 -> 8 the day the six remaining P0 bundles landed, and 8 -> 11 the day
#: `SEC-FIDO-006` was split into `SEC-FIDO-006A/B/C` and the three clause bundles
#: landed together. The value is the measured roster and not a margin under it: a
#: floor below the count is a bundle that can leave with the row green, which is
#: the direction above.
ROSTER_FLOOR = 11

#: The evidence store. Held BOTH ways, like [`BUNDLE_DIR`] one layer in: the
#: `[[artifact]]` rule below reads a bundle's path and asks whether the tree has
#: the file, and [`orphan_evidence`] walks the directory and asks whether any
#: bundle has the path. Only the first direction existed, so a log that stopped
#: being evidence stopped being read and nothing said so.
STORE = BUNDLE_DIR / "logs"

#: Files the store must carry, and the second of the two floor conventions in
#: this file. AT the measurement, [`ROSTER_FLOOR`]'s convention and not
#: [`VERDICT_FLOOR`]'s: a floor UNDER the count is for a population that is
#: incidental — how many bounds a method row happens to spell, how many numbers a
#: leaf happens to quote — where the floor only has to refuse degeneracy. Every
#: file here is a COMMITMENT instead: it carries a digest, a byte count and a
#: `[[cost]]` row, and one leaving is evidence leaving. A floor below the count
#: is exactly a log that can go with the row green.
#:
#: It is what makes the rule above non-degenerate rather than decoration. Delete
#: a log AND the `[[artifact]]` and `[[cost]]` rows that cite it and no clause in
#: this file objects: the orphan set is empty because the file is gone, the
#: forward rule is silent because the row is gone, and the `artifact`/`cost` leaf
#: floors are nowhere near — the group carries 40 leaves against a floor of 8.
#: Measured that way and not argued — deleting this clause alone leaves that
#: construction reporting NOTHING, which is
#: `test_evidence_can_leave_with_every_other_clause_green`.
#:
#: 100 the day it was written: ten directories of 5 to 13 logs each, plus the ten
#: at the root that are `SEC-FIDO-001`'s — the one bundle with no directory of its
#: own, which is why this walks the store rather than the ten names. Like
#: `ROSTER_FLOOR` it moves UP when a slice lands, and a diff someone has to write
#: is the point.
STORE_FLOOR = 100

REGISTRY = pathlib.Path("assurance/properties.toml")
#: Where a bare `Name.cfg` lives. The bundle names TLC configurations without a
#: directory throughout — four of the eight method rows do — and `formal/` is the
#: only place either extension is written.
FORMAL = pathlib.Path("formal")

#: Where a script that RAN something lives. Beside [`FORMAL`] because it is the
#: same shape of claim — the DIRECTORY carries it. A `KAT/differential` row's
#: `.py` half is the script that drove published vectors at a device or the
#: emulator, and `tests/` is where this tree keeps exactly those; `scripts/` is
#: gates and `tools/` is a CLI, and both resolved a KAT row at exit 0 before this.
RUNNERS = pathlib.Path("tests")

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
    # 18 and not 30: the group carries 22 keys, and 30 was written before it
    # existed and was never a measurement. Under the measurement like every
    # ratchet here — it has never been green at 30, so this lowers nothing.
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

#: Bounds per method row, and over the group. Both under the measurement — 30
#: keys across 8 rows, the smallest row carrying 2 — the way every other ratchet
#: here is. Two numbers, because 8 rows at the per-row floor is 16 against the 30
#: the bundle has, and a 47% strip with the row green is the same hole again.
BOUND_FLOOR, BOUNDS_FLOOR = 2, 24

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

#: The `#[test]` attribute, in the shape `kani_gate.HARNESS` has for its own. No
#: gate owns this token, so it is defined here rather than imported; and it is
#: not widened past the literal because the tree spells a unit test one way and
#: only one — 2349 sites over `crates/`, `firmware/` and `tools/`, and zero in
#: any other spelling — and a pattern covering spellings nothing here uses is a
#: rule nothing here can falsify.
UNIT_TEST = re.compile(r"#\[test\]")

#: [`UNIT_TEST`]'s counterpart one language over. Python has no attribute, and
#: the NAME is what its runner keys on instead, so the name is what the `.py` arm
#: holds: `python_functions`'s installed default, a PREFIX, read off pytest's own
#: `pytest_addoption` rather than invented. The tree overrides it nowhere — no
#: `pytest.ini`, no `setup.cfg`, no `[tool.pytest…]`, `third_party/` included.
#:
#: Two stronger shapes were refused by measurement, not by taste.
#: **`python_files` as well**, so the file must be a `test_*.py` too: 57 of
#: `third_party/openpgp-card-tests`' 62 collected modules are
#: `from card_test_… import *` and hold no test of their own, so the methods
#: `tests/third_party.py` really runs live in 26 `card_test_*.py` the pattern
#: rejects — a differential suite is the likeliest `.py` KAT artifact this tree
#: will ever have, and 26 honest refusals buys the refusal of two names
#: (`narrow_gate.py::test_functions`, `token_refinement_gate.py::
#: test_only_sources`). **pytest's ROOTS, derived from `check.sh`**: the rows
#: hand it three (`scripts`, `tools/rsk`, `tests/interop`) while
#: `tests/third_party.py` calls `pytest.main` over two more trees carrying 90
#: collected `test_*.py` between them, every one of which the rule would call
#: un-run. What the prefix alone still cannot see is a `def test_*` that runs no
#: vector; the `.rs` arm cannot see that either, since `#[test]` says a function
#: is a test and not what it checks.
PYTEST_FUNCTION = "test"

#: §4.1's method vocabulary, in `docs/authorization-slice.md` п.3's order — held
#: to that page by [`vocabulary_problems`], because until it was, "in п.3's order"
#: was a sentence and not a rule: both rosters were extended BY HAND when
#: `KAT/differential` arrived, and nothing anywhere compared them. A word
#: outside it is a finding and not a shrug: [`METHOD_KIND`] reads this field, so
#: `method = "bounded proofs"` would quietly drop the rule that field carries.
#:
#: `KAT/differential` is the tenth, and it cannot be spelled with any of the
#: nine. `measurement` is one of three spellings of "this evidence came off a
#: board" (`evidence_gate.MEASUREMENT_METHOD`, read by `hardware_claims`), so a
#: KAT row wearing it owes a `build.board_revision` naming a real RP2350
#: stepping — a false hardware claim on a tree whose hardware axis is honestly 0
#: of 59. A word is added here only WITH the rules it carries: on its own it
#: widens the vocabulary and takes the kind rule off the row, which is the pair
#: `test_the_kat_word_and_its_kind_are_one_change_or_neither` drives.
METHODS = (
    "review", "model-check", "bounded proof", "deductive proof",
    "exhaustive sweep", "mutation", "trace", "measurement", "accepted risk",
    "KAT/differential",
)

#: The page [`METHODS`] says it is a copy of, and the list item that publishes the
#: vocabulary. Anchored on the item's own heading and on the `§4.1 (…)`
#: parenthesis — NEVER on a line number: `citation_gate` reads `.rs`, `.sh` and
#: `.txt` only, so a line number written here would be held by nothing and rot in
#: silence, which is how five bare citations already rotted while that row printed
#: `ok`. (A colon and digits in this comment is itself one of that row's findings,
#: which is the shortest possible demonstration of the rule.)
#:
#: `bounds_gate.SLICE` is the same path for the same page's `## The bounds`
#: section, and that file already imports this one — one of the two should go.
SLICE = pathlib.Path("docs/authorization-slice.md")
SLICE_ITEM = "3. **Method and scope/bounds**"
SLICE_VOCABULARY = re.compile(r"the method per §4\.1 \(([^)]*)\)", re.S)

#: The separator between two words of that list: whitespace on BOTH sides, which
#: is what lets the page spell `KAT/differential` with a slash of its own. The
#: page wraps mid-list, so the halves are re-joined before they are compared.
SLICE_SEPARATOR = re.compile(r"\s+/\s+")

#: The three methods whose own word NAMES the kind of artifact discharging them.
#: Without it a row is satisfied by any file in the tree: re-pointing the walk
#: row's artifact at `CHANGELOG.md`, at `README.md` and at this bundle were all
#: exit 0, as were `state_kani.rs::STEPS` (a const) and `::StepRng` (a struct).
#: The other seven §4.1 methods name no kind — this bundle discharges an
#: `exhaustive sweep` with a `.py` over a `.tla` and with two `.cfg` — and
#: inventing one for them would be requiring the wrong one, which is why
#: `bound_*` is a prefix one field over.
#:
#: `KAT/differential` takes TWO suffixes because both are how this tree runs
#: vectors: a `#[test]` over an ACVP table in a crate, and a `tests/*.py` driving
#: a device or the emulator against a reference. Naming only `.rs` would refuse
#: the second half of the method's own word — and naming both without the RUNNER
#: rule below made the `.py` half a rule that cannot fail: this gate's own file,
#: `tools/rsk/__init__.py` and a bare `tests/*.py` were each exit 0, while the
#: mixed row that names the vectors AND the script was refused. The gradient ran
#: backwards, which is worse than the hole.
METHOD_KIND = {
    "model-check": (".cfg",),
    "bounded proof": (".rs",),
    "KAT/differential": (".rs", ".py"),
}

#: The method row's two PROSE fields — what the obligation is, and how the bound
#: relates to the shipped domain. A required field is satisfied by any string, so
#: `shipped_relation = "n/a"` cleared the rule that exists to demand the sentence.
PROSE_FIELDS = ("obligation", "shipped_relation")

#: Words that occupy a field without answering it, over EVERY string leaf.
#: Scoping this to [`PROSE_FIELDS`] reached 18 of the bundle's 348 string leaves,
#: and the sweep that set each of them to `"n/a"` in turn found 266 still at exit
#: 0 — `mutation.fell`, `mutation.verdict`, `mutation.expected`, `build.commit`,
#: `tool.version`, `property.statement`, `cost.basis` and `freshness.measured`
#: among them, while this file's own docstring says every `[[mutation]]` records
#: the assertion that FELL. Compared through [`core`], so punctuation buys no
#: second spelling. Still a blacklist, and still incomplete — `n/a (none)`
#: normalizes to `nanone` and passes; what carries the weight is the leaf.
NON_ANSWERS = frozenset(
    {
        "na", "notapplicable", "noanswer", "seeabove", "ditto",
        "none", "nil", "null", "nothing",
        "unknown", "unspecified", "undefined", "unclear",
        "tbd", "tba", "tobedetermined", "todo", "xxx", "pending", "wip",
    }
)

#: The two leaves where `none` IS an answer, and the reason the widening above is
#: per leaf and not per field: five method rows answer `cfg` with `none` and four
#: answer `features`, and both mean the build had none of it. The VALUE is named
#: too, because exempting the fields outright takes `cfg = "n/a"` back.
NONE_IS_AN_ANSWER = ("method.cfg", "method.features")

#: A row index inside a leaf path, so the exemption above is written once rather
#: than once per row.
ROW_INDEX = re.compile(r"\[\d+\]")

#: The `[result]` keys that transcribe another gate's derived output. A number
#: typed here is a copy of one some other program counts, and nothing compared
#: them: editing `gate_registry`'s `kani=4` to `kani=99` left this row, the
#: evidence vector and the assurance registry all at exit 0 — `35afe59` named
#: that line as the second half of the hole it closed and left it standing.
#: `run_count_gate.py` owns this class for the published pages and says in as
#: many words that it does not reach `assurance/`, "which is itself a record of
#: measurements and has `bundle_gate.py`", so it is this file's.
GATE_RESULTS = ("gate_ghost", "gate_ledger", "gate_assumption", "gate_matrix", "gate_registry")

#: `name=<number>`, the shape those lines carry their counts in.
CLAIMED_PAIR = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)=(\d+)\b")

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

#: The two keys that register belongs to. On a `modelled` row both were accepted
#: and neither was validated — the register filled in for a row it is not about,
#: which is a claim wearing a field's name. `reading` is NOT one of them: it
#: argues whichever direction the row records, and all ten `modelled` rows of
#: this bundle carry one. Measured, on a first version that refused them.
INVERSE_FIELDS = ("disposition", "superseded_by")

#: Mutation rows that are a RESULT about the property rather than a finding about
#: the mutant. Ten rows all `inverse` in a ten-cycle printed "0 mutation
#: verdict(s) and 10 disposed as inverse" at exit 0: a table that killed nothing,
#: read as one that killed ten. Under the measured 10, like every ratchet here.
VERDICT_FLOOR = 8

#: How a bundle writes a big number: `106 956 959`, where the log wrote
#: `106956959` and `45,810`. Both sides are reduced to their digits before they
#: are compared, so the grouping is a spelling and not a difference.
GROUPED = r"[\d\s,]"

#: A digit run that starts a TOKEN. A line-range citation followed by the word
#: `states` — as one `result` leaf of SEC-FIDO-006B is written — is a range and a
#: verb, not a count; without this it was the one false finding the tree produced.
STARTS = r"(?<![-:.\w])"

#: What TLC prints in its own summary, in the spelling the bundles quote it in.
#: The join for these is the CONFIGURATION name, so the vocabulary is TLC's and
#: nothing else's: letting `passed`/`failed` through here attributed
#: `cargo-test-always-uv.log`'s 446 to `tlc-AlwaysUv.log`, measured.
QUOTED_SEARCH = {
    "states": re.compile(rf"{STARTS}(\d{GROUPED}*?)\s*states\b"),
    "distinct": re.compile(rf"{STARTS}(\d{GROUPED}*?)\s*distinct\b"),
    "depth": re.compile(rf"\bdepth\s+{STARTS}(\d[\d ]*)"),
}

#: And what a test runner prints. Only reachable where the leaf names the LOG,
#: because that is the only join that says which runner the number came out of.
QUOTED_RESULT = {
    "passed": re.compile(rf"{STARTS}(\d{GROUPED}*?)\s*(?:passed|passing)\b"),
    "failed": re.compile(rf"{STARTS}(\d{GROUPED}*?)\s*(?:failed|FAILED|failures?)\b"),
}

#: An integer as a log prints one. Leading zeros are dropped on both sides so
#: `08` and `8` are one number.
INTEGER = re.compile(r"\d+")

#: `Name.cfg`, the way a bundle names a configuration mid-sentence.
CONFIGURATION = re.compile(r"\b([A-Za-z][A-Za-z0-9_]*)\.cfg\b")

#: A log, by path or by bare filename.
LOG_NAME = re.compile(r"[A-Za-z0-9_.\-/]*\.log(?:\.gz)?")

#: What [`quoted_numbers`] must reach. THE POINT OF THE RULE, not decoration:
#: `check_evidence`'s only shape rule keyed on a `board_revision` no row carried,
#: so it guarded zero rows while reading as if it guarded the hardware axis. The
#: measured tree is 198 numbers over 63 joins; AT the measurement like every
#: ratchet here, so a join that stops forming is a finding rather than a quieter
#: summary line.
QUOTE_FLOOR, QUOTE_JOIN_FLOOR = 198, 63

#: The two rosters above must name the same ten groups. One in `GROUPS` and not
#: in `FLOORS` is a `KeyError`; one in `FLOORS` and not in `GROUPS` is silently
#: dead, which is the direction nothing would have shown.
assert set(GROUPS) == set(FLOORS) == set(REQUIRED), "GROUPS, FLOORS and REQUIRED drifted"


def walk(value, path=""):
    """Every leaf under `value`, as (path, leaf).

    An EMPTY dict or list yields `(path, None)`: a heading with nothing under it
    is a hole, not a leaf. TOML has no null, so `None` cannot be a real value.
    """
    if isinstance(value, dict):
        if not value:
            yield path or "<root>", None
        for key, item in value.items():
            yield from walk(item, f"{path}.{key}" if path else key)
    elif isinstance(value, list):
        if not value:
            yield path, None
        for index, item in enumerate(value):
            yield from walk(item, f"{path}[{index + 1}]")
    else:
        yield path, value


def leaves(value, path="") -> tuple[int, list[str]]:
    """(leaf count, the paths that are empty) under `value`."""
    total, empty = 0, []
    for where, leaf in walk(value, path):
        if leaf is None:
            empty.append(where)
            continue
        total += 1
        if isinstance(leaf, str) and not leaf.strip():
            empty.append(where)
    return total, empty


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


def declarations(target: pathlib.Path) -> tuple[list[str], set[str], set[str]]:
    """(every Rust item `target` declares, those carrying `#[kani::proof]`, and
    those carrying `#[test]`).

    Rust is read as code — anything else has no item grammar this could parse and
    the claim there is only that the name occurs, which [`method_references`]
    handles in place.

    The harness half is `kani_gate.HARNESS`'s token and not a second copy of it.
    A bounded proof is discharged by a HARNESS, and `DECLARED` matches a const, a
    struct and anything inside a `#[cfg(test)]` block just as happily: `::STEPS`
    and `::StepRng` each discharged the walk row at exit 0.

    The test half is the same walk one attribute over, against the same hole: a
    `KAT/differential` row is discharged by the function that RAN the vectors,
    and `crates/rsk-mldsa/src/testvectors.rs::KeyGenKat` is the struct they sit
    in. A table of inputs is the input, not the check.
    """
    code = gate_lines.rust_code(target.read_text(encoding="utf-8", errors="replace"))
    lines = code.splitlines()
    names, proofs, tests = [], set(), set()
    for match in DECLARED.finditer(code):
        name = match.group(1)
        names.append(name)
        above = code.count("\n", 0, match.start()) - 1
        while above >= 0 and (not lines[above].strip() or ATTRIBUTE.match(lines[above])):
            if kani_gate.HARNESS.search(lines[above]):
                proofs.add(name)
            if UNIT_TEST.search(lines[above]):
                tests.add(name)
            above -= 1
    return names, proofs, tests


def definitions(target: pathlib.Path) -> set[str]:
    """Every `def` `target` declares, at any depth.

    The `.py` counterpart of [`declarations`], and PARSED rather than matched,
    because the Rust half already paid for that difference: what a file MENTIONS
    is not what it defines, and `# def ran_the_vectors` in a comment clears any
    pattern. A file that does not parse declares nothing, which reddens the row
    resting on it — the direction that refuses rather than the one that admits.
    """
    try:
        parsed = ast.parse(target.read_text(encoding="utf-8", errors="replace"))
    except SyntaxError:
        return set()
    return {
        node.name for node in ast.walk(parsed)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }


def core(value: str) -> str:
    """`value` as one word: case folded, with every non-alphanumeric removed.

    `n/a`, `N / A`, `n.a.`, `N/A;`, `(none)`, `not-applicable` and `todo:` are
    one non-answer in seven spellings. The first version removed whitespace and
    stripped a trailing `.!?…`, so five of the seven were exit 0 — a vocabulary
    that has to enumerate punctuation is bypassed by the next mark typed.
    """
    return re.sub(r"[^0-9a-z]", "", value.lower())


def answers(value) -> bool:
    """Whether a leaf says anything at all.

    A bare `0` or `x` still passes. Refusing a one-character word was the obvious
    close and is wrong: `mutation.level` is `A`, `B` and `C`, six real answers
    one character long, and the rule reddened every one of them.
    """
    if not isinstance(value, str):
        return False
    word = core(value)
    return bool(word) and word not in NON_ANSWERS


def leaf_answers(bundle: pathlib.Path, doc: dict, findings: list[str]) -> None:
    """Every string leaf of the bundle says something, not just the two prose ones."""
    for path, value in walk(doc):
        if not isinstance(value, str) or not value.strip():
            continue  # a blank leaf is the `leaves` rule's, reported once
        if ROW_INDEX.sub("", path) in NONE_IS_AN_ANSWER and core(value) == "none":
            continue
        if not answers(value):
            findings.append(
                f"{bundle}: `{path}` is {value!r}, which answers nothing — a field"
                " occupied by a non-answer is the same field dropped, in a spelling"
                " the REQUIRED roster cannot see"
            )


def method_answers(bundle: pathlib.Path, doc: dict, findings: list[str]) -> None:
    """A method row's two prose fields are PROSE.

    Their string values are [`leaf_answers`]'s, like every other leaf's. What is
    left here is the other half: a number in `obligation` is not a non-answer in
    any vocabulary, and it is not a sentence either.
    """
    for index, row in enumerate(doc.get("method", []), 1):
        if not isinstance(row, dict):
            continue
        for field in PROSE_FIELDS:
            if field in row and not isinstance(row[field], str):
                findings.append(
                    f"{bundle} method #{index}: `{field}` is {row[field]!r}, which"
                    " answers nothing — a required field occupied by a non-answer is"
                    " the same field dropped, in a spelling the roster cannot see"
                )


def method_bounds(bundle: pathlib.Path, doc: dict, findings: list[str]) -> None:
    """A method row's bounds are BOUNDS, and there are enough of them.

    `REQUIRED`'s `bound_*` is satisfied by one key: reducing all 8 rows to a
    single `bound_nothing = 0` was exit 0, and so were `bound_x = false`,
    `bound_x = ["n/a"]` and a key named literally `bound_`. The measured hole was
    zero bounds and the ratchet it left was one.
    """
    total = 0
    for index, row in enumerate(doc.get("method", []), 1):
        if not isinstance(row, dict):
            continue
        where = f"{bundle} method #{index}"
        bounds = [key for key in row if key.startswith("bound_") and key != "bound_"]
        total += len(bounds)
        if "bound_" in row:
            findings.append(
                f"{where}: `bound_` is the prefix and not a name — a key that IS the"
                " wildcard answers the roster and bounds nothing"
            )
        for key in bounds:
            if isinstance(row[key], bool):
                findings.append(
                    f"{where}: `{key}` is {row[key]!r} — a bound is a number, or the"
                    " sentence saying why it is not one, and never a flag"
                )
        if len(bounds) < BOUND_FLOOR:
            findings.append(
                f"{where}: {len(bounds)} bound(s), under the floor of {BOUND_FLOOR}"
            )
    if total < BOUNDS_FLOOR:
        findings.append(
            f"{bundle}: {total} `bound_*` key(s) over the method rows, under the"
            f" floor of {BOUNDS_FLOOR} — a scope sentence beside one bound is the"
            " same row the roster was added to refuse"
        )


def slice_methods(text: str) -> tuple[str, ...] | None:
    """§4.1's vocabulary as the SLICE PAGE words it, or None if it has stopped
    wording it.

    None rather than an empty tuple, because the two are different findings: a
    page that no longer publishes the list is a page that stopped being the
    source, and an equality against `()` would report it as ten missing words.
    """
    body = text.partition(SLICE_ITEM)[2]
    found = SLICE_VOCABULARY.search(body) if body else None
    if found is None:
        return None
    return tuple(
        " ".join(word.split()) for word in SLICE_SEPARATOR.split(found.group(1))
    )


def vocabulary_problems(text: str | None, methods=METHODS) -> list[str]:
    """[`METHODS`] against the page it says it is a copy of, in order.

    Two registers extended by hand on the same day and compared by nothing: the
    tenth word went into `METHODS`, `METHOD_KIND` and п.3 in one commit and would
    have gone into one of them just as quietly. `methods` is a PARAMETER so both
    directions are drivable without patching the roster the shipped run is judged
    by — the same shape as `bounds_gate`'s floors.

    ORDER as well as membership, because `METHODS` claims п.3's order in as many
    words, and a set equality would leave that half of the sentence a promise.
    """
    if text is None:
        return [
            f"{SLICE} is missing — §4.1's method vocabulary is published there and"
            " this roster says it is a copy of it"
        ]
    published = slice_methods(text)
    if published is None:
        return [
            f"{SLICE} no longer carries `{SLICE_ITEM}` with a `the method per §4.1"
            " (…)` list — the roster this gate reads has stopped having a source,"
            " and a copy of nothing agrees with everything"
        ]
    if published != tuple(methods):
        return [
            f"{SLICE} п.3 publishes {list(published)} and this gate reads"
            f" {list(methods)} — one was extended by hand and the other was not."
            " The page is what a reader is held to; make them the same list, in"
            " the same order"
        ]
    return []


def method_references(root: pathlib.Path, bundle: pathlib.Path, doc: dict, findings: list[str]) -> None:
    """Every `[[method]]`'s `artifact` names something this tree still has, OF THE
    KIND its own `method` word calls for.

    A `.rs` file must carry its `::symbol`, and for a bounded proof that symbol
    must be a harness. Naming the file alone is how this rule would be walked
    past — a bounded proof is identified by its harness, and the file outlives
    any one of them — and naming any DECLARATION is how it was: six of the eight
    rows carry no `::` at all, so the rule degenerated to "a file of that name
    exists" for all six.

    `KAT/differential` owes a RUNNER on whichever half it names — a `#[test]` in
    Rust, a `.py` under [`RUNNERS`] or one naming a `def` whose name pytest
    collects on ([`PYTEST_FUNCTION`]). Written for the `.rs` half alone it left
    the `.py` half with no requirement past the file existing, and it then ran
    backwards: `scripts/bundle_gate.py` discharged a KAT obligation at exit 0
    while the vectors PLUS a script was refused. One counter over both halves is
    what makes adding the vectors to a green row unable to redden it.

    The `.py` half then owed the second half of the same debt. `symbol in
    definitions(target)` took ANY `def`, so `scripts/bundle_gate.py::
    method_references` — this function — was green where the `.rs` arm refuses
    `testvectors.rs::KeyGenKat` for being a declaration and not a check.
    `scripts/rsa_vectors.py` is this tree's own instance of that shape: a KAT
    GENERATOR whose check is the Rust that reproduces what it wrote.

    What stays asymmetric, deliberately: a `.py` under `tests/` needs no symbol
    where a `.rs` always does. The unit differs, and it differs because the
    runner does — `scripts/emu-suites.sh` loops `tests/[0-9]*.py` and runs each
    FILE through `tests/emu.py`, while a `.rs` file holds many `#[test]`s and
    outlives any one of them. Requiring `::main` there would require the one
    symbol all 65 of them have, which names nothing.
    """
    for index, row in enumerate(doc.get("method", []), 1):
        if not isinstance(row, dict) or "artifact" not in row:
            continue  # a dropped field is the REQUIRED rule's, reported once
        where = f"{bundle} method #{index}"
        method = str(row.get("method", ""))
        if "method" in row and method not in METHODS:
            findings.append(
                f"{where}: method {method!r} is in no row of §4.1's vocabulary"
                f" {METHODS} — the kind rule reads this field, so a word outside"
                " it drops the rule the field carries"
            )
        resolved, last, named, proofs, runners, kinds = 0, None, [], 0, 0, set()
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
                declared, harnesses, unit_tests = declarations(target)
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
                    elif target.suffix == ".py" and (
                        RUNNERS in target.relative_to(root).parents
                        or (
                            symbol.startswith(PYTEST_FUNCTION)
                            and symbol in definitions(target)
                        )
                    ):
                        runners += 1
                    continue
                if not symbol:
                    findings.append(
                        f"{where}: `{name}` names a Rust file and no `::harness` —"
                        " the file is not the proof, and it outlives any one of them"
                    )
                    continue
                declared, harnesses, unit_tests = declarations(target)
                if symbol not in declared:
                    findings.append(
                        f"{where}: {target.relative_to(root)} declares no `{symbol}` —"
                        " the harness this row rests on is gone or renamed, and a file"
                        " that MENTIONS the name is not the file that has it"
                    )
                    continue
            named.append(symbol)
            proofs += symbol in harnesses
            runners += symbol in unit_tests
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
        # Conditioned on the row having reached an artifact of its own kind, so
        # the two rules do not say the same thing twice about one row — and so
        # that deleting the `METHOD_KIND` entry takes this rule off with it,
        # which is what makes the word a widening when it arrives alone.
        if method == "KAT/differential" and kinds.intersection(wanted) and not runners:
            findings.append(
                f"{where}: a KAT/differential row naming nothing that RAN the"
                " vectors — no `#[test]`, and no `.py` under `tests/` or naming a"
                f" `def` of its own whose name starts with {PYTEST_FUNCTION!r}."
                " `testvectors.rs::KeyGenKat` is the struct the table sits in and"
                " `scripts/bundle_gate.py::method_references` is a gate function:"
                " a table of inputs is the input, not the check, and so is a `def`"
                " nothing runs"
            )


@functools.cache
def gate_corpus() -> dict[str, str]:
    """What each gate of [`GATE_RESULTS`] derives, as text, from the gate itself.

    Over `ROOT` and not over `audit`'s `root`: the test fixture carries a bundle
    and not a checkout, and what these lines transcribe is a gate reading THIS
    tree. Cached, because the five derivations cost 2.7 s and the mutation table
    calls `audit` two hundred times in one process.
    """
    _, booleans, entries = assumption_gate.audit()
    arms = " ".join(
        f"{name} TRUE={sum(1 for arm in cfgs.values() if arm == 'TRUE')}"
        f" FALSE={sum(1 for arm in cfgs.values() if arm == 'FALSE')}"
        for name, cfgs in sorted(booleans.items())
    )
    return {
        "gate_ghost": ghost_gate.audit(ROOT)[1],
        "gate_ledger": token_refinement_gate.audit(ROOT)[1],
        "gate_assumption": f"{len(entries)} standing assumption(s) {arms}",
        "gate_matrix": matrix_gate.audit(ROOT)[1],
        # The per-property vector rows, which is where `cfgs=46 … kani=4` is
        # counted; `check_generated_readme` is a sibling row's rule, not this one's.
        "gate_registry": "\n".join(assurance_gate.audit(ROOT, False)[1]),
    }


def registry_line(corpus: str, subject: str) -> str:
    """The one `gate_registry` line about `subject`, not the whole roster.

    Found by a bundle going stale under this rule with the row GREEN. The corpus
    for `gate_registry` is every property's vector joined by newlines, so a pair
    like `rust=1` was compared against ALL of them — and `rust=1` is true of
    thirty other rows, so a bundle whose own property had moved to `rust=2`
    transcribed the old number and passed. The rule read "some property has this"
    where it meant "this property has this".
    """
    for line in corpus.splitlines():
        if subject and subject in line:
            return line
    return corpus


def gate_transcriptions(bundle: pathlib.Path, doc: dict, findings: list[str]) -> None:
    """Every number in a transcribed `[result]` gate line is that gate's own.

    A `name=<number>` pair is compared as a pair; everything else is compared as
    an integer, which is what holds `21 actions … over 24 routes` where the line
    carries no pairs at all. Neither reads the PROSE — `gate_matrix` ends in a
    sentence about the slice, and that sentence is the row's to write.
    """
    corpus = gate_corpus()
    result = doc.get("result", {})
    if not isinstance(result, dict):
        return  # `is not a table` is the roster rule's, reported once
    for key in GATE_RESULTS:
        if key not in result:
            findings.append(
                f"{bundle}: `result.{key}` is gone — this file derives that line"
                " from the gate that emits it, and a roster entry with nothing to"
                " check is the claim deleted rather than refuted"
            )
    for key in sorted(k for k in result if k.startswith("gate_")):
        if key not in corpus:
            findings.append(
                f"{bundle}: `result.{key}` transcribes a gate this file cannot"
                " derive — an unreadable claim that says nothing is the hole with"
                " more code"
            )
            continue
        claim, derived = str(result[key]), corpus[key]
        if key == "gate_registry":
            derived = registry_line(derived, str(doc.get("property", {}).get("id", "")))
        # Both rules below compare the numbers a line HAS, so a line with none
        # satisfies them: `gate_registry = "assurance-gate: all good"` clears the
        # roster, the leaf floor and the non-answer rule, and transcribes nothing.
        if not re.search(r"\d", claim):
            findings.append(
                f"{bundle}: `result.{key}` transcribes a gate and carries no number"
                " — the counts are what this line is, and a sentence in their place"
                " is the claim withdrawn rather than checked"
            )
        for name, value in CLAIMED_PAIR.findall(claim):
            if not re.search(rf"\b{re.escape(name)}={re.escape(value)}(?!\d)", derived):
                findings.append(
                    f"{bundle}: `result.{key}` says `{name}={value}` and the gate"
                    f" derives `{derived[:120]}…` — a transcribed count is a copy of"
                    " a number some other program counts"
                )
        for number in re.findall(r"\d+", CLAIMED_PAIR.sub("", claim)):
            if not re.search(rf"(?<!\d){re.escape(number)}(?!\d)", derived):
                findings.append(
                    f"{bundle}: `result.{key}` says {number} and the gate derives no"
                    f" such number — `{derived[:120]}…`"
                )


def corrected_by(rows: dict, start: str) -> str | None:
    """The row at the end of `start`'s `superseded_by` chain, or None on a cycle.

    A membership test alone was the whole rule and a CYCLE satisfies it: A
    superseded by B and B by A printed "8 mutation verdict(s) and 2 disposed as
    inverse" at exit 0, and so did a ten-row cycle over the entire group —
    neither mutant corrected, and every row of the register saying otherwise.
    """
    seen, name = set(), start
    while name in rows and rows[name].get("direction") == "inverse":
        if name in seen:
            return None
        seen.add(name)
        name = str(rows[name].get("superseded_by", ""))
    return name if name in rows else None


def mutation_dispositions(bundle: pathlib.Path, doc: dict, findings: list[str]) -> int:
    """Hold the `inverse` register, and return how many rows it disposed of."""
    rows = [row for row in doc.get("mutation", []) if isinstance(row, dict)]
    by_name = {str(row.get("mutant", "")): row for row in rows}
    named = [str(row.get("mutant", "")) for row in rows]
    readings, inverse = [], 0
    for index, row in enumerate(doc.get("mutation", []), 1):
        if not isinstance(row, dict):
            continue
        where = f"{bundle} mutation #{index} ({row.get('mutant', '?')})"
        direction = row.get("direction")
        readings.append(core(str(row.get("reading", ""))))
        if direction != "inverse":
            # The register is filled in for the row it is ABOUT. On a `modelled`
            # row all three were accepted and none was read: `disposition =
            # "banana"` beside a `superseded_by` naming nothing was exit 0.
            stray = [key for key in INVERSE_FIELDS if key in row]
            if stray:
                findings.append(
                    f"{where}: a {direction!r} row carrying {stray} — the disposition"
                    " register belongs to an inverse kill, and on any other row it is"
                    " a field nothing validates"
                )
        if direction not in DIRECTIONS:
            findings.append(
                f"{where}: direction {direction!r} is not one of {DIRECTIONS}"
                " — a red run is not evidence until the direction is read"
            )
        elif direction == "inverse":
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
                elif corrected_by(by_name, str(row.get("superseded_by", ""))) is None:
                    findings.append(
                        f"{where}: `superseded_by` reaches no corrected mutant — a"
                        " chain of inverse rows corrects nothing, and the step this"
                        " row claims to be has no result at the end of it"
                    )
            if not str(row.get("reading", "")).strip():
                findings.append(
                    f"{where}: an inverse kill with no `reading` — the direction is"
                    " the whole content, and nothing else in the row states it"
                )
    for text in sorted({r for r in readings if r and readings.count(r) > 1}):
        findings.append(
            f"{bundle}: {readings.count(text)} mutation rows share one `reading`"
            " — it argues THIS row's direction, and one sentence copied across"
            " rows argues none of them. All 10 in this bundle are distinct"
        )
    verdicts = len(named) - inverse
    if verdicts < VERDICT_FLOOR:
        findings.append(
            f"{bundle}: {verdicts} mutation verdict(s), under the floor of"
            f" {VERDICT_FLOOR} — all ten rows `inverse` printed '0 mutation"
            " verdict(s) and 10 disposed as inverse' at exit 0, and a group that"
            " disposed of every row killed nothing"
        )
    return inverse


def log_integers(root: pathlib.Path, target: str, cache: dict) -> frozenset[str]:
    """Every integer the log at `target` prints, memoised per audit.

    Lazily, because the corpus holds a 339 KB `.gz` that is 15.8 MB of CBMC
    unwinding lines and no leaf joins to it — reading it eagerly would put that
    decompression in every one of this table's cases.
    """
    if target not in cache:
        path = root / target
        raw = path.read_bytes() if path.is_file() else b""
        if path.suffix == ".gz":
            try:
                raw = gzip.decompress(raw)
            except (OSError, EOFError):
                raw = b""
        text = raw.decode("utf-8", "replace")
        cache[target] = frozenset(
            match.group(0).lstrip("0") or "0" for match in INTEGER.finditer(text)
        )
    return cache[target]


def parsed(root: pathlib.Path, bundle: pathlib.Path) -> dict | None:
    """The bundle, or `None` if TOML cannot read it.

    Both passes below walk EVERY bundle, and a file the glob found and tomllib
    cannot parse must not take the row down with a traceback: `audit_one` already
    reports it as a finding, and this pass has nothing to add.
    """
    try:
        return tomllib.loads((root / bundle).read_text(encoding="utf-8"))
    except (tomllib.TOMLDecodeError, OSError, UnicodeDecodeError):
        return None


def log_corpus(root: pathlib.Path) -> tuple[set[str], dict[str, set[str]], dict[str, set[str]]]:
    """The bundled logs, indexed the three ways a leaf can name one.

    Tree-wide and not per bundle: `SEC-FIDO-006B` quotes a log `SEC-FIDO-001`
    carries, and that is the join the whole rule exists for. Every path here is
    already held to its own byte count and digest above, so the log a number is
    compared against is the one the run wrote.
    """
    paths: set[str] = set()
    by_name: dict[str, set[str]] = {}
    by_configuration: dict[str, set[str]] = {}
    for bundle in bundles(root):
        doc = parsed(root, bundle)
        for row in (doc or {}).get("artifact", []):
            if not isinstance(row, dict):
                continue
            target = str(row.get("path", ""))
            name = pathlib.PurePosixPath(target).name
            paths.add(target)
            by_name.setdefault(name, set()).add(target)
            if name.startswith("tlc-"):
                stem = name[len("tlc-"):].partition(".log")[0]
                by_configuration.setdefault(stem, set()).add(target)
    return paths, by_name, by_configuration


def quoted_join(doc: dict, bundle: pathlib.Path, key: str, value: str, corpus) -> tuple[set[str], dict]:
    """Which log a leaf's numbers are about, and which vocabulary to read.

    Two joins, and the NAMED one wins: a leaf can say `AlwaysUv.cfg` in one
    clause and `cargo-test-always-uv.log` in the next, and reading the
    configuration first sent that log's `446 passed` to TLC's summary.
    """
    paths, by_name, by_configuration = corpus
    named: set[str] = set()
    for match in LOG_NAME.finditer(value):
        token = match.group(0)
        if token in paths:
            named.add(token)
        else:
            named |= by_name.get(pathlib.PurePosixPath(token).name, set())
    # An `[[artifact]].run` names its log in the field beside it rather than in
    # its own prose, which is where `172 failures` and four `depth N` sit.
    if not named and key.startswith("artifact[") and key.endswith(".run"):
        index = int(key.partition("[")[2].partition("]")[0]) - 1
        target = str(doc["artifact"][index].get("path", ""))
        if target in paths:
            named = {target}
    if named:
        return named, {**QUOTED_SEARCH, **QUOTED_RESULT}
    # ONE configuration, not one that happens to have a log: a sentence naming
    # `Historical_E76.cfg` and `Mut_BugSeedDoesNotLead.cfg` carries a number
    # belonging to the second, and only the first has an artifact here.
    spelled = {match.group(1) for match in CONFIGURATION.finditer(value)}
    if len(spelled) == 1:
        found = by_configuration.get(spelled.pop(), set())
        # Ten bundles carry a `tlc-ForceChange.log` of their own and they are not
        # the same run — 177 s in one, 178 s in another. Accepting the union
        # lets a number true of any bundle's copy stand in this one, so the
        # bundle's OWN copy is the log when it has one.
        own = {one for one in found if f"/{bundle.stem}/" in one}
        return own or found, QUOTED_SEARCH
    return set(), {}


def quoted_numbers(root: pathlib.Path, findings: list[str]) -> tuple[int, int]:
    """A number printed next to a log must occur in that log.

    The narrow, measured version of that sentence. `assurance/configurations.toml`
    already forbids the specific drift by hand — "the pair 446/172 is NOT a
    superseded version of this one and must not be reconciled with it" — and
    nothing enforced it: `446` and `172` are integers of
    `cargo-test-always-uv.log`, `493` and `176` are not, and rewriting one pair
    into the other was exit 0.

    What it does NOT claim: that the log is the run's, which the digest above
    holds; or that an unjoined number is right. 198 of the tree's 492
    measurement-shaped numbers reach a log, and the rest name no artifact at all.
    """
    corpus = log_corpus(root)
    cache: dict[str, frozenset[str]] = {}
    checked, joins = 0, set()
    for bundle in bundles(root):
        doc = parsed(root, bundle)
        if doc is None:
            continue
        for key, value in walk(doc):
            if not isinstance(value, str):
                continue
            named, shapes = quoted_join(doc, bundle, key, value, corpus)
            if not named:
                continue
            quoted = [
                (shape, match.group(1))
                for shape, pattern in shapes.items()
                for match in pattern.finditer(value)
            ]
            if not quoted:
                continue
            joins.add((str(bundle), tuple(sorted(named))))
            printed = set().union(*(log_integers(root, one, cache) for one in named))
            for shape, text in quoted:
                checked += 1
                digits = re.sub(r"\D", "", text).lstrip("0") or "0"
                if digits not in printed:
                    findings.append(
                        f"{bundle} `{key}`: {digits} {shape} is in no line of"
                        f" `{sorted(named)[0]}` — a number printed next to a log is a"
                        " transcription of it, and re-measuring the run does not"
                        " re-measure the log"
                    )
    return checked, len(joins)


def bundles(root: pathlib.Path) -> list[pathlib.Path]:
    """Every bundle in the tree, as a path relative to `root`.

    Sorted, so the summary and the findings are in a stable order and a diff of
    two runs is about the tree rather than about the filesystem.
    """
    return sorted(
        found.relative_to(root)
        for found in (root / BUNDLE_DIR).glob("*.toml")
        if found.is_file()
    )


def orphan_evidence(
    root: pathlib.Path, findings: list[str], store_floor: int = STORE_FLOOR
) -> int:
    """Every file under [`STORE`] is the `path` of some `[[artifact]]` row.

    The other direction of the rule `audit_one` already runs. Forwards, a path a
    bundle names must be a file in the tree; backwards, a file in the tree must
    be a path some bundle names. Only forwards existed, and it cannot see the
    half that matters here — a log nothing cites is evidence the roster no longer
    claims, sitting where a reader takes the directory for the exhibit list.

    Cited means an `[[artifact]].path` and not a mention. A `[[method]] artifact`
    naming a log, or a `result` leaf quoting one, would be a weaker join and a
    worse one: it would make a log with no digest, no byte count and no
    `[[cost]]` row legal here, which is every rule beside this one walked past.
    Three method rows name a log, and all three are `[[artifact]]` rows too, so
    the narrow reading loses nothing the tree has.

    Compared as the bundle writes it. All 100 paths are `root`-relative POSIX and
    the `[[artifact]]` rule beside this one already refuses an absolute one, so a
    `./` or `../` spelling would surface HERE, as a loud finding naming the file,
    rather than as a normalisation quietly agreeing with whatever was written.

    By full path and never by name: 15 basenames are carried by more than one
    directory — `tlc-Shipped.log` by all eleven, `tlc-AlwaysUv.log` by nine — and
    they are different runs of the same configuration. A name-keyed reading lets
    one bundle's copy discharge every other bundle's, which is the join
    [`quoted_join`] already had to un-widen for its own reason.
    """
    store = root / STORE
    cited = {
        str(row.get("path", ""))
        for bundle in bundles(root)
        for row in (parsed(root, bundle) or {}).get("artifact", [])
        if isinstance(row, dict)
    }
    # Directories are not walked as evidence and are not exempted either: the
    # store carries ten of them and no file that is not a log, so there is no
    # `README`/`.gitkeep` case to write a carve-out for. Anything that arrives is
    # a finding naming it, which is a decision someone makes rather than a
    # category that arrives already excused.
    stored = sorted(
        found.relative_to(root).as_posix()
        for found in store.rglob("*")
        if found.is_file()
    )
    for target in stored:
        if target not in cited:
            findings.append(
                f"{STORE}: `{target}` is the `path` of no `[[artifact]]` row — a"
                " file in the evidence store that no bundle cites is evidence the"
                " roster does not claim, and the directory is the exhibit list"
            )
    if len(stored) < store_floor:
        findings.append(
            f"{STORE}: {len(stored)} evidence file(s), under the floor of"
            f" {store_floor} — the rule above goes quiet when the store empties,"
            " and a log deleted with its `[[artifact]]` and `[[cost]]` rows is a"
            " run this slice can no longer show"
        )
    return len(stored)


def audit(
    root: pathlib.Path,
    roster_floor: int = ROSTER_FLOOR,
    store_floor: int = STORE_FLOOR,
) -> tuple[list[str], str]:
    root = pathlib.Path(root)
    findings: list[str] = []
    page = root / SLICE
    findings.extend(
        vocabulary_problems(
            page.read_text(encoding="utf-8") if page.is_file() else None
        )
    )
    roster = bundles(root)
    if len(roster) < roster_floor:
        findings.append(
            f"{BUNDLE_DIR}: {len(roster)} bundle(s), under the floor of"
            f" {roster_floor} — a closed slice whose bundle is gone is a slice"
            " that unclosed itself with this row green"
        )
    summaries = []
    for bundle in roster:
        one, summary = audit_one(root, bundle)
        findings.extend(one)
        if summary:
            summaries.append(summary)
    stored = orphan_evidence(root, findings, store_floor)
    quoted, joins = quoted_numbers(root, findings)
    # The floor is the rule's own non-degeneracy row. Every clause of
    # [`quoted_join`] can stop matching without a single finding being lost —
    # the numbers simply stop being read — and the summary line would say the
    # same either way.
    if quoted < QUOTE_FLOOR or joins < QUOTE_JOIN_FLOOR:
        findings.append(
            f"{BUNDLE_DIR}: {quoted} quoted number(s) over {joins} log join(s),"
            f" under the floor of {QUOTE_FLOOR} over {QUOTE_JOIN_FLOOR} — a"
            " transcription rule that joins nothing reads as one that holds every"
            " number in the tree"
        )
    summaries.append(f"{quoted} quoted number(s) held to {joins} log(s)")
    summaries.append(f"{stored} evidence file(s), every one cited")
    return findings, "bundle-gate: ok — " + "; ".join(summaries)


def audit_one(root: pathlib.Path, bundle: pathlib.Path) -> tuple[list[str], str]:
    root = pathlib.Path(root)
    findings: list[str] = []
    path = root / bundle
    if not path.is_file():
        return [f"{bundle}: no such bundle"], ""
    try:
        doc = tomllib.loads(path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as broken:
        # A file the glob found and TOML cannot read is a finding and not a
        # crash: the roster is the directory, so anything dropped in is audited,
        # and an unreadable one must say so rather than take the row down with a
        # traceback nobody attributes to a bundle.
        return [f"{bundle}: is not readable as TOML — {broken}"], ""

    for group in GROUPS:
        if group not in doc:
            findings.append(
                f"{bundle}: group `{group}` is missing — stage 1A п.3 blocks the exit"
                " on any field of the contract, not on most of them"
            )
    for group in sorted(set(doc) - set(GROUPS)):
        findings.append(f"{bundle}: `{group}` is in no group of the contract")

    total = 0
    for group in GROUPS:
        if group not in doc:
            continue
        found, empty = leaves(doc[group], group)
        total += found
        for hole in empty:
            findings.append(f"{bundle}: `{hole}` is empty — a blank leaf is a dropped field")
        if found < FLOORS[group]:
            findings.append(
                f"{bundle}: group `{group}` carries {found} leaf/leaves, under the floor"
                f" of {FLOORS[group]} — a heading with one line under it is what"
                " 'unabridged' has to be a predicate about"
            )

    for group in GROUPS:
        if group not in doc:
            continue
        rows = doc[group] if isinstance(doc[group], list) else [doc[group]]
        for index, row in enumerate(rows, 1):
            where = f"{bundle} {group}" + (f" #{index}" if isinstance(doc[group], list) else "")
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
        findings.append(f"{bundle}: property `{subject}` is in no row of {REGISTRY}")
    # The FILENAME is a claim, and it is the only one a reader of the directory
    # sees. Copying `SEC-FIDO-001.toml` to `SEC-FIDO-007.toml` and changing
    # nothing else clears every rule above — ten groups, every floor, every
    # artifact digest — and puts a second closed slice in the roster that is the
    # first one twice.
    if subject != bundle.stem:
        findings.append(
            f"{bundle}: carries property `{subject}` and is named for"
            f" `{bundle.stem}` — the filename is what the roster is read by"
        )

    leaf_answers(bundle, doc, findings)
    method_answers(bundle, doc, findings)
    method_bounds(bundle, doc, findings)
    method_references(root, bundle, doc, findings)

    for index, row in enumerate(doc.get("artifact", []), 1):
        if not isinstance(row, dict):
            continue  # `is not a table` is the roster rule's, reported once
        where = f"{bundle} artifact #{index}"
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

    logged = {
        str(row.get("path", ""))
        for row in doc.get("artifact", []) if isinstance(row, dict)
    }
    costed = set()
    for index, row in enumerate(doc.get("cost", []), 1):
        if not isinstance(row, dict):
            continue
        where = f"{bundle} cost #{index} ({row.get('artifact', '?')})"
        # A foreign key nothing joins is a name. 10 of the 11 cost rows are
        # byte-identical to an `[[artifact]].path` and the 11th is deliberate
        # prose; re-pointing all 11 at a log that is nowhere was exit 0.
        artifact = str(row.get("artifact", ""))
        costed.add(artifact)
        if FILE_SHAPED.search(artifact) and artifact not in logged:
            findings.append(
                f"{where}: `{artifact}` is the path of no `[[artifact]]` row — item"
                " 10 is three numbers PER ARTIFACT, and a row naming work with no"
                " artifact of its own says so in prose instead"
            )
        for field in COST_FIELDS:
            value = row.get(field)
            if value is None:
                findings.append(f"{where}: no `{field}` — the item measures three, not one")
            elif not isinstance(value, (int, float)) or isinstance(value, bool):
                findings.append(
                    f"{where}: `{field}` is {value!r}, which is not a number — a range is"
                    " an estimate, and an estimate in any of the three voids the measurement"
                )

    for target in sorted(logged - costed):
        findings.append(
            f"{bundle}: `{target}` is a raw artifact with no `[[cost]]` row — the"
            " other direction of the same join, and the one that loses a run's cost"
            " rather than inventing one"
        )

    gate_transcriptions(bundle, doc, findings)
    inverse = mutation_dispositions(bundle, doc, findings)

    summary = (
        f"{bundle.name} carries {len(GROUPS)} groups and {total}"
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
