# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""The mutation table for `bundle_gate.py`.

One arm per rule, each breaking the real bundle in one place — the fixture IS the
shipped bundle, because a synthetic one would prove the rules about a document
nobody has to keep true. The two arms worth naming are the ones the contract
turns on: a group that keeps its heading and loses its body, and a cost written
as a range.
"""

import json
import os
import pathlib
import re
import shutil
import sys
import tomllib

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import bundle_gate  # noqa: E402

ROOT = bundle_gate.ROOT


def scalar(value):
    """One TOML value. `json.dumps` because a basic string escapes the same way."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return repr(value)
    if isinstance(value, list):
        return "[" + ", ".join(scalar(v) for v in value) + "]"
    return json.dumps(str(value))


def dump(doc) -> str:
    """The bundle, re-serialised.

    The arms below delete a group and write the document back, and they cannot do
    that by cutting HEADING lines out of the text: the orphaned body then lands in
    whatever table precedes it and `tomllib` raises. Measured — 8 of the 20
    parametrized cases were a `TOMLDecodeError` and asserted nothing, on exactly
    the array-of-tables groups the contract is mostly made of.
    """
    out = []
    for key, value in doc.items():
        rows = value if isinstance(value, list) else [value]
        head = f"[[{key}]]" if isinstance(value, list) else f"[{key}]"
        for row in rows:
            out.append(head)
            for field, item in row.items():
                out.append(f"{field} = {scalar(item)}")
            out.append("")
    return "\n".join(out) + "\n"


def method_targets(doc):
    """The files the method rows point at, resolved the way the gate resolves
    them — derived rather than transcribed, so a new row arrives in the fixture
    instead of quietly dangling in it."""
    for row in doc.get("method", []):
        for word in re.split(r"[\s+]+", str(row.get("artifact", ""))):
            name = word.strip(bundle_gate.TRIM).partition("::")[0]
            found = bundle_gate.resolve(ROOT, name)
            if found is not None:
                yield str(found.relative_to(ROOT))


def tree(tmp_path):
    """A checkout carrying EVERY real bundle, the registry, every artifact and
    every file a method row's `artifact` names.

    Every bundle and not just [`bundle_gate.BUNDLE`], because the roster is the
    directory now: a fixture holding one of two would put the shipped roster
    under its own floor and make every case in this file fail for the wrong
    reason — the failure mode this table exists to refuse.
    """
    (tmp_path / bundle_gate.REGISTRY).parent.mkdir(parents=True, exist_ok=True)
    shutil.copy(ROOT / bundle_gate.REGISTRY, tmp_path / bundle_gate.REGISTRY)
    for relative in bundle_gate.bundles(ROOT):
        (tmp_path / relative).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(ROOT / relative, tmp_path / relative)
        doc = tomllib.loads((ROOT / relative).read_text())
        for name in [row["path"] for row in doc["artifact"]] + list(method_targets(doc)):
            target = tmp_path / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy(ROOT / name, target)
    return tmp_path


def rewrite(root, change):
    """Apply `change` to the parsed bundle and write it back."""
    path = root / bundle_gate.BUNDLE
    doc = tomllib.loads(path.read_text())
    change(doc)
    path.write_text(dump(doc))


def edit(root, old, new, count=1):
    path = root / bundle_gate.BUNDLE
    text = path.read_text()
    assert text.count(old) >= count, old
    path.write_text(text.replace(old, new, count))


def findings(root):
    return bundle_gate.audit(root)[0]


def test_the_real_bundle_is_green():
    assert findings(ROOT) == []


def test_the_fixture_is_the_real_bundle(tmp_path):
    assert findings(tree(tmp_path)) == []


@pytest.mark.parametrize("group", bundle_gate.GROUPS)
def test_a_missing_group_blocks_the_exit(tmp_path, group):
    root = tree(tmp_path)
    rewrite(root, lambda doc: doc.pop(group))
    assert any(f"group `{group}` is missing" in p for p in findings(root)), findings(root)


@pytest.mark.parametrize("group", bundle_gate.GROUPS)
def test_a_group_that_keeps_its_heading_and_loses_its_body(tmp_path, group):
    """Ten headings with one line each satisfy "all ten groups are present",
    which is the whole reason this counts leaves."""
    root = tree(tmp_path)

    def strip(doc):
        doc[group] = (
            [{"kept": "one line"}] if isinstance(doc[group], list) else {"kept": "one line"}
        )

    rewrite(root, strip)
    problems = findings(root)
    assert any(f"group `{group}` carries 1 leaf" in p for p in problems), problems


@pytest.mark.parametrize(
    "group,field",
    [(g, f) for g, fields in bundle_gate.REQUIRED.items() for f in fields],
)
def test_a_named_field_the_contract_owes_is_found_missing(tmp_path, group, field):
    """A leaf floor counts VOLUME. Renaming a field keeps the count, and padding
    a group with a long list of anything clears the floor — measured green.

    A trailing `*` is a prefix, so the arm for it drops the whole family: popping
    the literal key `bound_*` would raise `KeyError` and go red for the wrong
    reason, which is the shape this repo keeps paying for.
    """
    root = tree(tmp_path)

    def drop(doc):
        rows = doc[group] if isinstance(doc[group], list) else [doc[group]]
        gone = [field] if not field.endswith("*") else [
            key for key in rows[0] if key.startswith(field[:-1])
        ]
        assert gone, f"{field} matches nothing in row 0, so this case asserts nothing"
        for key in gone:
            rows[0].pop(key)

    rewrite(root, drop)
    assert any(f"no `{field}` — the contract names it" in p for p in findings(root)), findings(
        root
    )


@pytest.mark.parametrize("group", ["mutation", "cost", "artifact"])
def test_a_row_that_is_not_a_table(tmp_path, group):
    """`audit` has a finding for exactly this and never printed it: the filtered
    list was built and the UNFILTERED one iterated, so `mutation = ["a string"]`
    was an `AttributeError` traceback out of `row.get` — EXIT=1 for the wrong
    reason, in the file that exists to name the reason."""
    root = tree(tmp_path)
    path = root / bundle_gate.BUNDLE
    doc = tomllib.loads(path.read_text())
    doc.pop(group)
    path.write_text(f'{group} = ["a string, not a table"]\n' + dump(doc))
    problems = findings(root)
    assert any("is not a table" in p for p in problems), problems


def test_the_three_rosters_name_the_same_ten_groups():
    """`GROUPS` without `FLOORS` is a KeyError; `FLOORS` without `GROUPS` is
    silently dead, and that is the direction nothing would have shown."""
    assert set(bundle_gate.GROUPS) == set(bundle_gate.FLOORS) == set(bundle_gate.REQUIRED)


#: The contract's fields, by hand. The table above parametrizes over `REQUIRED`,
#: so it is a DRIFTER: removing `bound_*` from `REQUIRED["method"]` removes the
#: case with it — measured, 150 collected to 149, and the two failures that
#: arrived came from hand-written arms and not from the roster the commit
#: credited. This is the pin the drifter cannot be.
CONTRACT = {
    "property": ("id", "invariant", "statement", "subjects", "requirement", "threat_clause"),
    "build": ("commit", "tree_state", "matrix_column", "cargo_features", "host_triple"),
    "method": ("obligation", "method", "artifact", "bound_*", "shipped_relation", "cfg",
               "features"),
    "tool": ("name", "version", "provenance", "invocation", "environment"),
    "result": (),
    "artifact": ("run", "path", "bytes", "sha256"),
    "assumption": ("id", "statement", "kind", "discharger", "expressible", "registered"),
    "mutation": ("level", "mutant", "invocation", "expected", "verdict", "fell", "direction"),
    "freshness": ("measured",),
    "cost": ("artifact", "human_minutes", "runner_seconds", "peak_memory_mb", "basis"),
}


def test_every_field_the_contract_names_is_still_named():
    """A field dropped from `REQUIRED` takes its own negative arm with it, so the
    roster needs a copy nothing derives. Removing one here is a deliberate line
    in the diff, which is what a contract change should be."""
    assert bundle_gate.REQUIRED == CONTRACT


def test_a_log_of_the_same_length_is_not_the_same_log(tmp_path):
    """A byte count is satisfied by any file of that length — measured green
    before the digest, by swapping a 10-byte log for a different 10-byte one."""
    root = tree(tmp_path)
    doc = tomllib.loads((root / bundle_gate.BUNDLE).read_text())
    target = root / doc["artifact"][0]["path"]
    raw = target.read_bytes()
    target.write_bytes(bytes((b ^ 0x20) if b > 0x40 else b for b in raw))
    assert len(target.read_bytes()) == len(raw)
    assert any("is not the one the run wrote" in p for p in findings(root)), findings(root)


def test_an_absolute_artifact_path_escapes_the_tree(tmp_path):
    """`root / "/etc/hosts"` is `/etc/hosts`, so `is_file()` passes and only the
    byte count is compared. "In the tree" is not what that checks."""
    root = tree(tmp_path)
    rewrite(root, lambda doc: doc["artifact"][0].update(path="/etc/hosts"))
    assert any("is absolute" in p for p in findings(root)), findings(root)


def test_every_bound_stripped_from_every_method_row(tmp_path):
    """The measured hole, in the shape it was driven: all 30 `bound_*` keys out
    of all 8 rows took the leaf count 419 -> 389 and left the exit at 0, because
    every floor still cleared. Roadmap §7.2 wants the bound as structured data
    and the only structured thing about it was that nothing read it."""
    root = tree(tmp_path)

    def strip(doc):
        for row in doc["method"]:
            for key in [k for k in row if k.startswith("bound_")]:
                row.pop(key)

    rewrite(root, strip)
    assert any("no `bound_*`" in p for p in findings(root)), findings(root)


def test_a_bound_is_owed_per_row_and_not_per_group(tmp_path):
    """A group-wide rule is cleared by one row keeping its bounds, and the row
    that lost them is the one whose scope stopped being stated."""
    root = tree(tmp_path)

    def strip(doc):
        row = doc["method"][-1]
        for key in [k for k in row if k.startswith("bound_")]:
            row.pop(key)

    rewrite(root, strip)
    assert any("method #8: no `bound_*`" in p for p in findings(root)), findings(root)


def test_a_bound_key_of_any_name_satisfies_the_row(tmp_path):
    """Bounds are per method — a sequence length here, a cardinality there — so
    naming one key would be requiring the wrong one. The NAMES are free; how
    many there are is not."""
    root = tree(tmp_path)

    def rename(doc):
        for row in doc["method"]:
            for order, key in enumerate([k for k in row if k.startswith("bound_")]):
                row[f"bound_a_name_nobody_wrote_{order}"] = row.pop(key)

    rewrite(root, rename)
    assert findings(root) == []


def test_every_row_reduced_to_one_bound(tmp_path):
    """The ratchet the roster left: `REQUIRED`'s `bound_*` is satisfied by ONE
    key, so all 8 rows at a single `bound_nothing = 0` was EXIT=0 over 397
    leaves — the measured hole was zero bounds and its replacement was one."""
    root = tree(tmp_path)

    def strip(doc):
        for row in doc["method"]:
            for key in [k for k in row if k.startswith("bound_")]:
                row.pop(key)
            row["bound_nothing"] = 0

    rewrite(root, strip)
    problems = findings(root)
    assert any("bound(s), under the floor of 2" in p for p in problems), problems
    assert any("key(s) over the method rows" in p for p in problems), problems


def test_a_bound_that_is_a_flag(tmp_path):
    """`bound_x = false` cleared the roster and bounds nothing."""
    root = tree(tmp_path)
    rewrite(root, lambda doc: doc["method"][0].update({"bound_states": False}))
    assert any("never a flag" in p for p in findings(root)), findings(root)


def test_a_key_named_literally_bound_underscore(tmp_path):
    """The wildcard itself: `any(k.startswith("bound_"))` is true of `bound_`."""
    root = tree(tmp_path)

    def wildcard(doc):
        row = doc["method"][1]
        for key in [k for k in row if k.startswith("bound_")]:
            row.pop(key)
        row["bound_"] = 1
        row["bound_states"] = 2
        row["bound_pairs"] = 3

    rewrite(root, wildcard)
    assert any("is the prefix and not a name" in p for p in findings(root)), findings(root)


def test_a_bound_group_stripped_to_just_over_the_row_floor(tmp_path):
    """Eight rows at the per-row floor is 16 against the 30 the bundle carries,
    which is why the group has a floor of its own."""
    root = tree(tmp_path)

    def thin(doc):
        for row in doc["method"]:
            for key in [k for k in row if k.startswith("bound_")][2:]:
                row.pop(key)

    rewrite(root, thin)
    problems = findings(root)
    assert not any("bound(s), under the floor of 2" in p for p in problems), problems
    assert any("key(s) over the method rows" in p for p in problems), problems


@pytest.mark.parametrize(
    "value",
    ["n/a", "N/A", "N / A", "na", "-", "--", "—", "?", ".", "...", "…",
     "none", "None", "nil", "TBD", "todo", "unknown", "not applicable", 0],
)
@pytest.mark.parametrize("field", bundle_gate.PROSE_FIELDS)
def test_a_prose_field_occupied_by_a_non_answer(tmp_path, field, value):
    """`shipped_relation` refused a dropped key, an empty string and a
    whitespace-only one, and took `"n/a"` at exit 0 — the same dropped field in
    a spelling the REQUIRED roster cannot see."""
    root = tree(tmp_path)
    rewrite(root, lambda doc: doc["method"][0].update({field: value}))
    assert any("which answers nothing" in p for p in findings(root)), findings(root)


def test_none_is_an_answer_where_none_is_an_answer(tmp_path):
    """The two leaves the widening below is exempted at, and the only two: five
    method rows answer `cfg` with exactly `none` and four answer `features`,
    and there `none` means the build had none of it."""
    root = tree(tmp_path)
    doc = tomllib.loads((root / bundle_gate.BUNDLE).read_text())
    assert [r["cfg"] for r in doc["method"]].count("none") == 5, doc["method"]
    assert [r.get("features") for r in doc["method"]].count("none") == 4, doc["method"]
    assert findings(root) == []


@pytest.mark.parametrize("field", ["cfg", "features"])
def test_the_exemption_is_the_value_and_not_the_field(tmp_path, field):
    """Exempting the two FIELDS outright takes `cfg = "n/a"` back — the same
    dropped field one spelling over, which is the defect this rule is named for."""
    root = tree(tmp_path)
    rewrite(root, lambda doc: doc["method"][0].update({field: "n/a"}))
    assert any("which answers nothing" in p for p in findings(root)), findings(root)


@pytest.mark.parametrize(
    "path",
    ["mutation.fell", "mutation.verdict", "mutation.expected", "build.commit",
     "build.host_triple", "tool.version", "property.statement", "property.invariant",
     "cost.basis", "freshness.measured"],
)
def test_a_leaf_outside_the_two_prose_fields_occupied_by_a_non_answer(tmp_path, path):
    """The measured scope of the first version: a sweep setting each of the
    bundle's 348 string leaves to `"n/a"` in turn left 266 at EXIT=0, and the
    non-answer rule owned 18 of the 57 refusals — all of them `[[method]]`.
    Every one of these was green while the docstring said each `[[mutation]]`
    records the assertion that FELL."""
    group, field = path.split(".")
    root = tree(tmp_path)

    def occupy(doc):
        rows = doc[group] if isinstance(doc[group], list) else [doc[group]]
        assert field in rows[0], f"{path} is not in the bundle any more"
        rows[0][field] = "n/a"

    rewrite(root, occupy)
    assert any("which answers nothing" in p for p in findings(root)), findings(root)


#: The vocabulary, by hand. NOT parametrized over `bundle_gate.NON_ANSWERS`:
#: a table built from the constant loses a case when the constant loses a member,
#: which is the deletion this exists to catch. Measured — deleting 10 of the 18
#: members left `pytest scripts/test_bundle_gate.py` at EXIT=0, 150 passed, and
#: the table beside it had hand-written 19 values that reached 8 of them.
VOCABULARY = frozenset(
    {
        "na", "notapplicable", "noanswer", "seeabove", "ditto",
        "none", "nil", "null", "nothing",
        "unknown", "unspecified", "undefined", "unclear",
        "tbd", "tba", "tobedetermined", "todo", "xxx", "pending", "wip",
    }
)


def test_the_vocabulary_is_the_one_this_table_drives():
    """Equality, so a member deleted from the gate fails here rather than
    silently deleting its own case."""
    assert bundle_gate.NON_ANSWERS == VOCABULARY


@pytest.mark.parametrize("word", sorted(VOCABULARY))
def test_every_word_of_the_vocabulary_is_refused(tmp_path, word):
    """Driven through the gate, from the HAND roster: deleting `null`,
    `nothing`, `unspecified`, `undefined`, `unclear`, `tobedetermined`, `xxx`,
    `pending`, `wip` and the `n\\a` spelling was green over all 150 cases."""
    root = tree(tmp_path)
    rewrite(root, lambda doc: doc["mutation"][0].update({"fell": word}))
    assert any("which answers nothing" in p for p in findings(root)), findings(root)


@pytest.mark.parametrize(
    "spelling",
    ["n.a.", "t.b.d.", "N/A;", "todo:", "not-applicable", "(none)", "TBA",
     "no answer", "see above", "ditto", "N.A", "tbd;", "  none  "],
)
def test_a_non_answer_wearing_punctuation(tmp_path, spelling):
    """The vocabulary compared with whitespace removed and a trailing `.!?…`
    stripped, so `;` and `:` bought a second spelling of the same word and all
    of these were EXIT=0. Normalized to alphanumerics now."""
    root = tree(tmp_path)
    rewrite(root, lambda doc: doc["mutation"][0].update({"fell": spelling}))
    assert any("which answers nothing" in p for p in findings(root)), findings(root)


def test_a_method_artifact_naming_a_harness_that_is_gone(tmp_path):
    """The measured hole: deleting one of the four harnesses left the exit at 0,
    and the bundle's own `kani=4` line green at 3."""
    root = tree(tmp_path)
    harness = root / "crates/rsk-fido/src/state_kani.rs"
    harness.write_text(
        harness.read_text().replace("no_authorization_bypass_walk_owner", "a_harness_by_another_name")
    )
    assert any("declares no `" in p for p in findings(root)), findings(root)


def test_a_file_that_mentions_the_harness_is_not_the_file_that_has_it(tmp_path):
    """This rule's own first version read the file's raw text, and
    `credmgmt_kani.rs` names `no_authorization_bypass_walk_owner` in a doc
    comment — so pointing the walk row at the wrong file resolved at exit 0."""
    root = tree(tmp_path)
    mentions = (root / "crates/rsk-fido/src/credmgmt_kani.rs").read_text()
    assert "no_authorization_bypass_walk_owner" in mentions, "the fixture lost the mention"
    edit(root, "state_kani.rs::no_authorization_bypass_walk_owner",
         "credmgmt_kani.rs::no_authorization_bypass_walk_owner")
    assert any("declares no `no_authorization_bypass" in p for p in findings(root)), findings(root)


def test_a_harness_is_matched_whole_and_not_by_suffix(tmp_path):
    """The suffix arm belongs to the elision alone. Everywhere, it would make
    `::owner` resolve against `no_authorization_bypass_walk_owner` — the rule
    loosened by the shape it was written to support."""
    root = tree(tmp_path)
    edit(root, "state_kani.rs::no_authorization_bypass_walk_owner", "state_kani.rs::owner")
    assert any("declares no `owner`" in p for p in findings(root)), findings(root)


@pytest.mark.parametrize("symbol", ["STEPS", "StepRng", "OP_STOP"])
def test_a_bounded_proof_discharged_by_a_const_or_a_struct(tmp_path, symbol):
    """`DECLARED` matches a const, a struct and anything under `#[cfg(test)]`, so
    the whole rule was "the file declares SOMETHING by that name": all three were
    measured green on the walk row."""
    root = tree(tmp_path)
    edit(root, "state_kani.rs::no_authorization_bypass_walk_owner", f"state_kani.rs::{symbol}")
    assert any("naming no `#[kani::proof]`" in p for p in findings(root)), findings(root)


def test_a_harness_that_lost_its_proof_attribute(tmp_path):
    """The name survives the deletion of the thing that makes it a proof. Before
    this, only `kani_gate.py`'s global count floor moved — 92 to 91, a different
    row, and blind to WHICH harness went."""
    root = tree(tmp_path)
    harness = root / "crates/rsk-fido/src/state_kani.rs"
    harness.write_text(harness.read_text().replace("#[kani::proof]\nfn no_authorization_bypass_walk_owner",
                                                   "fn no_authorization_bypass_walk_owner"))
    assert any("naming no `#[kani::proof]`" in p for p in findings(root)), findings(root)


@pytest.mark.parametrize(
    "target", ["CHANGELOG.md", "README.md", "assurance/bundle/SEC-FIDO-001.toml"],
)
def test_a_bounded_proof_discharged_by_any_file_in_the_tree(tmp_path, target):
    """Six of the eight rows carry no `::` at all, so for them the rule was "a
    file of that name exists". All three of these were EXIT=0 on the walk row."""
    root = tree(tmp_path)
    (root / target).parent.mkdir(parents=True, exist_ok=True)
    shutil.copy(ROOT / target, root / target)
    edit(root, 'artifact = "crates/rsk-fido/src/state_kani.rs'
               '::no_authorization_bypass_walk_owner"', f'artifact = "{target}"')
    assert any("and no .rs" in p for p in findings(root)), findings(root)


def test_a_model_check_row_discharged_by_something_that_is_not_a_configuration(tmp_path):
    """The other half of the same rule, on the four rows that name a bare
    `Name.cfg`: the file resolving is not the file being a configuration."""
    root = tree(tmp_path)
    shutil.copy(ROOT / "CHANGELOG.md", root / "CHANGELOG.md")
    edit(root, 'artifact = "Shipped.cfg"', 'artifact = "CHANGELOG.md"')
    assert any("and no .cfg" in p for p in findings(root)), findings(root)


def test_what_a_rust_file_declares_and_which_of_them_are_proofs(tmp_path):
    """`gate_lines.rust_code` blanks string literals BEFORE this runs, so the
    `extern "…"` alternative the pattern first carried could never match and
    `pub extern "C" fn target` was reported as undeclared — a branch nothing can
    take, wrong in the direction that refuses real code. And a `#[test]` fn is a
    declaration and not a harness, which is the half `::STEPS` walked through."""
    source = tmp_path / "x.rs"
    source.write_text(
        'pub extern "C" fn exported() {}\n'
        "\n"
        "/// A doc comment, blank by the time this runs.\n"
        "#[kani::proof]\n"
        "fn a_harness() {}\n"
        "\n"
        "#[cfg(test)]\n"
        "mod tests {\n"
        "    #[test]\n"
        "    fn a_test() {}\n"
        "}\n"
    )
    declared, proofs = bundle_gate.declarations(source)
    assert {"exported", "a_harness", "a_test", "tests"} <= set(declared), declared
    assert proofs == {"a_harness"}, proofs


@pytest.mark.parametrize("word", ["bounded proofs", "model check", "reviewed", ""])
def test_a_method_word_outside_the_vocabulary(tmp_path, word):
    """The kind rule reads this field, so a typo silently drops it: `bounded
    proofs` is not `bounded proof`, and the harness arm stops applying."""
    root = tree(tmp_path)
    rewrite(root, lambda doc: doc["method"][4].update({"method": word}))
    assert any("is in no row of §4.1's vocabulary" in p for p in findings(root)), findings(root)


def test_a_bound_written_as_prose_answers_something(tmp_path):
    """Half the bounds are numbers and `bound_totals` is a sentence, so requiring
    the KEY is satisfied by one bound reading `n/a` — measured green."""
    root = tree(tmp_path)

    def blank(doc):
        row = doc["method"][2]
        row[[k for k in row if k.startswith("bound_")][0]] = "n/a"

    rewrite(root, blank)
    assert any("which answers nothing" in p for p in findings(root)), findings(root)


def test_a_numeric_bound_is_never_a_non_answer(tmp_path):
    """`bound_reset_window = 0` is a real bound — the window exercised closed."""
    root = tree(tmp_path)
    doc = tomllib.loads((root / bundle_gate.BUNDLE).read_text())
    assert 0 in [r.get("bound_reset_window") for r in doc["method"]], doc["method"]
    assert findings(root) == []


def test_an_elided_harness_is_resolved_against_the_file_before_it(tmp_path):
    """`…_creds_begin_at_call_site` is a second harness in the file the token
    before it named, so it is the spelling a `::`-only reader walks past."""
    root = tree(tmp_path)
    edit(root, "…_creds_begin_at_call_site", "…_creds_begin_at_the_wrong_site")
    assert any("ends 0 declaration(s)" in p for p in findings(root)), findings(root)


@pytest.mark.parametrize("elision", ["…site", "…e", "…n", "...site"])
def test_an_elision_that_resolves_on_any_suffix(tmp_path, elision):
    """`…site` ends the antecedent's OWN harness — the second reference
    discharged by the first, which is the self-reference `superseded_by` refuses
    one function away. All four were EXIT=0."""
    root = tree(tmp_path)
    edit(root, "…_creds_begin_at_call_site", elision)
    assert any("declaration(s) of" in p for p in findings(root)), findings(root)


def test_an_elision_that_names_the_token_before_it(tmp_path):
    """The ambiguity count alone does not reach this one: `…rps_begin_at_call_site`
    ends exactly ONE declaration, and it is the harness the `::` token already
    named — one row, one proof, counted twice. Measured: dropping the
    already-named clause and keeping the count left all 169 cases green."""
    root = tree(tmp_path)
    edit(root, "…_creds_begin_at_call_site", "…rps_begin_at_call_site")
    assert any("ends 0 declaration(s)" in p for p in findings(root)), findings(root)


def test_a_bare_ellipsis_elides_nothing(tmp_path):
    """The symbol is falsy, so the resolver never went looking: EXIT=0."""
    root = tree(tmp_path)
    edit(root, "…_creds_begin_at_call_site", "…")
    assert any("elides nothing" in p for p in findings(root)), findings(root)


def test_an_extension_the_resolver_does_not_read_is_not_silence(tmp_path):
    """The `gives up, says nothing` arm: `.tlaa` in row 8 was skipped as prose
    because the row's OTHER token resolved, so `resolved > 0` and the typo was
    never looked at — EXIT=0, while `formal/DoesNotExist.tla` reddened."""
    root = tree(tmp_path)
    edit(root, "formal/RSKeySecurityState.tla", "formal/RSKeySecurityState.tlaa")
    assert any("extension this resolver does not read" in p for p in findings(root)), findings(root)


def test_a_bare_configuration_that_is_not_in_formal(tmp_path):
    """Four of the eight rows name a `.cfg` with no directory. Reading only
    `path::harness` leaves every one of them unresolved."""
    root = tree(tmp_path)
    edit(root, 'artifact = "Shipped.cfg"', 'artifact = "NoSuchThing.cfg"')
    assert any("is not in the tree" in p for p in findings(root)), findings(root)


def test_a_rust_file_named_without_its_harness(tmp_path):
    """A file resolves and proves nothing: the harness is what a bounded proof
    is identified by, and the file outlives any one of them."""
    root = tree(tmp_path)
    edit(root, "state_kani.rs::no_authorization_bypass_walk_owner", "state_kani.rs")
    assert any("names a Rust file and no `::harness`" in p for p in findings(root)), findings(root)


@pytest.mark.parametrize("escape", ["absolute", "dot-dot"])
def test_a_method_artifact_that_escapes_the_tree(tmp_path, escape):
    """Both spellings point at a file that really is there — in the REAL tree.
    `root / "/x"` is `/x` and `root / "../../x"` climbs out, so `is_file()`
    answers yes to each and "in the tree" is not what that checks."""
    root = tree(tmp_path)
    real = ROOT / "formal/Shipped.cfg"
    target = str(real) if escape == "absolute" else os.path.relpath(real, root)
    assert (root / target).is_file(), target
    edit(root, 'artifact = "Shipped.cfg"', f'artifact = "{target}"')
    assert any("is not in the tree" in p for p in findings(root)), findings(root)


def test_a_method_row_whose_artifact_is_only_prose(tmp_path):
    root = tree(tmp_path)
    edit(root, 'artifact = "Shipped.cfg"', 'artifact = "a careful reading of the code"')
    assert any("resolves nothing in the tree" in p for p in findings(root)), findings(root)


def test_prose_beside_a_reference_is_not_demanded_to_resolve(tmp_path):
    """Two rows trail off into prose — `bounds table`, `over …`. A rule that
    demanded every word resolve is one that gets switched off inside a week."""
    root = tree(tmp_path)
    edit(root, 'artifact = "Shipped.cfg"', 'artifact = "Shipped.cfg, read against B1/B2 and the ladder"')
    assert findings(root) == []


def test_a_blank_leaf_is_a_dropped_field(tmp_path):
    root = tree(tmp_path)
    edit(root, 'id = "SEC-FIDO-001"', 'id = ""')
    assert any("is empty" in p for p in findings(root)), findings(root)


@pytest.mark.parametrize(
    "value", ['"1.5 to 3x"', '"a few hours"', '"unknown"', '"~500 s"']
)
def test_a_cost_written_as_a_range_is_refused(tmp_path, value):
    """The whole point of the first closed slice is that its cost is MEASURED.
    An estimate in any of the three voids the measurement, and the design page
    is where the calibration counterpart's estimate is labelled as one."""
    root = tree(tmp_path)
    import re

    path = root / bundle_gate.BUNDLE
    path.write_text(
        re.sub(r"runner_seconds = [0-9.]+", f"runner_seconds = {value}", path.read_text(), count=1)
    )
    assert any("is not a number" in p for p in findings(root)), findings(root)


def test_a_cost_naming_a_log_that_is_in_no_artifact_row(tmp_path):
    """`[[artifact]].path` has 10 values and `[[cost]].artifact` 11, ten of them
    byte-identical and none of them joined: re-pointing all 11 at a log that is
    nowhere was EXIT=0."""
    root = tree(tmp_path)

    def repoint(doc):
        for row in doc["cost"]:
            row["artifact"] = "a log that does not exist anywhere.log"

    rewrite(root, repoint)
    assert any("the path of no `[[artifact]]` row" in p for p in findings(root)), findings(root)


def test_a_raw_artifact_with_no_cost_row(tmp_path):
    """The other direction. Item 10 is three numbers per artifact, so a log that
    nothing costs is a run whose cost was dropped."""
    root = tree(tmp_path)
    rewrite(root, lambda doc: doc["cost"].pop(0))
    assert any("with no `[[cost]]` row" in p for p in findings(root)), findings(root)


def test_a_cost_row_for_work_with_no_artifact_of_its_own(tmp_path):
    """The eleventh row is prose on purpose — the gates, the ledger axes and the
    adversarial review produced no log of their own — so the join is asked of a
    value shaped like a path and not of every value."""
    root = tree(tmp_path)
    doc = tomllib.loads((root / bundle_gate.BUNDLE).read_text())
    prose = [r["artifact"] for r in doc["cost"] if r["artifact"].startswith("the work")]
    assert len(prose) == 1, [r["artifact"] for r in doc["cost"]]
    assert findings(root) == []


def test_a_missing_cost_field_is_found(tmp_path):
    root = tree(tmp_path)
    import re

    path = root / bundle_gate.BUNDLE
    path.write_text(re.sub(r"peak_memory_mb = [0-9.]+\n", "", path.read_text(), count=1))
    assert any("the item measures three, not one" in p for p in findings(root)), findings(root)


def test_an_artifact_that_is_not_in_the_tree(tmp_path):
    root = tree(tmp_path)
    gone = tomllib.loads((root / bundle_gate.BUNDLE).read_text())["artifact"][0]["path"]
    (root / gone).unlink()
    assert any("is not a log" in p for p in findings(root)), findings(root)


def test_a_summarized_log_is_not_an_artifact(tmp_path):
    """The byte count is what tells the unedited output from a tidied one."""
    root = tree(tmp_path)
    target = tomllib.loads((root / bundle_gate.BUNDLE).read_text())["artifact"][0]["path"]
    (root / target).write_text("summary only\n")
    assert any("was edited is not the unedited output" in p for p in findings(root)), findings(root)


def test_a_mutation_with_no_direction_is_not_a_verdict(tmp_path):
    """Two of twenty-four co-refutation patches scored a kill for the INVERSE
    defect, and the tell was that every failure said 'should have succeeded'."""
    root = tree(tmp_path)
    edit(root, 'direction = "modelled"', 'direction = "red"')
    assert any("is not one of" in p for p in findings(root)), findings(root)


def test_an_inverse_kill_with_no_disposition_is_not_a_verdict(tmp_path):
    """`"inverse"` was in the vocabulary and cost nothing: `"banana"` was refused
    and the word that names a kill for the OPPOSITE defect published at exit 0.
    Refusing it outright would have been worse — the cheapest way past a refusal
    is to type `modelled`, which nothing here resolves against a real run."""
    root = tree(tmp_path)
    edit(root, 'direction = "modelled"', 'direction = "inverse"')
    assert any("an INVERSE kill is a finding about the mutant" in p for p in findings(root)), (
        findings(root)
    )


@pytest.mark.parametrize("value", ["banana", "", "modelled ", "superseded_by", "n/a"])
def test_an_inverse_disposition_outside_the_vocabulary(tmp_path, value):
    root = tree(tmp_path)
    rewrite(root, lambda doc: doc["mutation"][0].update(direction="inverse", disposition=value))
    assert any("is not one of ('superseded'" in p for p in findings(root)), findings(root)


def test_a_superseded_inverse_kill_names_the_row_that_replaced_it(tmp_path):
    root = tree(tmp_path)
    rewrite(root, lambda doc: doc["mutation"][0].update(
        direction="inverse", disposition="superseded", superseded_by="a mutant nobody drove"))
    assert any("names no OTHER row" in p for p in findings(root)), findings(root)


def test_an_inverse_kill_cannot_supersede_itself(tmp_path):
    """A plain membership test over the group's own names is satisfied by the
    row's own `mutant`, which is the claim with nothing behind it again."""
    root = tree(tmp_path)

    def selfsame(doc):
        row = doc["mutation"][0]
        row.update(direction="inverse", disposition="superseded", superseded_by=row["mutant"])

    rewrite(root, selfsame)
    assert any("names no OTHER row" in p for p in findings(root)), findings(root)


def test_an_inverse_kill_kept_as_a_finding_still_owes_its_reading(tmp_path):
    """`reading` is where the direction is argued, and it is the whole content of
    a row that admits its kill was for the other defect."""
    root = tree(tmp_path)

    def strip(doc):
        row = doc["mutation"][0]
        row.update(direction="inverse", disposition="kept-as-a-finding")
        row["reading"] = "   "

    rewrite(root, strip)
    assert any("with no `reading`" in p for p in findings(root)), findings(root)


@pytest.mark.parametrize("disposition", bundle_gate.DISPOSITIONS)
def test_a_disposed_inverse_kill_is_admitted_and_counted_apart(tmp_path, disposition):
    """The positive arm, and the reason the word is not simply refused: an
    inverse kill stays SAYABLE, and the success line says how many there are so
    it cannot be read as a verdict."""
    root = tree(tmp_path)

    def dispose(doc):
        rows = doc["mutation"]
        rows[0].update(direction="inverse", disposition=disposition,
                       superseded_by=rows[1]["mutant"])

    rewrite(root, dispose)
    problems, summary = bundle_gate.audit(root)
    assert problems == [], problems
    assert "9 mutation verdict(s) and 1 disposed as inverse" in summary, summary


@pytest.mark.parametrize(
    "key,old,new",
    [("gate_registry", "kani=4", "kani=99"),
     ("gate_registry", "cfgs=46", "cfgs=47"),
     ("gate_ledger", "walk=4", "walk=5"),
     ("gate_assumption", "FALSE=89", "FALSE=88"),
     ("gate_ghost", "24 routes", "25 routes"),
     ("gate_matrix", "1240 cells", "1241 cells")],
)
def test_a_transcribed_gate_line_that_the_gate_does_not_derive(tmp_path, key, old, new):
    """The second half of the hole `35afe59` named and did not close: editing
    `kani=4` to `kani=99` left `bundle-gate`, `evidence-gate` AND
    `assurance-gate` at EXIT=0, because `REQUIRED["result"]` names no field and
    the group is held only by a leaf floor of 18.

    `FALSE=88` is the arm that found a real one: the bundle said 88 and the tree
    has held 89 `AlwaysUvShipped = FALSE` configurations at every commit from
    `58df09d` to HEAD, so the number was wrong the day it was typed.
    """
    root = tree(tmp_path)

    def retype(doc):
        assert old in doc["result"][key], doc["result"][key]
        doc["result"][key] = doc["result"][key].replace(old, new)

    rewrite(root, retype)
    problems = findings(root)
    assert any(f"result.{key}" in p for p in problems), problems


@pytest.mark.parametrize("key", bundle_gate.GATE_RESULTS)
def test_a_transcribed_gate_line_with_its_numbers_taken_out(tmp_path, key):
    """Both rules above compare the numbers a line HAS, so a line with none
    satisfies them — the same spelling as the roster satisfied by one key, one
    rule over. It clears the leaf floor and the non-answer rule too."""
    root = tree(tmp_path)
    rewrite(root, lambda doc: doc["result"].update({key: "the gate was green"}))
    assert any("carries no number" in p for p in findings(root)), findings(root)


def test_a_result_line_transcribing_a_gate_this_file_cannot_derive(tmp_path):
    """The resolver's own lesson one group over: a `gate_*` key nothing knows how
    to check must say so rather than be skipped."""
    root = tree(tmp_path)
    rewrite(root, lambda doc: doc["result"].update({"gate_nobody": "nobody-gate: 7 things"}))
    assert any("cannot" in p and "derive" in p for p in findings(root)), findings(root)


@pytest.mark.parametrize("key", bundle_gate.GATE_RESULTS)
def test_a_transcribed_gate_line_deleted(tmp_path, key):
    """Deleting one leaves the group at 21 leaves against a floor of 18, so the
    volume rule cannot see it — the roster is what does."""
    root = tree(tmp_path)
    rewrite(root, lambda doc: doc["result"].pop(key))
    assert any(f"`result.{key}` is gone" in p for p in findings(root)), findings(root)


def cycle(doc, length, reading=None):
    """The first `length` rows inverse, each superseded by the next, the last by
    the first — every row a step and none of them a result."""
    rows = doc["mutation"]
    for order in range(length):
        rows[order].update(
            direction="inverse", disposition="superseded",
            superseded_by=rows[(order + 1) % length]["mutant"],
            reading=reading or f"row {order} is a step towards row {order + 1}",
        )


@pytest.mark.parametrize("length", [2, 3])
def test_a_superseded_by_cycle_corrects_nothing(tmp_path, length):
    """Self-reference was excluded and cycles were not: A superseded by B and B
    by A printed `8 mutation verdict(s) and 2 disposed as inverse` at EXIT=0,
    with neither mutant corrected."""
    root = tree(tmp_path)
    rewrite(root, lambda doc: cycle(doc, length))
    assert any("reaches no corrected mutant" in p for p in findings(root)), findings(root)


def test_a_group_that_disposed_of_every_row(tmp_path):
    """All ten rows inverse in a ten-cycle printed `0 mutation verdict(s) and 10
    disposed as inverse` at EXIT=0 — a table that killed nothing, published as
    one that killed ten."""
    root = tree(tmp_path)
    rewrite(root, lambda doc: cycle(doc, 10))
    problems = findings(root)
    assert any("under the floor of 8" in p for p in problems), problems


def test_every_inverse_row_carrying_the_same_reading(tmp_path):
    """The reading argues THIS row's direction. Ten `kept-as-a-finding` rows all
    reading `x` was EXIT=0, and so was one sentence copied across all ten."""
    root = tree(tmp_path)
    rewrite(root, lambda doc: cycle(doc, 3, reading="the same sentence, three times"))
    assert any("share one `reading`" in p for p in findings(root)), findings(root)


def test_the_disposition_register_on_a_row_it_is_not_about(tmp_path):
    """`disposition = "banana"` beside a `superseded_by` naming no row at all,
    on a `modelled` row, was silently accepted and never validated."""
    root = tree(tmp_path)

    def stray(doc):
        doc["mutation"][0].update(disposition="banana",
                                  superseded_by="a row that does not exist")

    rewrite(root, stray)
    assert any("the disposition register belongs to" in p for p in findings(root)), findings(root)


def test_a_reading_is_owed_by_every_direction_not_only_by_the_inverse_one(tmp_path):
    """The first version of the rule above refused `reading` on a `modelled` row
    and reddened all ten of the real bundle's — it argues whichever direction the
    row records, so it belongs on any of them."""
    root = tree(tmp_path)
    doc = tomllib.loads((root / bundle_gate.BUNDLE).read_text())
    assert all(str(row.get("reading", "")).strip() for row in doc["mutation"]), doc["mutation"]
    assert findings(root) == []


def test_a_mutation_that_does_not_say_which_assertion_fell(tmp_path):
    root = tree(tmp_path)
    import re

    path = root / bundle_gate.BUNDLE
    path.write_text(re.sub(r'fell = "[^"]*"\n', 'fell = ""\n', path.read_text(), count=1))
    assert any("is empty" in p for p in findings(root)), findings(root)


def test_a_property_the_registry_does_not_carry(tmp_path):
    root = tree(tmp_path)
    edit(root, 'id = "SEC-FIDO-001"', 'id = "SEC-NOPE-999"')
    assert any("is in no row of" in p for p in findings(root)), findings(root)


def test_a_group_outside_the_contract_is_refused(tmp_path):
    root = tree(tmp_path)
    path = root / bundle_gate.BUNDLE
    path.write_text(path.read_text() + '\n[extra]\nnote = "not a group"\n')
    assert any("is in no group of the contract" in p for p in findings(root)), findings(root)


def test_an_empty_roster_is_under_the_floor(tmp_path):
    (tmp_path / "assurance").mkdir()
    assert any("under the floor of" in p for p in findings(tmp_path)), findings(tmp_path)


def test_a_bundle_removed_from_the_roster_reddens(tmp_path):
    """The direction that matters: a closed slice unclosing itself, silently.

    The floor is passed as a PARAMETER at the SHIPPED value, so this case proves
    the rule about the number the tree actually ships rather than about a 1 the
    case wrote. Deleting one bundle from an n-bundle tree must leave n-1 < n.
    """
    root = tree(tmp_path)
    shipped = len(bundle_gate.bundles(root))
    assert shipped >= bundle_gate.ROSTER_FLOOR, shipped
    (root / bundle_gate.bundles(root)[0]).unlink()
    reported = bundle_gate.audit(root, roster_floor=shipped)[0]
    assert any("under the floor of" in p for p in reported), reported


def test_the_shipped_floor_is_not_above_the_shipped_roster():
    """A floor over the count is the row red on a tree nobody touched."""
    assert len(bundle_gate.bundles(ROOT)) >= bundle_gate.ROSTER_FLOOR


def test_a_second_bundle_is_audited_and_not_merely_counted(tmp_path):
    """The roster is the DIRECTORY: a file dropped in is held to the contract.

    Without this the generalisation is a counter — `len(glob)` past a floor —
    and a second bundle arrives green because nothing opens it. Measured on the
    first version, which globbed for the count and audited `BUNDLE`.
    """
    root = tree(tmp_path)
    first = bundle_gate.bundles(root)[0]
    text = (root / first).read_text().replace('id = "SEC-FIDO-001"', 'id = "SEC-FIDO-002"', 1)
    # Broken in ONE place, and in the place the contract turns on: a copy that is
    # merely valid proves only that the roster counted it.
    (root / bundle_gate.BUNDLE_DIR / "SEC-FIDO-002.toml").write_text(
        text[: text.index("[[cost]]")]
    )
    reported = findings(root)
    assert any("SEC-FIDO-002.toml" in p and "`cost`" in p for p in reported), reported


def test_a_bundle_named_for_a_property_it_does_not_carry(tmp_path):
    """A copy under a new name is the first slice twice, and every other rule
    passes it: same ten groups, same floors, same artifact digests."""
    root = tree(tmp_path)
    first = bundle_gate.bundles(root)[0]
    shutil.copy(root / first, root / bundle_gate.BUNDLE_DIR / "SEC-FIDO-007.toml")
    reported = findings(root)
    assert any("is named for" in p and "SEC-FIDO-007" in p for p in reported), reported


def test_a_bundle_that_is_not_readable_as_toml(tmp_path):
    """The glob finds it, so it must be a finding and not a traceback."""
    root = tree(tmp_path)
    (root / bundle_gate.BUNDLE_DIR / "SEC-FIDO-008.toml").write_text("[property\nid =")
    reported = findings(root)
    assert any("is not readable as TOML" in p for p in reported), reported


def test_main_prints_a_summary_and_reports_findings(tmp_path, capsys, monkeypatch):
    assert bundle_gate.main() == 0
    assert capsys.readouterr().out.startswith("bundle-gate: ok —")
    root = tree(tmp_path)
    edit(root, 'direction = "modelled"', 'direction = "red"')
    monkeypatch.setattr(bundle_gate, "ROOT", root)
    assert bundle_gate.main() == 1
    assert "direction" in capsys.readouterr().err


def test_a_transcribed_registry_count_is_this_property_s(tmp_path):
    """The corpus for `gate_registry` is EVERY property's vector joined, so a pair
    was compared against all of them: `rust=1` is true of thirty other rows, and a
    bundle whose own property had moved to `rust=2` kept the old number at exit 0.
    Found by a real move, not invented — tagging the producer of `SEC-FIDO-007`'s
    antecedent took its `rust` column up and this row stayed green."""
    root = tree(tmp_path)
    bundle = root / bundle_gate.BUNDLE
    doc = tomllib.loads(bundle.read_text())
    line = doc["result"]["gate_registry"]
    # A count that is real SOMEWHERE in the roster and wrong for this property.
    doc["result"]["gate_registry"] = re.sub(r"\bkani=\d+", "kani=1", line)
    bundle.write_text(dump(doc))
    reported = findings(root)
    assert any("gate_registry" in p and "kani=1" in p for p in reported), reported


def test_the_registry_line_picked_is_the_subject_s():
    corpus = "  SEC-FIDO-001 A rust=2\n  SEC-FIDO-007 B rust=9\n"
    assert "rust=9" in bundle_gate.registry_line(corpus, "SEC-FIDO-007")
    assert "rust=2" in bundle_gate.registry_line(corpus, "SEC-FIDO-001")
    # No subject, or one the roster does not carry: the whole corpus, which is
    # the previous behaviour and refuses nothing extra.
    assert bundle_gate.registry_line(corpus, "SEC-NOPE-999") == corpus
