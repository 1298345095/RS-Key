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
    """A checkout carrying the real bundle, the registry, every artifact and
    every file a method row's `artifact` names."""
    for relative in (bundle_gate.BUNDLE, bundle_gate.REGISTRY):
        (tmp_path / relative).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(ROOT / relative, tmp_path / relative)
    doc = tomllib.loads((ROOT / bundle_gate.BUNDLE).read_text())
    for relative in [row["path"] for row in doc["artifact"]] + list(method_targets(doc)):
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(ROOT / relative, target)
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


def test_the_three_rosters_name_the_same_ten_groups():
    """`GROUPS` without `FLOORS` is a KeyError; `FLOORS` without `GROUPS` is
    silently dead, and that is the direction nothing would have shown."""
    assert set(bundle_gate.GROUPS) == set(bundle_gate.FLOORS) == set(bundle_gate.REQUIRED)


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


def test_one_bound_key_of_any_name_satisfies_the_row(tmp_path):
    """Bounds are per method — a sequence length here, a cardinality there — so
    naming one key would be requiring the wrong one."""
    root = tree(tmp_path)

    def strip(doc):
        row = doc["method"][0]
        for key in [k for k in row if k.startswith("bound_")][1:]:
            row.pop(key)

    rewrite(root, strip)
    assert findings(root) == []


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
    """The reason the rule is a named pair of fields and not every leaf: eight
    method rows answer `cfg` and `features` with exactly `none`, and a global
    non-answer vocabulary would redden every one of them."""
    root = tree(tmp_path)
    doc = tomllib.loads((root / bundle_gate.BUNDLE).read_text())
    assert [r["cfg"] for r in doc["method"]].count("none") >= 4, doc["method"]
    assert findings(root) == []


def test_a_method_artifact_naming_a_harness_that_is_gone(tmp_path):
    """The measured hole: deleting one of the four harnesses left the exit at 0,
    and the bundle's own `kani=4` line green at 3."""
    root = tree(tmp_path)
    harness = root / "crates/rsk-fido/src/state_kani.rs"
    harness.write_text(
        harness.read_text().replace("no_authorization_bypass_walk_owner", "a_harness_by_another_name")
    )
    assert any("appears nowhere in" in p for p in findings(root)), findings(root)


def test_an_elided_harness_is_resolved_against_the_file_before_it(tmp_path):
    """`…_creds_begin_at_call_site` is a second harness in the file the token
    before it named, so it is the spelling a `::`-only reader walks past."""
    root = tree(tmp_path)
    edit(root, "…_creds_begin_at_call_site", "…_creds_begin_at_the_wrong_site")
    assert any("appears nowhere in" in p for p in findings(root)), findings(root)


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


def test_a_bundle_that_is_gone(tmp_path):
    (tmp_path / "assurance").mkdir()
    assert any("no such bundle" in p for p in findings(tmp_path)), findings(tmp_path)


def test_main_prints_a_summary_and_reports_findings(tmp_path, capsys, monkeypatch):
    assert bundle_gate.main() == 0
    assert capsys.readouterr().out.startswith("bundle-gate: ok —")
    root = tree(tmp_path)
    edit(root, 'direction = "modelled"', 'direction = "red"')
    monkeypatch.setattr(bundle_gate, "ROOT", root)
    assert bundle_gate.main() == 1
    assert "direction" in capsys.readouterr().err
