# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""One mutation per rule `threat_gate.py` states, both directions.

The fixture is a four-file tree — a threat model, a clause roster, a property
registry and the tranche ledger — because every rule here is about the fit
BETWEEN them, and a mutation of one has to be seen from the others. The floors
are monkeypatched down for the fixture and asserted at their real values against
the real tree, so a case cannot go red for the wrong reason (a six-clause fixture
under a floor of 44 reddens every case, and none of them for the rule it names).
"""

import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).parent))
import gate_lines
import threat_gate

DOC = "\n".join(
    [
        "# Threat model",
        "",
        "## Assets",
        "",
        "The seed, the passkeys, the PINs.",
        "",
        "## Attackers, strongest defense first",
        "",
        "### 1. A hostile host (malware on the computer)",
        "",
        "- **Protocol gates.** PINs/UV with retry counters, touch on FIDO.",
        "- What a hostile host **can** do: drive an operation you authorized.",
        "",
        "## Zeroization",
        "",
        "Key-grade material in RAM is wiped when its use ends.",
        "",
        "```mermaid",
        "sequenceDiagram",
        "    - this arrow is not a clause",
        "```",
        "",
    ]
)

CLAUSES = """
[[clause]]
id = "TM-TITLE"
kind = "context"
where = "# Threat model"
why = "the page's own title; every clause of it is an entry below"

[[clause]]
id = "TM-ASSETS"
kind = "context"
where = "## Assets"
why = "the asset inventory the rest of the page defends, not a threat"

[[clause]]
id = "TM-ATTACKERS"
kind = "context"
where = "## Attackers, strongest defense first"
why = "a container heading; each attacker below is a clause of its own"

[[clause]]
id = "TM-HOST"
kind = "defence"
where = "### 1. A hostile host (malware on the computer)"

[[clause]]
id = "TM-HOST-GATES"
kind = "defence"
where = "- **Protocol gates.** PINs/UV with retry counters, touch on FIDO."

[[clause]]
id = "TM-HOST-AUTHORIZED-OPS"
kind = "context"
where = "- What a hostile host **can** do: drive an operation you authorized."
why = "a stated residual: what an authorized key deliberately does not prevent"

[[clause]]
id = "TM-ZEROIZATION"
kind = "defence"
where = "## Zeroization"

[[untraced]]
id = "SEC-STORE-001"
verdict = "missing-clause"
why = "the page states no power-interruption threat, and a torn delete is one"
"""

PROPERTIES = """
[[property]]
id = "SEC-FIDO-001"
name = "NoAuthorizationBypass"
status = "BOUNDED"
statement = "s"
source = ["CTAP 2.3 §6.5", "docs/threat-model.md#TM-HOST-GATES"]

[[property]]
id = "SEC-FIDO-007"
name = "RamNeverOutlivesFlashSeed"
status = "MODELLED-ONLY"
statement = "s"
source = ["docs/threat-model.md#TM-ZEROIZATION"]

[[property]]
id = "SEC-STORE-001"
name = "NoOrphanedMetadata"
status = "MODELLED-ONLY"
statement = "s"
source = ["docs/store-refinement.md"]

[[property]]
id = "SEC-ADM-001"
name = "AdminSurfaceAlwaysReachable"
status = "MODELLED-ONLY"
statement = "s"
source = ["docs/threat-model.md"]
"""

LEDGER = """
[tranche]
p0-launch = ["SEC-FIDO-001", "SEC-FIDO-007", "SEC-STORE-001"]
p0b = []
p1 = ["SEC-ADM-001"]
out-of-queue = []
"""


@pytest.fixture
def tree(tmp_path, monkeypatch):
    """A four-file checkout the gate is pointed at, with the floors scaled to it."""
    (tmp_path / "docs").mkdir()
    (tmp_path / "assurance").mkdir()
    (tmp_path / "docs" / "threat-model.md").write_text(DOC, encoding="utf-8")
    (tmp_path / "docs" / "store-refinement.md").write_text("prose", encoding="utf-8")
    (tmp_path / threat_gate.CLAUSES).write_text(CLAUSES, encoding="utf-8")
    (tmp_path / threat_gate.REGISTRY).write_text(PROPERTIES, encoding="utf-8")
    (tmp_path / threat_gate.LEDGER).write_text(LEDGER, encoding="utf-8")
    monkeypatch.setattr(threat_gate, "FLOOR_CLAUSES", 7)
    monkeypatch.setattr(threat_gate, "FLOOR_P0", 3)
    return tmp_path


def problems(tree):
    return threat_gate.audit(tree)[0]


def edit(tree, path, old, new):
    target = tree / path
    text = target.read_text(encoding="utf-8")
    assert old in text, old
    target.write_text(text.replace(old, new, 1), encoding="utf-8")


def test_the_fixture_is_clean(tree):
    """A table whose baseline is already red proves nothing below it."""
    assert problems(tree) == []


def test_the_shipped_tree_is_clean():
    """No fixture and the real floors: this is the row `check.sh` runs."""
    assert threat_gate.audit(threat_gate.ROOT)[0] == []


def test_the_shipped_ratchets_are_this_trees_counts():
    """The floors and the ceiling, AT the tree rather than under it.

    Every case below monkeypatches them, so nothing pinned their shipped values:
    measured, `FLOOR_CLAUSES = FLOOR_P0 = 0` and `CEILING_UNTRACED = 999` left
    the whole table green. The sibling this file borrows its constants from
    closed the same hole in `test_matrix_gate.py`.
    """
    root = threat_gate.ROOT
    doc = (root / threat_gate.DOC).read_text(encoding="utf-8")
    assert threat_gate.FLOOR_CLAUSES == len(threat_gate.clause_units(doc))
    assert threat_gate.FLOOR_P0 == len(threat_gate.p0_family(root))
    untraced = threat_gate.load(root, threat_gate.CLAUSES)["untraced"]
    assert threat_gate.CEILING_UNTRACED == len(untraced)


def test_a_new_bullet_is_a_clause_nobody_classified(tree):
    edit(
        tree,
        "docs/threat-model.md",
        "## Zeroization",
        "- **Fuzzing.** Every parser has a target.\n\n## Zeroization",
    )
    assert any("nobody classified" in p for p in problems(tree)), problems(tree)


def test_a_reworded_clause_rots_its_roster_entry(tree):
    """The lock is the clause's first line, so a reword is a citation moving."""
    edit(
        tree,
        "docs/threat-model.md",
        "- **Protocol gates.** PINs/UV with retry counters, touch on FIDO.",
        "- **Protocol gates.** PINs/UV, touch on FIDO.",
    )
    found = problems(tree)
    assert any("not a clause of" in p and "TM-HOST-GATES" in p for p in found), found


def test_a_deleted_clause_rots_its_roster_entry(tree):
    """The other spelling of the same edit: removed, not reworded."""
    edit(tree, "docs/threat-model.md", "## Zeroization\n", "")
    found = problems(tree)
    assert any("not a clause of" in p and "TM-ZEROIZATION" in p for p in found), found


def test_text_inserted_above_a_clause_does_not_rot_it(tree):
    """The reason `where` is content and not a line number.

    `formal/citations.lock` pays for the other choice: any inserted line shifts
    every citation below it, and re-pointing them is where five agents have gone
    wrong. A clause that only moved down the page is not a finding.
    """
    edit(tree, "docs/threat-model.md", "## Assets", "One more paragraph.\n\n## Assets")
    assert problems(tree) == []


@pytest.mark.parametrize(
    "marker",
    ["* **Fuzzing.** Every parser has a target.",
     "+ **Fuzzing.** Every parser has a target.",
     "1. **Fuzzing.** Every parser has a target.",
     "#### Fuzzing",
     "###### Fuzzing"],
)
def test_a_clause_in_another_spelling_is_still_a_clause(tree, marker):
    """The page writes `-` and `##`; the same clause by another hand is `*`, `+`,
    an ordered item or a deeper heading. A derivation that cannot SEE one is the
    only direction that fails green, so every marker CommonMark takes counts."""
    edit(tree, "docs/threat-model.md", "## Zeroization", f"{marker}\n\n## Zeroization")
    assert any("nobody classified" in p for p in problems(tree)), problems(tree)


@pytest.mark.parametrize("rule", ["=", "=======", "-", "--", "---", "-------"])
def test_a_setext_heading_is_refused_rather_than_missed(tree, rule):
    """The one heading spelling no regex above can read; refuse it out loud.

    Every underline length, because the first draft demanded `-{3,}` and
    CommonMark makes a SINGLE `-` an H2 — the rule written for one spelling,
    inside the guard written to close that.
    """
    edit(tree, "docs/threat-model.md", "## Zeroization", f"Fuzzing\n{rule}\n\n## Zeroization")
    found = problems(tree)
    assert any("setext heading" in p for p in found), found


@pytest.mark.parametrize(
    "shape",
    ["> - **Rate limiting.** A callout.",
     "> **Rate limiting.** A callout.",
     "| Threat | Defence |",
     "<ul><li><b>Rate limiting.</b> In HTML.</li></ul>"],
)
def test_a_clause_in_a_shape_this_row_cannot_read_is_refused(tree, shape):
    """A blockquote, a table row or an HTML list can each carry a clause and
    none of them is a heading or a list item. A table is the likeliest — this
    repo's other docs enumerate exactly this kind of thing in one."""
    edit(tree, "docs/threat-model.md", "## Zeroization", f"{shape}\n\n## Zeroization")
    found = problems(tree)
    assert any("cannot read" in p or "invisible" in p for p in found), found


def test_a_thematic_break_between_blank_lines_is_not_one(tree):
    """The other arm: an ordinary `---` rule is legal markdown, not a heading."""
    edit(tree, "docs/threat-model.md", "## Zeroization", "---\n\n## Zeroization")
    assert problems(tree) == []


def test_trailing_whitespace_is_not_a_clause_moving(tree):
    """`where` is the clause's text, and two trailing spaces are not a rewrite."""
    edit(
        tree,
        "docs/threat-model.md",
        "- **Protocol gates.** PINs/UV with retry counters, touch on FIDO.",
        "- **Protocol gates.** PINs/UV with retry counters, touch on FIDO.  ",
    )
    assert problems(tree) == []


def test_a_tilde_fence_hides_its_contents_too(tree):
    """`~~~` is the other fence CommonMark takes, and a `-` line inside one is
    no more a clause than a `-` line inside a mermaid diagram."""
    edit(tree, "docs/threat-model.md", "## Zeroization", "~~~\n- not a clause\n~~~\n\n## Zeroization")
    assert problems(tree) == []


def test_an_arrow_inside_a_fence_is_not_a_clause(tree):
    """The mermaid diagram carries `-` lines; reading them as clauses would put
    the roster permanently one entry short of a page nobody can classify."""
    assert "- this arrow is not a clause" in (tree / "docs/threat-model.md").read_text()
    assert problems(tree) == []


def test_a_p0_row_with_no_clause_and_no_verdict_is_refused(tree):
    edit(tree, threat_gate.CLAUSES, '\n[[untraced]]\nid = "SEC-STORE-001"', '\n[[unused]]\nid = "x"')
    found = problems(tree)
    assert any("no untraced verdict" in p and "SEC-STORE-001" in p for p in found), found


def test_the_bare_file_name_does_not_trace_a_p0_row(tree):
    """What 34 rows said. Naming the page names no threat."""
    edit(tree, threat_gate.REGISTRY, '"docs/store-refinement.md"', '"docs/threat-model.md"')
    found = problems(tree)
    assert any("say WHICH clause" in p for p in found), found


def test_the_tranche_is_what_decides_the_bare_spelling(tree):
    """The rule is scoped to the P0 family on purpose, so prove BOTH arms.

    `SEC-ADM-001` cites the page as a whole and is clean because it is `p1`; the
    same source text in `p0b` is a finding. A rule that reddened it either way
    would be a wider change wearing this one's justification, and one that
    reddened it neither way would be no rule at all.
    """
    assert all("SEC-ADM-001" not in p for p in problems(tree))
    # MOVED, not copied: `matrix_gate.py` owns the "in two tranches" rule, and a
    # property in both reads as the later one here.
    edit(tree, threat_gate.LEDGER, 'p0b = []', 'p0b = ["SEC-ADM-001"]')
    edit(tree, threat_gate.LEDGER, 'p1 = ["SEC-ADM-001"]', "p1 = []")
    found = problems(tree)
    assert any("SEC-ADM-001" in p and "say WHICH clause" in p for p in found), found


def test_a_clause_id_that_does_not_exist_is_refused(tree):
    edit(tree, threat_gate.REGISTRY, "#TM-ZEROIZATION", "#TM-ZEROISATION")
    found = problems(tree)
    assert any("is no clause of" in p for p in found), found


@pytest.mark.parametrize(
    "spelling",
    ["docs/threat-model.md#tm-zeroization",
     "./docs/threat-model.md#TM-ZEROIZATION",
     "docs/threat-model.md #TM-ZEROIZATION",
     "threat-model.md#TM-ZEROIZATION"],
)
def test_a_clause_reference_this_row_cannot_resolve_is_refused(tree, spelling):
    """Each of these falls through every rule while LOOKING like a citation."""
    edit(tree, threat_gate.REGISTRY, "docs/threat-model.md#TM-ZEROIZATION", spelling)
    found = problems(tree)
    assert any("cannot resolve" in p for p in found), found


def test_a_missing_input_is_a_sentence_not_a_traceback(tree):
    """Red either way; only one of the two says what to do about it."""
    (tree / threat_gate.CLAUSES).unlink()
    found = problems(tree)
    assert found == [f"{threat_gate.CLAUSES} is missing — the mapping is unchecked"]


def test_unparseable_toml_is_a_sentence_not_a_traceback(tree):
    (tree / threat_gate.CLAUSES).write_text("[[clause]\nid =", encoding="utf-8")
    found = problems(tree)
    assert len(found) == 1 and "cannot be read" in found[0], found


def test_an_empty_roster_does_not_pass_vacuously(tree):
    """A rule that loops over nothing holds over nothing."""
    (tree / threat_gate.CLAUSES).write_text("# nothing here\n", encoding="utf-8")
    found = problems(tree)
    assert sum("nobody classified" in p for p in found) == 7, found


def test_a_context_clause_cannot_be_served(tree):
    """"Serving" the asset list is not a claim, so citing one is a finding."""
    edit(tree, threat_gate.REGISTRY, "#TM-ZEROIZATION", "#TM-ASSETS")
    found = problems(tree)
    assert any("not a `defence`" in p and "TM-ASSETS" in p for p in found), found


def test_a_stale_untraced_entry_is_refused(tree):
    """The exemption outliving its finding — `assurance_gate.py`'s own rule."""
    edit(
        tree,
        threat_gate.REGISTRY,
        '"docs/store-refinement.md"',
        '"docs/threat-model.md#TM-HOST"',
    )
    found = problems(tree)
    assert any("stale" in p and "SEC-STORE-001" in p for p in found), found


def test_an_untraced_verdict_must_be_one_of_the_two(tree):
    edit(tree, threat_gate.CLAUSES, 'verdict = "missing-clause"', 'verdict = "later"')
    found = problems(tree)
    assert any("is not one of" in p and "SEC-STORE-001" in p for p in found), found


def test_an_untraced_shrug_is_refused(tree):
    edit(
        tree,
        threat_gate.CLAUSES,
        'why = "the page states no power-interruption threat, and a torn delete is one"',
        'why = "TODO"',
    )
    found = problems(tree)
    assert any("under" in p and "words" in p and "SEC-STORE-001" in p for p in found), found


def test_an_untraced_entry_for_a_row_outside_the_p0_family_is_refused(tree):
    edit(tree, threat_gate.CLAUSES, 'id = "SEC-STORE-001"\nverdict', 'id = "SEC-ADM-001"\nverdict')
    found = problems(tree)
    assert any("not a P0-family property" in p for p in found), found


def test_the_untraced_ceiling_holds(tree, monkeypatch):
    """A finding register that grows silently is a hatch."""
    monkeypatch.setattr(threat_gate, "CEILING_UNTRACED", 0)
    found = problems(tree)
    assert any("over the ceiling" in p for p in found), found


def test_a_context_clause_owes_its_argument(tree):
    edit(
        tree,
        threat_gate.CLAUSES,
        'why = "the asset inventory the rest of the page defends, not a threat"',
        'why = "n/a"',
    )
    found = problems(tree)
    assert any("TM-ASSETS" in p and "no argument" in p for p in found), found


def test_a_clause_kind_outside_the_two_is_refused(tree):
    edit(tree, threat_gate.CLAUSES, 'id = "TM-HOST"\nkind = "defence"', 'id = "TM-HOST"\nkind = "note"')
    found = problems(tree)
    assert any("is not one of" in p and "TM-HOST" in p for p in found), found


def test_a_clause_id_source_cannot_cite_is_refused(tree):
    """`REF` takes `TM-` and upper case; anything else is an entry no `source`
    can name, and the failure would otherwise surface as a message blaming the
    citing row's spelling."""
    edit(tree, threat_gate.CLAUSES, 'id = "TM-HOST"\nkind', 'id = "TM-Host"\nkind')
    found = problems(tree)
    assert any("not a clause id" in p for p in found), found


def test_a_clause_entry_missing_a_field_is_refused(tree):
    edit(tree, threat_gate.CLAUSES, 'where = "## Zeroization"\n', "")
    found = problems(tree)
    assert any("has no id or no `where`" in p for p in found), found


def test_an_untraced_entry_with_no_id_is_refused(tree):
    edit(tree, threat_gate.CLAUSES, '[[untraced]]\nid = "SEC-STORE-001"\n', "[[untraced]]\n")
    found = problems(tree)
    assert any("has no id" in p for p in found), found


def test_a_property_untraced_twice_is_refused(tree):
    """One row, one verdict: two entries can carry two different ones."""
    text = (tree / threat_gate.CLAUSES).read_text(encoding="utf-8")
    block = text[text.index("[[untraced]]"):]
    (tree / threat_gate.CLAUSES).write_text(text + "\n" + block, encoding="utf-8")
    found = problems(tree)
    assert any("untraced twice" in p for p in found), found


def test_a_duplicate_clause_id_is_refused(tree):
    edit(tree, threat_gate.CLAUSES, 'id = "TM-ZEROIZATION"', 'id = "TM-HOST"')
    found = problems(tree)
    assert any("duplicate clause id" in p for p in found), found


def test_two_entries_claiming_one_clause_are_refused(tree):
    """The mirror of the rule above: one page unit, one classification. Two of
    them can disagree about `kind`, and whichever came first would win."""
    edit(tree, threat_gate.CLAUSES, 'where = "## Zeroization"', 'where = "## Assets"')
    found = problems(tree)
    assert any("claim the same clause" in p for p in found), found


def test_two_clauses_that_read_alike_are_refused(tree):
    """The roster addresses a clause by its text; two of them cannot be told apart."""
    edit(tree, "docs/threat-model.md", "## Zeroization", "## Assets\n\n## Zeroization")
    found = problems(tree)
    assert any("read identically" in p for p in found), found


def test_a_source_naming_a_file_that_is_not_there_is_refused(tree):
    """The hook stages 9C/9D/10 land on: `docs/ct-audit.md`, `docs/unsafe.md`
    and `docs/limitations.md` are cited by nothing yet, and a citation of a page
    that moved reads as authoritative while pointing at nothing."""
    edit(tree, threat_gate.REGISTRY, '"docs/store-refinement.md"', '"docs/ct-audit.md"')
    found = problems(tree)
    assert any("not in the tree" in p for p in found), found


def test_the_clause_floor_is_not_vacuous(tree, monkeypatch):
    """A derivation that finds nothing satisfies every rule above it."""
    monkeypatch.setattr(threat_gate, "FLOOR_CLAUSES", 44)
    found = problems(tree)
    assert any("under the floor" in p for p in found), found


def test_the_p0_floor_is_not_vacuous(tree):
    """The tranche lists are another file's, so an emptied one arrives silently."""
    edit(tree, threat_gate.LEDGER, 'p0-launch = ["SEC-FIDO-001", "SEC-FIDO-007", ', "p0-launch = [")
    found = problems(tree)
    assert any("under the floor" in p and "P0-family" in p for p in found), found


def test_check_sh_runs_this_gate():
    """The row, with its flags — a name match cannot pin those.

    `test_gate_scripts.py` covers the set; this covers the invocation, the way
    `crate_graph` and `security_trace` pin theirs.
    """
    text = (threat_gate.ROOT / "scripts/check.sh").read_text()
    assert gate_lines.runs(text, "scripts/threat_gate.py"), "check.sh does not run it"
    assert 'run "threat-model traceability" python scripts/threat_gate.py' in text
