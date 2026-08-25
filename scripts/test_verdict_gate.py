# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""The mutation table `verdict_gate.py` is verified against.

Every case drives the REAL `formal/floors.txt` over the REAL `formal/*.cfg`,
because a fixture registry over fixture configurations would be two new things
agreeing with each other — and the measured hole was in the tree's own file, not
in a shape.

The families are DERIVED, never listed. That is the whole difference between
this table and `test_run_tlc.py`, which names five configurations and so happens
to cover `Mut_` and `Solo_` and nothing else: measured on this tree, 23 of the 25
wildcard families and 102 of the 192 configurations had no cheap merge-gate
witness at all, and a `SeamMut_*.cfg RED` turned `GREEN` was green everywhere.
Add a family to `floors.txt` and it arrives here parametrized, which is the only
way a roster of 25 stays a roster of 25.

The floor arms are parametrized over the rows that HAVE a floor rather than over
the families, and that is not a gap: every one of the 25 families is a RED row
carrying `-`, because "a counterexample search halts at the first violation, so
its state count is worker-scheduling dependent" is the file's own rule — and
this table asserts that rule too, in both directions.
"""

import pathlib

import pytest

import verdict_gate

ROOT = pathlib.Path(__file__).resolve().parent.parent
FORMAL = ROOT / "formal"
REGISTRY = (FORMAL / "floors.txt").read_text(encoding="utf-8")
RUNNER = (FORMAL / "run-tlc.sh").read_text(encoding="utf-8")

#: The committed registry the floor arms compare against, resolved once through
#: the real git history — so the arms exercise the shipped comparison rather than
#: a fixture of one, and `previous_registry` itself is driven by a case below.
PREVIOUS = verdict_gate.previous_registry()

ROWS, RATCHETS, PARSE_PROBLEMS = verdict_gate.read_registry(REGISTRY)
FAMILIES = [row["pattern"] for row in ROWS if verdict_gate.GLOB.search(row["pattern"])]
FLOORED = [row["pattern"] for row in ROWS if row["floor"] is not None]
#: Subjects of a floor: the configurations a floored row decides, plus the
#: coverage ratchets, which are the same ratchet written `@Name value`.
SUBJECTS = FLOORED + sorted(RATCHETS)


def findings(text, previous=PREVIOUS, runner=RUNNER):
    problems, _ = verdict_gate.audit(
        FORMAL, registry_text=text, previous_text=previous, runner_text=runner)
    return problems


def rewrite(pattern, replacement):
    """`floors.txt` with `pattern`'s row replaced, or dropped when None."""
    kept, seen = [], False
    for line in REGISTRY.splitlines():
        parts = line.split()
        if parts and parts[0] == pattern:
            seen = True
            if replacement is not None:
                kept.append(replacement)
            continue
        kept.append(line)
    assert seen, f"{pattern} is no longer a row of floors.txt"
    return "\n".join(kept) + "\n"


def members(pattern):
    """The configurations a family decides, under first match."""
    rows, _, _ = verdict_gate.read_registry(REGISTRY)
    names = sorted(p.name for p in FORMAL.glob("*.cfg"))
    first, _ = verdict_gate.resolve(rows, names)
    return [n for n, hit in first.items() if hit and hit["pattern"] == pattern]


def about(problems, name):
    return [p for p in problems if p.startswith(f"{name}:")]


def test_the_registry_parses_and_the_tree_is_clean():
    """Both halves, because a parse that quietly dropped every row would make
    each case below loop over nothing and pass."""
    assert not PARSE_PROBLEMS, PARSE_PROBLEMS
    assert not findings(REGISTRY)


def test_there_are_families_and_floors_to_check():
    """A parametrization that matches nothing passes every case it generates.

    Both halves of `SUBJECTS` are floored, not their sum: deleting all six
    ratchets left the sum at exactly 20 and quietly dropped twelve cases.
    """
    assert len(FAMILIES) >= 25, FAMILIES
    assert len(FLOORED) >= 20, FLOORED
    assert len(RATCHETS) >= 6, RATCHETS
    assert all(members(pattern) for pattern in FAMILIES)


def test_the_previous_registry_is_read_from_git_and_differs():
    """The floor arms are worth nothing if the comparison is a file against
    itself, which is what `HEAD` would be on every CI checkout."""
    assert PREVIOUS is not None
    assert PREVIOUS != REGISTRY


# --- the four arms, on every wildcard family ------------------------------


@pytest.mark.parametrize("pattern", FAMILIES)
def test_a_family_flipped_to_green_is_rejected(pattern):
    """The measured miss, verbatim: `SeamMut_*.cfg RED` → `GREEN` was green in
    the targeted subset because the fixture names no configuration of that
    family. The verdict is read off the CONSTANTS here, so no family is named."""
    problems = findings(rewrite(pattern, f"{pattern} GREEN 999999"))
    for name in members(pattern):
        assert any("owes RED" in p for p in about(problems, name)), (name, problems[:3])


@pytest.mark.parametrize("pattern", FAMILIES)
def test_a_deleted_family_row_is_rejected(pattern):
    problems = findings(rewrite(pattern, None))
    for name in members(pattern):
        assert any("no verdict entry" in p for p in about(problems, name)), name


@pytest.mark.parametrize("pattern", FAMILIES)
def test_a_broad_row_above_a_family_is_rejected(pattern):
    """First match wins, so a broader glob laid on top decides everything the
    family used to. Its payload is IDENTICAL here on purpose: nothing disagrees,
    no verdict moves, and the family row simply stops being consulted — which is
    the silent half of the shape, and what makes it a masking rule rather than a
    duplicate one."""
    broad = pattern.split("*", 1)[0][:-1] + "*"
    problems = findings(f"{broad} RED -\n" + REGISTRY)
    assert any(f"`{pattern}` never decides anything" in p for p in problems), problems[:3]


@pytest.mark.parametrize("pattern", FAMILIES)
def test_a_wrong_reason_red_on_a_family_is_rejected(pattern):
    """A real invariant, of a module this family does not run: the colour is
    right and the reason is not, which is how 2 of 24 co-refutation patches in
    this tree scored a kill for the INVERSE defect."""
    mine = set().union(*(set(verdict_gate.Config(FORMAL / n).invariants)
                         for n in members(pattern)))
    every = set().union(*(set(verdict_gate.Config(p).invariants)
                          for p in FORMAL.glob("*.cfg")))
    stranger = sorted(every - mine)[0]
    problems = findings(rewrite(pattern, f"{pattern} RED - - {stranger}"))
    for name in members(pattern):
        assert any("does not check" in p for p in about(problems, name)), (name, stranger)


# --- the floor arm, on every row and ratchet that carries one --------------


def lowered(subject):
    """(the registry with `subject`'s floor weakened, the two numbers)."""
    if subject.startswith("@"):
        was = RATCHETS[subject]
        # A `Max` is the same ratchet upside down: it is weakened by RISING.
        now = was + 1 if subject.endswith("Max") else max(0, was - 1)
        return REGISTRY.replace(f"{subject} {was}", f"{subject} {now}"), was, now
    row = next(r for r in ROWS if r["pattern"] == subject)
    was = row["floor"]
    now = max(verdict_gate.MIN_FLOOR, was // 2)
    return rewrite(subject, f"{subject} {row['want']} {now}"), was, now


@pytest.mark.parametrize("subject", SUBJECTS)
def test_an_unjustified_floor_decrease_is_rejected(subject):
    text, was, now = lowered(subject)
    assert was != now, subject
    problems = findings(text)
    assert any(f"floor {was} -> {now} with no justification" in p
               for p in about(problems, subject)), (subject, problems[:3])


@pytest.mark.parametrize("subject", SUBJECTS)
def test_a_justified_floor_decrease_is_accepted(subject):
    """The rule is "say so", not "never" — a guard that refuses a re-measurement
    outright gets deleted the first week a model legitimately shrinks."""
    text, was, now = lowered(subject)
    said = f"\\* floor-decrease: {subject} {was} -> {now} re-measured after the scope moved\n"
    assert not about(findings(said + text), subject)


def test_a_justification_without_a_reason_is_not_one():
    subject = SUBJECTS[0]
    text, was, now = lowered(subject)
    bare = f"\\* floor-decrease: {subject} {was} -> {now}\n"
    assert about(findings(bare + text), subject)


def test_a_marker_for_a_movement_that_did_not_happen_is_rejected():
    """A justification outliving its decrease is how the file fills with
    dispositions for movements nobody can find any more — and it is the same
    branch that refuses a marker invented for a floor that never fell."""
    subject = SUBJECTS[0]
    _, was, now = lowered(subject)
    said = f"\\* floor-decrease: {subject} {was} -> {now} re-measured\n"
    assert any("not the movement the committed registry shows" in p
               for p in about(findings(said + REGISTRY), subject))


def test_a_floor_that_is_deleted_outright_is_a_decrease():
    """`GREEN 20000000` → `GREEN -` weakens more than any number would."""
    row = next(r for r in ROWS if r["pattern"] == "Shipped.cfg")
    problems = findings(rewrite("Shipped.cfg", "Shipped.cfg GREEN -"))
    assert any(f"floor {row['floor']} -> 0" in p for p in about(problems, "Shipped.cfg"))


def test_no_previous_registry_is_a_finding_not_a_pass():
    """A guard that reads a git failure as "nothing moved" goes green the day the
    command's spelling breaks."""
    text, _, _ = lowered("Shipped.cfg")
    problems = findings(text, previous=None)
    assert any("no floor could be compared" in p for p in problems), problems


# --- the shape of a row ---------------------------------------------------


def test_a_green_row_with_no_floor_is_rejected():
    problems = findings(rewrite("Seams.cfg", "Seams.cfg GREEN -"))
    assert any("`Seams.cfg`: GREEN with no floor" in p for p in problems), problems[:3]


def test_a_green_row_floored_where_the_runner_already_refuses_is_rejected():
    problems = findings(rewrite("Seams.cfg", "Seams.cfg GREEN 1"))
    assert any("under the 2 the runner already refuses" in p for p in problems), problems[:3]


def test_a_red_row_given_a_floor_is_rejected():
    """One finding, not fourteen: `SeamMut_*.cfg` decides fourteen configurations
    and a mistyped column says the same thing about all of them.

    The `== problems` half alone was `[] == []` when the rule was removed — the
    one case of the 32-mutation sweep that killed nothing, which is the family
    this whole file exists for.
    """
    problems = findings(rewrite("SeamMut_*.cfg", "SeamMut_*.cfg RED 5000"))
    assert any("RED with a floor of 5000" in p for p in problems), problems[:3]
    assert [p for p in problems if "RED with a floor of 5000" in p] == [p for p in problems]


def test_a_green_row_naming_an_invariant_is_rejected():
    """Nothing compares an invariant on a pass, so a name there is a claim the
    runner never reads — and reads exactly like one it does."""
    text = rewrite("Shipped.cfg", "Shipped.cfg GREEN 20000000 - NoAuthorizationBypass")
    assert any("nothing compares" in p for p in findings(text))


def test_a_verdict_that_is_neither_colour_is_rejected():
    assert any("neither GREEN nor RED" in p for p in findings(rewrite("Seams.cfg", "Seams.cfg OK 200")))


# --- what the registry is measured against --------------------------------


def test_an_orphaned_row_is_rejected():
    assert any("matches no configuration" in p
               for p in findings("Gone_*.cfg RED -\n" + REGISTRY))


def test_conflicting_rows_are_refused_rather_than_ordered():
    """The rule the first-match resolution hides: two rows over one
    configuration, disagreeing, and the file decides by line number."""
    problems = findings("Shipped.cfg RED -\n" + REGISTRY)
    assert any("disagree" in p for p in about(problems, "Shipped.cfg")), problems[:3]


def test_the_no_verdict_exemption_is_checked_in_both_directions(monkeypatch):
    assert any("registered as having no verdict entry" in p
               for p in about(findings("TokenExport.cfg GREEN 2\n" + REGISTRY), "TokenExport.cfg"))
    monkeypatch.setitem(verdict_gate.NO_VERDICT, "NoSuch.cfg", "gone")
    assert any("stale entry" in p for p in about(findings(REGISTRY), "NoSuch.cfg"))


def test_the_unswitched_red_carve_out_is_checked_in_both_directions(monkeypatch):
    monkeypatch.setitem(verdict_gate.UNSWITCHED_RED, "Mut_BugCredBeforeRp.cfg", "not really")
    problems = about(findings(REGISTRY), "Mut_BugCredBeforeRp.cfg")
    assert any("drop the carve-out" in p for p in problems), problems
    monkeypatch.setitem(verdict_gate.UNSWITCHED_RED, "NoSuch.cfg", "gone")
    assert any("stale entry" in p for p in about(findings(REGISTRY), "NoSuch.cfg"))


def test_the_carve_out_exempts_the_derivation_and_not_the_verdict():
    """Both directions above are about MEMBERSHIP, and neither asked what the row
    says — so the one configuration singled out for attention was the only one
    whose RED could be turned GREEN with this row happy. Found by review."""
    victim = sorted(verdict_gate.UNSWITCHED_RED)[0]
    problems = findings(rewrite(victim, f"{victim} GREEN 999999"))
    assert any("the carve-out exempts the derivation, not the verdict" in p
               for p in about(problems, victim)), problems[:3]


def test_a_red_attributed_to_the_type_predicate_is_rejected():
    """`TypeOK` is checked by every configuration and targeted by no mutant, so
    naming it attributes the RED to nothing while satisfying "it checks it"."""
    text = rewrite("TraceSecurityBadPinSet.cfg", "TraceSecurityBadPinSet.cfg RED - - TypeOK")
    assert any("attributes the RED to nothing" in p
               for p in about(findings(text), "TraceSecurityBadPinSet.cfg"))


def test_a_red_attributed_to_a_property_is_rejected():
    """`run-tlc.sh` greps `Invariant … is violated` and nothing else, so a
    temporal refutation has no name it could ever compare."""
    text = rewrite("LiveMut_*.cfg", "LiveMut_*.cfg RED - - EveryWalkCloses")
    assert any("a temporal refutation cannot be named here" in p
               for p in about(findings(text), "LiveMut_BugWalkNeverExpires.cfg"))


def test_a_deleted_ratchet_is_the_largest_decrease_there_is():
    """Lowering `@TraceSecurityGatesMin` by one is caught above; deleting the line
    was free, and only the six `security_trace.py` names by constant had any
    backstop at all."""
    without = "\n".join(l for l in REGISTRY.splitlines() if not l.startswith("@")) + "\n"
    problems = findings(without)
    for ratchet in RATCHETS:
        assert any("a deleted ratchet is the largest decrease" in p
                   for p in about(problems, ratchet)), ratchet


def test_a_solo_row_flipped_to_green_leaves_its_multi_target_twin_unattributable():
    """The coupling that makes a multi-target RED mean anything: `SeamMut_*`
    checks six invariants and names none, so what says which defect its RED
    describes is the sibling running the same switches against ONE."""
    problems = findings(rewrite("SeamSolo_*.cfg", "SeamSolo_*.cfg GREEN 999999"))
    assert any("RED for no stated reason" in p
               for p in about(problems, "SeamMut_BugSigPinNotSpent.cfg")), problems[:3]


# --- the runner and this row reading the same file ------------------------


def test_a_runner_that_cannot_read_a_digit_is_rejected():
    """`[A-Za-z]+` was the runner's extractor for its whole life and every `R4*`
    invariant has a DIGIT in its name, so nine rows printed a blank verdict
    column and compared nothing. It is a static disagreement between two files."""
    narrowed = RUNNER.replace("[A-Za-z][A-Za-z0-9_]*", "[A-Za-z]+", 1)
    assert narrowed != RUNNER
    problems = findings(REGISTRY, runner=narrowed)
    assert any("cannot read" in p for p in problems), problems[:3]
    assert len(problems) == sum(1 for row in ROWS if row["invariant"]), problems


def test_a_runner_with_no_reader_at_all_is_rejected():
    assert any("no longer extracts an invariant name" in p
               for p in findings(REGISTRY, runner="#!/usr/bin/env bash\n"))


def test_a_comment_is_a_comment_only_where_the_runner_says_so():
    """`run-tlc.sh` skips a line whose FIRST WORD is `\\*`; `\\*Shipped.cfg` is a
    glob to it. A parser more generous about comments than the runner is a
    parser reading a different registry."""
    assert not findings("\\* Shipped.cfg GREEN 1\n" + REGISTRY)
    assert findings("\\*Shipped.cfg GREEN 1\n" + REGISTRY)


def test_the_invariant_column_runs_to_the_end_of_the_line():
    """`read -r want floor heap inv` leaves everything past the fourth field in
    `inv`, so a remark after the name is part of the name the runner compares —
    and every run of that row prints `!! expected` forever."""
    text = rewrite("TraceSecurityBadPinSet.cfg",
                   "TraceSecurityBadPinSet.cfg RED - - R4cGateAnswers  and a remark")
    assert any("cannot read" in p for p in findings(text)), findings(text)[:3]


def test_a_carriage_return_is_a_finding_rather_than_a_fold():
    """`read` leaves the CR on the last field, `[ "$distinct" -lt "200\\r" ]` errors,
    bash reads the non-zero as false — and every floored row falls through to
    GREEN. `read_text` folds it away, which is why the audit asks the bytes."""
    problems = findings(REGISTRY.replace("\n", "\r\n"))
    assert any("carries a CR" in p for p in problems), problems[:3]


def test_a_pattern_the_two_would_expand_differently_is_refused():
    """A shell `case` expands `Boot[MS]*.cfg` and this row would read it as a
    literal, so the two would resolve different configurations from one file."""
    assert any("carries a character class" in p
               for p in findings("Boot[MS]*.cfg RED -\n" + REGISTRY))


def test_a_glob_does_not_fold_case():
    """`fnmatch` would, on this filesystem, and `case` never does."""
    assert verdict_gate.glob_to_regex("Solo_*.cfg").match("Solo_x.cfg")
    assert not verdict_gate.glob_to_regex("Solo_*.cfg").match("solo_x.cfg")


def test_a_malformed_row_is_a_finding_rather_than_a_traceback():
    """Each of these reaches an `int()` or an index if its own branch goes."""
    assert any("expected `<config or glob>" in p for p in findings("Lonely.cfg\n" + REGISTRY))
    assert any("floor must be a count" in p
               for p in findings(rewrite("Seams.cfg", "Seams.cfg GREEN lots")))
    assert any("expected `@Name <integer>`" in p
               for p in findings("@TraceSecurityGatesMin seven\n" + REGISTRY))
    assert any("recorded twice" in p
               for p in findings("@TraceSecurityGatesMin 1\n" + REGISTRY))


def test_the_configuration_floor_catches_a_glob_that_found_nothing(tmp_path):
    """The shape five guards in this tree shipped with: every loop runs over an
    empty set and the row reads as a pass."""
    problems, _ = verdict_gate.audit(tmp_path, registry_text=REGISTRY,
                                     previous_text=PREVIOUS, runner_text=RUNNER)
    assert any(f"under the floor of {verdict_gate.CONFIG_FLOOR}" in p for p in problems)
