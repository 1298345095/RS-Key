# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""The rule the guards cannot state about themselves: every one is wired in.

Each `scripts/*_gate.py` asserts that `check.sh` runs *it* and that its own test
file is named after it. Neither direction covers the case that actually happens:
a new guard lands with no tests, or with tests nothing collects, and every
existing assertion stays green because none of them has heard of it. Found by
review, in the same pass that found four holes in the guards themselves.

Deliberately not inside one of the guards: it is a fact about the set of them,
and putting it in whichever one happened to be written last is how it comes to be
deleted with that one.

Both of its rules then shipped with a hole of that same family, found by the next
review and measured on the whole set rather than on the guard that prompted it. A
row can be COMMENTED OUT: the roster compared `check.sh`'s raw text while the
comment-cut written here for exactly that was applied only to `NAMED`, and all
eleven `*_gate.py` rows commented out at once left `pytest scripts -q` identical
to its baseline. And a table can be EMPTIED: the roster asked `is_file()` and
nothing else, so truncating one to its SPDX line took 241 cases out of the suite
with zero new failures. Deleting either — the line, the file — was caught, which
is what made the pair look covered.
"""

import pathlib
import re

import gate_lines

ROOT = pathlib.Path(__file__).resolve().parent.parent
HERE = pathlib.Path(__file__).resolve().parent

#: A gate script: run by `check.sh`, owed a mutation table. `gate_lines.py` is a
#: shared helper with no rule of its own, and the two `gate_*.py` spellings that
#: predate the convention are named here rather than pattern-matched, so the
#: pattern stays exact.
GATES = sorted(p.name for p in HERE.glob("*_gate.py") if not p.name.startswith("test_"))
#: Guards the `*_gate.py` pattern cannot reach, so they are owed a table by name
#: rather than by glob. Each value is **(mutation table, the file that runs it)**:
#: these guards are not wired in the same place, and "it has a table" says nothing
#: about whether anything invokes it — which is the half that goes missing. Each
#: once had no table at all, the same blind spot one file over; `run-tlc.sh` and
#: `kani.sh` are additionally not `check.sh` rows at all, so a rule that assumed
#: they were would be satisfied by the comments that name them.
NAMED = {
    "../formal/run-tlc.sh": ("test_run_tlc.py", "../.github/workflows/deep-checks.yml"),
    # The config generator: `config_gen_gate.py` is only as good as the script it
    # re-runs, and nothing else in `scripts/` names it — that guard IS its runner.
    "../formal/gen-configs.sh": ("test_config_gen_gate.py", "config_gen_gate.py"),
    "impact.py": ("test_impact.py", "hooks/pre-commit"),
    "kani.sh": ("test_kani_sh.py", "../.github/workflows/ci.yml"),
    "comutate.py": ("test_comutate.py", "check.sh"),
    "crate_graph.py": ("test_crate_graph.py", "check.sh"),
    # The font generator, the second of that shape: `check.sh` runs its `--check`
    # as a row, the name does not end in `_gate.py`, and it landed with no table.
    "generate_ui_fonts.py": ("test_generate_ui_fonts.py", "check.sh"),
    # The two `formal/` mappers: both are `check.sh` rows, neither ends in
    # `_gate.py`, so their tables could have been deleted with this file green.
    "security_trace.py": ("test_security_trace.py", "check.sh"),
    "trace_map.py": ("test_trace_map.py", "check.sh"),
}
#: The pytest invocation that has to reach the tests, wherever it is spelled.
COLLECTS = re.compile(r"pytest\s+([^\n|;&]*)")

#: A case of a mutation table. Counted as written rather than as pytest collects
#: it: a parametrized table counts higher either way, and re-entering pytest to
#: find that out costs more than the rule is worth.
CASE = re.compile(r"^def test_", re.M)

#: What a mutation table must carry. The smallest in the tree has 8 cases, so
#: this catches the COLLAPSE and not a slide — and the collapse is what was
#: measured: `test_verdict_gate.py` truncated to its SPDX line took 241 cases out
#: of `pytest scripts -q` with ZERO new failures, because the rule below asked
#: only whether the file exists. What it still does not cover: this file, which
#: is a table nothing else is a roster for, and the aggregate — `pytest` exits 5
#: on a collection of nothing, and no row floors it above that.
TABLE_FLOOR = 5


def check_sh():
    return (ROOT / "scripts/check.sh").read_text()


def test_there_are_gates_to_check():
    """A glob that matches nothing loops over nothing and passes every case below."""
    assert len(GATES) >= 4, GATES


def test_every_gate_is_run_by_check_sh():
    """The row's CODE, because a `#` in front of it is not a row.

    This compared the file's raw text and `code()` — written in this file for
    exactly that, citing the `kani_gate.py` precedent — was applied only to
    `NAMED`. Measured: all eleven `*_gate.py` rows commented out at once left
    `pytest scripts -q` identical to its baseline, while deleting one line
    outright was caught.
    """
    missing = [g for g in GATES if not gate_lines.runs(check_sh(), f"scripts/{g}")]
    assert not missing, f"check.sh runs none of {missing}"


def tables():
    """(guard, its mutation table) for both halves of the roster."""
    return [(g, f"test_{g}") for g in GATES] + [(g, t) for g, (t, _) in NAMED.items()]


def test_every_gate_has_a_mutation_table():
    missing = [g for g, table in tables() if not (HERE / table).is_file()]
    assert not missing, f"no scripts/test_<name>.py for {missing}"


def test_every_mutation_table_has_cases_in_it():
    """A file, not an empty one: the rule above asked `is_file()` and nothing
    else, so truncating `test_verdict_gate.py` to its SPDX line took 241 cases
    out of the suite with zero new failures. Deleting it outright was caught —
    which is the pair that says the hole is the emptying, not the removal."""
    empty = {table: len(CASE.findall((HERE / table).read_text()))
             for _, table in tables()
             if (HERE / table).is_file()
             and len(CASE.findall((HERE / table).read_text())) < TABLE_FLOOR}
    assert not empty, f"mutation tables under the floor of {TABLE_FLOOR}: {empty}"


def test_the_named_guards_still_exist():
    """A table kept for a guard that went away is one nobody will notice go stale."""
    missing = [g for g in NAMED if not (HERE / g).is_file()]
    assert not missing, f"{missing} are named here but not in scripts/"


def wired_in(guard, runner_text):
    """Whether the runner's code — not its prose — names `guard`.

    `gate_lines.runs` rather than a comment-cut written here: this file had one,
    and having it in the file that needed it did not stop the rule above from
    comparing raw text instead. The eight guards that assert their own row in
    their own table read it from there too now.
    """
    return gate_lines.runs(runner_text, pathlib.PurePath(guard).name)


def test_every_named_guard_is_run_by_its_stated_runner():
    """The property the glob half already has, for the half that lacked it.

    `test_every_gate_is_run_by_check_sh` covers `GATES` and nothing covered
    `NAMED`, so an entry could arrive with a table, a file, and nothing invoking
    it. Three tables do assert it (`crate_graph`, `security_trace`,
    `generate_ui_fonts`) — by convention, one guard at a time, which is how the
    fourth arrives without one. Those stay: they pin the exact row including its
    flags, which a name match cannot.
    """
    missing = [
        (guard, runner)
        for guard, (_, runner) in NAMED.items()
        # A runner that is not there is one cause, and the test below owns it —
        # reading it here would report the same cause a second time, as a
        # traceback rather than a sentence.
        if (HERE / runner).is_file()
        and not wired_in(guard, (HERE / runner).read_text())
    ]
    assert not missing, f"named but invoked nowhere in their runner: {missing}"


def test_the_named_runners_still_exist():
    """A runner that moved makes the rule above vacuous rather than red."""
    missing = [r for _, r in NAMED.values() if not (HERE / r).is_file()]
    assert not missing, f"{missing} are named as runners but do not exist"


def test_a_comment_is_not_an_invocation():
    """The rule above is only worth having if prose cannot satisfy it."""
    assert wired_in("kani.sh", "        run: ./scripts/kani.sh pr")
    assert not wired_in("kani.sh", "# the weekly row runs scripts/kani.sh")
    assert not wired_in("kani.sh", "true # scripts/kani.sh all")
    assert not wired_in("kani.sh", "   \n\n")


def test_the_mutation_tables_are_collected():
    """`check.sh` collects the directory, so a new table is registered by name.

    Over each row's CODE, like every other rule here: reading the raw text left a
    `#` in front of the `pytest scripts` row switching off every mutation table in
    the tree with this suite green. That is the third place the comment-cut was
    owed and the second time it was missed.
    """
    code = [gate_lines.split_at_comment(body)[0] for _indent, body in gate_lines.logical_lines(check_sh())]
    runs = [m.group(1) for line in code for m in COLLECTS.finditer(line)]
    assert any("scripts" in words for words in runs), runs


def test_every_gate_reports_a_summary_when_it_is_happy():
    """A guard that prints nothing on success is one nobody notices going quiet."""
    for name in GATES:
        text = (HERE / name).read_text()
        assert "def audit(" in text, f"{name} has no audit() the tests can drive"
        assert "def main(" in text, f"{name} has no main() check.sh can run"
