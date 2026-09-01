# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""The mutation table for the compile-only arm of `matrix_gate.check_evidence`.

`covered` is the strongest word in the matrix's vocabulary and every other thing
it used to rest on has been taken away from it in turn: a prose basis, then a row
that builds another image, then a row that builds this one and selects a crate
the property is not about. What was left is a row that builds THIS image, selects
the RIGHT crate, and runs none of it — `cargo build` and `cargo clippy` compile
and execute nothing. Measured on the real tree before the rule was written: 89
`gap` cells would pass the two older checks today and 9 of them name a build or a
lint row and nothing else, so the last route to a `covered` cell nobody measured
was open and the `why` was the only thing standing in it.

Both directions, and the third one that matters here — the rule must not SUPPRESS
its neighbour. A held-back list rather than an inline append, because the
owner-crate refusal fires only over an otherwise-clean row: appending inline
turned a row that was wrong twice into a row reported once, and the case that
caught it is `test_both_reasons_reach_the_reader` below. It was caught by an
existing case in `test_matrix_gate.py` going red, which is the only reason this
paragraph is not a hypothesis.
"""

import pathlib

import matrix_gate
from test_matrix_gate import Tree, red, tree  # noqa: F401  (`tree` is the fixture)

ROOT = pathlib.Path(__file__).resolve().parent.parent

#: A row that builds the `firmware-screen` column exactly — same feature, same
#: (absent) knobs — and selects the crate `SEC-B-001` is carried by. Everything
#: the two older rules ask for; it just never runs a line.
BUILD_ROW = 'run "build (screen)" cargo build -p rsk-screen -p firmware --features screen\n'
LINT_ROW = (
    'run "lint (screen)" cargo clippy -p rsk-screen -p firmware --features screen'
    " -- -D warnings\n"
)


def swap_evidence(tree, row, label):
    """Point the fixture's one `check-sh-rows` cell at `label`, and add the row."""
    tree.edit("scripts/check.sh", 'run "clippy (loud)"', row + 'run "clippy (loud)"')
    tree.edit(
        "assurance/configurations.toml",
        'evidence = ["test (screen)"]',
        f'evidence = ["{label}"]',
    )


# --- the green direction ------------------------------------------------------


def test_a_row_that_runs_the_crate_still_carries_a_covered_cell(tree):
    """`test (screen)` is `cargo test`; the fixture ships `covered` on it."""
    assert tree.run() == 0


def test_a_row_that_is_not_cargo_at_all_is_not_refused_for_compiling(tree, capsys):
    """A `check.sh` row can be a shell function reading the built ELF, and those
    DO measure something. Which of them measures a given property is the `why`'s
    judgement — this rule reads a cargo subcommand and must say nothing here.

    The row is still refused, and the assertion names WHY so the pass is not
    read as an endorsement: it carries no `--features`, so it is the older
    another-image rule that fell, not this one.
    """
    swap_evidence(tree, 'run "image budget" firmware_size_budget\n', "image budget")
    said = red(tree, capsys)
    assert "executes none of it" not in said
    assert "`image budget` builds [] and this column is ['screen']" in said


# --- and the red one ----------------------------------------------------------


def test_a_covered_cell_resting_on_a_cargo_build_row_is_refused(tree, capsys):
    swap_evidence(tree, BUILD_ROW, "build (screen)")
    said = red(tree, capsys)
    assert "`build (screen)` runs `cargo build`" in said
    assert "executes none of it, so it cannot say SEC-B-001 holds here" in said


def test_a_covered_cell_resting_on_a_clippy_row_is_refused(tree, capsys):
    """The lint arm on its own, because `--all-targets` type-checks the tests and
    is the shape most likely to read as "the tests were involved"."""
    swap_evidence(tree, LINT_ROW, "lint (screen)")
    assert "`lint (screen)` runs `cargo clippy`" in red(tree, capsys)


def test_both_reasons_reach_the_reader(tree, capsys):
    """A row wrong twice — it compiles nothing AND names the wrong crate — owes
    both messages. The first draft appended inline and reported one of them."""
    swap_evidence(
        tree,
        'run "build (firmware only)" cargo build -p firmware --features screen\n',
        "build (firmware only)",
    )
    said = red(tree, capsys)
    assert "runs `cargo build`" in said
    assert "no row named here selects ['rsk-screen']" in said


# --- and on the tree it ships in ---------------------------------------------


def test_no_shipped_cell_rests_on_a_compile_only_row():
    """Green on its own checkout, and for a reason worth stating: the ledger has
    no `check-sh-rows` cell at all today, so the rule costs nothing to adopt and
    is in place before the first one is written."""
    doc = matrix_gate.ledger(ROOT)
    resting = [
        entry
        for entry in doc.get("cell", [])
        if entry.get("basis") == matrix_gate.CHECK_SH_ROWS
    ]
    assert resting == []
    assert matrix_gate.run(ROOT) == 0


def test_the_compile_only_list_still_has_the_subcommands_in_it():
    """A rule over an empty tuple passes every case above it."""
    assert set(matrix_gate.COMPILE_ONLY) >= {"build", "clippy"}
