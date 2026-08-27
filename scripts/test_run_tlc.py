# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""Mutation table for the formal runner's verdict boundary.

TLC itself is the slow system under test in the weekly job. These cases replace
its output stream and the directory the log lands in — nothing else — then drive
the real runner, floors and configurations so each silent-pass shape is
permanently reproducible in the merge gate. The directory is not a detail: this
file used to write into the real `formal/out/`, so it truncated the log of any
real run beside it and left a NUL hole where that run kept writing.
"""

import os
import pathlib
import subprocess

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
RUNNER = ROOT / "formal" / "run-tlc.sh"

GREEN = """\
100 states generated
100 distinct states found
The depth of the complete state graph search is 3.
Model checking completed. No error has been found.
"""

VACUOUS = """\
1 states generated
1 distinct states found
The depth of the complete state graph search is 1.
Model checking completed. No error has been found.
"""

RED = """\
10 states generated
10 distinct states found
The depth of the complete state graph search is 2.
Invariant NoAuthorizationBypass is violated.
"""

#: What an INDUCTIVE probe looks like: every successor is already an initial
#: state, so the search ends at depth 1 with more states generated than found.
INDUCTIVE = """\
22920 states generated
1000 distinct states found
The depth of the complete state graph search is 1.
Model checking completed. No error has been found.
"""

#: And what it looks like when a step LEFT the predicate: a second level, which
#: is the refutation of `IndInv /\ Next => IndInv'` whatever the invariants say.
NOT_INDUCTIVE = """\
10748 states generated
788 distinct states found
The depth of the complete state graph search is 2.
Model checking completed. No error has been found.
"""


#: Where the stand-in punches the NUL run. An environment variable cannot carry a
#: NUL byte, so the hole travels as a marker in the output plus a count beside it.
HOLE = "@@HOLE@@"


@pytest.fixture
def fake_tlc(tmp_path):
    jar = tmp_path / "tla2tools.jar"
    jar.touch()
    java = tmp_path / "java"
    java.write_text(
        "#!/usr/bin/env python3\n"
        "import os, sys\n"
        # A real JVM dies on `-Xmx-`, and the heap column can now hold `-` as a
        # placeholder because a column follows it. Every row with one came back
        # "Could not create the Java Virtual Machine" — a RED for no reason at
        # all — so the stand-in refuses it too.
        "if '-Xmx-' in sys.argv:\n"
        "    sys.stderr.write('Error: Could not create the Java Virtual Machine.')\n"
        "    raise SystemExit(1)\n"
        f"head, _, tail = os.environ['FAKE_TLC_OUTPUT'].partition({HOLE!r})\n"
        "out = sys.stdout.buffer\n"
        "out.write(head.encode())\n"
        "out.write(b'\\0' * int(os.environ['FAKE_TLC_HOLE']))\n"
        # The mechanism itself, in one line: a SECOND O_TRUNC open on the log
        # this process still holds. Its own next write then lands at the offset
        # it had before, and everything between is a hole — which is the NULs.
        "if os.environ['FAKE_TLC_TRUNCATE']:\n"
        "    out.flush()\n"
        "    open(os.environ['FAKE_TLC_TRUNCATE'], 'w').close()\n"
        "out.write(tail.encode() + b'\\n')\n"
    )
    java.chmod(0o755)
    return jar, java, tmp_path / "out"


def run(
    fake_tlc,
    cfg: str,
    output: str,
    jar: pathlib.Path | None = None,
    hole: int = 0,
    truncate: pathlib.Path | None = None,
    coverage: bool = False,
):
    real_jar, java, out = fake_tlc
    env = {
        **os.environ,
        "COVERAGE": "1" if coverage else "0",
        "JAVA": str(java),
        "TLA2TOOLS_JAR": str(jar or real_jar),
        "FAKE_TLC_OUTPUT": output,
        "FAKE_TLC_HOLE": str(hole),
        "FAKE_TLC_TRUNCATE": str(truncate or ""),
        # Not `formal/out/`: these cases drive the REAL runner, so writing there
        # truncates the log of whatever real TLC run is in flight beside them —
        # which is the hole these cases are named for, and cost a standing rule.
        "TLC_OUT": str(out),
    }
    return subprocess.run(
        [str(RUNNER), cfg],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
    )


def test_broken_jar_path_fails_before_tlc(fake_tlc, tmp_path):
    result = run(fake_tlc, "Shipped.cfg", GREEN, tmp_path / "missing.jar")
    assert result.returncode == 2
    assert "not readable" in result.stderr


def test_broken_shipped_invariant_is_red(fake_tlc):
    result = run(fake_tlc, "Shipped.cfg", RED)
    assert result.returncode == 1
    assert "RED: NoAuthorizationBypass" in result.stdout
    assert "expected GREEN" in result.stdout


def test_one_state_model_is_vacuous_not_green(fake_tlc):
    result = run(fake_tlc, "Shipped.cfg", VACUOUS)
    assert result.returncode == 1
    assert "VACUOUS: nothing was enabled" in result.stdout
    assert "expected GREEN" in result.stdout


def test_floor_regression_is_not_green(fake_tlc):
    result = run(fake_tlc, "Shipped.cfg", GREEN)
    assert result.returncode == 1
    assert "FLOOR: 100 < 20000000" in result.stdout
    assert "expected GREEN" in result.stdout


def test_an_induction_probe_at_depth_one_is_green_and_not_vacuous(fake_tlc):
    """Depth 1 is what INDUCTIVE looks like, not what vacuity looks like.

    Every successor of an `INIT IndInv` run is already an initial state, so the
    search terminates immediately. The generic rule reads that as nothing having
    been enabled and would refuse every such row.
    """
    result = run(fake_tlc, "StoreInduction.cfg", INDUCTIVE)
    assert result.returncode == 0
    assert "GREEN" in result.stdout


def test_an_induction_probe_whose_step_left_the_predicate_is_refused(fake_tlc):
    """Depth 2 means a successor was NOT an initial state, which is the whole
    claim failing — and the INVARIANTS block need not have noticed, because a
    conjunct of `IndInv` is not necessarily one of them."""
    result = run(fake_tlc, "StoreInduction.cfg", NOT_INDUCTIVE)
    assert result.returncode == 1
    assert "NOT INDUCTIVE" in result.stdout


def test_the_exemption_does_not_reach_an_ordinary_specification(fake_tlc):
    """`Shipped.cfg` has no `INIT` line, so the depth floor still binds it."""
    result = run(fake_tlc, "Shipped.cfg", INDUCTIVE)
    assert result.returncode == 1
    assert "VACUOUS: nothing was enabled" in result.stdout


def test_invariant_that_stops_catching_its_solo_mutant_is_rejected(fake_tlc):
    result = run(fake_tlc, "Solo_BugResetGatesFirst.cfg", GREEN)
    assert result.returncode == 1
    assert "GREEN" in result.stdout
    assert "expected RED" in result.stdout


def test_mutant_that_stops_firing_is_rejected(fake_tlc):
    result = run(fake_tlc, "Mut_BugResetGatesFirst.cfg", GREEN)
    assert result.returncode == 1
    assert "GREEN" in result.stdout
    assert "expected RED" in result.stdout


#: A RED naming an invariant whose name carries a DIGIT. `[A-Za-z]+` matched none
#: of the nine trace rows for the whole life of the runner, so their verdict
#: column printed the raw error line and read RED coarsely — invisible until the
#: name started being compared.
RED_R4C = """\
37 states generated
37 distinct states found
The depth of the complete state graph search is 37.
Error: Invariant R4cGateAnswers is violated.
"""

RED_R4A = RED_R4C.replace("R4cGateAnswers", "R4aRawRefinesB")


def test_an_invariant_name_with_a_digit_is_read(fake_tlc):
    result = run(fake_tlc, "TraceSecurityBadAlwaysUvArm.cfg", RED_R4C)
    assert result.returncode == 0
    assert "RED: R4cGateAnswers" in result.stdout


def test_a_red_for_the_wrong_invariant_is_rejected(fake_tlc):
    """The colour is right and the reason is not — 2 of 24 co-refutation patches
    in this tree scored a kill that way. Measured on this very row: flipping the
    alwaysUv mutant to the INVERSE defect kept it red at a different boundary."""
    result = run(fake_tlc, "TraceSecurityBadAlwaysUvArm.cfg", RED_R4A)
    assert result.returncode == 1
    assert "expected RED: R4cGateAnswers" in result.stdout


def test_a_row_that_names_no_invariant_is_not_held_to_one(fake_tlc):
    """`TraceSeamsBad.cfg` is refused by a DEADLOCK, which names nothing, and the
    `Mut_*` families name theirs in their own INVARIANTS block."""
    result = run(fake_tlc, "Mut_BugResetGatesFirst.cfg", RED)
    assert result.returncode == 0
    assert "RED: NoAuthorizationBypass" in result.stdout


def test_a_placeholder_heap_does_not_reach_the_jvm(fake_tlc):
    """The row that exposed it: `RED - - <invariant>` gives `heap` the string
    `-`, and `-Xmx-` is not a heap."""
    result = run(fake_tlc, "TraceSecurityBadAlwaysUvArm.cfg", RED_R4C)
    assert "Could not create the Java Virtual Machine" not in result.stdout
    assert result.returncode == 0


#: What two writers leave on one path: the second's truncation resets the size,
#: the first writes on at its now-stale offset, and the gap between is NUL. The
#: shape is the measured one — the merge gate's own fixture above 1550 NULs at
#: offset 153, one straddled line, and the real run's own output from there on.
HOLED_GREEN = f"""\
22920 states generated
1000 distinct states found
The depth of the complete state graph search is 1.
Model checking completed. No error has been found.
{HOLE}states left on queue.
699350223 states generated
48679968 distinct states found
The depth of the complete state graph search is 55.
Model checking completed. No error has been found.
"""


def test_a_hole_in_the_log_does_not_turn_a_green_run_vacuous(fake_tlc):
    """One NUL byte makes grep call the whole log binary and match nothing, so
    every field comes back empty and the `< 2` rule fires over 48.7 M distinct
    states. Both implementations get it wrong and disagree on how: GNU sends
    `binary file matches` to stderr and the columns read `?`, BSD sends it to
    stdout and they read `Binary`. Fails safe, which is why it survived."""
    result = run(fake_tlc, "Shipped.cfg", HOLED_GREEN, hole=1550)
    assert result.returncode == 0
    assert "VACUOUS" not in result.stdout
    assert "states=699350223" in result.stdout
    assert "distinct=48679968" in result.stdout
    assert "depth=55" in result.stdout


#: The same hole under the other verdict branch, and under the one reader that
#: only `COVERAGE=1` reaches. Blinding either is a silent PASS, not a false red:
#: an unnamed RED still reads RED, and an unreported dead action reads GREEN.
HOLED_RED = f"""\
22920 states generated
1000 distinct states found
{HOLE}states left on queue.
37 states generated
37 distinct states found
The depth of the complete state graph search is 37.
Error: Invariant R4cGateAnswers is violated.
"""

HOLED_DEAD_ACTION = HOLED_GREEN.replace(
    "699350223 states generated",
    "<SetPin line 214, col 3 to line 219, col 41 of module RSKeySecurityState>: 0:0\n"
    "699350223 states generated",
)


def test_a_hole_does_not_cost_a_red_row_its_invariant_name(fake_tlc):
    """`-a` on the fields alone leaves this one blind, and the row still prints
    RED — the colour is right and the reason is gone, which is the shape that
    let nine trace rows compare nothing for their whole life."""
    result = run(fake_tlc, "TraceSecurityBadAlwaysUvArm.cfg", HOLED_RED, hole=1550)
    assert result.returncode == 0
    assert "RED: R4cGateAnswers" in result.stdout


def test_a_hole_does_not_hide_a_dead_action(fake_tlc):
    """The reader only `COVERAGE=1` reaches. An action that never fired makes
    every clause guarding it free, and a blinded grep reports none."""
    result = run(fake_tlc, "Shipped.cfg", HOLED_DEAD_ACTION, hole=1550, coverage=True)
    assert result.returncode == 1
    assert "DEAD ACTION in Shipped.cfg -- never fired: SetPin" in result.stderr


def test_a_second_writer_cannot_punch_a_hole_in_a_live_log(fake_tlc):
    """And the mechanism, not just its symptom, because `-a` is only a backstop:
    a hole that straddles a line takes that line with it whatever grep does. The
    log is truncated at open and APPENDED to, so a second writer's truncation
    leaves the first with no stale offset to write at."""
    log = fake_tlc[2] / "Shipped.log"
    result = run(fake_tlc, "Shipped.cfg", HOLED_GREEN, truncate=log)
    body = log.read_bytes()
    assert b"\0" not in body
    # Not decoration: the truncation above CREATES this path, so a runner writing
    # its log somewhere else entirely would leave an empty file here and satisfy
    # the line above. Measured — that mutant survived until this line was added.
    assert b"Model checking completed" in body
    assert result.returncode == 0
