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

The second fact about the set is what each script does with a temp. `check.sh`
was the only one of the nine that make one with no cleanup at all — five sites,
~10 GB of build trees per run, until a full volume stopped a session dead — and
nothing could say so, because every rule in the tree is about a guard's ROWS. One
of those five could not be cleaned even by hand: `out=$(mktemp -d)/pt.elf` keeps
the file and throws the directory away, so no name in the script reached it.

And the temp a script does NOT make. Those four rules are spelled over `mktemp`,
so the three `pytest` rows were invisible to every one of them while leaking
harder than any site they cover: pytest puts `tmp_path` under $TMPDIR, `nix
develop` hands each invocation a fresh one it never removes, and the retention
that would have swept it is counted per base directory — so it never met a
previous run. 361 orphaned bases, 8.9 GB, inside one day.
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


#: `VAR=$(mktemp …)` — the whole right-hand side, deliberately. A trailing path
#: (`out=$(mktemp -d)/pt.elf`) keeps the file and drops the directory, so nothing
#: in the script can name the temp to remove it; that is a leak by construction
#: rather than by oversight, and it is what check.sh shipped for the store row.
MKTEMP_ASSIGN = re.compile(
    r'^(?:local\s+|declare\s+(?:-\w+\s+)*)?(?P<var>[A-Za-z_]\w*)='
    r'(?P<q>"?)\$\(\s*mktemp[^()]*\)(?P=q)$'
)

#: How a script may put a temp on a cleanup path. Two idioms, because there are
#: two: eight scripts hold one temp and remove it from their own EXIT trap, and
#: `check.sh` holds seven — bash keeps ONE EXIT trap, so a per-site one there
#: replaces the previous rather than joining it — and accumulates instead.
REMOVES = "rm "
ACCUMULATOR = "GATE_TMP"


def shell_scripts():
    """Every `*.sh` of the checkout, git's answer to what the tree is."""
    return sorted(p for p in gate_lines.tree_files(ROOT) if p.suffix == ".sh")


def code_lines(text):
    """Each logical line's CODE, stripped — what the shell runs, not what it quotes."""
    for _indent, body in gate_lines.logical_lines(text):
        yield gate_lines.split_at_comment(body)[0].strip()


def mktemp_sites(text):
    """(line, variable) per live `mktemp`; the variable is "" when none is bound."""
    for code in code_lines(text):
        if "mktemp" in code:
            found = MKTEMP_ASSIGN.match(code)
            yield code, (found["var"] if found else "")


#: A top-level shell function. Its body is the scope a temp shares with its
#: cleanup — see [`regions`].
FUNCTION = re.compile(r"^[A-Za-z_]\w*\(\)\s*\{\s*$")


def regions(text):
    """The script split into the scopes a cleanup may live in: each top-level
    function body, and everything outside them as one more.

    File scope was the first spelling, and it is too coarse in exactly the way
    that matters: `dir` names the temp of three different `check.sh` rows, so one
    row's registration satisfied the rule for all three. Measured — deleting the
    assurance row's `GATE_TMP+=("$dir")`, and again with it merely commented out,
    left `python -m pytest scripts -q` at rc 0 with 1789 passed both times, while
    the other four mutations below were caught. The two spellings the class is
    actually written in are the two that survived.
    """
    top, held, out = [], None, []
    for line in text.splitlines():
        if held is None and FUNCTION.match(line):
            held = []
        elif held is None:
            top.append(line)
        elif line == "}":
            out.append("\n".join(held))
            held = None
        else:
            held.append(line)
    # An unbalanced body is kept rather than dropped: losing it would take its
    # sites with it and read as a script with nothing to check.
    return out + ([] if held is None else ["\n".join(held)]) + ["\n".join(top)]


def registered(text, var):
    """Whether this SCOPE's code puts `$var` on a removal path.

    The two idioms differ in where the `rm` is: the trap carries it on the same
    line, the accumulator carries it once in the handler that drains the list —
    so requiring one on both reads every `GATE_TMP+=` line as a non-registration.
    Measured: that spelling reported all seven of check.sh's registered sites as
    loose, which is the rule failing in the loud direction and how it was found.
    """
    return any(
        f'"${var}"' in code
        and ((code.startswith("trap ") and REMOVES in code) or f"{ACCUMULATOR}+=(" in code)
        for code in code_lines(text)
    )


def drains_accumulator(text):
    """Whether anything in the script removes what the accumulator holds.

    The half `registered` gives up when it stops asking for an `rm` on the line:
    a list every temp is appended to and nothing reads leaks exactly as loudly as
    no list at all, and reads as covered.
    """
    lines = list(code_lines(text))
    return not any(ACCUMULATOR in code for code in lines) or any(
        ACCUMULATOR in code and REMOVES in code for code in lines
    )


def traps_exit(text):
    """Whether the script installs an EXIT trap at all.

    The registration rule cannot see this: deleting `trap gate_cleanup EXIT` from
    `check.sh` leaves every `GATE_TMP+=` line exactly where it was, and seven
    temps with a list nothing reads. Same hole one layer out as an unwired guard.
    """
    return any(code.startswith("trap ") and code.endswith(" EXIT") for code in code_lines(text))


def temp_makers():
    """(path, whole text, scope, sites in that scope) per scope that makes a temp."""
    out = []
    for rel in shell_scripts():
        text = (ROOT / rel).read_text()
        for scope in regions(text):
            sites = list(mktemp_sites(scope))
            if sites:
                out.append((rel, text, scope, sites))
    return out


def test_there_are_temp_making_scripts():
    """A glob that matches nothing loops over nothing and passes every case below."""
    found = {str(rel) for rel, _, _, _ in temp_makers()}
    assert len(found) >= 8, sorted(found)


def test_every_mktemp_names_the_path_it_makes():
    """A temp the script cannot name is one nothing can remove."""
    unnamed = [(str(rel), line) for rel, _, _, sites in temp_makers() for line, var in sites if not var]
    assert not unnamed, f"mktemp with no variable bound to it: {unnamed}"


def test_every_mktemp_is_registered_for_removal():
    """…and one it names but never removes is the same leak, spelled longer."""
    loose = [
        (str(rel), var)
        for rel, _text, scope, sites in temp_makers()
        for _line, var in sites
        if var and not registered(scope, var)
    ]
    assert not loose, f"temps on no cleanup path: {loose}"


def test_every_temp_making_script_traps_exit():
    """The rule above says a name is listed; this says something reads the list."""
    untrapped = [str(rel) for rel, text, _, _ in temp_makers() if not traps_exit(text)]
    assert not untrapped, f"makes a temp and traps no EXIT: {untrapped}"


def test_the_accumulator_is_drained():
    """…and this says what reads it removes something."""
    inert = [str(rel) for rel, text, _, _ in temp_makers() if not drains_accumulator(text)]
    assert not inert, f"accumulates temps and removes none: {inert}"


def test_a_quoted_mktemp_is_not_one():
    """The rules above are only worth having if a comment cannot trip or satisfy them.

    Both directions: prose about a leak must not be read as one, and prose about a
    trap must not be read as the cleanup. The comment-cut is `gate_lines`', so this
    pins the two shapes that reach these rules rather than re-testing the cut.
    """
    assert not list(mktemp_sites("# dir=$(mktemp -d) used to leak here\n"))
    assert not list(mktemp_sites("true # log=$(mktemp)\n"))
    assert list(mktemp_sites("log=$(mktemp)\n")) == [("log=$(mktemp)", "log")]
    assert not registered('# trap \'rm -rf "$d"\' EXIT\n', "d")
    assert not traps_exit("# trap cleanup EXIT\n")


def test_the_temp_rules_can_go_red():
    """The mutation table: one line per way the class has actually been spelled.

    Each was applied to `scripts/check.sh` and driven through `python -m pytest
    scripts -q` — the `pytest (gate scripts)` row verbatim, exit code taken with
    no pipe, and the failure read rather than the return code trusted. Unmutated:
    rc 0, 1789 passed. Then rc 1 each, at the rule named beside it — the last one
    at three of them, since the pre-fix file breaks three ways at once:

    * registration deleted / commented out → `..._is_registered_for_removal`
    * `out=$(mktemp -d)/pt.elf` → `..._names_the_path_it_makes`
    * `trap gate_cleanup EXIT` deleted → `..._traps_exit`
    * the handler's `rm` replaced by an `echo` → `..._accumulator_is_drained`
    * the whole pre-fix `check.sh` → the first three together

    The first two of those are the reason [`regions`] exists: with the rule
    file-scoped they were rc 0, 1789 passed, indistinguishable from the control.
    """
    trapped = 'd=$(mktemp -d)\ntrap \'rm -rf "$d"\' EXIT\n'
    assert list(mktemp_sites(trapped)) == [("d=$(mktemp -d)", "d")]
    assert registered(trapped, "d") and traps_exit(trapped)

    # 1. the site is not registered at all — check.sh, every row, before this fix
    assert not registered('d=$(mktemp -d)\ntrap \'rm -rf "$other"\' EXIT\n', "d")
    # 1b/1c. …and the two spellings that survived a file-scoped version of it: a
    # sibling scope registering the SAME variable name must not answer for this
    # one, whether the registration was deleted or only commented out.
    two_rows = (
        'a() {\n  dir=$(mktemp -d)\n}\n'
        'b() {\n  dir=$(mktemp -d)\n  GATE_TMP+=("$dir")\n}\n'
    )
    covered = [registered(scope, "dir") for scope in regions(two_rows) if list(mktemp_sites(scope))]
    assert covered == [False, True], covered
    commented = two_rows.replace('GATE_TMP+=', '# GATE_TMP+=')
    assert not any(registered(scope, "dir") for scope in regions(commented))
    # 2. the directory is never bound, so no name reaches it — the store row
    assert list(mktemp_sites("out=$(mktemp -d)/pt.elf\n")) == [("out=$(mktemp -d)/pt.elf", "")]
    # 3. registered on a line that removes nothing — a list nothing acts on
    assert not registered('d=$(mktemp -d)\ntrap \'echo "$d"\' EXIT\n', "d")
    # 4. accumulated, but the EXIT trap that drains the accumulator is gone
    assert not traps_exit('d=$(mktemp -d)\nGATE_TMP+=("$d")\n')
    # 5. a trap on a signal is not the one that runs when the script simply ends
    assert not traps_exit('trap \'rm -rf "$d"\' INT\n')
    # 6. accumulated and trapped, but the handler removes nothing
    assert registered('GATE_TMP+=("$d")\n', "d")
    assert not drains_accumulator('GATE_TMP+=("$d")\ntrap \'echo "${GATE_TMP[@]}"\' EXIT\n')
    assert drains_accumulator('GATE_TMP+=("$d")\nrm -rf -- "${GATE_TMP[@]}"\n')


#: A quoted span, single or double. Blanked before a call is looked for, because
#: `echo "third_party (fido): pytest exit $tp"` is prose the shell prints and
#: reading it as an invocation would demand a `--basetemp` on an `echo`. It is
#: also what stops `run "pytest (gate scripts)" …` matching on its own label, and
#: `GATE_PYTEST_TMP=".../rs-key/pytest"` on the name of its own directory.
QUOTED = re.compile(r"\"[^\"]*\"|'[^']*'")

#: A live pytest invocation, at a command position rather than anywhere in the
#: line. Spelled to cover the bare `pytest foo -q` as well as the `python -m`
#: form the tree uses: a rule that only knew the long one would be satisfied by
#: writing the short one, which is the hole this file exists to catch.
PYTEST_CALL = re.compile(r"(?:^|[\s;|&(])pytest(?:\s|$)")

#: The pin that bounds it, `=` form only. `--basetemp <path>` leaves a bare path
#: in the row, and `roster_gate.collects` reads every word of a pytest row as
#: something it collects — a basetemp named `scripts` would answer for the row
#: that collects `scripts/`.
BASETEMP = re.compile(r"--basetemp=(?P<path>\S+)")


def unquoted(code):
    """`code` with quoted spans blanked — what it runs, not what it says."""
    return QUOTED.sub('""', code)


def pytest_calls():
    """(path, code line) per live pytest invocation in a tracked `*.sh`."""
    for rel in shell_scripts():
        for code in code_lines((ROOT / rel).read_text()):
            if PYTEST_CALL.search(unquoted(code)):
                yield str(rel), code


def pinned_at(code):
    """The `--basetemp` this line pins, quotes stripped, or "" if it pins none."""
    found = BASETEMP.search(code)
    return found["path"].strip("\"'") if found else ""


def test_there_are_pytest_rows():
    """A pattern that matches nothing loops over nothing and passes both rules."""
    found = list(pytest_calls())
    assert len(found) >= 3, found


def test_every_pytest_row_pins_a_basetemp():
    """An unpinned row leaks its whole `tmp_path` tree, once per run, for good.

    `--basetemp` is not the retention the docs describe — pytest removes the
    directory and recreates it at startup, so the row holds one run instead of
    every run. What this cannot say is WHERE: the path is a variable by the time
    it reaches here. That half is covered where it bites — a base inside the
    checkout lets `git rev-parse` answer from RS-Key's own .git, and
    `test_verdict_gate.py`'s "git cannot answer here" case fails on it (measured:
    `--basetemp=target/pytest/scripts` → 1788 of 1789, at that assertion).
    """
    loose = [(rel, code) for rel, code in pytest_calls() if not pinned_at(code)]
    assert not loose, f"pytest rows with no --basetemp: {loose}"


def test_no_two_pytest_rows_share_a_basetemp():
    """…and two rows pinned to one directory are a race, not a saving.

    The startup wipe is `rm -rf` over the whole path, so the second row through
    a shared base destroys the first row's output — silently, since it then runs
    green on an empty directory. Copying a row and forgetting its leaf is the way
    that arrives, and the copy is the half nobody re-reads. Compared as written,
    quotes off: two spellings of one path read as two, which errs toward letting
    a collision through rather than inventing one.
    """
    pinned = [pinned_at(code) for _rel, code in pytest_calls()]
    shared = sorted({p for p in pinned if p and pinned.count(p) > 1})
    assert not shared, f"pytest rows sharing one --basetemp: {shared}"


def test_a_quoted_pytest_is_not_a_call():
    """Both directions, the way the `mktemp` rules pin theirs.

    Prose about pytest must not be read as a row that owes a pin, and a row must
    not be excused by prose. One line in the tree needs the quote-cut and only
    one: `usbip-guest.sh` prints `pytest exit $tp`, where the word follows a
    space *inside* a string and matched. `emu-suites.sh`'s `tp_note="pytest exit
    $tp"` and `check.sh`'s own `…/rs-key/pytest` never did — [`PYTEST_CALL`] asks
    for a command position, so a `"` and a `/` in front of the word already
    answered for those two. Measured, both ways, before writing this down.
    """
    assert not PYTEST_CALL.search(unquoted('echo "third_party (fido): pytest exit $tp"'))
    assert not PYTEST_CALL.search(unquoted('GATE_PYTEST_TMP="${X:-$HOME/.cache}/rs-key/pytest"'))
    assert PYTEST_CALL.search(unquoted('run "pytest (x)" python -m pytest scripts -q'))
    assert PYTEST_CALL.search(unquoted("pytest scripts -q"))
    # The comment-cut is `code_lines`', so this pins that a commented-out row
    # neither owes a pin nor answers for one — the way `NAMED` learned to.
    assert not [c for c in code_lines("# python -m pytest scripts -q\n") if PYTEST_CALL.search(unquoted(c))]
    assert not [c for c in code_lines("true # pytest tools/rsk -q\n") if PYTEST_CALL.search(unquoted(c))]


def test_the_pytest_temp_rules_can_go_red():
    """The mutation table: one line per way the pin has been got wrong.

    Each was applied to `scripts/check.sh` and driven through the `pytest (gate
    scripts)` row, exit code taken with no pipe and the failing assertion read
    rather than the return code trusted. Unmutated: rc 0, 1794 passed.

    * the gate row's `--basetemp` deleted → `..._pins_a_basetemp`, rc 1
    * the `tools/rsk` row's deleted instead → the same rule, rc 1, other row
    * `tools/rsk` re-pinned onto the `gate` leaf → `..._share_a_basetemp`, rc 1
    * all three deleted → `..._pins_a_basetemp` names all three, rc 1
    * …and rewritten as a bare `pytest foo -q` → the same rule again, rc 1
    * every row's `pytest` renamed away → `..._there_are_pytest_rows`, rc 1
    * [`PYTEST_CALL`] narrowed to `python -m` while the rows say `pytest` → rc 1,
      but at `..._there_are_pytest_rows` and at this table, NOT at the pin rule

    The last one is the interesting reading and it corrected what was written
    here first. Narrowing the pattern does not leave the pin rule reporting a
    green tree — it leaves it with nothing to report on, and the sentinel above
    is what says so. That the three cases land at three different assertions is
    the point: with exactly three rows and a floor of three, one row going
    invisible is still a red, and it stops being one the moment a fourth row is
    added. Which is the argument for the pattern covering both spellings rather
    than for the floor being load-bearing.
    """
    pinned = 'run "x" python -m pytest scripts -q --basetemp="$T/scripts"'
    assert PYTEST_CALL.search(unquoted(pinned)) and pinned_at(pinned) == "$T/scripts"
    # 1. no pin at all — every row, before this fix
    assert not pinned_at('run "x" python -m pytest scripts -q')
    # 2. the bare spelling, which a `python -m`-only pattern would not see
    assert PYTEST_CALL.search(unquoted("pytest tools/rsk -q"))
    # 3. two rows on one leaf: the second wipes the first at startup
    rows = ['python -m pytest scripts -q --basetemp="$T/a"', "pytest tools/rsk -q --basetemp=$T/a"]
    seen = [pinned_at(r) for r in rows]
    assert len(set(seen)) == 1, seen
    # 4. …and the quoting must not be what makes two paths look different
    assert pinned_at('x --basetemp="$T/a"') == pinned_at("x --basetemp=$T/a")
