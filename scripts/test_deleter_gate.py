# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""The mutation table `deleter_gate.py` was verified against, kept.

The guard exists because a caller-by-caller audit is worth exactly as much as
the roster under it, and this tree has twice found a hand-kept one wrong. So the
table below breaks the real defect shape in a fixture checkout, one at a time,
and asserts the MESSAGE rather than a count — a red for the wrong reason proves
as little as a green.

Both directions, because a guard that cannot go green is deleted as fast as one
that cannot go red: the clean fixture passes, this checkout's own ledger passes,
and `check.sh` is asserted to run the row at all. Five of the five guards this
repo shipped before this one had a hole of this family, which is why the last
two cases are about the derivation itself rather than about the ledger.
"""

import pathlib
import textwrap

import pytest

import deleter_gate
import gate_lines

ROOT = pathlib.Path(__file__).resolve().parent.parent

#: A fixture crate with one of each shape: a caller that reads the answer, one
#: that discards it, and one on a `.method()` continuation, so the statement walk
#: is exercised rather than assumed.
CALLER = """\
fn wipe(fs: &mut Fs) -> Result<()> {
    fs.force_delete(SEED)?;
    let _ = fs.delete(INDEX);
    fs.delete_key(KEY)
        .map_err(|_| Sw::MEMORY_FAILURE)?;
    Ok(())
}
"""

MINTER = "fn head(fs: &mut Fs) { let _ = fs.meta_add(SLOT, &[0]); }\n"

LEDGER = """\
head_minters = ["crates/rsk-piv"]

[[site]]
file = "crates/rsk-app/src/lib.rs"
line = 2
call = "fs.force_delete(SEED)?;"
verb = "force_delete"
answer = "read"
class = "wipe-sweep"
metadata = "none"
disposition = "must-read"
why = "the sweep may not report a wipe it could not prove."

[[site]]
file = "crates/rsk-app/src/lib.rs"
line = 3
call = "let _ = fs.delete(INDEX);"
verb = "delete"
answer = "discarded"
class = "bookkeeping"
metadata = "none"
disposition = "best-effort"
why = "an index the store rebuilds."

[[site]]
file = "crates/rsk-app/src/lib.rs"
line = 4
call = "fs.delete_key(KEY)"
verb = "delete_key"
answer = "read"
class = "secret-or-gate"
metadata = "none"
disposition = "must-read"
why = "a survivor is a live key."
"""


class Tree:
    """A checkout shaped like this one: one caller crate, one head minter."""

    def __init__(self, root):
        self.root = root
        self.write("crates/rsk-app/src/lib.rs", CALLER)
        self.write("crates/rsk-piv/src/keygen.rs", MINTER)
        self.write("assurance/deleters.toml", LEDGER)

    def write(self, rel, text):
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)

    def edit(self, rel, old, new):
        """Replace `old` once, failing loudly if the fixture no longer says it."""
        path = self.root / rel
        text = path.read_text()
        assert text.count(old) == 1, f"{rel} does not say {old!r} exactly once"
        path.write_text(text.replace(old, new))

    def run(self):
        return deleter_gate.run(self.root)


@pytest.fixture
def tree(tmp_path, monkeypatch):
    # The shipped floor is about the real checkout's 43 sites. Scaled to the
    # fixture's three so the emptying case below still has one to trip.
    monkeypatch.setattr(deleter_gate, "FLOOR_SITES", 2)
    return Tree(tmp_path)


def red(tree, capsys):
    """Run the guard, require it red, and hand back what it said."""
    assert tree.run() == 1
    return capsys.readouterr().err


# --- both directions, and the wiring ------------------------------------------


def test_the_clean_fixture_passes(tree):
    assert tree.run() == 0


def test_this_checkout_passes():
    """The guard has to be green on the tree it ships in, or it is not a row."""
    assert deleter_gate.run(ROOT) == 0


def test_check_sh_runs_the_row():
    """A guard nothing invokes can have its whole table deleted, suite green."""
    text = (ROOT / "scripts/check.sh").read_text()
    assert gate_lines.runs(text, "scripts/deleter_gate.py")


# --- the roster, both directions ----------------------------------------------


def test_a_new_caller_with_no_disposition_is_rejected(tree, capsys):
    tree.edit(
        "crates/rsk-app/src/lib.rs",
        "    Ok(())",
        "    let _ = fs.delete(SURPRISE);\n    Ok(())",
    )
    assert "does not dispose of it" in red(tree, capsys)


def test_a_disposition_for_a_caller_that_is_gone_is_rejected(tree, capsys):
    tree.edit("crates/rsk-app/src/lib.rs", "    let _ = fs.delete(INDEX);\n", "")
    assert "which calls nothing" in red(tree, capsys)


def test_a_moved_caller_is_reported_with_where_it_went(tree, capsys):
    """The citation-gate rule: a line that has shifted says so and says where,
    because "repair the number" and "the claim was never true" need different
    answers from the reader."""
    tree.edit(
        "crates/rsk-app/src/lib.rs",
        "fn wipe(fs: &mut Fs) -> Result<()> {",
        "// a line arrives\nfn wipe(fs: &mut Fs) -> Result<()> {",
    )
    assert "it is at :" in red(tree, capsys)


def test_a_caller_that_became_a_different_call_is_rejected(tree, capsys):
    tree.edit("crates/rsk-app/src/lib.rs", "let _ = fs.delete(INDEX);", "let _ = fs.delete(OTHER);")
    assert "reads `let _ = fs.delete(OTHER);` now" in red(tree, capsys)


# --- the judgement, held to the code ------------------------------------------


def test_a_read_answer_turned_into_a_discard_is_rejected(tree, capsys):
    """The freshness trigger §5A п.6 asks for: the disposition is a claim about
    what the site does, so quietly making a must-read site discard the answer
    has to be red rather than a label mismatch nobody looks at."""
    tree.edit("crates/rsk-app/src/lib.rs", "    fs.delete_key(KEY)\n", "    let _ = fs.delete_key(KEY)\n")
    said = red(tree, capsys)
    assert "discards the deleter's answer" in said
    assert "do not re-label it" in said


def test_relabelling_instead_of_deciding_is_rejected(tree, capsys):
    """The other half of the pair: editing the ledger to match the new code
    without changing the disposition must not buy a green either."""
    tree.edit("crates/rsk-app/src/lib.rs", "    fs.delete_key(KEY)\n", "    let _ = fs.delete_key(KEY)\n")
    tree.edit("assurance/deleters.toml", 'call = "fs.delete_key(KEY)"', 'call = "let _ = fs.delete_key(KEY)"')
    tree.edit(
        "assurance/deleters.toml",
        'answer = "read"\nclass = "secret-or-gate"',
        'answer = "discarded"\nclass = "secret-or-gate"',
    )
    assert "while the site discards the answer" in red(tree, capsys)


def test_a_disposition_with_no_reason_is_rejected(tree, capsys):
    tree.edit("assurance/deleters.toml", 'why = "an index the store rebuilds."', 'why = "   "')
    assert "a disposition with no reason" in red(tree, capsys)


def test_an_invented_vocabulary_is_rejected(tree, capsys):
    tree.edit("assurance/deleters.toml", 'class = "bookkeeping"', 'class = "probably-fine"')
    assert "is not one of" in red(tree, capsys)


def test_two_entries_for_one_site_are_rejected(tree, capsys):
    tree.edit(
        "assurance/deleters.toml",
        'why = "an index the store rebuilds."\n',
        'why = "an index the store rebuilds."\n\n'
        + textwrap.dedent(
            """\
            [[site]]
            file = "crates/rsk-app/src/lib.rs"
            line = 3
            call = "let _ = fs.delete(INDEX);"
            verb = "delete"
            answer = "discarded"
            class = "bookkeeping"
            metadata = "none"
            disposition = "best-effort"
            why = "and again, differently."
            """
        ),
    )
    assert "same file and line" in red(tree, capsys)


# --- the metadata axis, and the premise under it -------------------------------


def test_a_head_claimed_from_a_crate_that_mints_none_is_rejected(tree, capsys):
    tree.edit("assurance/deleters.toml", 'metadata = "none"\ndisposition = "best-effort"',
              'metadata = "drops-head"\ndisposition = "best-effort"')
    assert "mints none" in red(tree, capsys)


def test_a_second_head_minter_arriving_is_rejected(tree, capsys):
    """Every `drops-head` disposition rests on one crate writing the heads. A
    second one arriving silently is how that premise stops being true while the
    entries still read as though it holds."""
    tree.write("crates/rsk-other/src/lib.rs", MINTER)
    assert "rests on that set" in red(tree, capsys)


# --- the derivation itself ------------------------------------------------------


def test_an_empty_roster_is_rejected(tree, capsys):
    """The failure a verdict column cannot show: a derivation that finds nothing
    satisfies every rule above. Driven by breaking the call matcher, which is
    what an edit to it would do."""
    tree.edit("crates/rsk-app/src/lib.rs", "fs.force_delete(SEED)?;", "")
    tree.edit("crates/rsk-app/src/lib.rs", "let _ = fs.delete(INDEX);", "")
    tree.edit("crates/rsk-app/src/lib.rs", "fs.delete_key(KEY)\n        .map_err(|_| Sw::MEMORY_FAILURE)?;", "")
    assert "under the floor of" in red(tree, capsys)


def test_the_scope_exclusions_are_the_two_the_roadmap_names():
    """A third exclusion is the rotted roster in modern spelling: nothing fails,
    the row just measures less. `BUILD_DIRS` is separate on purpose — it is
    determinism (a local `cargo build` drops generated `.rs` under the checkout),
    not scope."""
    assert deleter_gate.SKIP_DIRS == ("crates/rsk-fs", "fuzz")


def test_a_generated_source_under_a_nested_target_is_not_a_caller(tree):
    """`tools/emu` and `tools/tui` are their own workspaces with their own
    `target/`. A roster that walked into them would answer differently on a
    machine that had run cargo."""
    tree.write("tools/emu/target/debug/build/x/out/gen.rs", "fn f(fs: &mut Fs) { let _ = fs.delete(X); }\n")
    assert tree.run() == 0


def test_a_test_or_proof_sibling_is_not_a_caller(tree):
    """The cfg-gated sources by AGENTS.md's naming rule — which is what puts
    `reset_refinement_kani.rs` out, whose `reset.delete` is the refinement
    model's own verb rather than this file system's."""
    tree.write("crates/rsk-app/src/lib_tests.rs", "fn t(fs: &mut Fs) { let _ = fs.delete(X); }\n")
    tree.write("crates/rsk-app/src/reset_refinement_kani.rs", "fn p(r: &mut R) { assert!(r.delete(X)); }\n")
    assert tree.run() == 0


def test_a_continuation_line_call_is_read_against_the_let_that_owns_it():
    """A call on a `.method()` continuation has its `let _ =` lines above.
    Reading only the call's own line calls every one of those a reader, which is
    the direction that hides a discard."""
    lines = ["    let _ = ctx", "        .fs", "        .delete(X);"]
    assert deleter_gate.disposal(lines, 2) == "discarded"
    lines = ["    gate(ctx)?;", "    ctx.fs", "        .delete(X)", "        .map_err(f)?;"]
    assert deleter_gate.disposal(lines, 2) == "read"


def test_a_call_inside_a_condition_is_not_read_against_the_block_body():
    """The forward walk that finds a trailing `.ok();` must stop at a line that
    OPENS a block: `if ….is_err() {` reads the answer, and the first `;` after it
    belongs to the body. Two of the ten `force_delete` callers are that shape."""
    lines = [
        "    if fs.has_key(slot) && fs.force_delete(slot.get()).is_err() {",
        "        log(x).ok();",
        "    }",
    ]
    assert deleter_gate.disposal(lines, 0) == "read"


# --- the four spellings of "discard" -------------------------------------------


@pytest.mark.parametrize(
    "spelling",
    [
        # Rust 2021 destructuring assignment: `let`-less, and `cargo fmt --check`
        # and `clippy -D warnings` are both happy with it.
        "    _ = fs.delete_key(KEY);",
        "    fs.delete_key(KEY).ok();",
        "    drop(fs.delete_key(KEY));",
    ],
)
def test_every_spelling_of_a_discard_derives_as_one(tree, capsys, spelling):
    """A must-read site converted into any of these used to derive as `read`, so
    the ledger could be updated honestly and the row stayed green — verbatim the
    property the docstring claims. The `let _ =` spelling has its own case above;
    these are the three that were invisible."""
    tree.edit(
        "crates/rsk-app/src/lib.rs",
        "    fs.delete_key(KEY)\n        .map_err(|_| Sw::MEMORY_FAILURE)?;",
        spelling,
    )
    tree.edit(
        "assurance/deleters.toml",
        'call = "fs.delete_key(KEY)"',
        'call = "%s"' % spelling.strip(),
    )
    said = red(tree, capsys)
    assert "discards the deleter's answer" in said
    assert "do not re-label it" in said


def test_a_ufcs_caller_is_on_the_roster(tree, capsys):
    """The receiver test (`.delete(`) cannot see the same call spelled
    `Fs::force_delete(fs, x)` or `<Fs<S>>::delete(fs, x)`. Two callers were added
    that way, one of them deleting the FIDO seed, and the count did not move."""
    tree.edit(
        "crates/rsk-app/src/lib.rs",
        "    Ok(())",
        "    let _ = Fs::force_delete(fs, SEED);\n"
        "    let _ = <Fs<S>>::delete(fs, INDEX);\n    Ok(())",
    )
    said = red(tree, capsys)
    assert "Fs::force_delete(fs, SEED)" in said
    assert "<Fs<S>>::delete(fs, INDEX)" in said
