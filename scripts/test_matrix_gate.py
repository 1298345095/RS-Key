# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""The mutation table `matrix_gate.py` was verified against, kept.

The guard's whole claim is that a property proved on one image cannot silently
read as a claim about the other thirty. That claim is worth exactly as much as
the two refusals under it — a column the derivation misses, and an `equivalent`
cell whose sameness is a reviewer's impression — so both are broken here, one at
a time, in a fixture checkout, and the MESSAGE is asserted rather than a count.
A red for the inverse defect reads exactly like a red for the right one.

Both directions, because a guard that cannot go green is deleted as fast as one
that cannot go red: the clean fixture passes, this checkout's own matrix passes,
and `check.sh` is asserted to run the row. The last cases are about the
DERIVATION rather than the ledger — seven of the seven guards this repo shipped
before this one had a hole of that family, and an axis that quietly derives to
nothing satisfies every rule above it.
"""

import pathlib

import pytest

import gate_lines
import matrix_gate

ROOT = pathlib.Path(__file__).resolve().parent.parent

#: Two images with no features, one with a feature that swaps a gate out, one
#: that pulls an optional crate in, and one that only pins a knob — the four
#: shapes the real flake has, in the smallest tree that has all of them.
FLAKE = """\
{
  packages = {
    default = mkFirmware { name = "firmware"; };
    firmware = mkFirmware { name = "firmware"; };
    firmware-no-touch = mkFirmware {
      name = "firmware-no-touch";
      cargoFlags = [
        "--features"
        "no-touch"
      ];
    };
    firmware-screen = mkFirmware {
      name = "firmware-screen";
      cargoFlags = [
        "--features"
        "screen"
      ];
    };
    firmware-pinned = mkFirmware {
      name = "firmware-pinned";
      vidpid = "Pico";
    };
  };
}
"""

WORKSPACE = """\
[workspace]
members = ["firmware", "crates/rsk-core", "crates/rsk-screen"]
"""

MANIFEST = """\
[package]
name = "firmware"

[dependencies]
rsk-core = { path = "../crates/rsk-core" }
rsk-screen = { path = "../crates/rsk-screen", optional = true }

[features]
no-touch = []
screen = ["dep:rsk-screen"]
loud = []
"""

CORE = """\
[package]
name = "rsk-core"
"""

SCREEN = """\
[package]
name = "rsk-screen"
"""

#: The presence gate `no-touch` throws, so `gate-compiled-out` has a switch to
#: point at.
PRESENCE = """\
#[cfg(not(feature = "no-touch"))]
pub fn press() -> bool { sample() }
/// Refines `Fixture!Gated` — SEC-A-001.
pub fn gated() {}
/// Refines `Fixture!Held` — SEC-A-002.
pub fn held() {}
"""

CEREMONY = """\
/// Refines `Fixture!Shown` — SEC-B-001.
pub fn shown() {}
"""

REGISTRY = """\
[[property]]
id = "SEC-A-001"
name = "Gated"

[[property]]
id = "SEC-A-002"
name = "Held"

[[property]]
id = "SEC-B-001"
name = "Shown"

[[property]]
id = "SEC-C-001"
name = "Later"
"""

CHECK_SH = """\
run "clippy (loud)" cargo clippy -p firmware --features loud -- -D warnings
run "build-configuration matrix" python scripts/matrix_gate.py
"""

RELEASE = """\
jobs:
  build:
    steps:
      - name: build
        run: |
          for pkg in firmware firmware-screen; do
            nix build ".#$pkg"
          done
      - name: rebuild
        run: |
          for pkg in firmware firmware-screen; do
            nix build ".#$pkg" --rebuild
          done
"""

LEDGER = """\
[tranche]
p0-launch = ["SEC-A-001", "SEC-A-002"]
p0b = ["SEC-B-001"]
p1 = ["SEC-C-001"]
out-of-queue = []

[[cell]]
properties = ["SEC-A-001", "SEC-A-002"]
columns = ["firmware"]
disposition = "covered"
basis = "default-build"
why = "the image every measurement was taken on."

[[cell]]
properties = ["SEC-B-001"]
columns = ["firmware", "firmware-no-touch", "firmware-pinned", "loud", "board-a"]
disposition = "out-of-scope"
basis = "crate-absent"
why = "rsk-screen is dep-gated behind the screen feature."

[[cell]]
properties = ["SEC-B-001"]
columns = ["firmware-screen"]
disposition = "covered"
basis = "stated"
why = "the only column that compiles the ceremony."

[[cell]]
properties = ["SEC-A-001", "SEC-A-002"]
columns = ["firmware-pinned"]
same_as = "firmware"
knob_delta = ["vidpid=Pico"]
disposition = "equivalent"
basis = "same-cargo-features"
why = "identical feature closure; the delta is a USB identity pair."

[[cell]]
properties = ["SEC-A-001"]
columns = ["firmware-no-touch"]
feature = "no-touch"
disposition = "out-of-scope"
basis = "gate-compiled-out"
why = "no-touch replaces the press with an auto-confirm."

[[question]]
column = "firmware-no-touch"
text = "does SEC-A-002 depend on the press indirectly?"

[[question]]
column = "firmware-screen"
text = "the screen build is not default plus screen."

[[question]]
column = "loud"
text = "is a never-shipped build in the supported set?"

[[question]]
column = "board-a"
text = "the board moves the presence pin."
"""

BOARD_A = """\
[usb]
vidpid = "RSKey"

[presence]
source = "gpio"
pin = 23
"""


class Tree:
    """A checkout with all three axes, in the smallest shape that has them."""

    def __init__(self, root):
        self.root = root
        self.write("Cargo.toml", WORKSPACE)
        self.write("firmware/Cargo.toml", MANIFEST)
        self.write("firmware/src/presence.rs", PRESENCE)
        self.write("crates/rsk-core/Cargo.toml", CORE)
        self.write("crates/rsk-core/src/lib.rs", "pub fn core() {}\n")
        self.write("crates/rsk-screen/Cargo.toml", SCREEN)
        self.write("crates/rsk-screen/src/lib.rs", CEREMONY)
        self.write("nix/firmware.nix", FLAKE)
        self.write("firmware/boards/board-a.toml", BOARD_A)
        self.write(".github/workflows/release-build.yml", RELEASE)
        self.write("scripts/check.sh", CHECK_SH)
        self.write("assurance/properties.toml", REGISTRY)
        self.write("assurance/configurations.toml", LEDGER)
        (root / "docs").mkdir(parents=True, exist_ok=True)
        matrix_gate.run(root, write=True)

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
        return matrix_gate.run(self.root)


@pytest.fixture
def tree(tmp_path, monkeypatch):
    # The shipped floors are about the real tree's 19 packages, 6 boards and 40
    # rows. Scaled to the fixture's so the collapse cases below still trip.
    monkeypatch.setattr(matrix_gate, "FLOOR_PACKAGES", 2)
    monkeypatch.setattr(matrix_gate, "FLOOR_BOARDS", 1)
    monkeypatch.setattr(matrix_gate, "FLOOR_ROWS", 2)
    matrix_gate.cfg_sites.cache_clear()
    return Tree(tmp_path)


def red(tree, capsys):
    """Run the guard, require it red, and hand back what it said."""
    assert tree.run() == 1
    return capsys.readouterr().err


# --- both directions, and the wiring -----------------------------------------


def test_the_clean_fixture_passes(tree):
    assert tree.run() == 0


def test_this_checkout_passes():
    """The guard has to be green on the tree it ships in, or it is not a row."""
    assert matrix_gate.run(ROOT) == 0


def test_check_sh_runs_the_row():
    """A guard nothing invokes can have its whole table deleted, suite green."""
    assert gate_lines.runs((ROOT / "scripts/check.sh").read_text(), "scripts/matrix_gate.py")


def test_the_shipped_matrix_is_the_one_the_generator_writes():
    """The artifact half of the same rule, on the real tree rather than a fixture."""
    assert matrix_gate.render(ROOT) == (ROOT / matrix_gate.ARTIFACT).read_text()


# --- the axes: a configuration with no column --------------------------------


def test_a_new_flake_package_has_no_column_until_the_matrix_is_regenerated(tree, capsys):
    """The roadmap's exit predicate, first half: a new `firmware-*` reddens the row."""
    tree.edit(
        "nix/firmware.nix",
        "    firmware-pinned = mkFirmware {",
        '    firmware-fips = mkFirmware {\n      name = "firmware-fips";\n    };\n'
        "    firmware-pinned = mkFirmware {",
    )
    assert "is not what the generator writes" in red(tree, capsys)


def test_a_new_board_preset_has_no_column_until_the_matrix_is_regenerated(tree, capsys):
    tree.write("firmware/boards/board-b.toml", BOARD_A)
    assert "is not what the generator writes" in red(tree, capsys)


def test_a_new_cargo_feature_has_no_column_until_the_matrix_is_regenerated(tree, capsys):
    """The `largeblob-ext` shape: an orthogonal feature with no flake package."""
    tree.edit("firmware/Cargo.toml", "loud = []", 'loud = []\nquiet = []')
    assert "is not what the generator writes" in red(tree, capsys)


def test_a_check_sh_row_for_a_feature_the_manifest_dropped_is_rejected(tree, capsys):
    """The other direction of the same rule: the row outlives its feature, so
    there is nothing for the derivation to make a column out of."""
    tree.edit("firmware/Cargo.toml", "loud = []\n", "")
    said = red(tree, capsys)
    assert "--features loud" in said
    assert "does not define" in said


def test_a_new_p0_family_property_has_no_row_until_it_is_classified(tree, capsys):
    """The row axis: a registry entry in no tranche is a row nobody would miss."""
    tree.edit(
        "assurance/properties.toml",
        '[[property]]\nid = "SEC-C-001"',
        '[[property]]\nid = "SEC-D-001"\nname = "Fresh"\n\n[[property]]\nid = "SEC-C-001"',
    )
    said = red(tree, capsys)
    assert "SEC-D-001" in said
    assert "in no tranche" in said


def test_classifying_a_new_property_still_needs_the_matrix_regenerated(tree, capsys):
    tree.edit(
        "assurance/properties.toml",
        '[[property]]\nid = "SEC-C-001"',
        '[[property]]\nid = "SEC-D-001"\nname = "Fresh"\n\n[[property]]\nid = "SEC-C-001"',
    )
    tree.edit("assurance/configurations.toml", 'p0b = ["SEC-B-001"]', 'p0b = ["SEC-B-001", "SEC-D-001"]')
    assert "is not what the generator writes" in red(tree, capsys)


def test_a_tranche_naming_a_property_the_registry_lost_is_rejected(tree, capsys):
    tree.edit("assurance/configurations.toml", 'p1 = ["SEC-C-001"]', 'p1 = ["SEC-C-001", "SEC-Z-999"]')
    assert "no such property" in red(tree, capsys)


def test_a_property_in_two_tranches_is_rejected(tree, capsys):
    tree.edit("assurance/configurations.toml", 'p1 = ["SEC-C-001"]', 'p1 = ["SEC-C-001", "SEC-A-001"]')
    assert "in more than one tranche" in red(tree, capsys)


# --- the equivalences, which are what a reviewer will attack ------------------


def test_an_equivalence_the_feature_closure_refutes_is_rejected(tree, capsys):
    """The sharpest arm. `firmware-screen` compiles a crate `firmware` does not,
    so an `equivalent` between them is false however plausible it reads — and
    the refusal has to name the crate, not merely disagree."""
    tree.edit("assurance/configurations.toml", 'same_as = "firmware"', 'same_as = "firmware-screen"')
    said = red(tree, capsys)
    assert "an equivalence the tree refutes" in said
    assert "rsk-screen" in said


def test_an_equivalent_cell_with_the_basis_removed_is_rejected(tree, capsys):
    """The roadmap's exit predicate, second half: deleting the justification
    from an `equivalent` cell reddens the row."""
    tree.edit(
        "assurance/configurations.toml",
        'disposition = "equivalent"\nbasis = "same-cargo-features"',
        'disposition = "equivalent"',
    )
    assert "basis `None` is not one of" in red(tree, capsys)


def test_an_equivalent_cell_with_the_reason_removed_is_rejected(tree, capsys):
    tree.edit(
        "assurance/configurations.toml",
        'why = "identical feature closure; the delta is a USB identity pair."',
        'why = "  "',
    )
    assert "a disposition with no reason" in red(tree, capsys)


def test_an_equivalence_asserted_as_prose_is_rejected(tree, capsys):
    """`stated` is a legal basis for a judgement and never for a sameness: the
    whole failure mode is an equivalence nobody can check."""
    tree.edit(
        "assurance/configurations.toml",
        'disposition = "equivalent"\nbasis = "same-cargo-features"',
        'disposition = "equivalent"\nbasis = "stated"',
    )
    assert "the only sameness this tree can check" in red(tree, capsys)


def test_an_equivalence_naming_no_column_is_rejected(tree, capsys):
    tree.edit("assurance/configurations.toml", 'same_as = "firmware"', 'same_as = "firmware-ghost"')
    assert "names no column in `same_as`" in red(tree, capsys)


def test_an_equivalence_with_itself_is_rejected(tree, capsys):
    tree.edit("assurance/configurations.toml", 'same_as = "firmware"', 'same_as = "firmware-pinned"')
    assert "names its own column" in red(tree, capsys)


def test_an_equivalence_that_does_not_write_down_its_knob_delta_is_rejected(tree, capsys):
    """Without this half the rule was VACUOUS on every cell that used it: both
    sides carry an empty cargo-feature set — that is what "the delta is knobs"
    means — so the check compared the empty set with itself, 143 times."""
    tree.edit("assurance/configurations.toml", 'knob_delta = ["vidpid=Pico"]\n', "")
    said = red(tree, capsys)
    assert "owes a `knob_delta`" in said
    assert "the tree derives ['vidpid=Pico']" in said


def test_a_knob_the_column_gained_reddens_its_equivalence(tree, capsys):
    tree.edit("nix/firmware.nix", '      vidpid = "Pico";', '      vidpid = "Pico";\n      flashSize = "8M";')
    said = red(tree, capsys)
    assert "declares the knob delta ['vidpid=Pico']" in said
    assert "flashSize=8M" in said


def test_a_knob_whose_VALUE_moved_reddens_its_equivalence(tree, capsys):
    """The names alone cannot see this, and it is the edit that matters: a board
    earns its equivalence by setting knobs to the values `build.rs` defaults to,
    and one of them drifting leaves an identical name list."""
    tree.edit("nix/firmware.nix", 'vidpid = "Pico";', 'vidpid = "Dev";')
    said = red(tree, capsys)
    assert "declares the knob delta ['vidpid=Pico']" in said
    assert "vidpid=Dev" in said


def test_an_equivalence_over_several_columns_at_once_is_rejected(tree, capsys):
    """One cell, one column: the knob delta differs per column, so a cell that
    swept several would carry a delta true of at most one of them."""
    tree.edit(
        "assurance/configurations.toml",
        'columns = ["firmware-pinned"]\nsame_as',
        'columns = ["firmware-pinned", "board-a"]\nsame_as',
    )
    assert "names 2 columns" in red(tree, capsys)


# --- the other bases, each held to the tree it claims about -------------------


def test_claiming_an_absent_crate_that_is_compiled_in_is_rejected(tree, capsys):
    """Direction matters: the message has to say the crate is PRESENT, not that
    a label is unrecognised."""
    tree.edit(
        "assurance/configurations.toml",
        'columns = ["firmware", "firmware-no-touch", "firmware-pinned", "loud", "board-a"]',
        'columns = ["firmware", "firmware-no-touch", "firmware-pinned", "loud", "board-a",'
        ' "firmware-screen"]',
    )
    said = red(tree, capsys)
    assert "claims SEC-B-001's owners are absent" in said
    assert "rsk-screen" in said


def test_a_compiled_out_gate_a_column_does_not_enable_is_rejected(tree, capsys):
    tree.edit(
        "assurance/configurations.toml",
        'feature = "no-touch"',
        'feature = "screen"',
    )
    assert "which this column does not enable" in red(tree, capsys)


def test_a_compiled_out_gate_no_code_reads_is_rejected(tree, capsys):
    """A feature with no `cfg` site is a switch that throws nothing."""
    tree.edit("firmware/src/presence.rs", '#[cfg(not(feature = "no-touch"))]\n', "")
    assert "no production Rust gates on it" in red(tree, capsys)


def test_the_default_build_basis_on_a_configured_column_is_rejected(tree, capsys):
    tree.edit(
        "assurance/configurations.toml",
        'columns = ["firmware"]\ndisposition = "covered"',
        'columns = ["firmware-no-touch"]\ndisposition = "covered"',
    )
    assert "basis `default-build` on a column that enables" in red(tree, capsys)


# --- the vocabulary and the shape of the ledger -------------------------------


def test_a_sixth_disposition_is_rejected(tree, capsys):
    tree.edit(
        "assurance/configurations.toml",
        'disposition = "covered"\nbasis = "stated"',
        'disposition = "probably-fine"\nbasis = "stated"',
    )
    assert "disposition `probably-fine` is not one of" in red(tree, capsys)


def test_an_invented_basis_is_rejected(tree, capsys):
    tree.edit("assurance/configurations.toml", 'basis = "crate-absent"', 'basis = "looks-the-same"')
    assert "basis `looks-the-same` is not one of" in red(tree, capsys)


def test_two_dispositions_for_one_cell_are_rejected(tree, capsys):
    tree.edit(
        "assurance/configurations.toml",
        'properties = ["SEC-B-001"]\ncolumns = ["firmware-screen"]',
        'properties = ["SEC-B-001"]\ncolumns = ["firmware-screen", "firmware"]',
    )
    assert "is disposed of twice" in red(tree, capsys)


def test_a_cell_for_a_column_that_does_not_exist_is_rejected(tree, capsys):
    tree.edit("assurance/configurations.toml", '"loud", "board-a"]', '"loud", "board-a", "board-z"]')
    assert "no such build configuration" in red(tree, capsys)


def test_a_cell_for_a_property_outside_the_p0_family_is_rejected(tree, capsys):
    tree.edit(
        "assurance/configurations.toml",
        'properties = ["SEC-B-001"]\ncolumns = ["firmware-screen"]',
        'properties = ["SEC-B-001", "SEC-C-001"]\ncolumns = ["firmware-screen"]',
    )
    assert "is not a P0-family property" in red(tree, capsys)


# --- `gap` is a value, not a shrug -------------------------------------------


def test_a_declared_gap_cell_is_rejected(tree, capsys):
    """`gap` is the ABSENCE of a cell here. Declaring one put the cell in the
    placed set, which took the column out of the rule below while the grid still
    printed `gap` in every one of its cells — measured on the real ledger at 37
    cells and a deleted question, gate green."""
    tree.edit(
        "assurance/configurations.toml",
        'disposition = "covered"\nbasis = "stated"',
        'disposition = "gap"\nbasis = "stated"',
    )
    said = red(tree, capsys)
    assert "disposition `gap` is not one of" in said
    assert "owe a settling question" in said


def test_a_column_with_gaps_and_no_question_is_rejected(tree, capsys):
    tree.edit(
        "assurance/configurations.toml",
        '[[question]]\ncolumn = "firmware-no-touch"\ntext = "does SEC-A-002 depend on the press indirectly?"\n\n',
        "",
    )
    said = red(tree, capsys)
    assert "`gap` cell(s) and no settling question" in said
    assert "a shrug" in said


def test_a_question_for_a_column_with_nothing_left_to_settle_is_rejected(tree, capsys):
    tree.edit(
        "assurance/configurations.toml",
        '[[question]]\ncolumn = "loud"',
        '[[question]]\ncolumn = "firmware-pinned"\ntext = "nothing is open here."\n\n[[question]]\ncolumn = "loud"',
    )
    assert "no `gap` cell left to settle" in red(tree, capsys)


def test_a_question_for_a_column_that_does_not_exist_is_rejected(tree, capsys):
    tree.edit('assurance/configurations.toml', 'column = "board-a"', 'column = "board-z"')
    assert "which is no column" in red(tree, capsys)


# --- the derivation itself, which is the half a verdict column cannot show ----


def test_an_axis_that_derives_to_nothing_is_rejected(tree, capsys):
    """Every rule above passes over an empty matrix; five guards in this tree
    shipped with exactly that shape."""
    tree.write("nix/firmware.nix", "{ packages = { }; }\n")
    said = red(tree, capsys)
    assert "under the floors" in said
    assert "passed over an empty matrix" in said


def test_a_row_axis_that_derives_to_nothing_is_rejected(tree, capsys):
    tree.edit("assurance/configurations.toml", 'p0-launch = ["SEC-A-001", "SEC-A-002"]', "p0-launch = []")
    assert "under the floor of" in red(tree, capsys)


def test_a_published_image_the_flake_does_not_build_is_rejected(tree, capsys):
    tree.edit(
        ".github/workflows/release-build.yml",
        "          for pkg in firmware firmware-screen; do\n            nix build \".#$pkg\"\n",
        "          for pkg in firmware firmware-screen firmware-ghost; do\n            nix build \".#$pkg\"\n",
    )
    said = red(tree, capsys)
    assert "publishes firmware-ghost" in said
    assert "flavor loops disagree" in said


def test_a_package_the_pattern_cannot_see_is_reported(tree, capsys):
    """The saw-everything invariant. Without it a package written in a spelling
    the block pattern misses is a column that never exists, and the only thing
    the gate would ever say is "regenerate and commit" — which launders it."""
    tree.edit(
        "nix/firmware.nix",
        "    firmware-pinned = mkFirmware {",
        '    inherit (x) y;\n    z = { a = mkFirmware { name = "ghost"; }; };\n'
        "    firmware-pinned = mkFirmware {",
    )
    said = red(tree, capsys)
    assert "calls mkFirmware" in said
    assert "a column that never exists" in said


def test_a_package_with_the_call_on_the_next_line_is_still_a_column(tree, capsys):
    """The green direction of the same rule: `attr =` / newline / `mkFirmware {`
    is how this very file already breaks two other bindings, and reading it as
    absent would report a package that is there as gone."""
    tree.edit(
        "nix/firmware.nix",
        "    firmware-pinned = mkFirmware {",
        "    firmware-pinned =\n      mkFirmware {",
    )
    assert tree.run() == 0


def test_a_features_flag_written_with_an_equals_sign_is_read(tree, capsys):
    """`--features=a` is a spelling cargo takes and a hand-rolled word scan does
    not — and a package whose features read as empty looks like the default
    build, which is a basis the gate ACCEPTS."""
    tree.edit(
        "nix/firmware.nix",
        '        "--features"\n        "screen"\n',
        '        "--features=screen"\n',
    )
    assert tree.run() == 0


def test_a_board_in_a_subdirectory_is_a_column(tree, capsys):
    """`build.rs` reads `boards/{BOARD}.toml` with no rule against a `/`, so a
    flat glob calls a real, buildable preset no board at all."""
    tree.write("firmware/boards/vendor/board-c.toml", BOARD_A)
    assert "is not what the generator writes" in red(tree, capsys)


def test_one_flavor_loop_is_under_the_floor(tree, capsys):
    """Without the floor, a reflow that hides one loop leaves the "the two lists
    must agree" comparison running over a single list, in silence."""
    tree.edit(
        ".github/workflows/release-build.yml",
        "      - name: rebuild\n        run: |\n          for pkg in firmware firmware-screen; do\n            nix build \".#$pkg\" --rebuild\n          done\n",
        "",
    )
    assert "under the floor of" in red(tree, capsys)


def test_a_malformed_input_is_a_finding_and_not_a_traceback(tree, capsys):
    """A traceback is a red too, and a much worse one: it names a line of the
    guard rather than the file whose shape changed."""
    tree.write("firmware/boards/board-a.toml", "loose = 1\n")
    assert "the axes cannot be derived from the tree" in red(tree, capsys)


def test_a_weak_feature_edge_fires_whatever_order_it_is_offered_in(tree, capsys):
    """`dep?/feat` fires only once the optional dependency is in, and a single
    pass drops the edge when it is walked first. `Column` passes the features
    SORTED, so a single-pass answer depended on the alphabet — and it
    under-approximated, which is the direction that makes a false `equivalent`
    pass."""
    tree.edit("firmware/Cargo.toml", "loud = []", 'loud = ["rsk-screen?/loud"]')
    tree.write("crates/rsk-screen/Cargo.toml", SCREEN + "\n[features]\nloud = []\n")
    manifests = matrix_gate.workspace(tree.root)
    both = [matrix_gate.resolve(manifests, order)[1].get("rsk-screen", frozenset())
            for order in (["loud", "screen"], ["screen", "loud"])]
    assert both[0] == both[1] == frozenset({"loud"}), both
    assert matrix_gate.resolve(manifests, ["loud"])[1].get("rsk-screen") is None


def test_a_hand_edited_matrix_is_rejected(tree, capsys):
    """The artifact says "do not edit by hand" and nothing made that true until
    this row; `config_gen_gate.py` shipped for the same reason one file over."""
    tree.edit("docs/assurance-matrix.md", "## Open gaps", "## Open holes")
    assert "is not what the generator writes" in red(tree, capsys)
