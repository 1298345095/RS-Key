# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""The mutation table `platform_gate.py` is verified against.

Every rule is broken once on a fixture and the break must be the finding it
claims to be — the message is asserted, never the count, because a red run whose
reason nobody read proves as little as one that cannot go red. Then the real
checkout closes the other direction.

Two families here are the ones the guard was measured wrong on before it shipped.
The candidate derivations each have BOTH spellings driven: a slice assumption
declared in a bundle and one written only in a design page; a board-only suite
the USB/IP guest names as a glob (`tests/02_*.py`) and one it names in full
(`tests/73_otp_keyboard.py`). And the four derivations are floored apart rather
than in total, because a floor over the union cannot tell "the `unsafe` finder
stopped finding" from "the bundle reader did".
"""

import pathlib
import subprocess
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).parent))
import gate_lines
import platform_gate

ROOT = pathlib.Path(__file__).resolve().parents[1]

MODEL_REGISTRY = """\
[[assumption]]
constant = "WorldIsFlat"
statement = "A model constant the fixture pins both ways."
discharged_by = "a measurement"
risk = "coverage"
"""

PROPERTIES = """\
[[property]]
id = "SEC-T-001"
name = "FooStaysClosed"
status = "MODELLED-ONLY"
statement = "Foo stays closed."
source = ["spec"]
"""

BUNDLE = """\
[property]
id = "SEC-T-001"

[[assumption]]
id = "AS-T-1"
statement = "The emulator answers as the board."
registered = "yes — PLAT-TOOL-001"
"""

DESIGN_PAGE = """\
# The slice

| id | Assumption |
|---|---|
| `AS-T-2` | A design-page assumption with no bundle row yet |
"""

EMU_SHIM = '''\
"""The shim."""
UNSUPPORTED = {
    "29_reset_power_cut": "cuts physical USB power during a flash write",
    "02_usb_interfaces": "reads the USB descriptors; this shim serves reports",
    "73_otp_keyboard": "drives the OTP keyboard interface over raw USB",
}
'''

USBIP_GUEST = """\
#!/usr/bin/env bash
for t in tests/02_*.py; do run "$t"; done
run tests/73_otp_keyboard.py
"""

UNSAFE_RS = """\
pub fn steal() {
    unsafe { core::ptr::null::<u8>().read() };
}
"""

REGISTRY = """\
[[assumption]]
id = "PLAT-TOOL-001"
class = "tool-fidelity"
statement = "The emulator answers as the board."
discharge = "A board recording of the same session."
discharge_owner = "maintainer"
status = "pending"
failure_direction = "security: every trace-linked claim is about the emulator"
covers = ["slice:AS-T-1"]
supports = ["SEC-T-001"]

[[assumption]]
id = "PLAT-MODEL-001"
class = "model-abstraction"
statement = "A design-page assumption with no bundle row yet."
discharge = "The store slice."
discharge_owner = "contributor"
status = "pending"
failure_direction = "coverage: a cardinality nothing runs"
covers = ["slice:AS-T-2"]

[[assumption]]
id = "PLAT-BUILD-001"
class = "build-configuration"
statement = "The world is flat, as the build sees it."
discharge = "The manifest."
discharge_owner = "contributor"
status = "discharged"
evidence = ["assurance/properties.toml"]
revalidated_by = "any change to the manifest"
failure_direction = "coverage: the arm the tree does not take is the stricter one"
covers = ["model:WorldIsFlat"]
discharges = ["WorldIsFlat"]

[[assumption]]
id = "PLAT-FLASH-001"
class = "flash"
statement = "The tear model is the one the store assumes."
discharge = "A recorded PASS on a throwaway board."
discharge_owner = "maintainer"
status = "pending"
failure_direction = "security: a torn write could leave a credential live"
covers = ["board-only:29_reset_power_cut"]
supports = ["SEC-T-001"]

[[assumption]]
id = "PLAT-TOOLCHAIN-001"
class = "toolchain"
statement = "Every unsafe upholds an invariant the compiler cannot check."
discharge = "A source audit per site."
discharge_owner = "contributor"
status = "pending"
failure_direction = "security: the one class safe Rust does not rule out"
covers = ["unsafe:crates/rsk-a/src/lib.rs", "unsafe:firmware/src/main.rs"]
"""


class Tree:
    """A checkout shaped like this one, small enough to break one rule at a time."""

    def __init__(self, root):
        self.root = pathlib.Path(root)
        self.write("assurance/assumptions.toml", MODEL_REGISTRY)
        self.write("assurance/properties.toml", PROPERTIES)
        self.write("assurance/bundle/SEC-T-001.toml", BUNDLE)
        self.write("assurance/platform.toml", REGISTRY)
        self.write("docs/authorization-slice.md", DESIGN_PAGE)
        self.write("tests/emu.py", EMU_SHIM)
        self.write("scripts/usbip-guest.sh", USBIP_GUEST)
        self.write("crates/rsk-a/src/lib.rs", UNSAFE_RS)
        self.write("firmware/src/main.rs", UNSAFE_RS)
        # Tracked-but-safe Rust, so the `unsafe:` derivation is selecting rather
        # than returning everything it walks.
        self.write("crates/rsk-a/src/safe.rs", "pub const N: u8 = 1;\n")
        self.git("init", "-q")
        self.git("add", "-A")
        self.regenerate()

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

    def append(self, rel, text):
        (self.root / rel).write_text((self.root / rel).read_text() + text)

    def git(self, *args):
        subprocess.run(["git", "-C", str(self.root), *args], check=True, capture_output=True)

    def regenerate(self):
        self.write("docs/platform-assumptions.md", platform_gate.render(self.root))

    def problems(self):
        return platform_gate.audit(self.root)[0]


@pytest.fixture
def tree(tmp_path):
    return Tree(tmp_path)


def only(problems, needle):
    """The problems mentioning `needle`, so a message is asserted, not a count."""
    return [p for p in problems if needle in p]


# --- both directions of green -------------------------------------------------


def test_the_fixture_is_green(tree):
    assert tree.problems() == []


def test_this_checkout_is_green():
    findings, summary = platform_gate.audit(ROOT)
    assert findings == [], findings
    assert summary.startswith("platform-gate: ok")


def test_the_fixture_derives_all_four_candidate_kinds(tree):
    """A fixture missing a namespace would pass that namespace's rules vacuously."""
    found = platform_gate.candidates(tree.root)
    assert set(found) == {
        "slice:AS-T-1",
        "slice:AS-T-2",
        "model:WorldIsFlat",
        "board-only:29_reset_power_cut",
        "unsafe:crates/rsk-a/src/lib.rs",
        "unsafe:firmware/src/main.rs",
    }, sorted(found)


def test_the_checkout_derives_what_it_is_measured_at():
    """The four counts this row's own docstring in `check.sh` is written from.

    Not a transcription that drifts: each is an assertion about the SHAPE of the
    derivation. `board-only` is the one worth pinning by name — it is the pair of
    files that produced it, and either of them changing changes what this tree
    says it owes a board.
    """
    found = platform_gate.candidates(ROOT)
    kinds = {prefix: [k for k in found if k.startswith(f"{prefix}:")] for prefix in platform_gate.FLOORS}
    assert set(kinds["board-only"]) == {
        "board-only:29_reset_power_cut",
        "board-only:51_secure_reboot",
        "board-only:53_ccid_pinpad",
        "board-only:54_sram_residue",
        "board-only:90_otp_mkek_migration",
    }, kinds["board-only"]
    assert set(kinds["model"]) == {
        "model:PowerOnClearsScratch2",
        "model:AlwaysUvShipped",
    }, kinds["model"]
    assert len(kinds["slice"]) >= 8, kinds["slice"]
    assert len(kinds["unsafe"]) >= 7, kinds["unsafe"]


# --- rule 1: every derived candidate is claimed --------------------------------


def test_an_unclaimed_bundle_assumption_is_a_finding(tree):
    tree.append(
        "assurance/bundle/SEC-T-001.toml",
        '\n[[assumption]]\nid = "AS-T-9"\nstatement = "A ninth."\nregistered = "no"\n',
    )
    assert only(tree.problems(), "slice:AS-T-9: derived from")


def test_an_unclaimed_design_page_assumption_is_a_finding(tree):
    """The other spelling: prose, written before the slice has a bundle."""
    tree.append("docs/authorization-slice.md", "\n| `AS-T-3` | A third |\n")
    assert only(tree.problems(), "slice:AS-T-3: derived from")


def test_an_unclaimed_model_constant_is_a_finding(tree):
    tree.append(
        "assurance/assumptions.toml",
        '\n[[assumption]]\nconstant = "SkyIsGreen"\nstatement = "s"\n'
        'discharged_by = "d"\nrisk = "coverage"\n',
    )
    assert only(tree.problems(), "model:SkyIsGreen: derived from")


def test_an_unclaimed_board_only_suite_is_a_finding(tree):
    tree.edit(
        "tests/emu.py",
        '"73_otp_keyboard"',
        '"54_sram_residue": "measures SRAM residue on a real chip",\n    "73_otp_keyboard"',
    )
    assert only(tree.problems(), "board-only:54_sram_residue: derived from")


def test_an_unclaimed_unsafe_file_is_a_finding(tree):
    tree.write("crates/rsk-b/src/lib.rs", UNSAFE_RS)
    tree.git("add", "-A")
    assert only(tree.problems(), "unsafe:crates/rsk-b/src/lib.rs: derived from")


def test_a_usbip_glob_covers_its_suite(tree):
    """`tests/02_*.py` is a glob and `tests/73_otp_keyboard.py` is a full name.

    Both are how the guest actually writes them, and a rule that read only one
    would report an obligation for a suite a runner already passes.
    """
    found = platform_gate.candidates(tree.root)
    assert "board-only:02_usb_interfaces" not in found
    assert "board-only:73_otp_keyboard" not in found


# --- rule 2: and the other way -------------------------------------------------


def test_a_covers_no_derivation_produces_is_a_finding(tree):
    tree.edit("assurance/platform.toml", '"slice:AS-T-1"', '"slice:AS-T-404"')
    assert only(tree.problems(), "covers 'slice:AS-T-404', which no derivation produces")


def test_a_candidate_claimed_twice_is_a_finding(tree):
    tree.edit(
        "assurance/platform.toml",
        'covers = ["board-only:29_reset_power_cut"]',
        'covers = ["board-only:29_reset_power_cut", "slice:AS-T-1"]',
    )
    assert only(tree.problems(), "slice:AS-T-1 is claimed by both")


# --- rule 3: a discharge route and an owner ------------------------------------


def test_a_missing_hand_field_is_a_finding(tree):
    tree.edit("assurance/platform.toml", 'failure_direction = "coverage: a cardinality nothing runs"\n', "")
    assert only(tree.problems(), "PLAT-MODEL-001: is missing ['failure_direction']")


def test_a_field_outside_the_schema_is_a_finding(tree):
    tree.append("assurance/platform.toml", '\nconfidence = "high"\n')
    assert only(tree.problems(), "`confidence` is not a field of this registry")


def test_a_top_level_table_beside_the_entries_is_a_finding(tree):
    tree.append("assurance/platform.toml", '\n[summary]\ndischarged = 18\n')
    assert only(tree.problems(), "top-level `summary`")


def test_a_class_outside_the_vocabulary_is_a_finding(tree):
    tree.edit("assurance/platform.toml", 'class = "flash"', 'class = "vibes"')
    assert only(tree.problems(), "class 'vibes' is not one of")


def test_a_status_outside_the_vocabulary_is_a_finding(tree):
    tree.edit("assurance/platform.toml", 'status = "discharged"', 'status = "probably-fine"')
    assert only(tree.problems(), "status 'probably-fine' is not one of")


def test_an_owner_outside_the_vocabulary_is_a_finding(tree):
    tree.edit("assurance/platform.toml", 'discharge_owner = "maintainer"\nstatus = "pending"\nfailure_direction = "security: every', 'discharge_owner = "someone"\nstatus = "pending"\nfailure_direction = "security: every')
    assert only(tree.problems(), "an obligation nobody owns is a wish")


def test_an_empty_discharge_route_is_a_finding(tree):
    tree.edit("assurance/platform.toml", 'discharge = "The store slice."', 'discharge = "   "')
    assert only(tree.problems(), "no discharge route")


def test_a_bad_entry_id_is_a_finding(tree):
    tree.edit("assurance/platform.toml", 'id = "PLAT-FLASH-001"', 'id = "flash-tear"')
    assert only(tree.problems(), "entry id 'flash-tear' is not `PLAT-AREA-NNN`")


def test_a_duplicate_entry_id_is_a_finding(tree):
    tree.edit("assurance/platform.toml", 'id = "PLAT-MODEL-001"', 'id = "PLAT-TOOL-001"')
    assert only(tree.problems(), "PLAT-TOOL-001: a second entry under the same id")


# --- rule 4: a claim of discharge owes evidence --------------------------------


def test_a_discharge_with_no_evidence_is_a_finding(tree):
    tree.edit("assurance/platform.toml", 'evidence = ["assurance/properties.toml"]\n', "")
    assert only(tree.problems(), "with no `evidence`")


def test_a_discharge_naming_evidence_that_is_not_there_is_a_finding(tree):
    tree.edit("assurance/platform.toml", '"assurance/properties.toml"]', '"assurance/gone.toml"]')
    assert only(tree.problems(), "evidence 'assurance/gone.toml' is not in the tree")


def test_a_discharge_with_no_revalidation_trigger_is_a_finding(tree):
    tree.edit("assurance/platform.toml", 'revalidated_by = "any change to the manifest"\n', "")
    assert only(tree.problems(), "with no `revalidated_by`")


def test_a_hardware_discharge_with_no_board_revision_is_a_finding(tree):
    tree.edit(
        "assurance/platform.toml",
        'discharge_owner = "maintainer"\nstatus = "pending"\nfailure_direction = "security: a torn',
        'discharge_owner = "maintainer"\nstatus = "discharged"\n'
        'evidence = ["assurance/properties.toml"]\nrevalidated_by = "a new stepping"\n'
        'failure_direction = "security: a torn',
    )
    assert only(tree.problems(), "names no RP2350 stepping in `board_revision`")


def test_a_bare_stepping_is_not_a_board_revision(tree):
    """`A2` alone is what a Kani harness's own claims are named, not silicon."""
    tree.edit(
        "assurance/platform.toml",
        'discharge_owner = "maintainer"\nstatus = "pending"\nfailure_direction = "security: a torn',
        'discharge_owner = "maintainer"\nstatus = "discharged"\n'
        'evidence = ["assurance/properties.toml"]\nboard_revision = "A2"\n'
        'revalidated_by = "a new stepping"\nfailure_direction = "security: a torn',
    )
    assert only(tree.problems(), "names no RP2350 stepping in `board_revision`")


def test_a_pending_entry_carrying_evidence_is_a_finding(tree):
    tree.edit(
        "assurance/platform.toml",
        'failure_direction = "coverage: a cardinality nothing runs"',
        'evidence = ["assurance/properties.toml"]\n'
        'failure_direction = "coverage: a cardinality nothing runs"',
    )
    assert only(tree.problems(), "an artifact nothing rests on is decoration")


# --- rule 5: links resolve -----------------------------------------------------


def test_supports_naming_no_property_is_a_finding(tree):
    """A property depending on an assumption that does not exist, from the side
    that can be checked: the registry's id vocabulary is the one that is real."""
    tree.edit("assurance/platform.toml", 'supports = ["SEC-T-001"]\n\n[[assumption]]\nid = "PLAT-MODEL-001"', 'supports = ["SEC-T-404"]\n\n[[assumption]]\nid = "PLAT-MODEL-001"')
    assert only(tree.problems(), "supports 'SEC-T-404' is not a property")


def test_depends_on_naming_no_entry_is_a_finding(tree):
    tree.append("assurance/platform.toml", '\ndepends_on = ["PLAT-GONE-001"]\n')
    assert only(tree.problems(), "depends_on 'PLAT-GONE-001' is not an entry")


def test_refines_naming_itself_is_a_finding(tree):
    tree.append("assurance/platform.toml", '\nrefines = ["PLAT-TOOLCHAIN-001"]\n')
    assert only(tree.problems(), "PLAT-TOOLCHAIN-001: refines names itself")


def test_discharges_naming_no_constant_is_a_finding(tree):
    tree.edit("assurance/platform.toml", 'discharges = ["WorldIsFlat"]', 'discharges = ["SkyIsGreen"]')
    assert only(tree.problems(), "discharges 'SkyIsGreen' is not a constant")


def test_covering_a_model_constant_without_discharging_it_is_a_finding(tree):
    tree.edit("assurance/platform.toml", 'discharges = ["WorldIsFlat"]\n', "")
    assert only(tree.problems(), "covers model:WorldIsFlat but does not discharge it")


def test_discharging_a_constant_without_covering_it_is_a_finding(tree):
    """The half that keeps the two registries from holding two answers.

    Without it a second entry could claim the discharge of a constant a first
    entry covers, and each would look complete on its own.
    """
    tree.edit("assurance/platform.toml", 'covers = ["model:WorldIsFlat"]\n', "")
    assert only(tree.problems(), "without covering `model:WorldIsFlat`")


# --- rule 6: the page, and a status that moves silently ------------------------


def test_a_status_that_moves_without_the_page_is_a_finding(tree):
    """The whole content of "not silently": the flip is cheap, the diff is what
    this buys — and the byte-diff is what makes the diff compulsory."""
    tree.edit("assurance/platform.toml", 'status = "discharged"', 'status = "accepted-risk"')
    problems = tree.problems()
    assert only(problems, "docs/platform-assumptions.md is not what the generator writes")


def test_a_hand_edit_of_the_page_is_a_finding(tree):
    tree.edit("docs/platform-assumptions.md", "Discharged: 1 of 5.", "Discharged: 5 of 5.")
    assert only(tree.problems(), "docs/platform-assumptions.md is not what the generator writes")


def test_the_page_carries_every_entry_and_its_status(tree):
    page = (tree.root / "docs/platform-assumptions.md").read_text()
    for name in ("PLAT-TOOL-001", "PLAT-MODEL-001", "PLAT-BUILD-001", "PLAT-FLASH-001"):
        assert f"`{name}`" in page, name
    assert "Discharged: 1 of 5." in page


# --- rule 7: the bundle's own `registered` field -------------------------------


def test_a_bundle_saying_no_over_a_registered_assumption_is_a_finding(tree):
    """It said `no` on eight of ten rows the day this registry did not exist."""
    tree.edit("assurance/bundle/SEC-T-001.toml", 'registered = "yes — PLAT-TOOL-001"', 'registered = "no"')
    assert only(tree.problems(), "assurance/platform.toml does claim it")


def test_a_bundle_saying_yes_over_an_unregistered_assumption_is_a_finding(tree):
    """The claim is checked in both directions, so neither word is free."""
    tree.edit("assurance/platform.toml", 'covers = ["slice:AS-T-1"]', "covers = []")
    problems = tree.problems()
    assert only(problems, "assurance/platform.toml does not claim it")
    assert only(problems, "slice:AS-T-1: derived from")


def test_a_bundle_assumption_with_no_registered_field_is_a_finding(tree):
    tree.edit("assurance/bundle/SEC-T-001.toml", 'registered = "yes — PLAT-TOOL-001"\n', "")
    assert only(tree.problems(), "carries no `registered`")


# --- rule 8: a reader that stopped reading -------------------------------------


def test_the_board_only_derivation_is_floored(tree):
    """A source that is there and read as empty looks exactly like nothing to do."""
    tree.edit("tests/emu.py", "UNSUPPORTED = {", "UNSUPPORTED_SUITES = {")
    assert only(tree.problems(), "the `board-only:` derivation found 0 candidate(s)")


def test_the_slice_derivation_is_floored(tree):
    tree.write("assurance/bundle/SEC-T-001.toml", '[property]\nid = "SEC-T-001"\n')
    tree.write("docs/authorization-slice.md", "# The slice\n")
    assert only(tree.problems(), "the `slice:` derivation found 0 candidate(s)")


def test_the_unsafe_derivation_is_floored(tree):
    tree.write("crates/rsk-a/src/lib.rs", "pub const N: u8 = 1;\n")
    tree.write("firmware/src/main.rs", "pub const N: u8 = 1;\n")
    assert only(tree.problems(), "the `unsafe:` derivation found 0 candidate(s)")


def test_the_floors_are_apart_not_in_total(tree):
    """One number over the union cannot say WHICH reader stopped."""
    assert set(platform_gate.FLOORS) == {"slice", "model", "board-only", "unsafe"}


# --- the row that runs it ------------------------------------------------------


def test_check_sh_runs_this_gate():
    """Its own row, including that a `#` in front of it is not an invocation."""
    text = (ROOT / "scripts/check.sh").read_text()
    assert gate_lines.runs(text, "scripts/platform_gate.py")


def test_the_entry_point_exits_nonzero_on_a_finding(tmp_path):
    """Through `main()`, not `audit()`: the row runs the script, and a guard that
    finds a problem and returns 0 is one `check.sh` steps straight over."""
    tree = Tree(tmp_path)
    tree.edit("assurance/platform.toml", '"slice:AS-T-1"', '"slice:AS-T-404"')
    assert platform_gate.run(tree.root) == 1
    assert platform_gate.run(Tree(tmp_path / "clean").root) == 0
