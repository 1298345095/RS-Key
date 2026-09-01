# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""The mutation table `toolchain_gate.py` is verified against.

Same discipline as its siblings: for every rule, one mutation that must make the
row RED, and controls that must leave it GREEN. Two of those controls are the
point of the table rather than decoration.

The FIRST is the one this gate would most easily get wrong. Every `flake.lock`
node carries a `lastModified` beside its `rev`, and the obvious implementation —
hash the node, compare the hash — reddens on a plain re-fetch, where the
timestamp moves and the revision does not. A row that goes red on a no-op refresh
is a row somebody switches off, so `test_a_refetch_that_moves_only_lastmodified`
drives exactly that and demands EXIT=0.

The second is the shape this tree keeps shipping guards with: a parser that has
stopped matching finds nothing, loops over nothing and exits 0. So a `flake.lock`
whose format moved out from under the reader has to be RED and not green
(`test_a_lock_the_parser_cannot_read_is_red`), and both floors are driven from
BELOW rather than asserted from above.

Every fixture edit asserts its anchor resolved, so a fixture that has drifted
fails loudly instead of mutating nothing. The floors are PARAMETERS of `audit`
and not globals a case reaches in and lowers.
"""

import json
import pathlib

import pytest

import gate_lines
import toolchain_gate as gate

ROOT = pathlib.Path(__file__).resolve().parent.parent

NIXPKGS_REV = "331800de5053fcebacf6813adb5db9c9dca22a0c"
FENIX_REV = "3a556b6fbd42412b6f3f0ea8d35959b1826f86ff"
SDL_REV = "50ab793786d9de88ee30ec4e4c24fb4236fc2674"
UTILS_REV = "11707dc2f618dd54ca8739b309ec4fc024de578b"
CORTEX_M = "8ec610d8f49840a5b376c69663b6369e71f4b34484b9b2eb29fb918d92516cb9"


def lock(last_modified=1780243769):
    """The lock, with nixpkgs's `lastModified` as a parameter — see the control."""
    return {
        "nodes": {
            "root": {
                "inputs": {
                    "fenix": "fenix",
                    "flake-utils": "flake-utils",
                    "nixpkgs": "nixpkgs",
                    "nixpkgs-sdl2": "nixpkgs-sdl2",
                }
            },
            "fenix": {"locked": {"lastModified": 1780824777, "rev": FENIX_REV, "type": "github"}},
            "flake-utils": {"locked": {"lastModified": 1731533236, "rev": UTILS_REV, "type": "github"}},
            "nixpkgs": {"locked": {"lastModified": last_modified, "rev": NIXPKGS_REV, "type": "github"}},
            "nixpkgs-sdl2": {"locked": {"lastModified": 1751274312, "rev": SDL_REV, "type": "github"}},
        },
        "root": "root",
        "version": 7,
    }


CARGO = f"""\
version = 4

[[package]]
name = "cortex-m"
version = "0.7.7"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "{CORTEX_M}"

[[package]]
name = "firmware"
version = "0.1.0"
"""

PLATFORM = """\
[[assumption]]
id = "PLAT-TOOL-003"
class = "tool-tcb"
statement = "Kani/CBMC is sound for the arithmetic its harnesses bound."
status = "pending"

[[assumption]]
id = "PLAT-TOOL-004"
class = "tool-tcb"
statement = "TLC is sound for the finite configurations it checks."
status = "discharged"
"""

WORKFLOW_A = """\
name: ci
jobs:
  kani:
    env:
      KANI_VERSION: "0.67.0"
    steps:
      - run: cargo install --locked kani-verifier --version "$KANI_VERSION"
"""

WORKFLOW_B = """\
name: deep-checks
jobs:
  proofs:
    env:
      KANI_VERSION: "0.67.0"
    steps:
      - run: echo "$KANI_VERSION"
  shrink:
    env:
      KANI_VERSION: "0.67.0"
    steps:
      - run: echo "$KANI_VERSION"
"""

PAGE = """\
# Supply chain

Prose the gate must not touch.

<!-- toolchain-tcb:start -->
<!-- toolchain-tcb:end -->

More prose.
"""

REGISTRY = f"""\
# SPDX-License-Identifier: AGPL-3.0-only

[[tool]]
name = "rustc"
role = "compiler"
provenance = "flake.lock:fenix"
pin = "{FENIX_REV}"
statement = "Compiles every first-party crate in the image."

[[tool]]
name = "arm-none-eabi-as"
role = "assembler"
provenance = "flake.lock:nixpkgs"
pin = "{NIXPKGS_REV}"
statement = "Assembles rsk-rsa's hand-written ARM asm."

[[tool]]
name = "flip-link"
role = "linker"
provenance = "flake.lock:nixpkgs"
pin = "{NIXPKGS_REV}"
statement = "The linker .cargo/config.toml names."

[[tool]]
name = "picotool"
role = "packager"
provenance = "flake.lock:nixpkgs"
pin = "{NIXPKGS_REV}"
statement = "Writes the partition table and the published UF2."

[[tool]]
name = "tlaplus"
role = "checker"
provenance = "flake.lock:nixpkgs"
pin = "{NIXPKGS_REV}"
statement = "TLC, and the jar formal/run-tlc.sh runs."

[[tool]]
name = "jre8"
role = "runtime"
provenance = "flake.lock:nixpkgs"
pin = "{NIXPKGS_REV}"
statement = "The JVM TLC runs on."

[[tool]]
name = "cortex-m"
role = "assembler"
provenance = "Cargo.lock:cortex-m"
pin = "{CORTEX_M}"
statement = "A prebuilt asm blob, the second DWARF producer of the image."

[[tool]]
name = "cargo-kani"
role = "prover"
provenance = "workflow:.github/workflows/ci.yml:KANI_VERSION"
pin = "0.67.0"
statement = "Runs every #[kani::proof] harness."

[[tool]]
name = "cbmc"
role = "checker"
provenance = "unpinned"
pin = "PLAT-TOOL-003"
statement = "The model checker cargo-kani downloads with its own bundle."

[[not_tcb]]
input = "nixpkgs-sdl2"
reason = "SDL2 alone, for the tools/emu display window."

[[not_tcb]]
input = "flake-utils"
reason = "eachDefaultSystem plumbing; it emits no binary into any build."
"""

#: Lowered with the fixture, which carries 9 tools and 8 resolved pins. Handed to
#: `audit` rather than monkeypatched: both arms of each floor have to be drivable
#: without editing the number the run is judged by.
RESOLVED_FLOOR = 6
ROLE_FLOOR = 4


class Tree:
    def __init__(self, root):
        self.root = root
        self.write(gate.REGISTRY, REGISTRY)
        self.write(gate.CARGO_LOCK, CARGO)
        self.write(gate.PLATFORM, PLATFORM)
        self.write(gate.WORKFLOWS / "ci.yml", WORKFLOW_A)
        self.write(gate.WORKFLOWS / "deep-checks.yml", WORKFLOW_B)
        self.write(gate.PAGE, PAGE)
        self.write_lock()
        self.regenerate()

    def write(self, rel, text):
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    def write_lock(self, last_modified=1780243769):
        """The lock, with the timestamp the control moves as a parameter."""
        self.write(gate.FLAKE_LOCK, json.dumps(lock(last_modified), indent=2))

    def edit(self, rel, old, new):
        """Replace `old` once, failing loudly if the fixture no longer says it."""
        path = self.root / rel
        text = path.read_text(encoding="utf-8")
        assert text.count(old) == 1, f"{rel} does not say {old!r} exactly once"
        path.write_text(text.replace(old, new), encoding="utf-8")

    def regenerate(self):
        """Put the page's region back to what the generator writes."""
        assert gate.run(self.root, write=True) == 0

    def problems(self, **kwargs):
        kwargs.setdefault("resolved_floor", RESOLVED_FLOOR)
        kwargs.setdefault("role_floor", ROLE_FLOOR)
        return gate.audit(self.root, **kwargs)[0]


@pytest.fixture
def tree(tmp_path):
    return Tree(tmp_path)


def only(problems, needle):
    """The one problem carrying `needle`, so a case cannot pass on a stray."""
    hits = [p for p in problems if needle in p]
    assert len(hits) == 1, f"{needle!r} matched {hits} of {problems}"
    return hits[0]


# ---- the baseline, and the two controls --------------------------------------


def test_the_fixture_is_green(tree):
    """Every mutation below is meaningless if the unmutated tree is not clean."""
    assert tree.problems() == []


def test_a_refetch_that_moves_only_lastmodified(tree):
    """THE control. A plain `nix flake update` refetch moves the timestamp and
    not the revision, and a gate that hashed the node would go red on it — which
    is a row nobody keeps. Only `locked.rev` is read, so this is green by
    construction, and this case is what holds it that way."""
    before = (tree.root / gate.PAGE).read_text(encoding="utf-8")
    tree.write_lock(last_modified=1780243770)
    assert tree.problems() == []
    # And the printed page does not move either: a timestamp in the region would
    # make every refetch a docs diff.
    assert (tree.root / gate.PAGE).read_text(encoding="utf-8") == before


def test_a_new_correctly_pinned_tool_is_green(tree):
    """The registry has to be extensible without a code edit, or it stops growing."""
    tree.edit(
        gate.REGISTRY,
        '[[not_tcb]]\ninput = "nixpkgs-sdl2"',
        f'[[tool]]\nname = "rust-lld"\nrole = "linker"\n'
        f'provenance = "flake.lock:fenix"\npin = "{FENIX_REV}"\n'
        f'statement = "The linker flip-link shells out to."\n\n'
        f'[[not_tcb]]\ninput = "nixpkgs-sdl2"',
    )
    tree.regenerate()
    assert tree.problems() == []


# ---- rule 1: flake.lock ------------------------------------------------------


def test_a_pin_the_flake_node_does_not_carry_is_red(tree):
    """M1. Both values in the message: a mismatch nobody can read is one that gets
    'fixed' by editing whichever number is nearer."""
    tree.edit(gate.REGISTRY, f'pin = "{FENIX_REV}"', f'pin = "{"d" * 40}"')
    problem = only(tree.problems(), "`rustc` pins fenix at")
    assert "d" * 40 in problem and FENIX_REV in problem


def test_a_flake_input_that_is_not_a_root_input_is_red(tree):
    tree.edit(gate.REGISTRY, 'provenance = "flake.lock:fenix"', 'provenance = "flake.lock:fenixx"')
    assert only(tree.problems(), "input `fenixx`, which is not a root input")


def test_a_lock_the_parser_cannot_read_is_red(tree):
    """The family this tree ships guards with: a reader that stops matching finds
    nothing and passes everything. Driven by renaming the root node's key, which
    is the smallest format move that empties the derivation."""
    data = lock()
    data["nodes"]["root"]["inputs"] = {}
    tree.write(gate.FLAKE_LOCK, json.dumps(data))
    assert only(tree.problems(), "no root input resolved")


# ---- rule 2: Cargo.lock ------------------------------------------------------


def test_a_pin_the_cargo_checksum_does_not_carry_is_red(tree):
    tree.edit(gate.REGISTRY, f'pin = "{CORTEX_M}"', f'pin = "{"0" * 64}"')
    problem = only(tree.problems(), "`cortex-m` pins cortex-m at")
    assert CORTEX_M in problem and "0" * 64 in problem


def test_a_cargo_package_that_is_not_locked_is_red(tree):
    tree.edit(gate.REGISTRY, 'provenance = "Cargo.lock:cortex-m"', 'provenance = "Cargo.lock:cortex-n"')
    assert only(tree.problems(), "package `cortex-n`, which is locked 0 time(s)")


def test_a_cargo_package_locked_twice_is_red(tree):
    """Two versions of one name make `pin` ambiguous, and picking the first is how
    a rule silently starts answering about the wrong artifact."""
    tree.edit(
        gate.CARGO_LOCK,
        '[[package]]\nname = "firmware"',
        f'[[package]]\nname = "cortex-m"\nversion = "0.7.6"\nchecksum = "{"1" * 64}"\n\n'
        '[[package]]\nname = "firmware"',
    )
    assert only(tree.problems(), "locked 2 time(s) with a checksum")


# ---- rule 3: the workflow env: pin -------------------------------------------


def test_one_of_the_workflow_sites_disagreeing_is_red(tree):
    """M2: `KANI_VERSION` is written three times across two files, so an edit to
    any one of them has to be visible here. The message has to NAME the
    disagreeing file, or the reader is left grepping — and it names the file's
    OWN spread too, because deep-checks.yml assigns the variable twice and this
    mutation moves one of the two. `scripts/kani_gate.py` asks the same question
    of the same files now; what is this rule's alone is holding them to the
    registry's `pin`, which the mutation below drives."""
    tree.edit(gate.WORKFLOWS / "deep-checks.yml", 'KANI_VERSION: "0.67.0"\n    steps:\n      - run: echo "$KANI_VERSION"\n  shrink', 'KANI_VERSION: "0.68.0"\n    steps:\n      - run: echo "$KANI_VERSION"\n  shrink')
    problem = only(tree.problems(), "disagree")
    assert ".github/workflows/deep-checks.yml (0.67.0, 0.68.0)" in problem
    assert "written 3 time(s) across 2 workflow file(s)" in problem
    assert ".github/workflows/ci.yml" not in problem


def test_the_named_workflows_own_value_disagreeing_is_red(tree):
    """The near half of the same rule: the file the provenance points at."""
    tree.edit(gate.WORKFLOWS / "ci.yml", 'KANI_VERSION: "0.67.0"', 'KANI_VERSION: "0.69.0"')
    problem = only(tree.problems(), "pins KANI_VERSION at 0.67.0")
    assert "['0.69.0']" in problem


def test_an_assignment_outside_an_env_block_is_red(tree):
    """A `with:` key of the same name is an argument, not a pin. A line match
    would have counted it and reported the workflow as pinning something."""
    tree.edit(gate.WORKFLOWS / "ci.yml", "    env:\n      KANI_VERSION", "    with:\n      KANI_VERSION")
    assert only(tree.problems(), "no `env:` block")


def test_a_commented_out_pin_is_not_a_pin(tree):
    """The `gate_lines.runs` lesson one file over: a `#` in front of a line is not
    an assignment, and counting one is how a guard reads a dead row as live."""
    tree.edit(gate.WORKFLOWS / "ci.yml", '      KANI_VERSION: "0.67.0"', '      # KANI_VERSION: "0.67.0"')
    assert only(tree.problems(), "no `env:` block")


# ---- rule 4: the `unpinned` escape -------------------------------------------


def test_unpinned_against_a_closed_obligation_is_red(tree):
    """M3. The direction that matters: the obligation gets marked discharged while
    the tool it covers is still pinned by nothing."""
    tree.edit(gate.REGISTRY, 'pin = "PLAT-TOOL-003"', 'pin = "PLAT-TOOL-004"')
    problem = only(tree.problems(), "`cbmc` is unpinned against PLAT-TOOL-004")
    assert "'discharged'" in problem and "not 'pending'" in problem


def test_unpinned_against_a_missing_obligation_is_red(tree):
    tree.edit(gate.REGISTRY, 'pin = "PLAT-TOOL-003"', 'pin = "PLAT-TOOL-009"')
    assert only(tree.problems(), "has no such row")


def test_unpinned_against_something_that_is_not_an_obligation_is_red(tree):
    """Without the id shape, `pin = "we'll get to it"` satisfies the rule."""
    tree.edit(gate.REGISTRY, 'pin = "PLAT-TOOL-003"', 'pin = "TODO"')
    assert only(tree.problems(), "not a PLAT-TOOL* id")


# ---- rule 5: the flake's root inputs, both ways -------------------------------


def test_a_root_input_with_no_row_at_all_is_red(tree):
    """M4. Delete the only row that names an input and the registry understates
    its own contract with every remaining row still correct."""
    tree.edit(gate.REGISTRY, '[[not_tcb]]\ninput = "flake-utils"\nreason = "eachDefaultSystem plumbing; it emits no binary into any build."\n', "")
    assert only(tree.problems(), "root input `flake-utils` is in no tool's provenance")


def test_a_not_tcb_row_for_an_input_that_is_gone_is_red(tree):
    tree.edit(gate.REGISTRY, 'input = "flake-utils"', 'input = "flake-utilities"')
    assert only(tree.problems(), "not-TCB `flake-utilities` is not a root input")


def test_an_input_that_is_both_in_and_out_of_the_tcb_is_red(tree):
    tree.edit(gate.REGISTRY, 'input = "nixpkgs-sdl2"', 'input = "nixpkgs"')
    assert only(tree.problems(), "cannot be out of the TCB and pin a tool in it")


def test_a_not_tcb_row_with_no_reason_is_red(tree):
    """A bare exclusion is the gap parked under a different heading."""
    tree.edit(gate.REGISTRY, 'reason = "eachDefaultSystem plumbing; it emits no binary into any build."', 'reason = ""')
    assert only(tree.problems(), "states no reason")


# ---- the schema --------------------------------------------------------------


def test_a_derived_value_stored_on_a_row_is_red(tree):
    """The `evidence_gate` discipline: an eighth key is where a derived value
    starts being stored, and a stored derived value is the rot."""
    tree.edit(gate.REGISTRY, 'name = "rustc"', 'name = "rustc"\nversion = "1.96.0"')
    assert only(tree.problems(), "carries ['version']")


def test_a_role_outside_the_vocabulary_is_red(tree):
    """An open vocabulary lets a criterion category be covered by a word nobody
    agreed on."""
    tree.edit(gate.REGISTRY, 'role = "compiler"', 'role = "buildy-thing"')
    assert only(tree.problems(), "'buildy-thing', which is not one of")


def test_a_provenance_in_no_known_form_is_red(tree):
    tree.edit(gate.REGISTRY, 'provenance = "unpinned"', 'provenance = "the usual place"')
    assert only(tree.problems(), "which is none of")


def test_a_tool_registered_twice_is_red(tree):
    tree.edit(gate.REGISTRY, 'name = "jre8"', 'name = "tlaplus"')
    assert only(tree.problems(), "`tlaplus` is registered twice")


# ---- the structural rules ----------------------------------------------------


def test_a_criterion_category_no_tool_answers_for_is_red(tree):
    """`linker` printed as covered by an empty set is the overclaim the table
    exists to prevent, and every per-row rule stays green through it."""
    tree.edit(gate.REGISTRY, 'role = "linker"', 'role = "packager"')
    tree.regenerate()
    assert only(tree.problems(), "no registered tool answers for the criterion's `linker`")


def test_a_category_in_none_of_the_three_maps_is_red(tree, monkeypatch):
    """The map has to PARTITION the criterion. Dropping `bootrom` from the
    unreachable list would take it out of the printed table with no other rule
    noticing — a category silently not mentioned reads as one not needed."""
    monkeypatch.setattr(gate, "UNREACHABLE", {k: v for k, v in gate.UNREACHABLE.items() if k != "bootrom"})
    assert only(tree.problems(), "a category in neither map")


def test_a_roster_that_resolves_nothing_is_red(tree):
    """Driven from BELOW: every per-row rule above is satisfied by a roster that
    opens no file, and rule 4's escape is satisfied by a roster of nothing but
    escapes."""
    assert only(tree.problems(resolved_floor=9), "pin(s) resolved against a file, under the measured 9")


def test_a_roster_collapsed_onto_one_role_is_red(tree):
    assert only(tree.problems(role_floor=8), "role(s) carried, under the measured 8")


# ---- rule 6: the generated region --------------------------------------------


def test_a_hand_edit_inside_the_region_is_red(tree):
    """The whole of rule 6: the page is a byte diff, not a description."""
    tree.edit(gate.PAGE, "| `cbmc` | checker |", "| `cbmc` | pinned-and-fine |")
    assert only(tree.problems(), "is not what the generator writes")


def test_the_prose_outside_the_region_survives_a_write(tree):
    """A generator that ate the page around its region would be caught by nothing
    else here — every rule above reads the registry, not the page."""
    page = (tree.root / gate.PAGE).read_text(encoding="utf-8")
    assert "Prose the gate must not touch." in page and page.endswith("More prose.\n")


def test_the_region_carries_the_disclaimer_and_so_does_the_docstring(tree):
    """The claim boundary is the deliverable, not a comment on it: a reader of the
    published page has to see the same limits as a reader of the gate. Both
    copies are asserted because dropping either leaves the other true."""
    page = (tree.root / gate.PAGE).read_text(encoding="utf-8")
    for said in ("does not prove", "narHash", "which actually"):
        assert said in page, said
        assert said in gate.__doc__, said
    # Reflowed, because a needle that a line wrap can break is a rule that fails
    # on formatting instead of on meaning.
    flat = " ".join(gate.__doc__.split())
    assert "LLVM passes and the bootrom have no machine-readable source" in flat


def test_the_region_names_every_criterion_category(tree):
    """Three lists, six names, printed. A category that falls out of all three is
    caught by `test_a_category_in_none_of_the_three_maps_is_red`; this is the
    other end — that what the maps hold actually reaches the page."""
    page = (tree.root / gate.PAGE).read_text(encoding="utf-8")
    missing = [c for c in gate.CRITERION if f"**{c}**" not in page]
    assert not missing, missing


# ---- the row that runs it ----------------------------------------------------


def test_check_sh_runs_this_gate():
    """A guard nothing invokes can be deleted with the suite still green, and the
    row is the half `test_gate_scripts.py` covers by glob only for `GATES`. Read
    through `gate_lines.runs`, so a `#` in front of the row does not count."""
    assert gate_lines.runs((ROOT / "scripts/check.sh").read_text(), "scripts/toolchain_gate.py")


def test_the_real_registry_is_green():
    """The table above runs on a fixture; this is the tree. Without it every case
    could pass over a synthetic registry while the shipped one is red."""
    assert gate.audit(ROOT)[0] == []
