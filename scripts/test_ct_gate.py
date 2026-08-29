# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""The mutation table for `ct_gate.py`.

Every case runs against a RECORDED disassembly and a registry handed in as text:
the parser and the rule are what a case can decide, the shipped image is what the
gate row decides, and neither the ELF nor the working tree is touched here. Both
of those are corrections an independent review drove — the first version wrote
`assurance/ct_sites.toml` from a case and restored it in a `finally`, and three
of its cases read whichever firmware `target/` happened to hold, which after
`check.sh`'s later rows is the no-touch build.

The image arms are recorded in [`test_the_image_arms_were_driven_by_hand`].

The fixtures are the shipped comparator's actual lowering, copied out of
`arm-none-eabi-objdump -d -l --inlines` on the release image, with the inline
chain kept intact because attribution is half of what is under test.
"""

from __future__ import annotations

import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import ct_gate  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parent.parent

#: The paths are assembled rather than written out: `citation_gate.py` reads
#: `scripts/*.py` for `<file>.rs:<line>` and would resolve a fixture's synthetic
#: path against the tree, where it is not.
MAC = "/x/crates/rsk-crypto/src/mac.rs"
PIN = "/x/crates/rsk-openpgp/src/pin.rs"

CHAIN = (
    f"inlined by {MAC}:60 (_ZN10rsk_crypto3mac5ct_eq17h0000000000000000E)\n"
    f"inlined by {PIN}:93 (_ZN11rsk_openpgp3pin9check_pin17h0000000000000001E)"
)

#: The shipped loop, verbatim in shape: two byte loads, a flag-setting XOR, the
#: PUBLIC bound in its wide spelling, a branchless accumulate, the back edge,
#: then the barrier's spill/reload and the terminal reduction to a bool.
CLEAN = f"""{CHAIN}
10000000:\tf818 2001 \tldrb.w\tr2, [r8, r1]
{CHAIN}
10000004:\t5c6b      \tldrb\tr3, [r5, r1]
{CHAIN}
10000006:\t3101      \tadds\tr1, #1
{CHAIN}
10000008:\t4053      \teors\tr3, r2
{CHAIN}
1000000a:\tf1b1 0f20 \tcmp.w\tr1, #32
{CHAIN}
1000000e:\tea40 0003 \torr.w\tr0, r0, r3
{CHAIN}
10000012:\td1f5      \tbne.n\t10000000
{CHAIN}
10000014:\tf88d 0098 \tstrb.w\tr0, [sp, #152]
{CHAIN}
10000018:\tf89d 0098 \tldrb.w\tr0, [sp, #152]
{CHAIN}
1000001c:\t2800      \tcmp\tr0, #0
{CHAIN}
1000001e:\td005      \tbeq.n\t1000002a
"""

#: The defect: the loop branches on the XOR of two loaded bytes instead of on
#: the counter. One line moved, and it is the shape an early exit compiles to.
LEAKY = CLEAN.replace(
    "1000000a:\tf1b1 0f20 \tcmp.w\tr1, #32", "1000000a:\tf1b1 0f20 \tnop.w\tr1, #32"
)

#: The same defect ONE ARITHMETIC STEP further from the load, which is the shape
#: `if diff & 0x80 != 0 { return false; }` really compiles to. A depth-1 rule
#: reports zero here; a review drove that on the real image and it did.
TRANSITIVE = f"""{CHAIN}
10000100:\tf818 2001 \tldrb.w\tr2, [r8, r1]
{CHAIN}
10000104:\t5c6b      \tldrb\tr3, [r5, r1]
{CHAIN}
10000106:\t4053      \teors\tr3, r2
{CHAIN}
10000108:\tb2db      \tsxtb\tr3, r3
{CHAIN}
1000010a:\t2b00      \tcmp\tr3, #0
{CHAIN}
1000010c:\td1f8      \tbne.n\t10000100
"""

#: A PREDICATED compare, which is what `mac.rs`'s public length-equality early
#: return really lowers to. Here its operand comes from a buffer, so the case
#: asserts the taint is FOUND: a rule that refused any run containing an `IT`
#: reported the documented public return as a finding, and one that skipped the
#: predicated `cmpeq` would miss this. Either way the case falls.
PREDICATED = f"""{CHAIN}
100001fc:\tf89d 1010 \tldrb.w\tr1, [r8, #16]
{CHAIN}
10000200:\t2801      \tcmp\tr0, #1
{CHAIN}
10000202:\tbf08      \tit\teq
{CHAIN}
10000204:\t458b      \tcmpeq\tfp, r1
{CHAIN}
10000206:\td01f      \tbeq.n\t10000248
"""

#: The same shape over a value the frame itself stored — a spill, not a buffer.
PREDICATED_SPILL = f"""{CHAIN}
100002fc:\tf88d 1010 \tstrb.w\tr1, [sp, #16]
{CHAIN}
10000300:\tf89d 1010 \tldrb.w\tr1, [sp, #16]
{CHAIN}
10000304:\t2801      \tcmp\tr0, #1
{CHAIN}
10000306:\tbf08      \tit\teq
{CHAIN}
10000308:\t458b      \tcmpeq\tfp, r1
{CHAIN}
1000030a:\td01f      \tbeq.n\t10000348
"""

#: A literal-pool load: the base is `pc`, so it can only be reading a constant.
LITERAL = f"""{CHAIN}
10000300:\t4b02      \tldr\tr3, [pc, #8]
{CHAIN}
10000302:\t2b00      \tcmp\tr3, #0
{CHAIN}
10000304:\td004      \tbeq.n\t10000310
"""

SITE = {"CT-CMP-001": {"symbol": "rsk_crypto::mac::ct_eq", "class": "comparator"}}
NO_FLOORS = {"run_floor": 0, "branch_floor": 0, "reasoned_floor": 0}


def observed(text):
    return ct_gate.observe(ROOT, SITE, text.splitlines())["CT-CMP-001"]


def shipped_registry() -> str:
    return (ROOT / ct_gate.REGISTRY).read_text(encoding="utf-8")


def test_the_shipped_loop_is_clean():
    """The control. Without it every case below could pass over a dead parser."""
    violations, runs, branches, callers, reasoned = observed(CLEAN)
    assert (runs, branches, reasoned) == (1, 2, 2), (runs, branches, reasoned)
    assert violations == []
    assert callers == {"rsk_openpgp::pin::check_pin"}


def test_a_branch_on_the_loaded_bytes_is_caught():
    violations, _, _, _, _ = observed(LEAKY)
    assert len(violations) == 1, violations
    addr, mnemonic, source, load = violations[0]
    assert (addr, mnemonic) == (0x10000012, "bne")
    assert source.startswith("eors")
    assert "ldrb" in load


def test_a_taint_that_passes_through_arithmetic_is_still_a_taint():
    """The rule this shipped wrong. Depth-1 — the flag operand's own definition
    must BE a load — is defeated by one `sxtb`, and a review drove exactly that
    on the real image: a genuine early exit, reported as zero."""
    violations, _, _, _, _ = observed(TRANSITIVE)
    assert len(violations) == 1, violations
    assert violations[0][1] == "bne"
    assert "ldrb" in violations[0][3]


def test_the_depth_is_finite_and_stated():
    assert ct_gate.TAINT_DEPTH == 4
    assert "sxtb" in ct_gate.TRANSPARENT and "eors" in ct_gate.TRANSPARENT
    assert "bl" not in ct_gate.TRANSPARENT


def test_a_predicated_compare_is_read_as_a_flag_setter():
    """Predication read as predication, in both directions. A rule that refused
    any run containing an `IT` reported `mac.rs`'s documented public early return
    as a finding; a rule that skipped the predicated `cmpeq` would miss the taint
    the same instruction carries."""
    violations, runs, branches, _, reasoned = observed(PREDICATED)
    assert (runs, branches, reasoned) == (1, 1, 1)
    assert len(violations) == 1, violations
    assert violations[0][2].startswith("cmpeq")


def test_a_predicated_compare_of_a_spill_is_not_a_finding():
    violations, _, branches, _, reasoned = observed(PREDICATED_SPILL)
    assert (branches, reasoned) == (1, 1)
    assert violations == []


def test_a_reload_of_this_frames_own_store_is_not_a_buffer_read():
    """`black_box`'s spill/reload feeds the terminal `cmp r0, #0`. The first rule
    here whitelisted `sp` and missed the eight copies that spill through the frame
    register `r7` instead — the shipped comparator reported itself, eight times."""
    tail = CLEAN[CLEAN.index("10000014") - len(CHAIN) - 1 :]
    violations, _, branches, _, _ = observed(tail)
    assert branches == 1
    assert violations == []


def test_a_literal_pool_load_is_not_a_buffer_read():
    violations, _, branches, _, reasoned = observed(LITERAL)
    assert (branches, reasoned) == (1, 1)
    assert violations == []


def test_the_width_suffix_is_stripped_before_the_flag_set_is_consulted():
    """The defect this gate shipped with for one run: `cmp.w` was not in the set,
    the walk-back skipped the public bound and landed on the secret `eors`, and
    the shipped comparator was reported as secret-dependent — the inverse of the
    truth, at exit 1."""
    assert ct_gate.flag_setter("cmp") == ("cmp", False)
    assert ct_gate.flag_setter("cmpeq") == ("cmp", True)
    assert ct_gate.flag_setter("nop") is None
    wide = "10000000:\tf1b1 0f20 \tcmp.w\tr1, #32"
    assert list(ct_gate.instructions([wide]))[0][1] == "cmp"


def test_a_site_that_resolves_to_nothing_is_a_finding():
    """The vacuity control: a stripped image, or a symbol that stopped being
    inlined, makes every other rule pass over zero instructions."""
    findings, _ = ct_gate.audit(
        ROOT, lines=["10000000:\t4770      \tbx\tlr"], **NO_FLOORS
    )
    assert any("is in no inline chain" in f for f in findings), findings


@pytest.mark.parametrize(
    "floors,word",
    [
        ({"run_floor": 10_000}, "attributed run"),
        ({"branch_floor": 10_000}, "conditional branch"),
        ({"reasoned_floor": 10_000}, "traced to a definition"),
    ],
)
def test_each_floor_reports_its_own_shortfall(floors, word):
    """Three floors and three messages: a branch the rule WALKED PAST is not one
    it decided, and before the taint became transitive most of the shipped
    image's in-site branches were excused before the question was put."""
    kwargs = dict(NO_FLOORS)
    kwargs.update(floors)
    findings, _ = ct_gate.audit(ROOT, lines=CLEAN.splitlines(), **kwargs)
    assert any("under the measured" in f and word in f for f in findings), findings


def test_the_shipped_floors_are_parameters_and_not_globals():
    """A case cannot patch them down: the defaults bind at `def` time, so the
    values the row runs with are the ones in the module."""
    assert (ct_gate.RUN_FLOOR, ct_gate.BRANCH_FLOOR, ct_gate.REASONED_FLOOR) == (
        30,
        20,
        15,
    )


def test_an_unregistered_inliner_is_a_finding():
    """The caller set is held BOTH ways; this is the direction that catches a new
    surface reaching the comparator with nobody saying what it is."""
    # The length prefix is part of the name: `9check_pin` -> `10check_pinX`,
    # or the demangler reads nine characters and the rename vanishes.
    stranger = CLEAN.replace("3pin9check_pin17h", "3pin10check_pinX17h")
    findings, _ = ct_gate.audit(ROOT, lines=stranger.splitlines(), **NO_FLOORS)
    assert any("says which protocol surface" in f for f in findings), findings


def test_a_surface_that_stopped_routing_through_it_is_a_finding():
    """The direction that catches the defect `docs/ct-audit.md` records twice: a
    compare that BYPASSED the comparator. The registry entry survives; the ELF
    stops naming it. Keyed on the OUTERMOST frame this could not see a bypass
    added beside a surviving call in the same function — the review drove that on
    `cmd_update` and the row stayed green."""
    findings, _ = ct_gate.audit(ROOT, lines=CLEAN.splitlines(), **NO_FLOORS)
    stale = [f for f in findings if "inlines no site in the image" in f]
    assert len(stale) == 27, stale


def test_the_page_region_is_diffed_against_the_generator():
    findings, _ = ct_gate.audit(ROOT, lines=CLEAN.splitlines(), **NO_FLOORS)
    assert any("is not what the generator writes" in f for f in findings), findings


def test_the_registry_refuses_a_key_it_does_not_read():
    findings: list[str] = []
    patched = shipped_registry().replace(
        'class = "comparator"', 'class = "comparator"\nnote = "x"', 1
    )
    ct_gate.registry(ROOT, findings, text=patched)
    assert any("is not a field this registry reads" in f for f in findings), findings
    assert (ROOT / ct_gate.REGISTRY).read_text(encoding="utf-8") == shipped_registry()


def test_the_image_arms_were_driven_by_hand():
    """Recorded, because a case cannot relink the firmware.

    Driven through the row's own command (`python scripts/ct_gate.py`) after
    `cargo build --release -p firmware`:

    | arm | attributed runs | branches | secret-dependent | row |
    |---|---|---|---|---|
    | shipped | 39 | 26 | 0 | EXIT=0 |
    | early exit in `ct_eq` (`if diff != 0`) | 60 | 27 | 27 | EXIT=1 |
    | early exit on ONE BIT (`if diff & 0x80 != 0`) | 59 | 27 | 32 | EXIT=1 |
    | `cmd_update` back to a slice `!=`, `cmd_configure` untouched | 39 | 26 | 0 | EXIT=1, `cmd_update` inlines no site |

    The last two are the arms an independent review used to refute the first
    version of this gate: at depth-1 taint the bit test reported 0 and passed,
    and keyed on the outermost frame the bypass beside a surviving call reported
    0 and passed. Both now redden, and the fourth reddens with the right message
    rather than on a floor.

    `mac.rs` and `rsk-otp/src/lib.rs` restored byte-identical (sha256 compared)
    and the control re-run green after each rebuild.

    Cost, measured rather than quoted from the objdump alone: `arm-none-eabi-
    objdump -d -l --inlines` is 0.9 s over a 1 370 429-line dump, and the ROW —
    `python scripts/ct_gate.py` — is about 15 s wall, nearly all of it the Python
    pass. The firmware build it reads was already a row.
    """
    assert ct_gate.REGION == "ct-sites"
