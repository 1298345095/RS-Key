# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""The mutation table for `ct_gate.py`.

Every case runs against a RECORDED disassembly, not a live firmware build: the
parser and the rule are what a case can decide, and the shipped image is what the
gate row decides. The two arms of the real image — the shipped comparator and the
comparator with an early exit compiled back in — were driven by hand, through the
row's own command after a rebuild, and their numbers are in the docstring of
`test_the_shipped_image_arm_was_driven_by_hand`.

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
#: PUBLIC bound in its wide spelling, a branchless accumulate, the back edge.
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

#: The defect: the loop branches on the XOR of two loaded bytes instead of on the
#: counter. One line moved, and it is the shape an early exit compiles to.
LEAKY = CLEAN.replace(
    "1000000a:\tf1b1 0f20 \tcmp.w\tr1, #32", "1000000a:\tf1b1 0f20 \tnop.w\tr1, #32"
)

#: The public length-equality early return, which the shipped comparator really
#: does compile to a predicated compare. A rule that refuses predication outright
#: reports THIS as the finding — it did, before the rule learned to read it.
PREDICATED = f"""{CHAIN}
10000100:\t2801      \tcmp\tr0, #1
{CHAIN}
10000102:\tbf08      \tit\teq
{CHAIN}
10000104:\t458b      \tcmpeq\tfp, r1
{CHAIN}
10000106:\td01f      \tbeq.n\t10000148
"""

SITE = {"CT-CMP-001": {"symbol": "rsk_crypto::mac::ct_eq", "class": "comparator"}}


def observed(text):
    return ct_gate.observe(ROOT, SITE, text.splitlines())["CT-CMP-001"]


def test_the_shipped_loop_is_clean():
    """The control. Without it every case below could pass over a dead parser."""
    violations, runs, branches, callers = observed(CLEAN)
    assert (runs, branches) == (1, 2), (runs, branches)
    assert violations == []
    assert callers == {"rsk_openpgp::pin::check_pin"}


def test_a_branch_on_the_loaded_bytes_is_caught():
    violations, _, _, _ = observed(LEAKY)
    assert len(violations) == 1, violations
    addr, mnemonic, source, load = violations[0]
    assert (addr, mnemonic) == (0x10000012, "bne")
    assert source.startswith("eors")
    assert "ldrb" in load


def test_the_public_length_check_is_not_a_finding():
    """Predication read as predication. The first rule here refused any run with
    an `IT` in it and reported the documented public early return."""
    violations, runs, branches, _ = observed(PREDICATED)
    assert (runs, branches) == (1, 1)
    assert violations == []


def test_a_reload_of_this_frames_own_store_is_not_a_buffer_read():
    """`black_box`'s spill/reload feeds the terminal `cmp r0, #0`. The first rule
    here whitelisted `sp` and missed the eight copies that spill through the frame
    register `r7` instead — the shipped comparator reported itself, eight times."""
    tail = CLEAN[CLEAN.index("10000014") - len(CHAIN) - 1 :]
    violations, _, branches, _ = observed(tail)
    assert branches == 1
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
    findings, _ = ct_gate.audit(ROOT, lines=["10000000:\t4770      \tbx\tlr"])
    assert any("is in no inline chain" in f for f in findings), findings


@pytest.mark.parametrize("run_floor,branch_floor", [(10_000, 20), (30, 10_000)])
def test_the_floors_hold_the_shipped_values(run_floor, branch_floor):
    """Both are parameters of `audit`, so the case cannot patch the shipped value
    down and then prove nothing about it."""
    findings, _ = ct_gate.audit(ROOT, run_floor=run_floor, branch_floor=branch_floor)
    assert any("under the measured" in f for f in findings), findings


def test_the_shipped_floors_are_under_what_the_image_measures():
    """And the other direction: a floor ABOVE the measurement is a row that is red
    on a clean tree, which is how `run_count_gate`'s ratchet went out."""
    findings, summary = ct_gate.audit(ROOT)
    assert not findings, findings
    assert "0 secret-dependent" in summary


def test_an_unregistered_inliner_is_a_finding():
    """The caller set is held BOTH ways; this is the direction that catches a new
    surface reaching the comparator with nobody saying what it is."""
    # The length prefix is part of the name: `9check_pin` -> `10check_pinX`,
    # or the demangler reads nine characters and the rename vanishes.
    stranger = CLEAN.replace("3pin9check_pin17h", "3pin10check_pinX17h")
    findings, _ = ct_gate.audit(ROOT, lines=stranger.splitlines())
    assert any("says which protocol surface" in f for f in findings), findings


def test_a_surface_that_stopped_routing_through_it_is_a_finding():
    """The direction that catches the defect `docs/ct-audit.md` records twice: a
    compare that BYPASSED the comparator. The registry entry survives; the ELF
    stops naming it."""
    findings, _ = ct_gate.audit(ROOT, lines=CLEAN.splitlines())
    stale = [f for f in findings if "inlines no site in the image" in f]
    assert len(stale) == 15, stale


def test_the_page_region_is_diffed_against_the_generator():
    findings, _ = ct_gate.audit(ROOT, lines=CLEAN.splitlines())
    assert any("is not what the generator writes" in f for f in findings), findings


def test_the_registry_refuses_a_key_it_does_not_read():
    findings: list[str] = []
    doc = (ROOT / ct_gate.REGISTRY).read_text(encoding="utf-8")
    patched = doc.replace('class = "comparator"', 'class = "comparator"\nnote = "x"', 1)
    scratch = ROOT / "assurance" / "ct_sites.toml"
    original = scratch.read_text(encoding="utf-8")
    try:
        scratch.write_text(patched, encoding="utf-8")
        ct_gate.registry(ROOT, findings)
    finally:
        scratch.write_text(original, encoding="utf-8")
    assert any("is not a field this registry reads" in f for f in findings), findings


def test_the_shipped_image_arm_was_driven_by_hand():
    """Recorded, because a case cannot afford a firmware build.

    Driven through the row's own command (`python scripts/ct_gate.py`) after
    `cargo build --release -p firmware`, on the shipped tree and on one with
    `if diff != 0 { return false; }` inserted into `ct_eq`'s accumulate loop:

    | arm | attributed runs | branches | secret-dependent | row |
    |---|---|---|---|---|
    | shipped | 39 | 26 | 0 | EXIT=0 |
    | early exit in `ct_eq` | 60 | 27 | 27 | EXIT=1 |

    Each of the 27 names its own `cmp` of two byte loads, e.g. `0x10007ac4 beq`
    on `cmp r2, r1` after `ldrb r2, [r6, r0]`. `mac.rs` restored byte-identical
    (sha256 compared), and the control re-run green after the rebuild.

    The mutant that does NOT work, and is recorded so nobody re-tries it:
    deleting the `black_box`. `docs/ct-audit.md` says the barrier "does not change
    the code generated today", so that arm stays at 0 and is a check that cannot
    fail.
    """
    assert ct_gate.RUN_FLOOR == 30 and ct_gate.BRANCH_FLOOR == 20
