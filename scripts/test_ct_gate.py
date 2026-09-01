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

#: A second frame under the SAME outermost one, so the block below is next in
#: address order without being reachable from the comparator's — which is the
#: whole point: the frame check alone does not separate them.
OTHER = f"inlined by {PIN}:97 (_ZN11rsk_openpgp3pin9check_pin17h0000000000000001E)"

#: The comparator's loop, then an unconditional `b`, then a block that branches
#: on a register the comparator happened to leave in `r4`. Copied in shape from
#: `OtpApplet::process` at 0x10036fb0/0x10036fe0/0x10036ff8, where the branch is
#: `apdu.p1 == P1_CHAL_HMAC_SLOT1 || …` — an attacker's own APDU byte. Nothing
#: falls through the `b`, so the load is not a definition this branch can read.
ACROSS_BLOCKS = f"""{CHAIN}
10000400:\t5cc4      \tldrb\tr4, [r0, r3]
{CHAIN}
10000402:\t4066      \teors\tr6, r4
{CHAIN}
10000404:\t2b06      \tcmp\tr3, #6
{CHAIN}
10000406:\td1fb      \tbne.n\t10000400
{OTHER}
10000408:\te707      \tb.n\t10000500
{OTHER}
1000040a:\tf004 0022 \tand.w\tr0, r4, #34
{OTHER}
1000040e:\t2838      \tcmp\tr0, #56
{OTHER}
10000410:\td155      \tbne.n\t10000500
"""

#: The other direction of the same rule, and the one that matters more: a store
#: on the far side of a `b` must NOT excuse the load as a reload of it.
STORE_ACROSS_BLOCKS = f"""{OTHER}
10000600:\tf88d 0098 \tstrb.w\tr0, [sp, #152]
{OTHER}
10000604:\te707      \tb.n\t10000700
{CHAIN}
10000606:\tf89d 0098 \tldrb.w\tr0, [sp, #152]
{CHAIN}
1000060a:\t2800      \tcmp\tr0, #0
{CHAIN}
1000060c:\td005      \tbeq.n\t10000618
"""

#: The oracle a coarse barrier hid, in the shape a real build gave it: two secret
#: bytes loaded into CALLEE-saved registers, a libcall, then the early exit's
#: compare. AAPCS makes `bl` preserve `sl`/`fp`, and the call returns, so the
#: `cmp` is on the only path. Copied from `ct_eq` at 0x1006afa0..0x1006afb8 in a
#: firmware built with `copy_from_slice` inside the accumulate loop.
CALL_KEEPS_CALLEE_SAVED = f"""{CHAIN}
10000800:\tf816 ab01 \tldrb.w\tsl, [r6], #1
{CHAIN}
10000804:\tf814 bb01 \tldrb.w\tfp, [r4], #1
{CHAIN}
10000808:\tf04b fcfb \tbl\t100b69a8
{CHAIN}
1000080c:\t45d3      \tcmp\tfp, sl
{CHAIN}
1000080e:\td10b      \tbne.n\t10000820
"""

#: The same shape over CALLER-saved registers, which the call may have destroyed.
#: Without it `clobbers` could return False for everything and the case above
#: would still pass — a guard nothing exercises.
CALL_CLOBBERS_CALLER_SAVED = f"""{CHAIN}
10000900:\tf816 0b01 \tldrb.w\tr0, [r6], #1
{CHAIN}
10000904:\tf814 1b01 \tldrb.w\tr1, [r4], #1
{CHAIN}
10000908:\tf04b fcfb \tbl\t100b69a8
{CHAIN}
1000090c:\t4288      \tcmp\tr1, r0
{CHAIN}
1000090e:\td10b      \tbne.n\t10000920
"""

#: `cbz` is CONDITIONAL: the next instruction is on the path, so a walk that
#: stops there loses a load it should have reached.
CBZ_IS_NOT_A_STOP = f"""{CHAIN}
10000a00:\tf816 ab01 \tldrb.w\tsl, [r6], #1
{CHAIN}
10000a04:\tb11a      \tcbz\tr2, 10000a10
{CHAIN}
10000a06:\tf1ba 0f00 \tcmp.w\tsl, #0
{CHAIN}
10000a0a:\td10b      \tbne.n\t10000a20
"""

#: A clobber of the flag-setter's operand, SCHEDULED BETWEEN the compare and the
#: branch, over an operand that genuinely came from a buffer. Thumb is scheduled,
#: so this shape is ordinary; a trace that starts at the BRANCH answers with the
#: `mov` and goes blind to the load the compare actually read. The clobber is
#: `mov.w` and not `movs` on purpose — an `s` form would set the flags itself and
#: become the governing instruction, and the case would stop being about the walk.
CLOBBERED_OPERAND = f"""{CHAIN}
10000b00:\tf810 3003 \tldrb.w\tr3, [r0, r3]
{CHAIN}
10000b04:\t2b00      \tcmp\tr3, #0
{CHAIN}
10000b06:\tf04f 0305 \tmov.w\tr3, #5
{CHAIN}
10000b0a:\td10b      \tbne.n\t10000b20
"""

#: The same scheduling, the other way round: here the CLOBBER is what reads the
#: buffer and the compare's real operand does not. Copied instruction for
#: instruction from `OtpApplet::process` at 0x10036fee..0x10036ff8 on the shipped
#: image, where `cmp r0, #56` reads `orr.w r0, sl, #8` and the `and.w r0, r4, #34`
#: after it feeds the NEXT compare. Traced from the branch this invents a finding.
CLOBBER_IS_NOT_THE_OPERAND = f"""{CHAIN}
10000c00:\t5cc4      \tldrb\tr4, [r0, r3]
{CHAIN}
10000c02:\tf04a 0008 \torr.w\tr0, sl, #8
{CHAIN}
10000c06:\t2838      \tcmp\tr0, #56
{CHAIN}
10000c08:\tf004 0022 \tand.w\tr0, r4, #34
{CHAIN}
10000c0c:\td155      \tbne.n\t10000c60
"""

SITE = {"CT-CMP-001": {"symbol": "rsk_crypto::mac::ct_eq", "class": "comparator"}}
NO_FLOORS = {
    "run_floor": 0,
    "branch_floor": 0,
    "reasoned_floor": 0,
    "exposed_floor": 0,
}


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
    here whitelisted `sp` and missed the copies that spill through the frame
    register `r7` instead — the shipped comparator reported itself.

    How many, measured 2026-09-01 over the default release image rather than
    asserted: 14 of the 39 attributed runs excuse a reload through `r7`, and the
    `sp`-whitelist rule reports 9 of them, because a load is only reported once a
    branch traces to it. The docstring of `ct_gate` said eight of both for its
    whole life and a later reading said ten; neither was ever read off an ELF,
    and the two counts were never one number. The 14 is derived by the row now
    (`excused_loads`), so this case pins the RULE and the image pins the count.
    """
    tail = CLEAN[CLEAN.index("10000014") - len(CHAIN) - 1 :]
    violations, _, branches, _, _ = observed(tail)
    assert branches == 1
    assert violations == []


def test_an_excuse_that_covers_every_load_is_a_finding(monkeypatch):
    """The hole `EXPOSED_FLOOR` closes, driven in both directions.

    `reload_of_a_store` is the only rule here that EXCUSES a load, and nothing
    else this row counts asks it — runs, branches and traced come out identical
    whatever it answers. So a version that says True too often takes the row's
    own mutant with it and leaves every other number in place: a check that
    cannot fail, at exit 0. Measured the same way over the shipped image, stubbed
    to True it reports 0 secret-dependent branches over an unchanged 39 / 25 / 22
    with all three older floors satisfied.
    """
    kwargs = dict(NO_FLOORS)
    kwargs["exposed_floor"] = 2
    word = "still visible to the taint"

    before = observed(LEAKY)
    findings, _ = ct_gate.audit(ROOT, lines=LEAKY.splitlines(), **kwargs)
    assert len(before[0]) == 1, before[0]
    assert not any(word in f for f in findings), findings

    monkeypatch.setattr(ct_gate, "reload_of_a_store", lambda stream, index: True)
    after = observed(LEAKY)
    findings, _ = ct_gate.audit(ROOT, lines=LEAKY.splitlines(), **kwargs)
    assert after[0] == [], after[0]  # the mutant this row exists to catch, gone
    assert after[1:] == before[1:], (before, after)  # and nothing else moved
    assert any(word in f for f in findings), findings


def test_a_literal_pool_load_is_not_a_buffer_read():
    violations, _, branches, _, reasoned = observed(LITERAL)
    assert (branches, reasoned) == (1, 1)
    assert violations == []


def test_a_definition_on_the_far_side_of_a_barrier_is_not_a_definition():
    """The false positive that reddened the row, in the shape the image had it.

    A backward walk over the linear address order is a question about control
    flow, and past an unconditional `b` it answers with a block that has no edge
    to the use. The verdict then follows the block layout: nothing about the
    comparator or its callers changed, an unrelated OTP commit moved
    `cmd_configure`'s inlined copy near two PUBLIC branches in `cmd_calculate`,
    and both were reported as reading its operand load.

    Driven: with `last_definition` back to stepping OVER a barrier, this case
    falls on `violations == []` reporting `(0x10000410, 'bne', 'cmp r0, #56',
    'ldrb r4, [r0, r3]')` — the image's own finding, in the direction that
    invents one rather than the inverse that hides one.
    """
    violations, _, branches, _, _ = observed(ACROSS_BLOCKS)
    assert branches == 1, branches  # only the loop's back edge is inside the run
    assert violations == []


def test_a_call_does_not_hide_a_load_in_a_callee_saved_register():
    """The narrowing an independent review caught, and the reason the stop is a
    REGISTER question. Bundling every transfer into one barrier took a genuine
    oracle out of the row: measured on a real build, the rule before reported it
    and the bundled rule reported 0."""
    violations, _, _, _, _ = observed(CALL_KEEPS_CALLEE_SAVED)
    assert len(violations) == 1, violations
    assert violations[0][1] == "bne"
    assert violations[0][3].startswith("ldrb"), violations[0][3]


def test_a_call_does_hide_a_load_in_a_caller_saved_register():
    """The other half, so `clobbers` is a rule and not a constant: AAPCS lets the
    callee destroy r0-r3/ip/lr, so a definition before the call is not what the
    compare read."""
    violations, _, _, _, _ = observed(CALL_CLOBBERS_CALLER_SAVED)
    assert violations == [], violations


def test_a_conditional_branch_is_not_a_stop():
    """`cbz` falls through, so the walk must cross it."""
    violations, _, _, _, _ = observed(CBZ_IS_NOT_A_STOP)
    assert len(violations) == 1, violations
    assert violations[0][3].startswith("ldrb"), violations[0][3]


def test_the_operand_is_traced_from_the_flag_setter_and_not_the_branch():
    """The direction that HIDES a finding, and the reason the walk moved.

    `cmp r3, #0` reads a byte the comparator loaded, and the scheduler puts a
    `mov.w r3, #5` between it and the `bne`. Walking back from the BRANCH the
    rule met the `mov` first, traced `#5` to nothing and reported clean — the
    compare's real operand never asked about at all. That is the shape a live
    early exit has, so the miss is silent.

    Driven: with `governing`'s position dropped and the walk back on the branch
    index, this case falls on `len(violations) == 1` seeing `[]` — the gate
    SHOULD HAVE REFUSED this image and did not. The inverse defect would fall the
    other way, on a finding invented over a clean image, and
    [`test_the_clobber_after_the_compare_is_not_the_operand`] below is the case
    that falls THAT way; neither passes a rule that always answers the same.
    """
    violations, runs, branches, _, reasoned = observed(CLOBBERED_OPERAND)
    assert (runs, branches, reasoned) == (1, 1, 1), (runs, branches, reasoned)
    assert len(violations) == 1, violations
    addr, mnemonic, source, load = violations[0]
    assert (addr, mnemonic) == (0x10000B0A, "bne")
    assert source.startswith("cmp r3"), source
    assert load.startswith("ldrb "), load


def test_the_clobber_after_the_compare_is_not_the_operand():
    """The control, and the other direction of the same walk: a clobber that
    reads a buffer does not make the branch secret when the compare did not.

    Green before this change and after it — the rule must not have bought its
    reach by calling everything a taint. Driven with the walk back on the branch
    index it falls on `violations == []` reporting `(0x10000c0c, 'bne', 'cmp r0,
    #56', 'ldrb r4, [r0, r3]')`, which is the image's own `0x10036ff8` read
    wrongly."""
    violations, runs, branches, _, reasoned = observed(CLOBBER_IS_NOT_THE_OPERAND)
    assert (runs, branches, reasoned) == (1, 1, 1), (runs, branches, reasoned)
    assert violations == [], violations


def test_a_store_on_the_far_side_of_a_barrier_does_not_excuse_the_load():
    """Same rule, and this is the direction that could hide a finding: a match
    here EXCUSES the load, so a store the flow cannot have executed would excuse
    a genuine buffer read.

    Driven: with the barrier stop removed from `reload_of_a_store`, this case
    falls on `0 == 1` — the load excused, the finding gone."""
    violations, _, branches, _, _ = observed(STORE_ACROSS_BLOCKS)
    assert branches == 1
    assert len(violations) == 1, violations
    assert violations[0][3].startswith("ldrb ")


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
        ({"exposed_floor": 10_000}, "still visible to the taint"),
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
    values the row runs with are the ones in the module. Pinned, so a floor moves
    in a diff that says why — the reasoned one went 15 -> 20 when a review
    measured that 15 against 24 let nine branches go silently unasked, and STAYED
    at 20 when the measurement itself fell to 22: a floor walked down after every
    narrowing follows the defect it is there to catch."""
    assert (
        ct_gate.RUN_FLOOR,
        ct_gate.BRANCH_FLOOR,
        ct_gate.REASONED_FLOOR,
        ct_gate.EXPOSED_FLOOR,
    ) == (30, 20, 20, 43)


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


#: The scope clause as it read before `a4b53c2` refuted it, and the clause that
#: replaced it. Handed to `audit` as text, never written: the page is tracked,
#: and an interrupt mid-case would leave it modified.
REFUTED_SCOPE = "hand-written `rsk-rsa` keygen primitives."
SHIPPED_SCOPE = "hand-written `rsk-rsa` modexp, sieve and primality primitives"


def refuted_page() -> str:
    page = (ROOT / ct_gate.PAGE).read_text(encoding="utf-8")
    assert SHIPPED_SCOPE in page, "the scope clause moved; re-read the page"
    return page.replace(SHIPPED_SCOPE, REFUTED_SCOPE, 1)


def test_the_scope_paragraph_may_not_rescope_the_modexp_to_keygen():
    """Both directions of the only prose rule here.

    The shipped sentence passes and the refuted one does not, so the rule is not
    a constant. It is a WORD rule and cannot tell a refutation from a claim — the
    page's own residuals say "not keygen-only" — which is why it reads the scope
    paragraph alone, and why the case asserts the shipped page is clean rather
    than only that the mutant reddens.
    """
    page = (ROOT / ct_gate.PAGE).read_text(encoding="utf-8")
    assert ct_gate.scope_finding(page) is None
    problem = ct_gate.scope_finding(refuted_page())
    assert problem and "as keygen" in problem, problem


def test_the_row_itself_refuses_the_refuted_scope_sentence():
    """Through `audit`, not through the helper: a guard whose wiring nothing
    drives can be deleted with the suite still green."""
    findings, _ = ct_gate.audit(
        ROOT, lines=CLEAN.splitlines(), page=refuted_page(), **NO_FLOORS
    )
    assert any("as keygen" in f for f in findings), findings


def test_a_scope_paragraph_that_vanished_is_a_finding():
    """The deletion arm the rule needs to survive its own next edit: keyed on a
    string the page can simply drop, it would otherwise be silenced for free."""
    page = (ROOT / ct_gate.PAGE).read_text(encoding="utf-8")
    problem = ct_gate.scope_finding(
        page.replace(ct_gate.SCOPE_ANCHOR, "This audit covers", 1)
    )
    assert problem and "no paragraph says" in problem, problem


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

    | arm | attributed runs | branches | traced | secret-dependent | row |
    |---|---|---|---|---|---|
    | shipped | 39 | 25 | 22 | 0 | EXIT=0 |
    | early exit in `ct_eq` (`if diff != 0`) | 59 | 27 | 24 | 28 | EXIT=1 |
    | early exit on ONE BIT (`if diff & 0x80 != 0`) | 58 | 27 | 24 | 28 | EXIT=1 |
    | `cmd_update` back to a slice `!=`, `cmd_configure` untouched | 38 | 24 | 21 | 0 | EXIT=1, `cmd_update` inlines no site |
    | early exit with a `copy_from_slice` before it | 3 | 3 | — | 1 | EXIT=1, `0x1006afb8` |

    The last two are the arms an independent review used to refute the first
    version of this gate: at depth-1 taint the bit test reported 0 and passed,
    and keyed on the outermost frame the bypass beside a surviving call reported
    0 and passed. Both now redden, and the fourth reddens with the right message
    rather than on a floor.

    The fifth arm is the one an independent review built, and it is why the stop
    is a REGISTER question. Its `copy_from_slice` puts `bl __aeabi_memset4`
    between the two secret loads and the early exit's `cmp fp, sl`; `fp`/`sl` are
    callee-saved, so the call preserves them and the fall-through is the only
    path. A stop at every transfer reported 0 over it while the rule before this
    one reported 1 — measured on a real build, and the four arms above all sit
    BEFORE any transfer, so not one of them could have caught that.

    Re-driven when the walks were confined to the path, because a rule that stops
    earlier is exactly the change that could blind the row to its own mutant: all
    four arms answer as before, and the shipped one is 0 over 24 branches traced
    to a definition (floor 20). The counts moved from the
    previous recording because the IMAGE moved — two OTP commits — not the rule;
    that is also what surfaced the defect, `ct_eq`'s inlined copy landing within
    64 instructions of two public branches in `cmd_calculate` across two `b.n`
    and a `bl`.

    Re-driven again when the trace moved from the branch to the flag-setter, and
    the four rows above are that re-drive's own numbers. Both moves are the
    stricter direction: the shipped arm traces 22 and not 24, because a `subs r5,
    #1` is no longer credited as the definition of its own operand, and BOTH
    early-exit arms report 28 secret-dependent branches and not 27. The extra one
    is real — `0x10036ebe`, `bne` on `cmp r4, r3` over `ldrb r4, [r1, r2]` — and
    the shipped rule missed it because the walk from the BRANCH met the `b.n` at
    `0x10036ebc` and died one instruction short of the compare whose flags that
    branch reads. No arm lost a finding.

    The fifth row is the exception and is NOT this revision's measurement: its
    source edit was never recorded, so what ran here is a reconstruction —
    `copy_from_slice` into a scratch array ahead of the early exit. It answers 1
    secret-dependent at EXIT=1 like the original, but over 1 run and 2 branches
    rather than 3 and 3, so the row keeps the original's counts and its traced
    cell stays blank rather than borrowing a different mutant's number.

    `crates/rsk-crypto/src/mac.rs` and `crates/rsk-otp/src/lib.rs` restored
    byte-identical (sha256 compared) and the control re-run green after each
    rebuild.

    Cost, measured rather than quoted from the objdump alone: `arm-none-eabi-
    objdump -d -l --inlines` is 0.9 s over a 1 370 429-line dump, and the ROW —
    `python scripts/ct_gate.py` — is about 15 s wall, nearly all of it the Python
    pass. The firmware build it reads was already a row.
    """
    assert ct_gate.REGION == "ct-sites"
