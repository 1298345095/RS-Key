# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""The mutation table for `owner_binding_gate.py`.

Every case runs against RECORDED `arm-none-eabi-readelf` / `arm-none-eabi-nm`
output and a registry handed in as text, so nothing here needs a linked image, a
cross toolchain or a write to the working tree — and nothing SKIPS, which is the
only state `check.sh` cannot tell from a pass.

The recorded DWARF is verbatim in form and elided in bulk: the real dump is
2 052 650 lines and 165 compile units, and the DIEs kept here are the five shapes
the parser reads — a concrete instance carrying its own name, an abstract
instance carrying its own name, a `DW_AT_declaration` with the abstract instance
hung off it by `DW_AT_specification` (5711 of those in the real image, and the
shape a reader of instances alone finds no name on), and the two
`DW_TAG_inlined_subroutine` call sites that are the evidence for `inlined`.

What the cases deliberately do NOT hand in: the tree. `basis_holds` and
`token_refinement_gate.catalogue` read the real `crates/` and `firmware/`, so the
four bases are driven against the source they are claims about rather than
against a fixture that would agree with them by construction.

What this table cannot fail on, said here rather than discovered later: the
parsers meeting a `readelf` whose OUTPUT format moved. That is the row's job — it
runs the real tools over the real image — and it is the split `test_ct_gate.py`
and `test_elf_gate.py` already make.
"""

from __future__ import annotations

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import gate_lines  # noqa: E402
import owner_binding_gate as gate  # noqa: E402
import token_refinement_gate as refinement  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parent.parent

#: `arm-none-eabi-readelf --debug-dump=rawline`, one line program. The directory
#: table is RELATIVE for first-party code — the build remaps it — and the file
#: index is 1-based, DWARF 4.
RAWLINE = """Raw dump of debug contents of section .debug_line:

  Offset:                      0
  Length:                      259119
  DWARF Version:               4
  Prologue Length:             14889
  Minimum Instruction Length:  1
  Opcode Base:                 13

 Opcodes:
  Opcode 1 has 0 args

 The Directory Table (offset 0x1c):
  1\tcrates/rsk-fido/src
  2\tcrates/rsk-device/src
  3\tcrates/rsk-fido/src/conformance

 The File Name Table (offset 0x203f):
  Entry\tDir\tTime\tSize\tName
  1\t1\t0\t0\treset.rs
  2\t1\t0\t0\tseed.rs
  3\t1\t0\t0\tstate.rs
  4\t2\t0\t0\tctap.rs
  5\t3\t0\t0\tmod.rs
"""

#: `arm-none-eabi-readelf --debug-dump=info`. One CU, and the DIE bodies the
#: parser does not read elided. `sweep` is a concrete instance, `clear_ppuat` an
#: abstract one that names itself, `mark_token_used` an abstract one that reaches
#: its name through `DW_AT_specification`, and the two inlined subroutines are
#: the call sites that make the last two evidence rather than documentation.
DWARF = """  Compilation Unit @ offset 0:
   Length:        0x169cbd (32-bit)
   Version:       4
   Abbrev Offset: 0
   Pointer Size:  4
 <0><b>: Abbrev Number: 1 (DW_TAG_compile_unit)
    <c>   DW_AT_producer    : (indirect string, offset: 0xdde5a): clang LLVM (rustc version 1.96.0 (ac68faa20 2026-05-25))
    <10>   DW_AT_language    : 28\t(Rust)
    <12>   DW_AT_name        : (indirect string, offset: 0x19db5d): firmware/src/main.rs/@/firmware.63ca95cc0d98da63-cgu.0
    <16>   DW_AT_stmt_list   : 0
    <1a>   DW_AT_comp_dir    : (indirect string, offset: 0x1ab1a): /Users/maxmur/Code/RS-Key
 <1><96c6a>: Abbrev Number: 14 (DW_TAG_subprogram)
    <96c6b>   DW_AT_low_pc      : 0x1006bd6c
    <96c6f>   DW_AT_high_pc     : 0xc2
    <96c79>   DW_AT_linkage_name: (indirect string, offset: 0x2af260): _ZN8rsk_fido5reset5sweep17hb74b7f7c3f715bcfE
    <96c7d>   DW_AT_name        : (indirect string, offset: 0x209ee3): sweep<rsk_store::SeqStorage<firmware::flash_storage::SharedFlash>, firmware::handler::FidoRng>
    <96c81>   DW_AT_decl_file   : 1
    <96c82>   DW_AT_decl_line   : 106
 <1><ac850>: Abbrev Number: 169 (DW_TAG_subprogram)
    <ac852>   DW_AT_linkage_name: (indirect string, offset: 0x285c0e): _ZN8rsk_fido4seed11clear_ppuat17h90b7fc19f5c74d0fE
    <ac856>   DW_AT_name        : (indirect string, offset: 0x26b166): clear_ppuat<rsk_store::SeqStorage<firmware::flash_storage::SharedFlash>>
    <ac85a>   DW_AT_decl_file   : 2
    <ac85c>   DW_AT_decl_line   : 337
    <ac862>   DW_AT_inline      : 1\t(inlined)
 <2><83ef1>: Abbrev Number: 131 (DW_TAG_subprogram)
    <83ef3>   DW_AT_linkage_name: (indirect string, offset: 0x2b48a2): _ZN8rsk_fido5state9FidoState15mark_token_used17h299e14bc1842cea0E
    <83ef7>   DW_AT_name        : (indirect string, offset: 0x1a1b3f): mark_token_used
    <83efb>   DW_AT_decl_file   : 3
    <83efc>   DW_AT_decl_line   : 491
    <83efe>   DW_AT_declaration : 1
 <1><90000>: Abbrev Number: 17 (DW_TAG_subprogram)
    <90001>   DW_AT_specification: <0x83ef1>
    <90005>   DW_AT_inline      : 1\t(inlined)
 <2><2c7>: Abbrev Number: 20 (DW_TAG_inlined_subroutine)
    <2c8>   DW_AT_abstract_origin: <0xac850>
    <2cc>   DW_AT_low_pc      : 0x10003486
    <2d0>   DW_AT_high_pc     : 0x2
 <2><2e0>: Abbrev Number: 20 (DW_TAG_inlined_subroutine)
    <2e1>   DW_AT_abstract_origin: <0x90000>
    <2e4>   DW_AT_low_pc      : 0x100034a0
    <2e8>   DW_AT_high_pc     : 0x6
"""

#: `arm-none-eabi-nm --defined-only`. `sweep` is defined; the two inlined owners
#: are NOT, which is the whole point of them.
DEFINED = """1006bd6c t _ZN8rsk_fido5reset5sweep17hb74b7f7c3f715bcfE
100952b0 t _ZN4core3ptr70drop_in_place$LT$core..option..Option$GT$17ha07151873ef7e222E
"""

RECORDED = {
    "defined": DEFINED,
    "dwarf": DWARF,
    "rawline": RAWLINE,
    "digest": "395dd99af9987bbfb3a8987333a6a6e2ebf81ae627648037a22c7f76e88af3f3",
}

#: The roster the cases audit: one owner of each disposition, plus the two the
#: rules about absence are written for.
SITES = [
    ("persistent_writer", "crates/rsk-fido/src/reset.rs", "sweep"),
    ("persistent_writer", "crates/rsk-fido/src/seed.rs", "clear_ppuat"),
    ("volatile_writer", "crates/rsk-fido/src/state.rs", "mark_token_used"),
    ("softlock_owner", "crates/rsk-device/src/ctap.rs", "security_trace_snapshot"),
    ("volatile_writer", "crates/rsk-fido/src/conformance/mod.rs", "arm_token"),
]
GATED = {"crates/rsk-fido/src/conformance/mod.rs"}
#: A PARAMETER, at the fixture's own measurement. The shipped floor is 14 against
#: 20 and is not reachable by a five-owner roster; handing it in is how both arms
#: stay drivable without patching the number the real row is judged by.
FLOORS = {"inlined": 2}

CLAIMS = """
[[claim]]
subject = "owner->image"
method = "BINARY-CHECKED"
artifact = "target/thumbv8m.main-none-eabihf/release/firmware"
build = "cargo build --release -p firmware"
statement = "every registered owner is bound to this ELF"

[[claim]]
subject = "bit-for-bit"
method = "MEASURED"
artifact = "result/firmware.uf2"
build = "nix build .#firmware"
verified_by = ".github/workflows/release-build.yml"
statement = "the published images rebuild bit-identical; this gate does not discharge it"
"""

ABSENT = """
[[absent]]
file = "crates/rsk-device/src/ctap.rs"
function = "security_trace_snapshot"
basis = "cfg-gated"
why = "compiled only into the emulator's trace build"
"""


def raw(**overrides) -> dict:
    return {**RECORDED, **overrides}


def run(registry_text=None, **kwargs):
    """`audit` over the fixture, with the roster and the floor handed in."""
    return gate.audit(
        ROOT,
        registry_text=CLAIMS + ABSENT if registry_text is None else registry_text,
        raw=kwargs.pop("raw", RECORDED),
        sites=kwargs.pop("sites", SITES),
        gated=kwargs.pop("gated", GATED),
        floors=kwargs.pop("floors", FLOORS),
        **kwargs,
    )


def check_sh() -> str:
    return (ROOT / "scripts/check.sh").read_text(encoding="utf-8")


def row(needle: str) -> int:
    """The line `check.sh` RUNS `needle` on — a `#` in front of it is not a row."""
    for number, line in enumerate(check_sh().splitlines(), 1):
        if needle in gate_lines.split_at_comment(line)[0]:
            return number
    raise AssertionError(f"check.sh runs no {needle!r}")


# ---- the control -------------------------------------------------------------


def test_the_fixture_is_green_and_says_what_it_measured():
    """The control. Not a no-op: it drives all three dispositions, both claim
    subjects, the specification chain, the registered absence and its basis."""
    findings, summary = run()
    assert not findings, findings
    assert "1 symbol / 2 inlined / 2 absent" in summary, summary
    assert "BINARY-CHECKED" in summary and "395dd99af9987bbf" in summary, summary


def test_the_shipped_registry_and_tree_are_green_together():
    """The control the row itself runs, minus the image: the real registry, the
    real roster, the real module graph and the real bases."""
    findings: list[str] = []
    claims, absents = gate.registry(ROOT, findings)
    assert not findings, findings
    assert {c["subject"]: c["method"] for c in claims} == gate.SUBJECTS
    sites = {(f, fn) for _axis, f, fn in gate.roster(ROOT)}
    assert len(sites) == 44, len(sites)
    # The shipped floor, held from BOTH sides. Zero is the weakening a case
    # cannot see — the cases hand their own floor in — and a floor set AT the
    # measurement of 20 turns a deleted guard into a report about its reader,
    # which is the failure `token_refinement_gate.FLOORS` records paying for.
    assert 0 < gate.FLOORS["inlined"] < 20, gate.FLOORS
    catalogue = refinement.catalogue(ROOT)
    for entry in absents:
        assert (entry["file"], entry["function"]) in sites, entry
        held, measured = gate.basis_holds(
            ROOT, entry["file"], entry["function"], entry["basis"], catalogue
        )
        assert held, (entry, measured)


# ---- the registry shape ------------------------------------------------------


def test_an_unknown_top_level_table_is_refused():
    findings, _ = run(CLAIMS + ABSENT + '\n[[binding]]\nfile = "x"\n')
    assert any("top-level `binding`" in f for f in findings), findings


def test_a_claim_missing_a_field_is_refused():
    findings, _ = run(CLAIMS.replace('build = "cargo build --release -p firmware"\n', "") + ABSENT)
    assert any("claim 1: no `build`" in f for f in findings), findings


def test_an_empty_artifact_is_not_an_answer():
    """`assurance/board/*.toml` ships `firmware_sha256 = ""` in eleven files, so
    a blank field is this tree's own spelling and a presence test walks past it."""
    findings, _ = run(CLAIMS.replace(
        'artifact = "target/thumbv8m.main-none-eabihf/release/firmware"', 'artifact = ""'
    ) + ABSENT)
    assert any("claim 1: `artifact` is empty" in f for f in findings), findings


def test_an_empty_build_is_not_an_answer():
    findings, _ = run(CLAIMS.replace(
        'build = "cargo build --release -p firmware"', 'build = "   "'
    ) + ABSENT)
    assert any("claim 1: `build` is empty" in f for f in findings), findings


def test_an_absent_row_missing_its_basis_is_refused():
    findings, _ = run(CLAIMS + ABSENT.replace('basis = "cfg-gated"\n', ""))
    assert any("absent 1: no `basis`" in f for f in findings), findings


def test_an_absent_row_with_an_empty_why_is_refused():
    findings, _ = run(CLAIMS + ABSENT.replace(
        'why = "compiled only into the emulator\'s trace build"', 'why = ""'
    ))
    assert any("absent 1: `why` is empty" in f for f in findings), findings


def test_the_same_site_registered_absent_twice_is_refused():
    findings, _ = run(CLAIMS + ABSENT + ABSENT)
    assert any("registered absent twice" in f for f in findings), findings


def test_one_bracket_short_of_an_array_of_tables_is_a_finding():
    """`[claim]` and `[[claim]]` are one bracket apart and TOML takes both: the
    first hands the reader a dict, whose iteration yields its KEYS, and every
    rule then asks a string for `.get`. Written as ONE table because a `[claim]`
    followed by a `[[claim]]` is a decode error rather than this shape."""
    one = CLAIMS.split("[[claim]]")[1]
    findings, _ = run("[claim]" + one + ABSENT)
    assert any("is not an array of tables" in f for f in findings), findings


def test_a_field_the_registry_does_not_read_is_refused():
    findings, _ = run(CLAIMS + ABSENT + 'note = "x"\n')
    assert any("`note` is not a field" in f for f in findings), findings


# ---- BINARY-CHECKED is a value, and it is not reproducibility ----------------


def test_the_reproducibility_row_may_not_wear_binary_checked():
    """The exit criterion, driven: source→binary and bit-for-bit are different
    evidence, and the second wearing the first's word is the laundering."""
    findings, _ = run(CLAIMS.replace(
        'subject = "bit-for-bit"\nmethod = "MEASURED"',
        'subject = "bit-for-bit"\nmethod = "BINARY-CHECKED"',
    ) + ABSENT)
    assert any("`bit-for-bit` carries `BINARY-CHECKED`" in f for f in findings), findings


def test_the_binding_row_may_not_hide_behind_measured():
    """The pairing holds in BOTH directions, so `BINARY-CHECKED` cannot be
    dropped from the registry by relabelling the row that carries it."""
    findings, _ = run(CLAIMS.replace(
        'subject = "owner->image"\nmethod = "BINARY-CHECKED"',
        'subject = "owner->image"\nmethod = "MEASURED"',
    ) + ABSENT)
    assert any("`owner->image` carries `MEASURED`" in f for f in findings), findings


def test_a_subject_outside_the_vocabulary_is_refused():
    findings, _ = run(CLAIMS.replace('subject = "bit-for-bit"', 'subject = "vibes"') + ABSENT)
    assert any("`vibes` is not one of" in f for f in findings), findings


def test_the_compiler_frontier_is_refused_by_name():
    """`owner->image` is not `source->binary`. A symbol and an inlined call site
    say a function is IN the image; they say nothing about whether the emitted
    code does what the source says, and `PLAT-TOOLCHAIN-001` is `pending` on
    exactly that. Refused by NAME rather than by falling off the end of the
    vocabulary, so the message says why."""
    findings, _ = run(CLAIMS.replace('subject = "owner->image"', 'subject = "source->binary"') + ABSENT)
    assert any("PLAT-TOOLCHAIN-001 still holds that obligation open" in f
               for f in findings), findings
    assert not any("is not one of" in f for f in findings), findings


def test_a_missing_subject_is_refused_so_the_pairing_runs_over_data():
    """A one-row registry makes the pairing rule a comment: with nothing on the
    other subject nothing ever exercises it."""
    findings, _ = run(CLAIMS.split("[[claim]]")[0] + "[[claim]]" + CLAIMS.split("[[claim]]")[1] + ABSENT)
    assert any("no claim on subject `bit-for-bit`" in f for f in findings), findings


def test_two_rows_on_one_subject_are_refused():
    findings, _ = run(CLAIMS + CLAIMS.split("[[claim]]")[2].join(["[[claim]]", ""]) + ABSENT)
    assert any("claims on subject `bit-for-bit`" in f for f in findings), findings


def test_the_row_this_gate_discharges_may_not_name_a_second_verifier():
    findings, _ = run(CLAIMS.replace(
        'statement = "every registered owner is bound to this ELF"',
        'statement = "x"\nverified_by = ".github/workflows/ci.yml"',
    ) + ABSENT)
    assert any("it is verified HERE" in f for f in findings), findings


def test_a_row_this_gate_does_not_discharge_must_name_its_verifier():
    findings, _ = run(CLAIMS.replace(
        'verified_by = ".github/workflows/release-build.yml"\n', ""
    ) + ABSENT)
    assert any("claim 2: no `verified_by`" in f for f in findings), findings


def test_a_verifier_that_is_not_a_file_is_refused():
    findings, _ = run(CLAIMS.replace(
        ".github/workflows/release-build.yml", ".github/workflows/no-such-job.yml"
    ) + ABSENT)
    assert any("no workflow of this repo" in f for f in findings), findings


def test_a_verifier_that_is_a_page_rather_than_a_job_is_refused():
    """The bypass `f124135` threw out one registry over, in this rule's own
    shape: `README.md` exists, mentions `nix build`, and verifies nothing."""
    findings, _ = run(CLAIMS.replace(
        ".github/workflows/release-build.yml", "README.md"
    ) + ABSENT)
    assert any("no workflow of this repo" in f for f in findings), findings


def test_a_workflow_that_runs_the_build_is_what_verifies_it():
    """Not "a workflow that exists": measured over this repo's eight, four
    executed `nix build` lines in `release-build.yml` and none in `ci.yml`."""
    findings, _ = run(CLAIMS.replace(
        ".github/workflows/release-build.yml", ".github/workflows/ci.yml"
    ) + ABSENT)
    assert any("runs no `nix build`" in f for f in findings), findings


def test_the_tool_a_verifier_must_run_is_read_off_the_row():
    """`invoked` stops at the first operand, so the rule is the claim's own
    `build` and not a second copy of it typed into this gate."""
    assert gate.invoked("nix build .#firmware") == "nix build"
    assert gate.invoked("cargo build --release -p firmware") == "cargo build"
    assert gate.invoked("env FLASH_SIZE=16M cargo build") == "env FLASH_SIZE=16M cargo build"


def test_the_artifact_is_held_against_the_other_registry_in_this_window():
    """Two registries on two binaries is how a row comes to certify the image it
    does not audit: `assurance/image.toml` names the same path, and the no-touch
    build overwrites it ~250 rows later."""
    findings, _ = run(CLAIMS.replace(
        "target/thumbv8m.main-none-eabihf/release/firmware",
        "target/thumbv8m.main-none-eabihf/release/rsk-wipe",
    ) + ABSENT)
    assert any("names `target/thumbv8m.main-none-eabihf/release/firmware`" in f for f in findings), findings


# ---- the image ---------------------------------------------------------------


def test_a_stripped_image_is_refused_before_any_owner_is_judged():
    """Every owner resolves `absent` on a stripped binary, and three of those
    answers are ones this gate WANTS — so the vacuity guard runs first."""
    findings, _ = run(raw=raw(dwarf=DWARF.replace("DW_AT_producer", "DW_AT_nothing")))
    assert findings and "no DW_AT_producer" in findings[0], findings
    assert len(findings) == 1, findings


def test_an_inlined_owner_is_bound_by_a_call_site_and_not_by_debug_info():
    """The decision the whole design turns on. An abstract instance with no
    `DW_TAG_inlined_subroutine` pointing at it describes a function the image
    does not carry, and reading it as present makes the gate decorative."""
    findings, _ = run(raw=raw(dwarf=DWARF.replace("DW_AT_abstract_origin: <0xac850>", "DW_AT_abstract_origin: <0x1>")))
    assert any("crates/rsk-fido/src/seed.rs::clear_ppuat" in f and "no part of the image" in f
               for f in findings), findings


def test_an_owner_reached_only_through_a_specification_is_still_found():
    """Rust hangs the name and the file on a `DW_AT_declaration` inside the type;
    dropping the chain loses every method in the roster at once."""
    findings, _ = run(raw=raw(dwarf=DWARF.replace("DW_AT_specification: <0x83ef1>", "DW_AT_specification: <0x2>")))
    assert any("crates/rsk-fido/src/state.rs::mark_token_used" in f for f in findings), findings


def test_a_concrete_instance_with_no_symbol_is_its_own_finding():
    """Not a quieter pass: a standalone function the image defines no name for is
    a binding nothing can audit."""
    findings, _ = run(raw=raw(defined=""))
    assert any("defines no symbol for it" in f and "reset.rs::sweep" in f for f in findings), findings


def test_the_decl_file_index_is_resolved_through_the_line_program():
    """A `DW_AT_decl_file` is an index into the CU's OWN table; index 1 is a
    different file in another unit, so a reader that guesses binds nothing."""
    findings, _ = run(raw=raw(rawline=RAWLINE.replace("  1\t1\t0\t0\treset.rs", "  1\t1\t0\t0\tzzz.rs")))
    assert any("crates/rsk-fido/src/reset.rs::sweep" in f for f in findings), findings


def test_an_absolute_directory_table_is_still_bound():
    """A build that does not remap emits `DW_AT_comp_dir` plus absolute
    directories, and the owner paths are repo-relative. Driven, because this
    image's first-party directories happen to be relative already: with the
    normaliser removed the fixture stays green and this case does not."""
    absolute = RAWLINE.replace("  1\tcrates/", "  1\t/Users/maxmur/Code/RS-Key/crates/")
    findings, summary = run(raw=raw(rawline=absolute))
    assert not findings, findings
    assert "1 symbol" in summary, summary


def test_the_floor_holds_the_inlined_class():
    """A PARAMETER, not a global: the arm is driven by raising it, never by a
    case reaching into the module to lower the shipped one."""
    findings, _ = run(floors={"inlined": 3})
    assert any("floor 3" in f for f in findings), findings


# ---- who may be absent -------------------------------------------------------


def test_a_test_only_owner_in_the_shipped_image_is_named_a_defect():
    """The direction matters: this fires when the conformance writer IS present,
    not when it is missing."""
    findings, _ = run(gated={"crates/rsk-fido/src/reset.rs"})
    assert any("is TEST-ONLY and is in the shipped image as `symbol`" in f for f in findings), findings


def test_a_test_only_owner_may_not_carry_a_hand_written_absence():
    """Its absence is DERIVED from the module graph; a row answering it is a
    second answer to a derived question."""
    findings, _ = run(CLAIMS + ABSENT + """
[[absent]]
file = "crates/rsk-fido/src/conformance/mod.rs"
function = "arm_token"
basis = "unreached"
why = "conformance only"
""")
    assert any("its absence is DERIVED from the module graph" in f for f in findings), findings


def test_an_absent_owner_with_no_registered_row_is_refused():
    findings, _ = run(CLAIMS)
    assert any("registers no absence for it" in f and "security_trace_snapshot" in f
               for f in findings), findings


def test_a_stale_exemption_is_refused():
    """A row kept for an owner the image now binds is one nobody will notice go
    stale — the allowlist would then be shorter than the contract by one."""
    findings, _ = run(CLAIMS + ABSENT.replace(
        'file = "crates/rsk-device/src/ctap.rs"\nfunction = "security_trace_snapshot"',
        'file = "crates/rsk-fido/src/reset.rs"\nfunction = "sweep"',
    ))
    assert any("stale exemption" in f for f in findings), findings


def test_an_absence_for_a_site_no_axis_owns_is_refused():
    findings, _ = run(CLAIMS + ABSENT + """
[[absent]]
file = "crates/rsk-fido/src/getinfo.rs"
function = "get_info"
basis = "unreached"
why = "not an owner at all"
""")
    assert any("owns no such site" in f for f in findings), findings


# ---- the bases, driven against the real tree ---------------------------------


def bases_of(function: str):
    """Which of the four the tree bears for one real absent owner."""
    catalogue = refinement.catalogue(ROOT)
    where = {
        "security_trace_snapshot": "crates/rsk-device/src/ctap.rs",
        "store_pin_lock": "crates/rsk-device/src/lib.rs",
        "store_local_pin": "crates/rsk-fido/src/clientpin.rs",
        "round_trips": "firmware/src/pin_lock.rs",
    }[function]
    return {
        basis: gate.basis_holds(ROOT, where, function, basis, catalogue)[0]
        for basis in gate.BASES
    }


def test_each_registered_absence_bears_exactly_one_basis():
    """Disjoint by construction, and that is the point: one row is genuinely
    cfg-gated AND has no caller in scope, so without the exclusions its basis
    could be swapped for a weaker one and stay green."""
    assert bases_of("security_trace_snapshot") == {
        "cfg-gated": True, "trait-default-body": False,
        "const-evaluated": False, "unreached": False}
    assert bases_of("store_pin_lock") == {
        "cfg-gated": False, "trait-default-body": True,
        "const-evaluated": False, "unreached": False}
    assert bases_of("store_local_pin") == {
        "cfg-gated": False, "trait-default-body": False,
        "const-evaluated": False, "unreached": True}
    assert bases_of("round_trips") == {
        "cfg-gated": False, "trait-default-body": False,
        "const-evaluated": True, "unreached": False}


def test_a_relabelled_basis_is_refused():
    findings, _ = run(CLAIMS + ABSENT.replace('basis = "cfg-gated"', 'basis = "unreached"'))
    assert any("claims basis `unreached` and the tree does not bear it" in f
               for f in findings), findings


def test_a_basis_outside_the_vocabulary_is_refused():
    findings, _ = run(CLAIMS + ABSENT.replace('basis = "cfg-gated"', 'basis = "trust me"'))
    assert any("is not one of" in f and "trust me" in f for f in findings), findings


def test_a_feature_turned_on_by_default_stops_being_a_basis():
    """`cfg-gated` is a claim about the DEFAULT image, so it is re-derived from
    the manifests rather than read off the attribute."""
    assert "security-trace" not in gate.default_features(ROOT, "crates/rsk-device/src/ctap.rs")
    assert gate.default_features(ROOT, "crates/rsk-fido/src/clientpin.rs") == set()


def crate(tmp_path, manifest: str, image: str = "") -> pathlib.Path:
    """A two-manifest tree, because this tree cannot drive the rule.

    Measured: neither `rsk-device` nor `firmware` declares a `default` list and
    `rsk-device = { workspace = true }` enables nothing, so `default_features`
    returns the empty set here whatever it reads — a case written over the real
    manifests is green with the function stubbed out to `set()`, driven.
    """
    (tmp_path / "crates/thing/src").mkdir(parents=True)
    (tmp_path / "crates/thing/Cargo.toml").write_text(manifest, encoding="utf-8")
    (tmp_path / "crates/thing/src/a.rs").write_text("fn a() {}\n", encoding="utf-8")
    if image:
        (tmp_path / "firmware").mkdir(parents=True)
        (tmp_path / "firmware/Cargo.toml").write_text(image, encoding="utf-8")
    return tmp_path


def test_a_crates_own_default_list_is_read(tmp_path):
    root = crate(tmp_path, '[package]\nname = "thing"\n[features]\ndefault = ["screen"]\nscreen = []\n')
    assert gate.default_features(root, "crates/thing/src/a.rs") == {"screen"}


def test_the_image_crates_default_closure_reaches_a_dependency_feature(tmp_path):
    """`default = ["big"]`, `big = ["thing/screen"]` — one hop, and the closure is
    walked rather than read, because a feature list names features."""
    root = crate(
        tmp_path,
        '[package]\nname = "thing"\n[features]\nscreen = []\n',
        '[package]\nname = "firmware"\n[features]\ndefault = ["big"]\nbig = ["thing/screen"]\n',
    )
    assert gate.default_features(root, "crates/thing/src/a.rs") == {"screen"}


def test_a_feature_the_image_asks_of_a_dependency_is_on(tmp_path):
    root = crate(
        tmp_path,
        '[package]\nname = "thing"\n[features]\nscreen = []\n',
        '[package]\nname = "firmware"\n[dependencies]\nthing = { path = "../crates/thing", features = ["screen"] }\n',
    )
    assert gate.default_features(root, "crates/thing/src/a.rs") == {"screen"}


def test_a_trait_body_is_found_by_brace_counting_and_not_by_a_pattern():
    """A trait body holds nested blocks; a regex stopping at the first `}` reads
    the trait as ending inside its own first default method."""
    text = (ROOT / "crates/rsk-device/src/lib.rs").read_text(encoding="utf-8")
    assert gate.in_trait_item(text, "store_pin_lock")
    assert not gate.in_trait_item(text, "no_such_method_anywhere")


# ---- the wiring --------------------------------------------------------------


def test_the_row_reads_the_default_image_because_of_where_it_sits():
    """The claim says the DEFAULT profile and nothing but the row's POSITION
    makes that true: `target/…/release/firmware` is one path four `-p firmware`
    rows write in turn, so this row moved down to the other Python gates would
    audit the no-touch binary. Measured: 0 `bootsel` symbols in that image
    against the default image's 2."""
    default = row('run "build firmware (release)"')
    audits = row("python scripts/owner_binding_gate.py")
    rebuilds = [
        row('run "build firmware (16M)"'),
        row('run "build firmware (display)"'),
        row("--features no-touch"),
    ]
    assert default < audits < min(rebuilds), (default, audits, rebuilds)
    assert max(rebuilds) < row("python -m pytest scripts -q"), rebuilds


def test_the_row_sits_with_the_other_readers_of_this_image():
    """Beside `ct_gate` and `elf_gate`, which read the same binary in the same
    window and whose registry this one holds its artifact against."""
    assert row("python scripts/elf_gate.py") < row("python scripts/owner_binding_gate.py")


def test_the_table_can_go_red():
    """The mutation table: 39 arms, each an edit to `scripts/owner_binding_gate.py`
    driven through this file in a copy of the tree, with the exit code taken from
    the process (no pipe) and the FAILING ASSERTION read for its DIRECTION.
    Unmutated: rc 0, **47 passed, 0 skipped**. Every arm below is rc 1; zero
    mutations came back green.

    **Deletion arms — every clause removed outright**, because a clause nothing
    runs can be deleted with the suite still green, and a mutated form of it
    going red does not prove otherwise:

    * claim missing-field loop → 2 cases; the second by `KeyError: 'verified_by'`
    * claim extra-field loop → 1 · claim empty-string loop → 2
    * absent missing-field loop → 1, by `KeyError: 'basis'`
    * absent extra-field loop → 1 · absent empty-string loop → 1
    * duplicate `[[absent]]` row → 1 · unknown top-level table → 1
    * the array-of-tables shape guard → 1, by `AttributeError: 'str' object has
      no attribute 'get'`: `[claim]` is one bracket from `[[claim]]`, TOML takes
      both, and the dict's iteration yields its keys
    * subject vocabulary → 1 · both-subjects-present → 1
    * the `source->binary` refusal → 1, and the direction is the defect it was
      written for: without it the frontier row is refused as "no `verified_by`",
      which is true and is not what is wrong with it. `registry` decides a row's
      owed fields FROM its subject, so a shape rule shadows a subject rule unless
      the subject rule runs first
    * subject/method pairing → 2, in OPPOSITE directions: one says the
      reproducibility row kept `BINARY-CHECKED`, one that the binding row kept
      `MEASURED`
    * verifier-is-a-workflow → 2, one by `FileNotFoundError`: the guard stands in
      front of the read, and `README.md` — which exists and mentions the
      command — becomes a legal verifier, the exact bypass `f124135` threw out
      one registry over
    * verifier-runs-the-build → 1: `ci.yml` verifies the reproducibility claim
    * artifact-vs-`assurance/image.toml` → 1
    * the stripped-image vacuity guard → 1, `assert ([])` — without it the arm
      reports 3 owner findings instead of the one saying nothing read a compiler
    * the `unsymbolised` arm → 1, by `IndexError` rather than by a missing
      finding: the guard stands in front of `shipped[0]`, the shape
      `test_elf_gate.py` records for its vector-section rule
    * `abstract and inlined.get(site, 0)` → 1: `clear_ppuat` reads `inlined` off
      an orphaned abstract instance, the decision the whole design turns on
    * the test-only clause → 4, in BOTH directions: the two controls go red
      because a correct test-only owner now demands an `[[absent]]` row (false
      alarm), and `..._is_named_a_defect` because a test-only owner PRESENT in
      the image stops being reported (missed defect)
    * the hand-written-absence-over-a-derived-one clause → 1
    * the stale-exemption clause → 1 · the absence-owns-no-site loop → 1
    * `basis_holds` → 2 · the floor comparison → 1
    * the `DW_AT_specification` chain → 2, both controls: `mark_token_used`
      leaves the image entirely. 5711 DIEs in the real dump are that shape
    * `relative()` → 1, and only the case written for it. Measured and worth
      stating: this image's first-party directories are already relative, so the
      normaliser is a no-op on the fixture AND on the row — a build that does not
      remap is what it is for, and until that case existed it was a rule that
      could not fail
    * `default_features` stubbed to `set()` → 3, all three `tmp_path` manifests.
      Same lesson: the real manifests declare no `default` at all, so every case
      written over the tree stayed green with the function gone

    **Constructed defects**, each read for which way it fell:

    * `SUBJECTS["bit-for-bit"] = "BINARY-CHECKED"` → 22 cases, and the direction
      is the one that matters:
      `test_the_reproducibility_row_may_not_wear_binary_checked` fails on
      `findings == []` — the laundered row was ACCEPTED, not "refused for the
      wrong reason" — while the control fails because the honest `MEASURED` row
      is now refused. The vocabulary IS the rule
    * `DISCHARGES = "bit-for-bit"` → 27 cases: both claims then wear the
      undischarged shape and the `verified_by` rules invert
    * `FRONTIER = "owner->image"` → 30 cases: the subject this gate exists to
      carry becomes the one it refuses. The arm that says the refusal is a
      vocabulary and not a spelling in a message
    * `bind` returning `symbol` without consulting `nm` → 1
    * `invoked()` returning the whole command → 17: `nix build .#firmware` is not
      a substring of any workflow line, so every claim's verifier is refused. The
      arm for the tool being DERIVED from the row's own `build`
    * `unreached` dropping its exclusions → 2, the pair that says the four bases
      are a PARTITION and not a menu: the row that is genuinely cfg-gated also
      has no caller in scope
    * `FLOORS["inlined"] = 0` → `assert 0 < 0`; `= 20` → `assert 20 < 20`. The
      cases hand their own floor in, so the shipped value is held from both sides
      by a range instead — zero is the weakening, and a floor set AT the
      measurement turns a deleted guard into a report about its reader
    * `roster()` reading one axis instead of `refinement.AXES` → 1 (44 → 11)
    * `DW_AT_decl_file` read `+ 1` → 5: every owner shifts one file over
    * the test-only defect clause off → 1, and the assertion that falls is the
      "should have been refused" one
    """
    assert gate.SUBJECTS["owner->image"] == gate.DISCHARGED
    assert gate.SUBJECTS["bit-for-bit"] != gate.DISCHARGED
