# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""Legacy/v0 attribution and machine identity, using rustc-emitted v0 fixtures."""

import pathlib
import subprocess
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import ct_gate  # noqa: E402
import rust_symbols as symbols  # noqa: E402

# Emitted by rustc 1.99.1 with symbol-mangling-version=v0: two monomorphizations,
# two concrete impls, two traits, and two closures of the same enclosing function.
GENERIC = (
    "_RINvCshZXx2BFZwZ5_11rsk_fixture7generichEB2_",
    "_RINvCshZXx2BFZwZ5_11rsk_fixture7generictEB2_",
)
OWNER = (
    "_RNvMCshZXx2BFZwZ5_11rsk_fixtureINtB2_5OwnerhE5resetB2_",
    "_RNvMCshZXx2BFZwZ5_11rsk_fixtureINtB2_5OwnertE5resetB2_",
)
CONCRETE = (
    "_RNvMs_CshZXx2BFZwZ5_11rsk_fixtureINtB4_5OwnerhE5clear",
    "_RNvMs0_CshZXx2BFZwZ5_11rsk_fixtureINtB5_5OwnertE5clear",
)
TRAIT = (
    "_RNvXs1_CshZXx2BFZwZ5_11rsk_fixtureINtB5_5OwnerhEINtB5_5ResethE5reset",
    "_RNvXs2_CshZXx2BFZwZ5_11rsk_fixtureINtB5_5OwnerhEINtB5_5ResettE5reset",
    "_RNvXs3_CshZXx2BFZwZ5_11rsk_fixtureINtB5_5OwnerhENtB5_5Other5reset",
)
CLOSURE = (
    "_RNCNvCshZXx2BFZwZ5_11rsk_fixture8exercise0B3_",
    "_RNCNvCshZXx2BFZwZ5_11rsk_fixture8exercises_0B3_",
)
LEGACY = (
    "_ZN11rsk_fixture7generic17h0123456789abcde0E",
    "_ZN11rsk_fixture7generic17h0123456789abcde1E",
)


def test_source_identity_keeps_types_traits_and_numbered_closures_distinct():
    names = symbols.demangle_many(GENERIC + OWNER + CONCRETE + TRAIT + CLOSURE + LEGACY)
    assert names[GENERIC[0]] == names[GENERIC[1]] == names[LEGACY[0]] == "rsk_fixture::generic"
    assert names[OWNER[0]] == names[OWNER[1]] == "rsk_fixture::Owner::reset"
    assert names[TRAIT[0]] == names[TRAIT[1]] == "<rsk_fixture::Owner as rsk_fixture::Reset>::reset"
    assert names[TRAIT[0]] != names[TRAIT[2]] != names[OWNER[0]]
    assert names[CLOSURE[0]] == "rsk_fixture::exercise::{closure#0}"
    assert names[CLOSURE[1]] == "rsk_fixture::exercise::{closure#1}"
    assert names[CLOSURE[0]] != names[CLOSURE[1]]
    assert len({name.linkage for name in names.values()}) == len(names)
    assert names[OWNER[0]].spelling != names[OWNER[1]].spelling


@pytest.mark.parametrize(
    "pair", [GENERIC, OWNER, CONCRETE, TRAIT[:2], CLOSURE, LEGACY],
    ids=["generic", "owner", "concrete", "trait-argument", "closure", "legacy-hash"],
)
def test_source_aliases_never_join_machine_data_flow(pair):
    first, second = pair
    dump = [
        f"inlined by /x/f.rs:1 ({first})",
        "10000000:\t6002     \tstr\tr2, [r0, #0]",
        f"inlined by /x/f.rs:2 ({second})",
        "10000002:\t7802     \tldrb\tr2, [r0, #0]",
        "10000004:\t2a00     \tcmp\tr2, #0",
        "10000006:\td001     \tbne\t1000000c",
    ]
    stream = list(ct_gate.instructions(dump))
    assert len(stream) == 4
    assert list(ct_gate.walk_back(stream, 1, None)) == []
    assert ct_gate.last_definition(stream, 1, "r2") is None
    assert not ct_gate.reload_of_a_store(stream, 1)
    assert ct_gate.buffer_load(stream, 2, "r2")[0] == 0x10000002


@pytest.mark.parametrize("raw", ["_Rnot_a_valid_symbol", "_ZN3bad"])
def test_unsupported_rust_names_fail_closed(raw):
    with pytest.raises(ValueError, match="could not decode"):
        symbols.demangle(raw)


@pytest.mark.parametrize("output", ["", GENERIC[0] + "\n", "one\ntwo\n"])
def test_broken_decoder_output_cannot_become_an_unattributed_frame(monkeypatch, output):
    def broken(*args, **kwargs):
        return subprocess.CompletedProcess(args[0], 0, output)
    monkeypatch.setattr(symbols.subprocess, "run", broken)
    with pytest.raises(ValueError, match="Rust demangler"):
        symbols.demangle(GENERIC[0])


@pytest.mark.parametrize("error", [FileNotFoundError("no demangler"), subprocess.CalledProcessError(1, "demangler")])
def test_missing_or_failed_decoder_is_a_gate_finding(monkeypatch, error):
    def failed(*args, **kwargs):
        raise error
    monkeypatch.setattr(symbols.subprocess, "run", failed)
    findings, summary = ct_gate.audit(
        ct_gate.ROOT,
        lines=[f"inlined by /x/f.rs:1 ({GENERIC[0]})", "10000000:\t6002     \tstr\tr2, [r0]"],
    )
    assert findings and not summary


def test_same_named_function_in_a_different_crate_is_not_the_registered_site():
    names = symbols.demangle_many([
        "_ZN10rsk_crypto3mac5ct_eq17h0123456789abcde0E",
        "_ZN11rsk_fixture3mac5ct_eq17h0123456789abcde0E",
    ])
    assert set(names.values()) == {"rsk_crypto::mac::ct_eq", "rsk_fixture::mac::ct_eq"}


def test_legacy_closures_do_not_guess_a_v0_closure_number():
    old = symbols.demangle(
        "_ZN7rsk_otp9OtpApplet8cmd_swap28_$u7b$$u7b$closure$u7d$$u7d$17h0123456789abcdefE"
    )
    assert old == "rsk_otp::OtpApplet::cmd_swap::{{closure}}"
    assert old != "rsk_otp::OtpApplet::cmd_swap::{closure#0}"
