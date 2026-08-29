# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""The mutation table for `elf_gate.py`.

Every case runs against the REAL image the gate row reads, because that is the
subject; what the cases mutate is the registry and the linker script, both handed
in rather than written to the tree. The one thing a case cannot do is relink the
firmware, so the arms that need a different binary are driven by hand and
recorded in [`test_the_image_arms_were_driven_by_hand`].
"""

from __future__ import annotations

import copy
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import elf_gate  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parent.parent


def shipped():
    findings: list[str] = []
    image = elf_gate.registry(ROOT, findings)
    assert not findings, findings
    return image


def built() -> bool:
    return (ROOT / elf_gate.ELF).is_file()


needs_image = pytest.mark.skipif(
    not (ROOT / elf_gate.ELF).is_file(),
    reason="no release firmware built; the gate row builds it one line above",
)


def test_the_registry_is_the_shape_the_gate_reads():
    image = shipped()
    assert image["profile"] == "default"
    assert image["writable_executable"] == [".data"]
    assert set(image["allocator"]) == {
        "__rust_alloc",
        "__rust_realloc",
        "__rust_alloc_error_handler",
    }


def test_the_registry_refuses_a_key_it_does_not_read():
    findings: list[str] = []
    path = ROOT / elf_gate.REGISTRY
    original = path.read_text(encoding="utf-8")
    try:
        path.write_text(original.replace('profile = "default"', 'profile = "default"\nnote2 = "x"', 1))
        elf_gate.registry(ROOT, findings)
    finally:
        path.write_text(original, encoding="utf-8")
    assert any("is not a field this registry reads" in f for f in findings), findings


def test_the_linker_regions_parse():
    where = elf_gate.regions(ROOT)
    assert set(where) == {"FLASH", "KVMAIN", "KVCNT", "RAM"}
    assert where["FLASH"][0] == 0x10000000
    assert where["RAM"][0] == 0x20000000


@needs_image
def test_the_shipped_image_is_clean():
    """The control. Without it every case below could pass over a dead parser."""
    findings, summary = elf_gate.audit(ROOT)
    assert not findings, findings
    assert "0 undefined" in summary


@needs_image
def test_a_second_writable_executable_segment_is_a_finding():
    image = copy.deepcopy(shipped())
    image["writable_executable"] = []
    findings, _ = elf_gate.audit(ROOT, image=image)
    assert any("writable AND executable" in f for f in findings), findings


@needs_image
def test_an_allocator_symbol_that_is_not_registered_is_a_finding():
    image = copy.deepcopy(shipped())
    image["allocator"] = ["__rust_alloc"]
    findings, _ = elf_gate.audit(ROOT, image=image)
    assert any("allocator surface" in f for f in findings), findings


@needs_image
def test_a_vector_table_away_from_the_flash_origin_is_a_finding():
    image = copy.deepcopy(shipped())
    image["vector_section"] = ".text"
    findings, _ = elf_gate.audit(ROOT, image=image)
    assert any("not at" in f and "FLASH origin" in f for f in findings), findings


@needs_image
def test_a_segment_outside_every_region_is_a_finding():
    # FLASH shrunk to one page: `.text` no longer fits any region, and neither
    # does the vector table's own segment.
    linker = (ROOT / elf_gate.LINKER).read_text(encoding="utf-8").replace(
        "FLASH  : ORIGIN = 0x10000000, LENGTH = 2560K",
        "FLASH  : ORIGIN = 0x10000000, LENGTH = 4K",
        1,
    )
    findings, _ = elf_gate.audit(ROOT, linker=linker)
    assert any("outside every" in f for f in findings), findings


@needs_image
def test_code_landing_in_the_kv_store_is_a_finding():
    # The rule the partition table cannot state: KVMAIN moved down onto the code
    # the linker already placed. The table fences the store from BOOTSEL; this
    # fences it from the linker.
    linker = (ROOT / elf_gate.LINKER).read_text(encoding="utf-8").replace(
        "KVMAIN : ORIGIN = 0x10280000, LENGTH = 1408K",
        "KVMAIN : ORIGIN = 0x10001000, LENGTH = 1408K",
        1,
    )
    findings, _ = elf_gate.audit(ROOT, linker=linker)
    assert any("erased by its own store" in f for f in findings), findings


@needs_image
def test_the_entry_point_is_inside_flash():
    _, _, entry = elf_gate.segments(ROOT, pathlib.Path(shipped()["elf"]))
    flash = elf_gate.regions(ROOT)["FLASH"]
    assert flash[0] <= entry < flash[1], hex(entry)


def test_exactly_one_global_allocator_is_declared():
    """The other end of the allocator question, over the SOURCE. The symbol rule
    is a list of spellings and a rule that is a list of spellings is bypassed by
    one nobody listed; a second `#[global_allocator]` is a different heap
    whatever its symbols are called. Measured: one, `firmware/src/main.rs`."""
    declared = [
        path.relative_to(ROOT)
        for root_dir in elf_gate.FIRST_PARTY_RUST
        for path in sorted((ROOT / root_dir).rglob("*.rs"))
        if elf_gate.GLOBAL_ALLOCATOR.search(path.read_text(errors="replace"))
    ]
    assert [str(p) for p in declared] == ["firmware/src/main.rs"], declared


def test_the_declaration_pattern_is_anchored_to_the_attribute():
    """Not to the word: `docs/unsafe.md` and this docstring both say
    `global_allocator`, and a rule that matched the word would count them."""
    assert elf_gate.GLOBAL_ALLOCATOR.search("#[global_allocator]\n")
    assert elf_gate.GLOBAL_ALLOCATOR.search("    #[global_allocator]\n")
    assert not elf_gate.GLOBAL_ALLOCATOR.search("// a global_allocator lives here")
    assert not elf_gate.GLOBAL_ALLOCATOR.search("let global_allocator = 1;")


def test_the_image_arms_were_driven_by_hand():
    """Recorded, because a case cannot relink the firmware.

    Measured on the shipped default image, `arm-none-eabi-readelf -lW` and
    `arm-none-eabi-nm`:

    | fact | measured |
    |---|---|
    | LOAD segments | 5 (`.vector_table`+`.start_block`, `.text`, `.bi_entries`+`.rodata`, `.data`, `.bss`) |
    | writable AND executable | 1, `.data`, at run address `0x2002baa0` and load address `0x100c4f08` |
    | allocator symbols defined | 3 |
    | undefined symbols | 0 |
    | entry point | `0x1000013d`, inside `.text` |

    The `.data` segment is the reason the W+X rule is "exactly the registered
    one" and not "none": it carries the routines that must not run from XIP
    flash, and a blanket rule would be red on a correct image.
    """
    assert elf_gate.UNITS == {"": 1, "K": 1024, "M": 1024 * 1024}
