#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""Binary hygiene: what the linker actually produced, against what it may.

Stage 11A of the formal-verification programme asks for the ELF's segments,
memory map, vector table and allocator/FFI surface to be machine-checked rather
than described. `check.sh` already reads the image five ways — size, stack floor,
a debug-symbol deny-list, the partition table, the sealed IMAGE_DEF — and none of
them looks at where the sections LAND or at what the image links.

Two facts this measured that the tree's prose does not carry:

* **The image has a heap.** `firmware/src/main.rs` declares
  `#[global_allocator] static HEAP: embedded_alloc::LlffHeap` over 128 KiB, and
  the linked image defines `__rust_alloc`, `__rust_realloc` and
  `__rust_alloc_error_handler`. AGENTS.md's "no_std, no alloc" is a rule about
  new code, not a description of the tree — `docs/unsafe.md` site 4 is the heap
  init and says so. Nothing held that surface, so a SECOND allocator, or a
  `malloc` arriving through a dependency, was invisible.
* **One segment is writable AND executable, and that is deliberate.** `.data`
  carries the routines that must not run from XIP flash — the RSA assembly and
  the keygen sieve step, whose absence from `.data` was measured as a 1.36x
  regression. A blanket "no W+X" rule would be red on a correct image, which is
  why the rule here is "exactly the registered one".

The scope is the DEFAULT image and it says so: `check.sh` rebuilds this path
three more times below this row (16 MB, display, no-touch), so a row placed with
the other Python gates would audit the no-touch binary. The other profiles are a
named gap in `assurance/image.toml`, not a silent one.
"""

from __future__ import annotations

import pathlib
import re
import subprocess
import sys
import tomllib

ROOT = pathlib.Path(__file__).resolve().parent.parent

REGISTRY = pathlib.Path("assurance/image.toml")
ELF = pathlib.Path("target/thumbv8m.main-none-eabihf/release/firmware")
LINKER = pathlib.Path("firmware/memory.x")
READELF = "arm-none-eabi-readelf"
NM = "arm-none-eabi-nm"

HAND_FIELDS = {"profile", "elf", "allocator", "writable_executable", "vector_section", "note"}

#: `NAME : ORIGIN = 0x…, LENGTH = 123K` out of the linker script. The units the
#: script actually uses; a new one is a finding rather than a silent zero.
REGION = re.compile(
    r"^\s*(\w+)\s*:\s*ORIGIN\s*=\s*(0x[0-9a-fA-F]+)\s*,\s*LENGTH\s*=\s*(\d+)([KM]?)\s*$",
    re.M,
)
UNITS = {"": 1, "K": 1024, "M": 1024 * 1024}

#: `readelf -lW` rows. PhysAddr is the load address, VirtAddr where it runs —
#: they differ for `.data`, which is the whole reason both are read.
PHDR = re.compile(
    r"^\s+(\S+)\s+0x[0-9a-f]+\s+(0x[0-9a-f]+)\s+(0x[0-9a-f]+)\s+"
    r"(0x[0-9a-f]+)\s+(0x[0-9a-f]+)\s+([RWE ]{3})\s",
    re.M,
)
MAPPING = re.compile(r"^\s+(\d+)\s+(.*)$", re.M)
ENTRY = re.compile(r"^Entry point (0x[0-9a-f]+)$", re.M)

#: A symbol that allocates. Matched on the DEMANGLED-ish tail, because the v0
#: scheme wraps `__rust_alloc` in `_RNvCs…7___rustc12___rust_alloc`.
ALLOCATOR = re.compile(
    r"(__rust_alloc(_zeroed|_error_handler)?|__rust_dealloc|__rust_realloc"
    r"|\bmalloc\b|\bcalloc\b|\brealloc\b|\bfree\b)"
)


def registry(root: pathlib.Path, findings: list[str]) -> dict:
    doc = tomllib.loads((root / REGISTRY).read_text(encoding="utf-8"))
    for key in sorted(set(doc) - {"image"}):
        findings.append(f"{REGISTRY}: top-level `{key}` — the file holds `[image]`")
    image = doc.get("image", {})
    for key in sorted(set(image) - HAND_FIELDS):
        findings.append(f"{REGISTRY}: `{key}` is not a field this registry reads")
    for key in sorted(HAND_FIELDS - set(image)):
        findings.append(f"{REGISTRY}: no `{key}`")
    return image


def regions(root: pathlib.Path, text: str | None = None) -> dict[str, tuple[int, int]]:
    """`memory.x`'s MEMORY block as {name: (origin, end)}.

    `text` is the script, so a case can hand in a moved region instead of
    editing the file the firmware builds from.
    """
    text = (root / LINKER).read_text(encoding="utf-8") if text is None else text
    out = {}
    for name, origin, length, unit in REGION.findall(text):
        start = int(origin, 16)
        out[name] = (start, start + int(length) * UNITS[unit])
    return out


def segments(root: pathlib.Path, elf: pathlib.Path):
    """(type, virt, phys, filesz, memsz, flags, sections) per program header."""
    out = subprocess.run(
        [READELF, "-lW", str(root / elf)], capture_output=True, text=True, check=True
    ).stdout
    rows = [
        (
            kind,
            int(virt, 16),
            int(phys, 16),
            int(filesz, 16),
            int(memsz, 16),
            flags.replace(" ", ""),
        )
        for kind, virt, phys, filesz, memsz, flags in PHDR.findall(out)
    ]
    names: dict[int, str] = {}
    tail = out.split("Section to Segment mapping:", 1)
    if len(tail) == 2:
        for index, listed in MAPPING.findall(tail[1]):
            names[int(index)] = listed.strip()
    entry = ENTRY.search(out)
    return rows, names, int(entry.group(1), 16) if entry else 0


def symbols(root: pathlib.Path, elf: pathlib.Path):
    """(defined allocator symbols, undefined symbols)."""
    defined = subprocess.run(
        [NM, "--defined-only", str(root / elf)], capture_output=True, text=True, check=True
    ).stdout
    undefined = subprocess.run(
        [NM, "-u", str(root / elf)], capture_output=True, text=True, check=True
    ).stdout
    found = set()
    for line in defined.splitlines():
        hit = ALLOCATOR.search(line)
        if hit:
            found.add(hit.group(1))
    return found, [line.strip() for line in undefined.splitlines() if line.strip()]


def audit(root: pathlib.Path, image=None, linker=None):
    findings: list[str] = []
    image = registry(root, findings) if image is None else image
    if findings:
        return findings, ""
    elf = pathlib.Path(image["elf"])
    if not (root / elf).is_file():
        return [f"{elf} — build it first: cargo build --release -p firmware"], ""

    try:
        where = regions(root, linker)
        rows, names, entry = segments(root, elf)
        allocator, undefined = symbols(root, elf)
    except (OSError, subprocess.CalledProcessError, ValueError) as error:
        return [f"{elf}: {error}"], ""

    if not where:
        findings.append(f"{LINKER}: no MEMORY region parsed — the syntax moved")
    loads = [r for r in rows if r[0] == "LOAD"]
    if len(loads) < 2:
        findings.append(f"{elf}: {len(loads)} LOAD segment(s) — the parser found nothing")

    # Every byte the image occupies has to be inside a region the linker script
    # declares, at BOTH addresses: `.data` runs in RAM and is stored in flash.
    for kind, virt, phys, _filesz, memsz, flags in loads:
        for label, start in (("run", virt), ("load", phys)):
            end = start + memsz
            if not any(lo <= start and end <= hi for lo, hi in where.values()):
                findings.append(
                    f"{elf}: a LOAD segment's {label} address"
                    f" {start:#x}..{end:#x} ({flags}) is outside every"
                    f" {LINKER} region"
                )
        # And never in the KV store: the partition table fences it from BOOTSEL,
        # nothing fenced it from the linker.
        for name, (lo, hi) in where.items():
            if not name.startswith("KV"):
                continue
            if phys < hi and lo < phys + memsz:
                findings.append(
                    f"{elf}: a LOAD segment lands at {phys:#x}..{phys + memsz:#x},"
                    f" inside {name} ({lo:#x}..{hi:#x}) — the image would be"
                    " erased by its own store"
                )

    # W+X: exactly the registered one, by the sections it carries.
    wx = [
        names.get(index, "?")
        for index, row in enumerate(rows)
        if row[0] == "LOAD" and "W" in row[5] and "E" in row[5]
    ]
    want = list(image["writable_executable"])
    if sorted(wx) != sorted(want):
        findings.append(
            f"{elf}: writable AND executable segments carry {sorted(wx)},"
            f" registered {sorted(want)} — a new one is a page an attacker who"
            " can write RAM can also run"
        )

    # The vector table is what the bootrom jumps through, and it has to be at the
    # start of FLASH or the image does not boot at all.
    flash = where.get("FLASH")
    table = [
        row for index, row in enumerate(rows)
        if row[0] == "LOAD" and image["vector_section"] in names.get(index, "")
    ]
    if not table:
        findings.append(f"{elf}: no LOAD segment carries {image['vector_section']}")
    elif flash and table[0][2] != flash[0]:
        findings.append(
            f"{elf}: {image['vector_section']} loads at {table[0][2]:#x}, not at"
            f" {LINKER}'s FLASH origin {flash[0]:#x}"
        )

    if flash and not (flash[0] <= entry < flash[1]):
        findings.append(f"{elf}: entry point {entry:#x} is outside FLASH")

    if sorted(allocator) != sorted(image["allocator"]):
        findings.append(
            f"{elf}: the allocator surface is {sorted(allocator)}, registered"
            f" {sorted(image['allocator'])} — a second allocator, or a `malloc`"
            " arriving through a dependency, changes what the heap is"
        )
    if undefined:
        findings.append(
            f"{elf}: {len(undefined)} undefined symbol(s) in a fully linked"
            f" image, first {undefined[0]!r}"
        )

    summary = (
        f"elf-gate: ok — {len(loads)} LOAD segment(s) inside {len(where)}"
        f" {LINKER} region(s), {len(wx)} writable-executable as registered,"
        f" {len(allocator)} allocator symbol(s), 0 undefined"
    )
    return findings, summary


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv:
        print("usage: elf_gate.py", file=sys.stderr)
        return 2
    findings, summary = audit(ROOT)
    if findings:
        print("elf-gate:", file=sys.stderr)
        for finding in findings:
            print(f"  {finding}", file=sys.stderr)
        return 1
    print(summary)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
