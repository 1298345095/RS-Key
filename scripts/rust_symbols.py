# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""Rust source names for attribution, with linkage identity kept separately."""

from __future__ import annotations

import re
import subprocess

DEMANGLE = "arm-none-eabi-c++filt"
CRATE_HASH = re.compile(r"(?<=[A-Za-z0-9_])\[[0-9a-f]{1,16}\](?=::)")
LEGACY_HASH = re.compile(r"::h[0-9a-f]{16}$")


def angle_end(name: str, start: int) -> int:
    """Match a demangled generic/qualified segment, not the v0 encoding."""
    depth = 0
    for index in range(start, len(name)):
        if name[index] == "<":
            depth += 1
        elif name[index] == ">" and (index == 0 or name[index - 1] != "-"):
            depth -= 1
            if depth == 0:
                return index
    raise ValueError(f"unbalanced demangled Rust name: {name}")


def source_name(name: str) -> str:
    """Erase instantiations; retain the self type, trait and closure number."""
    out, index = "", 0
    while index < len(name):
        if name[index] != "<":
            out += name[index]
            index += 1
            continue
        end = angle_end(name, index)
        inner = name[index + 1:end]
        if index == 0:
            # An inherent qualification is <Type>::method; a trait qualification
            # must keep its as Trait, even when both declare the same method.
            normalized = source_name(inner)
            out += f"<{normalized}>" if " as " in normalized else normalized
        else:
            if out.endswith("::"):
                out = out[:-2]
        index = end + 1
    return out


class Symbol(str):
    """String equality is source attribution; linkage is machine identity."""

    def __new__(cls, linkage: str, spelling: str):
        value = super().__new__(cls, source_name(spelling))
        value.linkage = linkage
        value.spelling = spelling
        return value


def demangle_many(symbols) -> dict[str, Symbol]:
    """One standard demangler process per batch; an undecoded Rust name is fatal."""
    names = sorted(set(symbols))
    rust = [name for name in names if name.startswith(("_R", "_ZN"))]
    decoded = {}
    if rust:
        done = subprocess.run(
            [DEMANGLE, "-s", "rust"],
            input="\n".join(rust) + "\n",
            capture_output=True,
            text=True,
            check=True,
        )
        output = done.stdout.splitlines()
        if len(output) != len(rust):
            raise ValueError("Rust demangler returned the wrong number of names")
        for raw, path in zip(rust, output):
            if not path or path == raw or path.startswith(("_R", "_ZN")):
                raise ValueError(f"Rust demangler could not decode {raw}")
            decoded[raw] = LEGACY_HASH.sub("", CRATE_HASH.sub("", path))
    return {name: Symbol(name, decoded.get(name, name)) for name in names}


def demangle(symbol: str) -> Symbol:
    return demangle_many([symbol])[symbol]


def frame_identity(chain):
    """Never join neighbouring monomorphizations through their source name."""
    if not chain:
        return None
    return getattr(chain[-1], "linkage", chain[-1])
