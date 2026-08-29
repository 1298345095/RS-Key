#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors
"""Constant-time sites, read out of the shipped ELF instead of asserted in prose.

`docs/ct-audit.md` says the canonical comparator's inlined copies "lower to a
loop whose only branch is governed by the *public* length counter", and that
every PIN/MAC/verifier surface routes through it. Both sentences were true when
someone disassembled the image by hand once. Nothing re-read the image
afterwards, and the page's own "42 candidate sites were examined" names a table
that has never existed in any revision of the file — the only table there has
three rows, the three fixed findings.

This gate makes the two sentences machine-checked against the ELF `check.sh`
just built:

* **No branch anywhere depends on a byte a registered site loaded.** For every
  conditional branch in `.text`, the flag-setting instruction it reads is found,
  and each register that instruction reads is traced back to its last
  definition. A definition that is a LOAD FROM A BUFFER — a `ldr*` whose base is
  not `sp` — whose own inline chain names a registered site makes the branch
  secret-dependent, and one such branch fails the row.

  The taint hangs on the LOAD and not on the branch, and that is the whole
  difference between this rule and the one that shipped first here. Restricted to
  branches inside the site's own address runs, the rule MISSED the early-exit
  mutant it exists to catch: with the early exit compiled in, the secret `cmp r2,
  r1` is the last instruction the site's chain covers and the back edge that
  consumes its flags carries the enclosing applet's frame instead. Measured, that
  arm came back 0 violations, EXIT=0 — a check that could not fail, over the
  defect it was written for.
* **The caller set is derived, not listed.** The first-party functions that
  inline a site are read out of the same chains and held against
  `assurance/ct_sites.toml` BOTH WAYS: a surface that stops routing through the
  comparator disappears from the ELF and reddens, and a new one that appears
  owes the registry a line saying which protocol operation it is.

Two things it deliberately does NOT do. It does not print instruction counts or
addresses into the page: both move on any unrelated code change, and a generated
page whose diff is noise trains its reader to run `--write` without looking. And
it is not a timing measurement — `docs/ct-audit.md`'s own "Coverage & limits"
says what a source/disassembly audit cannot prove, and this changes none of it.

Why a RELOAD is not a buffer read, measured rather than assumed: the `black_box`
barrier the comparator ends with spills the accumulator and reads it straight
back (`strb.w r0, [r7, #-29]` / `ldrb.w r0, [r7, #-29]`), and the `cbz r0` on
that reload is the terminal reduction to a `bool` — inherent, since the function
returns one, and positionless. A whitelist of `sp` was the first version and it
missed this: eight of the comparator's copies spill through the frame register
`r7` instead, and the baseline reported all eight. The rule is therefore not
"which register" but "did this frame already write that address" — a load with a
matching earlier store is a reload, and a reload of a value is not a read of a
buffer.

The limit that leaves, stated rather than discovered later: a path that COPIES
secret bytes into a stack slot and then compares them there reads its own store
and is not flagged. Nothing in the audited sites does that — the comparator
indexes both operands in place — but the rule cannot see it if one starts.

The mutant this row exists to catch is an early exit inside the accumulate loop
(`if diff != 0 { return false; }`): the accumulator and the barrier vanish and
the loop becomes a `memcmp`, with the two secret bytes reaching a `cmp` that
governs a branch. Driven through the row's own command after a rebuild: the
shipped tree reports 0 secret-dependent branches over 39 attributed runs and 26
conditional branches, EXIT=0; with the early exit compiled in, 27 over 60 runs,
EXIT=1.
The mutant that does NOT work, and is recorded so nobody re-tries it: deleting
the `black_box` — the page itself says the barrier "does not change the code
generated today", so that arm stays green and is a check that cannot fail.
"""

from __future__ import annotations

import pathlib
import re
import subprocess
import sys
import tomllib

ROOT = pathlib.Path(__file__).resolve().parent.parent

REGISTRY = pathlib.Path("assurance/ct_sites.toml")
PAGE = pathlib.Path("docs/ct-audit.md")
ELF = pathlib.Path("target/thumbv8m.main-none-eabihf/release/firmware")
OBJDUMP = "arm-none-eabi-objdump"

#: The region this script owns inside an otherwise hand-written page. NOT an
#: `ARTIFACT`/`GENERATED_BY` pair: `claims_gate.generated_pages` reads that pair
#: to exempt a page WHOLE, and `docs/ct-audit.md` is prose that must stay under
#: the claims rule. A region is masked; a page is excused.
REGION = "ct-sites"
REGION_HEADER = "<!-- Generated by scripts/ct_gate.py --write; do not edit. -->"

#: Hand-written keys. Everything else about a site — where it is inlined, how
#: many copies, which branches it contains — is read from the image.
HAND_FIELDS = {"id", "symbol", "class", "statement"}
CALLER_FIELDS = {"symbol", "surface"}
CLASSES = {"comparator"}
SITE_ID = re.compile(r"^CT-[A-Z]+-\d{3}$")

#: A first-party frame, by CRATE and not by path: the paths objdump prints are
#: this machine's absolute build paths, and a rule keyed on them would answer
#: differently on the runner.
FIRST_PARTY = re.compile(r"^(rsk_[a-z0-9_]+|firmware)::")

INSN = re.compile(r"^\s*([0-9a-f]+):\t[0-9a-f ]+\t(\S+)\s*(.*)$")
FUNC_HEAD = re.compile(r"^(\S+)\(\):$")
INLINED_BY = re.compile(r"^inlined by (\S+):(\d+) \((\S+)\)$")
SOURCE_LINE = re.compile(r"^(/\S+):(\d+)(?: \(discriminator \d+\))?$")

#: Legacy Rust mangling: `_ZN` then length-prefixed components then `E`, with a
#: final `17h<16 hex>` disambiguator this drops.
LEGACY = re.compile(r"^_ZN(.+)E$")
COMPONENT = re.compile(r"(\d+)")
HASH_COMPONENT = re.compile(r"^h[0-9a-f]{16}$")

#: Every mnemonic is read with its width suffix REMOVED, and that is not a
#: nicety: the sets below first shipped matching `cmp` exactly, and the loop in
#: `spend_and_verify_pin_hash` spells its public bound `cmp.w fp, #32`. The
#: walk-back skipped it, landed on the `eors` that accumulates two secret bytes,
#: and reported the shipped comparator as secret-dependent. One spelling, and the
#: rule answered the opposite of the truth.
WIDTH = re.compile(r"\.[nw]$")

#: Conditional branches. `b` alone is unconditional and `bl`/`blx`/`bx` are
#: calls; the condition codes are spelled out rather than matched loosely,
#: because `bic` and `bfi` start with `b` too.
CONDS = (
    "eq", "ne", "cs", "hs", "cc", "lo", "mi", "pl",
    "vs", "vc", "hi", "ls", "ge", "lt", "gt", "le",
)
COND_BRANCH = re.compile(r"^b(" + "|".join(CONDS) + r")$")
CBZ = re.compile(r"^cbn?z$")

#: Everything that writes the flags. The `s`-suffixed forms are enumerated
#: rather than matched by a trailing `s`, because `movs` and `subs` share that
#: letter with `mrs`, `bics` and `ldrsb` — one of which is a load.
FLAG_ONLY = {"cmp", "cmn", "tst", "teq"}
FLAG_SETTING = FLAG_ONLY | {
    "adds", "adcs", "subs", "sbcs", "rsbs", "ands", "orrs", "orns", "eors",
    "bics", "movs", "mvns", "lsls", "lsrs", "asrs", "rors", "rrxs", "muls",
}
LOAD = re.compile(r"^ldr(b|h|sb|sh|d)?$")
REGISTER = re.compile(r"\b(r\d+|sl|fp|ip|sp|lr|pc)\b")

#: The address base a load reads from, if the operand list has one.
BASE = re.compile(r"\[(r\d+|sl|fp|ip|sp|pc)")

#: Predication. `IT` makes the next instructions conditional, and the shipped
#: comparator uses it: `crates/rsk-crypto/src/mac.rs:55`'s public length-equality early return lowers
#: to `cmp r0,#1 / it eq / cmpeq fp,r1 / beq`. A blanket refusal of any run
#: containing an `IT` was the first rule here and it reported that as a finding —
#: the DOCUMENTED public early return, called secret-dependent. The rule instead
#: reads a predicated flag-setter as a flag-setter and keeps walking past it,
#: because when its condition is false the PREVIOUS flags still govern the
#: branch; both candidates are then asked the same buffer-load question.
CONDITION = re.compile(r"^(.*?)(" + "|".join(CONDS) + r")$")

#: The address part of a load or store, matched verbatim so a reload is
#: recognised by ADDRESS rather than by which register happens to hold the frame.
ADDRESS = re.compile(r"(\[[^\]]*\])")

STORE = re.compile(r"^str(b|h|d)?$")

#: Floors, and they are PARAMETERS of `audit` rather than globals a case patches
#: down — `run_count_gate.SCAN_FLOOR` shipped the other way and its own docstring
#: says the shipped value was therefore never checked against the shipped tree.
#: Measured on this tree: 39 attributed runs, 26 conditional branches examined.
RUN_FLOOR = 30
BRANCH_FLOOR = 20


def demangle(symbol: str) -> str:
    """`_ZN10rsk_crypto3mac5ct_eq17h3eb6…E` -> `rsk_crypto::mac::ct_eq`.

    The v0 scheme (`_R…`) and plain C names are returned unchanged: nothing this
    gate registers is mangled that way, and a wrong guess would silently widen
    attribution rather than narrow it.
    """
    body = LEGACY.match(symbol)
    if not body:
        return symbol
    rest, parts = body.group(1), []
    while rest:
        size = COMPONENT.match(rest)
        if not size:
            break
        start = size.end()
        width = int(size.group(1))
        parts.append(rest[start : start + width])
        rest = rest[start + width :]
    if parts and HASH_COMPONENT.match(parts[-1]):
        parts.pop()
    return unescape("::".join(parts)) if parts else symbol


#: The escapes legacy mangling puts in a generic component. Only the ones this
#: tree actually produces, because an unescape nobody drove is a second parser.
ESCAPES = (("$LT$", "<"), ("$GT$", ">"), ("$C$", ","), ("$u20$", " "),
           ("$RF$", "&"), ("$u7b$", "{"), ("$u7d$", "}"), ("..", "::"))


def unescape(name: str) -> str:
    for spelling, char in ESCAPES:
        name = name.replace(spelling, char)
    return name


def registry(root: pathlib.Path, findings: list[str]):
    """The hand-written half: sites and the surface each caller stands for."""
    doc = tomllib.loads((root / REGISTRY).read_text(encoding="utf-8"))
    for key in sorted(set(doc) - {"site", "caller"}):
        findings.append(
            f"{REGISTRY}: top-level `{key}` — the file holds `[[site]]` and"
            " `[[caller]]` tables and nothing else"
        )
    sites, callers = {}, {}
    for entry in doc.get("site", []):
        name = str(entry.get("id", "")).strip()
        if not SITE_ID.match(name):
            findings.append(f"{REGISTRY}: `{name}` is not a `CT-<AREA>-<NNN>` id")
            continue
        for key in sorted(set(entry) - HAND_FIELDS):
            findings.append(f"{name}: `{key}` is not a field this registry reads")
        for key in sorted(HAND_FIELDS - set(entry)):
            findings.append(f"{name}: no `{key}`")
        if entry.get("class") not in CLASSES:
            findings.append(
                f"{name}: class {entry.get('class')!r} is outside"
                f" {sorted(CLASSES)} — a class the rule cannot decide is a label"
            )
        sites[name] = entry
    for entry in doc.get("caller", []):
        for key in sorted(set(entry) - CALLER_FIELDS):
            findings.append(f"{REGISTRY}: caller `{key}` is not a field it reads")
        symbol = str(entry.get("symbol", "")).strip()
        surface = str(entry.get("surface", "")).strip()
        if not symbol or not surface:
            findings.append(f"{REGISTRY}: a caller needs both `symbol` and `surface`")
            continue
        if symbol in callers:
            findings.append(f"{REGISTRY}: `{symbol}` is registered twice")
        callers[symbol] = surface
    return sites, callers


def disassembly(root: pathlib.Path) -> list[str]:
    elf = root / ELF
    if not elf.is_file():
        raise FileNotFoundError(
            f"{ELF} — build it first: cargo build --release -p firmware"
        )
    out = subprocess.run(
        [OBJDUMP, "-d", "-l", "--inlines", "--section=.text", str(elf)],
        capture_output=True,
        text=True,
        check=True,
    )
    return out.stdout.splitlines()


def instructions(lines):
    """(addr, mnemonic, operands, chain) per instruction, innermost frame first.

    objdump reprints a location line only when it CHANGES, so an instruction with
    no location lines of its own inherits the previous one. Rebuilding the chain
    from scratch per instruction would attribute those to nothing — which is the
    silent-undercount direction, so it is done the other way.
    """
    chain, inner, outer, func = [], None, [], None
    fresh = False
    for line in lines:
        head = FUNC_HEAD.match(line)
        if head:
            func, inner, outer, fresh = demangle(head.group(1)), None, [], True
            continue
        under = INLINED_BY.match(line)
        if under:
            outer.append(demangle(under.group(3)))
            fresh = True
            continue
        source = SOURCE_LINE.match(line)
        if source:
            inner, fresh = func, True
            continue
        code = INSN.match(line)
        if not code:
            continue
        if fresh:
            chain = ([inner] if inner else []) + outer
            inner, outer, fresh = None, [], False
        yield int(code.group(1), 16), WIDTH.sub("", code.group(2)), code.group(3), chain


def runs(stream, symbol):
    """Maximal contiguous instruction runs the inline chain attributes to `symbol`."""
    out, current = [], []
    for step in stream:
        if symbol in step[3]:
            current.append(step)
        elif current:
            out.append(current)
            current = []
    if current:
        out.append(current)
    return out


#: Where a backward walk stops. A call clobbers the caller-saved registers, an
#: unconditional transfer means the fall-through is not how we got here, and a
#: change of enclosing function means we left the frame entirely.
BARRIER = re.compile(r"^(bl|blx|bx|b|pop|cbz|cbnz)$")


def walk_back(stream, index, want, limit=64):
    """Steps before `index`, nearest first, until a barrier or `limit`."""
    frame = stream[index][3][-1] if stream[index][3] else None
    for step in range(index - 1, max(-1, index - limit - 1), -1):
        addr, mnemonic, operands, chain = stream[step]
        if (chain[-1] if chain else None) != frame:
            return
        yield stream[step]
        if BARRIER.match(mnemonic) and step != index - 1:
            return
        if want is not None and mnemonic == want:
            return


def last_definition(stream, index, register):
    """The nearest instruction before `index` that wrote `register`."""
    for addr, mnemonic, operands, chain in walk_back(stream, index, None):
        if mnemonic in FLAG_ONLY or BARRIER.match(mnemonic):
            continue
        written = REGISTER.search(operands.split(",")[0]) if operands else None
        if written and written.group(1) == register:
            return addr, mnemonic, operands, chain
    return None


def flag_setter(mnemonic):
    """(base mnemonic, predicated) if `mnemonic` writes the flags, else None."""
    if mnemonic in FLAG_SETTING:
        return mnemonic, False
    suffix = CONDITION.match(mnemonic)
    if suffix and suffix.group(1) in FLAG_SETTING:
        return suffix.group(1), True
    return None


def reload_of_a_store(stream, load):
    """Whether `load` reads back an address this frame already wrote."""
    address = ADDRESS.search(load[2])
    if not address:
        return False
    frame = load[3][-1] if load[3] else None
    index = next(i for i, step in enumerate(stream) if step[0] == load[0])
    for step in range(index - 1, max(-1, index - 64), -1):
        addr, mnemonic, operands, chain = stream[step]
        if (chain[-1] if chain else None) != frame:
            return False
        if STORE.match(mnemonic) and ADDRESS.search(operands or "") == None:
            continue
        if STORE.match(mnemonic):
            written = ADDRESS.search(operands)
            if written and written.group(1) == address.group(1):
                return True
    return False


def governing(stream, index):
    """Every flag-setter that can govern the branch at `index`.

    More than one when predication is in play: a predicated `cmpeq` writes the
    flags only if its own condition held, so the branch may still be reading what
    the flag-setter before it left. Walking back to the first UNPREDICATED one
    and asking all of them is the conservative direction.
    """
    out = []
    for step in walk_back(stream, index, None):
        found = flag_setter(step[1])
        if not found:
            continue
        out.append(step)
        if not found[1]:
            break
    return out


def secret_branches(stream, symbols):
    """Conditional branches whose flags trace to a byte a registered site loaded."""
    out = []
    for index, (addr, mnemonic, operands, _) in enumerate(stream):
        if CBZ.match(mnemonic):
            candidates = [(mnemonic, operands.split(",")[0].strip())]
        elif COND_BRANCH.match(mnemonic):
            candidates = [
                (f"{flags[1]} {flags[2]}", register)
                for flags in governing(stream, index)
                for register in REGISTER.findall(flags[2])
            ]
        else:
            continue
        for source, register in candidates:
            found = REGISTER.search(register)
            name = found.group(1) if found else None
            defined = last_definition(stream, index, name) if name else None
            if not defined or not LOAD.match(defined[1]):
                continue
            base = BASE.search(defined[2])
            if base and base.group(1) == "pc":
                continue  # a literal pool holds constants, never a buffer
            if reload_of_a_store(stream, defined):
                continue
            site = next((s for s in symbols if s in defined[3]), None)
            if site is None:
                continue
            out.append((site, addr, mnemonic, source, f"{defined[1]} {defined[2]}"))
            break
    return out


def observe(root: pathlib.Path, sites, lines=None):
    """{site id: (violations, run count, branch count, first-party callers)}.

    `lines` is the disassembly, so a case can hand in a recorded one instead of
    paying for a firmware build — the parser and the rule are what a case is
    about, and the live image is what the gate row is about.
    """
    lines = disassembly(root) if lines is None else lines
    stream = list(instructions(lines))
    by_site = {entry["symbol"]: name for name, entry in sites.items()}
    tainted = secret_branches(stream, set(by_site))
    out = {}
    for name, entry in sorted(sites.items()):
        found = runs(stream, entry["symbol"])
        branches, callers = 0, set()
        for run in found:
            branches += sum(
                1 for _, mnemonic, _, _ in run
                if CBZ.match(mnemonic) or COND_BRANCH.match(mnemonic)
            )
            # The OUTERMOST first-party frame, not every one: the chain also
            # names the per-crate forwarders and the `core` adapters the loop is
            # built from, and a roster of those describes the compiler rather
            # than the protocol.
            outer = [f for f in run[0][3] if f != entry["symbol"] and FIRST_PARTY.match(f)]
            if outer:
                callers.add(outer[-1])
        violations = [v[1:] for v in tainted if by_site[v[0]] == name]
        out[name] = (violations, len(found), branches, callers)
    return out


def toolchain() -> str:
    version = subprocess.run(
        ["rustc", "-vV"], capture_output=True, text=True, check=True
    ).stdout
    release = re.search(r"^release: (\S+)$", version, re.M)
    commit = re.search(r"^commit-hash: (\S+)$", version, re.M)
    return f"rustc {release.group(1) if release else '?'} ({commit.group(1)[:9] if commit else '?'})"


def body(sites, callers, seen) -> list[str]:
    """The region, and it prints NO count and NO address on purpose."""
    out = [
        f"<!-- {REGION}:start -->",
        REGION_HEADER,
        "",
        f"Read out of `{ELF}` with `{OBJDUMP} -d -l --inlines`, built by"
        f" {toolchain()}. A site's verdict is `constant-time` when no conditional"
        " branch inside any address run the inline chain attributes to it reads"
        " flags set from a buffer load; the callers are the first-party frames"
        " those chains name, so a surface that stops routing through the site"
        " leaves this table.",
        "",
        "| Site | Class | Verdict | Surfaces that inline it |",
        "|---|---|---|---|",
    ]
    for name, entry in sorted(sites.items()):
        violations, _, _, found = seen[name]
        verdict = "SECRET-DEPENDENT" if violations else "constant-time"
        surfaces = ", ".join(
            f"{callers.get(symbol, symbol)}" for symbol in sorted(found)
        )
        out.append(
            f"| `{entry['symbol']}` | {entry['class']} | {verdict} |"
            f" {surfaces or '—'} |"
        )
    out += ["", f"<!-- {REGION}:end -->"]
    return out


def render(root: pathlib.Path, sites, callers, seen) -> str:
    text = (root / PAGE).read_text(encoding="utf-8")
    start, end = f"<!-- {REGION}:start -->", f"<!-- {REGION}:end -->"
    head = text.find(start)
    tail = text.find(end)
    if head == -1 or tail == -1 or tail < head:
        raise ValueError(f"{PAGE} needs exactly one {REGION!r} marker pair")
    return text[:head] + "\n".join(body(sites, callers, seen)) + text[tail + len(end) :]


def audit(root: pathlib.Path, run_floor=RUN_FLOOR, branch_floor=BRANCH_FLOOR, lines=None):
    findings: list[str] = []
    sites, callers = registry(root, findings)
    if findings:
        return findings, ""
    try:
        seen = observe(root, sites, lines)
    except (OSError, subprocess.CalledProcessError) as error:
        return [f"{ELF}: {error}"], ""

    total_runs = total_branches = 0
    for name, (violations, found, branches, inlined) in sorted(seen.items()):
        total_runs += found
        total_branches += branches
        symbol = sites[name]["symbol"]
        if not found:
            findings.append(
                f"{name}: `{symbol}` is in no inline chain of the image — either"
                " it is gone or the DWARF is, and both make this row vacuous"
            )
        for addr, mnemonic, source, load in violations:
            findings.append(
                f"{name}: {addr:#x} `{mnemonic}` branches on flags from"
                f" `{source}`, whose operand was loaded by `{load}` — a"
                " secret-dependent branch inside a constant-time site"
            )
        for symbol in sorted(inlined - set(callers)):
            findings.append(
                f"{name}: `{symbol}` inlines it and no `[[caller]]` says which"
                " protocol surface that is"
            )
    for symbol in sorted(set(callers) - {s for _, _, _, c in seen.values() for s in c}):
        findings.append(
            f"{REGISTRY}: `{symbol}` is registered as a caller and inlines no"
            " site in the image — the surface stopped routing through it, or the"
            " entry is stale"
        )

    # Both floors answer the same question the other rules cannot: a parser that
    # silently stopped matching reports zero of everything and zero violations.
    if total_runs < run_floor:
        findings.append(
            f"{total_runs} attributed run(s), under the measured {run_floor} —"
            " the objdump format moved under the parser"
        )
    if total_branches < branch_floor:
        findings.append(
            f"{total_branches} conditional branch(es) examined, under the"
            f" measured {branch_floor} — a rule that reads no branch cannot fail"
        )

    try:
        want = render(root, sites, callers, seen)
    except (OSError, ValueError) as error:
        findings.append(f"{PAGE} cannot be generated: {error}")
    else:
        if (root / PAGE).read_text(encoding="utf-8") != want:
            findings.append(
                f"{PAGE}'s `{REGION}` region is not what the generator writes —"
                " run `python scripts/ct_gate.py --write` and commit the result"
            )

    summary = (
        f"ct-gate: ok — {len(sites)} constant-time site(s) over {total_runs}"
        f" attributed run(s), {total_branches} conditional branch(es) examined,"
        f" 0 secret-dependent, {len(callers)} surface(s) registered"
    )
    return findings, summary


def run(root: pathlib.Path, write=False) -> int:
    if write:
        findings: list[str] = []
        sites, callers = registry(root, findings)
        if findings:
            for finding in findings:
                print(f"  {finding}", file=sys.stderr)
            return 1
        seen = observe(root, sites)
        (root / PAGE).write_text(render(root, sites, callers, seen), encoding="utf-8")
        print(f"ct-gate: wrote the {REGION} region of {PAGE}")
        return 0
    findings, summary = audit(root)
    if findings:
        print("ct-gate:", file=sys.stderr)
        for finding in findings:
            print(f"  {finding}", file=sys.stderr)
        return 1
    print(summary)
    return 0


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv and argv != ["--write"]:
        print("usage: ct_gate.py [--write]", file=sys.stderr)
        return 2
    return run(ROOT, write=bool(argv))


if __name__ == "__main__":
    raise SystemExit(main())
