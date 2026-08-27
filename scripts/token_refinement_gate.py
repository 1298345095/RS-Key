#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Tree-wide completeness gate for the phase-5 concrete event boundary.

Every vocabulary this gate matches on is read out of the tree, because the four
holes the 2026-08-26 rescan found were all one class: a set spelled once in the
source and a second time in a regex here. The Fs write API was four names of
eleven, the permission set four of seven, the fid-parameter helpers two names in
an `if`, and the production/test split knew `*_tests.rs` but not
`#[cfg(test)] mod`. Each miss is silent — the site is simply never discovered, so
the roster stays "complete" over a shorter list.

Two shapes are still not discovered, and both were measured rather than assumed:
a fid bound to a local before the write (`let fid = EF_PIN; fs.put(fid, ..)`) and
a permission mask behind a helper taking `permissions: u8`. The coarse rules that
would catch them — "names a token fid and calls any writer", "hands
`paut.permissions` to anything" — cost 5 and 1 false owners on today's tree, so
what is here refuses to guess and this paragraph is the record.
"""

from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path

import bcd_gate

ROOT = Path(__file__).resolve().parents[1]

FIDO = Path("crates/rsk-fido/src")
STATE = FIDO / "state.rs"
PROJECTION = FIDO / "state_assurance.rs"
CONSTS = FIDO / "consts.rs"
STORE = Path("crates/rsk-fs/src/fs.rs")
MANIFEST = Path("assurance/token_refinement.toml")
EXPORT = Path("formal/generated/token_relation.txt")
# matrix_gate's own generated artifact, diffed against its generator by the
# "build-configuration matrix" row. Reading the column names here reuses that
# derivation; re-deriving the axis is what item 0 exists to prevent.
MATRIX = Path("docs/assurance-matrix.md")

# Roadmap stage 4 п.4: every production writer is one of these three.
DISPOSITIONS = ("step", "stutter", "out-of-scope")
#: Three writer axes and three GUARD axes. The token half was ledgered and the
#: other three clauses of `NoAuthorizationBypass` — the walk's owning channel,
#: the retry budget's soft lock and the reset window — were owned nowhere at all,
#: which is what made "the ledger covers the property" a sentence about one
#: quarter of it. Their sites are guards rather than writers, so they get their
#: own axes rather than a column: a guard writes no token field, and every rule
#: on the writer axes reads one.
AXES = (
    "volatile_writer",
    "persistent_writer",
    "outcome_producer",
    "walk_owner",
    "softlock_owner",
    "reset_window_owner",
)
RESET = FIDO / "reset.rs"
#: The three units the guard axes reach. The soft lock is marshalled across a
#: warm reset by the BOARD — `FidoState::pin_lock` has ZERO callers inside
#: `rsk-fido`, measured — so a family scanned with `catalogue()` alone derives an
#: empty roster and every rule below passes over it.
UNITS = (
    (FIDO, "lib.rs"),
    (Path("crates/rsk-device/src"), "lib.rs"),
    (Path("firmware/src"), "main.rs"),
)
#: A roster cannot derive to nothing without someone saying so. Set under the
#: measured counts so ordinary movement does not trip them and a derivation that
#: stopped reading does.
FLOORS = {
    "volatile_writer": 6,
    "persistent_writer": 8,
    "outcome_producer": 5,
    "walk_owner": 3,
    "softlock_owner": 8,
    # 1, not 2, and the difference is a measured direction failure: at 2 —
    # the derived count — renaming `in_reset_window` reported "the derivation
    # stopped reading the tree" and SUPPRESSED the two accurate `stale owner`
    # lines. A floor set AT the measurement turns a deleted guard into a report
    # about the guard's reader.
    "reset_window_owner": 1,
}

FN = re.compile(
    r"^\s*(?:pub(?:\([^)]*\))?\s+)?"
    r"(?:default\s+|const\s+|async\s+|unsafe\s+|extern\s+\"[^\"]*\"\s+)*"
    r"fn\s+([a-zA-Z0-9_]+)"
)
# Comments and string literals are blanked before any match: `reset()` names
# EF_PIN in prose only, and a model constant commented `\* TRUE` has already cost
# this programme one green run over a dead assumption. Char literals go too —
# a lone `'{'` desynchronises the brace depth below, and every writer after it in
# the file is then swallowed into the previous function's body, silently.
NOT_CODE = re.compile(r"\"(?:[^\"\\]|\\.)*\"|'(?:[^'\\]|\\.)'|//[^\n]*|/\*.*?\*/", re.S)
ASSIGN = r"(?:[-+&|^*/%]|<<|>>)?=[^=]"
IN_PLACE = r"(?:copy_from_slice|clone_from_slice|fill|swap|iter_mut|as_mut|get_mut)"
# A receiver is any expression, not one identifier: `Fs::put(&mut ctx.fs, EF_PIN)`
# and `Fs::delete(c.fs, EF_PIN)` are the same write as `fs.put(EF_PIN, ..)`.
RECEIVER = r"(?:[^,;()]|\([^()]*\))*?,\s*"
PUBLIC = re.compile(r"\s*pub(?:\([^)]*\))?\s")
COLUMN_ROW = re.compile(r"^\|\s*\d+\s*\|\s*`([^`]+)`\s*\|")
WHOLE = re.compile(r"\*self\s*=[^=]")
MAC = r"(?:\.|::)verify_token\s*\("
# The persistent `pcmr` grant: an authorization that never touches `paut`, so
# neither the MAC clause nor the permission clause can see it. Still a hand-named
# pair, and still the one hand-list left in this file.
GRANT = ("credmgmt.rs", "authorized_by_ppuat", "load_ppuat")


def functions(text: str) -> list[tuple[str, str]]:
    """(name, code) per `fn`, bodies closed by brace depth.

    Depth rather than "up to the next `fn`": the old line-run form attributed a
    `const fn`'s body to whatever plain `fn` preceded it, and `state.rs` has five.
    """
    lines = NOT_CODE.sub(lambda m: " " * (m.group(0).count("\n")), text).splitlines()
    found, index = [], 0
    while index < len(lines):
        head = FN.match(lines[index])
        if head is None:
            index += 1
            continue
        depth, started, cursor, body = 0, False, index, []
        while cursor < len(lines):
            body.append(lines[cursor])
            depth += lines[cursor].count("{") - lines[cursor].count("}")
            started = started or "{" in lines[cursor]
            if started and depth <= 0:
                break
            cursor += 1
        found.append((head.group(1), "\n".join(body)))
        index = cursor + 1
    return found


def production_sources(root: Path) -> list[Path]:
    base = root / FIDO
    return sorted(
        path
        for path in base.rglob("*.rs")
        if not path.name.endswith(("_tests.rs", "_kani.rs"))
        and path.name not in {"generated_token_edges.rs", "state_assurance.rs"}
    )


def test_only_sources(root: Path) -> set[str]:
    """The scanned files no build but a test one compiles.

    Walked with `bcd_gate`'s module-graph reader rather than a second one, and it
    is the walk that matters: `conformance/` is nineteen files declared by one
    `#[cfg(test)] mod conformance;`, and a name pattern calls every one of them
    production.
    """
    known = {
        path.relative_to(root).as_posix(): path.read_text(encoding="utf-8")
        for unit, _ in UNITS
        for path in (root / unit).rglob("*.rs")
    }
    seen, gated = set(), set()
    queue = [
        (rel, False)
        for unit, entry in UNITS
        if (rel := (unit / entry).as_posix()) in known
    ]
    while queue:
        rel, is_gated = queue.pop()
        if (rel, is_gated) in seen:
            continue
        seen.add((rel, is_gated))
        if is_gated:
            gated.add(rel)
        for name, operand, own in bcd_gate.declarations(known[rel]):
            child = bcd_gate.resolve(rel, name, operand, known)
            if child:
                queue.append((child, is_gated or own))
    return gated - {rel for rel, is_gated in seen if not is_gated}


def token_fields(root: Path) -> list[str]:
    body = re.search(
        r"pub struct PinUvAuthToken \{(.*?)\n\}", (root / STATE).read_text(), re.S
    )
    return re.findall(r"pub (\w+): ", body.group(1))


def permissions(root: Path) -> list[str]:
    return re.findall(r"pub const (PERM_[A-Z0-9_]+)", (root / STATE).read_text())


def abstraction(root: Path) -> tuple[list[str], list[str]]:
    """(token fields, permissions) the α of `abstract_token` actually observes."""
    text = (root / PROJECTION).read_text()
    return (
        sorted(set(re.findall(r"self\.paut\.(\w+)", text))),
        sorted(set(re.findall(r"PERM_[A-Z0-9_]+", text))),
    )


def key_names(root: Path) -> set[str]:
    match = re.search(
        r"TOKEN_PERSISTENT_FIDS[^=]*=\s*\[(.*?)\];",
        (root / PROJECTION).read_text(encoding="utf-8"),
        re.S,
    )
    if not match:
        return set()
    return set(re.findall(r"EF_[A-Z0-9_]+", match.group(1)))


def key_spellings(root: Path, keys: set[str]) -> set[str]:
    """Each token record's name AND the literal it is defined as.

    `fs.delete(0x1080)` writes clientPIN's verifier as surely as
    `fs.delete(EF_PIN)` does, and the constant is what makes the number
    findable — reading it here is the difference between a rule and a habit.
    """
    consts = (root / CONSTS).read_text(encoding="utf-8")
    out = set(keys)
    for key in keys:
        found = re.search(rf"\b{key}\s*:[^=]*=\s*(?:\w+::new\()?\s*(0[xX][0-9A-Fa-f]+)", consts)
        if found:
            out.add(found.group(1))
    return out


def store_writers(root: Path) -> set[str]:
    """The `Fs` methods that reach `storage.write`/`remove`/`compact`.

    Derived to a fixed point over the private helpers, because the hand-written
    four missed `delete_key`, `force_delete_halves`, `factory_wipe`, `compact`
    and all three `meta_*` — seven ways to write a token record unseen.
    """
    text = (root / STORE).read_text()
    bodies = dict(functions(text))
    writers = {
        name
        for name, body in bodies.items()
        if re.search(r"self\.storage\.(?:write|remove|compact)\s*\(", body)
    }
    while True:
        grown = {
            name
            for name, body in bodies.items()
            if name not in writers
            and any(re.search(rf"self\.{callee}\s*\(", body) for callee in writers)
        }
        if not grown:
            # The public half through `FN`, not a second `pub fn` pattern: this
            # gate exists because a set was spelled twice, and `pub(crate) fn`
            # appears 149 times in this tree.
            public = {name for name, body in functions(text) if PUBLIC.match(body)}
            return writers & public
        writers |= grown


def catalogue(root: Path) -> dict[tuple[str, str], str]:
    found = {}
    for path in production_sources(root):
        rel = str(path.relative_to(root))
        for name, body in functions(path.read_text(encoding="utf-8")):
            found[(rel, name)] = body
    return found


def discovered_volatile(code: dict, fields: list[str], seen: list[str], owner: str) -> tuple[set, set]:
    """(every writer of a token field, the subset α observes)."""
    every = re.compile(
        rf"\.paut(?:\.(?:{'|'.join(fields)}))?\s*{ASSIGN}"
        rf"|\.paut\.(?:{'|'.join(fields)})\.{IN_PLACE}\s*\("
        # `&mut …paut` covers `mem::take`/`replace`/`swap` too: mutating a field
        # through them needs the borrow, so a second alternative was dead.
        rf"|&mut\s+[\w.]*\bpaut\b"
    )
    visible = re.compile(rf"\.paut\.(?:{'|'.join(seen)})\s*{ASSIGN}")
    # `FidoState::reset` is `*self = Self::new()`, which replaces the token
    # wholesale — every abstract bit at once, and not one `.paut.` in sight.
    whole = {site for site, body in code.items() if site[0] == owner and WHOLE.search(body)}
    writers = {site for site, body in code.items() if every.search(body)} | whole
    return writers, {site for site in writers if visible.search(code[site])} | whole


def discovered_outcomes(code: dict, perms: list[str], seen: list[str]) -> tuple[set, set]:
    """(every authorization producer, the subset α observes).

    Two independent queries, unioned: the token-MAC check every command gate
    calls, and a mask of `paut.permissions` against any `PERM_*`. They name the
    same six sites, which is the evidence that neither spelling is the only door
    — and a seventh that checked the MAC and forgot the mask would be a bypass
    the mask query alone could not see.
    """
    masks = rf"\.paut\.permissions\s*[&|^]\s*\(?\s*(?:{'|'.join(perms)})"
    every = re.compile(rf"{MAC}|{masks}|(?:{'|'.join(perms)})\s*[&|^]\s*[\w.]*\.paut\.permissions")
    visible = re.compile(rf"\.paut\.permissions\s*[&|^]\s*\(?\s*(?:{'|'.join(seen)})")
    grant = {
        site
        for site, body in code.items()
        if site[0].endswith(GRANT[0]) and site[1] == GRANT[1] and GRANT[2] in body
    }
    producers = {site for site, body in code.items() if every.search(body)} | grant
    return producers, {site for site in producers if visible.search(code[site])} | grant


def discovered_persistent(code: dict, writers: set[str], keys: set[str]) -> tuple[set, set]:
    """(every writer of a token record, the fid-parameter helpers among them).

    Three clauses, because a token record is written three ways: the fid is named
    here, the fid arrives as a parameter, or the fid is named here and handed to
    something whose parameter it becomes. The middle one covers `reset::sweep`,
    whose fid arrives as a *predicate* — `sweep(ctx, is_fido_gate_fid)`.
    """
    call = rf"(?:\.|::)(?:{'|'.join(sorted(writers, key=len, reverse=True))})\s*\("
    alternation = "|".join(sorted(keys, key=len, reverse=True))
    named = re.compile(rf"{call}\s*(?:{RECEIVER})?(?:[a-z_]+::)*(?:{alternation})\b")
    parameterised = re.compile(rf"{call}\s*(?:{RECEIVER})?[a-z_]\w*\s*[,).]")
    mentions = re.compile(rf"\b(?:{alternation})\b")

    generic = {site for site, body in code.items() if parameterised.search(body)}
    naming = {site[1] for site, body in code.items() if mentions.search(body)}

    def carries_a_key(arguments: str) -> bool:
        return bool(mentions.search(arguments)) or any(
            word in naming for word in re.findall(r"\b([a-z_]\w*)\b", arguments)
        )

    reached, handing = set(), set()
    for site in generic:
        calls = re.compile(rf"\b{site[1]}\s*\(([^;]*?)\)", re.S)
        for caller, body in code.items():
            if caller == site:
                continue
            for found in calls.finditer(body):
                if carries_a_key(found.group(1)):
                    reached.add(site)
                    handing.add(caller)
    direct = {site for site, body in code.items() if named.search(body)}
    return direct | reached | handing, reached


#: The channel test IS the walk guard: a `CredMgmtState` method that compares the
#: cursor's owner with the request's. Derived rather than named, so a third walk
#: arriving with the same shape arrives as an unowned site.
CHANNEL_TEST = re.compile(r"self\.channel\s*==\s*channel")
#: §6.6's window is the only predicate in `reset.rs` that reads both halves of the
#: power-up: the boot's own origin and the deadline.
WINDOW = ("warm_boot", "RESET_WINDOW_MS")
#: The soft lock's accessor, and the anchor both halves of its vocabulary come
#: out of: its RETURN TYPE is the wire form the board carries across a reset, and
#: its BODY names the two `FidoState` fields the lock is made of.
LOCK_ACCESSOR = "pin_lock"
#: Anchored to the `fn` line: searching the whole body picks a `->` inside a
#: nested closure as the wire type.
RETURNS = re.compile(r"^[^\n{]*->\s*(\w+)")


def walk_guards(root: Path) -> list[str]:
    """Every `state.rs` method that IS the channel test.

    Not scoped to `CredMgmtState` — nothing here parses impl blocks — and the
    scan is the wider one on purpose: a second type growing the same guard is a
    site this axis should own, not one it should miss.
    """
    return sorted(
        name
        for name, body in functions((root / STATE).read_text(encoding="utf-8"))
        if CHANNEL_TEST.search(body)
    )


def window_guards(root: Path) -> list[str]:
    """The `reset.rs` predicate keyed on the power-up."""
    return sorted(
        name
        for name, body in functions((root / RESET).read_text(encoding="utf-8"))
        if all(word in body for word in WINDOW)
    )


def lock_vocabulary(root: Path):
    """(the lock's wire type, its fields, the methods that move it, a problem).

    All three out of `FidoState::pin_lock`: naming the type here as well would be
    the second spelling this whole file exists to delete. Both ways the anchor can
    move — the accessor renamed, its return type no longer a bare name — are a
    FINDING, because a traceback here aborts every one of the six axes before any
    of them is compared.
    """
    bodies = dict(functions((root / STATE).read_text(encoding="utf-8")))
    if LOCK_ACCESSOR not in bodies:
        return "", [], [], f"softlock: {STATE} defines no `{LOCK_ACCESSOR}` — the whole family hangs off it"
    accessor = bodies[LOCK_ACCESSOR]
    found = RETURNS.search(accessor)
    if not found:
        return "", [], [], f"softlock: `{LOCK_ACCESSOR}` returns no bare type — the wire form is read off its signature"
    kind = found.group(1)
    fields = sorted(set(re.findall(r"self\.(\w+)", accessor)))
    methods = sorted(n for n, b in bodies.items() if re.search(rf"\b{kind}\b", b))
    return kind, fields, methods, None


def guard_sites(root: Path, guards: list[str], kind: str | None) -> set[tuple[str, str]]:
    """The guards themselves and every production function that calls one.

    Scanned over `UNITS` rather than `crates/rsk-fido` alone, and the reason is
    the measurement: `pin_lock` / `restore_pin_lock` have no caller inside the
    applet at all. `kind`, where a family has one, also catches a board half that
    only ever names the wire TYPE — `Hooks::store_pin_lock` calls neither guard.
    """
    # An EMPTY vocabulary must derive NOTHING, and `\b(?:)\s*[(<]` derives
    # everything — it matches any open paren, so a family whose derivation
    # stopped reading would own the whole tree and its floor would never trip.
    # Measured on this file's own fixture, which is where the floor arms found it.
    call = re.compile(r"\b(?:" + "|".join(guards) + r")\s*[(<]") if guards else None
    named = re.compile(rf"\b{kind}\b") if kind else None
    found: set[tuple[str, str]] = set()
    for unit, _ in UNITS:
        for path in sorted((root / unit).rglob("*.rs")):
            # The SAME exclusion `production_sources` applies, so the guard scan
            # and the writer scan agree about what production is. They differed:
            # this one read `state_assurance.rs` and `generated_token_edges.rs`,
            # which the writer axes deliberately do not.
            if path.name.endswith(("_tests.rs", "_kani.rs")) or path.name in {
                "generated_token_edges.rs",
                "state_assurance.rs",
            }:
                continue
            rel = str(path.relative_to(root))
            for name, body in functions(path.read_text(encoding="utf-8")):
                if (
                    name in guards
                    or (call and call.search(body))
                    or (named and named.search(body))
                ):
                    found.add((rel, name))
    return found


def foreign_writers(root: Path, writers: set[str], keys: set[str]) -> list[str]:
    """Token-record writes outside `rsk-fido`, which the scan otherwise assumes away.

    Scoped by the import rather than by the name: `rsk-piv` defines its own
    `EF_PIN` (0xD180 against FIDO's 0x1080), so a name-only sweep of the tree
    reports three PIV sites that write a different record entirely.
    """
    call = rf"(?:\.|::)(?:{'|'.join(sorted(writers, key=len, reverse=True))})\s*\("
    alternation = "|".join(sorted(keys, key=len, reverse=True))
    named = re.compile(rf"{call}\s*(?:{RECEIVER})?(?:[a-z_]+::)*(?:{alternation})\b")
    # The module, not the two names: `use rsk_fido::consts;` then `consts::EF_PIN`
    # reaches the same record, and a glob import names neither.
    imports = re.compile(r"rsk_fido::consts\b")
    findings = []
    for base in (root / "crates", root / "firmware"):
        for path in sorted(base.rglob("*.rs")):
            rel = path.relative_to(root)
            if rel.is_relative_to(FIDO) or path.name.endswith(("_tests.rs", "_kani.rs")):
                continue
            text = path.read_text(encoding="utf-8")
            if not imports.search(text):
                continue
            for name, body in functions(text):
                if named.search(body):
                    findings.append(f"foreign: unowned concrete site {rel}::{name}")
    return findings


def matrix_columns(root: Path) -> set[str]:
    return {
        found.group(1)
        for line in (root / MATRIX).read_text(encoding="utf-8").splitlines()
        if (found := COLUMN_ROW.match(line))
    }


def owners(entries: list[dict]) -> set[tuple[str, str]]:
    return {(entry["file"], entry["function"]) for entry in entries}


def compare_axis(label: str, discovered: set, declared: set, findings: list[str]) -> None:
    for item in sorted(discovered - declared):
        findings.append(f"{label}: unowned concrete site {item[0]}::{item[1]}")
    for item in sorted(declared - discovered):
        findings.append(f"{label}: stale owner {item[0]}::{item[1]}")


def check_entry(
    label: str,
    entry: dict,
    ops: set[str],
    visible: bool,
    columns: set[str],
    test_only: bool,
    findings: list[str],
) -> None:
    site = f"{entry['file']}::{entry['function']}"
    disposition = entry.get("disposition", "step")
    if disposition not in DISPOSITIONS:
        findings.append(f"{label}: {site} carries disposition {disposition!r}")
        return
    if disposition == "step":
        if entry.get("op") not in ops:
            findings.append(f"{label}: {entry.get('op')} is outside the generated TLA+ Ops domain")
        if visible is False:
            findings.append(f"{label}: {site} is a step over state the abstraction cannot see")
    else:
        if "op" in entry:
            findings.append(f"{label}: {site} is {disposition} and still names an op")
        if not entry.get("why", "").strip():
            findings.append(f"{label}: {site} is {disposition} with no reason")
        if visible is True:
            findings.append(f"{label}: {site} writes abstract state and is not a step")
    if entry.get("test_only", False) is not test_only:
        state = "is" if test_only else "is not"
        findings.append(f"{label}: {site} {state} compiled only under cfg(test)")
    column = entry.get("column")
    if column is not None and column not in columns:
        findings.append(f"{label}: {site} names configuration {column!r}, which the matrix has no column for")
    if column is not None and not entry.get("why", "").strip():
        findings.append(f"{label}: {site} is configuration-conditional with no reason")


def audit(root: Path) -> tuple[list[str], str]:  # noqa: C901 — one clause per axis
    root = Path(root)
    data = tomllib.loads((root / MANIFEST).read_text(encoding="utf-8"))
    findings: list[str] = []
    ops = {
        line.split("|", 2)[2]
        for line in (root / EXPORT).read_text(encoding="utf-8").splitlines()
        if line.startswith("TOKEN|OP|")
    }
    keys = key_names(root)
    if keys != {"EF_PIN", "EF_PAUTHTOKEN"}:
        findings.append(f"TokenPersistentView key derivation yielded {sorted(keys)!r}")

    code = catalogue(root)
    fields, perms = token_fields(root), permissions(root)
    seen_fields, seen_perms = abstraction(root)
    writers = store_writers(root)
    volatile, volatile_seen = discovered_volatile(code, fields, seen_fields, str(STATE))
    outcomes, outcomes_seen = discovered_outcomes(code, perms, seen_perms)
    spellings = key_spellings(root, keys)
    persistent, generic = discovered_persistent(code, writers, spellings)
    kind, lock_fields, lock_methods, lock_problem = lock_vocabulary(root)
    if lock_problem:
        findings.append(lock_problem)
    if lock_fields and lock_fields != ["needs_power_cycle", "new_pin_mismatches"]:
        findings.append(f"the soft lock's field derivation yielded {lock_fields!r}")
    found = {
        # `None` on all three guard axes: alpha reads `paut.in_use`,
        # `permissions` and `has_rp_id`, and a guard writes none of them. The
        # visibility rule has nothing to say here, and saying it anyway would
        # make every one of these a step over state the abstraction cannot see.
        "walk_owner": (guard_sites(root, walk_guards(root), None), None),
        "softlock_owner": (guard_sites(root, lock_methods, kind), None),
        "reset_window_owner": (guard_sites(root, window_guards(root), None), None),
        "volatile_writer": (volatile, volatile_seen),
        # `None`: presence is what alpha reads of these records, and no regex
        # here can tell a write that changes it from one that rewrites in place.
        # `Noop` in the Ops domain is how a persistent stutter is spelled instead.
        "persistent_writer": (persistent, None),
        "outcome_producer": (outcomes, outcomes_seen),
    }
    gated = test_only_sources(root)
    columns = matrix_columns(root)
    for axis in AXES:
        label = axis.removesuffix("_writer").removesuffix("_producer").removesuffix("_owner")
        entries = data.get(axis, [])
        if len(found[axis][0]) < FLOORS[axis]:
            # Reported BESIDE the comparison, never instead of it. Skipping the
            # comparison made a deleted guard read as a broken reader — the same
            # failure one register over from a red run nobody read the reason for.
            findings.append(
                f"{label}: {len(found[axis][0])} site(s) derived, under the floor of"
                f" {FLOORS[axis]} — the derivation stopped reading the tree, and every"
                " rule below passes over the empty set"
            )
        compare_axis(label, found[axis][0], owners(entries), findings)
        for entry in entries:
            site = (entry["file"], entry["function"])
            # A stale owner is already named once; judging its fields as well
            # would bury that one message under the consequences of it.
            if site not in found[axis][0]:
                continue
            check_entry(
                label,
                entry,
                ops,
                None if found[axis][1] is None else site in found[axis][1],
                columns,
                site[0] in gated,
                findings,
            )
            if axis == "persistent_writer" and entry.get("generic", False) != (site in generic):
                state = "does" if site in generic else "does not"
                findings.append(f"{label}: {site[0]}::{site[1]} {state} write a fid it was handed")
    findings.extend(foreign_writers(root, writers, spellings))

    scanned = {site[0] for site in volatile | persistent | outcomes}
    summary = (
        f"token-refinement-gate: GREEN keys={len(keys)} api={len(writers)} "
        f"volatile={len(volatile)}/{len(volatile_seen)} "
        f"persistent={len(persistent)}/{len(generic)} "
        f"outcomes={len(outcomes)}/{len(outcomes_seen)} "
        f"walk={len(found['walk_owner'][0])} "
        f"softlock={len(found['softlock_owner'][0])} "
        f"window={len(found['reset_window_owner'][0])} "
        f"testonly={len(scanned & gated)}"
    )
    return findings, summary


def main() -> int:
    findings, summary = audit(ROOT)
    if findings:
        print("token-refinement-gate:", file=sys.stderr)
        for finding in findings:
            print(f"  {finding}", file=sys.stderr)
        return 1
    print(summary)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
